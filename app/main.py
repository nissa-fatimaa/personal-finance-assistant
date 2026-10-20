"""FastAPI authentication endpoints and cross-site request protection."""

import base64
import binascii
import ipaddress
import json
from datetime import date
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app import account_data, auth, chat, finance, insights, ledger, llm, ratelimit, receipts
from app.config import get_settings, local_today
from app.db import app_engine, audit_engine, stats_engine
from app.policy import needs

EMAIL_PATTERN = r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
GENERIC_REGISTER_RESPONSE = {
    "message": "Registration request received."
}
GENERIC_RESET_RESPONSE = {
    "message": "If an account matches, reset instructions will be handled by the configured email mode."
}


def _local_today() -> date:
    return local_today()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RegisterBody(StrictModel):
    email: str = Field(min_length=3, max_length=254, pattern=EMAIL_PATTERN)
    password: str = Field(min_length=1, max_length=1024)
    base_currency: str = Field(default="PKR", min_length=3, max_length=3)
    privacy_consent: bool
    ai_consent: bool = False


class LoginBody(StrictModel):
    email: str = Field(min_length=3, max_length=254, pattern=EMAIL_PATTERN)
    password: str = Field(min_length=1, max_length=1024)


class TotpCodeBody(StrictModel):
    code: str = Field(pattern=r"^\d{6}$")


class TotpEnrollBody(StrictModel):
    current_password: str = Field(min_length=1, max_length=1024)
    current_code: str | None = Field(default=None, pattern=r"^\d{6}$")


class ChangePasswordBody(StrictModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)
    current_code: str | None = Field(default=None, pattern=r"^\d{6}$")


class ResetRequestBody(StrictModel):
    email: str = Field(min_length=3, max_length=254, pattern=EMAIL_PATTERN)


class ResetConfirmBody(StrictModel):
    token: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=1024)


class RevokeCurrentBody(StrictModel):
    # Accepted for compatibility with clients; never used to select the session.
    user_id: UUID | None = None


class TransactionBody(StrictModel):
    kind: Literal["expense", "income", "refund", "transfer"]
    amount_minor: int = Field(strict=True, gt=0)
    currency: str = Field(min_length=3, max_length=3, pattern=r"^[A-Za-z]{3}$")
    merchant: str = Field(min_length=1, max_length=200)
    txn_date: date = Field(default_factory=_local_today)
    category_id: UUID | None = None
    account_id: UUID | None = None
    note: str | None = Field(default=None, max_length=1000)
    fee_minor: int | None = Field(default=None, strict=True, ge=0)
    fx_override_rate: str | None = Field(default=None, min_length=1, max_length=32)


class ChatBody(StrictModel):
    message: str = Field(min_length=1, max_length=2000)


class ReceiptReviewBody(StrictModel):
    filename: str = Field(min_length=1, max_length=255)
    content_type: str = Field(min_length=1, max_length=64)
    content_base64: str = Field(min_length=1, max_length=11_184_812)


class TransactionDateBody(StrictModel):
    txn_date: date


class AiConsentBody(StrictModel):
    enabled: bool


class AccountReauthBody(StrictModel):
    current_password: str = Field(min_length=1, max_length=1024)
    current_code: str | None = Field(default=None, pattern=r"^\d{6}$")


class DeleteAccountBody(AccountReauthBody):
    confirmation: Literal["DELETE"]


class AccountBody(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    type: Literal["cash", "bank", "card", "wallet"]
    currency: str = Field(min_length=3, max_length=3, pattern=r"^[A-Za-z]{3}$")


class MfaDisableBody(AccountReauthBody):
    pass


class RoleChangeBody(AccountReauthBody):
    role: Literal["user", "security_owner", "admin"]


class BudgetBody(StrictModel):
    category_id: UUID
    period: str = Field(pattern=r"^\d{4}-(0[1-9]|1[0-2])$")
    limit_minor: int = Field(strict=True, ge=0)


class BudgetPeriodBody(StrictModel):
    period: str = Field(pattern=r"^\d{4}-(0[1-9]|1[0-2])$")


class BillBody(StrictModel):
    biller: str = Field(min_length=1, max_length=200)
    amount_minor: int = Field(strict=True, gt=0)
    currency: str = Field(min_length=3, max_length=3, pattern=r"^[A-Za-z]{3}$")
    next_due_date: date
    recurrence: str = Field(default="monthly", min_length=1, max_length=32)


def client_ip(request: Request) -> str:
    """Resolve the client IP used for rate limiting (never stored in plaintext).

    Order: a configured platform header (e.g. CF-Connecting-IP, which the edge
    overwrites so clients cannot forge it), then the entry appended by the
    N-th trusted proxy in X-Forwarded-For, then the socket peer.
    """
    settings = get_settings()
    candidate: str | None = None
    if settings.client_ip_header:
        candidate = request.headers.get(settings.client_ip_header)
    if not candidate and settings.trusted_proxy_hops:
        hops = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
        if len(hops) >= settings.trusted_proxy_hops:
            candidate = hops[-settings.trusted_proxy_hops]
    if candidate:
        try:
            return str(ipaddress.ip_address(candidate.strip()))
        except ValueError:
            pass
    return request.client.host if request.client else "unknown"


def _family(request: Request) -> str:
    return auth.browser_family(request.headers.get("user-agent"))


def _set_session_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        "sid",
        token,
        max_age=12 * 60 * 60,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        "sid",
        path="/",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )


def create_app() -> FastAPI:
    app = FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Do not echo input values: validation inputs can include passwords or tokens.
        return JSONResponse(status_code=422, content={"detail": "invalid request"})

    @app.middleware("http")
    async def request_security(request: Request, call_next):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if request.headers.get("x-requested-with") != "pfa":
                return JSONResponse(status_code=403, content={"detail": "forbidden"})
            content_type = request.headers.get("content-type", "").split(";", 1)[0]
            if content_type.lower() != "application/json":
                return JSONResponse(status_code=415, content={"detail": "JSON required"})

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; object-src 'none'; "
            "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if get_settings().cookie_secure:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response

    @app.exception_handler(auth.RateLimited)
    async def rate_limited_handler(request: Request, exc: auth.RateLimited) -> JSONResponse:
        return JSONResponse(
            status_code=429,
            content={"detail": "too many attempts, try again later"},
            headers={"Retry-After": "900"},
        )

    @app.get("/health")
    def health():
        """Permission: public readiness check; proves a database round-trip.

        Returns 503 when PostgreSQL is unreachable so container and platform
        health checks fail (and restart/stop routing) instead of lying.
        """
        try:
            with app_engine.connect() as connection:
                connection.execute(text("SELECT 1")).scalar_one()
        except SQLAlchemyError:
            return JSONResponse(status_code=503, content={"status": "unavailable", "database": "down"})
        return {"status": "ok", "database": "ok"}

    @app.get("/health/live", include_in_schema=False)
    def liveness():
        """Permission: public process liveness only (no dependencies)."""
        return {"status": "ok"}

    @app.post("/auth/register", status_code=202)
    def register(body: RegisterBody, request: Request):
        """Permission: public registration; privacy consent is required; per-IP limited."""
        try:
            auth.register_account(
                email=body.email,
                password=body.password,
                base_currency=body.base_currency.upper(),
                privacy_consent=body.privacy_consent,
                ai_consent=body.ai_consent,
                ip_address=client_ip(request),
            )
        except auth.WeakPassword as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        except IntegrityError:
            return GENERIC_REGISTER_RESPONSE
        return GENERIC_REGISTER_RESPONSE

    @app.post("/auth/login")
    def login(body: LoginBody, request: Request, response: Response):
        """Permission: public first-factor authentication."""
        result = auth.authenticate(
            email=body.email,
            password=body.password,
            ip_address=client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
        if result is None:
            raise HTTPException(status_code=401, detail="invalid credentials")
        _set_session_cookie(response, result.token)
        return {"mfa_required": result.mfa_required}

    @app.post("/auth/mfa/verify")
    def verify_mfa(body: TotpCodeBody, request: Request):
        """Permission: an unverified first-factor session cookie."""
        try:
            session = auth.verify_login_totp(
                request.cookies.get("sid"),
                body.code,
                request.headers.get("user-agent"),
                client_ip(request),
            )
        except auth.InvalidCredentials:
            raise HTTPException(status_code=401, detail="invalid MFA verification") from None
        return {"authenticated": session.mfa_ok}

    @app.get("/auth/me")
    def me(session: Annotated[auth.AuthSession, Depends(needs("profile:own"))]):
        """Permission: profile:own."""
        security = auth.security_status(session.user_id)
        return {
            "user_id": str(session.user_id),
            "role": session.role,
            "mfa_ok": session.mfa_ok,
            "mfa_enabled": security["mfa_enabled"],
            "ai_consent": security["ai_consent"],
        }

    @app.get("/auth/sessions")
    def list_own_sessions(
        session: Annotated[auth.AuthSession, Depends(needs("session:revoke"))],
    ):
        """Permission: session:revoke; returns only the caller's safe session metadata."""
        return {
            "sessions": auth.list_sessions(session.user_id, session.session_id)
        }

    @app.post("/auth/sessions/{session_id}/revoke", status_code=204)
    def revoke_own_session(
        session_id: UUID,
        response: Response,
        session: Annotated[auth.AuthSession, Depends(needs("session:revoke"))],
    ):
        """Permission: session:revoke; may revoke only a session owned by the caller."""
        if not auth.revoke_user_session(session_id, session.user_id):
            raise HTTPException(status_code=404, detail="session not found")
        if session_id == session.session_id:
            _clear_session_cookie(response)
        response.status_code = 204
        return response

    @app.get("/me/settings")
    def own_settings(
        session: Annotated[auth.AuthSession, Depends(needs("profile:own"))],
    ):
        """Permission: profile:own; returns only this account's consent and MFA state."""
        return auth.security_status(session.user_id)

    @app.put("/me/ai-consent")
    def set_own_ai_consent(
        body: AiConsentBody,
        session: Annotated[auth.AuthSession, Depends(needs("profile:own"))],
    ):
        """Permission: profile:own; records or withdraws optional AI-processing consent."""
        auth.set_ai_consent(session.user_id, body.enabled)
        return auth.security_status(session.user_id)

    @app.post("/me/export")
    def export_own_account(
        body: AccountReauthBody,
        session: Annotated[auth.AuthSession, Depends(needs("export:own"))],
    ):
        """Permission: export:own; fresh password and configured MFA are required."""
        try:
            profile = auth.reauthenticate_account_export(
                user_id=session.user_id,
                session_id=session.session_id,
                current_password=body.current_password,
                current_code=body.current_code,
            )
        except auth.InvalidCredentials:
            raise HTTPException(status_code=401, detail="reauthentication failed") from None
        payload = account_data.export_user_data(session.user_id, profile)
        encoded = json.dumps(
            jsonable_encoder(payload), ensure_ascii=False, indent=2
        )
        return Response(
            content=encoded,
            media_type="application/json",
            headers={
                "Content-Disposition": 'attachment; filename="account-export.json"',
                "Cache-Control": "no-store",
            },
        )

    @app.post("/me/delete", status_code=204)
    def delete_own_account(
        body: DeleteAccountBody,
        response: Response,
        session: Annotated[auth.AuthSession, Depends(needs("account:delete"))],
    ):
        """Permission: account:delete; exact confirmation, password, and current MFA are required."""
        try:
            auth.delete_account(
                user_id=session.user_id,
                session_id=session.session_id,
                current_password=body.current_password,
                current_code=body.current_code,
            )
        except auth.InvalidCredentials:
            raise HTTPException(status_code=401, detail="reauthentication failed") from None

        _clear_session_cookie(response)
        try:
            account_data.shred_user_data(session.user_id)
        except SQLAlchemyError:
            # The DEK was already destroyed transactionally; retained ciphertext
            # is unreadable. Report that metadata cleanup needs attention.
            cleanup_response = JSONResponse(
                status_code=503,
                content={
                    "detail": (
                        "Account deletion is complete, but encrypted-record cleanup "
                        "could not be confirmed."
                    ),
                    "account_deleted": True,
                },
                headers={"Cache-Control": "no-store"},
            )
            _clear_session_cookie(cleanup_response)
            return cleanup_response
        response.status_code = 204
        return response

    @app.post("/auth/mfa/enroll")
    def enroll_mfa(
        body: TotpEnrollBody,
        request: Request,
        session: Annotated[auth.AuthSession, Depends(needs("auth:mfa_manage"))],
    ):
        """Permission: auth:mfa_manage; current password and active-session reauth."""
        try:
            uri = auth.begin_totp_enrollment(
                user_id=session.user_id,
                session_id=session.session_id,
                password=body.current_password,
                current_code=body.current_code,
            )
        except auth.InvalidCredentials:
            raise HTTPException(status_code=401, detail="reauthentication required") from None
        return {"provisioning_uri": uri}

    @app.post("/auth/mfa/confirm", status_code=204)
    def confirm_mfa(
        body: TotpCodeBody,
        request: Request,
        session: Annotated[auth.AuthSession, Depends(needs("auth:mfa_manage"))],
    ):
        """Permission: auth:mfa_manage; pending enrollment and a valid TOTP code."""
        try:
            auth.confirm_totp_enrollment(
                user_id=session.user_id,
                session_id=session.session_id,
                code=body.code,
                user_agent=request.headers.get("user-agent"),
            )
        except auth.InvalidCredentials:
            raise HTTPException(status_code=401, detail="invalid MFA code") from None
        return Response(status_code=204)

    @app.post("/auth/mfa/disable", status_code=204)
    def disable_mfa(
        body: MfaDisableBody,
        session: Annotated[auth.AuthSession, Depends(needs("auth:mfa_manage"))],
    ):
        """Permission: auth:mfa_manage; users only (mandatory for staff); password + current code."""
        try:
            auth.disable_totp(
                user_id=session.user_id,
                session_id=session.session_id,
                current_password=body.current_password,
                current_code=body.current_code,
            )
        except auth.InvalidCredentials:
            raise HTTPException(status_code=401, detail="reauthentication failed") from None
        except PermissionError:
            raise HTTPException(status_code=403, detail="MFA is mandatory for this role") from None
        return Response(status_code=204)

    @app.post("/auth/password/change", status_code=204)
    def password_change(
        body: ChangePasswordBody,
        request: Request,
        response: Response,
        session: Annotated[auth.AuthSession, Depends(needs("auth:password_change"))],
    ):
        """Permission: auth:password_change; revokes every active session."""
        try:
            auth.change_password(
                user_id=session.user_id,
                current_password=body.current_password,
                new_password=body.new_password,
                current_code=body.current_code,
                user_agent=request.headers.get("user-agent"),
            )
        except auth.WeakPassword as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        except auth.InvalidCredentials:
            raise HTTPException(status_code=401, detail="reauthentication failed") from None
        _clear_session_cookie(response)
        response.status_code = 204
        return response

    @app.post("/auth/password/reset", status_code=202)
    def request_password_reset(body: ResetRequestBody, request: Request):
        """Permission: public; generic response and bounded rate limits."""
        auth.request_password_reset(
            email=body.email,
            ip_address=client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
        return GENERIC_RESET_RESPONSE

    @app.post("/auth/password/reset/confirm", status_code=204)
    def confirm_password_reset(
        body: ResetConfirmBody, request: Request, response: Response
    ):
        """Permission: public single-use reset token; all prior sessions are revoked."""
        try:
            complete = auth.complete_password_reset(
                token=body.token,
                new_password=body.new_password,
                user_agent=request.headers.get("user-agent"),
            )
        except auth.WeakPassword as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        if not complete:
            raise HTTPException(status_code=400, detail="invalid or expired reset token")
        _clear_session_cookie(response)
        response.status_code = 204
        return response

    @app.post("/auth/logout", status_code=204)
    def logout(request: Request, response: Response):
        """Permission: public / current session; idempotently revokes only its cookie."""
        auth.logout(request.cookies.get("sid"))
        _clear_session_cookie(response)
        response.status_code = 204
        return response

    @app.post("/auth/sessions/revoke-current", status_code=204)
    def revoke_current(
        body: RevokeCurrentBody,
        response: Response,
        session: Annotated[auth.AuthSession, Depends(needs("session:revoke"))],
    ):
        """Permission: session:revoke; identity comes only from the authenticated session."""
        # The identity comes from the session, never from body.user_id.
        auth.revoke_current_session(session.session_id, session.user_id)
        _clear_session_cookie(response)
        response.status_code = 204
        return response

    @app.post("/chat")
    async def chat_entry(
        body: ChatBody,
        session: Annotated[auth.AuthSession, Depends(needs("chat:use"))],
    ):
        """Permission: chat:use; masks, parses, and stages only a reviewable draft."""
        if not ratelimit.hit(
            ratelimit.CHAT_PER_USER, ratelimit.key_for("user", str(session.user_id))
        ):
            raise auth.RateLimited("chat_per_user")
        try:
            parsed = chat.parse_message(
                body.message, ledger.get_base_currency(session.user_id)
            )
            if parsed["clarification"] and llm.is_configured():
                consent = auth.security_status(session.user_id)["ai_consent"]
                if consent:
                    parsed = await chat.extract_message(
                        body.message,
                        ledger.get_base_currency(session.user_id),
                        ai_consent=True,
                    )
            if parsed["clarification"]:
                return parsed
            fallback_category_id = None
            hint = chat.category_hint(parsed["merchant"])
            if hint is not None:
                fallback_category_id = ledger.shared_category_id(
                    session.user_id, hint
                )
            pending = ledger.create_pending(
                user_id=session.user_id,
                kind=parsed["kind"],
                amount_minor=parsed["amount_minor"],
                currency=parsed["currency"],
                merchant=parsed["merchant"],
                txn_date=parsed["txn_date"],
                source="chat",
                fallback_category_id=fallback_category_id,
            )
        except ledger.MissingObject:
            raise HTTPException(status_code=404, detail="object not found") from None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        if pending is None:
            raise HTTPException(status_code=409, detail="possible duplicate")
        return {
            "clarification": False,
            "confirmation_required": True,
            "confirmation_card": {
                "txn_id": pending["txn_id"],
                "kind": parsed["kind"],
                "amount_minor": parsed["amount_minor"],
                "currency": parsed["currency"],
                "merchant": parsed["merchant"],
                "category_id": pending["category_id"],
            },
        }

    @app.post("/receipts/review")
    async def review_receipt(
        body: ReceiptReviewBody,
        session: Annotated[
            auth.AuthSession, Depends(needs("transaction:create"))
        ],
    ):
        """Permission: transaction:create; reads a receipt in memory and stages pending."""
        if not ratelimit.hit(
            ratelimit.RECEIPT_PER_USER, ratelimit.key_for("user", str(session.user_id))
        ):
            raise auth.RateLimited("receipt_per_user")
        try:
            file_bytes = base64.b64decode(body.content_base64, validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(status_code=422, detail="invalid receipt encoding") from None
        try:
            extracted_text, text_source = receipts.extract_text(
                file_bytes, body.filename, body.content_type
            )
        except receipts.ReceiptUnavailable as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

        safe_text = chat.mask_pii(extracted_text)
        base_currency = ledger.get_base_currency(session.user_id)
        parsed_receipt = receipts.parse_receipt(safe_text, base_currency)
        if parsed_receipt["amount_minor"] is None and llm.is_configured():
            consent = auth.security_status(session.user_id)["ai_consent"]
            if consent:
                parsed_receipt = await receipts.extract_receipt_fields(
                    safe_text, base_currency, ai_consent=True
                )
        if not extracted_text.strip() or parsed_receipt["amount_minor"] is None:
            return {
                "clarification": True,
                "missing": ["readable text with a clearly labelled total"],
                "text_source": text_source,
            }

        purchase_date = parsed_receipt["purchase_date"]
        txn_date = purchase_date or _local_today()
        try:
            category_id = None
            category_hint = chat.category_hint(parsed_receipt["merchant"])
            if category_hint:
                category_id = ledger.shared_category_id(
                    session.user_id, category_hint
                )
            pending = ledger.create_pending(
                user_id=session.user_id,
                kind="expense",
                amount_minor=parsed_receipt["amount_minor"],
                currency=parsed_receipt["currency"],
                merchant=parsed_receipt["merchant"],
                txn_date=txn_date,
                source="receipt",
                fallback_category_id=category_id,
            )
        except ledger.MissingObject:
            raise HTTPException(status_code=404, detail="object not found") from None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        if pending is None:
            raise HTTPException(status_code=409, detail="possible duplicate")
        return {
            "clarification": False,
            "confirmation_required": True,
            "confirmation_card": {
                "txn_id": pending["txn_id"],
                "kind": "expense",
                "amount_minor": parsed_receipt["amount_minor"],
                "currency": parsed_receipt["currency"],
                "merchant": parsed_receipt["merchant"],
                "category_id": pending["category_id"],
                "txn_date": txn_date.isoformat(),
                "receipt_date_detected": purchase_date is not None,
            },
            "receipt_review": {
                "text_source": text_source,
                "status": "pending",
                "purchase_date": purchase_date.isoformat() if purchase_date else None,
                "reconciliation": parsed_receipt["reconciliation"],
                "subtotal_minor": parsed_receipt["subtotal_minor"],
                "tax_minor": parsed_receipt["tax_minor"],
                "expected_total_minor": parsed_receipt["expected_total_minor"],
                "printed_total_minor": parsed_receipt["amount_minor"],
            },
        }

    @app.put("/transactions/{txn_id}/date")
    def update_pending_transaction_date(
        txn_id: UUID,
        body: TransactionDateBody,
        session: Annotated[auth.AuthSession, Depends(needs("transaction:create"))],
    ):
        """Permission: transaction:create; adjusts only an owned pending transaction date."""
        try:
            ledger.update_pending_transaction_date(
                user_id=session.user_id,
                txn_id=txn_id,
                txn_date=body.txn_date,
            )
        except ledger.MissingObject:
            raise HTTPException(status_code=404, detail="object not found") from None
        except ValueError as exc:
            if str(exc) == "possible duplicate":
                raise HTTPException(status_code=409, detail=str(exc)) from None
            raise HTTPException(status_code=422, detail=str(exc)) from None
        return {"txn_id": txn_id, "status": "pending", "txn_date": body.txn_date}

    @app.post("/transactions", status_code=201)
    def create_transaction(
        body: TransactionBody,
        session: Annotated[auth.AuthSession, Depends(needs("transaction:create"))],
    ):
        """Permission: transaction:create; creates an encrypted pending transaction."""
        try:
            result = ledger.create_pending(
                user_id=session.user_id,
                kind=body.kind,
                amount_minor=body.amount_minor,
                currency=body.currency,
                merchant=body.merchant,
                txn_date=body.txn_date,
                category_id=body.category_id,
                account_id=body.account_id,
                note=body.note,
                fee_minor=body.fee_minor,
                fx_override_rate=body.fx_override_rate,
            )
        except ledger.MissingObject:
            raise HTTPException(status_code=404, detail="object not found") from None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        if result is None:
            raise HTTPException(status_code=409, detail="possible duplicate")
        return result

    @app.post("/transactions/{txn_id}/confirm")
    def confirm_transaction(
        txn_id: UUID,
        session: Annotated[auth.AuthSession, Depends(needs("transaction:create"))],
    ):
        """Permission: transaction:create; posts only a pending row visible under RLS."""
        try:
            ledger.confirm(session.user_id, txn_id)
        except ledger.MissingObject:
            raise HTTPException(status_code=404, detail="object not found") from None
        return {"txn_id": txn_id, "status": "posted"}

    @app.get("/transactions")
    def get_transactions(
        session: Annotated[auth.AuthSession, Depends(needs("transaction:read"))],
        month: str | None = None,
    ):
        """Permission: transaction:read; returns posted, non-deleted rows for one month."""
        month = month or _local_today().strftime("%Y-%m")
        try:
            rows = ledger.list_month(session.user_id, month)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        return {"month": month, "transactions": rows}

    @app.get("/transactions/{txn_id:uuid}")
    def get_transaction(
        txn_id: UUID,
        session: Annotated[auth.AuthSession, Depends(needs("transaction:read"))],
    ):
        """Permission: transaction:read; returns one posted transaction owned by caller."""
        try:
            return ledger.get_transaction(session.user_id, txn_id)
        except ledger.MissingObject:
            raise HTTPException(status_code=404, detail="object not found") from None

    @app.put("/transactions/{txn_id}")
    def update_transaction(
        txn_id: UUID,
        body: TransactionBody,
        session: Annotated[auth.AuthSession, Depends(needs("transaction:create"))],
    ):
        """Permission: transaction:create; updates an encrypted transaction owned by caller."""
        try:
            ledger.update_transaction(
                user_id=session.user_id,
                txn_id=txn_id,
                kind=body.kind,
                amount_minor=body.amount_minor,
                currency=body.currency,
                merchant=body.merchant,
                txn_date=body.txn_date,
                category_id=body.category_id,
                account_id=body.account_id,
                note=body.note,
                fee_minor=body.fee_minor,
                fx_override_rate=body.fx_override_rate,
            )
        except ledger.MissingObject:
            raise HTTPException(status_code=404, detail="object not found") from None
        except ValueError as exc:
            if str(exc) == "possible duplicate":
                raise HTTPException(status_code=409, detail=str(exc)) from None
            raise HTTPException(status_code=422, detail=str(exc)) from None
        return {"txn_id": txn_id, "status": "posted"}

    @app.delete("/transactions/{txn_id}", status_code=204)
    def delete_transaction(
        txn_id: UUID,
        session: Annotated[auth.AuthSession, Depends(needs("transaction:create"))],
    ):
        """Permission: transaction:create; soft-deletes an owned transaction."""
        try:
            ledger.soft_delete_transaction(session.user_id, txn_id)
        except ledger.MissingObject:
            raise HTTPException(status_code=404, detail="object not found") from None
        return Response(status_code=204)

    @app.get("/budgets")
    def get_budgets(
        session: Annotated[auth.AuthSession, Depends(needs("budget:write"))],
        period: str | None = None,
    ):
        """Permission: budget:write; reads the caller's encrypted monthly limits."""
        period = period or _local_today().strftime("%Y-%m")
        try:
            budgets = finance.list_budgets(session.user_id, period)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        return {"period": period, "budgets": budgets}

    @app.put("/budgets")
    def put_budget(
        body: BudgetBody,
        session: Annotated[auth.AuthSession, Depends(needs("budget:write"))],
    ):
        """Permission: budget:write; saves a manually chosen category limit."""
        try:
            return finance.save_budget(
                session.user_id,
                body.category_id,
                body.period,
                body.limit_minor,
            )
        except ledger.MissingObject:
            raise HTTPException(status_code=404, detail="category not found") from None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

    @app.get("/budgets/suggestions")
    def get_budget_suggestions(
        session: Annotated[auth.AuthSession, Depends(needs("budget:write"))],
        period: str | None = None,
    ):
        """Permission: budget:write; suggestions are calculated but never applied here."""
        period = period or _local_today().strftime("%Y-%m")
        try:
            return finance.get_budget_suggestions(session.user_id, period)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

    @app.post("/budgets/suggestions/{category_id}/approve")
    def approve_budget_suggestion(
        category_id: UUID,
        body: BudgetPeriodBody,
        session: Annotated[auth.AuthSession, Depends(needs("budget:write"))],
    ):
        """Permission: budget:write; persists only after explicit user approval."""
        try:
            return finance.approve_budget_suggestion(
                session.user_id, category_id, body.period
            )
        except finance.SuggestionUnavailable:
            raise HTTPException(
                status_code=409, detail="budget suggestion is unavailable"
            ) from None
        except ledger.MissingObject:
            raise HTTPException(status_code=404, detail="category not found") from None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

    @app.post("/bills", status_code=201)
    def create_bill(
        body: BillBody,
        session: Annotated[auth.AuthSession, Depends(needs("transaction:create"))],
    ):
        """Permission: transaction:create; stores an encrypted bill owned by the caller."""
        try:
            return ledger.create_bill(
                user_id=session.user_id,
                biller=body.biller,
                amount_minor=body.amount_minor,
                currency=body.currency,
                next_due_date=body.next_due_date,
                recurrence=body.recurrence,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

    @app.get("/bills")
    def get_bills(
        session: Annotated[auth.AuthSession, Depends(needs("transaction:read"))],
    ):
        """Permission: transaction:read; returns the caller's non-deleted bills."""
        return {"bills": ledger.list_bills(session.user_id)}

    @app.delete("/bills/{bill_id}", status_code=204)
    def delete_bill(
        bill_id: UUID,
        session: Annotated[auth.AuthSession, Depends(needs("transaction:create"))],
    ):
        """Permission: transaction:create; soft-deletes an owned bill."""
        try:
            ledger.soft_delete_bill(session.user_id, bill_id)
        except ledger.MissingObject:
            raise HTTPException(status_code=404, detail="object not found") from None
        return Response(status_code=204)

    @app.get("/accounts")
    def list_accounts(
        session: Annotated[auth.AuthSession, Depends(needs("transaction:read"))],
    ):
        """Permission: transaction:read; only the caller's accounts (RLS + ownership)."""
        return {"accounts": ledger.list_accounts(session.user_id)}

    @app.post("/accounts", status_code=201)
    def create_account(
        body: AccountBody,
        session: Annotated[auth.AuthSession, Depends(needs("account:manage"))],
    ):
        """Permission: account:manage; the name is encrypted with the user's key."""
        try:
            return ledger.create_account(
                session.user_id, name=body.name, type_=body.type, currency=body.currency.upper()
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

    @app.delete("/accounts/{account_id}", status_code=204)
    def delete_account_record(
        account_id: UUID,
        session: Annotated[auth.AuthSession, Depends(needs("account:manage"))],
    ):
        """Permission: account:manage; soft delete; foreign IDs return 404 and are audited."""
        try:
            ledger.soft_delete_account(session.user_id, account_id)
        except ledger.MissingObject:
            raise HTTPException(status_code=404, detail="object not found") from None
        return Response(status_code=204)

    @app.get("/security/users")
    def staff_list_users(
        session: Annotated[auth.AuthSession, Depends(needs("account:status"))],
        limit: int = Query(default=100, ge=1, le=500),
    ):
        """Permission: account:status (security_owner, admin); status metadata only."""
        return {"users": auth.list_accounts_for_staff(limit)}

    def _staff_action(fn, **kwargs):
        try:
            fn(**kwargs)
        except PermissionError:
            raise HTTPException(status_code=403, detail="forbidden") from None
        except LookupError:
            raise HTTPException(status_code=404, detail="Not found") from None

    @app.post("/security/users/{user_id}/lock", status_code=204)
    def staff_lock(
        user_id: UUID,
        session: Annotated[auth.AuthSession, Depends(needs("account:lock"))],
    ):
        """Permission: account:lock (security_owner); revokes every session; audited."""
        _staff_action(auth.set_account_lock, actor_user_id=session.user_id,
                      target_user_id=user_id, locked=True)
        return Response(status_code=204)

    @app.post("/security/users/{user_id}/unlock", status_code=204)
    def staff_unlock(
        user_id: UUID,
        session: Annotated[auth.AuthSession, Depends(needs("account:lock"))],
    ):
        """Permission: account:lock (security_owner); audited."""
        _staff_action(auth.set_account_lock, actor_user_id=session.user_id,
                      target_user_id=user_id, locked=False)
        return Response(status_code=204)

    @app.post("/security/users/{user_id}/force-reset", status_code=204)
    def staff_force_reset(
        user_id: UUID,
        session: Annotated[auth.AuthSession, Depends(needs("account:force_reset"))],
    ):
        """Permission: account:force_reset (security_owner); invalidates password + sessions."""
        _staff_action(auth.force_password_reset, actor_user_id=session.user_id,
                      target_user_id=user_id)
        return Response(status_code=204)

    @app.put("/security/users/{user_id}/role", status_code=204)
    def staff_change_role(
        user_id: UUID,
        body: RoleChangeBody,
        session: Annotated[auth.AuthSession, Depends(needs("role:change"))],
    ):
        """Permission: role:change (security_owner); actor re-auth with password + TOTP."""
        try:
            auth.change_role(
                actor_user_id=session.user_id,
                actor_session_id=session.session_id,
                target_user_id=user_id,
                new_role=body.role,
                current_password=body.current_password,
                current_code=body.current_code,
            )
        except auth.InvalidCredentials:
            raise HTTPException(status_code=401, detail="reauthentication failed") from None
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        except PermissionError:
            raise HTTPException(status_code=403, detail="forbidden") from None
        except LookupError:
            raise HTTPException(status_code=404, detail="Not found") from None
        return Response(status_code=204)

    @app.get("/categories")
    def get_categories(
        session: Annotated[auth.AuthSession, Depends(needs("transaction:read"))],
    ):
        """Permission: transaction:read; returns shared and caller-owned categories."""
        return {"categories": ledger.list_categories(session.user_id)}

    @app.get("/dashboard")
    def get_dashboard(
        session: Annotated[auth.AuthSession, Depends(needs("transaction:read"))],
        month: str | None = None,
        currency: str | None = None,
        policy: str = "as_recorded",
    ):
        """Permission: transaction:read; returns one RLS-scoped dashboard object."""
        month = month or _local_today().strftime("%Y-%m")
        try:
            return finance.dashboard(session.user_id, month, currency, policy)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

    @app.get("/api/insights")
    async def get_insights(
        session: Annotated[auth.AuthSession, Depends(needs("insight:read"))],
        month: str | None = None,
    ):
        """Permission: insight:read; computes facts locally, verifies optional wording."""
        month = month or _local_today().strftime("%Y-%m")
        try:
            dashboard = finance.dashboard(session.user_id, month)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        end_date = ledger.month_bounds(month)[1]
        days_left = max(0, (end_date - _local_today()).days)
        dashboard["days_left"] = days_left
        consent = (
            auth.security_status(session.user_id)["ai_consent"]
            if llm.is_configured()
            else False
        )
        return await insights.build_insights(dashboard, ai_consent=consent)

    @app.get("/admin/stats")
    def admin_stats(
        session: Annotated[auth.AuthSession, Depends(needs("stats:read"))],
    ):
        """Permission: stats:read; returns aggregate counts only, without row data."""
        with stats_engine.begin() as connection:
            row = connection.execute(
                text(
                    "SELECT active_users, txns_24h, failed_logins_24h "
                    "FROM public.stats_overview"
                )
            ).mappings().one()
        return {key: int(row[key]) for key in row.keys()}

    @app.get("/security/audit")
    def security_audit(
        session: Annotated[auth.AuthSession, Depends(needs("audit:read"))],
        limit: int = Query(default=50, ge=1, le=200),
    ):
        """Permission: audit:read; security_owner sees safe event metadata only."""
        with audit_engine.begin() as connection:
            rows = connection.execute(
                text(
                    "SELECT id, ts, action, result FROM public.audit_log "
                    "ORDER BY id DESC LIMIT :limit"
                ),
                {"limit": limit},
            ).mappings()
            events = [
                {
                    "id": int(row["id"]),
                    "ts": row["ts"],
                    "action": row["action"],
                    "result": row["result"],
                }
                for row in rows
            ]
        return {"events": events}

    static_dir = Path(__file__).resolve().parent / "static"
    index_file = static_dir / "index.html"
    assets_dir = static_dir / "assets"
    if index_file.is_file():
        if assets_dir.is_dir():
            app.mount(
                "/assets",
                StaticFiles(directory=assets_dir),
                name="frontend-assets",
            )

        @app.get("/", include_in_schema=False)
        def frontend_index():
            return FileResponse(index_file, headers={"Cache-Control": "no-store"})

        frontend_api_prefixes = {
            "auth",
            "transactions",
            "budgets",
            "bills",
            "dashboard",
            "chat",
            "receipts",
            "api",
            "categories",
            "me",
            "admin",
            "security",
            "accounts",
            "health",
        }

        @app.get("/{frontend_path:path}", include_in_schema=False)
        def frontend_routes(frontend_path: str):
            parts = frontend_path.strip("/").split("/")
            frontend_transaction_route = (
                frontend_path == "transactions/new"
                or (
                    len(parts) == 3
                    and parts[0] == "transactions"
                    and parts[2] == "edit"
                )
            )
            frontend_role_route = frontend_path in {"admin", "security"}
            if (
                parts[0] in frontend_api_prefixes
                and not frontend_transaction_route
                and not frontend_role_route
            ):
                raise HTTPException(status_code=404, detail="Not found")
            return FileResponse(index_file, headers={"Cache-Control": "no-store"})

    return app


app = create_app()
