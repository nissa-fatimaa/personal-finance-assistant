"""Authentication, MFA, lockout, session, and password-reset services."""

from dataclasses import dataclass
from datetime import timedelta, timezone
import hashlib
import hmac
import logging
import secrets
from typing import Any
from urllib.parse import quote
from uuid import UUID, uuid4

from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error, InvalidHashError, VerifyMismatchError
from argon2.low_level import Type
import pyotp
from sqlalchemy import text
from zxcvbn import zxcvbn

from app import crypto, ratelimit
from app.audit import append_event
from app.config import Settings, get_settings
from app.db import auth_engine
from app.email import (
    EmailProviderError,
    OutboundEmail,
    get_email_provider,
    notification_message,
)

logger = logging.getLogger(__name__)

PASSWORD_HASHER = PasswordHasher(
    time_cost=2,
    memory_cost=19_456,
    parallelism=1,
    type=Type.ID,
)
_DUMMY_HASH = PASSWORD_HASHER.hash(
    hmac.new(
        crypto.key_material().pepper,
        b"dummy-password-never-used",
        hashlib.sha256,
    ).hexdigest()
)
SUPPORTED_CURRENCIES = frozenset(
    {"PKR", "USD", "EUR", "GBP", "AED", "SAR", "CAD", "AUD", "CNY", "JPY"}
)
RESET_WINDOW = timedelta(minutes=15)
RESET_TOKEN_LIFETIME = timedelta(minutes=15)
RESET_PER_ACCOUNT_LIMIT = 3


class WeakPassword(ValueError):
    """Password does not meet the configured strength policy."""


class InvalidCredentials(ValueError):
    """Generic authentication or token failure."""


class RateLimited(RuntimeError):
    """A shared (database-backed) rate limit was exceeded."""


@dataclass(frozen=True)
class LoginResult:
    token: str
    session_id: UUID
    user_id: UUID
    role: str
    mfa_required: bool


@dataclass(frozen=True)
class AuthSession:
    session_id: UUID
    user_id: UUID
    role: str
    mfa_ok: bool


def normalize_password(password: str) -> str:
    if not isinstance(password, str):
        raise WeakPassword("Password must be text")
    pepper = crypto.key_material().pepper
    return hmac.new(pepper, password.encode("utf-8"), hashlib.sha256).hexdigest()


def validate_password(password: str, user_inputs: tuple[str, ...] = ()) -> None:
    if len(password) < 12:
        raise WeakPassword("Password must be at least 12 characters")
    try:
        score = zxcvbn(password, user_inputs=list(user_inputs))["score"]
    except Exception:
        raise WeakPassword("Password strength could not be checked") from None
    if score < 3:
        raise WeakPassword("Password does not meet strength requirements")


def hash_password(password: str, user_inputs: tuple[str, ...] = ()) -> str:
    validate_password(password, user_inputs)
    return PASSWORD_HASHER.hash(normalize_password(password))


def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(encoded_hash, normalize_password(password))
    except (VerifyMismatchError, InvalidHashError, Argon2Error, ValueError):
        return False


def _dummy_verify(password: str) -> None:
    try:
        PASSWORD_HASHER.verify(_DUMMY_HASH, normalize_password(password))
    except (Argon2Error, ValueError):
        pass


def browser_family(user_agent: str | None) -> str:
    value = (user_agent or "").lower()
    if "edg/" in value or "edge/" in value:
        return "Edge"
    if "firefox/" in value:
        return "Firefox"
    if "chrome/" in value or "chromium/" in value:
        return "Chrome"
    if "safari/" in value:
        return "Safari"
    return "Unknown"


def _decrypt_user_email(row: Any) -> str:
    user_id = row["user_id"]
    dek = crypto.unwrap_dek(bytes(row["dek_wrapped"]), user_id)
    return crypto.dec(
        dek,
        bytes(row["email_enc"]),
        "users",
        "email_enc",
        user_id,
    ).decode("utf-8")


def _notify_safely(message: OutboundEmail) -> None:
    try:
        get_email_provider().send(message)
    except (EmailProviderError, RuntimeError, ValueError):
        logger.warning("email_provider_failed kind=%s", message.kind)


def register_account(
    *,
    email: str,
    password: str,
    base_currency: str,
    privacy_consent: bool,
    ai_consent: bool,
    ip_address: str = "unknown",
) -> UUID:
    # Checked before zxcvbn and Argon2id so registration cannot be used to burn CPU.
    if not ratelimit.hit(ratelimit.REGISTER_PER_IP, ratelimit.key_for("ip", ip_address)):
        with auth_engine.begin() as connection:
            append_event(
                connection, action="register_rate_limited", result="limited",
                actor_user_id=None, target_id=None,
            )
        raise RateLimited("registration rate limit")
    normalized_email = crypto.norm_email(email)
    if not privacy_consent:
        raise ValueError("Privacy consent is required")
    if base_currency not in SUPPORTED_CURRENCIES:
        raise ValueError("Unsupported base currency")

    password_hash = hash_password(password, (normalized_email,))
    user_id = uuid4()
    dek = crypto.new_dek()
    with auth_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO public.users "
                "(user_id, email_hmac, email_enc, password_hash, dek_wrapped, "
                "base_currency, privacy_consent_at, ai_consent_at) "
                "VALUES (:user_id, :email_hmac, :email_enc, :password_hash, "
                ":dek_wrapped, :base_currency, now(), "
                "CASE WHEN :ai_consent THEN now() ELSE NULL END)"
            ),
            {
                "user_id": user_id,
                "email_hmac": crypto.hmac_email(normalized_email),
                "email_enc": crypto.enc(
                    dek, normalized_email.encode("utf-8"), "users", "email_enc", user_id
                ),
                "password_hash": password_hash,
                "dek_wrapped": crypto.wrap_dek(dek, user_id),
                "base_currency": base_currency,
                "ai_consent": ai_consent,
            },
        )
    return user_id


def _event(connection, action: str, result: str, user_id: UUID | None) -> None:
    append_event(
        connection,
        action=action,
        result=result,
        actor_user_id=user_id,
        target_id=user_id,
    )


def authenticate(
    *,
    email: str,
    password: str,
    ip_address: str,
    user_agent: str | None,
) -> LoginResult | None:
    normalized_email = crypto.norm_email(email)
    email_hmac = crypto.hmac_email(normalized_email)
    family = browser_family(user_agent)
    result: LoginResult | None = None
    notification: OutboundEmail | None = None
    ip_key = ratelimit.key_for("ip", ip_address or "unknown")

    if ratelimit.exceeded(ratelimit.LOGIN_FAIL_PER_IP, ip_key):
        _dummy_verify(password)
        with auth_engine.begin() as connection:
            append_event(
                connection, action="login_rate_limited", result="limited",
                actor_user_id=None, target_id=None,
            )
        raise RateLimited("login rate limit")

    with auth_engine.begin() as connection:
        now = connection.execute(text("SELECT now()")).scalar_one()
        user = (
            connection.execute(
                text(
                    "SELECT user_id, email_enc, dek_wrapped, password_hash, role, status, "
                    "failed_login_count, last_failed_at, locked_until, totp_secret_enc "
                    "FROM public.users WHERE email_hmac = :email_hmac FOR UPDATE"
                ),
                {"email_hmac": email_hmac},
            )
            .mappings()
            .first()
        )
        if user is None or user["status"] != "active":
            _dummy_verify(password)
            _event(connection, "login_fail", "fail", user["user_id"] if user else None)
            ratelimit.hit(ratelimit.LOGIN_FAIL_PER_IP, ip_key, connection)
        elif user["locked_until"] is not None and user["locked_until"] > now:
            _dummy_verify(password)
            _event(connection, "login_fail", "fail", user["user_id"])
            ratelimit.hit(ratelimit.LOGIN_FAIL_PER_IP, ip_key, connection)
        elif not verify_password(password, user["password_hash"]):
            ratelimit.hit(ratelimit.LOGIN_FAIL_PER_IP, ip_key, connection)
            recent = (
                user["last_failed_at"] is not None
                and user["last_failed_at"] >= now - RESET_WINDOW
            )
            failures = user["failed_login_count"] + 1 if recent else 1
            locked_until = now + RESET_WINDOW if failures >= 5 else None
            connection.execute(
                text(
                    "UPDATE public.users SET failed_login_count = :failures, "
                    "last_failed_at = :now, locked_until = :locked_until "
                    "WHERE user_id = :user_id"
                ),
                {
                    "failures": failures,
                    "now": now,
                    "locked_until": locked_until,
                    "user_id": user["user_id"],
                },
            )
            _event(connection, "login_fail", "fail", user["user_id"])
            if failures == 5:
                notification = notification_message(
                    kind="account_lockout",
                    recipient=_decrypt_user_email(user),
                    subject="Account temporarily locked",
                    browser_family=family,
                    now=now,
                )
        elif user["role"] in {"security_owner", "admin"} and not user["totp_secret_enc"]:
            _dummy_verify(password)
            _event(connection, "login_fail", "fail", user["user_id"])
            ratelimit.hit(ratelimit.LOGIN_FAIL_PER_IP, ip_key, connection)
        else:
            user_id = user["user_id"]
            browser_digest = crypto.browser_hmac(user_id, family)
            previously_seen = connection.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM public.sessions "
                    "WHERE user_id = :user_id AND browser_hmac = :browser_hmac)"
                ),
                {"user_id": user_id, "browser_hmac": browser_digest},
            ).scalar_one()
            needs_mfa = user["totp_secret_enc"] is not None
            token = secrets.token_urlsafe(32)
            session_id = connection.execute(
                text(
                    "INSERT INTO public.sessions "
                    "(user_id, token_hash, ip_hmac, mfa_ok, expires_at, browser_hmac, new_browser) "
                    "VALUES (:user_id, :token_hash, :ip_hmac, :mfa_ok, "
                    "now() + interval '12 hours', :browser_hmac, :new_browser) "
                    "RETURNING session_id"
                ),
                {
                    "user_id": user_id,
                    "token_hash": hashlib.sha256(token.encode("utf-8")).digest(),
                    "ip_hmac": crypto.hmac_ip(ip_address or "unknown"),
                    "mfa_ok": not needs_mfa,
                    "browser_hmac": browser_digest,
                    "new_browser": bool(not previously_seen and needs_mfa),
                },
            ).scalar_one()
            connection.execute(
                text(
                    "UPDATE public.users SET failed_login_count = 0, "
                    "last_failed_at = NULL, locked_until = NULL "
                    "WHERE user_id = :user_id"
                ),
                {"user_id": user_id},
            )
            if not needs_mfa:
                _event(connection, "login_ok", "ok", user_id)
                if not previously_seen:
                    notification = notification_message(
                        kind="new_browser_login",
                        recipient=_decrypt_user_email(user),
                        subject="New sign-in",
                        browser_family=family,
                        now=now,
                    )
            result = LoginResult(
                token=token,
                session_id=session_id,
                user_id=user_id,
                role=user["role"],
                mfa_required=needs_mfa,
            )

    if notification is not None:
        _notify_safely(notification)
    return result


def get_session(token: str | None) -> AuthSession | None:
    if not token or len(token) > 256:
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).digest()
    with auth_engine.begin() as connection:
        row = (
            connection.execute(
                text(
                    "SELECT s.session_id, s.user_id, s.mfa_ok, u.role "
                    "FROM public.sessions AS s "
                    "JOIN public.users AS u USING (user_id) "
                    "WHERE s.token_hash = :token_hash AND s.revoked_at IS NULL "
                    "AND s.expires_at > now() "
                    "AND s.last_seen_at > now() - interval '30 minutes' "
                    "AND u.status = 'active'"
                ),
                {"token_hash": token_hash},
            )
            .mappings()
            .first()
        )
        if row is None:
            return None
        connection.execute(
            text(
                "UPDATE public.sessions SET last_seen_at = now() "
                "WHERE session_id = :session_id"
            ),
            {"session_id": row["session_id"]},
        )
        return AuthSession(
            session_id=row["session_id"],
            user_id=row["user_id"],
            role=row["role"],
            mfa_ok=row["mfa_ok"],
        )


def _totp_secret(user_id: UUID, dek_wrapped: bytes, encrypted: bytes) -> str:
    dek = crypto.unwrap_dek(bytes(dek_wrapped), user_id)
    return crypto.dec(
        dek, bytes(encrypted), "users", "totp_secret_enc", user_id
    ).decode("ascii")


def verify_login_totp(
    token: str | None,
    code: str,
    user_agent: str | None,
    ip_address: str = "unknown",
) -> AuthSession:
    """Complete a first-factor session with TOTP.

    Brute force is bounded three ways, all shared across workers: 5 failures
    revoke the pending session, 10 failures in 15 minutes lock the account
    (same lockout as passwords), and 20 failures per IP block that IP.
    """
    if not token or len(token) > 256:
        raise InvalidCredentials("Invalid MFA verification")
    ip_key = ratelimit.key_for("ip", ip_address or "unknown")
    if ratelimit.exceeded(ratelimit.MFA_FAIL_PER_IP, ip_key):
        raise RateLimited("mfa rate limit")
    token_hash = hashlib.sha256(token.encode("utf-8")).digest()
    notification: OutboundEmail | None = None
    session: AuthSession | None = None
    invalid_code = False
    with auth_engine.begin() as connection:
        row = (
            connection.execute(
                text(
                    "SELECT s.session_id, s.user_id, s.mfa_ok, s.new_browser, "
                    "u.role, u.status, u.email_enc, u.dek_wrapped, u.totp_secret_enc, "
                    "u.locked_until, now() AS db_now "
                    "FROM public.sessions AS s JOIN public.users AS u USING (user_id) "
                    "WHERE s.token_hash = :token_hash AND s.revoked_at IS NULL "
                    "AND s.expires_at > now() "
                    "AND s.last_seen_at > now() - interval '30 minutes' "
                    "FOR UPDATE OF s"
                ),
                {"token_hash": token_hash},
            )
            .mappings()
            .first()
        )
        if (
            row is None
            or row["status"] != "active"
            or row["mfa_ok"]
            or row["totp_secret_enc"] is None
            or (row["locked_until"] is not None and row["locked_until"] > row["db_now"])
        ):
            raise InvalidCredentials("Invalid MFA verification")
        secret = _totp_secret(
            row["user_id"], row["dek_wrapped"], row["totp_secret_enc"]
        )
        if not pyotp.TOTP(secret).verify(code, valid_window=1):
            _event(connection, "mfa_verify_fail", "fail", row["user_id"])
            invalid_code = True
            ratelimit.hit(ratelimit.MFA_FAIL_PER_IP, ip_key, connection)
            session_spent = ratelimit.record_failure(
                ratelimit.MFA_FAIL_PER_SESSION,
                ratelimit.key_for("session", token_hash),
                connection,
            )
            account_spent = ratelimit.record_failure(
                ratelimit.MFA_FAIL_PER_ACCOUNT,
                ratelimit.key_for("account", str(row["user_id"])),
                connection,
            )
            if session_spent:
                connection.execute(
                    text("UPDATE public.sessions SET revoked_at = now() WHERE session_id = :sid"),
                    {"sid": row["session_id"]},
                )
                _event(connection, "mfa_session_revoked", "limited", row["user_id"])
            if account_spent:
                connection.execute(
                    text(
                        "UPDATE public.users SET locked_until = now() + interval '15 minutes' "
                        "WHERE user_id = :user_id"
                    ),
                    {"user_id": row["user_id"]},
                )
                connection.execute(
                    text(
                        "UPDATE public.sessions SET revoked_at = now() "
                        "WHERE user_id = :user_id AND revoked_at IS NULL AND mfa_ok = false"
                    ),
                    {"user_id": row["user_id"]},
                )
                _event(connection, "mfa_lockout", "limited", row["user_id"])
                notification = notification_message(
                    kind="account_lockout",
                    recipient=_decrypt_user_email(row),
                    subject="Account temporarily locked",
                    browser_family=browser_family(user_agent),
                    now=row["db_now"],
                )
        else:
            connection.execute(
                text(
                    "UPDATE public.sessions SET mfa_ok = true, last_seen_at = now(), "
                    "new_browser = false WHERE session_id = :session_id"
                ),
                {"session_id": row["session_id"]},
            )
            ratelimit.clear(
                ratelimit.MFA_FAIL_PER_SESSION, ratelimit.key_for("session", token_hash), connection
            )
            _event(connection, "login_ok", "ok", row["user_id"])
            if row["new_browser"]:
                notification = notification_message(
                    kind="new_browser_login",
                    recipient=_decrypt_user_email(row),
                    subject="New sign-in",
                    browser_family=browser_family(user_agent),
                )
            session = AuthSession(
                session_id=row["session_id"],
                user_id=row["user_id"],
                role=row["role"],
                mfa_ok=True,
            )
    if notification is not None:
        _notify_safely(notification)
    if invalid_code:
        raise InvalidCredentials("Invalid MFA verification")
    assert session is not None
    return session


def begin_totp_enrollment(
    *,
    user_id: UUID,
    session_id: UUID,
    password: str,
    current_code: str | None = None,
) -> str:
    with auth_engine.begin() as connection:
        active_session = connection.execute(
            text(
                "SELECT 1 FROM public.sessions WHERE session_id = :session_id "
                "AND user_id = :user_id AND revoked_at IS NULL AND mfa_ok "
                "AND expires_at > now() "
                "AND last_seen_at > now() - interval '30 minutes' FOR UPDATE"
            ),
            {"session_id": session_id, "user_id": user_id},
        ).first()
        user = (
            connection.execute(
                text(
                    "SELECT user_id, email_enc, dek_wrapped, password_hash, "
                    "totp_secret_enc FROM public.users "
                    "WHERE user_id = :user_id AND status = 'active' FOR UPDATE"
                ),
                {"user_id": user_id},
            )
            .mappings()
            .first()
        )
        if active_session is None or user is None or _reauth_blocked(user_id):
            raise InvalidCredentials("Re-authentication failed")
        if not verify_password(password, user["password_hash"]):
            _record_reauth_failure(user_id)
            raise InvalidCredentials("Re-authentication failed")
        if user["totp_secret_enc"] is not None:
            if not current_code:
                raise InvalidCredentials("Current MFA code is required")
            current_secret = _totp_secret(
                user_id, user["dek_wrapped"], user["totp_secret_enc"]
            )
            if not pyotp.TOTP(current_secret).verify(current_code, valid_window=1):
                _record_reauth_failure(user_id)
                raise InvalidCredentials("Re-authentication failed")

        secret = pyotp.random_base32()
        dek = crypto.unwrap_dek(bytes(user["dek_wrapped"]), user_id)
        pending_ciphertext = crypto.enc(
            dek,
            secret.encode("ascii"),
            "users",
            "totp_pending_enc",
            user_id,
        )
        connection.execute(
            text(
                "UPDATE public.users SET totp_pending_enc = :pending "
                "WHERE user_id = :user_id"
            ),
            {"pending": pending_ciphertext, "user_id": user_id},
        )
        email = _decrypt_user_email(user)
        append_event(
            connection,
            action="mfa_enrollment_started",
            result="pending",
            actor_user_id=user_id,
            target_id=user_id,
        )
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="PFA")


def confirm_totp_enrollment(
    *, user_id: UUID, session_id: UUID, code: str, user_agent: str | None
) -> None:
    notification: OutboundEmail | None = None
    with auth_engine.begin() as connection:
        active_session = connection.execute(
            text(
                "SELECT 1 FROM public.sessions WHERE session_id = :session_id "
                "AND user_id = :user_id AND revoked_at IS NULL AND mfa_ok "
                "AND expires_at > now() "
                "AND last_seen_at > now() - interval '30 minutes' FOR UPDATE"
            ),
            {"session_id": session_id, "user_id": user_id},
        ).first()
        user = (
            connection.execute(
                text(
                    "SELECT user_id, email_enc, dek_wrapped, totp_pending_enc "
                    "FROM public.users WHERE user_id = :user_id AND status = 'active' "
                    "FOR UPDATE"
                ),
                {"user_id": user_id},
            )
            .mappings()
            .first()
        )
        if active_session is None or user is None or user["totp_pending_enc"] is None:
            raise InvalidCredentials("MFA enrollment is not pending")
        dek = crypto.unwrap_dek(bytes(user["dek_wrapped"]), user_id)
        pending_secret = crypto.dec(
            dek,
            bytes(user["totp_pending_enc"]),
            "users",
            "totp_pending_enc",
            user_id,
        ).decode("ascii")
        if not pyotp.TOTP(pending_secret).verify(code, valid_window=1):
            raise InvalidCredentials("Invalid MFA code")
        active_ciphertext = crypto.enc(
            dek,
            pending_secret.encode("ascii"),
            "users",
            "totp_secret_enc",
            user_id,
        )
        connection.execute(
            text(
                "UPDATE public.users SET totp_secret_enc = :active, "
                "totp_pending_enc = NULL WHERE user_id = :user_id"
            ),
            {"active": active_ciphertext, "user_id": user_id},
        )
        connection.execute(
            text(
                "UPDATE public.sessions SET mfa_ok = true, last_seen_at = now() "
                "WHERE session_id = :session_id AND user_id = :user_id "
                "AND revoked_at IS NULL"
            ),
            {"session_id": session_id, "user_id": user_id},
        )
        _event(connection, "mfa_enabled", "ok", user_id)
        notification = notification_message(
            kind="mfa_enabled",
            recipient=_decrypt_user_email(user),
            subject="Multi-factor authentication enabled",
            browser_family=browser_family(user_agent),
        )
    _notify_safely(notification)


def change_password(
    *,
    user_id: UUID,
    current_password: str,
    new_password: str,
    current_code: str | None,
    user_agent: str | None,
) -> None:
    if _reauth_blocked(user_id):
        raise InvalidCredentials("Re-authentication failed")
    with auth_engine.begin() as connection:
        user = (
            connection.execute(
                text(
                    "SELECT user_id, email_enc, dek_wrapped, password_hash, "
                    "totp_secret_enc FROM public.users "
                    "WHERE user_id = :user_id AND status = 'active' FOR UPDATE"
                ),
                {"user_id": user_id},
            )
            .mappings()
            .first()
        )
        if user is None:
            raise InvalidCredentials("Re-authentication failed")
        ok = verify_password(current_password, user["password_hash"])
        if ok and user["totp_secret_enc"] is not None:
            ok = bool(current_code) and pyotp.TOTP(
                _totp_secret(user_id, user["dek_wrapped"], user["totp_secret_enc"])
            ).verify(current_code, valid_window=1)
        if not ok:
            _record_reauth_failure(user_id)
            raise InvalidCredentials("Re-authentication failed")
        new_hash = hash_password(new_password)
        connection.execute(
            text(
                "UPDATE public.users SET password_hash = :password_hash, "
                "password_reset_token_hash = NULL, password_reset_expires_at = NULL "
                "WHERE user_id = :user_id"
            ),
            {"password_hash": new_hash, "user_id": user_id},
        )
        connection.execute(
            text(
                "UPDATE public.sessions SET revoked_at = now() "
                "WHERE user_id = :user_id AND revoked_at IS NULL"
            ),
            {"user_id": user_id},
        )
        _event(connection, "password_changed", "ok", user_id)
        notification = notification_message(
            kind="password_changed",
            recipient=_decrypt_user_email(user),
            subject="Password changed",
            browser_family=browser_family(user_agent),
        )
    _notify_safely(notification)


def _reauth_key(user_id: UUID) -> bytes:
    return ratelimit.key_for("reauth", str(user_id))


def _reauth_blocked(user_id: UUID) -> bool:
    return ratelimit.exceeded(ratelimit.REAUTH_FAIL_PER_ACCOUNT, _reauth_key(user_id))


def _record_reauth_failure(user_id: UUID) -> None:
    """Count a failed re-authentication on its own connection (survives rollback).

    Callers hold the user/session rows FOR UPDATE, so nothing here touches them;
    once the limit is reached every further re-authentication is refused.
    """
    if ratelimit.record_failure(ratelimit.REAUTH_FAIL_PER_ACCOUNT, _reauth_key(user_id)):
        with auth_engine.begin() as own:
            append_event(
                own, action="reauth_rate_limited", result="limited",
                actor_user_id=user_id, target_id=user_id,
            )


def _reauthenticated_user(
    connection,
    *,
    user_id: UUID,
    session_id: UUID,
    current_password: str,
    current_code: str | None,
):
    session = connection.execute(
        text(
            "SELECT 1 FROM public.sessions WHERE session_id = :session_id "
            "AND user_id = :user_id AND revoked_at IS NULL AND mfa_ok "
            "AND expires_at > now() "
            "AND last_seen_at > now() - interval '30 minutes' FOR UPDATE"
        ),
        {"session_id": session_id, "user_id": user_id},
    ).first()
    user = (
        connection.execute(
            text(
                "SELECT user_id, email_enc, dek_wrapped, password_hash, role, "
                "created_at, privacy_consent_at, ai_consent_at, totp_secret_enc "
                "FROM public.users "
                "WHERE user_id = :user_id AND status = 'active' FOR UPDATE"
            ),
            {"user_id": user_id},
        )
        .mappings()
        .first()
    )
    if session is None or user is None or _reauth_blocked(user_id):
        return None
    ok = verify_password(current_password, user["password_hash"])
    if ok and user["totp_secret_enc"] is not None:
        ok = bool(current_code) and pyotp.TOTP(
            _totp_secret(user_id, user["dek_wrapped"], user["totp_secret_enc"])
        ).verify(current_code, valid_window=1)
    if not ok:
        _record_reauth_failure(user_id)
        return None
    return user


def reauthenticate_account_export(
    *, user_id: UUID, session_id: UUID, current_password: str, current_code: str | None
) -> dict:
    """Require current credentials before returning the user's export profile."""
    with auth_engine.begin() as connection:
        user = _reauthenticated_user(
            connection,
            user_id=user_id,
            session_id=session_id,
            current_password=current_password,
            current_code=current_code,
        )
        if user is None:
            _event(connection, "account_export", "reauth_failed", user_id)
        else:
            _event(connection, "account_export", "success", user_id)
            profile = {
                "user_id": str(user_id),
                "email": _decrypt_user_email(user),
                "role": user["role"],
                "created_at": user["created_at"],
                "privacy_consent_at": user["privacy_consent_at"],
                "ai_consent": user["ai_consent_at"] is not None,
                "mfa_enabled": user["totp_secret_enc"] is not None,
            }
    if user is None:
        raise InvalidCredentials("Re-authentication failed")
    return profile


def delete_account(
    *,
    user_id: UUID,
    session_id: UUID,
    current_password: str,
    current_code: str | None,
) -> None:
    """Tombstone the account, destroy its wrapped data key, and revoke its sessions."""
    with auth_engine.begin() as connection:
        user = _reauthenticated_user(
            connection,
            user_id=user_id,
            session_id=session_id,
            current_password=current_password,
            current_code=current_code,
        )
        if user is None:
            _event(connection, "account_delete", "reauth_failed", user_id)
        else:
            connection.execute(
                text(
                    "UPDATE public.sessions SET revoked_at = coalesce(revoked_at, now()) "
                    "WHERE user_id = :user_id"
                ),
                {"user_id": user_id},
            )
            connection.execute(
                text(
                    "UPDATE public.users SET status = 'deleted', "
                    "deleted_at = coalesce(deleted_at, now()), "
                    "email_hmac = public.gen_random_bytes(32), "
                    "email_enc = public.gen_random_bytes(64), "
                    "password_hash = 'deleted:' || encode(public.gen_random_bytes(32), 'hex'), "
                    "dek_wrapped = public.gen_random_bytes(60), base_currency = 'XXX', "
                    "ai_consent_at = NULL, totp_secret_enc = NULL, totp_pending_enc = NULL, "
                    "password_reset_token_hash = NULL, password_reset_expires_at = NULL, "
                    "reset_request_count = 0, reset_window_started_at = NULL "
                    "WHERE user_id = :user_id"
                ),
                {"user_id": user_id},
            )
            _event(connection, "account_delete", "success", user_id)
    if user is None:
        raise InvalidCredentials("Re-authentication failed")


def _reset_link(base_url: str, token: str) -> str:
    return f"{base_url}/reset-password#token={quote(token, safe='')}"


def request_password_reset(
    *,
    email: str,
    ip_address: str,
    user_agent: str | None,
    settings: Settings | None = None,
) -> None:
    configured = settings or get_settings()
    base_url = configured.public_app_base_url
    ip_allowed = ratelimit.hit(
        ratelimit.RESET_PER_IP, ratelimit.key_for("ip", ip_address or "unknown")
    )
    normalized_email = crypto.norm_email(email)
    email_digest = crypto.hmac_email(normalized_email)
    notification: OutboundEmail | None = None
    with auth_engine.begin() as connection:
        now = connection.execute(text("SELECT now()")).scalar_one()
        user = (
            connection.execute(
                text(
                    "SELECT user_id, email_enc, dek_wrapped, reset_window_started_at, "
                    "reset_request_count FROM public.users "
                    "WHERE email_hmac = :email_hmac AND status <> 'deleted' FOR UPDATE"
                ),
                {"email_hmac": email_digest},
            )
            .mappings()
            .first()
        )
        if user is not None:
            window_started = user["reset_window_started_at"]
            if window_started is None or window_started < now - RESET_WINDOW:
                request_count = 0
                window_started = now
            else:
                request_count = user["reset_request_count"]
            if ip_allowed and request_count < RESET_PER_ACCOUNT_LIMIT:
                token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(token.encode("ascii")).digest()
                expires_at = now + RESET_TOKEN_LIFETIME
                connection.execute(
                    text(
                        "UPDATE public.users SET reset_window_started_at = :window_started, "
                        "reset_request_count = :request_count, "
                        "password_reset_token_hash = :token_hash, "
                        "password_reset_expires_at = :expires_at "
                        "WHERE user_id = :user_id"
                    ),
                    {
                        "window_started": window_started,
                        "request_count": request_count + 1,
                        "token_hash": token_hash,
                        "expires_at": expires_at,
                        "user_id": user["user_id"],
                    },
                )
                append_event(
                    connection,
                    action="password_reset_requested",
                    result="ok",
                    actor_user_id=user["user_id"],
                    target_id=user["user_id"],
                )
                reset_link = _reset_link(base_url, token)
                family = browser_family(user_agent)
                timestamp = now.astimezone(timezone.utc).isoformat()
                notification = OutboundEmail(
                    kind="password_reset",
                    recipient=_decrypt_user_email(user),
                    subject="Password reset",
                    body=(
                        f"UTC: {timestamp}\n"
                        f"Browser: {family}\n"
                        f"Reset: {reset_link}"
                    ),
                    expires_at=expires_at,
                )
            else:
                append_event(
                    connection,
                    action="password_reset_requested",
                    result="limited",
                    actor_user_id=user["user_id"],
                    target_id=user["user_id"],
                )
        else:
            append_event(
                connection,
                action="password_reset_requested",
                result="not_found",
                actor_user_id=None,
                target_id=None,
            )
    if notification is not None:
        _notify_safely(notification)


def complete_password_reset(
    *, token: str, new_password: str, user_agent: str | None
) -> bool:
    if not token or len(token) > 256:
        return False
    new_hash = hash_password(new_password)
    token_hash = hashlib.sha256(token.encode("utf-8")).digest()
    notification: OutboundEmail | None = None
    with auth_engine.begin() as connection:
        user = (
            connection.execute(
                text(
                    "UPDATE public.users SET password_hash = :password_hash, "
                    "password_reset_token_hash = NULL, password_reset_expires_at = NULL, "
                    "failed_login_count = 0, last_failed_at = NULL, locked_until = NULL "
                    "WHERE password_reset_token_hash = :token_hash "
                    "AND password_reset_expires_at > now() AND status <> 'deleted' "
                    "RETURNING user_id, email_enc, dek_wrapped"
                ),
                {"password_hash": new_hash, "token_hash": token_hash},
            )
            .mappings()
            .first()
        )
        if user is None:
            _event(connection, "password_reset_failed", "fail", None)
            return False
        connection.execute(
            text(
                "UPDATE public.sessions SET revoked_at = now() "
                "WHERE user_id = :user_id AND revoked_at IS NULL"
            ),
            {"user_id": user["user_id"]},
        )
        _event(connection, "password_reset_completed", "ok", user["user_id"])
        notification = notification_message(
            kind="password_changed",
            recipient=_decrypt_user_email(user),
            subject="Password changed",
            browser_family=browser_family(user_agent),
        )
    _notify_safely(notification)
    return True


def logout(token: str | None) -> None:
    if not token or len(token) > 256:
        return
    token_hash = hashlib.sha256(token.encode("utf-8")).digest()
    with auth_engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE public.sessions SET revoked_at = now() "
                "WHERE token_hash = :token_hash AND revoked_at IS NULL"
            ),
            {"token_hash": token_hash},
        )


def revoke_current_session(session_id: UUID, user_id: UUID) -> None:
    with auth_engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE public.sessions SET revoked_at = now() "
                "WHERE session_id = :session_id AND user_id = :user_id "
                "AND revoked_at IS NULL"
            ),
            {"session_id": session_id, "user_id": user_id},
        )


def list_sessions(user_id: UUID, current_session_id: UUID) -> list[dict]:
    """Return safe session metadata for the authenticated user only."""
    with auth_engine.begin() as connection:
        rows = connection.execute(
            text(
                "SELECT session_id, issued_at, last_seen_at, expires_at, "
                "revoked_at, mfa_ok FROM public.sessions "
                "WHERE user_id = :user_id AND revoked_at IS NULL "
                "ORDER BY issued_at DESC LIMIT 50"
            ),
            {"user_id": user_id},
        ).mappings()
        return [
            {
                "session_id": str(row["session_id"]),
                "is_current": row["session_id"] == current_session_id,
                "issued_at": row["issued_at"],
                "last_seen_at": row["last_seen_at"],
                "expires_at": row["expires_at"],
                "revoked_at": row["revoked_at"],
                "mfa_ok": bool(row["mfa_ok"]),
            }
            for row in rows
        ]


def revoke_user_session(session_id: UUID, user_id: UUID) -> bool:
    """Revoke one session owned by the caller and audit the action."""
    with auth_engine.begin() as connection:
        revoked = connection.execute(
            text(
                "UPDATE public.sessions SET revoked_at = now() "
                "WHERE session_id = :session_id AND user_id = :user_id "
                "AND revoked_at IS NULL RETURNING session_id"
            ),
            {"session_id": session_id, "user_id": user_id},
        ).first()
        if revoked is None:
            return False
        _event(connection, "session_revoke", "success", user_id)
        return True


def security_status(user_id: UUID) -> dict:
    """Expose only the caller's MFA and AI-consent booleans."""
    with auth_engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT totp_secret_enc IS NOT NULL AS mfa_enabled, "
                "ai_consent_at IS NOT NULL AS ai_consent "
                "FROM public.users WHERE user_id = :user_id AND status = 'active'"
            ),
            {"user_id": user_id},
        ).mappings().first()
    if row is None:
        raise InvalidCredentials("account unavailable")
    return {"mfa_enabled": bool(row["mfa_enabled"]), "ai_consent": bool(row["ai_consent"])}


def set_ai_consent(user_id: UUID, enabled: bool) -> None:
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be a boolean")
    with auth_engine.begin() as connection:
        updated = connection.execute(
            text(
                "UPDATE public.users SET ai_consent_at = "
                "CASE WHEN :enabled THEN now() ELSE NULL END "
                "WHERE user_id = :user_id AND status = 'active' "
                "RETURNING user_id"
            ),
            {"enabled": enabled, "user_id": user_id},
        ).first()
        if updated is None:
            raise InvalidCredentials("account unavailable")
        _event(
            connection,
            "ai_consent_change",
            "enabled" if enabled else "revoked",
            user_id,
        )


def disable_totp(
    *, user_id: UUID, session_id: UUID, current_password: str, current_code: str | None
) -> None:
    """Let a regular user turn MFA off after password + current-code re-authentication.

    Staff roles cannot disable MFA because it is mandatory for them.
    """
    notification: OutboundEmail | None = None
    with auth_engine.begin() as connection:
        user = _reauthenticated_user(
            connection,
            user_id=user_id,
            session_id=session_id,
            current_password=current_password,
            current_code=current_code,
        )
        if user is None or user["totp_secret_enc"] is None:
            raise InvalidCredentials("Invalid re-authentication")
        if user["role"] != "user":
            raise PermissionError("MFA is mandatory for staff roles")
        connection.execute(
            text("UPDATE public.users SET totp_secret_enc = NULL WHERE user_id = :user_id"),
            {"user_id": user_id},
        )
        connection.execute(
            text(
                "UPDATE public.sessions SET revoked_at = now() WHERE user_id = :user_id "
                "AND revoked_at IS NULL AND session_id <> :session_id"
            ),
            {"user_id": user_id, "session_id": session_id},
        )
        _event(connection, "mfa_disabled", "ok", user_id)
        notification = notification_message(
            kind="mfa_disabled",
            recipient=_decrypt_user_email(user),
            subject="Two-step verification turned off",
            browser_family="Unknown",
        )
    _notify_safely(notification)


# ---------------------------------------------------------------------------
# Security-owner account administration (no financial data is ever touched).
# ---------------------------------------------------------------------------

STAFF_ROLES = frozenset({"security_owner", "admin"})
ALL_ROLES = frozenset({"user", "security_owner", "admin"})


def _mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"{local[:1]}***@{domain}" if domain else "***"


def list_accounts_for_staff(limit: int = 100) -> list[dict]:
    """Account status only: role, state, MFA flag, masked email. No financial data."""
    with auth_engine.begin() as connection:
        rows = connection.execute(
            text(
                "SELECT user_id, email_enc, dek_wrapped, role, status, created_at, "
                "locked_until > now() AS temporarily_locked, "
                "totp_secret_enc IS NOT NULL AS mfa_enabled "
                "FROM public.users WHERE status <> 'deleted' "
                "ORDER BY created_at DESC LIMIT :limit"
            ),
            {"limit": limit},
        ).mappings().all()
    return [
        {
            "user_id": str(row["user_id"]),
            "email_masked": _mask_email(_decrypt_user_email(row)),
            "role": row["role"],
            "status": row["status"],
            "temporarily_locked": bool(row["temporarily_locked"]),
            "mfa_enabled": bool(row["mfa_enabled"]),
            "created_at": row["created_at"].isoformat(),
        }
        for row in rows
    ]


def _staff_target(connection, actor_user_id: UUID, target_user_id: UUID):
    if actor_user_id == target_user_id:
        raise PermissionError("Staff cannot administer their own account")
    target = (
        connection.execute(
            text(
                "SELECT user_id, email_enc, dek_wrapped, role, status, totp_secret_enc "
                "FROM public.users WHERE user_id = :user_id AND status <> 'deleted' FOR UPDATE"
            ),
            {"user_id": target_user_id},
        )
        .mappings()
        .first()
    )
    if target is None:
        raise LookupError("account not found")
    return target


def _revoke_all(connection, user_id: UUID) -> None:
    connection.execute(
        text(
            "UPDATE public.sessions SET revoked_at = now() "
            "WHERE user_id = :user_id AND revoked_at IS NULL"
        ),
        {"user_id": user_id},
    )


def set_account_lock(*, actor_user_id: UUID, target_user_id: UUID, locked: bool) -> None:
    """security_owner: lock (revoking every session) or unlock an account."""
    with auth_engine.begin() as connection:
        target = _staff_target(connection, actor_user_id, target_user_id)
        if locked:
            connection.execute(
                text("UPDATE public.users SET status = 'locked' WHERE user_id = :user_id"),
                {"user_id": target["user_id"]},
            )
            _revoke_all(connection, target["user_id"])
        else:
            connection.execute(
                text(
                    "UPDATE public.users SET status = 'active', failed_login_count = 0, "
                    "last_failed_at = NULL, locked_until = NULL WHERE user_id = :user_id"
                ),
                {"user_id": target["user_id"]},
            )
        append_event(
            connection,
            action="account_locked" if locked else "account_unlocked",
            result="ok",
            actor_user_id=actor_user_id,
            target_id=target["user_id"],
        )


def force_password_reset(*, actor_user_id: UUID, target_user_id: UUID) -> None:
    """security_owner: invalidate the password and every session; the user must
    complete the normal emailed reset. Staff never see or set the new password."""
    with auth_engine.begin() as connection:
        target = _staff_target(connection, actor_user_id, target_user_id)
        unusable = PASSWORD_HASHER.hash(secrets.token_hex(32))
        connection.execute(
            text("UPDATE public.users SET password_hash = :hash WHERE user_id = :user_id"),
            {"hash": unusable, "user_id": target["user_id"]},
        )
        _revoke_all(connection, target["user_id"])
        append_event(
            connection,
            action="password_reset_forced",
            result="ok",
            actor_user_id=actor_user_id,
            target_id=target["user_id"],
        )
        notification = notification_message(
            kind="password_changed",
            recipient=_decrypt_user_email(target),
            subject="Password reset required",
            browser_family="Unknown",
        )
    _notify_safely(notification)


def change_role(
    *,
    actor_user_id: UUID,
    actor_session_id: UUID,
    target_user_id: UUID,
    new_role: str,
    current_password: str,
    current_code: str | None,
) -> None:
    """security_owner: change a role after the actor re-authenticates (password + TOTP).

    Promotion to a staff role requires the target to have MFA enrolled, since
    staff cannot sign in without it. The target's sessions are revoked.
    """
    if new_role not in ALL_ROLES:
        raise ValueError("unknown role")
    with auth_engine.begin() as connection:
        actor = _reauthenticated_user(
            connection,
            user_id=actor_user_id,
            session_id=actor_session_id,
            current_password=current_password,
            current_code=current_code,
        )
        if actor is None or actor["role"] != "security_owner":
            raise InvalidCredentials("Invalid re-authentication")
        target = _staff_target(connection, actor_user_id, target_user_id)
        if new_role in STAFF_ROLES and target["totp_secret_enc"] is None:
            raise ValueError("Target must enrol MFA before receiving a staff role")
        connection.execute(
            text("UPDATE public.users SET role = :role WHERE user_id = :user_id"),
            {"role": new_role, "user_id": target["user_id"]},
        )
        _revoke_all(connection, target["user_id"])
        append_event(
            connection,
            action=f"role_changed_to_{new_role}",
            result="ok",
            actor_user_id=actor_user_id,
            target_id=target["user_id"],
        )
