"""Authentication, session and password-reset tests on the real role-scoped PostgreSQL."""

from dataclasses import dataclass
import hashlib
import logging
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app import crypto
from app.db import audit_engine, auth_engine
from app.email import consume_dev_outbox
from app.main import create_app

CSRF = {"X-Requested-With": "pfa"}
TEST_APP_URL = "https://pfa.example.invalid"


@dataclass(frozen=True)
class AuthTestUser:
    user_id: UUID
    email: str
    password: str


def strong_password() -> str:
    return f"Amber!Quartz-{uuid4().hex}-Compass9"


@pytest.fixture
def auth_client(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("EMAIL_MODE", "dev_outbox")
    monkeypatch.setenv("PUBLIC_APP_URL", TEST_APP_URL)
    address = f"2001:db8::{uuid4().int & ((1 << 64) - 1):x}"
    with TestClient(create_app(), client=(address, 54321)) as client:
        yield client


@pytest.fixture
def user_factory(auth_client):
    users: list[AuthTestUser] = []

    def create() -> AuthTestUser:
        user = AuthTestUser(
            user_id=uuid4(),
            email=f"auth-{uuid4()}@example.invalid",
            password=strong_password(),
        )
        response = auth_client.post(
            "/auth/register",
            headers=CSRF,
            json={
                "email": user.email,
                "password": user.password,
                "base_currency": "PKR",
                "privacy_consent": True,
                "ai_consent": False,
            },
        )
        assert response.status_code == 202
        with auth_engine.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT user_id FROM public.users WHERE email_hmac = :email_hmac"
                ),
                {"email_hmac": crypto.hmac_email(user.email)},
            ).one()
        user = AuthTestUser(row.user_id, user.email, user.password)
        users.append(user)
        return user

    yield create

    with auth_engine.begin() as connection:
        for user in users:
            connection.execute(
                text(
                    "UPDATE public.sessions SET revoked_at = coalesce(revoked_at, now()) "
                    "WHERE user_id = :user_id"
                ),
                {"user_id": user.user_id},
            )
            connection.execute(
                text(
                    "UPDATE public.users SET status = 'deleted', "
                    "deleted_at = coalesce(deleted_at, now()), "
                    "password_reset_token_hash = NULL, password_reset_expires_at = NULL, "
                    "totp_pending_enc = NULL, totp_secret_enc = NULL "
                    "WHERE user_id = :user_id"
                ),
                {"user_id": user.user_id},
            )


def login(client: TestClient, user: AuthTestUser, user_agent: str = "Chrome/132.0"):
    return client.post(
        "/auth/login",
        headers={**CSRF, "User-Agent": user_agent},
        json={"email": user.email, "password": user.password},
    )


def _latest_reset_message():
    with auth_engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT message_id, body_enc, recipient_enc, subject_enc "
                "FROM public.dev_outbox "
                "WHERE email_kind = 'password_reset' "
                "ORDER BY created_at DESC, message_id DESC LIMIT 1"
            )
        ).one()
    message = consume_dev_outbox(row.message_id)[0]
    ciphertext = tuple(
        bytes(value) for value in (row.body_enc, row.recipient_enc, row.subject_enc)
    )
    return message, ciphertext


class _FakeResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code


def _capture_http_email(monkeypatch, *, status: int = 202, raise_with: str | None = None):
    import httpx

    sent: list[dict] = []

    def post(url, *, headers, json, timeout):
        sent.append({"url": url, "headers": headers, "json": json, "timeout": timeout})
        if raise_with is not None:
            raise httpx.ConnectError(raise_with)
        return _FakeResponse(status)

    monkeypatch.setattr("app.email.httpx.post", post)
    return sent


def _assert_reset_flow(auth_client, user, sent, body_of, recipients_of):
    known = auth_client.post(
        "/auth/password/reset",
        headers={**CSRF, "Host": "attacker.invalid"},
        json={"email": user.email.upper()},
    )
    unknown = auth_client.post(
        "/auth/password/reset",
        headers=CSRF,
        json={"email": f"unknown-{uuid4()}@example.invalid"},
    )
    assert known.status_code == unknown.status_code == 202
    assert known.content == unknown.content
    assert len(sent) == 1
    assert recipients_of(sent[0]["json"]) == [user.email]
    lines = body_of(sent[0]["json"]).splitlines()
    assert len(lines) == 3
    assert lines[0].startswith("UTC: ")
    assert lines[1].startswith("Browser: ")
    parsed = urlsplit(lines[2].removeprefix("Reset: "))
    # The link uses the configured origin, never the request's Host header.
    assert parsed.netloc == urlsplit(TEST_APP_URL).netloc
    assert parsed.path == "/reset-password"
    token = parse_qs(parsed.fragment)["token"][0]
    with auth_engine.connect() as connection:
        stored_hash = connection.execute(
            text("SELECT password_reset_token_hash FROM public.users WHERE user_id = :id"),
            {"id": user.user_id},
        ).scalar_one()
    assert bytes(stored_hash) == hashlib.sha256(token.encode()).digest()
    rejected = auth_client.post(
        "/auth/password/reset",
        headers=CSRF,
        json={"email": user.email, "recipient": "other@example.invalid"},
    )
    assert rejected.status_code == 422
    assert len(sent) == 1


def test_T47_resend_reset_uses_stored_registration_email_and_generic_response(
    auth_client, user_factory, monkeypatch
):
    user = user_factory()
    monkeypatch.setenv("EMAIL_MODE", "resend")
    monkeypatch.setenv("RESEND_FROM", "security@example.invalid")
    monkeypatch.setenv("RESEND_API_KEY", "re_canary_key")
    sent = _capture_http_email(monkeypatch)
    _assert_reset_flow(
        auth_client, user, sent,
        body_of=lambda payload: payload["text"],
        recipients_of=lambda payload: payload["to"],
    )
    assert sent[0]["url"] == "https://api.resend.com/emails"
    assert sent[0]["json"]["from"] == "security@example.invalid"


def test_T50_brevo_reset_uses_registered_email_and_configured_origin(
    auth_client, user_factory, monkeypatch
):
    user = user_factory()
    monkeypatch.setenv("EMAIL_MODE", "brevo")
    monkeypatch.setenv("BREVO_FROM", "sender@example.invalid")
    monkeypatch.setenv("BREVO_API_KEY", "xkeysib-canary")
    sent = _capture_http_email(monkeypatch, status=201)
    _assert_reset_flow(
        auth_client, user, sent,
        body_of=lambda payload: payload["textContent"],
        recipients_of=lambda payload: [entry["email"] for entry in payload["to"]],
    )
    assert sent[0]["url"] == "https://api.brevo.com/v3/smtp/email"
    assert sent[0]["json"]["sender"]["email"] == "sender@example.invalid"


def test_T48_resend_failure_stays_generic_without_logging_sensitive_data(
    auth_client, user_factory, monkeypatch, caplog
):
    user = user_factory()
    monkeypatch.setenv("EMAIL_MODE", "resend")
    monkeypatch.setenv("RESEND_FROM", "security@example.invalid")
    monkeypatch.setenv("RESEND_API_KEY", "re_canary_key")
    caplog.set_level(logging.INFO)
    sent = _capture_http_email(monkeypatch, raise_with="canary-upstream-credential")
    known = auth_client.post("/auth/password/reset", headers=CSRF, json={"email": user.email})
    unknown = auth_client.post(
        "/auth/password/reset",
        headers=CSRF,
        json={"email": f"unknown-{uuid4()}@example.invalid"},
    )
    assert known.status_code == unknown.status_code == 202
    assert known.content == unknown.content
    assert len(sent) == 1
    token = parse_qs(
        urlsplit(sent[0]["json"]["text"].splitlines()[2].removeprefix("Reset: ")).fragment
    )["token"][0]
    assert "email_provider_failed kind=password_reset" in caplog.text
    for canary in (user.email, token, user.password, "canary-upstream-credential", "re_canary_key"):
        assert canary not in caplog.text


def _token_from_reset_message(message) -> str:
    reset_line = next(line for line in message.body.splitlines() if line.startswith("Reset: "))
    reset_url = reset_line.removeprefix("Reset: ")
    parsed = urlsplit(reset_url)
    return parse_qs(parsed.fragment)["token"][0]


def test_T07_client_identity_does_not_select_the_revoked_session(auth_client, user_factory):
    user_a = user_factory()
    user_b = user_factory()

    response_a = login(auth_client, user_a)
    assert response_a.status_code == 200
    token_a = auth_client.cookies.get("sid")

    response_b = login(auth_client, user_b)
    assert response_b.status_code == 200
    token_b = auth_client.cookies.get("sid")

    auth_client.cookies.set("sid", token_a)
    response = auth_client.post(
        "/auth/sessions/revoke-current",
        headers=CSRF,
        json={"user_id": str(user_b.user_id)},
    )
    assert response.status_code == 204

    hashes = [
        hashlib.sha256(token.encode("utf-8")).digest() for token in (token_a, token_b)
    ]
    with auth_engine.connect() as connection:
        revoked_a = connection.execute(
            text(
                "SELECT revoked_at IS NOT NULL FROM public.sessions "
                "WHERE token_hash = :token_hash"
            ),
            {"token_hash": hashes[0]},
        ).scalar_one()
        revoked_b = connection.execute(
            text(
                "SELECT revoked_at IS NOT NULL FROM public.sessions "
                "WHERE token_hash = :token_hash"
            ),
            {"token_hash": hashes[1]},
        ).scalar_one()
    assert revoked_a is True
    assert revoked_b is False


def test_T09_password_storage_is_argon2id_and_not_plaintext(auth_client, user_factory):
    user = user_factory()
    with auth_engine.connect() as connection:
        stored_hash = connection.execute(
            text("SELECT password_hash FROM public.users WHERE user_id = :user_id"),
            {"user_id": user.user_id},
        ).scalar_one()
    assert stored_hash.startswith("$argon2id$")
    assert user.password not in stored_hash
    assert crypto.norm_email(user.email) not in stored_hash


def test_T12_six_failures_lock_for_fifteen_minutes_and_audit(auth_client, user_factory):
    user = user_factory()
    with audit_engine.connect() as connection:
        before_id = connection.execute(
            text("SELECT coalesce(max(id), 0) FROM public.audit_log")
        ).scalar_one()
    with auth_engine.connect() as connection:
        lockout_emails_before = connection.execute(
            text(
                "SELECT count(*) FROM public.dev_outbox "
                "WHERE email_kind = 'account_lockout' AND expires_at > now()"
            )
        ).scalar_one()
    for _ in range(6):
        response = auth_client.post(
            "/auth/login",
            headers=CSRF,
            json={"email": user.email, "password": "incorrect synthetic password"},
        )
        assert response.status_code == 401

    with auth_engine.connect() as connection:
        count, lock_active, lock_not_too_long = connection.execute(
            text(
                "SELECT failed_login_count, locked_until > now(), "
                "locked_until <= now() + interval '15 minutes' + interval '2 seconds' "
                "FROM public.users WHERE user_id = :user_id"
            ),
            {"user_id": user.user_id},
        ).one()
    assert count == 5
    assert lock_active is True
    assert lock_not_too_long is True
    with audit_engine.connect() as connection:
        failed_events = connection.execute(
            text(
                "SELECT count(*) FROM public.audit_log WHERE id > :before_id "
                "AND target_id = :user_id AND action = 'login_fail'"
            ),
            {"before_id": before_id, "user_id": user.user_id},
        ).scalar_one()
    assert failed_events == 6
    with auth_engine.connect() as connection:
        lockout_emails_after = connection.execute(
            text(
                "SELECT count(*) FROM public.dev_outbox "
                "WHERE email_kind = 'account_lockout' AND expires_at > now()"
            )
        ).scalar_one()
    assert lockout_emails_after - lockout_emails_before == 1


def test_T13_totp_must_be_confirmed_and_is_required_at_staff_login(
    auth_client, user_factory
):
    user = user_factory()
    assert login(auth_client, user).status_code == 200

    enrollment = auth_client.post(
        "/auth/mfa/enroll",
        headers=CSRF,
        json={"current_password": user.password},
    )
    assert enrollment.status_code == 200
    totp = pyotp.parse_uri(enrollment.json()["provisioning_uri"])
    with auth_engine.connect() as connection:
        before_confirmation = connection.execute(
            text(
                "SELECT totp_secret_enc IS NULL, totp_pending_enc IS NOT NULL "
                "FROM public.users WHERE user_id = :user_id"
            ),
            {"user_id": user.user_id},
        ).one()
    assert before_confirmation == (True, True)

    active_code = totp.now()
    invalid_code = f"{(int(active_code) + 123457) % 1_000_000:06d}"
    if totp.verify(invalid_code, valid_window=1):
        invalid_code = f"{(int(active_code) + 765431) % 1_000_000:06d}"
    rejected = auth_client.post(
        "/auth/mfa/confirm", headers=CSRF, json={"code": invalid_code}
    )
    assert rejected.status_code == 401
    with auth_engine.connect() as connection:
        still_pending = connection.execute(
            text(
                "SELECT totp_secret_enc IS NULL FROM public.users "
                "WHERE user_id = :user_id"
            ),
            {"user_id": user.user_id},
        ).scalar_one()
    assert still_pending is True

    confirmed = auth_client.post(
        "/auth/mfa/confirm", headers=CSRF, json={"code": totp.now()}
    )
    assert confirmed.status_code == 204
    with auth_engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT dek_wrapped, totp_secret_enc, totp_pending_enc "
                "FROM public.users WHERE user_id = :user_id"
            ),
            {"user_id": user.user_id},
        ).one()
    dek = crypto.unwrap_dek(bytes(row.dek_wrapped), user.user_id)
    stored_secret = crypto.dec(
        dek,
        bytes(row.totp_secret_enc),
        "users",
        "totp_secret_enc",
        user.user_id,
    ).decode("ascii")
    assert stored_secret == totp.secret
    assert row.totp_pending_enc is None

    assert auth_client.post("/auth/logout", headers=CSRF, json={}).status_code == 204
    first_factor = login(auth_client, user)
    assert first_factor.status_code == 200
    assert first_factor.json() == {"mfa_required": True}
    assert auth_client.get("/auth/me").status_code == 401
    verification = auth_client.post(
        "/auth/mfa/verify",
        headers=CSRF,
        json={"code": pyotp.TOTP(stored_secret).now()},
    )
    assert verification.status_code == 200
    assert auth_client.get("/auth/me").status_code == 200

    staff = user_factory()
    with auth_engine.begin() as connection:
        connection.execute(
            text("UPDATE public.users SET role = 'security_owner' WHERE user_id = :id"),
            {"id": staff.user_id},
        )
    auth_client.post("/auth/logout", headers=CSRF, json={})
    assert login(auth_client, staff).status_code == 401


def test_T14_logout_revokes_the_server_side_session(auth_client, user_factory):
    user = user_factory()
    assert login(auth_client, user).status_code == 200
    token = auth_client.cookies.get("sid")

    response = auth_client.post("/auth/logout", headers=CSRF, json={})
    assert response.status_code == 204
    auth_client.cookies.set("sid", token)
    assert auth_client.get("/auth/me").status_code == 401
    with auth_engine.connect() as connection:
        revoked = connection.execute(
            text(
                "SELECT revoked_at IS NOT NULL FROM public.sessions "
                "WHERE token_hash = :token_hash"
            ),
            {"token_hash": hashlib.sha256(token.encode("utf-8")).digest()},
        ).scalar_one()
    assert revoked is True


def test_T27_reset_token_expires_and_cannot_be_reused(auth_client, user_factory):
    user = user_factory()
    assert login(auth_client, user).status_code == 200
    prior_session_token = auth_client.cookies.get("sid")
    request = auth_client.post(
        "/auth/password/reset",
        headers={**CSRF, "Host": "attacker.invalid"},
        json={"email": user.email},
    )
    assert request.status_code == 202
    message, encrypted_fields = _latest_reset_message()
    token = _token_from_reset_message(message)
    assert token.encode("ascii") not in encrypted_fields[0]
    assert user.email.encode("utf-8") not in encrypted_fields[1]
    assert message.body.splitlines()[2].startswith(
        f"Reset: {TEST_APP_URL}/reset-password#token="
    )

    with auth_engine.connect() as connection:
        token_hash = connection.execute(
            text(
                "SELECT password_reset_token_hash FROM public.users "
                "WHERE user_id = :user_id"
            ),
            {"user_id": user.user_id},
        ).scalar_one()
    assert bytes(token_hash) == hashlib.sha256(token.encode("utf-8")).digest()

    with auth_engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE public.users SET password_reset_expires_at = "
                "now() - interval '1 second' WHERE user_id = :user_id"
            ),
            {"user_id": user.user_id},
        )
    expired = auth_client.post(
        "/auth/password/reset/confirm",
        headers=CSRF,
        json={"token": token, "new_password": strong_password()},
    )
    assert expired.status_code == 400

    assert (
        auth_client.post(
            "/auth/password/reset",
            headers=CSRF,
            json={"email": user.email},
        ).status_code
        == 202
    )
    replacement_message, _ = _latest_reset_message()
    replacement = _token_from_reset_message(replacement_message)
    new_password = strong_password()
    success = auth_client.post(
        "/auth/password/reset/confirm",
        headers=CSRF,
        json={"token": replacement, "new_password": new_password},
    )
    assert success.status_code == 204
    auth_client.cookies.set("sid", prior_session_token)
    assert auth_client.get("/auth/me").status_code == 401
    reused = auth_client.post(
        "/auth/password/reset/confirm",
        headers=CSRF,
        json={"token": replacement, "new_password": strong_password()},
    )
    assert reused.status_code == 400
    assert login(auth_client, AuthTestUser(user.user_id, user.email, new_password)).status_code == 200


def test_T28_reset_response_is_identical_for_existing_and_unknown_email(
    auth_client, user_factory
):
    user = user_factory()
    known = auth_client.post(
        "/auth/password/reset",
        headers=CSRF,
        json={"email": user.email},
    )
    unknown = auth_client.post(
        "/auth/password/reset",
        headers=CSRF,
        json={"email": f"unknown-{uuid4()}@example.invalid"},
    )
    assert known.status_code == unknown.status_code == 202
    assert known.content == unknown.content
    assert known.headers["content-type"] == unknown.headers["content-type"]


def test_T29_csrf_header_is_required_for_state_changes(auth_client, user_factory):
    user = user_factory()
    blocked = auth_client.post(
        "/auth/login",
        json={"email": user.email, "password": user.password},
    )
    assert blocked.status_code == 403
    wrong_header = auth_client.post(
        "/auth/login",
        headers={"X-Requested-With": "not-pfa"},
        json={"email": user.email, "password": user.password},
    )
    assert wrong_header.status_code == 403
    accepted = login(auth_client, user)
    assert accepted.status_code == 200


def test_T30_secrets_and_tokens_are_absent_from_application_logs(
    auth_client, user_factory, caplog
):
    caplog.set_level(logging.DEBUG)
    user = user_factory()
    password = user.password
    assert login(auth_client, user).status_code == 200
    session_token = auth_client.cookies.get("sid")
    assert (
        auth_client.post(
            "/auth/password/reset",
            headers=CSRF,
            json={"email": user.email},
        ).status_code
        == 202
    )
    reset_message, _ = _latest_reset_message()
    reset_token = _token_from_reset_message(reset_message)
    assert (
        auth_client.post(
            "/auth/login",
            headers=CSRF,
            json={"password": password},
        ).status_code
        == 422
    )
    captured_logs = caplog.text
    leaked_labels = [
        label
        for label, canary in (
            ("password", password),
            ("session_token", session_token),
            ("reset_token", reset_token),
            ("email", user.email),
        )
        if canary and canary in captured_logs
    ]
    assert leaked_labels == [], "sensitive canary categories appeared in logs"
    remaining_messages = consume_dev_outbox()
    for message in remaining_messages:
        if message.kind != "password_reset":
            assert message.body.splitlines()[0].startswith("UTC: ")
            assert message.body.splitlines()[1].startswith("Browser: ")
            assert "IP:" not in message.body
            assert "Location:" not in message.body


def test_T31_registration_response_is_generic_for_existing_and_new_email(
    auth_client, user_factory
):
    user = user_factory()
    duplicate = auth_client.post(
        "/auth/register",
        headers=CSRF,
        json={
            "email": user.email,
            "password": strong_password(),
            "base_currency": "PKR",
            "privacy_consent": True,
            "ai_consent": True,
        },
    )
    fresh_email = f"new-{uuid4()}@example.invalid"
    fresh = auth_client.post(
        "/auth/register",
        headers=CSRF,
        json={
            "email": fresh_email,
            "password": strong_password(),
            "base_currency": "PKR",
            "privacy_consent": True,
            "ai_consent": True,
        },
    )
    assert duplicate.status_code == fresh.status_code == 202
    assert duplicate.content == fresh.content
    with auth_engine.connect() as connection:
        existing_consents = connection.execute(
            text(
                "SELECT privacy_consent_at IS NOT NULL, ai_consent_at IS NULL "
                "FROM public.users WHERE user_id = :user_id"
            ),
            {"user_id": user.user_id},
        ).one()
        new_user_consents = connection.execute(
            text(
                "SELECT privacy_consent_at IS NOT NULL, ai_consent_at IS NOT NULL "
                "FROM public.users WHERE email_hmac = :email_hmac"
            ),
            {"email_hmac": crypto.hmac_email(fresh_email)},
        ).one()
    assert existing_consents == (True, True)
    assert new_user_consents == (True, True)

    unconsented_email = f"no-consent-{uuid4()}@example.invalid"
    unconsented = auth_client.post(
        "/auth/register",
        headers=CSRF,
        json={
            "email": unconsented_email,
            "password": strong_password(),
            "base_currency": "PKR",
            "privacy_consent": False,
            "ai_consent": True,
        },
    )
    assert unconsented.status_code == 422
    with auth_engine.connect() as connection:
        unconsented_exists = connection.execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM public.users WHERE email_hmac = :email_hmac)"
            ),
            {"email_hmac": crypto.hmac_email(unconsented_email)},
        ).scalar_one()
    assert unconsented_exists is False


def test_T32_password_reset_is_rate_limited_per_account_and_ip(
    auth_client, user_factory
):
    first = user_factory()
    for _ in range(3):
        response = auth_client.post(
            "/auth/password/reset",
            headers=CSRF,
            json={"email": first.email},
        )
        assert response.status_code == 202

    with auth_engine.connect() as connection:
        prior_token_hash, request_count = connection.execute(
            text(
                "SELECT password_reset_token_hash, reset_request_count "
                "FROM public.users WHERE user_id = :user_id"
            ),
            {"user_id": first.user_id},
        ).one()
    rate_limited_account = auth_client.post(
        "/auth/password/reset",
        headers=CSRF,
        json={"email": first.email},
    )
    assert rate_limited_account.status_code == 202
    with auth_engine.connect() as connection:
        after_token_hash, after_count = connection.execute(
            text(
                "SELECT password_reset_token_hash, reset_request_count "
                "FROM public.users WHERE user_id = :user_id"
            ),
            {"user_id": first.user_id},
        ).one()
    assert bytes(after_token_hash) == bytes(prior_token_hash)
    assert request_count == after_count == 3

    second = user_factory()
    third = user_factory()
    assert (
        auth_client.post(
            "/auth/password/reset", headers=CSRF, json={"email": second.email}
        ).status_code
        == 202
    )
    assert (
        auth_client.post(
            "/auth/password/reset", headers=CSRF, json={"email": third.email}
        ).status_code
        == 202
    )
    with auth_engine.connect() as connection:
        second_has_token = connection.execute(
            text(
                "SELECT password_reset_token_hash IS NOT NULL FROM public.users "
                "WHERE user_id = :user_id"
            ),
            {"user_id": second.user_id},
        ).scalar_one()
        third_has_token = connection.execute(
            text(
                "SELECT password_reset_token_hash IS NOT NULL FROM public.users "
                "WHERE user_id = :user_id"
            ),
            {"user_id": third.user_id},
        ).scalar_one()
    assert second_has_token is True
    assert third_has_token is False


def test_T33_password_change_revokes_all_sessions(auth_client, user_factory):
    user = user_factory()
    assert login(auth_client, user, "Chrome/132.0").status_code == 200
    first_token = auth_client.cookies.get("sid")
    assert login(auth_client, user, "Firefox/129.0").status_code == 200
    second_token = auth_client.cookies.get("sid")

    auth_client.cookies.set("sid", first_token)
    new_password = strong_password()
    changed = auth_client.post(
        "/auth/password/change",
        headers=CSRF,
        json={
            "current_password": user.password,
            "new_password": new_password,
        },
    )
    assert changed.status_code == 204
    hashes = [
        hashlib.sha256(token.encode("utf-8")).digest()
        for token in (first_token, second_token)
    ]
    with auth_engine.connect() as connection:
        first_revoked = connection.execute(
            text(
                "SELECT revoked_at IS NOT NULL FROM public.sessions "
                "WHERE token_hash = :token_hash"
            ),
            {"token_hash": hashes[0]},
        ).scalar_one()
        second_revoked = connection.execute(
            text(
                "SELECT revoked_at IS NOT NULL FROM public.sessions "
                "WHERE token_hash = :token_hash"
            ),
            {"token_hash": hashes[1]},
        ).scalar_one()
    assert first_revoked is True
    assert second_revoked is True
    assert login(auth_client, AuthTestUser(user.user_id, user.email, new_password)).status_code == 200


def test_T34_staff_creation_requires_and_stores_confirmed_totp(monkeypatch, capsys):
    from scripts import create_staff as staff_script

    email = f"staff-{uuid4()}@example.invalid"
    password = strong_password()
    secret = pyotp.random_base32()
    code = pyotp.TOTP(secret).now()
    prompts = iter((password, code))
    monkeypatch.setattr(staff_script.pyotp, "random_base32", lambda: secret)
    monkeypatch.setattr(staff_script.getpass, "getpass", lambda _prompt: next(prompts))
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")
    user_id = None
    try:
        staff_script.create_staff(email, "admin")
        capsys.readouterr()
        with auth_engine.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT user_id, role, dek_wrapped, totp_secret_enc "
                    "FROM public.users WHERE email_hmac = :email_hmac"
                ),
                {"email_hmac": crypto.hmac_email(email)},
            ).one()
        user_id = row.user_id
        assert row.role == "admin"
        assert row.totp_secret_enc is not None
        dek = crypto.unwrap_dek(bytes(row.dek_wrapped), user_id)
        stored_secret = crypto.dec(
            dek,
            bytes(row.totp_secret_enc),
            "users",
            "totp_secret_enc",
            user_id,
        ).decode("ascii")
        assert stored_secret == secret
    finally:
        if user_id is not None:
            with auth_engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE public.users SET status = 'deleted', deleted_at = now(), "
                        "totp_secret_enc = NULL WHERE user_id = :user_id"
                    ),
                    {"user_id": user_id},
                )


def _create_test_transaction(client: TestClient, merchant: str):
    return client.post(
        "/transactions",
        headers=CSRF,
        json={
            "kind": "expense",
            "amount_minor": 12345,
            "currency": "PKR",
            "merchant": merchant,
            "txn_date": "2026-10-20",
            "note": f"private note for {merchant}",
        },
    )


def test_account_export_requires_reauthentication_and_is_user_scoped(
    auth_client, user_factory
):
    user_a = user_factory()
    user_b = user_factory()

    assert login(auth_client, user_a).status_code == 200
    assert _create_test_transaction(auth_client, "export-owner-shop").status_code == 201
    assert login(auth_client, user_b).status_code == 200
    assert _create_test_transaction(auth_client, "other-person-shop").status_code == 201
    assert login(auth_client, user_a).status_code == 200

    bad_password = auth_client.post(
        "/me/export",
        headers=CSRF,
        json={"current_password": "incorrect password"},
    )
    assert bad_password.status_code == 401

    exported = auth_client.post(
        "/me/export",
        headers=CSRF,
        json={"current_password": user_a.password},
    )
    assert exported.status_code == 200
    assert "attachment; filename=\"account-export.json\"" in exported.headers[
        "content-disposition"
    ]
    assert exported.headers["cache-control"] == "no-store"
    payload = exported.json()
    assert payload["profile"]["email"] == user_a.email
    assert [row["merchant"] for row in payload["transactions"]] == [
        "export-owner-shop"
    ]
    assert "other-person-shop" not in exported.text

    with audit_engine.connect() as connection:
        results = connection.execute(
            text(
                "SELECT result FROM public.audit_log "
                "WHERE actor_user_id = :user_id AND action = 'account_export' "
                "ORDER BY id"
            ),
            {"user_id": user_a.user_id},
        ).scalars().all()
    assert "reauth_failed" in results
    assert "success" in results


def test_T25_account_deletion_requires_confirmation_revokes_sessions_and_shreds_data(
    auth_client, user_factory
):
    user = user_factory()
    assert login(auth_client, user).status_code == 200
    first_token = auth_client.cookies.get("sid")
    assert _create_test_transaction(auth_client, "delete-me-shop").status_code == 201
    assert login(auth_client, user).status_code == 200
    second_token = auth_client.cookies.get("sid")

    no_confirmation = auth_client.post(
        "/me/delete",
        headers=CSRF,
        json={"current_password": user.password, "confirmation": "delete"},
    )
    assert no_confirmation.status_code == 422

    auth_client.cookies.set("sid", first_token)
    wrong_password = auth_client.post(
        "/me/delete",
        headers=CSRF,
        json={"current_password": "incorrect password", "confirmation": "DELETE"},
    )
    assert wrong_password.status_code == 401
    deleted = auth_client.post(
        "/me/delete",
        headers=CSRF,
        json={"current_password": user.password, "confirmation": "DELETE"},
    )
    assert deleted.status_code == 204
    assert 'sid=""' in deleted.headers["set-cookie"]

    token_hashes = [
        hashlib.sha256(token.encode("utf-8")).digest()
        for token in (first_token, second_token)
    ]
    with auth_engine.connect() as connection:
        all_revoked, revoked_count = connection.execute(
            text(
                "SELECT bool_and(revoked_at IS NOT NULL), count(*) "
                "FROM public.sessions WHERE token_hash IN (:first, :second)"
            ),
            {"first": token_hashes[0], "second": token_hashes[1]},
        ).one()
        account_status = connection.execute(
            text(
                "SELECT status, dek_wrapped, totp_secret_enc, "
                "password_reset_token_hash FROM public.users WHERE user_id = :user_id"
            ),
            {"user_id": user.user_id},
        ).one()
    assert all_revoked is True
    assert revoked_count == 2
    assert account_status.status == "deleted"
    assert bytes(account_status.dek_wrapped) != b""
    with pytest.raises(crypto.InvalidTag):
        crypto.unwrap_dek(bytes(account_status.dek_wrapped), user.user_id)
    assert account_status.totp_secret_enc is None
    assert account_status.password_reset_token_hash is None

    from app.db import user_tx

    with user_tx(user.user_id) as connection:
        scrubbed = connection.execute(
            text(
                "SELECT deleted_at IS NOT NULL, currency, merchant_enc, amount_enc "
                "FROM public.transactions WHERE user_id = :user_id"
            ),
            {"user_id": user.user_id},
        ).one()
    assert scrubbed[0] is True
    assert scrubbed.currency == "XXX"
    assert scrubbed.merchant_enc is None
    with audit_engine.connect() as connection:
        audit_result = connection.execute(
            text(
                "SELECT result FROM public.audit_log WHERE actor_user_id = :user_id "
                "AND action = 'account_delete' ORDER BY id DESC LIMIT 1"
            ),
            {"user_id": user.user_id},
        ).scalar_one()
    assert audit_result == "success"


def test_account_export_requires_current_mfa_code(auth_client, user_factory):
    user = user_factory()
    assert login(auth_client, user).status_code == 200
    enrollment = auth_client.post(
        "/auth/mfa/enroll",
        headers=CSRF,
        json={"current_password": user.password},
    )
    assert enrollment.status_code == 200
    totp = pyotp.parse_uri(enrollment.json()["provisioning_uri"])
    assert auth_client.post(
        "/auth/mfa/confirm",
        headers=CSRF,
        json={"code": totp.now()},
    ).status_code == 204

    without_code = auth_client.post(
        "/me/export",
        headers=CSRF,
        json={"current_password": user.password},
    )
    assert without_code.status_code == 401
    with_code = auth_client.post(
        "/me/export",
        headers=CSRF,
        json={"current_password": user.password, "current_code": totp.now()},
    )
    assert with_code.status_code == 200
