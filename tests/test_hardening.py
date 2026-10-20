"""Security hardening tests against the real role-separated PostgreSQL.

Covers spec IDs T08, T10 and T24 plus the shared rate limits, MFA brute-force
limits, staff administration, accounts, FX writer isolation, health checks,
client-IP resolution and KEK rotation (T52-T65).
"""

from dataclasses import dataclass
import logging
from uuid import UUID, uuid4

import pyotp
import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, ProgrammingError
from starlette.requests import Request

from app import crypto, fx
from app.db import app_engine, audit_engine, auth_engine, fx_engine, stats_engine, user_tx
from app.main import client_ip, create_app

CSRF = {"X-Requested-With": "pfa"}


@dataclass
class Actor:
    client: TestClient
    user_id: UUID
    email: str
    password: str
    totp: pyotp.TOTP | None = None


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("EMAIL_MODE", "dev_outbox")
    monkeypatch.setenv("PUBLIC_APP_URL", "https://pfa.example.invalid")


def _ip() -> str:
    return f"2001:db8::{uuid4().int & ((1 << 64) - 1):x}"


def _client(ip: str | None = None) -> TestClient:
    client = TestClient(create_app(), client=(ip or _ip(), 50000))
    client.__enter__()
    return client


def _user(client: TestClient | None = None, *, login: bool = True) -> Actor:
    client = client or _client()
    email = f"hard-{uuid4()}@example.invalid"
    password = f"Amber!Quartz-{uuid4().hex}-Compass9"
    registered = client.post(
        "/auth/register",
        headers=CSRF,
        json={"email": email, "password": password, "privacy_consent": True},
    )
    assert registered.status_code == 202
    with auth_engine.connect() as connection:
        user_id = connection.execute(
            text("SELECT user_id FROM public.users WHERE email_hmac = :h"),
            {"h": crypto.hmac_email(email)},
        ).scalar_one()
    actor = Actor(client, user_id, email, password)
    if login:
        assert _login(actor).status_code == 200
    return actor


def _login(actor: Actor, password: str | None = None):
    return actor.client.post(
        "/auth/login",
        headers=CSRF,
        json={"email": actor.email, "password": password or actor.password},
    )


def _enroll_mfa(actor: Actor) -> pyotp.TOTP:
    started = actor.client.post(
        "/auth/mfa/enroll", headers=CSRF, json={"current_password": actor.password}
    )
    assert started.status_code == 200
    totp = pyotp.parse_uri(started.json()["provisioning_uri"])
    assert actor.client.post(
        "/auth/mfa/confirm", headers=CSRF, json={"code": totp.now()}
    ).status_code == 204
    actor.totp = totp
    return totp


def _wrong_code(totp: pyotp.TOTP) -> str:
    candidate = 123456
    while totp.verify(f"{candidate:06d}", valid_window=1):
        candidate = (candidate + 111111) % 1_000_000
    return f"{candidate:06d}"


def _staff(role: str) -> Actor:
    actor = _user()
    _enroll_mfa(actor)
    with auth_engine.begin() as connection:
        connection.execute(
            text("UPDATE public.users SET role = :role WHERE user_id = :id"),
            {"role": role, "id": actor.user_id},
        )
    assert _login(actor).status_code == 200
    verified = actor.client.post(
        "/auth/mfa/verify", headers=CSRF, json={"code": actor.totp.now()}
    )
    assert verified.status_code == 200
    return actor


def _audit_actions(target: UUID) -> list[str]:
    with audit_engine.connect() as connection:
        return list(
            connection.execute(
                text("SELECT action FROM public.audit_log WHERE target_id = :t ORDER BY id"),
                {"t": target},
            ).scalars()
        )


def _expense(actor: Actor, merchant: str, amount: int = 4321, **extra):
    return actor.client.post(
        "/transactions",
        headers=CSRF,
        json={"kind": "expense", "amount_minor": amount, "currency": "PKR",
              "merchant": merchant, **extra},
    )


# --------------------------------------------------------------- spec IDs


def test_T08_admin_is_denied_financial_data_and_sees_counts_only():
    admin = _staff("admin")
    for path in ("/transactions?month=2026-01", "/dashboard", "/budgets", "/bills", "/accounts"):
        assert admin.client.get(path).status_code == 403, path
    assert _expense(admin, "admin attempt").status_code == 403
    stats = admin.client.get("/admin/stats")
    assert stats.status_code == 200
    assert set(stats.json()) == {"active_users", "txns_24h", "failed_logins_24h"}
    assert all(isinstance(v, int) for v in stats.json().values())
    assert "permission_denied" in _audit_actions(admin.user_id)


def test_T10_stolen_database_dump_contains_only_ciphertext():
    owner = _user()
    created = _expense(owner, "CANARY-merchant-7781", amount=987654, note="CANARY-note-1123")
    assert created.status_code == 201
    txn_id = UUID(created.json()["txn_id"])
    with user_tx(owner.user_id) as connection:
        row = connection.execute(
            text("SELECT amount_enc, merchant_enc, note_enc FROM public.transactions "
                 "WHERE txn_id = :id"),
            {"id": txn_id},
        ).one()
    dumped = b"".join(bytes(value) for value in row)
    for plaintext in (b"CANARY", b"987654", b"7781", b"1123"):
        assert plaintext not in dumped
    # A thief with the rows but a different master secret cannot unwrap the key.
    with auth_engine.connect() as connection:
        wrapped = connection.execute(
            text("SELECT dek_wrapped FROM public.users WHERE user_id = :id"),
            {"id": owner.user_id},
        ).scalar_one()
    wrong = crypto.derive_keys(b"\x01" * 32).kek
    with pytest.raises(InvalidTag):
        crypto.unwrap_dek(bytes(wrapped), owner.user_id, kek=wrong)
    # Reporting roles cannot read the table at all.
    with pytest.raises(ProgrammingError):
        with stats_engine.connect() as connection:
            connection.execute(text("SELECT amount_enc FROM public.transactions LIMIT 1"))


def test_T24_planted_canaries_never_reach_logs_or_audit(caplog):
    caplog.set_level(logging.DEBUG)
    actor = _user()
    canaries = {
        "password": "CANARY-pass-" + uuid4().hex,
        "merchant": "CANARY-shop-" + uuid4().hex,
        "note": "CANARY-note-" + uuid4().hex,
        "chat": "CANARY-chat-" + uuid4().hex,
    }
    actor.client.post("/auth/login", headers=CSRF,
                      json={"email": actor.email, "password": canaries["password"]})
    _login(actor)
    _expense(actor, canaries["merchant"], note=canaries["note"])
    actor.client.post("/chat", headers=CSRF,
                      json={"message": f"spent 120 on {canaries['chat']}"})
    with audit_engine.connect() as connection:
        audit_dump = " ".join(
            str(value) for row in connection.execute(
                text("SELECT action, result, detail::text FROM public.audit_log "
                     "ORDER BY id DESC LIMIT 200")
            ) for value in row
        )
    for label, canary in [*canaries.items(), ("email", actor.email)]:
        assert canary not in caplog.text, label
        assert canary not in audit_dump, label


# --------------------------------------------------------------- shared rate limits


def test_T52_login_ip_limit_is_shared_across_instances_and_restarts():
    ip = _ip()
    first_instance, second_instance = _client(ip), _client(ip)
    body = {"email": f"nobody-{uuid4()}@example.invalid", "password": "wrong-password-x"}
    statuses = [first_instance.post("/auth/login", headers=CSRF, json=body).status_code
                for _ in range(20)]
    assert statuses == [401] * 20
    # A different app instance (another worker, or after a restart) sees the same counter.
    blocked = second_instance.post("/auth/login", headers=CSRF, json=body)
    assert blocked.status_code == 429
    assert blocked.headers["Retry-After"] == "900"


def test_T53_registration_is_limited_per_ip_before_password_hashing(monkeypatch):
    from app import auth

    client = _client()
    for _ in range(10):
        _user(client, login=False)
    calls = []
    monkeypatch.setattr(auth, "validate_password", lambda *a, **k: calls.append(1))
    limited = client.post(
        "/auth/register",
        headers=CSRF,
        json={"email": f"x-{uuid4()}@example.invalid", "password": "Amber!Quartz-x-Compass9",
              "privacy_consent": True},
    )
    assert limited.status_code == 429
    assert calls == []  # zxcvbn / Argon2 never ran: no CPU to burn


def test_T54_mfa_bruteforce_revokes_session_then_locks_account():
    actor = _user()
    totp = _enroll_mfa(actor)
    bad = _wrong_code(totp)

    assert _login(actor).json() == {"mfa_required": True}
    for _ in range(5):
        assert actor.client.post("/auth/mfa/verify", headers=CSRF,
                                 json={"code": bad}).status_code == 401
    # Session revoked after 5 failures: even the right code no longer works.
    assert actor.client.post("/auth/mfa/verify", headers=CSRF,
                             json={"code": totp.now()}).status_code == 401
    assert "mfa_session_revoked" in _audit_actions(actor.user_id)

    assert _login(actor).status_code == 200
    for _ in range(5):
        actor.client.post("/auth/mfa/verify", headers=CSRF, json={"code": bad})
    # 10 account-wide failures: locked for 15 minutes, password alone is not enough.
    assert _login(actor).status_code == 401
    assert "mfa_lockout" in _audit_actions(actor.user_id)


def test_T55_reauthentication_guessing_is_limited_per_account():
    actor = _user()
    for _ in range(5):
        response = actor.client.post("/me/export", headers=CSRF,
                                     json={"current_password": "wrong-guess"})
        assert response.status_code == 401
    correct = actor.client.post("/me/export", headers=CSRF,
                                json={"current_password": actor.password})
    assert correct.status_code == 401  # blocked even with the right password
    changed = actor.client.post(
        "/auth/password/change", headers=CSRF,
        json={"current_password": actor.password, "new_password": "Zephyr!Lantern-9-Orchid-Ridge"},
    )
    assert changed.status_code == 401  # all re-auth paths share the limit
    assert "reauth_rate_limited" in _audit_actions(actor.user_id)


# --------------------------------------------------------------- health, IP


def test_T56_health_reports_database_failure_instead_of_lying(monkeypatch):
    client = _client()
    healthy = client.get("/health")
    assert healthy.status_code == 200 and healthy.json()["database"] == "ok"
    dead = create_engine(
        "postgresql+psycopg://app_service@127.0.0.1:1/pfa",
        connect_args={"connect_timeout": 1},
    )
    monkeypatch.setattr("app.main.app_engine", dead)
    down = client.get("/health")
    assert down.status_code == 503 and down.json()["database"] == "down"
    assert client.get("/health/live").status_code == 200


def _request(headers: dict[str, str], peer: str = "10.0.0.9") -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "headers": raw, "client": (peer, 1234)})


def test_T57_client_ip_ignores_spoofed_forwarded_headers(monkeypatch):
    spoof = {"X-Forwarded-For": "6.6.6.6, 203.0.113.7", "CF-Connecting-IP": "198.51.100.4"}
    # Default: socket peer only; client-supplied headers are ignored.
    assert client_ip(_request(spoof)) == "10.0.0.9"
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "1")
    assert client_ip(_request(spoof)) == "203.0.113.7"  # rightmost = added by our proxy
    monkeypatch.setenv("CLIENT_IP_HEADER", "CF-Connecting-IP")
    assert client_ip(_request(spoof)) == "198.51.100.4"
    assert client_ip(_request({"CF-Connecting-IP": "not-an-ip"})) == "10.0.0.9"


# --------------------------------------------------------------- accounts


def test_T58_accounts_are_encrypted_owned_and_soft_deleted():
    owner, other = _user(), _user()
    created = owner.client.post("/accounts", headers=CSRF,
                                json={"name": "CANARY Savings", "type": "bank", "currency": "pkr"})
    assert created.status_code == 201
    account_id = created.json()["account_id"]
    assert owner.client.get("/accounts").json()["accounts"] == [
        {"account_id": account_id, "name": "CANARY Savings", "type": "bank", "currency": "PKR"}
    ]
    with user_tx(owner.user_id) as connection:
        stored = connection.execute(
            text("SELECT name_enc FROM public.accounts WHERE account_id = :id"),
            {"id": account_id},
        ).scalar_one()
    assert b"CANARY" not in bytes(stored)
    # Another user can neither see, delete nor reference it.
    assert other.client.get("/accounts").json()["accounts"] == []
    assert other.client.request("DELETE", f"/accounts/{account_id}", headers=CSRF, json={}).status_code == 404
    assert _expense(other, "theft", account_id=account_id).status_code == 404
    assert _expense(owner, "groceries", account_id=account_id).status_code == 201
    assert owner.client.request("DELETE", f"/accounts/{account_id}", headers=CSRF, json={}).status_code == 204
    assert _expense(owner, "after delete", account_id=account_id).status_code == 404
    assert owner.client.post("/accounts", headers=CSRF,
                             json={"name": "x", "type": "crypto", "currency": "PKR"}
                             ).status_code == 422


# --------------------------------------------------------------- FX writer


def test_T59_app_service_cannot_write_exchange_rates():
    with pytest.raises(ProgrammingError):
        with app_engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO public.fx_rates (rate_date, quote, rate_per_usd, source) "
                "VALUES ('1980-01-01', 'PKR', 1, 'synthetic-demo')"))


@pytest.mark.parametrize(
    "row",
    [
        {"rate_date": "1989-06-01", "quote": "PKR", "rate": "280", "source": "attacker"},
        {"rate_date": "1989-06-01", "quote": "XAU", "rate": "1", "source": "synthetic-demo"},
        {"rate_date": "1989-06-02", "quote": "PKR", "rate": "2800", "source": "synthetic-demo"},
        {"rate_date": "2999-01-01", "quote": "PKR", "rate": "280", "source": "synthetic-demo"},
        {"rate_date": "1989-06-03", "quote": "USD", "rate": "2", "source": "synthetic-demo"},
    ],
)
def test_T60_database_guard_rejects_poisoned_rates(row):
    assert fx_engine is not None
    with fx_engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO public.fx_rates (rate_date, quote, rate_per_usd, source) "
            "VALUES ('1989-05-31', 'PKR', 280, 'synthetic-demo') ON CONFLICT DO NOTHING"))
    with pytest.raises(DBAPIError):
        with fx_engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO public.fx_rates (rate_date, quote, rate_per_usd, source) "
                "VALUES (:rate_date, :quote, :rate, :source)"), row)


def test_T61_fx_fetch_is_claimed_once_across_processes(monkeypatch):
    from datetime import date

    day = date(1985, 1, 1 + uuid4().int % 27)
    fx.reset_attempt_state()
    calls = []

    def failing():
        calls.append(1)
        raise ValueError("provider down")

    monkeypatch.setattr(fx, "_fetch_rates", failing)
    assert fx.ensure_today(day=day) is False
    # Second "worker": the shared claim says a fetch failed < 1 hour ago, so it waits.
    assert fx.ensure_today(day=day) is False
    assert calls == [1]
    monkeypatch.setattr("app.db.fx_engine", None)
    assert fx.ensure_today(day=day) is False  # read-only web process never writes


# --------------------------------------------------------------- staff administration


def test_T62_security_owner_administers_accounts_with_audit_and_reauth():
    owner = _staff("security_owner")
    admin = _staff("admin")
    target = _user()

    listing = owner.client.get("/security/users").json()["users"]
    entry = next(u for u in listing if u["user_id"] == str(target.user_id))
    assert entry["email_masked"].startswith(target.email[0]) and "***@" in entry["email_masked"]
    assert target.email not in str(listing)
    assert admin.client.get("/security/users").status_code == 200  # admin: read status
    assert admin.client.post(f"/security/users/{target.user_id}/lock",
                             headers=CSRF, json={}).status_code == 403
    assert owner.client.get("/dashboard").status_code == 403  # no financial access

    assert owner.client.post(f"/security/users/{target.user_id}/lock",
                             headers=CSRF, json={}).status_code == 204
    assert target.client.get("/auth/me").status_code == 401  # sessions revoked
    assert _login(target).status_code == 401
    assert owner.client.post(f"/security/users/{target.user_id}/unlock",
                             headers=CSRF, json={}).status_code == 204
    assert _login(target).status_code == 200

    assert owner.client.post(f"/security/users/{target.user_id}/force-reset",
                             headers=CSRF, json={}).status_code == 204
    assert _login(target).status_code == 401
    assert owner.client.post(f"/security/users/{owner.user_id}/lock",
                             headers=CSRF, json={}).status_code == 403  # never on self

    role_url = f"/security/users/{admin.user_id}/role"
    no_code = owner.client.put(role_url, headers=CSRF,
                               json={"role": "user", "current_password": owner.password})
    assert no_code.status_code == 401
    no_mfa = owner.client.put(
        f"/security/users/{target.user_id}/role", headers=CSRF,
        json={"role": "admin", "current_password": owner.password,
              "current_code": owner.totp.now()},
    )
    assert no_mfa.status_code == 409  # staff roles require enrolled MFA
    demoted = owner.client.put(role_url, headers=CSRF, json={
        "role": "user", "current_password": owner.password, "current_code": owner.totp.now()})
    assert demoted.status_code == 204
    assert admin.client.get("/admin/stats").status_code == 401  # sessions revoked
    actions = _audit_actions(target.user_id) + _audit_actions(admin.user_id)
    for action in ("account_locked", "account_unlocked", "password_reset_forced",
                   "role_changed_to_user"):
        assert action in actions


def test_T63_users_can_disable_mfa_with_reauth_but_staff_cannot():
    actor = _user()
    totp = _enroll_mfa(actor)
    rejected = actor.client.post("/auth/mfa/disable", headers=CSRF, json={
        "current_password": actor.password, "current_code": _wrong_code(totp)})
    assert rejected.status_code == 401
    accepted = actor.client.post("/auth/mfa/disable", headers=CSRF, json={
        "current_password": actor.password, "current_code": totp.now()})
    assert accepted.status_code == 204
    assert actor.client.get("/me/settings").json()["mfa_enabled"] is False
    staff = _staff("security_owner")
    assert staff.client.post("/auth/mfa/disable", headers=CSRF, json={
        "current_password": staff.password, "current_code": staff.totp.now()}
    ).status_code == 403


# --------------------------------------------------------------- key rotation, audit


def test_T64_kek_rotation_rewraps_keys_without_reencrypting_rows(monkeypatch):
    from scripts.rotate_kek import rotate

    actor = _user()
    created = _expense(actor, "rotation check", amount=555)
    assert created.status_code == 201
    txn_id = created.json()["txn_id"]
    assert actor.client.post(f"/transactions/{txn_id}/confirm", headers=CSRF,
                             json={}).status_code == 200
    with user_tx(actor.user_id) as connection:
        before = bytes(connection.execute(
            text("SELECT amount_enc FROM public.transactions WHERE txn_id = :id"),
            {"id": txn_id}).scalar_one())
    new_secret = __import__("base64").b64encode(__import__("os").urandom(32)).decode()
    old_kek, new_kek = crypto.kek_from("master"), crypto.kek_from(new_secret)
    assert rotate(old_kek, new_kek, user_ids=[actor.user_id]) == 1
    try:
        monkeypatch.setenv("KEK_SECRET", new_secret)
        crypto._cached_keys.cache_clear()
        fresh = _client()
        actor.client = fresh
        assert _login(actor).status_code == 200
        assert fresh.get(f"/transactions/{txn_id}").json()["amount_minor"] == 555
        with user_tx(actor.user_id) as connection:
            after = bytes(connection.execute(
                text("SELECT amount_enc FROM public.transactions WHERE txn_id = :id"),
                {"id": txn_id}).scalar_one())
        assert after == before  # rows untouched; only the wrapped key changed
        with pytest.raises(ValueError):
            rotate(new_kek, new_kek, user_ids=[actor.user_id])
    finally:
        rotate(new_kek, old_kek, user_ids=[actor.user_id])
        monkeypatch.delenv("KEK_SECRET")
        crypto._cached_keys.cache_clear()


def test_T65_audit_chain_verification_script_reports_intact_chain():
    from scripts.verify_audit_chain import verify

    assert verify() is True


def test_T66_chat_and_receipt_ocr_are_limited_per_user(monkeypatch):
    from datetime import timedelta

    from app import ratelimit

    monkeypatch.setattr(ratelimit, "CHAT_PER_USER", ratelimit.Limit("chat_user", 2, timedelta(hours=1)))
    monkeypatch.setattr(ratelimit, "RECEIPT_PER_USER",
                        ratelimit.Limit("receipt_user", 1, timedelta(hours=1)))
    actor = _user()
    for amount in (5, 6):
        assert actor.client.post("/chat", headers=CSRF,
                                  json={"message": f"spent {amount} on tea"}).status_code == 200
    assert actor.client.post("/chat", headers=CSRF,
                             json={"message": "spent 7 on tea"}).status_code == 429
    receipt = {"filename": "r.txt", "content_type": "text/plain", "content_base64": "VG90YWwgMTIw"}
    first = actor.client.post("/receipts/review", headers=CSRF, json=receipt)
    assert first.status_code != 429
    assert actor.client.post("/receipts/review", headers=CSRF, json=receipt).status_code == 429
    # Limits are per user: another user is unaffected.
    assert _user().client.post("/chat", headers=CSRF,
                               json={"message": "spent 5 on tea"}).status_code == 200
