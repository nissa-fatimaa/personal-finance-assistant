"""Real-PostgreSQL ledger, budgets, bills, and dashboard tests."""

from dataclasses import dataclass
from datetime import date
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app import crypto, fx
from app.db import app_engine, audit_engine, auth_engine, fx_engine, user_tx
from app.main import create_app

CSRF = {"X-Requested-With": "pfa"}


@dataclass(frozen=True)
class LedgerUser:
    client: TestClient
    user_id: UUID


def _strong_password() -> str:
    return f"Amber!Quartz-{uuid4().hex}-Compass9"


@pytest.fixture
def ledger_user_factory(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("EMAIL_MODE", "dev_outbox")
    monkeypatch.setenv("PUBLIC_APP_URL", "https://pfa.example.invalid")
    created: list[LedgerUser] = []

    def create() -> LedgerUser:
        client = TestClient(
            create_app(),
            client=(f"2001:db8::{uuid4().int & ((1 << 64) - 1):x}", 54321),
        )
        client.__enter__()
        email = f"ledger-{uuid4()}@example.invalid"
        password = _strong_password()
        registration = client.post(
            "/auth/register",
            headers=CSRF,
            json={
                "email": email,
                "password": password,
                "base_currency": "PKR",
                "privacy_consent": True,
                "ai_consent": False,
            },
        )
        assert registration.status_code == 202
        with auth_engine.connect() as connection:
            user_id = connection.execute(
                text("SELECT user_id FROM public.users WHERE email_hmac = :email_hmac"),
                {"email_hmac": crypto.hmac_email(email)},
            ).scalar_one()
        login = client.post(
            "/auth/login",
            headers=CSRF,
            json={"email": email, "password": password},
        )
        assert login.status_code == 200
        result = LedgerUser(client=client, user_id=user_id)
        created.append(result)
        return result

    yield create

    for user in created:
        with user_tx(user.user_id) as connection:
            connection.execute(
                text(
                    "UPDATE public.transactions SET deleted_at = coalesce(deleted_at, now()) "
                    "WHERE user_id = :user_id"
                ),
                {"user_id": user.user_id},
            )
            connection.execute(
                text(
                    "UPDATE public.bills SET deleted_at = coalesce(deleted_at, now()), "
                    "is_active = false WHERE user_id = :user_id"
                ),
                {"user_id": user.user_id},
            )
            connection.execute(
                text(
                    "UPDATE public.accounts SET deleted_at = coalesce(deleted_at, now()) "
                    "WHERE user_id = :user_id"
                ),
                {"user_id": user.user_id},
            )
        with auth_engine.begin() as connection:
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
                    "deleted_at = coalesce(deleted_at, now()) WHERE user_id = :user_id"
                ),
                {"user_id": user.user_id},
            )
        user.client.close()


def _shared_category(name: str) -> UUID:
    with app_engine.connect() as connection:
        return connection.execute(
            text(
                "SELECT category_id FROM public.categories "
                "WHERE user_id IS NULL AND name = :name"
            ),
            {"name": name},
        ).scalar_one()


def _make_transaction(
    user: LedgerUser,
    *,
    kind: str = "expense",
    amount_minor: int = 85_000,
    merchant: str = "synthetic petrol",
    txn_date: date | None = None,
    category_id: UUID | None = None,
):
    body = {
        "kind": kind,
        "amount_minor": amount_minor,
        "currency": "PKR",
        "merchant": merchant,
        "txn_date": (txn_date or date.today()).isoformat(),
    }
    if category_id is not None:
        body["category_id"] = str(category_id)
    return user.client.post("/transactions", headers=CSRF, json=body)


def _confirm(user: LedgerUser, txn_id: str) -> None:
    response = user.client.post(
        f"/transactions/{txn_id}/confirm", headers=CSRF, json={}
    )
    assert response.status_code == 200, response.text


def test_transaction_and_reset_frontend_routes_are_not_captured_by_api(
    ledger_user_factory,
):
    user = ledger_user_factory()
    for path in ("/transactions/new", "/reset-password"):
        response = user.client.get(path)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")
        assert '<div id="root"></div>' in response.text


def _month_before(period: str, count: int) -> list[str]:
    year, month = map(int, period.split("-"))
    months = []
    for _ in range(count):
        month -= 1
        if month == 0:
            year -= 1
            month = 12
        months.append(f"{year:04d}-{month:02d}")
    return list(reversed(months))


def test_T01_pending_confirmation_updates_budget_and_month_list(ledger_user_factory):
    user = ledger_user_factory()
    transport = _shared_category("Transport")
    period = date.today().strftime("%Y-%m")
    budget = user.client.put(
        "/budgets",
        headers=CSRF,
        json={"category_id": str(transport), "period": period, "limit_minor": 100_000},
    )
    assert budget.status_code == 200, budget.text

    pending = user.client.post(
        "/chat",
        headers=CSRF,
        json={"message": "spent 850 on petrol"},
    )
    assert pending.status_code == 200, pending.text
    assert pending.json()["confirmation_required"] is True
    txn_id = pending.json()["confirmation_card"]["txn_id"]
    assert pending.json()["confirmation_card"]["category_id"] == str(transport)
    before = user.client.get("/dashboard", params={"month": period})
    assert before.status_code == 200
    assert before.json()["expenses_minor"] == 0
    assert before.json()["pending_count"] == 1

    _confirm(user, txn_id)
    transactions = user.client.get("/transactions", params={"month": period})
    assert transactions.status_code == 200
    assert len(transactions.json()["transactions"]) == 1
    assert transactions.json()["transactions"][0]["amount_minor"] == 85_000

    dashboard = user.client.get("/dashboard", params={"month": period})
    assert dashboard.status_code == 200
    assert dashboard.json()["expenses_minor"] == 85_000
    transport_budget = next(
        item for item in dashboard.json()["categories"] if item["category_id"] == str(transport)
    )
    assert transport_budget["spent_minor"] == 85_000
    assert transport_budget["status"] == "caution"


def test_T02_chat_without_amount_clarifies_without_a_row(ledger_user_factory):
    user = ledger_user_factory()
    with user_tx(user.user_id) as connection:
        before = connection.execute(
            text("SELECT count(*) FROM public.transactions")
        ).scalar_one()

    response = user.client.post(
        "/chat",
        headers=CSRF,
        json={"message": "spent on petrol"},
    )
    assert response.status_code == 200
    assert response.json()["clarification"] is True
    assert response.json()["missing"] == ["amount"]
    with user_tx(user.user_id) as connection:
        after = connection.execute(
            text("SELECT count(*) FROM public.transactions")
        ).scalar_one()
    assert after == before


def test_T03_foreign_transaction_id_returns_404_and_audits_denial(
    ledger_user_factory,
):
    user_a = ledger_user_factory()
    user_b = ledger_user_factory()
    pending = _make_transaction(user_b)
    assert pending.status_code == 201
    txn_id = UUID(pending.json()["txn_id"])

    response = user_a.client.post(
        f"/transactions/{txn_id}/confirm",
        headers=CSRF,
        json={"user_id": str(user_b.user_id)},
    )
    assert response.status_code == 404
    with audit_engine.connect() as connection:
        denied = connection.execute(
            text(
                "SELECT count(*) FROM public.audit_log "
                "WHERE action = 'object_denied' AND target_id = :target_id "
                "AND result = 'deny'"
            ),
            {"target_id": txn_id},
        ).scalar_one()
    assert denied >= 1


def test_T16_duplicate_is_blocked_by_dedupe_unique_index(ledger_user_factory):
    user = ledger_user_factory()
    txn_date = date.today()
    first = _make_transaction(user, merchant="synthetic duplicate", txn_date=txn_date)
    assert first.status_code == 201
    second = _make_transaction(user, merchant="synthetic duplicate", txn_date=txn_date)
    assert second.status_code == 409
    with user_tx(user.user_id) as connection:
        count = connection.execute(
            text(
                "SELECT count(*) FROM public.transactions "
                "WHERE status = 'pending' AND deleted_at IS NULL"
            )
        ).scalar_one()
    assert count == 1


def test_T22_refunds_reduce_spend_and_pending_and_transfers_are_excluded(
    ledger_user_factory,
):
    user = ledger_user_factory()
    food = _shared_category("Food")
    period = date.today().strftime("%Y-%m")
    saved_budget = user.client.put(
        "/budgets",
        headers=CSRF,
        json={"category_id": str(food), "period": period, "limit_minor": 0},
    )
    assert saved_budget.status_code == 200

    for kind, amount, merchant in (
        ("expense", 100_000, "synthetic groceries"),
        ("refund", 25_000, "synthetic grocery refund"),
        ("income", 200_000, "synthetic salary"),
        ("transfer", 40_000, "synthetic transfer"),
    ):
        created = _make_transaction(
            user,
            kind=kind,
            amount_minor=amount,
            merchant=merchant,
            category_id=food,
        )
        assert created.status_code == 201
        _confirm(user, created.json()["txn_id"])
    pending = _make_transaction(
        user, amount_minor=50_000, merchant="synthetic pending", category_id=food
    )
    assert pending.status_code == 201

    dashboard = user.client.get("/dashboard", params={"month": period})
    assert dashboard.status_code == 200
    result = dashboard.json()
    assert result["income_minor"] == 200_000
    assert result["expenses_minor"] == 75_000
    food_result = next(
        item for item in result["categories"] if item["category_id"] == str(food)
    )
    assert food_result["spent_minor"] == 75_000
    assert food_result["status"] == "unbudgeted"
    assert result["pending_count"] == 1


def test_T35_category_suggestion_uses_user_scoped_merchant_hmac(
    ledger_user_factory,
):
    user = ledger_user_factory()
    other_user = ledger_user_factory()
    food = _shared_category("Food")
    first = _make_transaction(
        user, merchant="synthetic corner shop", category_id=food
    )
    assert first.status_code == 201
    _confirm(user, first.json()["txn_id"])

    second = _make_transaction(
        user,
        amount_minor=99_000,
        merchant="synthetic corner shop",
        txn_date=date.today(),
    )
    assert second.status_code == 201
    assert second.json()["category_id"] == str(food)
    assert second.json()["suggested_category_id"] == str(food)

    other_user_entry = _make_transaction(
        other_user,
        amount_minor=111_000,
        merchant="synthetic corner shop",
        txn_date=date.today(),
    )
    assert other_user_entry.status_code == 201
    assert other_user_entry.json()["suggested_category_id"] is None


def test_T36_budget_suggestion_requires_explicit_approval(ledger_user_factory):
    user = ledger_user_factory()
    food = _shared_category("Food")
    income_category = _shared_category("Income")
    period = date.today().strftime("%Y-%m")
    history = _month_before(period, 3)
    for index, old_month in enumerate(history):
        txn_date = date.fromisoformat(f"{old_month}-15")
        for kind, amount, merchant, category in (
            ("expense", (index + 1) * 10_000, f"history food {index}", food),
            ("income", 10_000_000, f"history income {index}", income_category),
        ):
            created = _make_transaction(
                user,
                kind=kind,
                amount_minor=amount,
                merchant=merchant,
                txn_date=txn_date,
                category_id=category,
            )
            assert created.status_code == 201
            _confirm(user, created.json()["txn_id"])

    suggestions = user.client.get(
        "/budgets/suggestions", params={"period": period}
    )
    assert suggestions.status_code == 200
    payload = suggestions.json()
    food_suggestion = next(
        item for item in payload["suggestions"] if item["category_id"] == str(food)
    )
    assert food_suggestion["limit_minor"] == 25_000
    assert user.client.get("/budgets", params={"period": period}).json()["budgets"] == []

    approved = user.client.post(
        f"/budgets/suggestions/{food}/approve",
        headers=CSRF,
        json={"period": period},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["approved_suggestion"] is True
    budgets = user.client.get("/budgets", params={"period": period}).json()["budgets"]
    assert next(item for item in budgets if item["category_id"] == str(food))[
        "limit_minor"
    ] == 25_000


def test_T37_bill_crud_is_encrypted_and_soft_deleted(ledger_user_factory):
    user = ledger_user_factory()
    response = user.client.post(
        "/bills",
        headers=CSRF,
        json={
            "biller": "synthetic electricity",
            "amount_minor": 12_300,
            "currency": "PKR",
            "next_due_date": date.today().isoformat(),
            "recurrence": "monthly",
        },
    )
    assert response.status_code == 201, response.text
    bill_id = response.json()["bill_id"]
    bills = user.client.get("/bills")
    assert bills.status_code == 200
    assert bills.json()["bills"][0]["biller"] == "synthetic electricity"
    deleted = user.client.request(
        "DELETE", f"/bills/{bill_id}", headers=CSRF, json={}
    )
    assert deleted.status_code == 204
    assert user.client.get("/bills").json()["bills"] == []


def test_T38_transaction_delete_is_soft_and_releases_dedupe_key(
    ledger_user_factory,
):
    user = ledger_user_factory()
    txn_date = date.today()
    first = _make_transaction(
        user, merchant="synthetic soft delete", txn_date=txn_date
    )
    assert first.status_code == 201
    txn_id = first.json()["txn_id"]
    deleted = user.client.request(
        "DELETE", f"/transactions/{txn_id}", headers=CSRF, json={}
    )
    assert deleted.status_code == 204

    replacement = _make_transaction(
        user, merchant="synthetic soft delete", txn_date=txn_date
    )
    assert replacement.status_code == 201
    with user_tx(user.user_id) as connection:
        states = connection.execute(
            text(
                "SELECT status, deleted_at IS NOT NULL AS is_deleted "
                "FROM public.transactions WHERE dedupe_hmac = :dedupe_hmac "
                "ORDER BY deleted_at DESC NULLS LAST"
            ),
            {
                "dedupe_hmac": crypto.dedupe_hmac(
                    user.user_id,
                    "synthetic soft delete",
                    85_000,
                    "PKR",
                    txn_date,
                )
            },
        ).all()
    assert len(states) == 2
    assert states[0].is_deleted is True
    assert states[1].is_deleted is False


def test_T39_posted_transaction_can_be_read_and_updated_with_encryption(
    ledger_user_factory,
):
    user = ledger_user_factory()
    food = _shared_category("Food")
    original = _make_transaction(
        user, merchant="synthetic edit before", txn_date=date.today()
    )
    assert original.status_code == 201
    txn_id = original.json()["txn_id"]
    _confirm(user, txn_id)

    before = user.client.get(f"/transactions/{txn_id}")
    assert before.status_code == 200
    assert before.json()["merchant"] == "synthetic edit before"
    assert before.json()["amount_minor"] == 85_000

    corrected_date = date.today().replace(day=1)
    body = {
        "kind": "expense",
        "amount_minor": 12_345,
        "currency": "PKR",
        "merchant": " synthetic edit after ",
        "txn_date": corrected_date.isoformat(),
        "category_id": str(food),
        "note": "corrected private note",
        "fee_minor": 123,
        "fx_override_rate": "1.25",
    }
    updated = user.client.put(
        f"/transactions/{txn_id}", headers=CSRF, json=body
    )
    assert updated.status_code == 200, updated.text
    assert updated.json() == {"txn_id": txn_id, "status": "posted"}

    after = user.client.get(f"/transactions/{txn_id}")
    assert after.status_code == 200
    result = after.json()
    assert result["txn_id"] == txn_id
    assert result["merchant"] == "synthetic edit after"
    assert result["amount_minor"] == 12_345
    assert result["txn_date"] == corrected_date.isoformat()
    assert result["fx_date"] == corrected_date.isoformat()
    assert result["category_id"] == str(food)
    assert result["note"] == "corrected private note"
    assert result["fee_minor"] == 123
    assert result["fx_override_rate"] == "1.2500000000"
    assert result["fx_rate_source"] == "manual"

    expected_hash = crypto.dedupe_hmac(
        user.user_id, "synthetic edit after", 12_345, "PKR", corrected_date
    )
    with user_tx(user.user_id) as connection:
        raw = connection.execute(
            text(
                "SELECT amount_enc, merchant_enc, note_enc, fee_enc, "
                "merchant_hmac, dedupe_hmac FROM public.transactions "
                "WHERE txn_id = :txn_id"
            ),
            {"txn_id": UUID(txn_id)},
        ).one()
    assert bytes(raw.amount_enc) != b"12345"
    assert bytes(raw.merchant_enc) != b"synthetic edit after"
    assert bytes(raw.note_enc) != b"corrected private note"
    assert bytes(raw.fee_enc) != b"123"
    assert bytes(raw.merchant_hmac) == crypto.merchant_hmac(
        user.user_id, "synthetic edit after"
    )
    assert bytes(raw.dedupe_hmac) == expected_hash


def test_T40_transaction_edit_hides_foreign_owner_and_audits_denial(
    ledger_user_factory,
):
    owner = ledger_user_factory()
    other_user = ledger_user_factory()
    created = _make_transaction(owner, merchant="synthetic foreign edit")
    assert created.status_code == 201
    txn_id = created.json()["txn_id"]
    _confirm(owner, txn_id)

    get_response = other_user.client.get(f"/transactions/{txn_id}")
    assert get_response.status_code == 404
    update_response = other_user.client.put(
        f"/transactions/{txn_id}",
        headers=CSRF,
        json={
            "kind": "expense",
            "amount_minor": 99_000,
            "currency": "PKR",
            "merchant": "synthetic unauthorized change",
            "txn_date": date.today().isoformat(),
        },
    )
    assert update_response.status_code == 404
    assert owner.client.get(f"/transactions/{txn_id}").json()["merchant"] == (
        "synthetic foreign edit"
    )
    with audit_engine.connect() as connection:
        denied = connection.execute(
            text(
                "SELECT count(*) FROM public.audit_log "
                "WHERE action = 'object_denied' AND target_id = :target_id "
                "AND result = 'deny'"
            ),
            {"target_id": UUID(txn_id)},
        ).scalar_one()
    assert denied >= 2


def test_T41_transaction_edit_rejects_duplicate_without_changing_original(
    ledger_user_factory,
):
    user = ledger_user_factory()
    txn_date = date.today()
    first = _make_transaction(
        user, merchant="synthetic edit unique first", txn_date=txn_date
    )
    second = _make_transaction(
        user,
        amount_minor=95_000,
        merchant="synthetic edit unique second",
        txn_date=txn_date,
    )
    assert first.status_code == second.status_code == 201
    first_id = first.json()["txn_id"]
    second_id = second.json()["txn_id"]
    _confirm(user, first_id)
    _confirm(user, second_id)

    collision = user.client.put(
        f"/transactions/{first_id}",
        headers=CSRF,
        json={
            "kind": "expense",
            "amount_minor": 95_000,
            "currency": "PKR",
            "merchant": "synthetic edit unique second",
            "txn_date": txn_date.isoformat(),
        },
    )
    assert collision.status_code == 409
    unchanged = user.client.get(f"/transactions/{first_id}")
    assert unchanged.status_code == 200
    assert unchanged.json()["merchant"] == "synthetic edit unique first"
    assert unchanged.json()["amount_minor"] == 85_000


def test_T42_transaction_edit_validates_fields_and_only_updates_posted_rows(
    ledger_user_factory,
):
    user = ledger_user_factory()
    pending = _make_transaction(user, merchant="synthetic pending edit")
    assert pending.status_code == 201
    pending_id = pending.json()["txn_id"]
    body = {
        "kind": "expense",
        "amount_minor": 9_999,
        "currency": "PKR",
        "merchant": "synthetic pending corrected",
        "txn_date": date.today().isoformat(),
    }
    assert user.client.put(
        f"/transactions/{pending_id}", headers=CSRF, json=body
    ).status_code == 404
    _confirm(user, pending_id)
    body["amount_minor"] = 0
    invalid = user.client.put(
        f"/transactions/{pending_id}", headers=CSRF, json=body
    )
    assert invalid.status_code == 422
    assert user.client.get(f"/transactions/{pending_id}").json()["amount_minor"] == 85_000


def test_T44_dashboard_report_parameters_and_fee_manual_rate_api(
    ledger_user_factory, monkeypatch
):
    user = ledger_user_factory()
    report_day = date(1990, 8, 15)
    monkeypatch.setattr(fx, "today", lambda: report_day)
    fx.reset_attempt_state()
    rates = {
        "PKR": "280",
        "USD": "1",
        "EUR": "0.9",
        "GBP": "0.79",
        "AED": "3.6725",
        "SAR": "3.75",
        "CAD": "1.36",
        "AUD": "1.52",
        "CNY": "7.2",
        "JPY": "150",
    }
    with fx_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO public.fx_rates "
                "(rate_date, quote, rate_per_usd, source) "
                "VALUES (:rate_date, :quote, :rate_per_usd, :source) "
                "ON CONFLICT (rate_date, quote) DO NOTHING"
            ),
            [
                {
                    "rate_date": report_day,
                    "quote": quote,
                    "rate_per_usd": rate,
                    "source": "synthetic-demo",
                }
                for quote, rate in rates.items()
            ],
        )

    created = user.client.post(
        "/transactions",
        headers=CSRF,
        json={
            "kind": "expense",
            "amount_minor": 1_000,
            "currency": "USD",
            "merchant": f"Manual FX fee {uuid4()}",
            "txn_date": report_day.isoformat(),
            "category_id": str(_shared_category("Food")),
            "fee_minor": 100,
            "fx_override_rate": "300",
        },
    )
    assert created.status_code == 201, created.text
    _confirm(user, created.json()["txn_id"])

    recorded = user.client.get(
        "/dashboard",
        params={
            "month": "1990-08",
            "currency": "PKR",
            "policy": "as_recorded",
        },
    )
    current = user.client.get(
        "/dashboard",
        params={"month": "1990-08", "currency": "PKR", "policy": "current"},
    )
    assert recorded.status_code == current.status_code == 200
    assert recorded.json()["report_currency"] == "PKR"
    assert recorded.json()["policy"] == "as_recorded"
    assert recorded.json()["expenses_minor"] == 330_000
    assert recorded.json()["fees_minor"] == 30_000
    assert recorded.json()["rate_sources"] == ["manual"]
    assert current.json()["policy"] == "current"
    assert current.json()["expenses_minor"] == 308_000
    assert current.json()["fees_minor"] == 28_000
    assert current.json()["manual_rate_override_count"] == 0


def test_T45_frontend_support_endpoints_are_scoped_and_protected(
    ledger_user_factory,
):
    user = ledger_user_factory()

    settings = user.client.get("/me/settings")
    assert settings.status_code == 200
    assert settings.json() == {"mfa_enabled": False, "ai_consent": False}

    categories = user.client.get("/categories")
    assert categories.status_code == 200
    assert any(item["name"] == "Food" for item in categories.json()["categories"])

    sessions = user.client.get("/auth/sessions")
    assert sessions.status_code == 200
    assert len(sessions.json()["sessions"]) == 1
    assert sessions.json()["sessions"][0]["is_current"] is True

    consent = user.client.put(
        "/me/ai-consent", headers=CSRF, json={"enabled": True}
    )
    assert consent.status_code == 200
    assert consent.json()["ai_consent"] is True
    assert user.client.get("/auth/me").json()["ai_consent"] is True

    assert user.client.get("/admin/stats").status_code == 403
    assert user.client.get("/security/audit").status_code == 403


def test_update_transaction_cannot_target_another_users_row(ledger_user_factory):
    """Regression: PUT /transactions/{id} must stay tenant-scoped even with a known id."""
    owner = ledger_user_factory()
    attacker = ledger_user_factory()
    created = owner.client.post(
        "/transactions",
        headers=CSRF,
        json={
            "kind": "expense",
            "amount_minor": 1000,
            "currency": "PKR",
            "merchant": "Update target",
        },
    )
    assert created.status_code == 201
    txn_id = created.json()["txn_id"]
    confirmed = owner.client.post(f"/transactions/{txn_id}/confirm", headers=CSRF, json={})
    assert confirmed.status_code == 200

    hijack = attacker.client.put(
        f"/transactions/{txn_id}",
        headers=CSRF,
        json={
            "kind": "expense",
            "amount_minor": 999999,
            "currency": "PKR",
            "merchant": "Hijack attempt",
        },
    )
    assert hijack.status_code == 404

    unchanged = owner.client.get(f"/transactions/{txn_id}")
    assert unchanged.status_code == 200
    assert unchanged.json()["amount_minor"] == 1000
    assert unchanged.json()["merchant"] == "Update target"
