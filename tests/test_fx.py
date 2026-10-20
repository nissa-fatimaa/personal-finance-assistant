"""Currency conversion and FX snapshots against the real PostgreSQL database."""

from datetime import date, timedelta
from decimal import Decimal
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import text

from app import engine, finance, fx, ledger
from app.db import app_engine, fx_engine
from app.money import EXPONENTS, convert, fmt, to_minor


def _rates(*, pkr: str = "280", eur: str = "0.9", jpy: str = "150"):
    return {
        "PKR": pkr,
        "USD": "1",
        "EUR": eur,
        "GBP": "0.79",
        "AED": "3.6725",
        "SAR": "3.75",
        "CAD": "1.36",
        "AUD": "1.52",
        "CNY": "7.2",
        "JPY": jpy,
    }


def _insert_snapshot(rate_date: date, rates: dict[str, str]) -> None:
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
                    "rate_date": rate_date,
                    "quote": code,
                    "rate_per_usd": value,
                    "source": "synthetic-demo",
                }
                for code, value in rates.items()
            ],
        )


def _post(
    user_id,
    *,
    currency: str,
    amount_minor: int,
    txn_date: date,
    category_id,
    merchant: str | None = None,
    fee_minor: int | None = None,
    fx_override_rate: str | None = None,
):
    pending = ledger.create_pending(
        user_id=user_id,
        kind="expense",
        amount_minor=amount_minor,
        currency=currency,
        merchant=merchant or f"FX test {uuid4()}",
        txn_date=txn_date,
        category_id=category_id,
        fee_minor=fee_minor,
        fx_override_rate=fx_override_rate,
    )
    assert pending is not None
    ledger.confirm(user_id, pending["txn_id"])
    return pending["txn_id"]


def test_T18_mixed_currency_dashboard_matches_hand_computed_totals(
    user_pair, monkeypatch
):
    user, _ = user_pair
    report_day = date(1990, 3, 15)
    monkeypatch.setattr(fx, "today", lambda: report_day)
    fx.reset_attempt_state()
    _insert_snapshot(report_day, _rates())
    food = ledger.shared_category_id(user.user_id, "Food")
    assert food is not None

    _post(
        user.user_id,
        currency="PKR",
        amount_minor=2_800_000,
        txn_date=report_day,
        category_id=food,
    )
    _post(
        user.user_id,
        currency="USD",
        amount_minor=2_000,
        fee_minor=100,
        txn_date=report_day,
        category_id=food,
    )
    _post(
        user.user_id,
        currency="EUR",
        amount_minor=1_000,
        txn_date=report_day,
        category_id=food,
    )
    _post(
        user.user_id,
        currency="JPY",
        amount_minor=1_500,
        txn_date=report_day,
        category_id=food,
    )

    result = finance.dashboard(
        user.user_id, "1990-03", report_currency="PKR", policy="as_recorded"
    )
    # PKR 28,000 + USD 21.00 × 280 + EUR 10.00 × 280/.9
    # (rounded per transaction) + JPY 1,500 × 280/150 = PKR 39,791.11.
    assert result["expenses_minor"] == 3_979_111
    assert result["fees_minor"] == 28_000
    assert result["report_currency"] == "PKR"
    assert result["policy"] == "as_recorded"
    assert result["report_conversion_available"] is True
    assert result["rates_snapshot"] == "1990-03-15"
    assert result["rates_snapshot_age_days"] == 0
    assert result["fx_snapshots"][0]["source"] == "synthetic-demo"
    assert result["rate_attribution_url"] == "https://www.exchangerate-api.com"
    assert result["fx_effects"] == []

    transactions = ledger.list_month(user.user_id, "1990-03")
    usd_row = next(item for item in transactions if item["currency"] == "USD")
    assert usd_row["fee_minor"] == 100
    assert usd_row["fx_rate_source"] is None


def test_manual_rate_is_flagged_and_current_policy_ignores_override(
    user_pair, monkeypatch
):
    user, _ = user_pair
    report_day = date(1990, 4, 15)
    monkeypatch.setattr(fx, "today", lambda: report_day)
    fx.reset_attempt_state()
    _insert_snapshot(report_day, _rates(pkr="280"))
    food = ledger.shared_category_id(user.user_id, "Food")
    assert food is not None
    txn_id = _post(
        user.user_id,
        currency="USD",
        amount_minor=1_000,
        txn_date=report_day,
        category_id=food,
        fx_override_rate="300",
    )
    row = next(
        item for item in ledger.list_month(user.user_id, "1990-04")
        if item["txn_id"] == txn_id
    )
    assert row["fx_override_rate"] == "300.0000000000"
    assert row["fx_rate_source"] == "manual"

    recorded = finance.dashboard(
        user.user_id, "1990-04", report_currency="PKR", policy="as_recorded"
    )
    current = finance.dashboard(
        user.user_id, "1990-04", report_currency="PKR", policy="current"
    )
    assert recorded["expenses_minor"] == 300_000
    assert recorded["manual_rate_override_count"] == 1
    assert "manual" in recorded["rate_sources"]
    assert current["expenses_minor"] == 280_000
    assert current["manual_rate_override_count"] == 0


def test_T19_blocked_provider_uses_last_snapshot_and_reports_its_age(
    user_pair, monkeypatch
):
    user, _ = user_pair
    report_day = date(1990, 6, 10)
    last_snapshot = report_day - timedelta(days=3)
    monkeypatch.setattr(fx, "today", lambda: report_day)
    fx.reset_attempt_state()
    _insert_snapshot(last_snapshot, _rates(pkr="295"))

    def blocked_provider():
        raise httpx.ConnectError("provider blocked")

    monkeypatch.setattr(fx, "_fetch_rates", blocked_provider)
    food = ledger.shared_category_id(user.user_id, "Food")
    assert food is not None
    _post(
        user.user_id,
        currency="USD",
        amount_minor=1_000,
        txn_date=report_day,
        category_id=food,
    )
    result = finance.dashboard(
        user.user_id, "1990-06", report_currency="PKR", policy="current"
    )

    assert result["expenses_minor"] == 295_000
    assert result["rates_snapshot"] == last_snapshot.isoformat()
    assert result["rates_snapshot_age_days"] == 3
    assert result["fx_snapshots"][0]["source"] == "synthetic-demo"
    assert result["report_conversion_available"] is True
    with app_engine.connect() as connection:
        today_rows = connection.execute(
            text(
                "SELECT count(*) FROM public.fx_rates WHERE rate_date = :day"
            ),
            {"day": report_day},
        ).scalar_one()
    assert today_rows == 0


def test_fx_effect_uses_exact_volume_and_rate_decomposition(user_pair, monkeypatch):
    user, _ = user_pair
    january = date(1990, 1, 15)
    february = date(1990, 2, 15)
    monkeypatch.setattr(fx, "today", lambda: february)
    fx.reset_attempt_state()
    _insert_snapshot(january, _rates(pkr="280"))
    _insert_snapshot(february, _rates(pkr="300"))
    food = ledger.shared_category_id(user.user_id, "Food")
    assert food is not None
    _post(
        user.user_id,
        currency="USD",
        amount_minor=10_000,
        txn_date=january,
        category_id=food,
    )
    _post(
        user.user_id,
        currency="USD",
        amount_minor=12_000,
        txn_date=february,
        category_id=food,
    )

    result = finance.dashboard(
        user.user_id, "1990-02", report_currency="PKR", policy="as_recorded"
    )
    effect = next(item for item in result["fx_effects"] if item["currency"] == "USD")
    assert effect["volume_effect_minor"] == 560_000
    assert effect["rate_effect_minor"] == 240_000
    assert effect["base_change_minor"] == 800_000
    assert (
        effect["volume_effect_minor"] + effect["rate_effect_minor"]
        == effect["base_change_minor"]
    )
    assert effect["exact_identity"] is True

    exact = engine.fx_decomposition(
        Decimal("100"), Decimal("120"), Decimal("28000"), Decimal("36000")
    )
    assert exact is not None
    assert exact["volume_effect"] + exact["rate_effect"] == exact["base_change"]


def test_money_jpy_exponent_rounding_format_and_missing_rate():
    assert EXPONENTS["JPY"] == 0
    assert to_minor("500", "JPY") == 500
    assert fmt(500, "JPY") == "JPY 500"
    assert fmt(12_345, "PKR") == "PKR 123.45"
    assert convert(100, "USD", "JPY", {"USD": Decimal("1"), "JPY": Decimal("149.5")}) == 150
    with pytest.raises(KeyError, match="rate unavailable"):
        convert(100, "USD", "PKR", {"USD": Decimal("1")})


def test_dashboard_marks_conversion_unavailable_without_rate(
    user_pair, monkeypatch
):
    user, _ = user_pair
    report_day = date(1991, 1, 10)
    monkeypatch.setattr(fx, "today", lambda: report_day)
    fx.reset_attempt_state()
    monkeypatch.setattr(fx, "_fetch_rates", lambda: (_ for _ in ()).throw(ValueError()))
    monkeypatch.setattr(finance, "_snapshot_rates", lambda *args, **kwargs: None)
    food = ledger.shared_category_id(user.user_id, "Food")
    assert food is not None
    _post(
        user.user_id,
        currency="USD",
        amount_minor=1_000,
        txn_date=report_day,
        category_id=food,
    )
    result = finance.dashboard(
        user.user_id, "1991-01", report_currency="PKR", policy="current"
    )
    assert result["expenses_minor"] is None
    assert result["report_conversion_available"] is False
    assert result["unavailable_currencies"] == ["USD"]


def test_fx_history_generator_is_deterministic_and_synthetic():
    from scripts.seed import _transaction_specs, generate_fx_history

    day = date(2026, 10, 19)
    first = generate_fx_history(day)
    second = generate_fx_history(day)
    assert first == second
    assert len(first) == 90 * len(EXPONENTS)
    assert {row["source"] for row in first} == {"synthetic-demo"}
    pkr_values = [
        Decimal(row["rate_per_usd"]) for row in first if row["quote"] == "PKR"
    ]
    assert pkr_values[-1] > pkr_values[0]

    categories = [uuid4() for _ in range(5)]
    specs = _transaction_specs(day, *categories)
    assert {spec["currency"] for spec in specs} >= {"PKR", "USD", "EUR", "JPY"}
    assert {spec["txn_date"].strftime("%Y-%m") for spec in specs} == {
        "2026-08",
        "2026-09",
        "2026-10",
    }
    food_total = sum(
        spec["amount_minor"]
        for spec in specs
        if spec["category_id"] == categories[0]
        and spec["txn_date"].strftime("%Y-%m") == "2026-10"
    )
    ratio = Decimal(food_total) / (Decimal(3_000_000) * Decimal(19) / 31)
    assert abs(ratio - Decimal("1.17")) < Decimal("0.000001")
    assert sum("outlier" in spec["merchant"] for spec in specs) == 1
