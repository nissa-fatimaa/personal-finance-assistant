"""Golden tests for the pure integer-minor-unit finance engine."""

from decimal import Decimal

import pytest

from app import engine, money


def test_food_example():
    pace = engine.pace_ratio(3_000_000, 2_100_000, 18, 30)
    assert pace is not None
    assert pace.quantize(Decimal("0.01")) == Decimal("1.17")
    assert engine.daily_cap(3_000_000, 2_100_000, 18, 30) == 69_230
    assert engine.status(3_000_000, 2_100_000) == "on_track"


def test_T22_budget_math_zero_budget_refund_and_partial_month():
    assert engine.status(0, 0) == "unbudgeted"
    assert engine.daily_cap(0, 100, 18, 30) == 0
    assert engine.pace_ratio(0, 100, 18, 30) is None
    assert engine.pace_ratio(100_000, 10_000, 2, 30) is None
    assert engine.daily_cap(100_000, 25_000, 18, 30) == 5_769
    assert engine.safe_to_spend([(1_000, 1_500), (1_000, 400)], 10, 30) == 28
    # Refunds enter the engine as negative category spend: 2,100 - 100 = 2,000.
    assert engine.status(3_000, 2_000) == "on_track"
    assert engine.daily_cap(3_000, 2_000, 10, 30) == 47


def test_T22_budget_suggestion_is_median_plus_half_mad_and_scaled():
    suggestions = engine.suggest_budget(
        {"food": [10_000, 20_000, 30_000], "travel": [20_000, 40_000, 60_000]},
        expected_monthly_income_minor=50_000,
    )
    # Raw values are 25,000 and 50,000; the 70% cap is 35,000.
    assert suggestions["food"].limit_minor == 11_667
    assert suggestions["travel"].limit_minor == 23_333
    assert suggestions["food"].scaled_to_ceiling is True
    assert sum(item.limit_minor for item in suggestions.values()) == 35_000
    assert engine.suggest_budget({"food": [100, 200]}, 10_000) == {}


def test_T23_sparse_history_is_skipped_with_explanation():
    result = engine.anomaly_result(100_000, [1_000] * 9)
    assert result == {
        "checked": False,
        "is_anomaly": None,
        "message": "Insufficient history: at least 10 transactions are required.",
    }
    assert engine.is_anomaly(100_000, [1_000] * 9) is False


def test_forecast_requires_enough_days_and_transactions():
    assert engine.forecast(50_000, 6, 30, 12, 3_000) is None
    assert engine.forecast(50_000, 7, 30, 9, 3_000) is None
    assert engine.forecast(50_000, 10, 30, 10, 3_000) == 153_000


def test_currency_conversion_uses_integer_minor_units_and_half_up():
    rates = {"USD": Decimal("1"), "PKR": Decimal("280")}
    assert money.convert(2_000, "USD", "PKR", rates) == 560_000
    assert money.convert(500, "JPY", "PKR", {"JPY": Decimal("150"), **rates}) == 93_333
    assert money.to_minor("850", "PKR") == 85_000
    assert money.to_minor("500", "JPY") == 500
    with pytest.raises(TypeError):
        money.to_minor(850.0, "PKR")
