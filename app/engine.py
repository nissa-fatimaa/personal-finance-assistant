"""Pure finance calculations over integer minor-unit amounts."""

from dataclasses import dataclass
from decimal import Decimal, ROUND_FLOOR, ROUND_HALF_UP
from fractions import Fraction
from statistics import mean, median
from typing import Mapping, Sequence


@dataclass(frozen=True)
class BudgetSuggestion:
    limit_minor: int
    scaled_to_ceiling: bool


def _validate_month_day(day: int, days_in_month: int) -> None:
    if days_in_month < 1 or day < 1 or day > days_in_month:
        raise ValueError("day must be within the month")


def status(limit: int, spent: int) -> str:
    """Return the spec's budget status, using integer cross-multiplication."""
    if limit <= 0:
        return "unbudgeted"
    remaining = limit - spent
    if remaining < 0 or remaining * 100 < limit * 5:
        return "critical"
    if remaining * 100 < limit * 20:
        return "caution"
    return "on_track"


def pace_ratio(limit: int, spent: int, day: int, days_in_month: int) -> Decimal | None:
    """Return spend divided by expected spend to date; suppress before day 3."""
    _validate_month_day(day, days_in_month)
    if limit <= 0 or day < 3:
        return None
    return Decimal(spent) / (Decimal(limit) * Decimal(day) / Decimal(days_in_month))


def daily_cap(limit: int, spent: int, day: int, days_in_month: int) -> int:
    """Maximum daily amount remaining, with today included in days left."""
    _validate_month_day(day, days_in_month)
    days_left = days_in_month - day + 1
    return max(0, limit - spent) // days_left


def safe_to_spend(categories: Sequence[tuple[int, int]], day: int, days_in_month: int) -> int:
    """Sum category caps without allowing an overspent category to borrow."""
    _validate_month_day(day, days_in_month)
    days_left = days_in_month - day + 1
    return sum(max(0, limit - spent) for limit, spent in categories) // days_left


def modified_z(value: int, history: Sequence[int]) -> float:
    """Modified z-score; zero MAD uses the spec's mean-absolute-deviation fallback."""
    if not history:
        raise ValueError("history must not be empty")
    center = median(history)
    mad = median([abs(item - center) for item in history])
    if mad == 0:
        mean_absolute_deviation = mean([abs(item - center) for item in history])
        if mean_absolute_deviation == 0:
            return 0.0
        return (value - center) / (1.253314 * mean_absolute_deviation)
    return 0.6745 * (value - center) / mad


def is_anomaly(value: int, history: Sequence[int]) -> bool:
    """Skip sparse histories; otherwise flag only an absolute modified z above 3.5."""
    return len(history) >= 10 and abs(modified_z(value, history)) > 3.5


def anomaly_result(value: int, history: Sequence[int]) -> dict[str, bool | None | str]:
    """Return an explicit skipped state for the sparse-data UI."""
    if len(history) < 10:
        return {
            "checked": False,
            "is_anomaly": None,
            "message": "Insufficient history: at least 10 transactions are required.",
        }
    return {"checked": True, "is_anomaly": is_anomaly(value, history), "message": ""}


def forecast(
    spent: int,
    day: int,
    days_in_month: int,
    transaction_count: int,
    unpaid_bills: int,
) -> int | None:
    """Forecast month-end spend only with the spec's minimum data conditions."""
    _validate_month_day(day, days_in_month)
    if day < 7 or transaction_count < 10:
        return None
    return spent + spent * (days_in_month - day) // day + unpaid_bills


def suggest_budget(
    spending_by_category: Mapping[str, Sequence[int]],
    expected_monthly_income_minor: int | None,
    ceiling_ratio: Decimal = Decimal("0.70"),
) -> dict[str, BudgetSuggestion]:
    """Compute median + half MAD from three complete months and scale to the ceiling.

    Histories with anything other than three months are omitted. The function is
    pure: callers decide whether and when to persist a suggestion.
    """
    if ceiling_ratio < 0 or ceiling_ratio > 1:
        raise ValueError("ceiling_ratio must be between zero and one")
    if expected_monthly_income_minor is not None and expected_monthly_income_minor < 0:
        raise ValueError("expected monthly income cannot be negative")

    raw_limits: dict[str, int] = {}
    for category, history in spending_by_category.items():
        if len(history) != 3:
            continue
        if any(isinstance(value, bool) or not isinstance(value, int) for value in history):
            raise TypeError("historical spending must use integer minor units")
        center = Decimal(str(median(history)))
        mad = Decimal(str(median([abs(value - int(center)) for value in history])))
        candidate = max(Decimal(0), center + Decimal("0.5") * mad)
        raw_limits[category] = int(candidate.quantize(Decimal(1), rounding=ROUND_HALF_UP))

    total = sum(raw_limits.values())
    if expected_monthly_income_minor is None or total == 0:
        return {
            category: BudgetSuggestion(amount, False)
            for category, amount in raw_limits.items()
        }

    ceiling = int(
        (Decimal(expected_monthly_income_minor) * ceiling_ratio).to_integral_value(
            rounding=ROUND_FLOOR
        )
    )
    if total <= ceiling:
        return {
            category: BudgetSuggestion(amount, False)
            for category, amount in raw_limits.items()
        }

    exact_scaled = {
        category: Decimal(amount) * Decimal(ceiling) / Decimal(total)
        for category, amount in raw_limits.items()
    }
    allocated = {
        category: int(value.to_integral_value(rounding=ROUND_FLOOR))
        for category, value in exact_scaled.items()
    }
    residual = ceiling - sum(allocated.values())
    order = sorted(
        exact_scaled,
        key=lambda category: (
            -(exact_scaled[category] - allocated[category]),
            category,
        ),
    )
    for category in order[:residual]:
        allocated[category] += 1
    return {
        category: BudgetSuggestion(amount, True)
        for category, amount in allocated.items()
    }


def fx_decomposition(o0, o1, b0, b1) -> dict[str, Fraction] | None:
    """Return the exact volume/rate decomposition in base-currency major units.

    Inputs are original-currency totals and their corresponding base totals,
    each expressed in major units. Fractions preserve the identity exactly.
    """
    original_previous = Fraction(o0)
    original_current = Fraction(o1)
    base_previous = Fraction(b0)
    base_current = Fraction(b1)
    if original_previous == 0 or original_current == 0:
        return None

    effective_previous = base_previous / original_previous
    effective_current = base_current / original_current
    volume_effect = (original_current - original_previous) * effective_previous
    rate_effect = original_current * (effective_current - effective_previous)
    base_change = base_current - base_previous
    if volume_effect + rate_effect != base_change:
        raise ArithmeticError("FX volume/rate decomposition did not reconcile")
    return {
        "volume_effect": volume_effect,
        "rate_effect": rate_effect,
        "base_change": base_change,
        "effective_rate_previous": effective_previous,
        "effective_rate_current": effective_current,
    }
