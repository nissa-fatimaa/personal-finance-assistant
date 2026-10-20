"""Exact currency arithmetic in integer minor units."""

from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Mapping

EXPONENTS = {
    "PKR": 2,
    "USD": 2,
    "EUR": 2,
    "GBP": 2,
    "AED": 2,
    "SAR": 2,
    "CAD": 2,
    "AUD": 2,
    "CNY": 2,
    "JPY": 0,
}


def _currency(code: str) -> str:
    code = code.upper()
    if code not in EXPONENTS:
        raise ValueError("unsupported currency")
    return code


def to_minor(amount: str | Decimal, currency: str) -> int:
    """Parse a decimal amount without floats and enforce the currency exponent."""
    currency = _currency(currency)
    if isinstance(amount, float) or isinstance(amount, bool):
        raise TypeError("amount must be a decimal string or Decimal")
    try:
        value = Decimal(str(amount))
    except (InvalidOperation, ValueError):
        raise ValueError("invalid amount") from None
    if not value.is_finite() or value <= 0:
        raise ValueError("amount must be positive")
    scaled = value.scaleb(EXPONENTS[currency])
    if scaled != scaled.to_integral_value():
        raise ValueError("too many decimal places")
    return int(scaled)


def fmt(minor: int, currency: str) -> str:
    """Format integer minor units with the currency's ISO exponent."""
    currency = _currency(currency)
    if isinstance(minor, bool) or not isinstance(minor, int):
        raise TypeError("minor amount must be an integer")
    exponent = EXPONENTS[currency]
    amount = Decimal(minor).scaleb(-exponent)
    return f"{currency} {amount:,.{exponent}f}"


def _rate(value: Decimal | str) -> Decimal:
    if isinstance(value, (float, bool)):
        raise TypeError("exchange rates must be Decimal or decimal strings")
    try:
        rate = Decimal(value)
    except (InvalidOperation, TypeError, ValueError):
        raise ValueError("invalid exchange rate") from None
    if not rate.is_finite() or rate <= 0:
        raise ValueError("exchange rate must be positive and finite")
    return rate


def convert_at_rate(
    minor: int, source: str, target: str, rate: Decimal | str
) -> int:
    """Convert at a direct target-major-units per source-major-unit rate."""
    source, target = _currency(source), _currency(target)
    if isinstance(minor, bool) or not isinstance(minor, int):
        raise TypeError("minor amount must be an integer")
    if source == target:
        return minor
    source_major = Decimal(minor).scaleb(-EXPONENTS[source])
    target_major = source_major * _rate(rate)
    target_minor = target_major.scaleb(EXPONENTS[target])
    return int(target_minor.quantize(Decimal(1), rounding=ROUND_HALF_UP))


def convert(minor: int, source: str, target: str, rates: Mapping[str, Decimal]) -> int:
    """Convert minor units via units-per-USD rates, rounding half-up once."""
    source, target = _currency(source), _currency(target)
    if isinstance(minor, bool) or not isinstance(minor, int):
        raise TypeError("minor amount must be an integer")
    if source == target:
        return minor
    normalized_rates = {str(code).strip().upper(): value for code, value in rates.items()}
    if source not in normalized_rates or target not in normalized_rates:
        raise KeyError("rate unavailable")
    ratio = _rate(normalized_rates[target]) / _rate(normalized_rates[source])
    major = Decimal(minor).scaleb(-EXPONENTS[source])
    converted = (major * ratio).scaleb(EXPONENTS[target])
    return int(converted.quantize(Decimal(1), rounding=ROUND_HALF_UP))
