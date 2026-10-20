"""Lazy daily FX snapshots backed by stored rates or the public rate provider."""

import json
import logging
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation

import httpx
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app import db
from app.config import local_today
from app.db import app_engine
from app.money import EXPONENTS

LOGGER = logging.getLogger(__name__)
PROVIDER_URL = "https://open.er-api.com/v6/latest/USD"
SOURCE = "open-er-api.com"



@dataclass(frozen=True)
class RateSnapshot:
    rate_date: date
    rates: dict[str, Decimal]
    source: str
    age_days: int
    estimated: bool = False


def today() -> date:
    return local_today()


def _decimal_rate(value) -> Decimal:
    try:
        rate = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        raise ValueError("invalid provider rate") from None
    if not rate.is_finite() or rate <= 0:
        raise ValueError("invalid provider rate")
    return rate


def _fetch_rates() -> dict[str, Decimal]:
    response = httpx.get(PROVIDER_URL, timeout=8)
    response.raise_for_status()
    payload = json.loads(response.text, parse_float=Decimal, parse_int=Decimal)
    if not isinstance(payload, dict):
        raise ValueError("unexpected FX provider response")
    if payload.get("base_code") != "USD" or payload.get("result") == "error":
        raise ValueError("unexpected FX provider response")
    raw_rates = payload.get("rates") or payload.get("conversion_rates")
    if not isinstance(raw_rates, dict):
        raise ValueError("FX provider response has no rates")
    rates = {
        currency: _decimal_rate(raw_rates[currency])
        for currency in EXPONENTS
        if currency in raw_rates
    }
    if set(rates) != set(EXPONENTS):
        raise ValueError("FX provider response is missing supported currencies")
    if rates.get("USD") != Decimal(1):
        raise ValueError("FX provider base rate is not one USD")
    return rates


def _stored(snapshot_day: date) -> bool:
    # The refresh job holds only fx_writer credentials, which can read fx_rates.
    engine = db.fx_engine if db.fx_engine is not None else app_engine
    with engine.begin() as connection:
        return (
            connection.execute(
                text("SELECT 1 FROM public.fx_rates WHERE rate_date = :d LIMIT 1"),
                {"d": snapshot_day},
            ).first()
            is not None
        )


def _claim(snapshot_day: date) -> bool:
    """Atomically claim today's fetch for exactly one process (any worker/host).

    A failed attempt may be retried after an hour; a claim abandoned by a
    crashed process expires after ten minutes.
    """
    with db.fx_engine.begin() as connection:
        return (
            connection.execute(
                text(
                    "INSERT INTO public.fx_fetch_attempts (rate_date, outcome) "
                    "VALUES (:d, 'claimed') "
                    "ON CONFLICT (rate_date) DO UPDATE "
                    "SET attempted_at = now(), outcome = 'claimed' "
                    "WHERE (public.fx_fetch_attempts.outcome = 'failed' "
                    "AND public.fx_fetch_attempts.attempted_at < now() - interval '1 hour') "
                    "OR (public.fx_fetch_attempts.outcome = 'claimed' "
                    "AND public.fx_fetch_attempts.attempted_at < now() - interval '10 minutes') "
                    "RETURNING 1"
                ),
                {"d": snapshot_day},
            ).first()
            is not None
        )


def _finish(snapshot_day: date, outcome: str) -> None:
    with db.fx_engine.begin() as connection:
        connection.execute(
            text("UPDATE public.fx_fetch_attempts SET outcome = :o WHERE rate_date = :d"),
            {"o": outcome, "d": snapshot_day},
        )


def ensure_today(*, day: date | None = None) -> bool:
    """Make sure a snapshot exists for the day; return True when one is stored.

    Writing requires DATABASE_URL_FX (the fx_writer role). Without it the web
    process is read-only for rates and relies on the scheduled refresh job.
    A failed fetch leaves stored data untouched; callers use the last snapshot
    and report its age. No lock is held while the provider is contacted.
    """
    snapshot_day = day or today()
    if _stored(snapshot_day):
        return True
    if db.fx_engine is None or not _claim(snapshot_day):
        return False
    try:
        rates = _fetch_rates()
    except (httpx.HTTPError, json.JSONDecodeError, ValueError, KeyError):
        LOGGER.warning("fx_fetch_failed")
        _finish(snapshot_day, "failed")
        return False
    rows = [
        {
            "rate_date": snapshot_day,
            "quote": currency,
            "rate_per_usd": str(rate),
            "source": SOURCE,
        }
        for currency, rate in rates.items()
    ]
    try:
        with db.fx_engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO public.fx_rates "
                    "(rate_date, quote, rate_per_usd, source) "
                    "VALUES (:rate_date, :quote, :rate_per_usd, :source) "
                    "ON CONFLICT (rate_date, quote) DO NOTHING"
                ),
                rows,
            )
    except SQLAlchemyError:
        # The database guard rejected the snapshot (e.g. implausible jump).
        LOGGER.warning("fx_snapshot_rejected")
        _finish(snapshot_day, "failed")
        return False
    _finish(snapshot_day, "stored")
    return True


def rates_on(
    connection, requested_date: date, *, reference_date: date | None = None
) -> RateSnapshot | None:
    """Return the latest complete-enough stored snapshot for a date.

    If the requested date predates the first stored snapshot, use that earliest
    snapshot and mark it estimated. An absent table of rates returns None.
    """
    snapshot_date = connection.execute(
        text("SELECT max(rate_date) FROM public.fx_rates WHERE rate_date <= :day"),
        {"day": requested_date},
    ).scalar_one_or_none()
    estimated = False
    if snapshot_date is None:
        snapshot_date = connection.execute(
            text("SELECT min(rate_date) FROM public.fx_rates")
        ).scalar_one_or_none()
        estimated = snapshot_date is not None
    if snapshot_date is None:
        return None

    rows = connection.execute(
        text(
            "SELECT quote, rate_per_usd, source FROM public.fx_rates "
            "WHERE rate_date = :snapshot_date"
        ),
        {"snapshot_date": snapshot_date},
    ).all()
    rates = {
        row.quote.strip().upper(): Decimal(row.rate_per_usd)
        for row in rows
    }
    if not rates:
        return None
    sources = {row.source for row in rows}
    source = next(iter(sources)) if len(sources) == 1 else "mixed"
    as_of = reference_date or today()
    return RateSnapshot(
        rate_date=snapshot_date,
        rates=rates,
        source=source,
        age_days=max(0, (as_of - snapshot_date).days),
        estimated=estimated,
    )


def reset_attempt_state() -> None:
    """Clear fetch claims; intended for isolated tests and operators."""
    if db.fx_engine is None:
        return
    with db.fx_engine.begin() as connection:
        connection.execute(text("DELETE FROM public.fx_fetch_attempts"))
