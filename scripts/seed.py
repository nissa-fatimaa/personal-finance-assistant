"""Seed a fictional guest account and visibly synthetic FX history."""

from __future__ import annotations

import argparse
import getpass
import random
from datetime import date, timedelta
from decimal import Decimal, ROUND_HALF_UP

from sqlalchemy import text

from app import auth, crypto, fx, ledger
from app.db import auth_engine, fx_engine, user_tx
from app.finance import save_budget
from app.money import EXPONENTS

DEFAULT_GUEST_EMAIL = "guest@example.invalid"
SEED_MARKER = "PFA synthetic demo seed v1"
FX_BASE_RATES = {
    "PKR": Decimal("280"),
    "USD": Decimal("1"),
    "EUR": Decimal("0.92"),
    "GBP": Decimal("0.79"),
    "AED": Decimal("3.6725"),
    "SAR": Decimal("3.75"),
    "CAD": Decimal("1.36"),
    "AUD": Decimal("1.52"),
    "CNY": Decimal("7.2"),
    "JPY": Decimal("150"),
}


def _month_start(year: int, month: int) -> date:
    return date(year, month, 1)


def _previous_month(year: int, month: int) -> tuple[int, int]:
    return (year - 1, 12) if month == 1 else (year, month - 1)


def _last_three_months(today: date) -> list[tuple[int, int]]:
    values = []
    year, month = today.year, today.month
    for _ in range(3):
        values.append((year, month))
        year, month = _previous_month(year, month)
    return list(reversed(values))


def generate_fx_history(today: date) -> list[dict[str, str | date]]:
    """Generate repeatable synthetic rates, with PKR gradually weakening."""
    random.seed(42)
    rates = dict(FX_BASE_RATES)
    rows = []
    for offset in range(90):
        rate_date = today - timedelta(days=89 - offset)
        drift = Decimal("0.0004") + Decimal(
            str(random.uniform(-0.0002, 0.0002))
        )
        rates["PKR"] = (rates["PKR"] * (Decimal(1) + drift)).quantize(
            Decimal("0.0000000001"), rounding=ROUND_HALF_UP
        )
        for currency in EXPONENTS:
            rows.append(
                {
                    "rate_date": rate_date,
                    "quote": currency,
                    "rate_per_usd": str(rates[currency]),
                    "source": "synthetic-demo",
                }
            )
    return rows


def _transaction_specs(today: date, food_category, transport_category,
                       travel_category, shopping_category, entertainment_category):
    random.seed(42)
    months = _last_three_months(today)
    specs = []
    for year, month in months:
        is_current = (year, month) == (today.year, today.month)
        if month == 12:
            next_start = date(year + 1, 1, 1)
        else:
            next_start = date(year, month + 1, 1)
        month_last_day = (next_start - timedelta(days=1)).day

        def day_of(
            requested: int,
            *,
            _month_last_day: int = month_last_day,
            _is_current: bool = is_current,
            _year: int = year,
            _month: int = month,
        ) -> date:
            day = min(requested, _month_last_day)
            if _is_current:
                day = min(day, today.day)
            return date(_year, _month, day)

        if is_current:
            food_limit = 3_000_000
            food_target = int(
                (
                    Decimal(food_limit)
                    * Decimal(today.day)
                    * Decimal("1.17")
                    / Decimal(month_last_day)
                ).quantize(Decimal(1), rounding=ROUND_HALF_UP)
            )
            food_amounts = [
                food_target // 3,
                food_target // 3,
                food_target - 2 * (food_target // 3),
            ]
            food_days = [day_of(4), day_of(10), day_of(today.day)]
            for index, (amount, txn_day) in enumerate(zip(food_amounts, food_days)):
                specs.append(
                    {
                        "kind": "expense",
                        "amount_minor": amount,
                        "currency": "PKR",
                        "merchant": f"Demo groceries {index + 1} {year}-{month:02d}",
                        "txn_date": txn_day,
                        "category_id": food_category,
                    }
                )
        else:
            specs.append(
                {
                    "kind": "expense",
                    "amount_minor": random.randint(1_150_000, 1_350_000),
                    "currency": "PKR",
                    "merchant": f"Demo groceries {year}-{month:02d}",
                    "txn_date": day_of(8),
                    "category_id": food_category,
                }
            )

        specs.extend(
            [
                {
                    "kind": "expense",
                    "amount_minor": random.randint(25_000, 75_000),
                    "currency": "PKR",
                    "merchant": f"Demo transport {year}-{month:02d}",
                    "txn_date": day_of(13),
                    "category_id": transport_category,
                },
                {
                    "kind": "expense",
                    "amount_minor": 999,
                    "currency": "USD",
                    "merchant": f"Demo streaming {year}-{month:02d}",
                    "txn_date": day_of(16),
                    "category_id": entertainment_category,
                },
                {
                    "kind": "expense",
                    "amount_minor": 2_500,
                    "currency": "EUR",
                    "merchant": f"Demo travel {year}-{month:02d}",
                    "txn_date": day_of(20),
                    "category_id": travel_category,
                },
                {
                    "kind": "expense",
                    "amount_minor": 1_200,
                    "currency": "JPY",
                    "merchant": f"Demo Japan purchase {year}-{month:02d}",
                    "txn_date": day_of(22),
                    "category_id": shopping_category,
                },
            ]
        )
        for index in range(4):
            specs.append(
                {
                    "kind": "expense",
                    "amount_minor": random.randint(2_500, 5_000),
                    "currency": "PKR",
                    "merchant": f"Demo shopping {year}-{month:02d}-{index}",
                    "txn_date": day_of(5 + index * 5),
                    "category_id": shopping_category,
                }
            )
        if is_current:
            specs.append(
                {
                    "kind": "expense",
                    "amount_minor": 2_400_000,
                    "currency": "PKR",
                    "merchant": f"Demo one-time outlier {year}-{month:02d}",
                    "txn_date": day_of(max(1, today.day - 2)),
                    "category_id": shopping_category,
                }
            )
    return specs


def _find_or_create_guest(email: str, password: str | None):
    normalized_email = crypto.norm_email(email)
    if not normalized_email.endswith("@example.invalid"):
        raise ValueError("seed email must use the synthetic example.invalid domain")
    email_hmac = crypto.hmac_email(normalized_email)
    with auth_engine.connect() as connection:
        existing = connection.execute(
            text(
                "SELECT user_id, role, status, base_currency "
                "FROM public.users WHERE email_hmac = :email_hmac"
            ),
            {"email_hmac": email_hmac},
        ).first()
    if existing is not None:
        if existing.role != "user" or existing.status != "active":
            raise ValueError("the seed account must be an active guest user")
        if existing.base_currency.strip() != "PKR":
            raise ValueError("the seed account must use PKR as its base currency")
        return existing.user_id
    if password is None:
        password = getpass.getpass("New synthetic guest password: ")
        repeated = getpass.getpass("Repeat synthetic guest password: ")
        if password != repeated:
            raise ValueError("passwords do not match")
    return auth.register_account(
        email=normalized_email,
        password=password,
        base_currency="PKR",
        privacy_consent=True,
        ai_consent=False,
    )


def _clear_old_seed_rows(user_id) -> None:
    matching_ids = []
    with user_tx(user_id) as connection:
        dek, _ = ledger.data_key(connection, user_id)
        rows = connection.execute(
            text(
                "SELECT txn_id, note_enc FROM public.transactions "
                "WHERE deleted_at IS NULL AND note_enc IS NOT NULL"
            )
        ).all()
        for row in rows:
            note = crypto.dec(
                dek,
                bytes(row.note_enc),
                "transactions",
                "note_enc",
                row.txn_id,
            ).decode("utf-8")
            if note == SEED_MARKER:
                matching_ids.append(row.txn_id)
    for txn_id in matching_ids:
        ledger.soft_delete_transaction(user_id, txn_id)


def seed(email: str, password: str | None = None) -> dict[str, int | str]:
    """Insert 90 days of synthetic FX and three months through the real ledger."""
    today = fx.today()
    guest_id = _find_or_create_guest(email, password)
    fx_rows = generate_fx_history(today)
    if fx_engine is None:
        raise RuntimeError("seeding synthetic FX history requires DATABASE_URL_FX (fx_writer)")
    with fx_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO public.fx_rates "
                "(rate_date, quote, rate_per_usd, source) "
                "VALUES (:rate_date, :quote, :rate_per_usd, :source) "
                "ON CONFLICT (rate_date, quote) DO NOTHING"
            ),
            fx_rows,
        )

    _clear_old_seed_rows(guest_id)
    category_ids = {
        name: ledger.shared_category_id(guest_id, name)
        for name in (
            "Food",
            "Transport",
            "Travel",
            "Shopping",
            "Entertainment",
        )
    }
    missing = sorted(name for name, category_id in category_ids.items() if category_id is None)
    if missing:
        raise RuntimeError(
            "shared categories are missing; apply the current Alembic migrations"
        )

    transaction_specs = _transaction_specs(
        today,
        category_ids["Food"],
        category_ids["Transport"],
        category_ids["Travel"],
        category_ids["Shopping"],
        category_ids["Entertainment"],
    )
    for spec in transaction_specs:
        pending = ledger.create_pending(
            user_id=guest_id,
            **spec,
            note=SEED_MARKER,
        )
        if pending is None:
            raise RuntimeError("a synthetic seed transaction was unexpectedly duplicated")
        ledger.confirm(guest_id, pending["txn_id"])

    current_period = today.strftime("%Y-%m")
    save_budget(guest_id, category_ids["Food"], current_period, 3_000_000)
    save_budget(guest_id, category_ids["Transport"], current_period, 250_000)
    return {
        "fx_snapshots": len(fx_rows),
        "transactions": len(transaction_specs),
        "source": "synthetic-demo",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--email",
        default=DEFAULT_GUEST_EMAIL,
        help="fictional guest address; must end in @example.invalid",
    )
    args = parser.parse_args()
    outcome = seed(args.email)
    print(
        "Synthetic demo seed complete: "
        f"{outcome['fx_snapshots']} FX rows, "
        f"{outcome['transactions']} encrypted ledger transactions, "
        f"source={outcome['source']}."
    )


if __name__ == "__main__":
    main()
