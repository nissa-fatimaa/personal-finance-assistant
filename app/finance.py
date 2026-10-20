"""RLS-scoped budgets, FX-aware dashboard calculations, and bill projections."""

from datetime import date
from decimal import Decimal
from fractions import Fraction
from statistics import median
from uuid import UUID, uuid4

from sqlalchemy import text

from app import crypto, engine, fx
from app.audit import append_event
from app.db import user_tx
from app.ledger import MissingObject, data_key, month_bounds
from app.money import EXPONENTS, convert, convert_at_rate


class SuggestionUnavailable(Exception):
    """There is not enough complete, convertible history for a suggestion."""


def _previous_periods(period: str) -> list[str]:
    start, _ = month_bounds(period)
    year, month = start.year, start.month
    result = []
    for _ in range(3):
        month -= 1
        if month == 0:
            year -= 1
            month = 12
        result.append(f"{year:04d}-{month:02d}")
    return list(reversed(result))


def _snapshot_rates(connection, as_of: date, reference_date: date):
    return fx.rates_on(connection, as_of, reference_date=reference_date)


def _convert_amount(
    connection,
    amount_minor: int,
    source: str,
    target: str,
    as_of: date,
    rate_cache: dict[date, fx.RateSnapshot | None],
    *,
    reference_date: date,
    manual_rate: Decimal | None = None,
    base_currency: str | None = None,
) -> tuple[int | None, fx.RateSnapshot | None, str | None]:
    source, target = source.strip(), target.strip()
    source, target = source.upper(), target.upper()
    if source not in EXPONENTS or target not in EXPONENTS:
        return None, None, None
    if source == target:
        return amount_minor, None, "manual" if manual_rate is not None else None

    if manual_rate is not None and base_currency:
        try:
            base_value = convert_at_rate(
                amount_minor, source, base_currency, manual_rate
            )
        except (TypeError, ValueError):
            return None, None, "manual"
        if target == base_currency:
            return base_value, None, "manual"
        if as_of not in rate_cache:
            rate_cache[as_of] = _snapshot_rates(connection, as_of, reference_date)
        snapshot = rate_cache[as_of]
        if snapshot is None:
            return None, None, "manual"
        try:
            result = convert(base_value, base_currency, target, snapshot.rates)
        except (KeyError, TypeError, ValueError):
            return None, snapshot, "manual"
        return result, snapshot, "manual"

    if as_of not in rate_cache:
        rate_cache[as_of] = _snapshot_rates(connection, as_of, reference_date)
    snapshot = rate_cache[as_of]
    if snapshot is None:
        return None, None, None
    try:
        return convert(amount_minor, source, target, snapshot.rates), snapshot, snapshot.source
    except (KeyError, TypeError, ValueError):
        return None, snapshot, snapshot.source


def _decrypt_amount(dek: bytes, row, table: str, column: str, row_id) -> int:
    return int(
        crypto.dec(
            dek, bytes(row[column]), table, column, row_id
        ).decode("ascii")
    )


def _category_name(connection, dek: bytes, category_id: UUID) -> str:
    row = connection.execute(
        text(
            "SELECT name, name_enc FROM public.categories "
            "WHERE category_id = :category_id"
        ),
        {"category_id": category_id},
    ).first()
    if row is None:
        return "Other"
    if row.name is not None:
        return row.name
    return crypto.dec(
        dek,
        bytes(row.name_enc),
        "categories",
        "name_enc",
        category_id,
    ).decode("utf-8")


def _budget_rows(connection, user_id: UUID, dek: bytes, period: str) -> list[dict]:
    rows = connection.execute(
        text(
            "SELECT b.budget_id, b.category_id, b.limit_enc "
            "FROM public.budgets AS b "
            "WHERE b.period = :period ORDER BY b.category_id"
        ),
        {"period": period},
    ).mappings()
    return [
        {
            "budget_id": row["budget_id"],
            "category_id": row["category_id"],
            "category": _category_name(connection, dek, row["category_id"]),
            "limit_minor": _decrypt_amount(
                dek, row, "budgets", "limit_enc", row["budget_id"]
            ),
        }
        for row in rows
    ]


def list_budgets(user_id: UUID, period: str) -> list[dict]:
    month_bounds(period)
    with user_tx(user_id) as connection:
        dek, _ = data_key(connection, user_id)
        budgets = _budget_rows(connection, user_id, dek, period)
    return budgets


def save_budget(
    user_id: UUID, category_id: UUID, period: str, limit_minor: int
) -> dict:
    month_bounds(period)
    if isinstance(limit_minor, bool) or not isinstance(limit_minor, int) or limit_minor < 0:
        raise ValueError("limit_minor must be a non-negative integer")

    with user_tx(user_id) as connection:
        dek, _ = data_key(connection, user_id)
        if connection.execute(
            text("SELECT 1 FROM public.categories WHERE category_id = :category_id"),
            {"category_id": category_id},
        ).first() is None:
            raise MissingObject

        budget_id = uuid4()
        limit_enc = crypto.enc(
            dek,
            str(limit_minor).encode("ascii"),
            "budgets",
            "limit_enc",
            budget_id,
        )
        inserted = connection.execute(
            text(
                "INSERT INTO public.budgets "
                "(budget_id, user_id, category_id, period, limit_enc) "
                "VALUES (:budget_id, :user_id, :category_id, :period, :limit_enc) "
                "ON CONFLICT (user_id, category_id, period) DO NOTHING "
                "RETURNING budget_id"
            ),
            {
                "budget_id": budget_id,
                "user_id": user_id,
                "category_id": category_id,
                "period": period,
                "limit_enc": limit_enc,
            },
        ).first()
        if inserted is None:
            existing_id = connection.execute(
                text(
                    "SELECT budget_id FROM public.budgets "
                    "WHERE user_id = :user_id AND category_id = :category_id "
                    "AND period = :period FOR UPDATE"
                ),
                {"user_id": user_id, "category_id": category_id, "period": period},
            ).scalar_one()
            limit_enc = crypto.enc(
                dek,
                str(limit_minor).encode("ascii"),
                "budgets",
                "limit_enc",
                existing_id,
            )
            connection.execute(
                text(
                    "UPDATE public.budgets SET limit_enc = :limit_enc "
                    "WHERE budget_id = :budget_id"
                ),
                {"limit_enc": limit_enc, "budget_id": existing_id},
            )
            budget_id = existing_id
        append_event(
            connection,
            action="budget_saved",
            result="success",
            actor_user_id=user_id,
            target_id=budget_id,
        )
    return {
        "budget_id": budget_id,
        "category_id": category_id,
        "period": period,
        "limit_minor": limit_minor,
    }


def get_budget_suggestions(user_id: UUID, period: str) -> dict:
    month_bounds(period)
    previous = _previous_periods(period)
    period_starts = [month_bounds(item)[0] for item in previous]
    query_start = period_starts[0]
    target_start, _ = month_bounds(period)

    with user_tx(user_id) as connection:
        dek, base_currency = data_key(connection, user_id)
        rows = connection.execute(
            text(
                "SELECT txn_id, category_id, kind, currency, amount_enc, fee_enc, "
                "fx_override_rate, txn_date, fx_date "
                "FROM public.transactions "
                "WHERE txn_date >= :start_date AND txn_date < :end_date "
                "AND status = 'posted' AND deleted_at IS NULL "
                "AND kind IN ('expense', 'refund', 'income') "
                "ORDER BY txn_date, txn_id"
            ),
            {"start_date": query_start, "end_date": target_start},
        ).mappings()
        spend: dict[str, dict[str, int]] = {}
        incomes = {month: 0 for month in previous}
        rates_cache: dict[date, fx.RateSnapshot | None] = {}
        unavailable_currencies: set[str] = set()
        months_covered: set[str] = set()

        for row in rows:
            amount = _decrypt_amount(dek, row, "transactions", "amount_enc", row["txn_id"])
            currency = row["currency"].strip()
            manual_rate = (
                Decimal(row["fx_override_rate"])
                if row["fx_override_rate"] is not None
                else None
            )
            base_amount, _, _ = _convert_amount(
                connection,
                amount,
                currency,
                base_currency,
                row["fx_date"],
                rates_cache,
                reference_date=fx.today(),
                manual_rate=manual_rate,
                base_currency=base_currency,
            )
            if base_amount is None:
                unavailable_currencies.add(currency)
                continue
            fee_base_amount = 0
            if row["fee_enc"] is not None and row["kind"] != "income":
                fee_minor = _decrypt_amount(
                    dek, row, "transactions", "fee_enc", row["txn_id"]
                )
                fee_base, _, _ = _convert_amount(
                    connection,
                    fee_minor,
                    currency,
                    base_currency,
                    row["fx_date"],
                    rates_cache,
                    reference_date=fx.today(),
                    manual_rate=manual_rate,
                    base_currency=base_currency,
                )
                if fee_base is None:
                    unavailable_currencies.add(currency)
                    continue
                fee_base_amount = fee_base
            transaction_month = row["txn_date"].strftime("%Y-%m")
            months_covered.add(transaction_month)
            if row["kind"] == "income":
                incomes[transaction_month] += base_amount
            elif row["category_id"] is not None:
                category_key = str(row["category_id"])
                month_spend = spend.setdefault(category_key, {month: 0 for month in previous})
                month_spend[transaction_month] += (
                    (-base_amount if row["kind"] == "refund" else base_amount)
                    + fee_base_amount
                )

        if unavailable_currencies:
            return {
                "period": period,
                "available": False,
                "reason": "fx_rate_unavailable",
                "unavailable_currencies": sorted(unavailable_currencies),
                "suggestions": [],
            }

        if months_covered != set(previous):
            return {
                "period": period,
                "available": False,
                "reason": "insufficient_history",
                "unavailable_currencies": [],
                "suggestions": [],
            }

        expected_income = int(median(list(incomes.values()))) if incomes else None
        suggestions = engine.suggest_budget(
            {category: [spend[category][month] for month in previous] for category in spend},
            expected_income,
        )
        result = []
        for category_text, suggestion in suggestions.items():
            category_id = UUID(category_text)
            result.append(
                {
                    "category_id": category_id,
                    "category": _category_name(connection, dek, category_id),
                    "limit_minor": suggestion.limit_minor,
                    "scaled_to_ceiling": suggestion.scaled_to_ceiling,
                }
            )
        return {
            "period": period,
            "available": bool(result),
            "reason": None if result else "no_category_history",
            "expected_monthly_income_minor": expected_income,
            "suggestions": result,
        }


def approve_budget_suggestion(
    user_id: UUID, category_id: UUID, period: str
) -> dict:
    suggestions = get_budget_suggestions(user_id, period)
    if not suggestions["available"]:
        raise SuggestionUnavailable
    match = next(
        (
            item
            for item in suggestions["suggestions"]
            if item["category_id"] == category_id
        ),
        None,
    )
    if match is None:
        raise SuggestionUnavailable
    saved = save_budget(user_id, category_id, period, match["limit_minor"])
    return {
        **saved,
        "approved_suggestion": True,
        "scaled_to_ceiling": match["scaled_to_ceiling"],
    }


def _round_fraction(value: Fraction) -> int:
    sign = -1 if value < 0 else 1
    numerator = abs(value.numerator)
    quotient, remainder = divmod(numerator, value.denominator)
    if remainder * 2 >= value.denominator:
        quotient += 1
    return sign * quotient


def _fraction_to_minor(value: Fraction, currency: str) -> int:
    return _round_fraction(value * (10**EXPONENTS[currency]))


def _fx_effect_insights(
    connection,
    rows,
    dek: bytes,
    previous_month: str,
    current_month: str,
    base_currency: str,
    policy: str,
    today: date,
    rate_cache: dict[date, fx.RateSnapshot | None],
    snapshots_used: dict[date, fx.RateSnapshot],
    rate_sources: set[str],
) -> list[dict]:
    totals: dict[str, dict[str, dict[str, object]]] = {}
    for row in rows:
        row_month = row["txn_date"].strftime("%Y-%m")
        if row_month not in {previous_month, current_month}:
            continue
        if row["kind"] not in {"expense", "refund"}:
            continue
        currency = row["currency"].strip().upper()
        if currency == base_currency:
            continue

        sign = -1 if row["kind"] == "refund" else 1
        amount = _decrypt_amount(
            dek, row, "transactions", "amount_enc", row["txn_id"]
        )
        fee = (
            _decrypt_amount(
                dek,
                row,
                "transactions",
                "fee_enc",
                row["txn_id"],
            )
            if row["fee_enc"] is not None
            else 0
        )
        as_of = row["fx_date"] if policy == "as_recorded" else today
        manual_rate = (
            Decimal(row["fx_override_rate"])
            if policy == "as_recorded" and row["fx_override_rate"] is not None
            else None
        )
        converted, snapshot, rate_source = _convert_amount(
            connection,
            amount,
            currency,
            base_currency,
            as_of,
            rate_cache,
            reference_date=today,
            manual_rate=manual_rate,
            base_currency=base_currency,
        )
        fee_converted = 0
        if fee:
            fee_converted, fee_snapshot, fee_source = _convert_amount(
                connection,
                fee,
                currency,
                base_currency,
                as_of,
                rate_cache,
                reference_date=today,
                manual_rate=manual_rate,
                base_currency=base_currency,
            )
            if fee_snapshot is not None:
                snapshots_used[fee_snapshot.rate_date] = fee_snapshot
            if fee_source:
                rate_sources.add(fee_source)
            if fee_converted is None:
                converted = None
        if snapshot is not None:
            snapshots_used[snapshot.rate_date] = snapshot
        if rate_source:
            rate_sources.add(rate_source)

        month_total = totals.setdefault(currency, {}).setdefault(
            row_month,
            {
                "original": Fraction(0),
                "base": Fraction(0),
                "has_transactions": False,
                "has_rates": False,
                "valid": True,
            },
        )
        month_total["has_transactions"] = True
        if converted is None:
            month_total["valid"] = False
            continue
        if snapshot is None and rate_source != "manual":
            month_total["has_rates"] = False
            month_total["valid"] = False
            continue
        month_total["has_rates"] = True
        original_minor = sign * amount + fee
        base_minor = sign * converted + (fee_converted or 0)
        month_total["original"] += Fraction(
            original_minor, 10**EXPONENTS[currency]
        )
        month_total["base"] += Fraction(
            base_minor, 10**EXPONENTS[base_currency]
        )

    result = []
    for currency in sorted(totals):
        previous = totals[currency].get(previous_month)
        current = totals[currency].get(current_month)
        if not previous or not current:
            continue
        if not all(
            item["has_transactions"] and item["has_rates"] and item["valid"]
            for item in (previous, current)
        ):
            continue
        effects = engine.fx_decomposition(
            previous["original"],
            current["original"],
            previous["base"],
            current["base"],
        )
        if effects is None:
            continue
        volume_effect_minor = _fraction_to_minor(
            effects["volume_effect"], base_currency
        )
        base_change_minor = _fraction_to_minor(
            effects["base_change"], base_currency
        )
        result.append(
            {
                "currency": currency,
                "base_currency": base_currency,
                "previous_month": previous_month,
                "month": current_month,
                "volume_effect_minor": volume_effect_minor,
                # Assign the final minor-unit rounding remainder here so the
                # displayed integer effects reconcile exactly to the change.
                "rate_effect_minor": base_change_minor - volume_effect_minor,
                "base_change_minor": base_change_minor,
                "exact_identity": True,
            }
        )
    return result


def dashboard(
    user_id: UUID,
    month: str,
    report_currency: str | None = None,
    policy: str = "as_recorded",
) -> dict:
    start, end = month_bounds(month)
    if policy not in {"as_recorded", "current"}:
        raise ValueError("policy must be as_recorded or current")

    today = fx.today()
    fx.ensure_today(day=today)
    today_period = today.strftime("%Y-%m")
    days_in_month = (end - start).days
    day = min(today.day, days_in_month)
    if month < today_period:
        day = (end - start).days
    elif month > today_period:
        day = 1

    with user_tx(user_id) as connection:
        dek, base_currency = data_key(connection, user_id)
        report_currency = (report_currency or base_currency).upper()
        if report_currency not in EXPONENTS:
            raise ValueError("unsupported currency")

        txn_rows = connection.execute(
            text(
                "SELECT txn_id, category_id, kind, currency, amount_enc, fee_enc, "
                "fx_override_rate, txn_date, fx_date "
                "FROM public.transactions "
                "WHERE txn_date >= :start_date AND txn_date < :end_date "
                "AND status = 'posted' AND deleted_at IS NULL "
                "ORDER BY txn_date, txn_id"
            ),
            {"start_date": start, "end_date": end},
        ).mappings().all()
        pending_count = connection.execute(
            text(
                "SELECT count(*) FROM public.transactions "
                "WHERE txn_date >= :start_date AND txn_date < :end_date "
                "AND status = 'pending' AND deleted_at IS NULL"
            ),
            {"start_date": start, "end_date": end},
        ).scalar_one()

        budgets = _budget_rows(connection, user_id, dek, month)
        budget_by_category = {
            str(item["category_id"]): item["limit_minor"] for item in budgets
        }
        category_names = {
            str(item["category_id"]): item["category"] for item in budgets
        }
        rates_cache: dict[date, fx.RateSnapshot | None] = {}
        snapshots_used: dict[date, fx.RateSnapshot] = {}
        rate_sources: set[str] = set()
        manual_override_count = 0
        unavailable_currencies: set[str] = set()
        category_spend: dict[str, int] = {}
        income_base = expenses_base = 0
        income_report = expenses_report = 0
        fees_base = fees_report = 0
        base_complete = report_complete = True

        for row in txn_rows:
            amount = _decrypt_amount(dek, row, "transactions", "amount_enc", row["txn_id"])
            source = row["currency"].strip()
            as_of = row["fx_date"] if policy == "as_recorded" else today
            manual_rate = (
                Decimal(row["fx_override_rate"])
                if policy == "as_recorded" and row["fx_override_rate"] is not None
                else None
            )
            if manual_rate is not None:
                manual_override_count += 1
            base_value, base_snapshot, base_source = _convert_amount(
                connection,
                amount,
                source,
                base_currency,
                as_of,
                rates_cache,
                reference_date=today,
                manual_rate=manual_rate,
                base_currency=base_currency,
            )
            report_value, report_snapshot, report_source = _convert_amount(
                connection,
                amount,
                source,
                report_currency,
                as_of,
                rates_cache,
                reference_date=today,
                manual_rate=manual_rate,
                base_currency=base_currency,
            )
            for snapshot, rate_source in (
                (base_snapshot, base_source),
                (report_snapshot, report_source),
            ):
                if snapshot is not None:
                    snapshots_used[snapshot.rate_date] = snapshot
                if rate_source:
                    rate_sources.add(rate_source)

            fee_minor = (
                _decrypt_amount(dek, row, "transactions", "fee_enc", row["txn_id"])
                if row["fee_enc"] is not None
                else 0
            )
            fee_base = fee_report = 0
            if fee_minor:
                fee_base_value, fee_base_snapshot, fee_base_source = _convert_amount(
                    connection,
                    fee_minor,
                    source,
                    base_currency,
                    as_of,
                    rates_cache,
                    reference_date=today,
                    manual_rate=manual_rate,
                    base_currency=base_currency,
                )
                fee_report_value, fee_report_snapshot, fee_report_source = _convert_amount(
                    connection,
                    fee_minor,
                    source,
                    report_currency,
                    as_of,
                    rates_cache,
                    reference_date=today,
                    manual_rate=manual_rate,
                    base_currency=base_currency,
                )
                for snapshot, rate_source in (
                    (fee_base_snapshot, fee_base_source),
                    (fee_report_snapshot, fee_report_source),
                ):
                    if snapshot is not None:
                        snapshots_used[snapshot.rate_date] = snapshot
                    if rate_source:
                        rate_sources.add(rate_source)
                if fee_base_value is None:
                    base_complete = False
                    unavailable_currencies.add(source)
                else:
                    fee_base = fee_base_value
                if fee_report_value is None:
                    report_complete = False
                    unavailable_currencies.add(source)
                else:
                    fee_report = fee_report_value
                if manual_rate is not None:
                    rate_sources.add("manual")

            if base_value is None:
                base_complete = False
                unavailable_currencies.add(source)
            if report_value is None:
                report_complete = False
                unavailable_currencies.add(source)

            if row["kind"] == "income":
                if base_value is not None:
                    income_base += base_value
                if report_value is not None:
                    income_report += report_value
            elif row["kind"] in {"expense", "refund"}:
                sign = -1 if row["kind"] == "refund" else 1
                if base_value is not None:
                    expenses_base += sign * base_value
                    if row["category_id"] is not None:
                        key = str(row["category_id"])
                        category_spend[key] = category_spend.get(key, 0) + sign * base_value
                        if key not in category_names:
                            category_names[key] = _category_name(
                                connection, dek, row["category_id"]
                            )
                if report_value is not None:
                    expenses_report += sign * report_value
            # Transfers are deliberately absent from all spend and income totals.
            if fee_minor:
                fees_base += fee_base
                fees_report += fee_report
                expenses_base += fee_base
                expenses_report += fee_report
                if row["category_id"] is not None and row["kind"] in {"expense", "refund"}:
                    key = str(row["category_id"])
                    category_spend[key] = category_spend.get(key, 0) + fee_base

        unpaid_bills = 0
        bills_complete = True
        bill_rows = connection.execute(
            text(
                "SELECT bill_id, amount_enc, currency, next_due_date "
                "FROM public.bills WHERE deleted_at IS NULL AND is_active "
                "AND next_due_date >= :start_date AND next_due_date < :end_date"
            ),
            {"start_date": start, "end_date": end},
        ).mappings()
        for row in bill_rows:
            amount = _decrypt_amount(dek, row, "bills", "amount_enc", row["bill_id"])
            value, snapshot, rate_source = _convert_amount(
                connection,
                amount,
                row["currency"],
                base_currency,
                row["next_due_date"] if policy == "as_recorded" else today,
                rates_cache,
                reference_date=today,
            )
            if snapshot is not None:
                snapshots_used[snapshot.rate_date] = snapshot
            if rate_source:
                rate_sources.add(rate_source)
            if value is None:
                bills_complete = False
                unavailable_currencies.add(row["currency"].strip())
            else:
                unpaid_bills += value

        previous_month = _previous_periods(month)[-1]
        previous_start, _ = month_bounds(previous_month)
        fx_effect_rows = connection.execute(
            text(
                "SELECT txn_id, category_id, kind, currency, amount_enc, fee_enc, "
                "fx_override_rate, txn_date, fx_date FROM public.transactions "
                "WHERE txn_date >= :previous_start AND txn_date < :month_end "
                "AND status = 'posted' AND deleted_at IS NULL "
                "AND kind IN ('expense', 'refund') "
                "ORDER BY txn_date, txn_id"
            ),
            {"previous_start": previous_start, "month_end": end},
        ).mappings().all()
        fx_effects = _fx_effect_insights(
            connection,
            fx_effect_rows,
            dek,
            previous_month,
            month,
            base_currency,
            policy,
            today,
            rates_cache,
            snapshots_used,
            rate_sources,
        )

        categories = []
        safe_categories = []
        alerts = []
        for category_key in sorted(set(budget_by_category) | set(category_spend)):
            category_id = UUID(category_key)
            limit = budget_by_category.get(category_key, 0)
            spent = category_spend.get(category_key, 0)
            if not base_complete:
                item = {
                    "category_id": category_id,
                    "name": category_names.get(
                        category_key, _category_name(connection, dek, category_id)
                    ),
                    "limit_minor": limit,
                    "spent_minor": None,
                    "status": "unavailable",
                    "pace": None,
                    "daily_cap_minor": None,
                    "currency": base_currency,
                }
            else:
                pace = engine.pace_ratio(limit, spent, day, (end - start).days)
                daily = engine.daily_cap(limit, spent, day, (end - start).days)
                state = engine.status(limit, spent)
                item = {
                    "category_id": category_id,
                    "name": category_names.get(
                        category_key, _category_name(connection, dek, category_id)
                    ),
                    "limit_minor": limit,
                    "spent_minor": spent,
                    "status": state,
                    "pace": str(pace.quantize(Decimal("0.01"))) if pace is not None else None,
                    "daily_cap_minor": daily,
                    "currency": base_currency,
                }
                if limit > 0:
                    safe_categories.append((limit, spent))
                if state in {"critical", "caution"}:
                    alerts.append({"category_id": category_id, "status": state})
            categories.append(item)

        forecast_value = None
        if (
            month == today_period
            and base_complete
            and bills_complete
        ):
            forecast_value = engine.forecast(
                expenses_base,
                day,
                (end - start).days,
                len(txn_rows),
                unpaid_bills,
            )
        safe_value = (
            engine.safe_to_spend(safe_categories, day, (end - start).days)
            if base_complete
            else None
        )

        snapshot_records = [
            {
                "date": snapshot.rate_date.isoformat(),
                "age_days": snapshot.age_days,
                "source": snapshot.source,
                "estimated": snapshot.estimated,
            }
            for snapshot in sorted(
                snapshots_used.values(), key=lambda item: item.rate_date
            )
        ]
        latest_snapshot = max(
            snapshots_used.values(),
            key=lambda item: item.rate_date,
            default=None,
        )
        return {
            "month": month,
            "base_currency": base_currency,
            "report_currency": report_currency,
            "policy": policy,
            "rates_snapshot": (
                latest_snapshot.rate_date.isoformat() if latest_snapshot else None
            ),
            "rates_snapshot_age_days": (
                latest_snapshot.age_days if latest_snapshot else None
            ),
            "fx_snapshots": snapshot_records,
            "rate_sources": sorted(rate_sources),
            "manual_rate_override_count": manual_override_count,
            "rate_attribution": "Rates By Exchange Rate API",
            "rate_attribution_url": "https://www.exchangerate-api.com",
            "income_minor": income_report if report_complete else None,
            "expenses_minor": expenses_report if report_complete else None,
            "fees_minor": fees_report if report_complete else None,
            "fees_currency": report_currency,
            "categories": categories,
            "safe_to_spend_today_minor": safe_value,
            "safe_to_spend_currency": base_currency,
            "forecast_minor": forecast_value,
            "forecast_currency": base_currency,
            "forecast_label": "estimate" if forecast_value is not None else None,
            "alerts": alerts,
            "pending_count": pending_count,
            "analytics_available": base_complete,
            "report_conversion_available": report_complete,
            "unavailable_currencies": sorted(unavailable_currencies),
            "fx_effects": fx_effects,
        }
