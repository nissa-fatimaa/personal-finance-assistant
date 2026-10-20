"""Tenant-scoped encrypted transaction and bill persistence."""

from datetime import date
from decimal import Decimal, InvalidOperation
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app import crypto
from app.audit import append_event
from app.db import user_tx
from app.money import EXPONENTS


class MissingObject(Exception):
    """An object is absent or hidden by row-level security."""


def month_bounds(month: str) -> tuple[date, date]:
    """Return the inclusive start and exclusive end for a YYYY-MM period."""
    if len(month) != 7 or month[4] != "-":
        raise ValueError("month must be YYYY-MM")
    start = date.fromisoformat(f"{month}-01")
    if start.month == 12:
        end = date(start.year + 1, 1, 1)
    else:
        end = date(start.year, start.month + 1, 1)
    return start, end


def data_key(connection, user_id: UUID) -> tuple[bytes, str]:
    row = connection.execute(
        text(
            "SELECT dek_wrapped, base_currency FROM public.users "
            "WHERE user_id = :user_id"
        ),
        {"user_id": user_id},
    ).first()
    if row is None:
        raise MissingObject
    return crypto.unwrap_dek(bytes(row.dek_wrapped), user_id), row.base_currency.strip()


def get_base_currency(user_id: UUID) -> str:
    with user_tx(user_id) as connection:
        row = connection.execute(
            text("SELECT base_currency FROM public.users WHERE user_id = :user_id"),
            {"user_id": user_id},
        ).first()
        if row is None:
            raise MissingObject
        return row.base_currency.strip()


def shared_category_id(user_id: UUID, name: str) -> UUID | None:
    with user_tx(user_id) as connection:
        return connection.execute(
            text(
                "SELECT category_id FROM public.categories "
                "WHERE user_id IS NULL AND lower(name) = lower(:name) "
                "LIMIT 1"
            ),
            {"name": name},
        ).scalar_one_or_none()


def _category_is_visible(connection, category_id: UUID) -> bool:
    return (
        connection.execute(
            text(
                "SELECT 1 FROM public.categories WHERE category_id = :category_id"
            ),
            {"category_id": category_id},
        ).first()
        is not None
    )


def _account_is_owned(connection, account_id: UUID) -> bool:
    return (
        connection.execute(
            text(
                "SELECT 1 FROM public.accounts WHERE account_id = :account_id "
                "AND deleted_at IS NULL"
            ),
            {"account_id": account_id},
        ).first()
        is not None
    )


def _is_dedupe_conflict(error: IntegrityError) -> bool:
    diagnostic = getattr(error.orig, "diag", None)
    return getattr(diagnostic, "constraint_name", None) == "txn_dedupe"


def _validated_override_rate(value: str | Decimal | None) -> Decimal | None:
    if value is None:
        return None
    if isinstance(value, (float, bool)):
        raise TypeError("fx_override_rate must be a decimal string")
    try:
        rate = Decimal(value)
    except (InvalidOperation, TypeError, ValueError):
        raise ValueError("invalid fx_override_rate") from None
    if not rate.is_finite() or rate <= 0:
        raise ValueError("fx_override_rate must be positive and finite")
    if rate.as_tuple().exponent < -10 or rate >= Decimal("10000000000"):
        raise ValueError("fx_override_rate exceeds supported precision")
    return rate


def create_pending(
    *,
    user_id: UUID,
    kind: str,
    amount_minor: int,
    currency: str,
    merchant: str,
    txn_date: date,
    category_id: UUID | None = None,
    account_id: UUID | None = None,
    note: str | None = None,
    fee_minor: int | None = None,
    fx_override_rate: str | Decimal | None = None,
    source: str = "manual",
    fallback_category_id: UUID | None = None,
) -> dict | None:
    """Encrypt and insert a pending row; None means the unique dedupe index fired."""
    currency = currency.upper()
    merchant = merchant.strip()
    if currency not in EXPONENTS:
        raise ValueError("unsupported currency")
    if kind not in {"expense", "income", "refund", "transfer"}:
        raise ValueError("unsupported transaction kind")
    if source not in {"manual", "chat", "receipt"}:
        raise ValueError("unsupported transaction source")
    if isinstance(amount_minor, bool) or not isinstance(amount_minor, int) or amount_minor <= 0:
        raise ValueError("amount_minor must be a positive integer")
    if fee_minor is not None and (
        isinstance(fee_minor, bool) or not isinstance(fee_minor, int) or fee_minor < 0
    ):
        raise ValueError("fee_minor must be a non-negative integer")
    override_rate = _validated_override_rate(fx_override_rate)
    if not merchant:
        raise ValueError("merchant is required")

    txn_id = uuid4()
    merchant_hash = crypto.merchant_hmac(user_id, merchant)
    dedupe_hash = crypto.dedupe_hmac(
        user_id, merchant, amount_minor, currency, txn_date
    )
    try:
        with user_tx(user_id) as connection:
            dek, _ = data_key(connection, user_id)
            if account_id is not None and not _account_is_owned(connection, account_id):
                raise MissingObject
            if category_id is not None and not _category_is_visible(connection, category_id):
                raise MissingObject
            if (
                fallback_category_id is not None
                and not _category_is_visible(connection, fallback_category_id)
            ):
                raise MissingObject
            suggested_category_id = category_id
            if suggested_category_id is None:
                suggested_category_id = connection.execute(
                    text(
                        "SELECT category_id FROM public.transactions "
                        "WHERE merchant_hmac = :merchant_hmac "
                        "AND status = 'posted' AND deleted_at IS NULL "
                        "AND category_id IS NOT NULL "
                        "ORDER BY txn_date DESC, created_at DESC LIMIT 1"
                    ),
                    {"merchant_hmac": merchant_hash},
                ).scalar_one_or_none()
            if suggested_category_id is None:
                suggested_category_id = fallback_category_id

            connection.execute(
                text(
                    "INSERT INTO public.transactions "
                    "(txn_id, user_id, account_id, category_id, kind, status, "
                    "currency, amount_enc, merchant_enc, note_enc, fee_enc, "
                    "merchant_hmac, dedupe_hmac, txn_date, fx_date, "
                    "fx_override_rate, source) "
                    "VALUES (:txn_id, :user_id, :account_id, :category_id, :kind, "
                    "'pending', :currency, :amount_enc, :merchant_enc, :note_enc, "
                    ":fee_enc, :merchant_hmac, :dedupe_hmac, :txn_date, :fx_date, "
                    ":fx_override_rate, :source)"
                ),
                {
                    "txn_id": txn_id,
                    "user_id": user_id,
                    "account_id": account_id,
                    "category_id": suggested_category_id,
                    "kind": kind,
                    "currency": currency,
                    "amount_enc": crypto.enc(
                        dek,
                        str(amount_minor).encode("ascii"),
                        "transactions",
                        "amount_enc",
                        txn_id,
                    ),
                    "merchant_enc": crypto.enc(
                        dek, merchant.encode("utf-8"), "transactions", "merchant_enc", txn_id
                    ),
                    "note_enc": (
                        crypto.enc(
                            dek, note.encode("utf-8"), "transactions", "note_enc", txn_id
                        )
                        if note
                        else None
                    ),
                    "fee_enc": (
                        crypto.enc(
                            dek,
                            str(fee_minor).encode("ascii"),
                            "transactions",
                            "fee_enc",
                            txn_id,
                        )
                        if fee_minor is not None
                        else None
                    ),
                    "merchant_hmac": merchant_hash,
                    "dedupe_hmac": dedupe_hash,
                    "txn_date": txn_date,
                    "fx_date": txn_date,
                    "fx_override_rate": override_rate,
                    "source": source,
                },
            )
            append_event(
                connection,
                action="txn_pending",
                result="success",
                actor_user_id=user_id,
                target_id=txn_id,
            )
    except IntegrityError as error:
        if _is_dedupe_conflict(error):
            return None
        raise
    return {
        "txn_id": txn_id,
        "status": "pending",
        "category_id": suggested_category_id,
        "suggested_category_id": suggested_category_id,
        "fee_minor": fee_minor,
        "fx_override_rate": str(override_rate) if override_rate is not None else None,
        "fx_rate_source": "manual" if override_rate is not None else None,
    }


def confirm(user_id: UUID, txn_id: UUID) -> None:
    with user_tx(user_id) as connection:
        row = connection.execute(
            text(
                "UPDATE public.transactions SET status = 'posted' "
                "WHERE txn_id = :txn_id AND status = 'pending' "
                "AND deleted_at IS NULL RETURNING txn_id"
            ),
            {"txn_id": txn_id},
        ).first()
        if row is None:
            append_event(
                connection,
                action="object_denied",
                result="deny",
                actor_user_id=user_id,
                target_id=txn_id,
            )
        else:
            append_event(
                connection,
                action="txn_posted",
                result="success",
                actor_user_id=user_id,
                target_id=txn_id,
            )
    if row is None:
        raise MissingObject


def update_pending_transaction_date(
    *, user_id: UUID, txn_id: UUID, txn_date: date
) -> None:
    """Change the date of an owned pending record and refresh deduplication data."""
    try:
        missing = False
        with user_tx(user_id) as connection:
            dek, _ = data_key(connection, user_id)
            row = connection.execute(
                text(
                    "SELECT currency, amount_enc, merchant_enc "
                    "FROM public.transactions "
                    "WHERE txn_id = :txn_id AND user_id = :user_id "
                    "AND status = 'pending' AND deleted_at IS NULL "
                    "FOR UPDATE"
                ),
                {"txn_id": txn_id, "user_id": user_id},
            ).mappings().first()
            if row is None:
                append_event(
                    connection,
                    action="object_denied",
                    result="deny",
                    actor_user_id=user_id,
                    target_id=txn_id,
                )
                missing = True
            else:
                amount = int(
                    crypto.dec(
                        dek, bytes(row["amount_enc"]), "transactions", "amount_enc", txn_id
                    ).decode("ascii")
                )
                merchant = crypto.dec(
                    dek, bytes(row["merchant_enc"]), "transactions", "merchant_enc", txn_id
                ).decode("utf-8")
                dedupe_hash = crypto.dedupe_hmac(
                    user_id, merchant, amount, row["currency"], txn_date
                )
                connection.execute(
                    text(
                        "UPDATE public.transactions SET txn_date = :txn_date, "
                        "fx_date = :txn_date, dedupe_hmac = :dedupe_hmac "
                        "WHERE txn_id = :txn_id AND user_id = :user_id "
                        "AND status = 'pending' AND deleted_at IS NULL"
                    ),
                    {
                        "txn_id": txn_id,
                        "user_id": user_id,
                        "txn_date": txn_date,
                        "dedupe_hmac": dedupe_hash,
                    },
                )
                append_event(
                    connection,
                    action="txn_updated",
                    result="success",
                    actor_user_id=user_id,
                    target_id=txn_id,
                )
        if missing:
            raise MissingObject
    except IntegrityError as error:
        if _is_dedupe_conflict(error):
            raise ValueError("possible duplicate") from None
        raise


def _transaction_from_row(dek: bytes, row) -> dict:
    txn_id = row["txn_id"]
    amount = crypto.dec(
        dek,
        bytes(row["amount_enc"]),
        "transactions",
        "amount_enc",
        txn_id,
    )
    merchant = (
        crypto.dec(
            dek,
            bytes(row["merchant_enc"]),
            "transactions",
            "merchant_enc",
            txn_id,
        ).decode("utf-8")
        if row["merchant_enc"] is not None
        else None
    )
    note = (
        crypto.dec(
            dek, bytes(row["note_enc"]), "transactions", "note_enc", txn_id
        ).decode("utf-8")
        if row["note_enc"] is not None
        else None
    )
    fee_minor = (
        int(
            crypto.dec(
                dek,
                bytes(row["fee_enc"]),
                "transactions",
                "fee_enc",
                txn_id,
            ).decode("ascii")
        )
        if row["fee_enc"] is not None
        else None
    )
    return {
        "txn_id": txn_id,
        "category_id": row["category_id"],
        "account_id": row["account_id"],
        "kind": row["kind"],
        "status": row["status"],
        "currency": row["currency"].strip(),
        "amount_minor": int(amount.decode("ascii")),
        "merchant": merchant,
        "note": note,
        "fee_minor": fee_minor,
        "txn_date": row["txn_date"],
        "fx_date": row["fx_date"],
        "fx_override_rate": (
            str(row["fx_override_rate"])
            if row["fx_override_rate"] is not None
            else None
        ),
        "fx_rate_source": "manual" if row["fx_override_rate"] is not None else None,
        "source": row["source"],
    }


def get_transaction(user_id: UUID, txn_id: UUID) -> dict:
    """Return one posted, non-deleted transaction owned by the caller."""
    result = None
    with user_tx(user_id) as connection:
        dek, _ = data_key(connection, user_id)
        row = connection.execute(
            text(
                "SELECT txn_id, category_id, account_id, kind, status, currency, "
                "amount_enc, merchant_enc, note_enc, fee_enc, txn_date, fx_date, "
                "fx_override_rate, source "
                "FROM public.transactions "
                "WHERE txn_id = :txn_id AND user_id = :user_id "
                "AND status = 'posted' AND deleted_at IS NULL"
            ),
            {"txn_id": txn_id, "user_id": user_id},
        ).mappings().first()
        if row is None:
            append_event(
                connection,
                action="object_denied",
                result="deny",
                actor_user_id=user_id,
                target_id=txn_id,
            )
        else:
            result = _transaction_from_row(dek, row)
    if result is None:
        raise MissingObject
    return result


def update_transaction(
    *,
    user_id: UUID,
    txn_id: UUID,
    kind: str,
    amount_minor: int,
    currency: str,
    merchant: str,
    txn_date: date,
    category_id: UUID | None = None,
    account_id: UUID | None = None,
    note: str | None = None,
    fee_minor: int | None = None,
    fx_override_rate: str | Decimal | None = None,
) -> None:
    """Update an owned posted transaction while preserving encrypted storage."""
    currency = currency.upper()
    merchant = merchant.strip()
    if currency not in EXPONENTS:
        raise ValueError("unsupported currency")
    if kind not in {"expense", "income", "refund", "transfer"}:
        raise ValueError("unsupported transaction kind")
    if isinstance(amount_minor, bool) or not isinstance(amount_minor, int) or amount_minor <= 0:
        raise ValueError("amount_minor must be a positive integer")
    if fee_minor is not None and (
        isinstance(fee_minor, bool) or not isinstance(fee_minor, int) or fee_minor < 0
    ):
        raise ValueError("fee_minor must be a non-negative integer")
    override_rate = _validated_override_rate(fx_override_rate)
    if not merchant:
        raise ValueError("merchant is required")

    merchant_hash = crypto.merchant_hmac(user_id, merchant)
    dedupe_hash = crypto.dedupe_hmac(
        user_id, merchant, amount_minor, currency, txn_date
    )
    try:
        missing = False
        with user_tx(user_id) as connection:
            dek, _ = data_key(connection, user_id)
            if account_id is not None and not _account_is_owned(connection, account_id):
                raise MissingObject
            if category_id is not None and not _category_is_visible(connection, category_id):
                raise MissingObject

            row = connection.execute(
                text(
                    "UPDATE public.transactions SET "
                    "account_id = :account_id, category_id = :category_id, "
                    "kind = :kind, currency = :currency, amount_enc = :amount_enc, "
                    "merchant_enc = :merchant_enc, note_enc = :note_enc, "
                    "fee_enc = :fee_enc, merchant_hmac = :merchant_hmac, "
                    "dedupe_hmac = :dedupe_hmac, txn_date = :txn_date, "
                    "fx_date = :fx_date, fx_override_rate = :fx_override_rate "
                    "WHERE txn_id = :txn_id AND user_id = :user_id "
                    "AND status = 'posted' AND deleted_at IS NULL "
                    "RETURNING txn_id"
                ),
                {
                    "txn_id": txn_id,
                    "user_id": user_id,
                    "account_id": account_id,
                    "category_id": category_id,
                    "kind": kind,
                    "currency": currency,
                    "amount_enc": crypto.enc(
                        dek,
                        str(amount_minor).encode("ascii"),
                        "transactions",
                        "amount_enc",
                        txn_id,
                    ),
                    "merchant_enc": crypto.enc(
                        dek,
                        merchant.encode("utf-8"),
                        "transactions",
                        "merchant_enc",
                        txn_id,
                    ),
                    "note_enc": (
                        crypto.enc(
                            dek, note.encode("utf-8"), "transactions", "note_enc", txn_id
                        )
                        if note
                        else None
                    ),
                    "fee_enc": (
                        crypto.enc(
                            dek,
                            str(fee_minor).encode("ascii"),
                            "transactions",
                            "fee_enc",
                            txn_id,
                        )
                        if fee_minor is not None
                        else None
                    ),
                    "merchant_hmac": merchant_hash,
                    "dedupe_hmac": dedupe_hash,
                    "txn_date": txn_date,
                    "fx_date": txn_date,
                    "fx_override_rate": override_rate,
                },
            ).first()
            if row is None:
                append_event(
                    connection,
                    action="object_denied",
                    result="deny",
                    actor_user_id=user_id,
                    target_id=txn_id,
                )
                missing = True
            else:
                append_event(
                    connection,
                    action="txn_updated",
                    result="success",
                    actor_user_id=user_id,
                    target_id=txn_id,
                )
        if missing:
            raise MissingObject
    except IntegrityError as error:
        if _is_dedupe_conflict(error):
            raise ValueError("possible duplicate") from None
        raise


def soft_delete_transaction(user_id: UUID, txn_id: UUID) -> None:
    with user_tx(user_id) as connection:
        row = connection.execute(
            text(
                "UPDATE public.transactions SET deleted_at = now() "
                "WHERE txn_id = :txn_id AND deleted_at IS NULL "
                "RETURNING txn_id"
            ),
            {"txn_id": txn_id},
        ).first()
        if row is None:
            append_event(
                connection,
                action="object_denied",
                result="deny",
                actor_user_id=user_id,
                target_id=txn_id,
            )
        else:
            append_event(
                connection,
                action="txn_deleted",
                result="success",
                actor_user_id=user_id,
                target_id=txn_id,
            )
    if row is None:
        raise MissingObject


def list_month(user_id: UUID, month: str) -> list[dict]:
    start, end = month_bounds(month)
    with user_tx(user_id) as connection:
        dek, _ = data_key(connection, user_id)
        rows = connection.execute(
            text(
                "SELECT txn_id, category_id, account_id, kind, status, currency, "
                "amount_enc, merchant_enc, note_enc, fee_enc, txn_date, fx_date, "
                "fx_override_rate, source "
                "FROM public.transactions "
                "WHERE txn_date >= :start_date AND txn_date < :end_date "
                "AND status = 'posted' AND deleted_at IS NULL "
                "ORDER BY txn_date DESC, created_at DESC, txn_id"
            ),
            {"start_date": start, "end_date": end},
        ).mappings()
        result = []
        for row in rows:
            result.append(_transaction_from_row(dek, row))
    return result


def list_categories(user_id: UUID) -> list[dict]:
    """Return shared and caller-owned categories without exposing other users' names."""
    with user_tx(user_id) as connection:
        dek, _ = data_key(connection, user_id)
        rows = connection.execute(
            text(
                "SELECT category_id, user_id, name, name_enc "
                "FROM public.categories "
                "WHERE user_id IS NULL OR user_id = :user_id "
                "ORDER BY name NULLS LAST, category_id"
            ),
            {"user_id": user_id},
        ).mappings()
        categories = []
        for row in rows:
            name = row["name"]
            if name is None and row["name_enc"] is not None:
                name = crypto.dec(
                    dek,
                    bytes(row["name_enc"]),
                    "categories",
                    "name_enc",
                    row["category_id"],
                ).decode("utf-8")
            categories.append(
                {"category_id": row["category_id"], "name": name or "Other"}
            )
    return categories


def create_bill(
    *,
    user_id: UUID,
    biller: str,
    amount_minor: int,
    currency: str,
    next_due_date: date,
    recurrence: str,
) -> dict:
    currency = currency.upper()
    biller = biller.strip()
    if currency not in EXPONENTS:
        raise ValueError("unsupported currency")
    if not biller:
        raise ValueError("biller is required")
    if isinstance(amount_minor, bool) or not isinstance(amount_minor, int) or amount_minor <= 0:
        raise ValueError("amount_minor must be a positive integer")
    if not recurrence or len(recurrence) > 32:
        raise ValueError("invalid recurrence")

    bill_id = uuid4()
    with user_tx(user_id) as connection:
        dek, _ = data_key(connection, user_id)
        connection.execute(
            text(
                "INSERT INTO public.bills "
                "(bill_id, user_id, biller_enc, amount_enc, currency, "
                "next_due_date, recurrence) "
                "VALUES (:bill_id, :user_id, :biller_enc, :amount_enc, :currency, "
                ":next_due_date, :recurrence)"
            ),
            {
                "bill_id": bill_id,
                "user_id": user_id,
                "biller_enc": crypto.enc(
                    dek, biller.encode("utf-8"), "bills", "biller_enc", bill_id
                ),
                "amount_enc": crypto.enc(
                    dek,
                    str(amount_minor).encode("ascii"),
                    "bills",
                    "amount_enc",
                    bill_id,
                ),
                "currency": currency,
                "next_due_date": next_due_date,
                "recurrence": recurrence,
            },
        )
        append_event(
            connection,
            action="bill_created",
            result="success",
            actor_user_id=user_id,
            target_id=bill_id,
        )
    return {
        "bill_id": bill_id,
        "biller": biller,
        "amount_minor": amount_minor,
        "currency": currency,
        "next_due_date": next_due_date,
        "recurrence": recurrence,
        "is_active": True,
    }


def list_bills(user_id: UUID) -> list[dict]:
    with user_tx(user_id) as connection:
        dek, _ = data_key(connection, user_id)
        rows = connection.execute(
            text(
                "SELECT bill_id, biller_enc, amount_enc, currency, next_due_date, "
                "recurrence, is_active "
                "FROM public.bills WHERE deleted_at IS NULL "
                "ORDER BY next_due_date, bill_id"
            )
        ).mappings()
        result = []
        for row in rows:
            bill_id = row["bill_id"]
            result.append(
                {
                    "bill_id": bill_id,
                    "biller": crypto.dec(
                        dek,
                        bytes(row["biller_enc"]),
                        "bills",
                        "biller_enc",
                        bill_id,
                    ).decode("utf-8"),
                    "amount_minor": int(
                        crypto.dec(
                            dek,
                            bytes(row["amount_enc"]),
                            "bills",
                            "amount_enc",
                            bill_id,
                        ).decode("ascii")
                    ),
                    "currency": row["currency"].strip(),
                    "next_due_date": row["next_due_date"],
                    "recurrence": row["recurrence"],
                    "is_active": row["is_active"],
                }
            )
    return result


def soft_delete_bill(user_id: UUID, bill_id: UUID) -> None:
    with user_tx(user_id) as connection:
        row = connection.execute(
            text(
                "UPDATE public.bills SET deleted_at = now(), is_active = false "
                "WHERE bill_id = :bill_id AND deleted_at IS NULL "
                "RETURNING bill_id"
            ),
            {"bill_id": bill_id},
        ).first()
        if row is None:
            append_event(
                connection,
                action="object_denied",
                result="deny",
                actor_user_id=user_id,
                target_id=bill_id,
            )
        else:
            append_event(
                connection,
                action="bill_deleted",
                result="success",
                actor_user_id=user_id,
                target_id=bill_id,
            )
    if row is None:
        raise MissingObject


ACCOUNT_TYPES = frozenset({"cash", "bank", "card", "wallet"})


def create_account(user_id: UUID, *, name: str, type_: str, currency: str) -> dict:
    """Create a money account (cash, bank, card, wallet); the name is encrypted."""
    if type_ not in ACCOUNT_TYPES:
        raise ValueError("Unsupported account type")
    if currency not in EXPONENTS:
        raise ValueError("Unsupported currency")
    clean = name.strip()
    if not clean or len(clean) > 100:
        raise ValueError("Account name must be 1-100 characters")
    account_id = uuid4()
    with user_tx(user_id) as connection:
        dek, _base = data_key(connection, user_id)
        connection.execute(
            text(
                "INSERT INTO public.accounts (account_id, user_id, name_enc, type, currency) "
                "VALUES (:account_id, :user_id, :name_enc, :type, :currency)"
            ),
            {
                "account_id": account_id,
                "user_id": user_id,
                "name_enc": crypto.enc(
                    dek, clean.encode("utf-8"), "accounts", "name_enc", account_id
                ),
                "type": type_,
                "currency": currency,
            },
        )
        append_event(
            connection,
            action="account_created",
            result="success",
            actor_user_id=user_id,
            target_id=account_id,
        )
    return {"account_id": str(account_id), "name": clean, "type": type_, "currency": currency}


def list_accounts(user_id: UUID) -> list[dict]:
    with user_tx(user_id) as connection:
        dek, _base = data_key(connection, user_id)
        rows = connection.execute(
            text(
                "SELECT account_id, name_enc, type, currency, created_at "
                "FROM public.accounts WHERE deleted_at IS NULL ORDER BY created_at"
            )
        ).mappings().all()
        return [
            {
                "account_id": str(row["account_id"]),
                "name": crypto.dec(
                    dek, bytes(row["name_enc"]), "accounts", "name_enc", row["account_id"]
                ).decode("utf-8"),
                "type": row["type"],
                "currency": row["currency"].strip(),
            }
            for row in rows
        ]


def soft_delete_account(user_id: UUID, account_id: UUID) -> None:
    """Soft-delete an owned account; transactions keep their history but the
    account can no longer be selected. Foreign IDs behave like missing ones."""
    with user_tx(user_id) as connection:
        row = connection.execute(
            text(
                "UPDATE public.accounts SET deleted_at = now() "
                "WHERE account_id = :account_id AND deleted_at IS NULL RETURNING account_id"
            ),
            {"account_id": account_id},
        ).first()
        append_event(
            connection,
            action="account_deleted" if row else "object_denied",
            result="success" if row else "deny",
            actor_user_id=user_id,
            target_id=account_id,
        )
    if row is None:
        raise MissingObject
