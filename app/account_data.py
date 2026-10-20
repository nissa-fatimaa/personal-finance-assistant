"""User-scoped account data export and post-deletion cryptographic cleanup."""

import json
from datetime import date, datetime, timezone
from uuid import UUID

from sqlalchemy import text

from app import crypto
from app.db import app_engine, user_tx
from app.ledger import data_key


def _iso(value):
    return value.isoformat() if isinstance(value, (date, datetime)) else value


def _decrypt(dek: bytes, row, table: str, column: str, row_id) -> str:
    return crypto.dec(
        dek, bytes(row[column]), table, column, row_id
    ).decode("utf-8")


def _json_or_text(value: str):
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value


def export_user_data(user_id: UUID, profile: dict) -> dict:
    """Export personal data under transaction-local RLS for the authenticated user."""
    with user_tx(user_id) as connection:
        dek, base_currency = data_key(connection, user_id)

        accounts = []
        for row in connection.execute(
            text(
                "SELECT account_id, name_enc, type, currency, created_at, deleted_at "
                "FROM public.accounts WHERE user_id = :user_id "
                "ORDER BY created_at, account_id"
            ),
            {"user_id": user_id},
        ).mappings():
            accounts.append(
                {
                    "account_id": str(row["account_id"]),
                    "name": _decrypt(dek, row, "accounts", "name_enc", row["account_id"]),
                    "type": row["type"],
                    "currency": row["currency"].strip(),
                    "created_at": _iso(row["created_at"]),
                    "deleted_at": _iso(row["deleted_at"]),
                }
            )

        category_rows = connection.execute(
            text(
                "SELECT category_id, user_id, name, name_enc FROM public.categories "
                "WHERE user_id = :user_id OR (user_id IS NULL AND category_id IN ("
                "SELECT category_id FROM public.transactions WHERE user_id = :user_id "
                "UNION SELECT category_id FROM public.budgets WHERE user_id = :user_id"
                ")) ORDER BY category_id"
            ),
            {"user_id": user_id},
        ).mappings()
        categories = [
            {
                "category_id": str(row["category_id"]),
                "name": (
                    row["name"]
                    if row["name"] is not None
                    else _decrypt(
                        dek, row, "categories", "name_enc", row["category_id"]
                    )
                ),
                "custom": row["user_id"] == user_id,
            }
            for row in category_rows
        ]

        transactions = []
        for row in connection.execute(
            text(
                "SELECT txn_id, account_id, category_id, kind, status, currency, "
                "amount_enc, merchant_enc, note_enc, fee_enc, txn_date, fx_date, "
                "fx_override_rate, source, created_at, deleted_at "
                "FROM public.transactions WHERE user_id = :user_id "
                "ORDER BY txn_date, created_at, txn_id"
            ),
            {"user_id": user_id},
        ).mappings():
            txn_id = row["txn_id"]
            transactions.append(
                {
                    "txn_id": str(txn_id),
                    "account_id": str(row["account_id"]) if row["account_id"] else None,
                    "category_id": str(row["category_id"]) if row["category_id"] else None,
                    "kind": row["kind"],
                    "status": row["status"],
                    "currency": row["currency"].strip(),
                    "amount_minor": int(
                        _decrypt(dek, row, "transactions", "amount_enc", txn_id)
                    ),
                    "merchant": (
                        _decrypt(dek, row, "transactions", "merchant_enc", txn_id)
                        if row["merchant_enc"] is not None
                        else None
                    ),
                    "note": (
                        _decrypt(dek, row, "transactions", "note_enc", txn_id)
                        if row["note_enc"] is not None
                        else None
                    ),
                    "fee_minor": (
                        int(_decrypt(dek, row, "transactions", "fee_enc", txn_id))
                        if row["fee_enc"] is not None
                        else None
                    ),
                    "txn_date": _iso(row["txn_date"]),
                    "fx_date": _iso(row["fx_date"]),
                    "fx_override_rate": (
                        str(row["fx_override_rate"])
                        if row["fx_override_rate"] is not None
                        else None
                    ),
                    "source": row["source"],
                    "created_at": _iso(row["created_at"]),
                    "deleted_at": _iso(row["deleted_at"]),
                }
            )

        bills = []
        for row in connection.execute(
            text(
                "SELECT bill_id, biller_enc, amount_enc, currency, next_due_date, "
                "recurrence, is_active, created_at, deleted_at FROM public.bills "
                "WHERE user_id = :user_id ORDER BY next_due_date, bill_id"
            ),
            {"user_id": user_id},
        ).mappings():
            bill_id = row["bill_id"]
            bills.append(
                {
                    "bill_id": str(bill_id),
                    "biller": _decrypt(dek, row, "bills", "biller_enc", bill_id),
                    "amount_minor": int(
                        _decrypt(dek, row, "bills", "amount_enc", bill_id)
                    ),
                    "currency": row["currency"].strip(),
                    "next_due_date": _iso(row["next_due_date"]),
                    "recurrence": row["recurrence"],
                    "is_active": row["is_active"],
                    "created_at": _iso(row["created_at"]),
                    "deleted_at": _iso(row["deleted_at"]),
                }
            )

        budgets = []
        for row in connection.execute(
            text(
                "SELECT budget_id, category_id, period, limit_enc "
                "FROM public.budgets WHERE user_id = :user_id "
                "ORDER BY period, category_id"
            ),
            {"user_id": user_id},
        ).mappings():
            budgets.append(
                {
                    "budget_id": str(row["budget_id"]),
                    "category_id": str(row["category_id"]),
                    "period": row["period"].strip(),
                    "limit_minor": int(
                        _decrypt(
                            dek, row, "budgets", "limit_enc", row["budget_id"]
                        )
                    ),
                }
            )

        chat_messages = [
            {
                "message_id": str(row["msg_id"]),
                "thread_id": str(row["thread_id"]),
                "role": row["role"],
                "body": _decrypt(dek, row, "chat_messages", "body_enc", row["msg_id"]),
                "created_at": _iso(row["created_at"]),
            }
            for row in connection.execute(
                text(
                    "SELECT msg_id, thread_id, role, body_enc, created_at "
                    "FROM public.chat_messages WHERE user_id = :user_id "
                    "ORDER BY created_at, msg_id"
                ),
                {"user_id": user_id},
            ).mappings()
        ]

        insights = []
        for row in connection.execute(
            text(
                "SELECT insight_id, kind, source, body_enc, facts_enc, created_at "
                "FROM public.insights WHERE user_id = :user_id "
                "ORDER BY created_at, insight_id"
            ),
            {"user_id": user_id},
        ).mappings():
            insight_id = row["insight_id"]
            insights.append(
                {
                    "insight_id": str(insight_id),
                    "kind": row["kind"],
                    "source": row["source"],
                    "body": _decrypt(dek, row, "insights", "body_enc", insight_id),
                    "facts": _json_or_text(
                        _decrypt(dek, row, "insights", "facts_enc", insight_id)
                    ),
                    "created_at": _iso(row["created_at"]),
                }
            )

    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "profile": {**profile, "base_currency": base_currency},
        "accounts": accounts,
        "categories": categories,
        "transactions": transactions,
        "bills": bills,
        "budgets": budgets,
        "chat_messages": chat_messages,
        "insights": insights,
    }


def shred_user_data(user_id: UUID) -> None:
    """Make any retained encrypted data unrecoverable after the DEK is destroyed."""
    # The account's wrapped DEK is replaced before this runs. This follow-up
    # scrubs plaintext metadata and marks retained soft-delete records inactive.
    with app_engine.begin() as connection:
        connection.execute(
            text("SELECT set_config('app.current_user_id', :user_id, true)"),
            {"user_id": str(user_id)},
        )
        connection.execute(
            text(
                "UPDATE public.transactions SET deleted_at = coalesce(deleted_at, now()), "
                "account_id = NULL, category_id = NULL, kind = 'expense', status = 'rejected', "
                "currency = 'XXX', amount_enc = public.gen_random_bytes(60), "
                "merchant_enc = NULL, note_enc = NULL, fee_enc = NULL, merchant_hmac = NULL, "
                "dedupe_hmac = public.gen_random_bytes(32), txn_date = DATE '1970-01-01', "
                "fx_date = DATE '1970-01-01', fx_override_rate = NULL, source = 'manual' "
                "WHERE user_id = :user_id"
            ),
            {"user_id": user_id},
        )
        connection.execute(
            text(
                "UPDATE public.accounts SET deleted_at = coalesce(deleted_at, now()), "
                "name_enc = public.gen_random_bytes(60), type = 'cash', currency = 'XXX' "
                "WHERE user_id = :user_id"
            ),
            {"user_id": user_id},
        )
        connection.execute(
            text(
                "UPDATE public.bills SET deleted_at = coalesce(deleted_at, now()), "
                "is_active = false, biller_enc = public.gen_random_bytes(60), "
                "amount_enc = public.gen_random_bytes(60), currency = 'XXX', "
                "next_due_date = DATE '1970-01-01', recurrence = 'deleted' "
                "WHERE user_id = :user_id"
            ),
            {"user_id": user_id},
        )
        connection.execute(
            text(
                "UPDATE public.budgets SET limit_enc = public.gen_random_bytes(60) "
                "WHERE user_id = :user_id"
            ),
            {"user_id": user_id},
        )
        connection.execute(
            text(
                "UPDATE public.insights SET kind = 'deleted', source = 'template', "
                "body_enc = public.gen_random_bytes(60), facts_enc = public.gen_random_bytes(60) "
                "WHERE user_id = :user_id"
            ),
            {"user_id": user_id},
        )
        connection.execute(
            text(
                "UPDATE public.chat_messages SET thread_id = "
                "'00000000-0000-0000-0000-000000000000'::uuid, role = 'assistant', "
                "body_enc = public.gen_random_bytes(60) WHERE user_id = :user_id"
            ),
            {"user_id": user_id},
        )
