from datetime import date
from uuid import uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

from app import crypto
from app.audit import record_decryption_failure
from app.config import get_settings
from app.db import app_engine, audit_engine, user_tx
from tests.conftest import add_account


def test_T04_app_service_rls_filters_rows_without_where(user_pair):
    user_a, user_b = user_pair
    account_a = add_account(user_a, "synthetic-account-a")
    add_account(user_b, "synthetic-account-b")

    with user_tx(user_a.user_id) as connection:
        visible = connection.execute(
            text("SELECT account_id FROM public.accounts ORDER BY account_id")
        ).scalars().all()

    assert visible == [account_a]


def test_T05_every_user_id_table_has_forced_rls():
    with app_engine.connect() as connection:
        application_tables = set(
            connection.execute(
                text(
                    "SELECT tablename FROM pg_tables WHERE schemaname = 'public' "
                    "AND tablename IN "
                    "('users', 'sessions', 'accounts', 'categories', 'transactions', "
                    "'bills', 'budgets', 'insights', 'chat_messages', 'audit_log', 'fx_rates')"
                )
            ).scalars()
        )
        missing = connection.execute(
            text(
                "SELECT c.relname "
                "FROM pg_class AS c "
                "JOIN pg_namespace AS n ON n.oid = c.relnamespace "
                "JOIN pg_attribute AS a ON a.attrelid = c.oid "
                "WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') "
                "AND a.attname = 'user_id' AND a.attnum > 0 AND NOT a.attisdropped "
                "AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity) "
                "ORDER BY c.relname"
            )
        ).scalars().all()
        restricted_grants = connection.execute(
            text(
                "SELECT "
                "has_table_privilege('app_service', 'public.transactions', 'DELETE'), "
                "has_column_privilege('app_service', 'public.users', 'password_hash', 'SELECT'), "
                "has_table_privilege('stats_reader', 'public.users', 'SELECT'), "
                "has_table_privilege('audit_reader', 'public.audit_log', 'UPDATE')"
            )
        ).one()
    expected_tables = {
        "users",
        "sessions",
        "accounts",
        "categories",
        "transactions",
        "bills",
        "budgets",
        "insights",
        "chat_messages",
        "audit_log",
        "fx_rates",
    }
    assert application_tables == expected_tables
    assert missing == []
    assert tuple(restricted_grants) == (False, False, False, False)


def test_T06_missing_context_returns_zero_rows(user_pair):
    user_a, _ = user_pair
    add_account(user_a, "synthetic-account-without-context")

    with app_engine.connect() as connection:
        with connection.begin():
            context = connection.execute(
                text("SELECT current_setting('app.current_user_id', true)")
            ).scalar_one_or_none()
            visible_count = connection.execute(
                text("SELECT count(*) FROM public.accounts")
            ).scalar_one()

    assert context in (None, "")
    assert visible_count == 0


def test_T11_ciphertext_copy_to_another_row_fails_and_is_audited(user_pair):
    user_a, _ = user_pair
    txn_a, txn_b = uuid4(), uuid4()
    plaintext_a = b"12000"
    plaintext_b = b"13000"
    blob_a = crypto.enc(
        user_a.dek, plaintext_a, "transactions", "amount_enc", txn_a
    )
    blob_b = crypto.enc(
        user_a.dek, plaintext_b, "transactions", "amount_enc", txn_b
    )
    today = date.today()

    with user_tx(user_a.user_id) as connection:
        for txn_id, amount_blob, dedupe_marker in (
            (txn_a, blob_a, b"rowtest-a"),
            (txn_b, blob_b, b"rowtest-b"),
        ):
            connection.execute(
                text(
                    "INSERT INTO public.transactions "
                    "(txn_id, user_id, kind, currency, amount_enc, dedupe_hmac, "
                    "txn_date, fx_date, source) "
                    "VALUES (:txn_id, :user_id, 'expense', 'PKR', :amount_enc, "
                    ":dedupe_hmac, :txn_date, :fx_date, 'manual')"
                ),
                {
                    "txn_id": txn_id,
                    "user_id": user_a.user_id,
                    "amount_enc": amount_blob,
                    "dedupe_hmac": dedupe_marker + user_a.user_id.bytes,
                    "txn_date": today,
                    "fx_date": today,
                },
            )

        connection.execute(
            text(
                "UPDATE public.transactions SET amount_enc = :copied "
                "WHERE txn_id = :target_id"
            ),
            {"copied": blob_a, "target_id": txn_b},
        )
        copied_blob = connection.execute(
            text("SELECT amount_enc FROM public.transactions WHERE txn_id = :target_id"),
            {"target_id": txn_b},
        ).scalar_one()
        try:
            crypto.dec(
                user_a.dek,
                copied_blob,
                "transactions",
                "amount_enc",
                txn_b,
            )
        except crypto.InvalidTag:
            record_decryption_failure(
                connection, actor_user_id=user_a.user_id, target_id=txn_b
            )
        else:
            raise AssertionError("Ciphertext copied to a different row was accepted")

    with audit_engine.connect() as connection:
        event_count = connection.execute(
            text(
                "SELECT count(*) FROM public.audit_log "
                "WHERE action = 'decryption_failed' AND target_id = :target_id"
            ),
            {"target_id": txn_b},
        ).scalar_one()
    assert event_count == 1


def test_T21_user_context_does_not_carry_between_requests_on_same_connection(user_pair):
    user_a, user_b = user_pair
    account_a = add_account(user_a, "synthetic-isolation-a")
    account_b = add_account(user_b, "synthetic-isolation-b")

    with user_tx(user_a.user_id) as connection:
        first_pid = connection.execute(text("SELECT pg_backend_pid()")).scalar_one()
        first_rows = connection.execute(
            text("SELECT account_id FROM public.accounts")
        ).scalars().all()
    assert first_rows == [account_a]

    with app_engine.begin() as connection:
        between_requests_pid = connection.execute(
            text("SELECT pg_backend_pid()")
        ).scalar_one()
        between_requests_context = connection.execute(
            text("SELECT current_setting('app.current_user_id', true)")
        ).scalar_one_or_none()
    assert between_requests_pid == first_pid
    assert between_requests_context in (None, "")

    with user_tx(user_b.user_id) as connection:
        second_pid = connection.execute(text("SELECT pg_backend_pid()")).scalar_one()
        second_rows = connection.execute(
            text("SELECT account_id FROM public.accounts")
        ).scalars().all()
    assert second_pid == first_pid
    assert second_rows == [account_b]


def test_T26_audit_chain_detects_tampering():
    migration_url = get_settings().migrate_url
    engine = create_engine(
        migration_url,
        poolclass=NullPool,
        connect_args={"prepare_threshold": None},
    )
    target_id = uuid4()
    actor_id = uuid4()
    detected = False
    intact_before_tamper = False
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            function_settings = connection.execute(
                text(
                    "SELECT proname, proconfig FROM pg_proc "
                    "WHERE pronamespace = 'public'::regnamespace "
                    "AND proname IN ('audit_append', 'audit_verify')"
                )
            ).all()
            connection.execute(
                text(
                    "SELECT public.audit_append("
                    ":actor, CAST('t26_tamper_probe' AS text), :target, "
                    "CAST('ok' AS text), '{}'::jsonb)"
                ),
                {"actor": actor_id, "target": target_id},
            )
            intact_before_tamper = connection.execute(
                text("SELECT public.audit_verify()")
            ).scalar_one()
            row_id = connection.execute(
                text(
                    "SELECT id FROM public.audit_log "
                    "WHERE target_id = :target ORDER BY id DESC LIMIT 1"
                ),
                {"target": target_id},
            ).scalar_one()
            connection.execute(
                text(
                    "UPDATE public.audit_log SET result = 'tampered' WHERE id = :row_id"
                ),
                {"row_id": row_id},
            )
            detected = not connection.execute(
                text("SELECT public.audit_verify()")
            ).scalar_one()
        finally:
            transaction.rollback()
    engine.dispose()
    settings_by_function = {row.proname: row.proconfig for row in function_settings}
    assert any(
        setting.lower() == "timezone=utc"
        for setting in settings_by_function["audit_append"]
    )
    assert any(
        setting.lower() == "timezone=utc"
        for setting in settings_by_function["audit_verify"]
    )
    assert intact_before_tamper is True
    assert detected is True
