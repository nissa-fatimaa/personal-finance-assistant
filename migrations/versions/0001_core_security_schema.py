"""Create the PFA schema, forced RLS, least-privilege grants, and audit chain."""

from alembic import op
from sqlalchemy import text

revision = "0001_core_security_schema"
down_revision = None
branch_labels = None
depends_on = None

REQUIRED_ROLES = (
    "migration_owner",
    "app_service",
    "auth_service",
    "stats_reader",
    "audit_reader",
)


def _execute(sql: str) -> None:
    op.get_bind().exec_driver_sql(sql)


def _verify_roles() -> None:
    connection = op.get_bind()
    current_user = connection.exec_driver_sql("SELECT current_user").scalar_one()
    if current_user != "migration_owner":
        raise RuntimeError("Schema migration must connect as migration_owner")

    role_rows = connection.execute(
        text(
            "SELECT rolname, rolsuper, rolbypassrls "
            "FROM pg_roles "
            "WHERE rolname IN "
            "('migration_owner', 'app_service', 'auth_service', "
            "'stats_reader', 'audit_reader')"
        )
    ).mappings()
    roles = {row["rolname"]: row for row in role_rows}
    missing = sorted(set(REQUIRED_ROLES) - roles.keys())
    unsafe = sorted(
        name
        for name, row in roles.items()
        if row["rolsuper"] or row["rolbypassrls"]
    )
    if missing:
        raise RuntimeError(f"Required database roles are missing: {', '.join(missing)}")
    if unsafe:
        raise RuntimeError(
            f"Database roles must not be superusers or bypass RLS: {', '.join(unsafe)}"
        )


TABLES = (
    """
    CREATE TABLE public.users (
        user_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        email_hmac bytea UNIQUE NOT NULL,
        email_enc bytea NOT NULL,
        password_hash text NOT NULL,
        role text NOT NULL DEFAULT 'user'
            CHECK (role IN ('user', 'security_owner', 'admin')),
        status text NOT NULL DEFAULT 'active'
            CHECK (status IN ('active', 'locked', 'deleted')),
        failed_login_count integer NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
        last_failed_at timestamptz,
        locked_until timestamptz,
        totp_secret_enc bytea,
        dek_wrapped bytea NOT NULL,
        base_currency char(3) NOT NULL,
        ai_consent_at timestamptz,
        created_at timestamptz NOT NULL DEFAULT now(),
        deleted_at timestamptz
    )
    """,
    """
    CREATE TABLE public.sessions (
        session_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid NOT NULL REFERENCES public.users(user_id),
        token_hash bytea UNIQUE NOT NULL,
        ip_hmac bytea,
        mfa_ok boolean NOT NULL DEFAULT false,
        issued_at timestamptz NOT NULL DEFAULT now(),
        last_seen_at timestamptz NOT NULL DEFAULT now(),
        expires_at timestamptz NOT NULL,
        revoked_at timestamptz
    )
    """,
    """
    CREATE TABLE public.accounts (
        account_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid NOT NULL REFERENCES public.users(user_id),
        name_enc bytea NOT NULL,
        type text NOT NULL CHECK (type IN ('cash', 'bank', 'card', 'wallet')),
        currency char(3) NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        deleted_at timestamptz
    )
    """,
    """
    CREATE TABLE public.categories (
        category_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid REFERENCES public.users(user_id),
        name text,
        name_enc bytea,
        CHECK (
            (user_id IS NULL AND name IS NOT NULL)
            OR (user_id IS NOT NULL AND name_enc IS NOT NULL)
        )
    )
    """,
    """
    CREATE TABLE public.transactions (
        txn_id uuid PRIMARY KEY,
        user_id uuid NOT NULL REFERENCES public.users(user_id),
        account_id uuid REFERENCES public.accounts(account_id),
        category_id uuid REFERENCES public.categories(category_id),
        kind text NOT NULL CHECK (kind IN ('expense', 'income', 'refund', 'transfer')),
        status text NOT NULL DEFAULT 'pending'
            CHECK (status IN ('pending', 'posted', 'rejected')),
        currency char(3) NOT NULL,
        amount_enc bytea NOT NULL,
        merchant_enc bytea,
        note_enc bytea,
        fee_enc bytea,
        merchant_hmac bytea,
        dedupe_hmac bytea NOT NULL,
        txn_date date NOT NULL,
        fx_date date NOT NULL,
        fx_override_rate numeric(20, 10),
        source text NOT NULL CHECK (source IN ('manual', 'chat', 'receipt')),
        created_at timestamptz NOT NULL DEFAULT now(),
        deleted_at timestamptz
    )
    """,
    """
    CREATE TABLE public.bills (
        bill_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid NOT NULL REFERENCES public.users(user_id),
        biller_enc bytea NOT NULL,
        amount_enc bytea NOT NULL,
        currency char(3) NOT NULL,
        next_due_date date NOT NULL,
        recurrence text NOT NULL DEFAULT 'monthly',
        is_active boolean NOT NULL DEFAULT true,
        created_at timestamptz NOT NULL DEFAULT now(),
        deleted_at timestamptz
    )
    """,
    """
    CREATE TABLE public.budgets (
        budget_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid NOT NULL REFERENCES public.users(user_id),
        category_id uuid NOT NULL REFERENCES public.categories(category_id),
        period char(7) NOT NULL
            CHECK (period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
        limit_enc bytea NOT NULL,
        UNIQUE (user_id, category_id, period)
    )
    """,
    """
    CREATE TABLE public.insights (
        insight_id uuid PRIMARY KEY,
        user_id uuid NOT NULL REFERENCES public.users(user_id),
        kind text NOT NULL,
        source text NOT NULL CHECK (source IN ('llm', 'template')),
        body_enc bytea NOT NULL,
        facts_enc bytea NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE public.chat_messages (
        msg_id uuid PRIMARY KEY,
        user_id uuid NOT NULL REFERENCES public.users(user_id),
        thread_id uuid NOT NULL,
        role text NOT NULL CHECK (role IN ('user', 'assistant')),
        body_enc bytea NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE public.audit_log (
        id bigserial PRIMARY KEY,
        ts timestamptz NOT NULL,
        actor_user_id uuid,
        action text NOT NULL,
        target_id uuid,
        result text NOT NULL,
        detail jsonb NOT NULL DEFAULT '{}',
        prev_hash bytea,
        row_hash bytea NOT NULL
    )
    """,
    """
    CREATE TABLE public.fx_rates (
        rate_date date NOT NULL,
        quote char(3) NOT NULL,
        rate_per_usd numeric(20, 10) NOT NULL CHECK (rate_per_usd > 0),
        source text NOT NULL,
        fetched_at timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (rate_date, quote)
    )
    """,
)


POLICIES_AND_RLS = (
    "ALTER TABLE public.users ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE public.users FORCE ROW LEVEL SECURITY",
    "ALTER TABLE public.sessions ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE public.sessions FORCE ROW LEVEL SECURITY",
    "ALTER TABLE public.accounts ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE public.accounts FORCE ROW LEVEL SECURITY",
    "ALTER TABLE public.categories ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE public.categories FORCE ROW LEVEL SECURITY",
    "ALTER TABLE public.transactions ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE public.transactions FORCE ROW LEVEL SECURITY",
    "ALTER TABLE public.bills ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE public.bills FORCE ROW LEVEL SECURITY",
    "ALTER TABLE public.budgets ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE public.budgets FORCE ROW LEVEL SECURITY",
    "ALTER TABLE public.insights ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE public.insights FORCE ROW LEVEL SECURITY",
    "ALTER TABLE public.chat_messages ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE public.chat_messages FORCE ROW LEVEL SECURITY",
    "ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE public.audit_log FORCE ROW LEVEL SECURITY",
    """
    CREATE POLICY users_auth_all ON public.users
    FOR ALL TO auth_service USING (true) WITH CHECK (true)
    """,
    """
    CREATE POLICY users_self ON public.users
    TO app_service
    USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
    WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
    """,
    "CREATE POLICY users_stats_select ON public.users FOR SELECT TO migration_owner USING (true)",
    """
    CREATE POLICY sessions_auth_all ON public.sessions
    FOR ALL TO auth_service USING (true) WITH CHECK (true)
    """,
    """
    CREATE POLICY accounts_owner ON public.accounts
    TO app_service
    USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
    WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
    """,
    """
    CREATE POLICY categories_read ON public.categories
    FOR SELECT TO app_service
    USING (
        user_id IS NULL
        OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    )
    """,
    """
    CREATE POLICY categories_write ON public.categories
    FOR INSERT TO app_service
    WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
    """,
    """
    CREATE POLICY categories_migration ON public.categories
    FOR ALL TO migration_owner USING (true) WITH CHECK (true)
    """,
    """
    CREATE POLICY transactions_owner ON public.transactions
    TO app_service
    USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
    WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
    """,
    "CREATE POLICY transactions_stats_select ON public.transactions FOR SELECT TO migration_owner USING (true)",
    """
    CREATE POLICY bills_owner ON public.bills
    TO app_service
    USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
    WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
    """,
    """
    CREATE POLICY budgets_owner ON public.budgets
    TO app_service
    USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
    WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
    """,
    """
    CREATE POLICY insights_owner ON public.insights
    TO app_service
    USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
    WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
    """,
    """
    CREATE POLICY chat_messages_owner ON public.chat_messages
    TO app_service
    USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
    WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
    """,
    """
    CREATE POLICY audit_migration_all ON public.audit_log
    FOR ALL TO migration_owner USING (true) WITH CHECK (true)
    """,
    """
    CREATE POLICY audit_reader_select ON public.audit_log
    FOR SELECT TO audit_reader USING (true)
    """,
)


FUNCTIONS_AND_VIEWS = (
    """
    CREATE OR REPLACE FUNCTION public.audit_append(
        p_actor uuid,
        p_action text,
        p_target uuid,
        p_result text,
        p_detail jsonb
    )
    RETURNS void
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public
    SET timezone = 'UTC'
    AS $audit$
    DECLARE
        previous_hash bytea;
        current_hash bytea;
        event_time timestamptz := now();
    BEGIN
        IF p_action IS NULL OR p_result IS NULL THEN
            RAISE EXCEPTION 'audit action and result are required';
        END IF;

        PERFORM pg_advisory_xact_lock(7001);
        SELECT row_hash INTO previous_hash
        FROM public.audit_log
        ORDER BY id DESC
        LIMIT 1;

        current_hash := public.digest(
            coalesce(previous_hash, ''::bytea)
            || convert_to(
                concat_ws(
                    '|',
                    event_time::text,
                    coalesce(p_actor::text, ''),
                    p_action,
                    coalesce(p_target::text, ''),
                    p_result,
                    coalesce(p_detail, '{}'::jsonb)::text
                ),
                'UTF8'
            ),
            'sha256'
        );

        INSERT INTO public.audit_log(
            ts, actor_user_id, action, target_id, result, detail, prev_hash, row_hash
        )
        VALUES (
            event_time, p_actor, p_action, p_target, p_result,
            coalesce(p_detail, '{}'::jsonb), previous_hash, current_hash
        );
    END
    $audit$
    """,
    """
    CREATE OR REPLACE FUNCTION public.audit_verify()
    RETURNS boolean
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public
    SET timezone = 'UTC'
    AS $verify$
    DECLARE
        event record;
        previous_hash bytea;
        expected_hash bytea;
    BEGIN
        FOR event IN
            SELECT id, ts, actor_user_id, action, target_id, result, detail, prev_hash, row_hash
            FROM public.audit_log
            ORDER BY id
        LOOP
            IF event.prev_hash IS DISTINCT FROM previous_hash THEN
                RETURN false;
            END IF;

            expected_hash := public.digest(
                coalesce(previous_hash, ''::bytea)
                || convert_to(
                    concat_ws(
                        '|',
                        event.ts::text,
                        coalesce(event.actor_user_id::text, ''),
                        event.action,
                        coalesce(event.target_id::text, ''),
                        event.result,
                        coalesce(event.detail, '{}'::jsonb)::text
                    ),
                    'UTF8'
                ),
                'sha256'
            );
            IF event.row_hash IS DISTINCT FROM expected_hash THEN
                RETURN false;
            END IF;
            previous_hash := event.row_hash;
        END LOOP;

        RETURN true;
    END
    $verify$
    """,
    """
    CREATE VIEW public.stats_overview WITH (security_barrier = true) AS
    SELECT
        (SELECT count(*) FROM public.users WHERE status = 'active') AS active_users,
        (SELECT count(*) FROM public.transactions
         WHERE created_at > now() - interval '24 hours') AS txns_24h,
        (SELECT count(*) FROM public.audit_log
         WHERE action = 'login_fail' AND ts > now() - interval '24 hours')
        AS failed_logins_24h
    """,
)


GRANTS = (
    "REVOKE ALL ON TABLE public.users, public.sessions, public.accounts, "
    "public.categories, public.transactions, public.bills, public.budgets, "
    "public.insights, public.chat_messages, public.audit_log, public.fx_rates FROM PUBLIC",
    ("GRANT SELECT, INSERT, UPDATE ON public.accounts, public.transactions, "
     "public.bills, public.budgets, public.insights, public.chat_messages TO app_service"),
    "GRANT SELECT, INSERT ON public.categories TO app_service",
    "GRANT SELECT, INSERT ON public.fx_rates TO app_service",
    ("GRANT SELECT (user_id, email_enc, dek_wrapped, base_currency, role, ai_consent_at) "
     "ON public.users TO app_service"),
    ("GRANT UPDATE (base_currency, ai_consent_at) ON public.users TO app_service"),
    "GRANT SELECT, INSERT, UPDATE ON public.users, public.sessions TO auth_service",
    "GRANT SELECT ON public.fx_rates TO auth_service",
    "GRANT SELECT ON public.audit_log TO audit_reader",
    "GRANT SELECT ON public.stats_overview TO stats_reader",
    ("REVOKE ALL ON FUNCTION public.audit_append(uuid, text, uuid, text, jsonb) FROM PUBLIC"),
    ("GRANT EXECUTE ON FUNCTION public.audit_append(uuid, text, uuid, text, jsonb) "
     "TO app_service, auth_service"),
    ("REVOKE ALL ON FUNCTION public.audit_verify() FROM PUBLIC"),
    "GRANT EXECUTE ON FUNCTION public.audit_verify() TO audit_reader",
)


def upgrade() -> None:
    _verify_roles()
    _execute("CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public")
    for statement in TABLES:
        _execute(statement)
    _execute(
        "CREATE UNIQUE INDEX txn_dedupe ON public.transactions (user_id, dedupe_hmac) "
        "WHERE deleted_at IS NULL AND status <> 'rejected'"
    )
    _execute(
        "CREATE INDEX txn_user_date ON public.transactions (user_id, txn_date DESC) "
        "WHERE deleted_at IS NULL"
    )
    for statement in POLICIES_AND_RLS:
        _execute(statement)
    for statement in FUNCTIONS_AND_VIEWS:
        _execute(statement)
    for statement in GRANTS:
        _execute(statement)


def downgrade() -> None:
    _execute("DROP VIEW IF EXISTS public.stats_overview")
    _execute("DROP FUNCTION IF EXISTS public.audit_verify()")
    _execute(
        "DROP FUNCTION IF EXISTS public.audit_append(uuid, text, uuid, text, jsonb)"
    )
    _execute(
        "DROP TABLE IF EXISTS public.fx_rates, public.audit_log, "
        "public.chat_messages, public.insights, public.budgets, public.bills, "
        "public.transactions, public.categories, public.accounts, public.sessions, "
        "public.users CASCADE"
    )
