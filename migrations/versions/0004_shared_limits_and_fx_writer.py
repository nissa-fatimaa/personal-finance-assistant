"""Shared rate limits, a dedicated FX writer role, and an exchange-rate guard.

* rate_limits: per-IP / per-session / per-account counters shared by every
  worker and surviving restarts (replaces in-process limiters).
* fx_fetch_attempts: one claim row per day so only one process fetches rates.
* fx_writer: the only role allowed to insert exchange rates; app_service is
  reduced to SELECT so a compromised web process cannot write rates directly.
* fx_rates_guard: database-enforced allowlist (source, currency) and a
  plausibility band (0.5x-2x of the neighbouring snapshot within 31 days).
"""

from alembic import op
from sqlalchemy import text

revision = "0004_shared_limits_and_fx_writer"
down_revision = "0003_seed_shared_categories"
branch_labels = None
depends_on = None

CURRENCIES = "('PKR','USD','EUR','GBP','AED','SAR','CAD','AUD','CNY','JPY')"
SOURCES = "('open-er-api.com','synthetic-demo')"


def _verify_fx_writer() -> None:
    row = op.get_bind().execute(
        text(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'fx_writer'"
        )
    ).first()
    if row is None:
        raise RuntimeError(
            "Role fx_writer is missing; re-run db/init-roles.sh with FX_WRITER_PASSWORD"
        )
    if row.rolsuper or row.rolbypassrls:
        raise RuntimeError("fx_writer must not be superuser or bypass RLS")


STATEMENTS = (
    """
    CREATE TABLE public.rate_limits (
        bucket text NOT NULL CHECK (bucket ~ '^[a-z_]{1,32}$'),
        key_hmac bytea NOT NULL CHECK (octet_length(key_hmac) = 32),
        window_start timestamptz NOT NULL,
        hits integer NOT NULL CHECK (hits >= 0),
        PRIMARY KEY (bucket, key_hmac)
    )
    """,
    "CREATE INDEX rate_limits_window_idx ON public.rate_limits (window_start)",
    "REVOKE ALL ON TABLE public.rate_limits FROM PUBLIC",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.rate_limits TO auth_service",
    """
    CREATE TABLE public.fx_fetch_attempts (
        rate_date date PRIMARY KEY,
        attempted_at timestamptz NOT NULL DEFAULT now(),
        outcome text NOT NULL CHECK (outcome IN ('claimed', 'stored', 'failed'))
    )
    """,
    "REVOKE ALL ON TABLE public.fx_fetch_attempts FROM PUBLIC",
    "GRANT USAGE ON SCHEMA public TO fx_writer",
    "REVOKE INSERT, UPDATE, DELETE ON TABLE public.fx_rates FROM app_service",
    "GRANT SELECT, INSERT ON TABLE public.fx_rates TO fx_writer",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.fx_fetch_attempts TO fx_writer",
    f"""
    CREATE FUNCTION public.fx_rates_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, public
    AS $$
    DECLARE
        neighbour numeric;
    BEGIN
        IF NEW.source NOT IN {SOURCES} THEN
            RAISE EXCEPTION 'fx_rates: source is not allowlisted'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.quote NOT IN {CURRENCIES} THEN
            RAISE EXCEPTION 'fx_rates: unsupported currency'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.quote = 'USD' AND NEW.rate_per_usd <> 1 THEN
            RAISE EXCEPTION 'fx_rates: USD must equal 1'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.rate_date > current_date + 1 THEN
            RAISE EXCEPTION 'fx_rates: future-dated snapshot'
                USING ERRCODE = 'check_violation';
        END IF;
        FOR neighbour IN
            (SELECT r.rate_per_usd FROM public.fx_rates AS r
              WHERE r.quote = NEW.quote AND r.rate_date < NEW.rate_date
                AND r.rate_date >= NEW.rate_date - 31
              ORDER BY r.rate_date DESC LIMIT 1)
            UNION ALL
            (SELECT r.rate_per_usd FROM public.fx_rates AS r
              WHERE r.quote = NEW.quote AND r.rate_date > NEW.rate_date
                AND r.rate_date <= NEW.rate_date + 31
              ORDER BY r.rate_date ASC LIMIT 1)
        LOOP
            IF NEW.rate_per_usd > neighbour * 2 OR NEW.rate_per_usd < neighbour / 2 THEN
                RAISE EXCEPTION 'fx_rates: implausible change against neighbouring snapshot'
                    USING ERRCODE = 'check_violation';
            END IF;
        END LOOP;
        RETURN NEW;
    END
    $$
    """,
    "REVOKE ALL ON FUNCTION public.fx_rates_guard() FROM PUBLIC",
    """
    CREATE TRIGGER fx_rates_guard
        BEFORE INSERT OR UPDATE ON public.fx_rates
        FOR EACH ROW EXECUTE FUNCTION public.fx_rates_guard()
    """,
)


def upgrade() -> None:
    _verify_fx_writer()
    connection = op.get_bind()
    for statement in STATEMENTS:
        connection.exec_driver_sql(statement)


def downgrade() -> None:
    connection = op.get_bind()
    for statement in (
        "DROP TRIGGER IF EXISTS fx_rates_guard ON public.fx_rates",
        "DROP FUNCTION IF EXISTS public.fx_rates_guard()",
        "REVOKE ALL ON TABLE public.fx_rates FROM fx_writer",
        "GRANT INSERT ON TABLE public.fx_rates TO app_service",
        "DROP TABLE IF EXISTS public.fx_fetch_attempts",
        "DROP TABLE IF EXISTS public.rate_limits",
        "REVOKE USAGE ON SCHEMA public FROM fx_writer",
    ):
        connection.exec_driver_sql(statement)
