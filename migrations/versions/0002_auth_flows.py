"""Add secure auth-flow state and the development-only encrypted email outbox."""

from alembic import op

revision = "0002_auth_flows"
down_revision = "0001_core_security_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE public.users
            ADD COLUMN privacy_consent_at timestamptz,
            ADD COLUMN totp_pending_enc bytea,
            ADD COLUMN password_reset_token_hash bytea,
            ADD COLUMN password_reset_expires_at timestamptz,
            ADD COLUMN reset_window_started_at timestamptz,
            ADD COLUMN reset_request_count integer NOT NULL DEFAULT 0,
            ADD CONSTRAINT users_reset_count_nonnegative
                CHECK (reset_request_count >= 0),
            ADD CONSTRAINT users_reset_pair_consistent
                CHECK (
                    (password_reset_token_hash IS NULL)
                    = (password_reset_expires_at IS NULL)
                )
        """
    )
    op.execute(
        "ALTER TABLE public.sessions "
        "ADD COLUMN browser_hmac bytea, "
        "ADD COLUMN new_browser boolean NOT NULL DEFAULT false"
    )
    op.execute(
        """
        CREATE TABLE public.dev_outbox (
            message_id uuid PRIMARY KEY,
            email_kind text NOT NULL CHECK (
                email_kind IN (
                    'password_reset', 'password_changed', 'mfa_enabled',
                    'mfa_disabled', 'account_lockout', 'new_browser_login'
                )
            ),
            recipient_enc bytea NOT NULL,
            subject_enc bytea NOT NULL,
            body_enc bytea NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            expires_at timestamptz NOT NULL
        )
        """
    )
    op.execute(
        "COMMENT ON TABLE public.dev_outbox IS "
        "'Development-only encrypted mail outbox; entries are not delivery proof.'"
    )
    op.execute("ALTER TABLE public.dev_outbox ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE public.dev_outbox FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY dev_outbox_auth_access ON public.dev_outbox
        FOR ALL TO auth_service USING (true) WITH CHECK (true)
        """
    )
    op.execute("REVOKE ALL ON TABLE public.dev_outbox FROM PUBLIC")
    op.execute(
        "GRANT SELECT, INSERT, DELETE ON TABLE public.dev_outbox TO auth_service"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS public.dev_outbox")
    op.execute(
        "ALTER TABLE public.sessions "
        "DROP COLUMN IF EXISTS new_browser, DROP COLUMN IF EXISTS browser_hmac"
    )
    op.execute(
        """
        ALTER TABLE public.users
            DROP CONSTRAINT IF EXISTS users_reset_pair_consistent,
            DROP CONSTRAINT IF EXISTS users_reset_count_nonnegative,
            DROP COLUMN IF EXISTS reset_request_count,
            DROP COLUMN IF EXISTS reset_window_started_at,
            DROP COLUMN IF EXISTS password_reset_expires_at,
            DROP COLUMN IF EXISTS password_reset_token_hash,
            DROP COLUMN IF EXISTS totp_pending_enc,
            DROP COLUMN IF EXISTS privacy_consent_at
        """
    )
