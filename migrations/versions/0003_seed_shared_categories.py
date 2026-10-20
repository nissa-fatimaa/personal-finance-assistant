"""Seed the shared categories used by the ledger."""

from alembic import op
from sqlalchemy import text

revision = "0003_seed_shared_categories"
down_revision = "0002_auth_flows"
branch_labels = None
depends_on = None


CATEGORIES = (
    "Food",
    "Transport",
    "Bills",
    "Shopping",
    "Entertainment",
    "Travel",
    "Health",
    "Income",
    "Other",
)


def upgrade() -> None:
    connection = op.get_bind()
    for name in CATEGORIES:
        connection.execute(
            text(
                "INSERT INTO public.categories (user_id, name) "
                "SELECT NULL, :name WHERE NOT EXISTS "
                "(SELECT 1 FROM public.categories WHERE user_id IS NULL AND name = :name)"
            ),
            {"name": name},
        )


def downgrade() -> None:
    connection = op.get_bind()
    # migration_owner owns these tables, so it may lift forced RLS for the
    # destructive data release; force is re-enabled right after so a partial
    # downgrade never leaves tenant tables unprotected.
    for table in ("transactions", "budgets", "categories"):
        connection.exec_driver_sql(
            f"ALTER TABLE public.{table} NO FORCE ROW LEVEL SECURITY"
        )
    # Release references first: transactions detach, budgets that point at a
    # shared category are removed (a downgrade is destructive by definition).
    connection.execute(
        text(
            "UPDATE public.transactions SET category_id = NULL "
            "WHERE category_id IN ("
            "SELECT category_id FROM public.categories WHERE user_id IS NULL)"
        )
    )
    connection.execute(
        text(
            "DELETE FROM public.budgets WHERE category_id IN ("
            "SELECT category_id FROM public.categories WHERE user_id IS NULL)"
        )
    )
    for name in CATEGORIES:
        connection.execute(
            text("DELETE FROM public.categories WHERE user_id IS NULL AND name = :name"),
            {"name": name},
        )
    for table in ("transactions", "budgets", "categories"):
        connection.exec_driver_sql(
            f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY"
        )
