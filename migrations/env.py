"""Alembic environment that connects only as migration_owner."""

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool
from app.config import get_settings


config = context.config


def run_migrations_online() -> None:
    settings = get_settings()
    engine = create_engine(
        settings.migrate_url,
        poolclass=NullPool,
        connect_args={"prepare_threshold": None},
    )
    with engine.connect() as connection:
        current_user = connection.exec_driver_sql("SELECT current_user").scalar_one()
        connection.rollback()
        if current_user != "migration_owner":
            raise RuntimeError("Alembic must connect as migration_owner")
        context.configure(
            connection=connection,
            target_metadata=None,
            transaction_per_migration=True,
            compare_type=True,
            version_table_schema="public",
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    raise RuntimeError("Offline Alembic mode is disabled; use DATABASE_URL_MIGRATE")
run_migrations_online()
