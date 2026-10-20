"""Role-separated SQLAlchemy engines and transaction-local RLS context."""

from contextlib import contextmanager
from typing import Iterator
from uuid import UUID

from sqlalchemy import Engine, create_engine, text

from app.config import get_settings


def _engine(url, *, pool_size: int) -> Engine:
    return create_engine(
        url,
        pool_size=pool_size,
        max_overflow=0,
        pool_pre_ping=True,
        hide_parameters=True,
        connect_args={"prepare_threshold": None},
    )


_settings = get_settings()
app_engine = _engine(_settings.app_url, pool_size=10)
auth_engine = _engine(_settings.auth_url, pool_size=5)
stats_engine = _engine(_settings.stats_url, pool_size=2)
audit_engine = _engine(_settings.audit_url, pool_size=2)
# Only present when DATABASE_URL_FX is configured (FX refresh job / opt-in web).
fx_engine: Engine | None = (
    _engine(_settings.fx_url, pool_size=1) if _settings.fx_url is not None else None
)


@contextmanager
def user_tx(user_id: UUID | str) -> Iterator:
    """Open one app_service transaction with a transaction-local verified user ID."""
    try:
        identity = UUID(str(user_id))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("user_id must be a UUID") from None

    with app_engine.begin() as connection:
        connection.execute(
            text("SELECT set_config('app.current_user_id', :user_id, true)"),
            {"user_id": str(identity)},
        )
        yield connection


@contextmanager
def auth_tx() -> Iterator:
    with auth_engine.begin() as connection:
        yield connection


@contextmanager
def stats_tx() -> Iterator:
    with stats_engine.begin() as connection:
        yield connection


@contextmanager
def audit_tx() -> Iterator:
    with audit_engine.begin() as connection:
        yield connection
