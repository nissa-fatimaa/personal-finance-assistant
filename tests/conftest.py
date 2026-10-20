"""Synthetic fixtures for PostgreSQL security tests."""

from dataclasses import dataclass
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text

from app import crypto
from app.config import get_settings
from app.db import app_engine, audit_engine, auth_engine, fx_engine, stats_engine, user_tx


@dataclass(frozen=True)
class SyntheticUser:
    user_id: UUID
    dek: bytes
    email: str


@pytest.fixture
def user_pair():
    users = []
    for _ in range(2):
        user_id = uuid4()
        dek = crypto.new_dek()
        email = f"sec-{uuid4()}@example.invalid"
        with auth_engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO public.users "
                    "(user_id, email_hmac, email_enc, password_hash, dek_wrapped, base_currency) "
                    "VALUES (:user_id, :email_hmac, :email_enc, :password_hash, :dek_wrapped, :base_currency)"
                ),
                {
                    "user_id": user_id,
                    "email_hmac": crypto.hmac_email(email),
                    "email_enc": crypto.enc(dek, email.encode(), "users", "email_enc", user_id),
                    "password_hash": "synthetic-test-hash",
                    "dek_wrapped": crypto.wrap_dek(dek, user_id),
                    "base_currency": "PKR",
                },
            )
        users.append(SyntheticUser(user_id=user_id, dek=dek, email=email))

    try:
        yield users[0], users[1]
    finally:
        for user in users:
            with user_tx(user.user_id) as connection:
                connection.execute(
                    text(
                        "UPDATE public.accounts SET deleted_at = coalesce(deleted_at, now()) "
                        "WHERE user_id = :user_id"
                    ),
                    {"user_id": user.user_id},
                )
                connection.execute(
                    text(
                        "UPDATE public.transactions SET deleted_at = coalesce(deleted_at, now()) "
                        "WHERE user_id = :user_id"
                    ),
                    {"user_id": user.user_id},
                )
            with auth_engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE public.sessions SET revoked_at = coalesce(revoked_at, now()) "
                        "WHERE user_id = :user_id"
                    ),
                    {"user_id": user.user_id},
                )
                connection.execute(
                    text(
                        "UPDATE public.users SET status = 'deleted', "
                        "deleted_at = coalesce(deleted_at, now()) WHERE user_id = :user_id"
                    ),
                    {"user_id": user.user_id},
                )


def add_account(user: SyntheticUser, label: str) -> UUID:
    account_id = uuid4()
    name_enc = crypto.enc(
        user.dek, label.encode("utf-8"), "accounts", "name_enc", account_id
    )
    with user_tx(user.user_id) as connection:
        connection.execute(
            text(
                "INSERT INTO public.accounts "
                "(account_id, user_id, name_enc, type, currency) "
                "VALUES (:account_id, :user_id, :name_enc, 'cash', 'PKR')"
            ),
            {
                "account_id": account_id,
                "user_id": user.user_id,
                "name_enc": name_enc,
            },
        )
    return account_id


@pytest.fixture(scope="session", autouse=True)
def require_database_role_urls():
    """Fail clearly if the role-specific database configuration is incomplete."""
    assert get_settings().migrate_url.username == "migration_owner"
    assert app_engine.url.username == "app_service"
    assert auth_engine.url.username == "auth_service"
    assert stats_engine.url.username == "stats_reader"
    assert audit_engine.url.username == "audit_reader"
    assert fx_engine is not None and fx_engine.url.username == "fx_writer", (
        "set DATABASE_URL_FX for the test run"
    )
