"""Typed, secret-safe application configuration."""

import base64
from datetime import date, datetime
import binascii
from typing import Literal
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import AliasChoices, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL, make_url


class Settings(BaseSettings):
    """Load only role-specific database URLs and the field-encryption secret."""

    model_config = SettingsConfigDict(
        case_sensitive=True,
        extra="ignore",
        env_ignore_empty=True,
        hide_input_in_errors=True,  # never echo secrets in startup errors
    )

    database_url_migrate: SecretStr = Field(validation_alias="DATABASE_URL_MIGRATE")
    database_url_app: SecretStr = Field(validation_alias="DATABASE_URL_APP")
    database_url_auth: SecretStr = Field(validation_alias="DATABASE_URL_AUTH")
    database_url_stats: SecretStr = Field(validation_alias="DATABASE_URL_STATS")
    database_url_audit: SecretStr = Field(validation_alias="DATABASE_URL_AUDIT")
    # Optional. Only the FX refresh job needs it; when unset the web process can
    # read exchange rates but can never write them.
    database_url_fx: SecretStr | None = Field(default=None, validation_alias="DATABASE_URL_FX")
    master_secret: SecretStr = Field(validation_alias="MASTER_SECRET")
    app_env: Literal["development", "test", "production"] = Field(
        default="development", validation_alias="APP_ENV"
    )
    email_mode: Literal["dev_outbox", "smtp", "resend", "brevo"] = Field(
        default="dev_outbox", validation_alias="EMAIL_MODE"
    )
    resend_api_key: SecretStr | None = Field(default=None, validation_alias="RESEND_API_KEY")
    brevo_api_key: SecretStr | None = Field(default=None, validation_alias="BREVO_API_KEY")
    brevo_from: str | None = Field(
        default=None,
        validation_alias="BREVO_FROM",
        max_length=254,
        pattern=r"^[^@\s<>,;]+@[^@\s<>,;]+\.[^@\s<>,;]+$",
    )
    resend_from: str | None = Field(
        default=None,
        validation_alias="RESEND_FROM",
        max_length=254,
        pattern=r"^[^@\s<>,;]+@[^@\s<>,;]+\.[^@\s<>,;]+$",
    )
    # Render sets RENDER_EXTERNAL_URL automatically; PUBLIC_APP_URL wins if both exist.
    public_app_url: str | None = Field(
        default=None, validation_alias=AliasChoices("PUBLIC_APP_URL", "RENDER_EXTERNAL_URL")
    )
    cookie_secure_setting: bool | None = Field(
        default=None, validation_alias="COOKIE_SECURE"
    )
    smtp_host: str | None = Field(default=None, validation_alias="SMTP_HOST")
    smtp_port: int = Field(default=587, validation_alias="SMTP_PORT")
    smtp_username: SecretStr | None = Field(
        default=None, validation_alias="SMTP_USERNAME"
    )
    smtp_password: SecretStr | None = Field(
        default=None, validation_alias="SMTP_PASSWORD"
    )
    smtp_from: str | None = Field(default=None, validation_alias="SMTP_FROM")
    llm_base_url: str | None = Field(default=None, validation_alias="LLM_BASE_URL")
    llm_api_key: SecretStr | None = Field(default=None, validation_alias="LLM_API_KEY")
    llm_model: str | None = Field(default=None, validation_alias="LLM_MODEL")
    # Client IP resolution behind a reverse proxy (used only for rate limiting
    # and the IP HMAC). CLIENT_IP_HEADER names a header the platform overwrites
    # (e.g. CF-Connecting-IP on Render); TRUSTED_PROXY_HOPS counts proxies that
    # append to X-Forwarded-For. With neither set the socket peer is used.
    client_ip_header: str | None = Field(
        default=None, validation_alias="CLIENT_IP_HEADER", pattern=r"^[A-Za-z0-9-]{1,64}$"
    )
    trusted_proxy_hops: int = Field(default=0, ge=0, le=5, validation_alias="TRUSTED_PROXY_HOPS")
    app_timezone: str = Field(default="Asia/Karachi", validation_alias="APP_TIMEZONE")

    @model_validator(mode="after")
    def validate_runtime_settings(self):
        if self.email_mode == "dev_outbox" and self.app_env == "production":
            raise ValueError("dev_outbox mode is not allowed in production")
        if self.email_mode == "smtp" and not all(
            (self.smtp_host, self.smtp_username, self.smtp_password, self.smtp_from)
        ):
            raise ValueError("SMTP mode requires host, username, password, and from")
        if self.email_mode == "resend" and not (self.resend_from and self.resend_api_key):
            raise ValueError("Resend mode requires RESEND_API_KEY and RESEND_FROM")
        if self.email_mode == "brevo" and not (self.brevo_from and self.brevo_api_key):
            raise ValueError("Brevo mode requires BREVO_API_KEY and BREVO_FROM")
        try:
            ZoneInfo(self.app_timezone)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("APP_TIMEZONE must be an IANA time zone") from None
        if self.cookie_secure_setting is False and self.app_env == "production":
            raise ValueError("Secure cookies cannot be disabled in production")
        return self

    @staticmethod
    def _psycopg_url(value: SecretStr, expected_role: str) -> URL:
        try:
            url = make_url(value.get_secret_value())
        except Exception:
            raise ValueError(f"Invalid database URL for role {expected_role}") from None

        if url.drivername in {"postgres", "postgresql"}:
            url = url.set(drivername="postgresql+psycopg")
        elif url.drivername != "postgresql+psycopg":
            raise ValueError(f"Database URL for role {expected_role} must use PostgreSQL")

        if url.username != expected_role:
            raise ValueError(f"Database URL must authenticate as {expected_role}")
        return url

    @property
    def migrate_url(self) -> URL:
        return self._psycopg_url(self.database_url_migrate, "migration_owner")

    @property
    def app_url(self) -> URL:
        return self._psycopg_url(self.database_url_app, "app_service")

    @property
    def auth_url(self) -> URL:
        return self._psycopg_url(self.database_url_auth, "auth_service")

    @property
    def stats_url(self) -> URL:
        return self._psycopg_url(self.database_url_stats, "stats_reader")

    @property
    def audit_url(self) -> URL:
        return self._psycopg_url(self.database_url_audit, "audit_reader")

    @property
    def fx_url(self) -> URL | None:
        if self.database_url_fx is None:
            return None
        return self._psycopg_url(self.database_url_fx, "fx_writer")

    @property
    def master_key(self) -> bytes:
        try:
            key = base64.b64decode(self.master_secret.get_secret_value(), validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("MASTER_SECRET must be valid base64") from None
        if len(key) != 32:
            raise ValueError("MASTER_SECRET must decode to exactly 32 bytes")
        return key

    @property
    def cookie_secure(self) -> bool:
        if self.cookie_secure_setting is not None:
            return self.cookie_secure_setting
        return self.app_env != "development"

    @property
    def public_app_base_url(self) -> str:
        if not self.public_app_url:
            raise ValueError("PUBLIC_APP_URL must be configured for password reset")
        parsed = urlsplit(self.public_app_url)
        if (
            parsed.scheme not in {"https", "http"}
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("PUBLIC_APP_URL must be an absolute HTTP(S) URL without credentials")
        if self.app_env == "production" and parsed.scheme != "https":
            raise ValueError("PUBLIC_APP_URL must use HTTPS in production")
        return self.public_app_url.rstrip("/")


def get_settings() -> Settings:
    return Settings()


def local_today() -> date:
    """'Today' in APP_TIMEZONE (default Asia/Karachi), never the server's UTC date."""
    return datetime.now(ZoneInfo(get_settings().app_timezone)).date()
