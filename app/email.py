"""Email provider abstraction with a development-only encrypted outbox."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage as MimeEmail
import re
import smtplib
import ssl
from typing import Protocol
from uuid import UUID, uuid4

import httpx
from sqlalchemy import text

from app import crypto
from app.config import Settings, get_settings
from app.db import auth_engine


class EmailProviderError(RuntimeError):
    """Safe provider failure; never includes message content or credentials."""


@dataclass(frozen=True)
class OutboundEmail:
    kind: str
    recipient: str
    subject: str
    body: str
    expires_at: datetime


class EmailProvider(Protocol):
    def send(self, message: OutboundEmail) -> None: ...


class DevelopmentOutboxProvider:
    """Persist encrypted messages in a development-only table, never claim delivery."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        if self.settings.app_env != "development":
            raise RuntimeError("dev_outbox is available only in development")

    def send(self, message: OutboundEmail) -> None:
        message_id = uuid4()
        key = crypto.key_material().outbox_encryption
        values = {
            column: crypto.enc(
                key,
                value.encode("utf-8"),
                "dev_outbox",
                column,
                message_id,
            )
            for column, value in (
                ("recipient_enc", message.recipient),
                ("subject_enc", message.subject),
                ("body_enc", message.body),
            )
        }
        with auth_engine.begin() as connection:
            connection.execute(
                text("DELETE FROM public.dev_outbox WHERE expires_at <= now()")
            )
            connection.execute(
                text(
                    "INSERT INTO public.dev_outbox "
                    "(message_id, email_kind, recipient_enc, subject_enc, body_enc, expires_at) "
                    "VALUES (:message_id, :email_kind, :recipient_enc, :subject_enc, "
                    ":body_enc, :expires_at)"
                ),
                {
                    "message_id": message_id,
                    "email_kind": message.kind,
                    **values,
                    "expires_at": message.expires_at,
                },
            )


class SMTPEmailProvider:
    """Send email over authenticated TLS; delivery is not claimed until accepted."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        if self.settings.email_mode != "smtp":
            raise RuntimeError("SMTP provider requires EMAIL_MODE=smtp")

    def send(self, message: OutboundEmail) -> None:
        smtp_message = MimeEmail()
        smtp_message["From"] = self.settings.smtp_from
        smtp_message["To"] = message.recipient
        smtp_message["Subject"] = message.subject
        smtp_message.set_content(message.body)
        password = self.settings.smtp_password.get_secret_value()
        try:
            if self.settings.smtp_port == 465:
                with smtplib.SMTP_SSL(
                    self.settings.smtp_host,
                    self.settings.smtp_port,
                    timeout=10,
                    context=ssl.create_default_context(),
                ) as client:
                    client.login(
                        self.settings.smtp_username.get_secret_value(), password
                    )
                    client.send_message(smtp_message)
            else:
                with smtplib.SMTP(
                    self.settings.smtp_host, self.settings.smtp_port, timeout=10
                ) as client:
                    client.ehlo()
                    client.starttls(context=ssl.create_default_context())
                    client.ehlo()
                    client.login(
                        self.settings.smtp_username.get_secret_value(), password
                    )
                    client.send_message(smtp_message)
        except Exception:
            raise EmailProviderError("SMTP provider failed") from None


def _post_json(url: str, *, headers: dict, payload: dict, provider: str) -> None:
    """POST to an HTTPS email API. Errors never include the body, token or reply."""
    try:
        response = httpx.post(url, headers=headers, json=payload, timeout=10)
    except httpx.HTTPError:
        raise EmailProviderError(f"{provider} provider failed") from None
    if response.status_code not in (200, 201, 202):
        raise EmailProviderError(f"{provider} provider failed")


def _single_mailbox(address: str, provider: str) -> str:
    if not re.fullmatch(r"[^@\s<>,;]+@[^@\s<>,;]+\.[^@\s<>,;]+", address):
        raise EmailProviderError(f"{provider} provider failed")
    return address


class ResendEmailProvider:
    """Resend HTTPS API (https://resend.com). Needs RESEND_API_KEY + RESEND_FROM."""

    URL = "https://api.resend.com/emails"

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        if self.settings.email_mode != "resend" or not (
            self.settings.resend_from and self.settings.resend_api_key
        ):
            raise RuntimeError("Resend provider requires resend mode, key and sender")

    def send(self, message: OutboundEmail) -> None:
        if re.search(r"[\r\n]", message.subject):
            raise EmailProviderError("Resend provider failed")
        _post_json(
            self.URL,
            headers={
                "Authorization": f"Bearer {self.settings.resend_api_key.get_secret_value()}"
            },
            payload={
                "from": self.settings.resend_from,
                "to": [_single_mailbox(message.recipient, "Resend")],
                "subject": message.subject,
                "text": message.body,
            },
            provider="Resend",
        )


class BrevoEmailProvider:
    """Brevo transactional HTTPS API. Needs BREVO_API_KEY + BREVO_FROM (verified sender)."""

    URL = "https://api.brevo.com/v3/smtp/email"

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        if self.settings.email_mode != "brevo" or not (
            self.settings.brevo_from and self.settings.brevo_api_key
        ):
            raise RuntimeError("Brevo provider requires brevo mode, key and sender")

    def send(self, message: OutboundEmail) -> None:
        if re.search(r"[\r\n]", message.subject):
            raise EmailProviderError("Brevo provider failed")
        _post_json(
            self.URL,
            headers={"api-key": self.settings.brevo_api_key.get_secret_value()},
            payload={
                "sender": {"name": "Finwise", "email": self.settings.brevo_from},
                "to": [{"email": _single_mailbox(message.recipient, "Brevo")}],
                "subject": message.subject,
                "textContent": message.body,
            },
            provider="Brevo",
        )


def get_email_provider(settings: Settings | None = None) -> EmailProvider:
    configured = settings or get_settings()
    if configured.email_mode == "dev_outbox":
        return DevelopmentOutboxProvider(configured)
    if configured.email_mode == "resend":
        return ResendEmailProvider(configured)
    if configured.email_mode == "brevo":
        return BrevoEmailProvider(configured)
    return SMTPEmailProvider(configured)


def consume_dev_outbox(message_id: UUID | None = None) -> list[OutboundEmail]:
    """Consume and decrypt development messages once; disabled outside development."""
    settings = get_settings()
    if settings.app_env != "development" or settings.email_mode != "dev_outbox":
        raise RuntimeError("dev_outbox inspection is disabled")

    query = (
        "DELETE FROM public.dev_outbox WHERE expires_at > now() "
    )
    params = {}
    if message_id is not None:
        query += "AND message_id = :message_id "
        params["message_id"] = message_id
    query += (
        "RETURNING message_id, email_kind, recipient_enc, subject_enc, body_enc, expires_at"
    )

    with auth_engine.begin() as connection:
        connection.execute(
            text("DELETE FROM public.dev_outbox WHERE expires_at <= now()")
        )
        rows = connection.execute(text(query), params).mappings().all()

    key = crypto.key_material().outbox_encryption
    return [
        OutboundEmail(
            kind=row["email_kind"],
            recipient=crypto.dec(
                key, row["recipient_enc"], "dev_outbox", "recipient_enc", row["message_id"]
            ).decode("utf-8"),
            subject=crypto.dec(
                key, row["subject_enc"], "dev_outbox", "subject_enc", row["message_id"]
            ).decode("utf-8"),
            body=crypto.dec(
                key, row["body_enc"], "dev_outbox", "body_enc", row["message_id"]
            ).decode("utf-8"),
            expires_at=row["expires_at"],
        )
        for row in rows
    ]


def notification_message(
    *,
    kind: str,
    recipient: str,
    subject: str,
    browser_family: str,
    now: datetime | None = None,
) -> OutboundEmail:
    timestamp = now or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        raise ValueError("Email timestamp must be timezone-aware")
    body = (
        f"UTC: {timestamp.astimezone(timezone.utc).isoformat()}\n"
        f"Browser: {browser_family}"
    )
    return OutboundEmail(
        kind=kind,
        recipient=recipient,
        subject=subject,
        body=body,
        expires_at=timestamp + timedelta(days=1),
    )
