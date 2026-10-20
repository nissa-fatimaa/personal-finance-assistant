"""HTTPS email provider tests; no live messages or credentials are used."""

from datetime import datetime, timedelta, timezone

import httpx
import pytest
from pydantic import ValidationError

from app.config import Settings, get_settings
from app.email import (
    BrevoEmailProvider,
    EmailProviderError,
    OutboundEmail,
    ResendEmailProvider,
    get_email_provider,
)


class _Response:
    def __init__(self, status_code: int):
        self.status_code = status_code


def _message(recipient: str = "registered@example.invalid", subject: str = "Password reset"):
    return OutboundEmail(
        kind="password_reset",
        recipient=recipient,
        subject=subject,
        body="Reset: https://example.invalid/reset-password#token=canary-reset-token",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
    )


@pytest.fixture
def resend(monkeypatch):
    monkeypatch.setenv("EMAIL_MODE", "resend")
    monkeypatch.setenv("RESEND_FROM", "security@example.invalid")
    monkeypatch.setenv("RESEND_API_KEY", "re_canary_key")
    return ResendEmailProvider(get_settings())


@pytest.fixture
def brevo(monkeypatch):
    monkeypatch.setenv("EMAIL_MODE", "brevo")
    monkeypatch.setenv("BREVO_FROM", "security@example.invalid")
    monkeypatch.setenv("BREVO_API_KEY", "xkeysib-canary")
    return BrevoEmailProvider(get_settings())


def test_T46_resend_posts_one_recipient_over_https_with_bearer_key(resend, monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.email.httpx.post",
        lambda url, **kw: calls.append((url, kw)) or _Response(200),
    )
    resend.send(_message())
    url, kwargs = calls[0]
    assert url == "https://api.resend.com/emails"
    assert kwargs["headers"] == {"Authorization": "Bearer re_canary_key"}
    assert kwargs["json"]["to"] == ["registered@example.invalid"]
    assert kwargs["json"]["from"] == "security@example.invalid"
    assert kwargs["timeout"] == 10


def test_T46_provider_errors_never_include_payload_key_or_upstream_content(resend, monkeypatch):
    def boom(url, **kwargs):
        raise httpx.ConnectError("canary-upstream-body")

    monkeypatch.setattr("app.email.httpx.post", boom)
    with pytest.raises(EmailProviderError) as raised:
        resend.send(_message())
    for canary in ("canary-upstream-body", "canary-reset-token", "re_canary_key", "registered@"):
        assert canary not in str(raised.value)
    monkeypatch.setattr("app.email.httpx.post", lambda url, **kw: _Response(401))
    with pytest.raises(EmailProviderError) as raised:
        resend.send(_message())
    assert str(raised.value) == "Resend provider failed"


@pytest.mark.parametrize(
    "recipient",
    ["a@example.invalid, b@example.invalid", "a@example.invalid\nBcc: b@example.invalid", "x"],
)
def test_T49_providers_reject_multiple_or_injected_recipients(resend, brevo, monkeypatch, recipient):
    calls = []
    monkeypatch.setattr("app.email.httpx.post", lambda url, **kw: calls.append(url) or _Response(201))
    for provider in (resend, brevo):
        with pytest.raises(EmailProviderError):
            provider.send(_message(recipient=recipient))
    assert calls == []


def test_T49_subject_header_injection_is_rejected(brevo, monkeypatch):
    monkeypatch.setattr("app.email.httpx.post", lambda url, **kw: _Response(201))
    with pytest.raises(EmailProviderError):
        brevo.send(_message(subject="Reset\r\nBcc: attacker@example.invalid"))


def test_T49_brevo_uses_api_key_header(brevo, monkeypatch):
    calls = []
    monkeypatch.setattr("app.email.httpx.post", lambda url, **kw: calls.append((url, kw)) or _Response(201))
    brevo.send(_message())
    url, kwargs = calls[0]
    assert url == "https://api.brevo.com/v3/smtp/email"
    assert kwargs["headers"] == {"api-key": "xkeysib-canary"}
    assert kwargs["json"]["to"] == [{"email": "registered@example.invalid"}]


@pytest.mark.parametrize(
    "env",
    [
        {"EMAIL_MODE": "resend", "RESEND_FROM": "s@example.invalid"},  # no key
        {"EMAIL_MODE": "resend", "RESEND_API_KEY": "k"},  # no sender
        {"EMAIL_MODE": "brevo", "BREVO_API_KEY": "k"},
        {"EMAIL_MODE": "gmail"},  # removed mode: must be rejected, not silently accepted
        {"EMAIL_MODE": "dev_outbox", "APP_ENV": "production"},
    ],
)
def test_T51_config_rejects_unusable_email_modes(monkeypatch, env):
    for name in ("RESEND_FROM", "RESEND_API_KEY", "BREVO_FROM", "BREVO_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(ValidationError):
        Settings()


def test_dev_outbox_is_the_default_provider_in_development(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("EMAIL_MODE", "dev_outbox")
    assert type(get_email_provider()).__name__ == "DevelopmentOutboxProvider"
