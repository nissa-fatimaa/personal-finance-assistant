"""Database-backed fixed-window rate limits shared by every worker and restart.

Keys are HMACs (never raw IPs, emails or tokens). Each check is one atomic
UPSERT, so concurrent workers cannot both pass the last free slot.
"""

from dataclasses import dataclass
from datetime import timedelta
import hashlib
import hmac
import secrets

from sqlalchemy import text

from app import crypto
from app.db import auth_engine


@dataclass(frozen=True)
class Limit:
    bucket: str
    limit: int
    window: timedelta


# Per-IP limits (an IP may be shared, e.g. a campus NAT, so these are generous).
REGISTER_PER_IP = Limit("register_ip", 10, timedelta(hours=1))
LOGIN_FAIL_PER_IP = Limit("login_fail_ip", 20, timedelta(minutes=15))
RESET_PER_IP = Limit("reset_ip", 5, timedelta(minutes=15))
MFA_FAIL_PER_IP = Limit("mfa_fail_ip", 20, timedelta(minutes=15))
# Per-session / per-account MFA brute-force limits.
MFA_FAIL_PER_SESSION = Limit("mfa_fail_session", 5, timedelta(minutes=15))
MFA_FAIL_PER_ACCOUNT = Limit("mfa_fail_account", 10, timedelta(minutes=15))
# Per-user cost controls: OCR is CPU-heavy, chat may call a paid model.
RECEIPT_PER_USER = Limit("receipt_user", 30, timedelta(hours=1))
CHAT_PER_USER = Limit("chat_user", 120, timedelta(hours=1))
# Re-authentication inside a live session (export, delete, password/MFA/role changes).
REAUTH_FAIL_PER_ACCOUNT = Limit("reauth_fail_account", 5, timedelta(minutes=15))

_UPSERT = text(
    "INSERT INTO public.rate_limits (bucket, key_hmac, window_start, hits) "
    "VALUES (:bucket, :key, now(), :inc) "
    "ON CONFLICT (bucket, key_hmac) DO UPDATE SET "
    "hits = CASE WHEN public.rate_limits.window_start <= now() - :window "
    "THEN :inc ELSE public.rate_limits.hits + :inc END, "
    "window_start = CASE WHEN public.rate_limits.window_start <= now() - :window "
    "THEN now() ELSE public.rate_limits.window_start END "
    "RETURNING hits"
)


def key_for(kind: str, value: str | bytes) -> bytes:
    """Derive a 32-byte limiter key; raw identifiers never reach the table."""
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return hmac.new(
        crypto.key_material().ip_key, b"ratelimit|" + kind.encode() + b"|" + raw, hashlib.sha256
    ).digest()


def _apply(limit: Limit, key: bytes, increment: int, connection=None) -> int:
    params = {"bucket": limit.bucket, "key": key, "inc": increment, "window": limit.window}
    if connection is not None:
        return int(connection.execute(_UPSERT, params).scalar_one())
    with auth_engine.begin() as own:
        # Opportunistic cleanup keeps the table small without a cron job.
        if secrets.randbelow(100) == 0:
            own.execute(
                text("DELETE FROM public.rate_limits WHERE window_start < now() - interval '2 days'")
            )
        return int(own.execute(_UPSERT, params).scalar_one())


def hit(limit: Limit, key: bytes, connection=None) -> bool:
    """Record one event; return True while the window is still within its limit."""
    return _apply(limit, key, 1, connection) <= limit.limit


def record_failure(limit: Limit, key: bytes, connection=None) -> bool:
    """Record one failure; return True when this failure reaches the limit.

    Used for "N failures then act" rules (revoke, lock): the action happens on
    the N-th failure, and exceeded() blocks every attempt after it.
    """
    return _apply(limit, key, 1, connection) >= limit.limit


def exceeded(limit: Limit, key: bytes, connection=None) -> bool:
    """Read-only check (records nothing): has this key already used its window?"""
    query = text(
        "SELECT hits FROM public.rate_limits WHERE bucket = :bucket AND key_hmac = :key "
        "AND window_start > now() - :window"
    )
    params = {"bucket": limit.bucket, "key": key, "window": limit.window}
    if connection is not None:
        hits = connection.execute(query, params).scalar_one_or_none()
    else:
        with auth_engine.begin() as own:
            hits = own.execute(query, params).scalar_one_or_none()
    return hits is not None and hits >= limit.limit


def clear(limit: Limit, key: bytes, connection=None) -> None:
    query = text("DELETE FROM public.rate_limits WHERE bucket = :bucket AND key_hmac = :key")
    params = {"bucket": limit.bucket, "key": key}
    if connection is not None:
        connection.execute(query, params)
    else:
        with auth_engine.begin() as own:
            own.execute(query, params)
