"""Field encryption and purpose-separated key derivation.

This module never logs key material. Ciphertexts are stored as a 12-byte nonce
followed by AES-GCM ciphertext and its 16-byte authentication tag.
"""

import base64
import hashlib
import hmac
import os
import unicodedata
from dataclasses import dataclass, field
from datetime import date
from functools import lru_cache
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass(frozen=True, repr=False)
class KeyMaterial:
    kek: bytes = field(repr=False)
    email_lookup: bytes = field(repr=False)
    pepper: bytes = field(repr=False)
    ip_key: bytes = field(repr=False)
    outbox_encryption: bytes = field(repr=False)

    def __repr__(self) -> str:
        return "KeyMaterial(<redacted>)"


def _require_32_bytes(key: bytes, label: str) -> None:
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError(f"{label} must be exactly 32 bytes")


def _hkdf(master_secret: bytes, label: str, context: bytes = b"") -> bytes:
    _require_32_bytes(master_secret, "Master secret")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=label.encode("utf-8") + b"|" + context,
    ).derive(master_secret)


def derive_keys(master_secret: bytes, kek_secret: bytes | None = None) -> KeyMaterial:
    """Derive independent keys for wrapping, email lookup, password pepper, and IP HMAC.

    The key-encryption key comes from KEK_SECRET when set, so it can be rotated
    (scripts/rotate_kek.py re-wraps every data key) without touching the
    password pepper or lookup HMAC keys that MASTER_SECRET also feeds.
    """
    _require_32_bytes(master_secret, "Master secret")
    return KeyMaterial(
        kek=_hkdf(kek_secret if kek_secret is not None else master_secret, "kek"),
        email_lookup=_hkdf(master_secret, "email-lookup"),
        pepper=_hkdf(master_secret, "pepper"),
        ip_key=_hkdf(master_secret, "ip"),
        outbox_encryption=_hkdf(master_secret, "email-outbox"),
    )


def decode_secret(name: str, *, required: bool = True) -> bytes | None:
    encoded = os.environ.get(name)
    if not encoded:
        if required:
            raise RuntimeError(f"{name} is required")
        return None
    try:
        secret = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        raise ValueError(f"{name} must be valid base64") from None
    _require_32_bytes(secret, name)
    return secret


def _decode_master_secret() -> bytes:
    return decode_secret("MASTER_SECRET")


@lru_cache(maxsize=4)
def _cached_keys(master_secret: bytes, kek_secret: bytes | None) -> KeyMaterial:
    return derive_keys(master_secret, kek_secret)


def key_material(master_secret: bytes | None = None) -> KeyMaterial:
    """Return derived key material, loading secrets only when not injected."""
    if master_secret is not None:
        return _cached_keys(master_secret, None)
    return _cached_keys(_decode_master_secret(), decode_secret("KEK_SECRET", required=False))


def kek_from(source: str) -> bytes:
    """Resolve a rotation source: 'master' (HKDF of MASTER_SECRET) or a base64 secret."""
    if source == "master":
        return _hkdf(_decode_master_secret(), "kek")
    secret = base64.b64decode(source, validate=True)
    _require_32_bytes(secret, "KEK secret")
    return _hkdf(secret, "kek")


def _user_hmac_key(user_id: Any) -> bytes:
    return _hkdf(_decode_master_secret(), "user-hmac", str(user_id).encode("utf-8"))


def new_dek() -> bytes:
    """Create a random 256-bit per-user data-encryption key."""
    return os.urandom(32)


def wrap_dek(dek: bytes, user_id: Any, kek: bytes | None = None) -> bytes:
    """Wrap a user's data key with AES-256-GCM and bind it to that user ID."""
    _require_32_bytes(dek, "Data key")
    wrapping_key = key_material().kek if kek is None else kek
    _require_32_bytes(wrapping_key, "Key-encryption key")
    nonce = os.urandom(12)
    aad = b"dek|" + str(user_id).encode("utf-8")
    return nonce + AESGCM(wrapping_key).encrypt(nonce, dek, aad)


def unwrap_dek(blob: bytes, user_id: Any, kek: bytes | None = None) -> bytes:
    """Unwrap a user's data key; authentication failures propagate as InvalidTag."""
    wrapping_key = key_material().kek if kek is None else kek
    _require_32_bytes(wrapping_key, "Key-encryption key")
    if not isinstance(blob, bytes) or len(blob) < 12 + 16:
        raise ValueError("Wrapped data key is malformed")
    aad = b"dek|" + str(user_id).encode("utf-8")
    return AESGCM(wrapping_key).decrypt(blob[:12], blob[12:], aad)


def enc(dek: bytes, plaintext: bytes, table: str, column: str, row_id: Any) -> bytes:
    """Encrypt bytes using fresh-nonce AES-256-GCM and location-bound AAD."""
    _require_32_bytes(dek, "Data key")
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes")
    nonce = os.urandom(12)
    aad = f"{table}.{column}.{row_id}".encode("utf-8")
    return nonce + AESGCM(dek).encrypt(nonce, plaintext, aad)


def dec(dek: bytes, blob: bytes, table: str, column: str, row_id: Any) -> bytes:
    """Decrypt a location-bound ciphertext; tampering or moved rows raise InvalidTag."""
    _require_32_bytes(dek, "Data key")
    if not isinstance(blob, bytes) or len(blob) < 12 + 16:
        raise ValueError("Ciphertext is malformed")
    aad = f"{table}.{column}.{row_id}".encode("utf-8")
    return AESGCM(dek).decrypt(blob[:12], blob[12:], aad)


def norm_email(email: str) -> str:
    return unicodedata.normalize("NFKC", email).strip().lower()


def hmac_email(email: str) -> bytes:
    return hmac.new(
        key_material().email_lookup,
        norm_email(email).encode("utf-8"),
        hashlib.sha256,
    ).digest()


def hmac_ip(ip: str) -> bytes:
    return hmac.new(key_material().ip_key, ip.encode("utf-8"), hashlib.sha256).digest()


def merchant_hmac(user_id: Any, merchant: str) -> bytes:
    normalized = unicodedata.normalize("NFKC", merchant).strip().lower()
    return hmac.new(
        _user_hmac_key(user_id), normalized.encode("utf-8"), hashlib.sha256
    ).digest()


def browser_hmac(user_id: Any, browser_family: str) -> bytes:
    """Return a per-user HMAC for browser-family comparison without storing the UA."""
    normalized = unicodedata.normalize("NFKC", browser_family).strip().lower()
    return hmac.new(
        _user_hmac_key(user_id), b"browser|" + normalized.encode("utf-8"), hashlib.sha256
    ).digest()


def dedupe_hmac(
    user_id: Any,
    merchant: str,
    amount_minor: int,
    currency: str,
    txn_date: date,
    nonce: str = "",
) -> bytes:
    if isinstance(amount_minor, bool) or not isinstance(amount_minor, int):
        raise TypeError("amount_minor must be an integer")
    normalized = unicodedata.normalize("NFKC", merchant).strip().lower()
    message = "|".join(
        [normalized, str(amount_minor), currency, txn_date.isoformat(), nonce]
    )
    return hmac.new(
        _user_hmac_key(user_id), message.encode("utf-8"), hashlib.sha256
    ).digest()


__all__ = [
    "InvalidTag",
    "KeyMaterial",
    "browser_hmac",
    "dec",
    "dedupe_hmac",
    "derive_keys",
    "enc",
    "hmac_email",
    "hmac_ip",
    "key_material",
    "merchant_hmac",
    "new_dek",
    "norm_email",
    "unwrap_dek",
    "wrap_dek",
]
