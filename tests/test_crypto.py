from datetime import date
from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidTag

from app import crypto


def test_crypto_round_trip_and_key_wrapping():
    user_id = uuid4()
    dek = crypto.new_dek()
    wrapped = crypto.wrap_dek(dek, user_id)
    assert crypto.unwrap_dek(wrapped, user_id) == dek

    blob = crypto.enc(dek, b"synthetic finance field", "transactions", "amount_enc", user_id)
    assert crypto.dec(dek, blob, "transactions", "amount_enc", user_id) == b"synthetic finance field"


def test_crypto_tamper_is_rejected():
    user_id = uuid4()
    dek = crypto.new_dek()
    blob = crypto.enc(dek, b"synthetic", "accounts", "name_enc", user_id)
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(InvalidTag):
        crypto.dec(dek, tampered, "accounts", "name_enc", user_id)


def test_crypto_wrong_row_is_rejected():
    dek = crypto.new_dek()
    original_row = uuid4()
    different_row = uuid4()
    blob = crypto.enc(dek, b"synthetic", "transactions", "amount_enc", original_row)
    with pytest.raises(InvalidTag):
        crypto.dec(dek, blob, "transactions", "amount_enc", different_row)


def test_hkdf_separates_purposes_and_user_hmacs():
    keys = crypto.key_material()
    assert len({keys.kek, keys.email_lookup, keys.pepper, keys.ip_key}) == 4

    user_a, user_b = uuid4(), uuid4()
    assert crypto.merchant_hmac(user_a, " Coffee Shop ") != crypto.merchant_hmac(
        user_b, "coffee shop"
    )
    assert crypto.hmac_email("  TEST@example.invalid ") == crypto.hmac_email(
        "test@example.invalid"
    )


def test_dedupe_hmac_is_stable_for_same_normalized_record():
    user_id = uuid4()
    day = date(2026, 10, 19)
    one = crypto.dedupe_hmac(user_id, " Coffee Shop ", 1250, "PKR", day)
    two = crypto.dedupe_hmac(user_id, "coffee shop", 1250, "PKR", day)
    assert one == two
