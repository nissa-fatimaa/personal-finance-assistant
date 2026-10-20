"""Create a security_owner or admin account after a TOTP proof of possession."""

import argparse
import getpass
import re
import sys
from uuid import uuid4

import pyotp
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app import crypto
from app.audit import append_event
from app.auth import hash_password
from app.db import auth_engine

EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
STAFF_ROLES = {"security_owner", "admin"}


def create_staff(email: str, role: str) -> None:
    normalized_email = crypto.norm_email(email)
    if role not in STAFF_ROLES:
        raise ValueError("role must be security_owner or admin")
    if not EMAIL_PATTERN.fullmatch(normalized_email):
        raise ValueError("invalid email address")
    if input("Privacy notice accepted? Type yes: ").strip().lower() != "yes":
        raise ValueError("privacy notice acceptance is required")

    password = getpass.getpass("Initial password: ")
    password_hash = hash_password(password, (normalized_email,))
    secret = pyotp.random_base32()
    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
        name=normalized_email, issuer_name="PFA"
    )
    print("Scan this one-time TOTP provisioning URI in the staff authenticator:")
    print(provisioning_uri)
    code = getpass.getpass("Enter the current six-digit TOTP code: ").strip()
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        raise ValueError("TOTP proof failed; no account was created")

    user_id = uuid4()
    dek = crypto.new_dek()
    totp_ciphertext = crypto.enc(
        dek,
        secret.encode("ascii"),
        "users",
        "totp_secret_enc",
        user_id,
    )
    try:
        with auth_engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO public.users "
                    "(user_id, email_hmac, email_enc, password_hash, dek_wrapped, "
                    "base_currency, role, privacy_consent_at, totp_secret_enc) "
                    "VALUES (:user_id, :email_hmac, :email_enc, :password_hash, "
                    ":dek_wrapped, 'PKR', :role, now(), :totp_secret_enc)"
                ),
                {
                    "user_id": user_id,
                    "email_hmac": crypto.hmac_email(normalized_email),
                    "email_enc": crypto.enc(
                        dek,
                        normalized_email.encode("utf-8"),
                        "users",
                        "email_enc",
                        user_id,
                    ),
                    "password_hash": password_hash,
                    "dek_wrapped": crypto.wrap_dek(dek, user_id),
                    "role": role,
                    "totp_secret_enc": totp_ciphertext,
                },
            )
            append_event(
                connection,
                action="staff_created",
                result="ok",
                actor_user_id=None,
                target_id=user_id,
            )
    except IntegrityError:
        raise ValueError("account could not be created") from None
    print("Staff account created with confirmed TOTP.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("email")
    parser.add_argument("role", choices=sorted(STAFF_ROLES))
    args = parser.parse_args()
    try:
        create_staff(args.email, args.role)
    except (ValueError, RuntimeError):
        print("Staff account creation failed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
