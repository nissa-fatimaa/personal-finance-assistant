"""Rotate the key-encryption key (KEK) by re-wrapping every user's data key.

Rows are NOT re-encrypted: only users.dek_wrapped changes, inside one
transaction that is verified before commit (all-or-nothing).

Procedure (see README "Key rotation"):
  1. Generate a new secret:  python -c "import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())"
  2. Dry run:   KEK_ROTATE_FROM=master KEK_ROTATE_TO=<new> python -m scripts.rotate_kek --dry-run
     (FROM is 'master' the first time, or the current KEK_SECRET afterwards)
  3. Rotate:    same command without --dry-run
  4. Set KEK_SECRET=<new> on the service and restart. Keep the old value until
     the restart is confirmed, then destroy it.
"""

import argparse
import os
import sys
from uuid import UUID

from sqlalchemy import text

from app import crypto
from app.audit import append_event
from app.db import auth_engine


def rotate(old_kek: bytes, new_kek: bytes, *, dry_run: bool = False,
           user_ids: list[UUID] | None = None) -> int:
    if old_kek == new_kek:
        raise ValueError("new KEK must differ from the old KEK")
    query = (
        "SELECT user_id, dek_wrapped FROM public.users WHERE status <> 'deleted' "
        + ("AND user_id = ANY(:ids) " if user_ids is not None else "")
        + "FOR UPDATE"
    )
    with auth_engine.begin() as connection:
        rows = connection.execute(
            text(query), {"ids": user_ids} if user_ids is not None else {}
        ).all()
        rewrapped = []
        for row in rows:
            # Raises InvalidTag if the old KEK is wrong: nothing is written.
            dek = crypto.unwrap_dek(bytes(row.dek_wrapped), row.user_id, kek=old_kek)
            blob = crypto.wrap_dek(dek, row.user_id, kek=new_kek)
            if crypto.unwrap_dek(blob, row.user_id, kek=new_kek) != dek:
                raise RuntimeError("re-wrap verification failed")
            rewrapped.append({"user_id": row.user_id, "blob": blob})
        if dry_run:
            connection.rollback()
            return len(rewrapped)
        if rewrapped:
            connection.execute(
                text("UPDATE public.users SET dek_wrapped = :blob WHERE user_id = :user_id"),
                rewrapped,
            )
        append_event(connection, action="kek_rotated", result="ok")
    return len(rewrapped)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    source, target = os.environ.get("KEK_ROTATE_FROM"), os.environ.get("KEK_ROTATE_TO")
    if not source or not target:
        print("Set KEK_ROTATE_FROM ('master' or base64) and KEK_ROTATE_TO (base64).", file=sys.stderr)
        return 2
    count = rotate(crypto.kek_from(source), crypto.kek_from(target), dry_run=args.dry_run)
    verb = "would re-wrap" if args.dry_run else "re-wrapped"
    print(f"{verb} {count} data keys. Next: set KEK_SECRET to the new value and restart.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
