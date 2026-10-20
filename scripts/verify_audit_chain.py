"""Verify the hash-chained audit log (runs the database's audit_verify()).

Usage:  python -m scripts.verify_audit_chain      (exit code 0 = intact, 1 = tampered)
Connects as audit_reader, which can read and verify but never modify the log.
"""

from sqlalchemy import text

from app.db import audit_engine


def verify() -> bool:
    with audit_engine.begin() as connection:
        return bool(connection.execute(text("SELECT public.audit_verify()")).scalar_one())


if __name__ == "__main__":
    intact = verify()
    print("audit chain: INTACT" if intact else "audit chain: TAMPERING DETECTED")
    raise SystemExit(0 if intact else 1)
