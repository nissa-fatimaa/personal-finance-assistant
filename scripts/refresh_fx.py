"""Fetch and store today's exchange-rate snapshot as the fx_writer role.

Designed for a scheduled job (GitHub Actions cron or a platform cron job) so
the public web process can run without any write access to fx_rates.
Usage:  DATABASE_URL_FX=... python -m scripts.refresh_fx    (exit 0 = snapshot present)
"""

from app import db, fx


def main() -> int:
    if db.fx_engine is None:
        print("DATABASE_URL_FX is not set; nothing to do.")
        return 2
    stored = fx.ensure_today()
    print(f"fx snapshot for {fx.today().isoformat()}: {'present' if stored else 'not stored'}")
    return 0 if stored else 1


if __name__ == "__main__":
    raise SystemExit(main())
