#!/bin/sh
# Container entrypoint.
#   serve         (default) wait for the database, optionally migrate, then start the API
#   migrate       run Alembic migrations as migration_owner and exit
#   seed ARGS     create the synthetic guest demo account (interactive: use `run -it`)
#   create-staff  create a security_owner/admin account (interactive)
#   test          run the backend test suite against the configured database
#   refresh-fx    store today's exchange rates (needs DATABASE_URL_FX; for cron/sidecar)
#   verify-audit  verify the hash-chained audit log (exit 1 if tampered)
#   rotate-kek    re-wrap every data key (see scripts/rotate_kek.py)
#   anything else is executed as-is (e.g. `sh`)
set -eu

wait_for_db() {
  WAIT_DB_ROLE="${1:-app}" python - <<'PY'
import os, sys, time
from sqlalchemy import create_engine, text
from app.config import get_settings

# Jobs that hold only one credential (e.g. the FX sidecar) probe with that role.
role = os.environ.get("WAIT_DB_ROLE", "app")
settings = get_settings()
url = {"app": settings.app_url, "fx": settings.fx_url, "migrate": settings.migrate_url}[role]
engine = create_engine(url, connect_args={"prepare_threshold": None})
for attempt in range(1, 31):
    try:
        with engine.connect() as c:
            c.execute(text("SELECT 1"))
        print("entrypoint: database reachable", flush=True)
        sys.exit(0)
    except Exception as exc:
        print(f"entrypoint: waiting for database ({attempt}/30): {type(exc).__name__}", flush=True)
        time.sleep(2)
print("entrypoint: database not reachable, giving up", file=sys.stderr)
sys.exit(1)
PY
}

run_migrations() {
  echo "entrypoint: running migrations as migration_owner"
  alembic upgrade head
}

cmd="${1:-serve}"
case "$cmd" in
  serve)
    wait_for_db
    if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
      run_migrations
    fi
    # Rate limits live in PostgreSQL, so extra workers do not weaken them; the
    # default of 1 suits small free instances (Argon2id uses ~19 MiB per hash).
    exec uvicorn app.main:app \
      --host 0.0.0.0 \
      --port "${PORT:-8000}" \
      --workers "${WEB_CONCURRENCY:-1}" \
      --proxy-headers \
      --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-127.0.0.1}" \
      --no-server-header
    ;;
  migrate)
    wait_for_db migrate
    run_migrations
    ;;
  seed)
    shift
    wait_for_db
    exec python -m scripts.seed "$@"
    ;;
  create-staff)
    shift
    wait_for_db
    exec python -m scripts.create_staff "$@"
    ;;
  refresh-fx)
    wait_for_db fx
    exec python -m scripts.refresh_fx
    ;;
  fx-loop)
    # Long-running sidecar: refresh every 6 hours (a no-op once today is stored).
    wait_for_db fx
    while true; do python -m scripts.refresh_fx || true; sleep 21600; done
    ;;
  verify-audit)
    wait_for_db
    exec python -m scripts.verify_audit_chain
    ;;
  rotate-kek)
    shift
    wait_for_db
    exec python -m scripts.rotate_kek "$@"
    ;;
  test)
    shift
    wait_for_db
    exec python -m pytest -q "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
