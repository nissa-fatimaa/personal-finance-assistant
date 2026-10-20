#!/usr/bin/env bash
# Creates the six least-privilege PostgreSQL roles and the application database.
# Runs ONCE as the PostgreSQL superuser:
#   * automatically by the official postgres image (mounted in /docker-entrypoint-initdb.d), or
#   * manually against a managed database:  PGHOST=... PGUSER=<admin> ./db/init-roles.sh
# None of the roles is SUPERUSER or BYPASSRLS. The running app never uses migration_owner.
set -Eeuo pipefail

: "${PFA_DB_NAME:=pfa}"
for var in MIGRATION_OWNER_PASSWORD APP_SERVICE_PASSWORD AUTH_SERVICE_PASSWORD \
           STATS_READER_PASSWORD AUDIT_READER_PASSWORD FX_WRITER_PASSWORD; do
  if [ -z "${!var:-}" ]; then
    echo "init-roles: $var is required" >&2
    exit 1
  fi
done

PSQL=(psql -v ON_ERROR_STOP=1 --no-psqlrc)
# Inside the postgres image the superuser is reachable through the local socket.
if [ -n "${POSTGRES_USER:-}" ] && [ -z "${PGUSER:-}" ]; then
  PSQL+=(--username "$POSTGRES_USER")
fi

"${PSQL[@]}" --dbname "${PGDATABASE:-postgres}" \
  -v db_name="$PFA_DB_NAME" \
  -v p_mig="$MIGRATION_OWNER_PASSWORD" \
  -v p_app="$APP_SERVICE_PASSWORD" \
  -v p_auth="$AUTH_SERVICE_PASSWORD" \
  -v p_stats="$STATS_READER_PASSWORD" \
  -v p_audit="$AUDIT_READER_PASSWORD" \
  -v p_fx="$FX_WRITER_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE', r)
FROM unnest(ARRAY['migration_owner','app_service','auth_service','stats_reader','audit_reader','fx_writer']) AS r
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r)
\gexec

-- Managed hosts (Neon, Supabase, RDS) use a non-superuser admin. PostgreSQL 16 only lets it
-- create a database owned by migration_owner if it may SET ROLE to it, so grant that once.
SELECT format('GRANT migration_owner TO %I', current_user)
WHERE NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
  AND NOT pg_has_role(current_user, 'migration_owner', 'SET')
\gexec

ALTER ROLE migration_owner PASSWORD :'p_mig';
ALTER ROLE app_service     PASSWORD :'p_app';
ALTER ROLE auth_service    PASSWORD :'p_auth';
ALTER ROLE stats_reader    PASSWORD :'p_stats';
ALTER ROLE audit_reader    PASSWORD :'p_audit';
ALTER ROLE fx_writer       PASSWORD :'p_fx';

SELECT format('CREATE DATABASE %I OWNER migration_owner', :'db_name')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db_name')
\gexec
SQL

"${PSQL[@]}" --dbname "$PFA_DB_NAME" <<'SQL'
ALTER SCHEMA public OWNER TO migration_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO app_service, auth_service, stats_reader, audit_reader, fx_writer;
SQL

echo "init-roles: roles and database '$PFA_DB_NAME' are ready"
