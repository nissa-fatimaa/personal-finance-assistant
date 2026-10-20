# Finwise · Personal Finance Assistant

An intelligent assistant for individual users: budgeting, bill analysis, spending insights and actionable recommendations. FinTechathon 2026, Topic A.

- **Repository:** `https://github.com/nissa-fatimaa/personal-finance-assistant`
- **Live demo:** `https://personal-finance-assistant-tpb6.onrender.com` (free tier: first load after 15 idle minutes takes about a minute)
- **Documents:** `docs/Security_Self_Assessment_Report.docx`, `docs/Technical_Documentation.docx` (also attached with email sent). Test evidence: [`evidence/README.md`](evidence/README.md).
- **Presentation video:** `https://drive.google.com/file/d/1BgYJDAkw0ed7op1nIYnsiTrIwqOxGfDt/view?usp=drivesdk`

## What it does

- Record income and spending by form, by chat ("spent 850 on petrol") or by uploading a receipt or bill (PDF text or OCR). Every entry is confirmed before it counts.
- 10 currencies (PKR, USD, EUR, GBP, AED, SAR, CAD, AUD, CNY, JPY) with daily rate snapshots; reports in any currency, "as recorded" or "current" rate policy.
- Budgets with pace tracking, safe-to-spend today, month-end forecast, budget suggestions (approve each one), anomaly detection and insights whose numbers come only from Python, never from the AI.
- Bills, money accounts (cash, bank, card, wallet), data export and account deletion.
- Works fully offline from AI; an OpenAI-compatible model is optional and requires the user's consent.

## Security at a glance

| Layer | Control |
| --- | --- |
| Roles | `user` (own data only), `security_owner` (audit log, lock/unlock, force reset, role changes with re-auth), `admin` (counts and account status only). No staff role can read financial data. |
| Database | PostgreSQL Row Level Security, enabled and forced; six least-privilege roles, none superuser or BYPASSRLS; the app never connects as the table owner. |
| Encryption | AES-256-GCM per field, per-user data keys wrapped by a key-encryption key (rotatable), ciphertext bound to table, column and row. |
| Authentication | Argon2id + pepper, zxcvbn, TOTP MFA (mandatory for staff), server-side sessions (30 min idle, 12 h absolute), HttpOnly Secure SameSite=Strict cookie, CSRF header. |
| Abuse | Database-backed rate limits shared by all workers: login, registration, reset, MFA codes, re-authentication. |
| Integrity | Hash-chained, append-only audit log with a verifier; exchange rates guarded by a database trigger. |

Details: `docs/` and [`DECISIONS.md`](DECISIONS.md).

## Project layout

```
app/                FastAPI backend (auth, ledger, finance engine, fx, receipts, chat, insights)
app/static/         built React UI, served from the same origin (no CORS)
frontend/src/       React + TypeScript source and tests
migrations/         Alembic migrations (run only as migration_owner)
db/init-roles.sh    creates the six database roles and the database
scripts/            seed demo data, create staff, refresh FX, rotate KEK, verify audit, collect evidence
tests/              pytest suite (spec IDs T01-T26, extended T27-T65)
evidence/           generated test evidence
.github/workflows/  CI on every push, daily FX refresh, manual production migration
Dockerfile  docker-compose.yml  render.yaml  .env.example
```

## 1. Run locally with Docker

```bash
cp .env.example .env
# Fill in POSTGRES_SUPERUSER_PASSWORD, the six *_PASSWORD values and MASTER_SECRET:
openssl rand -hex 24          # one per password
python -c "import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())"   # MASTER_SECRET
docker compose up --build
```

Open http://localhost:8000. The `db` service creates the roles; `migrate` applies the schema as `migration_owner` and exits; `app` serves the API and UI; `fx` refreshes exchange rates. Each container holds only the credential it needs.

```bash
docker compose run --rm -it app seed --email guest@example.invalid   # 3 months of synthetic demo data
docker compose run --rm -it app create-staff owner@example.invalid security_owner
docker compose run --rm app verify-audit
docker compose down -v        # stop and wipe the database
```

The seed needs the FX writer credential: add `-e DATABASE_URL_FX=postgresql://fx_writer:<FX_WRITER_PASSWORD>@db:5432/pfa` to the seed command.

## 2. Deploy for free: Render (app) + Neon (database)

Render's free Postgres is deleted after 30 days, so the database goes on Neon's free tier, which does not expire. Render's free tier also blocks outbound SMTP, so email goes through Brevo's HTTPS API. Expect a cold start of about a minute after 15 idle minutes; open the site before you present.

**2.1 Database (Neon).** Create a project in the Singapore region, then copy its *direct* (non-pooled) connection details. From your computer run the role script once with the admin credentials Neon shows:

```bash
PGHOST=<neon-host> PGUSER=<neon-admin> PGPASSWORD=<admin-password> PGDATABASE=neondb PGSSLMODE=require \
MIGRATION_OWNER_PASSWORD=$(openssl rand -hex 24) APP_SERVICE_PASSWORD=$(openssl rand -hex 24) \
AUTH_SERVICE_PASSWORD=$(openssl rand -hex 24) STATS_READER_PASSWORD=$(openssl rand -hex 24) \
AUDIT_READER_PASSWORD=$(openssl rand -hex 24) FX_WRITER_PASSWORD=$(openssl rand -hex 24) \
./db/init-roles.sh
```

Save the six passwords in a password manager before closing the terminal. Each role's URL is `postgresql://<role>:<password>@<neon-host>/pfa?sslmode=require`.

**2.2 Schema.** Push the code to GitHub. Under *Settings → Secrets and variables → Actions* add `DATABASE_URL_MIGRATE` and `DATABASE_URL_FX`, then run the **Migrate production database** workflow from the *Actions* tab. Run it again after any future migration. The **FX refresh** workflow then stores rates daily.

**2.3 Web service (Render).** In Render choose *New → Blueprint* and select the repository; `render.yaml` creates a free Docker service. Fill in the secrets it asks for:

| Variable | Value |
| --- | --- |
| `MASTER_SECRET` | 32 random bytes, base64. Losing it makes every account unreadable: back it up. |
| `DATABASE_URL_APP`, `_AUTH`, `_STATS`, `_AUDIT` | the URLs for `app_service`, `auth_service`, `stats_reader`, `audit_reader` |
| `DATABASE_URL_MIGRATE` | `postgresql://migration_owner@<neon-host>/pfa` **without a password** (the web service never migrates) |
| `BREVO_API_KEY`, `BREVO_FROM` | free Brevo account; `BREVO_FROM` must be a sender address you verified in Brevo |
| `LLM_*` | optional |

`PUBLIC_APP_URL` is taken from Render's `RENDER_EXTERNAL_URL` automatically. Health checks use `/health`, which fails when the database is unreachable.

**2.4 Demo data.** From your computer, with all six URLs and `MASTER_SECRET` exported: `python -m scripts.seed --email guest@example.invalid`.

**2.5 Verify after deploy.** Visit `/health` (expect `"database":"ok"`), register, sign in, and add a transaction. Rate limits rely on the client IP: the blueprint uses Render's `CF-Connecting-IP` header with an `X-Forwarded-For` fallback. If every visitor shares one limit (logins blocked for everyone after 20 failures), set `CLIENT_IP_HEADER` to the header your platform guarantees.

**Upgrading an older database:** migration 0004 needs the new `fx_writer` role. Re-run `db/init-roles.sh` (it is idempotent) with `FX_WRITER_PASSWORD` set before migrating.

## 3. Run without Docker

Python 3.12+, Node 22, PostgreSQL 16, optionally `tesseract-ocr` and `poppler-utils` for receipt OCR.

```bash
PGUSER=postgres MIGRATION_OWNER_PASSWORD=... (all six) ./db/init-roles.sh
cp .env.example .env    # fill in the DATABASE_URL_* lines and MASTER_SECRET, then export them
pip install -r requirements.txt
npm ci && npm run build
alembic upgrade head
uvicorn app.main:app --port 8000
```

## 4. Tests

```bash
pytest -q                          # 117 backend tests against real PostgreSQL and real roles
npm test && npm run typecheck      # 44 frontend tests
python -m scripts.collect_evidence # regenerate evidence/ from real runs
```

CI (`.github/workflows/ci.yml`) runs all of this on every push, checks that no database role is superuser or bypasses RLS, verifies the audit chain, and smoke-tests the Docker Compose stack.

## 5. Operations

- **Key rotation (KEK):** `KEK_ROTATE_FROM=master KEK_ROTATE_TO=<new base64 secret> python -m scripts.rotate_kek --dry-run`, then without `--dry-run`, then set `KEK_SECRET=<new>` and restart. Only wrapped keys change; rows are not re-encrypted. Use the current `KEK_SECRET` as `FROM` for later rotations.
- **Audit check:** `python -m scripts.verify_audit_chain` (exit 1 means tampering).
- **Staff accounts:** `python -m scripts.create_staff <email> security_owner|admin` (requires an authenticator).
- **Suspected compromise:** lock the account from the security page (revokes all sessions), review `/security/audit`, rotate the affected secret, add a regression test.

## Known limitations

See the risk register in the Security Self-Assessment Report. In short: a fully compromised backend can still act as any user it can reach (RLS defends against bugs, not a hostile process); `MASTER_SECRET` lives in the host's secret store rather than a hardware KMS and cannot be rotated without password resets; bills have no paid state; transfers are excluded from totals; there has been no third-party penetration test.

Exchange rates by [Exchange Rate API](https://www.exchangerate-api.com). All demo data is synthetic.
