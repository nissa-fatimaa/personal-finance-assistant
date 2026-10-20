# Engineering decisions

Short records of choices that are not obvious from the code. Each states the decision and why.

## Database and access control

- **D-01 Roles exist before migrations.** `db/init-roles.sh` creates six roles (`migration_owner`, `app_service`, `auth_service`, `stats_reader`, `audit_reader`, `fx_writer`), none superuser or BYPASSRLS. Migrations verify those attributes and refuse to run otherwise; they never create cluster roles.
- **D-02 The running app never holds `migration_owner`.** Compose runs migrations in a one-shot service; on Render they run from a manual GitHub Actions job. Web containers receive a password-less `DATABASE_URL_MIGRATE`, which satisfies config validation but cannot authenticate.
- **D-03 Exchange rates are written only by `fx_writer`.** `app_service` can read `fx_rates` but not write it. A `BEFORE INSERT` trigger enforces a source allowlist, the 10 supported currencies, USD = 1, no future dates, and a 0.5×–2× band against the neighbouring snapshot within 31 days. Residual risk: anything holding the `fx_writer` secret can still write plausible rates; on Render only the scheduled GitHub job holds it.
- **D-04 Rate limits live in PostgreSQL.** `rate_limits` holds fixed-window counters keyed by HMAC (never raw IPs, emails or tokens). Each check is one atomic UPSERT, so limits are shared by all workers and survive restarts.
- **D-05 Hash-chained audit uses `pgcrypto`.** `digest(..., 'sha256')` from the trusted `pgcrypto` extension keeps SHA-256 chaining without elevated privileges.
- **D-06 One auxiliary development table.** `dev_outbox` stores encrypted development emails; it is refused in production.

## Authentication

- **D-07 Generic registration and reset responses** for new and existing emails, so neither endpoint reveals whether an account exists.
- **D-08 Brute-force limits.** Per account: 5 failed passwords in 15 minutes lock the account. Per IP: 20 failed logins, 10 registrations per hour (checked before zxcvbn and Argon2id so registration cannot burn CPU), 5 reset requests. MFA: 5 wrong codes revoke the pending session, 10 per account lock the account, 20 per IP block the IP. Re-authentication (export, delete, password, MFA, role changes): 5 failures per account, counted on a separate connection so a rollback cannot erase them.
- **D-09 Client IP resolution.** Rate limits use a platform header the edge overwrites (`CLIENT_IP_HEADER`, e.g. `CF-Connecting-IP`), then the N-th trusted `X-Forwarded-For` hop, then the socket peer. Client-supplied forwarding headers are ignored by default.
- **D-10 Password-reset link is the one token sent by email.** It uses the configured public URL and a URL fragment; the request's `Host` header is never used.
- **D-11 Staff administration never touches financial data.** security_owner can lock/unlock, force a reset (password made unusable and sessions revoked; staff never see or set a password) and change roles after re-entering password and TOTP. Staff cannot act on their own account; promotion to a staff role requires the target to have MFA. admin can only read account status.
- **D-12 MFA is optional for users and mandatory for staff;** users may turn it off after password + current code; staff may not.

## Money, currency and analytics

- **D-13 `fx_override_rate`** is base-currency major units per one original major unit. It applies to the `as_recorded` policy; `current` ignores it. A non-null override is reported as `fx_rate_source: "manual"`.
- **D-14 Fees** are encrypted separately in `fee_enc`, reported as a fee total and included in expenses, category spend and forecasts.
- **D-15 FX decomposition** uses exact rational arithmetic; the rounding remainder goes to the rate effect so displayed effects sum exactly.
- **D-16 Bills have no paid state;** forecasts treat active bills due in the month as unpaid.
- **D-17 "Today" uses `APP_TIMEZONE`** (default Asia/Karachi), not the server's UTC clock.
- **D-18 Chat text is not persisted.** Messages are parsed in memory; only the resulting pending transaction is stored. `chat_messages` exists for a future encrypted history and is included in export and deletion.

## Email and deployment

- **D-19 Email over HTTPS on free hosting.** Render's free tier blocks outbound SMTP, so production uses Brevo or Resend over HTTPS with an API key. Providers send to exactly one recipient (the stored account email), reject header injection, and never include message content, keys or upstream responses in errors or logs.
- **D-20 FX refresh outside the web process.** A daily GitHub Actions job (or the Compose sidecar) holds the `fx_writer` credential. Concurrent fetches are coordinated by a per-day claim row; failures retry after one hour.
- **D-21 KEK rotation without re-encrypting rows.** The key-encryption key can come from `KEK_SECRET`; `scripts/rotate_kek.py` re-wraps every data key in one verified transaction. Rotating `MASTER_SECRET` itself (pepper, lookup HMACs) is not supported and is listed as a known risk.
- **D-22 OCR tools ship in the image** (`tesseract-ocr`, `poppler-utils`); without them receipt reading degrades to "unreadable" rather than failing.
