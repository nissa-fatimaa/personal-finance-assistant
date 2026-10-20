"""Regenerate /evidence from real runs (never hand-edited).

Usage (database configured as in README):  python -m scripts.collect_evidence
Writes: evidence/README.md (test matrix with results), backend-tests.txt,
frontend-tests.txt, db-roles.txt, migrations.txt, audit-chain.txt, junit.xml.
"""

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import platform
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "evidence"

CONTROLS = {
    "T01": "Core flow: chat entry, confirm, budget updated",
    "T02": "Validation: message without amount asks, saves nothing",
    "T03": "Ownership: foreign transaction ID -> 404 + audit",
    "T04": "RLS: app_service sees only the context user's rows",
    "T05": "RLS coverage: every user_id table has forced RLS",
    "T06": "Missing RLS context returns zero rows",
    "T07": "Identity comes from the session, never the body",
    "T08": "Admin denied financial data; counts only",
    "T09": "Password storage is Argon2id, no plaintext",
    "T10": "Stolen DB dump is ciphertext only",
    "T11": "Ciphertext bound to its row (AAD); swap fails + audit",
    "T12": "Lockout after repeated failures + audit",
    "T13": "TOTP confirmed before use; mandatory for staff",
    "T14": "Logout/revoke rejects the cookie immediately",
    "T15": "Prompt injection in receipts treated as data",
    "T16": "Duplicate blocked by dedupe HMAC index",
    "T17": "Receipt total mismatch stays pending",
    "T18": "Mixed-currency totals match hand-computed values",
    "T19": "Rate outage: last snapshot + age, no invented rate",
    "T20": "LLM numbers rejected; template used",
    "T21": "No identity carry-over on pooled connections",
    "T22": "Budget math golden scenarios",
    "T23": "Sparse history: anomaly skipped with message",
    "T24": "Planted canaries absent from logs and audit",
    "T25": "Account deletion destroys key; data unreadable",
    "T26": "Audit chain detects tampering",
    "T27": "Reset token expires and is single-use",
    "T28": "Reset response identical for unknown email",
    "T29": "CSRF header required for state changes",
    "T30": "Secrets/tokens absent from application logs",
    "T31": "Registration response generic",
    "T32": "Reset limited per account and per IP",
    "T33": "Password change revokes all sessions",
    "T34": "Staff creation requires confirmed TOTP",
    "T35": "Category suggestion uses per-user merchant HMAC",
    "T36": "Budget suggestion needs explicit approval",
    "T37": "Bills encrypted and soft-deleted",
    "T38": "Soft delete releases dedupe key",
    "T39": "Posted transaction read/update stays encrypted",
    "T40": "Edit of foreign transaction hidden + audited",
    "T41": "Edit rejecting duplicates leaves original",
    "T42": "Edit validation; only posted rows editable",
    "T44": "Dashboard parameters, fees, manual rate",
    "T45": "Frontend support endpoints scoped",
    "T46": "Email provider uses HTTPS, safe errors",
    "T47": "Reset email to stored address only (Resend)",
    "T48": "Provider failure stays generic, nothing logged",
    "T49": "Single recipient; header injection rejected",
    "T50": "Reset email uses configured origin (Brevo)",
    "T51": "Config rejects unusable email modes",
    "T52": "Login IP limit shared across instances/restarts",
    "T53": "Registration limited per IP before hashing",
    "T54": "MFA brute force: session revoked, account locked",
    "T55": "Re-authentication guessing limited",
    "T56": "/health fails when the database is down",
    "T57": "Client IP not spoofable via forwarded headers",
    "T58": "Accounts encrypted, owned, soft-deleted",
    "T59": "app_service cannot write exchange rates",
    "T60": "Database guard rejects poisoned rates",
    "T61": "FX fetch claimed once across processes",
    "T62": "security_owner admin actions audited + re-auth",
    "T63": "Users may disable MFA; staff may not",
    "T64": "KEK rotation re-wraps keys, rows untouched",
    "T65": "Audit verification script",
    "T66": "Chat and receipt OCR limited per user",
}


def _portable(text: str) -> str:
    """Show repo-relative paths so transcripts do not expose the machine layout."""
    text = text.replace(sys.executable, "python").replace(str(ROOT) + "/", "").replace(str(ROOT), ".")
    return re.sub(r"(/[\w.\-]+)+/site-packages/", "site-packages/", text)


def run(cmd: list[str], out_file: str) -> tuple[int, str]:
    result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    text = _portable(
        f"$ {' '.join(cmd)}\n\n{result.stdout}{result.stderr}\nexit code: {result.returncode}\n"
    )
    (OUT / out_file).write_text(text)
    return result.returncode, result.stdout + result.stderr


def main() -> int:
    OUT.mkdir(exist_ok=True)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    from sqlalchemy import text

    from app.db import app_engine

    with app_engine.connect() as connection:
        version = connection.execute(text("SELECT version()")).scalar_one()
        roles = connection.execute(text(
            "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname IN "
            "('migration_owner','app_service','auth_service','stats_reader','audit_reader','fx_writer') "
            "ORDER BY rolname")).all()
    (OUT / "db-roles.txt").write_text(
        "role | superuser | bypass_rls\n" + "\n".join(f"{r[0]} | {r[1]} | {r[2]}" for r in roles) + "\n")
    unsafe = [r[0] for r in roles if r[1] or r[2]]

    run([sys.executable, "-m", "alembic", "current"], "migrations.txt")
    backend_rc, _ = run([sys.executable, "-m", "pytest", "-v", "-p", "no:cacheprovider",
                         f"--junitxml={OUT / 'junit.xml'}"], "backend-tests.txt")
    audit_rc, _ = run([sys.executable, "-m", "scripts.verify_audit_chain"], "audit-chain.txt")
    frontend_rc, frontend_out = run(["npx", "vitest", "run", "--config", "frontend/vite.config.ts",
                                     "--reporter=verbose"], "frontend-tests.txt")

    junit = OUT / "junit.xml"
    junit.write_text(_portable(junit.read_text()))
    results: dict[str, list[tuple[str, str]]] = defaultdict(list)
    totals = {"passed": 0, "failed": 0, "skipped": 0}
    for case in ET.parse(OUT / "junit.xml").iter("testcase"):
        name = case.get("name", "")
        outcome = ("FAIL" if case.find("failure") is not None or case.find("error") is not None
                   else "SKIP" if case.find("skipped") is not None else "PASS")
        totals[{"PASS": "passed", "FAIL": "failed", "SKIP": "skipped"}[outcome]] += 1
        match = re.match(r"test_(T\d{2})", name)
        if match:
            results[match.group(1)].append((name.split("[")[0], outcome))
    frontend_summary = re.findall(r"Tests\s+(.*?)\n", re.sub(r"\x1b\[[0-9;]*m", "", frontend_out))

    lines = [
        "# Test evidence",
        "",
        "Generated by `python -m scripts.collect_evidence` from real runs; do not edit by hand.",
        "",
        f"- Run: {started}",
        f"- Python {platform.python_version()} · {version.split(' on ')[0]}",
        f"- Database roles (none may be superuser or bypass RLS): "
        f"{'all safe' if not unsafe else 'UNSAFE: ' + ', '.join(unsafe)} → [db-roles.txt](db-roles.txt)",
        f"- Backend: {totals['passed']} passed, {totals['failed']} failed, {totals['skipped']} skipped "
        f"(exit {backend_rc}) → [backend-tests.txt](backend-tests.txt), [junit.xml](junit.xml)",
        f"- Frontend: {frontend_summary[-1].strip() if frontend_summary else 'see file'} "
        f"(exit {frontend_rc}) → [frontend-tests.txt](frontend-tests.txt)",
        f"- Audit chain after the full suite: {'INTACT' if audit_rc == 0 else 'TAMPERED'} → "
        "[audit-chain.txt](audit-chain.txt)",
        "",
        "## Test matrix",
        "",
        "| ID | Control | Result | Test |",
        "| --- | --- | --- | --- |",
    ]
    for test_id, control in CONTROLS.items():
        found = results.get(test_id, [])
        if not found:
            lines.append(f"| {test_id} | {control} | NOT RUN | (no test found) |")
            continue
        verdict = "PASS" if all(o == "PASS" for _, o in found) else "FAIL"
        names = "<br>".join(sorted({n for n, _ in found}))
        lines.append(f"| {test_id} | {control} | {verdict} | `{names}` |")
    lines += ["", "T43 is unused. Tests without an ID (crypto primitives, AI masking, receipts, "
              "forecast, money rounding) are listed in backend-tests.txt.", ""]
    (OUT / "README.md").write_text("\n".join(lines))
    print("\n".join(lines[:12]))
    return 0 if backend_rc == audit_rc == frontend_rc == 0 and not unsafe else 1


if __name__ == "__main__":
    raise SystemExit(main())
