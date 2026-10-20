"""Central default-deny permission map and FastAPI dependency."""

from fastapi import HTTPException, Request

from app import auth
from app.audit import append_event
from app.db import auth_engine


PERMISSIONS = {
    "user": frozenset(
        {
            "transaction:create",
            "transaction:read",
            "account:manage",
            "budget:write",
            "insight:read",
            "chat:use",
            "profile:own",
            "export:own",
            "account:delete",
            "session:revoke",
            "auth:password_change",
            "auth:mfa_manage",
        }
    ),
    "security_owner": frozenset(
        {
            "stats:read",
            "audit:read",
            "account:lock",
            "account:force_reset",
            "account:status",
            "role:change",
            "profile:own",
            "session:revoke",
            "auth:password_change",
            "auth:mfa_manage",
        }
    ),
    "admin": frozenset(
        {
            "stats:read",
            "account:status",
            "profile:own",
            "session:revoke",
            "auth:password_change",
            "auth:mfa_manage",
        }
    ),
}


def needs(permission: str):
    """Require an active server-side session and an explicit role permission."""

    def dependency(request: Request) -> auth.AuthSession:
        session = auth.get_session(request.cookies.get("sid"))
        if session is None or not session.mfa_ok:
            raise HTTPException(status_code=401, detail="authentication required")
        allowed = PERMISSIONS.get(session.role, frozenset())
        if permission not in allowed:
            with auth_engine.begin() as connection:
                append_event(
                    connection,
                    action="permission_denied",
                    result="deny",
                    actor_user_id=session.user_id,
                    target_id=session.user_id,
                )
            raise HTTPException(status_code=403, detail="forbidden")
        return session

    dependency.__name__ = f"require_{permission.replace(':', '_')}"
    return dependency


def permission_map() -> dict[str, tuple[str, ...]]:
    """Stable, sorted representation for documentation and checks."""
    return {role: tuple(sorted(values)) for role, values in PERMISSIONS.items()}
