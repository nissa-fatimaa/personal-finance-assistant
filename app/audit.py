"""Minimal parameterized calls to the database's append-only audit function."""

import re
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection


_SAFE_EVENT = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def append_event(
    connection: Connection,
    *,
    action: str,
    result: str,
    actor_user_id: UUID | None = None,
    target_id: UUID | None = None,
) -> None:
    """Append an ID-and-outcome-only event; never accept free-form detail text."""
    if not _SAFE_EVENT.fullmatch(action) or not _SAFE_EVENT.fullmatch(result):
        raise ValueError("Audit action and result must be safe event identifiers")
    connection.execute(
        text(
            "SELECT public.audit_append("
            ":actor_user_id, :action, :target_id, :result, '{}'::jsonb)"
        ),
        {
            "actor_user_id": actor_user_id,
            "action": action,
            "target_id": target_id,
            "result": result,
        },
    )


def record_decryption_failure(
    connection: Connection, *, actor_user_id: UUID, target_id: UUID
) -> None:
    append_event(
        connection,
        action="decryption_failed",
        result="fail",
        actor_user_id=actor_user_id,
        target_id=target_id,
    )
