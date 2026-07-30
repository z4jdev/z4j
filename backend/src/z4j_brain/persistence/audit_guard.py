"""Connection-local Boundary-F mutation authority for SQLite.

Activated SQLite databases call ``z4j_audit_guard`` from database triggers.
Current z4j connections register the function and explicitly arm one named
signer transition before changing audit rows or authenticated state.  A
pre-1.8 process does not register the function, so its legacy INSERT/DELETE
statements fail closed at the database boundary.
"""

from __future__ import annotations

from typing import Any

_TRANSITIONS = frozenset(
    {
        "append-v1",
        "retention-v1",
        "reset-v1",
        "frozen-export-delete-v1",
        "key-rotation-v1",
        "restore-v1",
    },
)
_INSERT_TRANSITIONS = frozenset(
    {
        "append-v1",
        "reset-v1",
        "key-rotation-v1",
    },
)
_DELETE_TRANSITIONS = frozenset(
    {
        "retention-v1",
        "reset-v1",
        "frozen-export-delete-v1",
    },
)


def _sqlite_audit_guard_function() -> Any:
    state: dict[str, str | None] = {"transition": None}

    def guard(operation: str, transition: str) -> int:
        if operation == "arm":
            if transition not in _TRANSITIONS:
                raise RuntimeError("unknown audit-chain transition")
            state["transition"] = transition
            return 1
        if operation == "clear":
            state["transition"] = None
            return 1

        active = state["transition"]
        if operation == "insert":
            allowed = _INSERT_TRANSITIONS
        elif operation == "delete":
            allowed = _DELETE_TRANSITIONS
        elif operation == "state_update":
            allowed = _TRANSITIONS
        elif operation == "state_delete":
            allowed = frozenset({"reset-v1", "restore-v1"})
        else:
            raise RuntimeError("unknown audit guard operation")
        if active not in allowed:
            raise RuntimeError("audit mutation is not signer-managed")
        return 1

    return guard


def register_sqlite_audit_guard(dbapi_connection: Any) -> None:
    """Register fresh fail-closed audit authority on one SQLite checkout."""

    dbapi_connection.create_function(
        "z4j_audit_guard",
        2,
        _sqlite_audit_guard_function(),
    )


__all__ = ["register_sqlite_audit_guard"]
