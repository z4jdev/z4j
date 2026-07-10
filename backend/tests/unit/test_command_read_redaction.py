"""Command read redaction (Codex P2): confirm_token is redacted for every
role, and who-did-what (issued_by) + the raw payload/result are gated to
OPERATOR+ so a VIEWER cannot read arguments or the purge secret."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

from z4j_brain.api.commands import _command_payload, _include_actor
from z4j_brain.persistence.enums import ProjectRole


def _cmd() -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        issued_by=uuid.uuid4(),
        action="purge_queue",
        target_type="queue",
        target_id="q",
        payload={
            "queue": "q",
            "confirm_token": "SECRET-TOKEN",
            "override_kwargs": {"x": 1},
        },
        status=SimpleNamespace(value="pending"),
        result={"ok": True},
        error=None,
        issued_at=datetime(2026, 1, 1, tzinfo=UTC),
        dispatched_at=None,
        completed_at=None,
        timeout_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def test_operator_sees_actor_but_confirm_token_always_redacted() -> None:
    pub = _command_payload(_cmd(), include_actor=True)
    assert pub.issued_by is not None
    # The purge secret is redacted even for OPERATOR+.
    assert pub.payload["confirm_token"] == "<redacted>"
    # Non-secret payload + result remain visible to OPERATOR+.
    assert pub.payload["override_kwargs"] == {"x": 1}
    assert pub.result == {"ok": True}


def test_viewer_gets_no_actor_no_payload() -> None:
    pub = _command_payload(_cmd(), include_actor=False)
    assert pub.issued_by is None
    assert pub.payload == {}
    assert pub.result is None
    # Operational shape stays visible so a VIEWER can still see activity.
    assert pub.action == "purge_queue"
    assert pub.target_id == "q"
    assert pub.status == "pending"


def test_include_actor_role_gate() -> None:
    assert _include_actor(SimpleNamespace(role=ProjectRole.ADMIN)) is True
    assert _include_actor(SimpleNamespace(role=ProjectRole.OPERATOR)) is True
    assert _include_actor(SimpleNamespace(role=ProjectRole.VIEWER)) is False
