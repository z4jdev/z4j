"""R10-L1 behavioral regression: bulk-retry audit-trail completeness.

Codex Round 10 confirmed the R9-H1 RQ RCE path is closed but flagged
two audit blind spots in ``issue_bulk_retry``:

1. The partial-DB-resolution 400 fast-path raises ``HTTPException``
   BEFORE the command-issuance audit row is written, so a refused RQ
   bulk-retry leaves no tamper-evident trace.
2. The ``rejected_client_supplied_filter_keys`` marker on a client's
   server-owned-key smuggling attempt lived only in the command
   payload (on the success path), not in the HMAC-chained audit
   metadata.

The fix records a dedicated chained audit row + commits it at both
decision points (so it survives the 400 rollback), independent of
the eventual request outcome.

These are BEHAVIORAL tests: they call ``issue_bulk_retry`` directly
with stubbed dependencies and assert the real audit side effects -
not source-string structural checks (which would pass on a
hollowed-out refactor that imports the audit service but never calls
it).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from z4j_brain.api import commands as commands_mod
from z4j_brain.api.commands import BulkRetryRequest, issue_bulk_retry


class _FakeAuditService:
    """Records every record() call so tests can assert the audit trail."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    async def record(self, repo, **kwargs) -> object:  # noqa: ANN001, ANN003
        self.records.append(kwargs)
        return object()


class _FakeProject:
    def __init__(self) -> None:
        self.id = uuid.uuid4()


class _FakePolicy:
    """Stands in for PolicyEngine: project resolves, member check passes."""

    def __init__(self, project: _FakeProject) -> None:
        self._project = project

    async def get_project_or_404(self, projects, slug):  # noqa: ANN001
        return self._project

    async def require_member(self, memberships, *, user, project, min_role):  # noqa: ANN001
        return None


class _FakeTaskRepo:
    """get_priorities_for_ids -> {}; get_names_for_ids -> a configurable
    (possibly partial) map so we can exercise the RQ partial-resolution
    400 branch."""

    def __init__(self, names: dict[str, str]) -> None:
        self._names = names

    def __call__(self, session):  # noqa: ANN001  - constructed as TaskRepository(db_session)
        return self

    async def get_priorities_for_ids(self, *, project_id, engine, task_ids):  # noqa: ANN001
        return {}

    async def get_names_for_ids(self, *, project_id, engine, task_ids):  # noqa: ANN001
        return dict(self._names)


class _FakeSession:
    def __init__(self) -> None:
        self.commits = 0

    async def commit(self) -> None:
        self.commits += 1


class _FakeUser:
    def __init__(self) -> None:
        self.id = uuid.uuid4()


def _patch_common(monkeypatch, project, names):  # noqa: ANN001
    monkeypatch.setattr(
        "z4j_brain.domain.policy_engine.PolicyEngine",
        lambda: _FakePolicy(project),
    )
    monkeypatch.setattr(
        "z4j_brain.persistence.repositories.TaskRepository",
        _FakeTaskRepo(names),
    )


@pytest.mark.asyncio
class TestR10L1AuditCompleteness:
    async def test_partial_rq_resolution_400_writes_denial_audit_row(
        self, monkeypatch,
    ) -> None:
        """The 400 fast-path must record a 'refused' audit row + commit
        BEFORE raising, so the refusal is durable (not rolled back)."""
        from fastapi import HTTPException

        project = _FakeProject()
        # Two ids requested; DB resolves only ONE -> partial -> 400.
        _patch_common(monkeypatch, project, names={"id-1": "tasks.work"})
        audit = _FakeAuditService()
        session = _FakeSession()

        body = BulkRetryRequest(
            agent_id=uuid.uuid4(),
            filter={"engine": "rq", "task_ids": ["id-1", "id-2"]},
            max=100,
        )

        with pytest.raises(HTTPException) as exc_info:
            await issue_bulk_retry(
                slug="proj",
                body=body,
                user=_FakeUser(),
                memberships=object(),
                projects=object(),
                audit_log=object(),
                audit_service=audit,  # type: ignore[arg-type]
                dispatcher=object(),
                db_session=session,  # type: ignore[arg-type]
                ip="127.0.0.1",
            )

        assert exc_info.value.status_code == 400
        # A denial audit row was recorded...
        refusals = [
            r for r in audit.records
            if r["action"] == "command.bulk_retry.refused"
        ]
        assert len(refusals) == 1, (
            "R10-L1 regression: the RQ partial-resolution 400 path "
            "must record a 'command.bulk_retry.refused' audit row. "
            f"Recorded actions: {[r['action'] for r in audit.records]}"
        )
        ref = refusals[0]
        assert ref["outcome"] == "deny"
        assert ref["result"] == "failure"
        assert ref["metadata"]["missing_task_names"] == ["id-2"]
        assert ref["metadata"]["engine"] == "rq"
        # ...and it was committed (durable past the HTTPException).
        assert session.commits >= 1, (
            "R10-L1 regression: the denial audit row must be committed "
            "BEFORE the HTTPException, or it rolls back and the 400 "
            "leaves no audit trail"
        )

    async def test_smuggled_server_owned_key_writes_sanitized_audit_row(
        self, monkeypatch,
    ) -> None:
        """An authenticated client supplying a server-owned filter key
        (the R9-H1 confused-deputy attempt) must leave a tamper-evident
        'filter_keys_rejected' audit row even on a non-400 path."""
        project = _FakeProject()
        # Full resolution so we do NOT hit the 400; the request proceeds
        # past the strip. We stop it before dispatcher.issue by giving a
        # non-RQ engine + no task_ids so the enrichment block is skipped
        # and _issue_generic_command would run - but we patch that out to
        # isolate the audit behavior.
        _patch_common(monkeypatch, project, names={})
        audit = _FakeAuditService()
        session = _FakeSession()

        async def _fake_issue_generic(**kwargs):  # noqa: ANN003
            # Stand in for _issue_generic_command; return a sentinel.
            return "ISSUED"

        monkeypatch.setattr(
            commands_mod, "_issue_generic_command", _fake_issue_generic,
        )

        body = BulkRetryRequest(
            agent_id=uuid.uuid4(),
            # No task_ids -> the enrichment/400 block is skipped; the
            # smuggled 'task_names' key must still be stripped + audited.
            filter={"task_names": {"x": "os.system"}},
            max=100,
        )

        result = await issue_bulk_retry(
            slug="proj",
            body=body,
            user=_FakeUser(),
            memberships=object(),
            projects=object(),
            audit_log=object(),
            audit_service=audit,  # type: ignore[arg-type]
            dispatcher=object(),
            db_session=session,  # type: ignore[arg-type]
            ip="127.0.0.1",
        )

        assert result == "ISSUED"
        sanitized = [
            r for r in audit.records
            if r["action"] == "command.bulk_retry.filter_keys_rejected"
        ]
        assert len(sanitized) == 1, (
            "R10-L1 regression: a smuggled server-owned filter key must "
            "record a 'command.bulk_retry.filter_keys_rejected' audit "
            f"row. Recorded: {[r['action'] for r in audit.records]}"
        )
        meta = sanitized[0]["metadata"]
        assert meta["rejected_client_supplied_filter_keys"] == ["task_names"]
        assert sanitized[0]["outcome"] == "sanitized"
        assert session.commits >= 1

    async def test_clean_filter_writes_no_extra_audit_row(
        self, monkeypatch,
    ) -> None:
        """A clean filter (no server-owned keys, no partial resolution)
        must NOT write a denial/sanitized row - only the normal command
        issuance audit (handled downstream)."""
        project = _FakeProject()
        _patch_common(monkeypatch, project, names={})
        audit = _FakeAuditService()
        session = _FakeSession()

        async def _fake_issue_generic(**kwargs):  # noqa: ANN003
            return "ISSUED"

        monkeypatch.setattr(
            commands_mod, "_issue_generic_command", _fake_issue_generic,
        )

        body = BulkRetryRequest(
            agent_id=uuid.uuid4(),
            filter={"state": "failed"},  # benign operator filter
            max=100,
        )

        result = await issue_bulk_retry(
            slug="proj",
            body=body,
            user=_FakeUser(),
            memberships=object(),
            projects=object(),
            audit_log=object(),
            audit_service=audit,  # type: ignore[arg-type]
            dispatcher=object(),
            db_session=session,  # type: ignore[arg-type]
            ip="127.0.0.1",
        )

        assert result == "ISSUED"
        assert audit.records == [], (
            "a clean filter must not emit a denial/sanitized audit row; "
            f"got {[r['action'] for r in audit.records]}"
        )
