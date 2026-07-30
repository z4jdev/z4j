"""Behavioral regression: bulk-retry audit-trail completeness.

The RQ RCE path is closed, but a later review found two
audit blind spots in ``issue_bulk_retry``:

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
it)."""

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

    async def record(self, repo, **kwargs) -> object:
        self.records.append(kwargs)
        return object()


class _FakeProject:
    def __init__(self) -> None:
        self.id = uuid.uuid4()


class _FakePolicy:
    """Stands in for PolicyEngine: project resolves, member check passes."""

    def __init__(self, project: _FakeProject) -> None:
        self._project = project

    async def get_project_or_404(self, projects, slug):
        return self._project

    async def require_member(self, memberships, *, user, project, min_role):
        return None


class _FakeTaskRepo:
    """get_priorities_for_ids -> {}; get_names_for_ids -> a configurable
    (possibly partial) map so we can exercise the RQ partial-resolution
    400 branch."""

    def __init__(self, names: dict[str, str]) -> None:
        self._names = names

    def __call__(self, session):
        return self

    async def get_priorities_for_ids(self, *, project_id, engine, task_ids):
        return {}

    async def get_names_for_ids(self, *, project_id, engine, task_ids):
        return dict(self._names)

    async def list_for_project(
        self,
        *,
        project_id,
        state,
        queue,
        engine=None,
        name_substring=None,
        since=None,
        until=None,
        limit,
    ):
        # RH4: the all-matching path resolves project-owned ids here. These
        # audit tests exercise the no-owned-match no-op branch, so return none.
        return []


class _FakeSession:
    def __init__(self) -> None:
        self.commits = 0
        #: Commands the request-scoped idempotency pre-check should find.
        #: Empty means "this request has not been seen", the normal first-call
        #: case these tests exercise.
        self.prior_by_key: dict[str, object] = {}

    async def commit(self) -> None:
        self.commits += 1

    async def refresh(self, obj) -> None:
        return None

    async def execute(self, statement):
        # Bulk retry now looks up a single request-scoped idempotency key
        # BEFORE expanding the filter, so a replay returns the original outcome
        # instead of re-expanding against live data. These tests drive the
        # endpoint with a fake session, so the double has to answer that read.
        prior = next(iter(self.prior_by_key.values()), None)

        class _Result:
            def scalar_one_or_none(self):
                return prior

        return _Result()


class _FakeUser:
    def __init__(self) -> None:
        self.id = uuid.uuid4()


def _patch_common(monkeypatch, project, names):
    monkeypatch.setattr(
        "z4j_brain.domain.policy_engine.PolicyEngine",
        lambda: _FakePolicy(project),
    )
    monkeypatch.setattr(
        "z4j_brain.persistence.repositories.TaskRepository",
        _FakeTaskRepo(names),
    )


async def _assert_legacy_all_matching_fenced(
    monkeypatch: pytest.MonkeyPatch,
    raw_filter: dict[str, Any],
) -> None:
    """The retired command endpoint must never expand an all-matching filter.

    Its former expansion/security assertions now run against the production
    durable resource in ``test_bulk_retry_request_boundary_b.py``.
    """

    from fastapi import HTTPException

    project = _FakeProject()
    monkeypatch.setattr(
        "z4j_brain.domain.policy_engine.PolicyEngine",
        lambda: _FakePolicy(project),
    )

    async def _must_not_expand(**_kwargs: Any) -> object:
        raise AssertionError("legacy all-matching expansion was reached")

    monkeypatch.setattr(
        commands_mod,
        "_resolve_and_issue_all_matching_bulk_retry",
        _must_not_expand,
    )
    with pytest.raises(HTTPException) as exc_info:
        await issue_bulk_retry(
            slug="proj",
            body=BulkRetryRequest(
                agent_id=uuid.uuid4(),
                filter=raw_filter,
                max=100,
                idempotency_key="legacy-fenced",
            ),
            user=_FakeUser(),
            memberships=object(),
            projects=object(),
            audit_log=object(),
            audit_service=_FakeAuditService(),  # type: ignore[arg-type]
            dispatcher=object(),
            db_session=_FakeSession(),  # type: ignore[arg-type]
            ip="127.0.0.1",
        )
    assert exc_info.value.status_code == 410
    assert "bulk-retry-requests" in str(exc_info.value.detail)


@pytest.mark.asyncio
class TestR10L1AuditCompleteness:
    async def test_partial_rq_resolution_400_writes_denial_audit_row(
        self,
        monkeypatch,
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
        refusals = [r for r in audit.records if r["action"] == "command.bulk_retry.refused"]
        assert len(refusals) == 1, (
            " regression: the RQ partial-resolution 400 path "
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
            " regression: the denial audit row must be committed "
            "BEFORE the HTTPException, or it rolls back and the 400 "
            "leaves no audit trail"
        )

    async def test_smuggled_server_owned_key_writes_sanitized_audit_row(
        self,
        monkeypatch,
    ) -> None:
        """The old endpoint cannot sanitize then execute an all-match request.

        The new durable endpoint's real-SQLite test proves the rejected key is
        denied and written to the HMAC-chained audit log.
        """
        await _assert_legacy_all_matching_fenced(
            monkeypatch,
            {"task_names": {"x": "os.system"}},
        )

    async def test_clean_filter_writes_no_extra_audit_row(
        self,
        monkeypatch,
    ) -> None:
        """A clean all-match request also moves to the durable resource."""
        await _assert_legacy_all_matching_fenced(
            monkeypatch,
            {"state": "failure"},
        )


class _FakeTask:
    def __init__(self, engine: str, task_id: str, name: str = "app.task") -> None:
        self.engine = engine
        self.task_id = task_id
        self.name = name


class _FakeOwnedTaskRepo:
    """list_for_project returns owned failed tasks; name/priority lookups echo
    the ids so the enriched per-engine filter is populated."""

    def __init__(self, tasks: list[_FakeTask]) -> None:
        self._tasks = tasks

    def __call__(self, session):
        return self

    async def list_for_project(
        self,
        *,
        project_id,
        state,
        queue,
        engine=None,
        name_substring=None,
        since=None,
        until=None,
        limit,
    ):
        # Mirror the SQL: apply engine + name predicates BEFORE the row cap.
        rows = [
            t
            for t in self._tasks
            if (engine is None or t.engine == engine)
            and (name_substring is None or name_substring in getattr(t, "name", ""))
        ]
        return rows[:limit]

    async def get_priorities_for_ids(self, *, project_id, engine, task_ids):
        return {}

    async def get_names_for_ids(self, *, project_id, engine, task_ids):
        return {tid: f"task.{tid}" for tid in task_ids}


@pytest.mark.asyncio
async def test_rh4_all_matching_resolves_owned_ids_per_engine(monkeypatch) -> None:
    """All-matching expansion is exclusively owned by the durable resource."""
    await _assert_legacy_all_matching_fenced(
        monkeypatch,
        {"state": "failure"},
    )


@pytest.mark.asyncio
async def test_rh4_engine_filter_scopes_the_row_cap_to_that_engine(monkeypatch) -> None:
    """The legacy endpoint cannot apply an all-match engine cap."""
    await _assert_legacy_all_matching_fenced(
        monkeypatch,
        {"engine": "rq", "state": "failure"},
    )


@pytest.mark.asyncio
async def test_rh4_all_matching_applies_name_filter_p1_4(monkeypatch) -> None:
    """The legacy endpoint cannot apply an all-match name filter."""
    await _assert_legacy_all_matching_fenced(
        monkeypatch,
        {"engine": "celery", "state": "failure", "name": "wanted"},
    )


@pytest.mark.asyncio
async def test_explicit_ids_sends_canonical_deduped_ids_p1_5(monkeypatch) -> None:
    """P1-5: the command must carry the DEDUPED/CAPPED ids that ownership was
    verified against, not the client's raw task_ids (with duplicates)."""
    project = _FakeProject()
    # Ownership resolves both a and b (get_names_for_ids returns both).
    monkeypatch.setattr("z4j_brain.domain.policy_engine.PolicyEngine", lambda: _FakePolicy(project))
    monkeypatch.setattr(
        "z4j_brain.persistence.repositories.TaskRepository",
        _FakeTaskRepo({"a": "app.a", "b": "app.b"}),
    )
    issued: list[dict[str, Any]] = []

    async def _fake_issue_generic(**kwargs):
        issued.append(kwargs["payload"])
        return "ISSUED"

    monkeypatch.setattr(commands_mod, "_issue_generic_command", _fake_issue_generic)

    body = BulkRetryRequest(
        agent_id=uuid.uuid4(),
        filter={"engine": "celery", "task_ids": ["a", "a", "b"]},  # duplicate a
        max=100,
    )
    await issue_bulk_retry(
        slug="proj",
        body=body,
        user=_FakeUser(),
        memberships=object(),
        projects=object(),
        audit_log=object(),
        audit_service=_FakeAuditService(),
        dispatcher=object(),
        db_session=_FakeSession(),
        ip="127.0.0.1",
    )
    assert len(issued) == 1
    # Deduped -> ["a", "b"], NOT the raw ["a", "a", "b"].
    assert issued[0]["filter"]["task_ids"] == ["a", "b"]


def test_engine_idempotency_key_bounded_and_injective_p1_1015_m2() -> None:
    # commands:1015 + M2: the derived key must fit VARCHAR(200), be deterministic,
    # and be INJECTIVE (distinct client keys never collapse to one derived key).
    import hashlib

    from z4j_brain.api.commands import _engine_idempotency_key

    assert _engine_idempotency_key(None, "celery") is None
    # Always a bounded sha256 digest + ":{engine}" (64 + suffix <= 200).
    k = _engine_idempotency_key("req-1", "celery")
    assert k is not None and len(k) <= 200 and k.endswith(":celery")
    # Deterministic -> a retry of the same request maps to the same key.
    assert _engine_idempotency_key("req-1", "celery") == k
    # Distinct engines never collide.
    assert _engine_idempotency_key("req-1", "rq") != k
    # A 200-char base fits (was the digest branch before; now always hashed).
    long_base = "x" * 200
    kl = _engine_idempotency_key(long_base, "celery")
    assert kl is not None and len(kl) <= 200
    # M2: the exact former collision -- a 200-char base vs a client key equal to
    # that base's sha256 hex digest -- must NOT collapse to the same derived key.
    digest_as_key = hashlib.sha256(long_base.encode("utf-8")).hexdigest()
    assert _engine_idempotency_key(long_base, "celery") != _engine_idempotency_key(
        digest_as_key, "celery"
    )


def test_noop_key_never_collides_with_engine_key_p1_1028() -> None:
    # commands:1028: the no-op bulk-retry key is namespaced under a reserved
    # pseudo-engine so it can NEVER collide with a real per-engine key -- even
    # for the exact adversarial base that used to collide.
    from z4j_brain.api.commands import _BULK_NOOP_KEY_ENGINE, _engine_idempotency_key

    noop = _engine_idempotency_key("K:celery", _BULK_NOOP_KEY_ENGINE)
    matched = _engine_idempotency_key("K", "celery")
    assert noop != matched  # the collision is gone
    assert noop.endswith(":__noop__")
    # Two no-ops with the same base still dedup against each other.
    assert _engine_idempotency_key("K", _BULK_NOOP_KEY_ENGINE) == _engine_idempotency_key(
        "K", _BULK_NOOP_KEY_ENGINE
    )
    # None base -> None (no idempotency protection requested).
    assert _engine_idempotency_key(None, _BULK_NOOP_KEY_ENGINE) is None


@pytest.mark.asyncio
async def test_replay_of_a_noop_request_does_not_execute_r13(monkeypatch) -> None:
    """Lost-response replay is handled only by the new durable resource.

    Its production-row test seals a no-match parent, adds a matching task, and
    proves replay returns the original terminal parent without re-expansion.
    """
    await _assert_legacy_all_matching_fenced(
        monkeypatch,
        {"state": "failure"},
    )


@pytest.mark.asyncio
async def test_noop_uses_synthetic_success_not_dispatch_m1_1028(monkeypatch) -> None:
    """The legacy command endpoint cannot synthesize all-match no-ops.

    The durable resource represents this as a zero-child terminal parent.
    """
    await _assert_legacy_all_matching_fenced(
        monkeypatch,
        {"state": "failure"},
    )


@pytest.mark.asyncio
async def test_empty_or_malformed_task_ids_rejected_h2(monkeypatch) -> None:
    # H2: an explicit task_ids that is empty [] or not a non-empty list must be
    # REJECTED (400), not silently treated as "retry all matching" (which would
    # mass-retry the whole failed backlog).
    from fastapi import HTTPException

    project = _FakeProject()
    monkeypatch.setattr("z4j_brain.domain.policy_engine.PolicyEngine", lambda: _FakePolicy(project))
    monkeypatch.setattr("z4j_brain.persistence.repositories.TaskRepository", _FakeOwnedTaskRepo([]))
    for bad in ([], "someid", 5):
        body = BulkRetryRequest(
            agent_id=uuid.uuid4(), filter={"engine": "celery", "task_ids": bad}, max=100
        )
        with pytest.raises(HTTPException) as ei:
            await issue_bulk_retry(
                slug="proj",
                body=body,
                user=_FakeUser(),
                memberships=object(),
                projects=object(),
                audit_log=object(),
                audit_service=_FakeAuditService(),
                dispatcher=object(),
                db_session=_FakeSession(),
                ip="127.0.0.1",
            )
        assert ei.value.status_code == 400


@pytest.mark.asyncio
async def test_malformed_narrowing_filter_rejected_h3(monkeypatch) -> None:
    """Malformed all-match filters cannot reach legacy expansion."""
    for bad_filter in (
        {"queue": 123},
        {"name": {}},
        {"engine": 7},
        {"since": "not-a-date"},
        {"until": ["x"]},
    ):
        await _assert_legacy_all_matching_fenced(monkeypatch, bad_filter)


@pytest.mark.asyncio
async def test_invalid_state_rejected_not_coerced_r5_h2(monkeypatch) -> None:
    """Invalid states cannot be coerced by retired legacy expansion."""
    bad_filters = [
        {"state": "sucess"},
        {"state": "failed"},
        {"status": 17},
        {"state": False},
        {"status": 0},
        {"state": []},
        {"state": {}},
    ]
    for bad_filter in bad_filters:
        await _assert_legacy_all_matching_fenced(monkeypatch, bad_filter)


@pytest.mark.asyncio
async def test_unknown_engine_rejected_not_false_success_r5_m1(monkeypatch) -> None:
    """An unknown engine cannot become a legacy false-success no-op."""
    await _assert_legacy_all_matching_fenced(
        monkeypatch,
        {"engine": "celrey"},
    )
