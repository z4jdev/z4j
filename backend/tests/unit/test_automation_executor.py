"""Automation executor governance: dry-run / failsafe / fault-isolation (R2).

Unit-tests the orchestration + audit logic with a fake ActionRunner and a
recording fake audit service, so it exercises the decision matrix without
a DB or the real notification/command machinery.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from z4j_brain.domain.automation import AutomationExecutor
from z4j_brain.persistence.repositories import CircuitDecision


class _FakeRunner:
    def __init__(self, *, result: str = "ran", exc: Exception | None = None):
        self.calls: list[dict] = []
        self._result = result
        self._exc = exc

    async def run(self, *, session, rule, action_spec, fields) -> str:
        self.calls.append({"action": action_spec, "rule": rule.name})
        if self._exc is not None:
            raise self._exc
        return self._result


class _FakeAudit:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def record(self, repo, **kw):
        self.rows.append(kw)
        return SimpleNamespace(id=uuid.uuid4())


def _rule(**kw) -> SimpleNamespace:
    kw.setdefault("id", uuid.uuid4())
    kw.setdefault("project_id", uuid.uuid4())
    kw.setdefault("name", "rule")
    kw.setdefault("trigger", "task.failed")
    kw.setdefault("dry_run", False)
    kw.setdefault("actions", [])
    return SimpleNamespace(**kw)


def _actions(audit: _FakeAudit) -> list[dict]:
    return [r for r in audit.rows if r["action"] == "automation.rule.fired"]


@pytest.mark.asyncio
class TestExecutorGovernance:
    async def test_normal_execute_runs_and_audits(self) -> None:
        runner = _FakeRunner(result="delivered")
        audit = _FakeAudit()
        ex = AutomationExecutor(audit=audit, runner=runner)
        rule = _rule(actions=[{"type": "notify", "channel_type": "slack"}])

        await ex._run_one(None, None, rule, {"task_id": "t1"}, CircuitDecision.EXECUTE)

        assert len(runner.calls) == 1
        fired = _actions(audit)
        assert len(fired) == 1
        assert fired[0]["metadata"]["outcome"] == "delivered"
        assert fired[0]["metadata"]["action"] == "notify"

    async def test_dry_run_does_not_execute(self) -> None:
        runner = _FakeRunner()
        audit = _FakeAudit()
        ex = AutomationExecutor(audit=audit, runner=runner)
        rule = _rule(dry_run=True, actions=[{"type": "cancel"}])

        await ex._run_one(None, None, rule, {}, CircuitDecision.EXECUTE)

        assert runner.calls == []
        assert _actions(audit)[0]["metadata"]["outcome"] == "dry_run"

    async def test_failsafe_skips_destructive_keeps_notify(self) -> None:
        runner = _FakeRunner(result="delivered")
        audit = _FakeAudit()
        ex = AutomationExecutor(audit=audit, runner=runner)
        rule = _rule(
            actions=[{"type": "cancel"}, {"type": "notify"}],
        )

        await ex._run_one(None, None, rule, {}, CircuitDecision.TRIPPED)

        # Destructive skipped, notify ran.
        assert len(runner.calls) == 1
        assert runner.calls[0]["action"]["type"] == "notify"
        outcomes = {r["metadata"]["action"]: r["metadata"]["outcome"] for r in _actions(audit)}
        assert outcomes["cancel"] == "skipped_failsafe"
        assert outcomes["notify"] == "delivered"

    async def test_trip_now_emits_circuit_audit_row(self) -> None:
        audit = _FakeAudit()
        ex = AutomationExecutor(audit=audit, runner=_FakeRunner())
        rule = _rule(actions=[{"type": "notify"}])

        await ex._run_one(None, None, rule, {}, CircuitDecision.TRIPPED_NOW)

        tripped = [r for r in audit.rows if r["action"] == "automation.rule.circuit_tripped"]
        assert len(tripped) == 1

    async def test_action_exception_is_isolated(self) -> None:
        runner = _FakeRunner(exc=RuntimeError("boom"))
        audit = _FakeAudit()
        ex = AutomationExecutor(audit=audit, runner=runner)
        rule = _rule(actions=[{"type": "notify"}, {"type": "webhook"}])

        # Must not raise; both actions audited, both "failed".
        await ex._run_one(None, None, rule, {}, CircuitDecision.EXECUTE)

        fired = _actions(audit)
        assert len(fired) == 2
        assert all(r["metadata"]["outcome"] == "failed" for r in fired)
        assert all(r["result"] == "failed" for r in fired)

    async def test_unknown_action_type(self) -> None:
        runner = _FakeRunner()
        audit = _FakeAudit()
        ex = AutomationExecutor(audit=audit, runner=runner)
        rule = _rule(actions=[{"type": "launch_missiles"}])

        await ex._run_one(None, None, rule, {}, CircuitDecision.EXECUTE)

        assert runner.calls == []
        assert _actions(audit)[0]["metadata"]["outcome"] == "unknown_action"


class _FakeSession:
    """Records commit/rollback so run_matching's per-rule transaction
    boundary is observable without a real DB."""

    def __init__(self) -> None:
        self.commits = 0
        self.rollbacks = 0

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


@pytest.mark.asyncio
async def test_run_matching_end_to_end() -> None:
    """run_matching: load rules -> match -> claim -> execute -> commit."""
    runner = _FakeRunner(result="issued")
    audit = _FakeAudit()
    ex = AutomationExecutor(audit=audit, runner=runner)

    rule = _rule(
        conditions={"engine": "celery"},
        actions=[{"type": "retry"}],
        is_enabled=True,
    )

    class _FakeRepo:
        async def list_enabled_for_trigger(self, *, project_id, trigger):
            return [rule]

        async def claim_execution(self, *, rule_id, now):
            return CircuitDecision.EXECUTE, rule

    session = _FakeSession()
    await ex.run_matching(
        session=session,
        rules_repo=_FakeRepo(),
        audit_log=None,
        project_id=rule.project_id,
        trigger="task.failed",
        fields={"engine": "celery", "task_id": "t9"},
        now=None,
    )

    assert len(runner.calls) == 1
    assert _actions(audit)[0]["metadata"]["outcome"] == "issued"
    # The rule committed in its own transaction.
    assert session.commits == 1
    assert session.rollbacks == 0


@pytest.mark.asyncio
async def test_run_matching_commits_per_rule_and_isolates_failure() -> None:
    """A DB failure on one rule rolls back only that rule; the rest of
    the event's fan-out still fires and commits (finding: per-action/
    per-rule fault isolation)."""
    runner = _FakeRunner(result="delivered")
    audit = _FakeAudit()
    ex = AutomationExecutor(audit=audit, runner=runner)

    rule_a = _rule(name="A", actions=[{"type": "notify"}], is_enabled=True)
    rule_b = _rule(name="B", actions=[{"type": "notify"}], is_enabled=True)

    class _FlakyRepo:
        async def list_enabled_for_trigger(self, *, project_id, trigger):
            return [rule_a, rule_b]

        async def claim_execution(self, *, rule_id, now):
            if rule_id == rule_b.id:
                raise RuntimeError("deadlock")
            return CircuitDecision.EXECUTE, rule_a

    session = _FakeSession()
    # Must not raise despite rule B blowing up.
    await ex.run_matching(
        session=session,
        rules_repo=_FlakyRepo(),
        audit_log=None,
        project_id=rule_a.project_id,
        trigger="task.failed",
        fields={"task_id": "t"},
        now=None,
    )

    # Rule A ran + committed; rule B failed -> rolled back, isolated.
    assert len(runner.calls) == 1
    assert session.commits == 1
    assert session.rollbacks == 1


@pytest.mark.asyncio
async def test_rollback_does_not_cascade_to_sibling_rules() -> None:
    """A real-session regression for the fault-isolation guarantee.

    With a REAL SQLAlchemy session, one rule's rollback EXPIRES every
    persistent object, so a naive loop that re-reads a pre-fetched rule's
    attributes on the next iteration triggers a lazy load outside the async
    greenlet and silently kills every subsequent matched rule. The fix
    carries plain ids and operates only on the fresh row claim_execution
    re-loads, so a failure on the first rule must NOT stop the second from
    firing. The fake-session tests above cannot catch this because their
    fake never expires anything.
    """
    from datetime import UTC, datetime

    from sqlalchemy import select as sa_select
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from z4j_brain.persistence import models  # noqa: F401
    from z4j_brain.persistence.base import Base
    from z4j_brain.persistence.models import AutomationRule, Project
    from z4j_brain.persistence.repositories import AutomationRuleRepository

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with factory() as session:
            project = Project(id=uuid.uuid4(), slug="p", name="P")
            session.add(project)
            await session.flush()
            for name in ("A", "B"):
                session.add(
                    AutomationRule(
                        project_id=project.id,
                        name=name,
                        trigger="task.failed",
                        actions=[{"type": "notify"}],
                        max_executions_per_window=100,
                        window_seconds=3600,
                    ),
                )
            await session.commit()

            # Fail the FIRST per-rule commit only; the second must succeed.
            real_commit = session.commit
            state = {"n": 0}

            async def flaky_commit() -> None:
                state["n"] += 1
                if state["n"] == 1:
                    raise RuntimeError("serialization_failure")
                await real_commit()

            session.commit = flaky_commit  # type: ignore[method-assign]

            runner = _FakeRunner(result="delivered")
            ex = AutomationExecutor(audit=_FakeAudit(), runner=runner)
            await ex.run_matching(
                session=session,
                rules_repo=AutomationRuleRepository(session),
                audit_log=None,
                project_id=project.id,
                trigger="task.failed",
                fields={"task_id": "t"},
                now=datetime.now(UTC),
            )

            # Both rules were PROCESSED: the runner ran for the first rule
            # (whose DB write then rolled back) and for the second rule
            # (which committed). With the cascade bug the second rule is
            # never reached -- reading the expired sibling's PK raises
            # MissingGreenlet before its claim -- so this would be 1, not 2.
            assert len(runner.calls) == 2

            session.commit = real_commit  # type: ignore[method-assign]
            rows = (await session.execute(sa_select(AutomationRule))).scalars().all()
            # Exactly one rule committed its counter; the other rolled back.
            assert sorted(r.cb_execution_count for r in rows) == [0, 1]
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_notify_coalesce_suppresses_flood_within_window() -> None:
    """With notify_coalesce_seconds > 0, a rule that already notified inside
    the window folds the next notify into it (one alert per window), and
    fires again once the window elapses. Regression for the unbounded
    notify fan-out under a distinct-event flood."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from z4j_brain.persistence import models  # noqa: F401
    from z4j_brain.persistence.base import Base
    from z4j_brain.persistence.models import AutomationRule, Project
    from z4j_brain.persistence.repositories import AutomationRuleRepository

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with factory() as session:
            project = Project(id=uuid.uuid4(), slug="p", name="P", automation_enabled=True)
            session.add(project)
            await session.flush()
            session.add(
                AutomationRule(
                    project_id=project.id,
                    name="alert",
                    trigger="task.failed",
                    actions=[{"type": "notify"}],
                ),
            )
            await session.commit()

            runner = _FakeRunner(result="notified")
            ex = AutomationExecutor(audit=_FakeAudit(), runner=runner)

            async def fire(now):
                await ex.run_matching(
                    session=session,
                    rules_repo=AutomationRuleRepository(session),
                    audit_log=None,
                    project_id=project.id,
                    trigger="task.failed",
                    fields={"task_id": "t"},
                    now=now,
                    notify_coalesce_seconds=60,
                )

            base = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
            await fire(base)  # first alert -> emits
            await fire(base + timedelta(seconds=5))  # within window -> coalesced
            await fire(base + timedelta(seconds=30))  # still within -> coalesced
            assert len(runner.calls) == 1
            await fire(base + timedelta(seconds=120))  # window elapsed -> emits again
            assert len(runner.calls) == 2
    finally:
        await engine.dispose()
