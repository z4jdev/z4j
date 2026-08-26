"""Automation executor governance: dry-run / failsafe / fault-isolation.

The decision-matrix tests use a fake ActionRunner and a recording fake audit
service, so the dry-run / failsafe / fault-isolation matrix is exercised
without a DB or the real notification/command machinery.

The tests that do need a real session run against a MIGRATED database rather
than a create_all() one, and on the REAL audit service. Every Boundary-D and
Boundary-F guard lives in a migration, so a create_all() schema refuses
nothing and cannot observe what an operator's database does; and a recording
fake writes nothing, so it cannot observe whether a firing is recordable at
the point the executor tries to record it. Both substitutions have to go
before the audit half of this module means anything."""

from __future__ import annotations

import secrets
import uuid
from types import SimpleNamespace
from typing import Any

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
    kw.setdefault("config_revision", 1)
    kw.setdefault("_z4j_automation_project_revision", 1)
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

    async def flush(self) -> None:
        pass


class _FakeAuditLogRepo:
    """Counts writer reservations so the per-rule arming is observable.

    The reservation itself is a real repository call that only does anything
    on SQLite; what these fake-session tests can see is whether the executor
    asks for one at all, and how often. Whether the reservation is ACCEPTED
    after a mid-fan-out commit is a question only a real database can answer,
    and the migrated-database tests below are where it is asked.
    """

    def __init__(self, *, refuse_arms: set[int] | None = None) -> None:
        self.arms = 0
        # 1-based reservation numbers to refuse. A reservation fails for
        # ordinary reasons (a busy writer, a lock timeout, a connection that
        # died between rules), and it fails at the one point in a rule's
        # transaction that is ahead of everything else in it.
        self._refuse_arms = refuse_arms or set()

    async def require_sqlite_immediate_write_unit(self) -> None:
        self.arms += 1
        if self.arms in self._refuse_arms:
            raise RuntimeError("could not begin an immediate write unit")


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

        async def claim_execution(self, *, candidate):
            return CircuitDecision.EXECUTE, rule

    session = _FakeSession()
    audit_log = _FakeAuditLogRepo()
    await ex.run_matching(
        session=session,
        rules_repo=_FakeRepo(),
        audit_log=audit_log,
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
    # Once before the rule load, once for the rule's own transaction.
    assert audit_log.arms == 2


@pytest.mark.asyncio
async def test_stale_candidate_runs_no_action() -> None:
    """A disable/edit detected at claim time is a silent safe skip."""
    runner = _FakeRunner(result="must-not-run")
    audit = _FakeAudit()
    ex = AutomationExecutor(audit=audit, runner=runner)
    rule = _rule(actions=[{"type": "notify"}], is_enabled=True)

    class _StaleRepo:
        async def list_enabled_for_trigger(self, *, project_id, trigger):
            return [rule]

        async def claim_execution(self, *, candidate):
            return CircuitDecision.STALE, rule

    session = _FakeSession()
    await ex.run_matching(
        session=session,
        rules_repo=_StaleRepo(),
        audit_log=_FakeAuditLogRepo(),
        project_id=rule.project_id,
        trigger="task.failed",
        fields={},
        now=None,
    )

    assert runner.calls == []
    assert audit.rows == []
    assert session.commits == 1  # releases the authoritative row locks


@pytest.mark.asyncio
async def test_mid_rule_authority_change_stops_remaining_actions() -> None:
    """A self-committing first action cannot carry stale authority onward."""
    runner = _FakeRunner(result="issued")
    audit = _FakeAudit()
    ex = AutomationExecutor(audit=audit, runner=runner)
    rule = _rule(
        actions=[{"type": "retry"}, {"type": "cancel"}],
        is_enabled=True,
    )

    class _ChangedAfterFirstActionRepo:
        async def list_enabled_for_trigger(self, *, project_id, trigger):
            return [rule]

        async def claim_execution(self, *, candidate):
            return CircuitDecision.EXECUTE, rule

        async def revalidate_execution(self, candidate):
            return None  # edit/disable committed after action one

    session = _FakeSession()
    await ex.run_matching(
        session=session,
        rules_repo=_ChangedAfterFirstActionRepo(),
        audit_log=_FakeAuditLogRepo(),
        project_id=rule.project_id,
        trigger="task.failed",
        fields={},
        now=None,
    )

    assert [call["action"]["type"] for call in runner.calls] == ["retry"]
    assert [row["metadata"]["action"] for row in _actions(audit)] == ["retry"]


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

        async def claim_execution(self, *, candidate):
            if candidate.rule_id == rule_b.id:
                raise RuntimeError("deadlock")
            return CircuitDecision.EXECUTE, rule_a

    session = _FakeSession()
    audit_log = _FakeAuditLogRepo()
    # Must not raise despite rule B blowing up.
    await ex.run_matching(
        session=session,
        rules_repo=_FlakyRepo(),
        audit_log=audit_log,
        project_id=rule_a.project_id,
        trigger="task.failed",
        fields={"task_id": "t"},
        now=None,
    )

    # Rule A ran + committed; rule B failed -> rolled back, isolated.
    assert len(runner.calls) == 1
    assert session.commits == 1
    assert session.rollbacks == 1
    # Every rule reserves the writer for itself, including the one that
    # follows a sibling's failure: the load plus one per matched rule.
    assert audit_log.arms == 3


@pytest.mark.asyncio
async def test_a_rule_denied_its_write_unit_does_not_abort_the_fan_out(monkeypatch) -> None:
    """A refused reservation is one rule's loss, not the whole event's.

    Every other failure this fan-out tolerates happens after the rule's
    transaction has been entered. This one happens before, which is the
    difference between a rule that is skipped and a fan-out that stops: the
    rules queued behind it never get their turn, and the operator is told a
    generator did not yield.
    """
    swallowed: list[tuple[str, str]] = []
    import z4j_brain.api.metrics as metrics_mod

    monkeypatch.setattr(
        metrics_mod,
        "record_swallowed",
        lambda component, operation: swallowed.append((component, operation)),
    )

    runner = _FakeRunner(result="delivered")
    audit = _FakeAudit()
    ex = AutomationExecutor(audit=audit, runner=runner)

    rule_a = _rule(name="A", actions=[{"type": "notify"}], is_enabled=True)
    rule_b = _rule(name="B", actions=[{"type": "notify"}], is_enabled=True)
    by_id = {rule_a.id: rule_a, rule_b.id: rule_b}

    class _Repo:
        async def list_enabled_for_trigger(self, *, project_id, trigger):
            return [rule_a, rule_b]

        async def claim_execution(self, *, candidate):
            return CircuitDecision.EXECUTE, by_id[candidate.rule_id]

    session = _FakeSession()
    # Arm 1 is the fan-out's reservation before the rule load; arm 2 is rule
    # A's own. Rule B's is arm 3, and it must still be asked for.
    audit_log = _FakeAuditLogRepo(refuse_arms={2})

    await ex.run_matching(
        session=session,
        rules_repo=_Repo(),
        audit_log=audit_log,
        project_id=rule_a.project_id,
        trigger="task.failed",
        fields={"task_id": "t"},
        now=None,
    )

    # Rule A never ran anything, because it never had a transaction to run in.
    assert [call["rule"] for call in runner.calls] == ["B"]
    assert _actions(audit) and all(row["metadata"]["rule_name"] == "B" for row in _actions(audit))
    # Rule B committed; rule A's dead transaction was ended.
    assert session.commits == 1
    assert session.rollbacks == 1
    assert audit_log.arms == 3
    # And the dropped rule is observable rather than silent.
    assert swallowed == [("automation_executor", "run_matching")]


@pytest.mark.asyncio
async def test_a_rollback_that_also_fails_does_not_abort_the_fan_out() -> None:
    """The cleanup path is the last thing standing between one lost rule and
    a lost fan-out, so it cannot be the thing that raises."""
    runner = _FakeRunner(result="delivered")
    audit = _FakeAudit()
    ex = AutomationExecutor(audit=audit, runner=runner)

    rule_a = _rule(name="A", actions=[{"type": "notify"}], is_enabled=True)
    rule_b = _rule(name="B", actions=[{"type": "notify"}], is_enabled=True)
    by_id = {rule_a.id: rule_a, rule_b.id: rule_b}

    class _Repo:
        async def list_enabled_for_trigger(self, *, project_id, trigger):
            return [rule_a, rule_b]

        async def claim_execution(self, *, candidate):
            if candidate.rule_id == rule_a.id:
                raise RuntimeError("deadlock")
            return CircuitDecision.EXECUTE, by_id[candidate.rule_id]

    class _UnrollbackableSession(_FakeSession):
        async def rollback(self) -> None:
            await super().rollback()
            raise RuntimeError("connection is gone")

    session = _UnrollbackableSession()

    await ex.run_matching(
        session=session,
        rules_repo=_Repo(),
        audit_log=_FakeAuditLogRepo(),
        project_id=rule_a.project_id,
        trigger="task.failed",
        fields={"task_id": "t"},
        now=None,
    )

    assert [call["rule"] for call in runner.calls] == ["B"]
    assert session.commits == 1


def _real_settings(database_url: str, audit_chain_secret: str) -> Any:
    """Settings shaped the way a brain that writes audit rows is configured.

    A migrated database has Boundary F activated, and activated state is bound
    to the key that signed it, so the chain key has to be the fixture's own or
    every append is refused for the wrong reason.
    """
    from z4j_brain.settings import Settings

    return Settings(
        database_url=database_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        audit_chain_secret=audit_chain_secret,  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )


async def _seed_rules(db: Any, *names: str) -> Any:
    """Create a project plus one always-matching rule per name."""
    from z4j_brain.persistence.models import AutomationRule, Project

    async with db.session(write=True) as session:
        project = Project(id=uuid.uuid4(), slug="p", name="P", automation_enabled=True)
        session.add(project)
        await session.flush()
        for name in names:
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
        return project.id


async def _committed_audit_actions(db: Any) -> list[str]:
    """Automation audit actions that actually survived a commit, in order.

    Filtered to ``automation.*`` because the migrated fixture already carries
    the rows the Boundary-F activation ceremony wrote, which are not this
    executor's business.
    """
    from sqlalchemy import select as sa_select
    from z4j_brain.persistence.models import AuditLog

    async with db.session() as session:
        result = await session.execute(
            sa_select(AuditLog)
            .where(AuditLog.action.startswith("automation."))
            .order_by(AuditLog.occurred_at),
        )
        return [row.action for row in result.scalars().all()]


@pytest.mark.asyncio
async def test_rollback_does_not_cascade_to_sibling_rules(
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> None:
    """A real-session regression for the fault-isolation guarantee.

    With a REAL SQLAlchemy session, one rule's rollback EXPIRES every
    persistent object, so a naive loop that re-reads a pre-fetched rule's
    attributes on the next iteration triggers a lazy load outside the async
    greenlet and silently kills every subsequent matched rule. The fix
    carries immutable plain-data configuration tokens and operates only on
    the fresh row claim_execution re-loads, so a failure on the first rule
    must NOT stop the second from firing. The fake-session tests above cannot
    catch this because their fake never expires anything.

    Run with the REAL :class:`AuditService` on a session opened the way the
    replay worker opens one, because the audit append is not a bystander here:
    it is a write on this same session, inside this same per-rule transaction,
    against an activated chain. A recording fake returns a row object and
    touches nothing, so it cannot see whether the second rule's firing is
    actually recordable after the first rule's transaction ended. That is the
    whole question a per-rule commit boundary raises.
    """
    from datetime import UTC, datetime

    from sqlalchemy import select as sa_select
    from sqlalchemy.ext.asyncio import create_async_engine
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence import models  # noqa: F401
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.models import AutomationRule
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        AutomationRuleRepository,
    )

    settings = _real_settings(migrated_db_url, migrated_audit_chain_secret)
    engine = create_async_engine(migrated_db_url)
    db = DatabaseManager(engine)
    try:
        project_id = await _seed_rules(db, "A", "B")

        # The replay worker's session shape: one write unit, opened before the
        # first read, holding the fan-out for the whole event.
        async with db.session(write=True) as session:
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
            ex = AutomationExecutor(audit=AuditService(settings), runner=runner)
            await ex.run_matching(
                session=session,
                rules_repo=AutomationRuleRepository(session),
                audit_log=AuditLogRepository(session),
                project_id=project_id,
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

        async with db.session() as session:
            rows = (await session.execute(sa_select(AutomationRule))).scalars().all()
            # Exactly one rule committed its counter; the other rolled back.
            assert sorted(r.cb_execution_count for r in rows) == [0, 1]

        assert await _committed_audit_actions(db) == ["automation.rule.fired"], (
            "the surviving rule fired but left no audit row, so the only "
            "record that automation acted on this event is a log line"
        )
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_notify_coalesce_suppresses_flood_within_window(
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> None:
    """With notify_coalesce_seconds > 0, a rule that already notified inside
    the window folds the next notify into it (one alert per window), and
    fires again once the window elapses. Regression for the unbounded
    notify fan-out under a distinct-event flood.

    Also on the real :class:`AuditService`: the coalesce window is remembered
    in ``last_notify_at``, which only survives if the firing's own transaction
    commits, and that transaction is the one the audit append participates in.
    A fake audit makes the window look durable when it is not.
    """
    from datetime import UTC, datetime, timedelta

    from sqlalchemy.ext.asyncio import create_async_engine
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence import models  # noqa: F401
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        AutomationRuleRepository,
    )

    settings = _real_settings(migrated_db_url, migrated_audit_chain_secret)
    engine = create_async_engine(migrated_db_url)
    db = DatabaseManager(engine)
    try:
        project_id = await _seed_rules(db, "alert")
        runner = _FakeRunner(result="notified")
        ex = AutomationExecutor(audit=AuditService(settings), runner=runner)

        async def fire(now):
            # One event, one write unit: the shape the replay worker uses.
            async with db.session(write=True) as session:
                await ex.run_matching(
                    session=session,
                    rules_repo=AutomationRuleRepository(session),
                    audit_log=AuditLogRepository(session),
                    project_id=project_id,
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

        assert await _committed_audit_actions(db) == ["automation.rule.fired"] * 4, (
            "every decision the executor made, emitted or coalesced, has to "
            "leave a row; a coalesced alert with no audit row is an alert that "
            "silently did not happen"
        )
    finally:
        await engine.dispose()
