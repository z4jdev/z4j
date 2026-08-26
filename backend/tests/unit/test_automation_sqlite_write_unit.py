"""Every rule in one fan-out gets a committed firing, not just the first.

``run_matching`` commits per rule. On SQLite that commit also ends the
``BEGIN IMMEDIATE`` reservation the audit chain requires before the first
read of a write unit, so a rule that does not take a fresh reservation runs
its actions and is only then refused its audit row. The executor swallows
that refusal and rolls the rule back, which means the side effects already
happened while the counter and the forensic row did not.

These run against a MIGRATED database on the REAL audit service. A
create_all() schema carries none of the Boundary-F machinery, and a recording
fake audit writes nothing, so neither can observe whether a firing is
recordable at the moment the executor tries to record it -- which is the only
question here.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.automation import AutomationExecutor
from z4j_brain.persistence import models  # noqa: F401  register mappers
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import AuditLog, AutomationRule, Project
from z4j_brain.persistence.repositories import (
    AuditLogRepository,
    AutomationRuleRepository,
)

_RULE_NAMES = ("first", "second", "third")


class _RecordingRunner:
    """Stands in for the notify/command runner; records what it was asked."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def run(self, *, session, rule, action_spec, fields) -> str:
        self.calls.append(rule.name)
        return "delivered"


def _settings(database_url: str, audit_chain_secret: str) -> Any:
    from z4j_brain.settings import Settings

    return Settings(
        database_url=database_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        audit_chain_secret=audit_chain_secret,  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )


async def _seed(db: DatabaseManager) -> uuid.UUID:
    """One project with three rules that all match the same event."""

    async with db.session(write=True) as session:
        project = Project(
            id=uuid.uuid4(),
            slug="fanout",
            name="Fanout",
            automation_enabled=True,
        )
        session.add(project)
        await session.flush()
        for name in _RULE_NAMES:
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


@pytest.mark.asyncio
async def test_every_matching_rule_commits_its_firing(
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> None:
    """Three matching rules, one event: three counters and three audit rows.

    Three rather than two on purpose. Re-arming the write unit once would
    carry the second rule and lose the third, which reads as a pass against
    two rules.
    """
    settings = _settings(migrated_db_url, migrated_audit_chain_secret)
    engine = create_async_engine(migrated_db_url)
    db = DatabaseManager(engine)
    try:
        project_id = await _seed(db)
        runner = _RecordingRunner()
        executor = AutomationExecutor(audit=AuditService(settings), runner=runner)

        # One event, one write unit opened before the first read: the shape
        # every caller of run_matching uses.
        async with db.session(write=True) as session:
            await executor.run_matching(
                session=session,
                rules_repo=AutomationRuleRepository(session),
                audit_log=AuditLogRepository(session),
                project_id=project_id,
                trigger="task.failed",
                fields={"task_id": "t1"},
                now=datetime.now(UTC),
            )

        assert sorted(runner.calls) == sorted(_RULE_NAMES)

        async with db.session() as session:
            rules = (await session.execute(select(AutomationRule))).scalars().all()
            fired = (
                (
                    await session.execute(
                        select(AuditLog)
                        .where(AuditLog.action == "automation.rule.fired")
                        .order_by(AuditLog.occurred_at),
                    )
                )
                .scalars()
                .all()
            )

        assert [rule.cb_execution_count for rule in rules] == [1, 1, 1], (
            "a rule whose actions ran but whose transaction rolled back leaves "
            "its circuit-breaker counter at zero, so the breaker never trips"
        )
        assert len(fired) == len(_RULE_NAMES), (
            "a firing with no audit row is a rule that acted on production "
            "with nothing but a log line to say so"
        )
        assert sorted(row.audit_metadata["rule_name"] for row in fired) == sorted(
            _RULE_NAMES,
        )
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_fan_out_reserves_its_own_write_unit(
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> None:
    """A caller that hands over a clean session still gets every firing.

    Not every caller opens the session immediately before the fan-out; the
    orphan-reconciliation path reaches it after a commit of its own. With the
    reservation taken inside ``run_matching`` the fan-out no longer depends on
    what the caller did with the session first.
    """
    settings = _settings(migrated_db_url, migrated_audit_chain_secret)
    engine = create_async_engine(migrated_db_url)
    db = DatabaseManager(engine)
    try:
        project_id = await _seed(db)
        runner = _RecordingRunner()
        executor = AutomationExecutor(audit=AuditService(settings), runner=runner)

        # write=False: no reservation from the caller at all.
        async with db.session() as session:
            await executor.run_matching(
                session=session,
                rules_repo=AutomationRuleRepository(session),
                audit_log=AuditLogRepository(session),
                project_id=project_id,
                trigger="task.failed",
                fields={"task_id": "t1"},
                now=datetime.now(UTC),
            )

        assert sorted(runner.calls) == sorted(_RULE_NAMES)

        async with db.session() as session:
            fired = (
                (
                    await session.execute(
                        select(AuditLog).where(
                            AuditLog.action == "automation.rule.fired",
                        ),
                    )
                )
                .scalars()
                .all()
            )
        assert len(fired) == len(_RULE_NAMES)
    finally:
        await engine.dispose()


class _WriterRefusedOnce(AuditLogRepository):
    """The real audit repository, with one reservation refused.

    Refusing the reservation rather than the append is the whole point: the
    append is inside the rule's own failure handling and the reservation is
    ahead of it. A busy writer, a lock timeout, or a connection that died
    between rules all arrive here.
    """

    def __init__(self, session, *, refuse_arm: int) -> None:
        super().__init__(session)
        self._refuse_arm = refuse_arm
        self.arms = 0

    async def require_sqlite_immediate_write_unit(self) -> None:
        self.arms += 1
        if self.arms == self._refuse_arm:
            raise OperationalError(
                "BEGIN IMMEDIATE",
                None,
                Exception("database is locked"),
            )
        await super().require_sqlite_immediate_write_unit()


@pytest.mark.asyncio
async def test_a_rule_refused_its_write_unit_costs_only_that_rule(
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> None:
    """One rule loses its writer; the other two still fire and commit.

    Three rules again, and the refusal aimed at the first of them, so a
    fan-out that stops at the refusal leaves two rules unfired rather than
    one ambiguous result.
    """
    settings = _settings(migrated_db_url, migrated_audit_chain_secret)
    engine = create_async_engine(migrated_db_url)
    db = DatabaseManager(engine)
    try:
        project_id = await _seed(db)
        runner = _RecordingRunner()
        executor = AutomationExecutor(audit=AuditService(settings), runner=runner)

        async with db.session(write=True) as session:
            # Arm 1 is the fan-out's own reservation before the rule load;
            # arm 2 is the first matched rule's.
            audit_log = _WriterRefusedOnce(session, refuse_arm=2)
            await executor.run_matching(
                session=session,
                rules_repo=AutomationRuleRepository(session),
                audit_log=audit_log,
                project_id=project_id,
                trigger="task.failed",
                fields={"task_id": "t1"},
                now=datetime.now(UTC),
            )

        # Every rule was still offered a reservation of its own: one for the
        # fan-out ahead of the rule load, one per rule, and one more per
        # firing, because the audit append reserves the writer too.
        assert audit_log.arms == 1 + len(_RULE_NAMES) + len(runner.calls)
        assert len(runner.calls) == len(_RULE_NAMES) - 1

        async with db.session() as session:
            fired = (
                (
                    await session.execute(
                        select(AuditLog).where(
                            AuditLog.action == "automation.rule.fired",
                        ),
                    )
                )
                .scalars()
                .all()
            )
            counts = sorted(
                rule.cb_execution_count
                for rule in (await session.execute(select(AutomationRule))).scalars().all()
            )

        assert len(fired) == len(_RULE_NAMES) - 1, (
            "a rule that could not reserve its writer must not take the rules "
            "queued behind it down with it"
        )
        assert counts == [0, 1, 1]
        assert sorted(row.audit_metadata["rule_name"] for row in fired) == sorted(runner.calls)
    finally:
        await engine.dispose()
