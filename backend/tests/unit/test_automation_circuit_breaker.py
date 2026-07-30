"""Automation rule circuit breaker: rolling-window trip + reset."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import AutomationRule, Project
from z4j_brain.persistence.repositories import (
    AutomationRuleRepository,
    CircuitDecision,
)


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


async def _rule(
    session: AsyncSession,
    *,
    max_exec: int,
    window: int,
) -> AutomationRule:
    project = Project(
        id=uuid.uuid4(),
        slug=f"p{uuid.uuid4().hex[:8]}",
        name="P",
    )
    session.add(project)
    await session.flush()
    rule = AutomationRule(
        project_id=project.id,
        name="r",
        trigger="task.failed",
        max_executions_per_window=max_exec,
        window_seconds=window,
    )
    session.add(rule)
    await session.commit()
    return rule


@pytest.mark.asyncio
async def test_trips_after_limit(session: AsyncSession) -> None:
    repo = AutomationRuleRepository(session)
    rule = await _rule(session, max_exec=2, window=3600)
    now = datetime.now(UTC)

    decisions = []
    for _ in range(4):
        decision, _row = await repo.claim_execution(rule_id=rule.id, now=now)
        decisions.append(decision)
        await session.commit()

    assert decisions == [
        CircuitDecision.EXECUTE,  # 1st
        CircuitDecision.EXECUTE,  # 2nd (at the limit)
        CircuitDecision.TRIPPED_NOW,  # 3rd -> over the limit, trips now
        CircuitDecision.TRIPPED,  # 4th -> already tripped
    ]


@pytest.mark.asyncio
async def test_window_resets(session: AsyncSession) -> None:
    repo = AutomationRuleRepository(session)
    rule = await _rule(session, max_exec=1, window=60)
    now = datetime.now(UTC)

    assert (await repo.claim_execution(rule_id=rule.id, now=now))[0] == CircuitDecision.EXECUTE
    await session.commit()
    assert (await repo.claim_execution(rule_id=rule.id, now=now))[0] == CircuitDecision.TRIPPED_NOW
    await session.commit()

    # Once the window elapses, the counter resets and execution resumes.
    later = now + timedelta(seconds=61)
    assert (await repo.claim_execution(rule_id=rule.id, now=later))[0] == CircuitDecision.EXECUTE


@pytest.mark.asyncio
async def test_claim_refreshes_stale_identity_map_row(session: AsyncSession) -> None:
    """claim_execution re-reads the locked row from the DB (populate_existing)
    rather than trusting an older copy already in the session identity map.

    Regression for the stale-counter under-count: the rule is loaded into
    the identity map, another writer advances cb_execution_count via a raw
    UPDATE the ORM object never sees, and the next claim must operate on the
    DB-current counter, not the cached snapshot.
    """
    from sqlalchemy import update as sa_update

    repo = AutomationRuleRepository(session)
    rule = await _rule(session, max_exec=100, window=3600)
    now = datetime.now(UTC)

    # rule is cached at cb_execution_count=0. Simulate a concurrent committed
    # writer advancing the counter out-of-band.
    await session.execute(
        sa_update(AutomationRule)
        .where(AutomationRule.id == rule.id)
        .values(cb_execution_count=5, cb_window_start=now),
    )

    decision, row = await repo.claim_execution(rule_id=rule.id, now=now)
    assert decision == CircuitDecision.EXECUTE
    # 5 (DB-current) + 1, not the stale 0 + 1.
    assert row is not None
    assert row.cb_execution_count == 6
