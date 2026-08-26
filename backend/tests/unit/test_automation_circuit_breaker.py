"""Automation rule circuit breaker: rolling-window trip + reset."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import AutomationRule, AutomationRuleAdmission, Project
from z4j_brain.persistence.repositories import (
    AutomationRuleRepository,
    CircuitDecision,
)
from z4j_brain.persistence.repositories.automation_rule import dispatch_candidate


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


def _candidate(rule: AutomationRule, *, project_revision: int = 1):
    return dispatch_candidate(rule, project_revision=project_revision)


@pytest.mark.asyncio
async def test_get_for_update_scopes_lock_to_project(session: AsyncSession) -> None:
    """A known cross-tenant rule UUID is not selected or transiently locked."""

    repo = AutomationRuleRepository(session)
    rule = await _rule(session, max_exec=2, window=60)

    assert await repo.get_for_update(rule.id, project_id=uuid.uuid4()) is None
    assert await repo.get_for_update(rule.id, project_id=rule.project_id) is rule


@pytest.mark.asyncio
async def test_trips_after_limit(session: AsyncSession) -> None:
    repo = AutomationRuleRepository(session)
    rule = await _rule(session, max_exec=2, window=3600)
    now = datetime.now(UTC)

    decisions = []
    for _ in range(4):
        decision, _row = await repo.claim_execution(
            candidate=_candidate(rule),
            now=now,
        )
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

    assert (await repo.claim_execution(candidate=_candidate(rule), now=now))[
        0
    ] == CircuitDecision.EXECUTE
    await session.commit()
    assert (await repo.claim_execution(candidate=_candidate(rule), now=now))[
        0
    ] == CircuitDecision.TRIPPED_NOW
    await session.commit()

    # Once the window elapses, the counter resets and execution resumes.
    later = now + timedelta(seconds=61)
    assert (await repo.claim_execution(candidate=_candidate(rule), now=later))[
        0
    ] == CircuitDecision.EXECUTE


@pytest.mark.asyncio
async def test_exact_rolling_window_blocks_fixed_boundary_burst(
    session: AsyncSession,
) -> None:
    """No fixed-window reset may admit >N events in any W interval."""
    repo = AutomationRuleRepository(session)
    rule = await _rule(session, max_exec=2, window=60)
    base = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)

    async def claim(at: datetime) -> CircuitDecision:
        decision, _ = await repo.claim_execution(
            candidate=_candidate(rule),
            now=at,
        )
        await session.commit()
        return decision

    assert await claim(base) == CircuitDecision.EXECUTE
    assert await claim(base + timedelta(seconds=59)) == CircuitDecision.EXECUTE
    # The admission at t=0 expires exactly at t=60, so one slot opens.
    assert await claim(base + timedelta(seconds=60)) == CircuitDecision.EXECUTE
    # A fixed window anchored at t=0 would allow this second post-boundary
    # burst too, producing three admissions inside (t=0, t=60]. The retained
    # timestamps correctly keep t=59 and t=60 at the configured limit.
    assert await claim(base + timedelta(seconds=60, milliseconds=1)) == (
        CircuitDecision.TRIPPED_NOW
    )
    for millis in range(2, 20):
        assert await claim(base + timedelta(seconds=60, milliseconds=millis)) == (
            CircuitDecision.TRIPPED
        )

    retained = (
        (
            await session.execute(
                select(AutomationRuleAdmission.admitted_at)
                .where(AutomationRuleAdmission.rule_id == rule.id)
                .order_by(AutomationRuleAdmission.admitted_at),
            )
        )
        .scalars()
        .all()
    )
    assert len(retained) == 2
    assert [_aware_for_test(value) for value in retained] == [
        base + timedelta(seconds=59),
        base + timedelta(seconds=60),
    ]


def _aware_for_test(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


@pytest.mark.asyncio
async def test_configuration_change_starts_a_bounded_new_epoch(
    session: AsyncSession,
) -> None:
    repo = AutomationRuleRepository(session)
    rule = await _rule(session, max_exec=1, window=60)
    base = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)

    assert (await repo.claim_execution(candidate=_candidate(rule), now=base))[
        0
    ] == CircuitDecision.EXECUTE
    await session.commit()

    # A wider window cannot reuse an incomplete history pruned under the old
    # configuration. The digest change atomically clears the old epoch.
    rule.window_seconds = 120
    await session.flush()
    assert (
        await repo.claim_execution(
            candidate=_candidate(rule),
            now=base + timedelta(seconds=1),
        )
    )[0] == CircuitDecision.EXECUTE
    await session.commit()

    count = await session.scalar(
        select(func.count(AutomationRuleAdmission.id)).where(
            AutomationRuleAdmission.rule_id == rule.id,
        ),
    )
    assert count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("authority", ["rule", "project"])
async def test_disable_after_match_is_revalidated_before_admission(
    session: AsyncSession,
    authority: str,
) -> None:
    repo = AutomationRuleRepository(session)
    rule = await _rule(session, max_exec=10, window=60)
    candidate = _candidate(rule)

    if authority == "rule":
        rule.is_enabled = False
    else:
        project = await session.get(Project, rule.project_id)
        assert project is not None
        project.automation_enabled = False
    await session.flush()

    decision, row = await repo.claim_execution(
        candidate=candidate,
        now=datetime(2026, 8, 12, 12, 0, tzinfo=UTC),
    )
    assert decision == CircuitDecision.STALE
    if authority == "rule":
        assert row is None  # disabled rule is excluded by the locked query
    assert (
        await session.scalar(
            select(func.count(AutomationRuleAdmission.id)).where(
                AutomationRuleAdmission.rule_id == rule.id,
            ),
        )
        == 0
    )


@pytest.mark.asyncio
async def test_claim_refreshes_stale_identity_map_row(session: AsyncSession) -> None:
    """A DB-current config edit invalidates a cached matched candidate."""
    from sqlalchemy import update as sa_update

    repo = AutomationRuleRepository(session)
    rule = await _rule(session, max_exec=100, window=3600)
    now = datetime.now(UTC)

    candidate = _candidate(rule)
    # Simulate a writer changing the action while this session's ORM object
    # remains stale. populate_existing must see the DB value and refuse to
    # combine the old condition match with the new action.
    await session.execute(
        sa_update(AutomationRule)
        .where(AutomationRule.id == rule.id)
        .values(actions=[{"type": "cancel"}])
        .execution_options(synchronize_session=False),
    )

    decision, row = await repo.claim_execution(candidate=candidate, now=now)
    assert decision == CircuitDecision.STALE
    assert row is None
    assert rule.cb_execution_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("authority", ["rule", "project"])
async def test_edit_away_and_back_still_invalidates_candidate(
    session: AsyncSession,
    authority: str,
) -> None:
    """Monotonic epochs close the digest/boolean ABA gap on SQLite too."""
    repo = AutomationRuleRepository(session)
    rule = await _rule(session, max_exec=10, window=60)
    candidate = _candidate(rule)

    if authority == "rule":
        locked = await repo.get_for_update(rule.id)
        assert locked is not None
        original = list(locked.actions)
        await repo.update_configuration(locked, {"actions": [{"type": "cancel"}]})
        await repo.update_configuration(locked, {"actions": original})
        assert locked.config_revision == candidate.rule_revision + 2
    else:
        project = await session.get(Project, rule.project_id)
        assert project is not None
        await repo.set_project_automation_enabled(project, enabled=False)
        await repo.set_project_automation_enabled(project, enabled=True)
        assert project.automation_revision == candidate.project_revision + 2

    decision, row = await repo.claim_execution(
        candidate=candidate,
        now=datetime(2026, 8, 12, 12, 0, tzinfo=UTC),
    )
    assert decision == CircuitDecision.STALE
    assert row is None
    assert (
        await session.scalar(
            select(func.count(AutomationRuleAdmission.id)).where(
                AutomationRuleAdmission.rule_id == rule.id,
            ),
        )
        == 0
    )
