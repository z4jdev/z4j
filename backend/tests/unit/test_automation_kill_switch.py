"""Per-project automation kill switch: the repo choke point (R3b).

``list_enabled_for_trigger`` is the executor's single rule-loading point,
so it is also where the whole-project kill switch is enforced: a project
with ``automation_enabled=False`` yields zero rules and nothing fires,
regardless of each rule's own ``is_enabled`` state.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import AutomationRule, Project
from z4j_brain.persistence.repositories.automation_rule import (
    AutomationRuleRepository,
    dispatch_candidate,
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


async def _seed(session: AsyncSession, *, automation_enabled: bool):
    project = Project(
        id=uuid.uuid4(),
        slug=f"p{uuid.uuid4().hex[:8]}",
        name="P",
        automation_enabled=automation_enabled,
    )
    session.add(project)
    await session.flush()
    rule = AutomationRule(
        project_id=project.id,
        name="r",
        trigger="task.failed",
        actions=[{"type": "notify"}],
        is_enabled=True,
    )
    session.add(rule)
    await session.flush()
    return project, rule


@pytest.mark.asyncio
async def test_switch_on_returns_rules(session: AsyncSession) -> None:
    project, rule = await _seed(session, automation_enabled=True)
    rows = await AutomationRuleRepository(session).list_enabled_for_trigger(
        project_id=project.id,
        trigger="task.failed",
    )
    assert [r.id for r in rows] == [rule.id]
    candidate = dispatch_candidate(rows[0])
    assert candidate.rule_revision == rule.config_revision == 1
    assert candidate.project_revision == project.automation_revision == 1


@pytest.mark.asyncio
async def test_switch_off_returns_nothing(session: AsyncSession) -> None:
    project, _ = await _seed(session, automation_enabled=False)
    rows = await AutomationRuleRepository(session).list_enabled_for_trigger(
        project_id=project.id,
        trigger="task.failed",
    )
    assert rows == []


@pytest.mark.asyncio
async def test_rule_load_cap_boundary(
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """At exactly the cap nothing is dropped; one over the cap truncates.

    Regression: the guard used ``>=`` against a query limited to the cap,
    so a project with EXACTLY cap rules got a false 'rules will not fire'
    warning even though all of them were returned. The fix fetches one past
    the cap and warns only on a real drop.
    """
    from z4j_brain.persistence.repositories import automation_rule as mod

    monkeypatch.setattr(mod, "_MAX_RULES_PER_TRIGGER", 3)

    project = Project(
        id=uuid.uuid4(),
        slug=f"p{uuid.uuid4().hex[:8]}",
        name="P",
        automation_enabled=True,
    )
    session.add(project)
    await session.flush()
    for i in range(4):
        session.add(
            AutomationRule(
                project_id=project.id,
                name=f"r{i}",
                trigger="task.failed",
                actions=[{"type": "notify"}],
                is_enabled=True,
            ),
        )
    await session.flush()

    repo = AutomationRuleRepository(session)
    # 4 rules, cap 3 -> truncated to exactly the cap.
    rows = await repo.list_enabled_for_trigger(
        project_id=project.id,
        trigger="task.failed",
    )
    assert len(rows) == 3


@pytest.mark.asyncio
async def test_disable_rules_created_by_targets_only_that_user(
    session: AsyncSession,
) -> None:
    """Deprovision hook: disabling a revoked creator's rules touches only
    THEIR still-enabled rules in the project, not other members' rules and
    not already-disabled ones."""
    project = Project(
        id=uuid.uuid4(),
        slug=f"p{uuid.uuid4().hex[:8]}",
        name="P",
        automation_enabled=True,
    )
    session.add(project)
    await session.flush()
    alice, bob = uuid.uuid4(), uuid.uuid4()

    def _rule(created_by, *, enabled):
        return AutomationRule(
            project_id=project.id,
            name=f"r{uuid.uuid4().hex[:8]}",
            trigger="task.failed",
            actions=[{"type": "notify"}],
            is_enabled=enabled,
            created_by=created_by,
        )

    # alice: two enabled + one already disabled; bob: one enabled.
    seeded = [
        _rule(alice, enabled=True),
        _rule(alice, enabled=True),
        _rule(alice, enabled=False),
        _rule(bob, enabled=True),
    ]
    session.add_all(seeded)
    await session.flush()

    repo = AutomationRuleRepository(session)
    n = await repo.disable_rules_created_by(user_id=alice, project_id=project.id)
    await session.commit()

    # Only alice's two ENABLED rules were disabled.
    assert n == 2
    for rule in seeded:
        await session.refresh(rule)
    assert [rule.config_revision for rule in seeded] == [2, 2, 1, 1]
    # Bob's rule still fires.
    remaining = await repo.list_enabled_for_trigger(
        project_id=project.id,
        trigger="task.failed",
    )
    assert [r.created_by for r in remaining] == [bob]


@pytest.mark.asyncio
async def test_disable_all_rules_created_by_user_spans_projects(
    session: AsyncSession,
) -> None:
    """User-delete hook: disabling a deleted creator's rules covers ALL
    their projects (the FK nulls created_by, so orphaned rules must be
    stopped everywhere before they become indistinguishable from system
    rules), touching only their still-enabled rules."""
    p1 = Project(id=uuid.uuid4(), slug=f"p{uuid.uuid4().hex[:8]}", name="P1")
    p2 = Project(id=uuid.uuid4(), slug=f"p{uuid.uuid4().hex[:8]}", name="P2")
    session.add_all([p1, p2])
    await session.flush()
    alice, bob = uuid.uuid4(), uuid.uuid4()

    def _rule(project_id, created_by, *, enabled):
        return AutomationRule(
            project_id=project_id,
            name=f"r{uuid.uuid4().hex[:8]}",
            trigger="task.failed",
            actions=[{"type": "notify"}],
            is_enabled=enabled,
            created_by=created_by,
        )

    seeded = [
        _rule(p1.id, alice, enabled=True),  # disabled
        _rule(p2.id, alice, enabled=True),  # disabled (different project)
        _rule(p1.id, alice, enabled=False),  # already off, untouched
        _rule(p1.id, bob, enabled=True),  # other user, untouched
    ]
    session.add_all(seeded)
    await session.flush()

    repo = AutomationRuleRepository(session)
    n = await repo.disable_all_rules_created_by_user(user_id=alice)
    await session.commit()

    # Alice's two enabled rules across BOTH projects were disabled.
    assert n == 2
    for rule in seeded:
        await session.refresh(rule)
    assert [rule.config_revision for rule in seeded] == [2, 2, 1, 1]
    assert (await repo.list_enabled_for_trigger(project_id=p1.id, trigger="task.failed"))[
        0
    ].created_by == bob
    assert (await repo.list_enabled_for_trigger(project_id=p2.id, trigger="task.failed")) == []
