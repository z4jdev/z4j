"""Tests for the durable automation firing outbox + drain worker (#5)."""

from __future__ import annotations

import secrets
import uuid

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.workers.automation_outbox import AutomationOutboxDrainWorker
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import (
    AutomationFiringOutbox,
    AutomationRule,
    Membership,
    Project,
    User,
    UserNotification,
)
from z4j_brain.persistence.repositories import AutomationFiringOutboxRepository
from z4j_brain.settings import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )


@pytest.fixture
async def db() -> DatabaseManager:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield DatabaseManager(engine)
    await engine.dispose()


class _DummyDispatcher:
    """Notify actions never touch the dispatcher; a stand-in is enough."""


@pytest.mark.asyncio
async def test_repo_enqueue_list_delete(db: DatabaseManager) -> None:
    project_id = uuid.uuid4()
    async with db.session() as s:
        s.add(Project(id=project_id, slug="p", name="P"))
        await s.flush()
        await AutomationFiringOutboxRepository(s).enqueue(
            project_id=project_id,
            trigger="task.failed",
            fields={"task_id": "t1"},
        )
        await s.commit()

    async with db.session() as s:
        repo = AutomationFiringOutboxRepository(s)
        rows = await repo.list_pending()
        assert len(rows) == 1
        assert rows[0].trigger == "task.failed"
        assert rows[0].fields["task_id"] == "t1"
        assert await repo.count() == 1
        await repo.delete_by_id(rows[0].id)
        await s.commit()

    async with db.session() as s:
        assert await AutomationFiringOutboxRepository(s).count() == 0


@pytest.mark.asyncio
async def test_drain_fires_matching_rule_and_clears_row(
    db: DatabaseManager,
    settings: Settings,
) -> None:
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    async with db.session() as s:
        s.add(Project(id=project_id, slug="p", name="P", automation_enabled=True))
        s.add(User(id=user_id, email="a@x.io", password_hash="x"))
        await s.flush()
        s.add(Membership(user_id=user_id, project_id=project_id, role=ProjectRole.OPERATOR))
        s.add(
            AutomationRule(
                project_id=project_id,
                name="alert",
                trigger="task.failed",
                actions=[{"type": "notify"}],
                is_enabled=True,
            ),
        )
        await s.flush()
        await AutomationFiringOutboxRepository(s).enqueue(
            project_id=project_id,
            trigger="task.failed",
            fields={"task_id": "t1", "task_name": "myapp.t", "engine": "celery"},
        )
        await s.commit()

    worker = AutomationOutboxDrainWorker(
        db=db,
        dispatcher=_DummyDispatcher(),
        audit=AuditService(settings),
        settings=settings,
    )
    await worker.tick()

    async with db.session() as s:
        notes = (await s.execute(select(UserNotification))).scalars().all()
        outbox = (await s.execute(select(AutomationFiringOutbox))).scalars().all()
    # The deferred firing replayed: the member got the notification and the
    # outbox row was cleared.
    assert len(notes) == 1
    assert notes[0].user_id == user_id
    assert outbox == []


@pytest.mark.asyncio
async def test_drain_gives_up_after_max_attempts(
    db: DatabaseManager,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from z4j_brain.domain import automation as automation_mod
    from z4j_brain.domain.workers import automation_outbox as outbox_mod

    monkeypatch.setattr(outbox_mod, "_MAX_ATTEMPTS", 2)

    async def _boom(self, **_kwargs):
        raise RuntimeError("simulated replay failure")

    monkeypatch.setattr(automation_mod.AutomationExecutor, "run_matching", _boom)

    project_id = uuid.uuid4()
    async with db.session() as s:
        s.add(Project(id=project_id, slug="p", name="P", automation_enabled=True))
        await s.flush()
        await AutomationFiringOutboxRepository(s).enqueue(
            project_id=project_id,
            trigger="task.failed",
            fields={"task_id": "t1"},
        )
        await s.commit()

    worker = AutomationOutboxDrainWorker(
        db=db,
        dispatcher=_DummyDispatcher(),
        audit=AuditService(settings),
        settings=settings,
    )
    # First failing tick: attempts -> 1, row backed off (survives).
    await worker.tick()
    async with db.session() as s:
        assert await AutomationFiringOutboxRepository(s).count() == 1
    # A failed row is backed off (next_attempt_at in the future) so it steps
    # out of the FIFO head. Simulate the backoff window elapsing so it is due
    # for its next attempt.
    async with db.session() as s:
        await s.execute(update(AutomationFiringOutbox).values(next_attempt_at=None))
        await s.commit()
    # Second failing tick: attempts -> 2 (>= cap), poison row dropped.
    await worker.tick()
    async with db.session() as s:
        assert await AutomationFiringOutboxRepository(s).count() == 0


@pytest.mark.asyncio
async def test_has_enabled_rule_for_trigger_gate(db: DatabaseManager) -> None:
    """The EXISTS gate the frame router uses to skip deferring firings for a
    project with no automation: true only for an enabled rule on an
    automation-enabled project."""
    from z4j_brain.persistence.models import AutomationRule
    from z4j_brain.persistence.repositories import AutomationRuleRepository

    project_id = uuid.uuid4()
    async with db.session() as s:
        s.add(Project(id=project_id, slug="p", name="P", automation_enabled=True))
        await s.flush()
        repo = AutomationRuleRepository(s)
        assert not await repo.has_enabled_rule_for_trigger(
            project_id=project_id, trigger="task.failed"
        )
        s.add(
            AutomationRule(
                project_id=project_id,
                name="r",
                trigger="task.failed",
                actions=[{"type": "notify"}],
                is_enabled=True,
            ),
        )
        await s.flush()
        assert await repo.has_enabled_rule_for_trigger(project_id=project_id, trigger="task.failed")
        assert not await repo.has_enabled_rule_for_trigger(
            project_id=project_id, trigger="task.succeeded"
        )


@pytest.mark.asyncio
async def test_drain_clears_multiple_batches_in_one_tick(
    db: DatabaseManager,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One tick drains the whole backlog (round-robin until empty), not just
    a single batch -- otherwise a flood would drain at a trickle."""
    from z4j_brain.domain.workers import automation_outbox as outbox_mod

    monkeypatch.setattr(outbox_mod, "_PER_PROJECT_BATCH", 2)

    project_id = uuid.uuid4()
    async with db.session() as s:
        s.add(Project(id=project_id, slug="p", name="P", automation_enabled=True))
        await s.flush()
        # 5 rows for a project with NO rules: run_matching no-ops but the
        # drain still deletes each. 5 rows / batch 2 => needs 3 batches.
        await AutomationFiringOutboxRepository(s).enqueue_many(
            project_id=project_id,
            items=[("task.failed", {"task_id": f"t{i}"}) for i in range(5)],
        )
        await s.commit()

    worker = AutomationOutboxDrainWorker(
        db=db,
        dispatcher=_DummyDispatcher(),
        audit=AuditService(settings),
        settings=settings,
    )
    await worker.tick()

    async with db.session() as s:
        assert await AutomationFiringOutboxRepository(s).count() == 0


@pytest.mark.asyncio
async def test_drain_round_robins_across_tenants(
    db: DatabaseManager,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tenant with a large backlog must not starve another tenant: the
    round-robin drain gives each project with due rows a turn per round, so
    both projects' firings drain in the same tick (a flooding tenant cannot
    dominate the head of the global FIFO queue)."""
    from z4j_brain.domain.workers import automation_outbox as outbox_mod

    # Only ONE round, one row per project per round -- so a global-FIFO drain
    # would spend the whole round on the flooding tenant and never reach B.
    monkeypatch.setattr(outbox_mod, "_MAX_ROUNDS_PER_TICK", 1)
    monkeypatch.setattr(outbox_mod, "_PER_PROJECT_BATCH", 1)

    flood, small = uuid.uuid4(), uuid.uuid4()
    async with db.session() as s:
        s.add_all(
            [
                Project(id=flood, slug="flood", name="F", automation_enabled=True),
                Project(id=small, slug="small", name="S", automation_enabled=True),
            ],
        )
        await s.flush()
        repo = AutomationFiringOutboxRepository(s)
        # Flooding tenant enqueues FIRST (older created_at => head of FIFO).
        await repo.enqueue_many(
            project_id=flood,
            items=[("task.failed", {"task_id": f"f{i}"}) for i in range(20)],
        )
        await repo.enqueue(project_id=small, trigger="task.failed", fields={"task_id": "s0"})
        await s.commit()

    worker = AutomationOutboxDrainWorker(
        db=db,
        dispatcher=_DummyDispatcher(),
        audit=AuditService(settings),
        settings=settings,
    )
    await worker.tick()

    # In a single round both tenants got a turn: the small tenant's lone row
    # drained (not starved behind the flood's 20).
    async with db.session() as s:
        assert await AutomationFiringOutboxRepository(s).count_for_project(small) == 0
        # The flood drained just one this round (fairness), not all 20.
        assert await AutomationFiringOutboxRepository(s).count_for_project(flood) == 19
