"""End-to-end test for the reconciliation apply path:

CommandResult arrives → CommandDispatcher.handle_result detects
``action == "reconcile_task"`` → TaskRepository.apply_reconciled_state
flips the Task row's state.

This test is the missing link from the worker tests - it proves
the *brain side* of the loop closes correctly when an agent comes
back with an authoritative engine_state.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import StaticPool

from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import TaskState
from z4j_brain.persistence.models import Project, Task
from z4j_brain.persistence.repositories import TaskRepository


@pytest.fixture
async def engine():
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest.fixture
async def project_and_task(engine) -> tuple[UUID, str]:
    """Insert a project + a task stuck in 'started'."""
    long_ago = datetime.now(UTC) - timedelta(hours=1)
    async with AsyncSession(engine) as s:
        p = Project(slug="proj", name="Proj")
        s.add(p)
        await s.commit()
        await s.refresh(p)
        project_id = p.id

        s.add(
            Task(
                project_id=project_id,
                engine="celery",
                task_id="stuck-1",
                name="myapp.tasks.flaky",
                state=TaskState.STARTED,
                started_at=long_ago,
            ),
        )
        await s.commit()
    return project_id, "stuck-1"


@pytest.mark.asyncio
async def test_apply_reconciled_state_promotes_started_to_success(
    engine, project_and_task,
):
    project_id, task_id = project_and_task

    async with AsyncSession(engine) as s:
        repo = TaskRepository(s)
        finished = datetime.now(UTC)
        changed = await repo.apply_reconciled_state(
            project_id=project_id,
            engine="celery",
            task_id=task_id,
            engine_state="success",
            finished_at=finished,
        )
        await s.commit()
        assert changed is True

    # Re-read in a fresh session to confirm the UPDATE persisted.
    async with AsyncSession(engine) as s:
        row = await TaskRepository(s).get_by_engine_task_id(
            project_id=project_id, engine="celery", task_id=task_id,
        )
        assert row is not None
        assert row.state == TaskState.SUCCESS
        assert row.finished_at is not None


@pytest.mark.asyncio
async def test_apply_reconciled_state_idempotent(engine, project_and_task):
    """Same call twice → second is a no-op (changed=False)."""
    project_id, task_id = project_and_task
    async with AsyncSession(engine) as s:
        repo = TaskRepository(s)
        first = await repo.apply_reconciled_state(
            project_id=project_id,
            engine="celery",
            task_id=task_id,
            engine_state="failure",
        )
        await s.commit()
        second = await repo.apply_reconciled_state(
            project_id=project_id,
            engine="celery",
            task_id=task_id,
            engine_state="failure",
        )
        assert first is True
        assert second is False  # already matches


@pytest.mark.asyncio
async def test_apply_reconciled_state_unknown_is_noop(engine, project_and_task):
    project_id, task_id = project_and_task
    async with AsyncSession(engine) as s:
        repo = TaskRepository(s)
        changed = await repo.apply_reconciled_state(
            project_id=project_id,
            engine="celery",
            task_id=task_id,
            engine_state="unknown",
        )
        assert changed is False


@pytest.mark.asyncio
async def test_apply_reconciled_state_unknown_task_is_noop(engine, project_and_task):
    """A reconciliation result for a task we never knew about should
    not invent a new row - it just no-ops."""
    project_id, _ = project_and_task
    async with AsyncSession(engine) as s:
        repo = TaskRepository(s)
        changed = await repo.apply_reconciled_state(
            project_id=project_id,
            engine="celery",
            task_id="never-seen",
            engine_state="success",
        )
        assert changed is False
