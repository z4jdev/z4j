"""M3: TaskRepository.list_for_project's name_substring filter must escape LIKE
metacharacters, so a literal '%' or '_' in an operator's bulk-retry selection
filter matches LITERALLY and does not over-match (which would widen a bulk retry
beyond the intended set)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import TaskState
from z4j_brain.persistence.models import Project, Task
from z4j_brain.persistence.repositories.tasks import TaskRepository


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


@pytest.mark.asyncio
async def test_name_substring_escapes_like_wildcards(session: AsyncSession) -> None:
    project = Project(slug="p", name="P")
    session.add(project)
    await session.flush()

    base = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
    for i, name in enumerate(
        ("billing%refund", "billingXrefund", "billing_refund", "billingYrefund")
    ):
        session.add(
            Task(
                project_id=project.id,
                engine="celery",
                task_id=f"t-{i}",
                name=name,
                state="failure",
                priority="normal",
                received_at=base,
            )
        )
    await session.flush()
    repo = TaskRepository(session)

    # A literal '%' must match ONLY the task literally named 'billing%refund',
    # NOT 'billingXrefund'/'billingYrefund' (which an unescaped % wildcard would
    # over-match).
    rows = await repo.list_for_project(
        project_id=project.id,
        state=TaskState.FAILURE,
        queue=None,
        name_substring="billing%refund",
        limit=100,
    )
    assert sorted(t.name for t in rows) == ["billing%refund"]

    # A literal '_' must match ONLY 'billing_refund', not any single-char variant.
    rows2 = await repo.list_for_project(
        project_id=project.id,
        state=TaskState.FAILURE,
        queue=None,
        name_substring="billing_refund",
        limit=100,
    )
    assert sorted(t.name for t in rows2) == ["billing_refund"]
