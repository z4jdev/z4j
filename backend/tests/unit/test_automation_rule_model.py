"""AutomationRule model round-trip + defaults + unique name (R1)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import AutomationRule, Project


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


async def _project(session: AsyncSession, slug: str) -> Project:
    project = Project(id=uuid.uuid4(), slug=slug, name=slug.upper())
    session.add(project)
    await session.flush()
    return project


@pytest.mark.asyncio
async def test_round_trip_and_defaults(session: AsyncSession) -> None:
    project = await _project(session, "p1")
    session.add(
        AutomationRule(
            project_id=project.id,
            name="retry SMTP failures",
            trigger="task.failed",
            conditions={"exception": "SMTP"},
            actions=[{"type": "notify", "channel_type": "slack"}],
        ),
    )
    await session.commit()

    loaded = (await session.execute(select(AutomationRule))).scalar_one()
    assert loaded.name == "retry SMTP failures"
    assert loaded.trigger == "task.failed"
    assert loaded.conditions == {"exception": "SMTP"}
    assert loaded.actions == [{"type": "notify", "channel_type": "slack"}]
    # Defaults.
    assert loaded.is_enabled is True
    assert loaded.dry_run is False
    assert loaded.max_executions_per_window == 100
    assert loaded.window_seconds == 3600
    assert loaded.cb_tripped is False
    assert loaded.cb_execution_count == 0
    assert loaded.created_by is None


@pytest.mark.asyncio
async def test_unique_name_per_project(session: AsyncSession) -> None:
    project = await _project(session, "p2")
    session.add(
        AutomationRule(
            project_id=project.id,
            name="dup",
            trigger="task.failed",
        ),
    )
    await session.commit()
    session.add(
        AutomationRule(
            project_id=project.id,
            name="dup",
            trigger="task.succeeded",
        ),
    )
    with pytest.raises(IntegrityError):
        await session.commit()
