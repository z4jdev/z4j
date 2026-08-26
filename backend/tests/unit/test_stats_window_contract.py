"""Regression coverage for the self-describing project-stats window."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.api.stats import get_stats
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import ProjectRole, TaskState
from z4j_brain.persistence.models import Membership, Project, Task, User
from z4j_brain.persistence.repositories import (
    MembershipRepository,
    ProjectRepository,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(("requested_hours", "effective_hours"), [(6, 6), (5, 24)])
async def test_effective_stats_window_is_reported_with_legacy_field_names(
    requested_hours: int,
    effective_hours: int,
) -> None:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        async with AsyncSession(engine, expire_on_commit=False) as session:
            project = Project(slug="window-test", name="Window test")
            user = User(
                email=f"stats-{uuid.uuid4()}@example.com",
                password_hash="unused",
                is_active=True,
            )
            session.add_all([project, user])
            await session.flush()
            session.add(
                Membership(
                    user_id=user.id,
                    project_id=project.id,
                    role=ProjectRole.VIEWER,
                ),
            )
            session.add(
                Task(
                    project_id=project.id,
                    engine="celery",
                    task_id="inside-six-hours",
                    name="example.task",
                    state=TaskState.FAILURE,
                    finished_at=datetime.now(UTC) - timedelta(hours=2),
                ),
            )
            await session.commit()

            response = await get_stats(
                project.slug,
                hours=requested_hours,
                user=user,
                memberships=MembershipRepository(session),
                projects=ProjectRepository(session),
                db_session=session,
            )

        assert response.window_hours == effective_hours
        assert response.tasks_failed_24h == 1
        assert response.failure_rate_24h == 1.0
    finally:
        await engine.dispose()
