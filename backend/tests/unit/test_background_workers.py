"""Tests for ``CommandTimeoutWorker`` and ``AgentHealthWorker``."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from z4j_brain.domain.workers import AgentHealthWorker, CommandTimeoutWorker
from z4j_brain.persistence.base import Base
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import AgentState, CommandStatus
from z4j_brain.persistence.models import Agent, Command, Project
from z4j_brain.settings import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        agent_offline_timeout_seconds=10,
    )


@pytest.fixture
async def db(settings: Settings) -> DatabaseManager:
    engine = create_async_engine(
        settings.database_url,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return DatabaseManager(engine)


@pytest.mark.asyncio
class TestCommandTimeoutWorker:
    async def test_marks_overdue_pending_as_timeout(
        self, db: DatabaseManager,
    ) -> None:
        async with db.session() as s:
            project = Project(slug="d", name="D")
            s.add(project)
            await s.flush()
            agent = Agent(
                project_id=project.id,
                name="w",
                token_hash=secrets.token_hex(32),
                protocol_version="1",
                framework_adapter="bare",
            )
            s.add(agent)
            await s.flush()
            past = datetime.now(UTC) - timedelta(seconds=10)
            future = datetime.now(UTC) + timedelta(seconds=60)
            s.add(
                Command(
                    project_id=project.id,
                    agent_id=agent.id,
                    action="retry_task",
                    target_type="task",
                    target_id="t1",
                    payload={},
                    status=CommandStatus.PENDING,
                    timeout_at=past,
                ),
            )
            s.add(
                Command(
                    project_id=project.id,
                    agent_id=agent.id,
                    action="retry_task",
                    target_type="task",
                    target_id="t2",
                    payload={},
                    status=CommandStatus.PENDING,
                    timeout_at=future,
                ),
            )
            await s.commit()

        worker = CommandTimeoutWorker(db)
        await worker.tick()

        async with db.session() as s:
            rows = (await s.execute(select(Command).order_by(Command.target_id))).scalars().all()
            assert {r.target_id: r.status for r in rows} == {
                "t1": CommandStatus.TIMEOUT,
                "t2": CommandStatus.PENDING,
            }


@pytest.mark.asyncio
class TestAgentHealthWorker:
    async def test_marks_stale_agents_offline(
        self, db: DatabaseManager, settings: Settings,
    ) -> None:
        async with db.session() as s:
            project = Project(slug="d", name="D")
            s.add(project)
            await s.flush()
            stale = Agent(
                project_id=project.id,
                name="stale",
                token_hash=secrets.token_hex(32),
                protocol_version="1",
                framework_adapter="bare",
                state=AgentState.ONLINE,
                last_seen_at=datetime.now(UTC) - timedelta(seconds=60),
            )
            fresh = Agent(
                project_id=project.id,
                name="fresh",
                token_hash=secrets.token_hex(32),
                protocol_version="1",
                framework_adapter="bare",
                state=AgentState.ONLINE,
                last_seen_at=datetime.now(UTC),
            )
            s.add(stale)
            s.add(fresh)
            await s.commit()

        worker = AgentHealthWorker(db=db, settings=settings)
        await worker.tick()

        async with db.session() as s:
            rows = (await s.execute(select(Agent).order_by(Agent.name))).scalars().all()
            states = {r.name: r.state for r in rows}
            assert states["stale"] == AgentState.OFFLINE
            assert states["fresh"] == AgentState.ONLINE
