"""PostgreSQL arbitration for the legacy ``worker_id IS NULL`` slot."""

from __future__ import annotations

import asyncio
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker
from z4j_brain.persistence.models import Agent, AgentWorker, Project
from z4j_brain.persistence.repositories import AgentWorkerRepository
from z4j_brain.settings import Settings

from tests.integration.conftest import _upgrade_integration_database

pytestmark = pytest.mark.asyncio


async def _seed_agent(engine: AsyncEngine, *, name: str) -> tuple[uuid.UUID, uuid.UUID]:
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as session:
        project = Project(
            slug=f"legacy-slot-{uuid.uuid4().hex[:8]}",
            name="Legacy worker slot",
        )
        session.add(project)
        await session.flush()
        agent = Agent(
            project_id=project.id,
            name=name,
            token_hash=uuid.uuid4().hex,
            protocol_version="1",
            framework_adapter="bare",
        )
        session.add(agent)
        await session.commit()
        return project.id, agent.id


async def _seed_historical_agent(
    engine: AsyncEngine,
    *,
    name: str,
) -> tuple[uuid.UUID, uuid.UUID]:
    """Insert through the pre-0014 physical schema, not current ORM metadata."""

    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    async with engine.begin() as connection:
        await connection.execute(
            text("INSERT INTO projects (id, slug, name) VALUES (:id, :slug, :name)"),
            {
                "id": project_id,
                "slug": f"legacy-slot-{uuid.uuid4().hex[:8]}",
                "name": "Legacy worker slot",
            },
        )
        await connection.execute(
            text(
                "INSERT INTO agents ("
                "id, project_id, name, token_hash, protocol_version, "
                "framework_adapter"
                ") VALUES ("
                ":id, :project_id, :name, :token_hash, :protocol_version, "
                ":framework_adapter"
                ")"
            ),
            {
                "id": agent_id,
                "project_id": project_id,
                "name": name,
                "token_hash": uuid.uuid4().hex,
                "protocol_version": "1",
                "framework_adapter": "bare",
            },
        )
    return project_id, agent_id


async def test_postgres_concurrent_legacy_reconnects_have_one_durable_slot(
    migrated_engine: AsyncEngine,
) -> None:
    project_id, agent_id = await _seed_agent(migrated_engine, name="legacy-concurrent")
    sessions = async_sessionmaker(migrated_engine, expire_on_commit=False)
    start = asyncio.Event()

    async def reconnect(number: int) -> None:
        await start.wait()
        async with sessions() as session:
            await AgentWorkerRepository(session).register_or_refresh(
                agent_id=agent_id,
                project_id=project_id,
                worker_id=None,
                role=f"legacy-{number}",
                pid=20_000 + number,
            )
            await session.commit()

    attempts = [asyncio.create_task(reconnect(number)) for number in range(8)]
    start.set()
    await asyncio.gather(*attempts)

    async with sessions() as session:
        rows = list(
            (
                await session.execute(
                    select(AgentWorker).where(
                        AgentWorker.agent_id == agent_id,
                        AgentWorker.worker_id.is_(None),
                    ),
                )
            ).scalars(),
        )
    assert len(rows) == 1
    assert rows[0].pid in range(20_000, 20_008)


async def test_postgres_upgrade_deduplicates_existing_legacy_slots(
    integration_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    await _upgrade_integration_database(
        integration_settings,
        "v1_9_schedule_control_columns",
    )
    project_id, agent_id = await _seed_historical_agent(
        integration_engine,
        name="legacy-upgrade",
    )
    sessions = async_sessionmaker(integration_engine, expire_on_commit=False)

    # Current consolidated metadata creates the index even when Alembic stops
    # at an older revision. Remove it to reproduce an actual prior-release
    # database, whose metadata did not yet declare the index.
    async with integration_engine.begin() as connection:
        await connection.execute(text("DROP INDEX IF EXISTS ux_agent_workers_legacy_agent"))

    async with sessions() as session:
        session.add_all(
            [
                AgentWorker(
                    agent_id=agent_id,
                    project_id=project_id,
                    worker_id=None,
                    role="older",
                    pid=1,
                ),
                AgentWorker(
                    agent_id=agent_id,
                    project_id=project_id,
                    worker_id=None,
                    role="newer",
                    pid=2,
                ),
            ],
        )
        await session.flush()
        rows = list(
            (
                await session.execute(
                    select(AgentWorker)
                    .where(
                        AgentWorker.agent_id == agent_id,
                        AgentWorker.worker_id.is_(None),
                    )
                    .order_by(AgentWorker.created_at),
                )
            ).scalars(),
        )
        assert len(rows) == 2
        # Make the survivor deterministic rather than relying on statement
        # insertion order or equal server-default timestamps.
        rows[0].last_connect_at = rows[0].created_at
        rows[1].last_connect_at = rows[1].created_at + timedelta(seconds=1)
        await session.commit()

    await _upgrade_integration_database(integration_settings, "head")

    async with sessions() as session:
        rows = list(
            (
                await session.execute(
                    select(AgentWorker).where(
                        AgentWorker.agent_id == agent_id,
                        AgentWorker.worker_id.is_(None),
                    ),
                )
            ).scalars(),
        )
    assert len(rows) == 1
    assert rows[0].role == "newer"
