"""Initial command-dispatch timeout semantics on real PostgreSQL."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models import Agent, Project
from z4j_brain.persistence.repositories import CommandRepository

pytestmark = pytest.mark.asyncio


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


async def test_initial_dispatch_refreshes_timeout_on_postgres(
    migrated_engine: AsyncEngine,
) -> None:
    """A late first claim receives its full response window on PostgreSQL."""
    sessions = async_sessionmaker(
        migrated_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with sessions() as session:
        project = Project(
            id=uuid.uuid4(),
            slug=f"dispatch-timeout-{uuid.uuid4().hex[:8]}",
            name="Dispatch timeout",
        )
        session.add(project)
        await session.flush()
        agent = Agent(
            id=uuid.uuid4(),
            project_id=project.id,
            name="dispatch-timeout-agent",
            token_hash=secrets.token_hex(32),
            protocol_version="2",
            framework_adapter="bare",
            engine_adapters=["celery"],
            scheduler_adapters=[],
            capabilities={},
            state=AgentState.ONLINE,
        )
        session.add(agent)
        await session.flush()

        commands = CommandRepository(session)
        issuance_deadline = datetime.now(UTC) - timedelta(seconds=1)
        command, _ = await commands.insert(
            project_id=project.id,
            agent_id=agent.id,
            issued_by=None,
            action="retry_task",
            target_type="task",
            target_id="task-1",
            payload={},
            idempotency_key=None,
            timeout_at=issuance_deadline,
            source_ip=None,
        )
        generation = await commands.mark_dispatched(
            command.id,
            timeout_seconds=60,
        )
        assert generation is not None
        await session.commit()

    expected_deadline = generation + timedelta(seconds=60)
    async with migrated_engine.connect() as connection:
        row = (
            await connection.execute(
                text(
                    "SELECT status, dispatched_at, timeout_at FROM commands WHERE id = :command_id"
                ),
                {"command_id": command.id},
            )
        ).one()

    # Read through independent SQL rather than the ORM identity map that wrote
    # the row: both timestamps must come from the one guarded PostgreSQL UPDATE.
    assert row.status == "dispatched"
    assert _as_utc(row.dispatched_at) == generation
    assert _as_utc(row.timeout_at) == expected_deadline
    assert _as_utc(row.timeout_at) > issuance_deadline

    async with sessions() as session:
        assert (
            await CommandRepository(session).sweep_timeouts(
                now=generation + timedelta(seconds=10),
            )
            == 0
        )
        await session.commit()

    async with migrated_engine.connect() as connection:
        status_before_deadline = await connection.scalar(
            text("SELECT status FROM commands WHERE id = :command_id"),
            {"command_id": command.id},
        )
    assert status_before_deadline == "dispatched"

    async with sessions() as session:
        assert (
            await CommandRepository(session).sweep_timeouts(
                now=expected_deadline + timedelta(microseconds=1),
            )
            == 1
        )
        await session.commit()

    async with migrated_engine.connect() as connection:
        status_after_deadline = await connection.scalar(
            text("SELECT status FROM commands WHERE id = :command_id"),
            {"command_id": command.id},
        )
    assert status_after_deadline == "timeout"
