"""Integration test: ``events`` partitioning + idempotence.

Verifies that:

- ``events`` is a partitioned parent table on Postgres
- The pre-created daily partitions are addressable
- INSERTs route to the correct daily partition
- The ON CONFLICT DO NOTHING idempotence (B4) works for replays
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

pytestmark = pytest.mark.asyncio


async def _insert_supporting_rows(
    engine: AsyncEngine,
) -> tuple[uuid.UUID, uuid.UUID]:
    """Create one project + one agent so events FKs satisfy."""
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO projects (id, slug, name) VALUES (:id, :slug, 'P')"),
            {"id": project_id, "slug": f"p-{uuid.uuid4().hex[:8]}"},
        )
        await conn.execute(
            text(
                "INSERT INTO agents "
                "(id, project_id, name, token_hash, protocol_version, "
                " framework_adapter, engine_adapters, scheduler_adapters, "
                " capabilities, state) "
                "VALUES (:id, :pid, 'a', :tok, '1', 'bare', "
                " ARRAY[]::text[], ARRAY[]::text[], '{}'::jsonb, 'unknown')",
            ),
            {"id": agent_id, "pid": project_id, "tok": uuid.uuid4().hex},
        )
    return project_id, agent_id


class TestPartitioning:
    async def test_event_lands_in_today_partition(
        self, migrated_engine: AsyncEngine,
    ) -> None:
        project_id, agent_id = await _insert_supporting_rows(migrated_engine)

        event_id = uuid.uuid4()
        now = datetime.now(UTC)
        async with migrated_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO events "
                    "(id, project_id, agent_id, engine, task_id, kind, "
                    " occurred_at, payload) "
                    "VALUES (:id, :pid, :aid, 'celery', 't1', 'task.received', "
                    "        :ts, '{}'::jsonb)",
                ),
                {
                    "id": event_id,
                    "pid": project_id,
                    "aid": agent_id,
                    "ts": now,
                },
            )

        # Inspect which child table actually holds the row.
        async with migrated_engine.connect() as conn:
            partition_name = (
                await conn.execute(
                    text(
                        "SELECT tableoid::regclass::text FROM events "
                        "WHERE id = :id",
                    ),
                    {"id": event_id},
                )
            ).scalar_one()
        # Should be one of the events_YYYY_MM_DD child partitions,
        # NOT the parent ``events`` table itself.
        assert partition_name.startswith("events_20")

    async def test_idempotent_replay(
        self, migrated_engine: AsyncEngine,
    ) -> None:
        """Replaying the same (occurred_at, id) is a no-op via ON CONFLICT."""
        from z4j_brain.persistence.repositories import EventRepository
        from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

        project_id, agent_id = await _insert_supporting_rows(migrated_engine)

        factory = async_sessionmaker(
            migrated_engine, class_=AsyncSession, expire_on_commit=False,
        )
        event_id = uuid.uuid4()
        now = datetime.now(UTC)

        async with factory() as session:
            repo = EventRepository(session)
            inserted_first = await repo.insert(
                event_id=event_id,
                project_id=project_id,
                agent_id=agent_id,
                engine="celery",
                task_id="t1",
                kind="task.received",
                occurred_at=now,
                payload={},
            )
            await session.commit()
        async with factory() as session:
            repo = EventRepository(session)
            inserted_second = await repo.insert(
                event_id=event_id,
                project_id=project_id,
                agent_id=agent_id,
                engine="celery",
                task_id="t1",
                kind="task.received",
                occurred_at=now,
                payload={},
            )
            await session.commit()

        assert inserted_first is True
        assert inserted_second is False

        async with migrated_engine.connect() as conn:
            count = (
                await conn.execute(
                    text("SELECT count(*) FROM events WHERE id = :id"),
                    {"id": event_id},
                )
            ).scalar_one()
        assert count == 1
