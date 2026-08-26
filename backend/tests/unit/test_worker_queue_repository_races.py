"""Concurrency contracts for worker liveness and queue discovery writes."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import bindparam, case, func, select, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import WorkerState
from z4j_brain.persistence.models import Project, Queue, Worker
from z4j_brain.persistence.repositories import QueueRepository, WorkerRepository
from z4j_brain.persistence.repositories.queues import (
    _queue_depth_upsert_statement,
    _queue_touch_upsert_statement,
)
from z4j_brain.persistence.repositories.workers import (
    _heartbeat_is_not_stale,
    _monotonic_heartbeat_value,
)


@pytest.fixture
async def repository_db(
    tmp_path: Path,
) -> AsyncIterator[tuple[async_sessionmaker[AsyncSession], uuid.UUID]]:
    """A file DB gives the two sessions distinct SQLite connections."""
    path = tmp_path / "repository-races.sqlite3"
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{path}",
        connect_args={"timeout": 10},
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(
        engine,
        expire_on_commit=False,
    )
    async with factory() as session:
        project = Project(slug="race-project", name="Race project")
        session.add(project)
        await session.commit()
        project_id = project.id
    yield factory, project_id
    await engine.dispose()


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


async def _seed_worker(
    factory: async_sessionmaker[AsyncSession],
    project_id: uuid.UUID,
    *,
    heartbeat: datetime,
) -> None:
    async with factory() as session:
        await WorkerRepository(session).upsert_from_event(
            project_id=project_id,
            engine="celery",
            name="celery@race",
            updates={
                "state": WorkerState.OFFLINE,
                "last_heartbeat": heartbeat,
            },
        )
        await session.commit()


async def _read_worker(
    factory: async_sessionmaker[AsyncSession],
) -> Worker:
    async with factory() as session:
        return (
            await session.execute(
                select(Worker).where(Worker.name == "celery@race"),
            )
        ).scalar_one()


@pytest.mark.asyncio
async def test_per_row_stale_identity_map_cannot_rewind_liveness(
    repository_db: tuple[async_sessionmaker[AsyncSession], uuid.UUID],
) -> None:
    """The UPDATE must not trust the stale object returned by its SELECT."""
    factory, project_id = repository_db
    initial = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
    fresh = initial + timedelta(minutes=2)
    stale = initial + timedelta(minutes=1)
    await _seed_worker(factory, project_id, heartbeat=initial)

    async with factory() as stale_session, factory() as fresh_session:
        # Keep an old ORM object in stale_session's identity map while ending
        # its read transaction so SQLite can deterministically commit the fresh
        # writer. The repository's next SELECT returns this same stale object.
        cached = (
            await stale_session.execute(
                select(Worker).where(Worker.name == "celery@race"),
            )
        ).scalar_one()
        assert _utc(cached.last_heartbeat) == initial
        await stale_session.commit()

        await WorkerRepository(fresh_session).upsert_from_event(
            project_id=project_id,
            engine="celery",
            name="celery@race",
            updates={
                "state": WorkerState.DRAINING,
                "last_heartbeat": fresh,
            },
        )
        await fresh_session.commit()

        returned = await WorkerRepository(stale_session).upsert_from_event(
            project_id=project_id,
            engine="celery",
            name="celery@race",
            updates={
                "state": WorkerState.ONLINE,
                "last_heartbeat": stale,
            },
        )
        await stale_session.commit()

    assert _utc(returned.last_heartbeat) == fresh
    assert returned.state == WorkerState.DRAINING
    persisted = await _read_worker(factory)
    assert _utc(persisted.last_heartbeat) == fresh
    assert persisted.state == WorkerState.DRAINING


@pytest.mark.asyncio
@pytest.mark.parametrize("write_path", ["bulk", "touch"])
async def test_atomic_worker_paths_recheck_after_waiting_for_fresh_writer(
    repository_db: tuple[async_sessionmaker[AsyncSession], uuid.UUID],
    write_path: str,
) -> None:
    """A blocked stale SQL statement rechecks the row after lock acquisition."""
    factory, project_id = repository_db
    initial = datetime(2026, 8, 12, 13, 0, tzinfo=UTC)
    fresh = initial + timedelta(minutes=2)
    stale = initial + timedelta(minutes=1)
    await _seed_worker(factory, project_id, heartbeat=initial)

    async with factory() as fresh_session, factory() as stale_session:
        if write_path == "bulk":
            await WorkerRepository(fresh_session).upsert_from_events_bulk(
                [
                    {
                        "project_id": project_id,
                        "engine": "celery",
                        "name": "celery@race",
                        "state": WorkerState.DRAINING,
                        "last_heartbeat": fresh,
                    },
                ],
            )
        else:
            # Model the newer lifecycle decision that the stale touch must not
            # replace with ONLINE while keeping its older timestamp out.
            await fresh_session.execute(
                update(Worker)
                .where(Worker.name == "celery@race")
                .values(
                    state=WorkerState.DRAINING,
                    last_heartbeat=fresh,
                ),
            )
        await fresh_session.flush()

        started = asyncio.Event()

        async def stale_write() -> None:
            started.set()
            repository = WorkerRepository(stale_session)
            if write_path == "bulk":
                await repository.upsert_from_events_bulk(
                    [
                        {
                            "project_id": project_id,
                            "engine": "celery",
                            "name": "celery@race",
                            "state": WorkerState.ONLINE,
                            "last_heartbeat": stale,
                        },
                    ],
                )
            else:
                await repository.touch_heartbeat(
                    project_id=project_id,
                    engine="celery",
                    name="celery@race",
                    when=stale,
                )
            await stale_session.commit()

        stale_task = asyncio.create_task(stale_write())
        await started.wait()
        await fresh_session.commit()
        await asyncio.wait_for(stale_task, timeout=10)

    persisted = await _read_worker(factory)
    assert _utc(persisted.last_heartbeat) == fresh
    assert persisted.state == WorkerState.DRAINING


@pytest.mark.asyncio
async def test_folded_duplicate_keeps_state_from_newest_heartbeat(
    repository_db: tuple[async_sessionmaker[AsyncSession], uuid.UUID],
) -> None:
    factory, project_id = repository_db
    fresh = datetime(2026, 8, 12, 14, 2, tzinfo=UTC)
    stale = fresh - timedelta(minutes=1)
    async with factory() as session:
        await WorkerRepository(session).upsert_from_events_bulk(
            [
                {
                    "project_id": project_id,
                    "engine": "celery",
                    "name": "celery@race",
                    "state": WorkerState.DRAINING,
                    "last_heartbeat": fresh,
                },
                {
                    "project_id": project_id,
                    "engine": "celery",
                    "name": "celery@race",
                    "state": WorkerState.ONLINE,
                    "last_heartbeat": stale,
                },
            ],
        )
        await session.commit()

    persisted = await _read_worker(factory)
    assert _utc(persisted.last_heartbeat) == fresh
    assert persisted.state == WorkerState.DRAINING


def test_worker_liveness_expressions_compile_for_postgresql() -> None:
    """All worker paths share SQL expressions PostgreSQL can evaluate atomically."""
    incoming = bindparam(
        "incoming_heartbeat",
        type_=Worker.__table__.c.last_heartbeat.type,
    )
    statement = update(Worker).values(
        last_heartbeat=_monotonic_heartbeat_value(incoming),
        state=case(
            (
                _heartbeat_is_not_stale(incoming),
                WorkerState.ONLINE,
            ),
            else_=Worker.state,
        ),
    )
    sql = str(statement.compile(dialect=postgresql.dialect()))
    assert "workers.last_heartbeat < %(incoming_heartbeat)s" in sql
    assert "workers.last_heartbeat <= %(incoming_heartbeat)s" in sql
    assert "ELSE workers.last_heartbeat" in sql
    assert "ELSE workers.state" in sql


@pytest.mark.asyncio
async def test_queue_depth_two_session_first_observation_is_one_atomic_upsert(
    repository_db: tuple[async_sessionmaker[AsyncSession], uuid.UUID],
) -> None:
    """The second first-observation cannot abort its surrounding transaction."""
    factory, project_id = repository_db
    first_observed = datetime(2026, 8, 12, 15, 0, tzinfo=UTC)
    second_observed = first_observed + timedelta(seconds=1)
    async with factory() as first_session, factory() as second_session:
        await QueueRepository(first_session).update_depth(
            project_id=project_id,
            engine="celery",
            name="critical",
            pending_count=11,
            observed_at=first_observed,
        )
        await first_session.flush()

        started = asyncio.Event()

        async def competing_observation() -> None:
            started.set()
            await QueueRepository(second_session).update_depth(
                project_id=project_id,
                engine="celery",
                name="critical",
                pending_count=29,
                observed_at=second_observed,
            )
            # Work after the conflict proves the caller-owned transaction was
            # not poisoned by a duplicate-insert rollback.
            second_session.add(
                Queue(
                    project_id=project_id,
                    engine="celery",
                    name="outer-work-survived",
                    pending_count=1,
                    last_seen_at=datetime.now(UTC),
                ),
            )
            await second_session.commit()

        second_task = asyncio.create_task(competing_observation())
        await started.wait()
        await first_session.commit()
        await asyncio.wait_for(second_task, timeout=10)

    async with factory() as verify:
        critical = (
            await verify.execute(
                select(Queue).where(Queue.name == "critical"),
            )
        ).scalar_one()
        count = await verify.scalar(
            select(func.count()).select_from(Queue),
        )
    assert critical.pending_count == 29
    assert critical.last_seen_at is not None
    assert _utc(critical.last_seen_at) == second_observed
    assert count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("observation_delta", [timedelta(seconds=-1), timedelta(0)])
async def test_queue_depth_delayed_older_or_tied_observation_is_a_noop(
    repository_db: tuple[async_sessionmaker[AsyncSession], uuid.UUID],
    observation_delta: timedelta,
) -> None:
    """Source time, not transaction scheduling, orders queue snapshots.

    Strict-newer ordering also defines the tie policy: the existing observation
    wins when two reporters carry the exact same source timestamp.
    """
    factory, project_id = repository_db
    fresh_observed = datetime(2026, 8, 12, 15, 30, tzinfo=UTC)
    delayed_observed = fresh_observed + observation_delta

    async with factory() as delayed_session, factory() as fresh_session:
        # Begin the delayed session before the fresh write, then end its empty
        # read transaction. Its already-captured source observation lands only
        # after the other session commits.
        missing = await delayed_session.scalar(
            select(Queue).where(Queue.name == "critical"),
        )
        assert missing is None
        await delayed_session.commit()

        await QueueRepository(fresh_session).update_depth(
            project_id=project_id,
            engine="celery",
            name="critical",
            pending_count=29,
            observed_at=fresh_observed,
        )
        await fresh_session.commit()

        await QueueRepository(delayed_session).update_depth(
            project_id=project_id,
            engine="celery",
            name="critical",
            pending_count=11,
            observed_at=delayed_observed,
        )
        await delayed_session.commit()

    async with factory() as verify:
        persisted = (
            await verify.execute(
                select(Queue).where(Queue.name == "critical"),
            )
        ).scalar_one()
    assert persisted.pending_count == 29
    assert persisted.last_seen_at is not None
    assert _utc(persisted.last_seen_at) == fresh_observed


@pytest.mark.asyncio
async def test_queue_touch_and_depth_share_one_source_time_order(
    repository_db: tuple[async_sessionmaker[AsyncSession], uuid.UUID],
) -> None:
    """A later queue touch preserves depth and outranks delayed snapshots."""
    factory, project_id = repository_db
    depth_observed = datetime(2026, 8, 12, 16, 0, tzinfo=UTC)
    touch_observed = depth_observed + timedelta(seconds=2)

    async with factory() as session:
        repository = QueueRepository(session)
        await repository.update_depth(
            project_id=project_id,
            engine="celery",
            name="critical",
            pending_count=29,
            observed_at=depth_observed,
        )
        await repository.touch(
            project_id=project_id,
            engine="celery",
            name="critical",
            observed_at=touch_observed,
        )
        # An older depth statement arriving after the newer observation must
        # not rewind either the queue's freshness or its stored snapshot.
        await repository.update_depth(
            project_id=project_id,
            engine="celery",
            name="critical",
            pending_count=11,
            observed_at=depth_observed + timedelta(seconds=1),
        )
        await session.commit()

    async with factory() as verify:
        persisted = (
            await verify.execute(
                select(Queue).where(Queue.name == "critical"),
            )
        ).scalar_one()
    assert persisted.pending_count == 29
    assert persisted.last_seen_at is not None
    assert _utc(persisted.last_seen_at) == touch_observed


def test_queue_depth_upsert_compiles_for_postgresql() -> None:
    statement = _queue_depth_upsert_statement(
        pg_insert,
        project_id=uuid.uuid4(),
        engine="celery",
        name="critical",
        pending_count=7,
        observed_at=datetime(2026, 8, 12, 15, 0, tzinfo=UTC),
    )
    sql = str(statement.compile(dialect=postgresql.dialect()))
    assert "ON CONFLICT (project_id, engine, name) DO UPDATE" in sql
    assert "pending_count = excluded.pending_count" in sql
    assert "last_seen_at = excluded.last_seen_at" in sql
    assert (
        "WHERE queues.last_seen_at IS NULL OR queues.last_seen_at < excluded.last_seen_at"
    ) in sql


def test_queue_touch_upsert_compiles_for_postgresql() -> None:
    statement = _queue_touch_upsert_statement(
        pg_insert,
        project_id=uuid.uuid4(),
        engine="celery",
        name="critical",
        observed_at=datetime(2026, 8, 12, 16, 30, tzinfo=UTC),
    )
    sql = str(statement.compile(dialect=postgresql.dialect()))
    assert "ON CONFLICT (project_id, engine, name) DO UPDATE" in sql
    assert "last_seen_at = excluded.last_seen_at" in sql
    assert "pending_count = excluded.pending_count" not in sql
    assert (
        "WHERE queues.last_seen_at IS NULL OR queues.last_seen_at < excluded.last_seen_at"
    ) in sql
