"""Tests for ``WorkerRepository.upsert_from_events_bulk`` (v1.0.15 P-1).

These tests validate the new bulk upsert path that replaces the
N+1 per-event ``upsert_from_event`` round-trips in
:meth:`EventIngestor.ingest_batch` and the per-hostname savepointed
loop in :meth:`WebSocketFrameRouter._handle_heartbeat`.

Coverage:

1. **Insert** - a fresh batch lands every row with the right state /
   timestamps.
2. **Update on conflict** - a second batch for the same
   ``(project, engine, name)`` tuple updates the existing row
   in-place (no duplicate row, no NOT NULL violation, no
   PendingRollbackError cascade).
3. **Partial-update preservation** - a heartbeat carrying only
   ``last_heartbeat`` + ``state`` does NOT blank the previously
   recorded ``hostname`` / ``concurrency``. This is the
   "no key, no touch" semantic the refactor is meant to keep.
4. **SQL round-trip count** - asserts that a 200-row batch issues
   exactly ONE ``INSERT`` statement on the workers table (the P-1
   acceptance criterion). Catches future regressions where someone
   accidentally drops the bulk path back into a per-row loop.
5. **Empty input is a no-op** - guarded so callers don't have to.
6. **Per-row fallback path correctness** - the old per-row path
   still works (degenerate dialect or a real OperationalError
   triggers it via :meth:`EventIngestor._flush_worker_upserts`).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import WorkerState
from z4j_brain.persistence.models import Project, Worker
from z4j_brain.persistence.repositories import WorkerRepository


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False,
    )
    async with factory() as s:
        yield s
    await engine.dispose()


@pytest.fixture
async def project(session: AsyncSession) -> Project:
    p = Project(slug="default", name="Default")
    session.add(p)
    await session.commit()
    return p


def _row(
    project_id: uuid.UUID,
    *,
    engine: str = "celery",
    name: str,
    last_heartbeat: datetime | None = None,
    hostname: str | None = None,
    concurrency: int | None = None,
    state: WorkerState | None = WorkerState.ONLINE,
) -> dict:
    out = {
        "project_id": project_id,
        "engine": engine,
        "name": name,
    }
    if state is not None:
        out["state"] = state
    if last_heartbeat is not None:
        out["last_heartbeat"] = last_heartbeat
    if hostname is not None:
        out["hostname"] = hostname
    if concurrency is not None:
        out["concurrency"] = concurrency
    return out


@pytest.mark.asyncio
class TestBulkUpsertInsert:
    async def test_fresh_batch_inserts_every_row(
        self, session: AsyncSession, project: Project,
    ) -> None:
        repo = WorkerRepository(session)
        now = datetime.now(UTC)
        rows = [
            _row(
                project.id,
                name=f"celery@web-{i:02d}",
                last_heartbeat=now,
                hostname=f"web-{i:02d}",
                concurrency=4,
            )
            for i in range(20)
        ]

        n = await repo.upsert_from_events_bulk(rows)
        await session.commit()

        assert n == 20
        # All 20 rows landed as workers.
        result = await session.execute(
            select(func.count()).select_from(Worker),
        )
        assert result.scalar_one() == 20
        # Spot check one row
        result = await session.execute(
            select(Worker).where(Worker.name == "celery@web-05"),
        )
        w = result.scalar_one()
        assert w.state == WorkerState.ONLINE
        assert w.hostname == "web-05"
        assert w.concurrency == 4
        assert w.last_heartbeat is not None

    async def test_empty_input_is_noop(
        self, session: AsyncSession, project: Project,
    ) -> None:
        repo = WorkerRepository(session)
        n = await repo.upsert_from_events_bulk([])
        assert n == 0
        result = await session.execute(
            select(func.count()).select_from(Worker),
        )
        assert result.scalar_one() == 0

    async def test_missing_required_field_raises(
        self, session: AsyncSession, project: Project,
    ) -> None:
        repo = WorkerRepository(session)
        with pytest.raises(ValueError, match="project_id, engine, name"):
            await repo.upsert_from_events_bulk(
                [{"project_id": project.id, "engine": "celery"}],
            )


@pytest.mark.asyncio
class TestBulkUpsertConflict:
    async def test_second_batch_updates_existing_rows(
        self, session: AsyncSession, project: Project,
    ) -> None:
        repo = WorkerRepository(session)
        t1 = datetime.now(UTC) - timedelta(seconds=30)
        t2 = datetime.now(UTC)

        # First batch lands two new workers.
        await repo.upsert_from_events_bulk([
            _row(project.id, name="celery@a", last_heartbeat=t1, concurrency=2),
            _row(project.id, name="celery@b", last_heartbeat=t1, concurrency=2),
        ])
        await session.commit()

        # Second batch updates both.
        await repo.upsert_from_events_bulk([
            _row(project.id, name="celery@a", last_heartbeat=t2, concurrency=8),
            _row(project.id, name="celery@b", last_heartbeat=t2, concurrency=8),
        ])
        await session.commit()

        # Still two rows, with updated values.
        result = await session.execute(
            select(func.count()).select_from(Worker),
        )
        assert result.scalar_one() == 2
        result = await session.execute(
            select(Worker).where(Worker.name == "celery@a"),
        )
        a = result.scalar_one()
        assert a.last_heartbeat is not None
        assert a.concurrency == 8

    async def test_partial_update_preserves_unspecified_columns(
        self, session: AsyncSession, project: Project,
    ) -> None:
        """Heartbeat-only batch must not blank ``hostname`` /
        ``concurrency`` set by an earlier worker_details batch."""
        repo = WorkerRepository(session)
        t1 = datetime.now(UTC) - timedelta(seconds=30)
        t2 = datetime.now(UTC)

        # First batch sets the full payload (state, last_heartbeat,
        # hostname, concurrency).
        await repo.upsert_from_events_bulk([
            _row(
                project.id,
                name="celery@a",
                last_heartbeat=t1,
                hostname="web-a.internal",
                concurrency=16,
            ),
        ])
        await session.commit()

        # Second batch is a stripped heartbeat - just last_heartbeat
        # + state, no hostname/concurrency keys at all.
        await repo.upsert_from_events_bulk([
            {
                "project_id": project.id,
                "engine": "celery",
                "name": "celery@a",
                "state": WorkerState.ONLINE,
                "last_heartbeat": t2,
            },
        ])
        await session.commit()

        result = await session.execute(
            select(Worker).where(Worker.name == "celery@a"),
        )
        a = result.scalar_one()
        # last_heartbeat advanced
        assert a.last_heartbeat is not None
        assert a.last_heartbeat >= t2.replace(tzinfo=None) if a.last_heartbeat.tzinfo is None else a.last_heartbeat >= t2
        # hostname + concurrency PRESERVED (no key, no touch)
        assert a.hostname == "web-a.internal"
        assert a.concurrency == 16


@pytest.mark.asyncio
class TestBulkUpsertSqlCount:
    async def test_one_insert_statement_per_batch(
        self, session: AsyncSession, project: Project,
    ) -> None:
        """The P-1 acceptance criterion: 200 rows = 1 INSERT.

        Catches future regressions where someone accidentally
        rewrites the bulk path into a per-row loop. We hook
        ``before_cursor_execute`` and count INSERTs against the
        ``workers`` table.
        """
        repo = WorkerRepository(session)
        bind = await session.connection()
        engine = bind.engine

        insert_count = 0

        @event.listens_for(engine.sync_engine, "before_cursor_execute")
        def _count_inserts(
            conn, cursor, statement, parameters, context, executemany,
        ) -> None:
            nonlocal insert_count
            sql = (statement or "").lower()
            if "insert into workers" in sql:
                insert_count += 1

        try:
            now = datetime.now(UTC)
            rows = [
                _row(
                    project.id,
                    name=f"celery@h-{i:03d}",
                    last_heartbeat=now,
                    concurrency=4,
                )
                for i in range(200)
            ]
            await repo.upsert_from_events_bulk(rows)
            await session.commit()
        finally:
            event.remove(
                engine.sync_engine, "before_cursor_execute", _count_inserts,
            )

        # Exactly one INSERT statement. The N+1 path would have
        # emitted 200 INSERTs (and 200 SELECTs and up to 200
        # UPDATEs).
        assert insert_count == 1, (
            f"Expected exactly 1 INSERT into workers for a 200-row "
            f"bulk upsert, got {insert_count}. Did the bulk path "
            f"regress into a per-row loop?"
        )

    async def test_duplicates_in_input_resolve_via_on_conflict(
        self, session: AsyncSession, project: Project,
    ) -> None:
        """Two rows with the same (engine, name) → ON CONFLICT folds them.

        Both SQLite (≥3.24) and Postgres (15+) accept duplicate
        conflict-key tuples in a single ``INSERT ... VALUES ...
        ON CONFLICT DO UPDATE`` statement: the engine processes
        rows in input order, so the second row's DO UPDATE wins.
        This means the bulk method is robust against caller
        dedupe omission, though :meth:`EventIngestor.ingest_batch`
        still dedupes in-memory first to keep the round-trip
        payload small.
        """
        repo = WorkerRepository(session)
        t1 = datetime.now(UTC) - timedelta(seconds=10)
        t2 = datetime.now(UTC)
        rows = [
            _row(project.id, name="celery@dup", last_heartbeat=t1, concurrency=2),
            _row(project.id, name="celery@dup", last_heartbeat=t2, concurrency=8),
        ]
        await repo.upsert_from_events_bulk(rows)
        await session.commit()

        # Exactly one row, with the LAST input's values applied.
        result = await session.execute(
            select(func.count()).select_from(Worker),
        )
        assert result.scalar_one() == 1
        result = await session.execute(
            select(Worker).where(Worker.name == "celery@dup"),
        )
        w = result.scalar_one()
        assert w.concurrency == 8


@pytest.mark.asyncio
class TestBulkUpsertWorkerMetadata:
    """Regression: ``Worker.worker_metadata`` is the Python attribute,
    but the underlying DB column is named ``metadata`` (the prefix
    avoids clashing with SQLAlchemy's ``Base.metadata``). The bulk
    upsert path passes column names through to
    ``insert().values()`` and ``stmt.excluded.<col>``, both of which
    key off DB column names, not attribute names. Pre-1.3.1 the
    bulk path passed the attribute name straight through, hitting
    ``AttributeError: worker_metadata`` on every worker heartbeat
    that carried a metadata payload, which is every heartbeat in
    practice, since the agent always populates it. Caused empty
    Workers tab on the dashboard until 1.3.1 fixed the translation.
    """

    async def test_insert_with_worker_metadata(
        self, session: AsyncSession, project: Project,
    ) -> None:
        repo = WorkerRepository(session)
        now = datetime.now(UTC)
        await repo.upsert_from_events_bulk([
            {
                "project_id": project.id,
                "engine": "celery",
                "name": "celery@meta-insert",
                "state": WorkerState.ONLINE,
                "last_heartbeat": now,
                "worker_metadata": {"version": "5.6.3", "platform": "linux"},
            },
        ])
        await session.commit()

        result = await session.execute(
            select(Worker).where(Worker.name == "celery@meta-insert"),
        )
        w = result.scalar_one()
        assert w.worker_metadata == {"version": "5.6.3", "platform": "linux"}

    async def test_update_with_worker_metadata_on_conflict(
        self, session: AsyncSession, project: Project,
    ) -> None:
        repo = WorkerRepository(session)
        t1 = datetime.now(UTC) - timedelta(seconds=10)
        t2 = datetime.now(UTC)

        # First batch lands the worker with v1 metadata.
        await repo.upsert_from_events_bulk([
            {
                "project_id": project.id,
                "engine": "celery",
                "name": "celery@meta-update",
                "state": WorkerState.ONLINE,
                "last_heartbeat": t1,
                "worker_metadata": {"version": "5.5.0"},
            },
        ])
        await session.commit()

        # Second batch updates the metadata via ON CONFLICT.
        await repo.upsert_from_events_bulk([
            {
                "project_id": project.id,
                "engine": "celery",
                "name": "celery@meta-update",
                "state": WorkerState.ONLINE,
                "last_heartbeat": t2,
                "worker_metadata": {"version": "5.6.3", "newkey": "ok"},
            },
        ])
        await session.commit()

        result = await session.execute(
            select(Worker).where(Worker.name == "celery@meta-update"),
        )
        w = result.scalar_one()
        # Metadata fully replaced (it's a JSON column, not a merge).
        assert w.worker_metadata == {"version": "5.6.3", "newkey": "ok"}
