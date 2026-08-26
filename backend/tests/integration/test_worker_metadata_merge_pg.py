"""The worker-metadata merge, on the engine production runs on.

The unit suite drives the same cases against SQLite. That was the gap: the
merge was expressed once per dialect, PostgreSQL's ``jsonb ||`` replacing a
nested object where SQLite's ``json_patch`` merged it, and every test in the
repository ran on the engine that happened to behave. This file exists so that
the two can never again be asserted separately -- the case table is imported,
not copied, so an expectation cannot be adjusted on one side alone.

Also covers what SQLite cannot show at all: on PostgreSQL a report that lands
as a JSON null in a nested document, or a document merged onto a column with a
NOT NULL constraint, is decided by real jsonb semantics rather than by SQLite's
lenient typing.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from z4j_brain.persistence.enums import WorkerState
from z4j_brain.persistence.models import Project, Worker
from z4j_brain.persistence.repositories import WorkerRepository

from tests.worker_metadata_cases import MERGE_CASES, WRITE_PATHS

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def pg_session(migrated_engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    sessions = async_sessionmaker(migrated_engine, expire_on_commit=False)
    async with sessions() as session:
        yield session


@pytest.fixture
async def pg_project(pg_session: AsyncSession) -> Project:
    project = Project(
        id=uuid.uuid4(),
        slug=f"merge-{uuid.uuid4().hex[:8]}",
        name="metadata merge",
    )
    pg_session.add(project)
    await pg_session.commit()
    return project


@pytest.mark.parametrize(("documents", "expected"), MERGE_CASES)
@pytest.mark.parametrize("write", WRITE_PATHS)
async def test_metadata_merge_case_on_postgres(
    pg_session: AsyncSession,
    pg_project: Project,
    write,
    documents,
    expected,
) -> None:
    stored = await write(pg_session, pg_project.id, "celery@merge", documents)
    assert stored == expected


async def test_a_duplicate_conflict_key_in_one_batch_is_folded_not_refused(
    pg_session: AsyncSession,
    pg_project: Project,
) -> None:
    """The divergence SQLite structurally cannot show.

    SQLite applies ``DO UPDATE`` twice when one statement proposes the same
    conflict key twice. PostgreSQL refuses the statement outright, so a batch
    that a contributor watched fold correctly takes the whole heartbeat down
    in production. Both entries have to survive, on the engine that runs it.
    """
    repo = WorkerRepository(pg_session)
    earlier = datetime.now(UTC) - timedelta(seconds=10)
    later = datetime.now(UTC)
    await repo.upsert_from_events_bulk(
        [
            {
                "project_id": pg_project.id,
                "engine": "celery",
                "name": "celery@dup",
                "state": WorkerState.ONLINE,
                "last_heartbeat": earlier,
                "concurrency": 2,
                "worker_metadata": {"conf": {"timezone": "UTC"}},
            },
            {
                "project_id": pg_project.id,
                "engine": "celery",
                "name": "celery@dup",
                "state": WorkerState.ONLINE,
                "last_heartbeat": later,
                "concurrency": 8,
                "worker_metadata": {"stats": {"clock": 3}},
            },
        ],
    )
    await pg_session.commit()

    total = (await pg_session.execute(select(func.count()).select_from(Worker))).scalar_one()
    assert total == 1
    worker = (
        await pg_session.execute(
            select(Worker).where(Worker.name == "celery@dup"),
        )
    ).scalar_one()
    assert worker.concurrency == 8
    assert worker.worker_metadata == {
        "conf": {"timezone": "UTC"},
        "stats": {"clock": 3},
    }


async def test_two_transactions_observing_one_worker_first_keep_both_reports(
    migrated_engine: AsyncEngine,
    pg_project: Project,
) -> None:
    """The first observation of a worker is the one race a row lock cannot hold.

    Every other concurrent heartbeat for the same worker is serialised by
    locking the stored row before the merged document is computed from it.
    That leaves exactly one hole: a worker nobody has recorded yet has no row
    to lock, so two agents describing it in the same instant both resolve
    against an empty document, and whichever commits second writes the other's
    report away. A fleet coming up is when that happens, and the report lost
    is the one the dashboard needs to say anything about the worker at all.

    The two transactions are interleaved rather than merely started together:
    the first is held open until the second has demonstrably blocked, which is
    the ordering that produces the loss.
    """
    sessions = async_sessionmaker(migrated_engine, expire_on_commit=False)
    name = f"celery@first-{uuid.uuid4().hex[:8]}"
    now = datetime.now(UTC)

    def _row(document: dict) -> list[dict]:
        return [
            {
                "project_id": pg_project.id,
                "engine": "celery",
                "name": name,
                "state": WorkerState.ONLINE,
                "last_heartbeat": now,
                "worker_metadata": document,
            },
        ]

    async with sessions() as first, sessions() as second:
        await WorkerRepository(first).upsert_from_events_bulk(
            _row({"stats": {"pid": 100}}),
        )

        blocked = asyncio.create_task(
            WorkerRepository(second).upsert_from_events_bulk(
                _row({"conf": {"timezone": "UTC"}}),
            ),
        )
        # Long enough that a write which was NOT going to wait has finished.
        await asyncio.sleep(1.0)
        assert not blocked.done(), (
            "the second transaction did not wait for the first, so the "
            "interleaving this test needs never happened and its result says "
            "nothing about the race"
        )

        await first.commit()
        await blocked
        await second.commit()

    async with sessions() as reader:
        worker = (
            await reader.execute(
                select(Worker).where(
                    Worker.project_id == pg_project.id,
                    Worker.name == name,
                ),
            )
        ).scalar_one()

    assert worker.worker_metadata == {
        "stats": {"pid": 100},
        "conf": {"timezone": "UTC"},
    }, (
        "one of two agents describing a worker for the first time had its "
        "report overwritten instead of merged"
    )
