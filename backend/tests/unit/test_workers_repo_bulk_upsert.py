"""Tests for ``WorkerRepository.upsert_from_events_bulk``.

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
4. **Heterogeneous rows** - the rows in one batch legitimately carry
   different columns, because each field an agent reports comes from
   its own inspect broadcast with its own timeout. One statement has
   one column list, so a batch like that is either refused outright or
   silently stripped of the columns its first row happens to omit.
5. **SQL round-trip count** - a 200-row batch costs a FIXED number of
   statements, not one per row. Catches future regressions where
   someone accidentally drops the bulk path back into a per-row loop.
6. **Empty input is a no-op** - guarded so callers don't have to.
7. **Per-row fallback path correctness** - the old per-row path
   still works (degenerate dialect or a deadlock triggers it via
   :meth:`EventIngestor._flush_worker_upserts`).
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

from tests.worker_metadata_cases import MERGE_CASES, WRITE_PATHS


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
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
        self,
        session: AsyncSession,
        project: Project,
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
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        repo = WorkerRepository(session)
        n = await repo.upsert_from_events_bulk([])
        assert n == 0
        result = await session.execute(
            select(func.count()).select_from(Worker),
        )
        assert result.scalar_one() == 0

    async def test_missing_required_field_raises(
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        repo = WorkerRepository(session)
        with pytest.raises(ValueError, match="project_id, engine, name"):
            await repo.upsert_from_events_bulk(
                [{"project_id": project.id, "engine": "celery"}],
            )


@pytest.mark.asyncio
class TestBulkUpsertConflict:
    async def test_second_batch_updates_existing_rows(
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        repo = WorkerRepository(session)
        t1 = datetime.now(UTC) - timedelta(seconds=30)
        t2 = datetime.now(UTC)

        # First batch lands two new workers.
        await repo.upsert_from_events_bulk(
            [
                _row(project.id, name="celery@a", last_heartbeat=t1, concurrency=2),
                _row(project.id, name="celery@b", last_heartbeat=t1, concurrency=2),
            ]
        )
        await session.commit()

        # Second batch updates both.
        await repo.upsert_from_events_bulk(
            [
                _row(project.id, name="celery@a", last_heartbeat=t2, concurrency=8),
                _row(project.id, name="celery@b", last_heartbeat=t2, concurrency=8),
            ]
        )
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

    async def test_last_heartbeat_compared_as_utc_instant_not_wallclock(
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        """A non-UTC last_heartbeat (e.g. from the WS heartbeat path's
        ``last_flush_at``) must be normalised to a UTC INSTANT before the
        monotonic comparison, else SQLite drops the offset and compares
        wall-clocks: stored 12:00Z, a newer 11:00-05:00 (=16:00Z) was wrongly
        SKIPPED and an older 13:00+05:00 (=08:00Z) wrongly ADVANCED it."""
        from datetime import timezone

        repo = WorkerRepository(session)
        utc_12 = datetime(2026, 7, 12, 12, 0, 0, tzinfo=UTC)
        later_instant = datetime(2026, 7, 12, 11, 0, 0, tzinfo=timezone(timedelta(hours=-5)))
        earlier_instant = datetime(2026, 7, 12, 13, 0, 0, tzinfo=timezone(timedelta(hours=5)))

        def _as_utc(dt: datetime) -> datetime:
            return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)

        async def _hb() -> datetime:
            w = (
                await session.execute(select(Worker).where(Worker.name == "celery@a"))
            ).scalar_one()
            return _as_utc(w.last_heartbeat)

        await repo.upsert_from_events_bulk(
            [_row(project.id, name="celery@a", last_heartbeat=utc_12)]
        )
        await session.commit()

        # 11:00-05:00 == 16:00Z is a LATER instant -> must ADVANCE.
        await repo.upsert_from_events_bulk(
            [_row(project.id, name="celery@a", last_heartbeat=later_instant)]
        )
        await session.commit()
        assert await _hb() == datetime(2026, 7, 12, 16, 0, 0, tzinfo=UTC)

        # 13:00+05:00 == 08:00Z is an EARLIER instant -> must be SKIPPED.
        await repo.upsert_from_events_bulk(
            [_row(project.id, name="celery@a", last_heartbeat=earlier_instant)]
        )
        await session.commit()
        assert await _hb() == datetime(2026, 7, 12, 16, 0, 0, tzinfo=UTC)

    async def test_last_heartbeat_is_monotonic_never_rewinds(
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        """A reconnect that re-flushes an OLD buffered
        batch (stale occurred_at) must NOT rewind a live worker's
        last_heartbeat -- otherwise the worker trips a false offline sweep.
        The ON CONFLICT keeps heartbeat + lifecycle state from the same newest
        observation, so a stale ONLINE replay cannot overwrite a newer
        DRAINING/OFFLINE decision."""
        repo = WorkerRepository(session)
        t_new = datetime.now(UTC)
        t_old = t_new - timedelta(minutes=10)

        async def _hb() -> object:
            w = (
                await session.execute(select(Worker).where(Worker.name == "celery@a"))
            ).scalar_one()
            return w.last_heartbeat, w.state

        # First: a fresh heartbeat at t_new. Capture the readback as the
        # reference (SQLite returns naive datetimes, so == against the aware
        # input would spuriously fail).
        await repo.upsert_from_events_bulk(
            [_row(project.id, name="celery@a", last_heartbeat=t_new, state=WorkerState.DRAINING)]
        )
        await session.commit()
        after_new, _ = await _hb()
        assert after_new is not None

        # Then: a replay of an OLD batch (t_old < t_new) marking ONLINE.
        await repo.upsert_from_events_bulk(
            [_row(project.id, name="celery@a", last_heartbeat=t_old, state=WorkerState.ONLINE)]
        )
        await session.commit()
        after_replay, state_replay = await _hb()
        # Neither part of the liveness observation rewound.
        assert after_replay == after_new
        assert state_replay == WorkerState.DRAINING

        # A genuinely-newer heartbeat DOES advance it.
        t_newer = t_new + timedelta(minutes=5)
        await repo.upsert_from_events_bulk(
            [
                _row(
                    project.id,
                    name="celery@a",
                    last_heartbeat=t_newer,
                    state=WorkerState.ONLINE,
                )
            ]
        )
        await session.commit()
        after_newer, state_newer = await _hb()
        assert after_newer > after_new
        assert state_newer == WorkerState.ONLINE

    async def test_per_row_fallback_last_heartbeat_monotonic_tz_safe(
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        """The per-row fallback's monotonic guard compares
        the incoming (tz-AWARE) occurred_at against the stored last_heartbeat,
        which comes back tz-NAIVE on SQLite. A bare ``<`` would raise
        "can't compare offset-naive and offset-aware datetimes" and abort the
        heartbeat update; the guard must normalise tz and stay monotonic.

        Seed the stored value tz-NAIVE (the SQLite readback shape) so the
        UPDATE-branch comparison exercises the mixed-tz path directly."""
        repo = WorkerRepository(session)
        t_new_naive = datetime(2026, 7, 12, 12, 0, 0)  # tz-naive, as SQLite returns
        t_old_aware = datetime(2026, 7, 12, 11, 50, 0, tzinfo=UTC)  # older, tz-aware
        t_newer_aware = datetime(2026, 7, 12, 12, 5, 0, tzinfo=UTC)  # newer, tz-aware

        # INSERT branch with a NAIVE stored heartbeat.
        await repo.upsert_from_event(
            project_id=project.id,
            engine="celery",
            name="celery@a",
            updates={"state": WorkerState.ONLINE, "last_heartbeat": t_new_naive},
        )
        await session.flush()

        # UPDATE branch, OLD (aware) heartbeat vs the NAIVE stored one: must NOT
        # raise a naive-vs-aware TypeError, and must NOT rewind.
        w = await repo.upsert_from_event(
            project_id=project.id,
            engine="celery",
            name="celery@a",
            updates={"state": WorkerState.ONLINE, "last_heartbeat": t_old_aware},
        )
        assert w.last_heartbeat == t_new_naive  # not rewound

        # A genuinely-newer (aware) heartbeat DOES advance it (also mixed-tz).
        w = await repo.upsert_from_event(
            project_id=project.id,
            engine="celery",
            name="celery@a",
            updates={"state": WorkerState.ONLINE, "last_heartbeat": t_newer_aware},
        )
        assert w.last_heartbeat is not None
        readback = (
            w.last_heartbeat.replace(tzinfo=UTC)
            if w.last_heartbeat.tzinfo is None
            else w.last_heartbeat.astimezone(UTC)
        )
        assert readback == t_newer_aware

    async def test_partial_update_preserves_unspecified_columns(
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        """Heartbeat-only batch must not blank ``hostname`` /
        ``concurrency`` set by an earlier worker_details batch."""
        repo = WorkerRepository(session)
        t1 = datetime.now(UTC) - timedelta(seconds=30)
        t2 = datetime.now(UTC)

        # First batch sets the full payload (state, last_heartbeat,
        # hostname, concurrency).
        await repo.upsert_from_events_bulk(
            [
                _row(
                    project.id,
                    name="celery@a",
                    last_heartbeat=t1,
                    hostname="web-a.internal",
                    concurrency=16,
                ),
            ]
        )
        await session.commit()

        # Second batch is a stripped heartbeat - just last_heartbeat
        # + state, no hostname/concurrency keys at all.
        await repo.upsert_from_events_bulk(
            [
                {
                    "project_id": project.id,
                    "engine": "celery",
                    "name": "celery@a",
                    "state": WorkerState.ONLINE,
                    "last_heartbeat": t2,
                },
            ]
        )
        await session.commit()

        result = await session.execute(
            select(Worker).where(Worker.name == "celery@a"),
        )
        a = result.scalar_one()
        # last_heartbeat advanced
        assert a.last_heartbeat is not None
        assert (
            a.last_heartbeat >= t2.replace(tzinfo=None)
            if a.last_heartbeat.tzinfo is None
            else a.last_heartbeat >= t2
        )
        # hostname + concurrency PRESERVED (no key, no touch)
        assert a.hostname == "web-a.internal"
        assert a.concurrency == 16


@pytest.mark.asyncio
class TestBulkUpsertHeterogeneousRows:
    """Rows in one batch legitimately carry different columns.

    Each field an agent reports comes from a separate inspect broadcast with
    its own timeout, so one worker answering for its pool while another does
    not is the ordinary case for this batch, not a malformed caller.

    One statement has one column list and one ``ON CONFLICT`` set clause, so
    a batch whose rows disagree has two ways to go wrong and it goes both:
    when the first row in canonical order carries a column a later row omits,
    the statement does not compile and the whole batch is lost; when the first
    row omits a column a later row carries, that column is dropped from the
    statement and the set clause writes the resulting NULL over every row's
    stored value. Both orders are driven below, because the sort is by
    conflict key and a caller does not choose which of its rows sorts first.
    """

    async def test_a_richer_row_sorting_first_does_not_lose_the_batch(
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        """The reporting worker sorts first, the quiet one second."""
        repo = WorkerRepository(session)
        now = datetime.now(UTC)

        n = await repo.upsert_from_events_bulk(
            [
                _row(
                    project.id,
                    name="celery@aaa",
                    last_heartbeat=now,
                    hostname="aaa",
                    concurrency=4,
                ),
                # Same round, same agent: this worker's stats broadcast timed
                # out, so there is no pool and no hostname to report.
                _row(project.id, name="celery@zzz", last_heartbeat=now),
            ],
        )
        await session.commit()

        assert n == 2
        landed = {
            w.name: w
            for w in (await session.execute(select(Worker).order_by(Worker.name))).scalars().all()
        }
        assert set(landed) == {"celery@aaa", "celery@zzz"}, (
            "the batch did not land; a row carrying a column its sibling "
            "omits must not cost the whole heartbeat"
        )
        assert landed["celery@aaa"].hostname == "aaa"
        assert landed["celery@aaa"].concurrency == 4
        assert landed["celery@zzz"].hostname is None
        assert landed["celery@zzz"].state == WorkerState.ONLINE

    async def test_a_leaner_row_sorting_first_does_not_drop_the_column(
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        """The quiet worker sorts first, so its gap decides the column list.

        Both rows are checked, not just the reporting one: the failure mode is
        that the column leaves the statement entirely, which loses the value
        the second row DID report as well as the value the first row already
        had stored.
        """
        repo = WorkerRepository(session)
        earlier = datetime.now(UTC) - timedelta(seconds=30)
        now = datetime.now(UTC)

        await repo.upsert_from_events_bulk(
            [
                _row(project.id, name="celery@aaa", last_heartbeat=earlier, hostname="kept"),
                _row(project.id, name="celery@zzz", last_heartbeat=earlier, hostname="also-kept"),
            ],
        )
        await session.commit()

        await repo.upsert_from_events_bulk(
            [
                # This worker's stats broadcast timed out this round.
                _row(project.id, name="celery@aaa", last_heartbeat=now),
                _row(project.id, name="celery@zzz", last_heartbeat=now, hostname="fresh"),
            ],
        )
        await session.commit()

        landed = {
            w.name: w
            for w in (await session.execute(select(Worker).order_by(Worker.name))).scalars().all()
        }
        assert landed["celery@aaa"].hostname == "kept", (
            "a worker that reported no hostname this round had its stored one "
            "blanked by a sibling row's update"
        )
        assert landed["celery@zzz"].hostname == "fresh", (
            "a worker that DID report a hostname did not get it stored; the "
            "column was dropped from the statement for every row"
        )

    async def test_a_row_that_reports_no_state_keeps_the_one_it_had(
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        """``state`` is the same shape, and the quiet way round.

        Every row carries a state on the wire whether or not its caller
        supplied one, so this column never raises and never disappears. It
        writes UNKNOWN over a live worker instead, which is a dashboard
        reporting a running fleet as unknown.
        """
        repo = WorkerRepository(session)
        now = datetime.now(UTC)

        await repo.upsert_from_events_bulk(
            [_row(project.id, name="celery@aaa", last_heartbeat=now)],
        )
        await session.commit()

        # The two rows differ in NOTHING but whether they carry a state, so
        # nothing else can be the reason for what lands.
        await repo.upsert_from_events_bulk(
            [
                _row(project.id, name="celery@aaa", last_heartbeat=now, state=None),
                _row(project.id, name="celery@zzz", last_heartbeat=now, state=WorkerState.OFFLINE),
            ],
        )
        await session.commit()

        landed = {
            w.name: w
            for w in (await session.execute(select(Worker).order_by(Worker.name))).scalars().all()
        }
        assert landed["celery@aaa"].state == WorkerState.ONLINE, (
            "a row that reported no state had a sibling row's set clause "
            "write the insert default over its stored state"
        )
        assert landed["celery@zzz"].state == WorkerState.OFFLINE

    async def test_every_row_carries_every_updated_column_by_the_time_it_compiles(
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        """The invariant underneath both failures, asserted where it is decided.

        SQLAlchemy compiles a multi-values INSERT from the first entry's key
        set. Anything that reaches that call with rows disagreeing is either a
        ``CompileError`` or a silently dropped column, so the property to hold
        is not "these two cases work" but "no row ever disagrees".
        """
        repo = WorkerRepository(session)
        now = datetime.now(UTC)
        seen: list[list[dict]] = []

        real_execute = repo.session.execute

        async def _capture(statement, *args, **kwargs):
            values = getattr(statement, "_multi_values", ())
            for group in values:
                seen.append([dict(entry) for entry in group])
            return await real_execute(statement, *args, **kwargs)

        repo.session.execute = _capture  # type: ignore[method-assign]
        try:
            await repo.upsert_from_events_bulk(
                [
                    _row(project.id, name="celery@aaa", last_heartbeat=now, hostname="aaa"),
                    _row(project.id, name="celery@mmm", last_heartbeat=now, concurrency=8),
                    _row(project.id, name="celery@zzz", last_heartbeat=now),
                ],
            )
        finally:
            repo.session.execute = real_execute  # type: ignore[method-assign]
        await session.commit()

        assert seen, "no multi-values INSERT was compiled; the batch took another path"
        for group in seen:
            key_sets = {frozenset(entry) for entry in group}
            assert len(key_sets) == 1, (
                f"rows reached the INSERT disagreeing about their columns: "
                f"{sorted(sorted(k) for k in key_sets)}"
            )

    async def test_rows_that_still_disagree_are_refused_rather_than_compiled(
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        """The guard behind the resolution, driven by breaking the resolution.

        A future column added to the whitelist with a path around the resolver
        would put the silent-drop back. The batch is worth more than the
        statement: both callers fall back to a per-row upsert when this raises,
        so refusing costs a slower write and dropping a column costs the data.
        """
        repo = WorkerRepository(session)
        now = datetime.now(UTC)

        async def _resolve_nothing(prepared, supplied, update_cols) -> None:
            return

        repo._resolve_shared_update_values = _resolve_nothing  # type: ignore[method-assign]

        with pytest.raises(RuntimeError, match="disagree about which columns"):
            await repo.upsert_from_events_bulk(
                [
                    _row(project.id, name="celery@aaa", last_heartbeat=now, hostname="aaa"),
                    _row(project.id, name="celery@zzz", last_heartbeat=now),
                ],
            )


@pytest.mark.asyncio
class TestBulkUpsertSqlCount:
    async def test_one_insert_statement_per_batch(
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        """200 rows = 1 INSERT.

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
            conn,
            cursor,
            statement,
            parameters,
            context,
            executemany,
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
                engine.sync_engine,
                "before_cursor_execute",
                _count_inserts,
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
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        """Two rows with the same (engine, name) → one row, later input wins.

        Only SQLite accepts a duplicate conflict key in a single
        ``INSERT ... VALUES ... ON CONFLICT DO UPDATE``; PostgreSQL refuses the
        whole statement with ``ON CONFLICT DO UPDATE command cannot affect row
        a second time``. The repository folds duplicates before it builds the
        statement so this holds on both, which is why the same case is driven
        against real PostgreSQL in
        ``tests/integration/test_worker_metadata_merge_pg.py``. Callers do
        their own dedupe on top, to keep the round-trip payload small.
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
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        repo = WorkerRepository(session)
        now = datetime.now(UTC)
        await repo.upsert_from_events_bulk(
            [
                {
                    "project_id": project.id,
                    "engine": "celery",
                    "name": "celery@meta-insert",
                    "state": WorkerState.ONLINE,
                    "last_heartbeat": now,
                    "worker_metadata": {"version": "5.6.3", "platform": "linux"},
                },
            ]
        )
        await session.commit()

        result = await session.execute(
            select(Worker).where(Worker.name == "celery@meta-insert"),
        )
        w = result.scalar_one()
        assert w.worker_metadata == {"version": "5.6.3", "platform": "linux"}

    async def test_update_with_worker_metadata_on_conflict(
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        repo = WorkerRepository(session)
        t1 = datetime.now(UTC) - timedelta(seconds=10)
        t2 = datetime.now(UTC)

        # First batch lands the worker with v1 metadata.
        await repo.upsert_from_events_bulk(
            [
                {
                    "project_id": project.id,
                    "engine": "celery",
                    "name": "celery@meta-update",
                    "state": WorkerState.ONLINE,
                    "last_heartbeat": t1,
                    "worker_metadata": {"version": "5.5.0"},
                },
            ]
        )
        await session.commit()

        # Second batch updates the metadata via ON CONFLICT.
        await repo.upsert_from_events_bulk(
            [
                {
                    "project_id": project.id,
                    "engine": "celery",
                    "name": "celery@meta-update",
                    "state": WorkerState.ONLINE,
                    "last_heartbeat": t2,
                    "worker_metadata": {"version": "5.6.3", "newkey": "ok"},
                },
            ]
        )
        await session.commit()

        result = await session.execute(
            select(Worker).where(Worker.name == "celery@meta-update"),
        )
        w = result.scalar_one()
        assert w.worker_metadata == {"version": "5.6.3", "newkey": "ok"}


# ---------------------------------------------------------------------------
# 1.5.1: lock-ordering deadlock prevention
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
class TestBulkUpsertLockOrdering:
    """1.5.1: rows MUST be sorted by (project_id, engine, name) before
    the INSERT so concurrent sessions acquire row-level btree locks in
    the same order. A sustained burst surfaced 140 deadlocks on this
    INSERT without it; this test pins the fix so a future refactor
    cannot silently remove it.
    """

    async def test_rows_land_in_database_in_canonical_lock_order(
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        # End-to-end check: pass rows in REVERSE lexical order, then
        # verify the rows actually committed by id-sequence reflect the
        # canonical sort. SQLite's autoincrement id is monotonic in
        # the order rows were INSERTed; if the repo sorted before
        # INSERT, the lowest id matches the lexically-first
        # (project_id, engine, name) triple.
        repo = WorkerRepository(session)
        unsorted = [
            _row(project.id, name="celery@z-zeta", concurrency=1),
            _row(project.id, name="celery@m-mu", concurrency=2),
            _row(project.id, name="celery@a-alpha", concurrency=3),
            _row(project.id, name="celery@d-delta", concurrency=4),
            _row(project.id, name="celery@p-pi", concurrency=5),
        ]
        await repo.upsert_from_events_bulk(unsorted)
        await session.commit()
        result = await session.execute(
            select(Worker).order_by(Worker.created_at, Worker.name),
        )
        actual = [w.name for w in result.scalars().all()]
        expected_sorted = sorted([r["name"] for r in unsorted])
        # The names should appear sorted (insertion order respected by
        # the lock-ordering sort the repo applies pre-INSERT). If the
        # sort is removed, the names will appear in input order.
        assert actual == expected_sorted, (
            f"rows landed in non-canonical order: {actual}. "
            "The lock-ordering sort in upsert_from_events_bulk was "
            "removed or bypassed; concurrent heartbeats will deadlock "
            "again."
        )


# ---------------------------------------------------------------------------
# The metadata merge
#
# The cases live in ``tests.worker_metadata_cases`` because the same table is
# driven against real PostgreSQL in
# ``tests/integration/test_worker_metadata_merge_pg.py``. That is the whole
# point of the file: the defect these cover was the two engines quietly
# implementing two different merges, which a case list living in one suite
# cannot see.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(("documents", "expected"), MERGE_CASES)
@pytest.mark.parametrize("write", WRITE_PATHS)
async def test_metadata_merge_case_on_sqlite(
    session: AsyncSession,
    project: Project,
    write,
    documents,
    expected,
) -> None:
    stored = await write(session, project.id, "celery@merge", documents)
    assert stored == expected


@pytest.mark.asyncio
class TestMetadataMergeBatchShape:
    """Properties of a BATCH that the per-document cases cannot reach."""

    async def test_a_row_without_a_report_does_not_clear_a_sibling_rows_report(
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        """One statement, one shared ON CONFLICT clause, two different rows.

        A heartbeat carries every worker the agent could see, and only some of
        them answered the config broadcast. The update clause is written once
        for the whole statement, so whatever the rows that answered nothing
        carry in that column is applied to them too.
        """
        repo = WorkerRepository(session)
        now = datetime.now(UTC)
        for name in ("celery@answered", "celery@silent"):
            await repo.upsert_from_events_bulk(
                [
                    {
                        "project_id": project.id,
                        "engine": "celery",
                        "name": name,
                        "state": WorkerState.ONLINE,
                        "last_heartbeat": now,
                        "worker_metadata": {"conf": {"task_acks_late": True}},
                    },
                ],
            )
        await session.commit()

        # The next round: one worker reports again, the other is in the batch
        # for its heartbeat alone and carries no report at all.
        await repo.upsert_from_events_bulk(
            [
                {
                    "project_id": project.id,
                    "engine": "celery",
                    "name": "celery@answered",
                    "state": WorkerState.ONLINE,
                    "last_heartbeat": now + timedelta(seconds=10),
                    "worker_metadata": {"stats": {"clock": 7}},
                },
                {
                    "project_id": project.id,
                    "engine": "celery",
                    "name": "celery@silent",
                    "state": WorkerState.ONLINE,
                    "last_heartbeat": now + timedelta(seconds=10),
                },
            ],
        )
        await session.commit()

        rows = {
            w.name: w.worker_metadata
            for w in (await session.execute(select(Worker))).scalars().all()
        }
        assert rows["celery@answered"] == {
            "conf": {"task_acks_late": True},
            "stats": {"clock": 7},
        }
        assert rows["celery@silent"] == {"conf": {"task_acks_late": True}}, (
            "a row that carried no report in a batch where another row did had "
            "its stored document overwritten by the shared update clause"
        )

    async def test_two_entries_for_one_worker_in_a_batch_fold_onto_each_other(
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        """Both entries have to survive, not just the last one.

        Each entry is merged onto what is stored, so two entries resolved
        independently would both merge onto the pre-batch document and the
        first one's contribution would be dropped by the second.
        """
        repo = WorkerRepository(session)
        now = datetime.now(UTC)
        await repo.upsert_from_events_bulk(
            [
                {
                    "project_id": project.id,
                    "engine": "celery",
                    "name": "celery@dupe",
                    "state": WorkerState.ONLINE,
                    "last_heartbeat": now,
                    "worker_metadata": {"conf": {"timezone": "UTC"}},
                },
                {
                    "project_id": project.id,
                    "engine": "celery",
                    "name": "celery@dupe",
                    "state": WorkerState.ONLINE,
                    "last_heartbeat": now,
                    "worker_metadata": {"stats": {"clock": 3}},
                },
            ],
        )
        await session.commit()

        result = await session.execute(
            select(Worker).where(Worker.name == "celery@dupe"),
        )
        assert result.scalar_one().worker_metadata == {
            "conf": {"timezone": "UTC"},
            "stats": {"clock": 3},
        }

    async def test_a_batch_carrying_reports_costs_a_fixed_number_of_statements(
        self,
        session: AsyncSession,
        project: Project,
    ) -> None:
        """Resolving the merge in Python must not reintroduce the N+1.

        The merge needs the stored document, so it reads before it writes, and
        the read can only lock a row that exists, so the conflict keys are
        inserted before it. Three statements for the whole batch: the
        conflict-key insert, the locked read, and the upsert. What matters is
        that the number does not grow with the batch -- a per-row read or a
        per-row insert would put the round trips back on a path that fires
        every ten seconds per agent, which is what the bulk statement was
        introduced to remove.

        Driven at 200 rows so a per-row regression is two orders of magnitude
        away from passing rather than one statement away.
        """
        repo = WorkerRepository(session)
        bind = await session.connection()
        engine = bind.engine
        counts = {"insert": 0, "select": 0}

        @event.listens_for(engine.sync_engine, "before_cursor_execute")
        def _count(conn, cursor, statement, parameters, context, executemany) -> None:
            sql = (statement or "").lower()
            if "insert into workers" in sql:
                counts["insert"] += 1
            elif "from workers" in sql:
                counts["select"] += 1

        try:
            now = datetime.now(UTC)
            await repo.upsert_from_events_bulk(
                [
                    {
                        "project_id": project.id,
                        "engine": "celery",
                        "name": f"celery@h-{i:03d}",
                        "state": WorkerState.ONLINE,
                        "last_heartbeat": now,
                        "worker_metadata": {"stats": {"clock": i}},
                    }
                    for i in range(200)
                ],
            )
            await session.commit()
        finally:
            event.remove(engine.sync_engine, "before_cursor_execute", _count)

        assert counts["insert"] == 2, (
            f"expected 2 INSERTs for a 200-row batch carrying reports (the "
            f"conflict-key insert that makes the rows lockable, then the "
            f"upsert), got {counts['insert']}; the merge turned the bulk path "
            f"into a loop"
        )
        assert counts["select"] == 1, (
            f"expected 1 read of the stored documents for a 200-row batch, got "
            f"{counts['select']}; the merge is reading per row"
        )
