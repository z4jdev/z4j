"""Tests for the pending_fires buffer + replay worker.

Three layers:

1. :class:`PendingFiresRepository` - direct CRUD (insert idempotency,
   list ordering, delete, expiry sweep, count).
2. :class:`PendingFiresReplayWorker` - per-tick behaviour with the
   three ``catch_up`` policies, agent-offline -> noop, sweep.
3. End-to-end via the FireSchedule gRPC handler is covered by the
   scheduler-side e2e test in ``packages/z4j-scheduler/tests/integration``.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from z4j_brain.persistence.base import Base
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import AgentState, ScheduleKind
from z4j_brain.persistence.models import (
    Agent,
    PendingFire,
    Project,
    Schedule,
)
from z4j_brain.persistence.repositories import PendingFiresRepository
from z4j_brain.settings import Settings


# =====================================================================
# Fixtures
# =====================================================================


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )


@pytest.fixture
async def engine():
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest.fixture
async def db(engine) -> DatabaseManager:
    return DatabaseManager(engine)


async def _seed_project_and_schedule(
    db: DatabaseManager,
    *,
    catch_up: str = "skip",
) -> tuple[uuid.UUID, uuid.UUID]:
    project_id = uuid.uuid4()
    schedule_id = uuid.uuid4()
    async with db.session() as s:
        s.add(Project(id=project_id, slug="proj", name="Proj"))
        s.add(
            Schedule(
                id=schedule_id,
                project_id=project_id,
                engine="celery",
                scheduler="z4j-scheduler",
                name="hourly",
                task_name="t.t",
                kind=ScheduleKind.CRON,
                expression="0 * * * *",
                timezone="UTC",
                args=[], kwargs={},
                is_enabled=True,
                catch_up=catch_up,
            ),
        )
        await s.commit()
    return project_id, schedule_id


async def _seed_online_agent(
    db: DatabaseManager,
    *,
    project_id: uuid.UUID,
    engines: list[str] | None = None,
) -> None:
    async with db.session() as s:
        s.add(
            Agent(
                id=uuid.uuid4(),
                project_id=project_id,
                name="agent-1",
                token_hash=secrets.token_hex(32),
                protocol_version=1,
                framework_adapter="bare",
                engine_adapters=engines or ["celery"],
                scheduler_adapters=["z4j-scheduler"],
                state=AgentState.ONLINE,
                last_seen_at=datetime.now(UTC),
            ),
        )
        await s.commit()


# =====================================================================
# Repository
# =====================================================================


class TestBuffer:
    @pytest.mark.asyncio
    async def test_insert_returns_row(self, db: DatabaseManager) -> None:
        project_id, schedule_id = await _seed_project_and_schedule(db)
        async with db.session() as s:
            repo = PendingFiresRepository(s)
            row = await repo.buffer(
                fire_id=uuid.uuid4(),
                schedule_id=schedule_id,
                project_id=project_id,
                engine="celery",
                payload={"a": 1},
                scheduled_for=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(days=7),
            )
            await s.commit()
        assert row.id is not None

    @pytest.mark.asyncio
    async def test_duplicate_fire_id_is_noop(
        self, db: DatabaseManager,
    ) -> None:
        project_id, schedule_id = await _seed_project_and_schedule(db)
        fire_id = uuid.uuid4()
        async with db.session() as s:
            await PendingFiresRepository(s).buffer(
                fire_id=fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                engine="celery",
                payload={},
                scheduled_for=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(days=7),
            )
            await s.commit()

        async with db.session() as s:
            # Re-buffer the same fire_id - dispatcher retry path.
            row2 = await PendingFiresRepository(s).buffer(
                fire_id=fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                engine="celery",
                payload={},
                scheduled_for=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(days=7),
            )
            assert row2.fire_id == fire_id

        # Exactly one row in the buffer.
        async with db.session() as s:
            count = (await s.execute(select(PendingFire))).scalars().all()
            assert len(count) == 1


class TestListForReplay:
    @pytest.mark.asyncio
    async def test_orders_by_scheduled_for(
        self, db: DatabaseManager,
    ) -> None:
        project_id, schedule_id = await _seed_project_and_schedule(db)
        base = datetime(2026, 4, 27, 10, 0, tzinfo=UTC)
        async with db.session() as s:
            repo = PendingFiresRepository(s)
            for offset_min in (30, 0, 15, 60):  # out-of-order inserts
                await repo.buffer(
                    fire_id=uuid.uuid4(),
                    schedule_id=schedule_id,
                    project_id=project_id,
                    engine="celery",
                    payload={},
                    scheduled_for=base + timedelta(minutes=offset_min),
                    expires_at=base + timedelta(days=7),
                )
            await s.commit()

        async with db.session() as s:
            fires = await PendingFiresRepository(s).list_for_replay(
                project_id=project_id, engine="celery",
            )
            # SQLite strips tz; normalise both sides to naive for
            # the diff. Postgres preserves tz; the comparison still
            # holds because we subtract two like-shaped datetimes.
            base_naive = base.replace(tzinfo=None)
            assert [
                int((f.scheduled_for.replace(tzinfo=None) - base_naive)
                    .total_seconds() // 60)
                for f in fires
            ] == [0, 15, 30, 60]


class TestDelete:
    @pytest.mark.asyncio
    async def test_delete_by_fire_id(self, db: DatabaseManager) -> None:
        project_id, schedule_id = await _seed_project_and_schedule(db)
        fire_id = uuid.uuid4()
        async with db.session() as s:
            await PendingFiresRepository(s).buffer(
                fire_id=fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                engine="celery",
                payload={},
                scheduled_for=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
            await s.commit()
        async with db.session() as s:
            removed = await PendingFiresRepository(s).delete_by_fire_id(
                fire_id,
            )
            await s.commit()
        assert removed is True

    @pytest.mark.asyncio
    async def test_delete_expired_only(self, db: DatabaseManager) -> None:
        project_id, schedule_id = await _seed_project_and_schedule(db)
        now = datetime.now(UTC)
        async with db.session() as s:
            repo = PendingFiresRepository(s)
            # Two expired, one fresh.
            for delta_days in (-2, -1, 5):
                await repo.buffer(
                    fire_id=uuid.uuid4(),
                    schedule_id=schedule_id,
                    project_id=project_id,
                    engine="celery",
                    payload={},
                    scheduled_for=now,
                    expires_at=now + timedelta(days=delta_days),
                )
            await s.commit()
        async with db.session() as s:
            removed = await PendingFiresRepository(s).delete_expired(now=now)
            await s.commit()
        assert removed == 2


class TestCount:
    @pytest.mark.asyncio
    async def test_count_for_schedule(self, db: DatabaseManager) -> None:
        project_id, schedule_id = await _seed_project_and_schedule(db)
        async with db.session() as s:
            repo = PendingFiresRepository(s)
            for _ in range(3):
                await repo.buffer(
                    fire_id=uuid.uuid4(),
                    schedule_id=schedule_id,
                    project_id=project_id,
                    engine="celery",
                    payload={},
                    scheduled_for=datetime.now(UTC),
                    expires_at=datetime.now(UTC) + timedelta(days=1),
                )
            await s.commit()
        async with db.session() as s:
            n = await PendingFiresRepository(s).count_for_schedule(
                schedule_id,
            )
        assert n == 3


# =====================================================================
# Replay worker (catch_up policy semantics)
# =====================================================================


class _RecordingDispatcher:
    """Stand-in for CommandDispatcher that records issue() calls."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def issue(self, **kwargs):  # noqa: ANN201, ANN003
        self.calls.append(kwargs)

        class _Cmd:
            id = uuid.uuid4()

        return _Cmd()


@pytest.fixture
def dispatcher() -> _RecordingDispatcher:
    return _RecordingDispatcher()


class TestReplayWorker:
    @pytest.mark.asyncio
    async def test_no_online_agent_is_noop(
        self, db: DatabaseManager, dispatcher,
    ) -> None:
        from z4j_brain.domain.workers.pending_fires import (
            PendingFiresReplayWorker,
        )

        project_id, schedule_id = await _seed_project_and_schedule(
            db, catch_up="fire_all_missed",
        )
        # No agent seeded for this project/engine.
        async with db.session() as s:
            await PendingFiresRepository(s).buffer(
                fire_id=uuid.uuid4(),
                schedule_id=schedule_id,
                project_id=project_id,
                engine="celery",
                payload={"a": 1},
                scheduled_for=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(days=7),
            )
            await s.commit()

        worker = PendingFiresReplayWorker(db=db, dispatcher=dispatcher)
        await worker.tick()

        # Buffer untouched, dispatcher never called.
        async with db.session() as s:
            rows = (await s.execute(select(PendingFire))).scalars().all()
        assert len(rows) == 1
        assert dispatcher.calls == []

    @pytest.mark.asyncio
    async def test_skip_policy_drops_buffered_fires(
        self, db: DatabaseManager, dispatcher,
    ) -> None:
        from z4j_brain.domain.workers.pending_fires import (
            PendingFiresReplayWorker,
        )

        project_id, schedule_id = await _seed_project_and_schedule(
            db, catch_up="skip",
        )
        await _seed_online_agent(db, project_id=project_id)
        async with db.session() as s:
            for _ in range(3):
                await PendingFiresRepository(s).buffer(
                    fire_id=uuid.uuid4(),
                    schedule_id=schedule_id,
                    project_id=project_id,
                    engine="celery",
                    payload={},
                    scheduled_for=datetime.now(UTC),
                    expires_at=datetime.now(UTC) + timedelta(days=7),
                )
            await s.commit()

        await PendingFiresReplayWorker(
            db=db, dispatcher=dispatcher,
        ).tick()

        # No issues from the dispatcher (skip policy).
        assert dispatcher.calls == []
        # Buffer rows still present - the worker only deletes after
        # a successful issue. Sweep removes them at expiry. (We
        # could have the worker drop skip-policy rows in this pass;
        # left as Phase 3 polish.)

    @pytest.mark.asyncio
    async def test_fire_one_missed_keeps_only_latest(
        self, db: DatabaseManager, dispatcher,
    ) -> None:
        from z4j_brain.domain.workers.pending_fires import (
            PendingFiresReplayWorker,
        )

        project_id, schedule_id = await _seed_project_and_schedule(
            db, catch_up="fire_one_missed",
        )
        await _seed_online_agent(db, project_id=project_id)
        base = datetime(2026, 4, 27, 10, 0, tzinfo=UTC)
        async with db.session() as s:
            for offset in (0, 15, 30, 45):
                await PendingFiresRepository(s).buffer(
                    fire_id=uuid.uuid4(),
                    schedule_id=schedule_id,
                    project_id=project_id,
                    engine="celery",
                    payload={"offset": offset},
                    scheduled_for=base + timedelta(minutes=offset),
                    expires_at=base + timedelta(days=7),
                )
            await s.commit()

        await PendingFiresReplayWorker(
            db=db, dispatcher=dispatcher,
        ).tick()

        # Exactly one issue, with the LATEST fire's payload.
        assert len(dispatcher.calls) == 1
        assert dispatcher.calls[0]["payload"]["offset"] == 45
        # The other rows still in buffer (not deleted because not
        # replayed).

    @pytest.mark.asyncio
    async def test_fire_all_missed_replays_in_order(
        self, db: DatabaseManager, dispatcher,
    ) -> None:
        from z4j_brain.domain.workers.pending_fires import (
            PendingFiresReplayWorker,
        )

        project_id, schedule_id = await _seed_project_and_schedule(
            db, catch_up="fire_all_missed",
        )
        await _seed_online_agent(db, project_id=project_id)
        base = datetime(2026, 4, 27, 10, 0, tzinfo=UTC)
        async with db.session() as s:
            for offset in (30, 0, 60, 15):  # insert out of order
                await PendingFiresRepository(s).buffer(
                    fire_id=uuid.uuid4(),
                    schedule_id=schedule_id,
                    project_id=project_id,
                    engine="celery",
                    payload={"offset": offset},
                    scheduled_for=base + timedelta(minutes=offset),
                    expires_at=base + timedelta(days=7),
                )
            await s.commit()

        await PendingFiresReplayWorker(
            db=db, dispatcher=dispatcher,
        ).tick()

        # All four issued, in scheduled_for order.
        offsets = [c["payload"]["offset"] for c in dispatcher.calls]
        assert offsets == [0, 15, 30, 60]

    @pytest.mark.asyncio
    async def test_expired_buffers_swept(
        self, db: DatabaseManager, dispatcher,
    ) -> None:
        from z4j_brain.domain.workers.pending_fires import (
            PendingFiresReplayWorker,
        )

        project_id, schedule_id = await _seed_project_and_schedule(
            db, catch_up="fire_all_missed",
        )
        await _seed_online_agent(db, project_id=project_id)
        async with db.session() as s:
            await PendingFiresRepository(s).buffer(
                fire_id=uuid.uuid4(),
                schedule_id=schedule_id,
                project_id=project_id,
                engine="celery",
                payload={},
                scheduled_for=datetime.now(UTC) - timedelta(days=10),
                expires_at=datetime.now(UTC) - timedelta(days=1),  # expired
            )
            await s.commit()

        await PendingFiresReplayWorker(
            db=db, dispatcher=dispatcher,
        ).tick()

        async with db.session() as s:
            rows = (await s.execute(select(PendingFire))).scalars().all()
        assert rows == []
        # Expired never got dispatched.
        assert dispatcher.calls == []
