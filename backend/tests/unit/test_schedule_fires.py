"""Tests for the Phase-4 schedule_fires history + circuit breaker.

Three layers:

1. ``ScheduleFireRepository`` - direct CRUD (idempotent insert,
   acknowledge updates with computed latency, recent_failures,
   list_recent_for_schedule project-scoping).
2. ``ScheduleCircuitBreakerWorker`` - tick logic with the
   threshold + consecutive-failure semantics.
3. ``ScheduleFiresPruneWorker`` - retention sweep.

The brain handler integration (FireSchedule + AcknowledgeFireResult
writing rows) is covered indirectly by the scheduler-side e2e
tests in packages/z4j-scheduler/tests/integration.
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
from z4j_brain.persistence.enums import ScheduleKind
from z4j_brain.persistence.models import (
    Project,
    Schedule,
    ScheduleFire,
)
from z4j_brain.persistence.repositories import ScheduleFireRepository
from z4j_brain.settings import Settings


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
    enabled: bool = True,
) -> tuple[uuid.UUID, uuid.UUID]:
    project_id = uuid.uuid4()
    schedule_id = uuid.uuid4()
    async with db.session() as s:
        s.add(Project(id=project_id, slug="proj", name="P"))
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
                is_enabled=enabled,
            ),
        )
        await s.commit()
    return project_id, schedule_id


# =====================================================================
# ScheduleFireRepository
# =====================================================================


class TestRecord:
    @pytest.mark.asyncio
    async def test_insert_returns_row(self, db: DatabaseManager) -> None:
        project_id, schedule_id = await _seed_project_and_schedule(db)
        async with db.session() as s:
            row = await ScheduleFireRepository(s).record(
                fire_id=uuid.uuid4(),
                schedule_id=schedule_id,
                project_id=project_id,
                command_id=None,
                status="delivered",
                scheduled_for=datetime.now(UTC),
            )
            await s.commit()
        assert row.id is not None

    @pytest.mark.asyncio
    async def test_duplicate_fire_id_returns_existing(
        self, db: DatabaseManager,
    ) -> None:
        project_id, schedule_id = await _seed_project_and_schedule(db)
        fire_id = uuid.uuid4()
        async with db.session() as s:
            await ScheduleFireRepository(s).record(
                fire_id=fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                command_id=None,
                status="delivered",
                scheduled_for=datetime.now(UTC),
            )
            await s.commit()
        async with db.session() as s:
            row2 = await ScheduleFireRepository(s).record(
                fire_id=fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                command_id=None,
                status="delivered",
                scheduled_for=datetime.now(UTC),
            )
            assert row2.fire_id == fire_id
        async with db.session() as s:
            count = (await s.execute(select(ScheduleFire))).scalars().all()
            assert len(count) == 1


class TestAcknowledge:
    @pytest.mark.asyncio
    async def test_ack_sets_acked_at_and_latency(
        self, db: DatabaseManager,
    ) -> None:
        project_id, schedule_id = await _seed_project_and_schedule(db)
        fire_id = uuid.uuid4()
        async with db.session() as s:
            await ScheduleFireRepository(s).record(
                fire_id=fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                command_id=None,
                status="delivered",
                scheduled_for=datetime.now(UTC),
                fired_at=datetime.now(UTC) - timedelta(milliseconds=500),
            )
            await s.commit()

        async with db.session() as s:
            row, was_first = await ScheduleFireRepository(s).acknowledge(
                fire_id=fire_id,
                status="acked_success",
            )
            await s.commit()
        assert row is not None
        assert row.status == "acked_success"
        assert row.acked_at is not None
        # Latency captured (~500ms; allow generous slack for test scheduling).
        assert row.latency_ms is not None
        assert row.latency_ms >= 400
        # Round-4 audit fix (Apr 2026): acknowledge now returns
        # ``(row, was_first_ack)``. First ack on an un-acked row.
        assert was_first is True

    @pytest.mark.asyncio
    async def test_ack_unknown_fire_id_returns_none(
        self, db: DatabaseManager,
    ) -> None:
        async with db.session() as s:
            row, was_first = await ScheduleFireRepository(s).acknowledge(
                fire_id=uuid.uuid4(),
                status="acked_failed",
            )
        assert row is None
        assert was_first is False


class TestListRecent:
    @pytest.mark.asyncio
    async def test_returns_newest_first(
        self, db: DatabaseManager,
    ) -> None:
        project_id, schedule_id = await _seed_project_and_schedule(db)
        async with db.session() as s:
            for offset_min in (10, 5, 0):  # write older → newer
                await ScheduleFireRepository(s).record(
                    fire_id=uuid.uuid4(),
                    schedule_id=schedule_id,
                    project_id=project_id,
                    command_id=None,
                    status="delivered",
                    scheduled_for=datetime.now(UTC),
                    fired_at=datetime.now(UTC) - timedelta(minutes=offset_min),
                )
            await s.commit()

        async with db.session() as s:
            rows = await ScheduleFireRepository(s).list_recent_for_schedule(
                schedule_id=schedule_id, project_id=project_id,
            )
        # Newest first: first row's fired_at > last row's fired_at.
        assert len(rows) == 3
        assert rows[0].fired_at > rows[-1].fired_at

    @pytest.mark.asyncio
    async def test_project_scoped(self, db: DatabaseManager) -> None:
        # Schedule in project A; query with project B's id should
        # return nothing - IDOR defence.
        project_id, schedule_id = await _seed_project_and_schedule(db)
        async with db.session() as s:
            await ScheduleFireRepository(s).record(
                fire_id=uuid.uuid4(),
                schedule_id=schedule_id,
                project_id=project_id,
                command_id=None,
                status="delivered",
                scheduled_for=datetime.now(UTC),
            )
            await s.commit()

        other_project = uuid.uuid4()
        async with db.session() as s:
            rows = await ScheduleFireRepository(s).list_recent_for_schedule(
                schedule_id=schedule_id, project_id=other_project,
            )
        assert rows == []


# =====================================================================
# Circuit breaker worker
# =====================================================================


class TestCircuitBreaker:
    @pytest.mark.asyncio
    async def test_disables_after_threshold_consecutive_failures(
        self, db: DatabaseManager, settings: Settings,
    ) -> None:
        from z4j_brain.domain.workers.schedule_circuit_breaker import (
            ScheduleCircuitBreakerWorker,
        )

        # Override threshold to 3 for test brevity.
        settings = settings.model_copy(
            update={"schedule_circuit_breaker_threshold": 3},
        )
        project_id, schedule_id = await _seed_project_and_schedule(db)
        async with db.session() as s:
            for _ in range(3):
                await ScheduleFireRepository(s).record(
                    fire_id=uuid.uuid4(),
                    schedule_id=schedule_id,
                    project_id=project_id,
                    command_id=None,
                    status="acked_failed",
                    scheduled_for=datetime.now(UTC),
                )
            await s.commit()

        worker = ScheduleCircuitBreakerWorker(db=db, settings=settings)
        await worker.tick()

        async with db.session() as s:
            row = await s.get(Schedule, schedule_id)
        assert row.is_enabled is False

    @pytest.mark.asyncio
    async def test_does_not_disable_with_recent_success(
        self, db: DatabaseManager, settings: Settings,
    ) -> None:
        # 4 failures + 1 recent success interleaved → NOT a streak.
        from z4j_brain.domain.workers.schedule_circuit_breaker import (
            ScheduleCircuitBreakerWorker,
        )

        settings = settings.model_copy(
            update={"schedule_circuit_breaker_threshold": 3},
        )
        project_id, schedule_id = await _seed_project_and_schedule(db)
        now = datetime.now(UTC)
        async with db.session() as s:
            # Oldest first: failed, failed, success, failed, failed.
            # When sorted DESC by fired_at the most recent 3 are
            # [failed, failed, success] - not all failures, so the
            # breaker should NOT trip.
            for offset_sec, status in (
                (50, "acked_failed"),
                (40, "acked_failed"),
                (30, "acked_success"),
                (20, "acked_failed"),
                (10, "acked_failed"),
            ):
                await ScheduleFireRepository(s).record(
                    fire_id=uuid.uuid4(),
                    schedule_id=schedule_id,
                    project_id=project_id,
                    command_id=None,
                    status=status,
                    scheduled_for=now,
                    fired_at=now - timedelta(seconds=offset_sec),
                )
            await s.commit()

        worker = ScheduleCircuitBreakerWorker(db=db, settings=settings)
        await worker.tick()

        async with db.session() as s:
            row = await s.get(Schedule, schedule_id)
        assert row.is_enabled is True

    @pytest.mark.asyncio
    async def test_does_not_disable_below_threshold(
        self, db: DatabaseManager, settings: Settings,
    ) -> None:
        # Only 2 failures + threshold 3 → not enough rows to trip.
        from z4j_brain.domain.workers.schedule_circuit_breaker import (
            ScheduleCircuitBreakerWorker,
        )

        settings = settings.model_copy(
            update={"schedule_circuit_breaker_threshold": 3},
        )
        project_id, schedule_id = await _seed_project_and_schedule(db)
        async with db.session() as s:
            for _ in range(2):
                await ScheduleFireRepository(s).record(
                    fire_id=uuid.uuid4(),
                    schedule_id=schedule_id,
                    project_id=project_id,
                    command_id=None,
                    status="acked_failed",
                    scheduled_for=datetime.now(UTC),
                )
            await s.commit()

        await ScheduleCircuitBreakerWorker(
            db=db, settings=settings,
        ).tick()

        async with db.session() as s:
            row = await s.get(Schedule, schedule_id)
        assert row.is_enabled is True

    @pytest.mark.asyncio
    async def test_threshold_zero_disables_breaker(
        self, db: DatabaseManager, settings: Settings,
    ) -> None:
        # Operator opt-out: threshold=0 → worker is a no-op.
        from z4j_brain.domain.workers.schedule_circuit_breaker import (
            ScheduleCircuitBreakerWorker,
        )

        settings = settings.model_copy(
            update={"schedule_circuit_breaker_threshold": 0},
        )
        project_id, schedule_id = await _seed_project_and_schedule(db)
        async with db.session() as s:
            for _ in range(20):
                await ScheduleFireRepository(s).record(
                    fire_id=uuid.uuid4(),
                    schedule_id=schedule_id,
                    project_id=project_id,
                    command_id=None,
                    status="acked_failed",
                    scheduled_for=datetime.now(UTC),
                )
            await s.commit()

        await ScheduleCircuitBreakerWorker(
            db=db, settings=settings,
        ).tick()

        async with db.session() as s:
            row = await s.get(Schedule, schedule_id)
        assert row.is_enabled is True


# =====================================================================
# Prune worker
# =====================================================================


class TestPrune:
    @pytest.mark.asyncio
    async def test_drops_old_rows_only(
        self, db: DatabaseManager, settings: Settings,
    ) -> None:
        from z4j_brain.domain.workers.schedule_circuit_breaker import (
            ScheduleFiresPruneWorker,
        )

        settings = settings.model_copy(
            update={"schedule_fires_retention_days": 7},
        )
        project_id, schedule_id = await _seed_project_and_schedule(db)
        now = datetime.now(UTC)
        async with db.session() as s:
            for delta_days, label in (
                (-30, "old"),
                (-10, "old"),
                (-3, "fresh"),
            ):
                await ScheduleFireRepository(s).record(
                    fire_id=uuid.uuid4(),
                    schedule_id=schedule_id,
                    project_id=project_id,
                    command_id=None,
                    status="delivered",
                    scheduled_for=now,
                    fired_at=now + timedelta(days=delta_days),
                )
            await s.commit()

        await ScheduleFiresPruneWorker(db=db, settings=settings).tick()

        async with db.session() as s:
            rows = (await s.execute(select(ScheduleFire))).scalars().all()
        assert len(rows) == 1
