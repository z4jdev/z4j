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

The worker layers run against a MIGRATED database. That matters most for
the breaker, which has two completely different disable paths depending on
whether Boundary D is activated, and for the prune worker, whose per-row
evidence-descriptor arming is inert on a create_all() schema. Layer 1 is
the legacy ``record``/``acknowledge`` API, which an activated database
refuses outright; those tests keep the create_all() fixtures.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import ScheduleKind
from z4j_brain.persistence.models import (
    Membership,
    Project,
    Schedule,
    ScheduleFire,
    User,
    UserNotification,
    UserSubscription,
)
from z4j_brain.persistence.repositories import ScheduleFireRepository
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
)
from z4j_brain.settings import Settings


@pytest.fixture
def settings(migrated_db_url: str, migrated_audit_chain_secret: str) -> Settings:
    return Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        # A migrated database has Boundary F activated, so it refuses an
        # audit row that carries no chain authentication.
        audit_chain_secret=migrated_audit_chain_secret,  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )


@pytest.fixture
async def engine(migrated_db_url: str):
    eng = create_async_engine(migrated_db_url)
    yield eng
    await eng.dispose()


@pytest.fixture
async def db(engine) -> DatabaseManager:
    # DatabaseManager installs the per-connection SQLite guard UDFs, exactly
    # as it does in production.
    return DatabaseManager(engine)


@pytest.fixture
async def legacy_db():
    """A create_all() manager, for the legacy record/acknowledge API."""
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield DatabaseManager(eng)
    await eng.dispose()


async def _seed_project_and_schedule(
    db: DatabaseManager,
    *,
    enabled: bool = True,
) -> tuple[uuid.UUID, uuid.UUID]:
    project_id = uuid.uuid4()
    async with db.session() as s:
        s.add(Project(id=project_id, slug="proj", name="P"))
        await s.flush()
        # Through the control repository, because Boundary D refuses a direct
        # INSERT into schedules. It is also the only way to get the control
        # token and digest every fire receipt has to carry.
        row = await ScheduleControlRepository(s).create_current(
            project_id=project_id,
            data={
                "engine": "celery",
                "scheduler": "z4j-scheduler",
                "name": "hourly",
                "task_name": "t.t",
                "kind": ScheduleKind.CRON.value,
                "expression": "0 * * * *",
                "timezone": "UTC",
                "args": [],
                "kwargs": {},
                "is_enabled": enabled,
            },
            planning_at=datetime.now(UTC),
        )
        await s.commit()
        return project_id, row.id


async def _seed_legacy_project_and_schedule(
    db: DatabaseManager,
) -> tuple[uuid.UUID, uuid.UUID]:
    """Seed the pre-Boundary-D shape, with no D identity on the row."""
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
                args=[],
                kwargs={},
                is_enabled=True,
            ),
        )
        await s.commit()
    return project_id, schedule_id


async def _record_fire(
    session: AsyncSession,
    *,
    project_id: uuid.UUID,
    schedule_id: uuid.UUID,
    status: str,
    scheduled_for: datetime | None = None,
    fired_at: datetime | None = None,
) -> ScheduleFire:
    """Write one fire the way an accepted current-protocol fire writes it.

    An activated database refuses a fire row whose receipt tuple is
    incomplete, so history a worker will later read has to be minted with
    the owning schedule's real control token, digest and revision.
    """
    row = await session.get(Schedule, schedule_id)
    assert row is not None
    assert row.control_token is not None
    assert row.definition_digest is not None
    slot = scheduled_for or datetime.now(UTC).replace(microsecond=0)
    fire, _created = await ScheduleFireRepository(session).record_current(
        fire_id=uuid.uuid4(),
        schedule_id=schedule_id,
        project_id=project_id,
        command_id=None,
        status=status,
        scheduled_for=slot,
        observed_control_token=row.control_token,
        receipt_control_token=row.control_token,
        acceptance_revision=int(row.schedule_revision or 1),
        definition_digest=row.definition_digest,
        expected_schedule_revision=int(row.schedule_revision or 1),
        expected_last_run_at=None,
        expected_next_run_at=slot,
        prepared_next_run_at=slot + timedelta(hours=1),
        fired_at=fired_at,
    )
    return fire


# =====================================================================
# ScheduleFireRepository
# =====================================================================


class TestRecord:
    """The legacy tokenless writer.

    Stays on create_all(). ``record()`` inserts a fire with no protocol
    marker and no receipt token, which an activated database refuses
    ('schedule fire protocol marker required'). That is not a gap in the
    test: the method is reachable only when Boundary D is NOT active.
    ``FireSchedule`` diverts to the legacy handler the moment
    ``control_is_active()`` is true (scheduler_grpc/handlers.py:1523), and
    the pending-fires replay worker that also calls it selects only
    ``protocol_marker IS NULL`` buffers (domain/workers/pending_fires.py:114),
    which an activated database cannot create either.
    """

    @pytest.mark.asyncio
    async def test_insert_returns_row(self, legacy_db: DatabaseManager) -> None:
        db = legacy_db
        project_id, schedule_id = await _seed_legacy_project_and_schedule(db)
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
        self,
        legacy_db: DatabaseManager,
    ) -> None:
        db = legacy_db
        project_id, schedule_id = await _seed_legacy_project_and_schedule(db)
        fire_id = uuid.uuid4()
        # scheduled_for is STABLE per fire_id in production (fire_id =
        # uuid5(schedule_id + scheduled_for)), so both record() calls for the
        # same fire pass the same value; the upgrade lookup prunes on it.
        sched_for = datetime.now(UTC)
        async with db.session() as s:
            await ScheduleFireRepository(s).record(
                fire_id=fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                command_id=None,
                status="delivered",
                scheduled_for=sched_for,
            )
            await s.commit()
        async with db.session() as s:
            row2 = await ScheduleFireRepository(s).record(
                fire_id=fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                command_id=None,
                status="delivered",
                scheduled_for=sched_for,
            )
            assert row2.fire_id == fire_id
        async with db.session() as s:
            count = (await s.execute(select(ScheduleFire))).scalars().all()
            assert len(count) == 1

    @pytest.mark.asyncio
    async def test_triggered_by_set_and_preserved_on_upgrade(
        self,
        legacy_db: DatabaseManager,
    ) -> None:
        """A5: a triggered fire records triggered_by_user_id, and a later
        status upgrade that passes None (the replay path) does NOT clobber
        it back to NULL."""
        import secrets

        from z4j_brain.persistence.models import User

        db = legacy_db
        project_id, schedule_id = await _seed_legacy_project_and_schedule(db)
        user_id = uuid.uuid4()
        async with db.session() as s:
            s.add(
                User(
                    id=user_id,
                    email=f"{uuid.uuid4().hex[:8]}@x.io",
                    password_hash=secrets.token_hex(8),
                ),
            )
            await s.commit()

        fire_id = uuid.uuid4()
        sched_for = datetime.now(UTC)  # stable per fire_id (see above)
        # Triggered fire buffers with the operator's id.
        async with db.session() as s:
            await ScheduleFireRepository(s).record(
                fire_id=fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                command_id=None,
                status="buffered",
                scheduled_for=sched_for,
                triggered_by_user_id=user_id,
            )
            await s.commit()
        # Replay upgrades buffered -> delivered with NO user id.
        async with db.session() as s:
            await ScheduleFireRepository(s).record(
                fire_id=fire_id,
                schedule_id=schedule_id,
                project_id=project_id,
                command_id=None,
                status="delivered",
                scheduled_for=sched_for,
                triggered_by_user_id=None,
            )
            await s.commit()

        async with db.session() as s:
            row = (
                await s.execute(
                    select(ScheduleFire).where(ScheduleFire.fire_id == fire_id),
                )
            ).scalar_one()
        assert row.status == "delivered"
        assert row.triggered_by_user_id == user_id  # preserved


class TestAcknowledge:
    """The legacy scheduler-receipt path.

    Stays on create_all(). ``acknowledge()`` rewrites ``status`` in place
    without rotating ``state_write_nonce``, and the activated fire-update
    guard requires a fresh nonce and one of a fixed set of transitions, so
    the UPDATE is refused. Like ``record()`` it is legacy-only: the current
    receipt path (``_acknowledge_current_fire_result``) hands over to it only
    when neither the command nor the retained history is current-protocol
    evidence (scheduler_grpc/handlers.py:2731-2733).
    """

    def test_latency_is_non_negative_and_saturates_for_retained_history(
        self,
    ) -> None:
        now = datetime(2026, 7, 25, tzinfo=UTC)

        assert ScheduleFireRepository._latency_ms(None, now) is None
        assert (
            ScheduleFireRepository._latency_ms(
                now + timedelta(seconds=1),
                now,
            )
            == 0
        )
        assert (
            ScheduleFireRepository._latency_ms(
                now - timedelta(milliseconds=1234),
                now,
            )
            == 1234
        )
        assert (
            ScheduleFireRepository._latency_ms(
                datetime(2019, 1, 1, tzinfo=UTC),
                now,
            )
            == 2_147_483_647
        )

    @pytest.mark.asyncio
    async def test_ack_sets_acked_at_and_latency(
        self,
        legacy_db: DatabaseManager,
    ) -> None:
        db = legacy_db
        project_id, schedule_id = await _seed_legacy_project_and_schedule(db)
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
            row, was_first, _became = await ScheduleFireRepository(s).acknowledge(
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
        self,
        legacy_db: DatabaseManager,
    ) -> None:
        db = legacy_db
        async with db.session() as s:
            row, was_first, _became = await ScheduleFireRepository(s).acknowledge(
                fire_id=uuid.uuid4(),
                status="acked_failed",
            )
        assert row is None
        assert was_first is False


class TestListRecent:
    @pytest.mark.asyncio
    async def test_returns_newest_first(
        self,
        db: DatabaseManager,
    ) -> None:
        project_id, schedule_id = await _seed_project_and_schedule(db)
        async with db.session() as s:
            for offset_min in (10, 5, 0):  # write older → newer
                await _record_fire(
                    s,
                    project_id=project_id,
                    schedule_id=schedule_id,
                    status="delivered",
                    fired_at=datetime.now(UTC) - timedelta(minutes=offset_min),
                )
            await s.commit()

        async with db.session() as s:
            rows = await ScheduleFireRepository(s).list_recent_for_schedule(
                schedule_id=schedule_id,
                project_id=project_id,
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
            await _record_fire(
                s,
                project_id=project_id,
                schedule_id=schedule_id,
                status="delivered",
            )
            await s.commit()

        other_project = uuid.uuid4()
        async with db.session() as s:
            rows = await ScheduleFireRepository(s).list_recent_for_schedule(
                schedule_id=schedule_id,
                project_id=other_project,
            )
        assert rows == []


# =====================================================================
# Circuit breaker worker
# =====================================================================


class TestCircuitBreaker:
    """The breaker has two disable paths and only one of them ships.

    On a create_all() schema ``control_is_active()`` is false, so every test
    here used to drive the raw ``UPDATE schedules SET is_enabled=false``
    fallback -- a statement an operator's database rejects outright. Against
    a migrated schema the worker takes the Boundary-D branch
    (``control.update_current``) instead, which is the only one a real trip
    can ever use.
    """

    @pytest.mark.asyncio
    async def test_disables_after_threshold_consecutive_failures(
        self,
        db: DatabaseManager,
        settings: Settings,
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
                await _record_fire(
                    s,
                    project_id=project_id,
                    schedule_id=schedule_id,
                    status="acked_failed",
                )
            await s.commit()

        worker = ScheduleCircuitBreakerWorker(db=db, settings=settings)
        await worker.tick()

        async with db.session() as s:
            row = await s.get(Schedule, schedule_id)
        assert row.is_enabled is False
        # The trip is a real Boundary-D transition, not a raw column write.
        # The worker keeps a pre-activation fallback that writes is_enabled
        # directly, and an operator's database rejects that statement; a
        # moved revision is the cheapest proof the shipping branch ran.
        assert row.schedule_revision == 2

    @pytest.mark.asyncio
    async def test_trip_notifies_circuit_breaker_subscriber(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # The schedule.circuit_breaker.tripped trigger was subscribable
        # since 1.6 but had no emit site (the same vapor class as the
        # removed task.slow). A trip must now fan out to project
        # subscriptions: an in-app subscriber gets exactly one bell row
        # whose deep-link data resolves to the schedule.
        from z4j_brain.domain.workers.schedule_circuit_breaker import (
            ScheduleCircuitBreakerWorker,
        )
        from z4j_brain.persistence.enums import ProjectRole

        settings = settings.model_copy(
            update={"schedule_circuit_breaker_threshold": 3},
        )
        project_id, schedule_id = await _seed_project_and_schedule(db)
        async with db.session() as s:
            user = User(
                email=f"{uuid.uuid4().hex[:8]}@x.io",
                password_hash=secrets.token_hex(8),
            )
            s.add(user)
            await s.flush()
            s.add(
                Membership(
                    user_id=user.id,
                    project_id=project_id,
                    role=ProjectRole.OPERATOR,
                ),
            )
            s.add(
                UserSubscription(
                    user_id=user.id,
                    project_id=project_id,
                    trigger="schedule.circuit_breaker.tripped",
                    filters={},
                    in_app=True,
                    project_channel_ids=[],
                    user_channel_ids=[],
                    cooldown_seconds=0,
                ),
            )
            for _ in range(3):
                await _record_fire(
                    s,
                    project_id=project_id,
                    schedule_id=schedule_id,
                    status="acked_failed",
                )
            await s.commit()

        await ScheduleCircuitBreakerWorker(db=db, settings=settings).tick()

        async with db.session() as s:
            row = await s.get(Schedule, schedule_id)
            assert row.is_enabled is False
            notes = list(
                (await s.execute(select(UserNotification))).scalars().all(),
            )
        assert len(notes) == 1
        assert notes[0].trigger == "schedule.circuit_breaker.tripped"
        assert notes[0].data["task_id"] == str(schedule_id)
        # The bell routes on resource_type; without the stamp a
        # breaker alert deep-links to a nonexistent task page
        # (round-4 LOW).
        assert notes[0].data["resource_type"] == "schedule"

    @pytest.mark.asyncio
    async def test_does_not_disable_with_recent_success(
        self,
        db: DatabaseManager,
        settings: Settings,
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
                await _record_fire(
                    s,
                    project_id=project_id,
                    schedule_id=schedule_id,
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
        self,
        db: DatabaseManager,
        settings: Settings,
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
                await _record_fire(
                    s,
                    project_id=project_id,
                    schedule_id=schedule_id,
                    status="acked_failed",
                )
            await s.commit()

        await ScheduleCircuitBreakerWorker(
            db=db,
            settings=settings,
        ).tick()

        async with db.session() as s:
            row = await s.get(Schedule, schedule_id)
        assert row.is_enabled is True

    @pytest.mark.asyncio
    async def test_threshold_zero_disables_breaker(
        self,
        db: DatabaseManager,
        settings: Settings,
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
                await _record_fire(
                    s,
                    project_id=project_id,
                    schedule_id=schedule_id,
                    status="acked_failed",
                )
            await s.commit()

        await ScheduleCircuitBreakerWorker(
            db=db,
            settings=settings,
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
        self,
        db: DatabaseManager,
        settings: Settings,
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
            for delta_days, _label in (
                (-30, "old"),
                (-10, "old"),
                (-3, "fresh"),
            ):
                await _record_fire(
                    s,
                    project_id=project_id,
                    schedule_id=schedule_id,
                    status="delivered",
                    scheduled_for=now,
                    fired_at=now + timedelta(days=delta_days),
                )
            await s.commit()

        await ScheduleFiresPruneWorker(db=db, settings=settings).tick()

        async with db.session() as s:
            rows = (await s.execute(select(ScheduleFire))).scalars().all()
        assert len(rows) == 1
