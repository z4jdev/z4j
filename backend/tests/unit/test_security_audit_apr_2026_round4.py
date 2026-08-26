"""Regression tests for the round-4 race-condition audit (Apr 2026).

Pins the 8 HIGH + 4 MEDIUM fixes from the deep race audit. Race
conditions are notoriously hard to trigger reliably in unit tests
- these tests pin the *invariants* the fixes establish (e.g.
"command insert is idempotent on collision", "total_runs uses a
SQL increment", "circuit breaker re-reads failure streak in
disable txn") so a future refactor can't silently regress.
"""

from __future__ import annotations

import asyncio
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest

# =====================================================================
# H--1: total_runs SQL-side increment (atomicity)
# =====================================================================


class TestR4TotalRunsAtomicIncrement:
    """Pre-fix: ``updates['total_runs'] = (schedule.total_runs or 0) +
    1`` was a Python-side read-modify-write. Two concurrent acks for
    two distinct fires of the same schedule both read 5, both wrote
    6 - silent lost increment.

    Post-fix: SQL expression ``Schedule.total_runs + 1`` makes the
    increment atomic in Postgres without needing FOR UPDATE on the
    schedule row.
    """

    @pytest.mark.asyncio
    async def test_two_concurrent_success_updates_are_both_counted(self, tmp_path) -> None:
        from sqlalchemy import select
        from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
        from sqlalchemy.orm import sessionmaker
        from z4j_brain.persistence.base import Base
        from z4j_brain.persistence.enums import ScheduleKind
        from z4j_brain.persistence.models import Project, Schedule
        from z4j_brain.scheduler_grpc.handlers import (
            _advance_legacy_schedule_after_success,
        )

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'atomic.sqlite3'}")
        factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        project_id = uuid.uuid4()
        schedule_id = uuid.uuid4()
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        try:
            async with factory() as session:
                session.add(Project(id=project_id, slug="atomic", name="Atomic"))
                session.add(
                    Schedule(
                        id=schedule_id,
                        project_id=project_id,
                        engine="celery",
                        scheduler="z4j-scheduler",
                        name="atomic",
                        task_name="tasks.atomic",
                        kind=ScheduleKind.CRON,
                        expression="* * * * *",
                        timezone="UTC",
                        args=[],
                        kwargs={},
                        total_runs=0,
                    ),
                )
                await session.commit()

            start = asyncio.Event()

            async def advance(slot_offset: int) -> None:
                async with factory() as session:
                    await start.wait()
                    now = datetime.now(UTC) + timedelta(seconds=slot_offset)
                    await _advance_legacy_schedule_after_success(
                        session,
                        schedule_id=schedule_id,
                        fire_id=uuid.uuid4(),
                        scheduled_for=now,
                        is_manual=True,
                        observed_at=now,
                    )
                    await session.commit()

            first = asyncio.create_task(advance(1))
            second = asyncio.create_task(advance(2))
            start.set()
            await asyncio.gather(first, second)

            async with factory() as session:
                total_runs = (
                    await session.execute(
                        select(Schedule.total_runs).where(Schedule.id == schedule_id),
                    )
                ).scalar_one()
            assert total_runs == 2
        finally:
            await engine.dispose()


# =====================================================================
# H--2: CommandRepository.insert idempotency
# =====================================================================


class TestR4CommandInsertIdempotent:
    """Pre-fix: two scheduler instances minting the same fire_id
    raced - one INSERT succeeded, the other raised IntegrityError.
    The handler reported ``brain_error`` to the second scheduler;
    scheduler retried; per-fire wedge cycle.

    Post-fix: CommandRepository.insert catches IntegrityError on
    (project_id, idempotency_key) and returns the existing row -
    second caller sees success with the same command_id, no wedge.
    """

    @pytest.mark.asyncio
    async def test_duplicate_idempotency_key_returns_existing(
        self,
    ) -> None:
        from datetime import timedelta

        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import StaticPool
        from z4j_brain.persistence.base import Base
        from z4j_brain.persistence.database import DatabaseManager
        from z4j_brain.persistence.models import Project
        from z4j_brain.persistence.repositories import CommandRepository

        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        try:
            db = DatabaseManager(engine)
            project_id = uuid.uuid4()
            async with db.session() as s:
                s.add(Project(id=project_id, slug="acme", name="A"))
                await s.commit()

            timeout_at = datetime.now(UTC) + timedelta(minutes=5)

            # First insert - wins.
            async with db.session() as s:
                row1, _ = await CommandRepository(s).insert(
                    project_id=project_id,
                    agent_id=None,
                    issued_by=None,
                    action="schedule.fire",
                    target_type="schedule",
                    target_id="x",
                    payload={"a": 1},
                    idempotency_key="schedule:S:fire:F",
                    timeout_at=timeout_at,
                    source_ip=None,
                )
                await s.commit()
                first_id = row1.id

            # Second insert with the same idempotency_key - was
            # IntegrityError pre-fix; returns row1 post-fix.
            sentinel_id = uuid.uuid4()
            async with db.session() as s:
                s.add(Project(id=sentinel_id, slug="outer-command", name="Outer command"))
                await s.flush()
                row2, _ = await CommandRepository(s).insert(
                    project_id=project_id,
                    agent_id=None,
                    issued_by=None,
                    action="schedule.fire",
                    target_type="schedule",
                    target_id="x",
                    payload={"a": 2},  # different payload, ignored
                    idempotency_key="schedule:S:fire:F",
                    timeout_at=timeout_at,
                    source_ip=None,
                )
                # The existing row's id is returned; the new payload
                # is NOT applied (idempotent semantics).
                assert row2.id == first_id, (
                    "duplicate idempotency_key must return existing row, not raise"
                )
                await s.commit()

            async with db.session() as s:
                assert await s.get(Project, sentinel_id) is not None
        finally:
            await engine.dispose()


# =====================================================================
# H--3 / H-1 (worker): SAVEPOINT in repository idempotency paths
# =====================================================================


@asynccontextmanager
async def _idempotency_database():
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import StaticPool
    from z4j_brain.persistence.base import Base
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.enums import ScheduleKind
    from z4j_brain.persistence.models import Project, Schedule

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    database = DatabaseManager(engine)
    project_id = uuid.uuid4()
    schedule_id = uuid.uuid4()
    async with database.session() as session:
        session.add(Project(id=project_id, slug="savepoint", name="Savepoint"))
        session.add(
            Schedule(
                id=schedule_id,
                project_id=project_id,
                engine="celery",
                scheduler="z4j-scheduler",
                name="savepoint",
                task_name="tasks.savepoint",
                kind=ScheduleKind.CRON,
                expression="* * * * *",
                timezone="UTC",
                args=[],
                kwargs={},
            ),
        )
        await session.commit()
    try:
        yield database, project_id, schedule_id
    finally:
        await engine.dispose()


class TestR4SavepointPattern:
    """Pre-fix: ``record()`` and ``buffer()`` called
    ``self.session.rollback()`` on IntegrityError, which wiped the
    caller's outer transaction (releasing FOR UPDATE locks +
    discarding queued writes). Post-fix: ``begin_nested()`` so only
    the failed INSERT rolls back."""

    @pytest.mark.asyncio
    async def test_schedule_fire_collision_preserves_outer_write(self) -> None:
        from z4j_brain.persistence.models import Project
        from z4j_brain.persistence.repositories import ScheduleFireRepository

        async with _idempotency_database() as (database, project_id, schedule_id):
            fire_id = uuid.uuid4()
            scheduled_for = datetime.now(UTC)
            async with database.session() as session:
                await ScheduleFireRepository(session).record(
                    fire_id=fire_id,
                    schedule_id=schedule_id,
                    project_id=project_id,
                    command_id=None,
                    status="delivered",
                    scheduled_for=scheduled_for,
                )
                await session.commit()

            sentinel_id = uuid.uuid4()
            async with database.session() as session:
                session.add(Project(id=sentinel_id, slug="outer-fire", name="Outer fire"))
                await session.flush()
                await ScheduleFireRepository(session).record(
                    fire_id=fire_id,
                    schedule_id=schedule_id,
                    project_id=project_id,
                    command_id=None,
                    status="delivered",
                    scheduled_for=scheduled_for,
                )
                await session.commit()
            async with database.session() as session:
                assert await session.get(Project, sentinel_id) is not None

    @pytest.mark.asyncio
    async def test_pending_fire_collision_preserves_outer_write(self) -> None:
        from z4j_brain.persistence.models import Project
        from z4j_brain.persistence.repositories.pending_fires import (
            PendingFiresRepository,
        )

        async with _idempotency_database() as (database, project_id, schedule_id):
            fire_id = uuid.uuid4()
            scheduled_for = datetime.now(UTC)
            arguments = {
                "fire_id": fire_id,
                "schedule_id": schedule_id,
                "project_id": project_id,
                "engine": "celery",
                "payload": {"task": "tasks.savepoint"},
                "scheduled_for": scheduled_for,
                "expires_at": scheduled_for + timedelta(hours=1),
            }
            async with database.session() as session:
                await PendingFiresRepository(session).buffer(**arguments)
                await session.commit()

            sentinel_id = uuid.uuid4()
            async with database.session() as session:
                session.add(
                    Project(id=sentinel_id, slug="outer-pending", name="Outer pending"),
                )
                await session.flush()
                await PendingFiresRepository(session).buffer(**arguments)
                await session.commit()
            async with database.session() as session:
                assert await session.get(Project, sentinel_id) is not None


# =====================================================================
# H-3 (worker): circuit breaker re-reads failure streak in disable txn
# =====================================================================


class TestR4CircuitBreakerReReadInDisableTxn:
    """Pre-fix: ``_disable_and_audit`` only re-checked is_enabled,
    not the failure streak. A successful fire landing between the
    breaker's tick read and the disable write still tripped the
    breaker on a healthy schedule. Post-fix: re-read recent_failures
    inside the disable transaction and bail if the streak no longer
    holds."""

    @pytest.mark.asyncio
    async def test_breaker_does_not_trip_when_streak_recovered(
        self,
    ) -> None:
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import StaticPool
        from z4j_brain.domain.audit_service import AuditService
        from z4j_brain.domain.workers.schedule_circuit_breaker import (
            ScheduleCircuitBreakerWorker,
        )
        from z4j_brain.persistence.base import Base
        from z4j_brain.persistence.database import DatabaseManager
        from z4j_brain.persistence.enums import ScheduleKind
        from z4j_brain.persistence.models import (
            Project,
            Schedule,
            ScheduleFire,
        )
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
                schedule_circuit_breaker_threshold=3,
            )
            project_id = uuid.uuid4()
            schedule_id = uuid.uuid4()

            now = datetime.now(UTC)
            async with db.session() as s:
                s.add(Project(id=project_id, slug="p", name="P"))
                s.add(
                    Schedule(
                        id=schedule_id,
                        project_id=project_id,
                        engine="celery",
                        scheduler="z4j-scheduler",
                        name="x",
                        task_name="t",
                        kind=ScheduleKind.CRON,
                        expression="* * * * *",
                        timezone="UTC",
                        args=[],
                        kwargs={},
                        is_enabled=True,
                    )
                )
                # Three failures in a row - breaker SHOULD trip.
                for offset_min in (3, 2, 1):
                    s.add(
                        ScheduleFire(
                            fire_id=uuid.uuid4(),
                            schedule_id=schedule_id,
                            project_id=project_id,
                            command_id=None,
                            status="acked_failed",
                            scheduled_for=now,
                            fired_at=now - timedelta(minutes=offset_min),
                        )
                    )
                await s.commit()

            worker = ScheduleCircuitBreakerWorker(
                db=db,
                settings=settings,
                audit=AuditService(settings),
            )

            # Race simulation: between the worker's tick() read
            # (which sees 3 failures) and the disable_and_audit
            # write, a successful fire lands. We trigger this by
            # calling _disable_and_audit DIRECTLY after pre-seeding
            # the schedule with a recovered streak.
            async with db.session() as s:
                # Insert a NEWER successful fire - this turns the
                # streak from "3 fails" into "1 success + 3 fails"
                # (newest first: success → fail → fail → fail).
                s.add(
                    ScheduleFire(
                        fire_id=uuid.uuid4(),
                        schedule_id=schedule_id,
                        project_id=project_id,
                        command_id=None,
                        status="acked_success",
                        scheduled_for=now,
                        fired_at=now,
                    )
                )
                await s.commit()

            # Now call _disable_and_audit as the breaker would have
            # called it had it ticked just before the success landed.
            async with db.session() as s:
                schedule = await s.get(Schedule, schedule_id)

            await worker._disable_and_audit(schedule, streak=3)

            # Post-fix the breaker re-reads recent_failures inside
            # the disable transaction; sees the success at the top
            # of the streak; bails without disabling. Schedule
            # stays enabled.
            async with db.session() as s:
                row = await s.get(Schedule, schedule_id)
                assert row.is_enabled is True, (
                    "circuit breaker tripped a healthy schedule (round-4 race fix regressed)"
                )
        finally:
            await engine.dispose()


# =====================================================================
# H-2 (worker): brain background workers per-tick advisory lock
# =====================================================================


class TestR4WorkerLeaderLock:
    """Pre-fix: every brain replica ran every worker tick - duplicate
    audit rows, duplicate dispatcher calls, etc.

    Post-fix: ``_with_leader_lock(worker_name)`` wraps each tick;
    only the replica that wins the per-worker advisory lock runs.
    """

    def test_lock_id_stable_across_invocations(self) -> None:
        from z4j_brain.domain.workers._leader_lock import _lock_id_for

        # Same worker name → same id (so multi-replica race for
        # the same lock).
        assert _lock_id_for("pending_fires_replay_worker") == _lock_id_for(
            "pending_fires_replay_worker"
        )
        # Different worker names → different ids (so prune +
        # breaker can run on different replicas in same window).
        assert _lock_id_for("pending_fires_replay_worker") != _lock_id_for(
            "schedule_circuit_breaker_worker"
        )

    def test_lock_id_in_signed_int_range(self) -> None:
        """Postgres pg_try_advisory_xact_lock takes a signed bigint;
        ids must fit in [0, 2^63 - 1]."""
        from z4j_brain.domain.workers._leader_lock import _lock_id_for

        ids = [
            _lock_id_for(name)
            for name in (
                "pending_fires_replay_worker",
                "schedule_circuit_breaker_worker",
                "schedule_fires_prune_worker",
            )
        ]
        for lock_id in ids:
            assert 0 <= lock_id < (1 << 63), f"lock id {lock_id} out of signed bigint range"

    @pytest.mark.asyncio
    async def test_sqlite_no_op_yields_true(self) -> None:
        """On SQLite the helper short-circuits and yields True
        unconditionally (single-writer DB → no contention possible)."""
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import StaticPool
        from z4j_brain.domain.workers._leader_lock import (
            acquire_per_worker_lock,
        )
        from z4j_brain.persistence.base import Base
        from z4j_brain.persistence.database import DatabaseManager

        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        try:
            db = DatabaseManager(engine)
            async with acquire_per_worker_lock(db, "x") as got:
                assert got is True
        finally:
            await engine.dispose()


# =====================================================================
# Notification idempotency on duplicate ack
# =====================================================================


class TestR4NotificationDedupOnDuplicateAck:
    """Pre-fix: two acks for the same fire_id (HA scheduler retry,
    network duplicate) each fanned out the notification trigger -
    operators got two pages for one failure.

    Post-fix: ScheduleFireRepository.acknowledge returns
    ``(row, was_first_ack)``; handler skips notification dispatch
    when ``was_first_ack is False``.
    """

    @pytest.mark.asyncio
    async def test_acknowledge_returns_was_first_ack(self) -> None:
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
        from z4j_brain.persistence.repositories import (
            ScheduleFireRepository,
        )

        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        try:
            db = DatabaseManager(engine)
            project_id = uuid.uuid4()
            schedule_id = uuid.uuid4()
            fire_id = uuid.uuid4()

            now = datetime.now(UTC)
            async with db.session() as s:
                s.add(Project(id=project_id, slug="p", name="P"))
                s.add(
                    Schedule(
                        id=schedule_id,
                        project_id=project_id,
                        engine="celery",
                        scheduler="z4j-scheduler",
                        name="x",
                        task_name="t",
                        kind=ScheduleKind.CRON,
                        expression="* * * * *",
                        timezone="UTC",
                        args=[],
                        kwargs={},
                        is_enabled=True,
                    )
                )
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

            async with db.session() as s:
                _row1, first1, _bs1 = await ScheduleFireRepository(
                    s,
                ).acknowledge(
                    fire_id=fire_id,
                    status="acked_failed",
                )
                await s.commit()
            assert first1 is True

            # Second ack for the same fire_id - duplicate.
            async with db.session() as s:
                _row2, first2, _bs2 = await ScheduleFireRepository(
                    s,
                ).acknowledge(
                    fire_id=fire_id,
                    status="acked_failed",
                )
                await s.commit()
            assert first2 is False, (
                "second ack must report was_first_ack=False so the "
                "handler can skip duplicate notification fan-out"
            )
        finally:
            await engine.dispose()


# =====================================================================
# Rate limiter refund on early-return paths
# =====================================================================


class TestR4RateLimiterRefund:
    """Pre-fix: FireSchedule consumed a token BEFORE validating the
    schedule (row lock, is_enabled). When the post-consume
    validation failed (schedule not found, disabled, binding
    rejected), the token charge persisted - operationally this
    over-charged the cert's bucket and could cause spurious 429s
    during mass-disable events.

    Post-fix: SchedulerRateLimiter.refund(cert_cn) returns the
    unspent token; the FireSchedule handler calls it on every
    early-return path.
    """

    @pytest.mark.asyncio
    async def test_refund_restores_token(self) -> None:
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import StaticPool
        from z4j_brain.domain.scheduler_rate_limiter import (
            SchedulerRateLimiter,
        )
        from z4j_brain.persistence.base import Base
        from z4j_brain.persistence.database import DatabaseManager
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
                scheduler_grpc_fire_rate_capacity=10.0,
                scheduler_grpc_fire_rate_per_second=0.01,
            )
            rl = SchedulerRateLimiter(db=db, settings=settings)
            # Drain the bucket.
            for _ in range(10):
                assert await rl.consume(cert_cn="c1") is True
            # 11th would deny.
            assert await rl.consume(cert_cn="c1") is False
            # Refund 1 - next consume should succeed.
            await rl.refund(cert_cn="c1", tokens=1.0)
            assert await rl.consume(cert_cn="c1") is True
        finally:
            await engine.dispose()


# =====================================================================
# Audit middleware: queue-based dispatch
# =====================================================================


class TestR4AuditQueue:
    """Pre-fix: middleware opened a NEW DB session per failed
    request to write the denial audit row. Under attack this
    doubled per-request connection demand, starving the pool.

    Post-fix: bounded async queue with single drain task; middleware
    enqueues fire-and-forget; over-cap events drop the oldest.
    """

    @pytest.mark.asyncio
    async def test_queue_drops_oldest_on_overflow(self) -> None:
        from z4j_brain.middleware._audit_queue import (
            AuditQueue,
            DenialAuditEvent,
        )

        q = AuditQueue()
        # Don't start the drain task; we want overflow.
        ev = DenialAuditEvent(
            action="schedules.access.denied",
            target_type="schedule_endpoint",
            target_id="/api/v1/projects/x/schedules",
            outcome="deny",
            user_id=None,
            project_slug="x",
            source_ip=None,
            user_agent=None,
            method="DELETE",
            error_class="AuthorizationError",
            message="x",
            occurred_at=datetime.now(UTC),
        )
        # Push past the cap (1024).
        for _ in range(1100):
            q.enqueue(ev)
        assert q.dropped_count > 0, (
            "queue must drop on overflow - pre-fix path would have blocked the request handler"
        )
