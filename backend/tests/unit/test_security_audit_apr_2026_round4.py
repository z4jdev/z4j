"""Regression tests for the round-4 race-condition audit (Apr 2026).

Pins the 8 HIGH + 4 MEDIUM fixes from the deep race audit. Race
conditions are notoriously hard to trigger reliably in unit tests
- these tests pin the *invariants* the fixes establish (e.g.
"command insert is idempotent on collision", "total_runs uses a
SQL increment", "circuit breaker re-reads failure streak in
disable txn") so a future refactor can't silently regress.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest


# =====================================================================
# H-R4-1: total_runs SQL-side increment (atomicity)
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

    def test_handler_uses_sql_expression_for_increment(self) -> None:
        from pathlib import Path

        src = (
            Path(__file__).resolve().parents[2]
            / "src" / "z4j_brain" / "scheduler_grpc" / "handlers.py"
        ).read_text()
        # Verify the SQL-expression form is in the handler. A
        # regression to ``(schedule.total_runs or 0) + 1`` would
        # silently re-introduce the lost-increment race.
        assert "Schedule.total_runs + 1" in src, (
            "AcknowledgeFireResult must use SQL-side increment to "
            "avoid lost-update race under concurrent acks"
        )


# =====================================================================
# H-R4-2: CommandRepository.insert idempotency
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
                row1 = await CommandRepository(s).insert(
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
            async with db.session() as s:
                row2 = await CommandRepository(s).insert(
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
                    "duplicate idempotency_key must return existing "
                    "row, not raise"
                )
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_no_idempotency_key_still_raises_on_duplicate(
        self,
    ) -> None:
        """Without an idempotency_key, the caller hasn't opted into
        dedup - duplicate inserts (which are very unlikely without
        a key) should surface the underlying error."""
        # The model's idempotency_key column has no unique constraint
        # when null; this test just verifies the no-key branch
        # doesn't silently swallow. We assert by inspecting source
        # because the SQL behavior depends on the constraint shape.
        from pathlib import Path

        src = (
            Path(__file__).resolve().parents[2]
            / "src" / "z4j_brain" / "persistence" / "repositories"
            / "commands.py"
        ).read_text()
        assert "if idempotency_key is None:" in src, (
            "idempotent branch must short-circuit on missing key"
        )
        # Specifically the comment / flow that re-raises.
        assert "raise" in src.split("if idempotency_key is None:")[1][:200]


# =====================================================================
# H-R4-3 / H-1 (worker): SAVEPOINT in repository idempotency paths
# =====================================================================


class TestR4SavepointPattern:
    """Pre-fix: ``record()`` and ``buffer()`` called
    ``self.session.rollback()`` on IntegrityError, which wiped the
    caller's outer transaction (releasing FOR UPDATE locks +
    discarding queued writes). Post-fix: ``begin_nested()`` so only
    the failed INSERT rolls back."""

    def test_schedule_fires_uses_begin_nested(self) -> None:
        from pathlib import Path

        src = (
            Path(__file__).resolve().parents[2]
            / "src" / "z4j_brain" / "persistence" / "repositories"
            / "schedule_fires.py"
        ).read_text()
        assert "begin_nested" in src, (
            "schedule_fires.record must use SAVEPOINT to scope "
            "rollback to the failed insert"
        )

    def test_commands_uses_begin_nested(self) -> None:
        from pathlib import Path

        src = (
            Path(__file__).resolve().parents[2]
            / "src" / "z4j_brain" / "persistence" / "repositories"
            / "commands.py"
        ).read_text()
        assert "begin_nested" in src, (
            "commands.insert must use SAVEPOINT to scope rollback "
            "to the failed insert"
        )

    def test_pending_fires_uses_begin_nested(self) -> None:
        from pathlib import Path

        src = (
            Path(__file__).resolve().parents[2]
            / "src" / "z4j_brain" / "persistence" / "repositories"
            / "pending_fires.py"
        ).read_text()
        assert "begin_nested" in src, (
            "pending_fires.buffer must use SAVEPOINT to scope "
            "rollback to the failed insert"
        )


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
            Project, Schedule, ScheduleFire,
        )
        from z4j_brain.persistence.repositories import (
            ScheduleFireRepository,
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
                environment="dev", log_json=False,
                schedule_circuit_breaker_threshold=3,
            )
            project_id = uuid.uuid4()
            schedule_id = uuid.uuid4()

            now = datetime.now(UTC)
            async with db.session() as s:
                s.add(Project(id=project_id, slug="p", name="P"))
                s.add(Schedule(
                    id=schedule_id, project_id=project_id,
                    engine="celery", scheduler="z4j-scheduler",
                    name="x", task_name="t",
                    kind=ScheduleKind.CRON, expression="* * * * *",
                    timezone="UTC", args=[], kwargs={},
                    is_enabled=True,
                ))
                # Three failures in a row - breaker SHOULD trip.
                for offset_min in (3, 2, 1):
                    s.add(ScheduleFire(
                        fire_id=uuid.uuid4(),
                        schedule_id=schedule_id,
                        project_id=project_id,
                        command_id=None,
                        status="acked_failed",
                        scheduled_for=now,
                        fired_at=now - timedelta(minutes=offset_min),
                    ))
                await s.commit()

            worker = ScheduleCircuitBreakerWorker(
                db=db, settings=settings, audit=AuditService(settings),
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
                s.add(ScheduleFire(
                    fire_id=uuid.uuid4(),
                    schedule_id=schedule_id,
                    project_id=project_id,
                    command_id=None,
                    status="acked_success",
                    scheduled_for=now,
                    fired_at=now,
                ))
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
                    "circuit breaker tripped a healthy schedule "
                    "(round-4 race fix regressed)"
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
        assert (
            _lock_id_for("pending_fires_replay_worker")
            == _lock_id_for("pending_fires_replay_worker")
        )
        # Different worker names → different ids (so prune +
        # breaker can run on different replicas in same window).
        assert (
            _lock_id_for("pending_fires_replay_worker")
            != _lock_id_for("schedule_circuit_breaker_worker")
        )

    def test_lock_id_in_signed_int_range(self) -> None:
        """Postgres pg_try_advisory_xact_lock takes a signed bigint;
        ids must fit in [0, 2^63 - 1]."""
        from z4j_brain.domain.workers._leader_lock import _lock_id_for

        ids = [
            _lock_id_for(name) for name in (
                "pending_fires_replay_worker",
                "schedule_circuit_breaker_worker",
                "schedule_fires_prune_worker",
            )
        ]
        for lock_id in ids:
            assert 0 <= lock_id < (1 << 63), (
                f"lock id {lock_id} out of signed bigint range"
            )

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
            Project, Schedule, ScheduleFire,
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
                s.add(Schedule(
                    id=schedule_id, project_id=project_id,
                    engine="celery", scheduler="z4j-scheduler",
                    name="x", task_name="t",
                    kind=ScheduleKind.CRON, expression="* * * * *",
                    timezone="UTC", args=[], kwargs={},
                    is_enabled=True,
                ))
                s.add(ScheduleFire(
                    fire_id=fire_id, schedule_id=schedule_id,
                    project_id=project_id, command_id=None,
                    status="delivered",
                    scheduled_for=now, fired_at=now,
                ))
                await s.commit()

            async with db.session() as s:
                row1, first1 = await ScheduleFireRepository(
                    s,
                ).acknowledge(
                    fire_id=fire_id, status="acked_failed",
                )
                await s.commit()
            assert first1 is True

            # Second ack for the same fire_id - duplicate.
            async with db.session() as s:
                row2, first2 = await ScheduleFireRepository(
                    s,
                ).acknowledge(
                    fire_id=fire_id, status="acked_failed",
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
                environment="dev", log_json=False,
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
            AuditQueue, DenialAuditEvent,
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
            "queue must drop on overflow - pre-fix path would have "
            "blocked the request handler"
        )
