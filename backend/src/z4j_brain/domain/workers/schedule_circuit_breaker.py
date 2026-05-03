"""``ScheduleCircuitBreakerWorker`` - auto-disables flapping schedules.

A flapping schedule (one that fails every tick because of a code
bug, missing dependency, or expired credential) consumes brain
capacity and floods the dashboard with red. The circuit breaker
watches the recent fire history; once a schedule racks up
``Z4J_SCHEDULE_CIRCUIT_BREAKER_THRESHOLD`` consecutive failures
the worker:

1. Disables the schedule (``is_enabled=False``) so the scheduler
   stops ticking it. The WatchSchedules push will deliver the
   change to the scheduler within ~100ms.
2. Writes an audit row naming the schedule and the streak length
   so security ops can see "this got auto-disabled" instead of
   silent state drift.
3. Emits a ``schedule.fire.failed`` notification (Phase 4 step 5
   wires the dispatcher to fire one).

The worker only acts on streaks of CONSECUTIVE failures. A
schedule that fails 4 times then succeeds doesn't trip - the
breaker is for "broken", not "flaky."
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings

logger = logging.getLogger("z4j.brain.workers.schedule_circuit_breaker")


_FAILURE_STATUSES = frozenset({"failed", "acked_failed"})


class ScheduleCircuitBreakerWorker:
    """Periodic worker that auto-disables schedules with N consecutive failures."""

    def __init__(
        self,
        *,
        db: DatabaseManager,
        settings: Settings,
        audit: AuditService | None = None,
    ) -> None:
        self._db = db
        self._settings = settings
        self._audit = audit
        self._threshold = settings.schedule_circuit_breaker_threshold

    async def tick(self) -> None:
        if self._threshold <= 0:
            # Operator opted out via Z4J_SCHEDULE_CIRCUIT_BREAKER_THRESHOLD=0
            return

        from sqlalchemy import select  # noqa: PLC0415

        from z4j_brain.persistence.models import Schedule  # noqa: PLC0415
        from z4j_brain.persistence.repositories import (  # noqa: PLC0415
            AuditLogRepository,
            ScheduleFireRepository,
        )

        # Round-7 audit fix R7-HIGH (perf) (Apr 2026): the prior
        # version opened ONE fresh session per enabled schedule and
        # ran ``recent_failures`` per-schedule. At 10k enabled
        # schedules (the comment below admitted this was the design
        # ceiling) that was 10k sessions + 10k SELECTs per breaker
        # tick, burning a connection-pool slot per tick second and
        # blocking unrelated request paths on enterprise installs.
        #
        # New shape: ONE session, ONE listing of enabled schedules,
        # ONE window query that returns the latest ``threshold``
        # fires per schedule id, then evaluation in-process. Brings
        # tick cost to 2 round-trips regardless of fleet size.
        async with self._db.session() as session:
            result = await session.execute(
                select(Schedule).where(Schedule.is_enabled.is_(True)),
            )
            enabled_schedules = list(result.scalars().all())

            if not enabled_schedules:
                return

            schedule_ids = [s.id for s in enabled_schedules]
            fires_by_schedule = await ScheduleFireRepository(
                session,
            ).recent_failures_for_many(
                schedule_ids=schedule_ids,
                per_schedule_limit=self._threshold,
            )

        tripped: list[tuple[object, int]] = []  # (schedule, streak)
        for schedule in enabled_schedules:
            fires = fires_by_schedule.get(schedule.id, [])
            # Need at least ``threshold`` rows to consider tripping.
            # A new schedule with 2 failures shouldn't trip a
            # threshold of 5.
            if len(fires) < self._threshold:
                continue
            # All N most recent must be failures, in order, with no
            # success interleaved.
            if all(f.status in _FAILURE_STATUSES for f in fires):
                tripped.append((schedule, self._threshold))

        if not tripped:
            return

        # Disable + audit each tripped schedule in its own
        # transaction so one failed audit insert doesn't roll back
        # the others.
        for schedule, streak in tripped:
            try:
                await self._disable_and_audit(schedule, streak)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "z4j.brain.workers.schedule_circuit_breaker: "
                    "failed to trip schedule_id=%s",
                    schedule.id,
                )

    async def _disable_and_audit(self, schedule, streak: int) -> None:
        from datetime import UTC, datetime  # noqa: PLC0415

        from sqlalchemy import update  # noqa: PLC0415

        from z4j_brain.persistence.models import Schedule  # noqa: PLC0415
        from z4j_brain.persistence.repositories import (  # noqa: PLC0415
            AuditLogRepository,
            ScheduleFireRepository,
        )

        async with self._db.session() as session:
            # Re-check is_enabled inside the transaction in case an
            # operator manually disabled the schedule in between.
            current = await session.get(Schedule, schedule.id)
            if current is None or not current.is_enabled:
                return

            # Round-4 audit fix (Apr 2026): re-read the failure
            # streak inside this transaction. Pre-fix, ``tick()``
            # opened session A, evaluated the streak, closed it,
            # then ``_disable_and_audit`` opened session B with
            # only an ``is_enabled`` re-check - a successful fire
            # landing between A and B still tripped the breaker on
            # a healthy schedule. The race was flagged in the
            # round-2 audit and re-flagged in round-3 as still
            # open. We now query ``recent_failures`` again under
            # session B and bail if the streak no longer holds.
            fires = await ScheduleFireRepository(
                session,
            ).recent_failures(
                schedule_id=schedule.id,
                limit=self._threshold,
            )
            if len(fires) < self._threshold:
                return
            if not all(f.status in _FAILURE_STATUSES for f in fires):
                logger.info(
                    "z4j.brain.workers.schedule_circuit_breaker: "
                    "schedule_id=%s recovered between read and "
                    "disable; not tripping",
                    schedule.id,
                )
                return

            await session.execute(
                update(Schedule)
                .where(Schedule.id == schedule.id)
                .values(
                    is_enabled=False,
                    updated_at=datetime.now(UTC),
                ),
            )
            if self._audit is not None:
                await self._audit.record(
                    AuditLogRepository(session),
                    action="schedule.circuit_breaker.tripped",
                    target_type="schedule",
                    target_id=str(schedule.id),
                    result="success",
                    outcome="deny",  # the schedule's fires are now denied
                    user_id=None,
                    project_id=schedule.project_id,
                    source_ip=None,
                    metadata={
                        "name": schedule.name,
                        "scheduler": schedule.scheduler,
                        "engine": schedule.engine,
                        "consecutive_failures": streak,
                    },
                )
            await session.commit()
        logger.warning(
            "z4j.brain.workers.schedule_circuit_breaker: TRIPPED "
            "schedule_id=%s name=%r after %d consecutive failures",
            schedule.id, schedule.name, streak,
        )


class ScheduleFiresPruneWorker:
    """Periodic retention worker for the ``schedule_fires`` table.

    Drops rows older than ``Z4J_SCHEDULE_FIRES_RETENTION_DAYS``.
    Bounds the table at typical fire rates (10 schedules × 1
    fire/min × 30d ≈ 430k rows). Single DELETE per tick.
    """

    def __init__(self, *, db: DatabaseManager, settings: Settings) -> None:
        self._db = db
        self._settings = settings

    async def tick(self) -> None:
        from datetime import UTC, datetime, timedelta  # noqa: PLC0415

        from z4j_brain.persistence.repositories import (  # noqa: PLC0415
            ScheduleFireRepository,
        )

        cutoff = datetime.now(UTC) - timedelta(
            days=self._settings.schedule_fires_retention_days,
        )
        async with self._db.session() as session:
            removed = await ScheduleFireRepository(session).delete_older_than(
                cutoff=cutoff,
            )
            await session.commit()
        if removed:
            logger.info(
                "z4j.brain.workers.schedule_fires_prune: pruned %d row(s)",
                removed,
            )


__all__ = [
    "ScheduleCircuitBreakerWorker",
    "ScheduleFiresPruneWorker",
]
