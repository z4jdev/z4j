"""``ScheduleCircuitBreakerWorker`` - auto-disables flapping schedules.

A flapping schedule (one that fails every tick because of a code
bug, missing dependency, or expired credential) consumes brain
capacity and floods the dashboard with red. The circuit breaker
watches the recent fire history; once a schedule racks up
``Z4J_SCHEDULE_CIRCUIT_BREAKER_THRESHOLD`` consecutive failures
the worker:

1. Disables the schedule (``is_enabled=False``) so the scheduler
   stops ticking it. PostgreSQL wakes the legacy watch stream via
   LISTEN/NOTIFY; SQLite observes it on the configured poll interval.
2. Writes an audit row naming the schedule and the streak length
   so security ops can see "this got auto-disabled" instead of
   silent state drift.
3. Emits a ``schedule.fire.failed`` notification.

The worker only acts on streaks of CONSECUTIVE failures. A
schedule that fails 4 times then succeeds doesn't trip - the
breaker is for "broken", not "flaky."
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings

logger = logging.getLogger("z4j.brain.workers.schedule_circuit_breaker")


#: Fire statuses that count as a failure for the circuit breaker AND for the
#: consecutive-failure count the schedules list surfaces. Defined once: if the
#: API and the worker disagreed about what a failure is, the dashboard would
#: show a run that never trips or a schedule that trips with nothing showing.
FAILURE_STATUSES = frozenset({"failed", "acked_failed"})

#: Back-compat alias for the module-private name this used to have.
_FAILURE_STATUSES = FAILURE_STATUSES

#: How many of a schedule's newest fires the consecutive-failure count looks
#: at when the breaker is switched off. With the breaker on, the count looks
#: at ``threshold`` fires, because that is all the breaker itself examines.
CONSECUTIVE_FAILURES_WINDOW = 20


def retention_floor(settings: object) -> datetime | None:
    """Oldest ``fired_at`` a fire row can still have, or None with retention off.

    Both retention mechanisms remove rows by the age of ``fired_at``: the
    prune worker DELETEs ``fired_at < now - schedule_fires_retention_days``,
    and the PostgreSQL partition worker drops whole days of slots, whose
    fires are at least that old. A read bounded here therefore excludes
    nothing that still exists. It is deliberately NOT a bound on the
    partition key: a fire replayed from the buffer, or caught up for a
    missed slot, carries an old ``scheduled_for`` with a recent ``fired_at``,
    and a bound on the slot hid exactly those fires from the breaker. One
    day of slack absorbs the prune worker's cadence and the partition
    worker's date arithmetic.
    """
    days = int(getattr(settings, "schedule_fires_retention_days", 0) or 0)
    if days <= 0:
        return None
    return datetime.now(UTC) - timedelta(days=days + 1)


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

    def _retention_floor(self) -> datetime | None:
        """See :func:`retention_floor`; the same bound the API reads use."""
        return retention_floor(self._settings)

    async def tick(self) -> None:
        if self._threshold <= 0:
            # Operator opted out via Z4J_SCHEDULE_CIRCUIT_BREAKER_THRESHOLD=0
            return

        from sqlalchemy import select

        from z4j_brain.persistence.models import Schedule
        from z4j_brain.persistence.repositories import (
            ScheduleFireRepository,
        )

        # The prior version opened ONE fresh session per enabled schedule and
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
                fired_at_floor=self._retention_floor(),
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
            except Exception:
                logger.exception(
                    "z4j.brain.workers.schedule_circuit_breaker: failed to trip schedule_id=%s",
                    schedule.id,
                )

    async def _disable_and_audit(self, schedule, streak: int) -> None:
        from datetime import UTC, datetime

        from sqlalchemy import select, update

        from z4j_brain.persistence.models import Schedule
        from z4j_brain.persistence.repositories import (
            AuditLogRepository,
            ScheduleFireRepository,
        )
        from z4j_brain.persistence.repositories.schedule_control import (
            ScheduleControlRepository,
        )

        async with self._db.session(write=True) as session:
            # The global Boundary-D lock order is schedule before fire
            # evidence. Re-check under that lock so a concurrent accepted fire
            # cannot land between the streak proof and the disable.
            current = (
                await session.execute(
                    select(Schedule).where(Schedule.id == schedule.id).with_for_update(),
                )
            ).scalar_one_or_none()
            if current is None or not current.is_enabled:
                return

            # Re-read the failure streak inside this
            # transaction. Without this re-read, ``tick()`` would
            # open session A, evaluate the streak, close it, then
            # ``_disable_and_audit`` would open session B with
            # only an ``is_enabled`` re-check - a successful fire
            # landing between A and B would still trip the
            # breaker on a healthy schedule. We query
            # ``recent_failures`` again under session B and bail
            # if the streak no longer holds.
            fires = await ScheduleFireRepository(
                session,
            ).recent_failures(
                schedule_id=schedule.id,
                limit=self._threshold,
                fired_at_floor=self._retention_floor(),
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

            now = datetime.now(UTC)
            control = ScheduleControlRepository(session)
            if await control.control_is_active():
                if current.scheduler != "z4j-scheduler":
                    raise RuntimeError(
                        "external schedule circuit-breaker transition "
                        "requires Boundary-E epoch authority",
                    )
                updated = await control.update_current(
                    project_id=current.project_id,
                    schedule_id=current.id,
                    data={"is_enabled": False},
                    planning_at=now,
                )
                if updated is None:
                    return
            else:
                await session.execute(
                    update(Schedule)
                    .where(Schedule.id == schedule.id)
                    .values(
                        is_enabled=False,
                        updated_at=now,
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
            schedule.id,
            schedule.name,
            streak,
        )
        # Fan the trip out to project subscriptions (the 7 delivery
        # channels + in-app bell). The ``schedule.circuit_breaker.tripped``
        # trigger was subscribable since 1.6 but nothing ever emitted it,
        # the same vapor class as the removed task.slow. Best-effort AFTER
        # the disable+audit commit: a notification failure must never undo
        # or block the trip itself. Fires once per episode by construction
        # (the is_enabled re-check above makes the trip transition happen
        # exactly once).
        await self._dispatch_subscription_notification(schedule, streak)

    async def _dispatch_subscription_notification(self, schedule, streak: int) -> None:
        from z4j_brain.domain.notifications.service import (
            NotificationService,
        )

        try:
            async with self._db.session() as session:
                await NotificationService().evaluate_and_dispatch(
                    session=session,
                    project_id=schedule.project_id,
                    trigger="schedule.circuit_breaker.tripped",
                    resource_type="schedule",
                    # No task is involved; use the schedule id + name so
                    # the bell row + deep link resolve to the schedule.
                    task_id=str(schedule.id),
                    task_name=schedule.name,
                    engine=schedule.engine,
                    state="circuit_tripped",
                    queue=schedule.queue,
                    exception=(
                        f"schedule disabled by circuit breaker after "
                        f"{streak} consecutive failed fires"
                    ),
                )
        except Exception:
            logger.exception(
                "z4j.brain.workers.schedule_circuit_breaker: subscription "
                "notification dispatch failed for schedule_id=%s",
                schedule.id,
            )


class ScheduleFiresPruneWorker:
    """Periodic retention worker for the ``schedule_fires`` table.

    Drops rows older than ``Z4J_SCHEDULE_FIRES_RETENTION_DAYS``.
    Bounds the table at typical fire rates (10 schedules x 1
    fire/min x 30d ~= 430k rows). Single DELETE per tick.
    """

    def __init__(self, *, db: DatabaseManager, settings: Settings) -> None:
        self._db = db
        self._settings = settings

    async def tick(self) -> None:
        from datetime import UTC, datetime, timedelta

        from z4j_brain.persistence.repositories import (
            ScheduleFireRepository,
        )

        cutoff = datetime.now(UTC) - timedelta(
            days=self._settings.schedule_fires_retention_days,
        )
        async with self._db.session(write=True) as session:
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
    "CONSECUTIVE_FAILURES_WINDOW",
    "FAILURE_STATUSES",
    "ScheduleCircuitBreakerWorker",
    "ScheduleFiresPruneWorker",
    "retention_floor",
]
