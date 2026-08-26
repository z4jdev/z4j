"""``MisfireDetector`` - brain-side detection of missed schedule fires.

A *misfire* is an enabled schedule whose expected next fire has come
and gone without the scheduler firing it. The usual cause is the
scheduler process being **down or partitioned** -- which is exactly
why detection lives in the brain and not in the scheduler: a
scheduler-side check cannot report its own death. The scheduler's tick
engine already handles the *alive-but-behind* case (catch-up); this
worker covers the case the tick engine structurally cannot.

Each ``Z4J_SCHEDULER_MISFIRE_SWEEP_SECONDS`` tick this worker:

1. Loads every enabled ``interval`` / ``cron`` schedule.
2. Computes each schedule's expected next fire from its cadence,
   anchored on ``last_run_at`` (or ``created_at`` when it has never
   fired).
3. Flags any schedule whose expected fire is older than
   ``Z4J_SCHEDULER_MISFIRE_GRACE_SECONDS`` (default 60s).
4. For each newly-flagged schedule: writes a
   ``scheduler.misfire_detected`` audit row via the HMAC-chained log,
   fires any ``schedule.misfired`` automation rule (notify / etc.)
   through the same governed executor the task-event path uses, and
   fans the alert out to any ``schedule.misfired`` project subscription
   across the operator's delivery channels + in-app bell.

Safety properties (mirroring :class:`ReconciliationWorker` /
:class:`ScheduleCircuitBreakerWorker`):

- **No false positives.** Grace absorbs normal fire latency + gRPC
  jitter + clock skew. Kinds whose cadence the brain cannot compute
  (``solar`` needs a location; ``clocked`` is single-fire) are skipped,
  not guessed. A bad cron / interval expression is skipped, never
  flagged.
- **Alert once per misfire episode.** Dedup is keyed by
  ``(schedule_id, last_run_at)`` -- one alert per gap. When the
  scheduler recovers and fires, ``last_run_at`` advances and the next
  gap is a fresh episode. In-memory dedup is bounded to the enabled
  fleet and pruned each sweep; a brain restart or HA failover may
  re-alert at most once per schedule (fails toward visibility, never
  toward silence), and the rule engine's own circuit breaker caps any
  downstream firing storm.
- **Bounded per tick.** At most ``_MAX_MISFIRES_PER_SWEEP`` *new*
  alerts fire per sweep, so a full-scheduler outage that misfires the
  whole fleet at once alerts gradually rather than in one burst; the
  overflow is logged and picked up on the next tick.
- **Fault isolated.** One schedule's audit/automation failure is
  logged and skipped; the rest of the sweep continues.
- **Kill-switch aware.** Automation firing goes through
  ``AutomationExecutor.run_matching`` whose single rule-loading choke
  point honours the per-project ``automation_enabled`` flag.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from collections.abc import Callable

    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings

logger = logging.getLogger("z4j.brain.workers.misfire_detector")

#: Cap on how many NEW misfires we alert on per sweep. A scheduler
#: outage misfires every enabled schedule at once; without a cap the
#: brain would write thousands of audit rows and fan out thousands of
#: rule firings in a single tick. The dedup set means the overflow is
#: picked up on subsequent ticks, so nothing is lost -- it is spread
#: over a few sweeps.
_MAX_MISFIRES_PER_SWEEP = 200

#: How long a durable misfire-dedup claim is retained before the sweep
#: prunes it. Long enough that a schedule down for weeks is not re-alerted,
#: bounded so the ledger cannot grow without limit.
_ALERT_RETENTION_DAYS = 30

#: Interval-expression grammar shared with z4j-scheduler's
#: ``tick/interval.py``: ``"30s"`` / ``"5m"`` / ``"2h"`` / ``"1d"`` or a
#: bare integer (seconds, celery-beat style).
_INTERVAL_UNIT_SECONDS: dict[str, int] = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_INTERVAL_RE = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$")


def _as_utc(value: datetime | None) -> datetime | None:
    """Normalise a possibly-naive DB datetime to tz-aware UTC.

    Postgres returns tz-aware datetimes for ``DateTime(timezone=True)``
    columns; SQLite (test + homelab) returns naive ones. Treat naive as
    UTC so cadence math never mixes aware/naive operands.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _kind_value(kind: Any) -> str:
    return str(getattr(kind, "value", kind))


def parse_interval_seconds(expression: str | None) -> int | None:
    """Parse an interval expression to whole seconds, or None if invalid.

    Mirrors z4j-scheduler's interval grammar so misfire detection and
    the fire path agree on cadence.
    """
    match = _INTERVAL_RE.match(expression or "")
    if match is None:
        return None
    value = int(match.group(1))
    seconds = value * _INTERVAL_UNIT_SECONDS[match.group(2) or "s"]
    return seconds if seconds > 0 else None


def cron_next_fire(
    expression: str,
    timezone: str | None,
    after: datetime,
) -> datetime | None:
    """Next cron fire strictly after ``after``, in UTC, or None if the
    expression is invalid.

    Uses croniter (the same engine z4j-scheduler's ``tick/cron.py``
    wraps) so the misfire bound matches the real fire schedule,
    including timezone handling. A malformed expression returns None so
    the detector skips it rather than raising a false misfire.

    Timezones resolve through :func:`packaged_zoneinfo`, the pinned
    ``tzdata`` wheel, because that is what the scheduler ticks with. This
    used bare ``ZoneInfo``, which searches the host's
    ``/usr/share/zoneinfo`` first, and the shipped image really does
    disagree with the pin: ``python:3.14-slim-trixie`` carries IANA 2026b
    against the wheel's 2026a. Measured across every available zone they
    answer differently for exactly one, ``America/Vancouver``, from
    2026-11-01 -- so for that zone this function computed an expected fire
    an hour away from the one the scheduler actually produces, and the
    detector flagged a schedule that had missed nothing: an audit row, a
    ``schedule.misfired`` automation and a delivery fanout, every sweep,
    for a schedule running exactly on time. That contradicts this module's
    headline property, "No false positives", and the detector is on by
    default.

    The set moves whenever the pin moves, so re-derive it rather than
    trusting this list.

    This is the only always-on path in the brain that derives a fire time
    from a schedule's timezone; the other two (the schedules API validator
    and the scheduler's shadow comparator) were already moved to the
    packaged wheel and this one was missed.
    """
    from zoneinfo import ZoneInfoNotFoundError

    from z4j_brain.domain.schedule_runtime import packaged_zoneinfo

    try:
        tz = packaged_zoneinfo(timezone or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        # Unchanged on purpose: an unresolvable zone still degrades to UTC
        # rather than raising, and test_unknown_timezone_falls_back_to_utc
        # pins that as deliberate. Whether a silent UTC fallback can itself
        # manufacture a false misfire is a separate question from which
        # tzdb we read, and is not settled here.
        tz = UTC  # type: ignore[assignment]

    from croniter import croniter

    base = after.astimezone(UTC) if after.tzinfo else after.replace(tzinfo=UTC)
    base_local = base.astimezone(tz)
    try:
        nxt = croniter(expression, base_local).get_next(datetime)
    except Exception:
        return None
    if nxt.tzinfo is None:
        nxt = nxt.replace(tzinfo=tz)
    return nxt.astimezone(UTC)


class MisfireDetector:
    """Periodic worker that flags schedules the scheduler failed to fire."""

    def __init__(
        self,
        *,
        db: DatabaseManager,
        settings: Settings,
        audit: AuditService,
        dispatcher: object | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        """
        Args:
            db: Shared DatabaseManager.
            settings: Brain settings (grace + sweep knobs).
            audit: AuditService for the ``scheduler.misfire_detected``
                row and the automation firing chain.
            dispatcher: CommandDispatcher for automation actions. When
                None the worker still DETECTS + audits misfires but
                fires no rules (useful for tests / detection-only mode).
            clock: Wall-clock source. Override in tests.
        """
        self._db = db
        self._settings = settings
        self._audit = audit
        self._dispatcher = dispatcher
        self._clock = clock
        self._grace = timedelta(seconds=settings.scheduler_misfire_grace_seconds)

    async def tick(self) -> None:
        """One misfire-detection sweep. Safe to call repeatedly."""
        if self._settings.scheduler_misfire_sweep_seconds <= 0:
            return  # detection disabled by the operator

        from sqlalchemy import select

        from z4j_brain.persistence.enums import ScheduleKind
        from z4j_brain.persistence.models import Schedule

        now = self._clock()

        async with self._db.session() as session:
            result = await session.execute(
                select(Schedule).where(
                    Schedule.is_enabled.is_(True),
                    # A held schedule is deliberately not running, and pause
                    # leaves is_enabled true while freezing last_run_at, which
                    # is exactly the value this detector anchors on. Without
                    # this every pause produced a misfire incident: an audit
                    # row with result "failed", a schedule.misfired automation,
                    # and fanout to every delivery channel. One deliberate
                    # operator action reading as a credible outage.
                    Schedule.paused_at.is_(None),
                    # Only kinds whose cadence the brain can compute
                    # without a location (solar) or that fire more than
                    # once (clocked is single-shot).
                    Schedule.kind.in_(
                        [ScheduleKind.CRON, ScheduleKind.INTERVAL],
                    ),
                ),
            )
            schedules = list(result.scalars().all())

        misfired: list[tuple[Any, datetime]] = []
        for schedule in schedules:
            expected = self._expected_next_fire(schedule, now=now)
            if expected is None:
                continue
            if expected + self._grace >= now:
                continue  # on time (within grace)
            misfired.append((schedule, expected))

        # Drop episodes already claimed (durable + shared) BEFORE the cap so
        # the per-sweep burst limit applies to FRESH misfires and the
        # remainder self-heals over subsequent sweeps. Best-effort pre-filter
        # -- the per-episode claim below is still the authoritative
        # cross-replica dedup, so a filter miss can never double-alert.
        fresh = await self._filter_unclaimed(misfired)

        # Bound the burst; the remainder self-heals on the next sweep.
        capped = fresh[:_MAX_MISFIRES_PER_SWEEP]
        for schedule, expected in capped:
            # Dedup is now DURABLE + shared across replicas, not in-memory.
            # The episode key is (schedule_id, anchor) where anchor =
            # last_run_at (or created_at if never fired) -- stable while the
            # schedule stays down, advancing to a fresh episode only when it
            # fires again. Only the replica that WINS the claim alerts, so a
            # persistent misfire is alerted exactly once fleet-wide even
            # though leadership rotates tick to tick.
            anchor_at = schedule.last_run_at or schedule.created_at
            try:
                if not await self._claim_episode(schedule.id, anchor_at):
                    continue  # already alerted for this episode
            except Exception:
                logger.exception(
                    "z4j.brain.workers.misfire_detector: claim failed schedule_id=%s",
                    schedule.id,
                )
                continue
            try:
                await self._alert_misfire(schedule, expected=expected, now=now)
                # Operators alert on metrics, not the audit log: bump a
                # counter so a dead/partitioned scheduler is visible on a
                # dashboard, not only by scraping audit rows. Best-effort.
                try:
                    from z4j_brain.api.metrics import (
                        z4j_scheduler_misfires_detected_total,
                    )

                    z4j_scheduler_misfires_detected_total.labels(
                        project=str(schedule.project_id),
                    ).inc()
                except Exception:
                    from z4j_brain.api.metrics import record_swallowed

                    record_swallowed("misfire_detector", "misfire_metric")
            except Exception:
                logger.exception(
                    "z4j.brain.workers.misfire_detector: failed to alert schedule_id=%s",
                    schedule.id,
                )
                # Release the claim so a transient alert failure does not
                # permanently swallow this episode -- next sweep retries.
                await self._release_episode(schedule.id, anchor_at)

        # Retention: drop old claims so the dedup ledger stays bounded.
        await self._prune_claims(now)

        if capped:
            logger.warning(
                "z4j.brain.workers.misfire_detector: %d misfire(s) detected "
                "this sweep (%d fresh, %d over per-sweep cap)",
                len(capped),
                len(fresh),
                max(0, len(fresh) - len(capped)),
            )

    async def _filter_unclaimed(
        self,
        candidates: list[tuple[Any, datetime]],
    ) -> list[tuple[Any, datetime]]:
        """Drop candidates whose current episode is already claimed."""
        if not candidates:
            return []
        from z4j_brain.persistence.repositories import (
            MisfireAlertRepository,
        )

        schedule_ids = {s.id for s, _ in candidates}
        async with self._db.session() as session:
            claimed = await MisfireAlertRepository(session).existing_claims(
                schedule_ids=schedule_ids,
            )
        return [
            (schedule, expected)
            for schedule, expected in candidates
            if (schedule.id, schedule.last_run_at or schedule.created_at) not in claimed
        ]

    async def _claim_episode(self, schedule_id: UUID, anchor_at: datetime) -> bool:
        """Durably claim a misfire episode across the replica fleet.

        Returns True only for the replica that wins the claim (which then
        alerts); False if another replica or an earlier sweep already
        claimed it. Committed in its own transaction so the claim is
        visible to other replicas immediately.
        """
        from z4j_brain.persistence.repositories import (
            MisfireAlertRepository,
        )

        async with self._db.session() as session:
            claimed = await MisfireAlertRepository(session).claim(
                schedule_id=schedule_id,
                anchor_at=anchor_at,
            )
            if claimed:
                await session.commit()
            return claimed

    async def _release_episode(self, schedule_id: UUID, anchor_at: datetime) -> None:
        """Release a claim after a failed alert so the next sweep retries."""
        from z4j_brain.persistence.repositories import (
            MisfireAlertRepository,
        )

        try:
            async with self._db.session() as session:
                await MisfireAlertRepository(session).release(
                    schedule_id=schedule_id,
                    anchor_at=anchor_at,
                )
                await session.commit()
        except Exception:
            logger.exception(
                "z4j.brain.workers.misfire_detector: failed to release claim schedule_id=%s",
                schedule_id,
            )

    async def _prune_claims(self, now: datetime) -> None:
        """Best-effort retention: drop misfire claims older than the window."""
        from z4j_brain.persistence.repositories import (
            MisfireAlertRepository,
        )

        try:
            async with self._db.session() as session:
                await MisfireAlertRepository(session).prune(
                    older_than=now - timedelta(days=_ALERT_RETENTION_DAYS),
                )
                await session.commit()
        except Exception:
            from z4j_brain.api.metrics import record_swallowed

            record_swallowed("misfire_detector", "claim_prune")

    def _expected_next_fire(
        self,
        schedule: Any,
        *,
        now: datetime,
    ) -> datetime | None:
        """Compute the schedule's expected next fire, or None to skip.

        Anchored on ``last_run_at`` when the schedule has fired, else on
        ``created_at``. Returns None for kinds/expressions the brain
        cannot reason about, so the caller never raises a false misfire.
        """
        anchor = _as_utc(schedule.last_run_at) or _as_utc(schedule.created_at)
        if anchor is None:
            return None
        kind = _kind_value(schedule.kind)
        if kind == "interval":
            seconds = parse_interval_seconds(schedule.expression)
            if seconds is None:
                return None
            return anchor + timedelta(seconds=seconds)
        if kind == "cron":
            return cron_next_fire(schedule.expression, schedule.timezone, anchor)
        return None  # solar / clocked: not misfire-detectable here

    async def _alert_misfire(
        self,
        schedule: Any,
        *,
        expected: datetime,
        now: datetime,
    ) -> None:
        """Write the detection audit row + fire schedule.misfired rules."""
        from z4j_brain.persistence.repositories import (
            AuditLogRepository,
        )

        lateness = (now - expected).total_seconds()
        last_run = _as_utc(schedule.last_run_at)
        async with self._db.session(write=True) as session:
            await self._audit.record(
                AuditLogRepository(session),
                action="scheduler.misfire_detected",
                target_type="schedule",
                target_id=str(schedule.id),
                result="failed",
                outcome="error",
                project_id=schedule.project_id,
                metadata={
                    "name": schedule.name,
                    "scheduler": schedule.scheduler,
                    "engine": schedule.engine,
                    "kind": _kind_value(schedule.kind),
                    "expected_fire_at": expected.isoformat(),
                    "last_run_at": last_run.isoformat() if last_run else None,
                    "lateness_seconds": round(lateness, 3),
                    "grace_seconds": int(self._grace.total_seconds()),
                },
            )
            await session.commit()

        logger.warning(
            "z4j.brain.workers.misfire_detector: MISFIRE schedule_id=%s "
            "name=%r expected=%s late=%.1fs",
            schedule.id,
            schedule.name,
            expected.isoformat(),
            lateness,
        )

        # The detection audit is committed and the episode claim is HELD, so
        # this misfire is recorded exactly once. Automation firing and the
        # subscription fanout are INDEPENDENT best-effort side effects: a
        # failure in either must NOT propagate (which would make tick()
        # release the claim and write a DUPLICATE audit row next sweep) nor
        # block the other. Isolate them here so a poisoned automation session
        # cannot swallow the operator's subscription alert or re-audit the
        # episode. (A failed misfire firing is not retried -- the misfire is
        # already audited + alerted; matches how automation failures are
        # swallowed on the task-event path.)
        try:
            await self._fire_automation(schedule, expected=expected, now=now)
        except Exception:
            logger.exception(
                "z4j.brain.workers.misfire_detector: schedule.misfired "
                "automation failed for schedule_id=%s (audited; not re-run)",
                schedule.id,
            )
        await self._dispatch_subscription_notification(
            schedule,
            expected=expected,
            lateness=lateness,
        )

    async def _fire_automation(
        self,
        schedule: Any,
        *,
        expected: datetime,
        now: datetime,
    ) -> None:
        """Run ``schedule.misfired`` automation rules for one schedule.

        No-op when no dispatcher is wired (detection-only mode). The
        executor owns its per-rule transaction boundary + the per-project
        kill-switch check, exactly as on the task-event path.
        """
        if self._dispatcher is None:
            return
        from z4j_brain.domain.automation import (
            AutomationActionRunner,
            AutomationExecutor,
        )
        from z4j_brain.persistence.repositories.audit_log import (
            AuditLogRepository,
        )
        from z4j_brain.persistence.repositories.automation_rule import (
            AutomationRuleRepository,
        )

        fields: dict[str, Any] = {
            # A misfire is the ABSENCE of a task, so there is no task_id
            # / agent_id / exception / runtime. The matchable schedule
            # attributes (engine / queue / task_name) let a rule scope
            # to "any celery schedule" etc.; the rest is context for
            # notify templates.
            "task_id": None,
            "task_name": schedule.task_name,
            "engine": schedule.engine,
            "queue": schedule.queue,
            "priority": _kind_value(schedule.priority),
            "exception": None,
            "runtime_ms": None,
            "agent_id": None,
            "schedule_id": str(schedule.id),
            "schedule_name": schedule.name,
            "scheduled_for": expected.isoformat(),
        }
        executor = AutomationExecutor(
            audit=self._audit,
            runner=AutomationActionRunner(dispatcher=self._dispatcher),
        )
        async with self._db.session(write=True) as session:
            await executor.run_matching(
                session=session,
                rules_repo=AutomationRuleRepository(session),
                audit_log=AuditLogRepository(session),
                project_id=schedule.project_id,
                trigger="schedule.misfired",
                fields=fields,
                now=now,
                notify_coalesce_seconds=self._settings.automation_notify_coalesce_seconds,
            )

    async def _dispatch_subscription_notification(
        self,
        schedule: Any,
        *,
        expected: datetime,
        lateness: float,
    ) -> None:
        """Fan a ``schedule.misfired`` alert out to project subscriptions.

        This is the operator-facing path (the 7 delivery channels +
        in-app bell), independent of automation rules and of the command
        dispatcher -- so misfire alerting works even in a brain that has
        no automation rules armed. Best-effort: a notification failure
        must never break detection, so it is caught and logged. Its own
        session because ``evaluate_and_dispatch`` opens deliveries that
        can outlast the detection write.
        """
        from z4j_brain.domain.notifications.service import (
            NotificationService,
        )

        try:
            async with self._db.session() as session:
                await NotificationService().evaluate_and_dispatch(
                    session=session,
                    project_id=schedule.project_id,
                    trigger="schedule.misfired",
                    resource_type="schedule",
                    # No real fire happened; use the schedule id + name so
                    # the bell row + deep link resolve to the schedule.
                    task_id=str(schedule.id),
                    task_name=schedule.name,
                    engine=schedule.engine,
                    state="misfired",
                    queue=schedule.queue,
                    exception=(
                        f"missed scheduled fire at {expected.isoformat()} ({int(lateness)}s late)"
                    ),
                )
        except Exception:
            logger.exception(
                "z4j.brain.workers.misfire_detector: subscription "
                "notification dispatch failed for schedule_id=%s",
                schedule.id,
            )


__all__ = [
    "MisfireDetector",
    "cron_next_fire",
    "parse_interval_seconds",
]
