"""``schedule_fires`` repository.

Three operation surfaces:

- :meth:`record` - the FireSchedule handler creates a row when
  it dispatches (status=delivered/buffered/failed).
- :meth:`acknowledge` - the AcknowledgeFireResult handler updates
  the row with ack outcome + latency.
- :meth:`list_recent_for_schedule` / :meth:`recent_failures` -
  read paths for the dashboard + circuit breaker worker.

Inserts are idempotent on ``fire_id`` so a scheduler retry doesn't
duplicate the row. Updates are bounded WHERE-clauses so the
acknowledge path can't accidentally rewrite history.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import ScheduleFire


class ScheduleFireRepository:
    """``schedule_fires`` table CRUD."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def record(
        self,
        *,
        fire_id: UUID,
        schedule_id: UUID,
        project_id: UUID,
        command_id: UUID | None,
        status: str,
        scheduled_for: datetime,
        fired_at: datetime | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> ScheduleFire:
        """Insert one fire row. Idempotent on ``fire_id``.

        A second insert of the same fire_id upgrades the row's
        ``status`` (e.g. ``buffered → delivered``) and returns the
        updated row. Lets the FireSchedule retry path + the
        pending-fires replay worker write the row blindly without
        TOCTOU concerns.

        Round-4 audit fix (Apr 2026): the previous
        ``session.rollback()`` on IntegrityError wiped the caller's
        ENTIRE outer transaction (releasing FOR UPDATE locks +
        discarding queued audit/dispatcher writes). Replaced with a
        SAVEPOINT (``begin_nested``) so only the failed INSERT
        rolls back. Also: previously the upgrade case (buffered →
        delivered) was a no-op; now we update the row's status +
        command_id so the dashboard's "buffered" state correctly
        progresses to "delivered" once the agent comes online.
        """
        row = ScheduleFire(
            fire_id=fire_id,
            schedule_id=schedule_id,
            project_id=project_id,
            command_id=command_id,
            status=status,
            scheduled_for=scheduled_for,
            fired_at=fired_at or datetime.now(UTC),
            error_code=error_code,
            error_message=(
                error_message[:2000] if error_message else None
            ),
        )
        try:
            async with self.session.begin_nested():
                self.session.add(row)
                await self.session.flush()
        except IntegrityError:
            existing = await self._get_by_fire_id(fire_id)
            if existing is None:
                raise
            # Upgrade transitions: buffered → delivered/failed,
            # delivered → acked_*. Do NOT downgrade an acked row
            # back to delivered (a late retry of FireSchedule for
            # an already-acked fire would otherwise rewrite
            # history). _UPGRADE_TRANSITIONS encodes the
            # permitted state machine.
            if _is_status_upgrade(existing.status, status):
                existing.status = status
                if command_id is not None:
                    existing.command_id = command_id
                if error_code is not None:
                    existing.error_code = error_code[:64]
                if error_message is not None:
                    existing.error_message = error_message[:2000]
                await self.session.flush()
            return existing
        return row

    async def acknowledge(
        self,
        *,
        fire_id: UUID,
        status: str,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> tuple[ScheduleFire | None, bool]:
        """Update an existing row with the ack outcome + latency.

        Returns ``(row, was_first_ack)`` where:
        - ``row`` is the updated row, or ``None`` if no row exists
          for this ``fire_id``.
        - ``was_first_ack`` is True iff the row was previously
          un-acked (``acked_at IS NULL``). False on a duplicate ack
          (HA scheduler retry, network duplicate).

        Round-4 audit fix (Apr 2026): callers use ``was_first_ack``
        to skip duplicate notification dispatch. Pre-fix two acks
        for the same fire_id (HA scheduler retry, network blip)
        would each fan out a notification → operators got two
        "Schedule X failed" alerts for one failure.

        ``latency_ms`` is computed here from
        ``acked_at - fired_at`` so callers don't have to.
        """
        row = await self._get_by_fire_id(fire_id)
        if row is None:
            return None, False
        was_first_ack = row.acked_at is None
        now = datetime.now(UTC)
        row.acked_at = now
        row.status = status
        if error_code is not None:
            row.error_code = error_code[:64]
        if error_message is not None:
            row.error_message = error_message[:2000]
        # Compute latency. SQLite drops tz info on stored timestamps
        # so ``row.fired_at`` may come back naive even though we
        # wrote it tz-aware. Normalise both sides to naive UTC for
        # the subtraction. Postgres preserves tz; the
        # replace(tzinfo=None) is a no-op on already-naive values.
        if row.fired_at is not None:
            now_naive = now.replace(tzinfo=None)
            fired_at_naive = (
                row.fired_at.replace(tzinfo=None)
                if row.fired_at.tzinfo is not None
                else row.fired_at
            )
            delta = (now_naive - fired_at_naive).total_seconds() * 1000
            row.latency_ms = int(max(0, delta))
        await self.session.flush()
        return row, was_first_ack

    async def list_recent_for_schedule(
        self,
        *,
        schedule_id: UUID,
        project_id: UUID,
        limit: int = 100,
    ) -> list[ScheduleFire]:
        """Newest-first fire history for one schedule.

        Project-scoped to defend against IDOR via guessed
        schedule_ids. Returns at most ``limit`` rows.
        """
        result = await self.session.execute(
            select(ScheduleFire)
            .where(
                ScheduleFire.schedule_id == schedule_id,
                ScheduleFire.project_id == project_id,
            )
            .order_by(ScheduleFire.fired_at.desc())
            .limit(limit),
        )
        return list(result.scalars().all())

    async def recent_failures(
        self,
        *,
        schedule_id: UUID,
        limit: int,
    ) -> list[ScheduleFire]:
        """Last N fires for circuit-breaker evaluation.

        Returns the LAST N rows regardless of status. The caller
        decides whether the streak is consecutive-failed (i.e.
        every row in the slice has ``status in ('failed',
        'acked_failed')``). Fetching all-status rows lets the
        worker distinguish "10 failures in a row" from "5 failures
        and 5 successes interleaved" - the second is healthy.
        """
        result = await self.session.execute(
            select(ScheduleFire)
            .where(ScheduleFire.schedule_id == schedule_id)
            .order_by(ScheduleFire.fired_at.desc())
            .limit(limit),
        )
        return list(result.scalars().all())

    async def recent_failures_for_many(
        self,
        *,
        schedule_ids: list[UUID],
        per_schedule_limit: int,
    ) -> dict[UUID, list[ScheduleFire]]:
        """Bulk variant of :meth:`recent_failures`.

        Round-7 audit fix R7-HIGH (perf) (Apr 2026): the
        ScheduleCircuitBreaker tick used to call
        :meth:`recent_failures` once per enabled schedule (10k
        SELECTs + 10k sessions for a 10k-fleet). This single-query
        variant returns the most-recent ``per_schedule_limit`` rows
        for every supplied id in one round-trip via
        ``ROW_NUMBER() OVER (PARTITION BY schedule_id ORDER BY
        fired_at DESC)``.

        On SQLite (no window function in older builds) we fall back
        to a single ``WHERE schedule_id IN (...)`` then sort + slice
        in Python. Acceptable for dev because SQLite installs are
        single-tenant.
        """
        from sqlalchemy import and_, select as _select  # noqa: PLC0415

        if not schedule_ids:
            return {}
        dialect = (
            self.session.bind.dialect.name
            if self.session.bind is not None else ""
        )
        out: dict[UUID, list[ScheduleFire]] = {sid: [] for sid in schedule_ids}
        if dialect == "postgresql":
            from sqlalchemy import func as _func, over  # noqa: PLC0415

            row_num = _func.row_number().over(
                partition_by=ScheduleFire.schedule_id,
                order_by=ScheduleFire.fired_at.desc(),
            ).label("rn")
            inner = (
                _select(ScheduleFire, row_num)
                .where(ScheduleFire.schedule_id.in_(schedule_ids))
                .subquery()
            )
            from sqlalchemy.orm import aliased  # noqa: PLC0415

            sf = aliased(ScheduleFire, inner)
            stmt = (
                _select(sf)
                .where(inner.c.rn <= per_schedule_limit)
                .order_by(
                    sf.schedule_id, sf.fired_at.desc(),
                )
            )
            result = await self.session.execute(stmt)
            for fire in result.scalars().all():
                out[fire.schedule_id].append(fire)
            return out
        # SQLite fallback: one IN-list query, sort + slice in Python.
        stmt = (
            _select(ScheduleFire)
            .where(ScheduleFire.schedule_id.in_(schedule_ids))
            .order_by(
                ScheduleFire.schedule_id, ScheduleFire.fired_at.desc(),
            )
        )
        result = await self.session.execute(stmt)
        for fire in result.scalars().all():
            bucket = out[fire.schedule_id]
            if len(bucket) < per_schedule_limit:
                bucket.append(fire)
        return out

    async def delete_older_than(
        self, *, cutoff: datetime,
    ) -> int:
        """Sweep rows older than ``cutoff``. Returns rows deleted.

        Called by the periodic retention worker. The 30-day default
        keeps the table bounded at typical fire rates (10 schedules
        × 1 fire/min × 30d ≈ 430k rows).
        """
        result = await self.session.execute(
            delete(ScheduleFire).where(ScheduleFire.fired_at < cutoff),
        )
        return result.rowcount or 0

    async def _get_by_fire_id(self, fire_id: UUID) -> ScheduleFire | None:
        result = await self.session.execute(
            select(ScheduleFire).where(ScheduleFire.fire_id == fire_id),
        )
        return result.scalar_one_or_none()


# Permitted ``status`` transitions for the upgrade-on-conflict path
# in :meth:`ScheduleFireRepository.record`. Encodes the contract:
# - ``buffered`` is the entry state when no agent is online
# - ``delivered`` / ``failed`` follow once dispatch attempts
# - ``acked_*`` is terminal (do NOT downgrade back to delivered)
#
# A late retry of FireSchedule for an already-acked fire would
# otherwise overwrite the ack outcome - this map blocks that.
_UPGRADE_TRANSITIONS: dict[str, frozenset[str]] = {
    "pending": frozenset({
        "buffered", "delivered", "failed",
        "acked_success", "acked_failed",
    }),
    "buffered": frozenset({
        "delivered", "failed", "acked_success", "acked_failed",
    }),
    "delivered": frozenset({"acked_success", "acked_failed", "failed"}),
    "failed": frozenset({"acked_success", "acked_failed"}),
    # ``acked_*`` are terminal - no upgrade.
    "acked_success": frozenset(),
    "acked_failed": frozenset(),
}


def _is_status_upgrade(current: str, proposed: str) -> bool:
    """True if ``proposed`` is a permitted forward transition.

    Used by :meth:`ScheduleFireRepository.record` to decide
    whether a late retry of FireSchedule for an existing fire_id
    should overwrite the row's status, or leave it alone (the
    proposed status would be a downgrade or sideways move).
    """
    if current == proposed:
        return False  # no-op
    return proposed in _UPGRADE_TRANSITIONS.get(current, frozenset())


__all__ = ["ScheduleFireRepository"]
