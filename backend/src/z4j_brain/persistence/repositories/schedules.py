"""``schedules`` repository."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import Schedule
from z4j_brain.persistence.repositories._base import BaseRepository


class ScheduleRepository(BaseRepository[Schedule]):
    """Schedule CRUD."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Schedule)

    async def list_for_project(
        self,
        project_id: UUID,
        *,
        limit: int | None = None,
        cursor_name: str | None = None,
        cursor_id: UUID | None = None,
    ) -> list[Schedule]:
        """List schedules for a project, ordered by ``(name, id)``.

        v1.1.0: gained keyset pagination params. Pre-1.1 the call
        was unbounded and returned every row in one shot, fine at
        small scale, but a project with 1000+ schedules pulled all
        of them into memory on every dashboard refresh. Operators
        on the new path pass ``limit + cursor`` for fixed-page
        responses; legacy callers omitting both still get the full
        unbounded list (back-compat, the endpoint layer enforces
        the cap going forward).

        The cursor is the ``(name, id)`` of the LAST row of the
        previous page; the next page starts strictly after it. The
        ``id`` tie-breaker prevents skips/dupes when multiple
        schedules share the same name (rare but possible across
        projects, within one project it's unique by constraint).
        """
        from sqlalchemy import and_, or_

        stmt = select(Schedule).where(Schedule.project_id == project_id)
        if cursor_name is not None and cursor_id is not None:
            stmt = stmt.where(
                or_(
                    Schedule.name > cursor_name,
                    and_(
                        Schedule.name == cursor_name,
                        Schedule.id > cursor_id,
                    ),
                ),
            )
        stmt = stmt.order_by(Schedule.name, Schedule.id)
        if limit is not None:
            stmt = stmt.limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_for_project(
        self,
        *,
        project_id: UUID,
        schedule_id: UUID,
    ) -> Schedule | None:
        """Resolve a schedule by id, scoped to a project.

        Returns ``None`` if the schedule exists but belongs to a
        different project - defends against IDOR via guessed UUIDs.
        """
        schedule = await self.get(schedule_id)
        if schedule is None or schedule.project_id != project_id:
            return None
        return schedule

    async def set_enabled(
        self,
        *,
        schedule_id: UUID,
        enabled: bool,
    ) -> bool:
        """Toggle the enabled flag. Returns True if a row was updated."""
        result = await self.session.execute(
            update(Schedule)
            .where(Schedule.id == schedule_id)
            .values(is_enabled=enabled, updated_at=datetime.now(UTC)),
        )
        return (result.rowcount or 0) > 0

    # ------------------------------------------------------------------
    # CRUD (Phase 3)
    # ------------------------------------------------------------------

    async def create_for_project(
        self,
        *,
        project_id: UUID,
        data: dict[str, Any],
    ) -> Schedule:
        """Insert a new schedule under ``(project_id, scheduler, name)``.

        Raises :class:`ValueError` on missing required fields or
        unknown ``kind`` enum value. Caller owns the transaction
        boundary.
        """
        from z4j_brain.persistence.enums import ScheduleKind

        name = str(data.get("name", "")).strip()
        if not name:
            raise ValueError("schedule.name is required")

        task_name = str(data.get("task_name", "")).strip()
        if not task_name:
            raise ValueError("schedule.task_name is required")

        kind_raw = str(data.get("kind", "")).strip()
        try:
            kind = ScheduleKind(kind_raw)
        except ValueError as exc:
            raise ValueError(
                f"schedule.kind {kind_raw!r} is not a recognised ScheduleKind",
            ) from exc

        row = Schedule(
            project_id=project_id,
            engine=str(data.get("engine", "celery")),
            scheduler=str(data.get("scheduler", "z4j-scheduler")),
            name=name,
            task_name=task_name,
            kind=kind,
            expression=str(data.get("expression", "")),
            timezone=str(data.get("timezone", "UTC")) or "UTC",
            queue=data.get("queue"),
            args=data.get("args") or [],
            kwargs=data.get("kwargs") or {},
            is_enabled=bool(data.get("is_enabled", True)),
            catch_up=str(data.get("catch_up", "skip")),
            source=str(data.get("source", "dashboard")),
            source_hash=data.get("source_hash"),
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def update_for_project(
        self,
        *,
        project_id: UUID,
        schedule_id: UUID,
        data: dict[str, Any],
    ) -> Schedule | None:
        """Apply a partial update. Returns ``None`` if the schedule is
        not in the project (IDOR-safe)."""
        from z4j_brain.persistence.enums import ScheduleKind

        existing = await self.get_for_project(
            project_id=project_id, schedule_id=schedule_id,
        )
        if existing is None:
            return None

        # Only fields present in ``data`` get touched; everything
        # else stays. Lets the dashboard PATCH a single field
        # without round-tripping every other column.
        for key, value in data.items():
            if key == "kind" and value is not None:
                value = ScheduleKind(str(value))  # noqa: PLW2901 - rebind on purpose
            if hasattr(existing, key):
                setattr(existing, key, value)
        existing.updated_at = datetime.now(UTC)
        await self.session.flush()
        return existing

    async def delete_for_project(
        self,
        *,
        project_id: UUID,
        schedule_id: UUID,
    ) -> bool:
        """Hard-delete one schedule. IDOR-safe.

        Cascades to ``pending_fires`` via the FK on schedule_id.
        Returns True iff a row was removed.
        """
        existing = await self.get_for_project(
            project_id=project_id, schedule_id=schedule_id,
        )
        if existing is None:
            return False
        await self.session.delete(existing)
        await self.session.flush()
        return True

    async def delete_by_source_except(
        self,
        *,
        project_id: UUID,
        source: str,
        keep_ids: set[UUID],
    ) -> int:
        """Delete every schedule with this source EXCEPT the given ids.

        Used by the declarative-reconciliation import mode
        (``replace_for_source``): the framework adapter sends a
        complete batch of schedules for one source label
        (e.g. ``"declarative_django"``), and brain treats absence
        from the batch as removal.

        Scoped to (project, source) so a Django app can manage its
        own declarative schedules without touching schedules from
        another framework or imported from celery-beat.

        Returns the number of rows deleted.
        """
        from sqlalchemy import delete as sa_delete

        stmt = sa_delete(Schedule).where(
            Schedule.project_id == project_id,
            Schedule.source == source,
        )
        if keep_ids:
            stmt = stmt.where(Schedule.id.notin_(keep_ids))
        result = await self.session.execute(stmt)
        return result.rowcount or 0


    async def reconcile_snapshot(
        self,
        *,
        project_id: UUID,
        scheduler: str,
        schedules: list[dict[str, Any]],
    ) -> dict[str, int]:
        """Reconcile every schedule the agent observes on one scheduler.

        The agent emits a ``schedule.snapshot`` event at boot, on a
        periodic timer, and on demand via the ``schedule.resync``
        command. The event carries the FULL inventory of every
        schedule the named scheduler adapter currently observes -
        the brain's job here is to make the DB match: insert new
        rows, update existing rows, and delete rows that exist in
        the brain for this (project, scheduler) but are NOT in the
        snapshot. Scoped to ``(project_id, scheduler)`` so a brain
        with multiple scheduler adapters in the same project (e.g.
        celery-beat AND apscheduler) does not cross-prune.

        Added in 1.3.3 alongside the new ``EventKind.SCHEDULE_SNAPSHOT``
        and the dashboard "Sync now" button. Closes the long-standing
        gap where existing celery-beat / rq-scheduler / apscheduler
        schedules were invisible to the dashboard until they were
        edited (because the agent's signal-based path only saw
        post-connect changes).

        Returns a summary dict ``{"inserted": N, "updated": M,
        "deleted": K}`` so the caller can log / report counts.
        """
        from sqlalchemy import delete as sa_delete

        summary = {"inserted": 0, "updated": 0, "deleted": 0}

        # 1) Upsert each schedule in the snapshot. Reuses the same
        # (project, name) key as ``upsert_from_event`` so the two
        # paths converge on the same row when both arrive (e.g.
        # the agent's signal-based ``schedule.created`` raced the
        # boot snapshot).
        observed_names: set[str] = set()
        for raw in schedules:
            if not isinstance(raw, dict):
                continue
            name = str(raw.get("name", "")).strip()
            if not name:
                continue
            observed_names.add(name)

            # Force the scheduler name to the snapshot's owning
            # adapter, the inner schedule dict may be missing it
            # or carry a stale value, but the snapshot's outer
            # ``scheduler`` field is the canonical source.
            enriched = dict(raw)
            enriched["scheduler"] = scheduler
            enriched.setdefault("engine", scheduler.split("-")[0] or scheduler)

            existed = await self.session.execute(
                select(Schedule.id).where(
                    Schedule.project_id == project_id,
                    Schedule.name == name,
                ),
            )
            had_row = existed.scalar_one_or_none() is not None
            await self.upsert_from_event(
                project_id=project_id, data=enriched,
            )
            if had_row:
                summary["updated"] += 1
            else:
                summary["inserted"] += 1

        # 2) Delete every (project, scheduler) row whose name is NOT
        # in the snapshot. Catches schedules deleted directly via
        # Django admin / SQL while the agent was offline (the
        # ``schedule.deleted`` event would have been lost).
        stmt = sa_delete(Schedule).where(
            Schedule.project_id == project_id,
            Schedule.scheduler == scheduler,
        )
        if observed_names:
            stmt = stmt.where(Schedule.name.notin_(observed_names))
        result = await self.session.execute(stmt)
        summary["deleted"] = result.rowcount or 0

        await self.session.flush()
        return summary

    async def upsert_from_event(
        self,
        *,
        project_id: UUID,
        data: dict[str, Any],
    ) -> Schedule:
        """Upsert a schedule from an agent-side schedule event.

        The event payload carries the full schedule data including
        a name which is unique per project. We use
        ``(project_id, name)`` as the upsert key.
        """
        name = str(data.get("name", ""))
        if not name:
            raise ValueError("schedule event missing name")

        result = await self.session.execute(
            select(Schedule).where(
                Schedule.project_id == project_id,
                Schedule.name == name,
            ),
        )
        existing = result.scalar_one_or_none()
        now = datetime.now(UTC)

        from z4j_brain.persistence.enums import ScheduleKind

        kind_raw = data.get("kind", "interval")
        try:
            kind = ScheduleKind(kind_raw)
        except ValueError:
            kind = ScheduleKind.INTERVAL

        values = {
            "engine": data.get("engine", "celery"),
            "scheduler": data.get("scheduler", "celery-beat"),
            "task_name": data.get("task_name", "unknown"),
            "kind": kind,
            "expression": data.get("expression", ""),
            "timezone": data.get("timezone", "UTC"),
            "queue": data.get("queue"),
            "args": data.get("args", []),
            "kwargs": data.get("kwargs", {}),
            "is_enabled": data.get("is_enabled", True),
            "last_run_at": _parse_dt(data.get("last_run_at")),
            "next_run_at": _parse_dt(data.get("next_run_at")),
            "total_runs": data.get("total_runs", 0),
        }

        if existing is None:
            row = Schedule(
                project_id=project_id,
                name=name,
                **values,
            )
            self.session.add(row)
            await self.session.flush()
            return row
        for key, value in values.items():
            setattr(existing, key, value)
        existing.updated_at = now
        await self.session.flush()
        return existing


def _parse_dt(value: Any) -> datetime | None:
    """Best-effort ISO-8601 parse, returns None on failure."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Import support (z4j-scheduler migration importers)
# ---------------------------------------------------------------------------

#: Outcome bucket for one row in a bulk import.
ImportRowOutcome = str  # "inserted" | "updated" | "unchanged"


async def upsert_imported_schedule(
    *,
    session: AsyncSession,
    project_id: UUID,
    data: dict[str, Any],
) -> tuple[ImportRowOutcome, Schedule]:
    """Insert or update one schedule from a migration importer payload.

    Identity is ``(project_id, scheduler, name)``. The same name can
    legitimately exist for two different schedulers in one project
    (e.g. the operator runs celery-beat AND z4j-scheduler in the
    same project during a migration cutover) so the scheduler field
    must participate in the conflict key.

    Idempotency: when the row already exists with the same
    ``source_hash``, this is a no-op and returns ``"unchanged"`` so
    the operator can re-run ``z4j-scheduler import`` and only see
    actual diffs land in the audit trail.

    Returns ``(outcome, row)`` where outcome is one of
    ``"inserted"`` / ``"updated"`` / ``"unchanged"`` and ``row`` is
    the upserted Schedule. The caller uses the row id to track
    survivors when running in ``replace_for_source`` import mode.

    Note: the caller is responsible for the surrounding transaction
    boundary - we do not commit here. The bulk import endpoint
    commits once after iterating the whole batch so a partial-write
    failure rolls back cleanly.
    """
    from z4j_brain.persistence.enums import ScheduleKind

    name = str(data.get("name", "")).strip()
    if not name:
        raise ValueError("imported schedule has empty name")

    scheduler = str(data.get("scheduler", "z4j-scheduler"))
    engine = str(data.get("engine", "celery"))
    task_name = str(data.get("task_name", ""))
    if not task_name:
        raise ValueError(f"imported schedule {name!r} has empty task_name")

    kind_raw = str(data.get("kind", "interval"))
    try:
        kind = ScheduleKind(kind_raw)
    except ValueError as exc:
        raise ValueError(
            f"imported schedule {name!r}: unknown kind {kind_raw!r}",
        ) from exc

    # Source-hash governs idempotency. If the operator's tooling
    # forgot to compute it, treat each import as fresh content
    # (we still write the row, just don't get the noop benefit).
    source_hash = data.get("source_hash") or None
    source = data.get("source") or "imported"

    new_values: dict[str, Any] = {
        "engine": engine,
        "task_name": task_name,
        "kind": kind,
        "expression": str(data.get("expression", "")),
        "timezone": str(data.get("timezone", "UTC")) or "UTC",
        "queue": data.get("queue"),
        "args": data.get("args") or [],
        "kwargs": data.get("kwargs") or {},
        "is_enabled": bool(data.get("is_enabled", True)),
        "catch_up": str(data.get("catch_up", "skip")),
        "source": source,
        "source_hash": source_hash,
    }

    result = await session.execute(
        select(Schedule).where(
            Schedule.project_id == project_id,
            Schedule.scheduler == scheduler,
            Schedule.name == name,
        ),
    )
    existing = result.scalar_one_or_none()

    if existing is None:
        row = Schedule(
            project_id=project_id,
            scheduler=scheduler,
            name=name,
            **new_values,
        )
        session.add(row)
        await session.flush()
        return "inserted", row

    # Re-import idempotency: same content hash AND existing row also
    # has a hash means nothing changed. We still touch updated_at?
    # No - keeping updated_at stable lets WatchSchedules treat the
    # noop as truly noop (it polls updated_at to detect diffs).
    if source_hash and existing.source_hash == source_hash:
        return "unchanged", existing

    for key, value in new_values.items():
        setattr(existing, key, value)
    existing.updated_at = datetime.now(UTC)
    await session.flush()
    return "updated", existing


__all__ = ["ScheduleRepository", "upsert_imported_schedule"]
