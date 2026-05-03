"""``pending_fires`` repository.

Wraps the small set of operations the FireSchedule handler and the
replay worker need:

- :meth:`buffer` - insert a new pending fire (called by FireSchedule
  when no agent is online and the schedule's catch_up policy buffers)
- :meth:`list_for_replay` - oldest-first by ``scheduled_for`` for one
  ``(project_id, engine)`` pair (called by the replay worker once an
  agent comes online)
- :meth:`delete_by_fire_id` - clean up after a successful replay
- :meth:`delete_expired` - sweep expired buffers (the catch-up window
  passed without an agent ever coming online)
- :meth:`count_for_schedule` - observability surface for dashboard

Implementation notes:

- Inserts are idempotent on ``fire_id`` (UNIQUE). A re-insert of the
  same fire_id is treated as "the buffer already has it" and the
  existing row is returned rather than raising.
- The repository never commits - the caller owns the transaction
  boundary. Matches the convention used by every other brain
  repository.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import PendingFire


class PendingFiresRepository:
    """``pending_fires`` table CRUD."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def buffer(
        self,
        *,
        fire_id: UUID,
        schedule_id: UUID,
        project_id: UUID,
        engine: str,
        payload: dict[str, Any],
        scheduled_for: datetime,
        expires_at: datetime,
    ) -> PendingFire:
        """Insert a buffered fire. Idempotent on ``fire_id``.

        Round-4 audit fix (Apr 2026): use a SAVEPOINT
        (``begin_nested``) on IntegrityError so the failed INSERT
        rolls back without wiping the caller's outer transaction.
        Pre-fix the ``session.rollback()`` released FOR UPDATE
        locks the FireSchedule handler held on the schedule row.
        """
        row = PendingFire(
            fire_id=fire_id,
            schedule_id=schedule_id,
            project_id=project_id,
            engine=engine,
            payload=payload,
            scheduled_for=scheduled_for,
            enqueued_at=datetime.now(UTC),
            expires_at=expires_at,
        )
        try:
            async with self.session.begin_nested():
                self.session.add(row)
                await self.session.flush()
        except IntegrityError:
            existing = await self._get_by_fire_id(fire_id)
            if existing is None:
                raise  # the IntegrityError came from somewhere else
            return existing
        return row

    async def list_for_replay(
        self,
        *,
        project_id: UUID,
        engine: str,
        limit: int = 1000,
    ) -> list[PendingFire]:
        """Return buffered fires for one (project, engine), oldest first.

        Round-4 audit fix (Apr 2026): on Postgres we use ``SELECT
        ... FOR UPDATE SKIP LOCKED`` so multi-replica brain
        workers cannot pick the same row. Pre-fix two replay
        workers running in parallel both fetched the same fire_id,
        both called ``dispatcher.issue`` (which now dedupes via
        commands.idempotency_key but still costs a round-trip),
        and one of them left the buffer row stuck because the
        ``IntegrityError`` was previously swallowed.

        SQLite doesn't support ``SKIP LOCKED`` and only one writer
        runs at a time anyway, so the lock falls through harmlessly.

        ``limit`` caps the batch so the replay worker doesn't
        materialise an unbounded list when an agent comes online
        after a long outage. The worker calls again on the next
        tick to drain the rest.
        """
        stmt = (
            select(PendingFire)
            .where(
                PendingFire.project_id == project_id,
                PendingFire.engine == engine,
            )
            .order_by(PendingFire.scheduled_for)
            .limit(limit)
        )
        # Postgres-only: row-level lock + skip rows already locked
        # by a sibling worker. No-op on SQLite (driver ignores).
        if self.session.bind.dialect.name == "postgresql":
            stmt = stmt.with_for_update(skip_locked=True)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def delete_by_fire_id(self, fire_id: UUID) -> bool:
        """Remove one buffered fire after successful replay.

        Returns True if a row was actually deleted (False = nothing
        to delete, e.g. the operator manually cleared the row).
        """
        result = await self.session.execute(
            delete(PendingFire).where(PendingFire.fire_id == fire_id),
        )
        return (result.rowcount or 0) > 0

    async def delete_expired(self, *, now: datetime | None = None) -> int:
        """Sweep buffers past their expiry window.

        Called by the periodic sweep worker. Returns the number of
        rows removed so the worker can emit a metric.
        """
        cutoff = now or datetime.now(UTC)
        result = await self.session.execute(
            delete(PendingFire).where(PendingFire.expires_at < cutoff),
        )
        return result.rowcount or 0

    async def count_for_schedule(self, schedule_id: UUID) -> int:
        """How many buffered fires exist for one schedule.

        Used by the dashboard to render a "N fires waiting" badge so
        the operator notices long agent outages before they bite.
        """
        from sqlalchemy import func

        result = await self.session.execute(
            select(func.count(PendingFire.id)).where(
                PendingFire.schedule_id == schedule_id,
            ),
        )
        return int(result.scalar_one() or 0)

    async def _get_by_fire_id(self, fire_id: UUID) -> PendingFire | None:
        result = await self.session.execute(
            select(PendingFire).where(PendingFire.fire_id == fire_id),
        )
        return result.scalar_one_or_none()


__all__ = ["PendingFiresRepository"]
