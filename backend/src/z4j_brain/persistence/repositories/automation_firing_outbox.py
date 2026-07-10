"""``automation_firing_outbox`` repository: enqueue + drain."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import AutomationFiringOutbox
from z4j_brain.persistence.repositories._base import BaseRepository


class AutomationFiringOutboxRepository(BaseRepository[AutomationFiringOutbox]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, AutomationFiringOutbox)

    async def enqueue(
        self,
        *,
        project_id: UUID,
        trigger: str,
        fields: dict[str, Any],
    ) -> AutomationFiringOutbox:
        """Persist a dropped firing for later replay. Does NOT commit."""
        row = AutomationFiringOutbox(
            project_id=project_id,
            trigger=trigger,
            fields=fields,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def enqueue_many(
        self,
        *,
        project_id: UUID,
        items: list[tuple[str, dict[str, Any]]],
    ) -> int:
        """Persist several dropped firings in one flush (one INSERT round
        trip instead of one per firing). ``items`` is a list of
        ``(trigger, fields)``. Does NOT commit."""
        rows = [
            AutomationFiringOutbox(project_id=project_id, trigger=trigger, fields=fields)
            for trigger, fields in items
        ]
        self.session.add_all(rows)
        await self.session.flush()
        return len(rows)

    async def count_for_project(self, project_id: UUID) -> int:
        """Pending rows for one project (for the per-project cap)."""
        from sqlalchemy import func

        result = await self.session.execute(
            select(func.count())
            .select_from(AutomationFiringOutbox)
            .where(AutomationFiringOutbox.project_id == project_id),
        )
        return int(result.scalar_one())

    @staticmethod
    def _due(stmt, now: datetime | None):
        """Restrict to rows eligible to replay now (next_attempt_at NULL or
        past). A FAILED replay backs a row off into the future, so it stops
        blocking the FIFO head."""
        if now is None:
            return stmt
        return stmt.where(
            or_(
                AutomationFiringOutbox.next_attempt_at.is_(None),
                AutomationFiringOutbox.next_attempt_at <= now,
            ),
        )

    async def list_due_project_ids(
        self,
        *,
        now: datetime | None = None,
        limit: int = 100,
    ) -> list[UUID]:
        """Distinct projects that have at least one firing due for replay,
        oldest-first. The drain round-robins across these so one flooding
        tenant cannot starve others at the head of a global FIFO queue."""
        capped = min(max(1, limit), 1000)
        stmt = self._due(select(AutomationFiringOutbox.project_id), now)
        stmt = (
            stmt.group_by(AutomationFiringOutbox.project_id)
            .order_by(func.min(AutomationFiringOutbox.created_at))
            .limit(capped)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_pending(
        self,
        *,
        limit: int = 100,
        now: datetime | None = None,
        project_id: UUID | None = None,
    ) -> list[AutomationFiringOutbox]:
        """Oldest-first batch of firings DUE for replay, optionally scoped to
        one project (for the round-robin drain). Bounded."""
        capped = min(max(1, limit), 1000)
        stmt = self._due(select(AutomationFiringOutbox), now)
        if project_id is not None:
            stmt = stmt.where(AutomationFiringOutbox.project_id == project_id)
        result = await self.session.execute(
            stmt.order_by(
                AutomationFiringOutbox.created_at,
                AutomationFiringOutbox.id,
            ).limit(capped),
        )
        return list(result.scalars().all())

    async def delete_by_id(self, row_id: UUID) -> bool:
        """Delete a drained row. Does NOT commit."""
        result = await self.session.execute(
            delete(AutomationFiringOutbox).where(AutomationFiringOutbox.id == row_id),
        )
        return bool(result.rowcount)

    async def increment_attempts(self, row_id: UUID) -> int:
        """Bump the replay attempt counter and return the new value. Does
        NOT commit. Returns 0 if the row vanished."""
        await self.session.execute(
            update(AutomationFiringOutbox)
            .where(AutomationFiringOutbox.id == row_id)
            .values(attempts=AutomationFiringOutbox.attempts + 1),
        )
        result = await self.session.execute(
            select(AutomationFiringOutbox.attempts).where(
                AutomationFiringOutbox.id == row_id,
            ),
        )
        value = result.scalar_one_or_none()
        return int(value or 0)

    async def backoff(self, row_id: UUID, *, until: datetime) -> None:
        """Back a FAILED row off until ``until`` so it stops blocking the
        FIFO head (the drain skips not-yet-due rows). Does NOT commit."""
        await self.session.execute(
            update(AutomationFiringOutbox)
            .where(AutomationFiringOutbox.id == row_id)
            .values(next_attempt_at=until),
        )

    async def count(self) -> int:
        """Total pending rows (for the in-memory-state gauge / tests)."""
        from sqlalchemy import func

        result = await self.session.execute(
            select(func.count()).select_from(AutomationFiringOutbox),
        )
        return int(result.scalar_one())


__all__ = ["AutomationFiringOutboxRepository"]
