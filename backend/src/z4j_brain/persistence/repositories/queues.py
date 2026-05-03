"""``queues`` repository."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import Queue
from z4j_brain.persistence.repositories._base import BaseRepository


class QueueRepository(BaseRepository[Queue]):
    """Queue CRUD."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Queue)

    async def list_for_project(self, project_id: UUID) -> list[Queue]:
        result = await self.session.execute(
            select(Queue)
            .where(Queue.project_id == project_id)
            .order_by(Queue.name),
        )
        return list(result.scalars().all())

    async def touch(
        self,
        *,
        project_id: UUID,
        engine: str,
        name: str,
    ) -> Queue:
        """Insert-or-update on ``(project, engine, name)``.

        Bumps ``last_seen_at``. Used by :class:`EventIngestor`
        whenever a task event arrives that mentions a queue we
        have not yet recorded.
        """
        result = await self.session.execute(
            select(Queue).where(
                Queue.project_id == project_id,
                Queue.engine == engine,
                Queue.name == name,
            ),
        )
        existing = result.scalar_one_or_none()
        now = datetime.now(UTC)
        if existing is None:
            from sqlalchemy.exc import IntegrityError

            row = Queue(
                project_id=project_id,
                engine=engine,
                name=name,
                last_seen_at=now,
            )
            # SAVEPOINT for the SELECT-then-INSERT race - see
            # tasks/workers upsert_from_event comments. Without
            # this, two concurrent events referencing the same
            # queue cascade a PendingRollbackError into the batch.
            try:
                async with self.session.begin_nested():
                    self.session.add(row)
                    await self.session.flush()
            except IntegrityError:
                result = await self.session.execute(
                    select(Queue).where(
                        Queue.project_id == project_id,
                        Queue.engine == engine,
                        Queue.name == name,
                    ),
                )
                existing = result.scalar_one()
            else:
                return row
        existing.last_seen_at = now
        await self.session.flush()
        return existing


    async def update_depth(
        self,
        *,
        project_id: UUID,
        engine: str,
        name: str,
        pending_count: int,
    ) -> None:
        """Update queue depth from heartbeat data.

        Creates the queue row if it doesn't exist (same upsert
        pattern as :meth:`touch`). Sets ``pending_count`` and
        bumps ``last_seen_at``.
        """
        result = await self.session.execute(
            select(Queue).where(
                Queue.project_id == project_id,
                Queue.engine == engine,
                Queue.name == name,
            ),
        )
        existing = result.scalar_one_or_none()
        now = datetime.now(UTC)
        if existing is None:
            row = Queue(
                project_id=project_id,
                engine=engine,
                name=name,
                last_seen_at=now,
                pending_count=pending_count,
            )
            self.session.add(row)
            await self.session.flush()
            return
        existing.pending_count = pending_count
        existing.last_seen_at = now
        await self.session.flush()


__all__ = ["QueueRepository"]
