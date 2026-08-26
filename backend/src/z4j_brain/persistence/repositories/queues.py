"""``queues`` repository."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import Queue
from z4j_brain.persistence.repositories._base import BaseRepository


def _queue_depth_upsert_statement(
    insert: Any,
    *,
    project_id: UUID,
    engine: str,
    name: str,
    pending_count: int,
    observed_at: datetime,
) -> Any:
    """Build the shared SQLite/PostgreSQL ordered depth observation.

    The source observation timestamp, rather than transaction commit order,
    decides which snapshot wins.  Exact timestamp ties keep the stored row so
    concurrent replicas resolve the same tie deterministically.
    """
    statement = insert(Queue).values(
        id=uuid4(),
        project_id=project_id,
        engine=engine,
        name=name,
        pending_count=pending_count,
        last_seen_at=observed_at,
    )
    return statement.on_conflict_do_update(
        index_elements=("project_id", "engine", "name"),
        set_={
            "pending_count": statement.excluded.pending_count,
            "last_seen_at": statement.excluded.last_seen_at,
            "updated_at": func.now(),
        },
        where=or_(
            Queue.last_seen_at.is_(None),
            Queue.last_seen_at < statement.excluded.last_seen_at,
        ),
    )


def _queue_touch_upsert_statement(
    insert: Any,
    *,
    project_id: UUID,
    engine: str,
    name: str,
    observed_at: datetime,
) -> Any:
    """Build an ordered queue-observation upsert without changing depth."""
    statement = insert(Queue).values(
        id=uuid4(),
        project_id=project_id,
        engine=engine,
        name=name,
        last_seen_at=observed_at,
    )
    return statement.on_conflict_do_update(
        index_elements=("project_id", "engine", "name"),
        set_={
            "last_seen_at": statement.excluded.last_seen_at,
            "updated_at": func.now(),
        },
        where=or_(
            Queue.last_seen_at.is_(None),
            Queue.last_seen_at < statement.excluded.last_seen_at,
        ),
    )


def _normalise_observed_at(observed_at: datetime) -> datetime:
    """Represent a queue observation as a UTC instant on every dialect."""
    return (
        observed_at.astimezone(UTC)
        if observed_at.tzinfo is not None
        else observed_at.replace(tzinfo=UTC)
    )


class QueueRepository(BaseRepository[Queue]):
    """Queue CRUD."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Queue)

    async def list_for_project(self, project_id: UUID) -> list[Queue]:
        result = await self.session.execute(
            select(Queue).where(Queue.project_id == project_id).order_by(Queue.name),
        )
        return list(result.scalars().all())

    async def touch(
        self,
        *,
        project_id: UUID,
        engine: str,
        name: str,
        observed_at: datetime,
    ) -> Queue:
        """Record an ordered queue observation without changing its depth.

        ``observed_at`` comes from the event or signed heartbeat that observed
        the queue. SQLite and PostgreSQL atomically advance ``last_seen_at``
        only for a strictly newer observation; exact ties keep the existing
        row. This gives :meth:`touch` and :meth:`update_depth` one ordering
        clock, so a wall-clock stamp from one path cannot suppress or reorder a
        source-timestamped depth snapshot from the other.
        """
        observed_at = _normalise_observed_at(observed_at)
        bind = await self.session.connection()
        insert: Any | None = None
        if bind.dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            insert = pg_insert
        elif bind.dialect.name == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            insert = sqlite_insert
        if insert is not None:
            await self.session.execute(
                _queue_touch_upsert_statement(
                    insert,
                    project_id=project_id,
                    engine=engine,
                    name=name,
                    observed_at=observed_at,
                ),
            )
            result = await self.session.execute(
                select(Queue)
                .where(
                    Queue.project_id == project_id,
                    Queue.engine == engine,
                    Queue.name == name,
                )
                .execution_options(populate_existing=True),
            )
            return result.scalar_one()

        # Conservative savepointed fallback for a future dialect without a
        # known native conflict clause. The UPDATE predicate still lives in
        # SQL, so a concurrent newer observation cannot be overwritten after
        # this path's earlier SELECT.
        from sqlalchemy.exc import IntegrityError

        result = await self.session.execute(
            select(Queue).where(
                Queue.project_id == project_id,
                Queue.engine == engine,
                Queue.name == name,
            ),
        )
        existing = result.scalar_one_or_none()
        if existing is None:
            row = Queue(
                project_id=project_id,
                engine=engine,
                name=name,
                last_seen_at=observed_at,
            )
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
        await self.session.execute(
            update(Queue)
            .where(
                Queue.project_id == project_id,
                Queue.engine == engine,
                Queue.name == name,
                or_(
                    Queue.last_seen_at.is_(None),
                    Queue.last_seen_at < observed_at,
                ),
            )
            .values(last_seen_at=observed_at)
            .execution_options(synchronize_session=False),
        )
        await self.session.flush()
        await self.session.refresh(existing)
        return existing

    async def update_depth(
        self,
        *,
        project_id: UUID,
        engine: str,
        name: str,
        pending_count: int,
        observed_at: datetime,
    ) -> None:
        """Update queue depth from heartbeat data.

        Creates the queue row if it doesn't exist, sets ``pending_count``, and
        advances ``last_seen_at`` to the heartbeat's source observation time.
        SQLite and PostgreSQL use one atomic ``INSERT .. ON CONFLICT DO
        UPDATE`` whose conflict branch runs only for a strictly newer
        observation. Thus commit/lock order cannot let an older queue snapshot
        replace newer depth data, and concurrent first observations cannot turn
        a uniqueness collision into an aborted outer event-batch transaction.
        Exact timestamp ties keep the existing row. Future dialects use the
        savepointed recovery pattern from :meth:`touch` plus an atomic guarded
        UPDATE.
        """
        observed_at = _normalise_observed_at(observed_at)
        bind = await self.session.connection()
        if bind.dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            await self.session.execute(
                _queue_depth_upsert_statement(
                    pg_insert,
                    project_id=project_id,
                    engine=engine,
                    name=name,
                    pending_count=pending_count,
                    observed_at=observed_at,
                ),
            )
            return
        if bind.dialect.name == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            await self.session.execute(
                _queue_depth_upsert_statement(
                    sqlite_insert,
                    project_id=project_id,
                    engine=engine,
                    name=name,
                    pending_count=pending_count,
                    observed_at=observed_at,
                ),
            )
            return

        # Conservative fallback for a future dialect without a known native
        # conflict clause. The losing INSERT rolls back only its SAVEPOINT;
        # caller-owned work in the outer transaction remains valid.
        from sqlalchemy.exc import IntegrityError

        result = await self.session.execute(
            select(Queue).where(
                Queue.project_id == project_id,
                Queue.engine == engine,
                Queue.name == name,
            ),
        )
        existing = result.scalar_one_or_none()
        if existing is None:
            row = Queue(
                project_id=project_id,
                engine=engine,
                name=name,
                last_seen_at=observed_at,
                pending_count=pending_count,
            )
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
                return
        await self.session.execute(
            update(Queue)
            .where(
                Queue.project_id == project_id,
                Queue.engine == engine,
                Queue.name == name,
                or_(
                    Queue.last_seen_at.is_(None),
                    Queue.last_seen_at < observed_at,
                ),
            )
            .values(
                pending_count=pending_count,
                last_seen_at=observed_at,
            )
            .execution_options(synchronize_session=False),
        )
        await self.session.flush()


__all__ = ["QueueRepository"]
