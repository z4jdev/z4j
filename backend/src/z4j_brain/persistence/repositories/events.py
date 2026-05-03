"""``events`` repository.

Hot table - partitioned by ``occurred_at``. Inserts are
append-only and idempotent on ``(occurred_at, id)``. Reads are
always project-scoped and time-bounded.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import Event
from z4j_brain.persistence.repositories._base import BaseRepository


class EventRepository(BaseRepository[Event]):
    """Append-only event log access."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Event)

    async def insert(
        self,
        *,
        event_id: UUID,
        project_id: UUID,
        agent_id: UUID,
        engine: str,
        task_id: str,
        kind: str,
        occurred_at: datetime,
        payload: dict[str, Any],
    ) -> bool:
        """Insert one event row.

        Idempotent on ``(project_id, occurred_at, id)``: returns
        False if the row already exists, True if it was inserted.
        Used by :class:`EventIngestor` to dedupe replayed events
        from a re-connecting agent.
        """
        is_postgres = (
            self.session.bind is not None
            and self.session.bind.dialect.name == "postgresql"
        )
        if is_postgres:
            stmt = (
                pg_insert(Event)
                .values(
                    id=event_id,
                    project_id=project_id,
                    agent_id=agent_id,
                    engine=engine,
                    task_id=task_id,
                    kind=kind,
                    occurred_at=occurred_at,
                    payload=payload,
                )
                # The conflict key intentionally INCLUDES
                # ``project_id`` so a Project-A agent cannot
                # collide its event_id with a Project-B row and
                # silently censor the legitimate write. This
                # matches the unique index added in the initial
                # migration (`ix_events_project_occurred_id`).
                .on_conflict_do_nothing(
                    index_elements=["project_id", "occurred_at", "id"],
                )
            )
            result = await self.session.execute(stmt)
            return (result.rowcount or 0) > 0
        # SQLite test path: a duplicate raises ``IntegrityError``.
        # We MUST scope the rollback to a SAVEPOINT so the outer
        # transaction (which owns the ingest batch's queue/worker
        # touches and task projections) is preserved - without
        # this, one duplicate event poisons every projection in
        # the batch (R3 finding C1).
        row = Event(
            id=event_id,
            project_id=project_id,
            agent_id=agent_id,
            engine=engine,
            task_id=task_id,
            kind=kind,
            occurred_at=occurred_at,
            payload=payload,
        )
        try:
            async with self.session.begin_nested():
                self.session.add(row)
                await self.session.flush()
        except IntegrityError:
            return False
        return True

    async def list_for_task(
        self,
        *,
        project_id: UUID,
        engine: str,
        task_id: str,
        cursor: tuple[Any, UUID] | None = None,
        limit: int = 50,
    ) -> list[Event]:
        """Return events for one task, newest first.

        Cursor is ``(occurred_at, id)``. The query is index-served
        by ``ix_events_project_task``.
        """
        stmt = select(Event).where(
            Event.project_id == project_id,
            Event.engine == engine,
            Event.task_id == task_id,
        )
        if cursor is not None:
            sort_value, tiebreaker = cursor
            stmt = stmt.where(
                or_(
                    Event.occurred_at < sort_value,
                    and_(
                        Event.occurred_at == sort_value,
                        Event.id < tiebreaker,
                    ),
                ),
            )
        stmt = (
            stmt.order_by(Event.occurred_at.desc(), Event.id.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())


__all__ = ["EventRepository"]
