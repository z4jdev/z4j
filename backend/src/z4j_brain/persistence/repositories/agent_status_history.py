"""``agent_status_history`` repository.

Append-only access to the agent self-report timeline (Phase H of
1.5.0). The :class:`AgentStatusHistoryRepository` is the only path
the rest of the brain takes to insert / query / purge these rows;
no SQL escapes this module.

Designed for three call sites:

- The WebSocket frame router calls :meth:`insert` once per
  inbound ``agent_status`` frame (default 10s cadence per agent).
- The dashboard / API will eventually call :meth:`recent_for_agent`
  to render a per-agent flap timeline. Out of scope for 1.5.0
  but the method ships now to keep the contract reviewable.
- The retention sweeper calls :meth:`delete_older_than` in
  bounded batches to enforce ``Z4J_EVENT_RETENTION_DAYS``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import AgentStatusHistory
from z4j_brain.persistence.repositories._base import BaseRepository


class AgentStatusHistoryRepository(BaseRepository[AgentStatusHistory]):
    """Append-only access to the per-agent status timeline."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, AgentStatusHistory)

    async def insert(
        self,
        *,
        project_id: UUID,
        agent_id: UUID,
        captured_at: datetime,
        payload: dict[str, Any],
    ) -> AgentStatusHistory:
        """Insert one snapshot row.

        Caller controls the transaction; this method flushes so the
        auto-generated ``id`` populates before the caller reads it
        back. ``captured_at`` is the frame's ``ts`` field, NOT
        ``datetime.now()`` - we keep the agent's snapshot timestamp
        so the dashboard timeline reflects when the agent saw the
        state, not when the brain finished writing it.
        """
        row = AgentStatusHistory(
            project_id=project_id,
            agent_id=agent_id,
            captured_at=captured_at,
            payload=payload,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def recent_for_agent(
        self,
        *,
        agent_id: UUID,
        limit: int = 100,
    ) -> list[AgentStatusHistory]:
        """Return the most recent ``limit`` rows for one agent.

        Ordered by ``captured_at`` DESCENDING so the dashboard's
        "show me the latest 100 status snapshots" view is index-only
        against ``agent_status_history_agent_time_idx``.

        ``limit`` is bounded between 1 and 1000 to mirror
        :meth:`BaseRepository.list` and prevent unbounded scans
        from a malformed API call.
        """
        if limit <= 0 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        stmt = (
            select(AgentStatusHistory)
            .where(AgentStatusHistory.agent_id == agent_id)
            .order_by(AgentStatusHistory.captured_at.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def delete_older_than(
        self,
        *,
        cutoff: datetime,
        batch_size: int = 5_000,
    ) -> int:
        """Bulk-delete rows whose ``captured_at`` is strictly older than cutoff.

        Designed to be called by the retention sweeper. Returns the
        number of rows deleted in this single batch so the caller
        can loop until the count drops below ``batch_size`` (drain
        complete) or hits its per-pass cap.

        Implementation note: SQLAlchemy 2.x ``delete().where(...)``
        on the ORM target compiles to a single bulk DELETE on both
        Postgres and SQLite, no row-by-row session round trip. We
        wrap the cutoff filter inside an ``id IN (SELECT ...)`` so
        the dialects that don't accept ``LIMIT`` directly on a
        DELETE (Postgres) still get a bounded delete. SQLite tolerates
        ``LIMIT`` on DELETE only with a compile-time flag, so the
        ``id IN (subquery)`` form is the lowest-common-denominator.
        """
        if batch_size <= 0 or batch_size > 100_000:
            raise ValueError("batch_size must be between 1 and 100_000")
        # Subquery picks at most ``batch_size`` victim ids ordered by
        # captured_at so the oldest rows die first - keeps the
        # surviving table the freshest possible at any drain
        # checkpoint, which is what the dashboard wants.
        victim_subq = (
            select(AgentStatusHistory.id)
            .where(AgentStatusHistory.captured_at < cutoff)
            .order_by(AgentStatusHistory.captured_at.asc())
            .limit(batch_size)
            .scalar_subquery()
        )
        result = await self.session.execute(
            delete(AgentStatusHistory).where(
                AgentStatusHistory.id.in_(victim_subq),
            ),
        )
        return result.rowcount or 0


__all__ = ["AgentStatusHistoryRepository"]
