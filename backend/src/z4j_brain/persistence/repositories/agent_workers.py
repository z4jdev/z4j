"""``agent_workers`` repository (1.2.1+).

Persists the worker-first protocol's per-worker state:

- ``register_or_refresh`` - upsert on hello / heartbeat; sets
  state='online' and bumps last_seen_at + last_connect_at.
- ``mark_offline`` - flip state on disconnect, keep the row
  for history (operator audit: "what workers ran on this host
  yesterday").
- ``touch_heartbeat`` - refresh last_seen_at on each heartbeat
  frame without rewriting the rest of the row.
- ``list_for_project`` / ``list_for_agent`` - dashboard reads.

The composite key is ``(agent_id, worker_id)``. Legacy 1.1.x
clients (worker_id=None) get exactly one row per agent_id;
worker-aware clients (1.2.0+) get one row per worker_id.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Sequence
from uuid import UUID

from sqlalchemy import and_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import AgentWorker
from z4j_brain.persistence.repositories._base import BaseRepository


class AgentWorkerRepository(BaseRepository[AgentWorker]):
    """CRUD + state bookkeeping for ``agent_workers`` rows."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, AgentWorker)

    async def register_or_refresh(
        self,
        *,
        agent_id: UUID,
        project_id: UUID,
        worker_id: str | None,
        role: str | None = None,
        framework: str | None = None,
        pid: int | None = None,
        started_at: datetime | None = None,
    ) -> None:
        """Upsert: insert a new row or refresh an existing one.

        Idempotent. Called from the WS gateway on every successful
        ``hello`` handshake. Sets state='online' and bumps both
        last_seen_at and last_connect_at to now.

        Cross-dialect: uses Postgres ON CONFLICT for the prod path,
        SQLite ON CONFLICT for the SQLite dev / test path. Both are
        single-statement upserts (no SELECT-then-UPDATE race).
        """
        now = datetime.now(UTC)
        bind = self.session.bind
        dialect = bind.dialect.name if bind is not None else ""

        values = {
            "agent_id": agent_id,
            "project_id": project_id,
            "worker_id": worker_id,
            "role": role,
            "framework": framework,
            "pid": pid,
            "started_at": started_at,
            "state": "online",
            "last_seen_at": now,
            "last_connect_at": now,
        }
        update_values = {
            "role": role,
            "framework": framework,
            "pid": pid,
            "started_at": started_at,
            "state": "online",
            "last_seen_at": now,
            "last_connect_at": now,
            "updated_at": now,
        }

        if dialect == "postgresql":
            stmt = pg_insert(AgentWorker).values(**values)
            stmt = stmt.on_conflict_do_update(
                constraint="uq_agent_workers_agent_worker",
                set_=update_values,
            )
            await self.session.execute(stmt)
        else:
            # SQLite path: ON CONFLICT(agent_id, worker_id) DO UPDATE.
            # Note SQLite UPSERT semantics treat NULL worker_id as
            # distinct (each NULL is its own row), so the legacy slot
            # may insert a duplicate row on reconnect. Mitigation:
            # the in-memory registry only allows one NULL slot per
            # agent_id at a time, so the worst case is one extra
            # offline row that the GC sweep will reap.
            stmt = sqlite_insert(AgentWorker).values(**values)
            stmt = stmt.on_conflict_do_update(
                index_elements=["agent_id", "worker_id"],
                set_=update_values,
            )
            await self.session.execute(stmt)

    async def touch_heartbeat(
        self,
        *,
        agent_id: UUID,
        worker_id: str | None,
        when: datetime | None = None,
    ) -> None:
        """Refresh last_seen_at on a heartbeat frame.

        Single indexed UPDATE. No-op if the row doesn't exist
        (which would be unusual: the row should have been created
        by ``register_or_refresh`` on the preceding ``hello``).
        """
        now = when or datetime.now(UTC)
        await self.session.execute(
            update(AgentWorker)
            .where(
                and_(
                    AgentWorker.agent_id == agent_id,
                    AgentWorker.worker_id.is_(worker_id)
                    if worker_id is None
                    else AgentWorker.worker_id == worker_id,
                ),
            )
            .values(last_seen_at=now, state="online"),
        )

    async def mark_offline(
        self,
        *,
        agent_id: UUID,
        worker_id: str | None,
    ) -> None:
        """Flip state='offline' for one (agent_id, worker_id) row.

        Row stays for history. Idempotent.
        """
        await self.session.execute(
            update(AgentWorker)
            .where(
                and_(
                    AgentWorker.agent_id == agent_id,
                    AgentWorker.worker_id.is_(worker_id)
                    if worker_id is None
                    else AgentWorker.worker_id == worker_id,
                ),
            )
            .values(state="offline"),
        )

    async def mark_all_offline_for_agent(self, agent_id: UUID) -> None:
        """Flip every row for ``agent_id`` to offline.

        Used on brain shutdown / agent removal. Idempotent.
        """
        await self.session.execute(
            update(AgentWorker)
            .where(AgentWorker.agent_id == agent_id)
            .values(state="offline"),
        )

    async def list_for_project(
        self,
        project_id: UUID,
        *,
        state: str | None = None,
        role: str | None = None,
        limit: int = 200,
    ) -> Sequence[AgentWorker]:
        """List workers in a project, newest-active first.

        ``state`` and ``role`` are optional filters. Default limit
        of 200 covers any realistic small/medium deployment;
        operators with thousands of workers paginate via offset.
        """
        stmt = select(AgentWorker).where(AgentWorker.project_id == project_id)
        if state is not None:
            stmt = stmt.where(AgentWorker.state == state)
        if role is not None:
            stmt = stmt.where(AgentWorker.role == role)
        stmt = stmt.order_by(
            AgentWorker.state.desc(),  # online before offline
            AgentWorker.last_seen_at.desc().nullslast(),
        ).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def list_for_agent(
        self,
        agent_id: UUID,
    ) -> Sequence[AgentWorker]:
        """All workers under one agent. Used on the agent detail page."""
        stmt = (
            select(AgentWorker)
            .where(AgentWorker.agent_id == agent_id)
            .order_by(
                AgentWorker.state.desc(),
                AgentWorker.last_seen_at.desc().nullslast(),
            )
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()


__all__ = ["AgentWorkerRepository"]
