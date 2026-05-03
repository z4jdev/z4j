"""``AgentHealthWorker`` - marks stale agents offline.

Every ``agent_health_sweep_seconds`` (default 10s) flips every
agent whose ``last_seen_at`` is older than
``agent_offline_timeout_seconds`` from ``online`` to ``offline``.
Single bulk UPDATE per tick.

Note that the in-memory ``BrainRegistry`` map is the source of
truth for "is the agent's WebSocket alive on this worker right
now"; the ``agents.state`` column is the dashboard's lagging
view of cluster-wide reachability.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings


logger = structlog.get_logger("z4j.brain.workers.agent_health")


class AgentHealthWorker:
    """Periodic agent-offline sweeper."""

    def __init__(
        self,
        *,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        self._db = db
        self._settings = settings

    async def tick(self) -> None:
        from z4j_brain.persistence.repositories import AgentRepository

        cutoff = datetime.now(UTC) - timedelta(
            seconds=self._settings.agent_offline_timeout_seconds,
        )
        async with self._db.session() as session:
            count = await AgentRepository(session).sweep_offline(cutoff=cutoff)
            await session.commit()
        if count:
            logger.info("z4j agent health sweep", marked_offline=count)


__all__ = ["AgentHealthWorker"]
