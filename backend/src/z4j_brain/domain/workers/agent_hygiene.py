"""``AgentHygieneWorker`` - prune ghost agent rows.

A long-running deployment eventually accumulates agent rows for
containers that were removed without calling the ``DELETE /agents/
{id}`` revoke endpoint (common on K8s rollouts, CI test runs,
hobby-stack cleanup). Each ghost shows up in the dashboard as
``state=offline`` and never recovers. The Agents page fills with
noise; evaluators notice.

This worker sweeps once a day and deletes every agent whose
``last_seen_at`` is older than the configured TTL (default 30d).
Events referencing the deleted agent have their ``agent_id`` set
to NULL by the FK ON DELETE CASCADE rule on the ``agents.id``
column's reverse side - see ``Event.agent_id`` on the model.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings


logger = structlog.get_logger("z4j.brain.workers.agent_hygiene")


class AgentHygieneWorker:
    """Daily ghost-agent prune.

    Pulls its TTL from ``Settings.agent_stale_prune_days``
    (default 30). Setting it to 0 disables pruning entirely - the
    dashboard just shows a "stale" badge instead. The supervisor
    is expected to invoke :meth:`tick` on a daily schedule.
    """

    def __init__(
        self,
        *,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        self._db = db
        self._settings = settings

    async def tick(self) -> None:
        """Single sweep: delete every agent stale past the TTL."""
        ttl_days = self._settings.agent_stale_prune_days
        if ttl_days <= 0:
            logger.debug(
                "z4j agent hygiene: pruning disabled (ttl_days=%d)", ttl_days,
            )
            return

        cutoff = datetime.now(UTC) - timedelta(days=ttl_days)
        from z4j_brain.persistence.repositories import AgentRepository

        async with self._db.session() as session:
            pruned = await AgentRepository(session).prune_stale(cutoff=cutoff)
            await session.commit()

        if pruned:
            logger.info(
                "z4j agent hygiene swept", pruned=pruned, ttl_days=ttl_days,
            )


__all__ = ["AgentHygieneWorker"]
