"""``AgentHygieneWorker`` - prune ghost agent rows.

A long-running deployment eventually accumulates agent rows for
containers that were removed without calling the ``DELETE /agents/
{id}`` revoke endpoint (common on K8s rollouts, CI test runs,
hobby-stack cleanup). Each ghost shows up in the dashboard as
``state=offline`` and never recovers. The Agents page fills with
noise; evaluators notice.

This worker sweeps once a day and soft-revokes stale, live agents. Their bearer
tokens stop working and normal fleet reads hide them, while every historical
reference keeps the same durable agent identity.
"""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
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
        """Soft-revoke stale live agents past the TTL."""
        ttl_days = self._settings.agent_stale_prune_days
        if ttl_days <= 0:
            logger.debug(
                "z4j agent hygiene: pruning disabled (ttl_days=%d)",
                ttl_days,
            )
            return

        cutoff = datetime.now(UTC) - timedelta(days=ttl_days)
        from z4j_brain.persistence.agent_authority import local_agent_authority
        from z4j_brain.persistence.repositories import AgentRepository
        from z4j_brain.persistence.repositories.agents import (
            AGENT_STALE_PRUNE_BATCH_SIZE,
        )

        # Drain bounded, deterministic batches. The old all-at-once shape could
        # exceed asyncpg's 32,767 bind-argument limit and retained one advisory
        # lock per stale row until a huge transaction committed. Bounded commits
        # also give supervisor cancellation a prompt transaction boundary.
        pruned = 0
        while True:
            # Discovery must not retain a SQLite transaction while waiting for
            # process-local authority. Mutation revalidates every candidate
            # after authority is acquired, so a reconnect that wins survives.
            async with self._db.session() as session:
                candidate_ids = await AgentRepository(session).list_stale_ids(
                    cutoff=cutoff,
                    limit=AGENT_STALE_PRUNE_BATCH_SIZE,
                )
            if not candidate_ids:
                break

            if self._db.engine.dialect.name == "sqlite":
                # Acquire the whole bounded set in stable order before opening
                # BEGIN IMMEDIATE. Waiting for a slow physical send must never
                # retain SQLite's database-global writer reservation.
                async with AsyncExitStack() as authority:
                    for agent_id in sorted(set(candidate_ids), key=str):
                        await authority.enter_async_context(
                            local_agent_authority(agent_id),
                        )
                    async with self._db.session(write=True) as session:
                        pruned += await AgentRepository(session).prune_stale(
                            cutoff=cutoff,
                            candidate_ids=candidate_ids,
                        )
                        await session.commit()
            else:
                async with self._db.session(write=True) as session:
                    pruned += await AgentRepository(session).prune_stale(
                        cutoff=cutoff,
                        candidate_ids=candidate_ids,
                    )
                    await session.commit()

            # Database awaits are cancellation points already; this explicit
            # yield also prevents a fast in-memory SQLite drain monopolising the
            # loop between bounded transactions.
            await asyncio.sleep(0)

        if pruned:
            logger.info(
                "z4j agent hygiene swept",
                pruned=pruned,
                ttl_days=ttl_days,
            )


__all__ = ["AgentHygieneWorker"]
