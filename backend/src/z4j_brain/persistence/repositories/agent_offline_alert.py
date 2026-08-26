"""``agent_offline_alerts`` repository -- durable cross-replica dedup claim.

Mirrors :class:`MisfireAlertRepository` (the A4 misfire dedup ledger),
keyed on ``(agent_id, anchor_at)`` instead of ``(schedule_id, anchor_at)``.
Unlike a misfire (a fact about the past that cannot un-happen), an
offline episode is a LIVE state that can end at any moment, so both the
claim and the retention prune here are conditional on the agent's
CURRENT row: the claim inserts only while the episode is still active
and the prune deletes only once it has ended."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, delete, insert, literal, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models.agent import Agent
from z4j_brain.persistence.models.agent_offline_alert import AgentOfflineAlert


class AgentOfflineAlertRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def existing_claims(
        self,
        *,
        agent_ids: Iterable[UUID],
    ) -> set[tuple[UUID, datetime]]:
        """Return the ``(agent_id, anchor_at)`` pairs already claimed for
        the given agents -- a best-effort pre-filter so the health worker's
        per-sweep cap applies to FRESH episodes (the durable ``claim``
        below is still the authoritative dedup)."""
        ids = list(agent_ids)
        if not ids:
            return set()
        result = await self.session.execute(
            select(AgentOfflineAlert.agent_id, AgentOfflineAlert.anchor_at).where(
                AgentOfflineAlert.agent_id.in_(ids),
            ),
        )
        return {(aid, anchor) for aid, anchor in result.all()}

    async def claim(self, *, agent_id: UUID, anchor_at: datetime) -> bool:
        """Try to claim an offline episode. Returns True if THIS caller won
        the claim (so it should alert), False if another replica / an
        earlier sweep already claimed it -- or if the episode ENDED (the
        agent recovered) between candidate selection and this claim.

        The claim is a UNIQUE ``(agent_id, anchor_at)`` ``INSERT ...
        SELECT`` conditioned on the agents row STILL showing
        ``state=offline`` with ``last_seen_at`` equal to the anchor the
        candidate was selected with. The health worker selects candidates
        in one session and claims in another; an agent that reconnected in
        between must not be minted a claim (and a false durable alert) for
        an episode that no longer exists -- the conditional insert
        simply affects zero rows and the caller skips silently. A plain
        ``INSERT ... SELECT`` is a single atomic statement on SQLite and
        Postgres alike, so no dialect-specific upsert is needed. The
        UNIQUE conflict is absorbed in a SAVEPOINT so the outer
        transaction stays alive. The caller commits on a True result to
        make the claim durable + visible to other replicas.
        """
        stmt = insert(AgentOfflineAlert).from_select(
            ["agent_id", "anchor_at"],
            select(
                Agent.id,
                literal(anchor_at, DateTime(timezone=True)),
            ).where(
                Agent.id == agent_id,
                Agent.state == AgentState.OFFLINE,
                Agent.revoked_at.is_(None),
                Agent.last_seen_at == anchor_at,
            ),
        )
        try:
            async with self.session.begin_nested():
                result = await self.session.execute(stmt)
        except IntegrityError:
            return False
        return bool(result.rowcount)

    async def release(self, *, agent_id: UUID, anchor_at: datetime) -> None:
        """Release a claim so the episode can be re-alerted next sweep.

        Called when the alert FAILED after the claim was taken, so a
        transient alert error does not permanently swallow the episode.
        Caller commits.
        """
        await self.session.execute(
            delete(AgentOfflineAlert).where(
                AgentOfflineAlert.agent_id == agent_id,
                AgentOfflineAlert.anchor_at == anchor_at,
            ),
        )

    async def prune(self, *, older_than: datetime) -> int:
        """Delete claims older than ``older_than`` whose episode has ENDED.

        A claim still backing an ACTIVE episode (the agents row still
        shows ``state=offline`` with ``last_seen_at`` equal to the claim's
        ``anchor_at``) is retained REGARDLESS of age: deleting it would
        make the next sweep re-claim and re-alert an unchanged ongoing
        outage. One alert per episode, however long it lasts.
        Aged-out claims ARE dropped once the episode is over: the agent
        recovered (state no longer offline), a new episode started
        (``last_seen_at`` moved off the claim's anchor), or the agent row
        is gone entirely (the FK cascade normally removes those claims
        already; the NOT EXISTS covers a ledger row that outlived its
        agent anyway). Caller commits. Returns the number deleted.
        """
        episode_still_active = (
            select(Agent.id)
            .where(
                Agent.id == AgentOfflineAlert.agent_id,
                Agent.state == AgentState.OFFLINE,
                Agent.revoked_at.is_(None),
                Agent.last_seen_at == AgentOfflineAlert.anchor_at,
            )
            .exists()
        )
        result = await self.session.execute(
            delete(AgentOfflineAlert).where(
                AgentOfflineAlert.created_at < older_than,
                ~episode_still_active,
            ),
        )
        return result.rowcount or 0


__all__ = ["AgentOfflineAlertRepository"]
