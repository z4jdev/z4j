"""``misfire_alerts`` repository -- durable cross-replica dedup claim."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models.misfire_alert import MisfireAlert


class MisfireAlertRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def existing_claims(
        self,
        *,
        schedule_ids: Iterable[UUID],
    ) -> set[tuple[UUID, datetime]]:
        """Return the ``(schedule_id, anchor_at)`` pairs already claimed for
        the given schedules -- a best-effort pre-filter so the detector's
        per-sweep cap applies to FRESH misfires (the durable ``claim`` below
        is still the authoritative dedup)."""
        ids = list(schedule_ids)
        if not ids:
            return set()
        result = await self.session.execute(
            select(MisfireAlert.schedule_id, MisfireAlert.anchor_at).where(
                MisfireAlert.schedule_id.in_(ids),
            ),
        )
        return {(sid, anchor) for sid, anchor in result.all()}

    async def claim(self, *, schedule_id: UUID, anchor_at: datetime) -> bool:
        """Try to claim a misfire episode. Returns True if THIS caller won
        the claim (so it should alert), False if another replica / an
        earlier sweep already claimed it.

        The claim is a UNIQUE ``(schedule_id, anchor_at)`` insert done in a
        SAVEPOINT so a conflict leaves the outer transaction alive. The
        caller commits on a True result to make the claim durable + visible
        to other replicas.
        """
        row = MisfireAlert(schedule_id=schedule_id, anchor_at=anchor_at)
        try:
            async with self.session.begin_nested():
                self.session.add(row)
                await self.session.flush()
        except IntegrityError:
            return False
        return True

    async def release(self, *, schedule_id: UUID, anchor_at: datetime) -> None:
        """Release a claim so the episode can be re-alerted next sweep.

        Called when the alert FAILED after the claim was taken, so a
        transient alert error does not permanently swallow the episode.
        Caller commits.
        """
        await self.session.execute(
            delete(MisfireAlert).where(
                MisfireAlert.schedule_id == schedule_id,
                MisfireAlert.anchor_at == anchor_at,
            ),
        )

    async def prune(self, *, older_than: datetime) -> int:
        """Delete claims older than ``older_than`` (retention). Caller
        commits. Returns the number deleted."""
        result = await self.session.execute(
            delete(MisfireAlert).where(MisfireAlert.created_at < older_than),
        )
        return result.rowcount or 0


__all__ = ["MisfireAlertRepository"]
