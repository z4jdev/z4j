"""``invitations`` repository.

CRUD for project invitation rows. Invitations are created by
project admins, accepted by the invited user via a one-time token,
or revoked before they expire.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models.invitation import Invitation
from z4j_brain.persistence.repositories._base import BaseRepository


class InvitationRepository(BaseRepository[Invitation]):
    """Invitation CRUD."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Invitation)

    async def create(
        self,
        *,
        project_id: uuid.UUID,
        email: str,
        role: str,
        invited_by: uuid.UUID | None,
        token_hash: str,
        expires_at: datetime,
    ) -> Invitation:
        """Insert a new invitation row."""
        row = Invitation(
            project_id=project_id,
            email=email,
            role=role,
            invited_by=invited_by,
            token_hash=token_hash,
            expires_at=expires_at,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def list_for_project(self, project_id: uuid.UUID) -> list[Invitation]:
        """Return active (non-accepted, non-revoked, non-expired) invitations."""
        now = datetime.now(UTC)
        result = await self.session.execute(
            select(Invitation)
            .where(
                Invitation.project_id == project_id,
                Invitation.accepted_at.is_(None),
                Invitation.revoked_at.is_(None),
                Invitation.expires_at > now,
            )
            .order_by(Invitation.created_at.desc()),
        )
        return list(result.scalars().all())

    async def get_by_hash(self, token_hash: str) -> Invitation | None:
        """Look up an invitation by its token hash (for accepting)."""
        result = await self.session.execute(
            select(Invitation).where(Invitation.token_hash == token_hash),
        )
        return result.scalars().first()

    async def accept(
        self,
        invitation_id: uuid.UUID,
        *,
        accepted_by_user_id: uuid.UUID,
    ) -> Invitation | None:
        """Stamp ``accepted_at`` + ``accepted_by_user_id`` atomically.

        Caller is responsible for running this inside the same
        transaction as the ``users`` insert + ``memberships`` grant
        so the three side-effects succeed or fail together.
        """
        row = await self.get(invitation_id)
        if row is None:
            return None
        row.accepted_at = datetime.now(UTC)
        row.accepted_by_user_id = accepted_by_user_id
        await self.session.flush()
        return row

    async def revoke(self, invitation_id: uuid.UUID) -> Invitation | None:
        """Set revoked_at on an invitation. Returns the updated row."""
        row = await self.get(invitation_id)
        if row is None:
            return None
        row.revoked_at = datetime.now(UTC)
        await self.session.flush()
        return row


__all__ = ["InvitationRepository"]
