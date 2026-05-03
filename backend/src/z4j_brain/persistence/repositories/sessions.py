"""``sessions`` repository.

Server-side session storage so logout / password-change / admin-kill
all work without waiting for an absolute expiry. The auth service
holds a SessionRepository and treats the database row as the
source of truth.

Hot path: every authenticated request runs ``get`` (PK SELECT) +
``touch`` (PK UPDATE). Both are O(1) by primary key - no scan, no
N+1.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import Session
from z4j_brain.persistence.repositories._base import BaseRepository


class SessionRepository(BaseRepository[Session]):
    """Server-side session CRUD + revocation."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Session)

    async def create(
        self,
        *,
        user_id: UUID,
        csrf_token: str,
        expires_at: datetime,
        ip_at_issue: str,
        user_agent_at_issue: str | None,
    ) -> Session:
        """Insert a fresh session row.

        The caller passes the absolute ``expires_at`` already
        computed (now + lifetime) so the policy lives in one place
        - :class:`AuthService`. ``last_seen_at`` and ``issued_at``
        default to ``now()`` server-side.
        """
        row = Session(
            user_id=user_id,
            csrf_token=csrf_token,
            expires_at=expires_at,
            ip_at_issue=ip_at_issue,
            user_agent_at_issue=(
                user_agent_at_issue[:256] if user_agent_at_issue else None
            ),
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def touch(self, session_id: UUID) -> None:
        """Bump ``last_seen_at`` to now.

        Single indexed UPDATE - O(1) by PK. Called once per
        authenticated request after the session has been validated.
        """
        await self.session.execute(
            update(Session)
            .where(Session.id == session_id)
            .values(last_seen_at=datetime.now(UTC)),
        )

    async def revoke(
        self,
        session_id: UUID,
        *,
        reason: str,
    ) -> None:
        """Mark a single session revoked. Idempotent."""
        await self.session.execute(
            update(Session)
            .where(Session.id == session_id, Session.revoked_at.is_(None))
            .values(revoked_at=datetime.now(UTC), revocation_reason=reason),
        )

    async def revoke_all_for_user(
        self,
        user_id: UUID,
        *,
        reason: str,
    ) -> int:
        """Mark every live session for ``user_id`` revoked.

        Returns the number of rows affected. Used by:
        - password change → ``reason="password_changed"``
        - admin disable → ``reason="deactivated"``
        - role demotion → ``reason="role_changed"``
        """
        result = await self.session.execute(
            update(Session)
            .where(Session.user_id == user_id, Session.revoked_at.is_(None))
            .values(revoked_at=datetime.now(UTC), revocation_reason=reason),
        )
        return int(result.rowcount or 0)

    async def list_active_for_user(self, user_id: UUID) -> list[Session]:
        """Return every live session for one user.

        Used by the dashboard "active sessions" view (B5). Bounded
        by the user's session count, which is bounded by browser
        + device count - never large enough to justify pagination
        in v1.
        """
        result = await self.session.execute(
            select(Session)
            .where(Session.user_id == user_id, Session.revoked_at.is_(None))
            .order_by(Session.issued_at.desc())
            .limit(100),
        )
        return list(result.scalars().all())


__all__ = ["SessionRepository"]
