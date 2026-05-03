"""``first_boot_tokens`` repository.

The first-boot token table holds at most one row at any time. The
setup service mints a token, stores its HMAC hash here, and
deletes it the moment setup completes (or expires). The repository
exposes the operations the service needs and nothing else.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import FirstBootToken
from z4j_brain.persistence.repositories._base import BaseRepository


class FirstBootTokenRepository(BaseRepository[FirstBootToken]):
    """Single-row table for the first-boot setup token."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, FirstBootToken)

    async def get_active(self, *, lock: bool = False) -> FirstBootToken | None:
        """Return the most recent unexpired token row, if any.

        There should only ever be one. The ``ORDER BY`` is
        defensive - if a previous boot crashed mid-flow and left
        more than one row, we always pick the newest.

        ``lock=True`` issues ``SELECT ... FOR UPDATE`` so concurrent
        ``setup.complete`` calls serialize on the row instead of
        racing each other through the read-verify-delete sequence.
        SQLite ignores the FOR UPDATE clause silently, which is
        fine for the unit suite - the race is a Postgres-shaped
        production concern.
        """
        stmt = (
            select(FirstBootToken)
            .order_by(FirstBootToken.created_at.desc())
            .limit(1)
        )
        if lock:
            stmt = stmt.with_for_update()
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def insert(
        self,
        *,
        token_hash: str,
        expires_at: datetime,
    ) -> FirstBootToken:
        """Insert a fresh token row.

        Caller is responsible for clearing any old rows first via
        :meth:`delete_all` - this method does not race-check.
        """
        row = FirstBootToken(token_hash=token_hash, expires_at=expires_at)
        self.session.add(row)
        await self.session.flush()
        return row

    async def delete_by_id(self, token_id: UUID) -> None:
        """Delete a single row by id.

        Used after a successful setup to consume the token.
        """
        await self.session.execute(
            delete(FirstBootToken).where(FirstBootToken.id == token_id),
        )

    async def delete_all(self) -> int:
        """Wipe the table.

        Called by the startup hook before minting a fresh token,
        and by the setup service after a successful complete (as
        defence against the rare case of a stale row leaking
        from a crashed previous run).
        """
        result = await self.session.execute(delete(FirstBootToken))
        return int(result.rowcount or 0)


__all__ = ["FirstBootTokenRepository"]
