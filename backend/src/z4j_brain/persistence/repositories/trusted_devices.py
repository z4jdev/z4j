"""``trusted_devices`` repository.

Server-side store backing the ``z4j_mfa_trust`` "remember this device"
cookie. The cookie carries an opaque random ``cookie_id`` (32 bytes
urlsafe-base64); the server stores its SHA-256 hash. Verification
hashes the inbound cookie value and looks up an unrevoked, unexpired
row for the user.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import TrustedDevice
from z4j_brain.persistence.repositories._base import BaseRepository


class TrustedDeviceRepository(BaseRepository[TrustedDevice]):
    """CRUD + lookup on the trusted-device store."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, TrustedDevice)

    async def create(
        self,
        *,
        user_id: UUID,
        cookie_id_hash: str,
        label: str,
        expires_at: datetime,
    ) -> TrustedDevice:
        row = TrustedDevice(
            user_id=user_id,
            cookie_id_hash=cookie_id_hash,
            label=label,
            expires_at=expires_at,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def find_active(
        self,
        *,
        user_id: UUID,
        cookie_id_hash: str,
    ) -> TrustedDevice | None:
        """Return the row iff it exists, matches the user, is not
        revoked, and has not expired.

        Used by login to decide whether to skip the MFA second step.
        The hash + user_id pair is uniquely indexed so the lookup is
        constant-time-ish at any reasonable user-fleet size.
        """
        result = await self.session.execute(
            select(TrustedDevice).where(
                TrustedDevice.user_id == user_id,
                TrustedDevice.cookie_id_hash == cookie_id_hash,
                TrustedDevice.revoked_at.is_(None),
                TrustedDevice.expires_at > datetime.now(UTC),
            ),
        )
        return result.scalar_one_or_none()

    async def count_active_for_user(self, user_id: UUID) -> int:
        """Count unrevoked, unexpired trust rows for the user.
        Used by the verify endpoint to enforce a per-user trust cap so
        an attacker with a stolen session cannot mint thousands of
        trust rows and DoS the table. (1.6.0 audit High-7.)
        """
        from sqlalchemy import func

        result = await self.session.execute(
            select(func.count())
            .select_from(TrustedDevice)
            .where(
                TrustedDevice.user_id == user_id,
                TrustedDevice.revoked_at.is_(None),
                TrustedDevice.expires_at > datetime.now(UTC),
            ),
        )
        return int(result.scalar() or 0)

    async def list_for_user(self, user_id: UUID) -> list[TrustedDevice]:
        """Return every trusted-device row for the user.

        Includes revoked + expired rows so the user can see what's
        been used historically; the API caller filters as needed.
        """
        result = await self.session.execute(
            select(TrustedDevice)
            .where(TrustedDevice.user_id == user_id)
            .order_by(TrustedDevice.last_seen_at.desc()),
        )
        return list(result.scalars().all())

    async def touch(self, device_id: UUID) -> None:
        """Bump ``last_seen_at`` after a successful trust-skip.
        Guarded so a revoke-vs-touch race cannot resurrect a revoked
        row's freshness. The guard is belt-and-braces: find_active()
        already filtered, but the row might have been revoked in the
        window between that read and this write. (1.6.0 High-1.)
        """
        await self.session.execute(
            update(TrustedDevice)
            .where(
                TrustedDevice.id == device_id,
                TrustedDevice.revoked_at.is_(None),
            )
            .values(last_seen_at=datetime.now(UTC)),
        )

    async def revoke(self, *, device_id: UUID, user_id: UUID) -> bool:
        """Mark a single device revoked. Idempotent.

        Scoped to ``user_id`` so an attacker who knows another user's
        device id cannot revoke it. Returns True iff a row was updated.
        """
        result = await self.session.execute(
            update(TrustedDevice)
            .where(
                TrustedDevice.id == device_id,
                TrustedDevice.user_id == user_id,
                TrustedDevice.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.now(UTC)),
        )
        return result.rowcount > 0

    async def rename(
        self,
        *,
        device_id: UUID,
        user_id: UUID,
        label: str,
    ) -> bool:
        """Rename the user-facing label for a device the user owns.

        Returns True iff a row was updated.
        """
        result = await self.session.execute(
            update(TrustedDevice)
            .where(
                TrustedDevice.id == device_id,
                TrustedDevice.user_id == user_id,
            )
            .values(label=label),
        )
        return result.rowcount > 0

    async def delete_all_for_user(self, user_id: UUID) -> None:
        """Hard-delete every trusted-device row for the user.

        Called by ``POST /auth/change-password`` and by
        ``POST /auth/mfa/disable`` and by ``z4j reset-mfa``. The
        cookie continues to send from the browser but the server
        will not find a row, so the trust is gone immediately.
        """
        await self.session.execute(
            delete(TrustedDevice).where(
                TrustedDevice.user_id == user_id,
            ),
        )


__all__ = ["TrustedDeviceRepository"]
