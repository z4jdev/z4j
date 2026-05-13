"""``mfa_recovery_codes`` repository.

Single-use TOTP recovery codes. argon2id-hashed at insert time;
verification iterates the user's not-yet-consumed codes and compares
each hash via :func:`z4j_brain.domain.mfa.recovery.verify_recovery_code`,
flipping ``consumed_at`` on a match.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import MfaRecoveryCode
from z4j_brain.persistence.repositories._base import BaseRepository


class MfaRecoveryCodeRepository(BaseRepository[MfaRecoveryCode]):
    """CRUD + consume on the user's recovery codes."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, MfaRecoveryCode)

    async def list_unused_for_user(
        self,
        user_id: UUID,
    ) -> list[MfaRecoveryCode]:
        """Return every not-yet-consumed code for the user.

        Verification reads this list and walks it linearly, comparing
        each hash. Default cap of 10 codes per user means linear scan
        is fine; if the cap is raised significantly, consider hashing
        the input code with a deterministic prefix first.
        """
        result = await self.session.execute(
            select(MfaRecoveryCode).where(
                MfaRecoveryCode.user_id == user_id,
                MfaRecoveryCode.consumed_at.is_(None),
            ),
        )
        return list(result.scalars().all())

    async def count_unused_for_user(self, user_id: UUID) -> int:
        result = await self.session.execute(
            select(MfaRecoveryCode).where(
                MfaRecoveryCode.user_id == user_id,
                MfaRecoveryCode.consumed_at.is_(None),
            ),
        )
        return len(list(result.scalars().all()))

    async def consume(self, code_id: UUID) -> bool:
        """Atomically flip ``consumed_at`` iff the row is still unused.

        Returns True when this call was the one that consumed the
        code, False when another concurrent verify won the race.
        Callers MUST check the return value: the recovery-code path
        in ``POST /auth/mfa/verify`` treats a False as "the code was
        already redeemed in a parallel request" and rejects the
        verify with the same error as a wrong code.

        The ``WHERE consumed_at IS NULL`` guard is what makes
        recovery codes truly single-use under concurrent verifies.
        Without it, two parallel verifies presenting the same code
        could BOTH mark the user as MFA-verified (audit Critical-1
        in the 1.6.0 audit). The flag here is the single source of
        truth -- callers must not pre-check ``consumed_at`` and skip
        this call.
        """
        result = await self.session.execute(
            update(MfaRecoveryCode)
            .where(
                MfaRecoveryCode.id == code_id,
                MfaRecoveryCode.consumed_at.is_(None),
            )
            .values(consumed_at=datetime.now(UTC)),
        )
        return result.rowcount > 0

    async def delete_all_for_user(self, user_id: UUID) -> None:
        """Hard-delete every code (consumed or not) for the user.

        Used by disable, regenerate, and admin reset paths.
        """
        await self.session.execute(
            delete(MfaRecoveryCode).where(
                MfaRecoveryCode.user_id == user_id,
            ),
        )

    async def bulk_insert(
        self,
        *,
        user_id: UUID,
        hashed_codes: list[str],
    ) -> None:
        """Insert one row per pre-hashed code.

        ``hashed_codes`` is a list of argon2id hashes produced by
        :func:`z4j_brain.domain.mfa.recovery.hash_recovery_code`.
        Plaintext is the caller's responsibility (returned to the
        user, never persisted here).
        """
        if not hashed_codes:
            return
        self.session.add_all(
            [
                MfaRecoveryCode(user_id=user_id, code_hash=h)
                for h in hashed_codes
            ],
        )


__all__ = ["MfaRecoveryCodeRepository"]
