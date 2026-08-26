"""``api_keys`` repository."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models.api_key import ApiKey
from z4j_brain.persistence.repositories._base import BaseRepository


class ApiKeyRepository(BaseRepository[ApiKey]):
    """Personal API key CRUD + lookup by token hash."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, ApiKey)

    async def create(
        self,
        *,
        user_id: UUID,
        name: str,
        token_hash: str,
        prefix: str,
        scopes: list[str],
        project_id: UUID | None = None,
        expires_at: datetime | None = None,
    ) -> ApiKey:
        """Insert a new API key row.

        The plaintext token is NOT stored - only the HMAC hash.
        Caller is responsible for returning the plaintext to the
        user exactly once.
        """
        api_key = ApiKey(
            user_id=user_id,
            name=name,
            token_hash=token_hash,
            prefix=prefix,
            scopes=scopes,
            project_id=project_id,
            expires_at=expires_at,
        )
        self.session.add(api_key)
        await self.session.flush()
        return api_key

    async def list_for_user(self, user_id: UUID) -> list[ApiKey]:
        """Return all active (non-revoked) keys for a user.

        Ordered by creation date descending so the newest key
        appears first.
        """
        result = await self.session.execute(
            select(ApiKey)
            .where(
                ApiKey.user_id == user_id,
                ApiKey.revoked_at.is_(None),
            )
            .order_by(ApiKey.created_at.desc()),
        )
        return list(result.scalars().all())

    async def get_by_hash(self, token_hash: str) -> ApiKey | None:
        """Resolve an API key by its HMAC hash.

        Used by auth middleware to authenticate inbound requests
        bearing a ``z4k_`` prefixed token. Single index lookup
        (``token_hash`` is UNIQUE).
        """
        result = await self.session.execute(
            select(ApiKey).where(ApiKey.token_hash == token_hash),
        )
        return result.scalar_one_or_none()

    async def revoke(
        self,
        key_id: UUID,
        user_id: UUID,
        *,
        reason: str | None = None,
    ) -> bool:
        """Soft-revoke a key by setting ``revoked_at``.

        ``reason`` is free-form (e.g. "rotated", "leaked",
        "user_deleted") and shown in the audit trail. Returns True
        if a row was updated, False if the key was not found or did
        not belong to the user.
        """
        result = await self.session.execute(
            update(ApiKey)
            .where(
                ApiKey.id == key_id,
                ApiKey.user_id == user_id,
                ApiKey.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.now(UTC), revoked_reason=reason),
        )
        return bool(result.rowcount)

    async def touch_used(
        self,
        *,
        key_id: UUID,
        ip: str | None = None,
        when: datetime | None = None,
    ) -> bool:
        """Advance ``last_used_at`` (and optionally ``last_used_ip``), MONOTONICALLY.

        Called on every successful authentication with this key. ``when`` is
        the moment the key AUTHENTICATED, which is not the moment this runs:
        the write is deferred until the request's own connection is back in
        the pool, so two overlapping requests arrive here in whatever order
        they finish rather than the order they started.

        The write is therefore refused unless it moves the stamp FORWARD.
        Unconditionally, a request that authenticated at 12:00 and finished
        at 12:05 overwrote the 12:04 stamp left by a request that started
        four minutes after it, and dragged ``last_used_ip`` back to the
        earlier caller's address with it. This pair is what an operator reads
        when deciding whether a key has been used since it leaked, so a value
        that belongs to an earlier use is not untidy, it is misleading.

        Returns True if the row moved.
        """
        stamp = when or datetime.now(UTC)
        values: dict[str, object] = {"last_used_at": stamp}
        if ip is not None:
            values["last_used_ip"] = ip
        result = await self.session.execute(
            update(ApiKey)
            .where(ApiKey.id == key_id)
            .where(or_(ApiKey.last_used_at.is_(None), ApiKey.last_used_at < stamp))
            .values(**values),
        )
        return bool(result.rowcount)


__all__ = ["ApiKeyRepository"]
