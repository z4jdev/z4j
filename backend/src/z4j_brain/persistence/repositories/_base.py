"""Generic repository base.

Holds the operations every concrete repository needs:
``get``, ``get_or_404``, ``add``, ``delete``, ``count``,
``list``. Concrete repositories add domain-specific finders
(``get_by_email``, ``find_active_for_user``, ...) and never reach
back into raw SQL outside their own module.
"""

from __future__ import annotations

from typing import Generic, TypeVar
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.errors import NotFoundError

ModelT = TypeVar("ModelT")


class BaseRepository(Generic[ModelT]):
    """Generic CRUD repository for one ORM model.

    Concrete subclasses should NOT override the methods here unless
    they have a real reason. Add domain-specific methods on the
    subclass instead - that keeps the contract simple to read.
    """

    def __init__(self, session: AsyncSession, model: type[ModelT]) -> None:
        self._session = session
        self._model = model

    @property
    def session(self) -> AsyncSession:
        """Expose the bound session for repositories that need raw select."""
        return self._session

    @property
    def model(self) -> type[ModelT]:
        """The ORM model class this repository operates on."""
        return self._model

    async def get(self, pk: UUID) -> ModelT | None:
        """Return the row by primary key, or ``None`` if missing."""
        return await self._session.get(self._model, pk)

    async def get_or_404(self, pk: UUID) -> ModelT:
        """Return the row by primary key, or raise :class:`NotFoundError`."""
        obj = await self._session.get(self._model, pk)
        if obj is None:
            raise NotFoundError(
                f"{self._model.__name__} {pk} not found",
                details={"model": self._model.__name__, "id": str(pk)},
            )
        return obj

    async def add(self, obj: ModelT) -> ModelT:
        """Add a new instance to the session.

        Does NOT commit - the caller controls the transaction.
        Flushes so server-side defaults populate before the caller
        reads them back.
        """
        self._session.add(obj)
        await self._session.flush()
        return obj

    async def delete(self, obj: ModelT) -> None:
        """Delete an instance. Does NOT commit."""
        await self._session.delete(obj)
        await self._session.flush()

    async def count(self) -> int:
        """Total row count for the model.

        Hot tables (``events``, ``audit_log``) should NOT use this
        - they need a more specific predicate. ``count()`` is for
        the small admin tables (``users``, ``first_boot_tokens``).
        """
        result = await self._session.execute(select(func.count()).select_from(self._model))
        return int(result.scalar_one())

    async def list(self, *, limit: int = 50, offset: int = 0) -> list[ModelT]:
        """Return a paginated list of rows. No filter - concrete
        repositories add filtered methods.

        Always bounded by ``limit`` to prevent unbounded scans.
        """
        if limit <= 0 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if offset < 0:
            raise ValueError("offset must be >= 0")
        result = await self._session.execute(
            select(self._model).limit(limit).offset(offset),
        )
        return list(result.scalars().all())


__all__ = ["BaseRepository"]
