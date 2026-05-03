"""Async SQLAlchemy engine + session lifecycle.

The brain owns a single ``AsyncEngine`` per process. Sessions are
opened per request via the ``get_session`` FastAPI dependency, which
yields an ``AsyncSession`` and closes it when the handler returns.
``DatabaseManager`` is the small object the app factory holds onto so
shutdown can dispose of the engine cleanly.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import structlog
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

if TYPE_CHECKING:
    from z4j_brain.settings import Settings

logger = structlog.get_logger("z4j.brain.persistence")


def create_engine_from_settings(settings: Settings) -> AsyncEngine:
    """Build the brain's :class:`AsyncEngine` from runtime settings.

    Defaults are tuned for a single-process brain serving the
    dashboard plus the agent gateway. Pool sizing should be revised
    when we benchmark - see ``docs/BACKEND.md §15``.
    """
    return create_async_engine(
        settings.database_url,
        pool_size=20,
        max_overflow=10,
        pool_pre_ping=True,
        pool_recycle=1800,
        echo=False,
        future=True,
    )


class DatabaseManager:
    """Owns the async engine + sessionmaker for the lifetime of the app.

    Constructed once by ``create_app`` and stashed on
    ``app.state.db``. Provides:

    - ``session()`` - async context manager yielding an
      ``AsyncSession`` (used by background workers)
    - ``dispose()`` - closes the engine on shutdown

    The FastAPI request dependency :func:`get_session` reads the
    ``DatabaseManager`` from the app state via ``request.app.state.db``
    so handlers do not need to import this module directly.
    """

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._sessionmaker: async_sessionmaker[AsyncSession] = async_sessionmaker(
            bind=engine,
            expire_on_commit=False,
            autoflush=False,
            class_=AsyncSession,
        )

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """Yield a session, rolling back on error.

        Used by background workers. Request handlers should depend
        on :func:`get_session` instead so the session is tied to the
        FastAPI request scope.
        """
        async with self._sessionmaker() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise

    async def dispose(self) -> None:
        """Dispose the engine on shutdown.

        Idempotent - calling twice is a no-op. Logged so operators
        can confirm clean shutdown in the structured logs.
        """
        await self._engine.dispose()
        logger.info("z4j database engine disposed")


async def get_session(request: "Any") -> AsyncIterator[AsyncSession]:  # type: ignore[name-defined]
    """FastAPI dependency yielding a per-request ``AsyncSession``.

    The session is tied to request scope: it is opened on enter and
    closed on exit, with a rollback on any unhandled exception. The
    handler is expected to ``await session.commit()`` itself when it
    has produced a successful response - the dependency does not
    auto-commit, since some endpoints (e.g. read-only queries)
    should never commit at all.
    """
    db: DatabaseManager = request.app.state.db
    async with db.session() as session:
        yield session


__all__ = [
    "DatabaseManager",
    "create_engine_from_settings",
    "get_session",
]
