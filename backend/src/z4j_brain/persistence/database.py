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

    1.5.1: pass asyncpg ``statement_cache_size`` +
    ``max_inactive_connection_lifetime`` via ``connect_args``. These
    cap the per-connection prepared-statement cache that was the
    dominant retainer under sustained burst load (Round 19 memray
    confirmed Python heap peak was only 58 MB while process RSS
    grew 1.5 GB -- the delta lived in C-level asyncpg per-connection
    state). Both knobs are exposed in settings.py for operator
    tuning. SQLite skips these (kwargs are asyncpg-only).
    """
    kwargs: dict = {
        "pool_size": 20,
        "max_overflow": 10,
        "pool_pre_ping": True,
        # 1.5.1: shortened from 1800s to the operator-configured
        # value so SQLAlchemy-level pool recycling rotates
        # connections fast enough to bound asyncpg per-connection
        # cache growth under sustained load.
        "pool_recycle": int(
            settings.database_max_inactive_connection_lifetime_seconds,
        ),
        "echo": False,
        "future": True,
    }
    if settings.database_url.startswith("postgresql+asyncpg://"):
        # asyncpg.connect() kwargs only. ``max_inactive_connection_lifetime``
        # is asyncpg.create_pool()'s parameter -- SQLAlchemy uses
        # connect() directly so we pass that kwarg upstairs to
        # ``pool_recycle`` (which is the SQLAlchemy equivalent).
        kwargs["connect_args"] = {
            "statement_cache_size": settings.database_statement_cache_size,
        }
    engine = create_async_engine(settings.database_url, **kwargs)

    # 1.5.1: wire the leak-visibility instrumentation.
    #
    # Listen for asyncpg DeadlockDetectedError surfacing through
    # SQLAlchemy and bump the Prometheus counter. The event fires on
    # every DBAPI exception; we filter to deadlocks only. No hot-path
    # cost on success: SQLAlchemy only calls the listener on error.
    _wire_deadlock_counter(engine)

    # Register the pool-gauge provider so /metrics scrape can read
    # current pool size + checked-out count. Cheap: reads two
    # in-memory attributes on the SQLAlchemy pool object.
    _register_pool_gauge_provider(engine)

    return engine


def _wire_deadlock_counter(engine: AsyncEngine) -> None:
    """Hook SQLAlchemy ``handle_error`` to count Postgres deadlocks.

    The listener fires for every DBAPI exception. We filter to
    deadlocks specifically so the counter reflects the specific
    contention pattern the 1.5.1 sort fixes target. Imports are
    lazy + guarded so the brain still boots cleanly on environments
    where asyncpg or the metrics module is unavailable (SQLite-only
    eval installs, for example).
    """
    try:
        from sqlalchemy import event

        from z4j_brain.api.metrics import (  # noqa: PLC0415
            record_swallowed,
            z4j_postgres_deadlocks_total,
        )
    except ImportError:
        return

    @event.listens_for(engine.sync_engine, "handle_error")
    def _on_dbapi_error(context) -> None:  # type: ignore[no-untyped-def]
        try:
            exc = context.original_exception
            # asyncpg's class hierarchy: DeadlockDetectedError is
            # asyncpg.exceptions.DeadlockDetectedError. The simplest
            # check is on the exception class name so we don't have
            # to import asyncpg at module load time (the SQLite eval
            # path doesn't ship asyncpg).
            if exc.__class__.__name__ == "DeadlockDetectedError":
                z4j_postgres_deadlocks_total.inc()
        except Exception:  # noqa: BLE001
            record_swallowed("database", "deadlock_counter")


def _register_pool_gauge_provider(engine: AsyncEngine) -> None:
    """Register a callable that reports current pool state.

    Invoked at every ``/metrics`` scrape so operators see the live
    pool size + checked-out count. Reads in-memory attributes only;
    no DB query.
    """
    try:
        from z4j_brain.api.metrics import (  # noqa: PLC0415
            register_pool_gauge_provider,
        )
    except ImportError:
        return

    def _read_pool_state() -> tuple[int, int]:
        # SQLAlchemy's async pool wraps a sync pool. Both expose
        # ``size()`` (configured size) and ``checkedout()`` (active
        # checkouts). For QueuePool, ``size()`` is the configured
        # max; for other pool classes the value may differ slightly
        # but the metric is still useful as a high-water signal.
        sync_pool = engine.sync_engine.pool
        try:
            size = sync_pool.size()  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            size = 0
        try:
            checked_out = sync_pool.checkedout()  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            checked_out = 0
        return (int(size), int(checked_out))

    register_pool_gauge_provider(_read_pool_state)


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
