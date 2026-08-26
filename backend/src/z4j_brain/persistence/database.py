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
from typing import TYPE_CHECKING, Any

import structlog
from sqlalchemy import event, text
from sqlalchemy.engine.url import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from z4j_brain.postgres_tls import asyncpg_engine_url_and_connect_args

if TYPE_CHECKING:
    from z4j_brain.settings import Settings

logger = structlog.get_logger("z4j.brain.persistence")


def _enable_sqlite_foreign_keys(dbapi_connection: Any) -> None:
    """Enable and verify SQLite referential actions on one DBAPI connection.

    SQLite defaults ``PRAGMA foreign_keys`` to OFF independently for every
    connection.  Declaring ``ON DELETE`` actions in metadata therefore is not
    sufficient: without this hook a pooled runtime connection can silently
    retain orphaned rows.  Read the value back so an unsupported or
    transaction-scoped no-op fails closed instead of merely looking enabled.
    """

    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute("PRAGMA foreign_keys")
        row = cursor.fetchone()
    finally:
        cursor.close()
    if row is None or int(row[0]) != 1:
        raise RuntimeError("SQLite connection refused PRAGMA foreign_keys = ON")


def _sqlite_foreign_keys_on_connect(
    dbapi_connection: Any,
    _connection_record: Any,
) -> None:
    _enable_sqlite_foreign_keys(dbapi_connection)


def _sqlite_foreign_keys_on_checkout(
    dbapi_connection: Any,
    _connection_record: Any,
    _connection_proxy: Any,
) -> None:
    # Also enforce on checkout.  ``create_app(..., engine=...)`` accepts an
    # engine that may already own a pooled connection, so a connect-only hook
    # would never see StaticPool's pre-existing in-memory SQLite connection.
    _enable_sqlite_foreign_keys(dbapi_connection)


def _install_sqlite_foreign_key_hooks(engine: AsyncEngine) -> None:
    """Install idempotent fail-closed SQLite FK enforcement hooks."""

    if engine.dialect.name != "sqlite":
        return
    sync_engine = engine.sync_engine
    if not event.contains(sync_engine, "connect", _sqlite_foreign_keys_on_connect):
        event.listen(sync_engine, "connect", _sqlite_foreign_keys_on_connect)
    if not event.contains(sync_engine, "checkout", _sqlite_foreign_keys_on_checkout):
        event.listen(sync_engine, "checkout", _sqlite_foreign_keys_on_checkout)


def create_async_engine_from_url(
    database_url: str,
    **kwargs: Any,
) -> AsyncEngine:
    """Create an async engine after translating asyncpg TLS URL options."""

    engine_url, tls_connect_args = asyncpg_engine_url_and_connect_args(database_url)
    supplied_connect_args = dict(kwargs.pop("connect_args", {}))
    conflicts = supplied_connect_args.keys() & tls_connect_args.keys()
    if conflicts:
        raise ValueError(
            "async engine connect_args conflict with database URL TLS options: "
            f"{sorted(conflicts)}",
        )
    connect_args = {**supplied_connect_args, **tls_connect_args}
    if connect_args:
        kwargs["connect_args"] = connect_args
    engine = create_async_engine(engine_url, **kwargs)
    _install_sqlite_foreign_key_hooks(engine)
    return engine


def _uses_static_pool(database_url: str) -> bool:
    """Does SQLAlchemy give this URL a StaticPool rather than a sized pool?

    Only in-memory SQLite. A shared-cache memory URL counts too, since it is
    still one database living in one connection.

    Asks SQLAlchemy what the URL means rather than matching text on it. The
    substring test missed the bare form, ``sqlite+aiosqlite://`` with no path,
    which SQLAlchemy also treats as in-memory: ``make_url(...).database`` is
    ``None``. That deployment got a sized pool over an in-memory database, so
    every connection opened its own empty one, and tables created during
    migration were invisible to the next request. Confusing to diagnose and
    trivial to configure by accident.
    """
    if not database_url.startswith("sqlite"):
        return False
    try:
        parsed = make_url(database_url)
        database = parsed.database
    except Exception:
        return ":memory:" in database_url or "mode=memory" in database_url
    if not database:
        # No path at all: SQLAlchemy opens an anonymous in-memory database.
        return True
    if ":memory:" in database:
        return True
    # ``mode=memory`` is a URI query parameter, and SQLAlchemy splits it off
    # the path, so looking for it in ``database`` alone finds nothing. The
    # first version of this fix did exactly that and broke the shared-cache
    # form it was not supposed to touch.
    return str(parsed.query.get("mode", "")) == "memory" or "mode=memory" in database


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
    from z4j_brain.management_restore import (
        assert_database_restore_not_pending,
    )

    assert_database_restore_not_pending(settings.database_url)
    kwargs: dict[str, Any] = {
        # Operator-configurable since 1.8.0. Previously hardcoded, which made
        # the brain's connection demand impossible to fit to a server the
        # operator does not control: each uvicorn worker builds its own
        # engine and `serve` defaults to min(4, cpu_count) workers, so the
        # worst case is workers * (pool_size + max_overflow). At the defaults
        # on a 4-core host that is 120, above a stock PostgreSQL
        # max_connections of 100. Defaults are unchanged; see settings.py and
        # docs/DATABASE.md for the sizing arithmetic.
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
    # Pool sizing only applies to a pool that HAS a size. SQLAlchemy gives an
    # in-memory SQLite database a StaticPool (one shared connection, by
    # necessity: separate connections would see separate empty databases), and
    # StaticPool rejects these arguments outright. Passing them unconditionally
    # made ``sqlite+aiosqlite:///:memory:`` fail at engine construction with an
    # opaque "Invalid argument(s) 'pool_size','max_overflow'". A file-backed
    # SQLite URL gets a real queue pool and is unaffected, which is why this
    # went unnoticed: the deployment shapes that matter both work.
    if not _uses_static_pool(settings.database_url):
        kwargs["pool_size"] = settings.database_pool_size
        kwargs["max_overflow"] = settings.database_max_overflow

    if settings.database_url.startswith("postgresql+asyncpg://"):
        # asyncpg.connect() kwargs only. ``max_inactive_connection_lifetime``
        # is asyncpg.create_pool()'s parameter -- SQLAlchemy uses
        # connect() directly so we pass that kwarg upstairs to
        # ``pool_recycle`` (which is the SQLAlchemy equivalent).
        kwargs["connect_args"] = {
            "statement_cache_size": settings.database_statement_cache_size,
        }
    engine = create_async_engine_from_url(settings.database_url, **kwargs)
    from z4j_brain.management_restore import (
        install_database_restore_fence_engine_hook,
    )

    install_database_restore_fence_engine_hook(
        engine,
        settings.database_url,
    )

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

        from z4j_brain.api.metrics import (
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
        except Exception:
            record_swallowed("database", "deadlock_counter")


def _register_pool_gauge_provider(engine: AsyncEngine) -> None:
    """Register a callable that reports current pool state.

    Invoked at every ``/metrics`` scrape so operators see the live
    pool size + checked-out count. Reads in-memory attributes only;
    no DB query.
    """
    try:
        from z4j_brain.api.metrics import (
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
        except Exception:
            size = 0
        try:
            checked_out = sync_pool.checkedout()  # type: ignore[attr-defined]
        except Exception:
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
        from z4j_brain.persistence.schedule_guard import (
            install_schedule_guard_engine_hooks,
        )

        _install_sqlite_foreign_key_hooks(engine)
        install_schedule_guard_engine_hooks(engine)
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
    async def session(
        self,
        *,
        write: bool = False,
    ) -> AsyncIterator[AsyncSession]:
        """Yield a session, rolling back on error.

        Used by background workers. Request handlers should depend
        on :func:`get_session` instead so the session is tied to the
        FastAPI request scope.
        """
        async with self._sessionmaker() as session:
            try:
                if write and self._engine.dialect.name == "sqlite":
                    await session.execute(text("BEGIN IMMEDIATE"))
                    session.sync_session.info["z4j_sqlite_immediate"] = True
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


async def get_session(request: Any) -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a per-request ``AsyncSession``.

    The session is tied to request scope: it is opened on enter and
    closed on exit, with a rollback on any unhandled exception. The
    handler is expected to ``await session.commit()`` itself when it
    has produced a successful response - the dependency does not
    auto-commit, since some endpoints (e.g. read-only queries)
    should never commit at all.
    """
    db: DatabaseManager = request.app.state.db
    write = str(getattr(request, "method", "GET")).upper() not in {
        "GET",
        "HEAD",
        "OPTIONS",
    }
    async with db.session(write=write) as session:
        yield session


__all__ = [
    "DatabaseManager",
    "create_async_engine_from_url",
    "create_engine_from_settings",
    "get_session",
]
