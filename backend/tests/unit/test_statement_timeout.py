"""The connect listener sets the PostgreSQL timeouts outside any transaction.

The listener used to run its three ``SET`` statements through the adapter's
cursor, which opens SQLAlchemy's implicit asyncpg transaction first, so the
first rollback on the connection (the pool's reset-on-return included) threw
the values away. These tests hold the listener to the path that lasts: the
raw driver connection through ``run_async``, in the documented order, with
the configured values, and nothing at all on SQLite.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.persistence.statement_timeout import install_statement_timeouts
from z4j_brain.settings import Settings


def _settings(database_url: str) -> Settings:
    return Settings(
        database_url=database_url,
        secret="x" * 48,  # type: ignore[arg-type]
        session_secret="y" * 48,  # type: ignore[arg-type]
        audit_chain_secret="z" * 48,  # type: ignore[arg-type]
        environment="dev",
        db_statement_timeout_ms=12_345,
        db_lock_timeout_ms=2_345,
        db_idle_in_tx_timeout_ms=34_567,
    )


EXPECTED = [
    "SET statement_timeout = 12345",
    "SET lock_timeout = 2345",
    "SET idle_in_transaction_session_timeout = 34567",
]


class _RawAsyncpgConnection:
    """The driver connection ``run_async`` hands over: records its ``execute`` calls."""

    def __init__(self) -> None:
        self.executed: list[str] = []

    async def execute(self, statement: str) -> None:
        self.executed.append(statement)


class _AdaptedConnection:
    """What the asyncpg adapter gives a connect listener.

    ``run_async`` runs the coroutine against the raw connection, as
    SQLAlchemy's ``AdaptedConnection.run_async`` does; a cursor is refused,
    because the cursor is the transaction-opening path the fix leaves.
    """

    def __init__(self) -> None:
        self.raw = _RawAsyncpgConnection()

    def run_async(self, fn: Callable[[Any], Awaitable[None]]) -> None:
        asyncio.run(fn(self.raw))

    def cursor(self) -> Any:
        raise AssertionError("the asyncpg path must not open the adapter's cursor")


class _SyncCursor:
    def __init__(self, owner: _SyncConnection) -> None:
        self._owner = owner

    def execute(self, statement: str) -> None:
        self._owner.executed.append(statement)

    def close(self) -> None:
        self._owner.closed_cursors += 1


class _SyncConnection:
    """A synchronous DBAPI connection: no ``run_async``, a cursor and a commit."""

    def __init__(self) -> None:
        self.executed: list[str] = []
        self.closed_cursors = 0
        self.commits = 0

    def cursor(self) -> _SyncCursor:
        return _SyncCursor(self)

    def commit(self) -> None:
        self.commits += 1


class _Untouchable:
    """A connection the SQLite listener must not even look at."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"listener touched the SQLite connection: {name}")


def _fire_connect(engine: Any, dbapi_connection: Any) -> None:
    """Call the listener ``install_statement_timeouts`` registered, and only it.

    The pool's ``connect`` dispatch also carries the dialect's own listener
    (SQLite registers REGEXP, asyncpg its JSON codecs), which would touch
    these stand-ins for reasons that have nothing to do with timeouts.
    """
    listeners = [
        fn
        for fn in engine.sync_engine.pool.dispatch.connect.listeners
        if fn.__qualname__ == "install_statement_timeouts.<locals>._on_connect"
    ]
    assert len(listeners) == 1, "expected exactly one timeout listener on the engine"
    listeners[0](dbapi_connection, None)


def test_listener_is_a_no_op_on_sqlite() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        install_statement_timeouts(engine, settings=_settings("sqlite+aiosqlite:///:memory:"))
        _fire_connect(engine, _Untouchable())
    finally:
        asyncio.run(engine.dispose())


def test_listener_sets_the_three_timeouts_on_the_raw_asyncpg_connection() -> None:
    url = "postgresql+asyncpg://u:p@localhost/d"
    engine = create_async_engine(url)
    try:
        install_statement_timeouts(engine, settings=_settings(url))
        connection = _AdaptedConnection()
        _fire_connect(engine, connection)
    finally:
        asyncio.run(engine.dispose())
    assert connection.raw.executed == EXPECTED


def test_listener_commits_the_cursor_path_on_a_synchronous_driver() -> None:
    url = "postgresql+asyncpg://u:p@localhost/d"
    engine = create_async_engine(url)
    try:
        install_statement_timeouts(engine, settings=_settings(url))
        connection = _SyncConnection()
        _fire_connect(engine, connection)
    finally:
        asyncio.run(engine.dispose())
    assert connection.executed == EXPECTED
    assert connection.closed_cursors == 1
    assert connection.commits == 1, "a cursor-issued SET is session-level only once committed"


@pytest.mark.asyncio
async def test_sqlite_engine_still_connects_and_serves() -> None:
    """The attached listener does not get in the way of a real SQLite connection."""
    from sqlalchemy import text

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        install_statement_timeouts(engine, settings=_settings("sqlite+aiosqlite:///:memory:"))
        async with engine.connect() as conn:
            assert (await conn.execute(text("SELECT 1"))).scalar_one() == 1
    finally:
        await engine.dispose()
