"""The connect-time PostgreSQL timeouts outlive a rollback and the pool's reset on return.

``install_statement_timeouts`` sets ``statement_timeout``, ``lock_timeout``
and ``idle_in_transaction_session_timeout`` once per connection. Issued
inside the adapter's implicit transaction they lasted only until the first
rollback, which the pool performs on every return; on one pooled connection
that is the second checkout. Each test here reads the three values from
``pg_settings`` on a one-connection pool, before and after that rollback,
on the same backend pid.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine
from z4j_brain.persistence.database import create_async_engine_from_url
from z4j_brain.persistence.statement_timeout import install_statement_timeouts
from z4j_brain.settings import Settings

pytestmark = pytest.mark.asyncio

#: Values no role or server default would produce, in milliseconds.
CONFIGURED = {
    "statement_timeout": 12_345,
    "lock_timeout": 2_345,
    "idle_in_transaction_session_timeout": 34_567,
}
#: PostgreSQL's own default for all three: disabled.
DISABLED = dict.fromkeys(CONFIGURED, 0)


def _settings(integration_settings: Settings) -> Settings:
    return integration_settings.model_copy(
        update={
            "db_statement_timeout_ms": CONFIGURED["statement_timeout"],
            "db_lock_timeout_ms": CONFIGURED["lock_timeout"],
            "db_idle_in_tx_timeout_ms": CONFIGURED["idle_in_transaction_session_timeout"],
        },
    )


def _one_connection_engine(url: str) -> AsyncEngine:
    """A pool of exactly one connection, so the second checkout reuses the first."""
    return create_async_engine_from_url(url, pool_size=1, max_overflow=0)


async def _timeouts(conn: AsyncConnection) -> dict[str, int]:
    """The three session values in milliseconds, as PostgreSQL holds them."""
    values: dict[str, int] = {}
    for name in CONFIGURED:
        raw = (
            await conn.execute(
                text("SELECT setting FROM pg_settings WHERE name = :name"),
                {"name": name},
            )
        ).scalar_one()
        values[name] = int(raw)
    return values


async def _backend_pid(conn: AsyncConnection) -> int:
    return int((await conn.execute(text("SELECT pg_backend_pid()"))).scalar_one())


async def test_timeouts_survive_a_rollback_and_the_pool_return(
    fresh_database_async_url: str,
    integration_settings: Settings,
) -> None:
    engine = _one_connection_engine(fresh_database_async_url)
    install_statement_timeouts(engine, settings=_settings(integration_settings))
    try:
        async with engine.connect() as conn:
            first_pid = await _backend_pid(conn)
            assert await _timeouts(conn) == CONFIGURED
            await conn.rollback()
        # Returned to the pool, which rolls the connection back once more.
        async with engine.connect() as conn:
            assert await _backend_pid(conn) == first_pid, "the pool handed out a new connection"
            assert await _timeouts(conn) == CONFIGURED

            # Positive control that this probe sees a change at all, and that
            # a transaction-scoped override (the startup verifier widens its
            # lock wait this way) is gone with its transaction.
            await conn.execute(text("SET LOCAL statement_timeout = 777"))
            assert (await _timeouts(conn))["statement_timeout"] == 777
            await conn.rollback()
        async with engine.connect() as conn:
            assert await _backend_pid(conn) == first_pid
            assert await _timeouts(conn) == CONFIGURED
    finally:
        await engine.dispose()


async def test_a_cursor_issued_set_is_lost_at_the_first_rollback(
    fresh_database_async_url: str,
    integration_settings: Settings,
) -> None:
    """The negative control: the listener as it used to be written loses the values.

    A cursor statement on a new adapted connection opens SQLAlchemy's implicit
    transaction first, and PostgreSQL drops a plain ``SET`` with the
    transaction it ran in. If this test ever starts passing the CONFIGURED
    values on the second checkout, the adapter changed and the probe above
    proves less than it claims.
    """
    engine = _one_connection_engine(fresh_database_async_url)
    settings = _settings(integration_settings)

    @event.listens_for(engine.sync_engine, "connect")
    def _old_listener(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute(f"SET statement_timeout = {settings.db_statement_timeout_ms}")
            cursor.execute(f"SET lock_timeout = {settings.db_lock_timeout_ms}")
            cursor.execute(
                f"SET idle_in_transaction_session_timeout = {settings.db_idle_in_tx_timeout_ms}",
            )
        finally:
            cursor.close()

    try:
        async with engine.connect() as conn:
            first_pid = await _backend_pid(conn)
            # Still inside the transaction the cursor opened: the values show.
            assert await _timeouts(conn) == CONFIGURED
            await conn.rollback()
        async with engine.connect() as conn:
            assert await _backend_pid(conn) == first_pid
            assert await _timeouts(conn) == DISABLED
    finally:
        await engine.dispose()
