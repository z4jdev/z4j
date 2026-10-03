"""SQLAlchemy event hooks that enforce per-statement DB timeouts.

Postgres exposes three timeouts that we want to set on every
connection:

- ``statement_timeout`` - kills any single statement that runs
  longer than the budget
- ``lock_timeout`` - kills any wait for a lock that runs longer
  than the budget
- ``idle_in_transaction_session_timeout`` - kills sessions that
  open a transaction and then sit on it

We set them via a ``connect`` event on the engine, NOT via
``SET LOCAL ...`` per-statement, because (a) per-statement is
overhead-heavy and (b) a session-level setting lasts for the
connection's lifetime, which matches what we actually want.

Session-level means issued OUTSIDE any transaction. PostgreSQL discards
a plain ``SET`` run inside a transaction that is later rolled back, and
SQLAlchemy's asyncpg adapter opens its implicit transaction before the
first cursor statement on a new connection. Issued through a cursor, the
three SETs therefore lasted only until that connection's first rollback
(the pool's reset-on-return is one), after which the connection ran with
none of the bounds for the rest of its life; a connection whose first unit
of work happened to commit kept them, so which pooled connections were
bounded depended on what they served first. The listener runs the SETs on
the raw asyncpg connection instead, through the adapted connection's
``run_async``: outside a transaction block asyncpg's ``execute``
autocommits, so the values are session-level and survive every rollback,
reset and ``SET LOCAL`` (startup verification widens its lock wait that
way, and the connection goes back to the pool with these values intact).

``idle_in_transaction_session_timeout`` applies to every connection
this engine hands out, including one that is not doing work itself
but holding something on behalf of work happening elsewhere. Anything
that has to outlive a single unit of work therefore must not sit
inside a transaction while it waits, or PostgreSQL will terminate it
mid-wait and the holder will never hear about it. The leader lock in
``domain/workers/_leader_lock`` is the case that matters: it holds a
session-scoped advisory lock on a connection with no open
transaction, precisely so this budget cannot apply to it.

SQLite has none of these knobs - the function is a no-op there.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import event

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine
    from sqlalchemy.ext.asyncio import AsyncEngine

    from z4j_brain.settings import Settings


def install_statement_timeouts(
    engine: AsyncEngine | Engine,
    *,
    settings: Settings,
) -> None:
    """Wire connect-time SET commands on every new DB connection.

    Idempotent: calling twice attaches a second listener which is
    harmless because the SET commands are themselves idempotent.
    Tests that build many short-lived engines should not care.

    On SQLite the listener is still attached but its body is a
    no-op - the dialect check inside the handler decides.
    """
    sync_engine = getattr(engine, "sync_engine", engine)

    # Session-level only if issued outside a transaction; see the module
    # docstring. Order is the one the settings are documented in.
    statements = (
        f"SET statement_timeout = {int(settings.db_statement_timeout_ms)}",
        f"SET lock_timeout = {int(settings.db_lock_timeout_ms)}",
        f"SET idle_in_transaction_session_timeout = {int(settings.db_idle_in_tx_timeout_ms)}",
    )

    async def _apply_on_raw_connection(raw_connection: Any) -> None:
        # asyncpg's ``execute`` outside a transaction block autocommits, and
        # a new connection has no transaction yet: the adapter opens its
        # implicit one at the first cursor statement, which this is not.
        for statement in statements:
            await raw_connection.execute(statement)

    @event.listens_for(sync_engine, "connect")
    def _on_connect(dbapi_connection: Any, connection_record: Any) -> None:
        # Determine dialect from the engine, not the dbapi
        # connection (which doesn't carry that info uniformly).
        dialect_name = sync_engine.dialect.name
        if dialect_name != "postgresql":
            return
        run_async = getattr(dbapi_connection, "run_async", None)
        if run_async is not None:
            # SQLAlchemy's asyncpg adapter: ``run_async`` hands the raw
            # driver connection to the coroutine, bypassing the adapter's
            # cursor and the transaction it would open.
            run_async(_apply_on_raw_connection)
            return
        # A synchronous DBAPI connection (psycopg) runs the cursor inside the
        # driver's implicit transaction; committing it is what makes the
        # SETs session-level there. No shipped engine takes this path today.
        cursor = dbapi_connection.cursor()
        try:
            for statement in statements:
                cursor.execute(statement)
        finally:
            cursor.close()
        dbapi_connection.commit()


__all__ = ["install_statement_timeouts"]
