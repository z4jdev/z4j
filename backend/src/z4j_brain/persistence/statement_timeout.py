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
overhead-heavy and (b) the connect-time setting persists across
the connection's lifetime which matches what we actually want.

SQLite has none of these knobs - the function is a no-op there.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

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

    statement_ms = settings.db_statement_timeout_ms
    lock_ms = settings.db_lock_timeout_ms
    idle_ms = settings.db_idle_in_tx_timeout_ms

    @event.listens_for(sync_engine, "connect")
    def _on_connect(dbapi_connection, connection_record) -> None:  # type: ignore[no-untyped-def]
        # Determine dialect from the engine, not the dbapi
        # connection (which doesn't carry that info uniformly).
        dialect_name = sync_engine.dialect.name
        if dialect_name != "postgresql":
            return
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute(f"SET statement_timeout = {int(statement_ms)}")
            cursor.execute(f"SET lock_timeout = {int(lock_ms)}")
            cursor.execute(
                f"SET idle_in_transaction_session_timeout = {int(idle_ms)}",
            )
        finally:
            cursor.close()


__all__ = ["install_statement_timeouts"]
