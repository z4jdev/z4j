"""Per-worker leader-lock helper.

Without leader-locking, every brain replica that boots with
``scheduler_grpc_enabled=True`` runs its own
``PendingFiresReplayWorker``, ``ScheduleCircuitBreakerWorker``,
and ``ScheduleFiresPruneWorker`` on the same cadence. With three
replicas behind a load balancer, every tick fires three times -
duplicate audit rows, duplicate dispatcher calls (deduped via
``commands.idempotency_key`` but still wasted work), and the
circuit breaker / prune workers contending for the same
schedule_fires rows.

This helper wraps each tick in ``pg_try_advisory_xact_lock(<id>)``
so only ONE replica claims the lock per tick window. The other
replicas no-op and try again on the next interval. The
transaction-scoped advisory lock auto-releases when the with-
block exits, so we don't need explicit unlock + we don't leak the
lock if the tick raises.

The lock id is a stable 64-bit hash of the worker name so each
worker gets its own lock (prune + breaker can run on different
replicas in the same window). Two replicas of the SAME worker
race for the lock; the loser skips.

SQLite path: no advisory locks. ``acquire_per_worker_lock``
returns True unconditionally (single-writer DB so no contention).
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncConnection

    from z4j_brain.persistence.database import DatabaseManager

logger = logging.getLogger("z4j.brain.workers._leader_lock")

# A stable namespace high-bit so worker locks can't collide with
# advisory locks elsewhere in the codebase (e.g. the schedule
# import endpoint's per-project lock). Keep the bit set so the
# resulting int never overlaps with a plain hash.
_NAMESPACE_PREFIX = b"z4j.brain.workers:"


def _lock_id_for(worker_name: str) -> int:
    """Return a stable signed 64-bit lock id for ``worker_name``.

    Postgres ``pg_try_advisory_xact_lock(bigint)`` takes a signed
    bigint; SHA-256-truncated-to-64-bits with the high bit cleared
    gives us a positive id in the safe range.
    """
    digest = hashlib.sha256(_NAMESPACE_PREFIX + worker_name.encode()).digest()
    # Use first 8 bytes; mask top bit so it stays positive in
    # signed-int interpretation.
    raw = int.from_bytes(digest[:8], "big")
    return raw & 0x7FFFFFFFFFFFFFFF


@contextlib.asynccontextmanager
async def acquire_per_worker_lock(
    db: DatabaseManager,
    worker_name: str,
) -> AsyncIterator[bool]:
    """Yield True iff this replica acquired the lock for ``worker_name``.

    Usage::

        async with acquire_per_worker_lock(db, "my_worker") as got_lock:
            if not got_lock:
                return  # another replica is running this tick
            # ... do the work ...

    The lock auto-releases on transaction end (the with-block
    exits, the underlying transaction commits, Postgres frees
    the advisory lock). So a crash mid-tick releases the lock for
    the next replica. No leak.

    On SQLite this is a no-op that always yields True.
    """
    if db.engine.dialect.name != "postgresql":
        # Single-writer DB; no contention possible.
        yield True
        return

    from sqlalchemy import text

    lock_id = _lock_id_for(worker_name)
    async with db.session() as session:
        result = await session.execute(
            text("SELECT pg_try_advisory_xact_lock(:lock_id)").bindparams(
                lock_id=lock_id,
            ),
        )
        got_it = bool(result.scalar())
        if not got_it:
            logger.debug(
                "z4j.brain.workers: skipping %r tick - another replica holds the advisory lock",
                worker_name,
            )
            yield False
            return
        try:
            yield True
        finally:
            # Lock is xact-scoped; commit or rollback releases it.
            # Commit so any side-effect work the caller did under
            # this lock persists. The caller may have already
            # committed inside its own session(s); this commit on
            # OUR session (which only did the advisory lock) is a
            # no-op for the caller's data.
            try:
                await session.commit()
            except Exception:
                await session.rollback()


class SingletonLockLease:
    """A held session-scoped PostgreSQL advisory lock.

    The lease owns the checked-out SQLAlchemy connection because PostgreSQL
    session locks belong to that physical connection.  Keeping only the
    boolean result of ``pg_try_advisory_lock`` lets the connection wrapper be
    garbage-collected immediately, which returns/terminates the connection and
    silently releases the lock.

    SQLite uses the same object with no connection so callers can keep one
    lifecycle contract across both backends.
    """

    __slots__ = ("_connection", "_lock_id", "_name", "_released")

    def __init__(
        self,
        *,
        connection: AsyncConnection | None = None,
        lock_id: int | None = None,
        name: str,
    ) -> None:
        self._connection = connection
        self._lock_id = lock_id
        self._name = name
        self._released = False

    @property
    def released(self) -> bool:
        """Return whether :meth:`release` has completed."""
        return self._released

    async def release(self) -> None:
        """Explicitly unlock and return the owned connection to its pool.

        ``AsyncConnection.close()`` alone only returns a healthy DBAPI
        connection to SQLAlchemy's pool; it does not end the PostgreSQL
        session, so a session-scoped advisory lock could leak into the next
        borrower.  Unlock first, then close in ``finally``.  Process crashes
        remain safe because PostgreSQL releases session locks when the socket
        dies.
        """
        if self._released:
            return
        self._released = True
        connection = self._connection
        self._connection = None
        if connection is None:
            return

        from sqlalchemy import text

        try:
            result = await connection.execute(
                text("SELECT pg_advisory_unlock(:lock_id)").bindparams(
                    lock_id=self._lock_id,
                ),
            )
            unlocked = bool(result.scalar())
            if unlocked:
                # End the implicit SQLAlchemy transaction before returning
                # the connection to the pool. Session-scoped advisory-lock
                # state is independent of commit/rollback.
                await connection.commit()
            else:
                logger.warning(
                    "z4j.brain.workers: singleton lock %r was not held at release",
                    self._name,
                )
                # A false result does not prove why this session no longer
                # owns the lock. Fail closed instead of returning an
                # unproved physical session to the pool.
                await connection.invalidate()
        except Exception:
            # If explicit unlock could not be confirmed, never put this
            # physical PostgreSQL session back into the pool: it may still
            # own the advisory lock. Invalidating forces the socket closed,
            # which is PostgreSQL's authoritative crash-release path.
            await connection.invalidate()
            raise
        finally:
            await connection.close()


async def try_acquire_singleton_lock(
    db: DatabaseManager,
    name: str,
) -> SingletonLockLease | None:
    """Acquire a SESSION-scoped advisory lock and return its lease.

    Unlike :func:`acquire_per_worker_lock`, this helper does NOT
    release the lock at a transaction boundary. The caller must
    retain the returned lease for the protected resource's whole
    lifetime and call :meth:`SingletonLockLease.release` during
    orderly shutdown. PostgreSQL releases it automatically if the
    process or connection dies.

    Use this for singleton resources that must be claimed for the
    entire lifespan of a brain worker process. Concrete example:
    the embedded scheduler subprocess. With ``--workers=4``,
    every uvicorn worker runs the brain lifespan and would
    otherwise spawn its own ``z4j-scheduler`` subprocess; all
    four race for the same port and three crashloop. Gating the
    spawn on this lock ensures only the worker that wins the
    advisory lock spawns the subprocess; the others log and skip.

    SQLite path: no advisory locks. Returns True unconditionally
    (single-writer DB; multi-worker uvicorn over SQLite is not a
    supported deployment shape anyway).

    Returns a lease if the lock was acquired (or we are on a
    SQLite backend), ``None`` if another worker holds it.
    """
    if db.engine.dialect.name != "postgresql":
        return SingletonLockLease(name=name)

    from sqlalchemy import text

    lock_id = _lock_id_for(name)
    # Keep this connection checked out in the returned lease so the
    # PostgreSQL session (and therefore the advisory lock) persists
    # across SQLAlchemy session boundaries.
    conn = await db.engine.connect()
    try:
        result = await conn.execute(
            text("SELECT pg_try_advisory_lock(:lock_id)").bindparams(
                lock_id=lock_id,
            ),
        )
        got_it = bool(result.scalar())
        if not got_it:
            await conn.close()
            logger.info(
                "z4j.brain.workers: %r singleton lock held by another worker; skipping",
                name,
            )
            return None
        # ``execute`` starts an implicit transaction. The advisory lock is
        # session-scoped and survives commit, so end that transaction now
        # instead of holding an idle-in-transaction session for the entire
        # brain lifespan.
        await conn.commit()
        logger.info(
            "z4j.brain.workers: acquired %r singleton lock (id=%d)",
            name,
            lock_id,
        )
        return SingletonLockLease(
            connection=conn,
            lock_id=lock_id,
            name=name,
        )
    except Exception:
        await conn.close()
        raise


__all__ = [
    "SingletonLockLease",
    "acquire_per_worker_lock",
    "try_acquire_singleton_lock",
]
