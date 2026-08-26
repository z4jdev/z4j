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

This helper wraps each tick in a PostgreSQL advisory lock so only
ONE replica claims the lock per tick window. The other replicas
no-op and try again on the next interval.

The lock id is a stable 64-bit hash of the worker name so each
worker gets its own lock (prune + breaker can run on different
replicas in the same window). Two replicas of the SAME worker
race for the lock; the loser skips.

SQLite path: no advisory locks. ``acquire_per_worker_lock``
returns True unconditionally (single-writer DB so no contention).

Why the lock is session-scoped, not transaction-scoped
------------------------------------------------------
The lock has to outlive the work it protects, and the work runs in
a different session from the lock. A transaction-scoped lock
(``pg_try_advisory_xact_lock``) can only stay held by keeping its
own transaction open and idle for the whole tick, which puts it
directly in the path of ``idle_in_transaction_session_timeout``.
The brain sets that on every connection (30 seconds by default,
see ``persistence/statement_timeout``), so PostgreSQL terminated
the lock session out from under any tick that ran longer, and a
second replica could take the lock while the first was still
working. Nothing raised, because the session being terminated was
not the session doing the work: the guarantee failed silently
under exactly the load that justifies having it.

A session-scoped lock (``pg_try_advisory_lock``) held on a
dedicated checked-out connection ends its transaction the moment
the lock is taken, so that connection sits *idle* rather than
*idle in transaction*. No idle-in-transaction budget applies to
it, and it registers no snapshot, so a tick that runs for minutes
does not pin the vacuum horizon either.

What that costs: the lock now has to be released explicitly rather
than falling out of a transaction boundary, and the connection has
to stay bound to one PostgreSQL backend for the duration of the
tick (a proxy doing transaction-level pooling in front of
PostgreSQL would break it). ``SingletonLockLease`` owns both
obligations, and the process-lifetime leases below already carried
the second one.

The residual is connection death: if the socket holding the lock
dies mid-tick, PostgreSQL releases the lock while the work carries
on in another session. No client-side design can close that window
while the work runs somewhere else. What we do instead is refuse
to let it pass unnoticed - the release path confirms the lock was
still ours and says so loudly when it was not.
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

    Postgres ``pg_try_advisory_lock(bigint)`` takes a signed
    bigint; SHA-256-truncated-to-64-bits with the high bit cleared
    gives us a positive id in the safe range.
    """
    digest = hashlib.sha256(_NAMESPACE_PREFIX + worker_name.encode()).digest()
    # Use first 8 bytes; mask top bit so it stays positive in
    # signed-int interpretation.
    raw = int.from_bytes(digest[:8], "big")
    return raw & 0x7FFFFFFFFFFFFFFF


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

    __slots__ = ("_connection", "_held_until_release", "_lock_id", "_name", "_released")

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
        self._held_until_release = True

    @property
    def released(self) -> bool:
        """Return whether :meth:`release` has completed."""
        return self._released

    async def release(self) -> bool:
        """Unlock, return the owned connection to its pool, and report.

        ``AsyncConnection.close()`` alone only returns a healthy DBAPI
        connection to SQLAlchemy's pool; it does not end the PostgreSQL
        session, so a session-scoped advisory lock could leak into the next
        borrower.  Unlock first, then close in ``finally``.  Process crashes
        remain safe because PostgreSQL releases session locks when the socket
        dies.

        Returns True when this lease still owned the lock at release, which is
        the only proof available that nothing else could have been holding it
        while the caller worked.  A False answer means the protected work was
        not in fact protected for its whole run, and the caller is the only
        one that knows what that is worth.
        """
        if self._released:
            return self._held_until_release
        self._released = True
        connection = self._connection
        self._connection = None
        if connection is None:
            return self._held_until_release

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
                self._held_until_release = False
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
            self._held_until_release = False
            await connection.invalidate()
            raise
        finally:
            await connection.close()
        return self._held_until_release


async def try_acquire_singleton_lock(
    db: DatabaseManager,
    name: str,
    *,
    announce: bool = True,
) -> SingletonLockLease | None:
    """Acquire a SESSION-scoped advisory lock and return its lease.

    The lock is not tied to a transaction boundary. The caller must retain
    the returned lease for the protected resource's whole lifetime and call
    :meth:`SingletonLockLease.release` when it is done. PostgreSQL releases
    it automatically if the process or connection dies.

    Use this wherever one holder at a time must be guaranteed for longer
    than a single transaction. Two shapes use it:

    * For a resource claimed for the lifespan of a brain process. Concrete
      example: the embedded scheduler subprocess. With ``--workers=4``,
      every uvicorn worker runs the brain lifespan and would otherwise
      spawn its own ``z4j-scheduler`` subprocess; all four race for the
      same port and three crashloop. Gating the spawn on this lock ensures
      only the worker that wins spawns the subprocess; the others log and
      skip.
    * For a resource claimed for the length of one unit of work, via
      :func:`acquire_per_worker_lock`.

    ``announce`` controls whether acquiring or losing the race is logged at
    info. Leave it on for process-lifetime claims, which happen once and are
    worth a line in the boot log; turn it off for per-tick claims, where one
    line per tick per replica is noise that buries everything else.

    SQLite path: no advisory locks. Returns a lease that holds nothing
    (single-writer DB; multi-worker uvicorn over SQLite is not a supported
    deployment shape anyway).

    Returns a lease if the lock was acquired (or we are on a SQLite
    backend), ``None`` if another holder has it.

    Raises whatever the database raised if the attempt could not be made at
    all. That is not the same answer as "someone else holds it" and callers
    must not treat it as one.
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
            if announce:
                logger.info(
                    "z4j.brain.workers: %r singleton lock held by another worker; skipping",
                    name,
                )
            return None
        # ``execute`` starts an implicit transaction. The advisory lock is
        # session-scoped and survives commit, so end that transaction now.
        # This is what keeps the holder out of the reach of
        # ``idle_in_transaction_session_timeout`` for however long it holds.
        await conn.commit()
        if announce:
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


@contextlib.asynccontextmanager
async def acquire_per_worker_lock(
    db: DatabaseManager,
    worker_name: str,
) -> AsyncIterator[bool]:
    """Yield True iff this replica holds the lock for ``worker_name``.

    Usage::

        async with acquire_per_worker_lock(db, "my_worker") as got_lock:
            if not got_lock:
                return  # another replica is running this tick
            # ... do the work ...

    The lock is held for as long as the with-block runs, whatever the work
    inside it costs, and is released on the way out including when the tick
    raises. A crash releases it too: PostgreSQL drops session locks when the
    backend's socket closes.

    On SQLite this is a no-op that always yields True.

    This never raises on the acquisition path. Failing to acquire and
    failing to ASK are different facts and are logged differently, but the
    safe action is the same: without proof that this replica leads, it must
    not run the work the lock exists to serialise. Raising instead would
    hand a database blip to the supervisor's failure backoff, which retries
    far more often than the operator's configured interval - a worker
    scheduled for once a day would start running every few seconds, against
    a database that is by then already in trouble, and would keep doing so
    until someone noticed.
    """
    lease: SingletonLockLease | None = None
    answered = True
    try:
        lease = await try_acquire_singleton_lock(db, worker_name, announce=False)
    except Exception:
        answered = False
        logger.exception(
            "z4j.brain.workers: could not determine leadership for %r; skipping tick",
            worker_name,
        )

    if lease is None:
        if answered:
            logger.debug(
                "z4j.brain.workers: skipping %r tick - another replica holds the advisory lock",
                worker_name,
            )
        yield False
        return

    try:
        yield True
    finally:
        await _release_after_tick(lease, worker_name)


async def _release_after_tick(lease: SingletonLockLease, worker_name: str) -> None:
    """Release ``lease``, reporting problems rather than raising them.

    The tick's work has already happened by the time this runs, so raising
    would only convert a completed tick into a supervisor-level failure and
    change the worker's cadence for something that is already behind it. The
    lease invalidates the physical session on any anomaly, so PostgreSQL
    gets the lock back either way; what is left to do is make sure the
    operator can see it happened.
    """
    try:
        held_throughout = await lease.release()
    except Exception:
        logger.exception(
            "z4j.brain.workers: releasing the %r lock failed; the connection "
            "was discarded so PostgreSQL has the lock back",
            worker_name,
        )
        return
    if not held_throughout:
        logger.error(
            "z4j.brain.workers: the %r lock was already gone when this tick "
            "finished, so another replica may have run the same work "
            "concurrently. The usual cause is the lock-holding connection "
            "dying mid-tick.",
            worker_name,
        )


__all__ = [
    "SingletonLockLease",
    "acquire_per_worker_lock",
    "try_acquire_singleton_lock",
]
