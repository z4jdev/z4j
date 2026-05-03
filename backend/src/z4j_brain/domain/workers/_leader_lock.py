"""Per-worker leader-lock helper.

Round-4 audit fix (Apr 2026). Pre-fix every brain replica that
booted with ``scheduler_grpc_enabled=True`` ran its own
``PendingFiresReplayWorker``, ``ScheduleCircuitBreakerWorker``,
and ``ScheduleFiresPruneWorker`` on the same cadence. With three
replicas behind a load balancer, every tick fired three times -
duplicate audit rows, duplicate dispatcher calls (now deduped via
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
from typing import TYPE_CHECKING, AsyncIterator

if TYPE_CHECKING:
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

    from sqlalchemy import text  # noqa: PLC0415

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
                "z4j.brain.workers: skipping %r tick - another replica "
                "holds the advisory lock", worker_name,
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
            except Exception:  # noqa: BLE001
                await session.rollback()


__all__ = ["acquire_per_worker_lock"]
