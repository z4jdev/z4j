"""Audit-log retention sweeper (1.2.2+).

Periodically deletes ``audit_log`` rows older than
``settings.audit_retention_days``. Wired into brain's lifespan so
it starts on boot and stops cleanly on shutdown.

Why bother:

- The audit trail grows linearly forever. A homelab brain doing
  10 actions/sec (~860k rows/day) hits 30M rows in a month and
  starts choking the dashboard's ``ORDER BY occurred_at`` paged
  reads. 90 days is enough trail for forensics; older rows are
  noise.
- Operators have asked for a "set retention and forget" knob
  rather than an external cron + ``DELETE`` script.

How it works:

- Postgres: opens ONE transaction per batch, ``SET LOCAL
  z4j.audit_sweep = 'on'`` (the trigger function added in
  ``2026_05_01_0015_audit_sweep`` permits DELETE iff that GUC is
  on), then ``DELETE FROM audit_log WHERE occurred_at < cutoff``
  in batches. ``SET LOCAL`` dies at COMMIT/ROLLBACK so each
  batch's GUC scope is contained. A
  ``pg_try_advisory_lock(hashtext('z4j.audit_sweep'))`` at the
  top of the pass means only one brain replica holds the sweep
  at a time, the others see the lock fail and skip the pass
  cleanly. (Audit fix MED-15.)
- SQLite: no trigger; plain DELETE. Most homelabs run SQLite,
  so this is the common path. SQLite is single-writer so the
  advisory-lock dance is unnecessary.

The sweep runs on a fixed cadence
(``audit_retention_sweep_interval_seconds``, default 3600s = 1h).
Each pass deletes in batches of
``audit_retention_sweep_batch_size`` to avoid long-running
transactions, AND caps the *whole* pass at
``audit_retention_sweep_max_per_pass`` so a multi-million-row
backlog doesn't run as one runaway transaction window. Errors
are logged but never crash the task; the next tick retries.

The hash chain (``prev_row_hmac``) breaks at the boundary where
old rows are deleted. Verification of the surviving chain still
works from the new oldest row forward, which is the documented
behaviour of any time-based audit retention policy.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import delete, text

from z4j_brain.persistence.models import AuditLog

if TYPE_CHECKING:
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings

logger = logging.getLogger("z4j.brain.audit_retention")


#: Postgres advisory-lock key for cross-worker sweep coordination.
#: Computed from ``hashtext('z4j.audit_sweep')``, any int32 will
#: do, but using ``hashtext`` keeps it readable in the migration's
#: comments. Audit fix MED-15.
_SWEEP_ADVISORY_LOCK_KEY: int = 0x7A346A41  # "z4jaA" stable seed


class AuditRetentionSweeper:
    """Background task that prunes ``audit_log`` on a schedule.

    Lifecycle::

        sweeper = AuditRetentionSweeper()
        sweeper.start(db=db, settings=settings)
        ...
        await sweeper.stop()

    All sweep activity is opt-in: when
    ``settings.audit_retention_days <= 0`` the task wakes,
    notices retention is disabled, and goes back to sleep. The
    operator can flip the setting at runtime (next tick picks it
    up) without restarting brain.
    """

    def __init__(self) -> None:
        self._db: DatabaseManager | None = None
        self._settings: Settings | None = None
        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()
        self._last_deleted: int = 0
        self._total_deleted: int = 0
        self._last_run_at: datetime | None = None
        self._last_error: str | None = None

    @property
    def last_deleted(self) -> int:
        """Rows deleted in the most recent sweep pass."""
        return self._last_deleted

    @property
    def total_deleted(self) -> int:
        """Cumulative rows deleted since :meth:`start`."""
        return self._total_deleted

    @property
    def last_run_at(self) -> datetime | None:
        """Wall-clock time of the most recent sweep pass."""
        return self._last_run_at

    @property
    def last_error(self) -> str | None:
        """Stringified exception from the most recent failed sweep."""
        return self._last_error

    def start(
        self,
        *,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        """Spawn the sweep task. Idempotent."""
        if self._task is not None:
            return
        self._db = db
        self._settings = settings
        self._stop_event.clear()
        self._task = asyncio.create_task(
            self._loop(),
            name="z4j.brain.audit_retention.sweep",
        )

    async def stop(self) -> None:
        """Signal the task to exit and wait briefly for it.

        Audit fix CRIT-2: ``CancelledError`` raised into ``stop()``
        from the outer lifespan (e.g. uvicorn shutdown timeout)
        propagates up, it MUST NOT be swallowed, otherwise the
        cancellation never reaches the parent and shutdown stalls.
        We catch ``TimeoutError`` (the wait_for budget elapsed) and
        broad ``Exception`` (the task itself raised) but explicitly
        re-raise ``CancelledError``.
        """
        if self._task is None:
            return
        self._stop_event.set()
        try:
            await asyncio.wait_for(self._task, timeout=5.0)
        except asyncio.CancelledError:
            # Outer scope is cancelling us, try a clean cancel of
            # the inner task, then re-raise so the cancellation
            # propagates.
            self._task.cancel()
            raise
        except (TimeoutError, Exception):  # noqa: BLE001
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            except Exception:  # noqa: BLE001
                pass
        self._task = None

    async def sweep_once(self) -> int:
        """Run one sweep pass synchronously and return rows deleted.

        Exposed for tests + the ``z4j audit prune`` CLI
        subcommand. Honours the same settings as the periodic loop.
        """
        return await self._do_sweep()

    async def _loop(self) -> None:
        assert self._settings is not None
        while not self._stop_event.is_set():
            interval = max(
                60, self._settings.audit_retention_sweep_interval_seconds,
            )
            try:
                await self._do_sweep()
            except asyncio.CancelledError:
                # Audit fix CRIT-2: explicit re-raise so the loop
                # exits cleanly when stop() / outer cancel fires
                # mid-sweep.
                raise
            except Exception as exc:  # noqa: BLE001
                self._last_error = f"{type(exc).__name__}: {exc}"
                logger.exception(
                    "z4j.brain.audit_retention: sweep pass failed; "
                    "next attempt in %ds", interval,
                )
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(), timeout=interval,
                )
                return
            except asyncio.CancelledError:
                raise
            except TimeoutError:
                continue

    async def _do_sweep(self) -> int:
        """Execute one pass.

        Per-batch transactions keep the WAL footprint bounded
        (audit fix CRIT-4). Postgres advisory-locks the sweep so
        multiple workers don't fight (audit fix MED-15). Caps at
        ``audit_retention_sweep_max_per_pass`` rows per pass to
        avoid a runaway transaction window (audit fix MED-18).
        """
        assert self._db is not None
        assert self._settings is not None

        # Audit fix HIGH-4 (second pass): clear last_error at the
        # top of every pass so retention-disabled / no-eligible-rows
        # paths reset the metric. Without this, an error from a
        # prior pass kept ``z4j_background_task_error_active`` at 1
        # indefinitely after the operator disabled retention.
        self._last_error = None

        retention_days = self._settings.audit_retention_days
        if retention_days <= 0:
            return 0
        if retention_days < 1:
            logger.warning(
                "z4j.brain.audit_retention: refusing to sweep with "
                "retention_days=%d (must be >= 1)", retention_days,
            )
            return 0

        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        batch_size = max(
            100, self._settings.audit_retention_sweep_batch_size,
        )
        max_per_pass = max(
            batch_size,
            self._settings.audit_retention_sweep_max_per_pass,
        )
        dialect_name = self._db.engine.dialect.name
        is_postgres = dialect_name == "postgresql"

        total = 0

        # Pre-flight: on Postgres only one worker should sweep at a
        # time. Use an xact-scoped advisory lock that auto-releases
        # at COMMIT/ROLLBACK, no explicit unlock needed.
        #
        # Audit fix CRIT-3 (1.2.2 third-pass): the previous design
        # used ``pg_try_advisory_lock`` (session-scoped) with an
        # explicit ``pg_advisory_unlock`` in a ``finally`` block
        # INSIDE ``async with session.begin()``. If the unlock
        # itself failed, the begin's __aexit__ rolled back the
        # entire transaction, including the legitimate batched
        # DELETEs from earlier in the pass. By switching to
        # ``pg_try_advisory_xact_lock`` we eliminate the unlock
        # call entirely; the lock auto-releases on the same
        # COMMIT that persists the deletes.
        #
        # ``SET LOCAL`` per batch is transaction-scoped (Postgres
        # docs); we re-set it every batch as belt-and-suspenders
        # so a future refactor that drops the SAVEPOINT still
        # works. The ``begin_nested()`` SAVEPOINTs isolate
        # batch-level errors so a single bad row doesn't abort
        # the whole pass.
        if is_postgres:
            async with self._db.session() as session:
                async with session.begin():
                    lock_row = await session.execute(
                        text("SELECT pg_try_advisory_xact_lock(:k)"),
                        {"k": _SWEEP_ADVISORY_LOCK_KEY},
                    )
                    got_lock = bool(lock_row.scalar())
                    if not got_lock:
                        logger.debug(
                            "z4j.brain.audit_retention: another "
                            "worker holds the sweep lock; "
                            "skipping pass",
                        )
                        # Audit fix HIGH (third-pass): update
                        # last_run_at even on the lock-skip path
                        # so /metrics doesn't report a stale
                        # timestamp making operators think the
                        # sweeper has stalled.
                        self._last_run_at = datetime.now(UTC)
                        return 0
                    while (
                        not self._stop_event.is_set()
                        and total < max_per_pass
                    ):
                        rows = await self._sweep_one_batch_postgres(
                            session,
                            cutoff=cutoff,
                            batch_size=batch_size,
                        )
                        total += rows
                        if rows < batch_size:
                            break
                    # The xact-scoped lock auto-releases at the
                    # implicit COMMIT when ``begin()`` exits.
        else:
            # SQLite: per-batch session so each commit returns the
            # connection to the pool and the WAL doesn't grow
            # unbounded across the pass.
            while (
                not self._stop_event.is_set()
                and total < max_per_pass
            ):
                rows = await self._sweep_one_batch_sqlite(
                    cutoff=cutoff, batch_size=batch_size,
                )
                total += rows
                if rows < batch_size:
                    break

        self._last_deleted = total
        self._total_deleted += total
        # Write last_run_at LAST so a /metrics scrape that
        # interleaves with the sweep doesn't see a stale timestamp
        # alongside an updated total. (See audit note on the
        # `_refresh_self_watch_gauges` race.)
        self._last_run_at = datetime.now(UTC)
        self._last_error = None
        if total:
            logger.info(
                "z4j.brain.audit_retention: pruned %d rows older than %s "
                "(retention_days=%d)",
                total, cutoff.isoformat(), retention_days,
            )
        return total

    async def _sweep_one_batch_postgres(
        self,
        session,
        *,
        cutoff: datetime,
        batch_size: int,
    ) -> int:
        """Delete one bounded batch on Postgres.

        Uses ``SET LOCAL z4j.audit_sweep = 'on'`` so the trigger
        function added in migration 0015 permits the DELETE.
        ``FOR UPDATE SKIP LOCKED`` cooperates with concurrent
        readers.

        Scoping note: per Postgres docs, ``SET LOCAL`` is
        TRANSACTION-scoped, not SAVEPOINT-scoped. The GUC
        therefore persists across savepoint releases until the
        outer COMMIT/ROLLBACK. We deliberately re-set it every
        batch as belt-and-suspenders so a future refactor that
        drops the per-batch SAVEPOINT (or moves the lock-and-loop
        out of the explicit outer begin) still has the GUC set
        for every DELETE.

        The SAVEPOINT itself isolates errors: a row-level failure
        in one batch rolls back to the SAVEPOINT without aborting
        the entire pass + losing the advisory lock.
        """
        async with session.begin_nested():
            await session.execute(
                text("SET LOCAL z4j.audit_sweep = 'on'"),
            )
            result = await session.execute(
                text(
                    "DELETE FROM audit_log "
                    "WHERE id IN ("
                    "  SELECT id FROM audit_log "
                    "  WHERE occurred_at < :cutoff "
                    "  ORDER BY occurred_at "
                    "  LIMIT :limit "
                    "  FOR UPDATE SKIP LOCKED"
                    ") RETURNING 1",
                ),
                {"cutoff": cutoff, "limit": batch_size},
            )
            return len(result.fetchall())

    async def _sweep_one_batch_sqlite(
        self,
        *,
        cutoff: datetime,
        batch_size: int,
    ) -> int:
        """Delete one bounded batch on SQLite, in its own tx."""
        async with self._db.session() as session:  # type: ignore[union-attr]
            result = await session.execute(
                delete(AuditLog).where(
                    AuditLog.id.in_(
                        text(
                            "SELECT id FROM audit_log "
                            "WHERE occurred_at < :cutoff "
                            "ORDER BY occurred_at LIMIT :limit",
                        ).bindparams(
                            cutoff=cutoff, limit=batch_size,
                        ),
                    ),
                ),
            )
            await session.commit()
            return result.rowcount or 0


__all__ = ["AuditRetentionSweeper"]
