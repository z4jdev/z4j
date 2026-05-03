"""SQLite WAL checkpoint task (1.2.2+).

SQLite in WAL mode (the default for our async aiosqlite engine)
accumulates pages in the ``-wal`` sidecar file as writes happen.
SQLite auto-checkpoints on a 1000-page threshold, which works
fine for write-light apps but lags badly when (a) the brain is
busy logging audit/event/command rows and (b) readers hold the
WAL open across many transactions.

The visible symptom on a homelab box is the ``brain.db-wal``
file growing into the hundreds of megabytes, which then breaks
``cp brain.db backup.db`` (the WAL holds uncheckpointed pages).

This task runs ``PRAGMA wal_checkpoint(PASSIVE)`` on a fixed
cadence (default every 5 minutes) so the WAL gets checkpointed
opportunistically without blocking concurrent readers/writers.
PASSIVE is the safe default; TRUNCATE (which forcibly resets
the WAL file) is reserved for an explicit operator action and
*not* the periodic loop, because it can stall behind a long-
running read transaction (audit fix MED-14).

Postgres deployments don't need this, the task detects the
dialect at start and exits cleanly if it's not SQLite.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import text

if TYPE_CHECKING:
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings

logger = logging.getLogger("z4j.brain.wal_checkpoint")


class WalCheckpointTask:
    """Background task that runs ``PRAGMA wal_checkpoint(PASSIVE)``.

    Lifecycle::

        task = WalCheckpointTask()
        task.start(db=db, settings=settings)
        ...
        await task.stop()

    On non-SQLite databases :meth:`start` logs once and returns
    without spawning a task, the operation is a no-op.
    """

    def __init__(self) -> None:
        self._db: DatabaseManager | None = None
        self._settings: Settings | None = None
        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()
        self._last_run_at: datetime | None = None
        # Audit fix MED (second pass): -1 sentinel matches the
        # documented "no useful number" semantics. 0 used to mean
        # "ran once and checkpointed nothing" AND "never run yet"
        #, distinct states that operators graphing the gauge need
        # to distinguish.
        self._last_pages_checkpointed: int = -1
        self._last_error: str | None = None

    @property
    def last_run_at(self) -> datetime | None:
        """Wall-clock time of the most recent checkpoint pass."""
        return self._last_run_at

    @property
    def last_pages_checkpointed(self) -> int:
        """Pages checkpointed in the most recent successful pass.

        Maps to the second column returned by
        ``PRAGMA wal_checkpoint``. ``-1`` indicates the pragma
        returned no useful number (very old SQLite or non-WAL DB).
        """
        return self._last_pages_checkpointed

    @property
    def last_error(self) -> str | None:
        """Stringified exception from the most recent failed pass."""
        return self._last_error

    def start(
        self,
        *,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        """Spawn the checkpoint task. Idempotent.

        Returns immediately without spawning a task if the
        database is not SQLite.
        """
        if self._task is not None:
            return
        if db.engine.dialect.name != "sqlite":
            logger.info(
                "z4j.brain.wal_checkpoint: dialect=%s; checkpoint task "
                "not needed", db.engine.dialect.name,
            )
            return
        self._db = db
        self._settings = settings
        self._stop_event.clear()
        self._task = asyncio.create_task(
            self._loop(),
            name="z4j.brain.wal_checkpoint.loop",
        )

    async def stop(self) -> None:
        """Signal the task to exit and wait briefly for it.

        Audit fix CRIT-2: re-raise ``CancelledError`` so an outer
        cancel propagates correctly.
        """
        if self._task is None:
            return
        self._stop_event.set()
        try:
            await asyncio.wait_for(self._task, timeout=5.0)
        except asyncio.CancelledError:
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

    async def checkpoint_once(self) -> int:
        """Run one checkpoint pass synchronously.

        Returns the number of pages checkpointed (or ``-1`` when
        the pragma response shape is unexpected). Exposed for tests
        and the ``z4j-brain wal-checkpoint`` CLI subcommand.

        Audit fix LOW: raise a clear error if called before
        ``start()``, pre-fix this hit ``AssertionError`` (or
        ``AttributeError`` under ``python -O``).
        """
        if self._db is None or self._settings is None:
            raise RuntimeError(
                "WalCheckpointTask.checkpoint_once called before start() "
                "(or on a non-SQLite database)",
            )
        return await self._do_checkpoint()

    async def _loop(self) -> None:
        assert self._settings is not None
        # Audit fix MEDIUM: wait the configured interval BEFORE the
        # first pass instead of running immediately. On a stale
        # install the inaugural checkpoint can be expensive; running
        # it during boot stalls /health/ready under k8s. The auto-
        # checkpoint at the 1000-page threshold still kicks in
        # opportunistically before our first deliberate pass.
        while not self._stop_event.is_set():
            interval = max(
                60, self._settings.wal_checkpoint_interval_seconds,
            )
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(), timeout=interval,
                )
                return
            except asyncio.CancelledError:
                raise
            except TimeoutError:
                pass
            try:
                await self._do_checkpoint()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                self._last_error = f"{type(exc).__name__}: {exc}"
                logger.exception(
                    "z4j.brain.wal_checkpoint: pass failed; "
                    "next attempt in %ds", interval,
                )

    async def _do_checkpoint(self) -> int:
        """Issue ``PRAGMA wal_checkpoint(PASSIVE)`` and record stats.

        Audit fix MED-14: PASSIVE (not TRUNCATE) is the periodic
        default. PASSIVE checkpoints as many pages as it can
        without blocking readers/writers; TRUNCATE additionally
        resets the WAL file size and waits for all readers to
        release, which can stall under a long-running read tx.
        Operators who specifically want the WAL file size to
        shrink should call the ``z4j-brain wal-checkpoint
        --truncate`` CLI (out of scope for the periodic loop).
        """
        assert self._db is not None
        async with self._db.session() as session:
            result = await session.execute(
                text("PRAGMA wal_checkpoint(PASSIVE)"),
            )
            row = result.fetchone()
            await session.commit()

        # Pragma response is ``(busy, log, checkpointed)`` per
        # https://sqlite.org/pragma.html#pragma_wal_checkpoint.
        # Older SQLite returns a single int; even older might
        # return None.
        pages = -1
        if row is not None:
            try:
                pages = int(row[2]) if len(row) >= 3 else int(row[0])
            except (TypeError, ValueError, IndexError):
                pages = -1

        self._last_pages_checkpointed = pages
        self._last_run_at = datetime.now(UTC)
        self._last_error = None
        if pages > 0:
            logger.debug(
                "z4j.brain.wal_checkpoint: checkpointed %d pages", pages,
            )
        return pages


__all__ = ["WalCheckpointTask"]
