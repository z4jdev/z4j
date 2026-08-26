"""Periodic background worker supervisor.

Each worker is a callable that runs once per tick. The supervisor
schedules them, catches exceptions, and applies an exponential
backoff before retrying. The brain's lifespan starts the
supervisor and stops it on shutdown.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import structlog

logger = structlog.get_logger("z4j.brain.workers")


#: Wait after the first failed tick. Short, because most failures are a blip
#: and recovering from one quickly is the whole point of retrying at all.
_BACKOFF_BASE_SECONDS: float = 1.0

#: Lower bound on where the doubling is allowed to stop. A worker configured
#: to run every few seconds still gets real relief from a failing dependency
#: rather than retrying at its normal cadence forever.
_BACKOFF_FLOOR_SECONDS: float = 30.0

#: Ceiling on the doubling exponent so a long outage cannot grow the shift
#: without bound. The interval caps the wait long before this bites.
_MAX_BACKOFF_EXPONENT: int = 20


def _failure_backoff_seconds(
    consecutive_failures: int,
    interval_seconds: float,
) -> float:
    """Seconds to wait after ``consecutive_failures`` ticks in a row failed.

    Doubles from a short first retry and stops at the worker's own interval,
    or at :data:`_BACKOFF_FLOOR_SECONDS`, whichever is longer.

    Stopping anywhere short of the interval turns a persistent failure into a
    permanent cadence change in the wrong direction. A chain verifier the
    operator scheduled for once a day would keep retrying every half minute,
    against a database that by then is already unwell, and would go on doing
    so for as long as the outage lasted. Every worker here is periodic by
    definition, so the cadence the operator chose is the slowest this should
    ever settle to, and the fastest.
    """
    exponent = min(max(consecutive_failures, 0), _MAX_BACKOFF_EXPONENT)
    ceiling = max(interval_seconds, _BACKOFF_FLOOR_SECONDS)
    return min(_BACKOFF_BASE_SECONDS * (2**exponent), ceiling)


#: Type of a worker tick: an async callable that does one unit of
#: work and returns. A returned number is a request to be woken after
#: that many seconds instead of after the configured interval; it can
#: only shorten the wait. Returning None takes the interval. Errors
#: must be allowed to propagate so the supervisor can apply backoff.
WorkerTick = Callable[[], Awaitable[float | None]]


@dataclass(slots=True)
class PeriodicWorker:
    """Description of one periodic background worker.

    Attributes:
        name: Friendly name used in logs and task names.
        tick: Async callable that does one unit of work. May return a
            shorter sleep for the next tick; see :data:`WorkerTick`.
        interval_seconds: Sleep between ticks on the happy path, and the
            ceiling on anything a tick asks for.
    """

    name: str
    tick: WorkerTick
    interval_seconds: float


class WorkerSupervisor:
    """Owns the asyncio tasks for every periodic worker.

    Lifecycle: ``start`` spawns one ``asyncio.Task`` per worker;
    ``stop`` cancels them and awaits exit. Each worker runs inside
    a ``while not stop_event.is_set()`` loop with a try/except
    that catches everything except ``CancelledError``, logs, then
    sleeps for the configured interval (with exponential backoff
    on consecutive failures, bounded by that same interval - see
    :func:`_failure_backoff_seconds`).
    """

    def __init__(self, workers: list[PeriodicWorker]) -> None:
        self._workers = workers
        self._tasks: list[asyncio.Task[None]] = []
        self._stop_event = asyncio.Event()

    async def start(self) -> None:
        if self._tasks:
            return
        self._stop_event.clear()
        for worker in self._workers:
            task = asyncio.create_task(
                self._run_worker(worker),
                name=f"z4j-{worker.name}",
            )
            self._tasks.append(task)
        logger.info(
            "z4j worker supervisor started",
            workers=[w.name for w in self._workers],
        )

    async def stop(self) -> None:
        self._stop_event.set()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._tasks.clear()
        logger.info("z4j worker supervisor stopped")

    async def _run_worker(self, worker: PeriodicWorker) -> None:
        consecutive_failures = 0
        while not self._stop_event.is_set():
            requested: float | None = None
            try:
                requested = await worker.tick()
                consecutive_failures = 0  # reset on success
            except asyncio.CancelledError:
                return
            except Exception:
                backoff = _failure_backoff_seconds(
                    consecutive_failures,
                    worker.interval_seconds,
                )
                logger.exception(
                    "z4j worker tick failed; backing off",
                    worker=worker.name,
                    consecutive_failures=consecutive_failures,
                    backoff_seconds=backoff,
                )
                consecutive_failures += 1
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=backoff,
                    )
                    return
                except TimeoutError:
                    continue

            # A tick that returned may ask to be woken sooner, which is how a
            # worker that could not do its job this time retries without
            # waiting out an interval that can be configured in days. Only
            # ever shorter: how often the work runs at all is the operator's
            # setting to make, not the worker's.
            delay = worker.interval_seconds
            if requested is not None and 0 < requested < delay:
                delay = requested
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=delay,
                )
                return
            except TimeoutError:
                continue


__all__ = ["PeriodicWorker", "WorkerSupervisor", "WorkerTick"]
