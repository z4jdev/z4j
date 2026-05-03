"""Periodic background worker supervisor.

Each worker is a callable that runs once per tick. The supervisor
schedules them, catches exceptions, and applies an exponential
backoff before retrying. The brain's lifespan starts the
supervisor and stops it on shutdown.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import structlog


logger = structlog.get_logger("z4j.brain.workers")


#: Type of a worker tick: an async callable that does one unit of
#: work and returns. Errors must be allowed to propagate so the
#: supervisor can apply backoff.
WorkerTick = Callable[[], Awaitable[None]]


@dataclass(slots=True)
class PeriodicWorker:
    """Description of one periodic background worker.

    Attributes:
        name: Friendly name used in logs and task names.
        tick: Async callable that does one unit of work.
        interval_seconds: Sleep between ticks on the happy path.
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
    on consecutive failures).
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
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._tasks.clear()
        logger.info("z4j worker supervisor stopped")

    async def _run_worker(self, worker: PeriodicWorker) -> None:
        backoff_index = 0
        backoff_schedule = (1.0, 2.0, 5.0, 10.0, 30.0)
        while not self._stop_event.is_set():
            try:
                await worker.tick()
                backoff_index = 0  # reset on success
            except asyncio.CancelledError:
                return
            except Exception:  # noqa: BLE001
                logger.exception(
                    "z4j worker tick failed; backing off",
                    worker=worker.name,
                    backoff_index=backoff_index,
                )
                backoff = backoff_schedule[
                    min(backoff_index, len(backoff_schedule) - 1)
                ]
                backoff_index += 1
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=backoff,
                    )
                    return
                except TimeoutError:
                    continue

            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=worker.interval_seconds,
                )
                return
            except TimeoutError:
                continue


__all__ = ["PeriodicWorker", "WorkerSupervisor", "WorkerTick"]
