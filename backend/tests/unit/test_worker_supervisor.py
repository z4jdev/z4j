"""The supervisor's sleep between ticks.

A periodic worker normally runs on the operator's configured interval, and
that interval can be long: audit-chain verification defaults to a day and is
accepted up to a week. A worker that completed but could not do its job needs
a way to be tried again before then, so a tick may name its own next sleep,
and the supervisor honours it in one direction only. Shortening is the
worker's business: it knows it failed. Lengthening is the operator's, and a
worker that could stretch its own interval could quietly stop running
altogether.

The failure path has the same interval to respect and gets it wrong in the
opposite direction. A tick that raises is retried on a backoff, and a backoff
that stops climbing at a fixed ceiling stops being a backoff for any worker
whose interval is longer than that ceiling: it becomes a permanent, and much
faster, cadence, imposed on a database that is by then already in trouble.
"""

from __future__ import annotations

import asyncio

import pytest
from z4j_brain.domain.workers import supervisor as supervisor_mod
from z4j_brain.domain.workers.supervisor import PeriodicWorker, WorkerSupervisor


async def _count_ticks(*, returns: float | None, interval: float, window: float) -> int:
    calls = 0

    async def _tick() -> float | None:
        nonlocal calls
        calls += 1
        return returns

    supervisor = WorkerSupervisor(
        [PeriodicWorker(name="test_worker", tick=_tick, interval_seconds=interval)],
    )
    await supervisor.start()
    try:
        await asyncio.sleep(window)
    finally:
        await supervisor.stop()
    return calls


@pytest.mark.asyncio
async def test_a_tick_can_ask_to_be_woken_before_its_interval() -> None:
    """Otherwise one bad run costs a whole interval of not running."""
    calls = await _count_ticks(returns=0.01, interval=3600.0, window=0.2)

    assert calls > 1, "the requested sleep was ignored and the interval was taken"


@pytest.mark.asyncio
async def test_a_tick_cannot_stretch_its_own_interval() -> None:
    """How often the work happens at all stays the operator's decision."""
    calls = await _count_ticks(returns=3600.0, interval=0.01, window=0.2)

    assert calls > 1, "a worker talked its own cadence down to once"


@pytest.mark.asyncio
async def test_a_tick_that_returns_nothing_keeps_the_interval() -> None:
    """The overwhelming majority of workers, and the pre-existing contract."""
    assert await _count_ticks(returns=None, interval=3600.0, window=0.1) == 1
    assert await _count_ticks(returns=None, interval=0.01, window=0.2) > 1


def test_a_failing_daily_worker_is_not_retried_every_half_minute() -> None:
    """One transient error must not become a permanent change of cadence.

    A day's interval retried every 30 seconds is not a backoff, it is 2880
    runs a day of work the operator asked for once, and it lands on a
    database that has just proved it is unwell.
    """
    daily = 86_400.0
    delays = [supervisor_mod._failure_backoff_seconds(n, daily) for n in range(40)]

    assert delays[0] < 5.0, "the first retry after a blip should still be prompt"
    assert max(delays) == daily, (
        "a worker that keeps failing settles somewhere other than the cadence "
        "its operator configured"
    )
    assert delays == sorted(delays), "the wait must never shorten as failures pile up"


def test_a_frequent_worker_still_gets_relief_from_a_failing_dependency() -> None:
    """The other direction: backing off means backing off.

    A worker configured to run every two seconds must not retry a broken
    dependency every two seconds forever just because that is its interval.
    """
    delays = [supervisor_mod._failure_backoff_seconds(n, 2.0) for n in range(40)]

    assert max(delays) >= 30.0, "a persistent failure was retried at the normal cadence"


def test_the_wait_never_exceeds_what_it_is_bounded_by() -> None:
    """The exponent cannot run away during a long outage."""
    for interval in (1.0, 45.0, 604_800.0):
        ceiling = max(interval, 30.0)
        for n in range(200):
            assert 0 < supervisor_mod._failure_backoff_seconds(n, interval) <= ceiling


@pytest.mark.asyncio
async def test_the_supervisor_backs_off_against_the_worker_s_own_interval(
    monkeypatch,
) -> None:
    """The bound above is worth nothing if the loop does not pass it in.

    Observed on the real loop with a real failing tick: what is replaced is
    the arithmetic, so that the arguments the loop chooses become visible.
    """
    seen: list[tuple[int, float]] = []

    def _record(consecutive_failures: int, interval_seconds: float) -> float:
        seen.append((consecutive_failures, interval_seconds))
        return 0.01

    monkeypatch.setattr(supervisor_mod, "_failure_backoff_seconds", _record)

    async def _always_fails() -> float | None:
        raise RuntimeError("the database is gone")

    supervisor = WorkerSupervisor(
        [PeriodicWorker(name="test_worker", tick=_always_fails, interval_seconds=86_400.0)],
    )
    await supervisor.start()
    try:
        await asyncio.sleep(0.5)
    finally:
        await supervisor.stop()

    assert len(seen) >= 3, "the failing worker was not retried"
    assert [interval for _, interval in seen] == [86_400.0] * len(seen), (
        "the loop backs off without reference to how often this worker is "
        "meant to run, so the bound cannot apply"
    )
    assert [failures for failures, _ in seen] == list(range(len(seen))), (
        "consecutive failures are not being counted, so the wait cannot grow"
    )
