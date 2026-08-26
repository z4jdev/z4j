"""The leader lock has to be held for as long as the work it protects.

That is the whole of its job. Two replicas of a periodic worker race for one
advisory lock and the loser skips, so a lock that quietly stops being held
part-way through a tick does not degrade the guarantee, it removes it: the
second replica starts the same work while the first is still doing it, and
nothing anywhere raises, because the thing that failed is not the thing doing
the work.

The failure has a specific cause worth pinning. Every connection this brain
opens carries an ``idle_in_transaction_session_timeout`` (30 seconds by
default), so a lock that keeps itself alive by holding a transaction open is
on a 30 second clock from the moment the tick starts. Multi-page scans,
retention deletes over a large table and partition DDL all run longer than
that on the deployments where the lock matters most.

Only PostgreSQL can settle any of this. SQLite has no advisory locks, and the
helper says so and no-ops, so a SQLite version of these tests would be a test
that cannot fail. Point ``Z4J_TEST_POSTGRES_URL`` at a PostgreSQL to run
them. No schema is needed; this is about locks and sessions, not data.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import secrets
import socket
from collections.abc import Iterator

import pytest
from sqlalchemy import text
from z4j_brain.domain.workers._leader_lock import (
    _lock_id_for,
    acquire_per_worker_lock,
    try_acquire_singleton_lock,
)
from z4j_brain.persistence.database import DatabaseManager, create_engine_from_settings
from z4j_brain.persistence.statement_timeout import install_statement_timeouts
from z4j_brain.settings import Settings

_POSTGRES_URL = os.environ.get("Z4J_TEST_POSTGRES_URL")

requires_postgres = pytest.mark.skipif(
    _POSTGRES_URL is None,
    reason="advisory locks and session timeouts are PostgreSQL behaviour",
)

#: Idle-in-transaction budget for the replicas under test. The product accepts
#: anything from 100 ms, and the default is 30 s; a short one is what makes a
#: tick that outlives it cheap to run rather than something different in kind.
_IDLE_BUDGET_MS: int = 500

#: How long a tick pretends to work. Comfortably past the budget above, so a
#: holder that depends on the transaction staying open has definitely lost it.
_WORK_SECONDS: float = 2.0


def _asyncpg_url(url: str) -> str:
    scheme, _, rest = url.partition("://")
    return f"postgresql+asyncpg://{rest}" if scheme.startswith("postgresql") else url


def _settings(url: str, *, idle_ms: int = _IDLE_BUDGET_MS) -> Settings:
    return Settings(  # type: ignore[arg-type]
        database_url=url,
        secret=secrets.token_urlsafe(48),
        session_secret=secrets.token_urlsafe(48),
        audit_chain_secret=secrets.token_urlsafe(48),
        environment="dev",
        log_json=False,
        db_idle_in_tx_timeout_ms=idle_ms,
    )


def _replica(url: str, *, idle_ms: int = _IDLE_BUDGET_MS) -> DatabaseManager:
    """Build one brain replica's database access the way the app factory does.

    ``create_engine_from_settings`` then ``install_statement_timeouts`` is the
    pair ``create_app`` runs, and the second half is where the budget that
    used to kill the lock comes from. Composing the product's own two calls
    rather than a hand-built engine is what makes this a test of the shipped
    configuration.
    """
    settings = _settings(url, idle_ms=idle_ms)
    engine = create_engine_from_settings(settings)
    install_statement_timeouts(engine, settings=settings)
    return DatabaseManager(engine)


def _unused_local_port() -> int:
    """Return a port nothing is listening on, so connecting is refused."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@contextlib.contextmanager
def _reported_by(logger_name: str) -> Iterator[list[logging.LogRecord]]:
    """Collect one logger's records, whatever the rest of the session did to it.

    Two pieces of global state have to be neutralised for this to measure the
    code under test rather than the order tests ran in. The brain's logging
    setup replaces the root handler list outright, so the capture attaches to
    the named logger instead of relying on the root. And ``fileConfig`` in the
    alembic environment disables every logger that already exists when it
    runs, which any earlier test that migrates a database will have done, so
    the flag is cleared here and restored on the way out.
    """
    collected: list[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            collected.append(record)

    logger = logging.getLogger(logger_name)
    handler = _Collect(level=logging.DEBUG)
    previous_level = logger.level
    previously_disabled = logger.disabled
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.disabled = False
    try:
        yield collected
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
        logger.disabled = previously_disabled


@requires_postgres
@pytest.mark.asyncio
async def test_a_second_replica_is_locked_out_for_the_whole_tick() -> None:
    """The one property the lock exists for, measured over a long tick."""
    url = _asyncpg_url(_POSTGRES_URL or "")
    first = _replica(url)
    second = _replica(url)
    worker_name = f"probe_{secrets.token_hex(6)}"
    try:
        async with acquire_per_worker_lock(first, worker_name) as leader:
            assert leader is True, "nothing else should hold this lock in a test"
            await asyncio.sleep(_WORK_SECONDS)
            async with acquire_per_worker_lock(second, worker_name) as intruder:
                assert intruder is False, (
                    "a second replica took the lock while the first was still "
                    "working, so both would have run the same tick"
                )
        # And once the first replica is done, the lock is free again: a lock
        # nobody can ever take next would be the same bug in the other
        # direction.
        async with acquire_per_worker_lock(second, worker_name) as after:
            assert after is True, "the lock was not released when the tick ended"
    finally:
        await first.engine.dispose()
        await second.engine.dispose()


@requires_postgres
@pytest.mark.asyncio
async def test_the_holder_waits_outside_a_transaction() -> None:
    """Why the lock survives: it is never idle *in a transaction*.

    Asserted against ``pg_stat_activity`` rather than reasoned about, because
    it is the difference between the two states that decides whether the
    idle-in-transaction budget applies at all. The snapshot check is the
    second half of the same fact: a holder parked inside a transaction pins
    the vacuum horizon for as long as the tick runs, which on a busy brain
    costs table bloat on every table, not just the one being worked on.
    """
    url = _asyncpg_url(_POSTGRES_URL or "")
    holder = _replica(url)
    observer = _replica(url)
    worker_name = f"probe_{secrets.token_hex(6)}"
    lock_id = _lock_id_for(worker_name)
    try:
        async with acquire_per_worker_lock(holder, worker_name) as leader:
            assert leader is True
            # Let the holder settle into whatever state it waits in.
            await asyncio.sleep(1.0)
            async with observer.session() as session:
                result = await session.execute(
                    text(
                        "SELECT a.state, a.backend_xmin IS NULL "
                        "FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid "
                        "WHERE l.locktype = 'advisory' AND l.granted "
                        "AND ((l.classid::bigint << 32) | l.objid::bigint) = :lock_id",
                    ).bindparams(lock_id=lock_id),
                )
                rows = result.all()

        assert len(rows) == 1, f"expected exactly one backend holding the lock, got {rows}"
        state, no_snapshot = rows[0]
        assert state == "idle", (
            f"the lock holder is {state!r}; a holder inside a transaction is on "
            "the idle-in-transaction clock and will be terminated mid-tick"
        )
        assert no_snapshot, (
            "the lock holder is advertising a snapshot, which holds back the "
            "vacuum horizon for the whole tick"
        )
    finally:
        await holder.engine.dispose()
        await observer.engine.dispose()


@requires_postgres
@pytest.mark.asyncio
async def test_losing_the_race_is_quiet() -> None:
    """Another replica having the lock is the system working, not an incident."""
    url = _asyncpg_url(_POSTGRES_URL or "")
    holder = _replica(url)
    loser = _replica(url)
    worker_name = f"probe_{secrets.token_hex(6)}"
    try:
        lease = await try_acquire_singleton_lock(holder, worker_name)
        assert lease is not None
        try:
            with _reported_by("z4j.brain.workers._leader_lock") as reported:
                async with acquire_per_worker_lock(loser, worker_name) as got:
                    assert got is False
        finally:
            await lease.release()

        assert not [r for r in reported if r.levelno >= logging.WARNING], (
            "losing the race was reported as a problem; an operator who sees "
            "that on every tick of every replica stops reading the logs"
        )
    finally:
        await holder.engine.dispose()
        await loser.engine.dispose()


@requires_postgres
@pytest.mark.asyncio
async def test_a_lock_lost_mid_tick_is_reported() -> None:
    """The residual risk, made loud instead of silent.

    No client-side design can stop PostgreSQL releasing the lock if the
    connection holding it dies while the work runs in a different session.
    What it can do is refuse to let the tick end as though nothing happened,
    because the operator's evidence that one replica did this work is
    otherwise unfalsifiable.
    """
    url = _asyncpg_url(_POSTGRES_URL or "")
    holder = _replica(url)
    assassin = _replica(url)
    worker_name = f"probe_{secrets.token_hex(6)}"
    lock_id = _lock_id_for(worker_name)
    try:
        with _reported_by("z4j.brain.workers._leader_lock") as reported:
            async with acquire_per_worker_lock(holder, worker_name) as leader:
                assert leader is True
                async with assassin.session() as session:
                    killed = await session.execute(
                        text(
                            "SELECT pg_terminate_backend(l.pid) FROM pg_locks l "
                            "WHERE l.locktype = 'advisory' AND l.granted "
                            "AND ((l.classid::bigint << 32) | l.objid::bigint) = :lock_id",
                        ).bindparams(lock_id=lock_id),
                    )
                    assert killed.scalars().all() == [True], "the holder was not killed"

        errors = [r for r in reported if r.levelno >= logging.ERROR]
        assert errors, (
            "the lock was gone before the tick finished and the tick ended "
            "silently, so a concurrent run leaves no trace at all"
        )
        assert any(worker_name in r.getMessage() for r in errors), (
            "the report does not name the worker whose lock was lost"
        )
    finally:
        await holder.engine.dispose()
        await assassin.engine.dispose()


@pytest.mark.asyncio
async def test_a_database_that_cannot_be_reached_skips_the_tick() -> None:
    """Failing to ask must not be louder, to the supervisor, than the answer.

    A raised acquisition error reaches the supervisor's failure backoff,
    which retries on its own schedule rather than the operator's interval. A
    worker configured to run once a day then runs every few seconds, against
    a database that is by definition already in trouble. Skipping is the same
    action the losing replica takes, and the log is where the difference
    between the two is recorded.
    """
    dead = _replica(f"postgresql+asyncpg://z4j:z4j@127.0.0.1:{_unused_local_port()}/z4j")
    try:
        async with acquire_per_worker_lock(dead, "probe_unreachable") as got:
            assert got is False, "a tick ran without any proof that this replica leads"
    finally:
        await dead.engine.dispose()


@pytest.mark.asyncio
async def test_a_database_that_cannot_be_reached_is_reported() -> None:
    """Skipping quietly forever is how a worker stops running unnoticed."""
    dead = _replica(f"postgresql+asyncpg://z4j:z4j@127.0.0.1:{_unused_local_port()}/z4j")
    try:
        with _reported_by("z4j.brain.workers._leader_lock") as reported:
            async with acquire_per_worker_lock(dead, "probe_unreachable") as got:
                assert got is False

        errors = [r for r in reported if r.levelno >= logging.ERROR]
        assert errors, "an unreachable database was indistinguishable from losing the race"
        assert any("probe_unreachable" in r.getMessage() for r in errors)
    finally:
        await dead.engine.dispose()
