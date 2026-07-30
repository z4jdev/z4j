"""Regression tests for the process-lifetime PostgreSQL singleton lock."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from z4j_brain.domain.workers import _leader_lock


def _result(value: bool) -> SimpleNamespace:
    return SimpleNamespace(scalar=lambda: value)


@pytest.mark.asyncio
async def test_postgres_winner_returns_connection_owning_lease() -> None:
    """The acquired connection must remain strongly owned until shutdown.

    The pre-fix helper returned only ``True``. Its local connection wrapper
    was then garbage-collected, SQLAlchemy terminated the leaked checkout,
    and PostgreSQL silently released the supposed process-lifetime lock.
    """
    connection = AsyncMock()
    connection.execute.side_effect = [_result(True), _result(True)]
    engine = SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql"),
        connect=AsyncMock(return_value=connection),
    )

    lease = await _leader_lock.try_acquire_singleton_lock(
        SimpleNamespace(engine=engine),
        "embedded_scheduler_supervisor",
    )

    assert not isinstance(lease, bool)
    assert hasattr(lease, "release")
    assert lease._connection is connection
    connection.commit.assert_awaited_once()
    connection.close.assert_not_awaited()

    await lease.release()

    assert lease.released is True
    assert lease._connection is None
    assert connection.execute.await_count == 2
    unlock_statement = str(connection.execute.await_args_list[1].args[0])
    assert "pg_advisory_unlock" in unlock_statement
    assert connection.commit.await_count == 2
    connection.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_postgres_loser_closes_connection_and_returns_none() -> None:
    connection = AsyncMock()
    connection.execute.return_value = _result(False)
    engine = SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql"),
        connect=AsyncMock(return_value=connection),
    )

    lease = await _leader_lock.try_acquire_singleton_lock(
        SimpleNamespace(engine=engine),
        "embedded_scheduler_supervisor",
    )

    assert lease is None
    connection.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_sqlite_lease_has_same_idempotent_lifecycle_contract() -> None:
    engine = SimpleNamespace(
        dialect=SimpleNamespace(name="sqlite"),
        connect=AsyncMock(),
    )

    lease = await _leader_lock.try_acquire_singleton_lock(
        SimpleNamespace(engine=engine),
        "embedded_scheduler_supervisor",
    )

    assert not isinstance(lease, bool)
    assert hasattr(lease, "release")
    assert lease.released is False
    await lease.release()
    await lease.release()
    assert lease.released is True
    engine.connect.assert_not_awaited()


@pytest.mark.asyncio
async def test_release_closes_connection_even_when_unlock_fails() -> None:
    connection = AsyncMock()
    connection.execute.side_effect = RuntimeError("connection lost")
    lease = _leader_lock.SingletonLockLease(
        connection=connection,
        lock_id=123,
        name="embedded_scheduler_supervisor",
    )

    with pytest.raises(RuntimeError, match="connection lost"):
        await lease.release()

    assert lease.released is True
    connection.invalidate.assert_awaited_once()
    connection.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_release_invalidates_when_unlock_is_not_confirmed() -> None:
    connection = AsyncMock()
    connection.execute.return_value = _result(False)
    lease = _leader_lock.SingletonLockLease(
        connection=connection,
        lock_id=123,
        name="embedded_scheduler_supervisor",
    )

    await lease.release()

    assert lease.released is True
    connection.commit.assert_not_awaited()
    connection.invalidate.assert_awaited_once()
    connection.close.assert_awaited_once()
