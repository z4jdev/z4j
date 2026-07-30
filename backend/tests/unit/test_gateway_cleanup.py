from __future__ import annotations

import asyncio

import pytest
from z4j_brain.websocket.gateway import (
    _finish_registered_connection_before_cancelling,
)

pytestmark = pytest.mark.asyncio


async def test_cancellation_waits_for_registered_connection_cleanup() -> None:
    cleanup_started = asyncio.Event()
    allow_cleanup_to_finish = asyncio.Event()
    cleanup_finished = asyncio.Event()
    cleanup_cancelled = asyncio.Event()

    async def cleanup() -> None:
        cleanup_started.set()
        try:
            await allow_cleanup_to_finish.wait()
            cleanup_finished.set()
        except asyncio.CancelledError:
            cleanup_cancelled.set()
            raise

    owner = asyncio.create_task(
        _finish_registered_connection_before_cancelling(cleanup()),
    )
    await asyncio.wait_for(cleanup_started.wait(), timeout=1)

    owner.cancel()
    await asyncio.sleep(0)

    assert not owner.done()
    assert not cleanup_cancelled.is_set()

    allow_cleanup_to_finish.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(owner, timeout=1)

    assert cleanup_finished.is_set()
    assert not cleanup_cancelled.is_set()
