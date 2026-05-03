"""Tests for the Batch-3 H5 fix: per-user dashboard subscription cap.

Prevents an authenticated admin (who, per the in-instance scope
statement, sees every project in the same brain) from opening one
WebSocket per project and starving the event loop with one
``asyncio.Task`` writer per WS. The cap is module-private; we read
it via ``_MAX_SUBSCRIBERS_PER_USER`` so the test pins the contract.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from z4j_brain.websocket.dashboard_hub import LocalDashboardHub
from z4j_brain.websocket.dashboard_hub.local import (
    _MAX_SUBSCRIBERS_PER_USER,
)

pytestmark = pytest.mark.asyncio


class _Sink:
    def __init__(self) -> None:
        self.frames: list[dict] = []

    async def __call__(self, frame: dict) -> None:
        self.frames.append(frame)


class TestPerUserCap:
    async def test_cap_is_modest(self) -> None:
        """Pin the constant so lowering it doesn't silently ship."""
        assert _MAX_SUBSCRIBERS_PER_USER >= 10
        assert _MAX_SUBSCRIBERS_PER_USER <= 500

    async def test_under_cap_accepts(self) -> None:
        hub = LocalDashboardHub()
        await hub.start()
        try:
            user = uuid4()
            # Open a handful of subs - far under the cap.
            subs = []
            for _ in range(5):
                subs.append(
                    await hub.add_subscriber(
                        project_id=uuid4(), send=_Sink(), user_id=user,
                    ),
                )
            assert len(subs) == 5
        finally:
            await hub.stop()

    async def test_exceeding_cap_rejects(self) -> None:
        """The (_MAX + 1)th subscription for the same user raises."""
        hub = LocalDashboardHub()
        await hub.start()
        try:
            user = uuid4()
            # Fill up to the cap.
            for _ in range(_MAX_SUBSCRIBERS_PER_USER):
                await hub.add_subscriber(
                    project_id=uuid4(), send=_Sink(), user_id=user,
                )
            # Next one must be refused.
            with pytest.raises(RuntimeError, match="cap"):
                await hub.add_subscriber(
                    project_id=uuid4(), send=_Sink(), user_id=user,
                )
        finally:
            await hub.stop()

    async def test_cap_isolated_per_user(self) -> None:
        """One user hitting the cap does NOT affect other users."""
        hub = LocalDashboardHub()
        await hub.start()
        try:
            noisy = uuid4()
            quiet = uuid4()
            # Fill up noisy user.
            for _ in range(_MAX_SUBSCRIBERS_PER_USER):
                await hub.add_subscriber(
                    project_id=uuid4(), send=_Sink(), user_id=noisy,
                )
            # quiet user is unaffected and can still subscribe.
            sub = await hub.add_subscriber(
                project_id=uuid4(), send=_Sink(), user_id=quiet,
            )
            assert sub is not None
        finally:
            await hub.stop()

    async def test_remove_subscriber_frees_slot(self) -> None:
        """``remove_subscriber`` must decrement the per-user count
        so the slot is released for the next subscription."""
        hub = LocalDashboardHub()
        await hub.start()
        try:
            user = uuid4()
            subs = []
            for _ in range(_MAX_SUBSCRIBERS_PER_USER):
                subs.append(
                    await hub.add_subscriber(
                        project_id=uuid4(), send=_Sink(), user_id=user,
                    ),
                )
            # Remove one - count should drop.
            await hub.remove_subscriber(subs[0])
            # Re-subscribe succeeds.
            new_sub = await hub.add_subscriber(
                project_id=uuid4(), send=_Sink(), user_id=user,
            )
            assert new_sub is not None
        finally:
            await hub.stop()

    async def test_user_id_none_bypasses_cap(self) -> None:
        """Legacy callers that don't pass ``user_id`` bypass the
        cap entirely. Production paths always thread ``user_id``
        from the gateway; callers that opt out intentionally accept
        the pre-Batch-3 behaviour."""
        hub = LocalDashboardHub()
        await hub.start()
        try:
            for _ in range(_MAX_SUBSCRIBERS_PER_USER + 5):
                await hub.add_subscriber(project_id=uuid4(), send=_Sink())
        finally:
            await hub.stop()
