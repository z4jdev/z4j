"""Integration test: ``PostgresNotifyRegistry`` against real Postgres NOTIFY.

This is the most important integration test in the suite. The B4
registry's failure modes (listener drop, queue lock, missed notify
during reconnect) are completely invisible to the SQLite unit suite
because SQLite has no LISTEN/NOTIFY at all.

What we verify here:

1. **LISTEN end-to-end** - a worker that registers an agent
   actually receives the NOTIFY when *another* component publishes
   one for that agent_id, and the local deliver callback fires.
2. **Cross-worker fan-out** - two ``PostgresNotifyRegistry``
   instances against the same database. Worker A holds the agent;
   Worker B publishes the notify; Worker A's callback fires.
3. **Heartbeat round-trip** - the registry's self-notify watchdog
   updates ``_last_heartbeat_round_trip`` within the configured
   interval.
4. **Stop is clean** - no leaked tasks, no leaked connections.

The B7 plan flagged the watchdog kill-on-wedge path as a stretch
goal that needs a real wedged listener; we cover the easier (and
honestly more important) "happy path actually works" cases here
and leave wedge simulation to a future round.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.settings import Settings
from z4j_brain.websocket.registry import PostgresNotifyRegistry

pytestmark = pytest.mark.asyncio


class FakeWebSocket:
    """Minimal stand-in for ``fastapi.WebSocket``."""

    def __init__(self, name: str = "ws") -> None:
        self.name = name
        self.closed = False
        self.close_code: int | None = None

    async def close(self, code: int = 1000) -> None:
        self.closed = True
        self.close_code = code


async def _build_registry(
    *,
    engine: AsyncEngine,
    settings: Settings,
    deliver_calls: list[tuple[uuid.UUID, str]],
) -> PostgresNotifyRegistry:
    """Build a registry whose deliver_local pushes onto a list."""
    db = DatabaseManager(engine)

    async def deliver(command_id: uuid.UUID, ws: Any) -> bool:
        deliver_calls.append((command_id, getattr(ws, "name", "?")))
        return True

    registry = PostgresNotifyRegistry(
        settings=settings,
        db=db,
        dsn_provider=lambda: settings.database_url,
        deliver_local=deliver,
    )
    return registry


class TestNotifyRoundTrip:
    async def test_notify_round_trip_same_worker(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """Worker registers an agent, publishes a notify, sees deliver fire."""
        deliver_calls: list[tuple[uuid.UUID, str]] = []
        registry = await _build_registry(
            engine=migrated_engine,
            settings=integration_settings,
            deliver_calls=deliver_calls,
        )
        await registry.start()
        try:
            agent_id = uuid.uuid4()
            project_id = uuid.uuid4()
            ws = FakeWebSocket("local")
            await registry.register(
                project_id=project_id,
                agent_id=agent_id,
                ws=ws,
            )

            # Publish a notify directly via the registry's slow
            # path. The local-fast-path branch returns immediately
            # without notifying, but here we go through the SQL
            # publish so the listener loop genuinely receives.
            command_id = uuid.uuid4()
            await registry._publish_command_notify(command_id, agent_id)  # type: ignore[attr-defined]

            # Give the listener task a chance to receive + dispatch.
            for _ in range(20):
                if deliver_calls:
                    break
                await asyncio.sleep(0.1)
            assert deliver_calls, "deliver callback never fired"
            assert deliver_calls[0][0] == command_id
        finally:
            await registry.stop()

    async def test_cross_worker_dispatch(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """Two registries against the same DB. A holds the agent, B notifies."""
        deliver_a: list[tuple[uuid.UUID, str]] = []
        deliver_b: list[tuple[uuid.UUID, str]] = []

        registry_a = await _build_registry(
            engine=migrated_engine,
            settings=integration_settings,
            deliver_calls=deliver_a,
        )
        registry_b = await _build_registry(
            engine=migrated_engine,
            settings=integration_settings,
            deliver_calls=deliver_b,
        )
        await registry_a.start()
        await registry_b.start()
        try:
            agent_id = uuid.uuid4()
            project_id = uuid.uuid4()
            await registry_a.register(
                project_id=project_id,
                agent_id=agent_id,
                ws=FakeWebSocket("on-A"),
            )

            command_id = uuid.uuid4()
            # Publish FROM B for an agent held by A. The notify
            # fans out to every listening worker; only A has the
            # agent in its local map, so only A's deliver fires.
            await registry_b._publish_command_notify(  # type: ignore[attr-defined]
                command_id, agent_id,
            )

            for _ in range(30):
                if deliver_a:
                    break
                await asyncio.sleep(0.1)
            assert deliver_a, "registry A never delivered the cross-worker notify"
            assert not deliver_b, "registry B should not deliver - agent is on A"
            assert deliver_a[0][0] == command_id
        finally:
            await registry_a.stop()
            await registry_b.stop()


class TestHeartbeat:
    async def test_heartbeat_round_trip_updates(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """The watchdog's self-NOTIFY round-trip should bump the timestamp."""
        deliver_calls: list[tuple[uuid.UUID, str]] = []
        registry = await _build_registry(
            engine=migrated_engine,
            settings=integration_settings,
            deliver_calls=deliver_calls,
        )
        await registry.start()
        try:
            initial = registry._last_heartbeat_round_trip  # type: ignore[attr-defined]
            # Heartbeat interval is 1s in integration settings.
            await asyncio.sleep(2.5)
            current = registry._last_heartbeat_round_trip  # type: ignore[attr-defined]
            # The watchdog should have processed at least one
            # heartbeat round-trip in 2.5 seconds.
            assert current > initial
        finally:
            await registry.stop()


class TestStop:
    async def test_stop_cancels_listener_task(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        deliver_calls: list[tuple[uuid.UUID, str]] = []
        registry = await _build_registry(
            engine=migrated_engine,
            settings=integration_settings,
            deliver_calls=deliver_calls,
        )
        await registry.start()
        # Let it run briefly so the listener task is fully alive.
        await asyncio.sleep(0.5)
        await registry.stop()
        # After stop, the registry's listener task should be None.
        assert registry._listener_task is None  # type: ignore[attr-defined]
        assert registry._reconcile_task is None  # type: ignore[attr-defined]
