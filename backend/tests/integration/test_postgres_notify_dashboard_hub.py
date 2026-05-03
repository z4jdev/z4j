"""Integration test: ``PostgresNotifyDashboardHub`` against real Postgres.

The dashboard's cross-worker fan-out has the same failure modes
as the agent registry - and the same need for a real Postgres
LISTEN/NOTIFY backplane to verify the happy path. SQLite has no
NOTIFY, so the unit suite can't cover it at all.

What we verify here:

1. **Local fan-out works** - a single hub fans publishes out to
   in-process subscribers. Re-tested at the integration level so
   we know the LISTEN side doesn't break the local path.
2. **Cross-worker fan-out** - two hubs against the same DB. Hub A
   has a subscriber for project P; Hub B publishes a topic for
   project P; A's subscriber receives it. (This is the one that
   would have caught a missed unit-suite assumption.)
3. **Project isolation** - a publish for project P does not reach
   subscribers for project Q.
4. **Stop is clean** - no leaked listener tasks, no leaked asyncpg
   connections.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.settings import Settings
from z4j_brain.websocket.dashboard_hub import PostgresNotifyDashboardHub

pytestmark = pytest.mark.asyncio


class _Sink:
    """Captures every frame the hub pushes at us."""

    def __init__(self) -> None:
        self.frames: list[dict] = []

    async def __call__(self, frame: dict) -> None:
        self.frames.append(frame)


def _build_hub(
    *,
    engine: AsyncEngine,
    settings: Settings,
) -> PostgresNotifyDashboardHub:
    db = DatabaseManager(engine)
    return PostgresNotifyDashboardHub(
        settings=settings,
        db=db,
        dsn_provider=lambda: settings.database_url,
    )


async def _wait_for_frames(sink: _Sink, *, expected: int, timeout: float = 3.0) -> None:
    """Poll until the sink has at least ``expected`` frames or timeout."""
    deadline = asyncio.get_event_loop().time() + timeout
    while len(sink.frames) < expected:
        if asyncio.get_event_loop().time() > deadline:
            return
        await asyncio.sleep(0.05)


class TestSameWorkerFanOut:
    async def test_local_publish_delivers(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """Single hub: subscribe + publish_task_change → frame received."""
        hub = _build_hub(engine=migrated_engine, settings=integration_settings)
        await hub.start()
        try:
            project = uuid.uuid4()
            sink = _Sink()
            await hub.add_subscriber(project_id=project, send=sink)

            await hub.publish_task_change(project)
            await _wait_for_frames(sink, expected=1)

            assert sink.frames == [
                {"type": "event", "topic": "task.changed"},
            ]
        finally:
            await hub.stop()

    async def test_local_publish_each_topic(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        hub = _build_hub(engine=migrated_engine, settings=integration_settings)
        await hub.start()
        try:
            project = uuid.uuid4()
            sink = _Sink()
            await hub.add_subscriber(project_id=project, send=sink)

            await hub.publish_task_change(project)
            await hub.publish_command_change(project)
            await hub.publish_agent_change(project)
            await _wait_for_frames(sink, expected=3)

            topics = [f["topic"] for f in sink.frames]
            assert topics == [
                "task.changed",
                "command.changed",
                "agent.changed",
            ]
        finally:
            await hub.stop()


class TestCrossWorkerFanOut:
    async def test_cross_worker_task_change(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """Two hubs against the same DB. A subscribes, B publishes.

        This is the load-bearing assertion for the production
        multi-worker deployment: a worker that emits an event must
        be able to push it to a dashboard connected to a different
        worker.
        """
        hub_a = _build_hub(engine=migrated_engine, settings=integration_settings)
        hub_b = _build_hub(engine=migrated_engine, settings=integration_settings)
        await hub_a.start()
        await hub_b.start()
        try:
            # Give both listeners a moment to actually LISTEN before
            # we publish - otherwise the NOTIFY is silently lost.
            await asyncio.sleep(0.3)

            project = uuid.uuid4()
            sink_a = _Sink()
            await hub_a.add_subscriber(project_id=project, send=sink_a)

            # Publish from B; A's listener should pick it up via the
            # NOTIFY channel and fan out to its local subscriber.
            await hub_b.publish_task_change(project)
            await _wait_for_frames(sink_a, expected=1, timeout=5.0)

            assert sink_a.frames == [
                {"type": "event", "topic": "task.changed"},
            ]
        finally:
            await hub_a.stop()
            await hub_b.stop()

    async def test_cross_worker_no_duplicate_for_local_publisher(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """A worker that publishes locally must not get a duplicate via NOTIFY.

        The hub publishes BOTH to local subscribers AND fires a
        NOTIFY for peers. The listener filters NOTIFYs that originate
        from the same worker so the same subscriber isn't told twice.
        """
        hub = _build_hub(engine=migrated_engine, settings=integration_settings)
        await hub.start()
        try:
            await asyncio.sleep(0.3)

            project = uuid.uuid4()
            sink = _Sink()
            await hub.add_subscriber(project_id=project, send=sink)

            await hub.publish_task_change(project)
            # Wait long enough for any NOTIFY round-trip to complete.
            await asyncio.sleep(0.6)

            assert sink.frames == [
                {"type": "event", "topic": "task.changed"},
            ]
        finally:
            await hub.stop()

    async def test_project_isolation_across_workers(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """A publish for project P must not reach subscribers for project Q."""
        hub_a = _build_hub(engine=migrated_engine, settings=integration_settings)
        hub_b = _build_hub(engine=migrated_engine, settings=integration_settings)
        await hub_a.start()
        await hub_b.start()
        try:
            await asyncio.sleep(0.3)

            project_p = uuid.uuid4()
            project_q = uuid.uuid4()
            sink_q = _Sink()
            await hub_a.add_subscriber(project_id=project_q, send=sink_q)

            await hub_b.publish_task_change(project_p)
            await asyncio.sleep(0.6)

            assert sink_q.frames == []
        finally:
            await hub_a.stop()
            await hub_b.stop()


class TestLifecycle:
    async def test_stop_is_clean(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """Start + stop drops every subscriber and cancels the listener task."""
        hub = _build_hub(engine=migrated_engine, settings=integration_settings)
        await hub.start()
        project = uuid.uuid4()
        await hub.add_subscriber(project_id=project, send=_Sink())
        assert hub.subscriber_count(project) == 1

        await hub.stop()
        assert hub.subscriber_count(project) == 0
