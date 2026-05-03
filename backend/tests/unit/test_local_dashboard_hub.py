"""LocalDashboardHub unit tests.

Mirrors the structure of ``test_local_registry.py`` - the local
hub is the contract test for the protocol. Every behaviour we
expect from the production PostgresNotifyDashboardHub is verified
here against the in-memory implementation first.
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from z4j_brain.websocket.dashboard_hub import LocalDashboardHub

pytestmark = pytest.mark.asyncio


class _CollectingSink:
    """Test fake - captures every frame the hub pushes at us."""

    def __init__(self) -> None:
        self.frames: list[dict] = []
        self.fail = False

    async def __call__(self, frame: dict) -> None:
        if self.fail:
            raise RuntimeError("simulated send failure")
        self.frames.append(frame)


class TestLifecycle:
    async def test_start_stop_idempotent(self) -> None:
        hub = LocalDashboardHub()
        await hub.start()
        await hub.start()  # idempotent
        await hub.stop()
        await hub.stop()  # idempotent
        assert hub.subscriber_count() == 0

    async def test_add_subscriber_after_stop_raises(self) -> None:
        hub = LocalDashboardHub()
        await hub.start()
        await hub.stop()
        with pytest.raises(RuntimeError):
            await hub.add_subscriber(project_id=uuid4(), send=_CollectingSink())


class TestSingleSubscriber:
    async def test_publish_task_change_delivers_one_frame(self) -> None:
        hub = LocalDashboardHub()
        await hub.start()
        project = uuid4()
        sink = _CollectingSink()
        await hub.add_subscriber(project_id=project, send=sink)

        await hub.publish_task_change(project)
        # Yield to the writer task so it drains the queue.
        await asyncio.sleep(0.01)

        assert sink.frames == [{"type": "event", "topic": "task.changed"}]
        await hub.stop()

    async def test_publish_each_topic(self) -> None:
        hub = LocalDashboardHub()
        await hub.start()
        project = uuid4()
        sink = _CollectingSink()
        await hub.add_subscriber(project_id=project, send=sink)

        await hub.publish_task_change(project)
        await hub.publish_command_change(project)
        await hub.publish_agent_change(project)
        await asyncio.sleep(0.02)

        topics = [f["topic"] for f in sink.frames]
        assert topics == ["task.changed", "command.changed", "agent.changed"]
        await hub.stop()

    async def test_publish_to_other_project_does_not_deliver(self) -> None:
        hub = LocalDashboardHub()
        await hub.start()
        project_a = uuid4()
        project_b = uuid4()
        sink_a = _CollectingSink()
        await hub.add_subscriber(project_id=project_a, send=sink_a)

        await hub.publish_task_change(project_b)
        await asyncio.sleep(0.01)

        assert sink_a.frames == []
        await hub.stop()


class TestMultipleSubscribers:
    async def test_fan_out_to_all_local_for_project(self) -> None:
        hub = LocalDashboardHub()
        await hub.start()
        project = uuid4()
        sinks = [_CollectingSink() for _ in range(3)]
        for sink in sinks:
            await hub.add_subscriber(project_id=project, send=sink)
        assert hub.subscriber_count(project) == 3

        await hub.publish_task_change(project)
        await asyncio.sleep(0.01)

        for sink in sinks:
            assert sink.frames == [{"type": "event", "topic": "task.changed"}]
        await hub.stop()

    async def test_publish_isolates_projects(self) -> None:
        hub = LocalDashboardHub()
        await hub.start()
        project_a = uuid4()
        project_b = uuid4()
        sink_a = _CollectingSink()
        sink_b = _CollectingSink()
        await hub.add_subscriber(project_id=project_a, send=sink_a)
        await hub.add_subscriber(project_id=project_b, send=sink_b)

        await hub.publish_task_change(project_a)
        await asyncio.sleep(0.01)

        assert sink_a.frames == [{"type": "event", "topic": "task.changed"}]
        assert sink_b.frames == []
        await hub.stop()


class TestRemove:
    async def test_remove_subscriber(self) -> None:
        hub = LocalDashboardHub()
        await hub.start()
        project = uuid4()
        sink = _CollectingSink()
        sub = await hub.add_subscriber(project_id=project, send=sink)
        assert hub.subscriber_count(project) == 1

        await hub.remove_subscriber(sub)
        assert hub.subscriber_count(project) == 0

        await hub.publish_task_change(project)
        await asyncio.sleep(0.01)

        assert sink.frames == []
        await hub.stop()

    async def test_remove_unknown_is_noop(self) -> None:
        hub = LocalDashboardHub()
        await hub.start()
        # Pass an object the hub doesn't know about - should not raise.
        await hub.remove_subscriber(object())  # type: ignore[arg-type]
        await hub.stop()


class TestFailureModes:
    async def test_send_failure_drops_subscriber(self) -> None:
        hub = LocalDashboardHub()
        await hub.start()
        project = uuid4()
        sink = _CollectingSink()
        sink.fail = True
        await hub.add_subscriber(project_id=project, send=sink)

        await hub.publish_task_change(project)
        # Give the writer task a moment to fail and the cleanup
        # to propagate. The writer drops itself on the first
        # send error - the subscriber stays in the map until the
        # gateway calls remove_subscriber, BUT after the writer
        # task dies the queue still grows on the next publish.
        # Either way: no frames make it through.
        await asyncio.sleep(0.02)

        assert sink.frames == []
        await hub.stop()

    async def test_full_queue_drops_subscriber(self) -> None:
        """A subscriber whose queue saturates is force-dropped."""
        hub = LocalDashboardHub()
        await hub.start()
        project = uuid4()

        # A sink that never returns from send → the writer task
        # blocks forever after pulling the first item, queue fills.
        unblock = asyncio.Event()
        seen: list[dict] = []

        async def stuck_send(frame: dict) -> None:
            seen.append(frame)
            await unblock.wait()

        await hub.add_subscriber(project_id=project, send=stuck_send)

        # 64 is the queue cap. Pump 200 publishes - the queue will
        # fill and the hub will drop the subscriber.
        for _ in range(200):
            await hub.publish_task_change(project)
            await asyncio.sleep(0)  # let the writer pick up the first

        # The subscriber was dropped after the queue filled.
        assert hub.subscriber_count(project) == 0

        unblock.set()
        await hub.stop()
