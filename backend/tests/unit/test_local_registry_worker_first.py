"""Worker-first protocol regression tests for LocalRegistry (1.2.0+).

Validates the four cross-version compatibility cases the new
``worker_id`` parameter must handle:

1. Legacy + legacy: 1.1.x agent connects, second 1.1.x agent on
   same agent_id replaces it (kick with code 4002). Preserves
   1.1.x semantics for clients that don't send worker_id.
2. Worker-first: two 1.2.0 agents with DIFFERENT worker_ids on
   the same agent_id - both register simultaneously, no kick.
   This is the new wave's headline behavior (4 gunicorn workers
   coexisting under one agent token).
3. Worker-first reconnect: a 1.2.0 agent with the SAME worker_id
   reconnects (process restart) - the old connection is kicked.
4. Mixed mode: 1.1.x legacy connection + 1.2.0 worker connections
   on the same agent_id coexist; only the legacy slot kicks
   another legacy slot.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from z4j_brain.websocket.registry.local import LocalRegistry


class FakeWebSocket:
    def __init__(self, name: str) -> None:
        self.name = name
        self.closed = False
        self.close_code: int | None = None

    async def close(self, code: int = 1000) -> None:
        self.closed = True
        self.close_code = code


@pytest.fixture
def registry() -> LocalRegistry:
    async def deliver(command_id: uuid.UUID, ws: Any) -> bool:  # noqa: ARG001
        return True

    return LocalRegistry(deliver_local=deliver)


@pytest.mark.asyncio
class TestWorkerFirstProtocol:
    async def test_legacy_agents_keep_kick_semantics(
        self, registry: LocalRegistry,
    ) -> None:
        """Two 1.1.x connections (no worker_id) - second kicks first."""
        ws1 = FakeWebSocket("legacy-1")
        ws2 = FakeWebSocket("legacy-2")
        agent_id = uuid.uuid4()

        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws1,
            worker_id=None,
        )
        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws2,
            worker_id=None,
        )

        assert ws1.closed and ws1.close_code == 4002
        assert not ws2.closed
        assert registry.is_online(agent_id)

    async def test_distinct_workers_coexist_no_kick(
        self, registry: LocalRegistry,
    ) -> None:
        """Two 1.2.0 connections with different worker_ids - both register."""
        ws_web1 = FakeWebSocket("gunicorn-1")
        ws_web2 = FakeWebSocket("gunicorn-2")
        agent_id = uuid.uuid4()

        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws_web1,
            worker_id="django-12345-1700000000000",
        )
        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws_web2,
            worker_id="django-12346-1700000000001",
        )

        # Neither was kicked.
        assert not ws_web1.closed
        assert not ws_web2.closed
        # Both are tracked under the agent.
        assert registry.is_online(agent_id)

    async def test_same_worker_reconnect_kicks_old(
        self, registry: LocalRegistry,
    ) -> None:
        """1.2.0 worker process restart - same worker_id reconnects, old kicked."""
        ws_old = FakeWebSocket("old-pid")
        ws_new = FakeWebSocket("new-pid")
        agent_id = uuid.uuid4()
        wid = "django-12345-1700000000000"

        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws_old,
            worker_id=wid,
        )
        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws_new,
            worker_id=wid,
        )

        assert ws_old.closed and ws_old.close_code == 4002
        assert not ws_new.closed

    async def test_mixed_legacy_and_workerfirst_coexist(
        self, registry: LocalRegistry,
    ) -> None:
        """A legacy 1.1.x slot + 1.2.0 worker slots all coexist."""
        ws_legacy = FakeWebSocket("legacy")
        ws_worker_a = FakeWebSocket("worker-a")
        ws_worker_b = FakeWebSocket("worker-b")
        agent_id = uuid.uuid4()

        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws_legacy,
            worker_id=None,  # legacy slot
        )
        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws_worker_a,
            worker_id="celery-100-ts1",
        )
        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws_worker_b,
            worker_id="celery-101-ts1",
        )

        # All three coexist; nothing kicked.
        assert not ws_legacy.closed
        assert not ws_worker_a.closed
        assert not ws_worker_b.closed
        assert registry.is_online(agent_id)

    async def test_unregister_only_drops_specified_worker(
        self, registry: LocalRegistry,
    ) -> None:
        """Disconnecting one worker keeps the others online.

        Also verifies the F3 atomic last-worker return value:
        ``unregister`` returns False while other workers remain,
        True when the last one is removed.
        """
        ws_a = FakeWebSocket("a")
        ws_b = FakeWebSocket("b")
        agent_id = uuid.uuid4()

        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws_a,
            worker_id="wid-a",
        )
        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws_b,
            worker_id="wid-b",
        )

        was_last = await registry.unregister(agent_id, ws=ws_a, worker_id="wid-a")
        assert was_last is False, "F3: unregister returned True with worker B still alive"

        # Agent still online via worker B.
        assert registry.is_online(agent_id)

        was_last = await registry.unregister(agent_id, ws=ws_b, worker_id="wid-b")
        assert was_last is True, "F3: unregister did NOT signal last-worker on final disconnect"

        # Last worker gone -> agent offline.
        assert not registry.is_online(agent_id)

    async def test_unregister_legacy_slot_doesnt_drop_workers(
        self, registry: LocalRegistry,
    ) -> None:
        """Disconnecting the legacy slot doesn't drop coexisting workers."""
        ws_legacy = FakeWebSocket("legacy")
        ws_worker = FakeWebSocket("worker")
        agent_id = uuid.uuid4()

        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws_legacy,
            worker_id=None,
        )
        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws_worker,
            worker_id="wid-1",
        )

        await registry.unregister(agent_id, ws=ws_legacy, worker_id=None)

        # Worker slot is still there.
        assert registry.is_online(agent_id)

    async def test_deliver_routes_to_first_available_worker(
        self, registry: LocalRegistry,
    ) -> None:
        """Commands flow to any registered worker."""
        ws_a = FakeWebSocket("a")
        ws_b = FakeWebSocket("b")
        agent_id = uuid.uuid4()

        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws_a,
            worker_id="wid-a",
        )
        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws_b,
            worker_id="wid-b",
        )

        result = await registry.deliver(
            command_id=uuid.uuid4(), agent_id=agent_id,
        )
        assert result.delivered_locally is True
        assert result.agent_was_known is True

    async def test_old_unregister_signature_still_works(
        self, registry: LocalRegistry,
    ) -> None:
        """Backwards: callers that don't pass worker_id (1.1.x code paths)
        still drop the legacy slot only."""
        ws = FakeWebSocket("legacy")
        agent_id = uuid.uuid4()

        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws,
        )  # worker_id defaults to None
        await registry.unregister(agent_id, ws=ws)  # also defaults to None

        assert not registry.is_online(agent_id)


@pytest.mark.asyncio
class TestF1LegacySlotCollision:
    """Audit F1 fix (1.2.1+): worker_id='__legacy__' must NOT collide
    with the legacy slot.

    Pre-1.2.1 used the string ``"__legacy__"`` as the legacy
    sentinel; a 1.2.0 agent that sent ``worker_id="__legacy__"``
    would land in the same slot and kick the legacy 1.1.x agent
    off (same-tenant DoS). 1.2.1 switched the sentinel to Python's
    ``None``, which cannot collide with any string-typed worker_id.
    """

    async def test_string_named_legacy_does_not_collide(
        self, registry: LocalRegistry,
    ) -> None:
        ws_legacy = FakeWebSocket("legacy-1.1.x")
        ws_named = FakeWebSocket("attacker-named-legacy")
        agent_id = uuid.uuid4()

        # Legacy 1.1.x agent connects (worker_id=None)
        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws_legacy,
            worker_id=None,
        )

        # 1.2.0+ agent (potentially malicious) sends worker_id="__legacy__"
        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws_named,
            worker_id="__legacy__",
        )

        # The legacy agent must NOT have been kicked. They are
        # in different slots: legacy in slot=None, attacker in
        # slot="__legacy__" (a regular string key).
        assert not ws_legacy.closed, (
            "F1 regression: worker_id='__legacy__' collided with "
            "the legacy None slot and kicked the 1.1.x agent off"
        )
        assert not ws_named.closed
        assert registry.is_online(agent_id)


@pytest.mark.asyncio
class TestF2WorkerCap:
    """Audit F2 fix (1.2.1+): per-agent worker connection cap
    bounds worst-case fd / memory per agent_token.

    Cap=0 disables (legacy 1.2.0 behavior, unbounded).
    Cap>0 raises ``WorkerCapExceeded`` when adding a NEW slot
    would push past the cap. Reconnects of an existing worker_id
    do NOT count against the cap (they replace in place).
    """

    async def test_cap_zero_is_unbounded(
        self, registry: LocalRegistry,
    ) -> None:
        agent_id = uuid.uuid4()
        # 100 distinct workers, no cap -> all accepted
        for i in range(100):
            await registry.register(
                project_id=uuid.uuid4(), agent_id=agent_id,
                ws=FakeWebSocket(f"w{i}"), worker_id=f"wid-{i}", cap=0,
            )
        assert registry.is_online(agent_id)

    async def test_cap_rejects_new_slot_past_cap(
        self, registry: LocalRegistry,
    ) -> None:
        from z4j_brain.websocket.registry._protocol import WorkerCapExceeded

        agent_id = uuid.uuid4()
        # Fill the cap (3)
        for i in range(3):
            await registry.register(
                project_id=uuid.uuid4(), agent_id=agent_id,
                ws=FakeWebSocket(f"w{i}"), worker_id=f"wid-{i}", cap=3,
            )

        # 4th distinct worker_id rejected
        with pytest.raises(WorkerCapExceeded) as exc_info:
            await registry.register(
                project_id=uuid.uuid4(), agent_id=agent_id,
                ws=FakeWebSocket("over"), worker_id="wid-3", cap=3,
            )
        assert exc_info.value.cap == 3
        assert exc_info.value.current == 3

    async def test_cap_allows_reconnect_of_existing_slot(
        self, registry: LocalRegistry,
    ) -> None:
        """Reconnecting under an existing worker_id (process restart
        in place) doesn't count against the cap."""
        agent_id = uuid.uuid4()
        for i in range(3):
            await registry.register(
                project_id=uuid.uuid4(), agent_id=agent_id,
                ws=FakeWebSocket(f"w{i}"), worker_id=f"wid-{i}", cap=3,
            )

        # Same worker_id reconnects (process restart with same id) -
        # should succeed even though we are AT the cap.
        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id,
            ws=FakeWebSocket("w0-reconnect"), worker_id="wid-0", cap=3,
        )
        assert registry.is_online(agent_id)

    async def test_cap_independent_per_agent(
        self, registry: LocalRegistry,
    ) -> None:
        """Cap is per-agent. Two agents can each fill the cap."""
        from z4j_brain.websocket.registry._protocol import WorkerCapExceeded

        agent_a = uuid.uuid4()
        agent_b = uuid.uuid4()

        for i in range(2):
            await registry.register(
                project_id=uuid.uuid4(), agent_id=agent_a,
                ws=FakeWebSocket(f"a{i}"), worker_id=f"a-wid-{i}", cap=2,
            )
            await registry.register(
                project_id=uuid.uuid4(), agent_id=agent_b,
                ws=FakeWebSocket(f"b{i}"), worker_id=f"b-wid-{i}", cap=2,
            )

        # Both at cap; 3rd in either bucket rejected
        with pytest.raises(WorkerCapExceeded):
            await registry.register(
                project_id=uuid.uuid4(), agent_id=agent_a,
                ws=FakeWebSocket("a3"), worker_id="a-wid-2", cap=2,
            )
        with pytest.raises(WorkerCapExceeded):
            await registry.register(
                project_id=uuid.uuid4(), agent_id=agent_b,
                ws=FakeWebSocket("b3"), worker_id="b-wid-2", cap=2,
            )
