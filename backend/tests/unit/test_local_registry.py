"""Tests for ``z4j_brain.websocket.registry.local.LocalRegistry``."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
from z4j_brain.websocket.registry.local import LocalRegistry


class FakeWebSocket:
    """Minimal stand-in for ``fastapi.WebSocket``."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.closed = False
        self.close_code: int | None = None

    async def close(self, code: int = 1000) -> None:
        self.closed = True
        self.close_code = code


@pytest.fixture
def captured_deliveries() -> list[uuid.UUID]:
    return []


@pytest.fixture
def registry(captured_deliveries: list[uuid.UUID]) -> LocalRegistry:
    async def deliver(command_id: uuid.UUID, ws: Any) -> bool:
        captured_deliveries.append(command_id)
        return True

    return LocalRegistry(deliver_local=deliver)


@pytest.mark.asyncio
class TestRegister:
    async def test_register_makes_agent_online(
        self,
        registry: LocalRegistry,
    ) -> None:
        ws = FakeWebSocket("a")
        agent_id = uuid.uuid4()
        await registry.register(
            project_id=uuid.uuid4(),
            agent_id=agent_id,
            ws=ws,
        )
        assert registry.is_online(agent_id)
        # Physical delivery revalidates this immutable registry coordinate
        # before it sends; a test double that sets it by hand would hide a
        # production registration regression.
        assert ws._z4j_agent_id == agent_id  # type: ignore[attr-defined]

    async def test_second_connection_kicks_first(
        self,
        registry: LocalRegistry,
    ) -> None:
        ws1 = FakeWebSocket("first")
        ws2 = FakeWebSocket("second")
        agent_id = uuid.uuid4()
        await registry.register(
            project_id=uuid.uuid4(),
            agent_id=agent_id,
            ws=ws1,
        )
        await registry.register(
            project_id=uuid.uuid4(),
            agent_id=agent_id,
            ws=ws2,
        )
        assert ws1.closed is True
        assert ws1.close_code == 4002
        assert ws2.closed is False

    async def test_unregister_removes_agent(
        self,
        registry: LocalRegistry,
    ) -> None:
        agent_id = uuid.uuid4()
        await registry.register(
            project_id=uuid.uuid4(),
            agent_id=agent_id,
            ws=FakeWebSocket("a"),
        )
        await registry.unregister(agent_id)
        assert not registry.is_online(agent_id)


@pytest.mark.asyncio
class TestDeliver:
    async def test_deliver_to_known_agent(
        self,
        registry: LocalRegistry,
        captured_deliveries: list[uuid.UUID],
    ) -> None:
        agent_id = uuid.uuid4()
        await registry.register(
            project_id=uuid.uuid4(),
            agent_id=agent_id,
            ws=FakeWebSocket("a"),
        )
        command_id = uuid.uuid4()
        result = await registry.deliver(command_id=command_id, agent_id=agent_id)
        assert result.delivered_locally is True
        assert result.agent_was_known is True
        assert captured_deliveries == [command_id]

    async def test_deliver_to_unknown_agent(
        self,
        registry: LocalRegistry,
    ) -> None:
        result = await registry.deliver(
            command_id=uuid.uuid4(),
            agent_id=uuid.uuid4(),
        )
        assert result.delivered_locally is False
        assert result.notified_cluster is False
        assert result.agent_was_known is False

    async def test_deliver_callback_failure(
        self,
        captured_deliveries: list[uuid.UUID],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from z4j_brain.websocket.registry import local

        async def deliver_fail(command_id: uuid.UUID, ws: Any) -> bool:
            raise RuntimeError("kaboom")

        class UnwritableLogger:
            def exception(self, *_args: object, **_kwargs: object) -> None:
                raise UnicodeEncodeError("cp1252", "→", 0, 1, "unencodable")

        monkeypatch.setattr(local, "logger", UnwritableLogger())
        registry = LocalRegistry(deliver_local=deliver_fail)
        agent_id = uuid.uuid4()
        await registry.register(
            project_id=uuid.uuid4(),
            agent_id=agent_id,
            ws=FakeWebSocket("a"),
        )
        result = await registry.deliver(
            command_id=uuid.uuid4(),
            agent_id=agent_id,
        )
        # Crash inside the callback collapses to "not delivered".
        assert result.delivered_locally is False
        assert result.agent_was_known is True

    async def test_frozen_delivery_rejects_replacement_generation(
        self,
        registry: LocalRegistry,
        captured_deliveries: list[uuid.UUID],
    ) -> None:
        agent_id = uuid.uuid4()
        project_id = uuid.uuid4()
        first = await registry.register(
            project_id=project_id,
            agent_id=agent_id,
            ws=FakeWebSocket("first"),
            worker_id="worker",
        )
        command_id = uuid.uuid4()
        assert await registry.deliver_frozen(
            command_id=command_id,
            agent_id=agent_id,
            registry_owner_id=first.registry_owner_id,
            session_generation=str(first.generation),
        )
        assert captured_deliveries == [command_id]

        await registry.register(
            project_id=project_id,
            agent_id=agent_id,
            ws=FakeWebSocket("replacement"),
            worker_id="worker",
        )
        assert not await registry.deliver_frozen(
            command_id=uuid.uuid4(),
            agent_id=agent_id,
            registry_owner_id=first.registry_owner_id,
            session_generation=str(first.generation),
        )
        assert captured_deliveries == [command_id]

    async def test_exact_delivery_allows_reconnect_and_rejects_displaced_send(
        self,
    ) -> None:
        entered = asyncio.Event()
        release = asyncio.Event()
        delivered_to: list[str] = []

        async def blocking_deliver(
            _command_id: uuid.UUID,
            ws: Any,
        ) -> bool:
            entered.set()
            await release.wait()
            validate = ws._z4j_validate_registry_generation
            if not await validate():
                return False
            delivered_to.append(ws.name)
            return True

        registry = LocalRegistry(deliver_local=blocking_deliver)
        agent_id = uuid.uuid4()
        project_id = uuid.uuid4()
        original = await registry.register(
            project_id=project_id,
            agent_id=agent_id,
            ws=FakeWebSocket("original"),
            worker_id="worker",
        )
        delivery = asyncio.create_task(
            registry.deliver_exact(
                command_id=uuid.uuid4(),
                session=original,
            ),
        )
        await entered.wait()
        try:
            replacement_handle = await asyncio.wait_for(
                registry.register(
                    project_id=project_id,
                    agent_id=agent_id,
                    ws=FakeWebSocket("replacement"),
                    worker_id="worker",
                ),
                timeout=1,
            )
        finally:
            release.set()
            delivered = await asyncio.wait_for(delivery, timeout=1)
        assert replacement_handle.generation != original.generation
        assert delivered is False
        assert delivered_to == []


@pytest.mark.asyncio
class TestStop:
    async def test_stop_closes_all_connections(
        self,
        registry: LocalRegistry,
    ) -> None:
        ws_list = [FakeWebSocket(f"a{i}") for i in range(3)]
        for ws in ws_list:
            await registry.register(
                project_id=uuid.uuid4(),
                agent_id=uuid.uuid4(),
                ws=ws,
            )
        await registry.stop()
        for ws in ws_list:
            assert ws.closed is True


@pytest.mark.asyncio
class TestKick:
    """1.6.5 advisory F2: ``kick(agent_id)`` MUST close every
    registered WebSocket for the agent and drop the registry entry.

    Pre-1.6.5 the agent-revoke route only deleted the DB row; the
    open WebSocket continued accepting signed frames. ``kick`` is
    the primitive the revoke route now calls to terminate the
    session promptly.
    """

    async def test_kick_closes_single_ws(
        self,
        registry: LocalRegistry,
    ) -> None:
        ws = FakeWebSocket("a")
        agent_id = uuid.uuid4()
        await registry.register(
            project_id=uuid.uuid4(),
            agent_id=agent_id,
            ws=ws,
        )
        assert registry.is_online(agent_id)

        closed = await registry.kick(agent_id)
        assert closed == 1
        assert ws.closed is True
        assert ws.close_code == 4003, (
            "kick MUST use close code 4003 (agent revoked) so clients "
            "can distinguish 'token revoked' from other close codes"
        )
        assert not registry.is_online(agent_id), (
            "kick MUST drop the registry entry; otherwise a stale "
            "is_online() reads true for a revoked agent"
        )

    async def test_kick_closes_all_workers_for_agent(
        self,
        registry: LocalRegistry,
    ) -> None:
        """If an agent has multiple worker connections (1.2.0+
        multi-worker model), kick closes ALL of them."""
        ws1 = FakeWebSocket("w1")
        ws2 = FakeWebSocket("w2")
        ws3 = FakeWebSocket("w3")
        agent_id = uuid.uuid4()
        project_id = uuid.uuid4()
        await registry.register(
            project_id=project_id,
            agent_id=agent_id,
            ws=ws1,
            worker_id="worker-1",
        )
        await registry.register(
            project_id=project_id,
            agent_id=agent_id,
            ws=ws2,
            worker_id="worker-2",
        )
        await registry.register(
            project_id=project_id,
            agent_id=agent_id,
            ws=ws3,
            worker_id="worker-3",
        )

        closed = await registry.kick(agent_id)
        assert closed == 3
        for ws in (ws1, ws2, ws3):
            assert ws.closed is True
            assert ws.close_code == 4003

    async def test_kick_is_idempotent(
        self,
        registry: LocalRegistry,
    ) -> None:
        """Calling kick on an unknown agent returns 0, not an error."""
        result = await registry.kick(uuid.uuid4())
        assert result == 0

    async def test_kick_does_not_affect_other_agents(
        self,
        registry: LocalRegistry,
    ) -> None:
        ws_a = FakeWebSocket("a")
        ws_b = FakeWebSocket("b")
        agent_a = uuid.uuid4()
        agent_b = uuid.uuid4()
        await registry.register(
            project_id=uuid.uuid4(),
            agent_id=agent_a,
            ws=ws_a,
        )
        await registry.register(
            project_id=uuid.uuid4(),
            agent_id=agent_b,
            ws=ws_b,
        )

        closed = await registry.kick(agent_a)
        assert closed == 1
        assert ws_a.closed is True
        assert ws_b.closed is False
        assert registry.is_online(agent_b), "kick MUST be scoped to the specified agent only"

    async def test_kick_tolerates_already_closed_ws(
        self,
        registry: LocalRegistry,
    ) -> None:
        """A WebSocket that errors on close (already torn down,
        network gone) MUST NOT raise out of kick. kick is the
        cleanup primitive of last resort.
        """

        class FailingWebSocket(FakeWebSocket):
            async def close(self, code: int = 1000) -> None:
                raise RuntimeError("connection already gone")

        ws = FailingWebSocket("failing")
        agent_id = uuid.uuid4()
        await registry.register(
            project_id=uuid.uuid4(),
            agent_id=agent_id,
            ws=ws,
        )
        # Should not raise; closed count is 0 (the close raised).
        closed = await registry.kick(agent_id)
        assert closed == 0
        # Registry entry is dropped regardless.
        assert not registry.is_online(agent_id)
