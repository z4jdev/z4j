"""Tests for ``z4j_brain.websocket.registry.local.LocalRegistry``."""

from __future__ import annotations

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
    async def deliver(command_id: uuid.UUID, ws: Any) -> bool:  # noqa: ARG001
        captured_deliveries.append(command_id)
        return True

    return LocalRegistry(deliver_local=deliver)


@pytest.mark.asyncio
class TestRegister:
    async def test_register_makes_agent_online(
        self, registry: LocalRegistry,
    ) -> None:
        ws = FakeWebSocket("a")
        agent_id = uuid.uuid4()
        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws,
        )
        assert registry.is_online(agent_id)

    async def test_second_connection_kicks_first(
        self, registry: LocalRegistry,
    ) -> None:
        ws1 = FakeWebSocket("first")
        ws2 = FakeWebSocket("second")
        agent_id = uuid.uuid4()
        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws1,
        )
        await registry.register(
            project_id=uuid.uuid4(), agent_id=agent_id, ws=ws2,
        )
        assert ws1.closed is True
        assert ws1.close_code == 4002
        assert ws2.closed is False

    async def test_unregister_removes_agent(
        self, registry: LocalRegistry,
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
        self, registry: LocalRegistry,
    ) -> None:
        result = await registry.deliver(
            command_id=uuid.uuid4(),
            agent_id=uuid.uuid4(),
        )
        assert result.delivered_locally is False
        assert result.notified_cluster is False
        assert result.agent_was_known is False

    async def test_deliver_callback_failure(
        self, captured_deliveries: list[uuid.UUID],  # noqa: ARG002
    ) -> None:
        async def deliver_fail(command_id: uuid.UUID, ws: Any) -> bool:  # noqa: ARG001
            raise RuntimeError("kaboom")

        registry = LocalRegistry(deliver_local=deliver_fail)
        agent_id = uuid.uuid4()
        await registry.register(
            project_id=uuid.uuid4(),
            agent_id=agent_id,
            ws=FakeWebSocket("a"),
        )
        result = await registry.deliver(
            command_id=uuid.uuid4(), agent_id=agent_id,
        )
        # Crash inside the callback collapses to "not delivered".
        assert result.delivered_locally is False
        assert result.agent_was_known is True


@pytest.mark.asyncio
class TestStop:
    async def test_stop_closes_all_connections(
        self, registry: LocalRegistry,
    ) -> None:
        ws_list = [FakeWebSocket(f"a{i}") for i in range(3)]
        for i, ws in enumerate(ws_list):
            await registry.register(
                project_id=uuid.uuid4(),
                agent_id=uuid.uuid4(),
                ws=ws,
            )
        await registry.stop()
        for ws in ws_list:
            assert ws.closed is True
