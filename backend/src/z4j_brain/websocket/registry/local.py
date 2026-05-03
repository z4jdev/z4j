"""In-process :class:`BrainRegistry` implementation.

Used by unit tests for speed and by single-worker development
loops where Postgres NOTIFY is unnecessary overhead. NEVER set
this as the production backend - it does not route across worker
processes, so commands issued from worker A targeting an agent on
worker B silently disappear.

The implementation is a thin wrapper around a single ``dict``
keyed by ``agent_id``. Concurrent register/unregister is safe via
an :class:`asyncio.Lock`; the dict itself is single-task-owned.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Callable, Awaitable
from uuid import UUID

import structlog

from z4j_brain.websocket.registry._protocol import (
    DeliveryResult,
    WorkerCapExceeded,
)

if TYPE_CHECKING:
    from fastapi import WebSocket


logger = structlog.get_logger("z4j.brain.registry.local")


#: Type of the per-command "deliver this command to the WS" callback
#: that the gateway gives the registry. The registry calls it from
#: the worker that owns the WebSocket. Returns True on successful
#: push, False on push failure (which the registry treats as
#: "not delivered locally").
LocalDeliverCallback = Callable[[UUID, "WebSocket"], Awaitable[bool]]


#: 1.2.1+: legacy 1.1.x clients (worker_id=None) use Python's
#: ``None`` directly as their dict key. Pre-1.2.1 used the string
#: ``"__legacy__"`` as a sentinel, but a 1.2.0 agent that sent
#: ``worker_id="__legacy__"`` could collide with the legacy slot
#: and kick the 1.1.x agent off (audit finding F1, LOW: same-
#: tenant DoS). Using ``None`` makes collision impossible because
#: Pydantic-validated string fields cannot be None when set.


class LocalRegistry:
    """Single-process registry for tests + single-worker dev mode.

    1.2.0+: tracks multiple WebSockets per agent_id, keyed by
    worker_id. Legacy 1.1.x clients (worker_id=None) use ``None``
    as their dict key (1.2.1+ - earlier patches used a string
    sentinel that could collide with attacker-chosen worker_ids).
    """

    def __init__(self, *, deliver_local: LocalDeliverCallback) -> None:
        self._lock = asyncio.Lock()
        # agent_id -> {worker_id (or None for legacy): WebSocket}
        self._connections: dict[UUID, dict[str | None, "WebSocket"]] = {}
        self._project_for_agent: dict[UUID, UUID] = {}
        self._deliver_local = deliver_local

    # ------------------------------------------------------------------
    # BrainRegistry
    # ------------------------------------------------------------------

    async def register(
        self,
        *,
        project_id: UUID,
        agent_id: UUID,
        ws: "WebSocket",
        worker_id: str | None = None,
        cap: int = 0,
    ) -> None:
        slot: str | None = worker_id  # None = legacy 1.1.x slot
        async with self._lock:
            workers = self._connections.setdefault(agent_id, {})
            # Cap check (1.2.1+): only counts NEW slot creations.
            # Reconnects of an existing worker_id (process restart)
            # don't push past the cap because they overwrite the
            # existing slot in place.
            if cap > 0 and slot not in workers and len(workers) >= cap:
                raise WorkerCapExceeded(
                    agent_id=agent_id, current=len(workers), cap=cap,
                )
            existing = workers.get(slot)
            if existing is not None and existing is not ws:
                # Same (agent_id, worker_id) reconnecting (or a
                # legacy-mode duplicate). Kick the old.
                try:
                    await existing.close(code=4002)
                except Exception:  # noqa: BLE001
                    pass
            workers[slot] = ws
            self._project_for_agent[agent_id] = project_id

    async def unregister(
        self,
        agent_id: UUID,
        *,
        ws: "WebSocket | None" = None,
        worker_id: str | None = None,
    ) -> bool:
        """Drop one slot for ``agent_id``. Returns ``True`` if the
        agent has no more workers registered after this call.

        v1.2.1 (audit F3 fix): the return value is determined
        atomically under ``self._lock``, so callers can
        ``mark_offline`` the agent without a TOCTOU race against a
        concurrent ``register``.
        """
        slot: str | None = worker_id  # None = legacy 1.1.x slot
        async with self._lock:
            workers = self._connections.get(agent_id)
            if workers is None:
                # Already gone; agent is not online.
                return True
            if ws is not None:
                current = workers.get(slot)
                if current is not ws:
                    # The new connection has already replaced this one;
                    # leave the registry entry intact. Other workers
                    # may be present, so the agent isn't offline.
                    return False
            workers.pop(slot, None)
            if not workers:
                # Last worker for this agent disconnected.
                self._connections.pop(agent_id, None)
                self._project_for_agent.pop(agent_id, None)
                return True
            return False

    def is_online(self, agent_id: UUID) -> bool:
        workers = self._connections.get(agent_id)
        return bool(workers)

    async def deliver(
        self,
        *,
        command_id: UUID,
        agent_id: UUID,
    ) -> DeliveryResult:
        workers = self._connections.get(agent_id)
        if not workers:
            return DeliveryResult(
                delivered_locally=False,
                notified_cluster=False,
                agent_was_known=False,
            )
        # Pick any worker - first-available semantics. Future:
        # per-role routing (deliver schedule.fire to role=task,
        # config-update to role=web, etc.). For 1.2.0 we stay
        # role-agnostic; commands flow to whichever worker the
        # registry iteration yields first.
        ws = next(iter(workers.values()))
        try:
            ok = await self._deliver_local(command_id, ws)
        except Exception:  # noqa: BLE001
            logger.exception(
                "z4j local registry deliver crashed",
                command_id=str(command_id),
                agent_id=str(agent_id),
            )
            ok = False
        return DeliveryResult(
            delivered_locally=ok,
            notified_cluster=False,
            agent_was_known=True,
        )

    async def start(self) -> None:
        # No background tasks. The lifespan call still goes through
        # so the brain factory can treat the two registries
        # uniformly.
        return None

    async def stop(self) -> None:
        async with self._lock:
            for workers in list(self._connections.values()):
                for ws in list(workers.values()):
                    try:
                        await ws.close(code=1001)
                    except Exception:  # noqa: BLE001
                        pass
            self._connections.clear()
            self._project_for_agent.clear()


__all__ = ["LocalDeliverCallback", "LocalRegistry"]
