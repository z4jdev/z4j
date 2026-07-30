"""In-process :class:`BrainRegistry` implementation.

Used by unit tests for speed and by single-worker development
loops where Postgres NOTIFY is unnecessary overhead. NEVER set
this as the production backend - it does not route across worker
processes, so commands issued from worker A targeting an agent on
worker B silently disappear.

The implementation stores immutable connection-generation handles
under ``(agent_id, worker_id)``. Concurrent register/unregister and
contract-aware selection are safe via an :class:`asyncio.Lock`.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import structlog

from z4j_brain.websocket.registry._protocol import (
    DeliveryResult,
    SessionHandle,
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

    Tracks multiple immutable session generations per agent_id,
    keyed by worker_id. Legacy 1.1.x clients (worker_id=None) use
    ``None`` as their dict key (1.2.1+ - earlier patches used a
    string sentinel that could collide with attacker-chosen
    worker_ids).
    """

    def __init__(self, *, deliver_local: LocalDeliverCallback) -> None:
        self._lock = asyncio.Lock()
        self._registry_owner_id = uuid4()
        # agent_id -> {worker_id (or None): immutable session generation}
        self._connections: dict[UUID, dict[str | None, SessionHandle]] = {}
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
        ws: WebSocket,
        worker_id: str | None = None,
        cap: int = 0,
        retry_contracts: dict[str, int] | None = None,
    ) -> SessionHandle:
        slot: str | None = worker_id  # None = legacy 1.1.x slot
        displaced: SessionHandle | None = None
        async with self._lock:
            workers = self._connections.setdefault(agent_id, {})
            # Cap check (1.2.1+): only counts NEW slot creations.
            # Reconnects of an existing worker_id (process restart)
            # don't push past the cap because they overwrite the
            # existing slot in place.
            if cap > 0 and slot not in workers and len(workers) >= cap:
                raise WorkerCapExceeded(
                    agent_id=agent_id,
                    current=len(workers),
                    cap=cap,
                )
            existing = workers.get(slot)
            if existing is not None and existing.websocket is not ws:
                displaced = existing
            handle = SessionHandle.create(
                agent_id=agent_id,
                worker_id=worker_id,
                websocket=ws,
                retry_contracts=retry_contracts,
                registry_owner_id=self._registry_owner_id,
            )
            # Starlette WebSocket instances carry these immutable delivery
            # coordinates into the app callback.  Registry protocol tests and
            # embedders may supply opaque sentinel objects with no ``__dict__``;
            # registration/selection must not fail merely because no physical
            # delivery can be attempted through such a sentinel.
            with contextlib.suppress(AttributeError, TypeError):
                ws._z4j_registry_owner_id = handle.registry_owner_id  # type: ignore[attr-defined]
                ws._z4j_session_generation = handle.generation  # type: ignore[attr-defined]
                ws._z4j_agent_id = handle.agent_id  # type: ignore[attr-defined]

                async def validate_registry_generation() -> bool:
                    return await self._session_is_current(handle)

                ws._z4j_validate_registry_generation = (  # type: ignore[attr-defined]
                    validate_registry_generation
                )
            workers[slot] = handle
            self._project_for_agent[agent_id] = project_id
        # The replacement is authoritative before any fallible socket close,
        # and the map mutex is never held across network I/O.
        if displaced is not None:
            with contextlib.suppress(Exception):
                await displaced.websocket.close(code=4002)
        return handle

    async def unregister(
        self,
        agent_id: UUID,
        *,
        ws: WebSocket | None = None,
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
                if current is None or current.websocket is not ws:
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

    async def _session_is_current(self, handle: SessionHandle) -> bool:
        async with self._lock:
            current = (self._connections.get(handle.agent_id) or {}).get(
                handle.worker_id,
            )
            return (
                current is handle
                and current.registry_owner_id == handle.registry_owner_id
                and current.generation == handle.generation
            )

    async def deliver(
        self,
        *,
        command_id: UUID,
        agent_id: UUID,
        required_retry_engine: str | None = None,
    ) -> DeliveryResult:
        async with self._lock:
            workers = self._connections.get(agent_id)
            handle = next(
                (
                    candidate
                    for candidate in (workers or {}).values()
                    if candidate.supports_retry_engine(
                        required_retry_engine,
                    )
                ),
                None,
            )
            if handle is None:
                return DeliveryResult(
                    delivered_locally=False,
                    notified_cluster=False,
                    agent_was_known=bool(workers),
                )
        # The immutable handle is the delivery authority. Never hold the
        # registry lock across database or network I/O: a reconnect may need
        # that lock while the selected generation's send is in flight. The
        # callback receives only this handle's socket and is never retargeted.
        ok = await self._deliver_handle(
            command_id=command_id,
            handle=handle,
        )
        return DeliveryResult(
            delivered_locally=ok,
            notified_cluster=False,
            agent_was_known=True,
        )

    async def deliver_exact(
        self,
        *,
        command_id: UUID,
        session: SessionHandle,
    ) -> bool:
        async with self._lock:
            current = (self._connections.get(session.agent_id) or {}).get(
                session.worker_id,
            )
            if (
                current is not session
                or current.registry_owner_id != session.registry_owner_id
                or current.generation != session.generation
            ):
                return False
            handle = current
        # Retain only the immutable selected handle. The callback performs the
        # just-before-send generation validation attached at registration.
        return await self._deliver_handle(
            command_id=command_id,
            handle=handle,
        )

    async def deliver_frozen(
        self,
        *,
        command_id: UUID,
        agent_id: UUID,
        registry_owner_id: UUID,
        session_generation: str,
    ) -> bool:
        async with self._lock:
            handle = next(
                (
                    candidate
                    for candidate in (self._connections.get(agent_id) or {}).values()
                    if candidate.registry_owner_id == registry_owner_id
                    and str(candidate.generation) == session_generation
                ),
                None,
            )
            if handle is None:
                return False
        return await self._deliver_handle(
            command_id=command_id,
            handle=handle,
        )

    async def _deliver_handle(
        self,
        *,
        command_id: UUID,
        handle: SessionHandle,
    ) -> bool:
        try:
            return await self._deliver_local(
                command_id,
                handle.websocket,
            )
        except Exception:
            # A callback failure must collapse to "not delivered" even when
            # the process console cannot encode the rendered traceback (for
            # example under a legacy Windows code page). Logging is
            # diagnostic and must never become the delivery outcome.
            with contextlib.suppress(Exception):
                logger.exception(
                    "z4j local registry deliver crashed",
                    command_id=str(command_id),
                    agent_id=str(handle.agent_id),
                )
            return False

    async def select_session(
        self,
        *,
        agent_id: UUID,
        required_retry_engine: str | None = None,
    ) -> SessionHandle | None:
        async with self._lock:
            workers = self._connections.get(agent_id)
            if not workers:
                return None
            return next(
                (
                    handle
                    for handle in workers.values()
                    if handle.supports_retry_engine(required_retry_engine)
                ),
                None,
            )

    async def select_project_session(
        self,
        *,
        project_id: UUID,
        required_retry_engine: str,
    ) -> SessionHandle | None:
        """Return one immutable compatible generation in this project."""

        async with self._lock:
            for agent_id in sorted(self._connections, key=str):
                if self._project_for_agent.get(agent_id) != project_id:
                    continue
                for worker_id in sorted(
                    self._connections[agent_id],
                    key=lambda value: "" if value is None else value,
                ):
                    handle = self._connections[agent_id][worker_id]
                    if handle.supports_retry_engine(required_retry_engine):
                        return handle
        return None

    async def kick(self, agent_id: UUID) -> int:
        """Close every WebSocket for ``agent_id`` and drop the entry.

        1.6.5 security advisory F2 (revoked agent must terminate
        active connections). Idempotent: if the agent has no
        registered connections, returns 0.

        Implementation: walks the per-worker slot dict, closes each
        WebSocket with code ``4003`` ("agent revoked"), and drops
        the agent's registry entry. Single-process backend, so no
        cross-worker broadcast is needed.
        """
        async with self._lock:
            workers = self._connections.pop(agent_id, None)
            self._project_for_agent.pop(agent_id, None)
        if not workers:
            return 0
        closed = 0
        for handle in list(workers.values()):
            try:
                await handle.websocket.close(code=4003)
                closed += 1
            except Exception:  # noqa: S110  best-effort close of revoked agent connection
                # Connection may already be torn down; tolerate.
                pass
        logger.info(
            "z4j local registry: kicked revoked agent",
            agent_id=str(agent_id),
            connections_closed=closed,
        )
        return closed

    def fleet_snapshot(self) -> dict[str, dict[str, int]]:
        """Return per-project agent + worker counts for this process.

        Synchronous + lock-free (reads dict snapshots without taking
        ``self._lock``). The result is point-in-time and slightly
        racy under heavy register/unregister churn, which is fine
        for a Prometheus scrape-time sampler. Multi-process
        deployments (PostgresNotifyRegistry) only see this process's
        view; the operator sums across replicas in PromQL.
        """
        # Copy under no lock; dict iteration on CPython is GIL-safe
        # enough for a metrics snapshot where slight skew is OK.
        agents_by_project: dict[str, int] = {}
        workers_by_project: dict[str, int] = {}
        for agent_id, workers in list(self._connections.items()):
            project_id = self._project_for_agent.get(agent_id)
            if project_id is None:
                continue
            key = str(project_id)
            agents_by_project[key] = agents_by_project.get(key, 0) + 1
            workers_by_project[key] = workers_by_project.get(key, 0) + len(workers)
        return {"agents": agents_by_project, "workers": workers_by_project}

    async def start(self) -> None:
        # No background tasks. The lifespan call still goes through
        # so the brain factory can treat the two registries
        # uniformly.
        return None

    async def stop(self) -> None:
        async with self._lock:
            for workers in list(self._connections.values()):
                for handle in list(workers.values()):
                    with contextlib.suppress(Exception):
                        await handle.websocket.close(code=1001)
            self._connections.clear()
            self._project_for_agent.clear()


__all__ = ["LocalDeliverCallback", "LocalRegistry"]
