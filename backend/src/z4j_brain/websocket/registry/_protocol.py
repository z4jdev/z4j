"""Registry Protocol shared by every implementation.

The protocol intentionally exposes a small surface so the two
implementations are easy to compare side-by-side.

Contract:

- ``register(agent_id, ws, worker_id=None)`` - the gateway calls
  this once per successful handshake.

  * v1.1.x semantics (worker_id=None): one WebSocket per agent;
    a second connection from the same agent kicks the first
    with close code 4002 ("displaced by newer connection").

  * v1.2.0+ semantics (worker_id=<str>): one WebSocket per
    (agent_id, worker_id) pair; the brain accepts multiple
    concurrent connections from the same agent_id when each
    has a distinct worker_id. Only same-worker reconnects (a
    worker process restarting with the SAME generated
    worker_id) trigger the 4002 displacement. Worker-first
    deployments (gunicorn with N workers, Celery with K
    workers, etc.) get one connection slot per worker without
    fighting.

  Both modes coexist on the same brain - the registry inspects
  worker_id at register time. A 1.1.x agent and a 1.2.0 agent
  on different worker_ids of the same agent_id can both be
  online simultaneously; the legacy connection is just one more
  slot in the (agent_id -> {worker_id: ws}) map.

- ``unregister(agent_id, ws=ws, worker_id=...)`` - called from
  the disconnect handler. With ``worker_id=None`` (legacy) it
  drops only the legacy slot; with ``worker_id=<str>`` it drops
  only that specific worker's slot.

- ``is_online(agent_id)`` - True if ANY worker (legacy or
  worker-id-aware) is connected for this agent.

- ``deliver(command_id, agent_id)`` - the load-bearing call. The
  caller has already INSERTed a ``commands`` row with status
  ``pending``; this asks the cluster to push it. With multiple
  workers per agent the registry picks one (first-available
  semantics; future: per-role routing). ACTUAL delivery
  confirmation arrives as a ``command_result`` frame; the
  timeout sweeper handles the case where it never does.

Implementations are free to be backend-specific below the line -
the Protocol exists so :mod:`z4j_brain.domain.command_dispatcher`
and the route layer never need to know.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol
from uuid import UUID

if TYPE_CHECKING:
    from fastapi import WebSocket


class WorkerCapExceeded(Exception):
    """Registering a new worker would exceed the per-agent cap.

    Raised by ``register`` when:
    - ``cap > 0`` (cap is enabled)
    - the (agent_id, worker_id) slot does not already exist
    - the agent already has ``cap`` distinct worker slots

    The gateway catches this and closes the new WebSocket with
    code 4429 ("too many workers under this agent"). Defense in
    depth alongside the per-IP rate limit on /ws/agent: bounds
    worst-case fd / memory per agent token even if a misbehaving
    or malicious agent invents many distinct worker_ids.

    Reconnects (same worker_id replacing its own existing slot)
    do NOT trigger this - cap counts new slot creations only.
    """

    def __init__(self, agent_id: UUID, current: int, cap: int) -> None:
        super().__init__(
            f"agent {agent_id} already has {current} worker connections; "
            f"cap is {cap}",
        )
        self.agent_id = agent_id
        self.current = current
        self.cap = cap


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    """Outcome of a single ``deliver`` call.

    Attributes:
        delivered_locally: True if the agent was connected to THIS
            worker and the frame was pushed synchronously. The
            ``commands`` row has been UPDATEd to ``dispatched``.
        notified_cluster: True if a NOTIFY was published. The local
            map did not hold the agent, so some other worker may or
            may not pick it up. ``CommandTimeoutWorker`` is the
            authority on what actually happened.
        agent_was_known: True if the local map OR cluster reported
            the agent online. Lets the caller distinguish "we
            asked the cluster" from "no one in the cluster has
            this agent connected".
    """

    delivered_locally: bool
    notified_cluster: bool
    agent_was_known: bool


class BrainRegistry(Protocol):
    """Where commands go when they need to find their agent."""

    async def register(
        self,
        *,
        project_id: UUID,
        agent_id: UUID,
        ws: "WebSocket",
        worker_id: str | None = None,
        cap: int = 0,
    ) -> None:
        """Register ``ws`` under (agent_id, worker_id).

        ``cap``: per-agent concurrent-worker cap (1.2.1+). When
        positive and adding this connection would push past it,
        raises :class:`WorkerCapExceeded`. ``cap=0`` (or omitted)
        keeps the unbounded 1.2.0 behavior.
        """
        ...

    async def unregister(
        self,
        agent_id: UUID,
        *,
        ws: "WebSocket | None" = None,
        worker_id: str | None = None,
    ) -> bool:
        """Drop one slot for ``agent_id``. Returns ``True`` if the
        agent has no more registered workers after this call.

        Round-7 audit fix R7-HIGH (race) (Apr 2026): callers that
        track the WebSocket they're tearing down should pass it as
        ``ws``; the registry only evicts the slot if its current
        entry IS that exact WebSocket. Prevents the old gateway's
        ``finally`` block from clobbering a freshly-replaced
        connection after a "second connection wins" force-close.

        v1.2.0+: when the connection was registered with a
        ``worker_id``, callers MUST pass the same ``worker_id``
        here so the registry evicts only that worker's slot
        (other workers under the same agent_id stay registered).

        v1.2.1+ (audit F3 fix): the bool return value is determined
        atomically under the registry lock. Callers that need to
        ``mark_offline`` the agent in the brain DB use this signal
        instead of a separate ``is_online`` check, eliminating the
        race window where another worker could connect between the
        check and the DB write.
        """
        ...

    def is_online(self, agent_id: UUID) -> bool: ...

    async def deliver(
        self,
        *,
        command_id: UUID,
        agent_id: UUID,
    ) -> DeliveryResult: ...

    async def start(self) -> None:
        """Start any background tasks the implementation needs.

        Called once from the brain's lifespan startup.
        ``LocalRegistry`` is a no-op; ``PostgresNotifyRegistry``
        spawns the listener task and watchdog here.
        """

    async def stop(self) -> None:
        """Cleanly stop background tasks. Called from lifespan shutdown."""


__all__ = ["BrainRegistry", "DeliveryResult", "WorkerCapExceeded"]
