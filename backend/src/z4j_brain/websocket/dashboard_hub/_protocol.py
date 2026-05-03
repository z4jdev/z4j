"""DashboardHub Protocol shared by every implementation.

Fan-out for the ``/ws/dashboard`` endpoint. The brain pushes
"something changed" notifications to subscribed dashboards so the
React app can invalidate stale TanStack Query caches and refetch.

Two implementations:

- :class:`LocalDashboardHub` - pure in-process. Used in tests
  and single-worker dev. No Postgres dependency.
- :class:`PostgresNotifyDashboardHub` - production. LISTEN/NOTIFY
  on ``z4j_dashboard`` so events emitted on worker A reach
  dashboards connected to worker B.

Wire format on the ``/ws/dashboard`` socket is intentionally tiny
- see ``docs/API.md §6``. The brain only tells the dashboard
*what changed* (topic + project_id), never *how* it changed; the
dashboard refetches the relevant REST endpoint to get the truth.
This keeps the protocol future-proof: schema additions on the
brain require zero changes to the wire format.

Topics emitted today (V1):

- ``task.changed``     - any task row mutated (created/state/result)
- ``command.changed``  - command row mutated (issued/dispatched/result)
- ``agent.changed``    - agent row mutated (online/offline/swept)

Worker / queue / schedule / audit topics land in a later phase.
"""

from __future__ import annotations

from typing import Literal, Protocol
from uuid import UUID

#: Set of valid topic strings the hub will accept. Anything outside
#: the union is a programming bug - the dashboard ignores unknown
#: topics so adding to this list is forward-compatible.
DashboardTopic = Literal[
    "task.changed",
    "command.changed",
    "agent.changed",
]

#: Frozen tuple form for runtime membership checks (``in`` against
#: a Literal-only type at runtime requires str comparison).
DASHBOARD_TOPICS: frozenset[str] = frozenset(
    {"task.changed", "command.changed", "agent.changed"},
)


class DashboardSubscription(Protocol):
    """Opaque handle returned by ``add_subscriber``.

    Implementations are free to back this with whatever data they
    need (queue, set membership, dataclass). The gateway only ever
    passes it back to ``remove_subscriber``.
    """


class DashboardHub(Protocol):
    """Cross-worker fan-out for dashboard change notifications.

    Lifecycle methods ``start`` / ``stop`` are called from the
    FastAPI lifespan. ``add_subscriber`` / ``remove_subscriber``
    are called from the ``/ws/dashboard`` endpoint per-connection.
    ``publish_*`` methods are called from the routes / frame
    router *after* the database commit succeeds - never inside
    a transaction (NOTIFY only fires on commit, and the dashboard
    must not see a topic referencing data that's still in flight).
    """

    async def start(self) -> None:
        """Spawn background listener tasks (if any)."""

    async def stop(self) -> None:
        """Cancel background tasks and close every local subscriber."""

    async def add_subscriber(
        self,
        *,
        project_id: UUID,
        send: "SendCallable",
        user_id: UUID | None = None,
    ) -> DashboardSubscription:
        """Register a new dashboard connection.

        Args:
            project_id: The project this subscriber wants change
                notifications for. One project per connection in
                V1 - the client must reconnect to switch projects.
            send: Async callable the hub uses to push frames at
                the connection. Same shape as
                ``websocket.send_json``. The hub never raises out
                of ``send``; if the callable raises the
                connection is treated as dead and removed.
        """

    async def remove_subscriber(self, sub: DashboardSubscription) -> None:
        """Drop a connection from the hub.

        Idempotent - calling twice is a no-op. Called from the
        gateway's ``finally`` block on disconnect.
        """

    async def publish_task_change(self, project_id: UUID) -> None:
        """Notify subscribers that *something* about a task changed.

        Fired once per ``ingest_batch`` even if the batch contained
        many task events - the dashboard refetches the list and
        gets all of them in one round trip.
        """

    async def publish_command_change(self, project_id: UUID) -> None:
        """Notify subscribers that a command row mutated."""

    async def publish_agent_change(self, project_id: UUID) -> None:
        """Notify subscribers that an agent row mutated."""


# ---------------------------------------------------------------------------
# SendCallable
# ---------------------------------------------------------------------------

from typing import Any, Awaitable, Callable

#: The hub-internal "push a JSON frame at this connection" callback.
#:
#: We type it loosely (``dict[str, Any]``) rather than tying it
#: directly to ``WebSocket.send_json`` so the hub can be unit-tested
#: with a fake send that just appends to a list. The gateway wraps
#: ``ws.send_json`` in a small adapter on registration.
SendCallable = Callable[[dict[str, Any]], Awaitable[None]]


__all__ = [
    "DASHBOARD_TOPICS",
    "DashboardHub",
    "DashboardSubscription",
    "DashboardTopic",
    "SendCallable",
]
