"""In-process :class:`DashboardHub` - single-worker + tests.

No Postgres, no LISTEN/NOTIFY. Maintains a per-project set of
subscribers and fans out publishes synchronously to each one's
``send`` callback. Slow subscribers do not block the publisher:
each subscriber gets a bounded outbound queue and a writer task
that drains it. If the queue is full when a publish arrives the
subscriber is dropped - the dashboard will reconnect and refetch.

This implementation is the contract test for the protocol - every
test that exercises the dashboard fan-out should run against the
local hub first, then optionally repeat against the
:class:`PostgresNotifyDashboardHub` for cross-worker coverage.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import structlog

if TYPE_CHECKING:
    from z4j_brain.websocket.dashboard_hub._protocol import (
        DashboardSubscription,
        SendCallable,
    )


logger = structlog.get_logger("z4j.brain.dashboard_hub.local")


#: Bounded outbound queue size per subscriber. The dashboard only
#: cares about *something changed* signals; bursting through 64
#: events is plenty for any realistic operator workflow. A
#: subscriber that can't drain 64 events fast enough is wedged and
#: should be dropped.
_QUEUE_MAX = 64

#: Cap on simultaneous dashboard subscriptions per user. A typical
#: operator opens 1-3 tabs against 1-3 projects; even an admin
#: who can see every project rarely needs more than a dozen open
#: at once. The cap defends against a hostile authenticated user
#: opening one WS per project (admins see ALL projects in a
#: brain instance) and exhausting the event loop with one
#: writer task per WS (R3 finding H5).
_MAX_SUBSCRIBERS_PER_USER = 50


@dataclass
class _Subscriber:
    """One connected dashboard.

    Holds the project filter, the send callback, an asyncio queue
    for outbound frames, and the writer task that drains it. The
    ``id`` field is opaque - the gateway only ever passes the whole
    object back to ``remove_subscriber``.
    """

    id: UUID = field(default_factory=uuid4)
    project_id: UUID = field(default=None)  # type: ignore[assignment]
    user_id: UUID | None = None
    send: "SendCallable" = field(default=None)  # type: ignore[assignment]
    queue: asyncio.Queue[dict] = field(default=None)  # type: ignore[assignment]
    writer: asyncio.Task[None] | None = None
    closed: bool = False


class LocalDashboardHub:
    """Pure in-process dashboard hub. No cross-worker fan-out."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._subscribers: dict[UUID, _Subscriber] = {}
        self._by_project: dict[UUID, set[UUID]] = {}
        self._by_user: dict[UUID, set[UUID]] = {}
        self._stopped = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """No-op - nothing to start in the local impl."""
        self._stopped = False

    async def stop(self) -> None:
        """Drop every subscriber and cancel their writer tasks."""
        async with self._lock:
            self._stopped = True
            subs = list(self._subscribers.values())
            self._subscribers.clear()
            self._by_project.clear()
        for sub in subs:
            await self._tear_down(sub)

    # ------------------------------------------------------------------
    # Subscribers
    # ------------------------------------------------------------------

    async def add_subscriber(
        self,
        *,
        project_id: UUID,
        send: "SendCallable",
        user_id: UUID | None = None,
    ) -> "DashboardSubscription":
        sub = _Subscriber(
            project_id=project_id,
            user_id=user_id,
            send=send,
            queue=asyncio.Queue(maxsize=_QUEUE_MAX),
        )
        sub.writer = asyncio.create_task(
            self._writer_loop(sub),
            name=f"z4j-dashboard-writer-{sub.id.hex[:8]}",
        )
        async with self._lock:
            if self._stopped:
                # Hub already stopped - refuse the subscription so
                # the gateway closes the WS cleanly.
                sub.writer.cancel()
                raise RuntimeError("dashboard hub is stopped")
            # Per-user cap: refuse new subscriptions once the user
            # has _MAX_SUBSCRIBERS_PER_USER live (R3 finding H5).
            if user_id is not None:
                user_subs = self._by_user.get(user_id, set())
                if len(user_subs) >= _MAX_SUBSCRIBERS_PER_USER:
                    sub.writer.cancel()
                    raise RuntimeError(
                        f"per-user dashboard subscription cap reached "
                        f"({_MAX_SUBSCRIBERS_PER_USER}); close existing tabs"
                    )
            self._subscribers[sub.id] = sub
            self._by_project.setdefault(project_id, set()).add(sub.id)
            if user_id is not None:
                self._by_user.setdefault(user_id, set()).add(sub.id)
        logger.info(
            "z4j dashboard_hub: subscriber added",
            sub_id=str(sub.id),
            project_id=str(project_id),
            user_id=str(user_id) if user_id else None,
        )
        return sub

    async def remove_subscriber(self, sub: "DashboardSubscription") -> None:
        if not isinstance(sub, _Subscriber):
            return  # not ours - ignore
        async with self._lock:
            self._subscribers.pop(sub.id, None)
            project_set = self._by_project.get(sub.project_id)
            if project_set is not None:
                project_set.discard(sub.id)
                if not project_set:
                    self._by_project.pop(sub.project_id, None)
            if sub.user_id is not None:
                user_set = self._by_user.get(sub.user_id)
                if user_set is not None:
                    user_set.discard(sub.id)
                    if not user_set:
                        self._by_user.pop(sub.user_id, None)
        await self._tear_down(sub)
        logger.info(
            "z4j dashboard_hub: subscriber removed",
            sub_id=str(sub.id),
        )

    # ------------------------------------------------------------------
    # Publishers
    # ------------------------------------------------------------------

    async def publish_task_change(self, project_id: UUID) -> None:
        await self._fan_out(project_id, "task.changed")

    async def publish_command_change(self, project_id: UUID) -> None:
        await self._fan_out(project_id, "command.changed")

    async def publish_agent_change(self, project_id: UUID) -> None:
        await self._fan_out(project_id, "agent.changed")

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _fan_out(self, project_id: UUID, topic: str) -> None:
        """Enqueue ``{type: event, topic}`` on every matching subscriber."""
        frame = {"type": "event", "topic": topic}
        async with self._lock:
            ids = list(self._by_project.get(project_id, ()))
            subs = [self._subscribers[i] for i in ids if i in self._subscribers]
        # Drop subscribers whose queue is full - they're stuck.
        # Iterate outside the lock so a slow drop doesn't block
        # other publishes.
        to_drop: list[_Subscriber] = []
        for sub in subs:
            try:
                sub.queue.put_nowait(frame)
            except asyncio.QueueFull:
                logger.warning(
                    "z4j dashboard_hub: subscriber queue full, dropping",
                    sub_id=str(sub.id),
                    project_id=str(project_id),
                    topic=topic,
                )
                to_drop.append(sub)
        for sub in to_drop:
            await self.remove_subscriber(sub)

    async def _writer_loop(self, sub: _Subscriber) -> None:
        """Drain ``sub.queue`` → ``sub.send``. Dies when send raises."""
        try:
            while True:
                frame = await sub.queue.get()
                try:
                    await sub.send(frame)
                except Exception:  # noqa: BLE001
                    logger.info(
                        "z4j dashboard_hub: send failed, dropping subscriber",
                        sub_id=str(sub.id),
                    )
                    return
        except asyncio.CancelledError:
            return

    async def _tear_down(self, sub: _Subscriber) -> None:
        sub.closed = True
        if sub.writer is not None and not sub.writer.done():
            sub.writer.cancel()
            try:
                await sub.writer
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    # ------------------------------------------------------------------
    # Test helpers
    # ------------------------------------------------------------------

    def subscriber_count(self, project_id: UUID | None = None) -> int:
        """Diagnostic - used by tests to assert state."""
        if project_id is None:
            return len(self._subscribers)
        return len(self._by_project.get(project_id, ()))


__all__ = ["LocalDashboardHub"]
