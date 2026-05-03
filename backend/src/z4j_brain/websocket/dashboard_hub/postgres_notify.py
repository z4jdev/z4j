"""Production :class:`DashboardHub` backed by Postgres LISTEN/NOTIFY.

Same shape as :class:`z4j_brain.websocket.registry.PostgresNotifyRegistry`,
just for the dashboard fan-out instead of agent commands. Each
worker:

1. Holds a local map of subscribers (built on
   :class:`LocalDashboardHub` for the in-process bookkeeping).
2. Owns a dedicated asyncpg connection that LISTENs on
   ``z4j_dashboard``. When ANY worker NOTIFYs, this worker's
   listener fans the event out to its local subscribers.
3. ``publish_*`` methods publish a NOTIFY (no SQLAlchemy session
   involvement - the publish is independent of the caller's
   transaction; the caller is responsible for committing first).
4. Self-NOTIFY heartbeat + watchdog identical to the registry,
   so a wedged listener is rebuilt within
   ``listener_heartbeat_timeout_seconds``.

Why share the existing settings: there are no
``Z4J_DASHBOARD_*`` knobs in V1. The dashboard hub re-uses the
registry's heartbeat / max-age / reconnect settings - they're
chosen for the same Postgres-NOTIFY failure modes.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from typing import TYPE_CHECKING, Any, Callable
from uuid import UUID

import asyncpg
import structlog

from z4j_brain.websocket.dashboard_hub._protocol import DASHBOARD_TOPICS
from z4j_brain.websocket.dashboard_hub.local import LocalDashboardHub

if TYPE_CHECKING:
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings
    from z4j_brain.websocket.dashboard_hub._protocol import (
        DashboardSubscription,
        SendCallable,
    )


logger = structlog.get_logger("z4j.brain.dashboard_hub.pg_notify")


def _log_dashboard_fanout_exception(task: asyncio.Task[object]) -> None:
    """Done-callback for fan-out tasks. Logs unhandled exceptions so
    a silent GC or asyncio loop teardown doesn't swallow them.

    Audit P-10 (added v1.0.14): without strong-ref + done-callback
    the task could be GC'd before its coroutine finished, and any
    exception inside ``_fan_out_remote`` would never be logged.
    Mirrors the pattern at ``registry/postgres_notify.py:60``.
    """
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.warning(
            "dashboard_hub_fanout_failed",
            task_name=task.get_name(),
            error_class=type(exc).__name__,
            error=str(exc)[:500],
        )


_DASHBOARD_CHANNEL: str = "z4j_dashboard"
_HEARTBEAT_CHANNEL: str = "z4j_dashboard_hb"

#: Same backoff schedule as the agent registry - these are
#: Postgres-NOTIFY-shaped failure modes, not WS-shaped ones.
_RECONNECT_BACKOFF: tuple[float, ...] = (0.5, 1.0, 2.0, 5.0, 10.0, 30.0)


#: ``DsnProvider`` mirrors the registry - a callable returning the
#: SQLAlchemy URL that the hub re-formats for raw asyncpg.
DsnProvider = Callable[[], str]


class PostgresNotifyDashboardHub:
    """Cross-worker dashboard fan-out via Postgres LISTEN/NOTIFY."""

    def __init__(
        self,
        *,
        settings: Settings,
        db: DatabaseManager,
        dsn_provider: DsnProvider,
    ) -> None:
        self._settings = settings
        self._db = db
        self._dsn_provider = dsn_provider
        self._worker_id: str = secrets.token_hex(8)

        # Local fan-out delegates to LocalDashboardHub. The pg
        # listener feeds it via _on_notify; publish_* methods both
        # fire NOTIFYs AND deliver locally so a single-worker
        # deployment doesn't pay an extra round-trip.
        self._local = LocalDashboardHub()

        self._listener_task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()
        self._last_heartbeat_round_trip: float = time.monotonic()
        # Strong references to fire-and-forget fan-out tasks. Without
        # this, Python may GC the task before its coroutine runs to
        # completion (asyncio docs note this explicitly). Audit P-10.
        # The set is bounded by NOTIFY arrival rate; tasks remove
        # themselves on completion via the done callback.
        self._pending_fanout_tasks: set[asyncio.Task[None]] = set()

    # ------------------------------------------------------------------
    # Subscribers - delegate straight to the local hub
    # ------------------------------------------------------------------

    async def add_subscriber(
        self,
        *,
        project_id: UUID,
        send: "SendCallable",
        user_id: UUID | None = None,
    ) -> "DashboardSubscription":
        return await self._local.add_subscriber(
            project_id=project_id, send=send, user_id=user_id,
        )

    async def remove_subscriber(self, sub: "DashboardSubscription") -> None:
        await self._local.remove_subscriber(sub)

    # ------------------------------------------------------------------
    # Publishers
    # ------------------------------------------------------------------

    async def publish_task_change(self, project_id: UUID) -> None:
        await self._local.publish_task_change(project_id)
        await self._publish_notify(project_id, "task.changed")

    async def publish_command_change(self, project_id: UUID) -> None:
        await self._local.publish_command_change(project_id)
        await self._publish_notify(project_id, "command.changed")

    async def publish_agent_change(self, project_id: UUID) -> None:
        await self._local.publish_agent_change(project_id)
        await self._publish_notify(project_id, "agent.changed")

    async def _publish_notify(self, project_id: UUID, topic: str) -> None:
        """Fire ``NOTIFY z4j_dashboard, '{p, t, w}'``.

        ``w`` is the publisher worker id so the listener can skip
        its own NOTIFY (we already delivered locally before firing).
        Uses a fresh SQLAlchemy session - the publish is independent
        of any caller transaction. The caller MUST have already
        committed the underlying data change.
        """
        from sqlalchemy import text

        payload = json.dumps(
            {"p": str(project_id), "t": topic, "w": self._worker_id},
            separators=(",", ":"),
        )
        try:
            async with self._db.session() as session:
                await session.execute(
                    text("SELECT pg_notify(:channel, :payload)"),
                    {"channel": _DASHBOARD_CHANNEL, "payload": payload},
                )
                await session.commit()
        except Exception:  # noqa: BLE001
            # Publish failures must NEVER break the request that
            # triggered them. The local subscribers were already
            # served above; we just lose cross-worker fan-out for
            # this one event.
            logger.exception(
                "z4j dashboard_hub: NOTIFY publish failed",
                project_id=str(project_id),
                topic=topic,
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        await self._local.start()
        if self._listener_task is not None:
            return
        self._stop_event.clear()
        self._listener_task = asyncio.create_task(
            self._run_listener_loop(),
            name="z4j-dashboard-hub-listener",
        )

    async def stop(self) -> None:
        self._stop_event.set()
        if self._listener_task is not None:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._listener_task = None
        await self._local.stop()

    # ------------------------------------------------------------------
    # Listener task - same shape as the registry
    # ------------------------------------------------------------------

    async def _run_listener_loop(self) -> None:
        backoff_index = 0
        while not self._stop_event.is_set():
            try:
                await self._listen_session()
                backoff_index = 0
            except asyncio.CancelledError:
                return
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "z4j dashboard_hub listener: error, will reconnect",
                    error_class=type(exc).__name__,
                    backoff_index=backoff_index,
                    worker_id=self._worker_id,
                )
                backoff = _RECONNECT_BACKOFF[
                    min(backoff_index, len(_RECONNECT_BACKOFF) - 1)
                ]
                backoff_index += 1
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=backoff,
                    )
                    return
                except TimeoutError:
                    pass

    async def _listen_session(self) -> None:
        dsn = self._asyncpg_dsn()
        conn: asyncpg.Connection | None = None
        try:
            conn = await asyncpg.connect(
                dsn=dsn,
                timeout=10.0,
                server_settings={
                    "tcp_keepalives_idle": "30",
                    "tcp_keepalives_interval": "10",
                    "tcp_keepalives_count": "3",
                    "application_name": (
                        f"z4j-brain-dashboard-hub-{self._worker_id}"
                    ),
                },
            )
            await conn.add_listener(_DASHBOARD_CHANNEL, self._on_notify)
            await conn.add_listener(_HEARTBEAT_CHANNEL, self._on_heartbeat)
            self._last_heartbeat_round_trip = time.monotonic()
            logger.info(
                "z4j dashboard_hub listener: connected",
                worker_id=self._worker_id,
            )
            await self._heartbeat_loop_until_done(conn)
        finally:
            if conn is not None:
                try:
                    await conn.close(timeout=5.0)
                except Exception:  # noqa: BLE001
                    pass

    async def _heartbeat_loop_until_done(
        self,
        conn: asyncpg.Connection,
    ) -> None:
        interval = self._settings.registry_listener_heartbeat_seconds
        timeout = self._settings.registry_listener_heartbeat_timeout_seconds
        max_age = self._settings.registry_listener_max_age_seconds
        connected_at = time.monotonic()

        while not self._stop_event.is_set():
            if time.monotonic() - connected_at > max_age:
                logger.info(
                    "z4j dashboard_hub listener: max age reached, recycling",
                    worker_id=self._worker_id,
                )
                return

            since_round_trip = (
                time.monotonic() - self._last_heartbeat_round_trip
            )
            if since_round_trip > timeout:
                raise RuntimeError(
                    f"dashboard heartbeat round-trip exceeded {timeout}s "
                    f"(last={since_round_trip:.1f}s)",
                )

            await conn.execute(
                "SELECT pg_notify($1, $2)",
                _HEARTBEAT_CHANNEL,
                self._worker_id,
            )

            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=interval,
                )
                return
            except TimeoutError:
                continue

    # ------------------------------------------------------------------
    # Listener callbacks
    # ------------------------------------------------------------------

    def _on_notify(
        self,
        connection: asyncpg.Connection,  # noqa: ARG002
        pid: int,  # noqa: ARG002
        channel: str,  # noqa: ARG002
        payload: str,
    ) -> None:
        """Handle a ``z4j_dashboard`` NOTIFY.

        asyncpg invokes listener callbacks synchronously from
        inside the read loop. We MUST NOT block - schedule the
        actual fan-out as an asyncio task.
        """
        try:
            data = json.loads(payload)
            project_id = UUID(data["p"])
            topic = str(data["t"])
            origin = str(data.get("w", ""))
        except (ValueError, KeyError, TypeError):
            logger.warning(
                "z4j dashboard_hub: malformed notify payload",
                payload_len=len(payload),
            )
            return

        if origin == self._worker_id:
            # We already delivered to local subscribers in the
            # publish_* method. Skip to avoid duplicate frames.
            return
        if topic not in DASHBOARD_TOPICS:
            return  # forward-compat: unknown topic

        # Strong-ref the fire-and-forget task to defeat GC + log any
        # unhandled exception (audit P-10). Mirrors the registry
        # pg-notify pattern at registry/postgres_notify.py:457.
        task = asyncio.create_task(
            self._fan_out_remote(project_id, topic),
            name="z4j-dashboard-hub-fanout",
        )
        self._pending_fanout_tasks.add(task)
        task.add_done_callback(self._pending_fanout_tasks.discard)
        task.add_done_callback(_log_dashboard_fanout_exception)

    def _on_heartbeat(
        self,
        connection: asyncpg.Connection,  # noqa: ARG002
        pid: int,  # noqa: ARG002
        channel: str,  # noqa: ARG002
        payload: str,
    ) -> None:
        if payload == self._worker_id:
            self._last_heartbeat_round_trip = time.monotonic()

    async def _fan_out_remote(self, project_id: UUID, topic: str) -> None:
        """Fan out a NOTIFY received from a peer worker."""
        if topic == "task.changed":
            await self._local.publish_task_change(project_id)
        elif topic == "command.changed":
            await self._local.publish_command_change(project_id)
        elif topic == "agent.changed":
            await self._local.publish_agent_change(project_id)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _asyncpg_dsn(self) -> str:
        url = self._dsn_provider()
        return url.replace("postgresql+asyncpg://", "postgresql://", 1)

    # ------------------------------------------------------------------
    # Test helpers
    # ------------------------------------------------------------------

    def subscriber_count(self, project_id: UUID | None = None) -> int:
        return self._local.subscriber_count(project_id)


__all__ = ["DsnProvider", "PostgresNotifyDashboardHub"]
