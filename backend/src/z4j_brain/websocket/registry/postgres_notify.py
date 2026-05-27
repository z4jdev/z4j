"""Production :class:`BrainRegistry` backed by Postgres LISTEN/NOTIFY.

Multi-worker safe. Each worker:

1. Holds a local map of ``{agent_id → WebSocket}`` for the agents
   currently connected to THIS worker.
2. Owns a dedicated asyncpg connection that LISTENs on two channels:
   ``z4j_commands`` (cross-worker delivery) and ``z4j_heartbeat``
   (watchdog round-trip).
3. Runs a watchdog task that NOTIFYs its own worker id every
   ``heartbeat_seconds`` and rebuilds the listener if its own
   message has not round-tripped within
   ``heartbeat_timeout_seconds``. This is the mandatory mitigation
   for the Postgres queue-lock failure mode where one stuck
   listener stalls every NOTIFY writer cluster-wide.
4. Runs a periodic reconcile sweeper that polls the ``commands``
   table for ``status='pending'`` rows whose ``agent_id`` is in
   the local map. Closes the gap when a NOTIFY is lost in transit
   or fired during a reconnect.
5. Recycles the listener connection every
   ``listener_max_age_seconds`` regardless. Belt-and-braces
   against silent NAT or proxy wedges.

The ``deliver`` fast path is "agent is in my local map → push
synchronously, skip NOTIFY entirely". The slow path is "publish a
NOTIFY with just ``{command_id, agent_id}`` and let whichever
worker has the agent pick it up". The notify payload is ~80 bytes
- well under the 8000-byte cap.

The whole module is 1 file by design - production debuggers should
be able to read it top to bottom in 10 minutes.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Awaitable, Callable
from uuid import UUID, uuid4

import asyncpg
import structlog

from z4j_brain.websocket.registry._protocol import (
    DeliveryResult,
    WorkerCapExceeded,
)

if TYPE_CHECKING:
    from fastapi import WebSocket
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings


logger = structlog.get_logger("z4j.brain.registry.pg_notify")


#: 1.2.1+: legacy 1.1.x clients use ``None`` as their dict key.
#: Pre-1.2.1 used a string sentinel that an attacker could collide
#: with via ``worker_id="__legacy__"`` (audit F1, LOW). ``None``
#: cannot collide with any string-typed worker_id from the wire.


def _log_task_exception(task: asyncio.Task[object]) -> None:
    """Done callback for fire-and-forget tasks. Logs unhandled exceptions."""
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.exception(
            "z4j registry: background task failed",
            task_name=task.get_name(),
            error_class=type(exc).__name__,
            exc_info=exc,
        )

_COMMANDS_CHANNEL: str = "z4j_commands"
_HEARTBEAT_CHANNEL: str = "z4j_heartbeat"
#: 1.6.5 security advisory F2: cross-replica agent-revocation
#: broadcast. The agent-revoke route publishes the agent_id; every
#: replica's listener calls its local kick to close any open WS
#: for that agent. Without this channel, revocation only deleted
#: the DB row -- already-connected agents on other replicas kept
#: forging signed event frames until natural disconnect.
_AGENT_REVOKED_CHANNEL: str = "z4j_agent_revoked"

#: Backoff schedule for the reconnect loop, in seconds. Caps at
#: 30s. The list is short because we WANT the listener back fast -
#: an ailing listener silently drops dispatch.
_RECONNECT_BACKOFF: tuple[float, ...] = (0.5, 1.0, 2.0, 5.0, 10.0, 30.0)


#: Type of the per-command "deliver this command to the WS" callback.
#: Same shape as the LocalRegistry's. The gateway constructs it once
#: and passes it to the registry - the registry calls it from the
#: worker that holds the WebSocket.
DeliverCallback = Callable[[UUID, "WebSocket"], Awaitable[bool]]

#: Type of the "fetch the canonical asyncpg connection URL" callback.
#: Production passes a closure over the configured database URL;
#: the registry needs the raw asyncpg URL because it must NOT use
#: the SQLAlchemy pool - LISTEN requires a dedicated session.
DsnProvider = Callable[[], str]


class PostgresNotifyRegistry:
    """The production registry implementation."""

    def __init__(
        self,
        *,
        settings: Settings,
        db: DatabaseManager,
        dsn_provider: DsnProvider,
        deliver_local: DeliverCallback,
    ) -> None:
        self._settings = settings
        self._db = db
        self._dsn_provider = dsn_provider
        self._deliver_local = deliver_local

        # Per-worker identifier so we can distinguish our own
        # heartbeat round-trips from other workers'.
        self._worker_id: str = secrets.token_hex(8)

        # Local connections map. Updated under ``_lock``.
        # 1.2.0+: stores multiple WS per agent_id, keyed by
        # worker_id. Legacy 1.1.x agents (no worker_id) live under
        # the ``__legacy__`` sentinel slot - one such slot per
        # agent_id, kicked on duplicate (preserving 1.1.x semantics
        # for that single connection). Worker-aware agents land in
        # their own slot keyed by their generated worker_id; the
        # brain accepts as many concurrent connections as the
        # operator's gunicorn / Celery / etc. workers spawn.
        self._lock = asyncio.Lock()
        self._connections: dict[UUID, dict[str | None, "WebSocket"]] = {}
        self._project_for_agent: dict[UUID, UUID] = {}

        # Watchdog state.
        self._listener_task: asyncio.Task[None] | None = None
        self._reconcile_task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()
        self._listener_alive = asyncio.Event()
        self._last_heartbeat_round_trip: float = time.monotonic()

    # ------------------------------------------------------------------
    # BrainRegistry - register / unregister / is_online
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
            # Cap check (1.2.1+): NEW slot creations only.
            if cap > 0 and slot not in workers and len(workers) >= cap:
                raise WorkerCapExceeded(
                    agent_id=agent_id, current=len(workers), cap=cap,
                )
            existing = workers.get(slot)
            if existing is not None and existing is not ws:
                # Same (agent_id, worker_id) reconnecting (a worker
                # process restarting, or a legacy-mode duplicate).
                # Kick the old; accept the new.
                try:
                    await existing.close(code=4002)
                except Exception:  # noqa: BLE001
                    pass
            workers[slot] = ws
            self._project_for_agent[agent_id] = project_id
        logger.info(
            "z4j registry: agent registered",
            agent_id=str(agent_id),
            project_id=str(project_id),
            worker_id=self._worker_id,
            agent_worker_id=worker_id,
        )

    async def unregister(
        self,
        agent_id: UUID,
        *,
        ws: "WebSocket | None" = None,
        worker_id: str | None = None,
    ) -> bool:
        """Drop one slot for ``agent_id``. Returns ``True`` if the
        agent has no more workers registered after this call.

        v1.2.1 (audit F3 fix): atomic last-worker signal under
        the registry lock so the gateway can ``mark_offline``
        without a race against a concurrent ``register``.
        """
        slot: str | None = worker_id  # None = legacy 1.1.x slot
        last = False
        async with self._lock:
            workers = self._connections.get(agent_id)
            if workers is None:
                last = True
            else:
                if ws is not None:
                    current = workers.get(slot)
                    if current is not ws:
                        last = False
                    else:
                        workers.pop(slot, None)
                        if not workers:
                            self._connections.pop(agent_id, None)
                            self._project_for_agent.pop(agent_id, None)
                            last = True
                        else:
                            last = False
                else:
                    workers.pop(slot, None)
                    if not workers:
                        self._connections.pop(agent_id, None)
                        self._project_for_agent.pop(agent_id, None)
                        last = True
        logger.info(
            "z4j registry: agent unregistered",
            agent_id=str(agent_id),
            worker_id=self._worker_id,
            agent_worker_id=worker_id,
            last_worker=last,
        )
        return last

    def is_online(self, agent_id: UUID) -> bool:
        # Local-only check. The dashboard renders agent state from
        # ``agents.state`` which the AgentHealthWorker maintains;
        # this method is only used for fast preflight checks before
        # issuing a command.
        workers = self._connections.get(agent_id)
        return bool(workers)

    async def kick(self, agent_id: UUID) -> int:
        """Close every WS for ``agent_id`` cluster-wide.

        1.6.5 security advisory F2. Three steps:

        1. Close LOCAL connections (this replica's map).
        2. Publish ``NOTIFY z4j_agent_revoked, '<agent_id>'``.
        3. Every replica's listener picks up the NOTIFY and runs
           its own local close.

        Returns the count of LOCAL connections closed. Remote
        replicas' counts are not surfaced here; the operator's
        audit-log row records the revoke intent and that's the
        source of truth for "how many connections existed".

        Idempotent: if no local connections, still publishes the
        NOTIFY (other replicas might be holding connections).
        """
        # Step 1: local kick.
        local_closed = await self._kick_local(agent_id)
        # Step 2: broadcast.
        await self._publish_revoke_notify(agent_id)
        logger.info(
            "z4j registry: agent revoked, kick broadcast issued",
            agent_id=str(agent_id),
            local_connections_closed=local_closed,
            worker_id=self._worker_id,
        )
        return local_closed

    async def _kick_local(self, agent_id: UUID) -> int:
        """Close every WS for ``agent_id`` in THIS process's map.

        Used by ``kick`` (operator-initiated) and by the
        ``_on_agent_revoked`` listener callback (cross-replica
        broadcast received from another worker).
        """
        async with self._lock:
            workers = self._connections.pop(agent_id, None)
            self._project_for_agent.pop(agent_id, None)
        if not workers:
            return 0
        closed = 0
        for ws in list(workers.values()):
            try:
                await ws.close(code=4003)
                closed += 1
            except Exception:  # noqa: BLE001
                pass
        return closed

    async def _publish_revoke_notify(self, agent_id: UUID) -> None:
        """Fire ``NOTIFY z4j_agent_revoked, '<agent_id>'``.

        Uses the SQLAlchemy session so the NOTIFY participates in
        the calling request's transaction (the agent-revoke handler
        commits the DELETE + the NOTIFY atomically -- if the txn
        rolls back, the cluster doesn't hear a phantom revoke).
        """
        from sqlalchemy import text

        async with self._db.session() as session:
            await session.execute(
                text("SELECT pg_notify(:channel, :payload)"),
                {"channel": _AGENT_REVOKED_CHANNEL, "payload": str(agent_id)},
            )
            await session.commit()

    # ------------------------------------------------------------------
    # BrainRegistry - deliver
    # ------------------------------------------------------------------

    async def deliver(
        self,
        *,
        command_id: UUID,
        agent_id: UUID,
    ) -> DeliveryResult:
        # Fast path: I have the agent locally → push synchronously
        # and skip NOTIFY entirely. This is the common case in
        # single-worker deployments AND the common case in
        # multi-worker deployments where most agents tend to land
        # on a few warm workers.
        # 1.2.0: when an agent has multiple workers in the local
        # map, deliver to first-available. Future v1.3 work:
        # per-role routing (schedule.fire -> role=task workers,
        # config-update broadcast -> all role=web workers, etc.).
        workers = self._connections.get(agent_id)
        ws = next(iter(workers.values()), None) if workers else None
        if ws is not None:
            try:
                ok = await self._deliver_local(command_id, ws)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "z4j registry: local deliver crashed",
                    command_id=str(command_id),
                    agent_id=str(agent_id),
                )
                ok = False
            return DeliveryResult(
                delivered_locally=ok,
                notified_cluster=False,
                agent_was_known=True,
            )

        # Slow path: publish a NOTIFY for the cluster. We do NOT
        # know which worker holds the agent; some other worker may
        # pick it up, or none may, in which case the
        # CommandTimeoutWorker eventually flips the row.
        await self._publish_command_notify(command_id, agent_id)
        return DeliveryResult(
            delivered_locally=False,
            notified_cluster=True,
            agent_was_known=False,
        )

    async def _publish_command_notify(
        self,
        command_id: UUID,
        agent_id: UUID,
    ) -> None:
        """Fire ``NOTIFY z4j_commands, '{c, a}'``.

        Uses the SQLAlchemy session because the payload is small
        and the SQLAlchemy session participates in the request's
        transaction - we want the NOTIFY and any other writes in
        the same scope to commit atomically.
        """
        from sqlalchemy import text

        payload = json.dumps(
            {"c": str(command_id), "a": str(agent_id)},
            separators=(",", ":"),
        )
        async with self._db.session() as session:
            await session.execute(
                text("SELECT pg_notify(:channel, :payload)"),
                {"channel": _COMMANDS_CHANNEL, "payload": payload},
            )
            await session.commit()

    # ------------------------------------------------------------------
    # BrainRegistry - start / stop
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Spawn the listener task and the reconcile sweeper."""
        if self._listener_task is not None:
            return
        self._stop_event.clear()
        self._listener_task = asyncio.create_task(
            self._run_listener_loop(),
            name="z4j-registry-listener",
        )
        self._reconcile_task = asyncio.create_task(
            self._run_reconcile_loop(),
            name="z4j-registry-reconcile",
        )

    def fleet_snapshot(self) -> dict[str, dict[str, int]]:
        """Per-project agent + worker counts for THIS brain process.

        Multi-replica deployments (the typical PostgresNotifyRegistry
        target) only see this process's view; the operator sums
        across replicas in PromQL or scrapes each replica's
        ``/metrics`` separately. Documented in the v1.6 Grafana docs.
        """
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

    async def stop(self) -> None:
        self._stop_event.set()
        for task in (self._listener_task, self._reconcile_task):
            if task is None:
                continue
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._listener_task = None
        self._reconcile_task = None
        async with self._lock:
            for workers in list(self._connections.values()):
                for ws in list(workers.values()):
                    try:
                        await ws.close(code=1001)
                    except Exception:  # noqa: BLE001
                        pass
            self._connections.clear()
            self._project_for_agent.clear()

    # ------------------------------------------------------------------
    # Listener task - reconnect loop
    # ------------------------------------------------------------------

    async def _run_listener_loop(self) -> None:
        """Outer reconnect loop.

        Runs forever until ``_stop_event`` is set. On every
        successful (re)connect we run :meth:`_reconcile_pending`
        to catch up on any commands that fired during the gap.
        """
        backoff_index = 0
        while not self._stop_event.is_set():
            try:
                await self._listen_session()
                # Clean exit (recycle / cancel) → reset backoff.
                backoff_index = 0
            except asyncio.CancelledError:
                return
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "z4j registry listener: error, will reconnect",
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
                    return  # stop requested during sleep
                except TimeoutError:
                    pass

    async def _listen_session(self) -> None:
        """One asyncpg connect → LISTEN → run-until-stop cycle.

        Returns cleanly when the listener_max_age_seconds budget
        elapses, the watchdog reports the listener wedged, or
        ``_stop_event`` is set. Any unexpected exception bubbles
        up to the outer reconnect loop.
        """
        dsn = self._asyncpg_dsn()
        conn: asyncpg.Connection | None = None
        try:
            conn = await asyncpg.connect(
                dsn=dsn,
                timeout=self._settings.asyncpg_connect_timeout,
                server_settings={
                    "tcp_keepalives_idle": "30",
                    "tcp_keepalives_interval": "10",
                    "tcp_keepalives_count": "3",
                    "application_name": (
                        f"z4j-brain-registry-{self._worker_id}"
                    ),
                },
            )
            await conn.add_listener(_COMMANDS_CHANNEL, self._on_notify)
            await conn.add_listener(_HEARTBEAT_CHANNEL, self._on_heartbeat)
            # 1.6.5 F2: cluster-wide agent revocation kick.
            await conn.add_listener(_AGENT_REVOKED_CHANNEL, self._on_agent_revoked)
            self._listener_alive.set()
            self._last_heartbeat_round_trip = time.monotonic()
            logger.info(
                "z4j registry listener: connected",
                worker_id=self._worker_id,
            )

            await self._reconcile_pending()

            await self._heartbeat_loop_until_done(conn)
        finally:
            self._listener_alive.clear()
            if conn is not None:
                try:
                    await conn.close(timeout=self._settings.asyncpg_close_timeout)
                except Exception:  # noqa: BLE001
                    pass

    async def _heartbeat_loop_until_done(
        self,
        conn: asyncpg.Connection,
    ) -> None:
        """Self-NOTIFY heartbeat + watchdog + max-age recycle.

        Loops forever waking up every ``heartbeat_seconds`` to:

        1. Fire a heartbeat NOTIFY with our worker id.
        2. Check that our previous heartbeat round-tripped within
           ``heartbeat_timeout_seconds``. If not, raise - the
           outer reconnect loop rebuilds the connection.
        3. Check the connection age vs ``listener_max_age_seconds``
           and return cleanly when exceeded.
        """
        interval = self._settings.registry_listener_heartbeat_seconds
        timeout = self._settings.registry_listener_heartbeat_timeout_seconds
        max_age = self._settings.registry_listener_max_age_seconds
        connected_at = time.monotonic()

        while not self._stop_event.is_set():
            # Age check.
            if time.monotonic() - connected_at > max_age:
                logger.info(
                    "z4j registry listener: max age reached, recycling",
                    worker_id=self._worker_id,
                )
                return

            # Watchdog check - if our last heartbeat did not
            # round-trip in time, raise.
            since_round_trip = time.monotonic() - self._last_heartbeat_round_trip
            if since_round_trip > timeout:
                raise RuntimeError(
                    f"heartbeat round-trip exceeded {timeout}s "
                    f"(last={since_round_trip:.1f}s)",
                )

            # Fire heartbeat.
            try:
                await conn.execute(
                    "SELECT pg_notify($1, $2)",
                    _HEARTBEAT_CHANNEL,
                    self._worker_id,
                )
            except Exception:
                # Connection is bad - let the outer loop reconnect.
                raise

            # Sleep until next tick or stop.
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
        """Handle a ``z4j_commands`` NOTIFY.

        asyncpg invokes listener callbacks synchronously from
        inside the read loop. We must NOT block here - the body
        parses the payload, decides whether the agent is local,
        and (if so) schedules an async task to do the actual push.
        """
        try:
            data = json.loads(payload)
            command_id = UUID(data["c"])
            agent_id = UUID(data["a"])
        except (ValueError, KeyError, TypeError):
            logger.warning(
                "z4j registry: malformed notify payload, ignoring",
                payload_len=len(payload),
            )
            return

        if agent_id not in self._connections:
            return  # not for us

        task = asyncio.create_task(
            self._dispatch_notified_command(command_id, agent_id),
            name="z4j-registry-dispatch",
        )
        task.add_done_callback(_log_task_exception)

    def _on_heartbeat(
        self,
        connection: asyncpg.Connection,  # noqa: ARG002
        pid: int,  # noqa: ARG002
        channel: str,  # noqa: ARG002
        payload: str,
    ) -> None:
        """Handle a ``z4j_heartbeat`` NOTIFY.

        We compare the payload's worker id to our own. Other
        workers' heartbeats are ignored (they're useful only as
        cluster-wide health signal we may surface as a metric in a
        later phase). Our own heartbeats reset the watchdog clock.
        """
        if payload == self._worker_id:
            self._last_heartbeat_round_trip = time.monotonic()

    def _on_agent_revoked(
        self,
        connection: asyncpg.Connection,  # noqa: ARG002
        pid: int,  # noqa: ARG002
        channel: str,  # noqa: ARG002
        payload: str,
    ) -> None:
        """Handle a ``z4j_agent_revoked`` NOTIFY (1.6.5 F2).

        Parses the agent_id from the payload, schedules a local
        kick if any connection for that agent lives on THIS replica.
        Same non-blocking pattern as the command-NOTIFY handler:
        the asyncpg listener callback runs synchronously inside the
        read loop and MUST NOT block, so we punt the actual close
        to a background task.
        """
        try:
            agent_id = UUID(payload)
        except (ValueError, TypeError):
            logger.warning(
                "z4j registry: malformed agent-revoked payload, ignoring",
                payload_len=len(payload),
            )
            return

        # Fast path: not for us.
        if agent_id not in self._connections:
            return

        task = asyncio.create_task(
            self._kick_local(agent_id),
            name="z4j-registry-kick-revoked",
        )
        task.add_done_callback(_log_task_exception)

    async def _dispatch_notified_command(
        self,
        command_id: UUID,
        agent_id: UUID,
    ) -> None:
        """Pick up a notified command and push it to the local WS."""
        # 1.2.0: pick first-available worker. v1.3 will support
        # role-based routing by inspecting the command's target_role
        # (if any) against each worker's declared role.
        workers = self._connections.get(agent_id)
        ws = next(iter(workers.values()), None) if workers else None
        if ws is None:
            return  # agent disconnected between notify and dispatch
        try:
            await self._deliver_local(command_id, ws)
        except Exception:  # noqa: BLE001
            logger.exception(
                "z4j registry: notified deliver crashed",
                command_id=str(command_id),
                agent_id=str(agent_id),
            )

    # ------------------------------------------------------------------
    # Reconcile sweeper - periodic catch-up
    # ------------------------------------------------------------------

    async def _run_reconcile_loop(self) -> None:
        interval = self._settings.registry_reconcile_interval_seconds
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=interval,
                )
                return
            except TimeoutError:
                pass
            try:
                await self._reconcile_pending()
            except Exception:  # noqa: BLE001
                logger.exception(
                    "z4j registry: periodic reconcile crashed",
                    worker_id=self._worker_id,
                )

    async def _reconcile_pending(self) -> None:
        """Find pending commands targeting our local agents and push them.

        Cheap because the WHERE filters by ``agent_id IN (...)``
        with the small list of agents this worker actually holds.
        Idempotent: the dispatch path UPDATEs ``status='dispatched'``
        with a ``WHERE status='pending'`` guard, so re-running this
        twice cannot double-deliver.
        """
        async with self._lock:
            agent_ids = list(self._connections.keys())
        if not agent_ids:
            return

        from sqlalchemy import select

        from z4j_brain.persistence.enums import CommandStatus
        from z4j_brain.persistence.models import Command

        async with self._db.session() as session:
            result = await session.execute(
                select(Command.id, Command.agent_id)
                .where(
                    Command.status == CommandStatus.PENDING,
                    Command.agent_id.in_(agent_ids),
                )
                .limit(500),
            )
            rows = result.all()

        for command_id, agent_id in rows:
            workers = self._connections.get(agent_id)
            ws = next(iter(workers.values()), None) if workers else None
            if ws is None:
                continue
            try:
                await self._deliver_local(command_id, ws)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "z4j registry: reconcile deliver crashed",
                    command_id=str(command_id),
                    agent_id=str(agent_id),
                )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _asyncpg_dsn(self) -> str:
        """Return the DSN suitable for ``asyncpg.connect``.

        SQLAlchemy uses ``postgresql+asyncpg://`` URLs but raw
        asyncpg wants ``postgresql://``. We strip the dialect tag.
        """
        url = self._dsn_provider()
        return url.replace("postgresql+asyncpg://", "postgresql://", 1)


__all__ = ["DeliverCallback", "DsnProvider", "PostgresNotifyRegistry"]
