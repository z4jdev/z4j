"""Production :class:`BrainRegistry` backed by Postgres LISTEN/NOTIFY.

Multi-worker safe. Each worker:

1. Holds a local map of immutable session-generation handles for
   the agents currently connected to THIS worker. Each handle binds
   its socket to adapter-derived retry contracts.
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

The ``deliver`` fast path selects one compatible local session and
pushes synchronously, skipping NOTIFY entirely. The slow path
publishes ``{command_id, agent_id, retry requirement}``; the
receiving worker re-derives the requirement from the canonical
command row before selecting one exact compatible generation. The
payload remains well under Postgres's 8000-byte cap.

The whole module is 1 file by design - production debuggers should
be able to read it top to bottom in 10 minutes.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import secrets
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import asyncpg
import structlog

from z4j_brain.websocket.registry._protocol import (
    DeliveryResult,
    SessionHandle,
    WorkerCapExceeded,
)

if TYPE_CHECKING:
    from fastapi import WebSocket

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
        # Private durable-delivery authority. Unlike worker_id, this is a typed
        # random identity copied into every immutable session handle and then
        # into a claimed Boundary-D command.
        self._registry_owner_id: UUID = uuid4()

        # Local connections map. Updated under ``_lock``.
        # Stores immutable session handles per agent_id, keyed by
        # worker_id. Legacy agents (no worker_id) use the collision-
        # proof ``None`` slot. Worker-aware agents land in their own
        # generated worker_id slot; reconnect replaces the generation
        # atomically and cannot inherit an earlier selection.
        self._lock = asyncio.Lock()
        self._connections: dict[UUID, dict[str | None, SessionHandle]] = {}
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
        ws: WebSocket,
        worker_id: str | None = None,
        cap: int = 0,
        retry_contracts: dict[str, int] | None = None,
    ) -> SessionHandle:
        slot: str | None = worker_id  # None = legacy 1.1.x slot
        displaced: SessionHandle | None = None
        async with self._lock:
            workers = self._connections.setdefault(agent_id, {})
            # Cap check (1.2.1+): NEW slot creations only.
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
            # Production Starlette WebSockets accept these immutable delivery
            # coordinates.  Keep registration usable for opaque protocol-test
            # sentinels that intentionally expose no attribute storage.
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
        if displaced is not None:
            with contextlib.suppress(Exception):
                await displaced.websocket.close(code=4002)
        logger.info(
            "z4j registry: agent registered",
            agent_id=str(agent_id),
            project_id=str(project_id),
            worker_id=self._worker_id,
            agent_worker_id=worker_id,
        )
        return handle

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

    async def unregister(
        self,
        agent_id: UUID,
        *,
        ws: WebSocket | None = None,
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
            elif ws is not None:
                current = workers.get(slot)
                if current is None or current.websocket is not ws:
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
        for handle in list(workers.values()):
            try:
                await handle.websocket.close(code=4003)
                closed += 1
            except Exception:  # noqa: S110  best-effort close of revoked agent connection
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
        required_retry_engine: str | None = None,
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
        if handle is not None:
            # The immutable selected handle is the authority. Release the map
            # lock before database/network I/O so a reconnect cannot deadlock
            # behind its own in-flight selected-generation send.
            ok = await self._deliver_handle(
                command_id=command_id,
                handle=handle,
            )
            return DeliveryResult(
                delivered_locally=ok,
                notified_cluster=False,
                agent_was_known=True,
            )

        # Slow path: publish a NOTIFY for the cluster. We do NOT
        # know which worker holds the agent; some other worker may
        # pick it up, or none may, in which case the
        # CommandTimeoutWorker eventually flips the row.
        await self._publish_command_notify(
            command_id,
            agent_id,
            required_retry_engine=required_retry_engine,
        )
        return DeliveryResult(
            delivered_locally=False,
            notified_cluster=True,
            agent_was_known=False,
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
        if handle is not None:
            return await self._deliver_handle(
                command_id=command_id,
                handle=handle,
            )
        await self._publish_command_notify(
            command_id,
            agent_id,
            frozen_registry_owner_id=registry_owner_id,
            frozen_session_generation=session_generation,
        )
        return True

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
            logger.exception(
                "z4j registry: local deliver crashed",
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
        """Return one exact compatible generation owned by this replica."""

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

    async def _publish_command_notify(
        self,
        command_id: UUID,
        agent_id: UUID,
        *,
        required_retry_engine: str | None = None,
        frozen_registry_owner_id: UUID | None = None,
        frozen_session_generation: str | None = None,
    ) -> None:
        """Fire ``NOTIFY z4j_commands, '{c, a, r?}'``.

        Uses the SQLAlchemy session because the payload is small
        and the SQLAlchemy session participates in the request's
        transaction - we want the NOTIFY and any other writes in
        the same scope to commit atomically.
        """
        from sqlalchemy import text

        body: dict[str, object] = {
            "c": str(command_id),
            "a": str(agent_id),
        }
        if required_retry_engine is not None:
            body["r"] = {"e": required_retry_engine, "v": 1}
        if frozen_registry_owner_id is not None and frozen_session_generation is not None:
            body["f"] = {
                "o": str(frozen_registry_owner_id),
                "g": frozen_session_generation,
            }
        payload = json.dumps(body, separators=(",", ":"))
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
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._listener_task = None
        self._reconcile_task = None
        async with self._lock:
            for workers in list(self._connections.values()):
                for handle in list(workers.values()):
                    with contextlib.suppress(Exception):
                        await handle.websocket.close(code=1001)
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
            except Exception as exc:
                logger.warning(
                    "z4j registry listener: error, will reconnect",
                    error_class=type(exc).__name__,
                    backoff_index=backoff_index,
                    worker_id=self._worker_id,
                )
                backoff = _RECONNECT_BACKOFF[min(backoff_index, len(_RECONNECT_BACKOFF) - 1)]
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
                    "application_name": (f"z4j-brain-registry-{self._worker_id}"),
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
                with contextlib.suppress(Exception):
                    await conn.close(timeout=self._settings.asyncpg_close_timeout)

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
                    f"heartbeat round-trip exceeded {timeout}s (last={since_round_trip:.1f}s)",
                )

            # Fire heartbeat. A failure means the connection is bad;
            # let it propagate so the outer loop reconnects.
            await conn.execute(
                "SELECT pg_notify($1, $2)",
                _HEARTBEAT_CHANNEL,
                self._worker_id,
            )

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
        connection: asyncpg.Connection,
        pid: int,
        channel: str,
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
            raw_requirement = data.get("r")
            if raw_requirement is None:
                notified_retry_engine = None
            elif (
                isinstance(raw_requirement, dict)
                and raw_requirement.get("v") == 1
                and isinstance(raw_requirement.get("e"), str)
            ):
                notified_retry_engine = raw_requirement["e"]
            else:
                logger.warning(
                    "z4j registry: malformed notify retry requirement, ignoring",
                    payload_len=len(payload),
                )
                return
            raw_frozen = data.get("f")
            if raw_frozen is None:
                frozen_owner_id = None
                frozen_generation = None
            elif (
                isinstance(raw_frozen, dict)
                and isinstance(raw_frozen.get("g"), str)
                and 0 < len(raw_frozen["g"]) <= 200
            ):
                frozen_owner_id = UUID(str(raw_frozen["o"]))
                frozen_generation = raw_frozen["g"]
            else:
                logger.warning(
                    "z4j registry: malformed frozen notify authority, ignoring",
                    payload_len=len(payload),
                )
                return
        except (ValueError, KeyError, TypeError):
            logger.warning(
                "z4j registry: malformed notify payload, ignoring",
                payload_len=len(payload),
            )
            return

        if agent_id not in self._connections:
            return  # not for us

        task = asyncio.create_task(
            self._dispatch_notified_command(
                command_id,
                agent_id,
                notified_retry_engine=notified_retry_engine,
                frozen_registry_owner_id=frozen_owner_id,
                frozen_session_generation=frozen_generation,
            ),
            name="z4j-registry-dispatch",
        )
        task.add_done_callback(_log_task_exception)

    def _on_heartbeat(
        self,
        connection: asyncpg.Connection,
        pid: int,
        channel: str,
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
        connection: asyncpg.Connection,
        pid: int,
        channel: str,
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
        *,
        notified_retry_engine: str | None = None,
        frozen_registry_owner_id: UUID | None = None,
        frozen_session_generation: str | None = None,
    ) -> None:
        """Pick up a notified command and push it to one exact session."""
        from sqlalchemy import select

        from z4j_brain.domain.retry_contract import required_retry_engine
        from z4j_brain.persistence.models import Command

        # The row is authoritative. Deriving again also makes an old brain's
        # pre-1.8 NOTIFY fail closed when a current listener receives it.
        async with self._db.session() as session:
            result = await session.execute(
                select(
                    Command.agent_id,
                    Command.action,
                    Command.payload,
                    Command.delivery_registry_owner_id,
                    Command.delivery_session_generation,
                ).where(Command.id == command_id)
            )
            row = result.one_or_none()
        if row is None or row.agent_id != agent_id:
            return
        required_engine = required_retry_engine(row.action, row.payload)
        if notified_retry_engine is not None and notified_retry_engine != required_engine:
            logger.warning(
                "z4j registry: notify retry requirement mismatched command",
                command_id=str(command_id),
                notified_engine=notified_retry_engine,
                command_engine=required_engine,
            )
            return
        frozen = frozen_registry_owner_id is not None and frozen_session_generation is not None
        if frozen:
            payload_owner = (
                str(row.payload.get("registry_owner_id") or "")
                if isinstance(row.payload, dict)
                else ""
            )
            payload_generation = (
                str(row.payload.get("session_generation") or "")
                if isinstance(row.payload, dict)
                else ""
            )
            row_authority_matches = (
                row.delivery_registry_owner_id == frozen_registry_owner_id
                and row.delivery_session_generation == frozen_session_generation
            ) or (
                row.action
                in {
                    "schedule.external.activate",
                    "schedule.external.control",
                }
                and payload_owner == str(frozen_registry_owner_id)
                and payload_generation == frozen_session_generation
            )
            if not row_authority_matches:
                return
            async with self._lock:
                handle = next(
                    (
                        candidate
                        for candidate in (self._connections.get(agent_id) or {}).values()
                        if candidate.registry_owner_id == frozen_registry_owner_id
                        and str(candidate.generation) == frozen_session_generation
                    ),
                    None,
                )
        else:
            handle = await self.select_session(
                agent_id=agent_id,
                required_retry_engine=required_engine,
            )
        if handle is None:
            return  # agent disconnected between notify and dispatch
        try:
            await self.deliver_exact(
                command_id=command_id,
                session=handle,
            )
        except Exception:
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
            except Exception:
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
            connections = {
                agent_id: tuple(handles.values()) for agent_id, handles in self._connections.items()
            }
        agent_ids = list(connections)
        if not agent_ids:
            return

        from sqlalchemy import and_, or_, select

        from z4j_brain.domain.retry_contract import (
            RETRY_FAMILY_ACTIONS,
            required_retry_engine,
        )
        from z4j_brain.persistence.enums import CommandStatus
        from z4j_brain.persistence.models import Command

        agents_by_retry_engine: dict[str, set[UUID]] = {}
        for agent_id, handles in connections.items():
            for handle in handles:
                for engine, version in handle.retry_contracts:
                    if version == 1:
                        agents_by_retry_engine.setdefault(engine, set()).add(agent_id)
        eligible_conditions = [
            ~Command.action.in_(RETRY_FAMILY_ACTIONS),
            *(
                or_(
                    and_(
                        Command.action == "retry_task",
                        Command.agent_id.in_(supported_agents),
                        Command.payload["engine"].as_string() == engine,
                    ),
                    and_(
                        Command.action == "bulk_retry",
                        Command.agent_id.in_(supported_agents),
                        Command.payload["filter"]["engine"].as_string() == engine,
                    ),
                )
                for engine, supported_agents in agents_by_retry_engine.items()
            ),
        ]
        async with self._db.session() as session:
            result = await session.execute(
                select(
                    Command.id,
                    Command.agent_id,
                    Command.action,
                    Command.payload,
                )
                .where(
                    Command.status == CommandStatus.PENDING,
                    Command.agent_id.in_(agent_ids),
                    or_(*eligible_conditions),
                )
                .limit(500),
            )
            rows = result.all()

        for command_id, agent_id, action, payload in rows:
            if action in {
                "schedule.external.activate",
                "schedule.external.control",
            } and isinstance(payload, dict):
                try:
                    owner_id = UUID(str(payload["registry_owner_id"]))
                    generation = str(payload["session_generation"])
                except (KeyError, TypeError, ValueError):
                    continue
                async with self._lock:
                    handle = next(
                        (
                            candidate
                            for candidate in (self._connections.get(agent_id) or {}).values()
                            if candidate.registry_owner_id == owner_id
                            and str(candidate.generation) == generation
                        ),
                        None,
                    )
            else:
                handle = await self.select_session(
                    agent_id=agent_id,
                    required_retry_engine=required_retry_engine(
                        action,
                        payload,
                    ),
                )
            if handle is None:
                continue
            try:
                await self.deliver_exact(
                    command_id=command_id,
                    session=handle,
                )
            except Exception:
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
