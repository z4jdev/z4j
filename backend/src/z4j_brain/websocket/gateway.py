"""``/ws/agent`` WebSocket endpoint.

The brain's bidirectional link with every connected ``z4j-bare``
agent. Per-connection state machine:

1. Accept the upgrade.
2. Authenticate via the ``Authorization: Bearer ...`` header.
   Failure → close with code 4401.
3. Receive the first frame; require it to be a ``hello``. Failure
   or version mismatch → close with code 4000 / 4400.
4. Reply with ``hello_ack``.
5. Mark the agent ``online``, register with the cluster registry,
   construct a per-connection :class:`FrameRouter`, drain pending
   commands.
6. Receive loop: parse → ``router.dispatch``. Connection-fatal
   errors close the WebSocket.
7. On disconnect: unregister, mark offline.

Close codes:
- ``4401`` - invalid bearer token
- ``4400`` - first frame was not ``hello`` or shape was malformed
- ``4426`` - protocol version not supported
- ``4427`` - agent outside the supported version skew. RESERVED, not sent
  yet: outdated agents treat unknown close codes as transient and would
  reconnect-storm. See ``CLOSE_VERSION_SKEW``.
- ``4429`` - agent connect rate limit exceeded
- ``4002`` - replaced by a newer connection from the same agent
- ``1000`` - clean shutdown
- ``1011`` - internal server error
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid
from collections.abc import Coroutine
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import anyio
import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import ValidationError as PydanticValidationError
from z4j_core.errors import SignatureError
from z4j_core.transport.frames import (
    CommandFrame,
    CommandPayload,
    Frame,
    HelloAckFrame,
    HelloAckPayload,
    HelloFrame,
    parse_frame,
    serialize_frame,
)
from z4j_core.transport.framing import FrameSigner, FrameVerifier
from z4j_core.transport.hmac import derive_project_secret
from z4j_core.transport.versioning import SUPPORTED_PROTOCOLS

from z4j_brain import (
    __version__ as BRAIN_VERSION,  # noqa: N812  conventional version-constant alias
)
from z4j_brain.domain.command_wire import wire_target
from z4j_brain.domain.retry_contract import (
    required_retry_engine,
    retry_contracts_from_capabilities,
)
from z4j_brain.domain.version_check import ParsedVersion
from z4j_brain.websocket.auth import resolve_agent_by_bearer
from z4j_brain.websocket.frame_router import FrameRouter

if TYPE_CHECKING:
    from z4j_brain.domain import CommandDispatcher, EventIngestor
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.models import Command
    from z4j_brain.settings import Settings
    from z4j_brain.websocket.dashboard_hub import DashboardHub
    from z4j_brain.websocket.registry import BrainRegistry, SessionHandle
from z4j_brain.websocket.registry._protocol import WorkerCapExceeded

logger = structlog.get_logger("z4j.brain.gateway")

router = APIRouter(tags=["gateway"])

#: Reserved close code for "agent is outside the supported version skew".
#: NOT sent yet, deliberately. z4j-bare 1.8 learns to treat it as terminal;
#: until 1.8 agents are the floor, closing with it would make outdated agents
#: reconnect-storm, because they classify unknown close codes as transient.
#: The brain starts using it once that floor is reached. See the skew comment
#: in ``ws_agent`` and docs/UPGRADE.md.
CLOSE_VERSION_SKEW = 4427

#: How many minors an agent may trail the brain by, per docs/UPGRADE.md.
_MAX_AGENT_MINOR_LAG = 1


def _warn_on_version_skew(
    *,
    agent_id: uuid.UUID,
    agent_version: str,
    brain_version: str,
) -> None:
    """Log only when the agent is OUTSIDE the supported skew window.

    Supported, and therefore silent: same major, agent minor equal to the
    brain's or exactly one behind. That is the normal rolling-upgrade state and
    warning about it trains operators to ignore the log.

    Warned about:

    - agent NEWER than the brain, which the contract forbids outright
    - agent more than one minor behind, which is what a 1.6 -> 1.8 jump
      produces and why docs/UPGRADE.md makes 1.7 a required stop
    - a different major, where nothing is promised
    """
    # "0.0.0" is the sentinel an agent sends when it cannot determine its own
    # version; skew is unknowable rather than wrong, so stay quiet.
    if not agent_version or not brain_version or agent_version == "0.0.0":
        return

    agent = ParsedVersion.parse(agent_version)
    brain = ParsedVersion.parse(brain_version)
    if agent is None or brain is None:
        logger.warning(
            "z4j gateway: agent/brain version unparseable, skew unchecked",
            agent_id=str(agent_id),
            agent_version=agent_version,
            brain_version=brain_version,
        )
        return

    if agent.major == brain.major:
        lag = brain.minor - agent.minor
        if 0 <= lag <= _MAX_AGENT_MINOR_LAG:
            return
        reason = (
            "agent is newer than the brain; the contract requires brain >= agent"
            if lag < 0
            else f"agent trails the brain by {lag} minors, "
            f"maximum supported is {_MAX_AGENT_MINOR_LAG}"
        )
    else:
        reason = "agent and brain are different majors; no compatibility is promised"

    logger.warning(
        "z4j gateway: agent outside the supported version skew",
        agent_id=str(agent_id),
        agent_version=str(agent),
        brain_version=str(brain),
        reason=reason,
        remedy=(
            "upgrade the agent to within one minor of the brain; see "
            "docs/UPGRADE.md for the required intermediate versions"
        ),
    )


@router.websocket("/ws/agent")
async def ws_agent(websocket: WebSocket) -> None:  # noqa: PLR0911, PLR0912, PLR0915  connection state machine
    """The agent gateway endpoint.

    See module docstring for the per-connection state machine.
    """
    settings = _settings_from(websocket)
    db = _db_from(websocket)

    # Per-IP rate limit on the WS handshake. Without this, a
    # leaked bearer could open thousands of connections; the
    # "second connection wins" policy only kicks the OTHER
    # active session per agent, it doesn't prevent connect
    # floods.
    from z4j_brain.domain.ip_rate_limit import _agent_connect_bucket

    client_host = websocket.client.host if websocket.client else None
    if client_host is not None:
        ok = await _agent_connect_bucket.hit(client_host)
        if not ok:
            await websocket.accept()
            await websocket.close(
                code=4429,  # custom: 4429 = "too many requests"
                reason="agent connect rate limit exceeded",
            )
            logger.warning(
                "z4j gateway: WS connect rate-limited",
                source_ip=client_host,
            )
            return

    await websocket.accept()

    # ------------------------------------------------------------------
    # 1) Authenticate
    # ------------------------------------------------------------------
    bearer = websocket.headers.get("authorization")
    from z4j_brain.persistence.repositories import (
        AgentRepository,
        AgentWorkerRepository,
        AuditLogRepository,
    )

    async with db.session() as session:
        agent_repo = AgentRepository(session)
        agent = await resolve_agent_by_bearer(
            bearer=bearer,
            settings=settings,
            agents=agent_repo,
        )
    if agent is None:
        # Audit the failure so operators have visibility into bearer
        # rejection patterns. The source IP is the realistic
        # rate-limit key for any future per-IP throttle middleware.
        client_host = websocket.client.host if websocket.client else None
        # Audit the rejection BEFORE closing the socket so the write
        # completes without racing the connection teardown.
        try:
            async with db.session(write=True) as audit_session:
                await websocket.app.state.audit_service.record(
                    AuditLogRepository(audit_session),
                    action="agent.auth.bearer_failed",
                    target_type="agent",
                    result="failed",
                    outcome="deny",
                    source_ip=client_host,
                )
                await audit_session.commit()
        except Exception:
            logger.exception("z4j gateway: failed to audit bearer rejection")
        finally:
            logger.info("z4j gateway: bearer rejected", source_ip=client_host)
            await websocket.close(code=4401)
        return

    project_id = agent.project_id
    agent_id = agent.id

    # ------------------------------------------------------------------
    # 2) Hello handshake
    # ------------------------------------------------------------------
    try:
        first_frame = await _recv_frame(
            websocket,
            max_bytes=settings.ws_max_frame_bytes,
        )
    except (WebSocketDisconnect, ConnectionError, _BadFrameError):
        await _safe_close(websocket, code=4400)
        return

    if not isinstance(first_frame, HelloFrame):
        logger.info(
            "z4j gateway: first frame was not hello",
            agent_id=str(agent_id),
            type=getattr(first_frame, "type", None),
        )
        await _safe_close(websocket, code=4400)
        return

    if first_frame.payload.protocol_version not in SUPPORTED_PROTOCOLS:
        logger.info(
            "z4j gateway: protocol version unsupported",
            agent_id=str(agent_id),
            advertised=first_frame.payload.protocol_version,
        )
        await _safe_close(websocket, code=4426)
        return

    # Agent/brain version skew against the documented contract in
    # docs/UPGRADE.md: brain minor >= agent minor, and the agent may be at
    # most ONE minor behind, same major.
    #
    # The previous implementation compared major.minor for plain inequality and
    # still reasoned about CalVer ("agent 2026.4 vs brain 2026.5") long after
    # the move to SemVer. Equality is the wrong test: it fired on a 1.7 agent
    # against a 1.8 brain, which the contract explicitly SUPPORTS, so the log
    # could not distinguish a supported rolling upgrade from an unsupported
    # one and operators learned to ignore it.
    #
    # Still a warning, not a rejection, and that is deliberate. A deployed
    # 1.6/1.7 agent classifies any close code other than 4401/4403 as a
    # transient ConnectionError and reconnects on the normal backoff, so
    # rejecting here would make exactly the outdated agents we are rejecting
    # reconnect-storm the brain. z4j-bare 1.8 adds terminal handling for
    # CLOSE_VERSION_SKEW; once 1.8 agents are the floor, the brain can start
    # closing with it. Same sequencing Celery used for the v1 -> v2 task
    # protocol: teach the old side to cope first, enforce afterwards.
    agent_ver = getattr(first_frame.payload, "agent_version", "")
    _warn_on_version_skew(
        agent_id=agent_id,
        agent_version=agent_ver,
        brain_version=BRAIN_VERSION,
    )

    # ------------------------------------------------------------------
    # 3) Update the agent row, send hello_ack
    # ------------------------------------------------------------------
    session_id = uuid.uuid4()
    # Capture this connection's mark_online timestamp
    # so the eventual mark_offline at close-time can pass it as
    # ``captured_at``. With the conditional WHERE on
    # ``last_connect_at <= captured_at`` in mark_offline, a fresh
    # reconnection's mark_online (which writes a NEWER
    # last_connect_at) cannot be clobbered by this connection's
    # late-arriving mark_offline.
    async with db.session() as db_session:
        connect_at = await AgentRepository(db_session).mark_online(
            agent_id,
            protocol_version=first_frame.payload.protocol_version,
            framework_adapter=first_frame.payload.framework,
            engine_adapters=list(first_frame.payload.engines),
            scheduler_adapters=list(first_frame.payload.schedulers),
            capabilities={k: list(v) for k, v in first_frame.payload.capabilities.items()},
            # Carries the agent's optional `host.name` label and any other
            # host-level metadata. The agent (z4j-bare 1.0.3+) populates
            # this from the operator's `Z4J_AGENT_NAME` env / settings.Z4J
            # ``agent_name`` field. Persisted under agent_metadata['host'].
            host=dict(first_frame.payload.host) if first_frame.payload.host else None,
            # 1.3.4: persist the agent's z4j-core version (sent in the
            # hello frame's ``agent_version`` field) for the dashboard's
            # per-agent VERSION column + *update available* badge.
            # Agents older than 1.0.3 may report empty / 0.0.0; the
            # dashboard renders ``unknown`` in that case.
            agent_version=(agent_ver if agent_ver and agent_ver != "0.0.0" else None),
            # Runtime-wide flags remain sticky observability only. Boundary A
            # derives retry authority from the hello's per-adapter capability
            # map below and binds it to the immutable registry session.
            runtime_features=list(getattr(first_frame.payload, "runtime_features", []) or []),
        )
        await db_session.commit()

    # Notify dashboards that an agent transitioned to online.
    dashboard_hub = getattr(websocket.app.state, "dashboard_hub", None)
    if dashboard_hub is not None:
        try:
            await dashboard_hub.publish_agent_change(project_id)
        except Exception:
            logger.exception(
                "z4j gateway: dashboard agent online publish failed",
                agent_id=str(agent_id),
            )

    hello_ack = HelloAckFrame(
        id=f"hack_{session_id.hex[:12]}",
        ts=datetime.now(UTC),
        payload=HelloAckPayload(
            protocol_version=first_frame.payload.protocol_version,
            brain_version=BRAIN_VERSION,
            agent_id=str(agent_id),
            project_id=str(project_id),
            session_id=str(session_id),
            heartbeat_interval_seconds=10,
            max_frame_size_bytes=settings.ws_max_frame_bytes,
        ),
    )
    try:
        await websocket.send_bytes(serialize_frame(hello_ack))
    except (WebSocketDisconnect, ConnectionError):
        return

    # ------------------------------------------------------------------
    # Protocol v2: build the per-session signer + verifier.
    # ------------------------------------------------------------------
    # The handshake frames are intentionally unsigned (they are the
    # moment we learn agent_id/project_id). Everything after this
    # point carries an envelope HMAC that binds (ts, nonce, seq,
    # agent_id, project_id) into the signature. The signer+verifier
    # are stateful per session; they live on the websocket object so
    # ``deliver_command_frame`` (called from another coroutine via
    # the registry's ``deliver_local``) can look them up.
    # Per-project derived signing secret (see
    # z4j_core.transport.hmac.derive_project_secret). The agent
    # holds the same derivation so a leaked agent host secret
    # cannot forge frames against other projects.
    master_bytes = settings.secret.get_secret_value().encode("utf-8")
    project_secret = derive_project_secret(master_bytes, project_id)
    # Pass the newly-minted session_id into the signer + verifier so the
    # HMAC envelope binds to this specific session. A captured
    # frame from a previous session can't be replayed inside this
    # one, the verifier reconstitutes the envelope with THIS
    # session_id and the bytes signed under the prior session's
    # binding fail HMAC.
    signer = FrameSigner(
        secret=project_secret,
        agent_id=agent_id,
        project_id=project_id,
        session_id=session_id,
    )
    verifier = FrameVerifier(
        secret=project_secret,
        agent_id=agent_id,
        project_id=project_id,
        session_id=session_id,
        direction="agent->brain",
    )
    # Attach as attributes - Starlette's WebSocket has no __slots__,
    # so a named attribute is the least-surprising way to thread
    # per-connection state through the registry callback.
    websocket._z4j_signer = signer  # type: ignore[attr-defined]
    websocket._z4j_verifier = verifier  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # 4) Register, build per-connection FrameRouter, drain pending commands
    # ------------------------------------------------------------------
    registry = _registry_from(websocket)
    ingestor: EventIngestor = websocket.app.state.event_ingestor
    dispatcher: CommandDispatcher = websocket.app.state.command_dispatcher

    # Callback the FrameRouter uses to emit
    # outbound frames (event_batch_ack today; reserved for any
    # future brain->agent control frame). The FrameSigner is
    # already attached to the websocket above; the closure binds
    # both. ``websocket.send_bytes`` is async; the closure preserves
    # exception propagation so the FrameRouter's ack-emit branch
    # can log on failure without losing the trace.
    async def _send_frame(out: Frame) -> None:
        await websocket.send_bytes(signer.sign_and_serialize(out))

    # Worker-first protocol (1.2.0+): pull the optional worker_id
    # off the Hello payload and pass to the registry. None for
    # legacy 1.1.x agents - the registry preserves the historical
    # "one connection per agent_id" semantics for those.
    agent_worker_id = first_frame.payload.worker_id
    try:
        session_handle = await registry.register(
            project_id=project_id,
            agent_id=agent_id,
            ws=websocket,
            worker_id=agent_worker_id,
            cap=settings.ws_per_agent_concurrency_cap,
            retry_contracts=retry_contracts_from_capabilities(first_frame.payload.capabilities),
        )
    except WorkerCapExceeded as exc:
        # Per-agent worker cap exceeded (1.2.1+, audit F2). Bound
        # the worst-case fd / memory per agent_id even if a buggy
        # or malicious agent invents many distinct worker_ids.
        # Defense in depth alongside the per-IP rate limit.
        logger.warning(
            "z4j gateway: per-agent worker cap exceeded; rejecting",
            agent_id=str(agent_id),
            current_workers=exc.current,
            cap=exc.cap,
            new_worker_id=agent_worker_id,
        )
        await _safe_close(websocket, code=4429)
        return

    frame_router = FrameRouter(
        db=db,
        ingestor=ingestor,
        dispatcher=dispatcher,
        project_id=project_id,
        agent_id=agent_id,
        dashboard_hub=getattr(websocket.app.state, "dashboard_hub", None),
        worker_id=first_frame.payload.worker_id,
        transport_kind="websocket",
        registry_owner_id=session_handle.registry_owner_id,
        session_generation=str(session_handle.generation),
        send_frame=_send_frame,
        automation_notify_coalesce_seconds=settings.automation_notify_coalesce_seconds,
        automation_outbox_max_rows_per_project=settings.automation_outbox_max_rows_per_project,
    )

    # Worker-first persistence (1.2.1+): durable per-worker tracking
    # in agent_workers. Idempotent upsert; safe to retry on each
    # hello (the gateway only reaches this code on successful
    # handshake + registry registration). Carries worker_role,
    # worker_pid, worker_started_at off the hello payload so the
    # dashboard can filter by role and show pid/uptime per worker.
    try:
        async with db.session() as db_session:
            await AgentWorkerRepository(db_session).register_or_refresh(
                agent_id=agent_id,
                project_id=project_id,
                worker_id=agent_worker_id,
                role=first_frame.payload.worker_role,
                framework=first_frame.payload.framework,
                pid=first_frame.payload.worker_pid,
                started_at=first_frame.payload.worker_started_at,
            )
            await db_session.commit()
    except Exception:
        # Best-effort: persistence is for the dashboard, not the
        # control flow. If the DB write fails (unlikely with
        # SQLite/Postgres in a healthy brain), the in-memory
        # registry still routes commands; the dashboard just won't
        # see this worker until the next heartbeat refreshes the
        # row. Log + continue.
        logger.exception(
            "z4j gateway: agent_worker upsert failed (dashboard view "
            "will be stale; control plane unaffected)",
            agent_id=str(agent_id),
            worker_id=agent_worker_id,
        )

    try:
        await _issue_external_schedule_activations(
            db=db,
            settings=settings,
            dispatcher=dispatcher,
            registry=registry,
            session_handle=session_handle,
            project_id=project_id,
            agent_id=agent_id,
            schedulers=list(first_frame.payload.schedulers),
            capabilities={
                key: list(value) for key, value in first_frame.payload.capabilities.items()
            },
            runtime_features=list(first_frame.payload.runtime_features),
        )
        await _drain_pending_for_agent(
            db=db,
            settings=settings,
            agent_id=agent_id,
            session_handle=session_handle,
            registry=registry,
        )

        # ------------------------------------------------------------------
        # 5) Receive loop
        # ------------------------------------------------------------------
        # Per-connection idle timeout. A well-behaved agent sends a
        # heartbeat every ``heartbeat_interval_seconds`` (declared
        # in hello_ack), so a healthy connection always gets a frame
        # within that window. If we go ``ws_idle_timeout_seconds``
        # with no frame the agent has either died, NAT-dropped us,
        # or wedged its event loop - in all cases the right answer
        # is to free the file descriptor.
        #
        # Decouple ingest from the recv loop. Awaiting
        # ``frame_router.dispatch(frame)`` inline here would open a
        # DB session, run N upserts per event_batch, and a
        # notification fanout - all while the python ``websockets``
        # library cannot dispatch its periodic PING (PING/PONG runs
        # on the same per-connection asyncio task as application
        # messages). After ~ping_interval (20s) of starvation the
        # brain's outbound PING never fires, the agent waits another
        # ping_timeout (30s), and the connection closes with code
        # 1011 "keepalive ping timeout". Under heavy event-fanout
        # this disconnect-storms multiple agents simultaneously even
        # though CPU is idle - the bottleneck is serialised awaitable
        # chains, not saturation.
        #
        # The fix: a per-connection bounded asyncio.Queue plus a
        # dedicated ingest worker coroutine. The recv loop just
        # enqueues and returns immediately, freeing the connection
        # task to handle protocol-layer PING/PONG promptly. The queue
        # is bounded so a saturated ingest path applies backpressure
        # rather than growing memory unboundedly; under sustained
        # overload the recv loop blocks on ``put`` (NOT on dispatch),
        # so PING/PONG can still drain in the meantime because
        # ``put`` releases the loop between awaits.
        idle_timeout = float(settings.ws_idle_timeout_seconds)
        ingest_queue: asyncio.Queue[Frame] = asyncio.Queue(
            maxsize=settings.ws_ingest_queue_maxsize,
        )

        async def _ingest_worker() -> None:
            """Drain ingest_queue and dispatch each frame.

            Single-producer / single-consumer: one worker per
            connection so within-connection ordering is preserved
            and the per-event savepoint+retry path in the
            event_ingestor cannot silently skip events that fail a
            non-deadlock SQL exception. Throughput-driven designs
            with multiple parallel workers per connection look
            tempting on benchmarks but produce out-of-order arrivals
            at the ingestor, which combined with the per-event
            savepoint loop's "log + skip on non-deadlock failure"
            branch silently drops events the agent has already had
            ack'd and confirmed-evicted. Single worker is the
            correct trade.

            ``frame_router.dispatch`` already wraps every code path
            in ``try/except`` and never raises, so this worker has
            no per-frame error handling of its own.
            """
            while True:
                frame = await ingest_queue.get()
                try:
                    await frame_router.dispatch(frame)
                finally:
                    ingest_queue.task_done()

        def _log_ingest_task_failure(t: asyncio.Task[None]) -> None:
            # Without this, a silent crash inside _ingest_worker leaves
            # the recv loop happily filling the queue while no one
            # drains it, wedging the connection until idle timeout
            # fires. Surfacing the exception in the gateway log gives
            # operators a fighting chance of noticing. (1.6.0 round-2
            # audit Medium-2.)
            if t.cancelled():
                return
            exc = t.exception()
            if exc is None:
                return
            logger.error(
                "websocket.ingest_task_crashed",
                agent_id=str(agent_id),
                error=type(exc).__name__,
                error_message=str(exc),
                exc_info=exc,
            )

        _ingest_task = asyncio.create_task(
            _ingest_worker(),
            name=f"z4j_ingest_{agent_id}",
        )
        _ingest_task.add_done_callback(_log_ingest_task_failure)
        ingest_tasks: list[asyncio.Task[None]] = [_ingest_task]

        try:
            while True:
                try:
                    frame = await asyncio.wait_for(
                        _recv_frame(
                            websocket,
                            max_bytes=settings.ws_max_frame_bytes,
                            verifier=verifier,
                        ),
                        timeout=idle_timeout,
                    )
                except TimeoutError:
                    logger.info(
                        "z4j gateway: idle timeout, closing",
                        agent_id=str(agent_id),
                        idle_seconds=idle_timeout,
                    )
                    await _safe_close(websocket, code=4408)
                    break
                except WebSocketDisconnect:
                    break
                except _BadFrameError:
                    # Bad frame is connection-fatal - kill the WS to
                    # avoid de-syncing the wire protocol.
                    await _safe_close(websocket, code=4400)
                    break
                except SignatureError as exc:
                    # v2 envelope verification failure. One forged frame
                    # means the peer cannot be trusted for the rest of
                    # the session; close with a distinct code so
                    # operators can distinguish a crypto failure from a
                    # plain malformed frame.
                    logger.exception(
                        "z4j gateway: frame verification failed, closing",
                        agent_id=str(agent_id),
                        reason=str(exc),
                    )
                    await _safe_close(websocket, code=4403)
                    break
                except Exception:
                    logger.exception("z4j gateway: unexpected recv error")
                    await _safe_close(websocket, code=1011)
                    break

                # Enqueue for the ingest worker. Block-don't-drop on
                # full: if the ingest path is sustained-saturated, the
                # recv loop blocks on ``put`` (NOT on dispatch), which
                # is fine because ``put`` releases the loop between
                # awaits so PING/PONG keeps flowing. Dropping on full
                # would silently lose frames - the agent has no way
                # to know it happened (ack-aware paths live a layer
                # up). Blocking instead applies backpressure all the
                # way back to the agent's send buffer where the
                # buffer's bounded size is the correct backpressure
                # signal.
                await ingest_queue.put(frame)
        finally:
            # Cancel the ingest workers so we don't leak coroutines
            # when the recv loop exits. Swallow each
            # ``CancelledError`` so the outer ``finally`` for the
            # connection cleanup still runs.
            for t in ingest_tasks:
                t.cancel()
            for t in ingest_tasks:
                with contextlib.suppress(asyncio.CancelledError, BaseException):
                    await t

            # Drain the ingest queue so any frames held by cancelled
            # ``put`` futures are released. Without this, an
            # ``EventBatchFrame`` sitting in ``Queue._putters`` (from
            # a recv loop that was cancelled mid-``put`` while the
            # queue was full) stays reachable through the queue
            # object's internal deques, which in turn stays reachable
            # via the ``_send_frame`` closure -> ``websocket`` ->
            # ``_z4j_verifier`` -> ``ReplayGuard`` cycle. The agent
            # re-ships unacked entries on reconnect via the
            # app-level ack and the brain dedupes via the
            # content-derived event_id, so dropping these in-flight
            # frames is safe.
            try:
                while True:
                    ingest_queue.get_nowait()
                    ingest_queue.task_done()
            except asyncio.QueueEmpty:
                pass

            # Drop the strong references the route handler attached
            # to the websocket so the per-session FrameSigner /
            # FrameVerifier (and its 4096-entry replay-guard nonce
            # window) can be GC'd as soon as the route handler
            # returns. Without this the verifier stays reachable
            # through ``websocket`` for as long as the framework
            # keeps the websocket object alive, and a high-churn
            # reconnect rate accumulates 4K nonces per disconnected
            # session in memory.
            try:
                websocket._z4j_signer = None  # type: ignore[attr-defined]
                websocket._z4j_verifier = None  # type: ignore[attr-defined]
            except Exception:  # noqa: S110  best-effort reference drop for GC
                pass

            # Tear down the FrameRouter's per-connection background
            # tasks + clear its outbound callback. The router holds a
            # closure capturing ``websocket`` + ``signer``; clearing
            # ``_send_frame`` breaks that cycle so the router itself
            # can be collected without waiting on cycle-GC.
            with contextlib.suppress(Exception):
                frame_router.aclose()
    finally:
        await _finish_registered_connection_before_cancelling(
            _cleanup_registered_connection(
                registry=registry,
                agent_id=agent_id,
                websocket=websocket,
                agent_worker_id=agent_worker_id,
                db=db,
                connect_at=connect_at,
                dashboard_hub=dashboard_hub,
                project_id=project_id,
                audit=dispatcher.audit,
                registry_owner_id=session_handle.registry_owner_id,
                session_generation=str(session_handle.generation),
            ),
        )


# ---------------------------------------------------------------------------
# Module-private helpers
# ---------------------------------------------------------------------------


async def _finish_registered_connection_before_cancelling(
    cleanup: Coroutine[Any, Any, None],
) -> None:
    """Finish registered-agent cleanup before propagating cancellation.

    ASGI servers may cancel a WebSocket handler as soon as the peer's close
    frame is observed.  The registered connection still owns durable
    worker/agent state and may be between SQLAlchemy checkout and pre-ping.
    Letting cancellation land there both skips the offline flip and can strand
    an async pooled connection until cycle-GC.  Run cleanup in its own task,
    shield it from the first cancellation, await it to completion, and only
    then re-raise the caller's cancellation.
    """
    with anyio.CancelScope(shield=True):
        cleanup_task = asyncio.create_task(
            cleanup,
            name="z4j-gateway-registered-connection-cleanup",
        )
        try:
            await asyncio.shield(cleanup_task)
        except asyncio.CancelledError:
            await cleanup_task
            raise


async def _cleanup_registered_connection(
    *,
    registry: BrainRegistry,
    agent_id: uuid.UUID,
    websocket: WebSocket,
    agent_worker_id: str | None,
    db: DatabaseManager,
    connect_at: datetime,
    dashboard_hub: DashboardHub | None,
    project_id: uuid.UUID,
    audit: AuditService,
    registry_owner_id: uuid.UUID,
    session_generation: str,
) -> None:
    """Unregister one connection and persist its final offline state."""
    from z4j_brain.persistence.repositories import (
        AgentRepository,
        AgentWorkerRepository,
        AuditLogRepository,
        ScheduleExternalRepository,
    )

    # Pass our own ``websocket`` so the registry only evicts the entry IF it
    # still points at us. v1.2.0: also pass worker_id so the registry only
    # drops THIS worker's slot, not all slots under this agent_id.
    #
    # v1.2.1 (audit F3 fix): use the atomic return value rather than a separate
    # ``is_online`` check. ``unregister`` returns whether the LAST worker was
    # removed, decided under the registry lock.
    last_worker_gone = await registry.unregister(
        agent_id,
        ws=websocket,
        worker_id=agent_worker_id,
    )
    # Worker-first persistence: flip THIS worker's row to offline regardless
    # of whether others remain. The agent-level flip only fires when the last
    # worker is gone.
    try:
        async with db.session(write=True) as db_session:
            ambiguous_operations = await ScheduleExternalRepository(
                db_session,
            ).mark_claimed_controls_for_executor_loss(
                project_id=project_id,
                agent_id=agent_id,
                registry_owner_id=registry_owner_id,
                session_generation=session_generation,
                occurred_at=datetime.now(UTC),
            )
            for operation_id in ambiguous_operations:
                await audit.record(
                    AuditLogRepository(db_session),
                    action="schedule.external_control.executor_lost",
                    target_type="schedule_external_control_operation",
                    target_id=str(operation_id),
                    result="ambiguous",
                    outcome="failure",
                    project_id=project_id,
                    metadata={
                        "operation_id": str(operation_id),
                        "agent_id": str(agent_id),
                        "registry_owner_id": str(registry_owner_id),
                        "session_generation": session_generation,
                    },
                )
            await AgentWorkerRepository(db_session).mark_offline(
                agent_id=agent_id,
                worker_id=agent_worker_id,
            )
            if last_worker_gone:
                # The captured mark-online time prevents this connection's
                # late cleanup from clobbering a fresher reconnect.
                await AgentRepository(db_session).mark_offline(
                    agent_id,
                    captured_at=connect_at,
                )
            await db_session.commit()
    except Exception:
        logger.exception(
            "z4j gateway: agent_worker offline flip failed",
            agent_id=str(agent_id),
            worker_id=agent_worker_id,
        )
    if dashboard_hub is not None:
        try:
            await dashboard_hub.publish_agent_change(project_id)
        except Exception:
            logger.exception(
                "z4j gateway: dashboard agent offline publish failed",
                agent_id=str(agent_id),
            )
    await _safe_close(websocket, code=1000)


class _BadFrameError(Exception):
    """Raised when a frame is unparseable / oversized / wrong type."""


async def _recv_frame(
    websocket: WebSocket,
    *,
    max_bytes: int,
    verifier: FrameVerifier | None = None,
):
    """Receive one frame and parse + verify it.

    When ``verifier`` is provided (every frame after the handshake),
    the parse + envelope-HMAC + replay-guard checks all run here so
    the receive loop can handle :class:`SignatureError` distinctly
    from :class:`_BadFrameError`. The handshake itself passes
    ``verifier=None`` because the session's agent/project bindings
    are still being negotiated at that point.
    """
    message = await websocket.receive()

    if message.get("type") != "websocket.receive":
        if message.get("type") == "websocket.disconnect":
            raise WebSocketDisconnect()
        raise _BadFrameError(f"unexpected message type: {message.get('type')}")

    raw: bytes
    if "bytes" in message and message["bytes"] is not None:
        raw = bytes(message["bytes"])
    elif "text" in message and message["text"] is not None:
        raw = message["text"].encode("utf-8")
    else:
        raise _BadFrameError("empty frame")

    if len(raw) > max_bytes:
        raise _BadFrameError(f"frame too large: {len(raw)} > {max_bytes}")

    if verifier is not None:
        # parse_and_verify raises SignatureError on any security
        # failure; we let it bubble to the recv loop. Parse errors
        # still translate to _BadFrameError so close codes stay
        # meaningful.
        try:
            return verifier.parse_and_verify(raw)
        except SignatureError:
            raise
        except (json.JSONDecodeError, PydanticValidationError) as exc:
            raise _BadFrameError(f"frame parse failed: {type(exc).__name__}") from exc

    try:
        return parse_frame(raw)
    except (json.JSONDecodeError, PydanticValidationError) as exc:
        raise _BadFrameError(f"frame parse failed: {type(exc).__name__}") from exc


async def _safe_close(websocket: WebSocket, *, code: int) -> None:
    """Close the WebSocket without raising on already-closed."""
    with contextlib.suppress(Exception):
        await websocket.close(code=code)


def _settings_from(ws: WebSocket) -> Settings:
    return ws.app.state.settings  # type: ignore[no-any-return]


def _db_from(ws: WebSocket) -> DatabaseManager:
    return ws.app.state.db  # type: ignore[no-any-return]


def _registry_from(ws: WebSocket) -> BrainRegistry:
    return ws.app.state.brain_registry  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Pending-command drain on connect
# ---------------------------------------------------------------------------


async def _issue_external_schedule_activations(
    *,
    db: DatabaseManager,
    settings: Settings,
    dispatcher: CommandDispatcher,
    registry: BrainRegistry,
    session_handle: SessionHandle,
    project_id: uuid.UUID,
    agent_id: uuid.UUID,
    schedulers: list[str],
    capabilities: dict[str, list[str]],
    runtime_features: list[str],
) -> int:
    """Assign fresh stable sources to this exact WebSocket generation."""
    from z4j_core.schedule_external import (
        EXTERNAL_SCHEDULE_RUNTIME_FEATURE,
        EXTERNAL_SCHEDULE_STABLE_SNAPSHOT_CAPABILITY,
        external_schedule_source_scope,
    )

    if EXTERNAL_SCHEDULE_RUNTIME_FEATURE not in runtime_features:
        return 0

    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        CommandRepository,
    )
    from z4j_brain.persistence.repositories.schedule_external import (
        ScheduleExternalRepository,
    )

    delivered = 0
    for owner in sorted(set(schedulers)):
        if EXTERNAL_SCHEDULE_STABLE_SNAPSHOT_CAPABILITY not in capabilities.get(owner, ()):
            continue
        adapter_instance_id = str(uuid.uuid4())
        source_scope = external_schedule_source_scope(owner)
        try:
            async with db.session(write=True) as session:
                external = ScheduleExternalRepository(session)
                stream = await external.ensure_activation_epoch(
                    project_id=project_id,
                    owner=owner,
                    source_scope=source_scope,
                    occurred_at=datetime.now(UTC),
                    adapter_instance_id=adapter_instance_id,
                    executor_agent_id=agent_id,
                    executor_registry_owner_id=(session_handle.registry_owner_id),
                    executor_session_generation=str(
                        session_handle.generation,
                    ),
                    executor_worker_id=session_handle.worker_id,
                )
                if stream.phase == "RESTORE_REACTIVATION_REQUIRED":
                    stream = await external.ensure_activation_epoch(
                        project_id=project_id,
                        owner=owner,
                        source_scope=source_scope,
                        occurred_at=datetime.now(UTC),
                        adapter_instance_id=adapter_instance_id,
                        executor_agent_id=agent_id,
                        executor_registry_owner_id=(session_handle.registry_owner_id),
                        executor_session_generation=str(
                            session_handle.generation,
                        ),
                        executor_worker_id=session_handle.worker_id,
                        reactivate_restored=True,
                    )
                replaced_undelivered = False
                if (
                    stream.phase == "ACTIVATING"
                    and stream.accepted_sequence == 0
                    and stream.activation_requirement is None
                    and stream.authorized_adapter_instance_id != adapter_instance_id
                ):
                    replaced_undelivered = await external.abandon_undelivered_activation(
                        project_id=project_id,
                        stream_id=stream.id,
                        occurred_at=datetime.now(UTC),
                    )
                    if replaced_undelivered:
                        stream = await external.ensure_activation_epoch(
                            project_id=project_id,
                            owner=owner,
                            source_scope=source_scope,
                            occurred_at=datetime.now(UTC),
                            adapter_instance_id=adapter_instance_id,
                            executor_agent_id=agent_id,
                            executor_registry_owner_id=(session_handle.registry_owner_id),
                            executor_session_generation=str(
                                session_handle.generation,
                            ),
                            executor_worker_id=session_handle.worker_id,
                            replace_retired=True,
                        )
                if (
                    stream.phase != "ACTIVATING"
                    or stream.accepted_sequence != 0
                    or stream.activation_requirement is not None
                    or stream.authorized_adapter_instance_id != adapter_instance_id
                ):
                    await session.rollback()
                    continue
                payload = {
                    "scheduler": owner,
                    "owner": owner,
                    "source_scope": source_scope,
                    "stream_id": str(stream.id),
                    "epoch_uuid": str(stream.current_epoch_uuid),
                    "epoch_number": stream.current_epoch_number,
                    "adapter_instance_id": adapter_instance_id,
                    "stable_source": True,
                    "registry_owner_id": str(
                        session_handle.registry_owner_id,
                    ),
                    "session_generation": str(session_handle.generation),
                }
                command, created = await CommandRepository(session).insert(
                    project_id=project_id,
                    agent_id=agent_id,
                    issued_by=None,
                    action="schedule.external.activate",
                    target_type="scheduler",
                    target_id=owner,
                    payload=payload,
                    idempotency_key=(
                        f"external-activation:{stream.current_epoch_uuid}:{adapter_instance_id}"
                    ),
                    timeout_at=datetime.now(UTC)
                    + timedelta(
                        seconds=settings.command_timeout_seconds,
                    ),
                    source_ip=None,
                    enforce_payload_identity=True,
                )
                if not created:
                    await session.rollback()
                    continue
                await dispatcher.audit.record(
                    AuditLogRepository(session),
                    action="schedule.external.activate",
                    target_type="schedule_external_stream",
                    target_id=str(stream.id),
                    result="success",
                    outcome="allow",
                    project_id=project_id,
                    metadata={
                        "command_id": str(command.id),
                        "agent_id": str(agent_id),
                        "worker_id": session_handle.worker_id,
                        "registry_owner_id": str(
                            session_handle.registry_owner_id,
                        ),
                        "session_generation": str(
                            session_handle.generation,
                        ),
                        "owner": owner,
                        "source_scope": source_scope,
                        "epoch_uuid": str(stream.current_epoch_uuid),
                        "epoch_number": stream.current_epoch_number,
                        "adapter_instance_id": adapter_instance_id,
                        "replaced_undelivered_activation": (replaced_undelivered),
                    },
                )
                await session.commit()
                command_id = command.id
            if await registry.deliver_exact(
                command_id=command_id,
                session=session_handle,
            ):
                delivered += 1
        except Exception:
            logger.exception(
                "z4j gateway: external schedule activation issue failed",
                project_id=str(project_id),
                agent_id=str(agent_id),
                owner=owner,
            )
    return delivered


async def _drain_pending_for_agent(
    *,
    db: DatabaseManager,
    settings: Settings,
    agent_id: uuid.UUID,
    session_handle: SessionHandle,
    registry: BrainRegistry | None = None,
) -> None:
    """Push every pending command targeting this agent.

    Called once after registration. Closes the gap when the agent
    was offline at the moment a command was issued - the row was
    persisted with ``status='pending'`` and is now waiting for us.
    """
    from sqlalchemy import and_, or_, select

    from z4j_brain.domain.retry_contract import RETRY_FAMILY_ACTIONS
    from z4j_brain.persistence.enums import CommandStatus
    from z4j_brain.persistence.models import Command

    retry_engines = tuple(
        engine for engine, version in session_handle.retry_contracts if version == 1
    )
    session_eligible = or_(
        ~Command.action.in_(RETRY_FAMILY_ACTIONS),
        and_(
            Command.action == "retry_task",
            Command.payload["engine"].as_string().in_(retry_engines),
        ),
        and_(
            Command.action == "bulk_retry",
            Command.payload["filter"]["engine"].as_string().in_(retry_engines),
        ),
    )
    async with db.session() as session:
        result = await session.execute(
            select(Command)
            .where(
                Command.agent_id == agent_id,
                Command.status == CommandStatus.PENDING,
                session_eligible,
            )
            .order_by(Command.issued_at.asc())
            .limit(500),
        )
        commands = list(result.scalars().all())

    for cmd in commands:
        # Boundary A: this reconnect drain belongs to exactly the newly
        # registered session generation. An old colocated adapter cannot claim
        # a retry merely because another worker under the agent id attested.
        if not session_handle.supports_retry_engine(required_retry_engine(cmd.action, cmd.payload)):
            continue
        if registry is not None:
            # Production reaches the database claim and physical send only
            # while this exact immutable generation remains registered.  The
            # registry holds its map lock across the callback, so a replacement
            # cannot slip between those edges.
            await registry.deliver_exact(
                command_id=cmd.id,
                session=session_handle,
            )
            continue
        # Claim FIRST, push second. Otherwise the registry's
        # reconcile loop could see this same PENDING command and
        # concurrently push it to the same agent - causing
        # duplicate execution for destructive commands
        # (purge_queue, restart_worker, bulk_retry) when the
        # agent's in-memory dedup TTL was exceeded or the agent
        # process restarted between the two pushes. Long-poll
        # path uses claim-then-push (agent_longpoll.py); the WS
        # path matches.
        async with db.session() as session:
            from z4j_brain.persistence.repositories import CommandRepository

            commands = CommandRepository(session)
            is_current, current_command = await commands.claim_current_schedule_delivery(
                cmd.id,
                project_id=cmd.project_id,
                agent_id=session_handle.agent_id,
                transport_kind="websocket",
                registry_owner_id=session_handle.registry_owner_id,
                session_generation=str(session_handle.generation),
                timeout_seconds=settings.command_timeout_seconds,
            )
            if is_current:
                generation = current_command.dispatched_at if current_command is not None else None
                command_to_send = current_command or cmd
            else:
                generation = await commands.mark_dispatched(
                    cmd.id,
                    timeout_seconds=settings.command_timeout_seconds,
                )
                command_to_send = cmd
            await session.commit()
        if not generation:
            # Another worker / replica already claimed it.
            continue
        try:
            await deliver_command_frame(
                websocket=session_handle.websocket,
                settings=settings,
                command=command_to_send,
            )
        except Exception:
            if command_to_send.schedule_protocol_marker is not None:
                logger.warning(
                    "z4j gateway: current cadence drain send became ambiguous "
                    "after its immutable claim; refusing generic revert",
                    command_id=str(command_to_send.id),
                )
                continue
            # Only revert a REDELIVERABLE command on a send failure -- the
            # send exception does not prove a non-idempotent action never reached
            # and executed at the agent, so reverting a destructive command would
            # re-drive a possibly-already-run side effect. Leave it DISPATCHED for
            # CommandTimeoutWorker (at-most-once).
            from z4j_brain.persistence.repositories.commands import (
                CommandRepository,
                action_is_redeliverable,
            )

            if not action_is_redeliverable(command_to_send.action):
                logger.warning(
                    "z4j gateway: drain push failed AFTER claim for a "
                    "non-redeliverable action %s; leaving DISPATCHED "
                    "(at-most-once). Continuing with the next command.",
                    command_to_send.action,
                    command_id=str(command_to_send.id),
                )
                continue
            logger.exception(
                "z4j gateway: drain push failed AFTER claim - reverting the "
                "DISPATCHED claim so the command is re-drivable. Continuing "
                "with the next command.",
                command_id=str(command_to_send.id),
            )
            # The claim (mark_dispatched) was committed but the push
            # failed, so the agent never received the frame. Revert the claim
            # DISPATCHED->PENDING (mirroring deliver_local's failed-push revert)
            # so the invariant DISPATCHED == physically delivered holds.:
            # pass the generation so a concurrent redispatch is never clobbered.
            try:
                async with db.session() as revert_session:
                    await CommandRepository(revert_session).revert_dispatch(
                        command_to_send.id,
                        timeout_seconds=settings.command_timeout_seconds,
                        expected_dispatched_at=generation,
                    )
                    await revert_session.commit()
            except Exception:
                logger.exception(
                    "z4j gateway: failed to revert DISPATCHED claim after a "
                    "drain push failure; CommandTimeoutWorker will retire it.",
                    command_id=str(command_to_send.id),
                )
            # Continue draining so a single push failure doesn't
            # strand the whole batch.
            continue


# ---------------------------------------------------------------------------
# Frame push (used by both the drain path AND the registry deliver_local)
# ---------------------------------------------------------------------------


async def deliver_command_frame(
    *,
    websocket: WebSocket,
    settings: Settings,
    command: Command,
) -> None:
    """Sign + serialize + send a single command to the agent.

    v2 signs the full envelope (``ts, nonce, seq, agent_id,
    project_id, payload``) via the per-session :class:`FrameSigner`
    attached to this websocket at handshake time. The agent's
    :class:`FrameVerifier` enforces strict seq monotonicity and
    nonce freshness, so the signer MUST be the same instance for
    every command on this connection - that's why it's attached to
    the websocket rather than constructed per-call.
    """
    signer: FrameSigner | None = getattr(websocket, "_z4j_signer", None)
    if signer is None:
        raise RuntimeError(
            "deliver_command_frame called on a websocket without an "
            "attached FrameSigner (handshake did not complete)",
        )
    payload = CommandPayload(
        action=command.action,
        target=wire_target(command.target_type, command.target_id, command.payload),
        parameters=command.payload,
        timeout_seconds=settings.command_timeout_seconds,
        issued_by=str(command.issued_by) if command.issued_by else None,
        delivery_claim_token=(
            str(command.delivery_claim_token) if command.delivery_claim_token is not None else None
        ),
    )
    frame = CommandFrame(
        id=str(command.id),
        payload=payload,
    )
    validate_generation = getattr(
        websocket,
        "_z4j_validate_registry_generation",
        None,
    )
    if validate_generation is not None and not await validate_generation():
        raise RuntimeError(
            "selected websocket generation was replaced before physical delivery",
        )
    await websocket.send_bytes(signer.sign_and_serialize(frame))


__all__ = ["deliver_command_frame", "router"]
