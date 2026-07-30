"""Inbound frame dispatch.

The gateway's receive loop hands every parsed frame to
:meth:`FrameRouter.dispatch`. The router routes by frame type to
the right domain service:

- ``event_batch`` → :class:`EventIngestor.ingest_batch`
- ``heartbeat`` → bump ``agents.last_seen_at``
- ``command_ack`` → :meth:`CommandDispatcher.handle_ack`
- ``command_result`` → :meth:`CommandDispatcher.handle_result`
- ``registry_delta`` → log only in B4 (full handling in B5)
- anything else → log + ignore

The router is created per-connection so it can hold a reference to
the connection's authenticated ``agent_id`` + ``project_id`` -
agents cannot inject events claiming to belong to a different
project.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any
from uuid import UUID

import structlog
from z4j_core.transport.frames import (
    AgentStatusFrame,
    CommandAckFrame,
    CommandResultFrame,
    ErrorFrame,
    ErrorPayload,
    EventBatchAckFrame,
    EventBatchAckPayload,
    EventBatchFrame,
    Frame,
    HeartbeatFrame,
    RegistryDeltaFrame,
)

from z4j_brain.domain.event_ingestor import _is_transient_db_error


class FrameOutcome(Enum):
    """Per-frame dispatch verdict -- the brain's instruction to the agent.

    The agent's delivery bookkeeping only needs to know CONFIRM vs RETRY,
    but the brain distinguishes DURABLE from DROP for its own logging.

    * ``DURABLE``   -- the frame was stored / handled. The agent confirms
      (deletes) it. Wire signal: WS ack sent / long-poll counts it accepted.
    * ``TRANSIENT`` -- a transient failure (deadlock, pool timeout, a
      transiently-skipped event). The agent RETRIES: WS ack withheld (the
      watchdog re-sends) / long-poll counts it rejected. The frame is
      deliverable and will succeed on a later attempt.
    * ``DROP``      -- a PERMANENT / deterministic failure (a content or
      schema error, a malformed payload, a non-DB bug). Re-sending the
      identical frame fails identically forever, so the brain drops it and
      tells the agent to confirm (delete) it too -- otherwise the agent
      would loop on it, pinning its buffer head and overflow-losing later
      frames. Logged loudly. Wire signal is the SAME as DURABLE (confirm);
      only the brain-side bookkeeping differs.
    * ``UPGRADE_REQUIRED`` -- an authenticated legacy schedule event reached
      an active Boundary-D brain. The frame stays unconfirmed and the
      WebSocket peer receives a typed fatal upgrade response.
    """

    DURABLE = "durable"
    TRANSIENT = "transient"
    DROP = "drop"
    UPGRADE_REQUIRED = "upgrade_required"

    @property
    def confirmed(self) -> bool:
        """True when the agent should delete the frame (DURABLE or DROP)."""
        return self not in {
            FrameOutcome.TRANSIENT,
            FrameOutcome.UPGRADE_REQUIRED,
        }


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.domain import CommandDispatcher, EventIngestor
    from z4j_brain.domain.notifications import NotificationService
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.websocket.dashboard_hub import DashboardHub


logger = structlog.get_logger("z4j.brain.frame_router")

#: Backpressure cap on detached notification dispatch tasks per
#: connection. Each task runs ``evaluate_and_dispatch``
#: in its own DB session and may make external HTTP calls; an event
#: flood from a misbehaving agent shouldn't be allowed to spawn
#: thousands of in-flight tasks. The cap is per-FrameRouter (i.e.
#: per agent connection); a busy fleet of 100 agents = 100 x cap
#: ceiling. 256 leaves room for a 200-event burst with a normal
#: subscription fanout.
_MAX_PENDING_NOTIFICATION_TASKS = 256

#: Cap on the agent-controlled ``exception`` blob persisted to the durable
#: outbox (the outbox fills under failure storms with large tracebacks).
_OUTBOX_EXCEPTION_CAP = 8192

#: TTL for the per-connection "does this project have rules for T" memo.
_HAS_RULES_TTL_SECONDS = 15.0

# SECURITY: defense-in-depth allowlist for worker_metadata.conf
# persistence. The CANONICAL source of this list lives at
# ``packages/z4j-celery/src/z4j_celery/engine.py::_CONF_ALLOWLIST`` and
# the adapter already filters before shipping. We re-apply the SAME
# filter here so that a compromised or downgraded agent (or any other
# adapter version that forgets to filter) cannot smuggle credentialed
# Celery conf keys (``broker_url``, ``result_backend``,
# ``broker_transport_options``, ``beat_schedule``, ...) into the brain
# DB, where they would be exposed to ProjectRole.VIEWER over the worker
# detail endpoint. Round-7 audit finding. Keep the two lists in
# sync; the audit-suite scans for divergence is a TODO for 1.7.
_WORKER_CONF_ALLOWLIST: frozenset[str] = frozenset(
    {
        # Serialization
        "task_serializer",
        "result_serializer",
        "accept_content",
        # Queue routing
        "task_default_queue",
        # Worker concurrency / lifecycle
        "worker_concurrency",
        "worker_prefetch_multiplier",
        "worker_max_tasks_per_child",
        "worker_max_memory_per_child",
        # Reliability semantics
        "task_acks_late",
        "task_reject_on_worker_lost",
        # Time limits
        "task_time_limit",
        "task_soft_time_limit",
        # Broker pooling (knobs, not creds; broker_url is excluded)
        "broker_pool_limit",
        "broker_heartbeat",
        # Time zone
        "timezone",
        "enable_utc",
    }
)


def _filter_worker_conf(cfg: Any) -> dict[str, Any]:
    """Strip credentialed keys from inbound worker conf payload.

    Defense-in-depth twin of
    ``z4j_celery.engine._redact_worker_conf``. Returns a plain ``dict``
    (empty if input is not dict-like) so the JSONB column write is
    always safe and non-null. See ``_WORKER_CONF_ALLOWLIST`` doc for
    threat model.
    """
    if not isinstance(cfg, dict):
        return {}
    return {k: v for k, v in cfg.items() if k in _WORKER_CONF_ALLOWLIST}


def _fingerprint_of(data: dict[str, Any]) -> str | None:
    """Failure fingerprint from an event's ``data`` (None for a
    non-failure event with no exception/traceback).

    Prefers the fingerprint the event ingestor already computed and
    stamped onto the event (from the scrubbed, full-length traceback) so
    a ``fingerprint``-keyed rule matches the SAME value the Issues view
    stores. Falls back to computing from the event data for any event
    that was not ingest-stamped (defence in depth)."""
    stamped = data.get("fingerprint")
    if isinstance(stamped, str) and stamped:
        return stamped

    from z4j_brain.domain.fingerprint import compute_fingerprint

    return compute_fingerprint(data.get("exception"), data.get("traceback"))


#: Hard cap on the number of notification dispatch tasks that can
#: hold an OPEN DB session
#: at once. Each ``_dispatch_notification`` call opens its own
#: ``db.session()`` inside the task body. Without this bound, the
#: 256-task ceiling above lets ~256 sessions drain the brain's pool
#: (default ~30 sync-equivalent connections) well before the task
#: cap kicks in. Setting the semaphore at half the typical pool
#: size keeps headroom for concurrent REST handlers + workers.
_NOTIFY_DB_SESSION_BOUND = 16
_notify_db_session_sem: asyncio.Semaphore | None = None


def _get_notify_db_session_semaphore() -> asyncio.Semaphore:
    """Lazy-init the per-process semaphore on first use.

    Created lazily because module import predates the running event
    loop in the unit-test fixtures; ``asyncio.Semaphore`` binds to
    the loop at construction.
    """
    global _notify_db_session_sem  # noqa: PLW0603  module-level singleton lazy-init
    if _notify_db_session_sem is None:
        _notify_db_session_sem = asyncio.Semaphore(_NOTIFY_DB_SESSION_BOUND)
    return _notify_db_session_sem


#: Automation gets its OWN DB-session semaphore, separate from the
#: notification bound, so an observability flood (many slow notify tasks
#: holding their slots across external HTTP delivery) can never starve
#: governed automation actions -- retry / cancel are safety controls and
#: must not queue behind Slack/webhook traffic.
_AUTOMATION_DB_SESSION_BOUND = 8
_automation_db_session_sem: asyncio.Semaphore | None = None


def _get_automation_db_session_semaphore() -> asyncio.Semaphore:
    """Lazy-init the per-process automation-dispatch semaphore."""
    global _automation_db_session_sem  # noqa: PLW0603  module-level singleton lazy-init
    if _automation_db_session_sem is None:
        _automation_db_session_sem = asyncio.Semaphore(_AUTOMATION_DB_SESSION_BOUND)
    return _automation_db_session_sem


def _is_benign_disconnect(exc: BaseException) -> bool:
    """True if an outbound-send failure is just the agent having already
    disconnected (keepalive timeout / reconnect), not a real error.

    A flaky link drops the connection mid-send, and every in-flight
    outbound frame (event_batch_ack, ...) then raises an ASGI/websockets
    "send after close" error. A missed ack is SELF-HEALING -- the agent
    re-ships unacked entries on reconnect and the brain dedupes by the
    content-derived event_id -- so these are DEBUG, not a per-send
    traceback storm that would drown real errors in the log.
    """
    msg = str(exc).lower()
    return (
        "close message has been sent" in msg
        or "after sending 'websocket.close'" in msg
        or "websocket is not connected" in msg
        or "connection is closed" in msg
        or "connection closed" in msg
        or "disconnect" in msg
    )


def _log_notify_task_exception(task: asyncio.Task[object]) -> None:
    """Done-callback for fire-and-forget notification dispatch tasks.

    Logs unhandled exceptions so a silent GC or asyncio loop
    teardown doesn't swallow them. Audit P-4 + P-10 (added
    v1.0.14). The dispatch coroutine
    (``FrameRouter._dispatch_notification``) already wraps its body
    in try/except + logger.exception, so this callback is mostly
    insurance against asyncio-level cancellation surprises.
    """
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.warning(
            "z4j frame_router: notification dispatch task exited with exception",
            task_name=task.get_name(),
            error_class=type(exc).__name__,
            error=str(exc)[:500],
        )


# Phase H rate cap. The agent's heartbeat module emits
# one agent_status per heartbeat (default 10s = 6/min). A misbehaving
# agent could ship them at line rate; we drop frames over this cap
# rather than amplify into per-frame DB writes. 12/min is 2x the
# nominal rate so transient catch-up after a backoff recovery still
# fits inside the window.
_AGENT_STATUS_RATE_PER_MINUTE = 12

# command_ack / command_result frames are fire-and-forget on the WS
# transport: the agent deletes the outbound control frame the instant it
# is written, so a transient DB failure while persisting the ack/result
# has no agent-side resend to recover it (unlike event_batch, which the
# agent retries until the brain confirms durable storage). The brain must
# therefore own a bounded internal retry for the control-plane persist so
# a momentary deadlock / serialization failure does not silently drop a
# command outcome. Permanent failures still fall through to dispatch,
# which classifies + logs them.
_CONTROL_FRAME_DB_RETRIES = 3
_CONTROL_FRAME_RETRY_BACKOFF = 0.1


class FrameRouter:
    """Per-connection inbound-frame dispatcher."""

    def __init__(
        self,
        *,
        db: DatabaseManager,
        ingestor: EventIngestor,
        dispatcher: CommandDispatcher,
        project_id: UUID,
        agent_id: UUID,
        dashboard_hub: DashboardHub | None = None,
        worker_id: str | None = None,
        transport_kind: str | None = None,
        registry_owner_id: UUID | None = None,
        session_generation: str | None = None,
        send_frame: Callable[[Frame], Awaitable[None]] | None = None,
        automation_notify_coalesce_seconds: int = 0,
        automation_outbox_max_rows_per_project: int = 10_000,
    ) -> None:
        self._db = db
        self._ingestor = ingestor
        self._dispatcher = dispatcher
        self._project_id = project_id
        self._agent_id = agent_id
        self._dashboard_hub = dashboard_hub
        #: Notify-coalesce window threaded into the automation executor so a
        #: distinct-event flood cannot fan out one notification per event.
        self._automation_notify_coalesce_seconds = automation_notify_coalesce_seconds
        #: Per-project ceiling on the durable firing outbox; above it we
        #: hard-drop (counted) instead of deferring, so a flood can't grow
        #: the outbox unbounded.
        self._automation_outbox_max_rows = automation_outbox_max_rows_per_project
        #: Short-TTL memo of "does this project have any enabled rule for
        #: trigger T" so the outbox-defer path can skip a project with no
        #: automation without a query per event. {trigger: (has_rules, expiry)}.
        self._has_rules_cache: dict[str, tuple[bool, float]] = {}
        # Worker-first persistence (1.2.1+): the per-connection
        # worker_id from the hello payload, threaded through here
        # so heartbeat handling can refresh THIS worker's row in
        # agent_workers (rather than guessing from the heartbeat
        # frame itself, which doesn't carry worker_id).
        self._worker_id = worker_id
        # Immutable inbound transport authority.  Current cadence ACK/result
        # transitions use these server-derived values; they never trust worker
        # id, agent id alone, or a fresh registry lookup after receipt.
        self._transport_kind = transport_kind
        self._registry_owner_id = registry_owner_id
        self._session_generation = session_generation
        # Callback to send a signed frame back
        # over the same connection. Used to emit ``event_batch_ack``
        # after a successful ingest commit so the agent can confirm-
        # and-evict the matching buffer entries. ``None`` for
        # connections that don't support outbound frames (none in
        # practice but kept optional so unit tests that construct a
        # bare FrameRouter don't have to wire a stub).
        self._send_frame = send_frame
        # Strong references to outstanding ack-send tasks (created
        # by ``asyncio.create_task`` in ``_handle_event_batch``).
        # Without this the asyncio loop GCs the coroutine before
        # the websocket write completes. Tasks remove themselves on
        # completion via ``discard`` callback.
        self._pending_ack_tasks: set[asyncio.Task[None]] = set()
        # Strong references to detached notification dispatch tasks.
        # Without this the asyncio event loop may GC the task before
        # its coroutine completes, swallowing any exception. Tasks
        # remove themselves on completion via the done callback.
        self._pending_notify_tasks: set[asyncio.Task[None]] = set()
        # Same strong-reference + backpressure discipline for detached
        # automation-rule dispatch tasks. Kept separate from the notify
        # set so the two backpressure caps don't interfere: a flood of
        # notifications must not starve rule evaluation, and vice versa.
        self._pending_automation_tasks: set[asyncio.Task[None]] = set()
        # Per-agent rate cap on inbound agent_status frames. The
        # agent's heartbeat module emits one every ~10s by design
        # (6/min); a misbehaving agent post-handshake (or a hostile
        # one with a stolen bearer that passed HMAC verification)
        # could ship them at line rate and force one DB INSERT each.
        # The sliding-window cap bounds the worst-case write rate
        # per (agent_id) connection.
        # 12/minute = 6x the nominal rate, so a stuck-at-1Hz agent
        # is throttled but a healthy agent that briefly bunches
        # frames after a backoff recovery still makes it through.
        self._agent_status_window: deque[float] = deque(
            maxlen=_AGENT_STATUS_RATE_PER_MINUTE,
        )
        # One WARNING per overflow burst, not per dropped frame.
        # A hostile peer holding a valid bearer
        # + HMAC could otherwise pump frames at line rate and turn
        # the rate cap into a log-volume amplifier (one structlog
        # JSON line per frame). Edge-triggered: warn on rising
        # edge, info on falling edge, silent in steady state.
        # Counter records the dropped-frame count so the
        # falling-edge log line still tells the operator how big
        # the burst was.
        self._agent_status_overflow_active: bool = False
        self._agent_status_overflow_dropped: int = 0

    def aclose(self) -> None:
        """Cancel pending background tasks and clear strong references.

        Called from the gateway's connection-cleanup ``finally`` so the
        router (and its captured closures) become collectible without
        waiting on Python's cyclic GC. Without this, the
        ``_send_frame`` closure pins ``websocket`` -> ``_z4j_verifier``
        -> ``ReplayGuard`` (4096 nonces) per disconnected session, and
        a high-churn reconnect rate accumulates the per-session state
        in memory. Idempotent and safe to call multiple times.

        ALL three detached-task sets are cancelled -- ack, notify, AND
        automation. A leaked automation task holds a DB-session-semaphore
        slot and keeps this router (and its per-connection caps) alive, so
        under reconnect churn old routers would accumulate and the
        per-connection pending cap would not bound total in-flight work.
        (Firings that genuinely need durability under backpressure already
        go to the durable automation_firing_outbox; the inline detached
        tasks here are best-effort and safe to cancel on disconnect.)
        """
        for t in list(self._pending_ack_tasks):
            t.cancel()
        for t in list(self._pending_notify_tasks):
            t.cancel()
        for t in list(self._pending_automation_tasks):
            t.cancel()
        self._send_frame = None

    async def _send_frame_safe(self, out: Frame) -> None:
        """Send ``out`` via the per-connection send_frame callback.

        Wraps any exception so a failed websocket write doesn't
        propagate out of an unawaited task and crash the surrounding
        connection. The agent's reconnect path re-ships unacked
        entries; the brain dedupes via the content-derived event_id
        (Bug X-B fix).
        """
        if self._send_frame is None:
            return
        try:
            await self._send_frame(out)
        except Exception as exc:
            if _is_benign_disconnect(exc):
                # Agent already disconnected mid-send (keepalive timeout /
                # reconnect). Self-healing: it re-ships unacked entries on
                # reconnect + the brain dedupes by event_id. DEBUG so a
                # flaky link cannot flood the error log with tracebacks.
                logger.debug(
                    "z4j frame_router: outbound frame skipped; agent already disconnected",
                    agent_id=str(self._agent_id),
                    frame_type=getattr(out, "type", None),
                )
            else:
                logger.exception(
                    "z4j frame_router: outbound frame send failed",
                    agent_id=str(self._agent_id),
                    frame_type=getattr(out, "type", None),
                )

    async def dispatch(self, frame: Frame) -> FrameOutcome:
        """Route ``frame`` to the right service. Never raises.

        Returns a :class:`FrameOutcome`. For an ``event_batch`` the outcome
        comes from :meth:`_handle_event_batch`. For a control frame the
        handler runs and, if it raises, the exception is CLASSIFIED: a
        transient DB error -> ``TRANSIENT`` (the agent re-sends), a
        permanent one (a deterministic constraint / data error from an
        agent-supplied payload, e.g. a NUL byte in a command_result) ->
        ``DROP`` (the agent confirms + deletes it so it does not loop). A
        clean run -> ``DURABLE``.

        The long-poll ``POST /events`` route consumes the same verdict:
        DURABLE and DROP count accepted; TRANSIENT retries; and
        UPGRADE_REQUIRED remains unconfirmed with a typed fatal response.
        On the WebSocket path event_batch acks are emitted inside
        :meth:`_handle_event_batch`; control frames are confirmed on send by
        the agent, so the gateway ignores this return for them.

        The whole body (INCLUDING the event_batch path) is inside the
        try/except so ``dispatch`` truly NEVER raises: the WS ingest worker
        (``gateway.py``) has no per-frame error handling and relies on that
        contract, so a raise here (e.g. an unexpected error while building an
        ack) would crash the worker and wedge the connection. An
        unexpected failure classifies TRANSIENT (agent re-sends) not lost.
        """
        try:
            if isinstance(frame, EventBatchFrame):
                return await self._handle_event_batch(frame)
            if isinstance(frame, HeartbeatFrame):
                await self._handle_heartbeat(frame)
            elif isinstance(frame, CommandAckFrame):
                await self._handle_command_ack(frame)
            elif isinstance(frame, CommandResultFrame):
                await self._handle_command_result(frame)
            elif isinstance(frame, AgentStatusFrame):
                await self._handle_agent_status(frame)
            elif isinstance(frame, RegistryDeltaFrame):
                # B5 wires this into the task discovery pipeline.
                logger.debug(
                    "z4j frame_router: registry_delta received (logged-only in B4)",
                    agent_id=str(self._agent_id),
                )
            else:
                logger.warning(
                    "z4j frame_router: unhandled frame type",
                    frame_type=getattr(frame, "type", None),
                )
        except Exception as exc:
            outcome = FrameOutcome.TRANSIENT if _is_transient_db_error(exc) else FrameOutcome.DROP
            logger.exception(
                "z4j frame_router: control-frame handler raised; connection survives",
                frame_type=getattr(frame, "type", None),
                agent_id=str(self._agent_id),
                project_id=str(self._project_id),
                error_class=type(exc).__name__,
                outcome=outcome.value,
            )
            return outcome
        return FrameOutcome.DURABLE

    # ------------------------------------------------------------------
    # event_batch
    # ------------------------------------------------------------------

    def _extract_events(self, frame: EventBatchFrame, cap: int) -> list[dict[str, Any]]:
        """Extract + cap the event list from an event_batch payload.

        Raises ``TypeError`` on a non-list ``events`` (a WS fast-path frame is
        ``model_construct``'d, so Pydantic is bypassed and ``events`` may be
        null / a non-list). The caller runs this INSIDE its try so a malformed
        payload classifies as a DROP (and the finally still acks it), rather
        than ``list(non_list)`` silently coercing a str/dict into invalid
        elements that ingest to nothing yet ack DURABLE (round-9 LOW).
        """
        raw_events = frame.payload.events
        if raw_events is None:
            # Absent / null == an empty batch (the schema default is an
            # empty list). Nothing to ingest, commits cleanly -> DURABLE.
            events: list[dict[str, Any]] = []
        elif isinstance(raw_events, list):
            events = raw_events
        else:
            raise TypeError(
                f"event_batch payload.events must be a list, got {type(raw_events).__name__}"
            )
        if len(events) > cap:
            logger.warning(
                "z4j frame_router: event_batch over cap; trimming",
                project_id=str(self._project_id),
                agent_id=str(self._agent_id),
                received=len(events),
                cap=cap,
            )
            events = events[:cap]
        return events

    async def _handle_event_batch(  # noqa: PLR0915  transactional ingest and wire outcome
        self,
        frame: EventBatchFrame,
    ) -> FrameOutcome:
        """Ingest an event batch. Returns a :class:`FrameOutcome`:

        * ``DURABLE``   -- committed with no transiently-skipped event; the
          agent confirms (WS ack sent / long-poll counts accepted).
        * ``TRANSIENT`` -- the commit succeeded but an event was
          transiently skipped, OR ingest/commit hit a transient DB error
          (deadlock, pool timeout). The ack is withheld (WS) / the frame
          counts rejected (long-poll) so the agent re-sends; the committed
          events dedup on the replay (-panel-HIGH).
        * ``DROP``      -- ingest/commit failed for a PERMANENT reason (a
          deterministic constraint / data error at commit that recurs on
          every replay). The batch is dropped-and-acked (logged loudly) so
          the agent does not loop on it forever; the events in it are lost,
          which is the bounded cost of not wedging the whole send loop.
        * ``UPGRADE_REQUIRED`` -- Boundary D rejected a legacy unsequenced
          schedule projection. The batch remains unacknowledged and the
          transport sends a typed fatal upgrade requirement.

        A permanent per-EVENT error is already dropped-and-acked INSIDE
        ``ingest_batch`` (so the batch stays DURABLE); this ``DROP`` outcome
        is only for a BATCH-level permanent failure (a deterministic commit
        error), which is rare.
        """
        # The agent's frame.payload.events list is exactly what
        # EventIngestor expects - a list of dicts with engine /
        # kind / task_id / occurred_at / data fields.
        from z4j_brain.persistence.repositories import (
            AgentRepository,
            EventRepository,
            QueueRepository,
            TaskRepository,
            WorkerRepository,
        )

        # Cap the per-frame
        # event count. The wire-frame validator already enforces
        # ``max_ws_frame_bytes`` (1 MiB by default). The cap is the PROTOCOL
        # maximum (``EventBatchPayload.events`` max_length, z4j_core frames),
        # so no protocol-legal frame is silently truncated while its ack
        # confirms the whole frame by id -- which would lose the tail
        # (/round-8-external). The downstream notification/automation
        # fan-out is independently bounded (detached-task cap + semaphores +
        # durable outbox), so this does not reopen the amplification concern.
        event_batch_cap = 5_000

        accepted_count = 0
        # The NEW (non-duplicate) events this batch actually ingested.
        # Automation fires only on these so an agent-reconnect buffer
        # re-flush (same event_ids) cannot re-fire a rule N times.
        new_events: list[dict[str, Any]] = []
        committed = False
        outcome = FrameOutcome.TRANSIENT
        # Initialised before the try so the finally's ack can reference it
        # even if the events extraction itself raises. The extraction is
        # INSIDE the try (a WS fast-path frame is model_construct'd, so
        # ``payload.events`` may be null/non-list); a failure there is then
        # classified -> DROP and the finally STILL emits the ack, so the
        # agent confirms+deletes the malformed frame instead of the WS
        # ingest worker silently withholding it forever (round-8 external).
        events: list[dict[str, Any]] = []
        try:
            events = self._extract_events(frame, event_batch_cap)
            async with self._db.session() as session:
                result = await self._ingestor.ingest_batch(
                    events=events,
                    project_id=self._project_id,
                    agent_id=self._agent_id,
                    agents=AgentRepository(session),
                    event_repo=EventRepository(session),
                    task_repo=TaskRepository(session),
                    queue_repo=QueueRepository(session),
                    worker_repo=WorkerRepository(session),
                )
                new_events = result.new_events
                accepted_count = len(new_events)
                await session.commit()
                committed = True
                # Emit the deferred Prometheus increments only NOW, after the
                # commit durably persisted the rows -- a transient rollback
                # before this point discards them, so a re-send counts each row
                # exactly once (round-9 external LOW). Best-effort inside.
                result.emit_metrics()
                # DURABLE only when nothing was transiently skipped. A
                # transient skip means the committed events are real (they
                # dedup on replay) but the batch must NOT be confirmed, so
                # the agent re-sends and the skipped event gets another
                # chance (-panel-HIGH).
                if result.upgrade_required:
                    outcome = FrameOutcome.UPGRADE_REQUIRED
                    if self._send_frame is not None:
                        raw_id = getattr(frame, "id", None)
                        frame_id = raw_id if isinstance(raw_id, str) else ""
                        await self._send_frame_safe(
                            ErrorFrame(
                                id=f"err_{frame_id}"[:64],
                                ts=datetime.now(UTC),
                                payload=ErrorPayload(
                                    code="scheduler_upgrade_required",
                                    message=(
                                        "schedule projection requires a current "
                                        "Boundary-D scheduler adapter"
                                    ),
                                    fatal=True,
                                ),
                            ),
                        )
                    logger.warning(
                        "z4j frame_router: rejected legacy schedule event "
                        "with a typed upgrade requirement",
                        project_id=str(self._project_id),
                        agent_id=str(self._agent_id),
                    )
                elif result.fully_durable:
                    outcome = FrameOutcome.DURABLE
                else:
                    outcome = FrameOutcome.TRANSIENT
                    logger.warning(
                        "z4j frame_router: event_batch had transient "
                        "skips; withholding ack so the agent re-sends",
                        project_id=str(self._project_id),
                        agent_id=str(self._agent_id),
                        transient_skips=result.transient_skips,
                    )
        except Exception as exc:
            # ingest_batch or session.commit() raised. Classify so a
            # TRANSIENT DB error (deadlock / pool timeout at commit)
            # withholds the ack for a re-send, while a PERMANENT one (a
            # deterministic constraint / data error that recurs every
            # replay) is dropped-and-acked so the agent does not loop on
            # this batch forever (round-8: a persistent partial-200 /
            # withheld-ack on the no-drop transient path wedged the agent).
            if _is_transient_db_error(exc):
                outcome = FrameOutcome.TRANSIENT
                logger.warning(
                    "z4j frame_router: event_batch transient DB failure; "
                    "withholding ack so the agent re-sends",
                    project_id=str(self._project_id),
                    agent_id=str(self._agent_id),
                    error_class=type(exc).__name__,
                )
            else:
                outcome = FrameOutcome.DROP
                logger.exception(
                    "z4j frame_router: event_batch PERMANENT failure; "
                    "dropping the batch (re-send would fail identically)",
                    project_id=str(self._project_id),
                    agent_id=str(self._agent_id),
                    error_class=type(exc).__name__,
                )
        finally:
            # Emit an ``event_batch_ack`` so the agent confirms-and-evicts
            # the matching buffer entries -- on DURABLE (stored) OR DROP
            # (permanently undeliverable). Withhold on TRANSIENT and
            # UPGRADE_REQUIRED, so neither a database retry nor an obsolete
            # scheduler emitter silently consumes its only buffered copy.
            #
            # Fire-and-forget the send so the next event_batch can start
            # ingesting immediately (awaiting inline would push the ack past
            # the agent's watchdog under high fanout).
            if outcome.confirmed and self._send_frame is not None:
                # Coerce + truncate ``acked_id`` to the payload's strict
                # ``max_length=64``: on the WS fast path the inbound frame is
                # built via ``model_construct`` (HMAC verified, Pydantic
                # constraints bypassed), so a buggy/compromised agent's
                # >64-char, non-str, or MISSING ``id`` would otherwise raise a
                # strict ValidationError HERE (in the finally) and, before 's
                # try-wrap, crash the WS ingest worker. Normalise the id
                # to a str ONCE: a None / non-str id becomes "" (round-9 LOW),
                # which the agent's _handle_event_batch_ack ignores -> it
                # re-sends and the brain dedups, rather than a misleading
                # "None" acked_id.
                #
                # SCOPED LIMITATION (round-10 external LOW): this is crash-
                # HARDENING, not a full protocol-level fix. An empty (or
                # over-64 truncated) acked_id does NOT correlate to a buffer
                # entry, so the agent re-sends and the brain DEDUPES rather than
                # the agent confirming-and-evicting -- loss-free but not a clean
                # confirm. This is only reachable by an HMAC-valid NON-CONFORMING
                # sender: the official agent's outbound path force-purges an
                # unparseable / malformed frame before it is ever sent
                # (UndeliverableFrameError), and a conforming agent's ids are
                # ~15 chars. A complete fix needs a second wire correlation key
                # for malformed-id frames; deferred (no conforming agent hits
                # it).
                raw_id = getattr(frame, "id", None)
                frame_id = raw_id if isinstance(raw_id, str) else ""
                acked_id = frame_id[:64]
                if acked_id != frame_id:
                    # UNREACHABLE for a conforming agent (event_batch ids are
                    # ~15 chars). If it ever fires, the truncated ack cannot
                    # correlate with the agent's full-id pending entry, so the
                    # agent would re-send until the brain-side dedupe/overflow
                    # settles it -- log so a future id-length regression is
                    # observable rather than a silent re-send storm.
                    logger.warning(
                        "z4j frame_router: event_batch id exceeds 64 chars; "
                        "ack acked_id was truncated and may not correlate",
                        agent_id=str(self._agent_id),
                        id_len=len(frame_id),
                    )
                ack = EventBatchAckFrame(
                    id=f"eba_{frame_id}"[:64],
                    ts=datetime.now(UTC),
                    payload=EventBatchAckPayload(
                        acked_id=acked_id,
                        received=len(events),
                        accepted=accepted_count,
                        rejected=max(len(events) - accepted_count, 0),
                    ),
                )
                ack_task = asyncio.create_task(
                    self._send_frame_safe(ack),
                    name=f"z4j_ack_{frame_id}"[:255],
                )
                # Hold a strong reference so the task isn't GC'd
                # mid-flight; it removes itself when done.
                self._pending_ack_tasks.add(ack_task)
                ack_task.add_done_callback(self._pending_ack_tasks.discard)

        # Post-commit side effects run ONLY when the batch actually committed
        # (DURABLE, or an unconfirmed outcome with committed siblings). Never
        # on DROP (nothing persisted). Each is best-effort: an exception here
        # must NOT change ``outcome`` -- the data is already committed and the
        # confirm decision is made.
        if committed:
            await self._run_post_commit_hook("publish", self._publish_task_change())
            # Notifications + automation fire on the NEW events only
            # (``new_events``, deduped): a re-delivered event was already
            # notified/fired on its first delivery, so a reconnect re-flush
            # or a long-poll retry must not re-page subscribers or re-run a
            # rule for the same task state change.
            await self._run_post_commit_hook(
                "notifications",
                self._evaluate_notifications(new_events),
            )
            await self._run_post_commit_hook(
                "automation",
                self._evaluate_automation(new_events),
            )
        return outcome

    async def _run_post_commit_hook(self, name: str, coro: Awaitable[None]) -> None:
        """Await a best-effort post-commit side effect, swallowing errors.

        The caller has already committed the batch; a hook failure must
        not propagate (see ``_handle_event_batch`` /).
        """
        try:
            await coro
        except Exception:
            logger.exception(
                "z4j frame_router: post-commit hook failed (events are committed; not re-sending)",
                hook=name,
                agent_id=str(self._agent_id),
                project_id=str(self._project_id),
            )

    # ------------------------------------------------------------------
    # heartbeat
    # ------------------------------------------------------------------

    async def _handle_heartbeat(self, frame: HeartbeatFrame) -> None:  # noqa: PLR0912, PLR0915  heartbeat handler
        from z4j_brain.persistence.repositories import (
            AgentRepository,
            AgentWorkerRepository,
            QueueRepository,
        )

        async with self._db.session() as session:
            agents_repo = AgentRepository(session)
            await agents_repo.touch_heartbeat(self._agent_id)
            # Promote state back to online if it was
            # wrongly pinned to offline by a late mark_offline that
            # lost a race against this connection's mark_online. The
            # operation is a single indexed UPDATE with a guard,
            # so it's a no-op when the agent is already online (the
            # common case).
            await agents_repo.promote_online_if_offline(self._agent_id)
            # Worker-first persistence (1.2.1+): refresh THIS worker's
            # last_seen_at so the dashboard can distinguish a healthy
            # multi-worker fleet from a partially-degraded one (e.g.
            # 3 of 4 gunicorn workers heartbeating, one wedged).
            await AgentWorkerRepository(session).touch_heartbeat(
                agent_id=self._agent_id,
                worker_id=self._worker_id,
            )

            # Project queue depths from the heartbeat's adapter_health.
            # The agent sends keys like "celery.queue_depths" with
            # a dict of {queue_name: depth}.
            adapter_health = frame.payload.adapter_health or {}
            # Cap the number of adapter_health top-level keys we'll
            # iterate. Nominal
            # production load is single-digit (one per engine + a
            # few well-known suffixes); a malicious or buggy agent
            # supplying 100k keys would otherwise force 100k key
            # ``str.endswith`` checks per heartbeat, fired every 10s
            # per connection. 256 leaves room for new suffixes
            # without ever becoming a meaningful work amplifier.
            adapter_health_keys_cap = 256
            if len(adapter_health) > adapter_health_keys_cap:
                logger.warning(
                    "z4j frame_router: adapter_health key cap exceeded; trimming",
                    project_id=str(self._project_id),
                    received=len(adapter_health),
                    cap=adapter_health_keys_cap,
                )
                adapter_health = dict(
                    list(adapter_health.items())[:adapter_health_keys_cap],
                )
            for key, value in adapter_health.items():
                if key.endswith(".queue_depths") and isinstance(value, str):
                    try:
                        import json as _json

                        depths = _json.loads(value)
                        if isinstance(depths, dict):
                            # cap inner queue_depths dict size to
                            # prevent a malicious agent from
                            # triggering thousands of upserts per
                            # heartbeat tick.
                            queue_depths_cap = 1024
                            if len(depths) > queue_depths_cap:
                                logger.warning(
                                    "z4j frame_router: queue_depths cap exceeded; trimming",
                                    key=key,
                                    received=len(depths),
                                    cap=queue_depths_cap,
                                )
                                depths = dict(
                                    list(depths.items())[:queue_depths_cap],
                                )
                            queue_repo = QueueRepository(session)
                            # 1.5.1: sort by queue name so concurrent
                            # heartbeats walk the row-lock acquisition
                            # path in the same order. Round 18 surfaced
                            # 6 ``UPDATE queues`` deadlocks under 200/s
                            # burst (docs/perf/1.5.1-round17-gate-result.md);
                            # different agents send depths.items() in
                            # different dict-insertion orders, opening
                            # a deadlock cycle on overlapping queue
                            # rows. Sorting the iteration eliminates
                            # that cycle. Cost: O(N log N) on N ~= 10
                            # queues; negligible vs deadlock-retry cost.
                            for queue_name, depth in sorted(depths.items()):
                                engine_name = key.split(".")[0]
                                q_depth = int(depth)
                                # Savepoint per queue so one bad row
                                # doesn't poison the outer tx.
                                try:
                                    async with session.begin_nested():
                                        await queue_repo.update_depth(
                                            project_id=self._project_id,
                                            engine=engine_name,
                                            name=str(queue_name),
                                            pending_count=q_depth,
                                        )
                                except Exception:
                                    logger.debug(
                                        "z4j frame_router: queue depth update failed",
                                        queue=str(queue_name),
                                    )
                                    continue
                                # Prometheus gauge. Best-effort:
                                # a metric-registry glitch must not
                                # break the heartbeat-ingest path.
                                try:
                                    from z4j_brain.api.metrics import z4j_queue_depth

                                    z4j_queue_depth.labels(
                                        project=str(self._project_id),
                                        queue=str(queue_name),
                                        engine=engine_name,
                                    ).set(q_depth)
                                except Exception:
                                    from z4j_brain.api.metrics import (
                                        record_swallowed,
                                    )

                                    record_swallowed(
                                        "frame_router",
                                        "queue_depth_gauge",
                                    )
                    except Exception:
                        logger.debug(
                            "z4j frame_router: failed to parse queue depths",
                            key=key,
                        )

            # SECURITY BOUNDARY: every worker-row dict in this handler
            # MUST set ``project_id=self._project_id`` (the value the
            # gateway captured from the authenticated bearer token at
            # connect time). NEVER read project_id from frame.payload
            # or anywhere on the wire; an attacker who controls a
            # signed agent could otherwise upsert rows into a sibling
            # project's worker table. (1.6.0 round-2 audit Medium-3:
            # cross-tenant routing boundary made explicit.)
            #
            # Project worker details from control.inspect() data.
            # The agent sends "celery.worker_details" with a JSON
            # string of {hostname: {stats: {...}, active: [...], ...}}.
            for key, value in adapter_health.items():
                if key.endswith(".worker_details") and isinstance(value, str):
                    try:
                        import json as _json

                        from z4j_brain.persistence.enums import WorkerState
                        from z4j_brain.persistence.repositories import (
                            QueueRepository,
                            WorkerRepository,
                        )

                        details = _json.loads(value)
                        if isinstance(details, dict):
                            engine = key.split(".")[0]
                            worker_repo = WorkerRepository(session)
                            queue_repo_w = QueueRepository(session)
                            # Collect every hostname's update payload
                            # into one list and emit ONE bulk upsert
                            # at the end. A per-hostname savepointed
                            # upsert would be the dominant cost in
                            # this hot path (heartbeat fires every
                            # 10s per agent connection, so even a
                            # handful of frontends with prefork
                            # pools produces enough concurrent
                            # heartbeats to trigger
                            # PendingRollbackError cascades without
                            # this batching).
                            bulk_rows: list[dict[str, Any]] = []
                            queue_names_to_touch: list[str] = []
                            for hostname, data in details.items():
                                if not isinstance(data, dict):
                                    continue
                                stats = data.get("stats", {})
                                if isinstance(stats, str):
                                    stats = _json.loads(stats)
                                pool = stats.get("pool", {}) if isinstance(stats, dict) else {}
                                rusage = stats.get("rusage", {}) if isinstance(stats, dict) else {}

                                row: dict[str, Any] = {
                                    "project_id": self._project_id,
                                    "engine": engine,
                                    "name": hostname,
                                    "state": WorkerState.ONLINE,
                                    "last_heartbeat": frame.payload.last_flush_at
                                    or datetime.now(UTC),
                                    "hostname": hostname,
                                    "worker_metadata": {
                                        "stats": stats,
                                        "active": data.get("active", []),
                                        "active_queues": data.get("active_queues", []),
                                        "registered": data.get("registered", []),
                                        # SECURITY: re-apply the
                                        # allowlist defense-in-depth so
                                        # a misbehaving / downgraded /
                                        # malicious adapter cannot
                                        # persist credentialed Celery
                                        # conf keys into the JSONB
                                        # column, where they would be
                                        # exposed to VIEWER role via
                                        # ``GET /api/v1/projects/{slug}/workers/{worker_id}``.
                                        "conf": _filter_worker_conf(
                                            data.get("conf", {}),
                                        ),
                                    },
                                }
                                # Pool info
                                if isinstance(pool, dict):
                                    row["concurrency"] = pool.get(
                                        "max-concurrency",
                                        pool.get("processes", None),
                                    )
                                    row["pid"] = stats.get("pid")
                                # Active tasks
                                active = data.get("active", [])
                                if isinstance(active, list):
                                    row["active_tasks"] = len(active)
                                # Active queues
                                aq = data.get("active_queues", [])
                                if isinstance(aq, list):
                                    queue_list = [
                                        q.get("name", "") for q in aq if isinstance(q, dict)
                                    ]
                                    row["queues"] = queue_list
                                    # Collect for separate queue touches below.
                                    # Worker → queue is N:M; one
                                    # worker can announce multiple
                                    # queues, so this stays a flat list.
                                    queue_names_to_touch.extend(
                                        q for q in queue_list if isinstance(q, str) and q
                                    )
                                # Load average
                                if isinstance(rusage, dict):
                                    loadavg = stats.get("loadavg")
                                    if isinstance(loadavg, list):
                                        row["load_average"] = loadavg
                                bulk_rows.append(row)

                            if bulk_rows:
                                # Bulk upsert in one statement, with
                                # the same savepoint + per-row fallback
                                # discipline used in EventIngestor.
                                # Defense in depth: if the bulk path
                                # raises (deadlock or otherwise), fall
                                # back to the original per-row
                                # savepointed loop for this batch only.
                                from sqlalchemy.exc import OperationalError

                                try:
                                    async with session.begin_nested():
                                        await worker_repo.upsert_from_events_bulk(
                                            bulk_rows,
                                        )
                                except OperationalError:
                                    logger.warning(
                                        "z4j frame_router: bulk worker "
                                        "upsert hit OperationalError "
                                        "(likely deadlock); falling back "
                                        "per-row",
                                        engine=engine,
                                        worker_count=len(bulk_rows),
                                    )
                                    for row in bulk_rows:
                                        try:
                                            async with session.begin_nested():
                                                await worker_repo.upsert_from_event(
                                                    project_id=row["project_id"],
                                                    engine=row["engine"],
                                                    name=row["name"],
                                                    updates={
                                                        k: v
                                                        for k, v in row.items()
                                                        if k
                                                        not in (
                                                            "project_id",
                                                            "engine",
                                                            "name",
                                                        )
                                                    },
                                                )
                                        except Exception:
                                            logger.debug(
                                                "z4j frame_router: per-row "
                                                "worker upsert fallback failed",
                                                engine=row["engine"],
                                                hostname=str(row["name"]),
                                            )

                            # Register each queue this worker is consuming
                            # so the Queues page reflects
                            # them even when task events don't carry
                            # a ``queue`` field (Celery only emits
                            # queue names for explicit routing;
                            # default-queue tasks arrive with
                            # queue=None, leaving the Queues page
                            # empty otherwise). Dedupe so two workers
                            # announcing the same queue don't emit
                            # two touches.
                            for qname in dict.fromkeys(queue_names_to_touch):
                                # Each touch runs in its own savepoint.
                                # Without this a single bad queue name
                                # poisons the outer session on Postgres
                                # (``InFailedSqlTransactionError``) and
                                # silently rolls back the worker state
                                # + heartbeats we just wrote.
                                try:
                                    async with session.begin_nested():
                                        await queue_repo_w.touch(
                                            project_id=self._project_id,
                                            engine=engine,
                                            name=qname,
                                        )
                                except Exception:
                                    logger.exception(
                                        "z4j frame_router: queue touch failed",
                                    )
                    except Exception:
                        logger.exception(
                            "z4j frame_router: failed to parse worker details",
                        )

            await session.commit()

    # ------------------------------------------------------------------
    # agent_status (Phase H, 1.5.0+)
    # ------------------------------------------------------------------

    async def _handle_agent_status(self, frame: AgentStatusFrame) -> None:
        """Persist one agent self-report snapshot to ``agent_status_history``.

        The frame's ``payload`` is dumped to a JSON-friendly dict and
        stored as JSONB on Postgres / JSON on SQLite. ``captured_at``
        is the frame's ``ts`` field (when the agent built the
        snapshot), NOT ``datetime.now()`` - the dashboard timeline
        should reflect the agent's clock, not the brain's.

        Rate-capped per audit M-6: a misbehaving (or compromised
        post-handshake) agent shipping frames at line rate would
        otherwise amplify into a DB INSERT per frame. The sliding
        window is per-(connection,agent_id); over-rate frames are
        dropped silently after a single WARNING per overflow.

        Errors during persistence are logged but never break the WS
        connection. agent_status is observability data, not load-
        bearing for the control plane; a transient DB hiccup must
        not flap the agent's session.
        """
        # Rate cap with edge-triggered logging (S-5).
        now_mono = time.monotonic()
        window = self._agent_status_window
        # Trim frames older than 60 seconds.
        while window and now_mono - window[0] > 60.0:
            window.popleft()
        if len(window) >= _AGENT_STATUS_RATE_PER_MINUTE:
            self._agent_status_overflow_dropped += 1
            if not self._agent_status_overflow_active:
                # Rising edge: one WARNING per overflow burst.
                self._agent_status_overflow_active = True
                logger.warning(
                    "z4j frame_router: agent_status rate cap exceeded; "
                    "subsequent frames dropped silently until window drains",
                    agent_id=str(self._agent_id),
                    cap_per_minute=_AGENT_STATUS_RATE_PER_MINUTE,
                )
            return
        if self._agent_status_overflow_active:
            # Falling edge: report the burst size and reset.
            logger.info(
                "z4j frame_router: agent_status rate cap window drained",
                agent_id=str(self._agent_id),
                dropped_in_burst=self._agent_status_overflow_dropped,
            )
            self._agent_status_overflow_active = False
            self._agent_status_overflow_dropped = 0
        window.append(now_mono)

        from z4j_brain.persistence.repositories import (
            AgentStatusHistoryRepository,
        )

        # Use the frame's ``ts`` if present; fall back to now() for
        # the rare case where an agent omits ts (Pydantic allows it
        # to be None on _FrameBase). datetime.now(UTC) keeps the row
        # roughly aligned with the brain's clock so dashboards still
        # render something reasonable.
        captured_at = frame.ts or datetime.now(UTC)

        # ``model_dump(mode="json")`` renders datetimes as ISO strings
        # (matches what the agent sent on the wire) so the JSONB
        # column round-trips through JSON cleanly. Without mode="json"
        # SQLAlchemy's JSON serialiser hits a ``datetime is not JSON
        # serializable`` TypeError on the SQLite path.
        payload_dict = frame.payload.model_dump(mode="json")

        try:
            async with self._db.session() as session:
                await AgentStatusHistoryRepository(session).insert(
                    project_id=self._project_id,
                    agent_id=self._agent_id,
                    captured_at=captured_at,
                    payload=payload_dict,
                )
                await session.commit()
        except Exception:
            logger.exception(
                "z4j frame_router: agent_status persist failed; "
                "snapshot dropped, connection survives",
                agent_id=str(self._agent_id),
                project_id=str(self._project_id),
            )

    # ------------------------------------------------------------------
    # command_ack / command_result
    # ------------------------------------------------------------------

    async def _run_control_persist(
        self,
        label: str,
        command_id: UUID,
        persist: Callable[[AsyncSession], Awaitable[None]],
    ) -> None:
        """Persist a fire-and-forget control frame with bounded retry.

        The agent deletes the control frame on send, so a transient DB
        failure has no agent-side resend to recover it. Retry the persist
        a bounded number of times on a transient (self-healing) DB error;
        re-raise on a permanent error or after the budget is spent so
        dispatch() classifies + logs it (and the long-poll path, where
        the agent CAN retry, sees the TRANSIENT verdict).
        """
        last_exc: Exception | None = None
        for attempt in range(_CONTROL_FRAME_DB_RETRIES):
            try:
                async with self._db.session(write=True) as session:
                    await persist(session)
                    await session.commit()
                return
            except Exception as exc:
                last_exc = exc
                transient = _is_transient_db_error(exc)
                if transient and attempt + 1 < _CONTROL_FRAME_DB_RETRIES:
                    logger.warning(
                        "z4j frame_router: %s persist transient failure; retrying",
                        label,
                        attempt=attempt + 1,
                        command_id=str(command_id),
                        agent_id=str(self._agent_id),
                    )
                    await asyncio.sleep(_CONTROL_FRAME_RETRY_BACKOFF * (attempt + 1))
                    continue
                # Permanent, or transient with the retry budget spent:
                # surface to dispatch(), which classifies + logs.
                raise
        # Unreachable (the loop either returns or raises) but keeps the
        # type checker happy about last_exc's use.
        if last_exc is not None:  # pragma: no cover
            raise last_exc

    async def _handle_command_ack(self, frame: CommandAckFrame) -> None:
        try:
            command_id = UUID(frame.id)
        except ValueError:
            return
        from z4j_brain.persistence.repositories import CommandRepository

        async def _persist(session: AsyncSession) -> None:
            await self._dispatcher.handle_ack(
                commands=CommandRepository(session),
                command_id=command_id,
                project_id=self._project_id,
                agent_id=self._agent_id,
                transport_kind=self._transport_kind,
                registry_owner_id=self._registry_owner_id,
                session_generation=self._session_generation,
                delivery_claim_token=(frame.payload.delivery_claim_token),
            )

        await self._run_control_persist("command_ack", command_id, _persist)
        await self._publish_command_change()

    async def _handle_command_result(self, frame: CommandResultFrame) -> None:
        try:
            command_id = UUID(frame.id)
        except ValueError:
            return
        from z4j_brain.persistence.repositories import (
            AuditLogRepository,
            CommandRepository,
        )

        async def _persist(session: AsyncSession) -> None:
            await self._dispatcher.handle_result(
                commands=CommandRepository(session),
                audit_log=AuditLogRepository(session),
                command_id=command_id,
                status=frame.payload.status,
                result_payload=frame.payload.result,
                error=frame.payload.error,
                project_id=self._project_id,
                agent_id=self._agent_id,
                transport_kind=self._transport_kind,
                registry_owner_id=self._registry_owner_id,
                session_generation=self._session_generation,
                delivery_claim_token=(frame.payload.delivery_claim_token),
            )

        await self._run_control_persist("command_result", command_id, _persist)
        await self._publish_command_change()

    # ------------------------------------------------------------------
    # Dashboard publish helpers
    # ------------------------------------------------------------------

    async def _evaluate_notifications(
        self,
        events: list[dict[str, Any]],
    ) -> None:
        """Fire per-user notification subscriptions for task state changes.

        Each evaluation runs in a detached background task
        instead of blocking the WS receive loop. Awaiting each
        ``evaluate_and_dispatch`` in series would pin the WS
        frame handler: each call awaits up to 16 concurrent HTTP
        deliveries with 10s timeouts, so a 50-event burst with
        email subscriptions could block the WS frame handler for
        tens of seconds and drop the agent's heartbeat clock.

        The detached tasks each open their own DB session (sessions
        are not safe to share across tasks). A class-level set holds
        strong references so Python doesn't GC the task before the
        coroutine finishes (audit P-10 same-pattern fix).
        Backpressure: if the pending set exceeds
        ``_MAX_PENDING_NOTIFICATION_TASKS`` we log + drop (event
        ingestion under burst takes priority over notification
        delivery; the next agent reconnect / heartbeat re-fires
        anything important).
        """
        from z4j_core.models.event import EventKind

        from z4j_brain.domain.notifications import NotificationService

        # Map event kinds to notification trigger types.
        kind_to_trigger: dict[str, str] = {
            EventKind.TASK_FAILED.value: "task.failed",
            EventKind.TASK_SUCCEEDED.value: "task.succeeded",
            EventKind.TASK_RETRIED.value: "task.retried",
        }

        # Deduplicate: only fire once per (trigger, task_id) per batch.
        seen: set[tuple[str, str]] = set()

        for raw_event in events:
            kind = raw_event.get("kind", "")
            trigger = kind_to_trigger.get(kind)
            if trigger is None:
                continue
            task_id = raw_event.get("task_id", "")
            if (trigger, task_id) in seen:
                continue
            seen.add((trigger, task_id))

            data = raw_event.get("data") or {}
            # Backpressure cap: if too many notification
            # tasks are already in flight we drop new ones rather than
            # let the FrameRouter's pending set grow unbounded under
            # an event flood from a misbehaving agent.
            if len(self._pending_notify_tasks) >= _MAX_PENDING_NOTIFICATION_TASKS:
                logger.warning(
                    "z4j frame_router: notification pending queue full "
                    "(%d tasks); dropping trigger=%s task_id=%s",
                    len(self._pending_notify_tasks),
                    trigger,
                    task_id,
                )
                continue

            task = asyncio.create_task(
                self._dispatch_notification(
                    NotificationService(),
                    trigger=trigger,
                    task_id=task_id,
                    task_name=data.get("task_name"),
                    engine=raw_event.get("engine"),
                    priority=data.get("priority", "normal"),
                    state=kind.split(".")[-1] if "." in kind else kind,
                    queue=data.get("queue"),
                    exception=data.get("exception"),
                    traceback=data.get("traceback"),
                ),
                name=f"z4j-notify-{trigger}",
            )
            self._pending_notify_tasks.add(task)
            task.add_done_callback(self._pending_notify_tasks.discard)
            task.add_done_callback(_log_notify_task_exception)

    async def _dispatch_notification(
        self,
        svc: NotificationService,
        *,
        trigger: str,
        task_id: str,
        task_name: str | None,
        engine: str | None,
        priority: str,
        state: str,
        queue: str | None,
        exception: str | None,
        traceback: str | None,
    ) -> None:
        """Single notification dispatch with its own DB session.

        Designed to be called from ``asyncio.create_task`` from
        ``_evaluate_notifications``. Each task owns its own DB
        session because sessions are not safe to share across
        tasks. Errors are logged in the done-callback, not
        raised.
        """
        try:
            # Hold a semaphore slot before opening the DB session so the
            # 256-task ceiling can't translate into 256 concurrent
            # sessions. Excess tasks queue here; the
            # ``_MAX_PENDING_NOTIFICATION_TASKS`` cap upstream is
            # the global drop-policy for sustained overflow.
            sem = _get_notify_db_session_semaphore()
            async with sem, self._db.session() as session:
                await svc.evaluate_and_dispatch(
                    session=session,
                    project_id=self._project_id,
                    trigger=trigger,
                    task_id=task_id,
                    task_name=task_name,
                    engine=engine,
                    priority=priority,
                    state=state,
                    queue=queue,
                    exception=exception,
                    traceback=traceback,
                )
        except Exception:
            logger.exception(
                "z4j frame_router: notification dispatch task failed",
                trigger=trigger,
                task_id=task_id,
            )

    async def _evaluate_automation(self, events: list[dict[str, Any]]) -> None:
        """Match + fire automation rules for task-lifecycle events.

        Mirrors :meth:`_evaluate_notifications`: same event-kind ->
        trigger mapping and per-batch dedup, but dispatches to the
        automation executor (rule match -> circuit-breaker claim ->
        governed action) instead of the subscription fan-out. Each match
        is a detached task with its own DB session, so a slow or failing
        rule never blocks event ingestion. Backpressure drops new work
        once the pending set is full (ingestion takes priority).

        NOTE: unlike notifications, a dropped automation firing is NOT
        recovered by an agent reconnect -- automation runs AFTER the event
        batch is acked (the agent has already evicted its buffer entry).
        A drop is therefore permanent, so it is logged at WARNING here for
        operator visibility; a durable firing outbox is a follow-up.
        """
        from z4j_core.models.event import EventKind

        kind_to_trigger: dict[str, str] = {
            EventKind.TASK_FAILED.value: "task.failed",
            EventKind.TASK_SUCCEEDED.value: "task.succeeded",
            EventKind.TASK_RETRIED.value: "task.retried",
        }
        seen: set[tuple[str, str]] = set()
        # Firings deferred to the outbox because the inline pending set was
        # full. Collected here and flushed in ONE batched, gated write after
        # the loop (not a session+commit per event on the awaited hot path).
        deferred: list[tuple[str, dict[str, Any]]] = []

        for raw_event in events:
            kind = raw_event.get("kind", "")
            trigger = kind_to_trigger.get(kind)
            if trigger is None:
                continue
            task_id = raw_event.get("task_id", "")
            if (trigger, task_id) in seen:
                continue
            seen.add((trigger, task_id))

            if len(self._pending_automation_tasks) >= _MAX_PENDING_NOTIFICATION_TASKS:
                # The inline pending set is full. Rather than permanently
                # drop the firing, defer it to the durable outbox -- but
                # collect them and write once after the loop.
                data = raw_event.get("data") or {}
                exception = data.get("exception")
                if isinstance(exception, str) and len(exception) > _OUTBOX_EXCEPTION_CAP:
                    # Bound agent-controlled blobs: the outbox fires under a
                    # failure storm (large tracebacks) and this is durable.
                    exception = exception[:_OUTBOX_EXCEPTION_CAP]
                outbox_fields: dict[str, Any] = {
                    "task_id": task_id,
                    "task_name": data.get("task_name"),
                    "engine": raw_event.get("engine"),
                    "queue": data.get("queue"),
                    "priority": data.get("priority", "normal"),
                    "exception": exception,
                    "runtime_ms": data.get("runtime_ms"),
                    "fingerprint": _fingerprint_of(data),
                    # JSON-safe: the drain worker rehydrates this straight
                    # into run_matching; the command runner accepts a str id.
                    "agent_id": str(self._agent_id),
                }
                deferred.append((trigger, outbox_fields))
                continue

            data = raw_event.get("data") or {}
            fields: dict[str, Any] = {
                "task_id": task_id,
                "task_name": data.get("task_name"),
                "engine": raw_event.get("engine"),
                "queue": data.get("queue"),
                "priority": data.get("priority", "normal"),
                "exception": data.get("exception"),
                "runtime_ms": data.get("runtime_ms"),
                # The failure fingerprint so a rule can condition on a
                # specific issue (e.g. notify when a fingerprint reappears).
                "fingerprint": _fingerprint_of(data),
                # The agent that REPORTED the event is the command target
                # for retry / cancel actions.
                "agent_id": self._agent_id,
            }
            task = asyncio.create_task(
                self._dispatch_automation(trigger=trigger, fields=fields),
                name=f"z4j-automation-{trigger}",
            )
            self._pending_automation_tasks.add(task)
            task.add_done_callback(self._pending_automation_tasks.discard)
            task.add_done_callback(_log_notify_task_exception)

        if deferred:
            await self._flush_deferred_to_outbox(deferred)

    async def _dispatch_automation(
        self,
        *,
        trigger: str,
        fields: dict[str, Any],
    ) -> None:
        """Run automation rules for one event in its own DB session.

        Detached task (see :meth:`_evaluate_automation`). Each task owns
        its session because sessions are not safe to share across tasks.
        ``run_matching`` commits (and rolls back) per rule -- it owns the
        transaction boundary so the audit-chain + circuit-breaker locks
        release promptly and one rule's DB error cannot abort the rest --
        so this method does NOT commit. Errors are logged in the
        done-callback, not raised.
        """
        try:
            from z4j_brain.domain.automation import (
                AutomationActionRunner,
                AutomationExecutor,
            )
            from z4j_brain.persistence.repositories.audit_log import (
                AuditLogRepository,
            )
            from z4j_brain.persistence.repositories.automation_rule import (
                AutomationRuleRepository,
            )

            sem = _get_automation_db_session_semaphore()
            async with sem, self._db.session(write=True) as session:
                executor = AutomationExecutor(
                    audit=self._dispatcher.audit,
                    runner=AutomationActionRunner(dispatcher=self._dispatcher),
                )
                await executor.run_matching(
                    session=session,
                    rules_repo=AutomationRuleRepository(session),
                    audit_log=AuditLogRepository(session),
                    project_id=self._project_id,
                    trigger=trigger,
                    fields=fields,
                    now=datetime.now(UTC),
                    notify_coalesce_seconds=self._automation_notify_coalesce_seconds,
                )
        except Exception:
            logger.exception(
                "z4j frame_router: automation dispatch task failed",
                trigger=trigger,
            )

    async def _project_has_rules_for(self, trigger: str, session: Any) -> bool:
        """Memoized (short TTL) EXISTS check: does this project have an
        enabled rule for ``trigger``? Skips deferring firings to the outbox
        for a project with no automation, so a busy no-rules project cannot
        bloat the outbox under a flood."""
        cached = self._has_rules_cache.get(trigger)
        now = time.monotonic()
        if cached is not None and cached[1] > now:
            return cached[0]
        from z4j_brain.persistence.repositories import (
            AutomationRuleRepository,
        )

        has_rules = await AutomationRuleRepository(session).has_enabled_rule_for_trigger(
            project_id=self._project_id,
            trigger=trigger,
        )
        self._has_rules_cache[trigger] = (has_rules, now + _HAS_RULES_TTL_SECONDS)
        return has_rules

    async def _flush_deferred_to_outbox(
        self,
        deferred: list[tuple[str, dict[str, Any]]],
    ) -> None:
        """Persist the firings deferred under backpressure in ONE batched
        write, after gating: skip triggers the project has no rule for, and
        stop deferring (hard-drop, counted) once the per-project outbox cap
        is reached. A single session + commit for the whole batch keeps the
        awaited ingest path off per-row fsyncs."""
        try:
            from z4j_brain.persistence.repositories import (
                AutomationFiringOutboxRepository,
            )

            async with self._db.session() as session:
                # Drop firings for triggers with no enabled rule -- they would
                # replay to a no-op. Count them so the drop is observable.
                to_write: list[tuple[str, dict[str, Any]]] = []
                skipped_norule = 0
                for trigger, fields in deferred:
                    if await self._project_has_rules_for(trigger, session):
                        to_write.append((trigger, fields))
                    else:
                        skipped_norule += 1

                dropped_cap = 0
                if to_write:
                    outbox = AutomationFiringOutboxRepository(session)
                    existing = await outbox.count_for_project(self._project_id)
                    room = max(0, self._automation_outbox_max_rows - existing)
                    if len(to_write) > room:
                        dropped_cap = len(to_write) - room
                        to_write = to_write[:room]
                    if to_write:
                        await outbox.enqueue_many(
                            project_id=self._project_id,
                            items=to_write,
                        )
                        await session.commit()

            self._bump_drop_metrics(
                enqueued=len(to_write),
                dropped=skipped_norule + dropped_cap,
                dropped_reason="outbox_full" if dropped_cap else "no_rule",
            )
            if to_write or skipped_norule or dropped_cap:
                logger.warning(
                    "z4j frame_router: automation pending queue full; "
                    "deferred=%d skipped_no_rule=%d dropped_cap=%d",
                    len(to_write),
                    skipped_norule,
                    dropped_cap,
                )
        except Exception:
            logger.exception(
                "z4j frame_router: failed to flush deferred firings to outbox; dropping %d",
                len(deferred),
            )
            self._bump_drop_metrics(
                enqueued=0,
                dropped=len(deferred),
                dropped_reason="pending_queue_full",
            )

    def _bump_drop_metrics(
        self,
        *,
        enqueued: int,
        dropped: int,
        dropped_reason: str,
    ) -> None:
        try:
            from z4j_brain.api.metrics import (
                z4j_automation_firings_dropped_total,
                z4j_automation_outbox_enqueued_total,
            )

            if enqueued:
                z4j_automation_outbox_enqueued_total.labels(
                    project=str(self._project_id),
                    trigger="batch",
                ).inc(enqueued)
            if dropped:
                z4j_automation_firings_dropped_total.labels(
                    project=str(self._project_id),
                    reason=dropped_reason,
                ).inc(dropped)
        except Exception:
            from z4j_brain.api.metrics import record_swallowed

            record_swallowed("frame_router", "automation_drop_metric")

    async def _publish_task_change(self) -> None:
        if self._dashboard_hub is None:
            return
        try:
            await self._dashboard_hub.publish_task_change(self._project_id)
        except Exception:
            logger.exception(
                "z4j frame_router: dashboard task publish failed",
                project_id=str(self._project_id),
            )

    async def _publish_command_change(self) -> None:
        if self._dashboard_hub is None:
            return
        try:
            await self._dashboard_hub.publish_command_change(self._project_id)
        except Exception:
            logger.exception(
                "z4j frame_router: dashboard command publish failed",
                project_id=str(self._project_id),
            )


__all__ = ["FrameRouter"]
