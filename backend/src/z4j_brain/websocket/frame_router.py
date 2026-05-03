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

from datetime import UTC, datetime
import asyncio
from typing import TYPE_CHECKING, Any
from uuid import UUID

import structlog

from z4j_core.transport.frames import (
    CommandAckFrame,
    CommandResultFrame,
    EventBatchFrame,
    Frame,
    HeartbeatFrame,
    RegistryDeltaFrame,
)

if TYPE_CHECKING:
    from z4j_brain.domain import CommandDispatcher, EventIngestor
    from z4j_brain.domain.notifications import NotificationService
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.websocket.dashboard_hub import DashboardHub


logger = structlog.get_logger("z4j.brain.frame_router")

#: Backpressure cap on detached notification dispatch tasks per
#: connection (audit P-4). Each task runs ``evaluate_and_dispatch``
#: in its own DB session and may make external HTTP calls; an event
#: flood from a misbehaving agent shouldn't be allowed to spawn
#: thousands of in-flight tasks. The cap is per-FrameRouter (i.e.
#: per agent connection); a busy fleet of 100 agents = 100 × cap
#: ceiling. 256 leaves room for a 200-event burst with a normal
#: subscription fanout.
_MAX_PENDING_NOTIFICATION_TASKS = 256

#: Round-8 audit fix R8-Async-H4 (Apr 2026): hard cap on the number
#: of notification dispatch tasks that can hold an OPEN DB session
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
    global _notify_db_session_sem
    if _notify_db_session_sem is None:
        _notify_db_session_sem = asyncio.Semaphore(_NOTIFY_DB_SESSION_BOUND)
    return _notify_db_session_sem


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
        dashboard_hub: "DashboardHub | None" = None,
        worker_id: str | None = None,
    ) -> None:
        self._db = db
        self._ingestor = ingestor
        self._dispatcher = dispatcher
        self._project_id = project_id
        self._agent_id = agent_id
        self._dashboard_hub = dashboard_hub
        # Worker-first persistence (1.2.1+): the per-connection
        # worker_id from the hello payload, threaded through here
        # so heartbeat handling can refresh THIS worker's row in
        # agent_workers (rather than guessing from the heartbeat
        # frame itself, which doesn't carry worker_id).
        self._worker_id = worker_id
        # Strong references to detached notification dispatch tasks
        # (audit P-4 + P-10). Without this the asyncio event loop
        # may GC the task before its coroutine completes, swallowing
        # any exception. Tasks remove themselves on completion via
        # the done callback.
        self._pending_notify_tasks: set[asyncio.Task[None]] = set()

    async def dispatch(self, frame: Frame) -> None:
        """Route ``frame`` to the right service. Never raises."""
        try:
            if isinstance(frame, EventBatchFrame):
                await self._handle_event_batch(frame)
            elif isinstance(frame, HeartbeatFrame):
                await self._handle_heartbeat(frame)
            elif isinstance(frame, CommandAckFrame):
                await self._handle_command_ack(frame)
            elif isinstance(frame, CommandResultFrame):
                await self._handle_command_result(frame)
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
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "z4j frame_router: dispatch crashed; connection survives",
                frame_type=getattr(frame, "type", None),
                agent_id=str(self._agent_id),
                project_id=str(self._project_id),
                error_class=type(exc).__name__,
            )

    # ------------------------------------------------------------------
    # event_batch
    # ------------------------------------------------------------------

    async def _handle_event_batch(self, frame: EventBatchFrame) -> None:
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

        # Round-6 audit fix WS-MED (Apr 2026): cap the per-frame
        # event count. The wire-frame validator already enforces
        # ``max_ws_frame_bytes`` (1 MiB by default), but events are
        # small JSON dicts so a single 1 MiB frame can carry
        # ~5_000-10_000 events. Cap to a defensive ceiling so the
        # downstream notification-evaluation loop (one query per
        # event) cannot be amplified by a malicious or buggy agent.
        # The agent's own batcher tops out near 500.
        _EVENT_BATCH_CAP = 1_000
        events = list(frame.payload.events)
        if len(events) > _EVENT_BATCH_CAP:
            logger.warning(
                "z4j frame_router: event_batch over cap; trimming",
                project_id=str(self._project_id),
                agent_id=str(self._agent_id),
                received=len(events),
                cap=_EVENT_BATCH_CAP,
            )
            events = events[:_EVENT_BATCH_CAP]

        async with self._db.session() as session:
            await self._ingestor.ingest_batch(
                events=events,
                project_id=self._project_id,
                agent_id=self._agent_id,
                agents=AgentRepository(session),
                event_repo=EventRepository(session),
                task_repo=TaskRepository(session),
                queue_repo=QueueRepository(session),
                worker_repo=WorkerRepository(session),
            )
            await session.commit()

        # One publish per batch (not per event) - the dashboard
        # refetches the list and gets every change in one round
        # trip. The publish runs after the commit so subscribers
        # never see a topic referencing data still in flight.
        await self._publish_task_change()

        # Evaluate per-user notification subscriptions for task-related
        # triggers. Each event may match one or more user subscriptions
        # (in-app, Slack, email, ...). We run this AFTER the commit so
        # the delivery log and any side-effect queries see the
        # committed data. Pass the trimmed list (not
        # ``frame.payload.events``) so the cap propagates here too.
        await self._evaluate_notifications(events)

    # ------------------------------------------------------------------
    # heartbeat
    # ------------------------------------------------------------------

    async def _handle_heartbeat(self, frame: HeartbeatFrame) -> None:
        from z4j_brain.persistence.repositories import (
            AgentRepository,
            AgentWorkerRepository,
            QueueRepository,
        )

        async with self._db.session() as session:
            await AgentRepository(session).touch_heartbeat(self._agent_id)
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
            # Round-6 audit fix WS-MED (Apr 2026): cap the number of
            # adapter_health top-level keys we'll iterate. Nominal
            # production load is single-digit (one per engine + a
            # few well-known suffixes); a malicious or buggy agent
            # supplying 100k keys would otherwise force 100k key
            # ``str.endswith`` checks per heartbeat, fired every 10s
            # per connection. 256 leaves room for new suffixes
            # without ever becoming a meaningful work amplifier.
            _ADAPTER_HEALTH_KEYS_CAP = 256
            if len(adapter_health) > _ADAPTER_HEALTH_KEYS_CAP:
                logger.warning(
                    "z4j frame_router: adapter_health key cap exceeded; "
                    "trimming",
                    project_id=str(self._project_id),
                    received=len(adapter_health),
                    cap=_ADAPTER_HEALTH_KEYS_CAP,
                )
                adapter_health = dict(
                    list(adapter_health.items())[:_ADAPTER_HEALTH_KEYS_CAP],
                )
            for key, value in adapter_health.items():
                if key.endswith(".queue_depths") and isinstance(value, str):
                    try:
                        import json as _json

                        depths = _json.loads(value)
                        if isinstance(depths, dict):
                            # Round-6 audit fix WS-MED (Apr 2026):
                            # cap inner queue_depths dict size to
                            # prevent a malicious agent from
                            # triggering thousands of upserts per
                            # heartbeat tick.
                            _QUEUE_DEPTHS_CAP = 1024
                            if len(depths) > _QUEUE_DEPTHS_CAP:
                                logger.warning(
                                    "z4j frame_router: queue_depths cap "
                                    "exceeded; trimming",
                                    key=key,
                                    received=len(depths),
                                    cap=_QUEUE_DEPTHS_CAP,
                                )
                                depths = dict(
                                    list(depths.items())[:_QUEUE_DEPTHS_CAP],
                                )
                            queue_repo = QueueRepository(session)
                            for queue_name, depth in depths.items():
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
                                except Exception:  # noqa: BLE001
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
                                except Exception:  # noqa: BLE001
                                    from z4j_brain.api.metrics import (
                                        record_swallowed,
                                    )

                                    record_swallowed(
                                        "frame_router", "queue_depth_gauge",
                                    )
                    except Exception:  # noqa: BLE001
                        logger.debug(
                            "z4j frame_router: failed to parse queue depths",
                            key=key,
                        )

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
                            # at the end (v1.0.15 P-1). Replaces the
                            # per-hostname savepointed upsert that was
                            # the dominant cost in this hot path
                            # (heartbeat fires every 10s per agent
                            # connection - ~6 frontends × prefork=2
                            # ≈ 6 concurrent heartbeats was where the
                            # original PendingRollbackError cascade
                            # was caught in audit pass 9 / 2026-04-21).
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
                                    "last_heartbeat": frame.payload.last_flush_at or datetime.now(UTC),
                                    "hostname": hostname,
                                    "worker_metadata": {
                                        "stats": stats,
                                        "active": data.get("active", []),
                                        "active_queues": data.get("active_queues", []),
                                        "registered": data.get("registered", []),
                                        "conf": data.get("conf", {}),
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
                                        q.get("name", "") for q in aq
                                        if isinstance(q, dict)
                                    ]
                                    row["queues"] = queue_list
                                    # Collect for separate queue touches
                                    # below. Worker → queue is N:M; one
                                    # worker can announce multiple
                                    # queues, so this stays a flat list.
                                    queue_names_to_touch.extend(
                                        q for q in queue_list
                                        if isinstance(q, str) and q
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
                                                        k: v for k, v in row.items()
                                                        if k not in (
                                                            "project_id", "engine", "name",
                                                        )
                                                    },
                                                )
                                        except Exception:  # noqa: BLE001
                                            logger.debug(
                                                "z4j frame_router: per-row "
                                                "worker upsert fallback failed",
                                                engine=row["engine"],
                                                hostname=str(row["name"]),
                                            )

                            # Register each queue this worker is
                            # consuming so the Queues page reflects
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
                                except Exception:  # noqa: BLE001
                                    logger.exception(
                                        "z4j frame_router: queue touch failed",
                                    )
                    except Exception:  # noqa: BLE001
                        logger.exception(
                            "z4j frame_router: failed to parse worker details",
                        )

            await session.commit()

    # ------------------------------------------------------------------
    # command_ack / command_result
    # ------------------------------------------------------------------

    async def _handle_command_ack(self, frame: CommandAckFrame) -> None:
        from uuid import UUID as _UUID

        try:
            command_id = _UUID(frame.id)
        except ValueError:
            return
        from z4j_brain.persistence.repositories import CommandRepository

        async with self._db.session() as session:
            await self._dispatcher.handle_ack(
                commands=CommandRepository(session),
                command_id=command_id,
                project_id=self._project_id,
                agent_id=self._agent_id,
            )
            await session.commit()

        await self._publish_command_change()

    async def _handle_command_result(self, frame: CommandResultFrame) -> None:
        from uuid import UUID as _UUID

        try:
            command_id = _UUID(frame.id)
        except ValueError:
            return
        from z4j_brain.persistence.repositories import (
            AuditLogRepository,
            CommandRepository,
        )

        async with self._db.session() as session:
            await self._dispatcher.handle_result(
                commands=CommandRepository(session),
                audit_log=AuditLogRepository(session),
                command_id=command_id,
                status=frame.payload.status,
                result_payload=frame.payload.result,
                error=frame.payload.error,
                project_id=self._project_id,
                agent_id=self._agent_id,
            )
            await session.commit()

        await self._publish_command_change()

    # ------------------------------------------------------------------
    # Dashboard publish helpers
    # ------------------------------------------------------------------

    async def _evaluate_notifications(
        self,
        events: list[dict[str, Any]],
    ) -> None:
        """Fire per-user notification subscriptions for task state changes.

        As of v1.0.14 (audit P-4) each evaluation runs in a detached
        background task instead of blocking the WS receive loop.
        Pre-1.0.14 this method awaited each ``evaluate_and_dispatch``
        in series, which itself awaits up to 16 concurrent HTTP
        deliveries with 10s timeouts - a 50-event burst with email
        subscriptions could pin the WS frame handler for tens of
        seconds, dropping the agent's heartbeat clock.

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
        KIND_TO_TRIGGER: dict[str, str] = {
            EventKind.TASK_FAILED.value: "task.failed",
            EventKind.TASK_SUCCEEDED.value: "task.succeeded",
            EventKind.TASK_RETRIED.value: "task.retried",
        }

        # Deduplicate: only fire once per (trigger, task_id) per batch.
        seen: set[tuple[str, str]] = set()

        for raw_event in events:
            kind = raw_event.get("kind", "")
            trigger = KIND_TO_TRIGGER.get(kind)
            if trigger is None:
                continue
            task_id = raw_event.get("task_id", "")
            if (trigger, task_id) in seen:
                continue
            seen.add((trigger, task_id))

            data = raw_event.get("data") or {}
            # Backpressure cap (audit P-4): if too many notification
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
        svc: "NotificationService",
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
        ``_evaluate_notifications`` (audit P-4). Each task owns its
        own DB session because sessions are not safe to share across
        tasks. Errors are logged in the done-callback, not raised.
        """
        try:
            # Round-8 audit fix R8-Async-H4 (Apr 2026): hold a
            # semaphore slot before opening the DB session so the
            # 256-task ceiling can't translate into 256 concurrent
            # sessions. Excess tasks queue here; the
            # ``_MAX_PENDING_NOTIFICATION_TASKS`` cap upstream is
            # the global drop-policy for sustained overflow.
            sem = _get_notify_db_session_semaphore()
            async with sem:
                async with self._db.session() as session:
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
        except Exception:  # noqa: BLE001
            logger.exception(
                "z4j frame_router: notification dispatch task failed",
                trigger=trigger,
                task_id=task_id,
            )

    async def _publish_task_change(self) -> None:
        if self._dashboard_hub is None:
            return
        try:
            await self._dashboard_hub.publish_task_change(self._project_id)
        except Exception:  # noqa: BLE001
            logger.exception(
                "z4j frame_router: dashboard task publish failed",
                project_id=str(self._project_id),
            )

    async def _publish_command_change(self) -> None:
        if self._dashboard_hub is None:
            return
        try:
            await self._dashboard_hub.publish_command_change(self._project_id)
        except Exception:  # noqa: BLE001
            logger.exception(
                "z4j frame_router: dashboard command publish failed",
                project_id=str(self._project_id),
            )


__all__ = ["FrameRouter"]
