"""Per-RPC handler implementations for the brain-side ``SchedulerService``.

The brain implements five of the six RPCs declared in
``packages/z4j-scheduler/proto/scheduler.proto``:

- :rpc:`ListSchedules` - server-streaming initial sync
- :rpc:`WatchSchedules` - server-streaming live diffs
- :rpc:`FireSchedule` - unary; creates a Command via ``CommandDispatcher``
- :rpc:`AcknowledgeFireResult` - unary; updates ``schedules.last_run_at``
- :rpc:`Ping` - unary liveness

The sixth RPC (:rpc:`TriggerSchedule`) lives on the scheduler side -
brain is the gRPC client for that one.

Per ``docs/SCHEDULER.md §13.2``, every state-changing RPC writes an
audit row through the existing HMAC-chained ``audit_log``. Pure read
RPCs (List/Watch/Ping) skip the audit because the scheduler reads
the same data on every reconnect; auditing each one would balloon
the log without operator value.

Phase 1 implementation notes:

- :rpc:`WatchSchedules` polls ``schedules.updated_at`` every
  ``Z4J_SCHEDULER_GRPC_WATCH_POLL_SECONDS`` (default 2s) and emits
  diff events. A future enhancement bolts on Postgres ``LISTEN`` for
  push semantics, but polling at 2s is well within the 100ms-target
  cache freshness budget when amortized against the scheduler's own
  tick cadence (250ms).
- :rpc:`FireSchedule` re-uses ``_pick_scheduler_agent`` from the REST
  handler so brain stays single-source-of-truth on agent selection.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, AsyncIterator
from uuid import UUID

import grpc
from google.protobuf.timestamp_pb2 import Timestamp

from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb
from z4j_brain.scheduler_grpc.proto import scheduler_pb2_grpc as pb_grpc

if TYPE_CHECKING:  # pragma: no cover
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.domain.command_dispatcher import CommandDispatcher
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.models import Schedule
    from z4j_brain.settings import Settings

logger = logging.getLogger("z4j.brain.scheduler_grpc.handlers")


# Action string the agent receives when the scheduler asks for a
# fire. Mirrors the REST ``trigger_now`` action but tagged separately
# so the audit log can distinguish "scheduled tick" from "operator
# clicked trigger now".
_FIRE_ACTION = "schedule.fire"

# Hard caps applied to operator-facing string fields the scheduler
# reports back via error responses. Keep error_message bounded so:
#
# - a chatty `str(exc)` (SQL fragments, file paths, tracebacks) does
#   not leak internals to the wire, AND
# - a hostile scheduler can't push a multi-MB string into our
#   schedule_fires history table by repeatedly failing.
#
# Audit finding L-3 / M-3 (Apr 2026 security audit).
_ERROR_MESSAGE_MAX_CHARS = 500
_ERROR_CODE_MAX_CHARS = 64


def _sanitize_error_message(raw: str | None, *, max_chars: int = _ERROR_MESSAGE_MAX_CHARS) -> str | None:
    """Bound + sanitize a scheduler-reported error string.

    Strips control characters (newlines, ANSI escapes) so a single
    error can't break log-line parsing or smuggle log injection
    payloads. Truncates to ``max_chars`` so error_message can't
    OOM the schedule_fires column.

    Returns ``None`` when input is empty so we don't store a
    sentinel that suggests a real error.
    """
    if not raw:
        return None
    # Keep printable ASCII + common Latin-1; drop ESC, DEL, NUL,
    # other control chars. Tab + space stay because real error
    # text uses them.
    cleaned = "".join(
        c for c in raw
        if c == "\t" or c == " " or (32 <= ord(c) < 127) or 160 <= ord(c) <= 255
    )
    cleaned = cleaned.strip()
    if not cleaned:
        return None
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars - 3] + "..."
    return cleaned

# Default page size when the scheduler does not specify one.
_DEFAULT_LIST_PAGE_SIZE = 100

# Hard upper bound on the per-page batch size we honor from a
# scheduler client. The scheduler is mTLS-authenticated so the
# usual hostile-internet threat model does not apply, but a
# misbehaving or compromised scheduler that passes
# ``page_size = 2_000_000_000`` would force the brain to allocate
# a giant ORM batch and exhaust process memory.
#
# 1000 covers any realistic deployment (10k schedules per project
# is already an extreme outlier; tens of pages of 1000 are still
# milliseconds at brain-side latency) while bounding the worst case.
#
# Audit fix S001 (1.4.0): pre-fix the caller-supplied page_size
# went straight into ``stmt.limit(page_size)`` with no upper bound.
_MAX_LIST_PAGE_SIZE = 1000

# Sentinel scheduler-name brain expects in the ``schedules.scheduler``
# column for rows that are managed by z4j-scheduler. Other rows
# (e.g. ``celery-beat`` rows from the agent-side mirror) are NOT
# returned to z4j-scheduler so the two scheduling surfaces don't
# step on each other.
_SCHEDULER_NAME = "z4j-scheduler"


#: Round-8 audit fix R8-Async-H3 (Apr 2026): per-process bound on
#: in-flight FireSchedule handlers. Each holds a DB session across
#: with_for_update + agent lookup + dispatcher.issue + commit; an
#: unbounded burst exhausts the pool and starves unrelated REST
#: handlers. 8 leaves headroom in a typical 30-conn pool for
#: workers + dashboard reads.
_FIRE_SCHEDULE_BOUND = 8
_fire_schedule_sem: asyncio.Semaphore | None = None


def _get_fire_schedule_semaphore() -> asyncio.Semaphore:
    """Lazy-init the FireSchedule semaphore on first call.

    Lazy because module import predates the running event loop in
    test fixtures; ``asyncio.Semaphore`` binds to the loop at
    construction.
    """
    global _fire_schedule_sem
    if _fire_schedule_sem is None:
        _fire_schedule_sem = asyncio.Semaphore(_FIRE_SCHEDULE_BOUND)
    return _fire_schedule_sem


# =====================================================================
# Service implementation
# =====================================================================


class SchedulerServiceImpl(pb_grpc.SchedulerServiceServicer):
    """gRPC servicer wired to brain's existing domain services.

    Construction takes the same singletons the REST routers use so
    there is one consistent path from "wire request arrives" to "row
    in the database is mutated". No new transactional code lives
    here; every handler opens its own ``async with db.session()`` and
    delegates to the shared repositories.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        db: DatabaseManager,
        command_dispatcher: CommandDispatcher,
        audit_service: AuditService,
    ) -> None:
        from collections import defaultdict  # noqa: PLC0415

        from z4j_brain.domain.scheduler_rate_limiter import (  # noqa: PLC0415
            SchedulerRateLimiter,
        )

        self._settings = settings
        self._db = db
        self._dispatcher = command_dispatcher
        self._audit = audit_service
        self._rate_limiter = SchedulerRateLimiter(db=db, settings=settings)
        # Used by Watch handler so multiple concurrent streams share
        # one polling loop's snapshot when load matters. Phase 1
        # implementation just keeps the lock to make the code shape
        # ready for that optimisation; each stream still polls
        # independently.
        self._watch_lock = asyncio.Lock()
        # Audit fix (Apr 2026 follow-up): bounded WatchSchedules
        # concurrency. Pre-fix every WatchSchedules RPC opened its
        # own asyncpg LISTEN connection with no cap - a misbehaving
        # scheduler that opened+dropped streams in a loop drained
        # Postgres ``max_connections`` and killed brain's main pool.
        # Two locks: a global semaphore caps total streams across
        # the brain process; a per-CN counter caps any single cert
        # from monopolising the global cap.
        # Round-10 audit fix R10-Sched-H1 (Apr 2026): replace the
        # ``asyncio.Semaphore`` + ``wait_for(..., timeout=0)`` pattern
        # with a plain counter under a lock. The semaphore approach
        # had two leak vectors:
        #
        # 1. ``asyncio.wait_for(sem.acquire(), 0)`` is documented as
        #    racy when the awaitable completes synchronously: the
        #    timer fires, ``wait_for`` cancels the task, but the
        #    task already decremented ``_value``, slot leaked,
        #    caller sees TimeoutError. Triggered on every successful
        #    acquire under load.
        #
        # 2. Acquire-then-cancel window between the acquire's own
        #    try-block and the stream's try-block (different try
        #    blocks): a gRPC ``context.cancel()`` in the gap left
        #    the slot held with no finally registered to release it.
        #
        # The counter-under-lock pattern is atomic (single
        # ``async with``), the release is shielded against cancel,
        # and we expose ``_watch_global_count`` for the
        # observability gauge below.
        self._watch_global_cap = settings.scheduler_grpc_watch_max_concurrent
        self._watch_global_count: int = 0
        self._watch_global_lock = asyncio.Lock()
        self._watch_per_cert_count: dict[str, int] = defaultdict(int)
        self._watch_per_cert_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # ListSchedules - server streaming
    # ------------------------------------------------------------------

    async def ListSchedules(  # noqa: N802 - gRPC-generated name
        self,
        request: pb.ListSchedulesRequest,
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[pb.Schedule]:
        from sqlalchemy import select

        from z4j_brain.persistence.models import Schedule
        from z4j_brain.scheduler_grpc.binding import (  # noqa: PLC0415
            enforce_cn_project_binding,
            filter_project_ids_by_binding,
        )

        bindings = self._settings.scheduler_grpc_cn_project_bindings

        # Audit fix S001 (1.4.0): clamp caller-supplied page_size to
        # ``_MAX_LIST_PAGE_SIZE``. A missing/zero value falls back to
        # the default; a too-large value is silently capped (we do
        # not abort -- legitimate schedulers asking for "as much as
        # possible" should still get a useful response).
        if request.page_size > 0:
            page_size = min(request.page_size, _MAX_LIST_PAGE_SIZE)
        else:
            page_size = _DEFAULT_LIST_PAGE_SIZE

        async with self._db.session() as session:
            stmt = select(Schedule).where(
                Schedule.scheduler == _SCHEDULER_NAME,
            )
            if request.project_id:
                try:
                    pid = UUID(request.project_id)
                except ValueError:
                    await context.abort(
                        grpc.StatusCode.INVALID_ARGUMENT,
                        f"invalid project_id {request.project_id!r}",
                    )
                    return
                # Audit fix M-5 (Apr 2026): enforce per-cert project
                # binding. Bound CNs can only see schedules for their
                # bound project list; no-op when bindings is empty or
                # the peer's CN isn't in the map.
                await enforce_cn_project_binding(
                    context=context,
                    project_id=pid,
                    bindings=bindings,
                    db=self._db,
                )
                stmt = stmt.where(Schedule.project_id == pid)
            else:
                # No project_id in request - if the peer is a bound
                # CN, narrow the query to its allowed projects so a
                # bound scheduler never sees rows it doesn't own.
                bound_projects = await filter_project_ids_by_binding(
                    context=context, bindings=bindings, db=self._db,
                )
                if bound_projects is not None:
                    if not bound_projects:
                        # Bound CN with no resolvable projects - empty
                        # result set rather than a leaking error.
                        return
                    stmt = stmt.where(Schedule.project_id.in_(bound_projects))
            stmt = stmt.order_by(Schedule.id)

            offset = 0
            while True:
                page = stmt.offset(offset).limit(page_size)
                result = await session.execute(page)
                rows = list(result.scalars().all())
                if not rows:
                    break
                for row in rows:
                    yield _schedule_to_pb(row)
                if len(rows) < page_size:
                    break
                offset += page_size

    # ------------------------------------------------------------------
    # WatchSchedules - server streaming
    # ------------------------------------------------------------------

    async def WatchSchedules(  # noqa: N802
        self,
        request: pb.WatchSchedulesRequest,
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[pb.ScheduleEvent]:
        """Stream create/update/delete events to the scheduler.

        Two implementations, picked at runtime based on the DB
        dialect:

        - **Postgres**: dedicated asyncpg connection LISTENing on
          ``z4j_schedules_changed`` (set up by migration
          ``2026_04_27_0007_sched_notify``). Sub-100ms cache
          freshness, near-zero idle CPU. Phase 3 default.
        - **SQLite**: polls ``schedules.updated_at`` every
          ``Z4J_SCHEDULER_GRPC_WATCH_POLL_SECONDS`` and emits diffs
          (Phase 1/2 path; SQLite has no LISTEN/NOTIFY). Used by the
          test fixtures + single-tenant evaluation deployments.

        The ``resume_token`` is the ISO timestamp of the latest
        ``updated_at`` the scheduler has seen; on reconnect the
        scheduler echoes it back so the first cycle skips events
        already delivered.
        """
        project_id: UUID | None = None
        if request.project_id:
            try:
                project_id = UUID(request.project_id)
            except ValueError:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT,
                    f"invalid project_id {request.project_id!r}",
                )
                return

        # Audit fix M-5 (Apr 2026): per-cert project binding. For an
        # explicit project_id, enforce binding. For "all projects"
        # mode (project_id=None), narrow to the peer's bound set.
        from z4j_brain.scheduler_grpc.binding import (  # noqa: PLC0415
            enforce_cn_project_binding,
            filter_project_ids_by_binding,
        )

        bindings = self._settings.scheduler_grpc_cn_project_bindings
        bound_project_ids: set[UUID] | None = None
        if project_id is not None:
            await enforce_cn_project_binding(
                context=context,
                project_id=project_id,
                bindings=bindings,
                db=self._db,
            )
        else:
            bound_project_ids = await filter_project_ids_by_binding(
                context=context, bindings=bindings, db=self._db,
            )
            if bound_project_ids is not None and not bound_project_ids:
                # Bound CN with no resolvable projects - close stream.
                return

        # Compute the effective project filter applied throughout the
        # stream. Three cases:
        #   - request.project_id set + binding allows  → single id
        #   - request.project_id unset, bound CN      → set of ids
        #   - request.project_id unset, unbound CN    → no filter
        if project_id is not None:
            project_filter: set[UUID] | None = {project_id}
        else:
            project_filter = bound_project_ids  # may be None

        # Audit fix (Apr 2026 follow-up): bounded WatchSchedules
        # concurrency. Acquire a global semaphore + bump the per-CN
        # counter; release both on stream end. RESOURCE_EXHAUSTED on
        # cap so the scheduler client retries with backoff (its
        # ``_backoff_or_stop`` already handles this).
        from z4j_brain.scheduler_grpc.binding import (  # noqa: PLC0415
            extract_peer_cns as _peer_cns,
        )

        peer_cns = _peer_cns(context)
        cert_cn = sorted(peer_cns)[0] if peer_cns else "_anon"
        per_cert_cap = self._settings.scheduler_grpc_watch_max_per_cert
        # Try to take the per-CN slot first; if denied, don't even
        # touch the global semaphore (no point queuing).
        async with self._watch_per_cert_lock:
            current = self._watch_per_cert_count[cert_cn]
            if current >= per_cert_cap:
                logger.warning(
                    "z4j.brain.scheduler_grpc: WatchSchedules per-cert "
                    "cap reached for cert_cn=%r (cap=%d); rejecting",
                    cert_cn, per_cert_cap,
                )
                await context.abort(
                    grpc.StatusCode.RESOURCE_EXHAUSTED,
                    "WatchSchedules per-cert concurrent stream cap reached",
                )
                return
            self._watch_per_cert_count[cert_cn] = current + 1
        # Acquire the global concurrency slot via the counter-under-
        # lock pattern. Round-10 audit fix R10-Sched-H1 (Apr 2026):
        # the prior implementation used
        # ``asyncio.wait_for(self._watch_global_sem.acquire(), 0)``
        # which has TWO leak vectors:
        #
        # 1. ``asyncio.wait_for(coro, 0)`` is documented as racy
        #    when ``coro`` completes synchronously. ``Semaphore.
        #    acquire()`` on an available slot decrements
        #    ``_value`` and returns immediately; the timer fires
        #    in the same tick and ``wait_for`` cancels the task
        #    that just succeeded, raising TimeoutError. The slot
        #    was DECREMENTED but the caller sees rejection, slot
        #    leaked permanently. Triggers on every successful
        #    acquire under load. Observed in production: a single
        #    scheduler client with retry-loop reconnects exhausted
        #    a default-64 cap within hours.
        #
        # 2. Acquire-then-cancel window between the
        #    ``except (TimeoutError, asyncio.TimeoutError):``
        #    block returning and the stream's own ``try:`` block
        #    registering its finally. A gRPC ``context.cancel()``
        #    landing in that gap left the slot acquired with no
        #    finally to release it.
        #
        # The new shape uses a plain integer + ``asyncio.Lock``:
        # the increment is atomic under one ``async with``, the
        # decrement is shielded against cancellation, and the
        # full lifecycle lives inside a single try/finally so
        # there's no acquire-then-cancel gap.
        async with self._watch_global_lock:
            if self._watch_global_count >= self._watch_global_cap:
                # Reject. Decrement the per-cert slot we already
                # took above. NOTE: this decrement is OK to do
                # outside a shield because we haven't crossed any
                # await that the caller could cancel; the lock is
                # purely synchronous after the await above.
                async with self._watch_per_cert_lock:
                    self._watch_per_cert_count[cert_cn] -= 1
                    if self._watch_per_cert_count[cert_cn] <= 0:
                        self._watch_per_cert_count.pop(cert_cn, None)
                logger.warning(
                    "z4j.brain.scheduler_grpc: WatchSchedules global "
                    "cap reached (current=%d max=%d); rejecting new "
                    "stream from cert_cn=%r",
                    self._watch_global_count,
                    self._watch_global_cap,
                    cert_cn,
                )
                await context.abort(
                    grpc.StatusCode.RESOURCE_EXHAUSTED,
                    "WatchSchedules concurrent stream cap reached",
                )
                return
            self._watch_global_count += 1
        try:
            # Dispatch on dialect. The async engine carries the
            # dialect name; we read it once at stream open. Falling
            # back to the poll path on any dialect we don't
            # recognise (defence in depth - a future Postgres
            # replacement should not silently drop notifications
            # because of a typo).
            dialect = self._db.engine.dialect.name
            if dialect == "postgresql":
                async for event in self._watch_via_listen(
                    project_filter=project_filter,
                    resume_token=request.resume_token,
                    context=context,
                ):
                    yield event
            else:
                # SQLite + everything else → polling fallback.
                async for event in self._watch_via_polling(
                    project_filter=project_filter,
                    resume_token=request.resume_token,
                    context=context,
                ):
                    yield event
        finally:
            # R10-Sched-H1: shield BOTH decrements so a
            # cancellation landing on the lock-acquire await
            # doesn't strand the slot. The shielded coroutine
            # below holds two locks back-to-back; on cancel the
            # inner work runs to completion, the cancellation
            # then propagates to whatever was awaiting us.
            await asyncio.shield(
                self._release_watch_slot(cert_cn),
            )

    async def _release_watch_slot(self, cert_cn: str) -> None:
        """Round-10 audit fix R10-Sched-H1 (Apr 2026): symmetric
        decrement of both the global counter and the per-cert
        counter. Wrapped in ``asyncio.shield`` by the caller so a
        cancel landing on the lock-acquire await can't strand
        either slot. Both locks are short-held (no I/O), so the
        shielded window is bounded to microseconds.
        """
        async with self._watch_global_lock:
            self._watch_global_count -= 1
            if self._watch_global_count < 0:
                # Defensive: never let the counter go negative.
                # If it does, log loud, that's a code bug.
                logger.error(
                    "z4j.brain.scheduler_grpc: watch_global_count "
                    "went negative (%d); resetting to 0",
                    self._watch_global_count,
                )
                self._watch_global_count = 0
        async with self._watch_per_cert_lock:
            self._watch_per_cert_count[cert_cn] -= 1
            if self._watch_per_cert_count[cert_cn] <= 0:
                self._watch_per_cert_count.pop(cert_cn, None)

    async def _watch_via_listen(
        self,
        *,
        project_filter: set[UUID] | None,
        resume_token: str,
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[pb.ScheduleEvent]:
        """Postgres LISTEN/NOTIFY-driven WatchSchedules implementation.

        Opens a dedicated asyncpg connection (LISTEN cannot be
        pooled - the listener identity is bound to the connection),
        subscribes to ``z4j_schedules_changed``, and emits gRPC
        events as notifications arrive.

        Catch-up on connect: if the scheduler sent a ``resume_token``
        we run one diff pass to deliver any events the scheduler
        missed during reconnect, then enter the live LISTEN loop.

        The dedicated connection is closed when the gRPC stream
        ends (client disconnect, scheduler shutdown, transient
        network drop).
        """
        try:
            import asyncpg  # noqa: PLC0415
        except ImportError:  # pragma: no cover
            # asyncpg is a hard dep of brain on Postgres - this branch
            # only fires if the operator stripped it out for some
            # reason. Fall back to polling.
            logger.warning(
                "z4j.brain.scheduler_grpc: asyncpg missing; falling "
                "back to polling for WatchSchedules",
            )
            async for event in self._watch_via_polling(
                project_filter=project_filter,
                resume_token=resume_token,
                context=context,
            ):
                yield event
            return

        # Catch-up pass: emit any events newer than resume_token so
        # the reconnecting scheduler doesn't miss diffs that landed
        # while the stream was down.
        last_seen_at: datetime | None = None
        if resume_token:
            try:
                last_seen_at = datetime.fromisoformat(resume_token)
            except ValueError:
                logger.warning(
                    "z4j.brain.scheduler_grpc: ignoring malformed "
                    "resume_token %r; starting from current state",
                    resume_token,
                )
        if last_seen_at is not None:
            catchup_events, _ = await self._compute_watch_diff(
                project_filter=project_filter,
                last_seen_at=last_seen_at,
                snapshot={},
                first_cycle=True,
            )
            for event in catchup_events:
                yield event

        # Open a dedicated asyncpg connection on the same DSN as the
        # SQLAlchemy engine. Audit fix L-1 (Apr 2026): pass connection
        # parameters as kwargs (host/port/user/password/database)
        # instead of materializing a plain-text URL string with the
        # password in it. The string-based path leaves the password
        # in heap until GC and would surface in any future log line
        # / core dump / exception traceback inside this function.
        # ``URL.translate_connect_args`` is the canonical SQLAlchemy
        # accessor for the libpq-style connection dict.
        connect_kwargs = self._db.engine.url.translate_connect_args(
            username="user",
        )
        conn = await asyncpg.connect(
            host=connect_kwargs.get("host"),
            port=connect_kwargs.get("port"),
            user=connect_kwargs.get("user"),
            password=connect_kwargs.get("password"),
            database=connect_kwargs.get("database"),
            server_settings={"application_name": "z4j-brain-watch-stream"},
        )
        notification_queue: asyncio.Queue = asyncio.Queue()

        def _on_notify(_conn, _pid, _channel, payload: str) -> None:
            # Called by asyncpg in the connection's task. Just
            # enqueue - the consumer below does the actual work.
            try:
                notification_queue.put_nowait(payload)
            except asyncio.QueueFull:  # pragma: no cover - unbounded queue
                pass

        await conn.add_listener("z4j_schedules_changed", _on_notify)
        try:
            while not context.cancelled():
                try:
                    payload = await asyncio.wait_for(
                        notification_queue.get(), timeout=30.0,
                    )
                except asyncio.TimeoutError:
                    # Liveness ping - keeps the gRPC stream alive
                    # under no-traffic conditions and lets us notice
                    # context cancellation without blocking forever.
                    continue
                except asyncio.CancelledError:
                    return

                event = await self._notification_to_event(
                    payload=payload, project_filter=project_filter,
                )
                if event is not None:
                    yield event
        finally:
            try:
                await conn.remove_listener(
                    "z4j_schedules_changed", _on_notify,
                )
            except Exception:  # noqa: BLE001
                pass
            try:
                await conn.close()
            except Exception:  # noqa: BLE001
                pass

    async def _watch_via_polling(
        self,
        *,
        project_filter: set[UUID] | None,
        resume_token: str,
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[pb.ScheduleEvent]:
        """SQLite (and fallback) polling implementation.

        Extracted from the original WatchSchedules body so the
        Postgres path can defer to it on asyncpg failure.
        """
        last_seen_at: datetime | None = None
        if resume_token:
            try:
                last_seen_at = datetime.fromisoformat(resume_token)
            except ValueError:
                logger.warning(
                    "z4j.brain.scheduler_grpc: ignoring malformed "
                    "resume_token %r; starting from current state",
                    resume_token,
                )

        snapshot: dict[UUID, datetime] = {}
        first_cycle = True
        poll_seconds = float(
            self._settings.scheduler_grpc_watch_poll_seconds,
        )

        while not context.cancelled():
            try:
                events, snapshot = await self._compute_watch_diff(
                    project_filter=project_filter,
                    last_seen_at=last_seen_at,
                    snapshot=snapshot,
                    first_cycle=first_cycle,
                )
            except Exception:  # noqa: BLE001
                logger.exception(
                    "z4j.brain.scheduler_grpc: watch poll crashed",
                )
                await asyncio.sleep(poll_seconds)
                continue

            for event in events:
                yield event
                if event.resume_token:
                    try:
                        last_seen_at = datetime.fromisoformat(
                            event.resume_token,
                        )
                    except ValueError:
                        pass

            first_cycle = False
            try:
                await asyncio.sleep(poll_seconds)
            except asyncio.CancelledError:
                return

    async def _notification_to_event(
        self,
        *,
        payload: str,
        project_filter: set[UUID] | None,
    ) -> pb.ScheduleEvent | None:
        """Convert one NOTIFY payload to a ScheduleEvent.

        Payload shape (from migration 2026_04_27_0007):
            {"op": "insert"|"update"|"delete", "id": <uuid>,
             "project_id": <uuid>}

        Returns ``None`` to skip emission when:
        - JSON is malformed
        - the row's project doesn't match this stream's filter
        - the row turns out to belong to a different scheduler
          (we only emit for ``scheduler='z4j-scheduler'``)
        """
        import json as _json  # noqa: PLC0415

        try:
            data = _json.loads(payload)
        except _json.JSONDecodeError:
            logger.warning(
                "z4j.brain.scheduler_grpc: dropped malformed NOTIFY %r",
                payload,
            )
            return None

        # Audit fix L-2 (Apr 2026): trust ONLY ``data["id"]`` from the
        # NOTIFY payload. Pre-fix the project_id filter ran against
        # the payload's own project_id field, which a Postgres role
        # with NOTIFY privilege on z4j_schedules_changed could
        # forge. We still load the row by id and read its REAL
        # project_id below; using the payload value as a pre-filter
        # is fine for performance but the authoritative check has
        # to be on the row, not on the wire.
        try:
            row_id = UUID(str(data["id"]))
        except (KeyError, ValueError):
            return None

        op_kind = data.get("op")
        if op_kind == "delete":
            # DELETE has no row to load - can't verify project_id at
            # this point. Drop the event when the payload's project_id
            # is missing or doesn't match (best-effort filter; the
            # authoritative full-resync sweep catches misses).
            try:
                row_project_id = UUID(str(data["project_id"]))
            except (KeyError, ValueError):
                return None
            if project_filter is not None and row_project_id not in project_filter:
                return None
            return pb.ScheduleEvent(
                kind=pb.ScheduleEvent.Kind.DELETED,
                deleted_id=str(row_id),
                resume_token=datetime.now(UTC).isoformat(),
            )

        # INSERT / UPDATE: fetch the row to build the full payload.
        # The trigger fires on every INSERT/UPDATE regardless of
        # scheduler value; filter here so we don't leak rows owned
        # by celery-beat etc. into the z4j-scheduler stream.
        from sqlalchemy import select  # noqa: PLC0415

        from z4j_brain.persistence.models import Schedule  # noqa: PLC0415

        async with self._db.session() as session:
            result = await session.execute(
                select(Schedule).where(
                    Schedule.id == row_id,
                    Schedule.scheduler == _SCHEDULER_NAME,
                ),
            )
            row = result.scalar_one_or_none()
        if row is None:
            return None
        if project_filter is not None and row.project_id not in project_filter:
            return None

        kind = (
            pb.ScheduleEvent.Kind.CREATED
            if op_kind == "insert"
            else pb.ScheduleEvent.Kind.UPDATED
        )
        return pb.ScheduleEvent(
            kind=kind,
            schedule=_schedule_to_pb(row),
            resume_token=row.updated_at.isoformat(),
        )

    async def _compute_watch_diff(
        self,
        *,
        project_filter: set[UUID] | None,
        last_seen_at: datetime | None,
        snapshot: dict[UUID, datetime],
        first_cycle: bool,
    ) -> tuple[list[pb.ScheduleEvent], dict[UUID, datetime]]:
        """Read the current schedule set and emit diff events.

        Returns the events to yield and the new snapshot.
        """
        from sqlalchemy import select

        from z4j_brain.persistence.models import Schedule

        async with self._db.session() as session:
            stmt = select(Schedule).where(
                Schedule.scheduler == _SCHEDULER_NAME,
            )
            if project_filter is not None:
                stmt = stmt.where(Schedule.project_id.in_(project_filter))
            result = await session.execute(stmt)
            rows = list(result.scalars().all())

        new_snapshot = {row.id: row.updated_at for row in rows}
        events: list[pb.ScheduleEvent] = []

        for row in rows:
            previous = snapshot.get(row.id)
            if previous is None:
                # New row. On the first cycle with a resume_token we
                # only emit rows whose updated_at is strictly after
                # the token (avoid replaying state the scheduler
                # already has). Without a token we emit nothing on
                # first cycle - the scheduler runs ListSchedules for
                # the bulk load path.
                if first_cycle:
                    if last_seen_at is None:
                        continue
                    if row.updated_at <= last_seen_at:
                        continue
                events.append(
                    pb.ScheduleEvent(
                        kind=pb.ScheduleEvent.Kind.CREATED,
                        schedule=_schedule_to_pb(row),
                        resume_token=row.updated_at.isoformat(),
                    ),
                )
            elif row.updated_at > previous:
                events.append(
                    pb.ScheduleEvent(
                        kind=pb.ScheduleEvent.Kind.UPDATED,
                        schedule=_schedule_to_pb(row),
                        resume_token=row.updated_at.isoformat(),
                    ),
                )

        # Detect deletes: anything in the previous snapshot that is
        # absent from new_snapshot.
        for sid in snapshot.keys() - new_snapshot.keys():
            events.append(
                pb.ScheduleEvent(
                    kind=pb.ScheduleEvent.Kind.DELETED,
                    deleted_id=str(sid),
                    resume_token=datetime.now(UTC).isoformat(),
                ),
            )

        return events, new_snapshot

    # ------------------------------------------------------------------
    # FireSchedule
    # ------------------------------------------------------------------

    async def FireSchedule(  # noqa: N802
        self,
        request: pb.FireScheduleRequest,
        context: grpc.aio.ServicerContext,
    ) -> pb.FireScheduleResponse:
        try:
            schedule_id = UUID(request.schedule_id)
            fire_id = UUID(request.fire_id)
        except ValueError as exc:
            return pb.FireScheduleResponse(
                error_code="invalid_request",
                error_message=str(exc),
            )

        # Audit fix (Apr 2026 follow-up): per-cert FireSchedule rate
        # limit. Bucket is keyed by the peer's primary CN; an empty
        # bucket -> RESOURCE_EXHAUSTED (gRPC standard for rate
        # limiting). The limiter is a no-op when
        # scheduler_grpc_fire_rate_limit_enabled is False.
        from z4j_brain.scheduler_grpc.binding import (  # noqa: PLC0415
            extract_peer_cns,
        )

        peer_cns = extract_peer_cns(context)
        # Pick a single deterministic CN for bucket keying. Sorted +
        # first-element so multi-SAN certs always map to the same
        # bucket regardless of dict iteration order.
        cert_cn = sorted(peer_cns)[0] if peer_cns else ""
        allowed = await self._rate_limiter.consume(cert_cn=cert_cn)
        if not allowed:
            logger.warning(
                "z4j.brain.scheduler_grpc: FireSchedule rate-limited "
                "for cert_cn=%r (schedule_id=%s)",
                cert_cn, schedule_id,
            )
            await context.abort(
                grpc.StatusCode.RESOURCE_EXHAUSTED,
                "FireSchedule rate limit exceeded for this scheduler",
            )
            return pb.FireScheduleResponse()  # unreachable; abort raises

        from z4j_brain.persistence.repositories import (
            AuditLogRepository,
            CommandRepository,
            ScheduleFireRepository,
            ScheduleRepository,
        )

        # Phase 4: parse the scheduler-supplied scheduled_for so the
        # fire-history row records the original tick boundary, not
        # whatever wall-clock the brain runs at.
        scheduled_for_dt = (
            datetime.fromtimestamp(
                request.scheduled_for.seconds
                + request.scheduled_for.nanos / 1e9,
                tz=UTC,
            )
            if request.scheduled_for.seconds
            else datetime.now(UTC)
        )

        # Round-8 audit fix R8-Async-H3 (Apr 2026): bound the number
        # of in-flight FireSchedule handlers that hold a DB session.
        # The handler holds one session across with_for_update +
        # agent lookup + dispatcher.issue + commit; a 100-fire
        # burst with slow agent lookup wedges every connection in
        # the pool and starves unrelated request paths. The
        # semaphore caps concurrent fires to a fraction of the pool
        # so REST handlers and workers always have headroom; excess
        # fires queue here (callers are the scheduler subprocess,
        # which already retries on the GRPC client side).
        sem = _get_fire_schedule_semaphore()
        async with sem, self._db.session() as session:
            # Audit-fix H-2 (Apr 2026): take a row-level lock on the
            # schedule from the moment we read ``is_enabled`` until
            # commit. Without it, a concurrent dashboard
            # ``disable``/``delete`` between this SELECT and the
            # ``commands`` insert would cause the brain to dispatch a
            # fire after the row says "off" - an operator who clicks
            # disable to halt a runaway schedule still sees one more
            # fire land. SQLite ignores ``with_for_update`` (single
            # writer) so dev/test paths are unaffected; Postgres
            # holds the row exclusively for the duration of this
            # transaction.
            from sqlalchemy import select  # noqa: PLC0415

            from z4j_brain.persistence.models import Schedule  # noqa: PLC0415

            schedules = ScheduleRepository(session)
            # Round-3 audit fix (Apr 2026): mirror the
            # ``scheduler == _SCHEDULER_NAME`` filter that List/
            # Watch already apply. Pre-fix, a z4j-scheduler peer
            # could call FireSchedule against a schedule_id that
            # belonged to a different scheduling surface (e.g.
            # ``celery-beat`` rows the operator manages
            # separately). Brain's dispatcher does not check the
            # schedule's ``scheduler`` field before minting a
            # Command, so a cross-scheduler fire would silently
            # land an extra dispatch outside celery-beat's
            # scheduling surface. The fix returns
            # ``schedule_not_found`` (same code as a missing row)
            # so a hostile peer can't enumerate "is this UUID a
            # celery-beat row?" via the error-code split.
            result = await session.execute(
                select(Schedule)
                .where(
                    Schedule.id == schedule_id,
                    Schedule.scheduler == _SCHEDULER_NAME,
                )
                .with_for_update(),
            )
            schedule = result.scalar_one_or_none()
            if schedule is None:
                # Round-4 audit fix (Apr 2026): refund the
                # rate-limit token we already charged. The fire
                # never landed; counting it would over-charge the
                # cert's bucket and could cause spurious 429s
                # during operational events (e.g. a schedule
                # mass-delete + scheduler still ticking the
                # in-flight slots).
                if cert_cn:
                    await self._rate_limiter.refund(cert_cn=cert_cn)
                return pb.FireScheduleResponse(
                    error_code="schedule_not_found",
                    error_message=(
                        f"schedule {schedule_id} not in brain"
                    ),
                )
            # Audit fix M-5 (Apr 2026): per-cert project binding.
            # Bound CNs cannot fire schedules for projects outside
            # their binding list - even if the row exists. Run the
            # check before the is_enabled gate so a bound peer that
            # tries to enumerate "does schedule X exist" via the
            # error-code split (schedule_not_found vs
            # schedule_disabled vs PERMISSION_DENIED) gets the same
            # answer regardless of the row's enabled state.
            from z4j_brain.scheduler_grpc.binding import (  # noqa: PLC0415
                enforce_cn_project_binding,
            )

            await enforce_cn_project_binding(
                context=context,
                project_id=schedule.project_id,
                bindings=self._settings.scheduler_grpc_cn_project_bindings,
                db=self._db,
            )
            if not schedule.is_enabled:
                # Scheduler should have skipped this on its side, but
                # defend against a race between disable + tick.
                # Round-4 audit fix (Apr 2026): refund the token.
                if cert_cn:
                    await self._rate_limiter.refund(cert_cn=cert_cn)
                return pb.FireScheduleResponse(
                    error_code="schedule_disabled",
                    error_message="schedule is disabled",
                )

            agent = await _pick_scheduler_agent_for_fire(
                session=session,
                schedule=schedule,
            )
            if agent is None:
                # No matching online agent. Phase 2: instead of
                # surfacing ``agent_offline`` immediately we buffer
                # the fire in ``pending_fires`` so the replay worker
                # can deliver it the moment a matching agent comes
                # online. The scheduler's ``catch_up`` policy still
                # governs replay behaviour at agent-online time:
                # ``skip`` drops, ``fire_one_missed`` keeps only the
                # latest, ``fire_all_missed`` drains the queue.
                #
                # Schedules with ``catch_up='skip'`` still get a row
                # written - the replay worker observes the policy at
                # replay time and drops them. Writing the row keeps
                # the buffer-depth metric honest ("we noticed an
                # outage"); a feature-flag operator who genuinely
                # wants zero buffering can disable buffering by
                # setting Z4J_PENDING_FIRES_BUFFER_SKIP_POLICY=false
                # (Phase 3 op knob; default True today).
                from datetime import timedelta  # noqa: PLC0415

                from z4j_brain.persistence.repositories import (  # noqa: PLC0415
                    PendingFiresRepository,
                )

                pending = PendingFiresRepository(session)
                retention_days = self._settings.pending_fires_retention_days
                expires_at = datetime.now(UTC) + timedelta(days=retention_days)
                await pending.buffer(
                    fire_id=fire_id,
                    schedule_id=schedule.id,
                    project_id=schedule.project_id,
                    engine=schedule.engine,
                    payload={
                        "schedule_id": str(schedule.id),
                        "schedule_name": schedule.name,
                        "task_name": schedule.task_name,
                        "engine": schedule.engine,
                        "queue": schedule.queue,
                        "args": schedule.args,
                        "kwargs": schedule.kwargs,
                        "fire_id": str(fire_id),
                        "scheduled_for": _ts_iso(request.scheduled_for),
                        "fired_at": _ts_iso(request.fired_at),
                    },
                    scheduled_for=scheduled_for_dt,
                    expires_at=expires_at,
                )
                # Phase 4: also write a schedule_fires row with
                # status="buffered" so the dashboard's fire-history
                # view shows "buffered, awaiting agent" rather than
                # silence. Replay later updates the same row to
                # acked_success/acked_failed via fire_id correlation.
                await ScheduleFireRepository(session).record(
                    fire_id=fire_id,
                    schedule_id=schedule.id,
                    project_id=schedule.project_id,
                    command_id=None,
                    status="buffered",
                    scheduled_for=scheduled_for_dt,
                )
                await session.commit()
                return pb.FireScheduleResponse(buffered=True)

            audit_log = AuditLogRepository(session)
            commands = CommandRepository(session)
            try:
                command = await self._dispatcher.issue(
                    commands=commands,
                    audit_log=audit_log,
                    project_id=schedule.project_id,
                    agent_id=agent.id,
                    action=_FIRE_ACTION,
                    target_type="schedule",
                    target_id=str(schedule.id),
                    payload={
                        "schedule_id": str(schedule.id),
                        "schedule_name": schedule.name,
                        "task_name": schedule.task_name,
                        "engine": schedule.engine,
                        "queue": schedule.queue,
                        "args": schedule.args,
                        "kwargs": schedule.kwargs,
                        "fire_id": str(fire_id),
                        "scheduled_for": _ts_iso(request.scheduled_for),
                        "fired_at": _ts_iso(request.fired_at),
                    },
                    issued_by=None,
                    ip=None,
                    user_agent=None,
                    idempotency_key=f"schedule:{schedule.id}:fire:{fire_id}",
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception(
                    "z4j.brain.scheduler_grpc: FireSchedule failed",
                    extra={
                        "schedule_id": str(schedule_id),
                        "fire_id": str(fire_id),
                    },
                )
                # Phase 4: even on dispatcher failure, write a
                # fire-history row so the dashboard shows "we tried
                # and failed" instead of silence. status="failed"
                # means brain didn't even reach an agent.
                # Audit fix L-3 (Apr 2026): sanitize the exception
                # text before persisting / returning to the wire so
                # SQL fragments / file paths / tracebacks don't leak.
                safe_error = _sanitize_error_message(str(exc))
                try:
                    await ScheduleFireRepository(session).record(
                        fire_id=fire_id,
                        schedule_id=schedule.id,
                        project_id=schedule.project_id,
                        command_id=None,
                        status="failed",
                        scheduled_for=scheduled_for_dt,
                        error_code="brain_error",
                        error_message=safe_error,
                    )
                    await session.commit()
                except Exception:  # noqa: BLE001
                    # Audit-write failure is non-fatal: don't mask the
                    # original error from the scheduler.
                    logger.exception(
                        "z4j.brain.scheduler_grpc: failed to record "
                        "schedule_fire row for failed fire",
                    )
                return pb.FireScheduleResponse(
                    error_code="brain_error",
                    error_message=safe_error or "brain dispatcher failure",
                )

            # Stash the fire_id on the schedule row so
            # AcknowledgeFireResult can correlate. Best-effort - the
            # ack handler can also infer correlation from fire_id
            # alone via the commands table's idempotency_key.
            schedule.last_fire_id = fire_id  # type: ignore[attr-defined]
            # Phase 4: write the fire-history row with the
            # brain-assigned command_id. AcknowledgeFireResult will
            # update it later with the agent's outcome.
            await ScheduleFireRepository(session).record(
                fire_id=fire_id,
                schedule_id=schedule.id,
                project_id=schedule.project_id,
                command_id=command.id,
                status="delivered",
                scheduled_for=scheduled_for_dt,
            )
            await session.commit()

            return pb.FireScheduleResponse(
                command_id=str(command.id),
            )

    # ------------------------------------------------------------------
    # AcknowledgeFireResult
    # ------------------------------------------------------------------

    async def AcknowledgeFireResult(  # noqa: N802
        self,
        request: pb.AcknowledgeFireResultRequest,
        context: grpc.aio.ServicerContext,
    ) -> pb.AcknowledgeFireResultResponse:
        """Update the schedule row to reflect a completed fire.

        The scheduler calls this after it observes (or gives up
        waiting for) the fire result. We update ``last_run_at``,
        bump ``total_runs``, and clear ``last_fire_id`` to make
        room for the next fire.

        The scheduler also re-computes ``next_run_at`` and writes it
        back here so the brain row stays accurate for dashboard
        display - even though the scheduler is the authoritative
        source for "what fires next", the brain shows it on the
        schedule detail page.
        """
        try:
            fire_id = UUID(request.fire_id)
        except ValueError as exc:
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"invalid fire_id: {exc}",
            )
            return pb.AcknowledgeFireResultResponse()

        from sqlalchemy import select, update

        from z4j_brain.persistence.models import Schedule, ScheduleFire

        async with self._db.session() as session:
            # Audit fix I-1 (Apr 2026): authoritative correlation by
            # ``schedule_fires.fire_id`` (which is UNIQUE) instead
            # of ``Schedule.last_fire_id`` (which is a moving target
            # overwritten on every fire). Pre-fix, two back-to-back
            # fires in flight raced: the second fire's FireSchedule
            # would overwrite ``last_fire_id`` BEFORE the first
            # fire's ack landed - the first ack then either
            # silently no-op'd (lookup miss) or, worse, updated the
            # WRONG schedule's last_run_at + total_runs. Joining via
            # schedule_fires makes the lookup unambiguous and
            # idempotent across concurrent fires.
            result = await session.execute(
                select(Schedule)
                .join(
                    ScheduleFire,
                    ScheduleFire.schedule_id == Schedule.id,
                )
                .where(ScheduleFire.fire_id == fire_id),
            )
            schedule = result.scalar_one_or_none()
            if schedule is None:
                logger.info(
                    "z4j.brain.scheduler_grpc: ack for unknown fire_id %s "
                    "(no schedule_fires row; either pre-restart fire "
                    "or different brain instance)",
                    fire_id,
                )
                return pb.AcknowledgeFireResultResponse()

            # Audit fix M-5 (Apr 2026): per-cert project binding.
            # A bound CN cannot ack fires belonging to projects
            # outside its binding list. Critical because ack writes
            # ``last_run_at`` + ``total_runs`` AND triggers
            # notifications, so a rogue bound cert could otherwise
            # forge "fire failed" alerts on cross-project schedules.
            from z4j_brain.scheduler_grpc.binding import (  # noqa: PLC0415
                enforce_cn_project_binding,
            )

            await enforce_cn_project_binding(
                context=context,
                project_id=schedule.project_id,
                bindings=self._settings.scheduler_grpc_cn_project_bindings,
                db=self._db,
            )

            now = datetime.now(UTC)
            # Round-4 audit fix (Apr 2026): atomic SQL-side
            # increment for ``total_runs``. Pre-fix:
            #     updates["total_runs"] = (schedule.total_runs or 0) + 1
            # was a Python-side read-modify-write. Two concurrent
            # acks for two distinct fires of the same schedule both
            # read ``total_runs=5``, both compute 6, both wrote 6
            # → silent lost increment. At enterprise scale (100s
            # of fires/sec across many schedules) the lifetime
            # counter drifted low. Using a SQL expression
            # ``Schedule.total_runs + 1`` makes the increment
            # atomic in Postgres without needing FOR UPDATE on the
            # schedule row.
            updates: dict[str, Any] = {
                "last_run_at": now,
                "updated_at": now,
            }
            if request.status == "success":
                updates["total_runs"] = Schedule.total_runs + 1

            # Audit fix I-1 (Apr 2026): conditionally clear
            # ``last_fire_id`` only if it still points at THIS
            # fire. Concurrently-in-flight fires would otherwise
            # have their pointer wiped by a late ack of an earlier
            # fire. Use the WHERE clause to make the clear atomic
            # without a separate read.
            await session.execute(
                update(Schedule)
                .where(Schedule.id == schedule.id)
                .values(**updates),
            )
            await session.execute(
                update(Schedule)
                .where(
                    Schedule.id == schedule.id,
                    Schedule.last_fire_id == fire_id,
                )
                .values(last_fire_id=None),
            )

            # Phase 4: also update the schedule_fires row with the
            # ack outcome + computed latency. The history view shows
            # the per-fire detail; the circuit breaker reads this to
            # detect consecutive failures.
            from z4j_brain.persistence.repositories import (  # noqa: PLC0415
                ScheduleFireRepository,
            )

            ack_status = (
                "acked_success"
                if request.status == "success"
                else "acked_failed"
            )
            # Audit fix M-3 (Apr 2026): sanitize scheduler-supplied
            # error text before persisting + dispatching downstream.
            # The scheduler is a trusted peer but its error string
            # ultimately came from the agent → engine → task path
            # (untrusted user code), so a malformed return value or
            # log-injection payload could otherwise propagate to the
            # notification template + dashboard rendering.
            safe_error = _sanitize_error_message(request.error)
            safe_error_code = _sanitize_error_message(
                request.error, max_chars=_ERROR_CODE_MAX_CHARS,
            )
            # Round-4 audit fix (Apr 2026): capture
            # ``was_first_ack`` so we only fan out notifications
            # for the FIRST ack of a given fire_id. Duplicate acks
            # (HA scheduler retry, network duplicate) skip the
            # notification dispatch to avoid two pages for one
            # failure.
            _row, was_first_ack = await ScheduleFireRepository(
                session,
            ).acknowledge(
                fire_id=fire_id,
                status=ack_status,
                error_code=safe_error_code,
                error_message=safe_error,
            )

            # Audit fix M-2 (Apr 2026): write an audit row for every
            # ack. Pre-fix the AcknowledgeFireResult handler mutated
            # ``schedules.last_run_at`` + ``total_runs`` and dispatched
            # notifications without leaving an audit breadcrumb. Any
            # alert-injection attempt (a rogue scheduler ACKing as
            # ``failed`` to trigger pages) was forensically invisible.
            from z4j_brain.persistence.repositories import (  # noqa: PLC0415
                AuditLogRepository,
            )
            from z4j_brain.domain.audit_service import (  # noqa: PLC0415
                AuditService as _AuditService,
            )

            try:
                audit_log_repo = AuditLogRepository(session)
                audit_service = _AuditService(self._settings)
                await audit_service.record(
                    audit_log_repo,
                    action=(
                        "schedule.ack.success"
                        if request.status == "success"
                        else "schedule.ack.failed"
                    ),
                    target_type="schedule",
                    target_id=str(schedule.id),
                    result="success",
                    outcome="allow",
                    user_id=None,
                    project_id=schedule.project_id,
                    source_ip=None,
                    metadata={
                        "fire_id": str(fire_id),
                        "ack_status": request.status,
                        # Surface the (sanitised) error so the audit
                        # trail names the failure - without it an
                        # operator investigating an alert flood has
                        # no way to correlate ack-failed audit rows
                        # with the underlying task error.
                        "error": safe_error,
                    },
                )
            except Exception:  # noqa: BLE001
                # Audit failure must not block the ack from
                # committing; the schedule row update + notification
                # dispatch are the load-bearing operations.
                logger.exception(
                    "z4j.brain.scheduler_grpc: failed to record ack "
                    "audit row for fire_id=%s (non-fatal)", fire_id,
                )

            await session.commit()

        # Phase 4 + 5: dispatch notifications matching the spec's
        # split between fire-side and task-side failures
        # (docs/SCHEDULER.md §5.9):
        #
        # - ``schedule.fire.{succeeded,failed}``, outcome of the
        #   FireSchedule round-trip itself.
        # - ``schedule.task_failed``, emitted in addition to
        #   ``schedule.fire.failed`` whenever the agent reports a
        #   task-side failure. The two are aliases at present
        #   because the brain can't yet distinguish "couldn't
        #   reach an agent" from "agent ran the task and it
        #   failed" without a task ↔ command linkage. Operators
        #   subscribe to either trigger and get the alert; if a
        #   future schema change splits the routing, existing
        #   subscriptions keep working.
        #
        # Runs in its own session because evaluate_and_dispatch
        # opens deliveries + may take longer than the ack response
        # should block for. Best-effort - failures here must NOT
        # bubble up (the ack succeeded; missed notification is a
        # secondary concern).
        # Round-4 audit fix (Apr 2026): skip notification fan-out
        # for duplicate acks. Two acks for the same fire_id (HA
        # scheduler retry, network duplicate) would otherwise
        # produce two pages for the same fire.
        if not was_first_ack:
            logger.info(
                "z4j.brain.scheduler_grpc: duplicate ack for "
                "fire_id=%s; skipping notification fan-out",
                fire_id,
            )
            return pb.AcknowledgeFireResultResponse()

        try:
            from z4j_brain.domain.notifications.service import (  # noqa: PLC0415
                NotificationService,
            )

            triggers: list[str] = []
            if request.status == "success":
                triggers.append("schedule.fire.succeeded")
            else:
                triggers.append("schedule.fire.failed")
                triggers.append("schedule.task_failed")
            async with self._db.session() as notify_session:
                svc = NotificationService()
                for trigger in triggers:
                    await svc.evaluate_and_dispatch(
                        session=notify_session,
                        project_id=schedule.project_id,
                        trigger=trigger,
                        task_id=str(fire_id),
                        task_name=schedule.name,
                        engine=schedule.engine,
                        state=request.status,
                        queue=schedule.queue,
                        # Audit fix M-3 (Apr 2026): sanitised error,
                        # not the raw scheduler-supplied string. The
                        # notification template + delivery channels
                        # render this verbatim into emails / Slack /
                        # webhook payloads, so log-injection or
                        # template-shape attacks land here otherwise.
                        exception=safe_error,
                    )
                await notify_session.commit()
        except Exception:  # noqa: BLE001
            logger.exception(
                "z4j.brain.scheduler_grpc: schedule notification "
                "dispatch failed for fire_id=%s (non-fatal)",
                fire_id,
            )

        return pb.AcknowledgeFireResultResponse()

    # ------------------------------------------------------------------
    # Ping
    # ------------------------------------------------------------------

    async def Ping(  # noqa: N802
        self,
        request: pb.PingRequest,
        context: grpc.aio.ServicerContext,
    ) -> pb.PingResponse:
        from z4j_brain import __version__

        ts = Timestamp()
        ts.FromDatetime(datetime.now(UTC))
        return pb.PingResponse(
            brain_version=__version__,
            brain_time=ts,
        )


# =====================================================================
# Helpers
# =====================================================================


def _schedule_to_pb(schedule: Schedule) -> pb.Schedule:
    """Translate a SQLAlchemy ``Schedule`` row to its protobuf form."""
    last_run = Timestamp()
    if schedule.last_run_at is not None:
        last_run.FromDatetime(schedule.last_run_at)
    next_run = Timestamp()
    if schedule.next_run_at is not None:
        next_run.FromDatetime(schedule.next_run_at)

    # JSONB columns may be dict/list - serialise to bytes for the
    # protobuf ``bytes`` fields.
    args_json = json.dumps(schedule.args or []).encode()
    kwargs_json = json.dumps(schedule.kwargs or {}).encode()

    # Optional fields added by the scheduler-columns migration may
    # not be present on rows from a pre-migration brain (defensive
    # ``getattr``).
    catch_up = getattr(schedule, "catch_up", None) or "skip"
    source = getattr(schedule, "source", None) or "dashboard"
    source_hash = getattr(schedule, "source_hash", None) or ""

    return pb.Schedule(
        id=str(schedule.id),
        project_id=str(schedule.project_id),
        engine=schedule.engine,
        name=schedule.name,
        task_name=schedule.task_name,
        kind=schedule.kind.value if hasattr(schedule.kind, "value") else str(schedule.kind),
        expression=schedule.expression,
        timezone=schedule.timezone or "UTC",
        queue=schedule.queue or "",
        args_json=args_json,
        kwargs_json=kwargs_json,
        is_enabled=bool(schedule.is_enabled),
        catch_up=catch_up,
        source=source,
        last_run_at=last_run,
        next_run_at=next_run,
        total_runs=int(schedule.total_runs or 0),
        source_hash=source_hash,
    )


def _ts_iso(ts: Timestamp) -> str:
    """Render a Timestamp as ISO-8601 for a Command payload."""
    if ts.seconds == 0 and ts.nanos == 0:
        return ""
    return datetime.fromtimestamp(
        ts.seconds + ts.nanos / 1_000_000_000, tz=UTC,
    ).isoformat()


async def _pick_scheduler_agent_for_fire(
    *,
    session: Any,
    schedule: Schedule,
) -> Any:
    """Pick an online agent that can run the schedule's engine.

    Returns ``None`` if no match exists. Mirrors the REST handler's
    ``_pick_scheduler_agent`` but filters on ``engine_adapters``
    (the engine name that will actually run the task) rather than
    ``scheduler_adapters`` - z4j-scheduler is the scheduler, the
    agent only needs the engine to execute the task.
    """
    from z4j_brain.persistence.repositories import AgentRepository

    agents = await AgentRepository(session).list_online_for_project(
        schedule.project_id,
    )
    for agent in agents:
        if schedule.engine in (agent.engine_adapters or ()):
            return agent
    return None


__all__ = ["SchedulerServiceImpl"]
