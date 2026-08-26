"""Per-RPC handler implementations for the brain-side ``SchedulerService``.

The brain implements every RPC declared in
``packages/z4j-scheduler/proto/scheduler.proto`` except the legacy reverse
:rpc:`TriggerSchedule` RPC. The current protocol adds exact negotiation, a
validated snapshot, revisioned change replay, per-schedule recovery,
quarantine and cursor-transition RPCs to the legacy list/watch/fire/receipt
surface.

The scheduler-side :rpc:`TriggerSchedule` server is retained for a Brain that
predates durable schedule control. A current Brain dispatches operator manual
fires directly and does not use that reverse RPC.

Per ``docs/SCHEDULER.md §13.2``, every state-changing RPC writes an
audit row through the existing HMAC-chained ``audit_log``. Pure read
RPCs (List/Watch/Ping) skip the audit because the scheduler reads
the same data on every reconnect; auditing each one would balloon
the log without operator value.

Implementation notes:

- Legacy :rpc:`WatchSchedules` uses PostgreSQL ``LISTEN/NOTIFY`` when
  available and polls at ``Z4J_SCHEDULER_GRPC_WATCH_POLL_SECONDS`` on
  SQLite. Revisioned :rpc:`WatchSchedulesV2` polls the durable change log at
  that configured interval on both backends. Neither stream promises a fixed
  delivery latency.
- :rpc:`FireSchedule` re-uses ``_pick_scheduler_agent`` from the REST
  handler so brain stays single-source-of-truth on agent selection.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

import grpc
from google.protobuf.timestamp_pb2 import Timestamp
from sqlalchemy.engine import make_url

from z4j_brain.postgres_tls import asyncpg_tls_connect_args
from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb
from z4j_brain.scheduler_grpc.proto import scheduler_pb2_grpc as pb_grpc

if TYPE_CHECKING:  # pragma: no cover
    from sqlalchemy.ext.asyncio import AsyncSession

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


def _sanitize_error_message(
    raw: str | None, *, max_chars: int = _ERROR_MESSAGE_MAX_CHARS
) -> str | None:
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
        c for c in raw if c in {"\t", " "} or (32 <= ord(c) < 127) or 160 <= ord(c) <= 255
    )
    cleaned = cleaned.strip()
    if not cleaned:
        return None
    if len(cleaned) > max_chars:
        cleaned = cleaned[: max_chars - 3] + "..."
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
# Without this cap the caller-supplied page_size would go
# straight into ``stmt.limit(page_size)`` with no upper bound.
_MAX_LIST_PAGE_SIZE = 1000

# Sentinel scheduler-name brain expects in the ``schedules.scheduler``
# column for rows that are managed by z4j-scheduler. Other rows
# (e.g. ``celery-beat`` rows from the agent-side mirror) are NOT
# returned to z4j-scheduler so the two scheduling surfaces don't
# step on each other.
_SCHEDULER_NAME = "z4j-scheduler"

# What a FireSchedule request has to be to be a cadence acceptance: an id
# derived from the slot it settles (uuid5), and no operator attribution. An
# extra fire on top of the cadence is neither, and this Brain does not take one
# from a scheduler in any protocol generation -- it performs an operator
# trigger itself, because it is the only side that can see a hold.
#
# Naming that refusal apart from "your scheduler is out of date" is the whole
# point of these two constants. The scheduler used to receive the upgrade code
# for an operator's click and rewrite it before an operator ever saw it, which
# left the Brain's own logs, audit rows and any other client holding a
# diagnosis that sends someone to redeploy a component that was never the
# problem. Said once, at the source, so both fire branches say the same thing.
_MANUAL_TRIGGER_REFUSED_CODE = "manual_trigger_not_accepted"
_MANUAL_TRIGGER_REFUSED_MESSAGE = (
    "this Brain does not accept operator triggers through the scheduler; "
    "it fires them itself, so unset scheduler_trigger_url and trigger from "
    "the Brain"
)


#: Per-process bound on
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
    global _fire_schedule_sem  # noqa: PLW0603  module-level singleton lazy-init
    if _fire_schedule_sem is None:
        _fire_schedule_sem = asyncio.Semaphore(_FIRE_SCHEDULE_BOUND)
    return _fire_schedule_sem


async def _advance_legacy_schedule_after_success(
    session: AsyncSession,
    *,
    schedule_id: UUID,
    fire_id: UUID,
    scheduled_for: datetime,
    is_manual: bool,
    observed_at: datetime,
) -> None:
    """Atomically count one successful legacy fire and advance its cursor."""

    from sqlalchemy import case, or_, update

    from z4j_brain.persistence.models import Schedule

    values: dict[str, Any] = {
        "total_runs": Schedule.total_runs + 1,
        "updated_at": case(
            (
                or_(Schedule.updated_at.is_(None), Schedule.updated_at < observed_at),
                observed_at,
            ),
            else_=Schedule.updated_at,
        ),
    }
    if not is_manual:
        values.update(
            last_run_at=case(
                (
                    or_(
                        Schedule.last_run_at.is_(None),
                        Schedule.last_run_at < scheduled_for,
                    ),
                    scheduled_for,
                ),
                else_=Schedule.last_run_at,
            ),
            last_fire_id=case(
                (Schedule.last_fire_id == fire_id, None),
                else_=Schedule.last_fire_id,
            ),
        )
    await session.execute(
        update(Schedule).where(Schedule.id == schedule_id).values(**values),
    )


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
        from collections import defaultdict

        from z4j_brain.domain.scheduler_rate_limiter import (
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
        # Bounded WatchSchedules concurrency. Without this cap,
        # every WatchSchedules RPC would open its own asyncpg
        # LISTEN connection with no bound - a misbehaving
        # scheduler that opened+dropped streams in a loop would
        # drain Postgres ``max_connections`` and kill brain's
        # main pool. Two locks: a global counter caps total
        # streams across the brain process; a per-CN counter
        # caps any single cert from monopolising the global cap.
        #
        # The counter-under-lock pattern is used instead of
        # ``asyncio.Semaphore`` + ``wait_for(..., timeout=0)``
        # because the semaphore approach has two leak vectors:
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
        from z4j_brain.scheduler_grpc.binding import (
            enforce_cn_project_binding,
            filter_project_ids_by_binding,
        )

        bindings = self._settings.scheduler_grpc_cn_project_bindings

        # Clamp caller-supplied page_size to
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
                # Enforce per-cert project
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
                    context=context,
                    bindings=bindings,
                    db=self._db,
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
                    yield _schedule_to_pb(row, include_current=False)
                if len(rows) < page_size:
                    break
                offset += page_size

    # ------------------------------------------------------------------
    # WatchSchedules - server streaming
    # ------------------------------------------------------------------

    async def WatchSchedules(  # noqa: N802, PLR0912  gRPC method name; branch-heavy stream handler
        self,
        request: pb.WatchSchedulesRequest,
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[pb.ScheduleEvent]:
        """Stream create/update/delete events to the scheduler.

        Two implementations, picked at runtime based on the DB
        dialect:

        - **Postgres**: dedicated asyncpg connection LISTENing on
          ``z4j_schedules_changed`` (set up by migration
          ``2026_04_27_0007_sched_notify``). Changes wake the stream
          through LISTEN/NOTIFY rather than a fixed polling interval.
        - **SQLite**: polls ``schedules.updated_at`` every
          ``Z4J_SCHEDULER_GRPC_WATCH_POLL_SECONDS`` and emits diffs
          because SQLite has no LISTEN/NOTIFY.

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

        # Per-cert project binding. For an
        # explicit project_id, enforce binding. For "all projects"
        # mode (project_id=None), narrow to the peer's bound set.
        from z4j_brain.scheduler_grpc.binding import (
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
                context=context,
                bindings=bindings,
                db=self._db,
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

        # Bounded WatchSchedules
        # concurrency. Acquire a global semaphore + bump the per-CN
        # counter; release both on stream end. RESOURCE_EXHAUSTED on
        # cap so the scheduler client retries with backoff (its
        # ``_backoff_or_stop`` already handles this).
        from z4j_brain.scheduler_grpc.binding import (
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
                    cert_cn,
                    per_cert_cap,
                )
                await context.abort(
                    grpc.StatusCode.RESOURCE_EXHAUSTED,
                    "WatchSchedules per-cert concurrent stream cap reached",
                )
                return
            self._watch_per_cert_count[cert_cn] = current + 1
        # Acquire the global concurrency slot via the counter-
        # under-lock pattern. An ``asyncio.wait_for(self.
        # _watch_global_sem.acquire(), 0)`` shape would have TWO
        # leak vectors:
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
            # Shield BOTH decrements so a cancellation landing
            # on the lock-acquire await doesn't strand the slot.
            # The shielded coroutine below holds two locks
            # back-to-back; on cancel the inner work runs to
            # completion, the cancellation then propagates to
            # whatever was awaiting us.
            await asyncio.shield(
                self._release_watch_slot(cert_cn),
            )

    async def _release_watch_slot(self, cert_cn: str) -> None:
        """Symmetric decrement of both the global counter and
        the per-cert counter. Wrapped in ``asyncio.shield`` by
        the caller so a cancel landing on the lock-acquire await
        can't strand
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
            import asyncpg
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

        # Open a dedicated asyncpg connection using the same address and TLS
        # policy as the SQLAlchemy engine. Audit fix L-1 (Apr 2026): pass connection
        # parameters as kwargs (host/port/user/password/database)
        # instead of materializing a plain-text URL string with the
        # password in it. The string-based path leaves the password
        # in heap until GC and would surface in any future log line
        # / core dump / exception traceback inside this function.
        # ``URL.translate_connect_args`` is the canonical SQLAlchemy
        # accessor for the libpq-style connection dict. Translate the captured
        # settings' libpq TLS keys separately and pass the resulting explicit
        # asyncpg ``ssl`` argument.
        tls_connect_args = asyncpg_tls_connect_args(
            self._settings.database_url,
        )
        connect_kwargs = make_url(self._settings.database_url).translate_connect_args(
            username="user",
        )
        conn = await asyncpg.connect(
            host=connect_kwargs.get("host"),
            port=connect_kwargs.get("port"),
            user=connect_kwargs.get("user"),
            password=connect_kwargs.get("password"),
            database=connect_kwargs.get("database"),
            server_settings={"application_name": "z4j-brain-watch-stream"},
            **tls_connect_args,
        )
        notification_queue: asyncio.Queue = asyncio.Queue()

        def _on_notify(_conn, _pid, _channel, payload: str) -> None:
            # Called by asyncpg in the connection's task. Just
            # enqueue - the consumer below does the actual work.
            with contextlib.suppress(asyncio.QueueFull):
                notification_queue.put_nowait(payload)

        await conn.add_listener("z4j_schedules_changed", _on_notify)
        try:
            while not context.cancelled():
                try:
                    payload = await asyncio.wait_for(
                        notification_queue.get(),
                        timeout=30.0,
                    )
                except TimeoutError:
                    # Liveness ping - keeps the gRPC stream alive
                    # under no-traffic conditions and lets us notice
                    # context cancellation without blocking forever.
                    continue
                except asyncio.CancelledError:
                    return

                event = await self._notification_to_event(
                    payload=payload,
                    project_filter=project_filter,
                )
                if event is not None:
                    yield event
        finally:
            with contextlib.suppress(Exception):
                await conn.remove_listener(
                    "z4j_schedules_changed",
                    _on_notify,
                )
            with contextlib.suppress(Exception):
                await conn.close()

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
            except Exception:
                logger.exception(
                    "z4j.brain.scheduler_grpc: watch poll crashed",
                )
                await asyncio.sleep(poll_seconds)
                continue

            for event in events:
                yield event
                if event.resume_token:
                    with contextlib.suppress(ValueError):
                        last_seen_at = datetime.fromisoformat(
                            event.resume_token,
                        )

            first_cycle = False
            try:
                await asyncio.sleep(poll_seconds)
            except asyncio.CancelledError:
                return

    async def _notification_to_event(  # noqa: PLR0911  notification decode dispatch
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
        import json as _json

        try:
            data = _json.loads(payload)
        except _json.JSONDecodeError:
            logger.warning(
                "z4j.brain.scheduler_grpc: dropped malformed NOTIFY %r",
                payload,
            )
            return None

        # Trust ONLY ``data["id"]`` from the NOTIFY payload. The
        # project_id filter must NOT run against the payload's
        # own project_id field, because a Postgres role with
        # NOTIFY privilege on z4j_schedules_changed could forge
        # it. We load the row by id and read its REAL project_id
        # below; using the payload value as a pre-filter is fine
        # for performance but the authoritative check has to be
        # on the row, not on the wire.
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
        from sqlalchemy import select

        from z4j_brain.persistence.models import Schedule

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
            pb.ScheduleEvent.Kind.CREATED if op_kind == "insert" else pb.ScheduleEvent.Kind.UPDATED
        )
        return pb.ScheduleEvent(
            kind=kind,
            schedule=_schedule_to_pb(row, include_current=False),
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
                        schedule=_schedule_to_pb(row, include_current=False),
                        resume_token=row.updated_at.isoformat(),
                    ),
                )
            elif row.updated_at > previous:
                events.append(
                    pb.ScheduleEvent(
                        kind=pb.ScheduleEvent.Kind.UPDATED,
                        schedule=_schedule_to_pb(row, include_current=False),
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
    # Boundary D current-protocol control plane
    # ------------------------------------------------------------------

    async def NegotiateSchedulerProtocol(  # noqa: N802
        self,
        request: pb.NegotiateSchedulerProtocolRequest,
        context: grpc.aio.ServicerContext,
    ) -> pb.NegotiateSchedulerProtocolResponse:
        from sqlalchemy.exc import SQLAlchemyError

        from z4j_brain.persistence.repositories.schedule_control import (
            ScheduleControlRepository,
            ScheduleControlStateUnavailableError,
        )
        from z4j_brain.scheduler_grpc.protocol import (
            capabilities_are_exact,
            current_capabilities,
        )

        if not capabilities_are_exact(request.offered):
            await context.abort(
                grpc.StatusCode.FAILED_PRECONDITION,
                "scheduler cadence/protocol tuple does not match this Brain",
            )
        async with self._db.session() as session:
            try:
                await ScheduleControlRepository(session).require_revision_state()
            except (ScheduleControlStateUnavailableError, SQLAlchemyError):
                await context.abort(
                    grpc.StatusCode.UNAVAILABLE,
                    "Boundary D control activation is not complete",
                )
        return pb.NegotiateSchedulerProtocolResponse(
            selected=current_capabilities(),
        )

    async def ListScheduleSnapshot(  # noqa: N802
        self,
        request: pb.ListScheduleSnapshotRequest,
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[pb.ScheduleSnapshotFrame]:
        from z4j_brain.persistence.repositories.schedule_control import (
            ScheduleControlRepository,
            ScheduleControlStateUnavailableError,
        )
        from z4j_brain.scheduler_grpc.binding import (
            enforce_cn_project_binding,
            filter_project_ids_by_binding,
        )
        from z4j_brain.scheduler_grpc.wire import (
            SNAPSHOT_FORMAT_VERSION,
            schedule_to_pb,
            stable_snapshot_digest,
        )

        if request.snapshot_format_version != SNAPSHOT_FORMAT_VERSION:
            await context.abort(
                grpc.StatusCode.FAILED_PRECONDITION,
                "unsupported stable snapshot format",
            )
            return
        project_id: UUID | None = None
        allowed_project_ids: set[UUID] | None = None
        if request.project_id:
            project_id = await _bound_project_id(
                request.project_id,
                context=context,
                bindings=self._settings.scheduler_grpc_cn_project_bindings,
                db=self._db,
                enforce=enforce_cn_project_binding,
            )
        else:
            allowed_project_ids = await filter_project_ids_by_binding(
                context=context,
                bindings=self._settings.scheduler_grpc_cn_project_bindings,
                db=self._db,
            )
        snapshot_id = uuid.uuid4()
        async with self._db.session() as session:
            try:
                snapshot = await ScheduleControlRepository(session).stable_snapshot(
                    project_id=project_id,
                    allowed_project_ids=allowed_project_ids,
                )
            except ScheduleControlStateUnavailableError:
                await context.abort(
                    grpc.StatusCode.UNAVAILABLE,
                    "Boundary D control activation is not complete",
                )
                return
            rows = [schedule_to_pb(row) for row in snapshot.rows]
            digest = stable_snapshot_digest(
                snapshot_id=snapshot_id,
                project_id=project_id,
                watermark=snapshot.watermark,
                rows=rows,
            )
            yield pb.ScheduleSnapshotFrame(
                header=pb.ScheduleSnapshotHeader(
                    format_version=SNAPSHOT_FORMAT_VERSION,
                    snapshot_id=str(snapshot_id),
                    project_id=(str(project_id) if project_id is not None else ""),
                ),
            )
            for row in rows:
                yield pb.ScheduleSnapshotFrame(
                    row=pb.ScheduleSnapshotRow(
                        snapshot_id=str(snapshot_id),
                        schedule=row,
                    ),
                )
            yield pb.ScheduleSnapshotFrame(
                complete=pb.ScheduleSnapshotComplete(
                    format_version=SNAPSHOT_FORMAT_VERSION,
                    snapshot_id=str(snapshot_id),
                    project_id=(str(project_id) if project_id is not None else ""),
                    watermark=snapshot.watermark,
                    row_count=len(rows),
                    digest=digest,
                ),
            )

    async def WatchSchedulesV2(  # noqa: N802, PLR0911, PLR0912, PLR0915 - ordered stream state machine
        self,
        request: pb.WatchSchedulesV2Request,
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[pb.ScheduleWatchFrame]:
        from sqlalchemy import select

        from z4j_brain.persistence.models import ScheduleChangeLog
        from z4j_brain.persistence.repositories.schedule_control import (
            ScheduleControlStateUnavailableError,
        )
        from z4j_brain.scheduler_grpc.binding import (
            enforce_cn_project_binding,
            filter_project_ids_by_binding,
        )
        from z4j_brain.scheduler_grpc.protocol import CURRENT_REVISION_WATCH_VERSION
        from z4j_brain.scheduler_grpc.wire import ScheduleWireError, schedule_to_pb

        if request.watch_format_version != CURRENT_REVISION_WATCH_VERSION:
            await context.abort(
                grpc.StatusCode.FAILED_PRECONDITION,
                "unsupported schedule Watch format",
            )
            return
        if request.after_revision < 0:
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                "schedule Watch cursor cannot be negative",
            )
            return
        project_id: UUID | None = None
        allowed_project_ids: set[UUID] | None = None
        if request.project_id:
            project_id = await _bound_project_id(
                request.project_id,
                context=context,
                bindings=self._settings.scheduler_grpc_cn_project_bindings,
                db=self._db,
                enforce=enforce_cn_project_binding,
            )
        else:
            allowed_project_ids = await filter_project_ids_by_binding(
                context=context,
                bindings=self._settings.scheduler_grpc_cn_project_bindings,
                db=self._db,
            )
        cursor = int(request.after_revision)
        poll_seconds = float(self._settings.scheduler_grpc_watch_poll_seconds)
        while not context.cancelled():
            async with self._db.session() as session:
                from z4j_brain.persistence.repositories.schedule_control import (
                    ScheduleControlRepository,
                )

                repository = ScheduleControlRepository(session)
                try:
                    await repository.begin_stable_read()
                    state = await repository.require_revision_state()
                except ScheduleControlStateUnavailableError:
                    await context.abort(
                        grpc.StatusCode.UNAVAILABLE,
                        "Boundary D control activation is not complete",
                    )
                    return
                if cursor < state.change_log_pruned_through:
                    await context.abort(
                        grpc.StatusCode.OUT_OF_RANGE,
                        "schedule Watch cursor is below retained history",
                    )
                    return
                server_revision = int(state.current_revision)
                result = await session.execute(
                    select(ScheduleChangeLog)
                    .where(
                        ScheduleChangeLog.revision > cursor,
                        ScheduleChangeLog.revision <= server_revision,
                    )
                    .order_by(ScheduleChangeLog.revision)
                    .limit(500),
                )
                changes = list(result.scalars().all())

            scanned_through: int | None = None
            for change in changes:
                revision = int(change.revision)
                relevant = change.schedule_owner == _SCHEDULER_NAME and (
                    (project_id is not None and change.project_id == project_id)
                    or (
                        project_id is None
                        and (
                            allowed_project_ids is None or change.project_id in allowed_project_ids
                        )
                    )
                )
                if not relevant:
                    scanned_through = revision
                    cursor = revision
                    continue
                if scanned_through is not None:
                    yield pb.ScheduleWatchFrame(
                        format_version=CURRENT_REVISION_WATCH_VERSION,
                        scanned_through=pb.ScannedThrough(
                            scanned_through_revision=scanned_through,
                            server_revision=server_revision,
                        ),
                    )
                    scanned_through = None
                if change.change_kind == "upsert" and change.snapshot is not None:
                    source = change.snapshot.get("schedule")
                    if not isinstance(source, dict):
                        await context.abort(
                            grpc.StatusCode.DATA_LOSS,
                            "schedule change log contains a malformed snapshot",
                        )
                        return
                    try:
                        projected = schedule_to_pb(source)
                    except ScheduleWireError as wire_error:
                        # An envelope that cannot say whether the schedule may
                        # run is as unusable as one with no schedule in it,
                        # and the stream has to stop rather than let the
                        # scheduler act on the half of it that did decode.
                        #
                        # In practice the likeliest cause is not corruption but
                        # version skew: a brain replica from an earlier release
                        # is still live against a migrated database and writes
                        # envelopes without the fields this release reads. The
                        # message says so, because "malformed snapshot" sends an
                        # operator looking for a damaged database when what they
                        # have is a half-finished rollout. The scheduler
                        # recovers on its own by reconnecting and re-syncing
                        # from live rows, but it refuses to fire while it does,
                        # and an older replica cannot honour a pause at all.
                        await context.abort(
                            grpc.StatusCode.DATA_LOSS,
                            "schedule change log contains a snapshot this "
                            f"release cannot project ({wire_error}). If a brain "
                            "replica from an earlier release is still running "
                            "against this database, finish the rollout: mixed "
                            "brain versions cannot agree on whether a schedule "
                            "is held.",
                        )
                        return
                    envelope = pb.ScheduleChange(
                        kind=pb.ScheduleChange.Kind.UPSERT,
                        revision=revision,
                        project_id=str(change.project_id),
                        schedule=projected,
                    )
                elif change.change_kind == "delete" and change.snapshot is None:
                    envelope = pb.ScheduleChange(
                        kind=pb.ScheduleChange.Kind.TOMBSTONE,
                        revision=revision,
                        project_id=str(change.project_id),
                        deleted_id=str(change.schedule_id),
                    )
                else:
                    await context.abort(
                        grpc.StatusCode.DATA_LOSS,
                        "schedule change log contains a contradictory envelope",
                    )
                    return
                yield pb.ScheduleWatchFrame(
                    format_version=CURRENT_REVISION_WATCH_VERSION,
                    change=envelope,
                )
                cursor = revision
            if scanned_through is not None:
                yield pb.ScheduleWatchFrame(
                    format_version=CURRENT_REVISION_WATCH_VERSION,
                    scanned_through=pb.ScannedThrough(
                        scanned_through_revision=scanned_through,
                        server_revision=server_revision,
                    ),
                )
            if changes:
                continue
            try:
                await asyncio.sleep(poll_seconds)
            except asyncio.CancelledError:
                return

    async def GetScheduleState(  # noqa: N802
        self,
        request: pb.GetScheduleStateRequest,
        context: grpc.aio.ServicerContext,
    ) -> pb.GetScheduleStateResponse:
        from sqlalchemy import select

        from z4j_brain.persistence.models import Schedule
        from z4j_brain.persistence.repositories.schedule_control import (
            ScheduleControlRepository,
            ScheduleControlStateUnavailableError,
        )
        from z4j_brain.scheduler_grpc.binding import enforce_cn_project_binding
        from z4j_brain.scheduler_grpc.wire import schedule_to_pb

        project_id = await _bound_project_id(
            request.project_id,
            context=context,
            bindings=self._settings.scheduler_grpc_cn_project_bindings,
            db=self._db,
            enforce=enforce_cn_project_binding,
        )
        try:
            schedule_id = UUID(request.schedule_id)
        except ValueError:
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                "schedule_id is not a UUID",
            )
            return pb.GetScheduleStateResponse()
        if request.minimum_observed_revision < 0:
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                "minimum observed revision cannot be negative",
            )
        async with self._db.session() as session:
            try:
                repository = ScheduleControlRepository(session)
                await repository.begin_stable_read()
                state = await repository.require_revision_state()
            except ScheduleControlStateUnavailableError:
                await context.abort(
                    grpc.StatusCode.UNAVAILABLE,
                    "Boundary D control activation is not complete",
                )
                return pb.GetScheduleStateResponse()
            if state.current_revision < request.minimum_observed_revision:
                await context.abort(
                    grpc.StatusCode.FAILED_PRECONDITION,
                    "Brain has not reached the caller's observed revision",
                )
            result = await session.execute(
                select(Schedule).where(
                    Schedule.project_id == project_id,
                    Schedule.id == schedule_id,
                    Schedule.scheduler == _SCHEDULER_NAME,
                ),
            )
            row = result.scalar_one_or_none()
            if row is not None:
                if not row.schedule_revision or (
                    row.schedule_revision < request.minimum_observed_revision
                ):
                    await context.abort(
                        grpc.StatusCode.FAILED_PRECONDITION,
                        "schedule state is older than the caller's observation",
                    )
                return pb.GetScheduleStateResponse(
                    observed_revision=row.schedule_revision,
                    schedule=schedule_to_pb(row),
                )
            return pb.GetScheduleStateResponse(
                observed_revision=state.current_revision,
                absence=pb.ScheduleAbsence(
                    project_id=str(project_id),
                    schedule_id=str(schedule_id),
                ),
            )

    async def QuarantineSchedule(  # noqa: N802
        self,
        request: pb.QuarantineScheduleRequest,
        context: grpc.aio.ServicerContext,
    ) -> pb.QuarantineScheduleResponse:
        from z4j_brain.persistence.repositories.schedule_control import (
            ScheduleControlRepository,
        )
        from z4j_brain.scheduler_grpc.binding import enforce_cn_project_binding

        if not _is_current_protocol_epoch(request.scheduler_protocol_epoch):
            await context.abort(
                grpc.StatusCode.FAILED_PRECONDITION,
                "unsupported scheduler protocol epoch",
            )
        project_id = await _bound_project_id(
            request.project_id,
            context=context,
            bindings=self._settings.scheduler_grpc_cn_project_bindings,
            db=self._db,
            enforce=enforce_cn_project_binding,
        )
        try:
            schedule_id = UUID(request.schedule_id)
            token = UUID(request.observed_control_token)
        except ValueError:
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                "schedule_id/control token is not a UUID",
            )
            return pb.QuarantineScheduleResponse()
        async with self._db.session(write=True) as session:
            from z4j_brain.persistence.repositories import AuditLogRepository

            repository = ScheduleControlRepository(session)
            state = await repository.require_revision_state()
            try:
                transition = await repository.quarantine(
                    project_id=project_id,
                    schedule_id=schedule_id,
                    observed_control_token=token,
                    reason_code=request.reason_code,
                    detail=request.detail,
                    occurred_at=datetime.now(UTC),
                )
            except ValueError as exc:
                await context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))
                return pb.QuarantineScheduleResponse()
            if transition.outcome == "applied":
                await self._audit.record(
                    AuditLogRepository(session),
                    action="schedule.quarantined",
                    target_type="schedule",
                    target_id=str(schedule_id),
                    result="success",
                    outcome="deny",
                    project_id=project_id,
                    metadata={
                        "control_token": str(token),
                        "reason_code": request.reason_code.strip(),
                    },
                )
            await session.commit()
            outcome = {
                "applied": pb.QuarantineOutcome.QUARANTINE_APPLIED,
                "already_applied": (pb.QuarantineOutcome.QUARANTINE_ALREADY_APPLIED),
                "stale_control": pb.QuarantineOutcome.QUARANTINE_STALE_CONTROL,
                "not_found": pb.QuarantineOutcome.QUARANTINE_NOT_FOUND,
            }[transition.outcome]
            observed_revision = (
                int(transition.schedule.schedule_revision or 0)
                if transition.schedule is not None
                else int(state.current_revision)
            )
            return pb.QuarantineScheduleResponse(
                outcome=outcome,
                observed_revision=observed_revision,
            )

    async def AdvanceScheduleCursor(  # noqa: N802
        self,
        request: pb.AdvanceScheduleCursorRequest,
        context: grpc.aio.ServicerContext,
    ) -> pb.AdvanceScheduleCursorResponse:
        from z4j_brain.persistence.repositories.schedule_control import (
            ScheduleControlConflictError,
            ScheduleControlRepository,
        )
        from z4j_brain.scheduler_grpc.binding import enforce_cn_project_binding

        if not _is_current_protocol_epoch(request.scheduler_protocol_epoch):
            await context.abort(
                grpc.StatusCode.FAILED_PRECONDITION,
                "unsupported scheduler protocol epoch",
            )
        project_id = await _bound_project_id(
            request.project_id,
            context=context,
            bindings=self._settings.scheduler_grpc_cn_project_bindings,
            db=self._db,
            enforce=enforce_cn_project_binding,
        )
        try:
            schedule_id = UUID(request.schedule_id)
            token = UUID(request.observed_control_token)
            expected_last = _pb_datetime(request.expected_last_run_at)
            expected_next = _required_pb_datetime(
                request.expected_next_run_at,
                field="expected_next_run_at",
            )
            skipped_through = _required_pb_datetime(
                request.skipped_through,
                field="skipped_through",
            )
            prepared_next = _pb_datetime(request.prepared_next_run_at)
        except ValueError as exc:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))
            return pb.AdvanceScheduleCursorResponse()

        async with self._db.session(write=True) as session:
            from z4j_brain.persistence.repositories import AuditLogRepository

            try:
                transition = await ScheduleControlRepository(
                    session,
                ).advance_cursor(
                    project_id=project_id,
                    schedule_id=schedule_id,
                    observed_control_token=token,
                    definition_digest=request.definition_digest,
                    expected_revision=request.expected_schedule_revision,
                    expected_last_run_at=expected_last,
                    expected_next_run_at=expected_next,
                    skipped_through=skipped_through,
                    prepared_next_run_at=prepared_next,
                    cadence_semantics_version=request.cadence_semantics_version,
                    cadence_fingerprint=request.cadence_runtime_fingerprint,
                    occurred_at=datetime.now(UTC),
                )
            except ScheduleControlConflictError as exc:
                await context.abort(grpc.StatusCode.FAILED_PRECONDITION, str(exc))
                return pb.AdvanceScheduleCursorResponse()
            if transition.disposition == "applied":
                await self._audit.record(
                    AuditLogRepository(session),
                    action="schedule.cadence_skipped_no_work",
                    target_type="schedule",
                    target_id=str(schedule_id),
                    result="success",
                    outcome="allow",
                    project_id=project_id,
                    metadata={
                        "control_token": str(token),
                        "expected_revision": request.expected_schedule_revision,
                        "skipped_through": skipped_through.isoformat(),
                        "prepared_next_run_at": (
                            prepared_next.isoformat() if prepared_next is not None else None
                        ),
                    },
                )
            await session.commit()

            row = transition.schedule
            if row is None:
                return pb.AdvanceScheduleCursorResponse(
                    disposition=(pb.CursorTransitionDisposition.CURSOR_STALE_CONTROL_REFRESH),
                    error_code="schedule_not_found",
                    error_message="schedule does not exist",
                )
            disposition = {
                "applied": pb.CursorTransitionDisposition.CURSOR_APPLIED,
                "idempotent": pb.CursorTransitionDisposition.CURSOR_IDEMPOTENT,
                "slot_resolved_refresh": (
                    pb.CursorTransitionDisposition.CURSOR_SLOT_RESOLVED_REFRESH
                ),
                "stale_control_refresh": (
                    pb.CursorTransitionDisposition.CURSOR_STALE_CONTROL_REFRESH
                ),
                "cadence_semantics_mismatch": (
                    pb.CursorTransitionDisposition.CURSOR_CADENCE_SEMANTICS_MISMATCH
                ),
            }[transition.disposition]
            return pb.AdvanceScheduleCursorResponse(
                disposition=disposition,
                committed_revision=int(transition.committed_revision or 0),
                committed_last_run_at=_pb_timestamp(
                    row.last_run_at if transition.committed_revision is not None else None,
                ),
                committed_next_run_at=_pb_timestamp(
                    row.next_run_at if transition.committed_revision is not None else None,
                ),
                live_control_token=str(row.control_token or ""),
                live_revision=int(row.schedule_revision or 0),
                live_last_run_at=_pb_timestamp(row.last_run_at),
                live_next_run_at=_pb_timestamp(row.next_run_at),
            )

    # ------------------------------------------------------------------
    # FireSchedule
    # ------------------------------------------------------------------

    async def FireSchedule(  # noqa: N802, PLR0911, PLR0912, PLR0915  gRPC method name; fire dispatch
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
        # The fire_id's UUID VERSION is protocol-significant -- a cadence
        # fire is uuid5 (v5, derive_fire_id) and a manual Trigger Now is uuid4
        # (v4). The ack path classifies ``version != 5`` as manual, so an
        # out-of-protocol version would be silently mis-classified. Reject any
        # other version up front (defense-in-depth; the scheduler is a trusted
        # peer, so this is unreachable via any in-tree path). A v5 that is
        # actually manual is indistinguishable at the wire and is closed by the
        # deferred proto ``manual`` flag, not here.
        if fire_id.version not in (4, 5):
            return pb.FireScheduleResponse(
                error_code="invalid_request",
                error_message=(
                    f"fire_id UUID version {fire_id.version} is not supported "
                    "(expected v4 manual or v5 cadence)"
                ),
            )

        # A5: the operator who triggered this fire (empty for
        # scheduler-driven cadence fires). Malformed -> unattributed
        # rather than a hard reject; attribution is best-effort metadata.
        triggered_by_user_id: UUID | None = None
        if request.triggered_by_user_id:
            try:
                triggered_by_user_id = UUID(request.triggered_by_user_id)
            except ValueError:
                triggered_by_user_id = None

        # Per-cert FireSchedule rate
        # limit. Bucket is keyed by the peer's primary CN; an empty
        # bucket -> RESOURCE_EXHAUSTED (gRPC standard for rate
        # limiting). The limiter is a no-op when
        # scheduler_grpc_fire_rate_limit_enabled is False.
        from z4j_brain.scheduler_grpc.binding import (
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
                cert_cn,
                schedule_id,
            )
            await context.abort(
                grpc.StatusCode.RESOURCE_EXHAUSTED,
                "FireSchedule rate limit exceeded for this scheduler",
            )
            return pb.FireScheduleResponse()  # unreachable; abort raises

        if request.scheduler_protocol_epoch:
            return await self._fire_current_schedule(
                request=request,
                context=context,
                schedule_id=schedule_id,
                fire_id=fire_id,
                cert_cn=cert_cn,
            )

        from z4j_brain.persistence.repositories.schedule_control import (
            ScheduleControlRepository,
            ScheduleControlStateUnavailableError,
        )

        try:
            async with self._db.session() as control_session:
                control_active = await ScheduleControlRepository(
                    control_session,
                ).control_is_active()
        except ScheduleControlStateUnavailableError:
            return pb.FireScheduleResponse(
                disposition=(pb.FireDisposition.FIRE_RETRYABLE_OR_AMBIGUOUS),
                error_code="schedule_control_unavailable",
                error_message="durable schedule control evidence is unavailable",
            )
        if control_active:
            return await self._fire_legacy_current_schedule(
                request=request,
                context=context,
                schedule_id=schedule_id,
                fire_id=fire_id,
                cert_cn=cert_cn,
            )

        from z4j_brain.persistence.repositories import (
            AuditLogRepository,
            CommandRepository,
            ScheduleFireRepository,
        )

        # Phase 4: parse the scheduler-supplied scheduled_for so the
        # fire-history row records the original tick boundary, not
        # whatever wall-clock the brain runs at.
        scheduled_for_dt = (
            datetime.fromtimestamp(
                request.scheduled_for.seconds + request.scheduled_for.nanos / 1e9,
                tz=UTC,
            )
            if request.scheduled_for.seconds
            else datetime.now(UTC)
        )
        # (Defensive): derive_fire_id ignores sub-second precision, so a
        # fire_id identifies a whole-SECOND slot. Truncate the recorded
        # scheduled_for to match, so the same fire_id can never be persisted with
        # two divergent sub-second values (which would collide on the Postgres
        # (fire_id, scheduled_for) composite key / make the SQLite upgrade lookup
        # miss). Cadence recomputes are already microsecond=0; this only
        # normalises the wall-clock fallback / manual path.
        scheduled_for_dt = scheduled_for_dt.replace(microsecond=0)

        # Bound the number of in-flight FireSchedule handlers that
        # hold a DB session.
        # The handler holds one session across with_for_update +
        # agent lookup + dispatcher.issue + commit; a 100-fire
        # burst with slow agent lookup wedges every connection in
        # the pool and starves unrelated request paths. The
        # semaphore caps concurrent fires to a fraction of the pool
        # so REST handlers and workers always have headroom; excess
        # fires queue here (callers are the scheduler subprocess,
        # which already retries on the GRPC client side).
        sem = _get_fire_schedule_semaphore()
        async with sem, self._db.session(write=True) as session:
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
            from sqlalchemy import select

            from z4j_brain.persistence.models import Schedule

            # Mirror the ``scheduler == _SCHEDULER_NAME`` filter
            # that List/Watch already apply. Otherwise a
            # z4j-scheduler peer could call FireSchedule against
            # a schedule_id that belonged to a different
            # scheduling surface (e.g. ``celery-beat`` rows the
            # operator manages separately). Brain's dispatcher
            # does not check the schedule's ``scheduler`` field
            # before minting a Command, so a cross-scheduler
            # fire would silently land an extra dispatch outside
            # celery-beat's scheduling surface. We return
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
                # Refund the rate-limit token we already charged. The fire
                # never landed; counting it would over-charge the
                # cert's bucket and could cause spurious 429s
                # during operational events (e.g. a schedule
                # mass-delete + scheduler still ticking the
                # in-flight slots).
                response = pb.FireScheduleResponse(
                    error_code="schedule_not_found",
                    error_message=(f"schedule {schedule_id} not in brain"),
                )
                if cert_cn:
                    await self._rate_limiter.refund(
                        cert_cn=cert_cn,
                        session=session,
                    )
                return response
            # Per-cert project binding.
            # Bound CNs cannot fire schedules for projects outside
            # their binding list - even if the row exists. Run the
            # check before the is_enabled gate so a bound peer that
            # tries to enumerate "does schedule X exist" via the
            # error-code split (schedule_not_found vs
            # schedule_disabled vs PERMISSION_DENIED) gets the same
            # answer regardless of the row's enabled state.
            from z4j_brain.scheduler_grpc.binding import (
                enforce_cn_project_binding,
            )

            await enforce_cn_project_binding(
                context=context,
                project_id=schedule.project_id,
                bindings=self._settings.scheduler_grpc_cn_project_bindings,
                db=self._db,
            )
            # A5: only attribute this fire to the operator if they are
            # actually a member of THIS schedule's project. Drops a forged
            # cross-project id (a compromised/buggy scheduler could
            # otherwise fabricate attribution) AND a stale/nonexistent id
            # that would fail the users FK on the "delivered" record()
            # write below -- which happens AFTER the command is already
            # dispatched, so an unguarded FK error would drop the
            # fire-history row and no-op the later ack. Unattributed is the
            # safe fallback.
            if triggered_by_user_id is not None:
                from z4j_brain.persistence.repositories import (
                    MembershipRepository,
                )

                _member = await MembershipRepository(session).get_for_user_project(
                    user_id=triggered_by_user_id,
                    project_id=schedule.project_id,
                )
                if _member is None:
                    logger.warning(
                        "z4j.brain.scheduler_grpc: FireSchedule "
                        "triggered_by_user_id %s is not a member of the "
                        "schedule's project %s; recording the fire as "
                        "unattributed",
                        triggered_by_user_id,
                        schedule.project_id,
                    )
                    triggered_by_user_id = None
            if not schedule.is_enabled:
                # Scheduler should have skipped this on its side, but
                # defend against a race between disable + tick.
                # Refund the token.
                response = pb.FireScheduleResponse(
                    error_code="schedule_disabled",
                    error_message="schedule is disabled",
                )
                if cert_cn:
                    await self._rate_limiter.refund(
                        cert_cn=cert_cn,
                        session=session,
                    )
                return response

            if schedule.paused_at is not None:
                # Paused is not disabled. Disabling retires a schedule;
                # pausing holds it during an incident and keeps the
                # timestamp that says how long the hold has run. They are
                # refused the same way here but reported distinctly, so an
                # operator reading the scheduler's logs can tell whether
                # someone retired this schedule or is holding it.
                #
                # Same race defence as above: the scheduler is expected to
                # skip a paused schedule on its side, and this is the
                # authority that makes it true even if it does not.
                response = pb.FireScheduleResponse(
                    error_code="schedule_paused",
                    error_message=(f"schedule is paused (since {schedule.paused_at.isoformat()})"),
                )
                if cert_cn:
                    await self._rate_limiter.refund(
                        cert_cn=cert_cn,
                        session=session,
                    )
                return response

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
                from datetime import timedelta

                from z4j_brain.persistence.repositories import (
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
                    triggered_by_user_id=triggered_by_user_id,
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
            except Exception as exc:
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
                # Sanitize the exception text before persisting /
                # returning to the wire so
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
                        triggered_by_user_id=triggered_by_user_id,
                    )
                    await session.commit()
                except Exception:
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
            # Derive the fire-history status from the command's ACTUAL
            # state, not an unconditional "delivered". ``issue()`` can RETURN a
            # terminally-FAILED command (an idempotent re-fire of a fire whose
            # earlier command failed returns that FAILED row without re-driving).
            # Recording "delivered" for it is a lie the ack path would then upgrade
            # to acked_success with a bumped run count. A FAILED command is recorded
            # as a failed fire and returned as an error so the scheduler does not
            # ack a phantom success.
            from z4j_brain.persistence.enums import CommandStatus as _CmdStatus

            if command.status == _CmdStatus.FAILED:
                await ScheduleFireRepository(session).record(
                    fire_id=fire_id,
                    schedule_id=schedule.id,
                    project_id=schedule.project_id,
                    command_id=command.id,
                    status="failed",
                    scheduled_for=scheduled_for_dt,
                    error_code="command_failed",
                    error_message=_sanitize_error_message(command.error or "command failed"),
                    triggered_by_user_id=triggered_by_user_id,
                )
                await session.commit()
                return pb.FireScheduleResponse(
                    error_code="command_failed",
                    error_message=_sanitize_error_message(
                        command.error or "command failed to deliver"
                    ),
                )
            # Phase 4: write the fire-history row with the
            # brain-assigned command_id. AcknowledgeFireResult will
            # update it later with the agent's outcome -- and it
            # CORRELATES the schedule by joining schedule_fires on
            # fire_id, so this row must always exist or the ack no-ops
            # (last_run_at / total_runs / notifications all skipped).
            await ScheduleFireRepository(session).record(
                fire_id=fire_id,
                schedule_id=schedule.id,
                project_id=schedule.project_id,
                command_id=command.id,
                status="delivered",
                scheduled_for=scheduled_for_dt,
                triggered_by_user_id=triggered_by_user_id,
            )
            await session.commit()

            return pb.FireScheduleResponse(
                command_id=str(command.id),
            )

    async def _fire_legacy_current_schedule(  # noqa: PLR0911, PLR0912, PLR0915
        self,
        *,
        request: pb.FireScheduleRequest,
        context: grpc.aio.ServicerContext,
        schedule_id: UUID,
        fire_id: UUID,
        cert_cn: str,
    ) -> pb.FireScheduleResponse:
        """Accept a tokenless cadence only through its explicit D grant."""

        from datetime import timedelta

        from sqlalchemy import select

        from z4j_brain.persistence.enums import CommandStatus
        from z4j_brain.persistence.models import Schedule
        from z4j_brain.persistence.repositories import (
            AuditLogRepository,
            CommandRepository,
            PendingFiresRepository,
            ScheduleFireRepository,
        )
        from z4j_brain.persistence.repositories.schedule_control import (
            ScheduleControlConflictError,
            ScheduleControlRepository,
            ScheduleControlStateUnavailableError,
        )
        from z4j_brain.scheduler_grpc.binding import (
            enforce_cn_project_binding,
        )

        # The disposition stays FIRE_LEGACY_UPGRADE_REQUIRED: it is the wire's
        # only terminal "this channel cannot carry it" value, an N-1 peer has
        # to keep decoding it, and a refusal reported as anything retryable
        # would put an operator's click into a retry loop that cannot succeed.
        if fire_id.version != 5 or request.triggered_by_user_id:
            return pb.FireScheduleResponse(
                disposition=(pb.FireDisposition.FIRE_LEGACY_UPGRADE_REQUIRED),
                error_code=_MANUAL_TRIGGER_REFUSED_CODE,
                error_message=_MANUAL_TRIGGER_REFUSED_MESSAGE,
            )
        if not request.HasField("scheduled_for"):
            return pb.FireScheduleResponse(
                disposition=(pb.FireDisposition.FIRE_LEGACY_UPGRADE_REQUIRED),
                error_code="scheduler_upgrade_required",
                error_message=(
                    "current schedule control accepts only explicitly "
                    "granted tokenless cadence fires"
                ),
            )
        try:
            scheduled_for = _present_pb_datetime(
                request.scheduled_for,
            ).replace(microsecond=0)
        except (ValueError, OverflowError) as exc:
            return pb.FireScheduleResponse(
                disposition=(pb.FireDisposition.FIRE_RETRYABLE_OR_AMBIGUOUS),
                error_code="invalid_legacy_fire",
                error_message=(_sanitize_error_message(str(exc)) or "invalid scheduled_for"),
            )

        command_id: UUID | None = None
        command_agent_id: UUID | None = None
        command_payload: dict[str, Any] | None = None
        buffered = False
        should_deliver = False
        transition = None
        sem = _get_fire_schedule_semaphore()
        try:
            async with sem, self._db.session(write=True) as session:
                schedule_result = await session.execute(
                    select(Schedule)
                    .where(
                        Schedule.id == schedule_id,
                        Schedule.scheduler == _SCHEDULER_NAME,
                    )
                    .with_for_update(),
                )
                schedule = schedule_result.scalar_one_or_none()
                if schedule is None:
                    response = pb.FireScheduleResponse(
                        disposition=(pb.FireDisposition.FIRE_STALE_CONTROL_REFRESH),
                        error_code="schedule_not_found",
                        error_message=f"schedule {schedule_id} not in brain",
                    )
                    if cert_cn:
                        await self._rate_limiter.refund(
                            cert_cn=cert_cn,
                            session=session,
                        )
                    return response
                await enforce_cn_project_binding(
                    context=context,
                    project_id=schedule.project_id,
                    bindings=(self._settings.scheduler_grpc_cn_project_bindings),
                    db=self._db,
                )
                receipt_token = schedule.control_token
                definition_digest = schedule.definition_digest
                expected_revision = int(schedule.schedule_revision or 0)
                expected_last_run_at = schedule.last_run_at
                expected_next_run_at = schedule.next_run_at
                if receipt_token is None or definition_digest is None:
                    raise ScheduleControlStateUnavailableError(  # noqa: TRY301
                        "legacy-compatible schedule lacks current identity",
                    )

                transition = await ScheduleControlRepository(
                    session,
                ).accept_legacy_fire_progress(
                    project_id=schedule.project_id,
                    schedule_id=schedule.id,
                    fire_id=fire_id,
                    scheduled_for=scheduled_for,
                    occurred_at=datetime.now(UTC),
                )
                schedule = transition.schedule
                assert schedule is not None
                if transition.disposition == "slot_resolved_refresh":
                    return pb.FireScheduleResponse(
                        buffered=True,
                        disposition=(pb.FireDisposition.FIRE_SLOT_RESOLVED_REFRESH),
                        live_control_token=str(
                            schedule.control_token or "",
                        ),
                        live_revision=int(
                            schedule.schedule_revision or 0,
                        ),
                        live_last_run_at=_pb_timestamp(
                            schedule.last_run_at,
                        ),
                        live_next_run_at=_pb_timestamp(
                            schedule.next_run_at,
                        ),
                    )
                if transition.disposition == "terminal_quarantined":
                    return pb.FireScheduleResponse(
                        disposition=(pb.FireDisposition.FIRE_TERMINAL_QUARANTINED),
                        error_code="schedule_disabled",
                        error_message=("cadence occurrence has an unresolved terminal hold"),
                        live_control_token=str(
                            schedule.control_token or "",
                        ),
                        live_revision=int(
                            schedule.schedule_revision or 0,
                        ),
                    )
                if transition.disposition == "schedule_paused":
                    # Held, not retired. Reported distinctly so an operator
                    # reading the scheduler's logs can tell which one is in
                    # force, and refused the same way either way.
                    response = pb.FireScheduleResponse(
                        disposition=(pb.FireDisposition.FIRE_RETRYABLE_OR_AMBIGUOUS),
                        error_code="schedule_paused",
                        error_message="schedule is paused",
                        live_control_token=str(
                            schedule.control_token or "",
                        ),
                        live_revision=int(
                            schedule.schedule_revision or 0,
                        ),
                    )
                    if cert_cn:
                        await self._rate_limiter.refund(
                            cert_cn=cert_cn,
                            session=session,
                        )
                    return response
                if transition.disposition == "schedule_disabled":
                    response = pb.FireScheduleResponse(
                        disposition=(pb.FireDisposition.FIRE_RETRYABLE_OR_AMBIGUOUS),
                        error_code="schedule_disabled",
                        error_message="schedule is disabled",
                        live_control_token=str(
                            schedule.control_token or "",
                        ),
                        live_revision=int(
                            schedule.schedule_revision or 0,
                        ),
                    )
                    if cert_cn:
                        await self._rate_limiter.refund(
                            cert_cn=cert_cn,
                            session=session,
                        )
                    return response
                if transition.disposition == "legacy_upgrade_required":
                    return pb.FireScheduleResponse(
                        disposition=(pb.FireDisposition.FIRE_LEGACY_UPGRADE_REQUIRED),
                        error_code="scheduler_upgrade_required",
                        error_message=(
                            "tokenless FireSchedule requires an explicit "
                            "current-generation compatibility grant"
                        ),
                        live_control_token=str(
                            schedule.control_token or "",
                        ),
                        live_revision=int(
                            schedule.schedule_revision or 0,
                        ),
                        live_last_run_at=_pb_timestamp(
                            schedule.last_run_at,
                        ),
                        live_next_run_at=_pb_timestamp(
                            schedule.next_run_at,
                        ),
                    )
                if transition.disposition == "legacy_operator_resolution_required":
                    return pb.FireScheduleResponse(
                        disposition=(pb.FireDisposition.FIRE_RETRYABLE_OR_AMBIGUOUS),
                        error_code="operator_resolution_required",
                        error_message=(
                            "legacy cadence evidence may have executed and "
                            "requires explicit operator resolution"
                        ),
                        live_control_token=str(
                            schedule.control_token or "",
                        ),
                        live_revision=int(
                            schedule.schedule_revision or 0,
                        ),
                    )
                if transition.disposition not in {
                    "applied",
                    "idempotent",
                }:
                    raise ScheduleControlStateUnavailableError(  # noqa: TRY301
                        "legacy cadence acceptance returned an unknown state",
                    )

                commands = CommandRepository(session)
                pending = PendingFiresRepository(session)
                fires = ScheduleFireRepository(session)
                existing_command = await commands.get_current_schedule_fire(
                    schedule_id=schedule.id,
                    fire_id=fire_id,
                    receipt_control_token=receipt_token,
                )
                existing_pending = await pending.get_current(
                    fire_id=fire_id,
                    receipt_control_token=receipt_token,
                )
                if transition.disposition == "idempotent":
                    if existing_command is None and existing_pending is None:
                        return pb.FireScheduleResponse(
                            buffered=True,
                            disposition=(pb.FireDisposition.FIRE_SLOT_RESOLVED_REFRESH),
                            live_control_token=str(
                                schedule.control_token or "",
                            ),
                            live_revision=int(
                                schedule.schedule_revision or 0,
                            ),
                            live_last_run_at=_pb_timestamp(
                                schedule.last_run_at,
                            ),
                            live_next_run_at=_pb_timestamp(
                                schedule.next_run_at,
                            ),
                        )
                    if existing_command is not None and existing_pending is not None:
                        raise ScheduleControlStateUnavailableError(  # noqa: TRY301
                            "legacy acceptance has two durable work oracles",
                        )
                    if existing_command is not None:
                        command_id = existing_command.id
                        command_agent_id = existing_command.agent_id
                        command_payload = existing_command.payload
                        should_deliver = existing_command.status == CommandStatus.PENDING
                    else:
                        buffered = True
                else:
                    acceptance_revision = transition.acceptance_revision
                    execution_fire_id = transition.execution_fire_id
                    prepared_next_run_at = schedule.next_run_at
                    if (
                        acceptance_revision is None
                        or execution_fire_id is None
                        or expected_revision <= 0
                        or expected_next_run_at is None
                    ):
                        raise ScheduleControlStateUnavailableError(  # noqa: TRY301
                            "legacy acceptance did not allocate complete authority",
                        )
                    command_payload = {
                        "schedule_id": str(schedule.id),
                        "schedule_name": schedule.name,
                        "task_name": schedule.task_name,
                        "engine": schedule.engine,
                        "queue": schedule.queue,
                        "args": schedule.args,
                        "kwargs": schedule.kwargs,
                        "fire_id": str(execution_fire_id),
                        "schedule_fire_id": str(fire_id),
                        "scheduled_for": scheduled_for.isoformat(),
                        "fired_at": _ts_iso(request.fired_at),
                    }
                    common = {
                        "fire_id": fire_id,
                        "schedule_id": schedule.id,
                        "project_id": schedule.project_id,
                        "scheduled_for": scheduled_for,
                        "observed_control_token": None,
                        "receipt_control_token": receipt_token,
                        "acceptance_revision": acceptance_revision,
                        "definition_digest": definition_digest,
                        "expected_last_run_at": expected_last_run_at,
                        "expected_next_run_at": expected_next_run_at,
                        "prepared_next_run_at": prepared_next_run_at,
                    }
                    agent = await _pick_scheduler_agent_for_fire(
                        session=session,
                        schedule=schedule,
                    )
                    deadline = datetime.now(UTC) + timedelta(
                        seconds=self._settings.command_timeout_seconds,
                    )
                    if agent is None:
                        buffered = True
                        await pending.buffer_current(
                            engine=schedule.engine,
                            payload=command_payload,
                            expires_at=(
                                datetime.now(UTC)
                                + timedelta(
                                    days=(self._settings.pending_fires_retention_days),
                                )
                            ),
                            expected_schedule_revision=expected_revision,
                            execution_fire_id=execution_fire_id,
                            **common,
                        )
                    else:
                        command, _created = await commands.insert_current_schedule_fire(
                            agent_id=agent.id,
                            payload=command_payload,
                            timeout_at=deadline,
                            initial_claim_deadline=deadline,
                            expected_revision=expected_revision,
                            execution_fire_id=execution_fire_id,
                            **common,
                        )
                        command_id = command.id
                        command_agent_id = agent.id
                        should_deliver = command.status == CommandStatus.PENDING
                    await fires.record_current(
                        command_id=command_id,
                        status=("buffered" if buffered else "accepted"),
                        expected_schedule_revision=expected_revision,
                        **common,
                    )
                    await self._audit.record(
                        AuditLogRepository(session),
                        action="schedule.fire.legacy_accepted",
                        target_type="schedule",
                        target_id=str(schedule.id),
                        result="success",
                        outcome="allow",
                        project_id=schedule.project_id,
                        metadata={
                            "fire_id": str(fire_id),
                            "command_id": (str(command_id) if command_id is not None else None),
                            "receipt_control_token": str(
                                receipt_token,
                            ),
                            "acceptance_revision": (acceptance_revision),
                            "buffered": buffered,
                        },
                    )
                    await session.commit()
        except ScheduleControlConflictError as exc:
            return pb.FireScheduleResponse(
                disposition=(pb.FireDisposition.FIRE_RETRYABLE_OR_AMBIGUOUS),
                error_code="fire_conflict",
                error_message=(_sanitize_error_message(str(exc)) or "legacy fire conflict"),
            )
        except ScheduleControlStateUnavailableError:
            logger.exception(
                "z4j.brain.scheduler_grpc: legacy FireSchedule authority failure",
                extra={
                    "schedule_id": str(schedule_id),
                    "fire_id": str(fire_id),
                },
            )
            return pb.FireScheduleResponse(
                disposition=(pb.FireDisposition.FIRE_RETRYABLE_OR_AMBIGUOUS),
                error_code="schedule_control_unavailable",
                error_message="durable schedule control evidence is unavailable",
            )

        if (
            command_id is not None
            and command_agent_id is not None
            and command_payload is not None
            and should_deliver
        ):
            await self._dispatcher.deliver_persisted(
                command_id=command_id,
                agent_id=command_agent_id,
                action=_FIRE_ACTION,
                payload=command_payload,
            )
        if command_id is not None:
            return await self._classify_current_fire_command(
                command_id=command_id,
            )
        assert transition is not None
        schedule = transition.schedule
        assert schedule is not None
        return pb.FireScheduleResponse(
            buffered=buffered,
            disposition=pb.FireDisposition.FIRE_ACCEPTED,
            acceptance_revision=int(
                transition.acceptance_revision or 0,
            ),
            accepted_last_run_at=_pb_timestamp(scheduled_for),
            accepted_next_run_at=_pb_timestamp(
                schedule.next_run_at,
            ),
            live_control_token=str(schedule.control_token or ""),
            live_revision=int(schedule.schedule_revision or 0),
            live_last_run_at=_pb_timestamp(schedule.last_run_at),
            live_next_run_at=_pb_timestamp(schedule.next_run_at),
        )

    async def _fire_current_schedule(  # noqa: PLR0911, PLR0912, PLR0915
        self,
        *,
        request: pb.FireScheduleRequest,
        context: grpc.aio.ServicerContext,
        schedule_id: UUID,
        fire_id: UUID,
        cert_cn: str,
    ) -> pb.FireScheduleResponse:
        """Persist one receipt-bound cadence acceptance before delivery."""

        from datetime import timedelta

        from sqlalchemy import select

        from z4j_brain.domain.schedule_cadence import (
            CADENCE_SEMANTICS_VERSION,
            cadence_runtime_fingerprint,
        )
        from z4j_brain.persistence.enums import CommandStatus
        from z4j_brain.persistence.models import Schedule
        from z4j_brain.persistence.repositories import (
            AuditLogRepository,
            CommandRepository,
            PendingFiresRepository,
            ScheduleFireRepository,
        )
        from z4j_brain.persistence.repositories.schedule_control import (
            ScheduleControlConflictError,
            ScheduleControlRepository,
            ScheduleControlStateUnavailableError,
        )
        from z4j_brain.scheduler_grpc.binding import (
            enforce_cn_project_binding,
        )
        from z4j_brain.scheduler_grpc.protocol import CURRENT_PROTOCOL_EPOCH

        if (
            request.scheduler_protocol_epoch != CURRENT_PROTOCOL_EPOCH
            or request.cadence_semantics_version != CADENCE_SEMANTICS_VERSION
            or request.cadence_runtime_fingerprint != cadence_runtime_fingerprint()
        ):
            return pb.FireScheduleResponse(
                disposition=(pb.FireDisposition.FIRE_CADENCE_SEMANTICS_MISMATCH),
                error_code="cadence_semantics_mismatch",
                error_message="scheduler cadence/protocol tuple does not match Brain",
            )
        # Refusing an operator trigger before the authority checks, and with
        # its own code, so the two causes are never confused: an extra fire is
        # turned away for what it is, not for a missing field it was never
        # going to carry, and the terminal disposition keeps it out of the
        # retry path that "ambiguous" invites.
        if fire_id.version != 5 or request.triggered_by_user_id:
            return pb.FireScheduleResponse(
                disposition=(pb.FireDisposition.FIRE_LEGACY_UPGRADE_REQUIRED),
                error_code=_MANUAL_TRIGGER_REFUSED_CODE,
                error_message=_MANUAL_TRIGGER_REFUSED_MESSAGE,
            )
        if (
            not request.HasField("scheduled_for")
            or not request.HasField("expected_next_run_at")
            or request.expected_schedule_revision <= 0
            or not request.definition_digest
            or not request.observed_control_token
        ):
            return pb.FireScheduleResponse(
                disposition=(pb.FireDisposition.FIRE_RETRYABLE_OR_AMBIGUOUS),
                error_code="invalid_current_fire",
                error_message="current cadence fire lacks complete authority",
            )
        try:
            observed_control_token = UUID(request.observed_control_token)
            scheduled_for = _present_pb_datetime(request.scheduled_for)
            expected_last_run_at = (
                _present_pb_datetime(request.expected_last_run_at)
                if request.HasField("expected_last_run_at")
                else None
            )
            expected_next_run_at = _present_pb_datetime(
                request.expected_next_run_at,
            )
            prepared_next_run_at = (
                _present_pb_datetime(request.prepared_next_run_at)
                if request.HasField("prepared_next_run_at")
                else None
            )
        except (ValueError, OverflowError) as exc:
            return pb.FireScheduleResponse(
                disposition=(pb.FireDisposition.FIRE_RETRYABLE_OR_AMBIGUOUS),
                error_code="invalid_current_fire",
                error_message=_sanitize_error_message(str(exc)) or "invalid timestamp",
            )

        command_id: UUID | None = None
        command_agent_id: UUID | None = None
        command_payload: dict[str, Any] | None = None
        should_deliver = False
        buffered = False
        transition = None
        sem = _get_fire_schedule_semaphore()
        try:
            async with sem, self._db.session(write=True) as session:
                # Resolve the target, then authorise it, then act on it -- the
                # order every other scheduler RPC uses.  The cadence acceptance
                # below allocates a revision, appends the change-log envelope
                # and moves the cursor, and several of the refusals it raises on
                # the way (slot identity, clock-skew bound, missing D identity)
                # never reach a project column at all.  Authorising afterwards
                # therefore both answers a peer this Brain has already decided
                # is not entitled to the project and leaves containment of the
                # attempted mutation to transaction rollback, which is a
                # backstop and not an authorisation decision.
                #
                # The row is locked here and the acceptance re-reads it under
                # the same lock in the same transaction, so nothing can move
                # between the check and the write.
                owner_result = await session.execute(
                    select(Schedule)
                    .where(
                        Schedule.id == schedule_id,
                        Schedule.scheduler == _SCHEDULER_NAME,
                    )
                    .with_for_update(),
                )
                owner = owner_result.scalar_one_or_none()
                if owner is None:
                    response = pb.FireScheduleResponse(
                        disposition=(pb.FireDisposition.FIRE_STALE_CONTROL_REFRESH),
                        error_code="schedule_not_found",
                        error_message="schedule does not exist",
                    )
                    if cert_cn:
                        await self._rate_limiter.refund(
                            cert_cn=cert_cn,
                            session=session,
                        )
                    return response
                await enforce_cn_project_binding(
                    context=context,
                    project_id=owner.project_id,
                    bindings=self._settings.scheduler_grpc_cn_project_bindings,
                    db=self._db,
                )
                control = ScheduleControlRepository(session)
                transition = await control.accept_current_fire_progress(
                    project_id=owner.project_id,
                    schedule_id=schedule_id,
                    fire_id=fire_id,
                    scheduled_for=scheduled_for,
                    observed_control_token=observed_control_token,
                    definition_digest=request.definition_digest,
                    expected_revision=request.expected_schedule_revision,
                    expected_last_run_at=expected_last_run_at,
                    expected_next_run_at=expected_next_run_at,
                    prepared_next_run_at=prepared_next_run_at,
                    cadence_semantics_version=request.cadence_semantics_version,
                    cadence_fingerprint=request.cadence_runtime_fingerprint,
                    occurred_at=datetime.now(UTC),
                )
                schedule = transition.schedule
                if schedule is None:
                    # The row was located and locked above, so the acceptance
                    # cannot legitimately fail to find it.
                    raise ScheduleControlStateUnavailableError(  # noqa: TRY301
                        "locked cadence row vanished during acceptance",
                    )
                refresh = _current_fire_refresh_response(transition)
                if refresh is not None:
                    return refresh

                commands = CommandRepository(session)
                pending = PendingFiresRepository(session)
                fires = ScheduleFireRepository(session)
                existing_command = await commands.get_current_schedule_fire(
                    schedule_id=schedule.id,
                    fire_id=fire_id,
                    receipt_control_token=observed_control_token,
                )
                existing_pending = await pending.get_current(
                    fire_id=fire_id,
                    receipt_control_token=observed_control_token,
                )
                if transition.disposition == "idempotent":
                    if existing_command is None and existing_pending is None:
                        return pb.FireScheduleResponse(
                            buffered=True,
                            disposition=(pb.FireDisposition.FIRE_SLOT_RESOLVED_REFRESH),
                            live_control_token=str(
                                schedule.control_token or "",
                            ),
                            live_revision=int(
                                schedule.schedule_revision or 0,
                            ),
                            live_last_run_at=_pb_timestamp(
                                schedule.last_run_at,
                            ),
                            live_next_run_at=_pb_timestamp(
                                schedule.next_run_at,
                            ),
                        )
                    if existing_command is not None and existing_pending is not None:
                        raise ScheduleControlStateUnavailableError(  # noqa: TRY301
                            "accepted cadence slot has two durable work oracles",
                        )
                    if existing_command is not None:
                        command_id = existing_command.id
                        command_agent_id = existing_command.agent_id
                        command_payload = existing_command.payload
                        should_deliver = existing_command.status == CommandStatus.PENDING
                    else:
                        buffered = True
                else:
                    agent = await _pick_scheduler_agent_for_fire(
                        session=session,
                        schedule=schedule,
                    )
                    execution_fire_id = transition.execution_fire_id
                    acceptance_revision = transition.acceptance_revision
                    if execution_fire_id is None or acceptance_revision is None:
                        raise ScheduleControlStateUnavailableError(  # noqa: TRY301
                            "fire acceptance did not allocate complete authority",
                        )
                    command_payload = {
                        "schedule_id": str(schedule.id),
                        "schedule_name": schedule.name,
                        "task_name": schedule.task_name,
                        "engine": schedule.engine,
                        "queue": schedule.queue,
                        "args": schedule.args,
                        "kwargs": schedule.kwargs,
                        "fire_id": str(execution_fire_id),
                        "schedule_fire_id": str(fire_id),
                        "scheduled_for": scheduled_for.isoformat(),
                        "fired_at": _ts_iso(request.fired_at),
                    }
                    common = {
                        "fire_id": fire_id,
                        "schedule_id": schedule.id,
                        "project_id": schedule.project_id,
                        "scheduled_for": scheduled_for,
                        "observed_control_token": observed_control_token,
                        "receipt_control_token": observed_control_token,
                        "acceptance_revision": acceptance_revision,
                        "definition_digest": request.definition_digest,
                        "expected_last_run_at": expected_last_run_at,
                        "expected_next_run_at": expected_next_run_at,
                        "prepared_next_run_at": prepared_next_run_at,
                    }
                    if agent is None:
                        buffered = True
                        await pending.buffer_current(
                            engine=schedule.engine,
                            payload=command_payload,
                            expires_at=(
                                datetime.now(UTC)
                                + timedelta(
                                    days=self._settings.pending_fires_retention_days,
                                )
                            ),
                            expected_schedule_revision=(request.expected_schedule_revision),
                            execution_fire_id=execution_fire_id,
                            **common,
                        )
                    else:
                        command, _created = await commands.insert_current_schedule_fire(
                            agent_id=agent.id,
                            payload=command_payload,
                            timeout_at=(
                                datetime.now(UTC)
                                + timedelta(
                                    seconds=self._settings.command_timeout_seconds,
                                )
                            ),
                            initial_claim_deadline=(
                                datetime.now(UTC)
                                + timedelta(
                                    seconds=self._settings.command_timeout_seconds,
                                )
                            ),
                            expected_revision=request.expected_schedule_revision,
                            execution_fire_id=execution_fire_id,
                            **common,
                        )
                        command_id = command.id
                        command_agent_id = agent.id
                        should_deliver = command.status == CommandStatus.PENDING
                    await fires.record_current(
                        command_id=command_id,
                        status="buffered" if buffered else "accepted",
                        expected_schedule_revision=(request.expected_schedule_revision),
                        **common,
                    )
                    await self._audit.record(
                        AuditLogRepository(session),
                        action="schedule.fire.accepted",
                        target_type="schedule",
                        target_id=str(schedule.id),
                        result="success",
                        outcome="allow",
                        project_id=schedule.project_id,
                        metadata={
                            "fire_id": str(fire_id),
                            "command_id": (str(command_id) if command_id is not None else None),
                            "receipt_control_token": str(
                                observed_control_token,
                            ),
                            "acceptance_revision": acceptance_revision,
                            "buffered": buffered,
                        },
                    )
                    await session.commit()
        except ScheduleControlConflictError as exc:
            return pb.FireScheduleResponse(
                disposition=(pb.FireDisposition.FIRE_RETRYABLE_OR_AMBIGUOUS),
                error_code="fire_conflict",
                error_message=_sanitize_error_message(str(exc)) or "fire conflict",
            )
        except ScheduleControlStateUnavailableError:
            logger.exception(
                "z4j.brain.scheduler_grpc: current FireSchedule authority failure",
                extra={"schedule_id": str(schedule_id), "fire_id": str(fire_id)},
            )
            return pb.FireScheduleResponse(
                disposition=(pb.FireDisposition.FIRE_RETRYABLE_OR_AMBIGUOUS),
                error_code="schedule_control_unavailable",
                error_message="durable schedule control evidence is unavailable",
            )

        if (
            command_id is not None
            and command_agent_id is not None
            and command_payload is not None
            and should_deliver
        ):
            await self._dispatcher.deliver_persisted(
                command_id=command_id,
                agent_id=command_agent_id,
                action=_FIRE_ACTION,
                payload=command_payload,
            )
        if command_id is not None:
            return await self._classify_current_fire_command(
                command_id=command_id,
            )
        assert transition is not None
        schedule = transition.schedule
        assert schedule is not None
        return pb.FireScheduleResponse(
            command_id=str(command_id or ""),
            buffered=buffered,
            disposition=pb.FireDisposition.FIRE_ACCEPTED,
            acceptance_revision=int(transition.acceptance_revision or 0),
            accepted_last_run_at=_pb_timestamp(scheduled_for),
            accepted_next_run_at=_pb_timestamp(prepared_next_run_at),
            live_control_token=str(schedule.control_token or ""),
            live_revision=int(schedule.schedule_revision or 0),
            live_last_run_at=_pb_timestamp(schedule.last_run_at),
            live_next_run_at=_pb_timestamp(schedule.next_run_at),
        )

    async def _classify_current_fire_command(  # noqa: PLR0911
        self,
        *,
        command_id: UUID,
    ) -> pb.FireScheduleResponse:
        """Apply the exhaustive current cadence replay table."""

        from z4j_brain.persistence.repositories import AuditLogRepository
        from z4j_brain.persistence.repositories.schedule_control import (
            ScheduleControlRepository,
        )

        async with self._db.session(write=True) as session:
            transition = await ScheduleControlRepository(
                session,
            ).terminalize_current_fire(
                command_id=command_id,
                occurred_at=datetime.now(UTC),
            )
            schedule = transition.schedule
            command = transition.command
            if transition.hold_created:
                assert schedule is not None
                assert command is not None
                await self._audit.record(
                    AuditLogRepository(session),
                    action="schedule.fire.terminal_hold",
                    target_type="schedule",
                    target_id=str(schedule.id),
                    result="failed",
                    outcome="failure",
                    project_id=schedule.project_id,
                    metadata={
                        "command_id": str(command.id),
                        "fire_id": str(command.schedule_fire_id),
                        "terminal_status": command.status.value,
                        "receipt_control_token": str(
                            command.schedule_receipt_control_token,
                        ),
                        "acceptance_revision": (command.schedule_acceptance_revision),
                    },
                )
                await session.commit()
            if command is None:
                return pb.FireScheduleResponse(
                    disposition=(pb.FireDisposition.FIRE_RETRYABLE_OR_AMBIGUOUS),
                    error_code="fire_evidence_missing",
                    error_message="accepted cadence command evidence is unavailable",
                )
            if transition.disposition == "terminal_quarantined":
                assert schedule is not None
                return _current_command_response(
                    disposition=(pb.FireDisposition.FIRE_TERMINAL_QUARANTINED),
                    schedule=schedule,
                    command=command,
                    error_code="schedule_disabled",
                    error_message=(f"cadence command is terminal: {command.status.value}"),
                )
            if transition.disposition in {"pending", "dispatched", "completed"}:
                assert schedule is not None
                return _current_command_response(
                    disposition=pb.FireDisposition.FIRE_ACCEPTED,
                    schedule=schedule,
                    command=command,
                )
            if transition.disposition == "slot_resolved_refresh":
                if schedule is None:
                    return pb.FireScheduleResponse(
                        disposition=(pb.FireDisposition.FIRE_SLOT_RESOLVED_REFRESH),
                        command_id=str(command.id),
                        acceptance_revision=int(
                            command.schedule_acceptance_revision or 0,
                        ),
                    )
                return _current_command_response(
                    disposition=(pb.FireDisposition.FIRE_SLOT_RESOLVED_REFRESH),
                    schedule=schedule,
                    command=command,
                    error_code="slot_resolved",
                    error_message="a later cadence transition already won",
                )
            if transition.disposition == "stale_control_refresh":
                assert schedule is not None
                return _current_command_response(
                    disposition=(pb.FireDisposition.FIRE_STALE_CONTROL_REFRESH),
                    schedule=schedule,
                    command=command,
                    error_code="stale_control",
                    error_message="schedule control generation changed",
                )
            if transition.disposition == "legacy_operator_resolution_required":
                assert schedule is not None
                return _current_command_response(
                    disposition=(pb.FireDisposition.FIRE_RETRYABLE_OR_AMBIGUOUS),
                    schedule=schedule,
                    command=command,
                    error_code="operator_resolution_required",
                    error_message=(
                        "legacy or incomplete cadence evidence requires operator resolution"
                    ),
                )
            return pb.FireScheduleResponse(
                disposition=(pb.FireDisposition.FIRE_RETRYABLE_OR_AMBIGUOUS),
                command_id=str(command.id),
                error_code="fire_ambiguous",
                error_message="cadence command state is unknown or malformed",
            )

    # ------------------------------------------------------------------
    # AcknowledgeFireResult
    # ------------------------------------------------------------------

    async def _acknowledge_current_fire_result(  # noqa: PLR0911, PLR0912, PLR0915
        self,
        *,
        request: pb.AcknowledgeFireResultRequest,
        context: grpc.aio.ServicerContext,
        fire_id: UUID,
    ) -> bool:
        """Handle a Boundary-D scheduler receipt when current evidence exists.

        Returns ``False`` only when neither the supplied command nor retained
        fire history is current-protocol evidence, allowing the legacy handler
        below to preserve its pre-activation behavior.
        """

        from sqlalchemy import select

        from z4j_brain.domain.schedule_fire_authority import (
            SCHEDULE_FIRE_PROTOCOL_MARKER,
        )
        from z4j_brain.persistence.models import Command, Schedule, ScheduleFire
        from z4j_brain.persistence.repositories import (
            AuditLogRepository,
            ScheduleFireRepository,
        )
        from z4j_brain.scheduler_grpc.binding import (
            enforce_cn_project_binding,
        )

        command_id: UUID | None = None
        if request.command_id:
            try:
                command_id = UUID(request.command_id)
            except ValueError as exc:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT,
                    f"invalid command_id: {exc}",
                )
                return True

        safe_error = _sanitize_error_message(request.error)
        safe_error_code = _sanitize_error_message(
            request.error,
            max_chars=_ERROR_CODE_MAX_CHARS,
        )
        should_notify = False
        notification: dict[str, Any] | None = None
        async with self._db.session(write=True) as session:
            command = await session.get(Command, command_id) if command_id is not None else None
            marked_command = (
                command is not None
                and command.schedule_protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER
            )
            current_command = (
                marked_command
                and command is not None
                and command.schedule_receipt_control_token is not None
            )
            current_fires: list[ScheduleFire] = []
            if not current_command:
                result = await session.execute(
                    select(ScheduleFire)
                    .where(
                        ScheduleFire.fire_id == fire_id,
                        ScheduleFire.protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER,
                    )
                    .limit(2),
                )
                current_fires = list(result.scalars())
                if not current_fires:
                    return False

            if current_command:
                assert command is not None
                project_id = command.project_id
                schedule_id = command.schedule_id
                if schedule_id is None:
                    await context.abort(
                        grpc.StatusCode.FAILED_PRECONDITION,
                        "current command lacks schedule identity",
                    )
                    return True
                await enforce_cn_project_binding(
                    context=context,
                    project_id=project_id,
                    bindings=(self._settings.scheduler_grpc_cn_project_bindings),
                    db=self._db,
                )
            else:
                if command_id is not None and not marked_command:
                    await context.abort(
                        grpc.StatusCode.FAILED_PRECONDITION,
                        "command id does not identify this current fire",
                    )
                    return True
                if len(current_fires) != 1:
                    await context.abort(
                        grpc.StatusCode.FAILED_PRECONDITION,
                        "command-less current fire identity is ambiguous",
                    )
                    return True
                fire = current_fires[0]
                if command_id is not None and fire.command_id != command_id:
                    await context.abort(
                        grpc.StatusCode.FAILED_PRECONDITION,
                        "command id does not match retained fire evidence",
                    )
                    return True
                project_id = fire.project_id
                schedule_id = fire.schedule_id
                await enforce_cn_project_binding(
                    context=context,
                    project_id=project_id,
                    bindings=(self._settings.scheduler_grpc_cn_project_bindings),
                    db=self._db,
                )

            repository = ScheduleFireRepository(session)
            try:
                if current_command:
                    assert command is not None
                    fire, should_notify = await repository.acknowledge_current_command(
                        command=command,
                        fire_id=fire_id,
                        status=request.status,
                        new_task_id=request.new_task_id or None,
                        error_code=safe_error_code,
                        error_message=safe_error,
                    )
                elif fire.receipt_control_token is None:
                    fire, should_notify = await repository.acknowledge_legacy_history(
                        fire=fire,
                        command_id=command_id,
                        status=request.status,
                        new_task_id=request.new_task_id or None,
                        error_code=safe_error_code,
                        error_message=safe_error,
                    )
                else:
                    fire = current_fires[0]
                    fire, should_notify = await repository.acknowledge_current_unbound(
                        fire=fire,
                        status=request.status,
                        new_task_id=request.new_task_id or None,
                        error_code=safe_error_code,
                        error_message=safe_error,
                    )
            except ValueError as exc:
                await context.abort(
                    grpc.StatusCode.FAILED_PRECONDITION,
                    str(exc),
                )
                return True

            schedule = await session.get(Schedule, schedule_id)
            if schedule is not None:
                notification = {
                    "project_id": schedule.project_id,
                    "name": schedule.name,
                    "engine": schedule.engine,
                    "queue": schedule.queue,
                }
            await self._audit.record(
                AuditLogRepository(session),
                action=(
                    "schedule.ack.success" if request.status == "success" else "schedule.ack.failed"
                ),
                target_type="schedule",
                target_id=str(schedule_id),
                result="success",
                outcome="allow",
                project_id=project_id,
                metadata={
                    "fire_id": str(fire_id),
                    "command_id": (str(command_id) if command_id is not None else None),
                    "ack_status": request.status,
                    "error": safe_error,
                    "history_retained": fire is not None,
                },
            )
            await session.commit()

        if not should_notify or notification is None:
            return True
        try:
            from z4j_brain.domain.notifications.service import (
                NotificationService,
            )

            triggers = (
                ["schedule.fire.succeeded"]
                if request.status == "success"
                else ["schedule.fire.failed", "schedule.task_failed"]
            )
            async with self._db.session() as notify_session:
                service = NotificationService()
                for trigger in triggers:
                    await service.evaluate_and_dispatch(
                        session=notify_session,
                        project_id=notification["project_id"],
                        trigger=trigger,
                        task_id=str(fire_id),
                        task_name=notification["name"],
                        engine=notification["engine"],
                        state=request.status,
                        queue=notification["queue"],
                        exception=safe_error,
                    )
                await notify_session.commit()
        except Exception:
            logger.exception(
                "z4j.brain.scheduler_grpc: current schedule notification "
                "dispatch failed for fire_id=%s (non-fatal)",
                fire_id,
            )
        return True

    async def AcknowledgeFireResult(  # noqa: N802, PLR0911, PLR0915  gRPC method
        self,
        request: pb.AcknowledgeFireResultRequest,
        context: grpc.aio.ServicerContext,
    ) -> pb.AcknowledgeFireResultResponse:
        """Record the scheduler's best-effort FireSchedule receipt.

        Current receipt-bound fires commit cadence progress in the original
        FireSchedule acceptance transaction.  Their later scheduler receipt is
        history/audit/notification only.  The legacy branch retains the 1.7
        schedule-projection behavior until Boundary-D activation fences it.
        """
        try:
            fire_id = UUID(request.fire_id)
        except ValueError as exc:
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"invalid fire_id: {exc}",
            )
            return pb.AcknowledgeFireResultResponse()

        if await self._acknowledge_current_fire_result(
            request=request,
            context=context,
            fire_id=fire_id,
        ):
            return pb.AcknowledgeFireResultResponse()

        from sqlalchemy import select

        from z4j_brain.persistence.models import Schedule, ScheduleFire

        async with self._db.session(write=True) as session:
            # Authoritative correlation by ``schedule_fires.fire_id`` instead
            # of ``Schedule.last_fire_id`` (which is a moving
            # target overwritten on every fire). Without this,
            # two back-to-back fires in flight could race: the
            # second fire's FireSchedule would overwrite
            # ``last_fire_id`` BEFORE the first fire's ack
            # landed, and the first ack would then either silently
            # no-op (lookup miss) or, worse, update the WRONG
            # schedule's last_run_at + total_runs. Joining via
            # schedule_fires makes the lookup unambiguous and
            # idempotent across concurrent fires.
            # PostgreSQL partitions this table by scheduled_for, so its schema
            # cannot enforce bare fire_id uniqueness across partitions.  A
            # pre-fence database can therefore contain two legacy rows for one
            # fire_id.  Inspect at most two deterministic identities and fail
            # closed instead of leaking SQLAlchemy MultipleResultsFound or
            # crediting an arbitrary schedule.
            fire_result = await session.execute(
                select(ScheduleFire)
                .where(ScheduleFire.fire_id == fire_id)
                .order_by(
                    ScheduleFire.scheduled_for.asc(),
                    ScheduleFire.id.asc(),
                )
                .limit(2),
            )
            fire_rows = list(fire_result.scalars())
            if len(fire_rows) > 1:
                await context.abort(
                    grpc.StatusCode.FAILED_PRECONDITION,
                    "legacy fire identity is ambiguous",
                )
                return pb.AcknowledgeFireResultResponse()
            if not fire_rows:
                logger.info(
                    "z4j.brain.scheduler_grpc: ack for unknown fire_id %s "
                    "(no schedule_fires row; either pre-restart fire "
                    "or different brain instance)",
                    fire_id,
                )
                return pb.AcknowledgeFireResultResponse()
            schedule = await session.get(Schedule, fire_rows[0].schedule_id)
            if schedule is None:
                logger.warning(
                    "z4j.brain.scheduler_grpc: ack fire_id %s refers to missing schedule_id %s",
                    fire_id,
                    fire_rows[0].schedule_id,
                )
                return pb.AcknowledgeFireResultResponse()

            # Per-cert project binding.
            # A bound CN cannot ack fires belonging to projects
            # outside its binding list. Critical because ack writes
            # ``last_run_at`` + ``total_runs`` AND triggers
            # notifications, so a rogue bound cert could otherwise
            # forge "fire failed" alerts on cross-project schedules.
            from z4j_brain.scheduler_grpc.binding import (
                enforce_cn_project_binding,
            )

            await enforce_cn_project_binding(
                context=context,
                project_id=schedule.project_id,
                bindings=self._settings.scheduler_grpc_cn_project_bindings,
                db=self._db,
            )

            now = datetime.now(UTC)
            # Atomic SQL-side increment for ``total_runs``. A
            # Python-side read-modify-write
            # (``updates["total_runs"] = (schedule.total_runs or
            # 0) + 1``) would race: two concurrent acks for two
            # distinct fires of the same schedule both read
            # ``total_runs=5``, both compute 6, both write 6
            # → silent lost increment. At enterprise scale (100s
            # of fires/sec across many schedules) the lifetime
            # counter would drift low. Using a SQL expression
            # ``Schedule.total_runs + 1`` makes the increment
            # atomic in Postgres without needing FOR UPDATE on
            # the schedule row.
            # Update the per-fire schedule_fires row FIRST so we learn
            # whether this is the first ack of this fire_id. The
            # schedule's lifetime counters must advance only once per
            # fire, so they have to be gated on that result.
            from z4j_brain.persistence.repositories import (
                ScheduleFireRepository,
            )

            ack_status = "acked_success" if request.status == "success" else "acked_failed"
            # Sanitize scheduler-supplied
            # error text before persisting + dispatching downstream.
            # The scheduler is a trusted peer but its error string
            # ultimately came from the agent → engine → task path
            # (untrusted user code), so a malformed return value or
            # log-injection payload could otherwise propagate to the
            # notification template + dashboard rendering.
            safe_error = _sanitize_error_message(request.error)
            safe_error_code = _sanitize_error_message(
                request.error,
                max_chars=_ERROR_CODE_MAX_CHARS,
            )
            # Capture
            # ``was_first_ack`` so we only fan out notifications AND only
            # advance the lifetime counters for the FIRST ack of a given
            # fire_id. Duplicate acks (HA scheduler retry, network
            # duplicate) skip both to avoid two pages -- and a
            # double-counted total_runs -- for one fire.
            _row, should_notify, became_success = await ScheduleFireRepository(
                session,
            ).acknowledge(
                fire_id=fire_id,
                status=ack_status,
                error_code=safe_error_code,
                error_message=safe_error,
            )

            # (+): touch the schedules row ONLY for a
            # CADENCE (non-manual) SUCCESS ack that transitions the fire INTO
            # acked_success. Then:
            #
            # - advance exactly once -- including a success ack that FOLLOWS a
            #   failed ack of the same fire_id (dispatch-failure retry); a
            #   duplicate success ack does not double-count (``became_success``).
            # - RH5: the anchor is the fire's LOGICAL ``scheduled_for``, not the
            #   ack wall-clock, so a cold restart reads a drift-free interval
            #   anchor and does not skip un-acked backlog.
            # - RH6: a MANUAL "Trigger Now" fire (``triggered_by_user_id`` set)
            #   must NOT advance last_run_at -- one_shot/clocked treat ANY
            #   last_fire_at as "already fired", so advancing it makes a manually
            #   triggered FUTURE schedule look completed and it never fires on
            #   its cadence. (A non-member trigger nulls the attribution and thus
            #   still advances -- a narrow documented residual; the reliable close
            #   is a proto ``manual`` flag, deferred until the pb2 can be
            #   regenerated.)
            # - RH7: a FAILED ack does not touch the schedules row AT ALL (not
            #   even ``updated_at``, and not the last_fire_id clear), so it emits
            #   NO schedules_notify echo. An echo would make an N-1 (1.7.0)
            #   scheduler replace its cache wholesale and drop the failed slot; a
            #   1.7.1 scheduler echo-merges, but emitting nothing is correct for
            #   both. The failure is recorded on the schedule_fires row, the audit
            #   trail, and the fire.failed notification -- none behind the trigger.
            # Manual detection is attribution-INDEPENDENT via the fire_id
            # UUID version. Cadence fires use derive_fire_id (uuid5, version 5); a
            # manual "Trigger Now" uses a fresh uuid4 (version 4). So a manual fire
            # is detected even when its user attribution was nulled (a non-member /
            # global-admin trigger, ~handlers.py:1036); the triggered_by_user_id
            # OR-clause is belt-and-suspenders. This closes the RH6 hole where a
            # normal admin Trigger Now still advanced the cadence anchor and
            # consumed a one_shot slot.
            is_manual = _row is not None and (
                _row.fire_id.version != 5 or _row.triggered_by_user_id is not None
            )
            if request.status == "success" and became_success and _row is not None:
                # Manual runs count without consuming a cadence slot; cadence
                # runs also advance the monotonic anchor and conditionally clear
                # their own last_fire_id. The helper emits one SQL UPDATE whose
                # ``total_runs = total_runs + 1`` expression cannot lose a
                # concurrent successful ack.
                await _advance_legacy_schedule_after_success(
                    session,
                    schedule_id=schedule.id,
                    fire_id=fire_id,
                    scheduled_for=_row.scheduled_for,
                    is_manual=is_manual,
                    observed_at=now,
                )

            # Write an audit row for every ack. Without this,
            # the AcknowledgeFireResult handler would mutate
            # ``schedules.last_run_at`` + ``total_runs`` and
            # dispatch notifications without leaving an audit
            # breadcrumb. Any alert-injection attempt (a rogue
            # scheduler ACKing as ``failed`` to trigger pages)
            # would be forensically invisible.
            from z4j_brain.domain.audit_service import (
                AuditService as _AuditService,
            )
            from z4j_brain.persistence.repositories import (
                AuditLogRepository,
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
            except Exception:
                # Audit failure must not block the ack from
                # committing; the schedule row update + notification
                # dispatch are the load-bearing operations.
                logger.exception(
                    "z4j.brain.scheduler_grpc: failed to record ack "
                    "audit row for fire_id=%s (non-fatal)",
                    fire_id,
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
        # RM2/RL1: fan out at most once per fire, using the ATOMIC
        # single-winner ``should_notify`` from acknowledge() (a success ack fans
        # out iff it transitioned into acked_success -- announcing a
        # failed->success recovery once; a failed ack fans out only on the FIRST
        # ack). This replaces the racy ``was_first_ack`` read-then-check that
        # could double-page two concurrent acks and that suppressed a genuine
        # success-after-failure recovery.
        if not should_notify:
            logger.info(
                "z4j.brain.scheduler_grpc: ack for fire_id=%s is a duplicate / "
                "non-transitioning; skipping notification fan-out",
                fire_id,
            )
            return pb.AcknowledgeFireResultResponse()

        # (KNOWN GAP, deferred): ``should_notify`` is the atomic
        # single-winner already COMMITTED by acknowledge() above, but the fan-out
        # below is a SEPARATE best-effort step. A crash after that commit and
        # before the fan-out completes loses the notification with no retry --
        # ``should_notify`` was already consumed, so a re-issued ack will not
        # re-fire it. Closing this needs a transactional OUTBOX: persist the
        # notification intent in the SAME transaction that claims the winner, then
        # a relay worker delivers it at-least-once. That is a substantial feature
        # (outbox table + relay + dedup) and is intentionally deferred, not an
        # oversight; the current best-effort fan-out is the documented behavior.
        try:
            from z4j_brain.domain.notifications.service import (
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
                        # Sanitised error,
                        # not the raw scheduler-supplied string. The
                        # notification template + delivery channels
                        # render this verbatim into emails / Slack /
                        # webhook payloads, so log-injection or
                        # template-shape attacks land here otherwise.
                        exception=safe_error,
                    )
                await notify_session.commit()
        except Exception:
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
        from sqlalchemy.exc import SQLAlchemyError

        from z4j_brain import __version__
        from z4j_brain.persistence.repositories.schedule_control import (
            ScheduleControlRepository,
            ScheduleControlStateUnavailableError,
        )
        from z4j_brain.scheduler_grpc.protocol import CURRENT_PROTOCOL_EPOCH

        ts = Timestamp()
        ts.FromDatetime(datetime.now(UTC))
        protocol_epoch = 0
        async with self._db.session() as session:
            try:
                await ScheduleControlRepository(session).require_revision_state()
            except (ScheduleControlStateUnavailableError, SQLAlchemyError):
                pass
            else:
                protocol_epoch = CURRENT_PROTOCOL_EPOCH
        return pb.PingResponse(
            brain_version=__version__,
            brain_time=ts,
            scheduler_protocol_epoch=protocol_epoch,
        )


# =====================================================================
# Helpers
# =====================================================================


async def _bound_project_id(
    raw_project_id: str,
    *,
    context: grpc.aio.ServicerContext,
    bindings: Any,
    db: Any,
    enforce: Any,
) -> UUID:
    try:
        project_id = UUID(raw_project_id)
    except ValueError as exc:
        await context.abort(
            grpc.StatusCode.INVALID_ARGUMENT,
            "project_id is not a UUID",
        )
        raise AssertionError("context.abort unexpectedly returned") from exc
    await enforce(
        context=context,
        project_id=project_id,
        bindings=bindings,
        db=db,
    )
    return project_id


def _is_current_protocol_epoch(value: int) -> bool:
    from z4j_brain.scheduler_grpc.protocol import CURRENT_PROTOCOL_EPOCH

    return value == CURRENT_PROTOCOL_EPOCH


def _pb_datetime(value: Timestamp) -> datetime | None:
    if value.seconds == 0 and value.nanos == 0:
        return None
    return datetime.fromtimestamp(
        value.seconds + value.nanos / 1_000_000_000,
        tz=UTC,
    )


def _present_pb_datetime(value: Timestamp) -> datetime:
    """Decode a timestamp whose protobuf message presence was proved."""

    return datetime.fromtimestamp(
        value.seconds + value.nanos / 1_000_000_000,
        tz=UTC,
    )


def _required_pb_datetime(value: Timestamp, *, field: str) -> datetime:
    parsed = _pb_datetime(value)
    if parsed is None:
        raise ValueError(f"{field} is required")
    return parsed


def _pb_timestamp(value: datetime | None) -> Timestamp:
    result = Timestamp()
    if value is not None:
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        result.FromDatetime(value.astimezone(UTC))
    return result


def _current_fire_refresh_response(transition: Any) -> pb.FireScheduleResponse | None:
    if transition.disposition in {"applied", "idempotent"}:
        return None
    schedule = transition.schedule
    if schedule is None:
        return pb.FireScheduleResponse(
            disposition=pb.FireDisposition.FIRE_STALE_CONTROL_REFRESH,
            error_code="schedule_not_found",
            error_message="schedule does not exist",
        )
    dispositions = {
        "slot_resolved_refresh": (
            pb.FireDisposition.FIRE_SLOT_RESOLVED_REFRESH,
            "slot_resolved",
            "cadence slot is already resolved",
        ),
        "stale_control_refresh": (
            pb.FireDisposition.FIRE_STALE_CONTROL_REFRESH,
            "stale_control",
            "schedule control state changed",
        ),
        "cadence_semantics_mismatch": (
            pb.FireDisposition.FIRE_CADENCE_SEMANTICS_MISMATCH,
            "cadence_semantics_mismatch",
            "scheduler cadence semantics do not match Brain",
        ),
    }
    disposition, code, message = dispositions.get(
        transition.disposition,
        (
            pb.FireDisposition.FIRE_RETRYABLE_OR_AMBIGUOUS,
            "fire_ambiguous",
            "fire acceptance could not be classified safely",
        ),
    )
    return pb.FireScheduleResponse(
        disposition=disposition,
        error_code=code,
        error_message=message,
        live_control_token=str(schedule.control_token or ""),
        live_revision=int(schedule.schedule_revision or 0),
        live_last_run_at=_pb_timestamp(schedule.last_run_at),
        live_next_run_at=_pb_timestamp(schedule.next_run_at),
    )


def _current_command_response(
    *,
    disposition: int,
    schedule: Any,
    command: Any,
    error_code: str = "",
    error_message: str = "",
) -> pb.FireScheduleResponse:
    return pb.FireScheduleResponse(
        command_id=str(command.id),
        disposition=disposition,
        acceptance_revision=int(command.schedule_acceptance_revision or 0),
        accepted_last_run_at=_pb_timestamp(command.schedule_scheduled_for),
        accepted_next_run_at=_pb_timestamp(command.schedule_next_run_at),
        live_control_token=str(schedule.control_token or ""),
        live_revision=int(schedule.schedule_revision or 0),
        live_last_run_at=_pb_timestamp(schedule.last_run_at),
        live_next_run_at=_pb_timestamp(schedule.next_run_at),
        error_code=error_code,
        error_message=error_message,
    )


def _schedule_to_pb(
    schedule: Schedule,
    *,
    include_current: bool = True,
) -> pb.Schedule:
    """Translate a SQLAlchemy ``Schedule`` row to its protobuf form."""
    from z4j_brain.scheduler_grpc.wire import schedule_to_pb

    return schedule_to_pb(schedule, include_current=include_current)


def _ts_iso(ts: Timestamp) -> str:
    """Render a Timestamp as ISO-8601 for a Command payload."""
    if ts.seconds == 0 and ts.nanos == 0:
        return ""
    return datetime.fromtimestamp(
        ts.seconds + ts.nanos / 1_000_000_000,
        tz=UTC,
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
        if schedule.engine not in (agent.engine_adapters or ()):
            continue
        # Selection is only a routing hint.  Re-lock the durable live row
        # immediately before the cadence transaction creates its command so a
        # concurrent revoke either waits behind this accepted fire or wins and
        # makes the caller take the existing buffered fallback.
        live = await AgentRepository(session).get_live(agent.id, lock=True)
        if live is not None:
            return live
    return None


__all__ = ["SchedulerServiceImpl"]
