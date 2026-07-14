"""Event ingestion: agent → events table → tasks projection.

The :class:`EventIngestor` is the brain-side counterpart of the
agent's event capture path. For each event in an inbound
``event_batch``:

1. Re-apply the redaction engine (defense in depth - the agent
   already redacted, but if the agent is misconfigured or
   compromised we MUST scrub before storage).
2. INSERT into the partitioned ``events`` table. Idempotent on
   ``(occurred_at, id)`` so a re-connecting agent that replays
   buffered events does not duplicate.
3. Project the event onto the ``tasks`` table - upsert by
   ``(project_id, engine, task_id)``, applying the right state
   transition + lifecycle timestamps for the event kind.
4. Touch the ``queues`` table if the event mentions a queue we
   have not yet recorded.
5. Bump the agent's ``last_seen_at`` (event traffic counts as a
   heartbeat).

The class is dependency-injected with a :class:`RedactionEngine`
plus the four repositories it writes to. No SQLAlchemy imports,
no FastAPI imports, no implicit globals.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4, uuid5

import structlog
from z4j_core.models.event import EventKind
from z4j_core.redaction import RedactionEngine

from z4j_brain.persistence.enums import (
    TERMINAL_TASK_STATES,
    TaskPriority,
    TaskState,
)

#: Namespace UUID used to derive the brain-side event id from the
#: agent-supplied id + project_id. Generated once via
#: ``uuid.uuid4()`` and pinned here so the same agent_event_id
#: under the same project_id always derives the same brain-side
#: id (idempotent across replays) but DIFFERENT project_ids
#: cannot ever collide on the same brain-side id (closes the
#: cross-project censorship vector).
_EVENT_ID_NAMESPACE = UUID("c4d2c84e-2f0a-4b6c-9c5b-1d6f9a1e7c2a")

#: Bounds for the ``occurred_at`` clamp. We accept events up to
#: this far in the past or future relative to brain wall-clock;
#: anything outside is clamped to ``now`` with a logged warning.
#: This protects against malicious agents picking an
#: ``occurred_at`` outside the pre-created partition window
#: (which would raise ``no partition of relation "events" found``
#: on Postgres). It also protects against an attacker using a
#: far-future timestamp to dodge dedupe.
_OCCURRED_AT_PAST_LIMIT = timedelta(days=400)
#: Tight future clamp (60s) so a hostile agent cannot stamp
#: ``task.succeeded`` minutes in the future to "lock" a task's
#: state column against every legitimate subsequent event within
#: the window. 60s is plenty of slack for NTP drift between the
#: agent's clock and the brain's; the ReplayGuard's freshness
#: window is already ±60s.
_OCCURRED_AT_FUTURE_LIMIT = timedelta(seconds=60)

if TYPE_CHECKING:
    from collections.abc import Callable

    from z4j_brain.persistence.repositories import (
        AgentRepository,
        EventRepository,
        QueueRepository,
        TaskRepository,
        WorkerRepository,
    )


logger = structlog.get_logger("z4j.brain.event_ingestor")


#: Max length of the ``task_name`` label on Prometheus metrics.
#: Names longer than this are truncated at the label boundary;
#: the original full string is still recorded in the task table
#: and audit log.
_METRIC_TASK_NAME_MAX_LEN: int = 128

#: Max distinct ``task_name`` labels we accept per project before
#: folding overflow into a single sentinel. With ~50 task_names per
#: project this is comfortable; 1000 leaves 20x headroom. The bound
#: prevents a malicious agent from blowing up Prometheus cardinality
#: with random distinct names. (Round 3 Crit-1.)
_METRIC_TASK_NAME_PER_PROJECT_CAP: int = 1000

#: Sentinel substituted for the metric label when a project exceeds
#: the per-project cap. Distinct projects keep distinct overflow
#: labels (via the project label dimension) so an alerting query
#: like ``rate(z4j_tasks_total{task_name="__overflow__"}[5m])`` still
#: tells the operator which project saturated.
_METRIC_TASK_NAME_OVERFLOW: str = "__overflow__"

# Per-project seen-set of task_names already admitted to the metric.
# This is a module-level dict keyed by project UUID; entries grow
# as new task_names appear and are bounded by the cap above. Reset
# on brain restart (which is fine for a Prometheus counter that
# also resets on restart).
_metric_task_name_seen: dict[UUID, set[str]] = {}


def _safe_metric_task_name(project_id: UUID, raw: str) -> str:
    """Return a metric-safe task_name label for the given project.

    Truncates the raw string to ``_METRIC_TASK_NAME_MAX_LEN`` and,
    once a project's seen-set has reached
    ``_METRIC_TASK_NAME_PER_PROJECT_CAP`` distinct names, folds any
    further new names into the overflow sentinel. (Round 3 Crit-1.)
    """
    truncated = raw[:_METRIC_TASK_NAME_MAX_LEN] if raw else "unknown"
    seen = _metric_task_name_seen.setdefault(project_id, set())
    if truncated in seen:
        return truncated
    if len(seen) >= _METRIC_TASK_NAME_PER_PROJECT_CAP:
        return _METRIC_TASK_NAME_OVERFLOW
    seen.add(truncated)
    return truncated


def _reset_metric_task_name_seen_for_tests() -> None:
    """Test hook -- clear the per-project seen-set so a single
    test's emissions do not affect the next test's overflow check.
    """
    _metric_task_name_seen.clear()


#: Postgres SQLSTATE *classes* (the 2-char prefix) that are TRANSIENT:
#: a fresh attempt is likely to succeed once the condition clears.
#:   08 connection exception
#:   40 transaction rollback (40001 serialization_failure, 40P01 deadlock)
#:   53 insufficient resources (disk full / out of memory / too many
#:      connections)
#:   55 object not in prerequisite state (55P03 lock_not_available)
#:   57 operator intervention (57014 query_canceled -- i.e. a statement /
#:      lock_timeout cancel -- 57P01 admin_shutdown, 57P03 cannot_connect_now)
#:   58 system error (io_error)
#:   42 syntax_error_or_access_rule_violation (42703 undefined_column, 42P01
#:      undefined_table, 42501 insufficient_privilege, ...) -- these are a
#:      BRAIN-side schema / SQL / privilege problem, NOT malformed event
#:      content, so a re-send after a rolling migration completes (or the
#:      operator fixes the deploy) succeeds. Treating it PERMANENT
#:      drop-and-acked EVERY event during a schema-skew rollout, silently
#:      losing the whole stream; TRANSIENT instead withholds+retries and
#:      recovers once the skew heals -- the common case (round-8 finding H2).
#:      A NEVER-healing class-42 (a genuine SQL bug, a permanent privilege
#:      misconfiguration, a syntax error) then behaves like any persistent
#:      outage: the agent re-sends until its buffer overflow-evicts oldest
#:      events. That is LOUD + observable (stuck buffer, repeated brain 42xxx
#:      logs, climbing stuck-entry metrics) and strictly better than the
#:      pre-fix silent TOTAL loss -- the operator must fix the brain, which no
#:      classification can substitute for (accepted residual, r11 review).
#:      INVARIANT SCOPE (round-10 / round-11 external): a never-healing class-42
#:      does NOT self-heal; it is deliberately treated as transient so the FAR
#:      more common rolling-migration skew (the healing case) recovers
#:      loss-free, and the residual is a LOUD, operator-actionable stuck-buffer
#:      state -- never a silent drop. Class 42 is ONE member of a category, not
#:      the only one: the resource / system classes 53 / 57 / 58 below are the
#:      same shape (a persistent disk-full / operator-intervention / I/O error
#:      loops loudly, its common transient form recovers). The invariant
#:      therefore reads: for an authenticated, protocol-compatible frame that
#:      reaches dispatch, every unconfirmed failure is either self-healing OR a
#:      loud, observable, operator-actionable infrastructure / brain-
#:      misconfiguration failure -- never a silent drop.
#: Everything else (22 data_exception, 23 integrity_constraint_violation,
#: 25 invalid_transaction_state, ...) is PERMANENT.
#: This is keyed on SQLSTATE rather than the SQLAlchemy exception class
#: because the asyncpg dialect boxes most server errors as the BARE
#: ``sqlalchemy.exc.DBAPIError`` (only integrity + syntax get a specific
#: OperationalError/IntegrityError/ProgrammingError subclass), so an
#: isinstance-only allowlist silently mis-dropped transient lock/resource
#: errors as permanent (round-8 asyncpg finding, real data loss).
_TRANSIENT_SQLSTATE_CLASSES: frozenset[str] = frozenset({"08", "40", "42", "53", "55", "57", "58"})

#: Specific transient SQLSTATE *codes* whose enclosing class is otherwise
#: PERMANENT, allowlisted by exact code (never the whole class):
#:   25006 read_only_sql_transaction -- a write hit a hot standby /
#:         not-yet-promoted primary during a Postgres failover; recovers once
#:         promotion completes (class 25 as a whole -- e.g. 25P02
#:         in_failed_sql_transaction -- stays permanent).
#:   25P03 idle_in_transaction_session_timeout, 25P04 -- the server closed a
#:         too-idle transaction; a fresh transaction succeeds.
#: NOTE: 0A000 (feature_not_supported) and XX000 (internal_error) are
#: deliberately NOT here. asyncpg DOES raise a stale prepared-plan / type-cache
#: invalidation under those codes, but so do genuinely PERMANENT failures (an
#: ordinary unsupported SQL feature is 0A000; a corrupt index / real backend
#: fault is XX000), so the bare code is not a reliable transient signal --
#: keying on it would withhold-confirm a deterministic failure forever
#: (external round-9 H1). The self-healing case is matched by the SPECIFIC
#: asyncpg exception CLASS instead (see _TRANSIENT_DRIVER_CACHE_ERRORS), which
#: is unambiguous.
_TRANSIENT_SQLSTATE_CODES: frozenset[str] = frozenset({"25006", "25P03", "25P04"})

#: asyncpg raises a stale prepared-plan / schema-cache invalidation as one of
#: these SPECIFIC exception classes. They self-heal on a fresh (re-planned)
#: transaction, and -- unlike their bare SQLSTATE (0A000 / XX000, which
#: deterministic failures also use) -- the class itself is an unambiguous
#: transient signal, so it is matched by class name BEFORE the SQLSTATE gate
#: (external round-8 H1, narrowed in round-9 H1). ``.orig`` (the raw asyncpg
#: error) or the SQLAlchemy wrapper may carry the class, so both are checked.
_TRANSIENT_DRIVER_CACHE_ERRORS: frozenset[str] = frozenset(
    {"InvalidCachedStatementError", "OutdatedSchemaCacheError"}
)

#: The SERVER-side stale-type-cache invalidation ("cache lookup failed for type
#: <oid>") is raised by asyncpg as a BARE ``InternalServerError`` (SQLSTATE
#: XX000), NOT one of the classes above, so it escapes the class-name match. It
#: fires when a type OID is invalidated mid-flight (a rolling ``ALTER TYPE`` /
#: DROP+CREATE TYPE migration) and self-heals once connections churn / re-
#: introspect, so it is TRANSIENT. It is matched by this exact MESSAGE signature
#: (not the bare XX000 code) so a GENERIC XX000 -- a corrupt index or real
#: backend fault, which never heals -- still classifies PERMANENT rather than
#: looping the agent forever (external round-9 re-review: dropping bare XX000
#: silently lost events across a type-recreation migration, reopening R8-H1).
_STALE_TYPE_CACHE_SIGNATURE = "cache lookup failed for type"


def _sqlstate_of(exc: BaseException) -> str | None:
    """Best-effort extraction of the driver SQLSTATE from a DB error.

    Looks on the SQLAlchemy-wrapped ``.orig`` (the raw DBAPI exception)
    for ``sqlstate`` (asyncpg) or ``pgcode`` (psycopg). Returns ``None``
    for a non-DB error (which then classifies via the isinstance fallback).
    """
    for candidate in (getattr(exc, "orig", None), exc):
        if candidate is None:
            continue
        for attr in ("sqlstate", "pgcode"):
            code = getattr(candidate, attr, None)
            if isinstance(code, str) and len(code) >= 2:
                return code
    return None


def _looks_like_stale_type_cache(exc: BaseException) -> bool:
    """True if a bare XX000 ``InternalServerError`` is the SELF-HEALING
    server-side stale-type-cache invalidation (``cache lookup failed for type
    <oid>``) rather than a generic, never-healing internal error.

    Matched by message ONLY on the raw driver error (``exc.orig``), NOT on the
    SQLAlchemy wrapper: ``str(DBAPIError)`` embeds the failing statement's bound
    ``[parameters: ...]``, so matching the wrapper would fire on an INSERT whose
    event payload merely QUOTES the signature text (a monitored task reporting a
    Postgres ``cache lookup failed for type`` error in its own failure field) --
    mis-classifying a generic never-healing XX000 as transient and looping the
    agent forever (external round-9 re-review). The raw asyncpg ``PostgresError``
    str is just its message, so it carries no bound parameters. Fall back to
    ``exc`` only when there is no ``.orig`` (an unwrapped raw error, whose str is
    likewise message-only).
    """
    orig = getattr(exc, "orig", None)
    candidate = orig if orig is not None else exc
    return _STALE_TYPE_CACHE_SIGNATURE in str(candidate).lower()


def _is_transient_db_error(exc: BaseException) -> bool:
    """True if a per-event failure is TRANSIENT (a fresh attempt would
    likely succeed) rather than PERMANENT (the same event fails the same
    way every time).

    This decides whether the batch withholds its delivery ack: a
    transient failure withholds the ack so the agent re-sends and the
    event gets another chance; a permanent failure does NOT withhold
    (re-sending would loop forever), so the event is dropped server-side
    and acked.

    Classification is primarily by Postgres SQLSTATE class (see
    ``_TRANSIENT_SQLSTATE_CLASSES``) because the production driver is
    asyncpg, which boxes lock/resource/connection errors as a bare
    ``DBAPIError`` an isinstance allowlist would miss. When there is no
    SQLSTATE (a non-Postgres backend such as dev SQLite, a driver-level
    interface error, or a non-DB exception) it falls back to exception
    class:

    * PERMANENT: ``IntegrityError`` / ``DataError`` (the event's own bad
      CONTENT -- a constraint violation / bad value) AND any non-DB
      deterministic bug (``RuntimeError``, ``TypeError``, ``ValueError``,
      ``StatementError``, a GENERIC ``InvalidRequestError``, a
      redaction/projection failure). Re-sending the identical event fails
      identically forever, so dropping-and-acking it (bounded single-event
      loss, logged) beats withholding the ack -- which would pin the agent's
      buffer HEAD and overflow-evict later events. NOTE: ``ProgrammingError``
      is NOT permanent here -- it is a brain-side schema / SQL / privilege
      problem (a rolling-migration column gap, a bad grant), not event
      content, so it classifies TRANSIENT (see below); it was moved out of
      this permanent set in R8-H2.
    * TRANSIENT: ``OperationalError`` (locks, connection resets) /
      ``InterfaceError`` / ``TimeoutError`` (pool) / ``ProgrammingError``
      (brain-side schema/SQL/privilege, R8-H2) / a ``PendingRollbackError``
      (a mid-transaction connection invalidation), an invalidated connection,
      low-level ``ConnectionError`` / ``OSError``, and a lock/deadlock matched
      by message. A no-SQLSTATE ``OperationalError`` is the one carve-out:
      SQLite raises the same catch-all
      ``OperationalError`` for DETERMINISTIC conditions (``no such column``
      after a bad migration, ``too many SQL variables``, a syntax error),
      which recur identically and must NOT loop the ack-withhold forever
      (R9), so a recognised deterministic-SQLite signature is PERMANENT.

    The UNKNOWN case (no SQLSTATE, no isinstance match) defaults to
    PERMANENT: it is almost always a non-DB deterministic bug, and the
    agent's transient-retry path carries no drop budget, so a wrong
    "transient" guess loops forever.
    """
    from sqlalchemy.exc import (
        DataError,
        IntegrityError,
        InterfaceError,
        OperationalError,
        PendingRollbackError,
        ProgrammingError,
    )
    from sqlalchemy.exc import TimeoutError as SATimeoutError

    # asyncpg raises a stale prepared-plan / schema-cache invalidation as a
    # SPECIFIC exception class (InvalidCachedStatementError /
    # OutdatedSchemaCacheError), which self-heals on a fresh (re-planned)
    # transaction. Match it by CLASS NAME first -- BEFORE the SQLSTATE gate --
    # because these carry SQLSTATE 0A000 (feature_not_supported) / XX000
    # (internal_error), whose whole CLASS is otherwise permanent and whose
    # exact CODE is NOT a reliable transient signal: an ordinary unsupported-
    # feature error also uses 0A000, and unrelated internal failures (a corrupt
    # index, a genuine backend fault) also use XX000. Keying transient on those
    # bare codes would withhold-confirm a deterministic failure forever
    # (round-9 external H1). The specific asyncpg cache CLASS is the reliable
    # self-healing signal, so it is honoured here and the bare 0A000/XX000
    # codes are NOT in _TRANSIENT_SQLSTATE_CODES.
    for candidate in (getattr(exc, "orig", None), exc):
        if candidate is not None and type(candidate).__name__ in _TRANSIENT_DRIVER_CACHE_ERRORS:
            return True

    sqlstate = _sqlstate_of(exc)
    if sqlstate is not None:
        # The server-side stale-type-cache invalidation arrives as a bare
        # InternalServerError (XX000) with a distinctive message; match it by
        # signature so it is TRANSIENT while a generic (never-healing) XX000
        # stays permanent (round-9 re-review).
        return (
            sqlstate[:2] in _TRANSIENT_SQLSTATE_CLASSES
            or sqlstate in _TRANSIENT_SQLSTATE_CODES
            or (sqlstate == "XX000" and _looks_like_stale_type_cache(exc))
        )

    # IntegrityError (constraint) and DataError (bad value/encoding) ARE the
    # event's content -- re-sending fails identically -- so they are PERMANENT.
    # ProgrammingError is NOT: it is a brain-side schema / SQL / privilege
    # problem (missing column during a rolling migration, etc.), so it is
    # TRANSIENT (heals on the deploy, or loops-without-loss observably rather
    # than silently dropping every event, R8-H2) -- handled in the transient
    # group below.
    if isinstance(exc, (IntegrityError, DataError)):
        return False
    # A no-SQLSTATE OperationalError (SQLite dev, since Postgres carries a
    # SQLSTATE handled above) with a recognised DETERMINISTIC signature --
    # schema drift / malformed statement -- is PERMANENT; otherwise the
    # catch-all OperationalError is TRANSIENT (a lock or connection reset).
    if isinstance(exc, OperationalError) and _looks_like_permanent_sqlite_error(exc):
        return False
    # OperationalError / InterfaceError / pool TimeoutError / ProgrammingError
    # (brain-side schema/SQL, R8-H2), low-level ConnectionError / OSError
    # (builtin TimeoutError is an OSError subclass), an invalidated DBAPI
    # connection, or a PendingRollbackError (a poisoned outer commit -- under a
    # live connection every permanent error rolls its savepoint back cleanly
    # and commit succeeds, so a PendingRollbackError means the connection was
    # invalidated mid-transaction, which self-heals on a fresh session, R8-H2)
    # are all transient (infrastructure or self-healing) failures. A GENERIC
    # InvalidRequestError (real API misuse) is NOT here -- only the
    # PendingRollbackError subtype is carved out.
    #
    # WHY THE PendingRollbackError CARVE-OUT IS SAFE (round-9 external MED,
    # REFUTED): a deterministic per-event flush error can never REACH this
    # classifier as a PendingRollbackError, because every catch-and-continue on
    # the ingest path is begin_nested()-isolated (ingest_batch's per-event
    # savepoint; the events / task / worker / schedule / canvas side writes each
    # in their own savepoint). A failing flush's savepoint rollback restores the
    # parent to ACTIVE and re-raises the ORIGINAL class (IntegrityError /
    # DataError / ProgrammingError -> handled above), never a PendingRollbackError.
    # The ONLY way a PendingRollbackError reaches here is a PRIOR event's
    # connection invalidation deactivating the outer transaction (its ROLLBACK TO
    # SAVEPOINT could not run on the dead connection) so the NEXT event's
    # begin_nested() raises it -- genuinely invalidation-derived and transient.
    # PendingRollbackError exposes NO connection_invalidated attribute of its own,
    # so this isinstance carve-out is the ONLY signal that keeps the follow-on
    # events after a real invalidation classified transient; narrowing/removing it
    # would drop-and-ack a recoverable event.
    if isinstance(
        exc,
        (
            OperationalError,
            InterfaceError,
            SATimeoutError,
            ProgrammingError,
            PendingRollbackError,
            ConnectionError,
            OSError,
        ),
    ) or getattr(exc, "connection_invalidated", False):
        return True
    return _looks_like_deadlock(exc)


def _looks_like_permanent_sqlite_error(exc: BaseException) -> bool:
    """True for a SQLite ``OperationalError`` whose message signals a
    DETERMINISTIC (permanent) condition -- schema drift or a malformed
    statement -- rather than the transient ``database is locked``.

    SQLite folds many unrelated failures into the single catch-all
    ``OperationalError`` with no SQLSTATE, so the transient (lock) vs
    permanent (schema/syntax) split can only be made by message here. Used
    only on the no-SQLSTATE dev/SQLite path; production Postgres classifies
    by SQLSTATE and never reaches this.
    """
    msg = str(exc).lower()
    return any(
        token in msg
        for token in (
            "no such column",
            "no such table",
            "no such function",
            "has no column",
            "syntax error",
            "too many",
            "unrecognized token",
        )
    )


def _looks_like_deadlock(exc: BaseException) -> bool:
    """Best-effort detection of a serialisation/deadlock error, used by the
    per-event savepoint RETRY path (one fresh-savepoint retry on a
    deadlock) and as the no-SQLSTATE transient fallback.

    Matches the deadlock/serialization SQLSTATEs, then falls back to a
    substring check so the SQLite ``database is locked`` and cockroachdb /
    yugabyte equivalents are also caught. Deliberately does NOT match
    ``current transaction is aborted``: that is a CASCADE from a prior
    (possibly permanent) error, not itself transient, and treating it as
    transient could withhold the ack forever behind a poison event.
    """
    sqlstate = _sqlstate_of(exc)
    if sqlstate in {"40P01", "40001"}:
        return True
    msg = str(exc).lower()
    return any(
        token in msg
        for token in (
            "deadlock",
            "could not serialize",
            "database is locked",
        )
    )


#: Map from agent-side EventKind to the TaskState the brain should
#: project onto the ``tasks`` row. Events whose state mapping is
#: None do not change the task's state column (e.g. heartbeat-only
#: events, schedule events).
# Terminal task states. Used by the state-machine guard to decide
# whether a late-arriving event with an earlier occurred_at should
# be allowed to overwrite the current row's state. A terminal state
# ALWAYS wins over a non-terminal state regardless of timestamp;
# within the same tier the monotonic-timestamp guard applies.
# Canonical definition lives in ``z4j_brain.persistence.enums`` so
# this guard and ``TaskRepository.apply_reconciled_state`` (R3 H1)
# share one notion of "terminal".
_TERMINAL_TASK_STATES = TERMINAL_TASK_STATES

_STATE_FOR_KIND: dict[EventKind, TaskState | None] = {
    EventKind.TASK_RECEIVED: TaskState.RECEIVED,
    EventKind.TASK_STARTED: TaskState.STARTED,
    EventKind.TASK_SUCCEEDED: TaskState.SUCCESS,
    EventKind.TASK_FAILED: TaskState.FAILURE,
    EventKind.TASK_RETRIED: TaskState.RETRY,
    EventKind.TASK_REVOKED: TaskState.REVOKED,
}


class BatchIngestResult:
    """Outcome of :meth:`EventIngestor.ingest_batch`.

    ``new_events`` are the NEW (non-duplicate) events actually inserted
    (used for once-per-logical-event hooks). ``transient_skips`` counts
    events that were dropped from THIS commit because of a TRANSIENT
    infrastructure error (a deadlock/serialization/operational failure
    that survived the per-event retry), not because their content was
    bad. A batch with any transient skip is NOT fully durable: the caller
    must withhold the delivery acknowledgement so the agent re-sends the
    batch (the committed events dedup on replay; the transiently-failed
    one gets another chance). Without this the skipped event would be
    silently dropped while the agent, seeing a durable ack, evicts its
    only copy (permanent data loss).

    ``pending_metrics`` are deferred Prometheus increments (the label set
    already resolved -- including the Crit-1 cardinality cap -- so only the
    ``.inc()`` / ``.observe()`` remains). The caller emits them AFTER the outer
    commit succeeds, so a transient rollback + re-send does not double-count a
    row that was never actually persisted (round-9 external LOW).
    """

    __slots__ = ("new_events", "pending_metrics", "transient_skips")

    def __init__(
        self,
        new_events: list[dict[str, Any]],
        transient_skips: int,
        pending_metrics: list[Callable[[], None]] | None = None,
    ) -> None:
        self.new_events = new_events
        self.transient_skips = transient_skips
        self.pending_metrics: list[Callable[[], None]] = pending_metrics or []

    @property
    def fully_durable(self) -> bool:
        return self.transient_skips == 0

    def emit_metrics(self) -> None:
        """Emit the deferred Prometheus increments. Call AFTER a successful
        commit. Best-effort: a metric-registry hiccup must never surface as a
        delivery failure for an already-committed batch."""
        for inc in self.pending_metrics:
            try:
                inc()
            except Exception:
                from z4j_brain.api.metrics import record_swallowed

                record_swallowed("event_ingestor", "deferred_metric")


class EventIngestor:
    """Project agent-side events onto the brain's persistent state."""

    __slots__ = ("_redaction",)

    def __init__(self, redaction: RedactionEngine) -> None:
        self._redaction = redaction

    async def ingest_batch(
        self,
        *,
        events: list[dict[str, Any]],
        project_id: UUID,
        agent_id: UUID,
        agents: AgentRepository,
        event_repo: EventRepository,
        task_repo: TaskRepository,
        queue_repo: QueueRepository,
        worker_repo: WorkerRepository | None = None,
    ) -> BatchIngestResult:
        """Ingest a batch of events. Returns a :class:`BatchIngestResult`
        carrying the NEW (non-duplicate) events -- the ones actually
        inserted, with re-delivered duplicates excluded (an agent
        reconnect re-flushes its buffered events with the SAME event_id;
        those dedup at insert time) -- and a count of events dropped from
        this commit for a TRANSIENT reason (so the caller can withhold
        the delivery ack and let the agent re-send).

        Returning the new events (not just a count) lets the caller run
        per-event hooks -- notably automation rule firing -- ONCE per
        LOGICAL event instead of once per delivery, so a flaky WS that
        re-delivers a ``task.failed`` cannot fire a rule (and its
        notify/retry action) N times for one failure.

        The full batch participates in the caller's transaction.
        Per-event redaction failures do NOT poison the batch - the
        bad event is logged + skipped, the rest still ingest.

        Worker upserts and the agent heartbeat are batched: instead
        of one ``upsert_from_event`` per event + ``touch_heartbeat``
        at the end (N+1 round-trips), we accumulate
        ``(engine, worker_name) -> max_occurred_at`` while iterating
        and emit ONE bulk upsert + ONE ``touch_heartbeat_at`` after
        the loop. Saves ~N round-trips per batch on the workers +
        agents tables.
        """
        # The NEW (actually-inserted) events, in arrival order. A
        # re-delivered duplicate (same event_id) dedups at insert time
        # and is NOT appended, so the caller's automation hook fires once
        # per logical event, not once per delivery.
        new_events: list[dict[str, Any]] = []
        # Events dropped from THIS commit because of a transient infra
        # error (deadlock/operational after the per-event retry). A
        # non-zero count means the batch is not fully durable and the
        # caller must NOT ack it, so the agent re-sends (R6-panel-HIGH).
        transient_skips = 0
        # Accumulator for worker upserts. Key is (engine, name);
        # value is the latest occurred_at observed for that worker
        # in this batch. We pick max so a stale event late in the
        # batch can't roll the worker's heartbeat backwards.
        worker_seen: dict[tuple[str, str], datetime] = {}
        # Same dedup trick for queue touches: collect
        # ``(engine, name)`` pairs while iterating and emit one
        # ``touch`` per unique pair after the loop, so a 1000-event
        # batch all hitting one queue does 1 upsert instead of 1000.
        queues_seen: set[tuple[str, str]] = set()
        # Track max(occurred_at) across the whole batch so the agent
        # heartbeat carries a real event timestamp instead of racing
        # with wall-clock now() (which would let a hostile clock
        # skew between brain replicas reorder agent liveness).
        batch_max_occurred_at: datetime | None = None
        # Deferred Prometheus increments: the label set (and its Crit-1
        # cardinality cap) resolves eagerly at ingest time, but the .inc() /
        # .observe() is held here and emitted by the CALLER only after the
        # outer commit succeeds, so a transient rollback + re-send cannot
        # double-count a row that was never persisted (round-9 external LOW).
        pending_metrics: list[Callable[[], None]] = []

        # Wrap each per-event ingest in its own savepoint
        # (``session.begin_nested()``) so a deadlock on event N rolls
        # back only event N's writes - the parent transaction stays
        # alive and the rest of the batch survives. Without per-event
        # savepoints a single deadlock would put asyncpg into
        # ``aborted`` state and every subsequent statement would
        # raise ``InFailedSqlTransactionError``, losing every
        # innocent event in the batch.
        #
        # The retry path runs the same event ONCE more inside a fresh
        # savepoint (covers the typical 2-process deadlock cycle
        # where one transaction wins on the retry). If the retry also
        # deadlocks we log + skip that single event; the rest of the
        # batch survives.
        session_obj = event_repo.session
        for raw_event in events:
            for _attempt in (1, 2):
                try:
                    async with session_obj.begin_nested():
                        event_max = await self._ingest_one(
                            raw_event=raw_event,
                            project_id=project_id,
                            agent_id=agent_id,
                            event_repo=event_repo,
                            task_repo=task_repo,
                            queue_repo=queue_repo,
                            worker_seen=worker_seen,
                            queues_seen=queues_seen,
                            pending_metrics=pending_metrics,
                        )
                except Exception as exc:
                    # ``begin_nested`` already rolled this event's
                    # savepoint back, so the parent transaction is intact
                    # and the rest of the batch still commits. Classify:
                    # a TRANSIENT infrastructure error (pool timeout /
                    # deadlock / connection reset) withholds the batch ack
                    # so the agent re-sends; a PERMANENT one -- a content/
                    # schema error OR any non-DB deterministic bug -- is
                    # dropped and acked, because re-sending the identical
                    # event fails identically forever and would pin the
                    # agent's buffer head. See ``_is_transient_db_error``
                    # (allowlist of transient DB-infra errors; everything
                    # else, incl. unknown non-DB errors, is permanent).
                    transient = _is_transient_db_error(exc)
                    # A deadlock/serialization failure gets ONE fresh-
                    # savepoint retry (covers the typical 2-process
                    # deadlock cycle) before it counts as a skip.
                    if _attempt == 1 and transient and _looks_like_deadlock(exc):
                        logger.info(
                            "z4j event_ingestor: per-event deadlock; "
                            "retrying inside fresh savepoint",
                            project_id=str(project_id),
                            agent_id=str(agent_id),
                        )
                        continue
                    if transient:
                        # Withhold the ack; the agent re-sends. We do NOT
                        # re-raise (a full-batch rollback under sustained
                        # contention amplifies latency an order of
                        # magnitude, round-13 perf); the committed events
                        # dedup on the replay.
                        transient_skips += 1
                        logger.warning(
                            "z4j event_ingestor: per-event transient DB "
                            "error survived retry; withholding ack so the "
                            "agent re-sends",
                            project_id=str(project_id),
                            agent_id=str(agent_id),
                            error_class=type(exc).__name__,
                        )
                    else:
                        # Permanent (malformed / constraint / bad value).
                        # Re-sending cannot help, so drop it and let the
                        # batch ack (NOT counted toward transient_skips).
                        logger.exception(
                            "z4j event_ingestor: per-event ingest failed (permanent); dropping",
                            project_id=str(project_id),
                            agent_id=str(agent_id),
                        )
                    break
                else:
                    if event_max is None:
                        # Per-event ingest skipped (bad envelope, dup, etc.)
                        break
                    inserted, occurred_at = event_max
                    if inserted:
                        new_events.append(raw_event)
                    if batch_max_occurred_at is None or occurred_at > batch_max_occurred_at:
                        batch_max_occurred_at = occurred_at
                    break

        # Bulk worker upsert. One round-trip for the whole batch.
        # Wrapped in a savepoint with per-row fallback so a deadlock
        # under concurrent heartbeats (the scenario the per-row
        # savepoint scaffolding originally guarded against) does not
        # poison the events transaction.
        if worker_repo is not None and worker_seen:
            await self._flush_worker_upserts(
                worker_repo=worker_repo,
                project_id=project_id,
                worker_seen=worker_seen,
            )

        # Best-effort side writes (queue liveness + agent heartbeat).
        # These are OBSERVABILITY, not event data, so each runs in its
        # own savepoint via _best_effort_side_write: a deadlock there (a
        # touch/heartbeat UPSERT lock-cycling with a concurrent agent, or
        # a heartbeat vs an automation firing's row lock) rolls back ONLY
        # that write, leaving the ingested events to commit and
        # automation to fire. Live-test finding: an UNprotected deadlock
        # on the heartbeat touch aborted the whole event batch.
        for engine_name, queue_name in queues_seen:
            await self._best_effort_side_write(
                session_obj,
                queue_repo.touch(
                    project_id=project_id,
                    engine=engine_name,
                    name=queue_name,
                ),
                write="queue.touch",
                queue=queue_name,
                engine=engine_name,
            )
        await self._best_effort_side_write(
            session_obj,
            agents.touch_heartbeat_at(agent_id, when=batch_max_occurred_at),
            write="agent.heartbeat",
            agent_id=str(agent_id),
        )
        return BatchIngestResult(
            new_events=new_events,
            transient_skips=transient_skips,
            pending_metrics=pending_metrics,
        )

    async def _best_effort_side_write(
        self,
        session_obj: Any,
        coro: Any,
        **ctx: Any,
    ) -> None:
        """Run a best-effort observability write in its own SAVEPOINT.

        A deadlock or error rolls back only this write (never the
        ingested events, which are the load-bearing data). A bare
        try/except would catch the error but leave the transaction
        aborted and poison the commit, so the savepoint is essential.
        """
        try:
            async with session_obj.begin_nested():
                await coro
        except Exception:
            logger.warning(
                "z4j event_ingestor: best-effort side write failed "
                "(non-fatal; events still commit)",
                **ctx,
            )

    async def _flush_worker_upserts(
        self,
        *,
        worker_repo: WorkerRepository,
        project_id: UUID,
        worker_seen: dict[tuple[str, str], datetime],
    ) -> None:
        """Issue the bulk worker upsert with a per-row fallback.

        Worker liveness is OBSERVABILITY, not load-bearing event data, so
        a worker upsert must NEVER fail the event batch. The bulk INSERT
        runs in its own savepoint; on ANY error -- a deadlock
        (``OperationalError``) between concurrent heartbeats, OR a
        deterministic ``DataError`` from an agent-supplied worker/host name
        that violates a column bound -- we fall back to the per-row
        savepointed path (:meth:`WorkerRepository.upsert_from_event`), which
        isolates each row so a single malformed row is skipped-and-logged
        while the good rows still land. Catching only ``OperationalError``
        here (the previous behaviour) let a malformed worker row propagate
        out of ``ingest_batch`` and fail the whole event batch -- which, on
        the no-drop transient delivery path, wedged the agent's send loop
        (round-8 worker-upsert finding).
        """
        from z4j_brain.persistence.enums import WorkerState

        rows = [
            {
                "project_id": project_id,
                "engine": engine,
                "name": name,
                "state": WorkerState.ONLINE,
                "last_heartbeat": occurred_at,
            }
            for (engine, name), occurred_at in worker_seen.items()
        ]
        try:
            async with worker_repo.session.begin_nested():
                await worker_repo.upsert_from_events_bulk(rows)
        except Exception:
            logger.warning(
                "z4j event_ingestor: bulk worker upsert failed (deadlock or "
                "a malformed worker row); falling back to per-row so a "
                "single bad row cannot fail the event batch",
                project_id=str(project_id),
                worker_count=len(rows),
            )
            for row in rows:
                # Each per-row upsert gets its OWN savepoint. ``upsert_from_event``
                # only savepoints its INSERT branch; its UPDATE branch (the
                # common re-observed-worker path) flushes UNprotected, so a
                # deadlock there under concurrent-heartbeat contention would
                # abort the OUTER events transaction -- and since this method
                # swallows the error, ``ingest_batch`` would return normally
                # and the caller's ``session.commit()`` would then silently
                # roll back every already-ingested event while the batch is
                # acked as durable (R9: observability-only worker contention
                # must never destroy deliverable events). The savepoint here
                # confines any per-row failure so the event rows survive.
                try:
                    async with worker_repo.session.begin_nested():
                        await worker_repo.upsert_from_event(
                            project_id=row["project_id"],
                            engine=row["engine"],
                            name=row["name"],
                            updates={
                                "state": row["state"],
                                "last_heartbeat": row["last_heartbeat"],
                            },
                        )
                except Exception:
                    logger.exception(
                        "z4j event_ingestor: per-row worker upsert fallback failed; skipping",
                        engine=row["engine"],
                        worker=row["name"],
                    )

    async def _ingest_one(  # noqa: PLR0912, PLR0915  event ingestion pipeline
        self,
        *,
        raw_event: dict[str, Any],
        project_id: UUID,
        agent_id: UUID,
        event_repo: EventRepository,
        task_repo: TaskRepository,
        queue_repo: QueueRepository,
        worker_seen: dict[tuple[str, str], datetime],
        queues_seen: set[tuple[str, str]] | None = None,
        pending_metrics: list[Callable[[], None]] | None = None,
    ) -> tuple[bool, datetime] | None:
        """Ingest one event.

        Returns ``(inserted, occurred_at)`` on success and ``None``
        when the event was rejected before insert (bad envelope,
        unparseable payload, etc.). ``inserted`` is True only when
        a new row landed in the partitioned events table; replays
        return False but still propagate ``occurred_at`` so the
        batch-level heartbeat sees the freshest timestamp.

        Worker hostnames carried in the event payload are recorded
        into ``worker_seen`` (an out-parameter dict) instead of
        being upserted inline; the caller flushes them as one bulk
        statement after the loop.
        """
        # Redaction defense in depth.
        scrubbed = self._redaction.scrub(raw_event)
        if not isinstance(scrubbed, dict):
            return None

        engine = str(scrubbed.get("engine", "")).strip()
        kind_value = str(scrubbed.get("kind", "")).strip()
        task_id = str(scrubbed.get("task_id", "")).strip()
        occurred_at_raw = scrubbed.get("occurred_at")
        data = scrubbed.get("data") or {}

        if not engine or not kind_value:
            return None

        try:
            kind = EventKind(kind_value)
        except ValueError:
            kind = EventKind.UNKNOWN

        occurred_at = _clamp_occurred_at(
            _parse_datetime(occurred_at_raw),
            project_id=project_id,
            agent_id=agent_id,
        )
        # Build the brain-side event id from the agent-supplied id,
        # NAMESPACED BY PROJECT_ID. Two consequences:
        #
        # 1. Replays from a re-connecting agent always derive the
        #    same brain-side id (idempotent - the conflict key on
        #    the partitioned events table fires).
        # 2. Project A and Project B can never collide on the same
        #    brain-side id, even if their agents pick the same
        #    raw uuid. Project-A agent CAN'T censor Project-B's
        #    events by picking known ids.
        #
        # If the agent omitted the id (or sent an unparseable /
        # nil / max / non-v4-v7 value - see _coerce_event_id), we
        # mint a fresh uuid4 with a logged warning. Idempotency
        # is lost for that single event but the system stays safe.
        agent_event_id = _coerce_event_id(scrubbed.get("id"))

        # For events that carry a task_id,
        # derive the brain-side event_id from the CONTENT
        # ``(project_id, task_id, kind, occurred_at_unix_seconds)``
        # rather than from the agent-supplied id. This dedupes the
        # celery-events fanout where 9 agents each receive every
        # task lifecycle event from the broker (different agents
        # generate different ids for the same logical event, so the
        # legacy agent-id-keyed dedupe missed them and the brain
        # inserted 9 rows per task per kind). The new key collapses
        # them to ONE row.
        #
        # Why second-precision: it collapses the celery-events fan-out
        # (several agents / two brain replicas reporting one broker event
        # within sub-seconds) to a single row. A genuine retry produces
        # occurred_at values seconds apart and gets a distinct id.
        # Heartbeats / agent_status frames have no task_id and stay on the
        # legacy agent-id key so per-agent freshness is preserved.
        #
        # ACCEPTED-TRADEOFF (Codex round-2 Finding 3, documented not fixed):
        # second-precision conflates two identities -- "logical event" and
        # "fan-out duplicate" -- so it has two residual failure modes:
        #   (a) two GENUINELY distinct same-(task,kind) events inside one
        #       wall-clock second collapse to one row (a low-rate silent
        #       drop, and a censorship vector if co-timed);
        #   (b) a reconnect replay whose occurred_at jitters ACROSS a second
        #       boundary mints a distinct id -> re-inserts -> can re-fire
        #       automation (the per-rule circuit breaker is the backstop,
        #       not this dedupe).
        # SCOPED FOLLOW-UP: separate the two identities -- key event ROWS on
        # a stable agent-supplied event/attempt/run id, and suppress the
        # multi-agent broker fan-out with a SEPARATE (task,kind,window)
        # dedupe key -- so neither distinct events nor jittered replays are
        # mis-collapsed. Tracked for a post-1.7 ingestion revision.
        if task_id:
            occurred_at_int = int(occurred_at.timestamp())
            event_id = uuid5(
                _EVENT_ID_NAMESPACE,
                f"{project_id}:{task_id}:{kind.value}:{occurred_at_int}",
            )
        elif agent_event_id is None:
            event_id = uuid4()
            logger.warning(
                "z4j event_ingestor: agent omitted or sent invalid event id, "
                "minting one (events table dedupe will not work for replays)",
                project_id=str(project_id),
                agent_id=str(agent_id),
            )
        else:
            event_id = uuid5(
                _EVENT_ID_NAMESPACE,
                f"{project_id}:{agent_event_id}",
            )

        # The task-keyed event_id above is derived at SECOND precision, but
        # the events conflict key is (project_id, occurred_at, id). Store
        # occurred_at at that same granularity on this path so two
        # deliveries of one logical event that differ only in sub-seconds
        # (the celery-events fan-out where several agents report the same
        # broker event, or two brain replicas) collapse to a single row
        # instead of both inserting and firing automation twice. Non-task
        # events keep full precision on their agent-id key.
        stored_occurred_at = occurred_at.replace(microsecond=0) if task_id else occurred_at

        # 1) Append to the partitioned events table.
        inserted = await event_repo.insert(
            event_id=event_id,
            project_id=project_id,
            agent_id=agent_id,
            engine=engine,
            task_id=task_id,
            kind=kind.value,
            occurred_at=stored_occurred_at,
            payload=data if isinstance(data, dict) else {},
        )

        # (The ingest Prometheus counter is emitted at the END of this
        # method, gated on ``inserted``, so a transient failure in a LATER
        # propagating write -- the task projection upsert -- that rolls back
        # this event's per-event savepoint does not leave the counter
        # incremented for a row that was un-inserted and will be re-sent
        # (R8-L1 double-count).)

        # 2) Touch the queue if mentioned.
        # Defer the touch when a batch-level dedup set was supplied; the
        # caller (``ingest_batch``) flushes one touch per unique
        # ``(engine, queue)`` pair after the loop. Keeps the legacy
        # eager path for any caller that doesn't batch.
        queue_name = data.get("queue") if isinstance(data, dict) else None
        if isinstance(queue_name, str) and queue_name:
            if queues_seen is not None:
                queues_seen.add((engine, queue_name))
            else:
                try:
                    await queue_repo.touch(
                        project_id=project_id,
                        engine=engine,
                        name=queue_name,
                    )
                except Exception:
                    logger.exception("z4j event_ingestor: queue touch failed")

        # 3) Record the worker into the batch-level accumulator.
        # The bulk upsert runs once after the whole batch is in;
        # see :meth:`ingest_batch`. Picking max occurred_at means
        # a stale event arriving late in the batch can't roll
        # the worker's heartbeat backwards.
        worker_name = data.get("worker") if isinstance(data, dict) else None
        if isinstance(worker_name, str) and worker_name:
            key = (engine, worker_name)
            previous = worker_seen.get(key)
            if previous is None or occurred_at > previous:
                worker_seen[key] = occurred_at

        # 4) Project onto tasks (only for a task-shaped event we ACTUALLY
        # inserted). A duplicate (inserted=False -- a reconnect replay or a
        # celery-events fan-out delivering the same logical event again) was
        # already projected atomically on its first delivery; re-projecting it
        # re-applies the kind-specific fields (finished_at / exception /
        # traceback / fingerprint), which are written UNCONDITIONALLY while
        # only the state column is monotonic-guarded, so a replay of an OLD
        # failure after a NEWER one would rewind those fields to the stale
        # value (R8-M3). Skipping re-projection for duplicates fixes that;
        # ``inserted`` and ``occurred_at`` are still returned unchanged so the
        # batch heartbeat / durability accounting is unaffected.
        if inserted and task_id and kind != EventKind.UNKNOWN:
            task_data = data if isinstance(data, dict) else {}
            if kind == EventKind.TASK_FAILED:
                # Stamp the SAME fingerprint the task row stores onto the
                # raw event, so the automation path (frame_router
                # ._fingerprint_of, reading raw_event["data"]) matches the
                # value the Issues view shows instead of recomputing from
                # the raw, un-scrubbed, un-truncated data. Both call sites
                # use fingerprint_from_data on the identical scrubbed
                # ``data`` object, so shown == matched.
                from z4j_brain.domain.fingerprint import (
                    fingerprint_from_data,
                )

                event_data = raw_event.get("data")
                if isinstance(event_data, dict):
                    event_data["fingerprint"] = fingerprint_from_data(task_data)
            await self._project_task(
                project_id=project_id,
                engine=engine,
                task_id=task_id,
                kind=kind,
                occurred_at=occurred_at,
                data=task_data,
                task_repo=task_repo,
                inserted=inserted,
                pending_metrics=pending_metrics,
            )

        # 5b) Snapshot reconciliation. The agent emits
        # ``schedule.snapshot`` at boot, on its periodic timer, and on
        # demand from a ``schedule.resync`` command. The data carries
        # the full inventory of every schedule its scheduler adapter
        # observes, we 3-way diff against the DB (insert / update /
        # delete-missing) scoped to (project, scheduler). Added in
        # 1.3.3 to close the gap where existing celery-beat /
        # rq-scheduler / apscheduler schedules were invisible until
        # they were edited (signal-based only).
        # Gated on ``inserted`` (R8-M3): a dedup'd duplicate snapshot already
        # reconciled on its first delivery; re-running a STALE snapshot would
        # 3-way-diff-delete a schedule that a newer snapshot added (replay of
        # [A] after [A,B] deletes B). A genuinely-needed re-reconcile still
        # lands via the next periodic snapshot (distinct event_id, inserted).
        if inserted and kind_value == EventKind.SCHEDULE_SNAPSHOT.value:
            schedules_in = data.get("schedules") if isinstance(data, dict) else None
            scheduler_name = (
                str(data.get("scheduler") or engine) if isinstance(data, dict) else engine
            )
            if isinstance(schedules_in, list):
                try:
                    from z4j_brain.persistence.repositories import (
                        ScheduleRepository,
                    )

                    schedule_repo = ScheduleRepository(task_repo.session)
                    # Own savepoint (R8-H3): a TRANSIENT error here (deadlock /
                    # lock timeout) must roll back ONLY this best-effort
                    # reconcile, not leave the per-event savepoint aborted so
                    # its RELEASE surfaces a permanent-looking 25P02 that
                    # drops-and-acks the whole event.
                    async with task_repo.session.begin_nested():
                        summary = await schedule_repo.reconcile_snapshot(
                            project_id=project_id,
                            scheduler=scheduler_name,
                            schedules=schedules_in,
                        )
                    logger.info(
                        "z4j event_ingestor: schedule snapshot reconciled",
                        project_id=str(project_id),
                        scheduler=scheduler_name,
                        reason=str(data.get("reason", "unknown"))
                        if isinstance(data, dict)
                        else "unknown",
                        inserted=summary["inserted"],
                        updated=summary["updated"],
                        deleted=summary["deleted"],
                    )
                except Exception:
                    logger.exception(
                        "z4j event_ingestor: schedule snapshot reconcile failed",
                        scheduler=scheduler_name,
                    )

        # 5) Project schedule events onto the schedules table. Gated on
        # ``inserted`` (R8-M3): a dedup'd duplicate already upserted on its
        # first delivery, so re-applying it is at best a no-op and at worst
        # rewinds a schedule row to a stale snapshot.
        if inserted and kind_value in (
            EventKind.SCHEDULE_CREATED.value,
            EventKind.SCHEDULE_UPDATED.value,
        ):
            schedule_data = data.get("schedule") if isinstance(data, dict) else None
            if isinstance(schedule_data, dict):
                try:
                    from z4j_brain.persistence.repositories import (
                        ScheduleRepository,
                    )

                    # Inject the engine + scheduler names from the
                    # outer Event envelope - the inner schedule
                    # payload doesn't carry them (and if it did, the
                    # repo was silently defaulting to "celery" /
                    # "celery-beat" - LATENT-1). Each scheduler
                    # adapter now reports its own name as
                    # ``Event.engine`` so rq-scheduler / apscheduler
                    # will land correctly once they ship.
                    enriched = dict(schedule_data)
                    enriched.setdefault("engine", engine)
                    enriched.setdefault("scheduler", engine)

                    schedule_repo = ScheduleRepository(task_repo.session)
                    # Own savepoint (R8-H3): a transient error here must not
                    # abort the per-event savepoint and surface as a
                    # permanent-looking 25P02 that drops-and-acks the event.
                    async with task_repo.session.begin_nested():
                        await schedule_repo.upsert_from_event(
                            project_id=project_id,
                            data=enriched,
                        )
                except Exception:
                    logger.exception(
                        "z4j event_ingestor: schedule upsert failed",
                    )

        # Prometheus ingest counter, gated on a NEW row. The label set resolves
        # eagerly here (after event_repo.insert AND the task-projection upsert,
        # the only un-swallowed propagating writes), but the ``.inc()`` is
        # DEFERRED into ``pending_metrics`` and emitted by the caller only after
        # the OUTER commit succeeds -- so a transient rollback + re-send does
        # not double-count a row that never persisted (R6-F3 gated on
        # ``inserted``; R8-L1 ordered it last; round-9 defers it past commit).
        # Best-effort: a metric-registry hiccup must not break ingestion.
        if inserted and pending_metrics is not None:
            try:
                from z4j_brain.api.metrics import z4j_events_ingested_total

                _counter = z4j_events_ingested_total.labels(
                    project=str(project_id),
                    engine=engine,
                    kind=kind_value,
                )
                pending_metrics.append(_counter.inc)
            except Exception:
                from z4j_brain.api.metrics import record_swallowed

                record_swallowed("event_ingestor", "counter_inc")

        return (inserted, occurred_at)

    async def _project_task(  # noqa: PLR0912, PLR0915  task projection pipeline
        self,
        *,
        project_id: UUID,
        engine: str,
        task_id: str,
        kind: EventKind,
        occurred_at: datetime,
        data: dict[str, Any],
        task_repo: TaskRepository,
        inserted: bool = True,
        pending_metrics: list[Callable[[], None]] | None = None,
    ) -> None:
        """Apply per-event-kind updates to the ``tasks`` row.

        ``inserted`` is False when this event was a duplicate (already in
        the partitioned events table). The state upsert still runs (it is
        idempotent, and the monotonic guard keeps it safe), but the
        Prometheus task counters are gated on ``inserted`` so a re-
        delivered terminal event -- e.g. a withheld-ack batch re-sent
        after a transient skip, whose committed events dedup on replay --
        does not double-count task throughput (R7-LOW, same rule as the
        ingest counter's R6-F3 gate).
        """
        # Resolve priority from event data. The agent includes it
        # if the task has ``@z4j_meta(priority="critical")`` etc.
        # Default to NORMAL for tasks without explicit priority.
        priority_raw = data.get("priority")
        try:
            priority = TaskPriority(priority_raw) if priority_raw else TaskPriority.NORMAL
        except ValueError:
            priority = TaskPriority.NORMAL

        # Monotonic-timestamp guard against state regression
        # (external-audit Medium #6). Events can legitimately
        # arrive out of order - a late ``task.started`` after
        # ``task.succeeded`` must NOT move a finished task back
        # to STARTED. We look up the current row's latest
        # lifecycle timestamp; if the incoming event is older,
        # we skip the state transition (other fields like
        # ``worker_name`` / ``exception`` can still be
        # back-filled because they're informational, not
        # lifecycle-bearing).
        existing_task = await task_repo.get_by_engine_task_id(
            project_id=project_id,
            engine=engine,
            task_id=task_id,
        )
        existing_latest = _task_latest_lifecycle_at(existing_task)

        defaults: dict[str, Any] = {
            "name": str(data.get("task_name") or "unknown"),
            "queue": (str(data.get("queue")) if data.get("queue") else None),
            "state": TaskState.PENDING,
            "priority": priority,
        }
        updates: dict[str, Any] = {}

        new_state = _STATE_FOR_KIND.get(kind)
        if new_state is not None:
            # Audit F-3 (1.5): the monotonic-timestamp guard was
            # designed to prevent a late ``task.started`` from
            # rewinding a finished ``task.succeeded``. But it also
            # dropped legitimate terminal events that arrived with
            # an earlier ``occurred_at`` than a non-terminal event
            # already in the row - common during reconnect-replay
            # bursts where the agent's buffer drains in non-strict
            # chronological order, and also when Celery's broker-
            # events monitor reports a child-process-emitted
            # ``task.started`` AFTER signals.task_postrun has
            # already emitted ``task.succeeded`` from the parent
            # (broker latency >> signal handler latency).
            #
            # Refined rule: terminal states (SUCCESS, FAILURE,
            # REVOKED) ALWAYS win over non-terminal states (PENDING,
            # RECEIVED, STARTED, RETRY) regardless of timestamp
            # ordering. Within the terminal set, the timestamp
            # ordering still applies (so a stale .succeeded does
            # not overwrite a fresher .failed and vice versa).
            # Within the non-terminal set, the timestamp ordering
            # also still applies (a stale .started does not
            # overwrite a fresher .received).
            current_state = existing_task.state if existing_task else None
            current_terminal = current_state in _TERMINAL_TASK_STATES
            new_terminal = new_state in _TERMINAL_TASK_STATES
            if new_terminal and not current_terminal:
                # Promote to terminal regardless of timestamp - the
                # task is provably done; non-terminal can't argue.
                updates["state"] = new_state
            elif not new_terminal and current_terminal:
                # Never demote terminal back to non-terminal.
                logger.debug(
                    "z4j event_ingestor: refusing to demote terminal state with non-terminal event",
                    project_id=str(project_id),
                    task_id=task_id,
                    event_kind=kind.value,
                    current_state=current_state.value if current_state else None,
                )
            elif existing_latest is not None and occurred_at < existing_latest:
                # Same-tier transition (terminal->terminal or
                # non-terminal->non-terminal): keep timestamp
                # monotonicity. Stale event for the same tier is
                # dropped.
                logger.info(
                    "z4j event_ingestor: dropping out-of-order state transition",
                    project_id=str(project_id),
                    task_id=task_id,
                    event_kind=kind.value,
                    event_at=occurred_at.isoformat(),
                    existing_latest=existing_latest.isoformat(),
                )
            else:
                updates["state"] = new_state

        # Only update priority if explicitly set in the event (don't
        # downgrade a previously-set priority with a default NORMAL
        # from a later event that happens to not carry the field).
        if priority_raw:
            updates["priority"] = priority

        if kind == EventKind.TASK_RECEIVED:
            updates.update(
                {
                    "received_at": occurred_at,
                    "args": data.get("args"),
                    "kwargs": data.get("kwargs"),
                    "queue": (str(data.get("queue")) if data.get("queue") else None),
                    "name": str(data.get("task_name") or "unknown"),
                }
            )
            # Canvas linkage from Celery's request: ``parent_task_id``
            # is the task that called ``apply_async`` for me;
            # ``root_task_id`` is the original entry point of the
            # chain / group / chord. Persist them so the dashboard
            # can render the dependency tree on the task detail
            # page.
            #
            # Defense against cross-project linkage poisoning: a
            # compromised Project-A agent could otherwise emit a
            # ``task-received`` event with ``parent_task_id``
            # pointing at a known Project-B task id. Reads via
            # ``get_tree`` are project-scoped today, so this would
            # not leak data - but any future query that joins on
            # ``parent_task_id`` without re-applying ``project_id``
            # would mix tenants. We refuse to store a parent /
            # root that already exists under a *different* project;
            # references that don't exist at all are stored as-is
            # to preserve the legitimate out-of-order ingest case
            # (child event arriving before parent).
            parent_task_id = data.get("parent_task_id")
            root_task_id = data.get("root_task_id")
            if parent_task_id:
                clean = await self._sanitize_canvas_ref(
                    project_id=project_id,
                    engine=engine,
                    task_id=task_id,
                    candidate=str(parent_task_id),
                    field="parent_task_id",
                    task_repo=task_repo,
                )
                if clean is not None:
                    updates["parent_task_id"] = clean
            if root_task_id:
                clean = await self._sanitize_canvas_ref(
                    project_id=project_id,
                    engine=engine,
                    task_id=task_id,
                    candidate=str(root_task_id),
                    field="root_task_id",
                    task_repo=task_repo,
                )
                if clean is not None:
                    updates["root_task_id"] = clean
        elif kind == EventKind.TASK_STARTED:
            updates.update(
                {
                    "started_at": occurred_at,
                    "worker_name": (str(data.get("worker")) if data.get("worker") else None),
                }
            )
        elif kind == EventKind.TASK_SUCCEEDED:
            updates.update(
                {
                    "finished_at": occurred_at,
                    "result": data.get("result"),
                    "runtime_ms": _coerce_int(data.get("runtime_ms")),
                    "exception": None,
                    "traceback": None,
                }
            )
        elif kind == EventKind.TASK_FAILED:
            from z4j_brain.domain.fingerprint import fingerprint_from_data

            updates.update(
                {
                    "finished_at": occurred_at,
                    # Failure "seen" time for the Issues view. Kept across a
                    # later recovery (TASK_SUCCEEDED overwrites finished_at
                    # but NOT this), so the issue window tracks failure time,
                    # not recovery time.
                    "last_failed_at": occurred_at,
                    "exception": _coerce_str(data.get("exception")),
                    "traceback": _coerce_str(data.get("traceback")),
                    # R4 fingerprint from the FULL scrubbed exception +
                    # traceback (``fingerprint_from_data``), set on failure
                    # and kept across a later recovery (TASK_SUCCEEDED does
                    # not clear it) so the Issues view can show recovered
                    # issues. ``_ingest_one`` stamps the SAME value onto the
                    # raw event so the automation path matches what is
                    # stored here.
                    "fingerprint": fingerprint_from_data(data),
                }
            )
        elif kind == EventKind.TASK_RETRIED:
            updates.update(
                {
                    "retry_count": _coerce_int(data.get("retry_count"), default=0) or 0,
                }
            )
        elif kind == EventKind.TASK_REVOKED:
            updates.update(
                {
                    "finished_at": occurred_at,
                }
            )

        # Pass the
        # ``existing_task`` we already loaded above so
        # ``upsert_from_event`` skips its own redundant SELECT.
        await task_repo.upsert_from_event(
            project_id=project_id,
            engine=engine,
            task_id=task_id,
            defaults=defaults,
            updates=updates,
            existing=existing_task,
            existing_loaded=True,
        )

        # Prometheus task metrics for terminal states, emitted AFTER the
        # upsert so a transient upsert failure that rolls back this event's
        # per-event savepoint does not leave the counter incremented for a
        # projection that did not persist and will be re-sent (R8-L1).
        #
        # v1.6 Round 3 Crit-1: task_name is an attacker-controlled string
        # from the agent. Without a cap a malicious agent can emit unbounded
        # distinct task_names; each new name creates a fresh Prometheus series
        # and the brain's RSS grows linearly until OOM. Defence: (a) truncate
        # to ``_METRIC_TASK_NAME_MAX_LEN`` chars, (b) bound the per-project set
        # of distinct names accepted into the labels; overflow folds into the
        # literal sentinel ``_METRIC_TASK_NAME_OVERFLOW``. The audit / task
        # tables still record the original task_name in full.
        #
        # ``inserted`` is always True here post-R8-M3 (a duplicate is not
        # projected), but the gate is kept defensively: a re-delivered
        # terminal event must never re-count task throughput (R7-LOW).
        if inserted and pending_metrics is not None:
            try:
                from z4j_brain.api.metrics import (
                    z4j_task_duration_seconds,
                    z4j_tasks_total,
                )

                raw_task_name = str(data.get("task_name") or "unknown")
                # Resolve the (capped) label set EAGERLY; DEFER only the
                # .inc()/.observe() into pending_metrics so a transient rollback
                # + re-send does not double-count (round-9 external LOW).
                task_name = _safe_metric_task_name(project_id, raw_task_name)
                if kind in (
                    EventKind.TASK_SUCCEEDED,
                    EventKind.TASK_FAILED,
                    EventKind.TASK_REVOKED,
                ):
                    _total = z4j_tasks_total.labels(
                        project=str(project_id),
                        task_name=task_name,
                        state=kind.value,
                    )
                    pending_metrics.append(_total.inc)
                if kind == EventKind.TASK_SUCCEEDED:
                    runtime_ms = _coerce_int(data.get("runtime_ms"))
                    if runtime_ms is not None and runtime_ms > 0:
                        _hist = z4j_task_duration_seconds.labels(
                            project=str(project_id),
                            task_name=task_name,
                        )
                        _seconds = runtime_ms / 1000.0
                        pending_metrics.append(lambda h=_hist, s=_seconds: h.observe(s))
            except Exception:
                # Metric write failed; event ingestion must not block.
                from z4j_brain.api.metrics import record_swallowed

                record_swallowed("event_ingestor", "task_metrics")

    async def _sanitize_canvas_ref(
        self,
        *,
        project_id: UUID,
        engine: str,
        task_id: str,
        candidate: str,
        field: str,
        task_repo: TaskRepository,
    ) -> str | None:
        """Validate a parent / root task-id reference before persisting.

        Refuses references that are structurally implausible
        (oversize, self-loop) and references that already belong
        to a *different* project (cross-project linkage poisoning
        - see caller for context). Returns the cleaned value or
        ``None`` to indicate "drop this field from the update".
        """
        # Structural floor: empty string already filtered by caller.
        # Reject oversize values that would silently truncate
        # against the column's String(200), and self-loops.
        if len(candidate) > 200 or "\x00" in candidate:
            logger.warning(
                "z4j event_ingestor: dropped malformed canvas reference",
                project_id=str(project_id),
                field=field,
            )
            return None
        if candidate == task_id:
            return None  # self-loop; meaningless
        try:
            # Own savepoint (R8-H3): a transient error on this read-only
            # lookup must roll back only itself, not abort the per-event
            # savepoint so its RELEASE surfaces a permanent-looking 25P02
            # that drops-and-acks the whole event.
            async with task_repo.session.begin_nested():
                elsewhere = await task_repo.other_project_owns(
                    project_id=project_id,
                    engine=engine,
                    task_id=candidate,
                )
        except Exception:
            # If the lookup fails for any reason, fall back to
            # storing as-is - we'd rather keep the linkage than
            # silently drop it because of a transient DB hiccup.
            return candidate
        if elsewhere:
            # The (engine, task_id) is unambiguously owned by
            # another project (no row exists in the caller's
            # project). This is the cross-project linkage
            # poisoning case we block. Two projects legitimately
            # sharing a task_id produce ``elsewhere=False`` and
            # the reference is kept - external-audit Medium #5
            # fix for false "cross-project" drops.
            logger.warning(
                "z4j event_ingestor: dropped cross-project canvas reference",
                project_id=str(project_id),
                field=field,
            )
            return None
        return candidate


def _task_latest_lifecycle_at(task: Any) -> datetime | None:
    """Return the newest lifecycle timestamp on a task row, or None.

    Used by the state-projection monotonic guard - a state
    transition whose ``occurred_at`` predates this value is a
    late / out-of-order event and must not regress the state
    column. We look at ``finished_at`` → ``started_at`` →
    ``received_at`` in that order (most recent lifecycle stage
    wins). Returns None when the task row doesn't exist yet.

    **Defence in depth:** even though the ingest path clamps
    incoming ``occurred_at`` to ``now + 60s``, an older row may
    still carry a timestamp from before the clamp was tightened.
    We apply ``min(ts, now)`` here so the guard can never "pin"
    a task's state by comparing against a future timestamp baked
    into its lifecycle columns.
    """
    if task is None:
        return None
    now = datetime.now(UTC)
    candidates = [
        getattr(task, "finished_at", None),
        getattr(task, "started_at", None),
        getattr(task, "received_at", None),
    ]
    newest: datetime | None = None
    for ts in candidates:
        if ts is None:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)  # noqa: PLW2901  normalized in-loop
        # Clamp future-dated lifecycle timestamps - a legacy row
        # (pre-R5) may have future stamps that would otherwise
        # freeze the state column against any legitimate event.
        ts = min(ts, now)  # noqa: PLW2901  normalized in-loop
        if newest is None or ts > newest:
            newest = ts
    return newest


#: UUID variants we trust as agent-supplied event ids. v4 is the
#: random variant the current agent mints. v7 is the time-ordered
#: variant a future agent may switch to. Versions 1, 2, 3, 5, 8
#: either leak host information or are derived from an external
#: namespace and could collide deliberately if the namespace is
#: known. Nil / max are obviously not random and would let a
#: well-known id be used as a collision pin.
_TRUSTED_UUID_VERSIONS = frozenset({4, 7})


def _coerce_event_id(value: Any) -> UUID | None:
    """Best-effort UUID coercion for the agent-supplied event id.

    Accepts a UUID instance or a string that ``UUID()`` can parse,
    AND requires it to be a v4 or v7 UUID with non-zero / non-max
    integer value. Anything else returns ``None`` so the caller
    can fall back to minting a fresh id with a logged warning.

    Tightened in R3 (finding H2) - the previous version accepted
    nil UUIDs and arbitrary versions, letting an attacker pin
    collision attempts at well-known ids.
    """
    if value is None:
        return None
    if isinstance(value, UUID):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = UUID(value)
        except (ValueError, AttributeError):
            return None
    else:
        return None
    if parsed.int == 0 or parsed.int == (1 << 128) - 1:
        return None
    if parsed.version not in _TRUSTED_UUID_VERSIONS:
        return None
    return parsed


def _clamp_occurred_at(
    value: datetime,
    *,
    project_id: UUID,
    agent_id: UUID,
) -> datetime:
    """Clamp ``occurred_at`` to ``[now - 400d, now + 5min]``.

    Defends against:

    - **DoS via unpartitioned timestamp**: the
      partitioned events table only has partitions pre-created
      for a finite window. A timestamp outside that window
      raises ``no partition of relation "events" found`` on
      Postgres, blowing up the ingest. Clamping prevents this
      class of failure structurally.
    - **Dedupe-dodging via far-future ts**: an attacker picking a
      future ``occurred_at`` lands the row in a partition where
      no legitimate event will ever land - defeats the (limited)
      protection of the conflict key.

    Out-of-range values are clamped to ``now`` and a warning is
    logged so misbehaving agents are observable in Grafana.
    """
    now = datetime.now(UTC)
    if value < now - _OCCURRED_AT_PAST_LIMIT:
        logger.warning(
            "z4j event_ingestor: occurred_at clamped (too far in past)",
            project_id=str(project_id),
            agent_id=str(agent_id),
            received=value.isoformat(),
        )
        return now
    if value > now + _OCCURRED_AT_FUTURE_LIMIT:
        logger.warning(
            "z4j event_ingestor: occurred_at clamped (too far in future)",
            project_id=str(project_id),
            agent_id=str(agent_id),
            received=value.isoformat(),
        )
        return now
    return value


def _parse_datetime(value: Any) -> datetime:
    """Best-effort ISO-8601 → datetime, NORMALISED to UTC. Falls back to
    ``now()``.

    An aware value is CONVERTED to UTC (``astimezone``), not just accepted with
    its wire offset: downstream storage on a naive-offset dialect (SQLite's
    ``DateTime(timezone=True)`` round-trips to a naive LOCAL wall-clock, dropping
    the offset) would otherwise mis-represent a non-UTC ``occurred_at``, and the
    monotonic last_seen / last_heartbeat guards that re-stamp a naive readback as
    UTC would then compare against a shifted instant (external round-9
    re-review). A naive value keeps the wire contract "naive == UTC".
    """
    dt: datetime | None = None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            dt = None
    if dt is None:
        return datetime.now(UTC)
    # Normalise to UTC. ``astimezone`` can raise OverflowError on a boundary-year
    # value whose offset shift crosses datetime.min/max (e.g.
    # "0001-01-01T00:00:00+05:00" from a broken RTC / a min-datetime sentinel
    # serialised with a non-UTC offset). OverflowError is NOT a ValueError, so
    # an unguarded raise would ESCAPE this function BEFORE _clamp_occurred_at can
    # neutralise the garbage value -- regressing a recoverable (clamp-to-now)
    # event into a permanent drop (round-9 re-review). Fall back to now() (the
    # clamp's net result for an out-of-range value) on overflow.
    try:
        return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)
    except (OverflowError, OSError, ValueError):
        return datetime.now(UTC)


def _coerce_int(value: Any, *, default: int | None = None) -> int | None:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text[:8192]


__all__ = ["EventIngestor"]
