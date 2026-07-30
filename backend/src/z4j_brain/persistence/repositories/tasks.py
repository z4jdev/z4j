"""``tasks`` repository."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.enums import TERMINAL_TASK_STATES, TaskState
from z4j_brain.persistence.models import Task
from z4j_brain.persistence.repositories._base import BaseRepository

logger = structlog.get_logger("z4j.brain.repositories.tasks")


class TaskRepository(BaseRepository[Task]):
    """Task latest-state CRUD + filtered listing."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Task)

    async def get_by_engine_task_id(
        self,
        *,
        project_id: UUID,
        engine: str,
        task_id: str,
    ) -> Task | None:
        """Resolve a task by ``(project, engine, task_id)``."""
        result = await self.session.execute(
            select(Task).where(
                Task.project_id == project_id,
                Task.engine == engine,
                Task.task_id == task_id,
            ),
        )
        return result.scalar_one_or_none()

    async def other_project_owns(
        self,
        *,
        project_id: UUID,
        engine: str,
        task_id: str,
    ) -> bool:
        """True iff ``(engine, task_id)`` is owned SOLELY by a
        different project.

        Task uniqueness is ``(project_id, engine, task_id)`` - the
        same ``task_id`` can legitimately exist in multiple
        projects (Celery generates per-call UUIDs but two
        independent Celery clusters may produce equivalent ids,
        or a task may be migrated between projects). The earlier
        ``find_owner_project`` returned ``LIMIT 1`` and falsely
        tagged any such reuse as cross-project poisoning.

        The ``LIMIT 2`` implementation still false-dropped
        when 3+ projects share the task_id - Postgres could
        return any two "other" rows without the caller's, yielding
        a false positive. The cleanest fix is two targeted
        EXISTS probes: "does the caller's project have a row?"
        → if yes, keep the link (no need to probe further);
        "does any other project have one?" → only then drop.

        This helper only returns True when:
          * at least one row with this ``(engine, task_id)`` exists
            in SOME OTHER project
          * AND NO row with this ``(engine, task_id)`` exists in
            the caller's project
        """
        from sqlalchemy import exists as _exists

        # Probe 1: fast path - if the caller's project already has
        # a row, the reference is legitimately theirs, never drop.
        caller_has = await self.session.execute(
            select(
                _exists().where(
                    Task.engine == engine,
                    Task.task_id == task_id,
                    Task.project_id == project_id,
                ),
            ),
        )
        if caller_has.scalar_one():
            return False
        # Probe 2: does anyone else have a row? If yes, drop;
        # otherwise it's an unknown id (out-of-order parent), keep.
        anyone_else = await self.session.execute(
            select(
                _exists().where(
                    Task.engine == engine,
                    Task.task_id == task_id,
                    Task.project_id != project_id,
                ),
            ),
        )
        return bool(anyone_else.scalar_one())

    async def upsert_from_event(
        self,
        *,
        project_id: UUID,
        engine: str,
        task_id: str,
        defaults: dict[str, Any],
        updates: dict[str, Any],
        existing: Task | None = None,
        existing_loaded: bool = False,
    ) -> Task:
        """Insert-or-update a task row from an inbound event.

        ``defaults`` populate the row on insert; ``updates`` are
        applied on every event regardless and override defaults
        when a key appears in both. Single round-trip in the
        common case via SELECT-then-update - production data
        volumes do not justify a real upsert until B5.

        Callers that have already loaded the row via
        ``get_by_engine_task_id`` (e.g.
        ``EventIngestor._project_task`` for the
        out-of-order-state-transition guard) can pass it as
        ``existing`` + ``existing_loaded=True`` to skip a
        redundant SELECT. With the 1000-event frame cap this
        halves the SELECTs in the dominant write path (~3000 →
        ~1500 round trips for a saturated batch).
        """
        from sqlalchemy.exc import IntegrityError

        if not existing_loaded:
            existing = await self.get_by_engine_task_id(
                project_id=project_id,
                engine=engine,
                task_id=task_id,
            )
        if existing is None:
            merged: dict[str, Any] = {**defaults, **updates}
            row = Task(
                project_id=project_id,
                engine=engine,
                task_id=task_id,
                **merged,
            )
            # SAVEPOINT - two concurrent events for the same
            # ``(project, engine, task_id)`` race on the insert.
            # Without the savepoint, the loser's ``UniqueViolation``
            # poisons the outer transaction and cascades a
            # ``PendingRollbackError`` through the whole event
            # batch (follow-up caught this under concurrent
            # enterprise-stack load).
            try:
                async with self.session.begin_nested():
                    self.session.add(row)
                    await self.session.flush()
            except IntegrityError:
                existing = await self.get_by_engine_task_id(
                    project_id=project_id,
                    engine=engine,
                    task_id=task_id,
                )
                if existing is None:
                    raise  # genuinely couldn't insert or read back
            else:
                return row
        for key, value in updates.items():
            setattr(existing, key, value)
        await self.session.flush()
        return existing

    async def apply_reconciled_state(
        self,
        *,
        project_id: UUID,
        engine: str,
        task_id: str,
        engine_state: str,
        finished_at: datetime | None = None,
        exception_text: str | None = None,
        probe_issued_at: datetime | None = None,
    ) -> bool:
        """Apply a reconciliation probe result to the task row.

        ``engine_state`` is one of ``"pending"`` / ``"started"`` /
        ``"success"`` / ``"failure"`` / ``"unknown"`` - the canonical
        set the brain expects from any adapter. ``"unknown"`` is a
        no-op (the adapter has no result-backend to consult).

        Transition matrix. Reconciliation may only move a
        task OUT of a non-terminal state:

        - current TERMINAL (success / failure / revoked) → any:
          REJECTED. Terminal states are terminal. Pre-fix, a stale
          "pending" probe response regressed a SUCCESS row back to
          PENDING (``finished_at`` retained!), and the next success
          response then looked like a fresh terminal correction -
          firing ``task.orphaned`` a second time and letting an
          automation rule duplicate already-completed work.
        - current non-terminal → TERMINAL: applied (the probe found
          the engine's terminal truth; timestamps don't argue, same
          rule as the EventIngestor's out-of-order guard).
        - current non-terminal → non-terminal: applied only when the
          response is not stale - if the row was written after the
          probe was issued (``updated_at > probe_issued_at``) the
          brain has observed fresher information than the probe saw,
          so the response is dropped.
        - current == new: no-op (idempotent replay).

        The UPDATE itself is conditional and atomic: the terminal
        guard is re-checked in the WHERE clause so a concurrent
        writer (fresh event, duplicate probe response on another
        replica) cannot interleave between our read and our write.
        A lost race returns ``False`` exactly like a rejected
        transition.

        Returns ``True`` when the row was actually updated, ``False``
        when the transition was rejected, the brain's state already
        matches, or the task isn't known to the brain. The caller's
        apply-once contract (``task.orphaned`` fires at most once per
        correction, audit "correction" rows only on real changes)
        rests on this: a rejected or replayed response MUST return
        ``False``. Idempotent: running twice produces the same final
        state.
        """
        mapping = {
            "pending": TaskState.PENDING,
            "started": TaskState.STARTED,
            "success": TaskState.SUCCESS,
            "failure": TaskState.FAILURE,
        }
        new_state = mapping.get(engine_state)
        if new_state is None:
            # Covers ``"unknown"`` (no result backend to consult) and
            # any out-of-vocabulary string from a hostile agent.
            return False

        existing = await self.get_by_engine_task_id(
            project_id=project_id,
            engine=engine,
            task_id=task_id,
        )
        if existing is None:
            return False
        if existing.state == new_state:
            # Already matches - skip the UPDATE so we don't churn the
            # ``updated_at`` timestamp and don't emit a meaningless
            # audit row.
            return False
        if existing.state in TERMINAL_TASK_STATES:
            # Terminal is terminal. A late probe response can never
            # demote (or sideways-move) a finished task.
            logger.info(
                "z4j tasks: rejecting reconciliation of terminal task",
                project_id=str(project_id),
                task_id=task_id,
                current_state=existing.state.value,
                engine_state=engine_state,
            )
            return False
        if new_state not in TERMINAL_TASK_STATES and _observed_after(
            existing.updated_at,
            probe_issued_at,
        ):
            # Stale non-terminal response: the row was written after
            # the probe was issued, so the brain already holds fresher
            # information than the probe observed. Terminal responses
            # are exempt (terminal wins regardless of timestamps).
            logger.info(
                "z4j tasks: rejecting stale reconciliation response",
                project_id=str(project_id),
                task_id=task_id,
                current_state=existing.state.value,
                engine_state=engine_state,
            )
            return False

        values: dict[str, Any] = {"state": new_state}
        if finished_at is not None:
            # Keep the earliest observed finish - same semantics as
            # the pre- ``if existing.finished_at is None`` guard,
            # but race-safe inside the single UPDATE.
            values["finished_at"] = func.coalesce(Task.finished_at, finished_at)
        if exception_text:
            # Preserve a non-empty stored exception; fill it from the
            # probe otherwise (NULLIF folds legacy '' into NULL).
            values["exception"] = func.coalesce(
                func.nullif(Task.exception, ""),
                exception_text[:500],
            )

        # CONDITIONAL ATOMIC update: the WHERE clause
        # re-asserts the eligibility rules so two racing appliers (or
        # an applier racing a fresh terminal event) serialize on the
        # row - the loser matches zero rows and reports False, and the
        # ``task.orphaned`` apply-once semantics survive the race.
        conditions = [
            Task.project_id == project_id,
            Task.engine == engine,
            Task.task_id == task_id,
            Task.state.not_in(TERMINAL_TASK_STATES),
            Task.state != new_state,
        ]
        if new_state not in TERMINAL_TASK_STATES:
            # Optimistic snapshot guards (+ round-4 LOW
            # residual): the staleness check above ran against the
            # row we READ, but a fresh event can commit between that
            # read and this UPDATE. Two predicates close the gap:
            #
            # 1. STATE snapshot -- catches any state-changing gap
            #    write (round 4 reproduced a stale "pending"
            #    overwriting a fresh RETRY). A timestamp EQUALITY
            #    would false-negative on SQLite (string comparison,
            #    server-default second precision vs microsecond
            #    binds), so the enum is the equality token.
            # 2. ``updated_at <= probe_issued_at`` -- catches a gap
            #    write that refreshes freshness WITHOUT changing
            #    state (a duplicate TASK_STARTED advancing
            #    started_at; round-4's remaining LOW). The
            #    INEQUALITY form is dialect-safe where equality is
            #    not: ISO-8601 text ordering is chronological under
            #    SQLite's string comparison even across mixed
            #    precision, and Postgres compares timestamptz
            #    natively.
            #
            # Terminal responses stay exempt from both: terminal
            # wins regardless of timestamps.
            conditions.append(Task.state == existing.state)
            if probe_issued_at is not None:
                conditions.append(Task.updated_at <= probe_issued_at)
        result = await self.session.execute(
            update(Task)
            .where(*conditions)
            .values(**values)
            .execution_options(synchronize_session=False),
        )
        # The in-session instance is stale after the core UPDATE;
        # expire it so any later read in this transaction (e.g. the
        # orphaned-automation field build) refetches fresh values.
        self.session.expire(existing)
        return bool(result.rowcount or 0)

    async def list_for_project(
        self,
        *,
        project_id: UUID,
        state: TaskState | None = None,
        priority: list[Any] | None = None,
        name_substring: str | None = None,
        search_query: str | None = None,
        queue: str | None = None,
        worker: str | None = None,
        engine: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        cursor: tuple[Any, UUID] | None = None,
        limit: int = 50,
    ) -> list[Task]:
        """Filtered + cursor-paginated task list.

        Cursor is a ``(started_at, id)`` pair from
        :func:`encode_cursor`. The query orders by
        ``started_at DESC, id DESC`` so newest tasks come first.

        New Phase A filters:
        - ``priority`` - list of TaskPriority values (multi-select)
        - ``search_query`` - substring search across name (uses
          ILIKE for case-insensitive match; the GIN index covers
          the Postgres full-text path for a future upgrade)
        - ``worker`` - exact match on worker_name
        - ``until`` - upper bound on received_at
        """
        stmt = select(Task).where(Task.project_id == project_id)
        if state is not None:
            stmt = stmt.where(Task.state == state)
        if engine is not None:
            # RH4: the engine predicate MUST be in the SQL WHERE so the row
            # ``limit`` applies to the already-engine-scoped set. Filtering by
            # engine in Python AFTER the limit lets other-engine rows consume the
            # cap and silently drops owned target-engine rows past the window.
            stmt = stmt.where(Task.engine == engine)
        if priority:
            stmt = stmt.where(Task.priority.in_(priority))
        if name_substring:
            # M3: escape LIKE metacharacters so a literal '%' or '_' in the
            # operator's selection filter matches literally. contains() defaults
            # to autoescape=False, which would let name='billing%refund'
            # over-match 'billingXrefund' and widen a bulk-retry beyond the
            # operator's intended set (retrying tasks they meant to exclude).
            stmt = stmt.where(Task.name.contains(name_substring, autoescape=True))
        if search_query:
            like_pattern = f"%{search_query}%"
            stmt = stmt.where(
                or_(
                    Task.name.ilike(like_pattern),
                    Task.queue.ilike(like_pattern),
                    Task.worker_name.ilike(like_pattern),
                    Task.task_id.ilike(like_pattern),
                ),
            )
        if queue:
            stmt = stmt.where(Task.queue == queue)
        if worker:
            stmt = stmt.where(Task.worker_name == worker)
        if since is not None:
            stmt = stmt.where(Task.received_at >= since)
        if until is not None:
            stmt = stmt.where(Task.received_at <= until)
        if cursor is not None:
            sort_value, tiebreaker = cursor
            if sort_value is None:
                stmt = stmt.where(
                    or_(
                        Task.started_at.is_(None) & (Task.id < tiebreaker),
                    ),
                )
            else:
                stmt = stmt.where(
                    or_(
                        Task.started_at < sort_value,
                        and_(
                            Task.started_at == sort_value,
                            Task.id < tiebreaker,
                        ),
                        # B12: NULL-started (pending/queued) tasks sort AFTER
                        # every non-null row under ``NULLS LAST``, so they must
                        # remain eligible while the cursor is still on a
                        # non-null row. Without this disjunct ``started_at <
                        # sort_value`` is NULL for them (SQL three-valued
                        # logic), so once page 1 filled with non-null rows the
                        # continuation never reached the NULL section and every
                        # pending task was permanently invisible.
                        Task.started_at.is_(None),
                    ),
                )
        stmt = stmt.order_by(
            Task.started_at.desc().nulls_last(),
            Task.id.desc(),
        ).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_priority_label(
        self,
        *,
        project_id: UUID,
        engine: str,
        task_id: str,
    ) -> str | None:
        """Return the user-facing priority label for one task.

        Used by the retry / bulk-retry command path so the agent
        can preserve the original priority on the re-enqueue
        instead of silently demoting high-priority work to the
        broker default. Returns ``None`` when the task isn't
        known to the brain (out-of-band tasks the agent has not
        yet seen) - the agent then falls back to broker default.
        """
        stmt = (
            select(Task.priority)
            .where(
                Task.project_id == project_id,
                Task.engine == engine,
                Task.task_id == task_id,
            )
            .limit(1)
        )
        result = await self.session.execute(stmt)
        value = result.scalar_one_or_none()
        return _priority_label(value)

    async def get_priorities_for_ids(
        self,
        *,
        project_id: UUID,
        engine: str,
        task_ids: list[str],
    ) -> dict[str, str]:
        """Bulk-retry companion: ``{task_id: priority_label}`` for the input set."""
        if not task_ids:
            return {}
        stmt = select(Task.task_id, Task.priority).where(
            Task.project_id == project_id,
            Task.engine == engine,
            Task.task_id.in_(task_ids),
        )
        result = await self.session.execute(stmt)
        out: dict[str, str] = {}
        for tid, p in result.all():
            label = _priority_label(p)
            if label is not None:
                out[tid] = label
        return out

    async def list_by_engine_task_ids(
        self,
        *,
        project_id: UUID,
        engine: str,
        task_ids: list[str],
    ) -> list[Task]:
        """Return the exact owned rows in caller order.

        Boundary B seals names/priorities into its plan from production Task
        rows.  Missing ids are omitted so the caller can fail the entire
        destructive request instead of silently narrowing it.
        """
        if not task_ids:
            return []
        result = await self.session.execute(
            select(Task).where(
                Task.project_id == project_id,
                Task.engine == engine,
                Task.task_id.in_(task_ids),
            )
        )
        by_id = {str(task.task_id): task for task in result.scalars().all()}
        return [by_id[task_id] for task_id in task_ids if task_id in by_id]

    async def get_names_for_ids(
        self,
        *,
        project_id: UUID,
        engine: str,
        task_ids: list[str],
    ) -> dict[str, str]:
        """Bulk-retry companion: ``{task_id: task_name}`` for the input set.

        The RQ adapter's bulk retry path
        requires per-task ``task_name`` so it can call
        ``queue.enqueue_call(func=task_name, ...)`` without reading
        ``job.func_name`` (which triggers pickle deserialization of
        attacker-controlled bytes inside the agent). Ids that don't
        resolve to a Task row are omitted; the agent-side action then
        refuses the whole batch with ``missing_task_names`` listing
        the affected ids.
        """
        if not task_ids:
            return {}
        stmt = select(Task.task_id, Task.name).where(
            Task.project_id == project_id,
            Task.engine == engine,
            Task.task_id.in_(task_ids),
        )
        result = await self.session.execute(stmt)
        out: dict[str, str] = {}
        for tid, n in result.all():
            if n:
                out[str(tid)] = str(n)
        return out

    async def get_tree(
        self,
        *,
        project_id: UUID,
        engine: str,
        task_id: str,
        max_nodes: int = 500,
    ) -> tuple[list[Task], str | None, bool]:
        """Return every task in the canvas tree containing ``task_id``.

        The tree is identified by ``root_task_id``: every task that
        Celery spawned from the same chain / group / chord shares a
        root. We resolve the root by looking up the requested task
        first - that's either ``task.root_task_id`` (children) or
        ``task.task_id`` (the root itself or a non-canvas standalone
        task that is its own root).

        Returns ``(tasks, root_id, truncated)``. ``tasks`` may be
        empty if the requested task isn't known to the brain.
        ``max_nodes`` caps the result so a runaway chain (or a
        malicious craft with a bogus ``root_task_id`` pointing at
        something with millions of siblings) cannot return an
        unbounded blob. We fetch ``max_nodes + 1`` so we can
        distinguish "exactly at the cap" from "actually truncated"
        instead of returning a misleading ``truncated=true`` for a
        chain that happens to have exactly ``max_nodes`` rows.
        """
        anchor = await self.get_by_engine_task_id(
            project_id=project_id,
            engine=engine,
            task_id=task_id,
        )
        if anchor is None:
            return [], None, False
        root_id = anchor.root_task_id or anchor.task_id

        stmt = (
            select(Task)
            .where(
                Task.project_id == project_id,
                Task.engine == engine,
                # Either the row IS the root OR it's a child whose
                # ``root_task_id`` points at the root. ``OR`` rather
                # than two queries; both legs are index-friendly.
                or_(
                    Task.task_id == root_id,
                    Task.root_task_id == root_id,
                ),
            )
            .order_by(Task.received_at.asc().nulls_last(), Task.task_id)
            .limit(max_nodes + 1)
        )
        result = await self.session.execute(stmt)
        rows = list(result.scalars().all())
        truncated = len(rows) > max_nodes
        if truncated:
            rows = rows[:max_nodes]
        return rows, root_id, truncated

    async def list_stuck_for_reconciliation(
        self,
        *,
        stuck_before: datetime,
        limit: int = 100,
    ) -> list[Task]:
        """Return tasks likely-stuck in ``pending`` or ``started``.

        A "stuck" task is one whose age anchor is older than
        ``stuck_before`` AND whose current state is not terminal. The
        age anchor is ``COALESCE(started_at, received_at,
        created_at)`` - (a): the previous ``started_at IS NOT
        NULL`` filter silently excluded tasks that never started, so
        an old PENDING task whose start event was lost could sit
        un-reconciled forever. ``created_at`` is NOT NULL, so the
        chain always yields a value. The ReconciliationWorker probes
        each candidate via the agent's ``reconcile_task(task_id)`` to
        see whether the engine's result backend has a more recent
        state.

        Ordered by the age anchor ASC so the oldest stuck tasks are
        reconciled first.
        """
        from z4j_brain.persistence.enums import TaskState

        age_anchor = func.coalesce(
            Task.started_at,
            Task.received_at,
            Task.created_at,
        )
        stmt = (
            select(Task)
            .where(
                Task.state.in_(
                    [TaskState.STARTED, TaskState.PENDING, TaskState.RETRY],
                ),
                age_anchor < stuck_before,
            )
            .order_by(age_anchor.asc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())


def _observed_after(
    row_updated_at: datetime | None,
    probe_issued_at: datetime | None,
) -> bool:
    """True iff the task row was written AFTER the probe was issued.

    Staleness heuristic for ``apply_reconciled_state``: any write to
    the task row lands through the event ingestor or a previous
    reconciliation, so ``updated_at > probe_issued_at`` means the
    brain holds a fresher observation than the probe could have seen.

    Timestamps are normalized to aware-UTC before comparing because
    the two values may cross the SQLite / Postgres divide: SQLite's
    ``CURRENT_TIMESTAMP`` yields naive UTC while Postgres
    ``timestamptz`` yields aware datetimes, and comparing the two
    raises ``TypeError``. Missing either timestamp fails open (not
    stale) - the terminal-state guard is the hard backstop.
    """
    if row_updated_at is None or probe_issued_at is None:
        return False
    row = row_updated_at if row_updated_at.tzinfo else row_updated_at.replace(tzinfo=UTC)
    probe = probe_issued_at if probe_issued_at.tzinfo else probe_issued_at.replace(tzinfo=UTC)
    return row > probe


def _priority_label(value: object) -> str | None:
    """Coerce a stored priority into the lowercase label the agent expects.

    Handles three shapes of stored value defensively:

    - ``None`` → ``None``
    - SQLAlchemy ``TaskPriority`` enum → ``value.value`` (e.g. ``"high"``)
    - Bare string from a legacy row, possibly carrying the enum
      repr prefix (``"TaskPriority.HIGH"``) → strips the prefix
      and lowercases. Without this strip the agent would receive
      ``"taskpriority.high"`` and fail label resolution, silently
      demoting the retry to broker default.
    """
    if value is None:
        return None
    enum_value = getattr(value, "value", None)
    if isinstance(enum_value, str):
        return enum_value.lower() or None
    if isinstance(value, str):
        text = value.split(".", 1)[-1] if "." in value else value
        return text.lower() or None
    return None


__all__ = ["TaskRepository"]
