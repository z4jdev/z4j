"""``tasks`` repository."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.enums import TaskState
from z4j_brain.persistence.models import Task
from z4j_brain.persistence.repositories._base import BaseRepository


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

        R5 M2: the ``LIMIT 2`` implementation still false-dropped
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

        Round-7 audit fix R7-HIGH (perf) (Apr 2026): callers that
        have already loaded the row via ``get_by_engine_task_id``
        (e.g. ``EventIngestor._project_task`` for the
        out-of-order-state-transition guard) can pass it as
        ``existing`` + ``existing_loaded=True`` to skip a redundant
        SELECT. With the 1000-event frame cap this halves the
        SELECTs in the dominant write path (~3000 → ~1500 round
        trips for a saturated batch).
        """
        from sqlalchemy.exc import IntegrityError

        if not existing_loaded:
            existing = await self.get_by_engine_task_id(
                project_id=project_id, engine=engine, task_id=task_id,
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
            # batch (R4 follow-up caught this under concurrent
            # enterprise-stack load).
            try:
                async with self.session.begin_nested():
                    self.session.add(row)
                    await self.session.flush()
            except IntegrityError:
                existing = await self.get_by_engine_task_id(
                    project_id=project_id, engine=engine, task_id=task_id,
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
    ) -> bool:
        """Apply a reconciliation probe result to the task row.

        ``engine_state`` is one of ``"pending"`` / ``"started"`` /
        ``"success"`` / ``"failure"`` / ``"unknown"`` - the canonical
        set the brain expects from any adapter. ``"unknown"`` is a
        no-op (the adapter has no result-backend to consult).

        Returns ``True`` when the row was actually updated, ``False``
        when the brain's state already matches or the task isn't
        known to the brain. Idempotent: running twice produces the
        same final state.
        """
        if engine_state == "unknown":
            return False

        mapping = {
            "pending": TaskState.PENDING,
            "started": TaskState.STARTED,
            "success": TaskState.SUCCESS,
            "failure": TaskState.FAILURE,
        }
        new_state = mapping.get(engine_state)
        if new_state is None:
            return False

        existing = await self.get_by_engine_task_id(
            project_id=project_id, engine=engine, task_id=task_id,
        )
        if existing is None:
            return False
        if existing.state == new_state:
            # Already matches - skip the UPDATE so we don't churn the
            # ``updated_at`` timestamp and don't emit a meaningless
            # audit row.
            return False

        existing.state = new_state
        if finished_at is not None and existing.finished_at is None:
            existing.finished_at = finished_at
        if exception_text and not existing.exception:
            existing.exception = exception_text[:500]
        await self.session.flush()
        return True

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
        if priority:
            stmt = stmt.where(Task.priority.in_(priority))
        if name_substring:
            stmt = stmt.where(Task.name.contains(name_substring))
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
                    ),
                )
        stmt = stmt.order_by(
            Task.started_at.desc().nulls_last(),
            Task.id.desc(),
        ).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())


    async def get_priority_label(
        self, *, project_id: UUID, engine: str, task_id: str,
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
        stmt = (
            select(Task.task_id, Task.priority)
            .where(
                Task.project_id == project_id,
                Task.engine == engine,
                Task.task_id.in_(task_ids),
            )
        )
        result = await self.session.execute(stmt)
        out: dict[str, str] = {}
        for tid, p in result.all():
            label = _priority_label(p)
            if label is not None:
                out[tid] = label
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
            project_id=project_id, engine=engine, task_id=task_id,
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

        A "stuck" task is one whose ``started_at`` (or ``created_at``
        fallback) is older than ``stuck_before`` AND whose current
        state is not terminal. The ReconciliationWorker probes each
        of these via the agent's ``reconcile_task(task_id)`` to see
        whether the engine's result backend has a more recent state.

        Ordered by ``started_at ASC`` so the oldest stuck tasks are
        reconciled first.
        """
        from z4j_brain.persistence.enums import TaskState

        stmt = (
            select(Task)
            .where(
                Task.state.in_(
                    [TaskState.STARTED, TaskState.PENDING, TaskState.RETRY],
                ),
                Task.started_at.is_not(None),
                Task.started_at < stuck_before,
            )
            .order_by(Task.started_at.asc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())


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
