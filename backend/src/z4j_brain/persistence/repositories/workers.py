"""``workers`` repository."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.enums import WorkerState
from z4j_brain.persistence.models import Event, Worker
from z4j_brain.persistence.repositories._base import BaseRepository

#: Columns that vary between heartbeats and should be updated on
#: ON CONFLICT. ``id``, ``project_id``, ``engine``, ``name``,
#: ``created_at`` are immutable per row; everything else may change.
#: Names here are the Python ATTRIBUTE names (what callers pass in
#: ``r``); the upsert machinery below translates them to DB column
#: names via ``_ATTR_TO_COL`` for ``stmt.excluded`` and ``.values()``.
_UPSERT_VARIABLE_COLS = (
    "state",
    "last_heartbeat",
    "hostname",
    "pid",
    "concurrency",
    "queues",
    "load_average",
    "memory_bytes",
    "active_tasks",
    "worker_metadata",
)

#: Map Worker model attribute name -> actual DB column name. Almost
#: every column name matches its attribute, except
#: ``Worker.worker_metadata`` whose DB column is plain ``metadata``
#: (the attribute is prefixed only because ``metadata`` clashes with
#: SQLAlchemy's reserved ``Base.metadata``). The dialect-level
#: ``insert(Worker).values(...)`` and ``stmt.excluded.<col>`` paths
#: BOTH key off DB column names, so we translate before either
#: touches SQL. Bug fixed in 1.3.1: pre-1.3.1 the bulk-upsert path
#: passed the attribute name straight through, hitting
#: ``AttributeError: worker_metadata`` on every worker heartbeat.
_ATTR_TO_COL = {
    "worker_metadata": "metadata",
}


def _to_col(attr: str) -> str:
    """Return DB column name for a Worker attribute name."""
    return _ATTR_TO_COL.get(attr, attr)


#: Event kinds we count per worker. Source of truth is
#: ``z4j_core.models.event.EventKind`` - duplicated here as
#: literals because importing the enum into the brain repo would
#: create a brain → core dep that import-linter forbids in this
#: direction. A drift test in ``tests/unit/test_workers_repo.py``
#: catches any rename in either side.
_KIND_SUCCEEDED = "task.succeeded"
_KIND_FAILED = "task.failed"
_KIND_RETRIED = "task.retried"


class WorkerRepository(BaseRepository[Worker]):
    """Worker process state CRUD."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Worker)

    async def list_for_project(
        self,
        project_id: UUID,
        *,
        limit: int = 500,
    ) -> list[Worker]:
        """Workers for a project, freshest heartbeat first.

        Hard-capped at ``limit`` (default 500, max 5000) so a busy
        project with churning worker rows from autoscaling pods
        doesn't return tens of thousands of rows (audit P-7, added
        v1.0.14). AgentHygieneWorker normally sweeps stale rows but
        in environments where it's behind, the cap protects the
        response path.
        """
        if limit < 1 or limit > 5000:
            raise ValueError("limit must be between 1 and 5000")
        result = await self.session.execute(
            select(Worker)
            .where(Worker.project_id == project_id)
            .order_by(Worker.last_heartbeat.desc().nulls_last(), Worker.name)
            .limit(limit),
        )
        return list(result.scalars().all())

    async def upsert_from_event(
        self,
        *,
        project_id: UUID,
        engine: str,
        name: str,
        defaults: dict[str, Any] | None = None,
        updates: dict[str, Any],
    ) -> Worker:
        """Insert or update by ``(project, engine, name)``.

        Two concurrent events for the same ``(project, engine,
        name)`` race on the SELECT-then-INSERT window below. The
        INSERT wraps in a SAVEPOINT so a ``UniqueViolation``
        rollback is scoped to this one row - the outer transaction
        (which owns the events batch's other writes) survives.
        If the insert loses the race the caller re-reads the now-
        existing row and applies the updates (R4 follow-up: the
        enterprise stack exercised this path under concurrent
        load and caught a ``PendingRollbackError`` cascade).
        """
        from sqlalchemy.exc import IntegrityError

        result = await self.session.execute(
            select(Worker).where(
                Worker.project_id == project_id,
                Worker.engine == engine,
                Worker.name == name,
            ),
        )
        existing = result.scalar_one_or_none()
        if existing is None:
            row = Worker(
                project_id=project_id,
                engine=engine,
                name=name,
                state=(updates.get("state") or WorkerState.UNKNOWN),
                **(defaults or {}),
            )
            for key, value in updates.items():
                setattr(row, key, value)
            try:
                async with self.session.begin_nested():
                    self.session.add(row)
                    await self.session.flush()
            except IntegrityError:
                # Another concurrent event inserted first. Re-read
                # and fall through to the update branch.
                result = await self.session.execute(
                    select(Worker).where(
                        Worker.project_id == project_id,
                        Worker.engine == engine,
                        Worker.name == name,
                    ),
                )
                existing = result.scalar_one()
            else:
                return row
        for key, value in updates.items():
            setattr(existing, key, value)
        await self.session.flush()
        return existing

    async def upsert_from_events_bulk(
        self,
        rows: list[dict[str, Any]],
    ) -> int:
        """Bulk upsert N worker rows in one statement (v1.0.15 P-1).

        Each ``rows`` entry must include ``project_id``, ``engine``,
        ``name``; any of the columns in :data:`_UPSERT_VARIABLE_COLS`
        may be present. Missing columns are NOT touched on the
        conflict path - only keys actually present in the input
        propagate into the ``ON CONFLICT DO UPDATE`` set, so this
        method is safe to call with partial-update payloads (e.g. a
        heartbeat that only carries ``last_heartbeat`` + ``state``
        will not blank the previously-recorded ``concurrency`` /
        ``hostname``).

        On Postgres + SQLite (≥ 3.24) we emit one
        ``INSERT ... ON CONFLICT (project_id, engine, name) DO UPDATE``
        statement. On any other dialect we transparently fall back
        to the per-row :meth:`upsert_from_event` path so non-prod
        adapters keep working.

        Returns the number of input rows processed (not the number
        of new inserts; ``ON CONFLICT DO UPDATE`` does not surface
        that distinction to the client).

        Replaces the per-event N+1 round-trips in
        :meth:`EventIngestor.ingest_batch` and the per-hostname
        savepointed loop in :class:`WebSocketFrameRouter._handle_heartbeat`.
        """
        if not rows:
            return 0

        # Validate the contract early so a malformed caller fails
        # the whole batch instead of corrupting half of it.
        for r in rows:
            if "project_id" not in r or "engine" not in r or "name" not in r:
                raise ValueError(
                    "each row must include project_id, engine, name",
                )

        bind = await self.session.connection()
        dialect = bind.dialect.name

        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as _ins
        elif dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as _ins
        else:
            # Unknown dialect - fall back to the per-row safe path.
            # Preserves correctness on any future adapter we add.
            for r in rows:
                await self.upsert_from_event(
                    project_id=r["project_id"],
                    engine=r["engine"],
                    name=r["name"],
                    updates={
                        k: v for k, v in r.items()
                        if k in _UPSERT_VARIABLE_COLS
                    },
                )
            return len(rows)

        # Build the dense INSERT payload. ``id`` needs a Python-side
        # uuid because ``pg_insert(...).values(list_of_dicts)`` does
        # not honor SQLAlchemy ORM column defaults. ``state`` falls
        # back to UNKNOWN to satisfy NOT NULL on insert; on the
        # update path the caller's value (if any) wins.
        prepared: list[dict[str, Any]] = []
        present_update_cols: set[str] = set()
        for r in rows:
            row_payload: dict[str, Any] = {
                "id": uuid.uuid4(),
                "project_id": r["project_id"],
                "engine": r["engine"],
                "name": r["name"],
                "state": r.get("state", WorkerState.UNKNOWN),
            }
            # Pass-through optional columns so INSERT carries them
            # if this row is the first observation. Only keys we
            # whitelist propagate - extra junk gets dropped. Keys
            # stay as ATTRIBUTE names here because ``_ins(Worker)``
            # is mapper-aware: ``.values()`` resolves attribute names
            # to columns. In the ON CONFLICT branch below we DO
            # translate to DB column names because ``stmt.excluded``
            # and the ``set_=`` dict are NOT mapper-aware.
            for col in _UPSERT_VARIABLE_COLS:
                if col == "state":
                    continue
                if col in r:
                    row_payload[col] = r[col]
                    present_update_cols.add(col)
            # ``state`` is always present (we just defaulted it) but
            # we only want to OVERWRITE on conflict if the caller
            # supplied one - otherwise the existing online state
            # would get clobbered to UNKNOWN.
            if "state" in r:
                present_update_cols.add("state")
            prepared.append(row_payload)

        stmt = _ins(Worker).values(prepared)

        # Build ON CONFLICT DO UPDATE set_ from the union of columns
        # any input row carried. This preserves "no key, no touch"
        # semantics: a heartbeat carrying only ``last_heartbeat`` +
        # ``state`` will not write NULL into ``hostname``. Both the
        # set_= keys and ``stmt.excluded.<>`` lookups need the DB
        # column name (Worker.worker_metadata -> "metadata").
        update_cols: dict[str, Any] = {}
        for col in present_update_cols:
            db_col = _to_col(col)
            update_cols[db_col] = getattr(stmt.excluded, db_col)

        if not update_cols:
            # Nothing to update on conflict - degenerate case where
            # every input row is just (project, engine, name) with
            # no payload. Insert-or-do-nothing then.
            stmt = stmt.on_conflict_do_nothing(
                index_elements=("project_id", "engine", "name"),
            )
        else:
            stmt = stmt.on_conflict_do_update(
                index_elements=("project_id", "engine", "name"),
                set_=update_cols,
            )

        await self.session.execute(stmt)
        return len(prepared)

    async def counts_for_project(
        self,
        project_id: UUID,
        *,
        since: datetime | None = None,
    ) -> dict[str, dict[str, int]]:
        """Return per-worker task counts aggregated from the events table.

        Returns a mapping of ``worker_name -> {processed, succeeded,
        failed, retried}``. Worker names match
        ``events.payload->>'worker'`` which the agent's mapper sets
        from the Celery signal's ``hostname`` (e.g.
        ``celery@web-01``). Workers with zero events are simply
        absent from the dict; the API layer fills zero-defaults so
        the dashboard table stays uniform.

        SQL is dialect-portable: ``payload->>'worker'`` works on
        Postgres + SQLite (the ``->>`` JSON-extract operator is
        supported by both). ``GROUP BY`` keeps the work on the
        database.

        ``processed = succeeded + failed`` (the conventional
        Celery-flower meaning - retries do NOT count as processed
        since the task has not finished). We expose all four so
        the dashboard can render Total / Succeeded / Failed /
        Retried columns separately.

        Round-7 audit fix R7-HIGH (perf) (Apr 2026): the prior
        version had no ``since`` bound and no LIMIT, so every
        Workers tab refresh did a full GROUP BY across the entire
        partitioned ``events`` history. Defaults to a 24-hour
        window now (matches dashboard intent: "what's each worker
        done recently"). Callers wanting all-time totals must pass
        ``since=datetime.min`` explicitly so the cost is opt-in.
        """
        worker_expr = Event.payload["worker"].astext.label("worker_name")
        succeeded_sum = func.sum(
            case((Event.kind == _KIND_SUCCEEDED, 1), else_=0),
        ).label("succeeded")
        failed_sum = func.sum(
            case((Event.kind == _KIND_FAILED, 1), else_=0),
        ).label("failed")
        retried_sum = func.sum(
            case((Event.kind == _KIND_RETRIED, 1), else_=0),
        ).label("retried")
        from datetime import UTC as _UTC, datetime as _dt, timedelta as _td  # noqa: PLC0415
        if since is None:
            since = _dt.now(_UTC) - _td(hours=24)
        stmt = (
            select(worker_expr, succeeded_sum, failed_sum, retried_sum)
            .where(
                Event.project_id == project_id,
                Event.occurred_at >= since,
                Event.kind.in_(
                    (_KIND_SUCCEEDED, _KIND_FAILED, _KIND_RETRIED),
                ),
                worker_expr.is_not(None),
            )
            .group_by(worker_expr)
        )
        result = await self.session.execute(stmt)
        out: dict[str, dict[str, int]] = {}
        for row in result.all():
            name = row.worker_name
            if not name:
                continue
            succeeded = int(row.succeeded or 0)
            failed = int(row.failed or 0)
            retried = int(row.retried or 0)
            out[name] = {
                "succeeded": succeeded,
                "failed": failed,
                "retried": retried,
                "processed": succeeded + failed,
            }
        return out

    async def touch_heartbeat(
        self,
        *,
        project_id: UUID,
        engine: str,
        name: str,
        when: datetime,
    ) -> None:
        result = await self.session.execute(
            select(Worker).where(
                Worker.project_id == project_id,
                Worker.engine == engine,
                Worker.name == name,
            ),
        )
        worker = result.scalar_one_or_none()
        if worker is None:
            return
        worker.last_heartbeat = when
        worker.state = WorkerState.ONLINE
        await self.session.flush()


__all__ = ["WorkerRepository"]
