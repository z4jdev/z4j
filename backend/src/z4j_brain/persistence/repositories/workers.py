"""``workers`` repository."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, case, func, literal, or_, select, update
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
#: touches SQL. Without the translation the bulk-upsert path would
#: hit ``AttributeError: worker_metadata`` on every worker
#: heartbeat.
_ATTR_TO_COL = {
    "worker_metadata": "metadata",
}

#: What the database would have put in a column had the INSERT left it out.
#: Only the NOT NULL ones need an entry: a row that has to be given a value
#: for a column it never reported (because another row in the same batch did
#: report it) must be given the same value the column default would have
#: produced, and ``None`` is not that for these four. Every other variable
#: column is nullable, so ``None`` is exactly right and the ``.get`` below
#: supplies it.
_INSERT_DEFAULTS: dict[str, Any] = {
    "state": WorkerState.UNKNOWN,
    "queues": [],
    "active_tasks": 0,
    "worker_metadata": {},
}


def _to_col(attr: str) -> str:
    """Return DB column name for a Worker attribute name."""
    return _ATTR_TO_COL.get(attr, attr)


def _to_utc(value: Any) -> Any:
    """Normalise a datetime to UTC so ``last_heartbeat`` is stored as a true
    INSTANT, not an offset-dropped wall-clock.

    ``DateTime(timezone=True)`` round-trips to a NAIVE local wall-clock on
    SQLite (and other naive-offset dialects), silently dropping any non-UTC
    offset -- which corrupts the monotonic ``greatest(stored, incoming)``
    comparison (a "newer" 11:00-05:00 = 16:00Z would compare below a stored
    12:00Z). Callers that do not run values through the event ingestor's
    ``_parse_datetime`` (notably the WS heartbeat path,
    ``frame_router._handle_heartbeat``, which passes ``last_flush_at`` straight
    through) would otherwise store a non-normalised heartbeat. ``astimezone`` can OverflowError on a boundary-year offset (mirrors
    the event-path guard), so fall back to now(). Non-datetime values pass
    through unchanged.

    SCOPE: this normalises NEW writes. A value already
    stored on SQLite BEFORE this wave with a non-UTC offset kept only its naive
    wall-clock (the offset is gone and unrecoverable), so the monotonic
    comparison can reject a correct new UTC heartbeat until real UTC passes that
    stale wall-clock. This affects worker LIVENESS only, is bounded by the old
    offset, self-corrects on the first heartbeat past it, and does not occur on
    Postgres (timestamptz stores true UTC) or for a conforming agent (which
    emits UTC). Repairing a legacy row would need an upgrade-time reset of
    ``workers.last_heartbeat``; deferred as not worth a migration.
    """
    if isinstance(value, datetime):
        try:
            return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
        except (OverflowError, OSError, ValueError):
            return datetime.now(UTC)
    return value


def _heartbeat_is_not_stale(incoming: Any) -> Any:
    """Return the SQL predicate that lets an observation change liveness.

    The comparison deliberately lives in SQL.  A Python read/check/write can
    observe an old row, wait behind a concurrent fresh heartbeat, then overwrite
    that fresh value after the lock is released.  Database evaluation happens
    after the writer owns the row, so PostgreSQL rechecks against the committed
    value it waited for and SQLite applies the same rule inside its serialized
    write statement.

    ``NULL`` means the caller supplied no ordering observation; it may still
    update state for the state-only paths.  A real timestamp must be at least as
    new as the stored heartbeat before it can change state.
    """
    return or_(
        incoming.is_(None),
        Worker.last_heartbeat.is_(None),
        Worker.last_heartbeat <= incoming,
    )


def _monotonic_heartbeat_value(incoming: Any) -> Any:
    """Return a SQL expression that can advance, but never rewind, heartbeat."""
    return case(
        (
            or_(
                Worker.last_heartbeat.is_(None),
                Worker.last_heartbeat < incoming,
            ),
            incoming,
        ),
        else_=Worker.last_heartbeat,
    )


#: How far into ``workers.metadata`` the merge below looks before it stops
#: inspecting and replaces the value wholesale. The document arrives from an
#: agent over the wire, so an unbounded walk would hand a peer control of this
#: process's recursion depth. The deepest report an agent actually sends is
#: ``stats.rusage.<field>``, three levels in.
_METADATA_MERGE_MAX_DEPTH = 8


def _merge_worker_metadata(
    stored: Any,
    incoming: Any,
    *,
    _depth: int = 0,
) -> Any:
    """Fold an incoming worker report into the stored document, keeping the union.

    ``workers.metadata`` holds several independent reports under one key each
    (``stats``, ``active``, ``active_queues``, ``registered``, ``conf``), and
    an agent does not always carry all of them: each one is a separate Celery
    inspect broadcast with its own timeout, so a worker can answer for its
    stats and miss the same round's conf. During a rolling upgrade the problem
    goes a level deeper, because two agent versions inspecting the same broker
    describe the SAME worker with different vocabularies -- an older agent
    reports only the settings an application overrode explicitly, a current one
    reports the whole effective configuration including defaults. Replacing
    either document with the other makes the persisted configuration a coin
    flip on which heartbeat landed last, and the lint panel flaps between
    evaluated and unevaluated for the length of the upgrade.

    So the rule is union, applied at every level: a key the incoming report
    does not carry is left alone, a key it does carry wins, and two objects at
    the same key merge rather than replace. Lists replace wholesale -- an empty
    ``active`` is a worker with nothing running, which is a fact, not a gap.

    A ``None`` value is stored as a null rather than treated as a delete
    instruction. The agents have no reason to ask for a deletion, and reading
    one out of a wire-supplied document would let a peer erase what another
    agent reported.

    This lives in Python, evaluated per row, rather than in the SQL of the
    ``ON CONFLICT`` clause. PostgreSQL's ``jsonb ||`` replaces a nested object
    and SQLite's ``json_patch`` merges it, so expressing the rule in each
    dialect's own JSON operator meant two implementations, and the two drifted
    into two different semantics that no test compared. One implementation
    cannot drift from itself.
    """
    if (
        _depth >= _METADATA_MERGE_MAX_DEPTH
        or not isinstance(stored, dict)
        or not isinstance(incoming, dict)
    ):
        return incoming
    merged = dict(stored)
    for key, value in incoming.items():
        merged[key] = _merge_worker_metadata(
            merged.get(key),
            value,
            _depth=_depth + 1,
        )
    return merged


def _fold_duplicate_rows(prepared: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse entries that target the same row into one.

    A statement that proposes the same conflict key twice is applied twice by
    SQLite and refused outright by PostgreSQL, which raises
    ``ON CONFLICT DO UPDATE command cannot affect row a second time``. Leaving
    the duplicates in the payload therefore means a batch that works on a
    contributor's SQLite and takes the whole heartbeat down on the database
    production runs on.

    Folding in input order keeps the outcome SQLite produced -- the later entry
    wins per column -- and makes PostgreSQL produce the same one. Heartbeat and
    lifecycle state move together: an older duplicate may contribute other
    metadata, but it cannot keep the newer timestamp while replacing the newer
    observation's state. Metadata is recursively merged. A fold therefore
    cannot smuggle in a result the conflict clause would have refused.

    ``prepared`` is already sorted by conflict key and dicts keep insertion
    order, so the folded list stays in canonical lock order.
    """
    folded: dict[tuple[Any, str, str], dict[str, Any]] = {}
    for payload in prepared:
        key = (payload["project_id"], payload["engine"], payload["name"])
        kept = folded.get(key)
        if kept is None:
            folded[key] = payload
            continue
        kept_heartbeat = kept.get("last_heartbeat")
        incoming_heartbeat = payload.get("last_heartbeat")
        stale_observation = (
            incoming_heartbeat is not None
            and kept_heartbeat is not None
            and incoming_heartbeat < kept_heartbeat
        )
        for column, value in payload.items():
            if column == "id":
                # Whichever entry got there first owns the row it inserts.
                continue
            if column == "worker_metadata":
                kept[column] = _merge_worker_metadata(kept.get(column), value)
                continue
            if column == "state" and stale_observation:
                continue
            if column == "last_heartbeat" and stale_observation:
                continue
            kept[column] = value
    return list(folded.values())


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
        doesn't return tens of thousands of rows. AgentHygieneWorker normally sweeps stale rows but
        in environments where it's behind, the cap protects the
        response path.
        """
        if limit < 1 or limit > 5000:
            raise ValueError("limit must be between 1 and 5000")
        result = await self.session.execute(
            select(Worker)
            .where(Worker.project_id == project_id)
            # Worker.id breaks ORDER BY ties on exact-equal heartbeats
            # and identical names so cursor pagination cannot skip or
            # duplicate rows under churn.
            .order_by(
                Worker.last_heartbeat.desc().nulls_last(),
                Worker.name,
                Worker.id,
            )
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
        existing row and applies the updates: under concurrent
        load this path was caught raising a ``PendingRollbackError``
        cascade without the savepoint.

        Existing-row heartbeat and state changes use one conditional SQL
        UPDATE.  The database, rather than the earlier SELECT, compares the
        incoming heartbeat with the value current after lock acquisition.  A
        stale transaction therefore cannot rewind ``last_heartbeat`` or apply
        its stale lifecycle state after a fresher transaction commits.
        """
        from sqlalchemy.exc import IntegrityError

        # Normalise last_heartbeat to a UTC instant BEFORE it is stored on
        # either the INSERT or the UPDATE branch: a
        # non-UTC value stored on SQLite loses its offset and later corrupts the
        # monotonic comparison. Copy so the caller's dict is not mutated.
        if "last_heartbeat" in updates:
            updates = {**updates, "last_heartbeat": _to_utc(updates["last_heartbeat"])}

        # ``worker_metadata`` is the one column whose new value is COMPUTED
        # from the stored one, so for that column alone the read has to be the
        # start of the write rather than an independent observation: two
        # concurrent heartbeats for the same worker would otherwise both read
        # the same document, both merge onto it, and the second write would
        # drop whatever the first contributed. Rendered only where the dialect
        # has it -- SQLite serialises writers itself and SQLAlchemy omits the
        # clause there.
        lookup = select(Worker).where(
            Worker.project_id == project_id,
            Worker.engine == engine,
            Worker.name == name,
        )
        if "worker_metadata" in updates:
            lookup = lookup.with_for_update()

        result = await self.session.execute(lookup)
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
                result = await self.session.execute(lookup)
                existing = result.scalar_one()
            else:
                return row
        values: dict[str, Any] = {}
        incoming_heartbeat = updates.get("last_heartbeat")
        heartbeat_expression = (
            literal(
                incoming_heartbeat,
                type_=Worker.__table__.c.last_heartbeat.type,
            )
            if "last_heartbeat" in updates
            else None
        )
        for key, value in updates.items():
            if key == "last_heartbeat":
                assert heartbeat_expression is not None
                values[key] = _monotonic_heartbeat_value(
                    heartbeat_expression,
                )
            elif key == "state" and heartbeat_expression is not None:
                # State belongs to the same observation as its heartbeat. A
                # stale ONLINE replay must not erase a newer OFFLINE/DRAINING
                # decision (or vice versa).
                values[key] = case(
                    (
                        _heartbeat_is_not_stale(heartbeat_expression),
                        value,
                    ),
                    else_=Worker.state,
                )
            elif key == "worker_metadata":
                # ``lookup`` is FOR UPDATE on PostgreSQL when metadata is in
                # play, so this merge remains lossless there. SQLite serializes
                # writers and callers isolate this fallback in a savepoint.
                values[key] = _merge_worker_metadata(
                    existing.worker_metadata,
                    value,
                )
            else:
                values[key] = value
        if values:
            await self.session.execute(
                update(Worker)
                .where(Worker.id == existing.id)
                .values(**values)
                .execution_options(synchronize_session=False),
            )
            await self.session.flush()
            await self.session.refresh(existing)
        return existing

    async def _materialize_batch_rows(
        self,
        prepared: list[dict[str, Any]],
        insert: Any,
    ) -> None:
        """Make sure every row this batch touches EXISTS before it is locked.

        ``SELECT ... FOR UPDATE`` locks rows, and a row that is not there yet
        is not a row: two transactions observing the same worker for the FIRST
        time both read nothing, both resolve against an empty document, and the
        second one's ``ON CONFLICT DO UPDATE`` writes away what the first
        contributed. The lock cannot close that window because there was
        nothing to lock.

        Inserting the conflict key first turns the absent row into a present
        one, which the read below can then lock like any other. PostgreSQL
        makes this work under contention: an ``ON CONFLICT DO NOTHING`` that
        collides with an in-flight insert waits for that transaction to finish
        rather than assuming the row is absent, so whichever of the two gets
        here second still ends up locking a row that exists.

        The payload is deliberately the conflict key plus ``state`` and nothing
        else. Those columns are the same on every row, so this statement never
        has the sparseness problem the main one below has to resolve, and every
        other column keeps the value its column default gives it -- which is
        the value the read is about to hand back to a row that did not report
        one.
        """
        await self.session.execute(
            insert(Worker)
            .values(
                [
                    {
                        "id": payload["id"],
                        "project_id": payload["project_id"],
                        "engine": payload["engine"],
                        "name": payload["name"],
                        "state": payload.get("state", WorkerState.UNKNOWN),
                    }
                    for payload in prepared
                ],
            )
            .on_conflict_do_nothing(
                index_elements=("project_id", "engine", "name"),
            ),
        )

    async def _resolve_shared_update_values(
        self,
        prepared: list[dict[str, Any]],
        supplied: dict[tuple[Any, str, str], set[str]],
        update_cols: set[str],
    ) -> None:
        """Give every row an explicit value for every column the statement updates.

        One ``ON CONFLICT DO UPDATE`` set clause is shared by every row in the
        statement, and one VALUES clause has one column list. Rows that
        disagree about which columns they carry therefore cannot be sent as
        they are: whichever column list SQLAlchemy takes is wrong for the other
        rows, either loudly (a ``CompileError`` that costs the whole batch) or
        silently (the column is dropped, and the set clause then writes the
        NULL that leaves behind over every row's stored value).

        That disagreement is normal here rather than exceptional. Each field an
        agent reports comes from a separate inspect broadcast with its own
        timeout, so within one heartbeat one worker answers for its queues and
        another does not.

        The resolution is to fill in what a row did not report with what the
        database already holds for it, which makes the shared set clause write
        that column's own value back -- indistinguishable from not touching it,
        which is what "no key, no touch" promised. ``worker_metadata`` is the
        one column resolved to something new rather than something stored: the
        union of the two, per :func:`_merge_worker_metadata`.

        Runs after ``prepared`` is in canonical order and folded to one entry
        per row, so rows are locked in the order the INSERT takes them and no
        row is resolved against twice. The lock is held for the rest of the
        transaction so a concurrent heartbeat for the same worker cannot read
        the same values, resolve against them, and write this batch's
        contribution away. SQLAlchemy omits the clause on SQLite, which
        serialises writers itself.
        """
        columns = sorted(update_cols)
        lookup = (
            select(
                Worker.project_id,
                Worker.engine,
                Worker.name,
                *(getattr(Worker, column).label(column) for column in columns),
            )
            .where(
                or_(
                    *(
                        and_(
                            Worker.project_id == key[0],
                            Worker.engine == key[1],
                            Worker.name == key[2],
                        )
                        for key in {(r["project_id"], r["engine"], r["name"]) for r in prepared}
                    ),
                ),
            )
            .order_by(Worker.project_id, Worker.engine, Worker.name)
            .with_for_update()
        )
        stored: dict[tuple[Any, str, str], Any] = {}
        for row in (await self.session.execute(lookup)).all():
            stored[(row.project_id, row.engine, row.name)] = row._mapping

        for payload in prepared:
            key = (payload["project_id"], payload["engine"], payload["name"])
            row_stored = stored.get(key)
            row_supplied = supplied.get(key, set())
            for column in columns:
                held = _INSERT_DEFAULTS.get(column)
                if row_stored is not None:
                    held = row_stored[column]
                if column == "worker_metadata":
                    base = held if isinstance(held, dict) else {}
                    payload[column] = (
                        _merge_worker_metadata(base, payload[column])
                        if column in row_supplied
                        else base
                    )
                    continue
                if column in row_supplied:
                    continue
                # Normalised on the way back out for the same reason it is
                # normalised on the way in: a naive-offset dialect hands back a
                # wall clock, and the monotonic comparison compares instants.
                payload[column] = _to_utc(held) if column == "last_heartbeat" else held

    async def upsert_from_events_bulk(  # noqa: PLR0912, PLR0915  bulk upsert
        self,
        rows: list[dict[str, Any]],
    ) -> int:
        """Bulk upsert N worker rows in one statement.

        SECURITY: ``project_id`` MUST come from the caller's
        authenticated context (e.g. ``self._project_id`` in
        ``frame_router``). Do NOT take ``project_id`` from a value
        on the wire / inside a frame payload, otherwise an attacker
        who controls a signed agent could upsert into another
        tenant's worker rows. The repository trusts the caller
        deliberately; the boundary lives in the API/WS layer.

        Each ``rows`` entry must include ``project_id``, ``engine``,
        ``name``; any of the columns in :data:`_UPSERT_VARIABLE_COLS`
        may be present. A column a row does not carry is not touched
        for that row, so this method is safe to call with partial-update
        payloads (e.g. a heartbeat that only carries ``last_heartbeat``
        + ``state`` will not blank the previously-recorded
        ``concurrency`` / ``hostname``).

        Rows may carry DIFFERENT columns from each other, which is the
        normal case rather than the exotic one: each field an agent reports
        comes from its own inspect broadcast with its own timeout. One
        statement has one column list and one set clause, so those rows
        cannot be sent as they arrive; :meth:`_resolve_shared_update_values`
        fills each row's gaps from what the database already holds for it,
        which is what makes "not touched" true through a shared clause.

        ``worker_metadata`` is the exception to last-writer-wins: it is
        merged onto the stored document by :func:`_merge_worker_metadata`
        rather than replacing it, identically on every dialect. See that
        function for why the union is the right rule and why it is resolved
        in Python.

        On Postgres + SQLite (≥ 3.24) we emit one
        ``INSERT ... ON CONFLICT (project_id, engine, name) DO UPDATE``
        statement, preceded (only when a stored value is needed) by the
        conflict-key insert and the locked read that
        :meth:`_materialize_batch_rows` and
        :meth:`_resolve_shared_update_values` describe. Those are two
        statements for the whole batch, not per row. On any other dialect
        we transparently fall back to the per-row
        :meth:`upsert_from_event` path so non-prod adapters keep working.

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

        _ins: Any
        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            _ins = pg_insert
        elif dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            _ins = sqlite_insert
        else:
            # Unknown dialect - fall back to the per-row safe path.
            # Preserves correctness on any future adapter we add.
            for r in rows:
                await self.upsert_from_event(
                    project_id=r["project_id"],
                    engine=r["engine"],
                    name=r["name"],
                    updates={k: v for k, v in r.items() if k in _UPSERT_VARIABLE_COLS},
                )
            return len(rows)

        # Build the INSERT payload. ``id`` needs a Python-side uuid because
        # ``pg_insert(...).values(list_of_dicts)`` does not honor SQLAlchemy
        # ORM column defaults.
        #
        # A payload carries exactly what its caller supplied, and
        # ``supplied`` records that per conflict key so the difference between
        # "reported this column" and "happens to hold a default for it" stays
        # available after the payloads have been folded. The two are not the
        # same fact: a defaulted value written through the shared set clause
        # overwrites a live worker's stored one.
        prepared: list[dict[str, Any]] = []
        supplied: dict[tuple[Any, str, str], set[str]] = {}
        present_update_cols: set[str] = set()
        for r in rows:
            key = (r["project_id"], r["engine"], r["name"])
            row_supplied = supplied.setdefault(key, set())
            row_payload: dict[str, Any] = {
                "id": uuid.uuid4(),
                "project_id": r["project_id"],
                "engine": r["engine"],
                "name": r["name"],
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
                if col in r:
                    # Normalise last_heartbeat to a UTC instant before it is
                    # stored / compared.
                    row_payload[col] = _to_utc(r[col]) if col == "last_heartbeat" else r[col]
                    row_supplied.add(col)
                    present_update_cols.add(col)
            prepared.append(row_payload)

        # 1.5.1: sort by the conflict-target key so concurrent
        # sessions acquire row-level locks in the SAME order. A
        # sustained 200/s burst surfaced 140 deadlocks on this INSERT
        # without it.
        # Two heartbeats from different agents could carry overlapping
        # (project_id, engine, name) triples in opposite orders; the
        # ON CONFLICT row-lock window then opens a deadlock cycle.
        # Sorting eliminates that cycle by making every session walk
        # the same lock-acquisition path. Costs O(N log N) on tiny N
        # (~20 rows per heartbeat); negligible vs the deadlock-retry
        # penalty it removes.
        prepared.sort(key=lambda r: (r["project_id"], r["engine"], r["name"]))
        prepared = _fold_duplicate_rows(prepared)

        # A batch is resolvable as it stands only when every row reported every
        # column any row reported, and even then not if a report is in play:
        # ``worker_metadata``'s new value is computed from the stored one, so
        # for that column the read has to be part of the write.
        needs_stored_values = "worker_metadata" in present_update_cols or any(
            column not in supplied[(payload["project_id"], payload["engine"], payload["name"])]
            for payload in prepared
            for column in present_update_cols
        )
        if needs_stored_values:
            await self._materialize_batch_rows(prepared, _ins)
            await self._resolve_shared_update_values(
                prepared,
                supplied,
                present_update_cols,
            )

        # NOT NULL with no stored value to take: a batch nobody reported a
        # state for inserts the same UNKNOWN it always did, uniformly, so the
        # column list stays the same on every row.
        for payload in prepared:
            payload.setdefault("state", WorkerState.UNKNOWN)

        # One column list has to describe every row. Anything that reaches
        # here disagreeing would be compiled from the first row alone, which
        # is a dropped column and a set clause that writes the resulting NULL
        # over every row. Refusing is recoverable (both callers fall back to
        # the per-row path); a silent drop is not.
        expected_columns = set(prepared[0])
        for payload in prepared[1:]:
            if set(payload) != expected_columns:
                raise RuntimeError(
                    "bulk worker upsert rows disagree about which columns they "
                    "carry after resolution",
                )

        stmt = _ins(Worker).values(prepared)

        # Build ON CONFLICT DO UPDATE set_ from the union of columns
        # any input row carried. This preserves "no key, no touch"
        # semantics: a heartbeat carrying only ``last_heartbeat`` +
        # ``state`` will not write NULL into ``hostname``. Both the
        # set_= keys and ``stmt.excluded.<>`` lookups need the DB
        # column name (Worker.worker_metadata -> "metadata").
        update_cols: dict[str, Any] = {}
        excluded_heartbeat = (
            stmt.excluded.last_heartbeat if "last_heartbeat" in present_update_cols else None
        )
        for col in present_update_cols:
            db_col = _to_col(col)
            if db_col == "last_heartbeat":
                assert excluded_heartbeat is not None
                # Portable conditional value (no Postgres-only greatest()).
                # It is evaluated by the conflict UPDATE after row-lock
                # acquisition, so a transaction that waited behind a newer
                # writer cannot use its pre-wait view to rewind liveness.
                update_cols[db_col] = _monotonic_heartbeat_value(
                    excluded_heartbeat,
                )
            elif db_col == "state" and excluded_heartbeat is not None:
                # Lifecycle state and heartbeat are one observation. Keep both
                # from the same newest observation rather than retaining the
                # timestamp while a stale replay overwrites its state.
                update_cols[db_col] = case(
                    (
                        _heartbeat_is_not_stale(excluded_heartbeat),
                        stmt.excluded.state,
                    ),
                    else_=Worker.state,
                )
            else:
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
        # Input rows, not statement rows: folding duplicates is an
        # implementation detail of getting one statement past both engines, and
        # a caller counting its own batch should not see it.
        return len(rows)

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

        Defaults to a 24-hour window so a Workers tab refresh
        doesn't do a full GROUP BY across the entire partitioned
        ``events`` history (matches dashboard intent: "what's
        each worker done recently"). Callers wanting all-time
        totals must pass ``since=datetime.min`` explicitly so
        the cost is opt-in.
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
        from datetime import UTC as _UTC
        from datetime import datetime as _dt
        from datetime import timedelta as _td

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
        """Atomically advance one worker heartbeat and mark it online.

        The timestamp predicate is evaluated in the UPDATE after database row
        locking. A delayed/stale heartbeat is therefore a no-op for both the
        timestamp and state, even when it began before a fresher transaction.
        """
        normalized = _to_utc(when)
        incoming = literal(
            normalized,
            type_=Worker.__table__.c.last_heartbeat.type,
        )
        await self.session.execute(
            update(Worker)
            .where(
                Worker.project_id == project_id,
                Worker.engine == engine,
                Worker.name == name,
                _heartbeat_is_not_stale(incoming),
            )
            .values(
                last_heartbeat=normalized,
                state=WorkerState.ONLINE,
            )
            .execution_options(synchronize_session=False),
        )
        await self.session.flush()


__all__ = ["WorkerRepository"]
