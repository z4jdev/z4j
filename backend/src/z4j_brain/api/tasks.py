"""``/api/v1/projects/{slug}/tasks`` REST router."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from z4j_brain.api._pagination import (
    clamp_limit,
    decode_cursor,
    encode_cursor,
)
from z4j_brain.api.deps import (
    get_audit_log_repo,
    get_current_user,
    get_membership_repo,
    get_project_repo,
    get_session,
    get_settings,
    require_csrf,
)
from z4j_brain.domain.ip_rate_limit import require_bulk_action_throttle
from z4j_brain.errors import NotFoundError, ValidationError
from z4j_brain.persistence.enums import ProjectRole, TaskState

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.persistence.models import Task, User
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        MembershipRepository,
        ProjectRepository,
    )
    from z4j_brain.settings import Settings


router = APIRouter(prefix="/projects/{slug}/tasks", tags=["tasks"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class TaskPublic(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    engine: str
    task_id: str
    name: str
    queue: str | None
    state: str
    priority: str = "normal"
    args: Any | None
    kwargs: Any | None
    result: Any | None
    exception: str | None
    traceback: str | None
    retry_count: int
    eta: datetime | None
    received_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    runtime_ms: int | None
    worker_name: str | None
    parent_task_id: str | None
    root_task_id: str | None
    tags: list[str]
    created_at: datetime
    updated_at: datetime


class TaskListResponse(BaseModel):
    items: list[TaskPublic]
    next_cursor: str | None


def _task_payload(task: "Task") -> TaskPublic:
    return TaskPublic(
        id=task.id,
        project_id=task.project_id,
        engine=task.engine,
        task_id=task.task_id,
        name=task.name,
        queue=task.queue,
        state=task.state.value,
        args=task.args,
        kwargs=task.kwargs,
        result=task.result,
        exception=task.exception,
        traceback=task.traceback,
        retry_count=task.retry_count,
        eta=task.eta,
        received_at=task.received_at,
        started_at=task.started_at,
        finished_at=task.finished_at,
        runtime_ms=task.runtime_ms,
        worker_name=task.worker_name,
        parent_task_id=task.parent_task_id,
        root_task_id=task.root_task_id,
        tags=list(task.tags or []),
        created_at=task.created_at,
        updated_at=task.updated_at,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("", response_model=TaskListResponse)
async def list_tasks(
    slug: str,
    state: str | None = Query(default=None),
    priority: str | None = Query(default=None),
    name: str | None = Query(default=None, max_length=200),
    search: str | None = Query(default=None, max_length=200),
    queue: str | None = Query(default=None, max_length=200),
    worker: str | None = Query(default=None, max_length=200),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=5000),
    format: str | None = Query(default=None, pattern="^(csv|xlsx|json)$"),
    fields: str | None = Query(default=None, max_length=500),
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
    settings: "Settings" = Depends(get_settings),
) -> Any:
    """List tasks with filtering, search, pagination, and export.

    New filters (Phase A):
    - ``priority`` - comma-separated: ``?priority=critical,high``
    - ``search`` - full-text search across name, queue, worker
    - ``worker`` - exact match on worker_name
    - ``until`` - upper bound on received_at (pair with ``since``)
    - ``format`` - ``csv`` or ``xlsx`` for export (overrides pagination)
    """
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import TaskRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.VIEWER,
    )

    state_enum: TaskState | None = None
    if state:
        try:
            state_enum = TaskState(state)
        except ValueError:
            state_enum = None

    # Parse priority multi-select: ?priority=critical,high
    from z4j_brain.persistence.enums import TaskPriority

    priority_list: list[TaskPriority] | None = None
    if priority:
        priority_list = []
        for p in priority.split(","):
            p = p.strip().lower()
            try:
                priority_list.append(TaskPriority(p))
            except ValueError:
                pass
        if not priority_list:
            priority_list = None

    cursor_pair = decode_cursor(cursor)

    # Parse field selection: ?fields=task_id,name,state,priority
    selected_fields: list[str] | None = None
    if fields:
        selected_fields = [f.strip() for f in fields.split(",") if f.strip()]

    # For exports: no pagination, higher limit. Audit 2026-04-24
    # Low-3 - made configurable via ``tasks_export_max_rows`` so
    # tenants with very large projects can raise it safely instead
    # of forking the brain.
    if format in ("csv", "xlsx", "json"):
        page_size = settings.tasks_export_max_rows
    else:
        page_size = clamp_limit(
            limit,
            default=settings.rest_default_page_size,
            maximum=settings.rest_max_page_size,
        )

    tasks = TaskRepository(db_session)
    rows = await tasks.list_for_project(
        project_id=project.id,
        state=state_enum,
        priority=priority_list,
        name_substring=name,
        search_query=search,
        queue=queue,
        worker=worker,
        since=since,
        until=until,
        cursor=cursor_pair,
        limit=page_size,
    )

    # Export path: return file.
    if format == "csv":
        return _export_csv(rows, slug, selected_fields)
    if format == "json":
        return _export_json(rows, slug, selected_fields)
    if format == "xlsx":
        return _export_xlsx(rows, slug, selected_fields)

    next_cursor: str | None = None
    if len(rows) == page_size:
        last = rows[-1]
        next_cursor = encode_cursor(last.started_at, last.id)

    return TaskListResponse(
        items=[_task_payload(t) for t in rows],
        next_cursor=next_cursor,
    )


@router.get("/{engine}/{task_id}", response_model=TaskPublic)
async def get_task(
    slug: str,
    engine: str,
    task_id: str,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> TaskPublic:
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import TaskRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.VIEWER,
    )
    task = await TaskRepository(db_session).get_by_engine_task_id(
        project_id=project.id,
        engine=engine,
        task_id=task_id,
    )
    if task is None:
        raise NotFoundError(
            "task not found",
            details={"engine": engine, "task_id": task_id},
        )
    return _task_payload(task)


class TaskTreeNode(BaseModel):
    """One node in the canvas-tree response."""

    task_id: str
    name: str
    state: str
    parent_task_id: str | None
    root_task_id: str | None
    received_at: datetime | None
    finished_at: datetime | None


class TaskTreeResponse(BaseModel):
    """Response shape for ``GET /tasks/{engine}/{task_id}/tree``.

    ``root_task_id`` is the id of the canvas root (the original
    ``apply_async`` entry point). ``nodes`` is a flat list - the
    dashboard reconstructs the parent → child tree client-side
    from the ``parent_task_id`` field, which keeps this endpoint
    cheap and the rendering layout-flexible.

    Standalone tasks (no canvas) return a single-node tree where
    the root is the task itself.
    """

    root_task_id: str
    node_count: int
    truncated: bool
    nodes: list[TaskTreeNode]


@router.get(
    "/{engine}/{task_id}/tree",
    response_model=TaskTreeResponse,
)
async def get_task_tree(
    slug: str,
    engine: str,
    task_id: str,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> TaskTreeResponse:
    """Return the full canvas (chain / group / chord) tree this task belongs to.

    Looks up the requested task, walks to its root via
    ``root_task_id`` (or treats the task as its own root if the
    field is null), then returns every task in the project sharing
    that root. Capped at 500 nodes so a runaway chain doesn't
    return an unbounded blob; the response carries ``truncated:
    true`` when the cap kicks in so the dashboard can show a
    "showing first 500 of N" notice.
    """
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import TaskRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.VIEWER,
    )
    max_nodes = 500
    rows, root_id, truncated = await TaskRepository(db_session).get_tree(
        project_id=project.id,
        engine=engine,
        task_id=task_id,
        max_nodes=max_nodes,
    )
    if not rows or root_id is None:
        raise NotFoundError(
            "task not found",
            details={"engine": engine, "task_id": task_id},
        )
    return TaskTreeResponse(
        root_task_id=root_id,
        node_count=len(rows),
        truncated=truncated,
        nodes=[
            TaskTreeNode(
                task_id=t.task_id,
                name=t.name,
                state=t.state.value if hasattr(t.state, "value") else str(t.state),
                parent_task_id=t.parent_task_id,
                root_task_id=t.root_task_id,
                received_at=t.received_at,
                finished_at=t.finished_at,
            )
            for t in rows
        ],
    )


# ---------------------------------------------------------------------------
# Bulk operations
# ---------------------------------------------------------------------------


class BulkDeleteRequest(BaseModel):
    """Delete tasks by explicit ID list or by filter."""

    # ``extra=forbid`` rejects unknown keys at the Pydantic
    # validation layer so a caller can't smuggle a body field
    # like ``project_id`` or ``engine`` and accidentally hit a
    # future code path that respects it (R3 finding M12 - the
    # current handler hardwires Task.project_id == project.id
    # in the WHERE clause, so this is defence in depth).
    model_config = {"extra": "forbid"}

    # Round-8 audit fix R8-Pyd-H4 (Apr 2026): cap the explicit list.
    # The handler slices to :1000 below the validator, but Pydantic
    # parses + UUID-validates the whole list first, a 10M-element
    # list still OOM-walks the validator before the slice. The cap
    # matches the handler's existing trim ceiling.
    task_ids: list[uuid.UUID] | None = Field(default=None, max_length=1000)
    filter_state: str | None = None
    filter_name: str | None = None
    filter_queue: str | None = None
    filter_since: datetime | None = None
    filter_until: datetime | None = None


class BulkDeleteResponse(BaseModel):
    deleted_count: int


@router.post(
    "/bulk-delete",
    response_model=BulkDeleteResponse,
    dependencies=[
        Depends(require_csrf),
        Depends(require_bulk_action_throttle),
    ],
)
async def bulk_delete_tasks(
    slug: str,
    body: BulkDeleteRequest,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    settings: "Settings" = Depends(get_settings),
) -> BulkDeleteResponse:
    """Delete task records from the brain database.

    Supports two modes:
    - By ID list: provide ``task_ids`` (up to 1000).
    - By filter: provide ``filter_*`` params (deletes up to 10000).

    This is a brain-side operation (no agent command needed).
    Requires ADMIN role.
    """
    from sqlalchemy import delete, select
    from sqlalchemy import func as sql_func

    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.models import Task

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.ADMIN,
    )

    if body.task_ids:
        # Delete by explicit IDs (max 1000).
        ids = body.task_ids[:1000]
        result = await db_session.execute(
            delete(Task).where(
                Task.project_id == project.id,
                Task.id.in_(ids),
            ),
        )
        deleted = result.rowcount or 0
    else:
        # Delete by filter (max 10000).
        q = select(Task.id).where(Task.project_id == project.id)
        if body.filter_state:
            try:
                q = q.where(Task.state == TaskState(body.filter_state))
            except ValueError:
                pass
        if body.filter_name:
            q = q.where(Task.name.ilike(f"%{body.filter_name}%"))
        if body.filter_queue:
            q = q.where(Task.queue == body.filter_queue)
        if body.filter_since:
            q = q.where(Task.received_at >= body.filter_since)
        if body.filter_until:
            q = q.where(Task.received_at <= body.filter_until)
        q = q.limit(10_000)

        subq = q.subquery()
        result = await db_session.execute(
            delete(Task).where(Task.id.in_(select(subq.c.id))),
        )
        deleted = result.rowcount or 0

    await AuditService(settings).record(
        audit_log,
        action="tasks.bulk_delete",
        target_type="task",
        target_id=None,
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project.id,
        source_ip=None,
        user_agent=None,
        metadata={"deleted_count": deleted},
    )
    await db_session.commit()
    return BulkDeleteResponse(deleted_count=deleted)


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------

#: All exportable fields and their extractors.
#:
#: Every extractor returns one of: ``str``, ``int``, ``None``.
#: Type stability per column matters for xlsx export - Excel
#: renders a column as "mixed type" if some rows write strings
#: and others write ints, which makes downstream filtering /
#: pivot-tables awkward. ``runtime_ms`` is ``int | None``;
#: ``retry_count`` is ``int``; everything else is ``str | None``.
_ALL_EXPORT_FIELDS: list[tuple[str, Any]] = [
    ("task_id", lambda r: r.task_id),
    ("name", lambda r: r.name),
    ("state", lambda r: r.state.value if hasattr(r.state, "value") else r.state),
    ("priority", lambda r: r.priority.value if hasattr(r.priority, "value") else getattr(r, "priority", "normal")),
    ("queue", lambda r: r.queue or ""),
    ("worker", lambda r: r.worker_name or ""),
    ("received_at", lambda r: r.received_at.isoformat() if r.received_at else ""),
    ("started_at", lambda r: r.started_at.isoformat() if r.started_at else ""),
    ("finished_at", lambda r: r.finished_at.isoformat() if r.finished_at else ""),
    ("runtime_ms", lambda r: r.runtime_ms),
    ("retry_count", lambda r: r.retry_count),
    ("exception", lambda r: r.exception or ""),
    ("traceback", lambda r: r.traceback or ""),
    ("args", lambda r: str(r.args) if r.args else ""),
    ("kwargs", lambda r: str(r.kwargs) if r.kwargs else ""),
    ("result", lambda r: str(r.result) if r.result else ""),
    ("tags", lambda r: ",".join(r.tags) if r.tags else ""),
]

#: Hard cap on rows per xlsx export. ``in_memory=True`` builds the
#: whole workbook in RAM (~200-400 bytes per cell × 17 cols × N
#: rows). At 25 000 rows that's ~150 MB of resident memory per
#: concurrent export - past which we'd rather force operators to
#: switch to CSV (which streams). The cap sits well below the
#: 50 000-row export ceiling on `list_tasks`.
_XLSX_ROW_CAP = 25_000

#: First-character prefixes that Excel / Google Sheets / LibreOffice
#: interpret as formulas when a cell starts with one. Attacker-
#: controlled task names / exceptions / args can otherwise become
#: live formulas in the operator's spreadsheet (CSV injection).
#: The neutralisation is to prefix a leading apostrophe - the
#: apostrophe is hidden by the spreadsheet UI but forces the cell
#: to render as text (external-audit High #4).
_SPREADSHEET_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _neutralise_formula(value: Any) -> Any:
    """Return a spreadsheet-safe form of ``value``.

    If ``value`` is a string starting with one of the formula
    trigger characters, prefix an apostrophe so the cell renders
    as text instead of being evaluated. Non-strings (int, float,
    bool, None) pass through unchanged - they cannot introduce
    formula injection.
    """
    if isinstance(value, str) and value.startswith(_SPREADSHEET_FORMULA_PREFIXES):
        return "'" + value
    return value


def _resolve_fields(
    selected: list[str] | None,
) -> list[tuple[str, Any]]:
    """Filter _ALL_EXPORT_FIELDS to only the selected field names."""
    if not selected:
        # Default: metadata only (no args/kwargs/result/traceback)
        return [
            (name, fn)
            for name, fn in _ALL_EXPORT_FIELDS
            if name not in ("traceback", "args", "kwargs", "result", "tags")
        ]
    all_by_name = {name: fn for name, fn in _ALL_EXPORT_FIELDS}
    return [(name, all_by_name[name]) for name in selected if name in all_by_name]


def _export_csv(
    rows: list[Any],
    slug: str,
    selected_fields: list[str] | None = None,
) -> Any:
    """Stream tasks as CSV."""
    import csv
    import io

    from fastapi.responses import StreamingResponse

    field_defs = _resolve_fields(selected_fields)
    headers = [name for name, _ in field_defs]

    def generate() -> Any:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(headers)
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate()
        for row in rows:
            # Neutralise every cell against CSV-formula injection
            # - task ``name`` / ``exception`` / ``args`` etc. are
            # attacker-controlled and get opened in Excel /
            # Sheets / LibreOffice by operators (external-audit
            # High #4).
            writer.writerow(
                [_neutralise_formula(fn(row)) for _, fn in field_defs],
            )
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate()

    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="z4j-tasks-{slug}.csv"',
        },
    )


def _export_json(
    rows: list[Any],
    slug: str,
    selected_fields: list[str] | None = None,
) -> Any:
    """Return tasks as a JSON array file download."""
    import json as _json

    from fastapi.responses import Response

    field_defs = _resolve_fields(selected_fields)
    data = []
    for row in rows:
        item = {}
        for name, fn in field_defs:
            item[name] = fn(row)
        data.append(item)

    body = _json.dumps(data, indent=2, default=str, ensure_ascii=False)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="z4j-tasks-{slug}.json"',
        },
    )


def _export_xlsx(
    rows: list[Any],
    slug: str,
    selected_fields: list[str] | None = None,
) -> Any:
    """Generate tasks as XLSX (Excel).

    Implementation: ``xlsxwriter`` - pure Python, write-only, no
    native deps, tiny (~1 MB). We picked it over ``openpyxl``
    (read+write, ~5 MB with transitive deps) because our use case
    is export-only: the brain never needs to READ xlsx. Pandas
    itself uses xlsxwriter as its default xlsx engine, so this is
    the boring, well-known choice. Shipping as a direct runtime
    dep (no opt-in extra) because the size cost is negligible and
    operators shouldn't need to know the file-format quirk to get
    xlsx export working.
    """
    import io

    import xlsxwriter
    from fastapi.responses import StreamingResponse

    if len(rows) > _XLSX_ROW_CAP:
        # Don't try to build a multi-hundred-MB workbook in RAM.
        # CSV streams; tell the operator to use it.
        raise ValidationError(
            f"xlsx export is capped at {_XLSX_ROW_CAP} rows; use CSV for larger result sets",
            details={"row_count": len(rows), "cap": _XLSX_ROW_CAP},
        )

    field_defs = _resolve_fields(selected_fields)
    headers = [name for name, _ in field_defs]

    buf = io.BytesIO()
    # ``in_memory=True`` keeps the temp file off disk - matters
    # when the brain runs in a read-only container.
    #
    # ``strings_to_formulas=False`` disables xlsxwriter's default
    # of auto-converting any string starting with ``=`` into a
    # formula - the first defence against spreadsheet-formula
    # injection (external-audit High #4). We ALSO apostrophe-
    # prefix every at-risk string in ``_neutralise_formula``
    # below so ``+``, ``-``, ``@``, tab, CR prefixes are
    # neutralised too; xlsxwriter's flag only covers ``=``.
    wb = xlsxwriter.Workbook(
        buf,
        {"in_memory": True, "strings_to_formulas": False},
    )
    try:
        ws = wb.add_worksheet("Tasks")
        header_fmt = wb.add_format({"bold": True, "bg_color": "#f1f5f9"})

        for col, h in enumerate(headers):
            ws.write(0, col, h, header_fmt)
        for r, row in enumerate(rows, start=1):
            for col, (_, fn) in enumerate(field_defs):
                value = _neutralise_formula(fn(row))
                # xlsxwriter refuses ``None`` and a few other
                # types it can't serialise (dict, list). Coerce
                # everything to a string when we can't write it
                # directly - type stability per column matters
                # for Excel filtering.
                if value is None or value == "":
                    ws.write_blank(r, col, None)
                elif isinstance(value, (str, int, float, bool)):
                    ws.write(r, col, value)
                else:
                    ws.write_string(r, col, str(value))

        # Freeze the header row so scrolling a long task list
        # keeps the column titles visible - matches what every
        # operator expects from a tasks export.
        ws.freeze_panes(1, 0)
    finally:
        # ``Workbook.close`` flushes the zip container to ``buf``.
        # If a row extractor raised mid-loop we still want to
        # release the workbook's file handles + temp resources.
        wb.close()
    buf.seek(0)

    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f'attachment; filename="z4j-tasks-{slug}.xlsx"',
        },
    )


__all__ = ["TaskListResponse", "TaskPublic", "router"]
