"""``/api/v1/projects/{slug}/audit`` REST router.

Read-only access to the audit log. Filterable by action prefix,
outcome, user, and time range. Keyset-paginated by ``occurred_at``
so query work does not grow with page depth.

This router exposes no write path at all. Within the application trust
boundary, the database mutation trigger and per-row HMAC chain detect a
write outside :class:`AuditService`: an allowed mutation that does not
also reproduce the authenticated chain leaves retained rows disagreeing
with the head, and ``z4j audit verify`` names the row.

That evidence stops at the database boundary. A role that can write
both ``audit_log`` and ``audit_chain_state`` can delete recent rows
and restore an earlier copy of the state row, which still
authenticates because the brain signed it when it was current, and
verification then reports the shortened history as clean. Evidence
that has to survive a hostile database role belongs outside the
database (see ``docs/SECURITY.md`` section 10.2).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy import and_, or_, select

from z4j_brain.api._export import (
    XLSX_ROW_CAP,
    FieldDef,
    export_csv,
    export_json,
    export_xlsx,
)
from z4j_brain.api._pagination import (
    clamp_limit,
    decode_cursor,
    encode_cursor,
)
from z4j_brain.api.deps import (
    get_audit_service,
    get_client_ip,
    get_current_user,
    get_db,
    get_membership_repo,
    get_project_repo,
    get_session,
    get_settings,
    resolve_api_key_id,
)
from z4j_brain.domain.policy_engine import Action
from z4j_brain.errors import ValidationError
from z4j_brain.persistence.models import AuditLog

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.models import User
    from z4j_brain.persistence.repositories import (
        MembershipRepository,
        ProjectRepository,
    )
    from z4j_brain.settings import Settings


router = APIRouter(prefix="/projects/{slug}/audit", tags=["audit"])


class AuditLogPublic(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID | None
    user_id: uuid.UUID | None
    action: str
    target_type: str
    target_id: str | None
    result: str
    outcome: str | None
    event_id: uuid.UUID | None
    metadata: dict[str, Any]
    source_ip: str | None
    user_agent: str | None
    occurred_at: datetime


class AuditLogListResponse(BaseModel):
    items: list[AuditLogPublic]
    next_cursor: str | None


def _payload(row: AuditLog) -> AuditLogPublic:
    return AuditLogPublic(
        id=row.id,
        project_id=row.project_id,
        user_id=row.user_id,
        action=row.action,
        target_type=row.target_type,
        target_id=row.target_id,
        result=row.result,
        outcome=row.outcome,
        event_id=row.event_id,
        metadata=dict(row.audit_metadata or {}),
        source_ip=str(row.source_ip) if row.source_ip is not None else None,
        user_agent=row.user_agent,
        occurred_at=row.occurred_at,
    )


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

#: Maximum rows returned by the CSV and JSON export paths. XLSX uses the
#: lower :data:`XLSX_ROW_CAP` because xlsxwriter assembles its workbook in
#: memory. Above either format-specific ceiling the operator must narrow
#: the filter; every audit row may carry a JSONB metadata blob.
_EXPORT_ROW_CAP = 50_000


def _export_row_cap(export_format: str) -> int:
    """Return the safe row ceiling for an audit export format."""
    return XLSX_ROW_CAP if export_format == "xlsx" else _EXPORT_ROW_CAP


#: Every exportable audit column + its value extractor. Order is
#: preserved in the output. ``metadata`` is a JSON blob; we
#: serialise to a compact JSON string so one audit row fits on one
#: CSV / xlsx line.
_ALL_EXPORT_FIELDS: list[FieldDef] = [
    ("id", lambda r: str(r.id)),
    ("occurred_at", lambda r: r.occurred_at.isoformat() if r.occurred_at else ""),
    ("action", lambda r: r.action),
    ("target_type", lambda r: r.target_type),
    ("target_id", lambda r: r.target_id or ""),
    ("result", lambda r: r.result),
    ("outcome", lambda r: r.outcome or ""),
    ("user_id", lambda r: str(r.user_id) if r.user_id else ""),
    ("event_id", lambda r: str(r.event_id) if r.event_id else ""),
    ("source_ip", lambda r: str(r.source_ip) if r.source_ip is not None else ""),
    ("user_agent", lambda r: r.user_agent or ""),
    (
        "metadata",
        lambda r: __import__("json").dumps(
            dict(r.audit_metadata or {}),
            default=str,
            ensure_ascii=False,
        ),
    ),
]


#: Public name for the export columns, so the export-jobs worker writes
#: the same columns in the same order as the synchronous download.
AUDIT_EXPORT_FIELDS: list[FieldDef] = _ALL_EXPORT_FIELDS

#: Column names a caller may select, in export order.
AUDIT_EXPORT_FIELD_NAMES: tuple[str, ...] = tuple(name for name, _ in _ALL_EXPORT_FIELDS)


def _resolve_fields(selected: list[str] | None) -> list[FieldDef]:
    """Filter the full field set to a caller-selected subset.

    When ``selected`` is ``None`` or empty we export every column -
    audit exports are already filtered by action / outcome / user /
    time window, so the ceiling is low enough that 'all columns
    by default' is the useful behaviour.
    """
    if not selected:
        return list(_ALL_EXPORT_FIELDS)
    by_name = dict(_ALL_EXPORT_FIELDS)
    return [(name, by_name[name]) for name in selected if name in by_name]


#: The worker's name for :func:`_resolve_fields`.
resolve_audit_export_fields = _resolve_fields


def build_audit_export_statement(
    project_id: uuid.UUID,
    *,
    action_prefix: str | None = None,
    outcome: str | None = None,
    user_id: uuid.UUID | None = None,
    since: datetime | None = None,
) -> Any:
    """The filtered, unordered ``SELECT`` behind every audit export.

    Shared by the synchronous download and the export-jobs worker so the
    two cannot disagree about what a filter means. Callers add their own
    ordering and limit: the download orders newest first and caps, the
    worker orders the same way and pages.
    """
    stmt = select(AuditLog).where(AuditLog.project_id == project_id)
    if action_prefix:
        # Escape LIKE metacharacters so a filter like "task.%" or
        # "audit_" is matched LITERALLY, not as a wildcard. Bare
        # startswith() left %/_ active (parity gap with activity.py's
        # M16 fix); autoescape handles %, _ and the escape char.
        stmt = stmt.where(
            AuditLog.action.startswith(action_prefix, autoescape=True),
        )
    if outcome:
        stmt = stmt.where(AuditLog.outcome == outcome)
    if user_id is not None:
        stmt = stmt.where(AuditLog.user_id == user_id)
    if since is not None:
        stmt = stmt.where(AuditLog.occurred_at >= since)
    return stmt


@router.get("")
async def list_audit(
    slug: str,
    request: Request,
    action_prefix: str | None = Query(default=None, max_length=80),
    outcome: str | None = Query(default=None, max_length=20),
    user_id: uuid.UUID | None = Query(default=None),
    since: datetime | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=5000),
    format: str | None = Query(  # noqa: A002 - FastAPI query-param name shadows builtin
        default=None,
        pattern="^(csv|json|xlsx)$",
        description=(
            "Optional export format. When set, pagination is "
            "ignored and the filtered result is returned as a file "
            "download. CSV and JSON are capped at 50 000 rows; XLSX "
            "is capped at 25 000 rows because the workbook is built "
            "in memory."
        ),
    ),
    fields: str | None = Query(
        default=None,
        max_length=400,
        description=(
            "Comma-separated list of column names to include in "
            "the export. Only applies when ``format`` is set. "
            "Unknown names are silently ignored."
        ),
    ),
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    db_session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    db: DatabaseManager = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service),
    ip: str = Depends(get_client_ip),
) -> Any:
    """List audit log entries for one project.

    Requires the auditor tier on the project (``auditor`` or
    ``admin``): audit reads are privileged because they reveal who
    did what when, which is itself sensitive, and they are kept
    away from the operator tier so the people who review the
    record are not the people who produce it. The list path is
    ``Action.READ_AUDIT``; the export path is ``Action.EXPORT_AUDIT``.
    Both resolve to the same tier through the core table.

    When ``format`` is ``csv`` / ``json`` the response is a file
    download containing up to 50 000 matching rows; ``xlsx`` is
    capped at 25 000 because its workbook is built in memory.
    Cursor + limit are ignored on the export path - operators
    narrow via the filter params instead.

    A served export is itself recorded: one ``audit.export`` row through
    the chained writer naming the format, the filters, the selected
    columns and the row count, so the trail shows who took a copy of it
    and how much. The list path writes nothing; a page read is not an
    extraction.
    """
    from z4j_brain.domain.policy_engine import PolicyEngine

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project=project,
        action=Action.EXPORT_AUDIT if format is not None else Action.READ_AUDIT,
    )

    stmt = build_audit_export_statement(
        project.id,
        action_prefix=action_prefix,
        outcome=outcome,
        user_id=user_id,
        since=since,
    )

    # Export path: no pagination, full result (capped).
    if format is not None:
        export_cap = _export_row_cap(format)
        stmt = stmt.order_by(
            AuditLog.occurred_at.desc(),
            AuditLog.id.desc(),
        ).limit(export_cap + 1)
        rows = list((await db_session.execute(stmt)).scalars().all())
        if len(rows) > export_cap:
            raise ValidationError(
                f"{format} audit export is capped at {export_cap} rows; "
                "narrow the filter (action, outcome, since), or queue a "
                "background export job (POST .../audit/export-jobs) when "
                "an export sink is configured",
                details={"cap": export_cap, "format": format},
            )
        selected = [f.strip() for f in fields.split(",") if f.strip()] if fields else None
        field_defs = _resolve_fields(selected)
        # The row goes on a write session of its own, as the dead-letter
        # listing's does: the request session is a read unit on a GET.
        from z4j_brain.persistence.repositories import AuditLogRepository

        user_agent = request.headers.get("user-agent")
        async with db.session(write=True) as write_session:
            await audit_service.record(
                AuditLogRepository(write_session),
                action="audit.export",
                target_type="audit_log",
                target_id=slug,
                result="success",
                outcome="allow",
                user_id=user.id,
                project_id=project.id,
                api_key_id=resolve_api_key_id(request),
                source_ip=ip or None,
                user_agent=user_agent[:256] if user_agent else None,
                metadata={
                    "format": format,
                    "row_count": len(rows),
                    "fields": [name for name, _ in field_defs],
                    "filters": {
                        "action_prefix": action_prefix,
                        "outcome": outcome,
                        "user_id": str(user_id) if user_id is not None else None,
                        "since": since.isoformat() if since is not None else None,
                    },
                },
            )
            await write_session.commit()
        base = f"z4j-audit-{slug}"
        if format == "csv":
            return export_csv(rows, field_defs, f"{base}.csv")
        if format == "json":
            return export_json(rows, field_defs, f"{base}.json")
        # xlsx
        return export_xlsx(rows, field_defs, f"{base}.xlsx", sheet_name="Audit")

    # List path: cursor-paginated JSON.
    page_size = clamp_limit(
        limit,
        default=settings.rest_default_page_size,
        maximum=settings.rest_max_page_size,
    )
    cursor_pair = decode_cursor(cursor)
    if cursor_pair is not None:
        sort_value, tiebreaker = cursor_pair
        stmt = stmt.where(
            or_(
                AuditLog.occurred_at < sort_value,
                and_(
                    AuditLog.occurred_at == sort_value,
                    AuditLog.id < tiebreaker,
                ),
            ),
        )
    stmt = stmt.order_by(
        AuditLog.occurred_at.desc(),
        AuditLog.id.desc(),
    ).limit(page_size)

    rows = list((await db_session.execute(stmt)).scalars().all())
    next_cursor: str | None = None
    if len(rows) == page_size:
        last = rows[-1]
        next_cursor = encode_cursor(last.occurred_at, last.id)

    return AuditLogListResponse(
        items=[_payload(r) for r in rows],
        next_cursor=next_cursor,
    )


__all__ = [
    "AUDIT_EXPORT_FIELDS",
    "AUDIT_EXPORT_FIELD_NAMES",
    "AuditLogListResponse",
    "AuditLogPublic",
    "build_audit_export_statement",
    "resolve_audit_export_fields",
    "router",
]
