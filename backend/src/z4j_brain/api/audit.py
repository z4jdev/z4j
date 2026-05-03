"""``/api/v1/projects/{slug}/audit`` REST router.

Read-only access to the append-only audit log. Filterable by
action prefix, outcome, user, and time range. Cursor-paginated by
``occurred_at`` so deep paging stays O(1).

The audit log is append-only at the database level (B2 trigger
+ row HMAC), so this router cannot mutate. Operators inspect
events here; the verifier CLI (``z4j audit verify``)
re-checks the row HMAC chain offline.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import and_, or_, select

from z4j_brain.api._export import (
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
    get_current_user,
    get_membership_repo,
    get_project_repo,
    get_session,
    get_settings,
)
from z4j_brain.errors import ValidationError
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import AuditLog

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

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

#: Maximum rows returned by the export path. Above this we ask
#: the operator to narrow the filter - dumping a multi-million-row
#: audit log in one shot is rarely what they actually want, and
#: the memory cost is real (every row carries a JSONB metadata
#: blob). Matches the tasks export ceiling.
_EXPORT_ROW_CAP = 50_000

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
            dict(r.audit_metadata or {}), default=str, ensure_ascii=False,
        ),
    ),
]


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


@router.get("")
async def list_audit(
    slug: str,
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
            "ignored and the full filter result (capped at "
            "50 000 rows) is returned as a file download."
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
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
    settings: "Settings" = Depends(get_settings),
) -> Any:
    """List audit log entries for one project.

    Requires admin role on the project - audit reads are
    privileged because they can reveal who did what when, which
    is itself sensitive.

    When ``format`` is ``csv`` / ``json`` / ``xlsx`` the response
    is a file download containing up to ``_EXPORT_ROW_CAP`` rows
    that match the filter. Cursor + limit are ignored on the
    export path - operators narrow via the filter params instead.
    """
    from z4j_brain.domain.policy_engine import PolicyEngine

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.ADMIN,
    )

    stmt = select(AuditLog).where(AuditLog.project_id == project.id)
    if action_prefix:
        stmt = stmt.where(AuditLog.action.startswith(action_prefix))
    if outcome:
        stmt = stmt.where(AuditLog.outcome == outcome)
    if user_id is not None:
        stmt = stmt.where(AuditLog.user_id == user_id)
    if since is not None:
        stmt = stmt.where(AuditLog.occurred_at >= since)

    # Export path: no pagination, full result (capped).
    if format is not None:
        stmt = stmt.order_by(
            AuditLog.occurred_at.desc(), AuditLog.id.desc(),
        ).limit(_EXPORT_ROW_CAP + 1)
        rows = list((await db_session.execute(stmt)).scalars().all())
        if len(rows) > _EXPORT_ROW_CAP:
            raise ValidationError(
                f"audit export is capped at {_EXPORT_ROW_CAP} rows; "
                "narrow the filter (action, outcome, since)",
                details={"cap": _EXPORT_ROW_CAP},
            )
        selected = (
            [f.strip() for f in fields.split(",") if f.strip()]
            if fields
            else None
        )
        field_defs = _resolve_fields(selected)
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
        AuditLog.occurred_at.desc(), AuditLog.id.desc(),
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


__all__ = ["AuditLogListResponse", "AuditLogPublic", "router"]
