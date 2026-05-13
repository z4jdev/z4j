"""``/api/v1/activity`` cross-project live activity feed.

Aggregates audit-log rows across every project the caller can see.
For admins that is every project; for non-admin users it is just
the projects they hold a membership in. The endpoint is the data
source for the dashboard's Live Activity Feed page.

Cursor pagination is keyed on ``(occurred_at, id)`` because the
audit-log row id is ``uuid4`` (random, not time-ordered) -- ordering
by ``id`` alone would shuffle rows unpredictably. (v1.6 audit C8.)

The endpoint is READ-ONLY against the audit table; the brain's
existing per-project audit router (``api/audit.py``) handles
deep-dive forensics with HMAC re-verification. This module is the
brain-wide overview surface.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select

from z4j_brain.api.deps import (
    get_current_user,
    get_membership_repo,
    get_session,
)
from z4j_brain.persistence.models import AuditLog, Project

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.persistence.models import User
    from z4j_brain.persistence.repositories import MembershipRepository


router = APIRouter(prefix="/activity", tags=["activity"])


#: Hard cap on how many distinct callers can poll the activity feed
#: per minute. PER WORKER PROCESS: with ``Z4J_WORKERS=N`` and M
#: brain replicas, the effective cluster-wide ceiling is N*M*60/min
#: per user. This is documented in operations/activity-feed.md;
#: the message at the 429 boundary calls out "per worker" so an
#: operator chasing a 429 in their dashboard sees it correctly.
_RATE_LIMIT_PER_USER_PER_MINUTE: int = 60

#: Cap on the size of the per-user bucket dict. Beyond this we
#: evict the least-recently-used user_id. Prevents a multi-tenant
#: brain with high user churn from leaking memory permanently.
#: (Round 2 Sev-7 / High-1.)
_RATE_LIMIT_USER_CAP: int = 50_000


# v1.6 audit H13: simple per-user-id token bucket so a misbehaving
# dashboard or a malicious enumeration probe cannot turn the
# activity endpoint into a sustained DB-query DoS amplifier.
# Uses OrderedDict so we can pop the LRU entry when the cap is
# exceeded. ``move_to_end`` on each access keeps the eviction
# order accurate.
from collections import OrderedDict as _OrderedDict
_user_bucket: "_OrderedDict[str, list[float]]" = _OrderedDict()


def _rate_limit_check(user_id: str) -> bool:
    """Returns True when the caller is within budget, False to deny.

    Sliding window of 60 seconds, capped at
    ``_RATE_LIMIT_PER_USER_PER_MINUTE`` hits per user_id per
    worker. The bucket dict is bounded at
    ``_RATE_LIMIT_USER_CAP`` entries via LRU eviction so a
    multi-tenant brain with high user churn cannot leak memory.
    """
    import time
    now = time.monotonic()
    window_start = now - 60.0
    bucket = _user_bucket.get(user_id)
    if bucket is None:
        # New user. Evict LRU if at cap.
        if len(_user_bucket) >= _RATE_LIMIT_USER_CAP:
            _user_bucket.popitem(last=False)
        bucket = []
        _user_bucket[user_id] = bucket
    # Drop entries outside the window.
    while bucket and bucket[0] < window_start:
        bucket.pop(0)
    if len(bucket) >= _RATE_LIMIT_PER_USER_PER_MINUTE:
        # Rate-limited. v1.6 Round 5 F2 fix: do NOT touch the LRU
        # order on a denied call. Otherwise a hostile caller that
        # sits at the 429 boundary keeps their entry MRU forever
        # and pushes legitimate users out via LRU eviction -- both
        # a memory pin and a fairness DoS.
        return False
    bucket.append(now)
    # Granted: touch the LRU so legitimate active users stay MRU.
    _user_bucket.move_to_end(user_id)
    return True


def _reset_rate_limit_for_tests() -> None:
    """Clear the per-user buckets so a single test's polling does
    not affect the next test's counter."""
    _user_bucket.clear()


def _escape_like(pattern: str) -> str:
    """Escape LIKE metacharacters so a user-supplied ``action_prefix``
    cannot inject wildcards. The brain uses backslash as the LIKE
    escape; we escape ``\\``, ``%``, ``_`` to ensure ``task.`` matches
    only literal ``task.`` and not ``task_`` (single-char wildcard)
    or ``tas%`` (multi-char wildcard). (v1.6 audit M16.)
    """
    return (
        pattern.replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )


class ActivityItem(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID | None
    project_slug: str | None
    user_id: uuid.UUID | None
    action: str
    target_type: str
    target_id: str | None
    result: str
    outcome: str | None
    metadata: dict[str, Any]
    source_ip: str | None
    occurred_at: datetime


class ActivityListResponse(BaseModel):
    items: list[ActivityItem]
    #: Cursor for the next-older page. String form
    #: ``"<iso_occurred_at>|<id>"``; pass to ``before_cursor`` to walk
    #: backwards. ``None`` when the current page is the last one.
    next_before_cursor: str | None
    #: Cursor for the newest row on this page. String form
    #: ``"<iso_occurred_at>|<id>"``; pass to ``since_cursor`` on the
    #: next poll to fetch only newly-written rows.
    newest_cursor: str | None


def _encode_cursor(row: AuditLog) -> str:
    """Format ``(occurred_at, id)`` as the wire cursor."""
    return f"{row.occurred_at.isoformat()}|{row.id}"


def _decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    """Parse the wire cursor. Raises ``HTTPException(422)`` on malformed
    input so an attacker probing the cursor parser does not get a 500.

    v1.6 Round 5 F11 fix: force UTC on a naive-datetime cursor so the
    Postgres `occurred_at` comparison (timezone-aware column) does not
    raise ``can't compare offset-naive and offset-aware`` at query
    time -- a hostile cursor like ``2026-05-13T10:00:00|<uuid>`` would
    otherwise produce a 500 the docstring promises won't happen.
    """
    from datetime import UTC
    try:
        iso_part, id_part = cursor.split("|", 1)
        dt = datetime.fromisoformat(iso_part)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return (dt, uuid.UUID(id_part))
    except (ValueError, AttributeError) as exc:
        raise HTTPException(
            status_code=422, detail="malformed cursor",
        ) from exc


def _slug_for(
    project_ids_to_slug: dict[uuid.UUID, str], pid: uuid.UUID | None,
) -> str | None:
    if pid is None:
        return None
    return project_ids_to_slug.get(pid)


@router.get("", response_model=ActivityListResponse)
async def list_activity(
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    session: "AsyncSession" = Depends(get_session),
    limit: int = Query(50, ge=1, le=200),
    since_cursor: str | None = Query(
        None,
        max_length=128,
        description=(
            "Return only rows newer than this cursor. Use for live "
            "polling; the response's ``newest_cursor`` is the next "
            "``since_cursor``. Format: ``<iso_occurred_at>|<uuid>``."
        ),
    ),
    before_cursor: str | None = Query(
        None,
        max_length=128,
        description=(
            "Return only rows older than this cursor. Use for "
            "backwards pagination; the response's "
            "``next_before_cursor`` is the next ``before_cursor``."
        ),
    ),
    action_prefix: str | None = Query(
        None,
        max_length=80,
        description="Literal action-name prefix filter (LIKE metachars escaped).",
    ),
    project_slug: str | None = Query(
        None,
        max_length=80,
        description="Constrain to a single project slug (must be in caller's accessible set).",
    ),
) -> ActivityListResponse:
    """List audit rows across every project the caller can see.

    Admins see every row including brain-wide rows (no project_id);
    non-admins see only rows whose project they hold a membership in.
    """
    # v1.6 audit H13: per-user rate limit (per worker process).
    # Include Retry-After per RFC 6585 so well-behaved clients
    # (the dashboard's TanStack Query infinite-query, Grafana
    # alerts, etc.) back off rather than hammering. (Round 2 M-8.)
    if not _rate_limit_check(str(user.id)):
        raise HTTPException(
            status_code=429,
            detail="activity feed rate limit exceeded (60/min per worker)",
            headers={"Retry-After": "60"},
        )

    accessible_project_ids: list[uuid.UUID] | None
    if user.is_admin:
        accessible_project_ids = None
    else:
        rows = await memberships.list_for_user(user.id)
        accessible_project_ids = [m.project_id for m in rows]
        if not accessible_project_ids:
            return ActivityListResponse(
                items=[],
                next_before_cursor=None,
                newest_cursor=None,
            )

    project_id_filter = accessible_project_ids
    if project_slug is not None:
        slug_lookup = await session.execute(
            select(Project).where(Project.slug == project_slug),
        )
        target = slug_lookup.scalar_one_or_none()
        if target is None:
            return ActivityListResponse(
                items=[],
                next_before_cursor=None,
                newest_cursor=None,
            )
        if (
            accessible_project_ids is not None
            and target.id not in accessible_project_ids
        ):
            return ActivityListResponse(
                items=[],
                next_before_cursor=None,
                newest_cursor=None,
            )
        project_id_filter = [target.id]

    # v1.6 audit C8: order by (occurred_at, id) because audit_log.id
    # is uuid4 (random); ordering by id alone reshuffles rows on
    # every page. The (occurred_at, id) tuple is monotonic and
    # stable across replicas; the secondary id key handles ties when
    # two rows share microsecond-precision timestamps.
    stmt = (
        select(AuditLog)
        .order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc())
        .limit(limit)
    )
    if project_id_filter is not None:
        # v1.6 Round 5 G fix: include the caller's OWN user-scoped
        # audit rows (e.g., their own MFA enroll / verify / recovery
        # actions, which have ``project_id IS NULL``). Otherwise the
        # activity feed silently hides the user's own MFA history --
        # the per-project audit page never showed it either, so this
        # is a UX gap, not a leak. The added clause says "row is in
        # an accessible project OR row belongs to me with no project".
        stmt = stmt.where(
            or_(
                AuditLog.project_id.in_(project_id_filter),
                and_(
                    AuditLog.project_id.is_(None),
                    AuditLog.user_id == user.id,
                ),
            ),
        )
    if since_cursor is not None:
        cur_ts, cur_id = _decode_cursor(since_cursor)
        # Rows STRICTLY NEWER than (cur_ts, cur_id).
        stmt = stmt.where(
            or_(
                AuditLog.occurred_at > cur_ts,
                and_(
                    AuditLog.occurred_at == cur_ts,
                    AuditLog.id > cur_id,
                ),
            ),
        )
    if before_cursor is not None:
        cur_ts, cur_id = _decode_cursor(before_cursor)
        # Rows STRICTLY OLDER than (cur_ts, cur_id).
        stmt = stmt.where(
            or_(
                AuditLog.occurred_at < cur_ts,
                and_(
                    AuditLog.occurred_at == cur_ts,
                    AuditLog.id < cur_id,
                ),
            ),
        )
    if action_prefix:
        # v1.6 audit M16: escape LIKE wildcards. Without this an
        # operator typing "%" or "_" in the filter could match
        # actions outside what they intended; an attacker probing
        # could enumerate action shapes by injecting wildcards.
        escaped = _escape_like(action_prefix)
        stmt = stmt.where(AuditLog.action.like(f"{escaped}%", escape="\\"))

    result = await session.execute(stmt)
    rows = list(result.scalars().all())

    if rows:
        project_ids = [r.project_id for r in rows if r.project_id is not None]
        project_lookup_result = await session.execute(
            select(Project.id, Project.slug).where(
                Project.id.in_(set(project_ids)),
            ),
        )
        project_slug_by_id: dict[uuid.UUID, str] = dict(
            project_lookup_result.all(),
        )
    else:
        project_slug_by_id = {}

    # v1.6 audit M15: ``source_ip`` is a privacy-sensitive field
    # that the per-project audit page already gates behind the
    # operator's project membership. The cross-project feed widened
    # the audience to every admin AND every multi-project member.
    # Strip ``source_ip`` for non-admins so the field's exposure
    # surface does not regress versus the per-project audit page.
    expose_source_ip = bool(user.is_admin)

    items = [
        ActivityItem(
            id=row.id,
            project_id=row.project_id,
            project_slug=_slug_for(project_slug_by_id, row.project_id),
            user_id=row.user_id,
            action=row.action,
            target_type=row.target_type,
            target_id=row.target_id,
            result=row.result,
            outcome=row.outcome,
            metadata=dict(row.audit_metadata or {}),
            source_ip=(
                str(row.source_ip) if (expose_source_ip and row.source_ip is not None) else None
            ),
            occurred_at=row.occurred_at,
        )
        for row in rows
    ]

    next_before_cursor = (
        _encode_cursor(rows[-1]) if len(rows) == limit else None
    )
    newest_cursor = _encode_cursor(rows[0]) if rows else None

    return ActivityListResponse(
        items=items,
        next_before_cursor=next_before_cursor,
        newest_cursor=newest_cursor,
    )
