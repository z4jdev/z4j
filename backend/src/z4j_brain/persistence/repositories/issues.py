"""Issues aggregation: group task failures by fingerprint.

An "issue" is a distinct failure fingerprint on a project. This repository
aggregates the ``tasks`` table (which carries a stable ``fingerprint`` set
when a task last failed, kept across a later recovery) into one row per
fingerprint: how many tasks hit it, how many are still failing vs
recovered, when it was first/last seen, which engines it spans, and a
representative exception + task name.

Pagination is an OPAQUE offset cursor. Distinct fingerprints per project are
few (one per bug class), so offset is robust + dialect-agnostic; the cursor
stays opaque so it can become a keyset later without an API change."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import and_, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from z4j_core.models.task import TaskState

from z4j_brain.persistence.models import Task

_MAX_LIMIT = 200


@dataclass
class IssueRow:
    fingerprint: str
    occurrences: int  # distinct tasks (task_ids) that hit this fingerprint
    open_count: int  # currently state=FAILURE
    recovered_count: int  # occurrences - open_count
    first_seen: datetime | None
    last_seen: datetime | None
    engine_count: int
    engines: list[str]
    sample_exception: str | None
    sample_task_name: str | None


def encode_issues_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(str(max(0, offset)).encode()).decode()


def decode_issues_cursor(cursor: str | None) -> int:
    if not cursor:
        return 0
    try:
        return max(0, int(base64.urlsafe_b64decode(cursor.encode()).decode()))
    except (ValueError, TypeError):
        return 0


class IssuesRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_issues(
        self,
        *,
        project_id: UUID,
        engine: str | None = None,
        since: datetime | None = None,
        status: str | None = None,  # "ongoing" | "recovered"
        cursor: str | None = None,
        limit: int = 50,
    ) -> tuple[list[IssueRow], str | None]:
        capped = min(max(1, limit), _MAX_LIMIT)
        offset = decode_issues_cursor(cursor)

        # Failure "seen" time: prefer last_failed_at (set on failure, kept
        # across recovery). finished_at is overwritten by a later recovery,
        # so using it would make an old failure that recovered recently look
        # recent. Fall back to finished_at/created_at for rows written before
        # last_failed_at existed (N-1 / pre-migration).
        seen_at = func.coalesce(Task.last_failed_at, Task.finished_at, Task.created_at)
        open_expr = func.sum(case((Task.state == TaskState.FAILURE, 1), else_=0))

        conds = [Task.project_id == project_id, Task.fingerprint.is_not(None)]
        if engine:
            conds.append(Task.engine == engine)
        if since:
            conds.append(seen_at >= since)

        agg = (
            select(
                Task.fingerprint.label("fingerprint"),
                func.count().label("occurrences"),
                open_expr.label("open_count"),
                func.min(seen_at).label("first_seen"),
                func.max(seen_at).label("last_seen"),
                func.count(func.distinct(Task.engine)).label("engine_count"),
                func.max(Task.exception).label("sample_exception"),
                func.max(Task.name).label("sample_task_name"),
            )
            .where(and_(*conds))
            .group_by(Task.fingerprint)
            .subquery()
        )

        stmt = select(agg)
        if status == "ongoing":
            stmt = stmt.where(agg.c.open_count > 0)
        elif status == "recovered":
            stmt = stmt.where(agg.c.open_count == 0)
        stmt = (
            stmt.order_by(agg.c.last_seen.desc(), agg.c.fingerprint.desc())
            .offset(offset)
            .limit(capped + 1)  # +1 to detect a next page
        )

        rows = (await self.session.execute(stmt)).mappings().all()
        has_more = len(rows) > capped
        rows = rows[:capped]

        engines_by_fp = await self._engines_for(
            project_id=project_id,
            fingerprints=[r["fingerprint"] for r in rows],
            engine=engine,
            since=since,
        )

        issues = [
            IssueRow(
                fingerprint=r["fingerprint"],
                occurrences=int(r["occurrences"]),
                open_count=int(r["open_count"] or 0),
                recovered_count=int(r["occurrences"]) - int(r["open_count"] or 0),
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
                engine_count=int(r["engine_count"]),
                engines=engines_by_fp.get(r["fingerprint"], []),
                sample_exception=r["sample_exception"],
                sample_task_name=r["sample_task_name"],
            )
            for r in rows
        ]
        next_cursor = encode_issues_cursor(offset + capped) if has_more else None
        return issues, next_cursor

    async def _engines_for(
        self,
        *,
        project_id: UUID,
        fingerprints: list[str],
        engine: str | None = None,
        since: datetime | None = None,
    ) -> dict[str, list[str]]:
        """One query for the distinct engines of the page's fingerprints
        (avoids a non-portable DISTINCT string-agg in the main query).

        MUST apply the SAME engine + time-window filters as the main
        aggregation, or the ``engines`` list contradicts ``engine_count``
        (e.g. ``?engine=celery`` would still list ``rq``) and leaks
        out-of-window engines."""
        if not fingerprints:
            return {}
        conds = [
            Task.project_id == project_id,
            Task.fingerprint.in_(fingerprints),
        ]
        if engine:
            conds.append(Task.engine == engine)
        if since:
            conds.append(
                func.coalesce(Task.last_failed_at, Task.finished_at, Task.created_at) >= since,
            )
        result = await self.session.execute(
            select(Task.fingerprint, Task.engine)
            .where(*conds)
            .group_by(Task.fingerprint, Task.engine)
            .order_by(Task.fingerprint, Task.engine),
        )
        out: dict[str, list[str]] = {}
        for fp, eng in result.all():
            out.setdefault(fp, []).append(eng)
        return out


__all__ = [
    "IssueRow",
    "IssuesRepository",
    "decode_issues_cursor",
    "encode_issues_cursor",
]
