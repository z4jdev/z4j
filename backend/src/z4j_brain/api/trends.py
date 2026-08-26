"""``/api/v1/projects/{slug}/trends`` REST router.

Time-bucketed task outcome trends for the Trends dashboard page.

Design note: v1 computes the rollup on-demand by GROUP BY a
bucketed ``finished_at``. A persistent ``metrics_rollup`` table
with a periodic aggregator worker is a pure perf optimization -
it would not change this endpoint's shape - and is deferred to a
later minor release. The bucketing call is dialect-aware so the
same endpoint runs on both SQLite (dev) and PostgreSQL (prod).

Request shape:

    GET /api/v1/projects/{slug}/trends?window=24h&bucket=1h

``window`` (one of 1h, 6h, 24h, 72h, 7d) sets the look-back.
``bucket`` (one of 1m, 5m, 15m, 1h, 1d) sets the granularity.
The window:bucket pair is validated to stay under 500 buckets
per response.

Response:

    {
      "window": "24h",
      "bucket": "1h",
      "series": [
        {"t": "2026-04-15T10:00:00Z",
         "success": 120, "failure": 2, "retry": 0, "revoked": 0,
         "total": 122, "avg_runtime_ms": 843},
        ...
      ]
    }
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from z4j_brain.api.deps import (
    get_current_user,
    get_membership_repo,
    get_project_repo,
    get_session,
)
from z4j_brain.persistence.enums import ProjectRole, TaskState
from z4j_brain.persistence.models import Task

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.persistence.models import User
    from z4j_brain.persistence.repositories import (
        MembershipRepository,
        ProjectRepository,
    )


router = APIRouter(prefix="/projects/{slug}/trends", tags=["trends"])


_WINDOW_SECONDS = {
    "1h": 3_600,
    "6h": 21_600,
    "24h": 86_400,
    "72h": 259_200,
    "7d": 604_800,
}
_BUCKET_SECONDS = {
    "1m": 60,
    "5m": 300,
    "15m": 900,
    "1h": 3_600,
    "1d": 86_400,
}


class TrendBucket(BaseModel):
    t: datetime  # UTC-aware ISO-8601 bucket start timestamp
    success: int = 0
    failure: int = 0
    retry: int = 0
    revoked: int = 0
    total: int = 0
    avg_runtime_ms: int | None = None


class TrendsResponse(BaseModel):
    window: str
    bucket: str
    series: list[TrendBucket]


def _bucket_expr(session: AsyncSession, bucket_seconds: int):
    """Return a dialect-appropriate bucket-start expression for
    ``Task.finished_at``.

    On Postgres, computes ``to_timestamp(floor(epoch / N) * N)``;
    on SQLite, uses the same epoch-floor approach via
    ``strftime('%s', ...)``.
    PostgreSQL returns a timezone-aware timestamp. SQLite's
    ``datetime`` function returns a naive UTC value; the response
    materializer below explicitly attaches UTC before serialization.
    """
    from sqlalchemy import Integer, cast

    # ``AsyncSession.bind`` goes through a greenlet; ``sync_session.bind``
    # is plain synchronous attribute access.
    bind = session.sync_session.bind
    dialect = bind.dialect.name if bind else ""
    if dialect == "postgresql":
        # Convert to epoch seconds, floor-divide by bucket, multiply
        # back, convert to timestamp. Works for any bucket size.
        epoch = func.extract("epoch", Task.finished_at)
        return func.to_timestamp(
            func.floor(epoch / bucket_seconds) * bucket_seconds,
        )
    # SQLite path. ``strftime('%s', col)`` returns epoch seconds as
    # text; cast to Integer, floor-divide (SQLite ``/`` on ints is
    # integer division), then build a timestamp back via
    # ``datetime(..., 'unixepoch')``.
    # Use floor-division (``//``) not ``/`` - SQLAlchemy's ``/``
    # emits true division (``x / (N + 0.0)``) which defeats bucketing.
    epoch = cast(func.strftime("%s", Task.finished_at), Integer)
    bucketed_epoch = (epoch // bucket_seconds) * bucket_seconds
    return func.datetime(bucketed_epoch, "unixepoch")


def _normalize_bucket_timestamp(value: datetime | str) -> datetime:
    """Return a bucket timestamp as an aware UTC ``datetime``.

    PostgreSQL returns the ``to_timestamp`` expression as an aware
    ``datetime``. SQLite returns its ``datetime`` expression as a raw
    ``YYYY-MM-DD HH:MM:SS`` string. Normalizing both shapes here keeps the
    public response identical across the supported database dialects.
    """
    if isinstance(value, datetime):
        timestamp = value
    else:
        raw = str(value)
        if raw.endswith("Z"):
            raw = f"{raw[:-1]}+00:00"
        timestamp = datetime.fromisoformat(raw)

    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=UTC)
    return timestamp.astimezone(UTC)


@router.get("", response_model=TrendsResponse)
async def get_trends(
    slug: str,
    window: Literal["1h", "6h", "24h", "72h", "7d"] = Query("24h"),
    bucket: Literal["1m", "5m", "15m", "1h", "1d"] = Query("1h"),
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    db_session: AsyncSession = Depends(get_session),
) -> TrendsResponse:
    """Return per-bucket task outcome counts + avg runtime.

    Only tasks with a non-null ``finished_at`` inside ``window`` are
    included; in-flight (pending/started) tasks are excluded by
    design - trend charts show completed work.
    """
    from z4j_brain.domain.policy_engine import PolicyEngine

    window_secs = _WINDOW_SECONDS[window]
    bucket_secs = _BUCKET_SECONDS[bucket]
    if window_secs // bucket_secs > 500:
        # Protect the endpoint from a 7d/1m combo = 10_080 buckets.
        raise HTTPException(
            status_code=400,
            detail=(
                f"window/bucket ratio too fine ({window}/{bucket}); max 500 buckets per response"
            ),
        )

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project=project,
        min_role=ProjectRole.VIEWER,
    )

    cutoff = datetime.now(UTC) - timedelta(seconds=window_secs)
    b_expr = _bucket_expr(db_session, bucket_secs).label("b")

    rows = (
        await db_session.execute(
            select(
                b_expr,
                Task.state,
                func.count(Task.id).label("cnt"),
                func.sum(Task.runtime_ms).label("runtime_sum"),
                func.count(Task.runtime_ms).label("runtime_cnt"),
            )
            .where(
                Task.project_id == project.id,
                Task.finished_at.is_not(None),
                Task.finished_at >= cutoff,
                Task.state.in_(
                    [
                        TaskState.SUCCESS,
                        TaskState.FAILURE,
                        TaskState.RETRY,
                        TaskState.REVOKED,
                    ]
                ),
            )
            .group_by(b_expr, Task.state)
            .order_by(b_expr),
        )
    ).all()

    # Materialize buckets in a dict keyed by one normalized UTC datetime.
    buckets: dict[datetime, TrendBucket] = {}
    running_runtime_sum: dict[datetime, int] = {}
    running_runtime_count: dict[datetime, int] = {}
    for b, state, cnt, runtime_sum, runtime_cnt in rows:
        key = _normalize_bucket_timestamp(b)
        bucket_row = buckets.setdefault(key, TrendBucket(t=key))
        state_name = state.value if hasattr(state, "value") else str(state)
        setattr(bucket_row, state_name, int(cnt))
        bucket_row.total += int(cnt)
        non_null_runtime_count = int(runtime_cnt)
        if runtime_sum is not None and non_null_runtime_count > 0:
            running_runtime_sum[key] = running_runtime_sum.get(key, 0) + int(runtime_sum)
            running_runtime_count[key] = running_runtime_count.get(key, 0) + non_null_runtime_count

    for key, bucket_row in buckets.items():
        n = running_runtime_count.get(key, 0)
        if n > 0:
            total_runtime = running_runtime_sum[key]
            bucket_row.avg_runtime_ms = (
                total_runtime // n if total_runtime >= 0 else -((-total_runtime) // n)
            )

    series = sorted(buckets.values(), key=lambda row: row.t)
    return TrendsResponse(window=window, bucket=bucket, series=series)


__all__ = ["TrendBucket", "TrendsResponse", "router"]
