"""``/api/v1/home`` REST router - cross-project Home dashboard.

Two endpoints, both available to any authenticated user:

- ``GET /home/summary``
    One JSON blob powering the home dashboard: user info, per-project
    cards (tasks/failures/agents/workers/stuck commands), aggregate
    KPIs across everything the user can see, and an "attention list"
    of things that need operator eyes.

- ``GET /home/recent-failures``
    Recent ``task.failed`` events across every project the user is a
    member of (or the configured first page of projects if the user is
    a global admin), with keyset pagination on ``(occurred_at, id)``.

Both endpoints scope to the caller's memberships - a non-admin user
only sees projects they have a row for in ``memberships``. Global
admins are bounded by ``Settings.admin_project_list_cap`` (configured
as ``Z4J_ADMIN_PROJECT_LIST_CAP``; default 500) so one request cannot
materialize an unbounded tenant-wide dashboard. Aggregate queries are
grouped over that visible project set; their database and response cost
therefore grows with the number of visible rows and matching events.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy import and_, case, func, or_, select

from z4j_brain.api.deps import (
    get_current_user,
    get_membership_repo,
    get_project_repo,
    get_session,
    get_settings,
)
from z4j_brain.persistence.enums import (
    AgentState,
    CommandStatus,
    WorkerState,
)
from z4j_brain.persistence.models import (
    Agent,
    Command,
    Event,
    Project,
    Worker,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.persistence.models import User
    from z4j_brain.persistence.repositories import (
        MembershipRepository,
        ProjectRepository,
    )
    from z4j_brain.settings import Settings


router = APIRouter(prefix="/home", tags=["home"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ProjectCard(BaseModel):
    id: uuid.UUID
    slug: str
    name: str
    environment: str
    role: str | None
    tasks_24h: int
    failures_24h: int
    failure_rate_24h: float
    workers_online: int
    workers_total: int
    agents_online: int
    agents_total: int
    stuck_commands: int
    last_activity_at: datetime | None
    health: str


class AttentionItem(BaseModel):
    kind: str
    severity: str
    project_id: uuid.UUID
    project_slug: str
    project_name: str
    message: str
    count: int | None = None


class Aggregate(BaseModel):
    tasks_24h: int
    failures_24h: int
    failure_rate_24h: float
    workers_online: int
    workers_total: int
    agents_online: int
    agents_total: int
    stuck_commands: int


class UserMini(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str | None
    is_admin: bool


class HomeSummaryPublic(BaseModel):
    user: UserMini
    aggregate: Aggregate
    projects: list[ProjectCard]
    attention: list[AttentionItem]


class RecentFailurePublic(BaseModel):
    id: uuid.UUID
    occurred_at: datetime
    project_id: uuid.UUID
    project_slug: str
    project_name: str
    # Engine that produced this failure (``celery``, ``rq``,
    # ``dramatiq``, ...). Required for the dashboard's deep-link -
    # without it every non-Celery failure in the Home card would
    # 404 when clicked. See docs/MULTI_ENGINE_VERIFICATION_2026Q2.md
    # BUG-1.
    engine: str
    task_id: str
    task_name: str | None
    worker: str | None
    exception: str | None
    priority: str


class RecentFailuresPublic(BaseModel):
    items: list[RecentFailurePublic]
    #: Opaque cursor for the next page. Encoded as
    #: ``"<iso8601>|<uuid_hex>"`` so the keyset spans
    #: ``(occurred_at, id)`` - without the id tiebreaker, multiple
    #: failures at the exact same millisecond (replay storms,
    #: batch retries) straddle page boundaries and silently drop
    #: or duplicate.
    next_cursor: str | None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _visible_projects(
    *,
    user: User,
    memberships: MembershipRepository,
    projects_repo: ProjectRepository,
    admin_project_cap: int,
    bound_slug: str | None = None,
) -> tuple[list[Project], dict[uuid.UUID, str | None]]:
    """Return the list of projects the user can see and a map
    ``project_id -> role`` (role is ``None`` for global admins viewing
    projects they don't belong to).

    Archived (``is_active=False``) projects are filtered out - they
    shouldn't appear on the Home dashboard. For global admins, the
    repository query is capped at ``admin_project_cap`` before that
    filtering, so this is a bounded first page rather than an exhaustive
    tenant-wide project list.

    When ``bound_slug`` is non-None (caller authenticated via a
    project-scoped Bearer key), the returned list is filtered to
    that single project only - without this, a project-A-bound
    key would see every project its owner has access to via the
    home / recent-failures aggregates.
    """
    if user.is_admin:
        # Global admin: the configured first page of projects, retaining
        # active projects and their actual role where one exists (None
        # otherwise). The cap is a deliberate request-memory/DB guardrail.
        admin_rows = await projects_repo.list(limit=admin_project_cap, offset=0)
        active = [project for project in admin_rows if project.is_active]
        member_rows = await memberships.list_for_user(user.id)
        role_map: dict[uuid.UUID, str | None] = {
            m.project_id: m.role.value if hasattr(m.role, "value") else str(m.role)
            for m in member_rows
        }
        role_by_project: dict[uuid.UUID, str | None] = {p.id: role_map.get(p.id) for p in active}
        if bound_slug is not None:
            active = [p for p in active if p.slug == bound_slug]
            role_by_project = {p.id: role_by_project.get(p.id) for p in active}
        return active, role_by_project

    member_rows = await memberships.list_for_user(user.id)
    if not member_rows:
        return [], {}
    role_by_project = {
        m.project_id: m.role.value if hasattr(m.role, "value") else str(m.role) for m in member_rows
    }
    # Use one IN-query for the member's projects instead of one round trip
    # per membership. Query and materialisation cost still scales with the
    # membership set; this only bounds the number of round trips.
    from sqlalchemy import select as _select

    member_projects = (
        (
            await projects_repo.session.execute(
                _select(Project).where(
                    Project.id.in_(role_by_project.keys()),
                    Project.is_active.is_(True),
                ),
            )
        )
        .scalars()
        .all()
    )
    visible = list(member_projects)
    if bound_slug is not None:
        visible = [p for p in visible if p.slug == bound_slug]
        role_by_project = {p.id: role_by_project.get(p.id) for p in visible}
    return visible, role_by_project


def _bounded_failure_rate(*, tasks_24h: int, failures_24h: int) -> float:
    """Return a bounded failure signal for the rolling event window.

    ``task.failed`` can fall inside the window while its matching
    ``task.received`` falls outside it, so the two counters are not a strict
    ratio denominator/numerator pair. Any observed failure with zero receives
    must remain visible as the maximum bounded signal rather than being
    reported as a healthy-looking zero. Values above 100% are likewise capped.
    """
    if failures_24h <= 0:
        return 0.0
    if tasks_24h <= 0:
        return 1.0
    return min(failures_24h / tasks_24h, 1.0)


def _failure_attention_severity(
    *,
    tasks_24h: int,
    failures_24h: int,
    failure_rate_24h: float,
) -> str | None:
    """Choose attention severity without hiding a zero-denominator failure.

    Ordinary ratios retain the existing ``>20``-task noise floor. A failure
    with no receive events is a distinct, severe signal: it both degrades the
    project health and emits a critical attention item so the dashboard can
    explain the card state.
    """
    if failures_24h > 0 and tasks_24h == 0:
        return "critical"
    if failure_rate_24h <= 0.05 or tasks_24h <= 20:
        return None
    return "critical" if failure_rate_24h > 0.20 else "warning"


def _failure_attention_message(
    *,
    tasks_24h: int,
    failures_24h: int,
    failure_rate_24h: float,
) -> str:
    """Describe the evidence behind a high-failure attention item."""
    if tasks_24h == 0:
        return (
            f"{failures_24h} failure(s) with no task.received events (24h)"
            if failures_24h != 1
            else "1 failure with no task.received events (24h)"
        )
    return f"Failure rate {failure_rate_24h:.1%} over {tasks_24h} tasks (24h)"


def _compute_health(
    *,
    failure_rate_24h: float,
    stuck_commands: int,
    agents_online: int,
    agents_total: int,
    tasks_24h: int,
    workers_online: int,
) -> str:
    """Return the health label for one project card.

    Rules (checked in order):
      - offline  : at least one agent exists, and every agent is
                   offline.
      - degraded : failure rate > 5% OR stuck commands > 0 OR some
                   (but not all) agents offline.
      - idle     : no tasks in the last 24h AND no online workers.
      - healthy  : otherwise.
    """
    if agents_total > 0 and agents_online == 0:
        return "offline"
    if (
        failure_rate_24h > 0.05
        or stuck_commands > 0
        or (agents_total > 0 and agents_online < agents_total)
    ):
        return "degraded"
    if tasks_24h == 0 and workers_online == 0:
        return "idle"
    return "healthy"


def _severity_rank(severity: str) -> int:
    return {"critical": 0, "warning": 1}.get(severity, 2)


# ---------------------------------------------------------------------------
# GET /home/summary
# ---------------------------------------------------------------------------


@router.get("/summary", response_model=HomeSummaryPublic)
async def get_summary(  # noqa: PLR0915  home summary aggregation
    request: Request,
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects_repo: ProjectRepository = Depends(get_project_repo),
    db_session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> HomeSummaryPublic:
    """Return the bounded project set the SPA renders as Home cards.

    Non-admins are scoped to their active memberships. Global-admin results
    are bounded by ``Settings.admin_project_list_cap``
    (``Z4J_ADMIN_PROJECT_LIST_CAP``, default 500); this endpoint is not an
    exhaustive tenant-wide project export.
    """
    bound_slug: str | None = getattr(
        request.state,
        "api_key_project_slug",
        None,
    )
    visible, role_by_project = await _visible_projects(
        user=user,
        memberships=memberships,
        projects_repo=projects_repo,
        admin_project_cap=settings.admin_project_list_cap,
        bound_slug=bound_slug,
    )

    user_mini = UserMini(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        is_admin=user.is_admin,
    )

    if not visible:
        return HomeSummaryPublic(
            user=user_mini,
            aggregate=Aggregate(
                tasks_24h=0,
                failures_24h=0,
                failure_rate_24h=0.0,
                workers_online=0,
                workers_total=0,
                agents_online=0,
                agents_total=0,
                stuck_commands=0,
            ),
            projects=[],
            attention=[],
        )

    project_ids = [p.id for p in visible]
    now = datetime.now(UTC)
    cutoff_24h = now - timedelta(hours=24)

    # ------------------------------------------------------------------
    # Event aggregates per project: tasks_24h and failures_24h.
    # ------------------------------------------------------------------
    task_stats: dict[uuid.UUID, tuple[int, int]] = {}
    event_rows = (
        await db_session.execute(
            select(
                Event.project_id,
                func.sum(
                    case((Event.kind == "task.received", 1), else_=0),
                ).label("tasks_24h"),
                func.sum(
                    case((Event.kind == "task.failed", 1), else_=0),
                ).label("failures_24h"),
            )
            .where(
                Event.project_id.in_(project_ids),
                Event.occurred_at >= cutoff_24h,
            )
            .group_by(Event.project_id),
        )
    ).all()
    for row in event_rows:
        task_stats[row.project_id] = (int(row.tasks_24h or 0), int(row.failures_24h or 0))

    # last_activity_at is MAX(occurred_at) within a rolling 30-day window,
    # deliberately distinct from the 24-hour task counters above. Bounding
    # the aggregate avoids scanning every events partition on every summary
    # load. Projects with no event in the window return null and the card
    # renders "no recent activity".
    cutoff_activity = now - timedelta(days=30)
    last_activity: dict[uuid.UUID, datetime | None] = {}
    last_rows = (
        await db_session.execute(
            select(
                Event.project_id,
                func.max(Event.occurred_at).label("last_activity_at"),
            )
            .where(
                Event.project_id.in_(project_ids),
                Event.occurred_at >= cutoff_activity,
            )
            .group_by(Event.project_id),
        )
    ).all()
    for row in last_rows:
        last_activity[row.project_id] = row.last_activity_at

    # ------------------------------------------------------------------
    # Agents online/total per project.
    # ------------------------------------------------------------------
    agents_stats: dict[uuid.UUID, tuple[int, int]] = {}
    agent_rows = (
        await db_session.execute(
            select(
                Agent.project_id,
                func.sum(
                    case((Agent.state == AgentState.ONLINE, 1), else_=0),
                ).label("online"),
                func.count(Agent.id).label("total"),
            )
            .where(
                Agent.project_id.in_(project_ids),
                Agent.revoked_at.is_(None),
            )
            .group_by(Agent.project_id),
        )
    ).all()
    for row in agent_rows:
        agents_stats[row.project_id] = (int(row.online or 0), int(row.total or 0))

    # ------------------------------------------------------------------
    # Workers online/total per project.
    # ------------------------------------------------------------------
    workers_stats: dict[uuid.UUID, tuple[int, int]] = {}
    worker_rows = (
        await db_session.execute(
            select(
                Worker.project_id,
                func.sum(
                    case((Worker.state == WorkerState.ONLINE, 1), else_=0),
                ).label("online"),
                func.count(Worker.id).label("total"),
            )
            .where(Worker.project_id.in_(project_ids))
            .group_by(Worker.project_id),
        )
    ).all()
    for row in worker_rows:
        workers_stats[row.project_id] = (int(row.online or 0), int(row.total or 0))

    # ------------------------------------------------------------------
    # Stuck commands per project: dispatched + past their timeout_at.
    # ------------------------------------------------------------------
    stuck_stats: dict[uuid.UUID, int] = {}
    stuck_rows = (
        await db_session.execute(
            select(
                Command.project_id,
                func.count(Command.id).label("stuck"),
            )
            .where(
                Command.project_id.in_(project_ids),
                Command.status == CommandStatus.DISPATCHED,
                Command.timeout_at < now,
            )
            .group_by(Command.project_id),
        )
    ).all()
    for row in stuck_rows:
        stuck_stats[row.project_id] = int(row.stuck or 0)

    # ------------------------------------------------------------------
    # Build per-project cards + aggregate + attention items.
    # ------------------------------------------------------------------
    cards: list[ProjectCard] = []
    attention: list[AttentionItem] = []

    agg_tasks_24h = 0
    agg_failures_24h = 0
    agg_workers_online = 0
    agg_workers_total = 0
    agg_agents_online = 0
    agg_agents_total = 0
    agg_stuck = 0

    for project in visible:
        tasks_24h, failures_24h = task_stats.get(project.id, (0, 0))
        agents_online, agents_total = agents_stats.get(project.id, (0, 0))
        workers_online, workers_total = workers_stats.get(project.id, (0, 0))
        stuck = stuck_stats.get(project.id, 0)
        last_at = last_activity.get(project.id)

        failure_rate = _bounded_failure_rate(
            tasks_24h=tasks_24h,
            failures_24h=failures_24h,
        )
        health = _compute_health(
            failure_rate_24h=failure_rate,
            stuck_commands=stuck,
            agents_online=agents_online,
            agents_total=agents_total,
            tasks_24h=tasks_24h,
            workers_online=workers_online,
        )

        cards.append(
            ProjectCard(
                id=project.id,
                slug=project.slug,
                name=project.name,
                environment=project.environment,
                role=role_by_project.get(project.id),
                tasks_24h=tasks_24h,
                failures_24h=failures_24h,
                failure_rate_24h=failure_rate,
                workers_online=workers_online,
                workers_total=workers_total,
                agents_online=agents_online,
                agents_total=agents_total,
                stuck_commands=stuck,
                last_activity_at=last_at,
                health=health,
            ),
        )

        agg_tasks_24h += tasks_24h
        agg_failures_24h += failures_24h
        agg_workers_online += workers_online
        agg_workers_total += workers_total
        agg_agents_online += agents_online
        agg_agents_total += agents_total
        agg_stuck += stuck

        # ------------------------------------------------------------------
        # Attention items (one per applicable rule per project).
        # ------------------------------------------------------------------
        # Agents offline - one item covers both "all offline" and
        # "partial offline". Critical when no agents are online at all.
        if agents_total > 0 and agents_online < agents_total:
            offline_count = agents_total - agents_online
            if agents_online == 0:
                msg = (
                    f"All {agents_total} agent(s) offline" if agents_total != 1 else "Agent offline"
                )
            else:
                msg = f"{offline_count} of {agents_total} agents offline"
            attention.append(
                AttentionItem(
                    kind="agent_offline",
                    severity="critical" if agents_online == 0 else "warning",
                    project_id=project.id,
                    project_slug=project.slug,
                    project_name=project.name,
                    message=msg,
                    count=offline_count,
                ),
            )

        # Ordinary high rates retain the >20-task noise floor. A failure
        # with no receives is handled as a separate critical signal because
        # suppressing it would leave a degraded card with no explanation.
        failure_severity = _failure_attention_severity(
            tasks_24h=tasks_24h,
            failures_24h=failures_24h,
            failure_rate_24h=failure_rate,
        )
        if failure_severity is not None:
            attention.append(
                AttentionItem(
                    kind="high_failure_rate",
                    severity=failure_severity,
                    project_id=project.id,
                    project_slug=project.slug,
                    project_name=project.name,
                    message=_failure_attention_message(
                        tasks_24h=tasks_24h,
                        failures_24h=failures_24h,
                        failure_rate_24h=failure_rate,
                    ),
                    count=failures_24h,
                ),
            )

        # Stuck commands - dispatched frames whose timeout_at is in
        # the past. Always warning; the CommandTimeoutWorker should
        # be chasing them down, so a sustained count is a signal.
        if stuck > 0:
            attention.append(
                AttentionItem(
                    kind="stuck_commands",
                    severity="warning",
                    project_id=project.id,
                    project_slug=project.slug,
                    project_name=project.name,
                    message=(
                        f"{stuck} stuck command(s) past timeout"
                        if stuck != 1
                        else "1 stuck command past timeout"
                    ),
                    count=stuck,
                ),
            )

        # TODO(metrics): could emit a per-project gauge for each
        # attention kind so Prometheus can alert without polling
        # this endpoint. Out of scope for the initial build.

    # Sort attention: critical first, then warning, then by project name
    # so the ordering is stable across refreshes.
    attention.sort(key=lambda a: (_severity_rank(a.severity), a.project_name))

    # Keep cards in a deterministic order too - by name ascending.
    cards.sort(key=lambda c: c.name)

    agg_failure_rate = _bounded_failure_rate(
        tasks_24h=agg_tasks_24h,
        failures_24h=agg_failures_24h,
    )

    return HomeSummaryPublic(
        user=user_mini,
        aggregate=Aggregate(
            tasks_24h=agg_tasks_24h,
            failures_24h=agg_failures_24h,
            failure_rate_24h=agg_failure_rate,
            workers_online=agg_workers_online,
            workers_total=agg_workers_total,
            agents_online=agg_agents_online,
            agents_total=agg_agents_total,
            stuck_commands=agg_stuck,
        ),
        projects=cards,
        attention=attention,
    )


# ---------------------------------------------------------------------------
# GET /home/recent-failures
# ---------------------------------------------------------------------------


def _truncate(value: str | None, limit: int = 500) -> str | None:
    if value is None:
        return None
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "\u2026"  # ellipsis


def _encode_recent_failures_cursor(when: datetime, event_id: uuid.UUID) -> str:
    """Encode a (occurred_at, id) cursor for the recent-failures feed."""
    return f"{when.isoformat()}|{event_id.hex}"


def _decode_recent_failures_cursor(
    raw: str | None,
) -> tuple[datetime | None, uuid.UUID | None]:
    """Inverse of :func:`_encode_recent_failures_cursor`.

    Returns ``(None, None)`` for any unparseable input - the
    handler then treats it as "no cursor" instead of erroring,
    which matches the prior datetime-only behaviour.
    """
    if not raw or "|" not in raw:
        return None, None
    iso, _, hex_id = raw.partition("|")
    try:
        when = datetime.fromisoformat(iso)
        event_id = uuid.UUID(hex=hex_id)
    except (ValueError, AttributeError):
        return None, None
    return when, event_id


@router.get("/recent-failures", response_model=RecentFailuresPublic)
async def get_recent_failures(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects_repo: ProjectRepository = Depends(get_project_repo),
    db_session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> RecentFailuresPublic:
    """Recent ``task.failed`` events across every visible project.

    Non-admin visibility follows active project memberships. Global-admin
    project visibility is bounded by ``Settings.admin_project_list_cap``
    (``Z4J_ADMIN_PROJECT_LIST_CAP``, default 500), just like Home summary.

    Keyset pagination on ``(occurred_at, id)`` - the second element
    is required to break ties when multiple failures share an exact
    millisecond (replay storms, batch retries). Without it the page
    boundary silently drops or duplicates rows. The cursor is
    encoded as ``"<iso8601>|<uuid_hex>"``.
    """
    bound_slug: str | None = getattr(
        request.state,
        "api_key_project_slug",
        None,
    )
    visible, _role_by_project = await _visible_projects(
        user=user,
        memberships=memberships,
        projects_repo=projects_repo,
        admin_project_cap=settings.admin_project_list_cap,
        bound_slug=bound_slug,
    )
    if not visible:
        return RecentFailuresPublic(items=[], next_cursor=None)

    project_ids = [p.id for p in visible]
    project_by_id = {p.id: p for p in visible}

    cursor_dt, cursor_id = _decode_recent_failures_cursor(cursor)

    where_conds: list[Any] = [
        Event.project_id.in_(project_ids),
        Event.kind == "task.failed",
    ]
    if cursor_dt is not None and cursor_id is not None:
        # Strict-tuple keyset: (occurred_at, id) lexicographically
        # less than the cursor pair.
        where_conds.append(
            or_(
                Event.occurred_at < cursor_dt,
                and_(
                    Event.occurred_at == cursor_dt,
                    Event.id < cursor_id,
                ),
            ),
        )

    rows = (
        (
            await db_session.execute(
                select(Event)
                .where(and_(*where_conds))
                .order_by(Event.occurred_at.desc(), Event.id.desc())
                .limit(limit + 1),
            )
        )
        .scalars()
        .all()
    )

    next_cursor: str | None = None
    if len(rows) > limit:
        # B10: keyset next-page uses a STRICT ``< cursor`` predicate, so the
        # cursor must be the LAST RETURNED row -- not the trimmed overflow
        # row. Encoding the overflow row (rows[limit]) excluded it from page
        # 1 (trimmed) AND page 2 (strictly-less-than), silently dropping one
        # failure per page boundary. Trim first, then anchor on rows[-1].
        # (Same fix already applied to notifications.py / user_notifications.py.)
        rows = rows[:limit]
        last = rows[-1]
        next_cursor = _encode_recent_failures_cursor(
            last.occurred_at,
            last.id,
        )

    items: list[RecentFailurePublic] = []
    for ev in rows:
        project = project_by_id.get(ev.project_id)
        if project is None:
            # Defensive: should never happen because project_ids was
            # derived from visible, but skip silently if it does
            # rather than leak data the user can't see.
            continue
        payload = ev.payload or {}
        items.append(
            RecentFailurePublic(
                id=ev.id,
                occurred_at=ev.occurred_at,
                project_id=project.id,
                project_slug=project.slug,
                project_name=project.name,
                engine=ev.engine,
                task_id=ev.task_id,
                task_name=payload.get("task_name") or payload.get("name"),
                worker=payload.get("worker") or payload.get("worker_name"),
                exception=_truncate(payload.get("exception"), 500),
                priority=str(payload.get("priority") or "normal"),
            ),
        )

    return RecentFailuresPublic(items=items, next_cursor=next_cursor)


__all__ = [
    "Aggregate",
    "AttentionItem",
    "HomeSummaryPublic",
    "ProjectCard",
    "RecentFailurePublic",
    "RecentFailuresPublic",
    "UserMini",
    "router",
]
