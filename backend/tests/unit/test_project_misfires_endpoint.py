"""``GET /projects/{slug}/schedules/misfires`` (project-wide misfires).

The VIEWER-accessible projection of every ``scheduler.misfire_detected``
audit row in a project, spanning ALL its schedules. Proves: a VIEWER can
read; the rows span multiple schedules with each carrying its own
``schedule_id``; the newest row is first; the audit metadata maps onto
the response; a non-member is refused (404 -- ``require_member`` returns
404, not 403, for non-members by design, to keep project slugs
non-enumerable, exactly like the per-schedule endpoint); a project with
no misfires returns [].

These run against a MIGRATED database rather than a create_all() one. The
Boundary-D guards that refuse a direct INSERT into ``schedules`` and the
Boundary-F chain that authenticates every audit row both live in
migrations, so a create_all() schema refuses nothing and cannot show what
an operator's database does to this endpoint's seed data.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.auth.csrf import csrf_cookie_name
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.enums import ProjectRole, ScheduleKind
from z4j_brain.persistence.models import (
    Membership,
    Project,
    Session,
    User,
)
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
)
from z4j_brain.settings import Settings


@pytest.fixture
def settings(migrated_db_url: str, migrated_audit_chain_secret: str) -> Settings:
    return Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        # A migrated database has Boundary F activated, so it refuses an audit
        # row that carries no chain authentication. The misfire rows this file
        # seeds are audit rows, so without the key there is nothing to read.
        audit_chain_secret=migrated_audit_chain_secret,  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        login_min_duration_ms=10,
        registry_backend="local",
        metrics_public=True,
        disable_spa_fallback=True,
    )


@pytest.fixture
async def brain_app(settings: Settings):
    engine = create_async_engine(settings.database_url)
    app = create_app(settings, engine=engine)
    yield app
    await engine.dispose()


async def _seed(*, settings: Settings, brain_app, with_misfires: bool = True) -> dict:
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    # A second authenticated user with NO membership on the project.
    nonmember_id = uuid.uuid4()
    nonmember_session_id = uuid.uuid4()
    csrf = secrets.token_urlsafe(32)

    async with db.session() as s:
        s.add_all(
            [
                Project(id=project_id, slug="default", name="Default"),
                User(
                    id=user_id,
                    email=f"u-{uuid.uuid4().hex[:8]}@example.com",
                    password_hash=hasher.hash("correct horse battery staple 9"),
                    is_admin=False,
                    is_active=True,
                ),
                User(
                    id=nonmember_id,
                    email=f"n-{uuid.uuid4().hex[:8]}@example.com",
                    password_hash=hasher.hash("correct horse battery staple 9"),
                    is_admin=False,
                    is_active=True,
                ),
            ]
        )
        await s.flush()
        s.add_all(
            [
                Session(
                    id=session_id,
                    user_id=user_id,
                    csrf_token=csrf,
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                    ip_at_issue="127.0.0.1",
                    user_agent_at_issue="test",
                ),
                Session(
                    id=nonmember_session_id,
                    user_id=nonmember_id,
                    csrf_token=csrf,
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                    ip_at_issue="127.0.0.1",
                    user_agent_at_issue="test",
                ),
                # VIEWER membership -- proves the endpoint is viewer-accessible.
                Membership(
                    user_id=user_id,
                    project_id=project_id,
                    role=ProjectRole.VIEWER,
                ),
            ]
        )
        await s.flush()
        # Through the control repository, because Boundary D refuses a direct
        # INSERT into schedules. The ids are assigned by the repository, so
        # they are collected here rather than minted above.
        control = ScheduleControlRepository(s)
        created_ids: dict[str, uuid.UUID] = {}
        for sched_name in ("nightly", "hourly"):
            created = await control.create_current(
                project_id=project_id,
                data={
                    "engine": "celery",
                    "scheduler": "z4j-scheduler",
                    "name": sched_name,
                    "task_name": "app.t",
                    "kind": ScheduleKind.INTERVAL.value,
                    "expression": "60s",
                    "timezone": "UTC",
                    "args": [],
                    "kwargs": {},
                    "is_enabled": True,
                },
                planning_at=datetime.now(UTC),
            )
            created_ids[sched_name] = created.id
        await s.commit()
        sched_a = created_ids["nightly"]
        sched_b = created_ids["hourly"]

        if with_misfires:
            audit = AuditService(settings)
            # Three misfire rows across TWO schedules (oldest -> newest).
            for sid, sname, late, when in (
                (sched_a, "nightly", 120.0, "2026-06-01T00:00:00+00:00"),
                (sched_b, "hourly", 300.0, "2026-06-01T01:00:00+00:00"),
                (sched_a, "nightly", 540.0, "2026-06-01T02:00:00+00:00"),
            ):
                await audit.record(
                    AuditLogRepository(s),
                    action="scheduler.misfire_detected",
                    target_type="schedule",
                    target_id=str(sid),
                    result="failed",
                    outcome="error",
                    project_id=project_id,
                    metadata={
                        "name": sname,
                        "scheduler": "z4j-scheduler",
                        "engine": "celery",
                        "kind": "interval",
                        "expected_fire_at": when,
                        "last_run_at": None,
                        "lateness_seconds": late,
                        "grace_seconds": 60,
                    },
                )
                await s.commit()

    return {
        "project_id": project_id,
        "session_id": session_id,
        "nonmember_session_id": nonmember_session_id,
        "csrf": csrf,
        "sched_a": sched_a,
        "sched_b": sched_b,
    }


def _client(brain_app, settings: Settings, seed: dict, *, session_key: str = "session_id"):
    from httpx import ASGITransport, AsyncClient

    ac = AsyncClient(
        transport=ASGITransport(app=brain_app),
        base_url="http://testserver",
        headers={"X-CSRF-Token": seed["csrf"]},
    )
    codec = SessionCookieCodec(settings)
    ac.cookies.set(
        cookie_name(environment=settings.environment),
        codec.encode(seed[session_key]),
    )
    ac.cookies.set(
        csrf_cookie_name(environment=settings.environment),
        seed["csrf"],
    )
    return ac


@pytest.mark.asyncio
async def test_viewer_lists_project_misfires_spanning_schedules(
    settings: Settings,
    brain_app,
) -> None:
    seed = await _seed(settings=settings, brain_app=brain_app)
    async with _client(brain_app, settings, seed) as ac:
        r = await ac.get("/api/v1/projects/default/schedules/misfires")
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body) == 3
    # Newest first (the 02:00 slot, lateness 540, schedule A).
    assert body[0]["lateness_seconds"] == 540.0
    assert body[0]["expected_fire_at"] == "2026-06-01T02:00:00Z"
    assert body[0]["schedule_id"] == str(seed["sched_a"])
    assert body[0]["engine"] == "celery"
    assert body[0]["kind"] == "interval"
    assert body[0]["grace_seconds"] == 60
    assert body[0]["detected_at"] is not None
    # The middle row belongs to the OTHER schedule -- rows span schedules.
    assert body[1]["schedule_id"] == str(seed["sched_b"])
    assert body[1]["lateness_seconds"] == 300.0
    assert body[2]["schedule_id"] == str(seed["sched_a"])
    assert body[2]["lateness_seconds"] == 120.0
    # Every row carries a schedule_id, and both schedules are represented.
    assert {row["schedule_id"] for row in body} == {
        str(seed["sched_a"]),
        str(seed["sched_b"]),
    }


@pytest.mark.asyncio
async def test_limit_query_param_bounds_rows(
    settings: Settings,
    brain_app,
) -> None:
    seed = await _seed(settings=settings, brain_app=brain_app)
    async with _client(brain_app, settings, seed) as ac:
        r = await ac.get("/api/v1/projects/default/schedules/misfires?limit=1")
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body) == 1
    assert body[0]["lateness_seconds"] == 540.0


@pytest.mark.asyncio
async def test_non_member_is_refused(settings: Settings, brain_app) -> None:
    """A logged-in non-member cannot read the project's misfires.

    ``require_member`` returns 404 (not 403) for non-members by design,
    so the project slug stays non-enumerable -- byte-identical to the
    per-schedule endpoint's behaviour.
    """
    seed = await _seed(settings=settings, brain_app=brain_app)
    async with _client(
        brain_app,
        settings,
        seed,
        session_key="nonmember_session_id",
    ) as ac:
        r = await ac.get("/api/v1/projects/default/schedules/misfires")
    assert r.status_code == 404, r.text


@pytest.mark.asyncio
async def test_project_with_no_misfires_returns_empty(
    settings: Settings,
    brain_app,
) -> None:
    seed = await _seed(settings=settings, brain_app=brain_app, with_misfires=False)
    async with _client(brain_app, settings, seed) as ac:
        r = await ac.get("/api/v1/projects/default/schedules/misfires")
    assert r.status_code == 200, r.text
    assert r.json() == []
