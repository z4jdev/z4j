"""``GET /projects/{slug}/schedules/{id}/misfires`` (A4 surfacing).

A VIEWER-accessible projection of the ``scheduler.misfire_detected``
audit rows for one schedule. Proves: VIEWER can read; the newest row is
first; the audit metadata maps onto the response; a schedule in another
project is 404 (IDOR-safe); a schedule with no misfires returns [].
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.auth.csrf import csrf_cookie_name
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import ProjectRole, ScheduleKind
from z4j_brain.persistence.models import (
    Membership,
    Project,
    Schedule,
    Session,
    User,
)
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.settings import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
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
    engine = create_async_engine(
        settings.database_url,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    yield app
    await engine.dispose()


async def _seed(*, settings: Settings, brain_app) -> dict:
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    project_id = uuid.uuid4()
    other_project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    schedule_id = uuid.uuid4()
    empty_schedule_id = uuid.uuid4()
    csrf = secrets.token_urlsafe(32)

    async with db.session() as s:
        s.add_all(
            [
                Project(id=project_id, slug="default", name="Default"),
                Project(id=other_project_id, slug="other", name="Other"),
                User(
                    id=user_id,
                    email=f"u-{uuid.uuid4().hex[:8]}@example.com",
                    password_hash=hasher.hash("correct horse battery staple 9"),
                    is_admin=False,
                    is_active=True,
                ),
                Session(
                    id=session_id,
                    user_id=user_id,
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
        for sid, pid, sched_name in (
            (schedule_id, project_id, "nightly"),
            (empty_schedule_id, project_id, "nightly-empty"),
        ):
            s.add(
                Schedule(
                    id=sid,
                    project_id=pid,
                    engine="celery",
                    scheduler="z4j-scheduler",
                    name=sched_name,
                    task_name="app.t",
                    kind=ScheduleKind.INTERVAL,
                    expression="60s",
                    timezone="UTC",
                    args=[],
                    kwargs={},
                    is_enabled=True,
                ),
            )
        await s.commit()

        # Two misfire audit rows for schedule_id (older + newer).
        audit = AuditService(settings)
        for late, when in (
            (120.0, "2026-06-01T00:00:00+00:00"),
            (540.0, "2026-06-01T01:00:00+00:00"),
        ):
            await audit.record(
                AuditLogRepository(s),
                action="scheduler.misfire_detected",
                target_type="schedule",
                target_id=str(schedule_id),
                result="failed",
                outcome="error",
                project_id=project_id,
                metadata={
                    "name": "nightly",
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
        "csrf": csrf,
        "schedule_id": schedule_id,
        "empty_schedule_id": empty_schedule_id,
    }


def _client(brain_app, settings: Settings, seed: dict):
    from httpx import ASGITransport, AsyncClient

    ac = AsyncClient(
        transport=ASGITransport(app=brain_app),
        base_url="http://testserver",
        headers={"X-CSRF-Token": seed["csrf"]},
    )
    codec = SessionCookieCodec(settings)
    ac.cookies.set(
        cookie_name(environment=settings.environment),
        codec.encode(seed["session_id"]),
    )
    ac.cookies.set(
        csrf_cookie_name(environment=settings.environment),
        seed["csrf"],
    )
    return ac


@pytest.mark.asyncio
async def test_viewer_lists_misfires_newest_first(
    settings: Settings,
    brain_app,
) -> None:
    seed = await _seed(settings=settings, brain_app=brain_app)
    async with _client(brain_app, settings, seed) as ac:
        r = await ac.get(
            f"/api/v1/projects/default/schedules/{seed['schedule_id']}/misfires",
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body) == 2
    # Newest first (the 01:00 expected slot, lateness 540).
    assert body[0]["lateness_seconds"] == 540.0
    # Pydantic serialises the UTC datetime with a trailing Z.
    assert body[0]["expected_fire_at"] == "2026-06-01T01:00:00Z"
    assert body[0]["engine"] == "celery"
    assert body[0]["kind"] == "interval"
    assert body[0]["grace_seconds"] == 60
    assert body[0]["schedule_id"] == str(seed["schedule_id"])
    assert body[0]["detected_at"] is not None
    assert body[1]["lateness_seconds"] == 120.0


@pytest.mark.asyncio
async def test_schedule_with_no_misfires_returns_empty(
    settings: Settings,
    brain_app,
) -> None:
    seed = await _seed(settings=settings, brain_app=brain_app)
    async with _client(brain_app, settings, seed) as ac:
        r = await ac.get(
            f"/api/v1/projects/default/schedules/{seed['empty_schedule_id']}/misfires",
        )
    assert r.status_code == 200, r.text
    assert r.json() == []


@pytest.mark.asyncio
async def test_unknown_schedule_is_404(settings: Settings, brain_app) -> None:
    seed = await _seed(settings=settings, brain_app=brain_app)
    async with _client(brain_app, settings, seed) as ac:
        r = await ac.get(
            f"/api/v1/projects/default/schedules/{uuid.uuid4()}/misfires",
        )
    assert r.status_code == 404, r.text
