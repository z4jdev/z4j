"""Regression tests for the v1.1.0 N+1 fixes (cursor pagination).

Two list endpoints used to return unbounded ``list[T]`` and grew
linearly with project / user data. v1.1.0 switches them to keyset-
paged envelopes:

- ``GET /api/v1/projects/{slug}/schedules`` →
  ``{items: list[SchedulePublic], next_cursor: str | None}``,
  keyset on ``(name, id)``.

- ``GET /api/v1/user/subscriptions`` →
  ``{items: list[UserSubscriptionPublic], next_cursor: str | None}``,
  keyset on ``(project_id, trigger, id)``.

The dashboard hooks transparently walk ``next_cursor`` so existing
call sites that expected a flat list keep working. These tests pin
the new envelope shape and the cursor walk so we don't regress.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence.base import Base
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.enums import ProjectRole, ScheduleKind
from z4j_brain.persistence.models import (
    Membership,
    Project,
    Schedule,
    Session,
    User,
)
from z4j_brain.persistence.models.notification import UserSubscription
from z4j_brain.settings import Settings


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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


async def _seed_user_in_project(
    *,
    settings: Settings,
    brain_app,
    role: ProjectRole = ProjectRole.VIEWER,
    project_slug: str = "default",
) -> dict:
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    csrf = secrets.token_urlsafe(32)

    async with db.session() as s:
        s.add_all(
            [
                Project(id=project_id, slug=project_slug, name=project_slug),
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
                Membership(
                    user_id=user_id,
                    project_id=project_id,
                    role=role,
                ),
            ],
        )
        await s.commit()

    return {
        "project_id": project_id,
        "user_id": user_id,
        "session_id": session_id,
        "csrf": csrf,
    }


def _make_client(brain_app, settings: Settings, seed: dict):
    from httpx import ASGITransport, AsyncClient

    from z4j_brain.auth.csrf import csrf_cookie_name

    transport = ASGITransport(app=brain_app)
    ac = AsyncClient(
        transport=transport,
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


# ---------------------------------------------------------------------------
# Schedules pagination
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSchedulesPagination:
    """``GET /api/v1/projects/{slug}/schedules``, keyset on (name, id)."""

    async def test_envelope_shape_when_empty(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_user_in_project(
            settings=settings, brain_app=brain_app,
        )
        async with _make_client(brain_app, settings, seed) as client:
            r = await client.get("/api/v1/projects/default/schedules")
        assert r.status_code == 200
        body = r.json()
        assert body == {"items": [], "next_cursor": None}

    async def test_pagination_walks_all_pages(
        self, settings: Settings, brain_app,
    ) -> None:
        """Seed 7 schedules, page through with limit=3, assert full set."""
        seed = await _seed_user_in_project(
            settings=settings, brain_app=brain_app,
        )
        async with brain_app.state.db.session() as s:
            for i in range(7):
                s.add(
                    Schedule(
                        project_id=seed["project_id"],
                        engine="celery",
                        scheduler="celery-beat",
                        name=f"sched-{i:02d}",
                        task_name=f"tasks.t{i}",
                        kind=ScheduleKind.CRON,
                        expression="0 * * * *",
                    ),
                )
            await s.commit()

        seen: list[str] = []
        cursor: str | None = None
        pages = 0
        async with _make_client(brain_app, settings, seed) as client:
            while True:
                pages += 1
                params = {"limit": 3}
                if cursor is not None:
                    params["cursor"] = cursor
                r = await client.get(
                    "/api/v1/projects/default/schedules", params=params,
                )
                assert r.status_code == 200, r.text
                body = r.json()
                seen.extend(item["name"] for item in body["items"])
                cursor = body["next_cursor"]
                if cursor is None:
                    break
                # Safety net so a buggy cursor encoder doesn't loop forever.
                assert pages < 10

        assert seen == [f"sched-{i:02d}" for i in range(7)]

    async def test_cursor_does_not_skip_or_duplicate_at_boundary(
        self, settings: Settings, brain_app,
    ) -> None:
        """The boundary row must appear exactly once across page edges."""
        seed = await _seed_user_in_project(
            settings=settings, brain_app=brain_app,
        )
        async with brain_app.state.db.session() as s:
            for i in range(5):
                s.add(
                    Schedule(
                        project_id=seed["project_id"],
                        engine="celery",
                        scheduler="celery-beat",
                        name=f"row-{i}",
                        task_name="t",
                        kind=ScheduleKind.CRON,
                        expression="0 * * * *",
                    ),
                )
            await s.commit()

        async with _make_client(brain_app, settings, seed) as client:
            r1 = await client.get(
                "/api/v1/projects/default/schedules", params={"limit": 2},
            )
            assert r1.status_code == 200
            page1 = r1.json()
            assert [i["name"] for i in page1["items"]] == ["row-0", "row-1"]
            assert page1["next_cursor"] is not None

            r2 = await client.get(
                "/api/v1/projects/default/schedules",
                params={"limit": 2, "cursor": page1["next_cursor"]},
            )
            assert r2.status_code == 200
            page2 = r2.json()
            assert [i["name"] for i in page2["items"]] == ["row-2", "row-3"]

            r3 = await client.get(
                "/api/v1/projects/default/schedules",
                params={"limit": 2, "cursor": page2["next_cursor"]},
            )
            assert r3.status_code == 200
            page3 = r3.json()
            assert [i["name"] for i in page3["items"]] == ["row-4"]
            assert page3["next_cursor"] is None

    async def test_invalid_cursor_treated_as_no_cursor(
        self, settings: Settings, brain_app,
    ) -> None:
        """A garbage cursor must not 500, return the first page instead."""
        seed = await _seed_user_in_project(
            settings=settings, brain_app=brain_app,
        )
        async with brain_app.state.db.session() as s:
            s.add(
                Schedule(
                    project_id=seed["project_id"],
                    engine="celery",
                    scheduler="celery-beat",
                    name="only",
                    task_name="t",
                    kind=ScheduleKind.CRON,
                    expression="0 * * * *",
                ),
            )
            await s.commit()

        async with _make_client(brain_app, settings, seed) as client:
            r = await client.get(
                "/api/v1/projects/default/schedules",
                params={"cursor": "not-a-valid-cursor"},
            )
        assert r.status_code == 200
        assert [i["name"] for i in r.json()["items"]] == ["only"]


# ---------------------------------------------------------------------------
# User subscriptions pagination
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestUserSubscriptionsPagination:
    """``GET /api/v1/user/subscriptions``, keyset on (project_id, trigger, id)."""

    async def test_envelope_shape_when_empty(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_user_in_project(
            settings=settings, brain_app=brain_app,
        )
        async with _make_client(brain_app, settings, seed) as client:
            r = await client.get("/api/v1/user/subscriptions")
        assert r.status_code == 200
        body = r.json()
        assert body == {"items": [], "next_cursor": None}

    async def test_pagination_walks_all_pages(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_user_in_project(
            settings=settings, brain_app=brain_app,
        )
        # Six distinct (project, trigger) subscriptions for the user.
        triggers = [
            "task.failed",
            "task.succeeded",
            "task.retried",
            "task.slow",
            "agent.offline",
            "agent.online",
        ]
        async with brain_app.state.db.session() as s:
            for trig in triggers:
                s.add(
                    UserSubscription(
                        user_id=seed["user_id"],
                        project_id=seed["project_id"],
                        trigger=trig,
                        filters={},
                        in_app=True,
                        project_channel_ids=[],
                        user_channel_ids=[],
                        cooldown_seconds=0,
                    ),
                )
            await s.commit()

        seen: list[str] = []
        cursor: str | None = None
        pages = 0
        async with _make_client(brain_app, settings, seed) as client:
            while True:
                pages += 1
                params = {"limit": 2}
                if cursor is not None:
                    params["cursor"] = cursor
                r = await client.get(
                    "/api/v1/user/subscriptions", params=params,
                )
                assert r.status_code == 200, r.text
                body = r.json()
                seen.extend(i["trigger"] for i in body["items"])
                cursor = body["next_cursor"]
                if cursor is None:
                    break
                assert pages < 10

        # Repository orders by (project_id, trigger, id); single project
        # so just trigger-sorted alphabetically.
        assert sorted(seen) == sorted(triggers)
        assert len(seen) == len(triggers)
        assert len(set(seen)) == len(seen)  # no duplicates across boundaries

    async def test_invalid_cursor_treated_as_no_cursor(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_user_in_project(
            settings=settings, brain_app=brain_app,
        )
        async with brain_app.state.db.session() as s:
            s.add(
                UserSubscription(
                    user_id=seed["user_id"],
                    project_id=seed["project_id"],
                    trigger="task.failed",
                    filters={},
                    in_app=True,
                    project_channel_ids=[],
                    user_channel_ids=[],
                    cooldown_seconds=0,
                ),
            )
            await s.commit()

        async with _make_client(brain_app, settings, seed) as client:
            r = await client.get(
                "/api/v1/user/subscriptions",
                params={"cursor": "garbage|not-a-uuid"},
            )
        assert r.status_code == 200
        assert [i["trigger"] for i in r.json()["items"]] == ["task.failed"]
