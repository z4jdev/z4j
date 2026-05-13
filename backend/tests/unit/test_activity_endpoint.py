"""Tests for the v1.6 cross-project ``/api/v1/activity`` feed."""

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
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import (
    AuditLog,
    Membership,
    Project,
    Session,
    User,
)
from z4j_brain.api import activity as activity_mod
from z4j_brain.settings import Settings


@pytest.fixture(autouse=True)
def _reset_activity_rate_limit() -> Any:
    """v1.6 audit H13: each test starts with a fresh per-user rate
    bucket so a previous test's polling does not bleed into the
    next test's 429 envelope."""
    activity_mod._reset_rate_limit_for_tests()
    yield
    activity_mod._reset_rate_limit_for_tests()


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


async def _seed_two_projects_one_user(
    *,
    settings: Settings,
    brain_app,
    is_admin: bool = False,
    member_of_b: bool = False,
) -> dict:
    """Two projects, one user, optionally admin and/or member of B.

    Project A: user is member; Project B: user is NOT a member
    unless ``member_of_b`` is true. Admins see both regardless.
    """
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    proj_a = uuid.uuid4()
    proj_b = uuid.uuid4()
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    csrf = secrets.token_urlsafe(32)

    rows = [
        Project(id=proj_a, slug="alpha", name="alpha"),
        Project(id=proj_b, slug="bravo", name="bravo"),
        User(
            id=user_id,
            email=f"u-{uuid.uuid4().hex[:8]}@example.com",
            password_hash=hasher.hash("correct horse battery staple 9"),
            is_admin=is_admin,
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
            user_id=user_id, project_id=proj_a, role=ProjectRole.VIEWER,
        ),
    ]
    if member_of_b:
        rows.append(
            Membership(
                user_id=user_id, project_id=proj_b, role=ProjectRole.VIEWER,
            ),
        )

    async with db.session() as s:
        s.add_all(rows)
        await s.commit()

    return {
        "proj_a": proj_a,
        "proj_b": proj_b,
        "user_id": user_id,
        "session_id": session_id,
        "csrf": csrf,
    }


async def _seed_audit_row(
    db, *, project_id: uuid.UUID | None, action: str = "task.failed",
) -> uuid.UUID:
    """Insert one audit row directly. The activity endpoint reads
    from the audit_log table; the row HMAC is not verified by the
    activity endpoint so any string is acceptable here."""
    row_id = uuid.uuid7() if hasattr(uuid, "uuid7") else uuid.uuid4()
    async with db.session() as s:
        s.add(
            AuditLog(
                id=row_id,
                action=action,
                target_type="task",
                target_id="t-1",
                result="success",
                outcome="allow",
                event_id=None,
                user_id=None,
                project_id=project_id,
                source_ip=None,
                user_agent=None,
                audit_metadata={"k": "v"},
                row_hmac="0" * 64,
                prev_row_hmac=None,
                occurred_at=datetime.now(UTC),
            ),
        )
        await s.commit()
    return row_id


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


@pytest.mark.asyncio
class TestActivityScopeEnforcement:
    """Non-admins see ONLY rows from projects they are a member of."""

    async def test_non_admin_excludes_other_projects(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_two_projects_one_user(
            settings=settings, brain_app=brain_app,
            is_admin=False, member_of_b=False,
        )
        db = brain_app.state.db
        a_id = await _seed_audit_row(
            db, project_id=seed["proj_a"], action="task.failed",
        )
        b_id = await _seed_audit_row(
            db, project_id=seed["proj_b"], action="task.failed",
        )
        async with _make_client(brain_app, settings, seed) as c:
            r = await c.get("/api/v1/activity")
        assert r.status_code == 200, r.text
        body = r.json()
        seen_ids = {item["id"] for item in body["items"]}
        assert str(a_id) in seen_ids
        assert str(b_id) not in seen_ids

    async def test_non_admin_with_no_memberships_returns_empty(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_two_projects_one_user(
            settings=settings, brain_app=brain_app,
            is_admin=False, member_of_b=False,
        )
        # Drop the membership we created in the seed.
        db = brain_app.state.db
        from sqlalchemy import delete as _delete
        async with db.session() as s:
            await s.execute(_delete(Membership).where(
                Membership.user_id == seed["user_id"],
            ))
            await s.commit()
        await _seed_audit_row(db, project_id=seed["proj_a"])
        async with _make_client(brain_app, settings, seed) as c:
            r = await c.get("/api/v1/activity")
        assert r.status_code == 200
        body = r.json()
        assert body["items"] == []
        assert body["next_before_cursor"] is None
        assert body["newest_cursor"] is None

    async def test_admin_sees_every_project(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_two_projects_one_user(
            settings=settings, brain_app=brain_app,
            is_admin=True, member_of_b=False,
        )
        db = brain_app.state.db
        a_id = await _seed_audit_row(db, project_id=seed["proj_a"])
        b_id = await _seed_audit_row(db, project_id=seed["proj_b"])
        async with _make_client(brain_app, settings, seed) as c:
            r = await c.get("/api/v1/activity")
        assert r.status_code == 200
        ids = {item["id"] for item in r.json()["items"]}
        assert str(a_id) in ids
        assert str(b_id) in ids

    async def test_admin_sees_rows_without_project(
        self, settings: Settings, brain_app,
    ) -> None:
        """Brain-wide rows (no project_id) are admin-only."""
        seed = await _seed_two_projects_one_user(
            settings=settings, brain_app=brain_app,
            is_admin=True, member_of_b=False,
        )
        db = brain_app.state.db
        brain_id = await _seed_audit_row(db, project_id=None)
        async with _make_client(brain_app, settings, seed) as c:
            r = await c.get("/api/v1/activity")
        assert r.status_code == 200
        ids = {item["id"] for item in r.json()["items"]}
        assert str(brain_id) in ids

    async def test_non_admin_does_not_see_rows_without_project(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_two_projects_one_user(
            settings=settings, brain_app=brain_app,
            is_admin=False, member_of_b=False,
        )
        db = brain_app.state.db
        await _seed_audit_row(db, project_id=None)
        await _seed_audit_row(db, project_id=seed["proj_a"])
        async with _make_client(brain_app, settings, seed) as c:
            r = await c.get("/api/v1/activity")
        assert r.status_code == 200
        items = r.json()["items"]
        # Only the proj_a row should appear, not the project-less one.
        for it in items:
            assert it["project_id"] == str(seed["proj_a"])


@pytest.mark.asyncio
class TestActivityFilters:
    async def test_action_prefix_filter(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_two_projects_one_user(
            settings=settings, brain_app=brain_app, is_admin=True,
        )
        db = brain_app.state.db
        await _seed_audit_row(
            db, project_id=seed["proj_a"], action="user.password_changed",
        )
        await _seed_audit_row(
            db, project_id=seed["proj_a"], action="task.failed",
        )
        async with _make_client(brain_app, settings, seed) as c:
            r = await c.get("/api/v1/activity?action_prefix=task.")
        assert r.status_code == 200
        actions = [item["action"] for item in r.json()["items"]]
        assert all(a.startswith("task.") for a in actions)

    async def test_project_slug_filter_constrains_results(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_two_projects_one_user(
            settings=settings, brain_app=brain_app, is_admin=True,
        )
        db = brain_app.state.db
        await _seed_audit_row(db, project_id=seed["proj_a"])
        await _seed_audit_row(db, project_id=seed["proj_b"])
        async with _make_client(brain_app, settings, seed) as c:
            r = await c.get("/api/v1/activity?project_slug=alpha")
        assert r.status_code == 200
        items = r.json()["items"]
        for it in items:
            assert it["project_id"] == str(seed["proj_a"])
            assert it["project_slug"] == "alpha"

    async def test_unknown_project_slug_returns_empty(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_two_projects_one_user(
            settings=settings, brain_app=brain_app, is_admin=True,
        )
        async with _make_client(brain_app, settings, seed) as c:
            r = await c.get("/api/v1/activity?project_slug=nonexistent")
        assert r.status_code == 200
        assert r.json()["items"] == []

    async def test_non_admin_project_slug_outside_memberships_empty(
        self, settings: Settings, brain_app,
    ) -> None:
        """A non-admin asking for a project they don't belong to
        must get an empty result, not the rows."""
        seed = await _seed_two_projects_one_user(
            settings=settings, brain_app=brain_app,
            is_admin=False, member_of_b=False,
        )
        db = brain_app.state.db
        await _seed_audit_row(db, project_id=seed["proj_b"])
        async with _make_client(brain_app, settings, seed) as c:
            r = await c.get("/api/v1/activity?project_slug=bravo")
        assert r.status_code == 200
        assert r.json()["items"] == []


@pytest.mark.asyncio
class TestActivityPagination:
    async def test_limit_caps_result_count(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_two_projects_one_user(
            settings=settings, brain_app=brain_app, is_admin=True,
        )
        db = brain_app.state.db
        for _ in range(5):
            await _seed_audit_row(db, project_id=seed["proj_a"])
        async with _make_client(brain_app, settings, seed) as c:
            r = await c.get("/api/v1/activity?limit=2")
        assert r.status_code == 200
        body = r.json()
        assert len(body["items"]) == 2
        # next_before_cursor is set when the page is full.
        assert body["next_before_cursor"] is not None
        # newest_cursor encodes the first item (rows return newest-first).
        first_id = body["items"][0]["id"]
        assert first_id in body["newest_cursor"]
        # Cursor shape: <iso>|<uuid>.
        assert "|" in body["next_before_cursor"]
        assert "|" in body["newest_cursor"]

    async def test_since_cursor_returns_only_newer_rows(
        self, settings: Settings, brain_app,
    ) -> None:
        """v1.6 audit C8: cursor is (occurred_at, id) because the row
        id is uuid4 (random). Seed two batches with an explicit
        ``await asyncio.sleep(0.001)`` so occurred_at orders them."""
        import asyncio as _asyncio
        seed = await _seed_two_projects_one_user(
            settings=settings, brain_app=brain_app, is_admin=True,
        )
        db = brain_app.state.db
        for _ in range(3):
            await _seed_audit_row(db, project_id=seed["proj_a"])
        await _asyncio.sleep(0.01)
        async with _make_client(brain_app, settings, seed) as c:
            r0 = await c.get("/api/v1/activity?limit=3")
        boundary_cursor = r0.json()["newest_cursor"]
        assert boundary_cursor is not None
        # Second batch (newer occurred_at).
        for _ in range(2):
            await _seed_audit_row(db, project_id=seed["proj_a"])
        async with _make_client(brain_app, settings, seed) as c:
            r = await c.get(
                f"/api/v1/activity?since_cursor={boundary_cursor}",
            )
        assert r.status_code == 200
        items = r.json()["items"]
        # Exactly the two newer rows are returned.
        assert len(items) == 2

    async def test_malformed_cursor_returns_422(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_two_projects_one_user(
            settings=settings, brain_app=brain_app, is_admin=True,
        )
        async with _make_client(brain_app, settings, seed) as c:
            r = await c.get("/api/v1/activity?since_cursor=not-a-cursor")
        assert r.status_code == 422

    async def test_limit_below_one_rejected(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_two_projects_one_user(
            settings=settings, brain_app=brain_app, is_admin=True,
        )
        async with _make_client(brain_app, settings, seed) as c:
            r = await c.get("/api/v1/activity?limit=0")
        assert r.status_code == 422

    async def test_limit_above_cap_rejected(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_two_projects_one_user(
            settings=settings, brain_app=brain_app, is_admin=True,
        )
        async with _make_client(brain_app, settings, seed) as c:
            r = await c.get("/api/v1/activity?limit=999")
        assert r.status_code == 422


@pytest.mark.asyncio
class TestActivityAuditFixes:
    """v1.6 audit follow-ups."""

    async def test_source_ip_hidden_from_non_admin(
        self, settings: Settings, brain_app,
    ) -> None:
        """v1.6 audit M15: source_ip is privacy-sensitive. The cross-
        project feed widens the audience versus the per-project page;
        non-admins MUST NOT see source_ip in the feed."""
        seed = await _seed_two_projects_one_user(
            settings=settings, brain_app=brain_app,
            is_admin=False, member_of_b=False,
        )
        db = brain_app.state.db
        async with db.session() as s:
            s.add(
                AuditLog(
                    id=uuid.uuid4(),
                    action="task.failed",
                    target_type="task",
                    target_id="t-1",
                    result="success",
                    outcome="allow",
                    event_id=None,
                    user_id=None,
                    project_id=seed["proj_a"],
                    source_ip="192.0.2.10",
                    user_agent=None,
                    audit_metadata={},
                    row_hmac="0" * 64,
                    prev_row_hmac=None,
                    occurred_at=datetime.now(UTC),
                ),
            )
            await s.commit()
        async with _make_client(brain_app, settings, seed) as c:
            r = await c.get("/api/v1/activity")
        assert r.status_code == 200
        items = r.json()["items"]
        assert items, "expected at least one row"
        for item in items:
            assert item["source_ip"] is None, (
                "non-admin must not see source_ip"
            )

    async def test_source_ip_shown_to_admin(
        self, settings: Settings, brain_app,
    ) -> None:
        """Admins KEEP source_ip access. The redaction is non-admin-only."""
        seed = await _seed_two_projects_one_user(
            settings=settings, brain_app=brain_app, is_admin=True,
        )
        db = brain_app.state.db
        async with db.session() as s:
            s.add(
                AuditLog(
                    id=uuid.uuid4(),
                    action="task.failed",
                    target_type="task",
                    target_id="t-1",
                    result="success",
                    outcome="allow",
                    event_id=None,
                    user_id=None,
                    project_id=seed["proj_a"],
                    source_ip="192.0.2.10",
                    user_agent=None,
                    audit_metadata={},
                    row_hmac="0" * 64,
                    prev_row_hmac=None,
                    occurred_at=datetime.now(UTC),
                ),
            )
            await s.commit()
        async with _make_client(brain_app, settings, seed) as c:
            r = await c.get("/api/v1/activity")
        items = r.json()["items"]
        assert items[0]["source_ip"] == "192.0.2.10"

    async def test_action_prefix_wildcard_does_not_match_anywhere(
        self, settings: Settings, brain_app,
    ) -> None:
        """v1.6 audit M16: LIKE metachars in action_prefix must be
        escaped so ``%fail`` does not match ``task.failed``."""
        seed = await _seed_two_projects_one_user(
            settings=settings, brain_app=brain_app, is_admin=True,
        )
        db = brain_app.state.db
        await _seed_audit_row(
            db, project_id=seed["proj_a"], action="task.failed",
        )
        await _seed_audit_row(
            db, project_id=seed["proj_a"], action="user.password_changed",
        )
        async with _make_client(brain_app, settings, seed) as c:
            # Inject a leading ``%`` -- if unescaped, this would
            # match ANY action; after escape, it matches only
            # actions literally starting with ``%``.
            r = await c.get("/api/v1/activity?action_prefix=%25fail")
        assert r.status_code == 200
        assert r.json()["items"] == []

    async def test_action_prefix_underscore_does_not_match_single_char(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_two_projects_one_user(
            settings=settings, brain_app=brain_app, is_admin=True,
        )
        db = brain_app.state.db
        await _seed_audit_row(
            db, project_id=seed["proj_a"], action="task.failed",
        )
        async with _make_client(brain_app, settings, seed) as c:
            # ``_ask.`` would match ``task.`` if ``_`` were a wildcard.
            r = await c.get("/api/v1/activity?action_prefix=_ask.")
        # No literal action starts with ``_ask.``, so empty.
        assert r.json()["items"] == []

    async def test_rate_limit_kicks_in_after_quota(
        self, settings: Settings, brain_app,
    ) -> None:
        """v1.6 audit H13: per-user 60/min rate limit. We exhaust
        the bucket then assert the 61st request gets 429."""
        seed = await _seed_two_projects_one_user(
            settings=settings, brain_app=brain_app, is_admin=True,
        )
        async with _make_client(brain_app, settings, seed) as c:
            for _ in range(60):
                r = await c.get("/api/v1/activity?limit=1")
                assert r.status_code == 200
            r = await c.get("/api/v1/activity?limit=1")
            assert r.status_code == 429
            assert "rate limit" in r.text.lower()


@pytest.mark.asyncio
async def test_unauthenticated_request_rejected(
    settings: Settings, brain_app,
) -> None:
    """No session cookie -> 401. Activity feed is logged-in-only."""
    from httpx import ASGITransport, AsyncClient
    transport = ASGITransport(app=brain_app)
    async with AsyncClient(
        transport=transport, base_url="http://testserver",
    ) as c:
        r = await c.get("/api/v1/activity")
    assert r.status_code in (401, 403)
