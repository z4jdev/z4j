"""Regression tests for v1.0.18 personal-notification additions.

Two new behaviours land in this release:

1. ``GET /api/v1/user/deliveries`` - personal delivery history
   across all of the user's projects. Mirror of the project-scoped
   audit log, filtered by user-owned subscriptions. Survives
   project membership changes (a user who left project X still
   sees their historical deliveries from X with a "you left" hint
   on the dashboard side).

2. ``PATCH /api/v1/user/subscriptions/{sub_id}`` - the existing
   endpoint gained a ``trigger`` field for full parity with the
   project-defaults edit endpoint that landed in v1.0.18 alongside.
   Renaming defends the (user, project, trigger) uniqueness
   invariant with a clean 409.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from z4j_brain.auth.csrf import csrf_cookie_name
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import (
    Membership,
    NotificationChannel,
    NotificationDelivery,
    Project,
    Session,
    User,
    UserSubscription,
)
from z4j_brain.persistence.enums import ProjectRole
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


async def _seed_basic(brain_app, settings: Settings):
    """One user, two projects (alpha + beta), member of both."""
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    csrf = secrets.token_urlsafe(32)
    alpha_id = uuid.uuid4()
    beta_id = uuid.uuid4()
    sub_alpha_id = uuid.uuid4()
    sub_beta_id = uuid.uuid4()
    alpha_channel_id = uuid.uuid4()

    async with db.session() as s:
        s.add_all([
            Project(id=alpha_id, slug="alpha", name="Alpha"),
            Project(id=beta_id, slug="beta", name="Beta"),
            User(
                id=user_id,
                email=f"u-{uuid.uuid4().hex[:8]}@example.com",
                password_hash=hasher.hash(
                    "correct horse battery staple 9",
                ),
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
                user_id=user_id, project_id=alpha_id,
                role=ProjectRole.VIEWER,
            ),
            Membership(
                user_id=user_id, project_id=beta_id,
                role=ProjectRole.VIEWER,
            ),
            NotificationChannel(
                id=alpha_channel_id,
                project_id=alpha_id,
                name="alpha-webhook",
                type="webhook",
                config={"url": "https://example.test/alpha"},
                is_active=True,
            ),
            UserSubscription(
                id=sub_alpha_id,
                user_id=user_id,
                project_id=alpha_id,
                trigger="task.failed",
                filters={},
                in_app=True,
                project_channel_ids=[alpha_channel_id],
                user_channel_ids=[],
                cooldown_seconds=0,
                is_active=True,
            ),
            UserSubscription(
                id=sub_beta_id,
                user_id=user_id,
                project_id=beta_id,
                trigger="task.failed",
                filters={},
                in_app=True,
                project_channel_ids=[],
                user_channel_ids=[],
                cooldown_seconds=0,
                is_active=True,
            ),
        ])
        # Three deliveries: 2 to alpha sub, 1 to beta sub.
        now = datetime.now(UTC)
        for i, sub_id in enumerate([sub_alpha_id, sub_alpha_id, sub_beta_id]):
            s.add(NotificationDelivery(
                subscription_id=sub_id,
                channel_id=(
                    alpha_channel_id if sub_id == sub_alpha_id else None
                ),
                project_id=(
                    alpha_id if sub_id == sub_alpha_id else beta_id
                ),
                trigger="task.failed",
                task_id=f"t-{i}",
                task_name=f"app.task.{i}",
                status="success",
                response_code=200,
                sent_at=now - timedelta(minutes=i),
            ))
        await s.commit()

    return {
        "user_id": user_id,
        "session_id": session_id,
        "csrf": csrf,
        "alpha_id": alpha_id,
        "beta_id": beta_id,
        "sub_alpha_id": sub_alpha_id,
        "sub_beta_id": sub_beta_id,
        "alpha_channel_id": alpha_channel_id,
    }


def _client(brain_app, settings: Settings, seed: dict) -> AsyncClient:
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
class TestUserDeliveries:
    async def test_returns_all_user_deliveries_across_projects(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_basic(brain_app, settings)
        async with _client(brain_app, settings, seed) as client:
            resp = await client.get("/api/v1/user/deliveries")
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert "items" in body
            # 3 deliveries seeded total (2 alpha + 1 beta)
            assert len(body["items"]) == 3
            triggers = {item["trigger"] for item in body["items"]}
            assert triggers == {"task.failed"}

    async def test_filter_by_project_slug(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_basic(brain_app, settings)
        async with _client(brain_app, settings, seed) as client:
            resp = await client.get(
                "/api/v1/user/deliveries?project_slug=alpha",
            )
            assert resp.status_code == 200
            body = resp.json()
            # Only the 2 alpha deliveries
            assert len(body["items"]) == 2

    async def test_unknown_project_slug_returns_empty(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_basic(brain_app, settings)
        async with _client(brain_app, settings, seed) as client:
            resp = await client.get(
                "/api/v1/user/deliveries?project_slug=nope",
            )
            assert resp.status_code == 200
            assert resp.json() == {"items": [], "next_cursor": None}

    async def test_other_users_deliveries_invisible(
        self, settings: Settings, brain_app,
    ) -> None:
        """A second user's deliveries must not surface in the
        first user's history. Pure IDOR-by-design check.
        """
        seed = await _seed_basic(brain_app, settings)
        # Second user with their own subscription + delivery.
        other_user_id = uuid.uuid4()
        other_sub_id = uuid.uuid4()
        async with brain_app.state.db.session() as s:
            hasher = PasswordHasher(settings)
            s.add(User(
                id=other_user_id,
                email=f"o-{uuid.uuid4().hex[:8]}@example.com",
                password_hash=hasher.hash(
                    "correct horse battery staple 9",
                ),
                is_admin=False, is_active=True,
            ))
            s.add(Membership(
                user_id=other_user_id, project_id=seed["alpha_id"],
                role=ProjectRole.VIEWER,
            ))
            s.add(UserSubscription(
                id=other_sub_id,
                user_id=other_user_id,
                project_id=seed["alpha_id"],
                trigger="task.failed",
                filters={},
                in_app=True,
                project_channel_ids=[],
                user_channel_ids=[],
                cooldown_seconds=0,
                is_active=True,
            ))
            s.add(NotificationDelivery(
                subscription_id=other_sub_id,
                project_id=seed["alpha_id"],
                trigger="task.failed",
                task_id="other-task",
                task_name="other.app",
                status="success",
                sent_at=datetime.now(UTC),
            ))
            await s.commit()

        async with _client(brain_app, settings, seed) as client:
            resp = await client.get("/api/v1/user/deliveries")
            assert resp.status_code == 200
            body = resp.json()
            # Still 3 (the other user's delivery NOT included)
            assert len(body["items"]) == 3
            assert all("other-task" != item["task_id"] for item in body["items"])

    async def test_deliveries_for_left_project_still_visible(
        self, settings: Settings, brain_app,
    ) -> None:
        """User leaves alpha after the deliveries fired. Historical
        rows MUST still surface (audit data outlives membership).
        """
        seed = await _seed_basic(brain_app, settings)
        # Yank the alpha membership.
        from sqlalchemy import delete

        async with brain_app.state.db.session() as s:
            await s.execute(
                delete(Membership).where(
                    Membership.user_id == seed["user_id"],
                    Membership.project_id == seed["alpha_id"],
                ),
            )
            await s.commit()

        async with _client(brain_app, settings, seed) as client:
            resp = await client.get("/api/v1/user/deliveries")
            assert resp.status_code == 200
            body = resp.json()
            # All 3 still there. The "you left this project" hint
            # is a dashboard concern - the API just returns the rows.
            assert len(body["items"]) == 3

    async def test_pagination_cursor(
        self, settings: Settings, brain_app,
    ) -> None:
        """Limit + cursor round-trip yields stable ordered pages."""
        seed = await _seed_basic(brain_app, settings)
        async with _client(brain_app, settings, seed) as client:
            page1 = await client.get("/api/v1/user/deliveries?limit=2")
            assert page1.status_code == 200
            body1 = page1.json()
            assert len(body1["items"]) == 2
            assert body1["next_cursor"] is not None

            page2 = await client.get(
                f"/api/v1/user/deliveries?limit=2&cursor={body1['next_cursor']}",
            )
            assert page2.status_code == 200
            body2 = page2.json()
            assert len(body2["items"]) == 1
            assert body2["next_cursor"] is None
            # Pages must not overlap.
            ids_p1 = {it["id"] for it in body1["items"]}
            ids_p2 = {it["id"] for it in body2["items"]}
            assert ids_p1.isdisjoint(ids_p2)


@pytest.mark.asyncio
class TestChannelTestInUserLog:
    """v1.1.0 Bug 1 fix: channel-test fires triggered by the user
    must surface in their personal Global Notification Log.

    Pre-1.1.0: ``test_channel_config`` wrote a delivery row with
    ``subscription_id=NULL``, and the personal-log query filtered
    by ``subscription_id IN (subs owned by user)``. So test fires
    never appeared in the personal log.

    v1.1.0: new ``triggered_by_user_id`` column gets stamped with
    the user's id at write time, and the personal-log query OR's
    that into the WHERE clause. Pinned by migration
    2026_04_27_0009.
    """

    async def test_test_fire_appears_in_users_personal_log(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_basic(brain_app, settings)
        # Hand-write a row that mimics what _dispatch_test produces:
        # subscription_id=NULL, trigger="test.dispatch",
        # triggered_by_user_id=current_user.
        async with brain_app.state.db.session() as s:
            s.add(NotificationDelivery(
                subscription_id=None,
                channel_id=seed["alpha_channel_id"],
                project_id=seed["alpha_id"],
                trigger="test.dispatch",
                task_id=None,
                task_name=None,
                status="sent",
                response_code=200,
                sent_at=datetime.now(UTC),
                channel_name="alpha-webhook",
                channel_type="webhook",
                triggered_by_user_id=seed["user_id"],
            ))
            await s.commit()

        async with _client(brain_app, settings, seed) as client:
            resp = await client.get("/api/v1/user/deliveries")
            assert resp.status_code == 200, resp.text
            body = resp.json()
            triggers = [item["trigger"] for item in body["items"]]
            # Original 3 task.failed rows + the new test.dispatch row
            assert "test.dispatch" in triggers, (
                f"test fire not surfaced in personal log; got: {triggers}"
            )
            test_row = next(
                it for it in body["items"]
                if it["trigger"] == "test.dispatch"
            )
            assert test_row["triggered_by_user_id"] == str(seed["user_id"])
            assert test_row["subscription_id"] is None

    async def test_test_fire_only_visible_to_triggering_user(
        self, settings: Settings, brain_app,
    ) -> None:
        """Two members on the same project. User A triggers a test.
        Only A sees it in their personal log; member B does not.
        """
        seed = await _seed_basic(brain_app, settings)
        # Add a second user as member of alpha + a session for them.
        other_user_id = uuid.uuid4()
        other_session_id = uuid.uuid4()
        other_csrf = secrets.token_urlsafe(32)
        async with brain_app.state.db.session() as s:
            hasher = PasswordHasher(settings)
            s.add(User(
                id=other_user_id,
                email=f"o-{uuid.uuid4().hex[:8]}@example.com",
                password_hash=hasher.hash(
                    "correct horse battery staple 9",
                ),
                is_admin=False, is_active=True,
            ))
            s.add(Session(
                id=other_session_id,
                user_id=other_user_id,
                csrf_token=other_csrf,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                ip_at_issue="127.0.0.1",
                user_agent_at_issue="test",
            ))
            s.add(Membership(
                user_id=other_user_id, project_id=seed["alpha_id"],
                role=ProjectRole.VIEWER,
            ))
            # User A triggers a test fire
            s.add(NotificationDelivery(
                subscription_id=None,
                channel_id=seed["alpha_channel_id"],
                project_id=seed["alpha_id"],
                trigger="test.dispatch",
                status="sent",
                sent_at=datetime.now(UTC),
                triggered_by_user_id=seed["user_id"],
            ))
            await s.commit()

        # User B logs in, asks for personal log, must NOT see A's test.
        other_seed = {
            "user_id": other_user_id,
            "session_id": other_session_id,
            "csrf": other_csrf,
            "alpha_id": seed["alpha_id"],
            "beta_id": seed["beta_id"],
            "sub_alpha_id": seed["sub_alpha_id"],
            "sub_beta_id": seed["sub_beta_id"],
            "alpha_channel_id": seed["alpha_channel_id"],
        }
        async with _client(brain_app, settings, other_seed) as client:
            resp = await client.get("/api/v1/user/deliveries")
            assert resp.status_code == 200, resp.text
            body = resp.json()
            triggers = [item["trigger"] for item in body["items"]]
            assert "test.dispatch" not in triggers, (
                f"user B leaked user A's test fire: {triggers}"
            )


@pytest.mark.asyncio
class TestUserSubscriptionTriggerRename:
    async def test_rename_user_sub_trigger(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed_basic(brain_app, settings)
        async with _client(brain_app, settings, seed) as client:
            url = f"/api/v1/user/subscriptions/{seed['sub_alpha_id']}"
            resp = await client.patch(url, json={"trigger": "task.succeeded"})
            assert resp.status_code == 200, resp.text
            assert resp.json()["trigger"] == "task.succeeded"

    async def test_rename_collides_with_existing_409(
        self, settings: Settings, brain_app,
    ) -> None:
        """User already has task.failed on alpha; can't also rename
        another sub on alpha to task.failed.
        """
        seed = await _seed_basic(brain_app, settings)
        # Insert a second sub on alpha for a different trigger.
        other_sub_id = uuid.uuid4()
        async with brain_app.state.db.session() as s:
            s.add(UserSubscription(
                id=other_sub_id,
                user_id=seed["user_id"],
                project_id=seed["alpha_id"],
                trigger="task.succeeded",
                filters={},
                in_app=True,
                project_channel_ids=[],
                user_channel_ids=[],
                cooldown_seconds=0,
                is_active=True,
            ))
            await s.commit()

        async with _client(brain_app, settings, seed) as client:
            url = f"/api/v1/user/subscriptions/{other_sub_id}"
            resp = await client.patch(url, json={"trigger": "task.failed"})
            assert resp.status_code == 409, resp.text
            assert "already have" in resp.json()["message"]
