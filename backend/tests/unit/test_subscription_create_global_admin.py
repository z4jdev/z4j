"""Regression: a global brain admin (``user.is_admin=True``) MUST be
allowed to create a per-user subscription on any project, even if the
``Membership`` table has no row for them on that project.

The 1.3.2 hotfix story:

- ``GET /api/v1/auth/me`` synthesises an admin-grade membership row
  for every active project for global admins, so the dashboard's
  project switcher and the ``/settings/memberships`` page list them
  with full admin badges. The synthesis is a UI affordance, no row
  is written to the ``memberships`` table.
- ``POST /api/v1/user/subscriptions`` (the New Subscription modal)
  pre-1.3.2 queried the ``memberships`` table directly via
  ``MembershipRepository.get_for_user_project``. For a global admin
  the query returned ``None`` and the endpoint 403'd with
  *you are not a member of this project*, directly contradicting
  the dashboard, which had just rendered them as admin.
- The sibling ``GET /api/v1/user/subscriptions`` endpoint already
  used the ``not user.is_admin`` short-circuit. The POST had drifted
  out of sync. 1.3.2 switches the POST to the canonical
  ``PolicyEngine.require_member`` helper which handles the
  ``is_admin`` bypass uniformly.

This file exists to keep the bug from re-shipping a third time.
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
    Project,
    Session,
    User,
)
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


async def _seed_global_admin_no_membership(
    brain_app, settings: Settings,
) -> dict:
    """Seed exactly the production scenario:

    - Global admin user (is_admin=True, e.g. created via ``z4j
      bootstrap-admin``).
    - One project (e.g. ``picker``).
    - **No Membership row connecting the admin to the project.**
      The admin can still see / operate on the project because of
      the ``is_admin`` bypass in ``PolicyEngine.require_member``
      and the synthesised membership in ``/auth/me``.
    """
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    csrf = secrets.token_urlsafe(32)
    project_id = uuid.uuid4()

    async with db.session() as s:
        s.add_all([
            Project(id=project_id, slug="picker", name="Picker"),
            User(
                id=user_id,
                email=f"admin-{uuid.uuid4().hex[:8]}@example.com",
                password_hash=hasher.hash("a strong-enough-password 9"),
                is_admin=True,  # <-- the critical bit
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
            # NO Membership row inserted: this is the whole point.
        ])
        await s.commit()

    return {
        "user_id": user_id,
        "session_id": session_id,
        "csrf": csrf,
        "project_id": project_id,
    }


def _admin_client(brain_app, settings: Settings, seed: dict) -> AsyncClient:
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
class TestSubscriptionCreateGlobalAdmin:
    async def test_global_admin_can_create_subscription_without_membership(
        self, settings: Settings, brain_app,
    ) -> None:
        """Pre-1.3.2 this returned 403 *you are not a member of this
        project*. Post-1.3.2 it must return 201."""
        seed = await _seed_global_admin_no_membership(brain_app, settings)

        async with _admin_client(brain_app, settings, seed) as client:
            resp = await client.post(
                "/api/v1/user/subscriptions",
                json={
                    "project_id": str(seed["project_id"]),
                    "trigger": "task.failed",
                    "filters": {
                        "priority": ["critical", "high", "normal", "low"],
                    },
                    "in_app": True,
                    "project_channel_ids": [],
                    "user_channel_ids": [],
                    "cooldown_seconds": 300,
                },
            )
            assert resp.status_code == 201, (
                f"global admin POST /user/subscriptions returned "
                f"{resp.status_code}: {resp.text}. Pre-1.3.2 this 403'd "
                f"with 'you are not a member of this project' even "
                f"though /auth/me synthesises an admin membership for "
                f"global admins on every project."
            )
            body = resp.json()
            assert body["project_id"] == str(seed["project_id"])
            assert body["trigger"] == "task.failed"
            assert body["in_app"] is True

    async def test_non_admin_non_member_still_blocked(
        self, settings: Settings, brain_app,
    ) -> None:
        """Sanity check: the bypass is gated on ``is_admin``. A regular
        user with no Membership row MUST still be blocked, otherwise
        we've turned the membership check into a no-op for everyone.
        """
        db = brain_app.state.db
        hasher = PasswordHasher(settings)
        user_id = uuid.uuid4()
        session_id = uuid.uuid4()
        csrf = secrets.token_urlsafe(32)
        project_id = uuid.uuid4()

        async with db.session() as s:
            s.add_all([
                Project(id=project_id, slug="picker", name="Picker"),
                User(
                    id=user_id,
                    email=f"user-{uuid.uuid4().hex[:8]}@example.com",
                    password_hash=hasher.hash("a strong-enough-password 9"),
                    is_admin=False,  # <-- NOT a global admin
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
                # No Membership.
            ])
            await s.commit()

        seed = {
            "user_id": user_id, "session_id": session_id,
            "csrf": csrf, "project_id": project_id,
        }
        async with _admin_client(brain_app, settings, seed) as client:
            resp = await client.post(
                "/api/v1/user/subscriptions",
                json={
                    "project_id": str(project_id),
                    "trigger": "task.failed",
                    "filters": {"priority": ["critical"]},
                    "in_app": True,
                    "project_channel_ids": [],
                    "user_channel_ids": [],
                    "cooldown_seconds": 0,
                },
            )
            # Either 403 (auth error path) or 401 (deps decided session
            # was anonymous) is acceptable here, the point is that the
            # 1.3.2 fix MUST NOT have widened the door to non-admins.
            assert resp.status_code in (401, 403), (
                f"non-admin non-member POST /user/subscriptions "
                f"returned {resp.status_code}: {resp.text}. The "
                f"1.3.2 ``is_admin`` bypass must remain narrow."
            )
