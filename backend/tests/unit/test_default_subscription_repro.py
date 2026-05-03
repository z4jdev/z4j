"""Reproducer for the production 500 on Add Default Subscription.

NOTE: passes on SQLite (in-memory). Bug only surfaces on the
Postgres deployment - probably the ``ARRAY(Uuid)`` column type
or a JSONB serialisation difference. The Postgres reproducer is
in ``tests/integration/test_default_subscription_pg.py``.

Screenshot from operator: clicking "Create Default" in the
dashboard's Project Settings → Defaults page produced three
"Failed: the brain encountered an unexpected error" toasts. Form
shape:

- Trigger: "Task failed"  → ``task.failed``
- In-app: True
- Project channels: telegram + slack + email (3 ids)
- Cooldown: 300

These tests poke the same code path with the same shape to find
out which branch is throwing.
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
from z4j_brain.persistence.models import (
    Membership,
    NotificationChannel,
    Project,
    Session,
    User,
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


async def _seed(brain_app, settings: Settings):
    """Admin user + project + three project channels matching the screenshot."""
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    csrf = secrets.token_urlsafe(32)
    channel_ids = {
        "telegram": uuid.uuid4(),
        "slack": uuid.uuid4(),
        "email": uuid.uuid4(),
    }

    async with db.session() as s:
        s.add_all(
            [
                Project(id=project_id, slug="fragai", name="FragAI"),
                User(
                    id=user_id,
                    email=f"u-{uuid.uuid4().hex[:8]}@example.com",
                    password_hash=hasher.hash("correct horse battery staple 9"),
                    is_admin=True,
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
                NotificationChannel(
                    id=channel_ids["telegram"],
                    project_id=project_id,
                    name="Frag.ai Fail Task TG",
                    type="telegram",
                    config={"bot_token": "x", "chat_id": "y"},
                    is_active=True,
                ),
                NotificationChannel(
                    id=channel_ids["slack"],
                    project_id=project_id,
                    name="Fragi.ai Failed Task",
                    type="slack",
                    config={"webhook_url": "https://hooks.slack.example.com/x"},
                    is_active=True,
                ),
                NotificationChannel(
                    id=channel_ids["email"],
                    project_id=project_id,
                    name="Frag.ai Fail Task Gmail",
                    type="email",
                    config={"to": "ops@example.com"},
                    is_active=True,
                ),
            ],
        )
        await s.commit()

    return {
        "project_id": project_id,
        "user_id": user_id,
        "session_id": session_id,
        "csrf": csrf,
        "channel_ids": channel_ids,
    }


def _client(brain_app, settings: Settings, seed: dict):
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


class TestProductionRepro:
    @pytest.mark.asyncio
    async def test_create_default_with_three_channels(
        self, settings: Settings, brain_app,
    ) -> None:
        # Exact shape from the screenshot.
        seed = await _seed(brain_app, settings)
        async with _client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/fragai/notifications/defaults",
                json={
                    "trigger": "task.failed",
                    "in_app": True,
                    "project_channel_ids": [
                        str(seed["channel_ids"]["telegram"]),
                        str(seed["channel_ids"]["slack"]),
                        str(seed["channel_ids"]["email"]),
                    ],
                    "cooldown_seconds": 300,
                },
            )
        # Print the body so the failure surfaces the actual error.
        if r.status_code != 201:
            print(f"\n!!! status={r.status_code}\nbody={r.text}")
        assert r.status_code == 201, r.text


class TestBadInputShapes:
    """The operator's screenshot shows three 'unexpected error' toasts.

    A 500 (vs 422) means the route accepted the request body and
    threw inside the handler. Try every plausible bad-input shape
    that could land in a 500 instead of a clean 422/409.
    """

    @pytest.mark.asyncio
    async def test_dashboard_label_instead_of_value_returns_422_not_500(
        self, settings: Settings, brain_app,
    ) -> None:
        # The dashboard might send the LABEL ("Task failed") instead
        # of the VALUE ("task.failed"). Should be a clean 422.
        seed = await _seed(brain_app, settings)
        async with _client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/fragai/notifications/defaults",
                json={
                    "trigger": "Task failed",  # WRONG - has space + cap
                    "in_app": True,
                    "project_channel_ids": [],
                    "cooldown_seconds": 300,
                },
            )
        assert r.status_code in (400, 422), (
            f"bad trigger should be 422/400, got {r.status_code}: {r.text}"
        )

    @pytest.mark.asyncio
    async def test_invalid_uuid_in_channel_list_clean_status(
        self, settings: Settings, brain_app,
    ) -> None:
        # Sending a non-UUID string in project_channel_ids.
        seed = await _seed(brain_app, settings)
        async with _client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/fragai/notifications/defaults",
                json={
                    "trigger": "task.failed",
                    "in_app": True,
                    "project_channel_ids": ["not-a-uuid"],
                    "cooldown_seconds": 300,
                },
            )
        assert r.status_code == 422, (
            f"bad uuid should be 422, got {r.status_code}: {r.text}"
        )

    @pytest.mark.asyncio
    async def test_channel_id_from_other_project_returns_clean_409(
        self, settings: Settings, brain_app,
    ) -> None:
        # Sending a channel id that exists but belongs to a
        # different project. Should hit the validator and return
        # 409, NOT 500. Tests the IDOR scoping path.
        seed = await _seed(brain_app, settings)
        # Create a second project + channel.
        from z4j_brain.persistence.models import Project as P, NotificationChannel as NC
        other_project_id = uuid.uuid4()
        other_channel_id = uuid.uuid4()
        async with brain_app.state.db.session() as s:
            s.add(P(id=other_project_id, slug="other", name="Other"))
            await s.commit()
        async with brain_app.state.db.session() as s:
            s.add(
                NC(
                    id=other_channel_id,
                    project_id=other_project_id,
                    name="other-channel",
                    type="slack",
                    config={"webhook_url": "https://x"},
                    is_active=True,
                ),
            )
            await s.commit()

        async with _client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/fragai/notifications/defaults",
                json={
                    "trigger": "task.failed",
                    "in_app": True,
                    "project_channel_ids": [str(other_channel_id)],
                    "cooldown_seconds": 300,
                },
            )
        # MUST be 409, not 500. If 500, the IDOR scoping check is
        # broken and returns a generic error instead of a clean
        # ConflictError.
        assert r.status_code == 409, (
            f"cross-project channel id should be 409, got "
            f"{r.status_code}: {r.text}"
        )

    @pytest.mark.asyncio
    async def test_duplicate_trigger_returns_409_on_second_post(
        self, settings: Settings, brain_app,
    ) -> None:
        # First create succeeds; second with same trigger must
        # return 409, not 500.
        seed = await _seed(brain_app, settings)
        body = {
            "trigger": "task.failed",
            "in_app": True,
            "project_channel_ids": [],
            "cooldown_seconds": 300,
        }
        async with _client(brain_app, settings, seed) as client:
            r1 = await client.post(
                "/api/v1/projects/fragai/notifications/defaults",
                json=body,
            )
            assert r1.status_code == 201
            r2 = await client.post(
                "/api/v1/projects/fragai/notifications/defaults",
                json=body,
            )
        assert r2.status_code == 409, (
            f"duplicate trigger should be 409, got "
            f"{r2.status_code}: {r2.text}"
        )

    @pytest.mark.asyncio
    async def test_unknown_filter_field_silently_dropped(
        self, settings: Settings, brain_app,
    ) -> None:
        """v1.0.19 H2 fix: ``SubscriptionFilters`` switched from
        ``extra="forbid"`` to ``extra="ignore"`` so a newer dashboard
        sending a future filter key against an older brain doesn't
        422. Unknown keys are silently dropped at validate time;
        the created row carries only the keys the brain knows
        about. Pinned by
        ``test_compat_fixes.py::TestH2SubscriptionFiltersExtraIgnore``;
        this test is the project-defaults companion check.
        """
        seed = await _seed(brain_app, settings)
        async with _client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/fragai/notifications/defaults",
                json={
                    "trigger": "task.failed",
                    "in_app": True,
                    "project_channel_ids": [],
                    "cooldown_seconds": 300,
                    "filters": {"made_up_field": "x", "priority": ["high"]},
                },
            )
        assert r.status_code in (200, 201), (
            f"unknown filter key should be silently dropped (v1.0.19 H2), "
            f"got {r.status_code}: {r.text}"
        )
        body = r.json()
        # The known key survived; the unknown key was stripped.
        assert body.get("filters", {}).get("priority") == ["high"]
        assert "made_up_field" not in body.get("filters", {})
