"""Postgres-backed reproducer for the production 500 on Add Default Subscription.

The unit test in tests/unit/test_default_subscription_repro.py
passes against SQLite. The operator's screenshot shows a 500 in
production, which runs Postgres - so the bug is in a code path
that diverges between SQLite and Postgres. Suspects:

- ``ARRAY(Uuid(as_uuid=True))`` for ``project_channel_ids``
- JSONB serialisation of ``filters``
- Unique-constraint violation surfaced through asyncpg

Reproducing here lets us see the actual exception class and
fix it.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence.models import (
    AuditLog,
    NotificationChannel,
    Project,
    ProjectDefaultSubscription,
    Session,
    User,
)
from z4j_brain.persistence.repositories import ProjectDefaultSubscriptionRepository
from z4j_brain.settings import Settings


@pytest.fixture
async def brain_app(integration_settings: Settings, migrated_engine):
    """create_app bound to a real Postgres + alembic-migrated schema."""
    app = create_app(integration_settings, engine=migrated_engine)
    yield app


async def _seed(brain_app, settings: Settings) -> dict:
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

    # Commit in FK-safe order: project + user first, then session
    # (FK→user), then channels (FK→project). SQLAlchemy's bulk
    # insert reorders by class but the reorder doesn't always
    # match our FKs.
    async with db.session() as s:
        s.add(Project(id=project_id, slug="fragai", name="FragAI"))
        s.add(
            User(
                id=user_id,
                email=f"u-{uuid.uuid4().hex[:8]}@example.com",
                password_hash=hasher.hash("correct horse battery staple 9"),
                is_admin=True,
                is_active=True,
            ),
        )
        await s.commit()

    async with db.session() as s:
        s.add(
            Session(
                id=session_id,
                user_id=user_id,
                csrf_token=csrf,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                ip_at_issue="127.0.0.1",
                user_agent_at_issue="test",
            ),
        )
        await s.commit()

    async with db.session() as s:
        s.add(
            NotificationChannel(
                id=channel_ids["telegram"],
                project_id=project_id,
                name="Frag.ai Fail Task TG",
                type="telegram",
                config={"bot_token": "x", "chat_id": "y"},
                is_active=True,
            ),
        )
        s.add(
            NotificationChannel(
                id=channel_ids["slack"],
                project_id=project_id,
                name="Fragi.ai Failed Task",
                type="slack",
                config={"webhook_url": "https://hooks.slack.example.com/x"},
                is_active=True,
            ),
        )
        s.add(
            NotificationChannel(
                id=channel_ids["email"],
                project_id=project_id,
                name="Frag.ai Fail Task Gmail",
                type="email",
                config={"to": "ops@example.com"},
                is_active=True,
            ),
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
    async def test_create_default_with_three_channels_pg(
        self,
        integration_settings: Settings,
        brain_app,
    ) -> None:
        """Same shape as the operator's screenshot. Against real Postgres."""
        seed = await _seed(brain_app, integration_settings)
        async with _client(brain_app, integration_settings, seed) as client:
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
        if r.status_code != 201:
            print(f"\n!!! status={r.status_code}\nbody={r.text}")  # noqa: T201  diagnostic on assertion failure
        assert r.status_code == 201, r.text


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["create", "update"])
async def test_default_trigger_race_returns_conflict(
    operation: str,
    integration_settings: Settings,
    brain_app,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A committed arrival after the precheck loses cleanly at the real flush."""
    seed = await _seed(brain_app, integration_settings)
    original_id, competitor_id = uuid.uuid4(), uuid.uuid4()
    async with brain_app.state.db.session() as session:
        session.add(
            ProjectDefaultSubscription(
                id=original_id,
                project_id=seed["project_id"],
                trigger="task.failed",
                filters={},
                in_app=True,
                project_channel_ids=[],
                cooldown_seconds=300,
            ),
        )
        await session.commit()

    original_check = ProjectDefaultSubscriptionRepository.exists_for_project_trigger

    async def concurrent_arrival(repo, project_id, trigger):
        exists = await original_check(repo, project_id, trigger)
        assert not exists
        # PostgreSQL lets this independent writer commit while the request's
        # READ COMMITTED transaction still retains its earlier precheck result.
        async with brain_app.state.db.session() as session:
            session.add(
                ProjectDefaultSubscription(
                    id=competitor_id,
                    project_id=project_id,
                    trigger=trigger,
                    filters={},
                    in_app=True,
                    project_channel_ids=[],
                    cooldown_seconds=10,
                ),
            )
            await session.commit()
        return exists

    monkeypatch.setattr(
        ProjectDefaultSubscriptionRepository,
        "exists_for_project_trigger",
        concurrent_arrival,
    )
    async with _client(brain_app, integration_settings, seed) as client:
        url = "/api/v1/projects/fragai/notifications/defaults"
        body = {"trigger": "task.succeeded", "cooldown_seconds": 90}
        if operation == "create":
            response = await client.post(url, json=body)
        else:
            response = await client.patch(f"{url}/{original_id}", json=body)

    assert response.status_code == 409, response.text
    assert response.json()["details"] == {"trigger": "task.succeeded"}
    async with brain_app.state.db.session() as session:
        defaults = list(
            await session.scalars(
                select(ProjectDefaultSubscription).where(
                    ProjectDefaultSubscription.project_id == seed["project_id"],
                ),
            ),
        )
        assert {row.id for row in defaults} == {original_id, competitor_id}
        original = next(row for row in defaults if row.id == original_id)
        assert original.trigger == "task.failed"
        assert original.cooldown_seconds == 300
        competitor = next(row for row in defaults if row.id == competitor_id)
        assert competitor.trigger == "task.succeeded"
        assert competitor.cooldown_seconds == 10
        audit_rows = list(
            await session.scalars(
                select(AuditLog).where(
                    AuditLog.action.in_(
                        ["notifications.default.create", "notifications.default.update"],
                    ),
                ),
            ),
        )
        assert audit_rows == []
