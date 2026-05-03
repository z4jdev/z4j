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

from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import (
    NotificationChannel,
    Project,
    Session,
    User,
)
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
        self, integration_settings: Settings, brain_app,
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
            print(f"\n!!! status={r.status_code}\nbody={r.text}")
        assert r.status_code == 201, r.text
