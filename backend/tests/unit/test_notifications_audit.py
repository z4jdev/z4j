"""Regression tests for the notification-routes audit gap.

Audit found that 8 of 9 mutating routes in
``z4j_brain.api.notifications`` had NO audit log entries despite
handling privileged operations:

- ``create_channel`` / ``update_channel`` / ``delete_channel`` -
  manage destinations carrying webhook URLs, bot tokens, SMTP
  creds.
- ``import_channel_from_user`` - copies a personal channel (with
  secrets) into a project. Cross-boundary secret movement.
- ``test_channel_config`` / ``test_saved_channel`` - dispatches a
  test message; classic data-exfil vector via attacker-controlled
  webhook URL.
- ``create_default`` / ``delete_default`` - templates that
  auto-materialise into every new member's preferences.

Per CLAUDE.md §2.3: "every command execution must write to the
audit log - no silent allows." These tests pin the fix.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence.base import Base
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.models import (
    AuditLog,
    NotificationChannel,
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


async def _seed(brain_app, settings: Settings) -> dict:
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    csrf = secrets.token_urlsafe(32)

    async with db.session() as s:
        s.add_all(
            [
                Project(id=project_id, slug="audit", name="Audit"),
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
            ],
        )
        await s.commit()

    return {
        "project_id": project_id,
        "user_id": user_id,
        "session_id": session_id,
        "csrf": csrf,
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


async def _audit_rows_for(brain_app, action: str) -> list:
    async with brain_app.state.db.session() as s:
        rows = (
            await s.execute(
                select(AuditLog).where(AuditLog.action == action),
            )
        ).scalars().all()
        return list(rows)


# =====================================================================
# Channel CRUD
# =====================================================================


class TestChannelCreateAudits:
    @pytest.mark.asyncio
    async def test_audit_row_written(
        self, settings: Settings, brain_app,
    ) -> None:
        # Use telegram - it's a no-URL channel type, so the
        # SSRF validator doesn't try to resolve a fake hostname.
        seed = await _seed(brain_app, settings)
        async with _client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/audit/notifications/channels",
                json={
                    "name": "ops-telegram",
                    "type": "telegram",
                    # Bot token must match the format the validator
                    # enforces (\d+:[A-Za-z0-9_-]+).
                    "config": {
                        "bot_token": "1234567890:ABCdefGHIjklMNOpqrSTUvwx",
                        "chat_id": "123456",
                    },
                    "is_active": True,
                },
            )
        assert r.status_code == 201, r.text
        rows = await _audit_rows_for(brain_app, "notifications.channel.create")
        assert len(rows) == 1
        meta = rows[0].audit_metadata
        assert meta["name"] == "ops-telegram"
        assert meta["type"] == "telegram"
        # NEVER include the raw config (would leak secrets to a
        # long-lived audit table).
        assert "config" not in meta
        assert "bot_token" not in str(meta)
        assert "chat_id" not in str(meta)


class TestChannelUpdateAudits:
    @pytest.mark.asyncio
    async def test_audit_row_with_changed_fields(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed(brain_app, settings)
        # Seed a channel.
        channel_id = uuid.uuid4()
        async with brain_app.state.db.session() as s:
            s.add(
                NotificationChannel(
                    id=channel_id,
                    project_id=seed["project_id"],
                    name="orig",
                    type="slack",
                    config={"webhook_url": "https://hooks.slack.example.com/old"},
                    is_active=True,
                ),
            )
            await s.commit()

        async with _client(brain_app, settings, seed) as client:
            r = await client.patch(
                f"/api/v1/projects/audit/notifications/channels/{channel_id}",
                json={"name": "renamed"},
            )
        assert r.status_code == 200, r.text
        rows = await _audit_rows_for(brain_app, "notifications.channel.update")
        assert len(rows) == 1
        meta = rows[0].audit_metadata
        assert meta["fields_changed"] == ["name"]
        assert meta["url_changed"] is False


class TestChannelDeleteAudits:
    @pytest.mark.asyncio
    async def test_audit_includes_deleted_name(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed(brain_app, settings)
        channel_id = uuid.uuid4()
        async with brain_app.state.db.session() as s:
            s.add(
                NotificationChannel(
                    id=channel_id,
                    project_id=seed["project_id"],
                    name="goner",
                    type="webhook",
                    config={"webhook_url": "https://example.com/hook"},
                    is_active=True,
                ),
            )
            await s.commit()

        async with _client(brain_app, settings, seed) as client:
            r = await client.delete(
                f"/api/v1/projects/audit/notifications/channels/{channel_id}",
            )
        assert r.status_code == 204
        rows = await _audit_rows_for(brain_app, "notifications.channel.delete")
        assert len(rows) == 1
        meta = rows[0].audit_metadata
        # Deleted channel's name + type land in metadata so the audit
        # row is human-readable instead of an opaque UUID reference.
        assert meta["name"] == "goner"
        assert meta["type"] == "webhook"


# =====================================================================
# Default subscription CRUD
# =====================================================================


class TestDefaultCreateAudits:
    @pytest.mark.asyncio
    async def test_audit_includes_trigger_and_channel_count(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed(brain_app, settings)
        async with _client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/audit/notifications/defaults",
                json={
                    "trigger": "task.failed",
                    "in_app": True,
                    "project_channel_ids": [],
                    "cooldown_seconds": 300,
                },
            )
        assert r.status_code == 201, r.text
        rows = await _audit_rows_for(brain_app, "notifications.default.create")
        assert len(rows) == 1
        meta = rows[0].audit_metadata
        assert meta["trigger"] == "task.failed"
        assert meta["in_app"] is True
        assert meta["channel_count"] == 0
        assert meta["cooldown_seconds"] == 300


class TestDefaultDeleteAudits:
    @pytest.mark.asyncio
    async def test_delete_audit_names_trigger(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _seed(brain_app, settings)
        # Create a default first via the API so it's in the DB.
        async with _client(brain_app, settings, seed) as client:
            r1 = await client.post(
                "/api/v1/projects/audit/notifications/defaults",
                json={
                    "trigger": "task.failed",
                    "in_app": True,
                    "project_channel_ids": [],
                    "cooldown_seconds": 0,
                },
            )
            assert r1.status_code == 201
            default_id = r1.json()["id"]

            r2 = await client.delete(
                f"/api/v1/projects/audit/notifications/defaults/{default_id}",
            )
        assert r2.status_code == 204
        rows = await _audit_rows_for(brain_app, "notifications.default.delete")
        assert len(rows) == 1
        # Trigger preserved in metadata so the audit row says
        # "deleted default for task.failed", not "deleted <uuid>".
        assert rows[0].audit_metadata["trigger"] == "task.failed"


# =====================================================================
# Source-code pin: every mutating route now imports + calls audit
# =====================================================================


class TestEveryWriteRouteImportsAudit:
    """Forensic check that future refactors don't drop the audit calls.

    Reads the source of api/notifications.py and asserts that every
    mutating handler references ``audit.record(``. A future
    refactor that accidentally drops one will fail this test.
    """

    def test_all_eight_routes_call_audit(self) -> None:
        import inspect

        from z4j_brain.api import notifications

        source = inspect.getsource(notifications)
        # Every mutating route handler should appear in the source
        # AND audit.record should appear in the source. Stronger:
        # for each handler, scan its specific function body.
        handlers = (
            notifications.create_channel,
            notifications.import_channel_from_user,
            notifications.update_channel,
            notifications.delete_channel,
            notifications.test_channel_config,
            notifications.test_saved_channel,
            notifications.create_default,
            notifications.delete_default,
        )
        for handler in handlers:
            handler_src = inspect.getsource(handler)
            assert "audit.record(" in handler_src, (
                f"{handler.__name__} does not call audit.record - "
                "audit-Phase4-1 regression"
            )
