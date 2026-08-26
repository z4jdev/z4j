"""Regression tests for the notification-routes audit gap.

The router currently exposes ten mutating routes.  The inventory test derives
that set from FastAPI's route table, so adding an eleventh mutator without
accounting for it fails instead of silently escaping a hand-maintained list.

- ``create_channel`` / ``update_channel`` / ``delete_channel`` -
  manage destinations carrying webhook URLs, bot tokens, SMTP
  creds.
- ``import_channel_from_user`` - copies a personal channel (with
  secrets) into a project. Cross-boundary secret movement.
- ``test_channel_config`` / ``test_saved_channel`` - dispatches a
  test message; classic data-exfil vector via attacker-controlled
  webhook URL.
- ``create_default`` / ``update_default`` / ``delete_default`` - templates that
  auto-materialise into every new member's preferences.
- ``clear_deliveries`` - destructive removal of delivery history.

Invariant: every command execution must write to the audit log, with
no silent allows. These tests pin the fix.
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
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import (
    AuditLog,
    NotificationChannel,
    NotificationDelivery,
    Project,
    ProjectDefaultSubscription,
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
            ],
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
            (
                await s.execute(
                    select(AuditLog).where(AuditLog.action == action),
                )
            )
            .scalars()
            .all()
        )
        return list(rows)


# =====================================================================
# Channel CRUD
# =====================================================================


class TestChannelCreateAudits:
    @pytest.mark.asyncio
    async def test_audit_row_written(
        self,
        settings: Settings,
        brain_app,
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
        self,
        settings: Settings,
        brain_app,
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
        self,
        settings: Settings,
        brain_app,
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
        self,
        settings: Settings,
        brain_app,
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
        self,
        settings: Settings,
        brain_app,
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


class TestDefaultUpdateAudits:
    @pytest.mark.asyncio
    async def test_update_audit_records_runtime_changes(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        seed = await _seed(brain_app, settings)
        default_id = uuid.uuid4()
        async with brain_app.state.db.session() as session:
            session.add(
                ProjectDefaultSubscription(
                    id=default_id,
                    project_id=seed["project_id"],
                    trigger="task.failed",
                    filters={},
                    in_app=True,
                    project_channel_ids=[],
                    cooldown_seconds=0,
                ),
            )
            await session.commit()

        async with _client(brain_app, settings, seed) as client:
            response = await client.patch(
                f"/api/v1/projects/audit/notifications/defaults/{default_id}",
                json={"cooldown_seconds": 90},
            )

        assert response.status_code == 200, response.text
        rows = await _audit_rows_for(brain_app, "notifications.default.update")
        assert len(rows) == 1
        assert rows[0].audit_metadata["changed"] == {
            "cooldown_seconds": {"from": 0, "to": 90},
        }


class TestClearDeliveriesAudits:
    @pytest.mark.asyncio
    async def test_clear_audit_records_deleted_count(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        seed = await _seed(brain_app, settings)
        async with brain_app.state.db.session() as session:
            session.add(
                NotificationDelivery(
                    project_id=seed["project_id"],
                    trigger="task.failed",
                    status="failed",
                    error="transport unavailable",
                ),
            )
            await session.commit()

        async with _client(brain_app, settings, seed) as client:
            response = await client.delete(
                "/api/v1/projects/audit/notifications/deliveries",
            )

        assert response.status_code == 200, response.text
        assert response.json() == {"deleted": 1}
        rows = await _audit_rows_for(brain_app, "notifications.deliveries.clear")
        assert len(rows) == 1
        assert rows[0].audit_metadata["deleted_count"] == 1


# =====================================================================
# Complete route inventory, plus ordering guards for outbound side effects
# =====================================================================


class TestEveryWriteRouteIsAccountedFor:
    def test_fastapi_mutator_inventory_is_complete(self) -> None:
        from z4j_brain.api import notifications

        expected_actions = {
            "create_channel": "notifications.channel.create",
            "import_channel_from_user": "notifications.channel.import",
            "update_channel": "notifications.channel.update",
            "delete_channel": "notifications.channel.delete",
            "test_channel_config": "notifications.channel.test",
            "test_saved_channel": "notifications.channel.test",
            "create_default": "notifications.default.create",
            "update_default": "notifications.default.update",
            "delete_default": "notifications.default.delete",
            "clear_deliveries": "notifications.deliveries.clear",
        }
        actual = {
            route.endpoint.__name__
            for route in notifications.router.routes
            if route.methods & {"POST", "PATCH", "PUT", "DELETE"}
        }

        assert actual == expected_actions.keys()

    def test_saved_channel_contract_discloses_delivery_log_persistence(self) -> None:
        from z4j_brain.api import notifications

        contract = " ".join((notifications.test_saved_channel.__doc__ or "").split())
        assert "logged to ``notification_deliveries``" in contract
        assert '``trigger="test.dispatch"``' in contract
        assert "NOT logged" not in contract

    @pytest.mark.asyncio
    async def test_project_channel_preflight_commits_intent_before_dispatch(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from types import SimpleNamespace
        from unittest.mock import AsyncMock

        from starlette.requests import Request
        from z4j_brain.api import notifications

        project_id = uuid.uuid4()
        audit = SimpleNamespace(record=AsyncMock())
        session = SimpleNamespace(commit=AsyncMock())

        async def dispatch(*_args, **_kwargs):
            assert session.commit.await_count == 1
            assert [call.kwargs["action"] for call in audit.record.await_args_list] == [
                "notifications.channel.test_requested",
            ]
            return notifications.ChannelTestResult(success=True, status_code=200)

        monkeypatch.setattr(
            notifications,
            "_resolve_member_project",
            AsyncMock(return_value=project_id),
        )
        monkeypatch.setattr(notifications, "_dispatch_test", dispatch)
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/v1/projects/audit/notifications/channels/test",
                "headers": [],
                "client": ("127.0.0.1", 1234),
            },
        )

        result = await notifications.test_channel_config(
            slug="audit",
            body=notifications.ChannelTestRequest(
                type="telegram",
                config={"bot_token": "123:token", "chat_id": "123"},
            ),
            request=request,
            user=SimpleNamespace(id=uuid.uuid4()),
            memberships=object(),
            projects=object(),
            audit_log=object(),
            audit=audit,
            db_session=session,
        )

        assert result.success is True
        assert [call.kwargs["action"] for call in audit.record.await_args_list] == [
            "notifications.channel.test_requested",
            "notifications.channel.test",
        ]
        assert session.commit.await_count == 2

    @pytest.mark.asyncio
    async def test_invitation_email_commits_intent_before_send(
        self,
        monkeypatch: pytest.MonkeyPatch,
        brain_settings,
    ) -> None:
        from types import SimpleNamespace
        from unittest.mock import AsyncMock

        from z4j_brain.api import invitations

        project = SimpleNamespace(id=uuid.uuid4(), slug="audit", name="Audit", is_active=True)
        user = SimpleNamespace(id=uuid.uuid4(), is_admin=True)
        now = datetime.now(UTC)
        invitation = SimpleNamespace(
            id=uuid.uuid4(),
            project_id=project.id,
            email="invitee@example.com",
            role="viewer",
            invited_by=user.id,
            expires_at=now + timedelta(days=7),
            accepted_at=None,
            revoked_at=None,
            created_at=now,
        )
        repository = SimpleNamespace(create=AsyncMock(return_value=invitation))
        audit = SimpleNamespace(record=AsyncMock())
        session = SimpleNamespace(commit=AsyncMock())

        async def send(**_kwargs) -> bool:
            assert session.commit.await_count == 1
            assert [call.kwargs["action"] for call in audit.record.await_args_list] == [
                "invitation.mint",
                "invitation.email_delivery_requested",
            ]
            return True

        monkeypatch.setattr(invitations, "_try_send_invitation_email", send)
        result = await invitations.mint_invitation(
            slug="audit",
            body=invitations.InvitationCreateRequest(
                email="invitee@example.com",
                role="viewer",
            ),
            user=user,
            memberships=object(),
            projects=SimpleNamespace(get_by_slug=AsyncMock(return_value=project)),
            invitations=repository,
            users=SimpleNamespace(get_by_email=AsyncMock(return_value=None)),
            settings=brain_settings,
            audit=audit,
            audit_log=object(),
            db_session=session,
            ip="127.0.0.1",
        )

        assert result.email_sent is True
        assert [call.kwargs["action"] for call in audit.record.await_args_list] == [
            "invitation.mint",
            "invitation.email_delivery_requested",
            "invitation.email_delivery_result",
        ]
        assert session.commit.await_count == 2
