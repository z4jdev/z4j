"""Saved channel responses redact credentials without breaking subsequent edits."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.domain.notifications import channels
from z4j_brain.main import create_app
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import Membership, NotificationChannel, Project, Session, User
from z4j_brain.persistence.models.notification import UserChannel
from z4j_brain.settings import Settings

MASK = "••••••••"
CONFIGS = {
    "webhook": {
        "url": "https://hooks.example.com/FAKESECRET",
        "headers": {"X-Api-Key": "FAKESECRET"},
        "hmac_secret": "FAKESECRET",
    },
    "slack": {"webhook_url": "https://hooks.slack.com/services/FAKESECRET"},
    "discord": {"webhook_url": "https://discord.com/api/webhooks/123/FAKESECRET"},
    "teams": {"webhook_url": "https://tenant.webhook.office.com/webhookb2/FAKESECRET"},
}


@pytest_asyncio.fixture
async def channel_app(migrated_db_url, migrated_audit_chain_secret, monkeypatch):
    settings = Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),
        session_secret=secrets.token_urlsafe(48),
        audit_chain_secret=migrated_audit_chain_secret,
        environment="dev",
        registry_backend="local",
        disable_spa_fallback=True,
    )
    engine = create_async_engine(migrated_db_url)
    app = create_app(settings, engine=engine)
    user_id, project_id, sid = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    csrf = secrets.token_urlsafe(32)
    # Keep the real per-type validation and merge paths; network destination
    # resolution alone is deterministic so these tests never contact services.
    resolver = AsyncMock(return_value=["93.184.216.34"])
    monkeypatch.setattr(channels, "_resolve_cached", resolver)
    async with app.state.db.session() as session:
        session.add_all(
            [
                User(
                    id=user_id, email="member@example.com", password_hash="unused", is_active=True
                ),
                Project(id=project_id, slug="channels", name="Channels"),
            ]
        )
        await session.flush()
        session.add_all(
            [
                Membership(user_id=user_id, project_id=project_id, role=ProjectRole.ADMIN),
                Session(
                    id=sid,
                    user_id=user_id,
                    csrf_token=csrf,
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                    ip_at_issue="127.0.0.1",
                    user_agent_at_issue="test",
                ),
            ]
        )
        await session.commit()
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
            headers={"X-CSRF-Token": csrf},
            cookies={cookie_name(environment="dev"): SessionCookieCodec(settings).encode(sid)},
        ) as client:
            yield SimpleNamespace(app=app, client=client, user_id=user_id, project_id=project_id)
    finally:
        await engine.dispose()


async def seed_channel(ctx, scope, channel_type="webhook", config=None):
    model = NotificationChannel if scope == "project" else UserChannel
    owner = {"project_id": ctx.project_id} if scope == "project" else {"user_id": ctx.user_id}
    async with ctx.app.state.db.session() as session:
        row = model(
            name="Operations", type=channel_type, config=config or CONFIGS[channel_type], **owner
        )
        session.add(row)
        await session.commit()
        channel_id = row.id
    prefix = "/api/v1/projects/channels/notifications" if scope == "project" else "/api/v1/user"
    return model, channel_id, f"{prefix}/channels"


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["project", "personal"])
@pytest.mark.parametrize("channel_type", CONFIGS)
async def test_reads_redact_destinations_and_header_credentials(channel_app, scope, channel_type):
    ctx = channel_app
    _, channel_id, path = await seed_channel(ctx, scope, channel_type)
    # A project viewer can read usable channel metadata, but not destination
    # bearer tokens or arbitrary custom-header credentials.
    async with ctx.app.state.db.session() as session:
        from sqlalchemy import update

        await session.execute(update(Membership).values(role=ProjectRole.VIEWER))
        await session.commit()
    response = await ctx.client.get(path)
    assert response.status_code == 200, response.text
    assert "FAKESECRET" not in response.text
    assert response.json()[0]["id"] == str(channel_id)
    assert response.json()[0]["name"] == "Operations"
    assert response.json()[0]["type"] == channel_type
    if scope == "project":
        denied = await ctx.client.patch(f"{path}/{channel_id}", json={"name": "Unauthorized"})
        assert denied.status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["project", "personal"])
@pytest.mark.parametrize("channel_type", CONFIGS)
async def test_read_edit_roundtrip_preserves_saved_credentials(channel_app, scope, channel_type):
    ctx = channel_app
    model, channel_id, path = await seed_channel(ctx, scope, channel_type)
    payload = (await ctx.client.get(path)).json()[0]
    response = await ctx.client.patch(
        f"{path}/{channel_id}",
        json={
            "name": "Renamed",
            "config": payload["config"],
        },
    )
    assert response.status_code == 200, response.text
    assert "FAKESECRET" not in response.text
    async with ctx.app.state.db.session() as session:
        row = await session.get(model, channel_id)
        assert row.name == "Renamed"
        assert row.config == CONFIGS[channel_type]


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["project", "personal"])
async def test_changing_destination_cannot_reuse_saved_headers(channel_app, scope):
    ctx = channel_app
    model, channel_id, path = await seed_channel(ctx, scope)
    response = await ctx.client.patch(
        f"{path}/{channel_id}",
        json={
            "config": {"url": "https://other.example.com/new"},
        },
    )
    assert response.status_code == 200, response.text
    async with ctx.app.state.db.session() as session:
        row = await session.get(model, channel_id)
        assert row.config == {"url": "https://other.example.com/new"}


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["project", "personal"])
async def test_invalid_masked_patch_rolls_back_other_fields(channel_app, scope):
    ctx = channel_app
    model, channel_id, path = await seed_channel(ctx, scope)
    response = await ctx.client.patch(
        f"{path}/{channel_id}",
        json={
            "name": "Should roll back",
            "config": {"url": MASK, "headers": ["invalid"]},
        },
    )
    assert response.status_code == 409, response.text
    async with ctx.app.state.db.session() as session:
        row = await session.get(model, channel_id)
        assert row.name == "Operations"
        assert row.config == CONFIGS["webhook"]


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["project", "personal"])
async def test_teams_create_rejects_non_teams_destination(channel_app, scope):
    prefix = "/api/v1/projects/channels/notifications" if scope == "project" else "/api/v1/user"
    response = await channel_app.client.post(
        f"{prefix}/channels",
        json={
            "name": "Invalid Teams",
            "type": "teams",
            "config": {"webhook_url": "https://attacker.example.com/collect"},
        },
    )
    assert response.status_code == 409, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["project", "personal"])
@pytest.mark.parametrize(
    "destination",
    [
        {"smtp_host": "other.example.com"},
        {"smtp_port": 465},
        {"smtp_tls": False},
    ],
)
async def test_changing_smtp_destination_discards_saved_password(channel_app, scope, destination):
    ctx = channel_app
    config = {"smtp_host": "smtp.example.com", "smtp_port": 587, "smtp_pass": "FAKESECRET"}
    model, channel_id, path = await seed_channel(ctx, scope, "email", config)
    response = await ctx.client.patch(f"{path}/{channel_id}", json={"config": destination})
    assert response.status_code == 200, response.text
    async with ctx.app.state.db.session() as session:
        row = await session.get(model, channel_id)
        assert row.config == {"smtp_host": "smtp.example.com", "smtp_port": 587, **destination}
    # A subsequent explicit rotation belongs to the new destination and persists.
    rotated = await ctx.client.patch(
        f"{path}/{channel_id}", json={"config": {"smtp_pass": "NEWSECRET"}}
    )
    assert rotated.status_code == 200, rotated.text
    assert "NEWSECRET" not in rotated.text
    async with ctx.app.state.db.session() as session:
        row = await session.get(model, channel_id)
        assert row.config["smtp_pass"] == "NEWSECRET"


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["project", "personal"])
async def test_destination_change_accepts_explicit_new_credentials(channel_app, scope):
    ctx = channel_app
    model, channel_id, path = await seed_channel(ctx, scope)
    config = {"url": "https://other.example.com/new", "headers": {"X-Api-Key": "NEWSECRET"}}
    response = await ctx.client.patch(f"{path}/{channel_id}", json={"config": config})
    assert response.status_code == 200, response.text
    assert "NEWSECRET" not in response.text
    async with ctx.app.state.db.session() as session:
        row = await session.get(model, channel_id)
        assert row.config == config


@pytest.mark.asyncio
async def test_non_ascii_csrf_header_is_refused_without_mutation(channel_app):
    ctx = channel_app
    model, channel_id, path = await seed_channel(ctx, "project")
    length = len(ctx.client.headers["X-CSRF-Token"])
    response = await ctx.client.patch(
        f"{path}/{channel_id}",
        headers={b"X-CSRF-Token": b"\xe9" * length},
        json={"name": "Should not save"},
    )
    assert response.status_code == 403, response.text
    async with ctx.app.state.db.session() as session:
        row = await session.get(model, channel_id)
        assert row.name == "Operations"
