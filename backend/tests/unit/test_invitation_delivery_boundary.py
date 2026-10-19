"""Invitation mint survives the channel-read rollback and SMTP failures."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.api.invitations import _hash_token
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.domain.notifications import channels
from z4j_brain.main import create_app
from z4j_brain.persistence.models import (
    AuditLog,
    Invitation,
    NotificationChannel,
    Project,
    Session,
    User,
)
from z4j_brain.settings import Settings


@pytest.mark.asyncio
@pytest.mark.parametrize("delivery", ["none", "success", "failed", "exception"])
async def test_mint_returns_token_after_channel_transaction_ends(
    delivery: str,
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),
        session_secret=secrets.token_urlsafe(48),
        audit_chain_secret=migrated_audit_chain_secret,
        environment="dev",
        log_json=False,
        registry_backend="local",
        disable_spa_fallback=True,
    )
    engine = create_async_engine(settings.database_url)
    app = create_app(settings, engine=engine)
    project_id, user_id, session_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    csrf = secrets.token_urlsafe(32)
    observations = []

    async def deliver(**kwargs):
        # The transport must run after the mint/intent commit and without
        # retaining the request connection or its channel-read transaction.
        checked_out = engine.pool.checkedout()
        async with app.state.db.session() as session:
            invitation = (await session.scalars(select(Invitation))).one()
            actions = list(
                await session.scalars(
                    select(AuditLog.action).where(AuditLog.target_id == str(invitation.id)),
                ),
            )
        observations.append((checked_out, set(actions), kwargs))
        if delivery == "exception":
            raise RuntimeError("SMTP unavailable")
        return SimpleNamespace(success=delivery == "success", error="SMTP unavailable")

    send = AsyncMock(side_effect=deliver)
    monkeypatch.setattr(channels, "deliver_email", send)
    try:
        async with app.state.db.session() as session:
            session.add_all(
                [
                    Project(id=project_id, slug="invite-team", name="Invite Team"),
                    User(
                        id=user_id,
                        email="admin@example.com",
                        password_hash="unused-password-hash",
                        is_admin=True,
                        is_active=True,
                    ),
                ],
            )
            await session.flush()
            session.add(
                Session(
                    id=session_id,
                    user_id=user_id,
                    csrf_token=csrf,
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                    ip_at_issue="127.0.0.1",
                    user_agent_at_issue="test",
                ),
            )
            if delivery != "none":
                session.add(
                    NotificationChannel(
                        project_id=project_id,
                        name="Team email",
                        type="email",
                        config={"smtp_host": "smtp.example.com"},
                        is_active=True,
                    ),
                )
            await session.commit()

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
            headers={"X-CSRF-Token": csrf},
            cookies={
                cookie_name(environment=settings.environment): SessionCookieCodec(settings).encode(
                    session_id,
                ),
            },
        ) as client:
            response = await client.post(
                "/api/v1/projects/invite-team/invitations",
                json={"email": "invitee@example.com", "role": "viewer"},
            )
            assert response.status_code == 201, response.text
            body = response.json()
            assert body["email_sent"] is (delivery == "success")
            assert body["accept_url_path"] == f"/invite#token={body['token']}"
            assert body["invitation"]["project_id"] == str(project_id)
            assert body["invitation"]["invited_by"] == str(user_id)
            assert body["invitation"]["email"] == "invitee@example.com"
            preview = await client.post(
                "/api/v1/invitations/preview",
                json={"token": body["token"]},
            )
            assert preview.status_code == 200, preview.text
            assert preview.json()["email"] == "invitee@example.com"

        async with app.state.db.session() as session:
            invitation = (await session.scalars(select(Invitation))).one()
            assert str(invitation.id) == body["invitation"]["id"]
            assert invitation.token_hash == _hash_token(body["token"], settings)
            audit_rows = list(
                await session.scalars(
                    select(AuditLog).where(AuditLog.target_id == str(invitation.id)),
                ),
            )
            assert {row.action for row in audit_rows} == {
                "invitation.mint",
                "invitation.email_delivery_requested",
                "invitation.email_delivery_result",
            }
            result = next(row for row in audit_rows if row.action.endswith("delivery_result"))
            assert result.result == ("success" if delivery == "success" else "failed")
            assert result.user_id == user_id
            assert result.project_id == project_id
            assert result.audit_metadata["delivered"] is (delivery == "success")

        if delivery == "none":
            send.assert_not_awaited()
        else:
            send.assert_awaited_once()
            checked_out, actions, kwargs = observations[0]
            assert checked_out == 0
            assert actions == {"invitation.mint", "invitation.email_delivery_requested"}
            assert body["token"] in kwargs["payload"]["body"]
    finally:
        await engine.dispose()
