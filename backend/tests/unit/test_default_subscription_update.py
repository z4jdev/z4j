"""Regression tests for PATCH /defaults/{default_id} (added v1.0.18).

Closes the operator-reported gap: previously the only way to add a
new channel to an existing default subscription was to delete and
recreate it. The PATCH endpoint allows partial updates - any subset
of trigger / filters / in_app / project_channel_ids /
cooldown_seconds.

These tests cover:

1. Partial update: change ONLY project_channel_ids, leave everything
   else (trigger, in_app, cooldown) intact.
2. Trigger rename: change task.failed -> task.succeeded.
3. Trigger collision: rename to a trigger that already has a
   default in the same project -> 409 ConflictError.
4. Channel-not-in-project: PATCH with a channel id that belongs to
   a different project -> 409 ConflictError, no partial write.
5. IDOR: admin of project A cannot PATCH a default in project B
   even with the right default_id -> 404 (the get_for_project
   scoping returns None).
6. Empty PATCH body: no-op, returns the row unchanged.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.auth.csrf import csrf_cookie_name
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
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
    """Admin + project + 3 channels + 1 existing default subscription."""
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    csrf = secrets.token_urlsafe(32)
    ch_ids = [uuid.uuid4() for _ in range(3)]
    default_id = uuid.uuid4()

    async with db.session() as s:
        project = Project(id=project_id, slug="fragai", name="FragAI")
        user = User(
            id=user_id,
            email=f"u-{uuid.uuid4().hex[:8]}@example.com",
            password_hash=hasher.hash(
                "correct horse battery staple 9",
            ),
            is_admin=True,
            is_active=True,
        )
        s.add_all([project, user])
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
            ]
        )
        for i, cid in enumerate(ch_ids):
            s.add(
                NotificationChannel(
                    id=cid,
                    project_id=project_id,
                    name=f"channel-{i}",
                    type="webhook",
                    config={"url": f"https://example.test/{i}"},
                    is_active=True,
                )
            )
        # Existing default - exactly two of the three channels.
        s.add(
            ProjectDefaultSubscription(
                id=default_id,
                project_id=project_id,
                trigger="task.failed",
                filters={},
                in_app=True,
                project_channel_ids=[ch_ids[0], ch_ids[1]],
                cooldown_seconds=300,
            )
        )
        await s.commit()

    return {
        "project_id": project_id,
        "user_id": user_id,
        "session_id": session_id,
        "csrf": csrf,
        "channel_ids": ch_ids,
        "default_id": default_id,
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
class TestUpdateDefaultSubscription:
    async def test_add_third_channel_to_existing_default(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        """The exact operator workflow: existing default has 2
        channels, admin wants to add a 3rd. Pre-PATCH the only
        path was delete + recreate.
        """
        seed = await _seed(brain_app, settings)
        async with _client(brain_app, settings, seed) as client:
            url = f"/api/v1/projects/fragai/notifications/defaults/{seed['default_id']}"
            resp = await client.patch(
                url,
                json={
                    "project_channel_ids": [
                        str(seed["channel_ids"][0]),
                        str(seed["channel_ids"][1]),
                        str(seed["channel_ids"][2]),
                    ],
                },
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["id"] == str(seed["default_id"])
            assert len(body["project_channel_ids"]) == 3
            # Other fields untouched
            assert body["trigger"] == "task.failed"
            assert body["in_app"] is True
            assert body["cooldown_seconds"] == 300

    async def test_partial_update_only_cooldown(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        """Body containing only cooldown_seconds leaves everything else."""
        seed = await _seed(brain_app, settings)
        async with _client(brain_app, settings, seed) as client:
            url = f"/api/v1/projects/fragai/notifications/defaults/{seed['default_id']}"
            resp = await client.patch(url, json={"cooldown_seconds": 30})
            assert resp.status_code == 200
            body = resp.json()
            assert body["cooldown_seconds"] == 30
            # Channels unchanged
            assert len(body["project_channel_ids"]) == 2

    async def test_rename_trigger(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        """task.failed -> task.succeeded."""
        seed = await _seed(brain_app, settings)
        async with _client(brain_app, settings, seed) as client:
            url = f"/api/v1/projects/fragai/notifications/defaults/{seed['default_id']}"
            resp = await client.patch(url, json={"trigger": "task.succeeded"})
            assert resp.status_code == 200
            assert resp.json()["trigger"] == "task.succeeded"

    async def test_rename_trigger_to_already_used_409(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        """Renaming to a trigger that already has a default -> 409."""
        seed = await _seed(brain_app, settings)
        # Insert a second default so the rename collides.
        async with brain_app.state.db.session() as s:
            s.add(
                ProjectDefaultSubscription(
                    project_id=seed["project_id"],
                    trigger="task.succeeded",
                    filters={},
                    in_app=True,
                    project_channel_ids=[],
                    cooldown_seconds=0,
                )
            )
            await s.commit()
        async with _client(brain_app, settings, seed) as client:
            url = f"/api/v1/projects/fragai/notifications/defaults/{seed['default_id']}"
            resp = await client.patch(url, json={"trigger": "task.succeeded"})
            assert resp.status_code == 409, resp.text
            assert "already exists" in resp.json()["message"]

    async def test_channel_not_in_project_409(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        """A channel id from a different project is rejected
        before any write hits the DB."""
        seed = await _seed(brain_app, settings)
        # Create a second project + a channel in it; the admin
        # tries to attach that foreign channel to the FragAI
        # default.
        other_project_id = uuid.uuid4()
        other_channel_id = uuid.uuid4()
        async with brain_app.state.db.session() as s:
            s.add(Project(id=other_project_id, slug="other", name="Other"))
            await s.flush()
            s.add(
                NotificationChannel(
                    id=other_channel_id,
                    project_id=other_project_id,
                    name="other-channel",
                    type="webhook",
                    config={"url": "https://example.test/other"},
                    is_active=True,
                )
            )
            await s.commit()

        async with _client(brain_app, settings, seed) as client:
            url = f"/api/v1/projects/fragai/notifications/defaults/{seed['default_id']}"
            resp = await client.patch(
                url,
                json={
                    "project_channel_ids": [str(other_channel_id)],
                },
            )
            assert resp.status_code == 409, resp.text
            assert "do not belong to this project" in resp.json()["message"]
            # No partial write: the original 2-channel list survives.
            async with brain_app.state.db.session() as s:
                from sqlalchemy import select

                result = await s.execute(
                    select(ProjectDefaultSubscription).where(
                        ProjectDefaultSubscription.id == seed["default_id"],
                    ),
                )
                row = result.scalar_one()
                assert len(row.project_channel_ids) == 2

    async def test_idor_default_in_other_project_404(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        """Admin of /fragai cannot PATCH a default in /other even
        if they know the default_id.
        """
        seed = await _seed(brain_app, settings)
        # Create a second project + default; the FragAI admin tries
        # to PATCH it through their own slug.
        other_project_id = uuid.uuid4()
        other_default_id = uuid.uuid4()
        async with brain_app.state.db.session() as s:
            s.add(Project(id=other_project_id, slug="other", name="Other"))
            await s.flush()
            s.add(
                ProjectDefaultSubscription(
                    id=other_default_id,
                    project_id=other_project_id,
                    trigger="task.failed",
                    filters={},
                    in_app=True,
                    project_channel_ids=[],
                    cooldown_seconds=0,
                )
            )
            await s.commit()

        async with _client(brain_app, settings, seed) as client:
            # Try PATCHing the OTHER project's default through the
            # FragAI route. The default_id is real but not scoped
            # to /fragai.
            url = f"/api/v1/projects/fragai/notifications/defaults/{other_default_id}"
            resp = await client.patch(url, json={"in_app": False})
            assert resp.status_code == 404, resp.text

    async def test_empty_body_is_noop(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        """Empty PATCH body returns the row unchanged."""
        seed = await _seed(brain_app, settings)
        async with _client(brain_app, settings, seed) as client:
            url = f"/api/v1/projects/fragai/notifications/defaults/{seed['default_id']}"
            resp = await client.patch(url, json={})
            assert resp.status_code == 200
            body = resp.json()
            assert body["trigger"] == "task.failed"
            assert body["in_app"] is True
            assert len(body["project_channel_ids"]) == 2
            assert body["cooldown_seconds"] == 300


@pytest.mark.asyncio
class TestDefaultSubscriptionWriteBoundary:
    @pytest.mark.parametrize("operation", ["create", "update"])
    async def test_real_unique_violation_after_stale_precheck_returns_conflict(
        self,
        operation: str,
        settings: Settings,
        brain_app,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        seed = await _seed(brain_app, settings)
        competitor_id = uuid.uuid4()
        async with brain_app.state.db.session() as session:
            session.add(
                ProjectDefaultSubscription(
                    id=competitor_id,
                    project_id=seed["project_id"],
                    trigger="task.succeeded",
                    filters={},
                    in_app=True,
                    project_channel_ids=[],
                    cooldown_seconds=10,
                ),
            )
            await session.commit()

        original_check = ProjectDefaultSubscriptionRepository.exists_for_project_trigger

        async def stale_precheck(repo, project_id, trigger):
            # Simulate the stale precheck a concurrent PostgreSQL arrival
            # produces, while letting the real database arbitrate the write.
            assert await original_check(repo, project_id, trigger)
            return False

        monkeypatch.setattr(
            ProjectDefaultSubscriptionRepository,
            "exists_for_project_trigger",
            stale_precheck,
        )
        async with _client(brain_app, settings, seed) as client:
            url = "/api/v1/projects/fragai/notifications/defaults"
            body = {"trigger": "task.succeeded", "cooldown_seconds": 90}
            if operation == "create":
                response = await client.post(url, json=body)
            else:
                response = await client.patch(f"{url}/{seed['default_id']}", json=body)

        assert response.status_code == 409, response.text
        assert response.json()["details"] == {"trigger": "task.succeeded"}
        async with brain_app.state.db.session() as session:
            defaults = list(await session.scalars(select(ProjectDefaultSubscription)))
            assert {row.id for row in defaults} == {seed["default_id"], competitor_id}
            original = next(row for row in defaults if row.id == seed["default_id"])
            assert original.trigger == "task.failed"
            assert original.cooldown_seconds == 300
            competitor = next(row for row in defaults if row.id == competitor_id)
            assert competitor.trigger == "task.succeeded"
            assert competitor.cooldown_seconds == 10
            assert list(await session.scalars(select(AuditLog))) == []

    @pytest.mark.parametrize("operation", ["create", "update"])
    @pytest.mark.parametrize("failure", ["foreign_key", "other_unique"])
    async def test_other_integrity_errors_roll_back_without_becoming_trigger_conflicts(
        self,
        operation: str,
        failure: str,
        settings: Settings,
        brain_app,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        seed = await _seed(brain_app, settings)

        async def failing_audit(_self, repo, **_kwargs):
            # Fail after the default flush with a different real constraint.
            # Neither a foreign key nor another unique key means the requested
            # notification trigger already exists.
            if failure == "foreign_key":
                statement = insert(ProjectDefaultSubscription).values(
                    project_id=uuid.uuid4(),
                    trigger="agent.offline",
                    filters={},
                    project_channel_ids=[],
                )
            else:
                statement = insert(Project).values(slug="fragai", name="Duplicate")
            await repo.session.execute(statement)

        monkeypatch.setattr(AuditService, "record", failing_audit)
        async with _client(brain_app, settings, seed) as client:
            url = "/api/v1/projects/fragai/notifications/defaults"
            body = {"trigger": "task.succeeded", "cooldown_seconds": 90}
            if operation == "create":
                response = await client.post(url, json=body)
            else:
                response = await client.patch(f"{url}/{seed['default_id']}", json=body)

        assert response.status_code == 500, response.text
        assert response.json()["error"] == "internal_error"
        async with brain_app.state.db.session() as session:
            original = (await session.scalars(select(ProjectDefaultSubscription))).one()
            assert original.id == seed["default_id"]
            assert original.trigger == "task.failed"
            assert original.cooldown_seconds == 300
            assert list(await session.scalars(select(AuditLog))) == []
