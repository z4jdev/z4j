"""Tests for the bulk-import endpoint at
``POST /api/v1/projects/{slug}/schedules:import``.

Covers:

- Happy path: insert a fresh batch, get inserted=N response.
- Re-import with same source_hash -> unchanged=N (idempotency).
- Re-import with changed expression -> updated=N.
- Per-row failure (bad kind) is captured in ``errors`` map; other
  rows still land.
- Authz: a non-admin (operator) member is rejected with 403.
- The audit log records one ``schedules.import`` row per batch.
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
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import (
    AuditLog,
    Membership,
    Project,
    Schedule,
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


async def _make_seed(
    *,
    settings: Settings,
    brain_app,
    is_admin: bool,
    role: ProjectRole | None = ProjectRole.ADMIN,
) -> dict:
    """Insert project + user + session; optionally a membership row.

    ``is_admin=True`` makes the user a global brain admin, which
    bypasses the per-project ``require_member`` check entirely.
    Set ``role=None`` to skip writing a membership row (useful for
    the operator-rejection test).
    """
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    csrf = secrets.token_urlsafe(32)

    async with db.session() as s:
        rows = [
            Project(id=project_id, slug="default", name="Default"),
            User(
                id=user_id,
                email=f"u-{uuid.uuid4().hex[:8]}@example.com",
                password_hash=hasher.hash("correct horse battery staple 9"),
                is_admin=is_admin,
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
        ]
        if role is not None and not is_admin:
            rows.append(
                Membership(
                    user_id=user_id,
                    project_id=project_id,
                    role=role,
                ),
            )
        s.add_all(rows)
        await s.commit()

    return {
        "project_id": project_id,
        "user_id": user_id,
        "session_id": session_id,
        "csrf": csrf,
    }


def _make_client(brain_app, settings: Settings, seed: dict):
    from httpx import ASGITransport, AsyncClient

    from z4j_brain.auth.csrf import csrf_cookie_name

    transport = ASGITransport(app=brain_app)
    # The double-submit CSRF check requires the same token in both
    # the cookie and the X-CSRF-Token header. Default the header on
    # the client so tests don't have to spell it out per call.
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


def _sample_schedule(name: str = "every-hour", **overrides) -> dict:
    """Build one ImportedScheduleIn-shaped dict."""
    base = {
        "name": name,
        "engine": "celery",
        "kind": "cron",
        "expression": "0 * * * *",
        "task_name": "tasks.heartbeat",
        "timezone": "UTC",
        "queue": None,
        "args": [],
        "kwargs": {},
        "catch_up": "skip",
        "is_enabled": True,
        "scheduler": "z4j-scheduler",
        "source": "imported_celerybeat",
        "source_hash": "deadbeef" * 8,  # 64-char hex
    }
    base.update(overrides)
    return base


# =====================================================================
# Happy path
# =====================================================================


class TestImportSchedulesHappyPath:
    @pytest.mark.asyncio
    async def test_fresh_import_returns_inserted_count(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _make_seed(
            settings=settings, brain_app=brain_app, is_admin=True,
        )
        async with _make_client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules:import",
                json={
                    "schedules": [
                        _sample_schedule("a"),
                        _sample_schedule(
                            "b", source_hash="cafebabe" * 8,
                        ),
                    ],
                },
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["inserted"] == 2
        assert body["updated"] == 0
        assert body["unchanged"] == 0
        assert body["failed"] == 0
        assert body["errors"] == {}

        # Schedules landed in the DB with scheduler="z4j-scheduler".
        async with brain_app.state.db.session() as s:
            rows = (
                await s.execute(
                    select(Schedule).where(
                        Schedule.project_id == seed["project_id"],
                    ),
                )
            ).scalars().all()
            assert {r.name for r in rows} == {"a", "b"}
            assert {r.scheduler for r in rows} == {"z4j-scheduler"}

    @pytest.mark.asyncio
    async def test_reimport_same_hash_is_noop(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _make_seed(
            settings=settings, brain_app=brain_app, is_admin=True,
        )
        payload = {"schedules": [_sample_schedule("noop")]}
        async with _make_client(brain_app, settings, seed) as client:
            r1 = await client.post(
                "/api/v1/projects/default/schedules:import",
                json=payload,
            )
            assert r1.status_code == 200
            assert r1.json()["inserted"] == 1

            r2 = await client.post(
                "/api/v1/projects/default/schedules:import",
                json=payload,
            )
        assert r2.status_code == 200
        body = r2.json()
        assert body["inserted"] == 0
        assert body["unchanged"] == 1
        assert body["updated"] == 0

    @pytest.mark.asyncio
    async def test_reimport_changed_hash_updates(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _make_seed(
            settings=settings, brain_app=brain_app, is_admin=True,
        )
        async with _make_client(brain_app, settings, seed) as client:
            await client.post(
                "/api/v1/projects/default/schedules:import",
                json={"schedules": [_sample_schedule("hourly")]},
            )
            # Change expression + hash, re-import.
            r = await client.post(
                "/api/v1/projects/default/schedules:import",
                json={
                    "schedules": [
                        _sample_schedule(
                            "hourly",
                            expression="*/30 * * * *",
                            source_hash="abadidea" * 8,
                        ),
                    ],
                },
            )
        assert r.status_code == 200
        body = r.json()
        assert body["updated"] == 1
        assert body["inserted"] == 0
        # Verify the row was actually mutated.
        async with brain_app.state.db.session() as s:
            row = (
                await s.execute(
                    select(Schedule).where(
                        Schedule.project_id == seed["project_id"],
                        Schedule.name == "hourly",
                    ),
                )
            ).scalar_one()
            assert row.expression == "*/30 * * * *"


# =====================================================================
# Per-row failure handling
# =====================================================================


class TestImportPerRowErrors:
    @pytest.mark.asyncio
    async def test_bad_kind_rejects_whole_batch_at_schema(
        self, settings: Settings, brain_app,
    ) -> None:
        # Audit fix REST H-2 (Apr 2026): the API now validates
        # ``kind`` at the Pydantic schema layer instead of letting
        # bad rows slip through to the repository's per-row check.
        # That changes the failure mode from a partial-success 200
        # with an error map to a fail-fast 422 - the operator's
        # importer sees a clean schema error pointing at row 1
        # rather than a confusing "1 of 2 inserted" result. Whole-
        # batch rejection on schema errors is the more defensive
        # default for the API surface.
        seed = await _make_seed(
            settings=settings, brain_app=brain_app, is_admin=True,
        )
        async with _make_client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules:import",
                json={
                    "schedules": [
                        _sample_schedule("good"),
                        _sample_schedule(
                            "bogus",
                            kind="not-a-real-kind",
                        ),
                    ],
                },
            )
        # FastAPI returns 422 on schema-validation failure.
        assert r.status_code == 422, r.text
        # The error body names ``kind`` so the importer can
        # surface the offending field.
        assert "kind" in r.text


# =====================================================================
# Authorization
# =====================================================================


class TestImportRequiresAdmin:
    @pytest.mark.asyncio
    async def test_operator_role_rejected(
        self, settings: Settings, brain_app,
    ) -> None:
        # Operator-role member - cannot import.
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=False,
            role=ProjectRole.OPERATOR,
        )
        async with _make_client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules:import",
                json={"schedules": [_sample_schedule("x")]},
            )
        assert r.status_code == 403, r.text


# =====================================================================
# Audit
# =====================================================================


class TestImportAudit:
    @pytest.mark.asyncio
    async def test_one_audit_row_per_batch(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _make_seed(
            settings=settings, brain_app=brain_app, is_admin=True,
        )
        async with _make_client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules:import",
                json={
                    "schedules": [
                        _sample_schedule(f"sched-{i}",
                                          source_hash=f"{i:064d}")
                        for i in range(5)
                    ],
                },
            )
            assert r.status_code == 200

        async with brain_app.state.db.session() as s:
            rows = (
                await s.execute(
                    select(AuditLog).where(
                        AuditLog.action == "schedules.import",
                    ),
                )
            ).scalars().all()
            # Exactly one audit row, not five.
            assert len(rows) == 1
            audit_row = rows[0]
            assert audit_row.audit_metadata["inserted"] == 5
            assert audit_row.audit_metadata["failed"] == 0
