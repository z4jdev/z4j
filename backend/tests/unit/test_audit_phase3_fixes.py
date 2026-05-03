"""Regression tests for Phase-3 audit findings.

Three fixes landed before declaring Phase 3 done:

- **HIGH-1**: ``mode="replace_for_source"`` audit metadata omitted
  the ``source_filter`` value. An admin running ``reconcile(
  source="dashboard", schedules=[])`` could wipe every dashboard-
  managed schedule and leave only ``deleted=N`` in the audit log,
  with no breadcrumb of which source label was nuked. Fix: write
  ``source_filter`` into the audit metadata for replace mode.
- **HIGH-2**: Concurrent ``replace_for_source`` reconciles for the
  same ``(project, source)`` had a TOCTOU race (READ COMMITTED
  isolation): both compute ``surviving_ids`` from a stale
  snapshot, second one's DELETE removes first one's just-inserted
  rows. Fix: take a per-(project, source) ``pg_advisory_xact_lock``
  on Postgres so the requests serialize. SQLite is single-writer
  and immune.
- **MED-2**: CRUD endpoints raised ``NotFoundError`` (404) on bad
  enum / missing field. Fix: raise ``ValidationError`` (422).

The cron-exporter shell-quote fix lives in the scheduler-package
test_audit_phase3_fixes.py.
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
from z4j_brain.persistence.enums import ScheduleKind
from z4j_brain.persistence.models import (
    AuditLog,
    Project,
    Schedule,
    Session,
    User,
)
from z4j_brain.settings import Settings


# =====================================================================
# Fixtures
# =====================================================================


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


async def _make_admin_seed(
    *, settings: Settings, brain_app,
) -> dict:
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    csrf = secrets.token_urlsafe(32)

    async with db.session() as s:
        s.add_all(
            [
                Project(id=project_id, slug="default", name="Default"),
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


# =====================================================================
# HIGH-1: audit log captures source_filter
# =====================================================================


class TestAuditCapturesSourceFilter:
    @pytest.mark.asyncio
    async def test_replace_for_source_audit_records_source_filter(
        self, settings: Settings, brain_app,
    ) -> None:
        """The audit row MUST name the source label that was replaced.

        Otherwise an admin running a destructive reconcile leaves
        no forensic breadcrumb of WHICH source was wiped. The fix
        writes ``source_filter`` into the audit metadata.
        """
        seed = await _make_admin_seed(
            settings=settings, brain_app=brain_app,
        )
        # Pre-seed two rows with source="declarative_django" so the
        # reconcile has something to delete.
        async with brain_app.state.db.session() as s:
            for name in ("a", "b"):
                s.add(
                    Schedule(
                        project_id=seed["project_id"],
                        engine="celery",
                        scheduler="z4j-scheduler",
                        name=name,
                        task_name="t.t",
                        kind=ScheduleKind.CRON,
                        expression="0 * * * *",
                        timezone="UTC",
                        args=[], kwargs={},
                        is_enabled=True,
                        source="declarative_django",
                    ),
                )
            await s.commit()

        async with _client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules:import",
                json={
                    "mode": "replace_for_source",
                    "schedules": [],
                    "source_filter": "declarative_django",
                },
            )
        assert r.status_code == 200, r.text

        async with brain_app.state.db.session() as s:
            audit_rows = (
                await s.execute(
                    select(AuditLog).where(
                        AuditLog.action == "schedules.import",
                    ),
                )
            ).scalars().all()

        assert len(audit_rows) == 1
        meta = audit_rows[0].audit_metadata
        # The fix: source_filter is in the audit metadata.
        assert meta["mode"] == "replace_for_source"
        assert meta["source_filter"] == "declarative_django"
        assert meta["deleted"] == 2

    @pytest.mark.asyncio
    async def test_upsert_mode_audit_omits_source_filter(
        self, settings: Settings, brain_app,
    ) -> None:
        # Plain ``upsert`` mode doesn't have a source_filter -
        # only replace_for_source does. The audit metadata stays
        # focused; we don't pollute it with None.
        seed = await _make_admin_seed(
            settings=settings, brain_app=brain_app,
        )
        async with _client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules:import",
                json={
                    "mode": "upsert",
                    "schedules": [
                        {
                            "name": "x",
                            "engine": "celery",
                            "kind": "cron",
                            "expression": "0 * * * *",
                            "task_name": "t.t",
                            "source_hash": "h" * 64,
                        },
                    ],
                },
            )
        assert r.status_code == 200, r.text

        async with brain_app.state.db.session() as s:
            row = (
                await s.execute(
                    select(AuditLog).where(
                        AuditLog.action == "schedules.import",
                    ),
                )
            ).scalar_one()
        meta = row.audit_metadata
        assert meta["mode"] == "upsert"
        assert "source_filter" not in meta


# =====================================================================
# HIGH-2: pg_advisory_xact_lock guards concurrent replace_for_source
# =====================================================================


class TestConcurrentReconcileGuard:
    """Source-code pin for the advisory-lock fix.

    The actual concurrency demonstration needs a real Postgres
    (SQLite is single-writer so the race is impossible there).
    This test pins the SQL string in the route source so a future
    refactor can't silently drop the lock.
    """

    def test_route_takes_advisory_lock_on_replace_mode(self) -> None:
        import inspect

        from z4j_brain.api import schedules as routes

        source = inspect.getsource(routes)
        # The fix is the explicit advisory-lock call gated on
        # postgres dialect + replace_for_source mode.
        assert "pg_advisory_xact_lock" in source
        # And it must be inside the import_schedules handler.
        import_handler_src = inspect.getsource(routes.import_schedules)
        assert "pg_advisory_xact_lock" in import_handler_src
        assert "replace_for_source" in import_handler_src


# =====================================================================
# MED-2: validation returns 422 not 404
# =====================================================================


class TestValidationStatusCode:
    @pytest.mark.asyncio
    async def test_create_bad_enum_returns_422(
        self, settings: Settings, brain_app,
    ) -> None:
        # Pinned again here (also covered by the updated test in
        # test_schedules_crud.py) to make the audit fix visible
        # in the audit-fixes file - new contributors find it
        # together with the other Phase 3 regression tests.
        seed = await _make_admin_seed(
            settings=settings, brain_app=brain_app,
        )
        async with _client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules",
                json={
                    "name": "bad",
                    "engine": "celery",
                    "kind": "not-a-real-kind",
                    "expression": "0 * * * *",
                    "task_name": "t.t",
                },
            )
        assert r.status_code == 422
        # Body should mention the offending value so the operator
        # can fix their request.
        assert "not-a-real-kind" in r.text or "kind" in r.text.lower()

    @pytest.mark.asyncio
    async def test_update_bad_enum_returns_422(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _make_admin_seed(
            settings=settings, brain_app=brain_app,
        )
        # Seed a schedule first.
        sid = uuid.uuid4()
        async with brain_app.state.db.session() as s:
            s.add(
                Schedule(
                    id=sid,
                    project_id=seed["project_id"],
                    engine="celery",
                    scheduler="z4j-scheduler",
                    name="x",
                    task_name="t.t",
                    kind=ScheduleKind.CRON,
                    expression="0 * * * *",
                    timezone="UTC",
                    args=[], kwargs={},
                    is_enabled=True,
                ),
            )
            await s.commit()

        async with _client(brain_app, settings, seed) as client:
            r = await client.patch(
                f"/api/v1/projects/default/schedules/{sid}",
                json={"kind": "not-a-real-kind"},
            )
        assert r.status_code == 422
