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

These run against a MIGRATED database rather than a create_all() one. Both
guarded boundaries matter here: the reconcile writes an audit row (Boundary
F) and deletes schedules (Boundary D), and neither guard exists in a
create_all() schema.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.enums import ScheduleKind
from z4j_brain.persistence.models import (
    AuditLog,
    Project,
    Session,
    User,
)
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
)
from z4j_brain.settings import Settings

# =====================================================================
# Fixtures
# =====================================================================


@pytest.fixture
def settings(migrated_db_url: str, migrated_audit_chain_secret: str) -> Settings:
    return Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        # A migrated database has Boundary F activated, so it refuses an
        # audit row that carries no chain authentication. Production always
        # has this configured; a test that omits it is not testing production.
        audit_chain_secret=migrated_audit_chain_secret,  # type: ignore[arg-type]
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
    engine = create_async_engine(settings.database_url)
    app = create_app(settings, engine=engine)
    app.state.lifespan_ready = True
    yield app
    await engine.dispose()


async def _make_admin_seed(
    *,
    settings: Settings,
    brain_app,
) -> dict:
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    csrf = secrets.token_urlsafe(32)

    async with db.session() as s:
        project = (
            await s.execute(select(Project).where(Project.slug == "default"))
        ).scalar_one_or_none()
        if project is None:
            project = Project(id=uuid.uuid4(), slug="default", name="Default")
            s.add(project)
            await s.flush()
        s.add(
            User(
                id=user_id,
                email=f"u-{uuid.uuid4().hex[:8]}@example.com",
                password_hash=hasher.hash("correct horse battery staple 9"),
                is_admin=True,
                is_active=True,
            ),
        )
        await s.flush()
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

    return {
        "project_id": project.id,
        "user_id": user_id,
        "session_id": session_id,
        "csrf": csrf,
    }


async def _seed_schedule(brain_app, seed: dict, **overrides) -> uuid.UUID:
    """Create one schedule the way the product does.

    Boundary D refuses a direct INSERT into ``schedules``: the row has to
    arrive with an allocated revision and a matching change-log envelope,
    which only the control repository produces.
    """
    data = {
        "engine": "celery",
        "scheduler": "z4j-scheduler",
        "name": "x",
        "task_name": "t.t",
        "kind": ScheduleKind.CRON.value,
        "expression": "0 * * * *",
        "timezone": "UTC",
        "is_enabled": True,
    }
    data.update(overrides)
    async with brain_app.state.db.session() as s:
        row = await ScheduleControlRepository(s).create_current(
            project_id=seed["project_id"],
            data=data,
            planning_at=datetime.now(UTC),
        )
        await s.commit()
    return row.id


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
        self,
        settings: Settings,
        brain_app,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The audit row MUST name the source label that was replaced.

        Otherwise an admin running a destructive reconcile leaves
        no forensic breadcrumb of WHICH source was wiped. The fix
        writes ``source_filter`` into the audit metadata.
        """
        seed = await _make_admin_seed(
            settings=settings,
            brain_app=brain_app,
        )
        from z4j_brain.api import schedules as schedule_routes

        acquire_lock = AsyncMock(
            wraps=schedule_routes._acquire_replace_for_source_lock,
        )
        monkeypatch.setattr(
            schedule_routes,
            "_acquire_replace_for_source_lock",
            acquire_lock,
        )
        # Pre-seed two rows with source="declarative_django" so the
        # reconcile has something to delete.
        for name in ("a", "b"):
            await _seed_schedule(
                brain_app,
                seed,
                name=name,
                source="declarative_django",
            )

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
                (
                    await s.execute(
                        select(AuditLog).where(
                            AuditLog.action == "schedules.import",
                        ),
                    )
                )
                .scalars()
                .all()
            )

        assert len(audit_rows) == 1
        meta = audit_rows[0].audit_metadata
        # The fix: source_filter is in the audit metadata.
        assert meta["mode"] == "replace_for_source"
        assert meta["source_filter"] == "declarative_django"
        assert meta["deleted"] == 2
        acquire_lock.assert_awaited_once()
        assert acquire_lock.await_args.kwargs["project_id"] == seed["project_id"]
        assert acquire_lock.await_args.kwargs["source_label"] == "declarative_django"

    @pytest.mark.asyncio
    async def test_upsert_mode_audit_omits_source_filter(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        # Plain ``upsert`` mode doesn't have a source_filter -
        # only replace_for_source does. The audit metadata stays
        # focused; we don't pollute it with None.
        seed = await _make_admin_seed(
            settings=settings,
            brain_app=brain_app,
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
    @pytest.mark.asyncio
    async def test_postgres_helper_executes_the_transaction_lock(self) -> None:
        from z4j_brain.api.schedules import _acquire_replace_for_source_lock

        session = SimpleNamespace(
            bind=SimpleNamespace(dialect=SimpleNamespace(name="postgresql")),
            execute=AsyncMock(),
        )

        acquired = await _acquire_replace_for_source_lock(
            session,
            project_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
            source_label="declarative_django",
        )

        assert acquired is True
        statement, parameters = session.execute.await_args.args
        assert str(statement) == "SELECT pg_advisory_xact_lock(:p, :s)"
        assert set(parameters) == {"p", "s"}

    @pytest.mark.asyncio
    async def test_sqlite_helper_is_an_observable_noop(self) -> None:
        from z4j_brain.api.schedules import _acquire_replace_for_source_lock

        session = SimpleNamespace(
            bind=SimpleNamespace(dialect=SimpleNamespace(name="sqlite")),
            execute=AsyncMock(),
        )

        acquired = await _acquire_replace_for_source_lock(
            session,
            project_id=uuid.uuid4(),
            source_label="declarative_django",
        )

        assert acquired is False
        session.execute.assert_not_awaited()


# =====================================================================
# MED-2: validation returns 422 not 404
# =====================================================================


class TestValidationStatusCode:
    @pytest.mark.asyncio
    async def test_create_bad_enum_returns_422(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        # Pinned again here (also covered by the updated test in
        # test_schedules_crud.py) to make the audit fix visible
        # in the audit-fixes file - new contributors find it
        # together with the other Phase 3 regression tests.
        seed = await _make_admin_seed(
            settings=settings,
            brain_app=brain_app,
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
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        seed = await _make_admin_seed(
            settings=settings,
            brain_app=brain_app,
        )
        # Seed a schedule first.
        sid = await _seed_schedule(brain_app, seed)

        async with _client(brain_app, settings, seed) as client:
            r = await client.patch(
                f"/api/v1/projects/default/schedules/{sid}",
                json={"kind": "not-a-real-kind"},
            )
        assert r.status_code == 422
