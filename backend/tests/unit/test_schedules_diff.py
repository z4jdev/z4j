"""Tests for the ``/projects/{slug}/schedules:diff`` endpoint.

The diff endpoint is the dry-run preview of ``:import`` - it
returns four buckets (insert / update / unchanged / delete) without
mutating brain state. The dashboard reconciliation panel
(docs/SCHEDULER.md §13.1) and the CLI ``import --verify`` flag both
consume this contract; the per-bucket counts feed the operator's
"is this safe to apply?" decision before they run reconcile for real.

These tests exercise the four buckets independently plus the
mode + RBAC gates.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence.base import Base
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.enums import ScheduleKind
from z4j_brain.persistence.models import (
    Project,
    Schedule,
    Session,
    User,
)
from z4j_brain.settings import Settings


# =====================================================================
# Fixtures (mirror test_audit_phase3_fixes.py)
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


async def _make_admin_seed(*, settings: Settings, brain_app) -> dict:
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
                    password_hash=hasher.hash(
                        "correct horse battery staple 9",
                    ),
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


def _row(name: str, **overrides) -> dict:
    base = {
        "name": name,
        "engine": "celery",
        "scheduler": "z4j-scheduler",
        "kind": "cron",
        "expression": "0 * * * *",
        "task_name": f"app.tasks.{name}",
        "timezone": "UTC",
        "queue": None,
        "args": [],
        "kwargs": {},
        "is_enabled": True,
        "catch_up": "skip",
        "source": "declarative:django",
        "source_hash": f"hash-{name}",
    }
    base.update(overrides)
    return base


# =====================================================================
# Bucket classification
# =====================================================================


@pytest.mark.asyncio
class TestDiffBuckets:

    async def test_new_row_lands_in_insert_bucket(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _make_admin_seed(
            settings=settings, brain_app=brain_app,
        )
        async with _client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules:diff",
                json={"mode": "upsert", "schedules": [_row("new-job")]},
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["summary"]["insert"] == 1
        assert body["summary"]["update"] == 0
        assert body["summary"]["unchanged"] == 0
        assert body["inserted"][0]["name"] == "new-job"
        # The current shape is empty for INSERT (no brain row yet).
        assert body["inserted"][0]["current"] == {}
        assert body["inserted"][0]["proposed"]["task_name"] == "app.tasks.new-job"

    async def test_matching_hash_lands_in_unchanged_bucket(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _make_admin_seed(
            settings=settings, brain_app=brain_app,
        )
        # Pre-seed a row with the same source_hash the diff will send.
        async with brain_app.state.db.session() as s:
            s.add(Schedule(
                project_id=seed["project_id"],
                engine="celery",
                scheduler="z4j-scheduler",
                name="stable",
                task_name="app.tasks.stable",
                kind=ScheduleKind.CRON,
                expression="0 * * * *",
                timezone="UTC",
                args=[], kwargs={},
                is_enabled=True,
                source="declarative:django",
                source_hash="hash-stable",
            ))
            await s.commit()

        async with _client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules:diff",
                json={"mode": "upsert", "schedules": [_row("stable")]},
            )
        body = r.json()
        assert body["summary"]["unchanged"] == 1
        assert body["summary"]["update"] == 0
        assert body["unchanged"][0]["name"] == "stable"

    async def test_diff_hash_lands_in_update_bucket(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _make_admin_seed(
            settings=settings, brain_app=brain_app,
        )
        # Brain has the old expression + an old hash. The diff payload
        # carries a new expression + new hash, so the row must land
        # in UPDATE with both shapes visible to the operator.
        async with brain_app.state.db.session() as s:
            s.add(Schedule(
                project_id=seed["project_id"],
                engine="celery",
                scheduler="z4j-scheduler",
                name="changed",
                task_name="app.tasks.changed",
                kind=ScheduleKind.CRON,
                expression="0 0 * * *",  # midnight
                timezone="UTC",
                args=[], kwargs={},
                is_enabled=True,
                source="declarative:django",
                source_hash="OLD-HASH",
            ))
            await s.commit()

        proposed = _row("changed", expression="*/5 * * * *", source_hash="NEW-HASH")
        async with _client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules:diff",
                json={"mode": "upsert", "schedules": [proposed]},
            )
        body = r.json()
        assert body["summary"]["update"] == 1
        entry = body["updated"][0]
        # Operator must see both the current and the proposed
        # values inline so they can decide whether to apply.
        assert entry["current"]["expression"] == "0 0 * * *"
        assert entry["proposed"]["expression"] == "*/5 * * * *"
        assert entry["current"]["source_hash"] == "OLD-HASH"
        assert entry["proposed"]["source_hash"] == "NEW-HASH"

    async def test_replace_for_source_surfaces_deletes(
        self, settings: Settings, brain_app,
    ) -> None:
        # Brain has two schedules under source="declarative:django".
        # The proposed batch carries only the first; the second
        # (``orphan``) must show up in the DELETE bucket because
        # replace_for_source treats absence as removal.
        seed = await _make_admin_seed(
            settings=settings, brain_app=brain_app,
        )
        async with brain_app.state.db.session() as s:
            for name in ("kept", "orphan"):
                s.add(Schedule(
                    project_id=seed["project_id"],
                    engine="celery",
                    scheduler="z4j-scheduler",
                    name=name,
                    task_name=f"app.tasks.{name}",
                    kind=ScheduleKind.CRON,
                    expression="0 * * * *",
                    timezone="UTC",
                    args=[], kwargs={},
                    is_enabled=True,
                    source="declarative:django",
                    source_hash=f"hash-{name}",
                ))
            await s.commit()

        async with _client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules:diff",
                json={
                    "mode": "replace_for_source",
                    "source_filter": "declarative:django",
                    "schedules": [_row("kept")],
                },
            )
        body = r.json()
        assert body["summary"]["delete"] == 1
        assert body["deleted"][0]["name"] == "orphan"
        # The surviving row from the batch is in unchanged (hash matches
        # what we pre-seeded).
        assert body["summary"]["unchanged"] == 1

    async def test_diff_does_not_mutate_brain_state(
        self, settings: Settings, brain_app,
    ) -> None:
        # The whole point of the dry-run endpoint: zero side effects.
        # Run a diff that would otherwise insert + update + delete
        # multiple rows and confirm the schedule count is unchanged.
        seed = await _make_admin_seed(
            settings=settings, brain_app=brain_app,
        )
        async with brain_app.state.db.session() as s:
            s.add(Schedule(
                project_id=seed["project_id"],
                engine="celery",
                scheduler="z4j-scheduler",
                name="will-update",
                task_name="t.t",
                kind=ScheduleKind.CRON,
                expression="0 * * * *",
                timezone="UTC",
                args=[], kwargs={},
                is_enabled=True,
                source="declarative:django",
                source_hash="OLD",
            ))
            s.add(Schedule(
                project_id=seed["project_id"],
                engine="celery",
                scheduler="z4j-scheduler",
                name="will-delete",
                task_name="t.t",
                kind=ScheduleKind.CRON,
                expression="0 * * * *",
                timezone="UTC",
                args=[], kwargs={},
                is_enabled=True,
                source="declarative:django",
                source_hash="X",
            ))
            await s.commit()

        async with _client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules:diff",
                json={
                    "mode": "replace_for_source",
                    "source_filter": "declarative:django",
                    "schedules": [
                        _row("brand-new"),
                        _row("will-update", source_hash="NEW"),
                    ],
                },
            )
        body = r.json()
        assert body["summary"] == {
            "insert": 1, "update": 1, "unchanged": 0, "delete": 1, "total": 3,
        }

        # Verify the schedules table is untouched.
        from sqlalchemy import select
        async with brain_app.state.db.session() as s:
            rows = (await s.execute(select(Schedule))).scalars().all()
        names = {r.name for r in rows}
        assert names == {"will-update", "will-delete"}, (
            "diff endpoint must not mutate; expected the original two "
            f"rows but got {names}"
        )
        # And the existing row's hash is still the old value (no
        # update applied).
        old = next(r for r in rows if r.name == "will-update")
        assert old.source_hash == "OLD"


# =====================================================================
# Mode + RBAC + audit gates
# =====================================================================


@pytest.mark.asyncio
class TestDiffGates:

    async def test_unknown_mode_rejected_422(
        self, settings: Settings, brain_app,
    ) -> None:
        seed = await _make_admin_seed(
            settings=settings, brain_app=brain_app,
        )
        async with _client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules:diff",
                json={"mode": "destroy_everything", "schedules": []},
            )
        assert r.status_code == 422, r.text

    async def test_diff_writes_no_audit_row(
        self, settings: Settings, brain_app,
    ) -> None:
        # Audit hygiene: a dry-run preview must not flood the audit
        # log. If the operator runs the dashboard panel many times
        # while iterating on a Z4J["schedules"] dict, brain's
        # AuditLog stays clean.
        from sqlalchemy import select

        from z4j_brain.persistence.models import AuditLog

        seed = await _make_admin_seed(
            settings=settings, brain_app=brain_app,
        )
        async with _client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules:diff",
                json={"mode": "upsert", "schedules": [_row("anything")]},
            )
        assert r.status_code == 200

        async with brain_app.state.db.session() as s:
            rows = (await s.execute(
                select(AuditLog).where(
                    AuditLog.action.like("schedules.%"),
                ),
            )).scalars().all()
        assert rows == [], (
            "diff endpoint wrote an audit row; preview must be silent"
        )
