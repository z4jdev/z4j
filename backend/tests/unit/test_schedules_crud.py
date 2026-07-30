"""Tests for the Phase-3 schedule CRUD endpoints + replace-for-source mode.

Covers:

- ``POST /schedules`` creates a row with ADMIN role.
- ``PATCH /schedules/{id}`` partial update; only sent fields touched.
- ``DELETE /schedules/{id}`` removes the row + cascades to pending_fires.
- IDOR: PATCH/DELETE on a schedule that belongs to a different
  project returns 404 (does NOT leak existence).
- ``POST /schedules:import`` with ``mode="replace_for_source"``
  removes schedules absent from the batch (per-source scoped).

Reuses the same auth fixture pattern as test_schedules_import.py.
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
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.schedule_fire_authority import (
    derive_scheduler_fire_id,
)
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import (
    CommandStatus,
    ProjectRole,
    ScheduleKind,
)
from z4j_brain.persistence.models import (
    Command,
    Membership,
    PendingFire,
    Project,
    Schedule,
    ScheduleChangeLog,
    ScheduleFire,
    ScheduleOccurrenceResolution,
    ScheduleRevisionState,
    Session,
    User,
)
from z4j_brain.persistence.models.schedule_control import (
    SCHEDULE_REVISION_SINGLETON_ID,
)
from z4j_brain.settings import Settings

# =====================================================================
# Fixtures (mirror test_schedules_import.py)
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


async def _make_seed(
    *,
    settings: Settings,
    brain_app,
    is_admin: bool,
    role: ProjectRole | None = ProjectRole.ADMIN,
) -> dict:
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


def _create_body(name: str = "every-hour", **overrides) -> dict:
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
        "source": "dashboard",
    }
    base.update(overrides)
    return base


async def _activate_current_control(brain_app) -> None:
    async with brain_app.state.db.session() as session:
        session.add(
            ScheduleRevisionState(
                singleton_id=SCHEDULE_REVISION_SINGLETON_ID,
                current_revision=0,
                change_log_pruned_through=0,
            ),
        )
        await session.commit()


# =====================================================================
# CREATE
# =====================================================================


class TestCreateSchedule:
    @pytest.mark.asyncio
    async def test_active_current_create_has_complete_identity_and_envelope(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        await _activate_current_control(brain_app)

        async with _make_client(brain_app, settings, seed) as client:
            response = await client.post(
                "/api/v1/projects/default/schedules",
                json=_create_body("current-hourly"),
            )
        assert response.status_code == 201, response.text

        async with brain_app.state.db.session() as session:
            row = (
                await session.execute(
                    select(Schedule).where(Schedule.name == "current-hourly"),
                )
            ).scalar_one()
            change = (
                await session.execute(
                    select(ScheduleChangeLog).where(
                        ScheduleChangeLog.schedule_id == row.id,
                    ),
                )
            ).scalar_one()
            state = await session.get(
                ScheduleRevisionState,
                SCHEDULE_REVISION_SINGLETON_ID,
            )
            assert state is not None
            assert row.control_token is not None
            assert row.schedule_revision == state.current_revision == 1
            assert row.definition_digest
            assert row.next_run_at is not None
            assert change.revision == 1
            assert change.snapshot["schedule"]["control_token"] == str(
                row.control_token,
            )

    @pytest.mark.asyncio
    async def test_create_returns_201_and_row(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        async with _make_client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules",
                json=_create_body("hourly"),
            )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["name"] == "hourly"
        assert body["kind"] == "cron"
        assert body["expression"] == "0 * * * *"
        assert body["scheduler"] == "z4j-scheduler"

        # Row landed.
        async with brain_app.state.db.session() as s:
            rows = (
                (
                    await s.execute(
                        select(Schedule).where(
                            Schedule.project_id == seed["project_id"],
                        ),
                    )
                )
                .scalars()
                .all()
            )
            assert len(rows) == 1

    @pytest.mark.asyncio
    async def test_create_rejects_operator_role(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        # OPERATOR can trigger but not create. Mirrors the import-
        # endpoint convention.
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=False,
            role=ProjectRole.OPERATOR,
        )
        async with _make_client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules",
                json=_create_body(),
            )
        assert r.status_code == 403, r.text

    @pytest.mark.asyncio
    async def test_create_with_unknown_kind_returns_422(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        # Audit-Phase3-4 fix: bad enum is a semantic validation
        # failure, not a "resource missing" condition. Endpoint
        # returns 422 (Unprocessable Entity) so clients can
        # distinguish "you sent garbage" from "we don't have it".
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        async with _make_client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules",
                json=_create_body(kind="not-a-kind"),
            )
        assert r.status_code == 422
        assert "kind" in r.text.lower() or "schedulekind" in r.text.lower()


class TestLegacyFireGrant:
    @pytest.mark.asyncio
    async def test_grant_requires_attestation_and_returns_current_identity(
        self,
        settings: Settings,
        brain_app,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        await _activate_current_control(brain_app)
        async with _make_client(brain_app, settings, seed) as client:
            created = await client.post(
                "/api/v1/projects/default/schedules",
                json=_create_body("legacy-grant"),
            )
            assert created.status_code == 201, created.text
            schedule_id = created.json()["id"]
            token = created.json()["control_token"]

            denied = await client.post(
                (f"/api/v1/projects/default/schedules/{schedule_id}/legacy-fire-grant"),
                json={
                    "observed_control_token": token,
                    "allow": True,
                    "all_replicas_quiesced_and_resynced": False,
                },
            )
            assert denied.status_code == 422, denied.text

            async def _fail_audit(*args: object, **kwargs: object) -> None:
                raise RuntimeError("injected grant audit failure")

            with monkeypatch.context() as patch:
                patch.setattr(
                    AuditService,
                    "record",
                    _fail_audit,
                )
                audit_failed = await client.post(
                    (f"/api/v1/projects/default/schedules/{schedule_id}/legacy-fire-grant"),
                    json={
                        "observed_control_token": token,
                        "allow": True,
                        "all_replicas_quiesced_and_resynced": True,
                    },
                )
                assert audit_failed.status_code == 500

            async with brain_app.state.db.session() as session:
                rolled_back = await session.get(
                    Schedule,
                    uuid.UUID(schedule_id),
                )
                assert rolled_back is not None
                assert rolled_back.legacy_fire_control_token is None
                assert rolled_back.schedule_revision == 1
                assert (await session.get(ScheduleChangeLog, 2)) is None

            granted = await client.post(
                (f"/api/v1/projects/default/schedules/{schedule_id}/legacy-fire-grant"),
                json={
                    "observed_control_token": token,
                    "allow": True,
                    "all_replicas_quiesced_and_resynced": True,
                },
            )
        assert granted.status_code == 200, granted.text
        assert granted.json()["control_token"] == token
        assert granted.json()["legacy_fire_control_token"] == token
        assert granted.json()["schedule_revision"] == 2

        async with brain_app.state.db.session() as session:
            row = await session.get(Schedule, uuid.UUID(schedule_id))
            assert row is not None
            assert row.control_token == row.legacy_fire_control_token
            assert row.schedule_revision == 2


class TestOccurrenceResolution:
    @pytest.mark.asyncio
    async def test_receipt_null_resolution_is_idempotent_product_action(
        self,
        settings: Settings,
        brain_app,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        await _activate_current_control(brain_app)
        async with _make_client(brain_app, settings, seed) as client:
            created = await client.post(
                "/api/v1/projects/default/schedules",
                json=_create_body(
                    "legacy-resolution",
                    kind="interval",
                    expression="5m",
                ),
            )
            assert created.status_code == 201, created.text
            schedule_id = uuid.UUID(created.json()["id"])
            token = created.json()["control_token"]

            async with brain_app.state.db.session() as session:
                schedule = await session.get(Schedule, schedule_id)
                assert schedule is not None
                slot = schedule.next_run_at
                assert slot is not None
                fire_id = derive_scheduler_fire_id(
                    schedule_id,
                    slot.replace(tzinfo=UTC),
                )
                command = Command(
                    project_id=seed["project_id"],
                    agent_id=None,
                    issued_by=None,
                    action="schedule.fire",
                    target_type="schedule",
                    target_id=str(schedule_id),
                    payload={},
                    idempotency_key=f"legacy:{fire_id}",
                    status=CommandStatus.FAILED,
                    timeout_at=slot + timedelta(minutes=1),
                    source_ip=None,
                    schedule_protocol_marker=1,
                    schedule_state_nonce=uuid.uuid4(),
                    schedule_id=schedule_id,
                    schedule_fire_id=fire_id,
                    schedule_scheduled_for=slot,
                    schedule_observed_control_token=None,
                    schedule_receipt_control_token=None,
                )
                session.add(command)
                await session.commit()
                command_id = command.id

            payload = {
                "fire_id": str(fire_id),
                "command_id": str(command_id),
                "expected_status": "failed",
                "observed_control_token": token,
                "work_may_have_executed": True,
                "enabled_after_resolution": True,
            }

            async def _fail_audit(*args: object, **kwargs: object) -> None:
                raise RuntimeError("injected resolution audit failure")

            with monkeypatch.context() as patch:
                patch.setattr(
                    AuditService,
                    "record",
                    _fail_audit,
                )
                audit_failed = await client.post(
                    (f"/api/v1/projects/default/schedules/{schedule_id}/resolve-terminal-fire"),
                    json=payload,
                )
                assert audit_failed.status_code == 500

            async with brain_app.state.db.session() as session:
                rolled_back = await session.get(Schedule, schedule_id)
                assert rolled_back is not None
                assert str(rolled_back.control_token) == token
                assert rolled_back.schedule_revision == 1
                assert (
                    await session.execute(
                        select(ScheduleOccurrenceResolution),
                    )
                ).scalars().all() == []

            resolved = await client.post(
                (f"/api/v1/projects/default/schedules/{schedule_id}/resolve-terminal-fire"),
                json=payload,
            )
            replay = await client.post(
                (f"/api/v1/projects/default/schedules/{schedule_id}/resolve-terminal-fire"),
                json=payload,
            )

        assert resolved.status_code == 200, resolved.text
        assert resolved.json()["disposition"] == "resolved"
        assert resolved.json()["resolution_control_token"] != token
        assert resolved.json()["grant_carried"] is False
        assert replay.status_code == 200, replay.text
        assert replay.json()["disposition"] == "already_resolved"
        assert (
            replay.json()["resolution_control_token"] == resolved.json()["resolution_control_token"]
        )

        async with brain_app.state.db.session() as session:
            schedule = await session.get(Schedule, schedule_id)
            resolution = (
                await session.execute(
                    select(ScheduleOccurrenceResolution),
                )
            ).scalar_one()
            assert schedule is not None
            assert schedule.control_token == resolution.resolution_control_token
            assert schedule.total_runs == 0
            assert resolution.command_id == command_id
            assert resolution.command_status == "failed"

    @pytest.mark.asyncio
    async def test_receipt_null_pending_has_product_resolution_route(
        self,
        settings: Settings,
        brain_app,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        await _activate_current_control(brain_app)
        async with _make_client(brain_app, settings, seed) as client:
            created = await client.post(
                "/api/v1/projects/default/schedules",
                json=_create_body(
                    "legacy-pending-resolution",
                    kind="interval",
                    expression="5m",
                ),
            )
            assert created.status_code == 201, created.text
            schedule_id = uuid.UUID(created.json()["id"])
            token = created.json()["control_token"]

            async with brain_app.state.db.session() as session:
                schedule = await session.get(Schedule, schedule_id)
                assert schedule is not None
                slot = schedule.next_run_at
                assert slot is not None
                fire_id = derive_scheduler_fire_id(
                    schedule_id,
                    slot.replace(tzinfo=UTC),
                )
                pending = PendingFire(
                    id=uuid.uuid4(),
                    fire_id=fire_id,
                    schedule_id=schedule_id,
                    project_id=seed["project_id"],
                    engine="celery",
                    payload={},
                    scheduled_for=slot,
                    enqueued_at=slot,
                    expires_at=slot + timedelta(days=1),
                    protocol_marker=1,
                    state_write_nonce=uuid.uuid4(),
                    observed_control_token=None,
                    receipt_control_token=None,
                )
                session.add_all(
                    [
                        pending,
                        ScheduleFire(
                            id=uuid.uuid4(),
                            fire_id=fire_id,
                            schedule_id=schedule_id,
                            project_id=seed["project_id"],
                            command_id=None,
                            status="buffered",
                            scheduled_for=slot,
                            fired_at=slot,
                            protocol_marker=1,
                            state_write_nonce=uuid.uuid4(),
                            observed_control_token=None,
                            receipt_control_token=None,
                        ),
                    ],
                )
                await session.commit()
                pending_id = pending.id

            payload = {
                "fire_id": str(fire_id),
                "source_evidence_kind": "PENDING_FIRE",
                "source_evidence_id": str(pending_id),
                "observed_control_token": token,
                "work_may_have_executed": True,
                "enabled_after_resolution": True,
            }

            async def _fail_audit(*args: object, **kwargs: object) -> None:
                raise RuntimeError(
                    "injected legacy resolution audit failure",
                )

            with monkeypatch.context() as patch:
                patch.setattr(
                    AuditService,
                    "record",
                    _fail_audit,
                )
                audit_failed = await client.post(
                    (f"/api/v1/projects/default/schedules/{schedule_id}/resolve-legacy-evidence"),
                    json=payload,
                )
                assert audit_failed.status_code == 500

            async with brain_app.state.db.session() as session:
                rolled_back = await session.get(Schedule, schedule_id)
                pending_rolled_back = await session.get(
                    PendingFire,
                    pending_id,
                )
                fire_rolled_back = (
                    await session.execute(
                        select(ScheduleFire).where(
                            ScheduleFire.fire_id == fire_id,
                        ),
                    )
                ).scalar_one()
                assert rolled_back is not None
                assert str(rolled_back.control_token) == token
                assert rolled_back.schedule_revision == 1
                assert pending_rolled_back is not None
                assert fire_rolled_back.status == "buffered"
                assert (
                    await session.execute(
                        select(ScheduleOccurrenceResolution),
                    )
                ).scalars().all() == []

            resolved = await client.post(
                (f"/api/v1/projects/default/schedules/{schedule_id}/resolve-legacy-evidence"),
                json=payload,
            )

        assert resolved.status_code == 200, resolved.text
        assert resolved.json()["disposition"] == "resolved"
        assert resolved.json()["source_evidence_id"] == str(pending_id)
        async with brain_app.state.db.session() as session:
            assert await session.get(PendingFire, pending_id) is None
            fire = (
                await session.execute(
                    select(ScheduleFire).where(
                        ScheduleFire.fire_id == fire_id,
                    ),
                )
            ).scalar_one()
            assert fire.status == "operator_skipped"


# =====================================================================
# 1.2.2 - Per-project default_scheduler_owner fallback
# =====================================================================


class TestDefaultSchedulerOwnerFallback:
    """When ScheduleCreateIn.scheduler is omitted, the create handler
    must fall back to the project's ``default_scheduler_owner``.
    Pre-1.2.2 this defaulted to ``"z4j-scheduler"`` unconditionally.
    Post-1.2.2 the project owns the default so celery-beat-first
    shops can flip it without per-create overrides.
    """

    @pytest.mark.asyncio
    async def test_create_without_scheduler_uses_project_default(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        # Flip the project default to "celery-beat" before creating
        # the schedule.
        async with brain_app.state.db.session() as s:
            project = (
                await s.execute(
                    select(Project).where(Project.id == seed["project_id"]),
                )
            ).scalar_one()
            project.default_scheduler_owner = "celery-beat"
            await s.commit()

        body = _create_body("via-default")
        body.pop("scheduler", None)  # let server pick

        async with _make_client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules",
                json=body,
            )
        assert r.status_code == 201, r.text
        assert r.json()["scheduler"] == "celery-beat"

    @pytest.mark.asyncio
    async def test_explicit_scheduler_overrides_project_default(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        # Project default = celery-beat, but body explicitly picks
        # z4j-scheduler. Body wins.
        async with brain_app.state.db.session() as s:
            project = (
                await s.execute(
                    select(Project).where(Project.id == seed["project_id"]),
                )
            ).scalar_one()
            project.default_scheduler_owner = "celery-beat"
            await s.commit()

        body = _create_body("explicit-z4j")
        body["scheduler"] = "z4j-scheduler"

        async with _make_client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules",
                json=body,
            )
        assert r.status_code == 201, r.text
        assert r.json()["scheduler"] == "z4j-scheduler"

    @pytest.mark.asyncio
    async def test_fresh_project_defaults_to_z4j_scheduler(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        """Fresh project with no operator override: scheduler='z4j-scheduler'."""
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        body = _create_body("fresh")
        body.pop("scheduler", None)

        async with _make_client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules",
                json=body,
            )
        assert r.status_code == 201, r.text
        assert r.json()["scheduler"] == "z4j-scheduler"


# =====================================================================
# UPDATE
# =====================================================================


class TestUpdateSchedule:
    @pytest.mark.asyncio
    async def test_active_current_update_rotates_control_and_emits_revision(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        await _activate_current_control(brain_app)
        async with _make_client(brain_app, settings, seed) as client:
            created = await client.post(
                "/api/v1/projects/default/schedules",
                json=_create_body("rotate-me"),
            )
            schedule_id = created.json()["id"]
            async with brain_app.state.db.session() as session:
                before = await session.get(Schedule, uuid.UUID(schedule_id))
                assert before is not None
                old_token = before.control_token

            updated = await client.patch(
                f"/api/v1/projects/default/schedules/{schedule_id}",
                json={"expression": "*/15 * * * *"},
            )
        assert updated.status_code == 200, updated.text

        async with brain_app.state.db.session() as session:
            row = await session.get(Schedule, uuid.UUID(schedule_id))
            assert row is not None
            assert row.control_token is not None
            assert row.control_token != old_token
            assert row.schedule_revision == 2
            changes = (
                (
                    await session.execute(
                        select(ScheduleChangeLog)
                        .where(ScheduleChangeLog.schedule_id == row.id)
                        .order_by(ScheduleChangeLog.revision),
                    )
                )
                .scalars()
                .all()
            )
            assert [change.revision for change in changes] == [1, 2]

    @pytest.mark.asyncio
    async def test_partial_update_only_touches_sent_fields(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        # Seed a row directly via the DB so we know baseline values.
        schedule_id = uuid.uuid4()
        async with brain_app.state.db.session() as s:
            s.add(
                Schedule(
                    id=schedule_id,
                    project_id=seed["project_id"],
                    engine="celery",
                    scheduler="z4j-scheduler",
                    name="orig",
                    task_name="t.t",
                    kind=ScheduleKind.CRON,
                    expression="0 * * * *",
                    timezone="UTC",
                    args=[1, 2],
                    kwargs={"k": "v"},
                    is_enabled=True,
                ),
            )
            await s.commit()

        async with _make_client(brain_app, settings, seed) as client:
            r = await client.patch(
                f"/api/v1/projects/default/schedules/{schedule_id}",
                json={"expression": "*/15 * * * *"},
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["expression"] == "*/15 * * * *"
        # Untouched fields preserved.
        assert body["args"] == [1, 2]
        assert body["kwargs"] == {"k": "v"}

    @pytest.mark.asyncio
    async def test_update_unknown_id_returns_404(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        async with _make_client(brain_app, settings, seed) as client:
            r = await client.patch(
                f"/api/v1/projects/default/schedules/{uuid.uuid4()}",
                json={"expression": "*/15 * * * *"},
            )
        assert r.status_code == 404


class TestUpdateIDOR:
    @pytest.mark.asyncio
    async def test_cross_project_update_returns_404_not_403(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        # The schedule exists - but in a DIFFERENT project. The
        # request scopes to /projects/default/schedules/{id}. The
        # repo's get_for_project rejects, the route raises 404.
        # Returning 404 (not 403) deliberately hides existence.
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        other_project_id = uuid.uuid4()
        schedule_id = uuid.uuid4()
        async with brain_app.state.db.session() as s:
            s.add(Project(id=other_project_id, slug="other", name="Other"))
            s.add(
                Schedule(
                    id=schedule_id,
                    project_id=other_project_id,  # not seed.project_id
                    engine="celery",
                    scheduler="z4j-scheduler",
                    name="evil",
                    task_name="t.t",
                    kind=ScheduleKind.CRON,
                    expression="0 * * * *",
                    timezone="UTC",
                    args=[],
                    kwargs={},
                    is_enabled=True,
                ),
            )
            await s.commit()

        async with _make_client(brain_app, settings, seed) as client:
            r = await client.patch(
                f"/api/v1/projects/default/schedules/{schedule_id}",
                json={"expression": "*/15 * * * *"},
            )
        # Defends against IDOR via guessed UUIDs - the response is
        # the same as for a totally non-existent schedule.
        assert r.status_code == 404


# =====================================================================
# DELETE
# =====================================================================


class TestDeleteSchedule:
    @pytest.mark.asyncio
    async def test_active_current_delete_commits_tombstone(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        await _activate_current_control(brain_app)
        async with _make_client(brain_app, settings, seed) as client:
            created = await client.post(
                "/api/v1/projects/default/schedules",
                json=_create_body("do-not-cascade"),
            )
            schedule_id = created.json()["id"]
            response = await client.delete(
                f"/api/v1/projects/default/schedules/{schedule_id}",
            )
        assert response.status_code == 204

        async with brain_app.state.db.session() as session:
            assert await session.get(Schedule, uuid.UUID(schedule_id)) is None
            tombstone = await session.scalar(
                select(ScheduleChangeLog).where(
                    ScheduleChangeLog.schedule_id == uuid.UUID(schedule_id),
                    ScheduleChangeLog.change_kind == "delete",
                ),
            )
            assert tombstone is not None
            assert tombstone.snapshot is None

    @pytest.mark.asyncio
    async def test_active_current_disable_is_revisioned_without_agent_command(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        await _activate_current_control(brain_app)
        async with _make_client(brain_app, settings, seed) as client:
            created = await client.post(
                "/api/v1/projects/default/schedules",
                json=_create_body("disable-current"),
            )
            schedule_id = created.json()["id"]
            response = await client.post(
                f"/api/v1/projects/default/schedules/{schedule_id}/disable",
            )
        assert response.status_code == 200, response.text
        assert response.json()["is_enabled"] is False

        async with brain_app.state.db.session() as session:
            row = await session.get(Schedule, uuid.UUID(schedule_id))
            assert row is not None
            assert row.schedule_revision == 2
            assert row.legacy_fire_control_token is None

    @pytest.mark.asyncio
    async def test_active_current_fired_schedule_can_be_reenabled_on_sqlite(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        """SQLite must not leak its naive datetime round-trip into cadence."""

        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        await _activate_current_control(brain_app)
        async with _make_client(brain_app, settings, seed) as client:
            created = await client.post(
                "/api/v1/projects/default/schedules",
                json=_create_body("reenable-fired-current"),
            )
            assert created.status_code == 201, created.text
            schedule_id = uuid.UUID(created.json()["id"])

            # Persist an aware fire cursor, then leave the transaction so the
            # next request observes SQLite's real naive datetime round-trip.
            async with brain_app.state.db.session() as session:
                row = await session.get(Schedule, schedule_id)
                assert row is not None
                row.last_run_at = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
                await session.commit()

            disabled = await client.post(
                f"/api/v1/projects/default/schedules/{schedule_id}/disable",
            )
            assert disabled.status_code == 200, disabled.text

            enabled = await client.post(
                f"/api/v1/projects/default/schedules/{schedule_id}/enable",
            )

        assert enabled.status_code == 200, enabled.text
        assert enabled.json()["is_enabled"] is True
        assert enabled.json()["last_run_at"].startswith("2026-07-25T12:00:00")
        assert enabled.json()["next_run_at"] is not None

    @pytest.mark.asyncio
    async def test_delete_returns_204_and_removes_row(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        schedule_id = uuid.uuid4()
        async with brain_app.state.db.session() as s:
            s.add(
                Schedule(
                    id=schedule_id,
                    project_id=seed["project_id"],
                    engine="celery",
                    scheduler="z4j-scheduler",
                    name="goner",
                    task_name="t.t",
                    kind=ScheduleKind.CRON,
                    expression="0 * * * *",
                    timezone="UTC",
                    args=[],
                    kwargs={},
                    is_enabled=True,
                ),
            )
            await s.commit()

        async with _make_client(brain_app, settings, seed) as client:
            r = await client.delete(
                f"/api/v1/projects/default/schedules/{schedule_id}",
            )
        assert r.status_code == 204

        async with brain_app.state.db.session() as s:
            row = await s.get(Schedule, schedule_id)
            assert row is None

    @pytest.mark.asyncio
    async def test_delete_unknown_returns_404(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        async with _make_client(brain_app, settings, seed) as client:
            r = await client.delete(
                f"/api/v1/projects/default/schedules/{uuid.uuid4()}",
            )
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_rejects_operator_role(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        # Even if the schedule exists, OPERATOR can't delete it.
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=False,
            role=ProjectRole.OPERATOR,
        )
        schedule_id = uuid.uuid4()
        async with brain_app.state.db.session() as s:
            s.add(
                Schedule(
                    id=schedule_id,
                    project_id=seed["project_id"],
                    engine="celery",
                    scheduler="z4j-scheduler",
                    name="protected",
                    task_name="t.t",
                    kind=ScheduleKind.CRON,
                    expression="0 * * * *",
                    timezone="UTC",
                    args=[],
                    kwargs={},
                    is_enabled=True,
                ),
            )
            await s.commit()

        async with _make_client(brain_app, settings, seed) as client:
            r = await client.delete(
                f"/api/v1/projects/default/schedules/{schedule_id}",
            )
        assert r.status_code == 403


# =====================================================================
# Replace-for-source mode (declarative reconciliation prep)
# =====================================================================


class TestImportReplaceForSource:
    @pytest.mark.asyncio
    async def test_replace_mode_deletes_absent_rows_with_same_source(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        # Seed three schedules with source="declarative_django":
        #   alpha, beta, gamma. Then import a batch with only
        #   alpha + delta. Expected: gamma+beta deleted, delta
        #   inserted, alpha unchanged (same hash).
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        async with brain_app.state.db.session() as s:
            for name, sh in (
                ("alpha", "alpha-hash"),
                ("beta", "beta-hash"),
                ("gamma", "gamma-hash"),
            ):
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
                        args=[],
                        kwargs={},
                        is_enabled=True,
                        source="declarative_django",
                        source_hash=sh,
                    ),
                )
            await s.commit()

        async with _make_client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules:import",
                json={
                    "mode": "replace_for_source",
                    "schedules": [
                        {
                            "name": "alpha",
                            "engine": "celery",
                            "kind": "cron",
                            "expression": "0 * * * *",
                            "task_name": "t.t",
                            "source": "declarative_django",
                            "source_hash": "alpha-hash",
                        },
                        {
                            "name": "delta",
                            "engine": "celery",
                            "kind": "cron",
                            "expression": "*/5 * * * *",
                            "task_name": "t.t",
                            "source": "declarative_django",
                            "source_hash": "delta-hash",
                        },
                    ],
                },
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["unchanged"] == 1  # alpha
        assert body["inserted"] == 1  # delta
        assert body["deleted"] == 2  # beta + gamma

        async with brain_app.state.db.session() as s:
            rows = (
                (
                    await s.execute(
                        select(Schedule).where(
                            Schedule.project_id == seed["project_id"],
                        ),
                    )
                )
                .scalars()
                .all()
            )
            assert {r.name for r in rows} == {"alpha", "delta"}

    @pytest.mark.asyncio
    async def test_replace_mode_does_not_delete_other_sources(
        self,
        settings: Settings,
        brain_app,
    ) -> None:
        # Two source labels coexist. Replace-mode for one source
        # must NOT touch rows from the other.
        seed = await _make_seed(
            settings=settings,
            brain_app=brain_app,
            is_admin=True,
        )
        async with brain_app.state.db.session() as s:
            s.add(
                Schedule(
                    project_id=seed["project_id"],
                    engine="celery",
                    scheduler="z4j-scheduler",
                    name="from-celerybeat",
                    task_name="t.t",
                    kind=ScheduleKind.CRON,
                    expression="0 * * * *",
                    timezone="UTC",
                    args=[],
                    kwargs={},
                    is_enabled=True,
                    source="imported_celerybeat",
                ),
            )
            s.add(
                Schedule(
                    project_id=seed["project_id"],
                    engine="celery",
                    scheduler="z4j-scheduler",
                    name="from-django",
                    task_name="t.t",
                    kind=ScheduleKind.CRON,
                    expression="0 * * * *",
                    timezone="UTC",
                    args=[],
                    kwargs={},
                    is_enabled=True,
                    source="declarative_django",
                ),
            )
            await s.commit()

        async with _make_client(brain_app, settings, seed) as client:
            r = await client.post(
                "/api/v1/projects/default/schedules:import",
                json={
                    "mode": "replace_for_source",
                    # Empty batch from the django source = delete
                    # all django-sourced rows.
                    "schedules": [],
                    "source_filter": "declarative_django",
                },
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["deleted"] == 1  # the django row, not celerybeat

        async with brain_app.state.db.session() as s:
            rows = (
                (
                    await s.execute(
                        select(Schedule).where(
                            Schedule.project_id == seed["project_id"],
                        ),
                    )
                )
                .scalars()
                .all()
            )
            assert {r.name for r in rows} == {"from-celerybeat"}
