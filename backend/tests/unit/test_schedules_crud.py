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

Most of this file runs against a MIGRATED database rather than a
create_all() one. Every Boundary-D guard lives in a migration, so a
create_all() schema refuses nothing and cannot observe what an operator's
database does to a CRUD write.

Two tests deliberately construct receipt-NULL legacy fire evidence, which
an activated database refuses at INSERT. They keep the create_all()
fixtures; see :class:`TestOccurrenceResolution`.
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
from z4j_brain.domain.schedule_cadence import (
    CADENCE_SEMANTICS_VERSION,
    cadence_runtime_fingerprint,
)
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
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
)
from z4j_brain.settings import Settings

# =====================================================================
# Fixtures (mirror test_schedules_import.py)
# =====================================================================


@pytest.fixture
def settings(migrated_db_url: str, migrated_audit_chain_secret: str) -> Settings:
    return Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        # A migrated database has Boundary F activated, so it refuses an
        # audit row that carries no chain authentication. Every write in
        # this file records one.
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
    # A migrated database, not a create_all() one: the Boundary-D guards
    # that decide whether a CRUD write lands live in the migration chain.
    engine = create_async_engine(settings.database_url)
    app = create_app(settings, engine=engine)
    yield app
    await engine.dispose()


@pytest.fixture
def legacy_settings() -> Settings:
    """Settings for the pre-Boundary-D shape. See :class:`TestOccurrenceResolution`."""
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
async def legacy_brain_app(legacy_settings: Settings):
    """A create_all() brain, for evidence an activated database cannot hold."""
    engine = create_async_engine(
        legacy_settings.database_url,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(legacy_settings, engine=engine)
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
                is_admin=is_admin,
                is_active=True,
            )
        )
        await s.flush()
        rows = [
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
                    project_id=project.id,
                    role=role,
                ),
            )
        s.add_all(rows)
        await s.commit()

    return {
        "project_id": project.id,
        "user_id": user_id,
        "session_id": session_id,
        "csrf": csrf,
    }


async def _seed_schedule(
    brain_app,
    project_id: uuid.UUID,
    name: str,
    **overrides,
) -> uuid.UUID:
    """Pre-seed one row the way the product creates it, and return its id.

    Through the control repository, because Boundary D refuses a direct
    INSERT into ``schedules``. A hand-built row is a row no operator's
    database contains, so an endpoint tested against one is untested.
    """
    data: dict[str, object] = {
        "engine": "celery",
        "scheduler": "z4j-scheduler",
        "name": name,
        "task_name": "t.t",
        "kind": ScheduleKind.CRON.value,
        "expression": "0 * * * *",
        "timezone": "UTC",
        "args": [],
        "kwargs": {},
        "is_enabled": True,
    }
    data.update(overrides)
    async with brain_app.state.db.session() as s:
        row = await ScheduleControlRepository(s).create_current(
            project_id=project_id,
            data=data,
            planning_at=datetime.now(UTC),
        )
        await s.commit()
        return row.id


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
    """Hand-activate Boundary D on a create_all() schema.

    Only :class:`TestOccurrenceResolution` still needs this. A migrated
    database arrives activated, and its ``schedule_revision_state`` row is
    itself guarded, so this INSERT is refused there.
    """
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
    """The operator exit from receipt-NULL evidence.

    These two stay on the create_all() schema on purpose. Both build a
    tokenless fire (``schedule_receipt_control_token IS NULL``) and then
    drive the product's resolution route over it, and an activated database
    refuses that INSERT outright: the command and pending-fire guards demand
    a complete receipt tuple. Such rows exist only because Boundary-D
    activation MARKED pre-1.8 evidence rather than inventing authority for
    it, so the only faithful way to produce one is to migrate a 1.7 database
    forward -- which is what test_schedule_activation_boundary_d.py does.
    Reproducing that here would replace the resolution contract under test
    with a migration test.
    """

    @pytest.mark.asyncio
    async def test_receipt_null_resolution_is_idempotent_product_action(
        self,
        legacy_settings: Settings,
        legacy_brain_app,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        settings = legacy_settings
        brain_app = legacy_brain_app
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
        legacy_settings: Settings,
        legacy_brain_app,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        settings = legacy_settings
        brain_app = legacy_brain_app
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
        # 409, not 201. The project default is honoured (the owner in the
        # message is the one the project named), but an externally owned
        # schedule is defined in the scheduler that owns it and projected here
        # from what its adapter reports. The brain is not its author, so there
        # is nothing for this endpoint to create.
        #
        # This used to answer 201 only because the test schema was built with
        # create_all(), which leaves Boundary D unactivated: the one state in
        # which the legacy writer still works. On a real database it answered
        # 422 carrying internal wording.
        assert r.status_code == 409, r.text
        body = r.json()
        assert "celery-beat" in body["message"]
        # The operator is told what to do instead, not just that it failed.
        assert "z4j-scheduler" in body["message"]
        assert "Boundary" not in body["message"]

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
        # Seed a row through the product so we know baseline values.
        schedule_id = await _seed_schedule(
            brain_app,
            seed["project_id"],
            "orig",
            args=[1, 2],
            kwargs={"k": "v"},
        )

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

    # FAILING ON PURPOSE: this is a product defect, not a stale test. When the
    # row is missing, update_schedule's control branch is skipped on the
    # ``existing is not None`` term and the request falls through to the legacy
    # writer (api/schedules.py:1105-1121), which an activated database refuses.
    # The 404 at api/schedules.py:1129 is unreachable there. delete_schedule
    # gets this right: it raises NotFoundError BEFORE choosing a writer
    # (api/schedules.py:1554).
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
    # FAILING ON PURPOSE: same defect as test_update_unknown_id_returns_404. A
    # cross-project schedule id makes ``get_for_project`` return None, so the
    # request takes the refused legacy writer and answers 422 rather than the
    # documented 404. Existence is still not leaked (the missing-row case
    # answers 422 too), but the stated contract is not what the endpoint does.
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
        async with brain_app.state.db.session() as s:
            s.add(Project(id=other_project_id, slug="other", name="Other"))
            await s.commit()
        schedule_id = await _seed_schedule(
            brain_app,
            other_project_id,  # not seed.project_id
            "evil",
        )

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
        async with _make_client(brain_app, settings, seed) as client:
            created = await client.post(
                "/api/v1/projects/default/schedules",
                json=_create_body("reenable-fired-current"),
            )
            assert created.status_code == 201, created.text
            schedule_id = uuid.UUID(created.json()["id"])

            # Persist an aware fire cursor the way a fire does, then leave the
            # transaction so the next request observes SQLite's real naive
            # datetime round-trip. A direct column write would be refused by
            # Boundary D and would also skip the code that stores the cursor.
            async with brain_app.state.db.session() as session:
                row = await session.get(Schedule, schedule_id)
                assert row is not None
                assert row.next_run_at is not None
                assert row.control_token is not None
                assert row.definition_digest is not None
                slot = row.next_run_at.replace(tzinfo=UTC)
                accepted = await ScheduleControlRepository(
                    session,
                ).accept_current_fire_progress(
                    project_id=seed["project_id"],
                    schedule_id=schedule_id,
                    fire_id=derive_scheduler_fire_id(schedule_id, slot),
                    scheduled_for=slot,
                    observed_control_token=row.control_token,
                    definition_digest=row.definition_digest,
                    expected_revision=row.schedule_revision,
                    expected_last_run_at=None,
                    expected_next_run_at=slot,
                    prepared_next_run_at=slot + timedelta(hours=1),
                    cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
                    cadence_fingerprint=cadence_runtime_fingerprint(),
                    occurred_at=slot + timedelta(seconds=1),
                )
                assert accepted.disposition == "applied"
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
        assert enabled.json()["last_run_at"].startswith(
            slot.strftime("%Y-%m-%dT%H:%M:%S"),
        )
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
        schedule_id = await _seed_schedule(brain_app, seed["project_id"], "goner")

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
        schedule_id = await _seed_schedule(brain_app, seed["project_id"], "protected")

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
        for name in ("alpha", "beta", "gamma"):
            await _seed_schedule(
                brain_app,
                seed["project_id"],
                name,
                source="declarative_django",
                source_hash=f"{name}-hash",
            )

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
        await _seed_schedule(
            brain_app,
            seed["project_id"],
            "from-celerybeat",
            source="imported_celerybeat",
        )
        await _seed_schedule(
            brain_app,
            seed["project_id"],
            "from-django",
            source="declarative_django",
        )

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
