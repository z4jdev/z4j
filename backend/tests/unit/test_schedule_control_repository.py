"""Boundary-D schedule control transitions.

Most of this file runs against a MIGRATED database rather than a
create_all() one. Every Boundary-D guard is a database trigger installed by
a migration, so a create_all() schema accepts every write the repository
emits and proves only that the Python half agrees with itself.

Six tests deliberately construct states an activated database forbids: an
absent revision singleton, a foreign-owner schedule row, and receipt-NULL
fire evidence. They keep the create_all() fixtures; each says why.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.domain.schedule_cadence import (
    CADENCE_SEMANTICS_VERSION,
    cadence_runtime_fingerprint,
)
from z4j_brain.domain.schedule_fire_authority import (
    derive_execution_fire_id,
    derive_scheduler_fire_id,
)
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState, CommandStatus
from z4j_brain.persistence.models import (
    Agent,
    Command,
    PendingFire,
    Project,
    Schedule,
    ScheduleChangeLog,
    ScheduleFire,
    ScheduleOccurrenceResolution,
    ScheduleRevisionState,
    ScheduleTerminalHold,
)
from z4j_brain.persistence.models.schedule_control import (
    SCHEDULE_REVISION_SINGLETON_ID,
)
from z4j_brain.persistence.repositories.commands import CommandRepository
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlConflictError,
    ScheduleControlRepository,
    ScheduleControlStateUnavailableError,
)
from z4j_brain.persistence.repositories.schedule_fires import (
    ScheduleFireRepository,
)
from z4j_brain.persistence.repositories.schedules import (
    ScheduleRepository,
    upsert_imported_schedule,
)
from z4j_brain.persistence.schedule_guard import (
    install_schedule_guard_engine_hooks,
)


@pytest.fixture
async def session(migrated_db_url: str) -> AsyncIterator[AsyncSession]:
    engine = create_async_engine(migrated_db_url)
    # Production installs these when ``DatabaseManager`` wraps the engine.
    # The SQLite guard UDFs are per-connection and a connection without them
    # fails closed inside the trigger, so a raw-session test has to install
    # them itself or it is testing a permanently fenced database.
    install_schedule_guard_engine_hooks(engine)
    async with AsyncSession(engine, expire_on_commit=False) as active:
        yield active
        await active.rollback()
    await engine.dispose()


@pytest.fixture
async def project(session: AsyncSession) -> Project:
    # No revision-state row here: a migrated database arrives with the
    # singleton already activated, and that table is itself guarded.
    row = Project(id=uuid.uuid4(), slug="control", name="Control")
    session.add(row)
    await session.commit()
    return row


@pytest.fixture
async def legacy_session() -> AsyncIterator[AsyncSession]:
    """A create_all() session, for states an activated database forbids."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with AsyncSession(engine, expire_on_commit=False) as active:
        yield active
        await active.rollback()
    await engine.dispose()


@pytest.fixture
async def legacy_project(legacy_session: AsyncSession) -> Project:
    """Hand-activate Boundary D on a create_all() schema."""
    row = Project(id=uuid.uuid4(), slug="control", name="Control")
    legacy_session.add_all(
        [
            row,
            ScheduleRevisionState(
                singleton_id=SCHEDULE_REVISION_SINGLETON_ID,
                current_revision=0,
                change_log_pruned_through=0,
            ),
        ],
    )
    await legacy_session.commit()
    return row


def _definition(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "name": "cleanup",
        "task_name": "jobs.cleanup",
        "engine": "celery",
        "scheduler": "z4j-scheduler",
        "kind": "interval",
        "expression": "5m",
        "timezone": "UTC",
        "queue": "maintenance",
        "priority": "normal",
        "args": [],
        "kwargs": {"dry_run": False},
        "is_enabled": True,
        "catch_up": "skip",
        "source": "dashboard",
    }
    result.update(overrides)
    return result


async def _create(
    session: AsyncSession,
    project: Project,
    *,
    planning_at: datetime | None = None,
) -> Schedule:
    return await ScheduleControlRepository(session).create_current(
        project_id=project.id,
        data=_definition(),
        planning_at=planning_at or datetime(2026, 1, 1, 12, 3, 7, tzinfo=UTC),
    )


async def _accept_command(
    session: AsyncSession,
    project: Project,
) -> tuple[Schedule, Command]:
    row = await _create(session, project)
    agent = Agent(
        id=uuid.uuid4(),
        project_id=project.id,
        name="terminal-agent",
        token_hash=uuid.uuid4().hex,
        protocol_version="1",
        framework_adapter="bare",
        engine_adapters=["celery"],
        scheduler_adapters=[],
        capabilities={},
        state=AgentState.ONLINE,
    )
    session.add(agent)
    await session.commit()
    token = row.control_token
    digest = row.definition_digest
    assert token is not None
    assert digest is not None
    slot = datetime(2026, 1, 1, 12, 5, tzinfo=UTC)
    prepared = datetime(2026, 1, 1, 12, 10, tzinfo=UTC)
    fire_id = derive_scheduler_fire_id(row.id, slot)
    transition = await ScheduleControlRepository(
        session,
    ).accept_current_fire_progress(
        project_id=project.id,
        schedule_id=row.id,
        fire_id=fire_id,
        scheduled_for=slot,
        observed_control_token=token,
        definition_digest=digest,
        expected_revision=1,
        expected_last_run_at=None,
        expected_next_run_at=slot,
        prepared_next_run_at=prepared,
        cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
        cadence_fingerprint=cadence_runtime_fingerprint(),
        occurred_at=slot + timedelta(seconds=1),
    )
    execution_fire_id = transition.execution_fire_id
    acceptance_revision = transition.acceptance_revision
    assert execution_fire_id is not None
    assert acceptance_revision is not None
    payload = {
        "schedule_id": str(row.id),
        "task_name": row.task_name,
        "fire_id": str(execution_fire_id),
        "schedule_fire_id": str(fire_id),
    }
    command, _created = await CommandRepository(
        session,
    ).insert_current_schedule_fire(
        project_id=project.id,
        agent_id=agent.id,
        schedule_id=row.id,
        fire_id=fire_id,
        scheduled_for=slot,
        observed_control_token=token,
        receipt_control_token=token,
        execution_fire_id=execution_fire_id,
        acceptance_revision=acceptance_revision,
        definition_digest=digest,
        expected_revision=1,
        expected_last_run_at=None,
        expected_next_run_at=slot,
        prepared_next_run_at=prepared,
        payload=payload,
        timeout_at=slot + timedelta(minutes=1),
        initial_claim_deadline=slot + timedelta(minutes=1),
    )
    await ScheduleFireRepository(session).record_current(
        fire_id=fire_id,
        schedule_id=row.id,
        project_id=project.id,
        command_id=command.id,
        status="accepted",
        scheduled_for=slot,
        observed_control_token=token,
        receipt_control_token=token,
        acceptance_revision=acceptance_revision,
        definition_digest=digest,
        expected_schedule_revision=1,
        expected_last_run_at=None,
        expected_next_run_at=slot,
        prepared_next_run_at=prepared,
    )
    await session.commit()
    return row, command


async def test_activation_fences_every_legacy_schedule_writer(
    session: AsyncSession,
    project: Project,
) -> None:
    repo = ScheduleRepository(session)
    schedule_id = uuid.uuid4()
    legacy_calls = (
        lambda: repo.set_enabled(schedule_id=schedule_id, enabled=False),
        lambda: repo.create_for_project(project_id=project.id, data=_definition()),
        lambda: repo.update_for_project(
            project_id=project.id,
            schedule_id=schedule_id,
            data={"is_enabled": False},
        ),
        lambda: repo.delete_for_project(
            project_id=project.id,
            schedule_id=schedule_id,
        ),
        lambda: repo.reconcile_snapshot(
            project_id=project.id,
            scheduler="celery-beat",
            schedules=[],
        ),
        lambda: repo.upsert_from_event(
            project_id=project.id,
            data={
                "name": "legacy-event",
                "scheduler": "celery-beat",
            },
        ),
    )

    for call in legacy_calls:
        with pytest.raises(
            ScheduleControlConflictError,
            match="legacy schedule writer",
        ):
            await call()

    count = (await session.execute(select(func.count()).select_from(Schedule))).scalar_one()
    assert count == 0


async def test_activation_routes_reserved_import_and_source_delete(
    session: AsyncSession,
    project: Project,
) -> None:
    first_outcome, first = await upsert_imported_schedule(
        session=session,
        project_id=project.id,
        data=_definition(
            name="import-one",
            source="imported",
            source_hash="sha-one",
        ),
    )
    assert first_outcome == "inserted"
    assert first.schedule_revision == 1
    first_token = first.control_token
    assert first_token is not None

    replay_outcome, replay = await upsert_imported_schedule(
        session=session,
        project_id=project.id,
        data=_definition(
            name="import-one",
            source="imported",
            source_hash="sha-one",
        ),
    )
    assert replay_outcome == "unchanged"
    assert replay.schedule_revision == 1
    assert replay.control_token == first_token

    updated_outcome, updated = await upsert_imported_schedule(
        session=session,
        project_id=project.id,
        data=_definition(
            name="import-one",
            source="imported",
            source_hash="sha-two",
            expression="10m",
        ),
    )
    assert updated_outcome == "updated"
    assert updated.schedule_revision == 2
    assert updated.control_token != first_token

    second_outcome, second = await upsert_imported_schedule(
        session=session,
        project_id=project.id,
        data=_definition(
            name="import-two",
            source="imported",
            source_hash="sha-three",
        ),
    )
    assert second_outcome == "inserted"
    assert second.schedule_revision == 3

    deleted = await ScheduleRepository(session).delete_by_source_except(
        project_id=project.id,
        source="imported",
        keep_ids={first.id},
    )
    assert deleted == 1
    assert await session.get(Schedule, first.id) is first
    assert await session.get(Schedule, second.id) is None
    tombstone = await session.scalar(
        select(ScheduleChangeLog).where(
            ScheduleChangeLog.schedule_id == second.id,
            ScheduleChangeLog.change_kind == "delete",
        ),
    )
    assert tombstone is not None
    assert tombstone.revision == 4


async def test_reserved_import_refuses_cross_owner_name_collision(
    legacy_session: AsyncSession,
    legacy_project: Project,
) -> None:
    """An import cannot silently create a second enabled owner for one name.

    Stays on create_all(). The collision needs a foreign-owner row to
    already exist, and on an activated database a non-reserved schedule can
    only be minted by the Boundary-E stream-epoch protocol (activation
    epoch, snapshot frame, projection) or carried in by a 1.7 upgrade.
    Standing that up here would replace the import-collision contract under
    test with a Boundary-E integration; the repository check itself is in
    Python and fires identically on either schema.
    """
    session, project = legacy_session, legacy_project
    external = Schedule(
        id=uuid.uuid4(),
        project_id=project.id,
        engine="celery",
        scheduler="celery-beat",
        name="nightly",
        task_name="jobs.nightly",
        kind="interval",
        expression="5m",
        timezone="UTC",
        args=[],
        kwargs={},
        is_enabled=True,
        source="external",
    )
    session.add(external)
    await session.flush()

    with pytest.raises(
        ScheduleControlConflictError,
        match="explicit owner cutover",
    ):
        await upsert_imported_schedule(
            session=session,
            project_id=project.id,
            data=_definition(
                name="nightly",
                scheduler="z4j-scheduler",
                source="imported",
            ),
        )

    rows = (
        await session.execute(
            select(Schedule).where(
                Schedule.project_id == project.id,
                Schedule.name == "nightly",
            ),
        )
    ).scalars()
    assert list(rows) == [external]


async def test_activation_refuses_unsequenced_external_import_and_delete(
    legacy_session: AsyncSession,
    legacy_project: Project,
) -> None:
    """Stays on create_all() for the same reason as the collision test above:
    the delete half needs a pre-existing foreign-owner row."""
    session, project = legacy_session, legacy_project
    with pytest.raises(
        ScheduleControlConflictError,
        match="stream epoch authority",
    ):
        await upsert_imported_schedule(
            session=session,
            project_id=project.id,
            data=_definition(
                name="external-import",
                scheduler="celery-beat",
                source="imported",
            ),
        )

    external = Schedule(
        id=uuid.uuid4(),
        project_id=project.id,
        engine="celery",
        scheduler="celery-beat",
        name="external-existing",
        task_name="jobs.external",
        kind="interval",
        expression="5m",
        timezone="UTC",
        args=[],
        kwargs={},
        source="imported",
    )
    session.add(external)
    await session.flush()
    with pytest.raises(
        ScheduleControlConflictError,
        match="stream epoch authority",
    ):
        await ScheduleRepository(session).delete_by_source_except(
            project_id=project.id,
            source="imported",
            keep_ids=set(),
        )
    assert await session.get(Schedule, external.id) is external


async def test_current_create_allocates_complete_authority_and_envelope(
    session: AsyncSession,
    project: Project,
) -> None:
    row = await _create(session, project)

    assert row.schedule_revision == 1
    assert row.control_token is not None
    assert row.legacy_fire_control_token is None
    assert row.definition_digest is not None
    assert row.cadence_semantics_version == CADENCE_SEMANTICS_VERSION
    assert row.cadence_runtime_fingerprint == cadence_runtime_fingerprint()
    assert row.next_run_at == datetime(2026, 1, 1, 12, 5, tzinfo=UTC)

    state = await session.get(
        ScheduleRevisionState,
        SCHEDULE_REVISION_SINGLETON_ID,
    )
    assert state is not None
    assert state.current_revision == 1
    envelope = await session.get(ScheduleChangeLog, 1)
    assert envelope is not None
    assert envelope.change_kind == "upsert"
    assert envelope.schedule_id == row.id
    assert envelope.schedule_owner == "z4j-scheduler"
    assert envelope.snapshot is not None
    assert envelope.snapshot["schedule"]["control_token"] == str(row.control_token)
    assert envelope.snapshot["schedule"]["schedule_revision"] == 1


async def test_current_fire_progress_is_atomic_and_response_loss_idempotent(
    session: AsyncSession,
    project: Project,
) -> None:
    row = await _create(session, project)
    await session.commit()
    token = row.control_token
    digest = row.definition_digest
    assert token is not None
    assert digest is not None
    expected_revision = int(row.schedule_revision or 0)
    expected_next = datetime(2026, 1, 1, 12, 5, tzinfo=UTC)
    slot = expected_next
    prepared_next = datetime(2026, 1, 1, 12, 10, tzinfo=UTC)
    fire_id = derive_scheduler_fire_id(row.id, slot)

    applied = await ScheduleControlRepository(session).accept_current_fire_progress(
        project_id=project.id,
        schedule_id=row.id,
        fire_id=fire_id,
        scheduled_for=slot,
        observed_control_token=token,
        definition_digest=digest,
        expected_revision=expected_revision,
        expected_last_run_at=None,
        expected_next_run_at=expected_next,
        prepared_next_run_at=prepared_next,
        cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
        cadence_fingerprint=cadence_runtime_fingerprint(),
        occurred_at=datetime(2026, 1, 1, 12, 5, 1, tzinfo=UTC),
    )

    assert applied.disposition == "applied"
    assert applied.acceptance_revision == expected_revision + 1
    assert applied.execution_fire_id == derive_execution_fire_id(fire_id, token)
    assert row.last_run_at == slot
    assert row.next_run_at == prepared_next
    assert row.total_runs == 1
    assert row.last_cadence_acceptance_control_token == token
    assert row.last_cadence_acceptance_fire_id == fire_id
    assert row.last_cadence_acceptance_scheduled_for == slot
    assert row.last_cadence_acceptance_revision == applied.acceptance_revision

    replay = await ScheduleControlRepository(session).accept_current_fire_progress(
        project_id=project.id,
        schedule_id=row.id,
        fire_id=fire_id,
        scheduled_for=slot,
        observed_control_token=token,
        definition_digest=digest,
        expected_revision=expected_revision,
        expected_last_run_at=None,
        expected_next_run_at=expected_next,
        prepared_next_run_at=prepared_next,
        cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
        cadence_fingerprint=cadence_runtime_fingerprint(),
        occurred_at=datetime(2026, 1, 1, 12, 5, 2, tzinfo=UTC),
    )
    assert replay.disposition == "idempotent"
    assert replay.acceptance_revision == applied.acceptance_revision
    assert row.total_runs == 1

    state = await session.get(
        ScheduleRevisionState,
        SCHEDULE_REVISION_SINGLETON_ID,
    )
    assert state is not None
    assert state.current_revision == expected_revision + 1
    envelope = await session.get(
        ScheduleChangeLog,
        applied.acceptance_revision,
    )
    assert envelope is not None
    assert envelope.snapshot is not None
    assert envelope.snapshot["transition"]["kind"] == "accept_fire"
    assert envelope.snapshot["transition"]["fire_id"] == str(fire_id)


async def test_current_fire_rejects_noncanonical_successor_before_mutation(
    session: AsyncSession,
    project: Project,
) -> None:
    row = await _create(session, project)
    await session.commit()
    token = row.control_token
    digest = row.definition_digest
    assert token is not None
    assert digest is not None
    expected_revision = int(row.schedule_revision or 0)
    slot = datetime(2026, 1, 1, 12, 5, tzinfo=UTC)

    with pytest.raises(
        ScheduleControlConflictError,
        match="prepared next cursor",
    ):
        await ScheduleControlRepository(session).accept_current_fire_progress(
            project_id=project.id,
            schedule_id=row.id,
            fire_id=derive_scheduler_fire_id(row.id, slot),
            scheduled_for=slot,
            observed_control_token=token,
            definition_digest=digest,
            expected_revision=expected_revision,
            expected_last_run_at=None,
            expected_next_run_at=slot,
            prepared_next_run_at=datetime(2026, 1, 1, 12, 11, tzinfo=UTC),
            cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
            cadence_fingerprint=cadence_runtime_fingerprint(),
            occurred_at=datetime(2026, 1, 1, 12, 5, 1, tzinfo=UTC),
        )

    assert row.schedule_revision == expected_revision
    assert row.last_run_at is None
    assert row.next_run_at == slot
    assert row.total_runs == 0


@pytest.mark.parametrize(
    "status",
    [
        CommandStatus.FAILED,
        CommandStatus.CANCELLED,
        CommandStatus.TIMEOUT,
    ],
)
async def test_current_terminal_command_creates_one_generation_hold(
    legacy_session: AsyncSession,
    legacy_project: Project,
    status: CommandStatus,
) -> None:
    """Stays on create_all(), along with the three tests below it.

    All four need a cadence command that is ALREADY terminal before
    ``terminalize_current_fire`` runs, and on an activated database a
    ``schedule.fire`` command may only leave 'dispatched' through a real
    transition: ``apply_current_agent_result`` for failed/completed,
    ``expire_current_schedule_delivery`` for timeout. Nothing in the product
    ever cancels a cadence command, so this parametrization has no product
    route at all for one of its three cases.

    Worse, ``apply_current_agent_result`` IS the site that creates the
    terminal hold (schedule_control.py:3227-3260). Reaching the precondition
    through it would make the call under test a replay rather than the first
    application, so the conversion would silently retarget every assertion
    below. The database-level version of this transition is covered by
    test_schedule_activation_boundary_d.py.
    """
    session, project = legacy_session, legacy_project
    row, command = await _accept_command(session, project)
    command.status = status
    command.error = f"{status.value} evidence"
    await session.commit()

    applied = await ScheduleControlRepository(session).terminalize_current_fire(
        command_id=command.id,
        occurred_at=datetime(2026, 1, 1, 12, 6, tzinfo=UTC),
    )
    await session.commit()
    replay = await ScheduleControlRepository(session).terminalize_current_fire(
        command_id=command.id,
        occurred_at=datetime(2026, 1, 1, 12, 7, tzinfo=UTC),
    )

    assert applied.disposition == "terminal_quarantined"
    assert replay.disposition == "terminal_quarantined"
    assert replay.hold is not None
    assert applied.hold is not None
    assert replay.hold.id == applied.hold.id
    assert row.is_enabled is False
    assert row.schedule_revision == 3
    holds = list(
        (await session.execute(select(ScheduleTerminalHold))).scalars(),
    )
    fires = list((await session.execute(select(ScheduleFire))).scalars())
    assert len(holds) == 1
    assert holds[0].terminal_status == status.value
    assert holds[0].command_id == command.id
    assert len(fires) == 1
    assert fires[0].status == f"terminal_{status.value}"


async def test_terminal_hold_resolution_rotates_token_and_carries_exact_grant(
    legacy_session: AsyncSession,
    legacy_project: Project,
) -> None:
    """Stays on create_all(); see the terminal-hold note above."""
    session, project = legacy_session, legacy_project
    row, command = await _accept_command(session, project)
    token = row.control_token
    assert token is not None
    granted = await ScheduleControlRepository(
        session,
    ).set_legacy_fire_grant(
        project_id=project.id,
        schedule_id=row.id,
        observed_control_token=token,
        allow=True,
        all_replicas_quiesced_and_resynced=True,
        occurred_at=datetime(2026, 1, 1, 12, 5, 10, tzinfo=UTC),
    )
    assert granted.disposition == "granted"
    command.status = CommandStatus.FAILED
    command.error = "may have executed"
    terminal = await ScheduleControlRepository(
        session,
    ).terminalize_current_fire(
        command_id=command.id,
        occurred_at=datetime(2026, 1, 1, 12, 6, tzinfo=UTC),
    )
    assert terminal.disposition == "terminal_quarantined"
    await session.commit()

    actor = uuid.uuid4()
    resolved = await ScheduleControlRepository(
        session,
    ).resolve_terminal_occurrence(
        project_id=project.id,
        schedule_id=row.id,
        fire_id=command.schedule_fire_id,
        command_id=command.id,
        expected_status=CommandStatus.FAILED,
        observed_control_token=token,
        resolved_by=actor,
        work_may_have_executed=True,
        enabled_after_resolution=True,
        occurred_at=datetime(2026, 1, 1, 12, 7, tzinfo=UTC),
    )
    await session.commit()

    assert resolved.disposition == "resolved"
    assert resolved.changed is True
    assert resolved.grant_carried is True
    assert resolved.hold is not None
    assert resolved.hold.resolution_disposition == "OPERATOR_SKIPPED"
    assert resolved.hold.resolved_by == actor
    assert resolved.hold.work_may_have_executed is True
    assert row.control_token != token
    assert row.legacy_fire_control_token == row.control_token
    assert resolved.hold.resolution_control_token == row.control_token
    assert row.is_enabled is True
    assert row.schedule_revision == 5
    assert row.total_runs == 1
    fire = (await session.execute(select(ScheduleFire))).scalar_one()
    assert fire.status == "operator_skipped"

    replay = await ScheduleControlRepository(
        session,
    ).resolve_terminal_occurrence(
        project_id=project.id,
        schedule_id=row.id,
        fire_id=command.schedule_fire_id,
        command_id=command.id,
        expected_status=CommandStatus.FAILED,
        observed_control_token=token,
        resolved_by=actor,
        work_may_have_executed=True,
        enabled_after_resolution=True,
        occurred_at=datetime(2026, 1, 1, 12, 8, tzinfo=UTC),
    )
    assert replay.disposition == "already_resolved"
    assert row.schedule_revision == 5


@pytest.mark.parametrize("status", list(CommandStatus))
async def test_receipt_null_occurrence_has_exact_operator_exit(
    legacy_session: AsyncSession,
    legacy_project: Project,
    status: CommandStatus,
) -> None:
    """Stays on create_all(). A receipt-NULL ``schedule.fire`` command is
    refused at INSERT by an activated database ('current schedule command
    receipt tuple is required'). Such rows exist only because activation
    MARKED pre-1.8 evidence rather than inventing authority for it, so the
    faithful way to produce one is to migrate a 1.7 database forward, which
    test_schedule_activation_boundary_d.py already does."""
    session, project = legacy_session, legacy_project
    row = await _create(session, project)
    token = row.control_token
    slot = row.next_run_at
    assert token is not None
    assert slot is not None
    fire_id = derive_scheduler_fire_id(row.id, slot)
    command = Command(
        project_id=project.id,
        agent_id=None,
        issued_by=None,
        action="schedule.fire",
        target_type="schedule",
        target_id=str(row.id),
        payload={},
        idempotency_key=f"legacy-resolution:{status.value}",
        status=status,
        timeout_at=slot + timedelta(minutes=1),
        source_ip=None,
        schedule_protocol_marker=1,
        schedule_state_nonce=uuid.uuid4(),
        schedule_id=row.id,
        schedule_fire_id=fire_id,
        schedule_scheduled_for=slot,
        schedule_observed_control_token=None,
        schedule_receipt_control_token=None,
    )
    session.add(command)
    await session.flush()

    transition = await ScheduleControlRepository(
        session,
    ).resolve_terminal_occurrence(
        project_id=project.id,
        schedule_id=row.id,
        fire_id=fire_id,
        command_id=command.id,
        expected_status=status,
        observed_control_token=token,
        resolved_by=uuid.uuid4(),
        work_may_have_executed=True,
        enabled_after_resolution=True,
        occurred_at=slot + timedelta(minutes=1),
    )

    assert transition.disposition == "resolved"
    assert transition.grant_carried is False
    assert transition.resolution is not None
    assert transition.resolution.authority_kind == "LEGACY_NULL"
    assert transition.resolution.command_status == status.value
    assert transition.resolution.work_may_have_executed is True
    assert transition.resolution.resolution_control_token == row.control_token
    assert row.control_token != token
    assert row.legacy_fire_control_token is None
    assert row.last_run_at == slot
    assert row.next_run_at == slot + timedelta(minutes=5)
    assert row.total_runs == 0
    assert (
        await session.execute(
            select(func.count()).select_from(
                ScheduleOccurrenceResolution,
            ),
        )
    ).scalar_one() == 1


async def test_receipt_null_pending_resolution_deletes_only_unaccepted_state(
    legacy_session: AsyncSession,
    legacy_project: Project,
) -> None:
    """Stays on create_all(): the buffered pending-fire and fire rows it
    resolves both carry a NULL receipt token, which an activated database
    refuses at INSERT."""
    session, project = legacy_session, legacy_project
    row = await _create(session, project)
    token = row.control_token
    slot = row.next_run_at
    assert token is not None
    assert slot is not None
    fire_id = derive_scheduler_fire_id(row.id, slot)
    pending = PendingFire(
        id=uuid.uuid4(),
        fire_id=fire_id,
        schedule_id=row.id,
        project_id=project.id,
        engine=row.engine,
        payload={},
        scheduled_for=slot,
        enqueued_at=slot,
        expires_at=slot + timedelta(days=1),
        protocol_marker=1,
        state_write_nonce=uuid.uuid4(),
        observed_control_token=None,
        receipt_control_token=None,
    )
    fire = ScheduleFire(
        id=uuid.uuid4(),
        fire_id=fire_id,
        schedule_id=row.id,
        project_id=project.id,
        command_id=None,
        status="buffered",
        scheduled_for=slot,
        fired_at=slot,
        protocol_marker=1,
        state_write_nonce=uuid.uuid4(),
        observed_control_token=None,
        receipt_control_token=None,
    )
    session.add_all([pending, fire])
    await session.flush()

    transition = await ScheduleControlRepository(
        session,
    ).resolve_legacy_evidence(
        project_id=project.id,
        schedule_id=row.id,
        fire_id=fire_id,
        source_evidence_kind="PENDING_FIRE",
        source_evidence_id=pending.id,
        observed_control_token=token,
        resolved_by=uuid.uuid4(),
        work_may_have_executed=True,
        enabled_after_resolution=True,
        occurred_at=slot + timedelta(minutes=1),
    )
    await session.commit()

    assert transition.disposition == "resolved"
    assert transition.resolution is not None
    assert transition.resolution.source_evidence_kind == "PENDING_FIRE"
    assert transition.resolution.command_id is None
    assert transition.resolution.command_status == "buffered"
    assert await session.get(PendingFire, pending.id) is None
    retained_fire = await session.get(ScheduleFire, fire.id)
    assert retained_fire is not None
    assert retained_fire.status == "operator_skipped"
    assert row.control_token != token
    assert row.total_runs == 0

    granted = await ScheduleControlRepository(
        session,
    ).set_legacy_fire_grant(
        project_id=project.id,
        schedule_id=row.id,
        observed_control_token=row.control_token,
        allow=True,
        all_replicas_quiesced_and_resynced=True,
        occurred_at=slot + timedelta(minutes=2),
    )
    assert granted.disposition == "granted"
    assert granted.blockers == ()


async def test_completed_current_command_never_creates_terminal_hold(
    legacy_session: AsyncSession,
    legacy_project: Project,
) -> None:
    """Stays on create_all(); see the terminal-hold note above."""
    session, project = legacy_session, legacy_project
    row, command = await _accept_command(session, project)
    command.status = CommandStatus.COMPLETED
    await session.commit()

    result = await ScheduleControlRepository(session).terminalize_current_fire(
        command_id=command.id,
        occurred_at=datetime(2026, 1, 1, 12, 6, tzinfo=UTC),
    )

    assert result.disposition == "completed"
    assert row.is_enabled is True
    assert row.schedule_revision == 2
    count = (
        await session.execute(
            select(func.count()).select_from(ScheduleTerminalHold),
        )
    ).scalar_one()
    assert count == 0


async def test_old_receipt_terminal_cannot_disable_repaired_definition(
    legacy_session: AsyncSession,
    legacy_project: Project,
) -> None:
    """Stays on create_all(); see the terminal-hold note above."""
    session, project = legacy_session, legacy_project
    row, command = await _accept_command(session, project)
    old_token = row.control_token
    command.status = CommandStatus.FAILED
    command.error = "old poison"
    repaired = await ScheduleControlRepository(session).update_current(
        project_id=project.id,
        schedule_id=row.id,
        data={"task_name": "jobs.cleanup_repaired"},
        planning_at=datetime(2026, 1, 1, 12, 5, 30, tzinfo=UTC),
    )
    assert repaired is row
    assert row.control_token != old_token
    await session.commit()

    result = await ScheduleControlRepository(session).terminalize_current_fire(
        command_id=command.id,
        occurred_at=datetime(2026, 1, 1, 12, 6, tzinfo=UTC),
    )

    assert result.disposition == "stale_control_refresh"
    assert row.is_enabled is True
    assert row.schedule_revision == 3
    count = (
        await session.execute(
            select(func.count()).select_from(ScheduleTerminalHold),
        )
    ).scalar_one()
    assert count == 0


async def test_missing_revision_state_refuses_before_schedule_mutation(
    legacy_session: AsyncSession,
) -> None:
    """Stays on create_all(). The state under test is an ABSENT revision
    singleton, and a migrated database always has one: the row is created by
    the activation migration and its table is guarded against deletion."""
    session = legacy_session
    project = Project(id=uuid.uuid4(), slug="missing", name="Missing")
    session.add(project)
    await session.commit()

    with pytest.raises(
        ScheduleControlStateUnavailableError,
        match="missing or malformed",
    ):
        await ScheduleControlRepository(session).create_current(
            project_id=project.id,
            data=_definition(),
            planning_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
    await session.rollback()

    count = (await session.execute(select(func.count()).select_from(Schedule))).scalar_one()
    assert count == 0


async def test_invalid_cadence_refuses_before_revision_allocation(
    session: AsyncSession,
    project: Project,
) -> None:
    with pytest.raises(ValueError, match="interval"):
        await ScheduleControlRepository(session).create_current(
            project_id=project.id,
            data=_definition(expression="0s"),
            planning_at=datetime(2026, 1, 1, tzinfo=UTC),
        )

    state = await session.get(
        ScheduleRevisionState,
        SCHEDULE_REVISION_SINGLETON_ID,
    )
    assert state is not None
    assert state.current_revision == 0


async def test_metadata_update_allocates_revision_without_rotating_token(
    session: AsyncSession,
    project: Project,
) -> None:
    row = await _create(session, project)
    token = row.control_token
    digest = row.definition_digest

    updated = await ScheduleControlRepository(session).update_current(
        project_id=project.id,
        schedule_id=row.id,
        data={"name": "cleanup-renamed"},
        planning_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
    )

    assert updated is row
    assert row.schedule_revision == 2
    assert row.control_token == token
    assert row.definition_digest == digest
    assert (await session.get(ScheduleChangeLog, 2)) is not None


async def test_control_update_rotates_token_and_clears_same_generation_state(
    session: AsyncSession,
    project: Project,
) -> None:
    row = await _create(session, project)
    original_token = row.control_token
    assert original_token is not None
    repository = ScheduleControlRepository(session)
    # Reach the same-generation state through the two transitions that
    # actually produce it. Assigning the columns directly is refused by
    # Boundary D, and it also proved less: a hand-set token was never a
    # grant the fire authority would have honoured.
    granted = await repository.set_legacy_fire_grant(
        project_id=project.id,
        schedule_id=row.id,
        observed_control_token=original_token,
        allow=True,
        all_replicas_quiesced_and_resynced=True,
        occurred_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
    )
    assert granted.disposition == "granted"
    quarantined = await repository.quarantine(
        project_id=project.id,
        schedule_id=row.id,
        observed_control_token=original_token,
        reason_code="cadence_definition_invalid",
        detail="old",
        occurred_at=datetime(2026, 1, 1, 12, 5, tzinfo=UTC),
    )
    assert quarantined.outcome == "applied"
    assert row.control_token == original_token
    assert row.legacy_fire_control_token == original_token
    assert row.quarantine_control_token == original_token

    updated = await repository.update_current(
        project_id=project.id,
        schedule_id=row.id,
        data={"queue": "critical"},
        planning_at=datetime(2026, 1, 1, 12, 6, tzinfo=UTC),
    )

    assert updated is row
    assert row.control_token != original_token
    assert row.legacy_fire_control_token is None
    assert row.quarantine_control_token is None
    assert row.quarantine_code is None
    # create + grant + quarantine + this update.
    assert row.schedule_revision == 4


async def test_legacy_grant_requires_attestation_and_is_generation_cas(
    session: AsyncSession,
    project: Project,
) -> None:
    row = await _create(session, project)
    token = row.control_token
    assert token is not None
    repository = ScheduleControlRepository(session)

    with pytest.raises(ValueError, match="all-replica"):
        await repository.set_legacy_fire_grant(
            project_id=project.id,
            schedule_id=row.id,
            observed_control_token=token,
            allow=True,
            all_replicas_quiesced_and_resynced=False,
            occurred_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
        )
    assert row.schedule_revision == 1
    assert row.legacy_fire_control_token is None

    stale = await repository.set_legacy_fire_grant(
        project_id=project.id,
        schedule_id=row.id,
        observed_control_token=uuid.uuid4(),
        allow=True,
        all_replicas_quiesced_and_resynced=True,
        occurred_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
    )
    assert stale.disposition == "stale_control"
    assert row.schedule_revision == 1

    granted = await repository.set_legacy_fire_grant(
        project_id=project.id,
        schedule_id=row.id,
        observed_control_token=token,
        allow=True,
        all_replicas_quiesced_and_resynced=True,
        occurred_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
    )
    assert granted.disposition == "granted"
    assert row.legacy_fire_control_token == token
    assert row.control_token == token
    assert row.schedule_revision == 2
    envelope = await session.get(ScheduleChangeLog, 2)
    assert envelope is not None
    assert envelope.snapshot is not None
    assert envelope.snapshot["transition"] == {
        "kind": "legacy_fire_grant",
        "observed_control_token": str(token),
        "granted_control_token": str(token),
        "attestation_version": 1,
    }

    replay = await repository.set_legacy_fire_grant(
        project_id=project.id,
        schedule_id=row.id,
        observed_control_token=token,
        allow=True,
        all_replicas_quiesced_and_resynced=True,
        occurred_at=datetime(2026, 1, 1, 12, 5, tzinfo=UTC),
    )
    assert replay.disposition == "already_applied"
    assert row.schedule_revision == 2

    revoked = await repository.set_legacy_fire_grant(
        project_id=project.id,
        schedule_id=row.id,
        observed_control_token=token,
        allow=False,
        all_replicas_quiesced_and_resynced=False,
        occurred_at=datetime(2026, 1, 1, 12, 6, tzinfo=UTC),
    )
    assert revoked.disposition == "revoked"
    assert row.legacy_fire_control_token is None
    assert row.control_token == token
    assert row.schedule_revision == 3


@pytest.mark.parametrize("status", list(CommandStatus))
async def test_legacy_grant_refuses_every_receipt_null_command_status(
    legacy_session: AsyncSession,
    legacy_project: Project,
    status: CommandStatus,
) -> None:
    """Stays on create_all(): the blocker under test IS a receipt-NULL
    command, which an activated database refuses at INSERT."""
    session, project = legacy_session, legacy_project
    row = await _create(session, project)
    assert row.control_token is not None
    session.add(
        Command(
            project_id=project.id,
            agent_id=None,
            issued_by=None,
            action="schedule.fire",
            target_type="schedule",
            target_id=str(row.id),
            payload={},
            idempotency_key=f"legacy:{status.value}",
            status=status,
            timeout_at=datetime(2026, 1, 1, 13, tzinfo=UTC),
            source_ip=None,
            schedule_protocol_marker=1,
            schedule_state_nonce=uuid.uuid4(),
            schedule_id=row.id,
            schedule_fire_id=uuid.uuid4(),
            schedule_scheduled_for=datetime(
                2026,
                1,
                1,
                12,
                5,
                tzinfo=UTC,
            ),
            schedule_observed_control_token=None,
            schedule_receipt_control_token=None,
        ),
    )
    await session.flush()

    transition = await ScheduleControlRepository(
        session,
    ).set_legacy_fire_grant(
        project_id=project.id,
        schedule_id=row.id,
        observed_control_token=row.control_token,
        allow=True,
        all_replicas_quiesced_and_resynced=True,
        occurred_at=datetime(2026, 1, 1, 12, 6, tzinfo=UTC),
    )

    assert transition.disposition == "blocked_unresolved_evidence"
    assert transition.blockers == ("cadence_command",)
    assert row.legacy_fire_control_token is None
    assert row.schedule_revision == 1


async def test_exact_noop_allocates_neither_revision_nor_envelope(
    session: AsyncSession,
    project: Project,
) -> None:
    row = await _create(session, project)

    updated = await ScheduleControlRepository(session).update_current(
        project_id=project.id,
        schedule_id=row.id,
        data={"queue": "maintenance"},
        planning_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
    )

    assert updated is row
    assert row.schedule_revision == 1
    count = (
        await session.execute(select(func.count()).select_from(ScheduleChangeLog))
    ).scalar_one()
    assert count == 1


async def test_generic_owner_change_requires_cutover(
    session: AsyncSession,
    project: Project,
) -> None:
    row = await _create(session, project)

    with pytest.raises(ScheduleControlConflictError, match="Promote"):
        await ScheduleControlRepository(session).update_current(
            project_id=project.id,
            schedule_id=row.id,
            data={"scheduler": "celery-beat"},
            planning_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
        )

    assert row.schedule_revision == 1


async def test_quarantine_is_token_cas_and_same_token_idempotent(
    session: AsyncSession,
    project: Project,
) -> None:
    row = await _create(session, project)
    repository = ScheduleControlRepository(session)

    stale = await repository.quarantine(
        project_id=project.id,
        schedule_id=row.id,
        observed_control_token=uuid.uuid4(),
        reason_code="cadence_definition_invalid",
        detail="stale",
        occurred_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
    )
    assert stale.outcome == "stale_control"
    assert row.schedule_revision == 1

    assert row.control_token is not None
    applied = await repository.quarantine(
        project_id=project.id,
        schedule_id=row.id,
        observed_control_token=row.control_token,
        reason_code="cadence_definition_invalid",
        detail="bad\ninterval\x1b",
        occurred_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
    )
    assert applied.outcome == "applied"
    assert row.is_enabled is False
    assert row.quarantine_control_token == row.control_token
    assert row.quarantine_detail == "badinterval"
    assert row.schedule_revision == 2
    change = await session.get(ScheduleChangeLog, 2)
    assert change is not None
    assert change.snapshot is not None
    assert change.snapshot["transition"] == {
        "kind": "definition_quarantine",
        "observed_control_token": str(row.control_token),
        "reason_code": "cadence_definition_invalid",
    }

    replay = await repository.quarantine(
        project_id=project.id,
        schedule_id=row.id,
        observed_control_token=row.control_token,
        reason_code="cadence_definition_invalid",
        detail="bad\ninterval\x1b",
        occurred_at=datetime(2026, 1, 1, 12, 5, tzinfo=UTC),
    )
    assert replay.outcome == "already_applied"
    assert row.schedule_revision == 2


async def test_cursor_advance_recomputes_successor_before_persistence(
    session: AsyncSession,
    project: Project,
) -> None:
    row = await _create(session, project)
    assert row.control_token is not None
    assert row.definition_digest is not None
    original_next = row.next_run_at
    assert original_next is not None
    skipped_through = original_next + timedelta(minutes=10)
    prepared = skipped_through + timedelta(minutes=5)

    transition = await ScheduleControlRepository(session).advance_cursor(
        project_id=project.id,
        schedule_id=row.id,
        observed_control_token=row.control_token,
        definition_digest=row.definition_digest,
        expected_revision=1,
        expected_last_run_at=None,
        expected_next_run_at=original_next,
        skipped_through=skipped_through,
        prepared_next_run_at=prepared,
        cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
        cadence_fingerprint=cadence_runtime_fingerprint(),
        occurred_at=datetime(2026, 1, 1, 12, 16, tzinfo=UTC),
    )

    assert transition.disposition == "applied"
    assert transition.committed_revision == 2
    assert row.last_run_at == skipped_through
    assert row.next_run_at == prepared
    assert row.total_runs == 0


async def test_cursor_advance_rejects_forged_successor_without_revision(
    session: AsyncSession,
    project: Project,
) -> None:
    row = await _create(session, project)
    assert row.control_token is not None
    assert row.definition_digest is not None
    assert row.next_run_at is not None

    with pytest.raises(ScheduleControlConflictError, match="disagrees"):
        await ScheduleControlRepository(session).advance_cursor(
            project_id=project.id,
            schedule_id=row.id,
            observed_control_token=row.control_token,
            definition_digest=row.definition_digest,
            expected_revision=1,
            expected_last_run_at=None,
            expected_next_run_at=row.next_run_at,
            skipped_through=row.next_run_at,
            prepared_next_run_at=row.next_run_at + timedelta(minutes=6),
            cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
            cadence_fingerprint=cadence_runtime_fingerprint(),
            occurred_at=datetime(2026, 1, 1, 12, 6, tzinfo=UTC),
        )

    state = await session.get(
        ScheduleRevisionState,
        SCHEDULE_REVISION_SINGLETON_ID,
    )
    assert state is not None
    assert state.current_revision == 1
