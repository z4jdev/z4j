"""Native writes must pass authority, tenant and observed-truth boundaries."""

# ruff: noqa: F811 - pytest fixture imports are intentionally shadowed
from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from z4j_brain.domain import schedule_native_mutations as native
from z4j_brain.errors import ConflictError, NotFoundError
from z4j_brain.persistence.enums import AgentState, CommandStatus, ProjectRole
from z4j_brain.persistence.models import Agent, Command, Schedule
from z4j_brain.persistence.repositories.schedule_external import ScheduleExternalRepository
from z4j_core.schedule_external import (
    EXTERNAL_SCHEDULE_MUTATION_CAPABILITY,
    external_projection_body,
    external_projection_digest,
    external_schedule_configuration,
    external_schedule_source_scope,
    external_snapshot_frame_body,
    external_snapshot_frame_digest,
    normalize_external_schedule,
)

from tests.unit.test_schedules_crud import (
    _make_client,
    _make_seed,
    brain_app,  # noqa: F401 - migrated fixtures
    settings,  # noqa: F401
)


async def snapshot(session, stream, rows, sequence):
    body = external_projection_body(
        stream_id=str(stream.id),
        epoch_uuid=str(stream.current_epoch_uuid),
        epoch_number=stream.current_epoch_number,
        sequence=sequence,
        kind="snapshot",
        owner=stream.owner,
        source_scope=stream.source_scope,
        adapter_instance_id=stream.authorized_adapter_instance_id,
        schedules=rows,
        complete=True,
        stable_source=True,
    )
    digest = external_projection_digest(body)
    snapshot_id = uuid.uuid4()
    repo = ScheduleExternalRepository(session)
    # Exercise migrated frame guards and complete-snapshot acceptance, not a mocked receipt.
    for index, kind in enumerate(("rows", "terminal") if rows else ("terminal",)):
        frame = external_snapshot_frame_body(
            stream_id=str(stream.id),
            epoch_uuid=str(stream.current_epoch_uuid),
            epoch_number=stream.current_epoch_number,
            sequence=sequence,
            owner=stream.owner,
            source_scope=stream.source_scope,
            adapter_instance_id=stream.authorized_adapter_instance_id,
            snapshot_id=str(snapshot_id),
            frame_kind=kind,
            frame_index=index,
            frame_count=1 if rows else 0,
            row_count=len(rows),
            snapshot_digest=digest,
            stable_source=True,
            schedules=rows if kind == "rows" else [],
        )
        args = dict(frame)
        args.pop("protocol_version")
        args.update(
            project_id=stream.project_id,
            stream_id=stream.id,
            epoch_uuid=stream.current_epoch_uuid,
            snapshot_id=snapshot_id,
            frame_digest=external_snapshot_frame_digest(frame),
            occurred_at=datetime.now(UTC),
        )
        outcome = await repo.stage_snapshot_frame(**args)
    assert outcome.disposition in {"applied", "exact_replay"}, outcome.disposition


@pytest.fixture
async def native_source(brain_app, settings):
    seed = await _make_seed(
        brain_app=brain_app, settings=settings, is_admin=False, role=ProjectRole.ADMIN
    )
    db = brain_app.state.db
    async with db.session(write=True) as session:
        agent = Agent(
            id=uuid.uuid4(),
            project_id=seed["project_id"],
            name="beat",
            token_hash=uuid.uuid4().hex,
            protocol_version="2",
            framework_adapter="django",
            engine_adapters=["celery"],
            scheduler_adapters=["celery-beat"],
            capabilities={"celery-beat": [EXTERNAL_SCHEDULE_MUTATION_CAPABILITY]},
            state=AgentState.ONLINE,
        )
        session.add(agent)
        await session.flush()
        stream = await ScheduleExternalRepository(session).ensure_activation_epoch(
            project_id=seed["project_id"],
            owner="celery-beat",
            source_scope=external_schedule_source_scope("celery-beat"),
            occurred_at=datetime.now(UTC),
            adapter_instance_id="beat-native",
            executor_agent_id=agent.id,
            executor_registry_owner_id=uuid.uuid4(),
            executor_session_generation=uuid.uuid4().hex,
        )
        agent.agent_metadata = {
            "_z4j_external_capabilities": {
                stream.owner: {
                    "epoch_uuid": str(stream.current_epoch_uuid),
                    "registry_owner_id": str(stream.executor_registry_owner_id),
                    "session_generation": stream.executor_session_generation,
                    "capabilities": [
                        EXTERNAL_SCHEDULE_MUTATION_CAPABILITY,
                        "trigger_now",
                        "create",
                        "update",
                        "delete",
                        "enable",
                        "disable",
                    ],
                }
            }
        }
        row = normalize_external_schedule(
            {
                "external_id": "dcb:1",
                "engine": "celery",
                "scheduler": "celery-beat",
                "name": "native",
                "task_name": "jobs.run",
                "kind": "interval",
                "expression": "60",
                "timezone": "UTC",
                "args": [],
                "kwargs": {},
                "is_enabled": True,
                "source": "celery-beat:database",
            },
            owner="celery-beat",
        )
        await snapshot(session, stream, [row], 1)
        schedule = (
            await session.execute(select(Schedule).where(Schedule.external_stream_id == stream.id))
        ).scalar_one()
        await session.commit()
    return seed, stream, schedule, row


def intent(seed, schedule=None, **overrides):
    args = {
        "project_id": seed["project_id"],
        "user_id": seed["user_id"],
        "scheduler": "celery-beat",
        "operation": "update" if schedule else "create",
        "schedule_id": schedule.id if schedule else None,
        "observed_control_token": schedule.control_token if schedule else None,
        "definition": {"expression": "120"}
        if schedule
        else {"name": "created", "task_name": "jobs.run", "kind": "interval", "expression": "60"},
        "request_id": uuid.uuid4(),
        "source_ip": "127.0.0.1",
        "timeout_seconds": 30,
    }
    return args | overrides


async def test_native_plan_idempotency_stale_edit_and_inflight_lock(brain_app, native_source):
    seed, _, schedule, _ = native_source
    async with brain_app.state.db.session(write=True) as session:
        with pytest.raises(ConflictError, match="changed since"):
            await native.plan(
                session, **intent(seed, schedule, observed_control_token=uuid.uuid4())
            )
        args = intent(seed, schedule)
        command, _ = await native.plan(session, **args)
        replay, _ = await native.plan(session, **args)
        assert replay.id == command.id
        with pytest.raises(ConflictError, match="different content"):
            await native.plan(session, **(args | {"definition": {"expression": "180"}}))
        with pytest.raises(ConflictError, match="awaiting confirmation"):
            await native.plan(session, **intent(seed))


@pytest.mark.parametrize("stale_binding", [False, True])
async def test_native_capabilities_belong_to_scheduler_connection(
    brain_app, native_source, stale_binding
):
    seed, stream, schedule, _ = native_source
    async with brain_app.state.db.session(write=True) as session:
        agent = await session.get(Agent, stream.executor_agent_id)
        # A later engine-only worker hello replaces these display fields.
        agent.capabilities = {"celery": ["retry"]}
        agent.scheduler_adapters = []
        if stale_binding:
            metadata = dict(agent.agent_metadata)
            binding = dict(metadata["_z4j_external_capabilities"][stream.owner])
            binding["session_generation"] = uuid.uuid4().hex
            metadata["_z4j_external_capabilities"] = {stream.owner: binding}
            agent.agent_metadata = metadata
            with pytest.raises(ConflictError, match="does not support atomic"):
                await native.plan(session, **intent(seed, schedule))
        else:
            command, _ = await native.plan(session, **intent(seed, schedule))
            assert command.payload["session_generation"] == stream.executor_session_generation


async def test_native_status_requires_snapshot_and_desired_definition(brain_app, native_source):
    seed, stream, schedule, before = native_source
    async with brain_app.state.db.session(write=True) as session:
        command, stream = await native.plan(session, **intent(seed, schedule))
        command.status = CommandStatus.COMPLETED
        after = dict(before, expression="120")
        receipt = {
            "operation_id": command.payload["operation_id"],
            "stream_id": str(stream.id),
            "epoch_uuid": str(stream.current_epoch_uuid),
            "epoch_number": stream.current_epoch_number,
            "sequence": 2,
            "source_key": before["source_key"],
            "observed_configuration": external_schedule_configuration(after),
        }
        command.result = receipt
        await session.flush()
        assert (await native.status(session, project_id=seed["project_id"], command_id=command.id))[
            "status"
        ] == "PENDING"
        await snapshot(session, stream, [after], 2)
        assert (await native.status(session, project_id=seed["project_id"], command_id=command.id))[
            "status"
        ] == "APPLIED"
        command.result = receipt | {"epoch_uuid": str(uuid.uuid4())}
        await session.flush()
        assert (await native.status(session, project_id=seed["project_id"], command_id=command.id))[
            "status"
        ] == "UNCONFIRMED"
        # A valid accepted snapshot of unchanged source data cannot prove an ignored edit.
        await snapshot(session, stream, [before], 3)
        command.result = receipt | {
            "sequence": 3,
            "observed_configuration": external_schedule_configuration(before),
        }
        await session.flush()
        assert (await native.status(session, project_id=seed["project_id"], command_id=command.id))[
            "status"
        ] == "UNCONFIRMED"
        with pytest.raises(NotFoundError):
            await native.status(session, project_id=uuid.uuid4(), command_id=command.id)


async def test_disconnect_never_reassigns_pending_native_write(brain_app, native_source):
    seed, stream, _, _ = native_source
    async with brain_app.state.db.session(write=True) as session:
        command, stream = await native.plan(session, **intent(seed))
        repo = ScheduleExternalRepository(session)
        args = {
            "agent_id": stream.executor_agent_id,
            "registry_owner_id": stream.executor_registry_owner_id,
            "session_generation": stream.executor_session_generation,
        }
        assert await repo.hold_disconnected_streams(**args) == 0
        command.status = CommandStatus.TIMEOUT
        await session.flush()
        assert await repo.hold_disconnected_streams(**args) == 1
        # The original request still resolves after disconnect; it never creates another command.
        replay, _ = await native.plan(
            session, **intent(seed, request_id=uuid.UUID(command.payload["operation_id"]))
        )
        assert replay.id == command.id
        assert (await native.status(session, project_id=seed["project_id"], command_id=command.id))[
            "status"
        ] == "UNCONFIRMED"


@pytest.mark.parametrize("role", [ProjectRole.VIEWER, ProjectRole.OPERATOR])
async def test_native_api_requires_admin(brain_app, settings, role):
    seed = await _make_seed(brain_app=brain_app, settings=settings, is_admin=False, role=role)
    async with _make_client(brain_app, settings, seed) as client:
        response = await client.post(
            "/api/v1/projects/default/schedules/native-operations",
            json={
                "request_id": str(uuid.uuid4()),
                "scheduler": "celery-beat",
                "operation": "create",
                "definition": {"name": "blocked"},
            },
        )
    assert response.status_code == 403
    async with brain_app.state.db.session() as session:
        assert (await session.execute(select(Command))).scalars().all() == []


async def test_capabilities_are_tenant_and_current_connection_bound(brain_app, native_source):
    seed, stream, _, _ = native_source
    async with brain_app.state.db.session(write=True) as session:
        assert (
            "create"
            in (await native.capabilities(session, project_id=seed["project_id"]))["celery-beat"]
        )
        assert await native.capabilities(session, project_id=uuid.uuid4()) == {}
        agent = await session.get(Agent, stream.executor_agent_id)
        agent.agent_metadata = {
            "_z4j_external_capabilities": {
                "celery-beat": {
                    "epoch_uuid": str(stream.current_epoch_uuid),
                    "registry_owner_id": str(stream.executor_registry_owner_id),
                    "session_generation": "obsolete-connection",
                    "capabilities": ["create"],
                }
            }
        }
        await session.flush()
        assert await native.capabilities(session, project_id=seed["project_id"]) == {}


async def test_capability_route_exposes_only_actions_and_disable_uses_native_command(
    brain_app, settings, native_source
):
    seed, _, schedule, _ = native_source
    async with _make_client(brain_app, settings, seed) as client:
        response = await client.get("/api/v1/projects/default/schedules/native-capabilities")
        assert response.status_code == 200
        assert all(isinstance(action, str) for action in response.json()["celery-beat"])
        assert "epoch_uuid" not in response.text
        response = await client.post(f"/api/v1/projects/default/schedules/{schedule.id}/disable")
        assert response.status_code == 202
        assert "native-operations" in response.headers["location"]
    async with brain_app.state.db.session() as session:
        commands = (await session.execute(select(Command))).scalars().all()
        assert len(commands) == 1 and commands[0].payload["definition"] == {"is_enabled": False}


def test_apscheduler_equivalent_cron_receipt_is_confirmed_without_changing_other_semantics():
    observed = {"scheduler": "apscheduler", "kind": "cron", "expression": "0 3 * * *"}
    assert native._matches_requested_definition(observed, {"expression": "00 3 */1 * *"})
    assert not native._matches_requested_definition(observed, {"expression": "0 4 * * *"})
    observed["scheduler"] = "taskiq-scheduler"
    assert not native._matches_requested_definition(observed, {"expression": "00 3 */1 * *"})
