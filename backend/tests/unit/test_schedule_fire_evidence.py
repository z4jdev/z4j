"""Generation-scoped current-protocol fire evidence.

These run against a MIGRATED database rather than a create_all() one. The
evidence tables are exactly where the Boundary-D triggers live: an
activated ``commands``, ``schedule_fires`` or ``pending_fires`` INSERT is
refused unless its receipt tuple is complete. A create_all() schema accepts
any shape, so it cannot tell a complete evidence row from a partial one.
"""

from __future__ import annotations

import secrets
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from z4j_brain.domain.schedule_fire_authority import derive_execution_fire_id
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.enums import AgentState, CommandStatus, ScheduleKind
from z4j_brain.persistence.models import (
    Agent,
    Command,
    PendingFire,
    Project,
    Schedule,
    ScheduleFire,
)
from z4j_brain.persistence.repositories import (
    CommandRepository,
    PendingFiresRepository,
    ScheduleFireRepository,
)
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
)
from z4j_brain.persistence.schedule_guard import (
    install_schedule_guard_engine_hooks,
)
from z4j_brain.websocket.gateway import deliver_command_frame
from z4j_core.errors import ConflictError
from z4j_core.transport.frames import CommandFrame, parse_frame
from z4j_core.transport.framing import FrameSigner


@pytest.fixture
async def evidence(
    migrated_db_url: str,
) -> AsyncIterator[tuple[AsyncSession, Project, Schedule, Agent]]:
    engine = create_async_engine(migrated_db_url)
    # Production installs these when ``DatabaseManager`` wraps the engine.
    # The SQLite guard UDFs are per-connection, and a connection without them
    # fails closed inside the trigger, so a raw-session test has to install
    # them itself or it is testing a permanently fenced database.
    install_schedule_guard_engine_hooks(engine)
    async with AsyncSession(engine, expire_on_commit=False) as session:
        project = Project(id=uuid.uuid4(), slug="evidence", name="Evidence")
        agent = Agent(
            id=uuid.uuid4(),
            project_id=project.id,
            name="agent",
            token_hash=secrets.token_hex(32),
            protocol_version="1",
            framework_adapter="bare",
            engine_adapters=["celery"],
            scheduler_adapters=[],
            capabilities={},
            state=AgentState.ONLINE,
        )
        session.add_all([project, agent])
        await session.flush()
        # Through the control repository, because Boundary D refuses a direct
        # INSERT into schedules.
        schedule = await ScheduleControlRepository(session).create_current(
            project_id=project.id,
            data={
                "engine": "celery",
                "scheduler": "z4j-scheduler",
                "name": "cleanup",
                "task_name": "jobs.cleanup",
                "kind": ScheduleKind.INTERVAL.value,
                "expression": "5m",
                "timezone": "UTC",
                "args": [],
                "kwargs": {},
                "is_enabled": True,
            },
            planning_at=datetime(2026, 1, 1, 12, tzinfo=UTC),
        )
        await session.commit()
        yield session, project, schedule, agent
        await session.rollback()
    await engine.dispose()


def _authority() -> dict[str, object]:
    token = uuid.UUID("8d1c33d6-15a4-4c93-917b-479906b92d01")
    fire_id = uuid.UUID("35efbcaa-5438-5d14-b6e5-fc1d9f92c66a")
    slot = datetime(2026, 1, 1, 12, 5, tzinfo=UTC)
    return {
        "fire_id": fire_id,
        "scheduled_for": slot,
        "observed_control_token": token,
        "receipt_control_token": token,
        "execution_fire_id": derive_execution_fire_id(fire_id, token),
        "acceptance_revision": 2,
        "definition_digest": "d" * 64,
        "expected_schedule_revision": 1,
        "expected_last_run_at": None,
        "expected_next_run_at": slot,
        "prepared_next_run_at": slot + timedelta(minutes=5),
    }


async def test_current_command_retains_complete_authority_and_reuses_exactly(
    evidence: tuple[AsyncSession, Project, Schedule, Agent],
) -> None:
    session, project, schedule, agent = evidence
    authority = _authority()
    execution_fire_id = authority["execution_fire_id"]
    assert isinstance(execution_fire_id, uuid.UUID)
    payload = {
        "schedule_id": str(schedule.id),
        "fire_id": str(execution_fire_id),
        "task_name": schedule.task_name,
    }
    arguments = {
        "project_id": project.id,
        "agent_id": agent.id,
        "schedule_id": schedule.id,
        "fire_id": authority["fire_id"],
        "scheduled_for": authority["scheduled_for"],
        "observed_control_token": authority["observed_control_token"],
        "receipt_control_token": authority["receipt_control_token"],
        "execution_fire_id": authority["execution_fire_id"],
        "acceptance_revision": authority["acceptance_revision"],
        "definition_digest": authority["definition_digest"],
        "expected_revision": authority["expected_schedule_revision"],
        "expected_last_run_at": authority["expected_last_run_at"],
        "expected_next_run_at": authority["expected_next_run_at"],
        "prepared_next_run_at": authority["prepared_next_run_at"],
        "payload": payload,
        "timeout_at": datetime(2026, 1, 1, 12, 6, tzinfo=UTC),
        "initial_claim_deadline": datetime(2026, 1, 1, 12, 6, tzinfo=UTC),
    }
    command, created = await CommandRepository(
        session,
    ).insert_current_schedule_fire(**arguments)
    duplicate, duplicate_created = await CommandRepository(
        session,
    ).insert_current_schedule_fire(**arguments)

    assert created is True
    assert duplicate_created is False
    assert duplicate.id == command.id
    assert command.schedule_fire_id == authority["fire_id"]
    assert command.schedule_receipt_control_token == authority["receipt_control_token"]
    assert command.schedule_execution_fire_id == execution_fire_id
    assert command.payload["fire_id"] == str(execution_fire_id)
    assert command.cadence_initial_claim_deadline == arguments["initial_claim_deadline"]

    divergent = dict(arguments)
    divergent["prepared_next_run_at"] = datetime(2026, 1, 1, 12, 15, tzinfo=UTC)
    with pytest.raises(ConflictError, match="divergent"):
        await CommandRepository(session).insert_current_schedule_fire(**divergent)


async def test_current_delivery_claim_freezes_exact_session_authority(
    evidence: tuple[AsyncSession, Project, Schedule, Agent],
) -> None:
    session, project, schedule, agent = evidence
    authority = _authority()
    execution_fire_id = authority["execution_fire_id"]
    assert isinstance(execution_fire_id, uuid.UUID)
    command, _created = await CommandRepository(
        session,
    ).insert_current_schedule_fire(
        project_id=project.id,
        agent_id=agent.id,
        schedule_id=schedule.id,
        fire_id=authority["fire_id"],
        scheduled_for=authority["scheduled_for"],
        observed_control_token=authority["observed_control_token"],
        receipt_control_token=authority["receipt_control_token"],
        execution_fire_id=execution_fire_id,
        acceptance_revision=authority["acceptance_revision"],
        definition_digest=authority["definition_digest"],
        expected_revision=authority["expected_schedule_revision"],
        expected_last_run_at=authority["expected_last_run_at"],
        expected_next_run_at=authority["expected_next_run_at"],
        prepared_next_run_at=authority["prepared_next_run_at"],
        payload={"fire_id": str(execution_fire_id)},
        timeout_at=datetime(2026, 1, 1, 12, 6, tzinfo=UTC),
        initial_claim_deadline=datetime(
            2026,
            1,
            1,
            12,
            6,
            tzinfo=UTC,
        ),
    )
    owner = uuid.uuid4()
    generation = str(uuid.uuid4())
    is_current, claimed = await CommandRepository(
        session,
    ).claim_current_schedule_delivery(
        command.id,
        project_id=project.id,
        agent_id=agent.id,
        transport_kind="websocket",
        registry_owner_id=owner,
        session_generation=generation,
        timeout_seconds=60,
        occurred_at=datetime(2026, 1, 1, 12, 5, 30, tzinfo=UTC),
    )

    assert is_current is True
    assert claimed is not None
    assert claimed.status == CommandStatus.DISPATCHED
    assert claimed.first_delivery_claimed_at is not None
    assert claimed.cadence_redelivery_deadline == datetime(
        2026,
        1,
        1,
        12,
        6,
        30,
        tzinfo=UTC,
    )
    assert claimed.delivery_transport_kind == "websocket"
    assert claimed.delivery_registry_owner_id == owner
    assert claimed.delivery_session_generation == generation
    assert claimed.delivery_claim_token is not None
    frozen_token = claimed.delivery_claim_token

    # Replacing the handle under the same agent/worker identity cannot inherit
    # or retarget the already-claimed cadence command.
    is_current, replacement_claim = await CommandRepository(
        session,
    ).claim_current_schedule_delivery(
        command.id,
        project_id=project.id,
        agent_id=agent.id,
        transport_kind="websocket",
        registry_owner_id=uuid.uuid4(),
        session_generation=str(uuid.uuid4()),
        timeout_seconds=60,
        occurred_at=datetime(2026, 1, 1, 12, 5, 40, tzinfo=UTC),
    )
    assert is_current is True
    assert replacement_claim is None
    assert command.delivery_claim_token == frozen_token
    assert command.delivery_registry_owner_id == owner
    assert command.delivery_session_generation == generation

    original_deadline = command.cadence_redelivery_deadline
    is_current, recovered = await CommandRepository(
        session,
    ).claim_current_schedule_delivery(
        command.id,
        project_id=project.id,
        agent_id=agent.id,
        transport_kind="websocket",
        registry_owner_id=owner,
        session_generation=generation,
        timeout_seconds=3600,
        occurred_at=datetime(2026, 1, 1, 12, 5, 41, tzinfo=UTC),
    )
    assert is_current is True
    assert recovered is command
    assert command.delivery_claim_token == frozen_token
    assert command.cadence_redelivery_deadline == original_deadline
    assert command.timeout_at == original_deadline
    assert command.dispatched_at == datetime(
        2026,
        1,
        1,
        12,
        5,
        41,
        tzinfo=UTC,
    )
    is_current, duplicate_recovery = await CommandRepository(
        session,
    ).claim_current_schedule_delivery(
        command.id,
        project_id=project.id,
        agent_id=agent.id,
        transport_kind="websocket",
        registry_owner_id=owner,
        session_generation=generation,
        timeout_seconds=60,
        occurred_at=datetime(2026, 1, 1, 12, 5, 42, tzinfo=UTC),
    )
    assert is_current is True
    assert duplicate_recovery is None
    assert await CommandRepository(
        session,
    ).list_recoverable_current_websocket_deliveries(
        now=datetime(2026, 1, 1, 12, 5, 52, tzinfo=UTC),
        minimum_interval_seconds=10,
    ) == [
        (
            command.id,
            agent.id,
            owner,
            generation,
        ),
    ]
    assert (
        await CommandRepository(session).mark_failed(
            command.id,
            error="generic shortcut must not own cadence",
        )
        is False
    )
    assert (
        await CommandRepository(session).revert_dispatch(
            command.id,
            expected_dispatched_at=command.dispatched_at,
        )
        is False
    )
    assert (
        await CommandRepository(session).sweep_timeouts(
            now=datetime(2026, 1, 1, 12, 7, tzinfo=UTC),
        )
        == 0
    )
    assert command.status == CommandStatus.DISPATCHED

    class CapturingWebSocket:
        def __init__(self) -> None:
            self.sent: list[bytes] = []
            self._z4j_signer = FrameSigner(
                secret=b"cadence-delivery-frame-test-key!",
                agent_id=agent.id,
                project_id=project.id,
                session_id=generation,
            )

        async def send_bytes(self, data: bytes) -> None:
            self.sent.append(data)

    websocket = CapturingWebSocket()
    await deliver_command_frame(
        websocket=websocket,  # type: ignore[arg-type]
        settings=SimpleNamespace(command_timeout_seconds=60),  # type: ignore[arg-type]
        command=command,
    )
    assert len(websocket.sent) == 1
    frame = parse_frame(websocket.sent[0])
    assert isinstance(frame, CommandFrame)
    assert frame.payload.delivery_claim_token == str(frozen_token)

    displaced = CapturingWebSocket()

    async def generation_was_replaced() -> bool:
        return False

    displaced._z4j_validate_registry_generation = generation_was_replaced
    with pytest.raises(RuntimeError, match="generation was replaced"):
        await deliver_command_frame(
            websocket=displaced,  # type: ignore[arg-type]
            settings=SimpleNamespace(command_timeout_seconds=60),  # type: ignore[arg-type]
            command=command,
        )
    assert displaced.sent == []


async def test_current_pending_and_fire_evidence_are_generation_scoped(
    evidence: tuple[AsyncSession, Project, Schedule, Agent],
) -> None:
    session, project, schedule, _agent = evidence
    first = _authority()
    first_execution = first["execution_fire_id"]
    assert isinstance(first_execution, uuid.UUID)
    common = {
        "schedule_id": schedule.id,
        "project_id": project.id,
        "engine": schedule.engine,
        "payload": {"fire_id": str(first_execution)},
        "expires_at": datetime(2026, 1, 2, tzinfo=UTC),
        **first,
    }
    first_pending, created = await PendingFiresRepository(session).buffer_current(
        **common,
    )
    duplicate, duplicate_created = await PendingFiresRepository(
        session,
    ).buffer_current(**common)
    assert created is True
    assert duplicate_created is False
    assert duplicate.id == first_pending.id

    fire_arguments = {key: value for key, value in first.items() if key != "execution_fire_id"}
    first_fire, fire_created = await ScheduleFireRepository(session).record_current(
        schedule_id=schedule.id,
        project_id=project.id,
        command_id=None,
        status="buffered",
        **fire_arguments,
    )
    assert fire_created is True

    second_token = uuid.UUID("f690a09f-a6f5-408c-9ed7-3f677f6a7258")
    second_execution = derive_execution_fire_id(first["fire_id"], second_token)
    second = {
        **common,
        "observed_control_token": second_token,
        "receipt_control_token": second_token,
        "execution_fire_id": second_execution,
        "payload": {"fire_id": str(second_execution)},
        "acceptance_revision": 3,
    }
    second_pending, second_created = await PendingFiresRepository(
        session,
    ).buffer_current(**second)
    second_fire_arguments = {
        key: value
        for key, value in second.items()
        if key
        not in {
            "engine",
            "payload",
            "expires_at",
            "execution_fire_id",
        }
    }
    second_fire, second_fire_created = await ScheduleFireRepository(
        session,
    ).record_current(
        command_id=None,
        status="buffered",
        **second_fire_arguments,
    )

    assert second_created is True
    assert second_fire_created is True
    assert second_pending.id != first_pending.id
    assert second_fire.id != first_fire.id
    assert (await session.execute(select(func.count()).select_from(PendingFire))).scalar_one() == 2
    assert (await session.execute(select(func.count()).select_from(ScheduleFire))).scalar_one() == 2
    assert (await session.execute(select(func.count()).select_from(Command))).scalar_one() == 0
