"""Native writes stay bound to their first connection while buffers recover."""

# ruff: noqa: F811 - pytest fixture imports are intentionally shadowed
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from z4j_brain.domain import schedule_native_mutations as native
from z4j_brain.persistence.enums import CommandStatus
from z4j_brain.persistence.models import Command
from z4j_brain.persistence.repositories.commands import CommandRepository, action_is_redeliverable

from tests.unit.test_native_schedule_mutations import (
    brain_app,  # noqa: F401 - migrated fixtures
    intent,
    native_source,  # noqa: F401
    settings,  # noqa: F401
)


@pytest.mark.parametrize("delivered_before_restart", [False, True])
async def test_native_write_cannot_follow_a_reconnected_executor(
    brain_app, native_source, delivered_before_restart
):
    """Exercise the real migrated DB and delivery claim used before a frame is sent."""
    seed, stream, schedule, _ = native_source
    args = intent(seed, schedule)
    original = {
        "project_id": seed["project_id"],
        "agent_id": stream.executor_agent_id,
        "transport_kind": "websocket",
        "registry_owner_id": stream.executor_registry_owner_id,
        "session_generation": stream.executor_session_generation,
        "timeout_seconds": 30,
    }
    async with brain_app.state.db.session(write=True) as session:
        command, _ = await native.plan(session, **args)
        command_id = command.id
        assert not action_is_redeliverable(command.action)
        if delivered_before_restart:
            current, claimed = await CommandRepository(session).claim_current_schedule_delivery(
                command_id, **original
            )
            assert current and claimed is command
            assert command.status == CommandStatus.DISPATCHED
        await session.commit()

    # A new connection cannot inherit the command, even with the same durable
    # agent token and registry process. A new Brain worker is also refused.
    for overrides in (
        {"session_generation": uuid.uuid4().hex},
        {"registry_owner_id": uuid.uuid4()},
        {"transport_kind": "longpoll"},
    ):
        async with brain_app.state.db.session(write=True) as session:
            current, claimed = await CommandRepository(session).claim_current_schedule_delivery(
                command_id, **(original | overrides)
            )
            assert current is True, "refusal must not fall through to generic delivery"
            assert claimed is None
            await session.commit()

    async with brain_app.state.db.session(write=True) as session:
        repository = CommandRepository(session)
        current, claimed = await repository.claim_current_schedule_delivery(command_id, **original)
        assert current
        assert (claimed is not None) is (not delivered_before_restart)
        # The only accepted delivery is the original connection's first claim.
        current, claimed = await repository.claim_current_schedule_delivery(command_id, **original)
        assert current and claimed is None
        replay, _ = await native.plan(session, **args)
        assert replay.id == command_id
        assert replay.status == CommandStatus.DISPATCHED
        assert len((await session.execute(select(Command))).scalars().all()) == 1
        await session.commit()

    # No result after disconnect is an unknown outcome, not permission to
    # re-execute. Repeating the public request retains the original command.
    async with brain_app.state.db.session(write=True) as session:
        command = await session.get(Command, command_id)
        command.status = CommandStatus.TIMEOUT
        await session.flush()
        replay, _ = await native.plan(session, **args)
        assert replay.id == command_id and replay.status == CommandStatus.TIMEOUT
        result = await native.status(session, project_id=seed["project_id"], command_id=command_id)
        assert result["status"] == "UNCONFIRMED"
        current, claimed = await CommandRepository(session).claim_current_schedule_delivery(
            command_id, **original
        )
        assert current and claimed is None


@pytest.mark.parametrize("action", ["schedule.external.mutate", "schedule.external.activate"])
@pytest.mark.parametrize("generic_method", ["dispatch", "redispatch", "revert", "reassign"])
async def test_external_commands_cannot_use_generic_delivery_transitions(
    brain_app, native_source, action, generic_method
):
    from datetime import UTC, datetime, timedelta

    seed, _, schedule, _ = native_source
    async with brain_app.state.db.session(write=True) as session:
        command, _ = await native.plan(session, **intent(seed, schedule))
        command.action = action
        if generic_method in {"redispatch", "revert"}:
            command.status = CommandStatus.DISPATCHED
            command.dispatched_at = datetime.now(UTC) - timedelta(seconds=60)
        await session.flush()
        repository = CommandRepository(session)
        if generic_method == "dispatch":
            outcome = await repository.mark_dispatched(command.id, timeout_seconds=30)
        elif generic_method == "redispatch":
            outcome = await repository.claim_redispatch(
                command.id,
                min_interval_seconds=0,
                expected_dispatched_at=command.dispatched_at,
            )
        elif generic_method == "revert":
            outcome = await repository.revert_dispatch(
                command.id,
                timeout_seconds=30,
                expected_dispatched_at=command.dispatched_at,
            )
        else:
            outcome = await repository.reassign_pending_owner(
                command.id, new_agent_id=command.agent_id
            )
        assert not outcome, f"{action} was admitted by generic {generic_method}"


@pytest.mark.parametrize("action", ["schedule.external.mutate", "schedule.external.activate"])
async def test_longpoll_leaves_frozen_websocket_commands_and_delivers_ordinary_work(
    brain_app, native_source, settings, action
):
    from datetime import UTC, datetime, timedelta

    from httpx import ASGITransport, AsyncClient
    from z4j_brain.persistence.models import Agent
    from z4j_brain.websocket.auth import hash_agent_token

    seed, stream, schedule, _ = native_source
    token = f"native-recovery-test-{uuid.uuid4()}"
    async with brain_app.state.db.session(write=True) as session:
        agent = await session.get(Agent, stream.executor_agent_id)
        agent.token_hash = hash_agent_token(
            plaintext=token, secret=settings.secret.get_secret_value().encode()
        )
        frozen, _ = await native.plan(session, **intent(seed, schedule))
        frozen.action = action
        ordinary, _ = await CommandRepository(session).insert(
            project_id=seed["project_id"],
            agent_id=agent.id,
            issued_by=seed["user_id"],
            action="schedule.resync",
            target_type="scheduler",
            target_id="celery-beat",
            payload={},
            idempotency_key=None,
            timeout_at=datetime.now(UTC) + timedelta(seconds=60),
            source_ip=None,
        )
        await session.commit()
    async with AsyncClient(
        transport=ASGITransport(app=brain_app), base_url="http://testserver"
    ) as client:
        response = await client.get(
            "/api/v1/agent/commands",
            params={"wait": 0, "max_frames": 1},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 200, response.text
    frames = response.json()["frames"]
    assert len(frames) == 1
    assert str(ordinary.id) in frames[0], "frozen native work must not occupy the poll limit"
    assert str(frozen.id) not in frames[0]
    async with brain_app.state.db.session() as session:
        frozen = await session.get(Command, frozen.id)
        ordinary = await session.get(Command, ordinary.id)
        assert frozen.status == CommandStatus.PENDING
        assert frozen.first_delivery_claimed_at is None
        assert ordinary.status == CommandStatus.DISPATCHED


async def test_actual_websocket_callbacks_refuse_restart_and_missing_session_binding(
    brain_app, native_source, settings
):
    from z4j_brain.websocket.gateway import _drain_pending_for_agent
    from z4j_brain.websocket.registry import SessionHandle
    from z4j_core.transport.framing import FrameSigner

    seed, stream, schedule, _ = native_source
    async with brain_app.state.db.session(write=True) as session:
        command, _ = await native.plan(session, **intent(seed, schedule))
        command_id = command.id
        await session.commit()

    class CapturingWebSocket:
        def __init__(self, *, generation=None):
            self.sent = []
            self._z4j_agent_id = stream.executor_agent_id
            if generation is not None:
                self._z4j_registry_owner_id = stream.executor_registry_owner_id
                self._z4j_session_generation = generation
            self._z4j_signer = FrameSigner(
                secret=b"native-command-recovery-frame-key-32",
                agent_id=stream.executor_agent_id,
                project_id=seed["project_id"],
                session_id=generation or "unbound",
            )

        async def send_bytes(self, data):
            self.sent.append(data)

    callback = brain_app.state.brain_registry._deliver_local
    missing = CapturingWebSocket()
    assert await callback(command_id, missing) is False
    assert missing.sent == []
    restarted = CapturingWebSocket(generation=str(uuid.uuid4()))
    assert await callback(command_id, restarted) is False
    assert restarted.sent == []

    handle = SessionHandle.create(
        agent_id=stream.executor_agent_id,
        worker_id="replacement",
        websocket=restarted,
        retry_contracts={},
        registry_owner_id=stream.executor_registry_owner_id,
    )
    # The reconnect drain also has a direct delivery route used when no
    # registry is supplied. It must obey the same immutable generation.
    await _drain_pending_for_agent(
        db=brain_app.state.db,
        settings=settings,
        agent_id=stream.executor_agent_id,
        session_handle=handle,
    )
    assert restarted.sent == []

    original = CapturingWebSocket(generation=stream.executor_session_generation)
    assert await callback(command_id, original) is True
    assert len(original.sent) == 1 and str(command_id).encode() in original.sent[0]
    assert await callback(command_id, original) is False
    assert await callback(command_id, restarted) is False
    assert len(original.sent) == 1
    assert restarted.sent == []
