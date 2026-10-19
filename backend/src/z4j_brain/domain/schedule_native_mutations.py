"""Native writes use signed commands; accepted snapshots remain the sole writer."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from z4j_core.schedule_external import (
    EXTERNAL_SCHEDULE_MUTATION_CAPABILITY,
    external_schedule_configuration,
)

from z4j_brain.errors import ConflictError, NotFoundError, ValidationError
from z4j_brain.persistence.enums import CommandStatus
from z4j_brain.persistence.models import (
    Agent,
    Command,
    Schedule,
    ScheduleExternalControlOperation,
    ScheduleExternalProjection,
    ScheduleExternalSnapshotFrame,
    ScheduleExternalStream,
)
from z4j_brain.persistence.repositories import CommandRepository
from z4j_brain.persistence.repositories.schedule_external import _business_projection

ACTION = "schedule.external.mutate"
EDITABLE = {
    "name",
    "task_name",
    "kind",
    "expression",
    "timezone",
    "queue",
    "args",
    "kwargs",
    "is_enabled",
}


async def capabilities(session: AsyncSession, *, project_id: uuid.UUID) -> dict[str, list[str]]:
    """Return operations bound to each active scheduler's exact connection."""
    rows = (
        await session.execute(
            select(ScheduleExternalStream, Agent)
            .join(
                Agent,
                Agent.id == ScheduleExternalStream.executor_agent_id,
            )
            .where(
                ScheduleExternalStream.project_id == project_id,
                ScheduleExternalStream.phase == "ACTIVE",
                Agent.revoked_at.is_(None),
            )
        )
    ).all()
    result = {}
    for stream, agent in rows:
        bound = (
            (agent.agent_metadata or {}).get("_z4j_external_capabilities", {}).get(stream.owner, {})
        )
        if (
            bound.get("epoch_uuid") == str(stream.current_epoch_uuid)
            and bound.get("registry_owner_id") == str(stream.executor_registry_owner_id)
            and bound.get("session_generation") == stream.executor_session_generation
        ):
            result[stream.owner] = list(bound.get("capabilities", []))
    return result


def _matches_requested_definition(observed: dict[str, Any], definition: dict[str, Any]) -> bool:
    """Native stores may normalize equivalent interval and clocked expressions."""
    for key, value in definition.items():
        if observed.get(key) == value:
            continue
        if key != "expression":
            return False
        try:
            if observed["kind"] == "interval" and Decimal(observed[key]) == Decimal(str(value)):
                continue
            if observed["kind"] == "clocked" and datetime.fromisoformat(
                observed[key]
            ) == datetime.fromisoformat(value):
                continue
            if observed["kind"] == "cron":
                if observed[key].split() == value.split():
                    continue
                if observed.get("scheduler") == "apscheduler":
                    from z4j_core.cron_fields import numeric_cron_field

                    bounds = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 6))
                    left, right = observed[key].split(), value.split()
                    if len(left) == len(right) == 5 and all(
                        numeric_cron_field(a, low, high) == numeric_cron_field(b, low, high)
                        for a, b, (low, high) in zip(left, right, bounds, strict=True)
                    ):
                        continue
        except (TypeError, ValueError, InvalidOperation):
            return False
        return False
    return True


async def plan(  # noqa: PLR0912 - explicit authority and operation checks
    session: AsyncSession,
    *,
    project_id: uuid.UUID,
    user_id: uuid.UUID,
    scheduler: str,
    operation: str,
    schedule_id: uuid.UUID | None,
    definition: dict[str, Any],
    request_id: uuid.UUID,
    observed_control_token: uuid.UUID | None,
    source_ip: str,
    timeout_seconds: int,
) -> tuple[Command, ScheduleExternalStream]:
    if operation not in {"create", "update", "delete", "trigger"} or set(definition) - EDITABLE:
        raise ValidationError("unsupported native schedule operation or fields")
    if scheduler == "z4j-scheduler":
        raise ValidationError("use the normal schedule endpoint for z4j-owned schedules")
    if operation in {"delete", "trigger"} and definition:
        raise ValidationError("delete and trigger do not accept definition changes")
    stream = (
        await session.execute(
            select(ScheduleExternalStream)
            .where(
                ScheduleExternalStream.project_id == project_id,
                ScheduleExternalStream.owner == scheduler,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if stream is None:
        raise ConflictError("native scheduler is not connected with current source authority")
    intent = {
        "scheduler": scheduler,
        "operation": operation,
        "schedule_id": str(schedule_id) if schedule_id else None,
        "definition": definition,
        "observed_control_token": str(observed_control_token) if observed_control_token else None,
    }
    prior_command = (
        await session.execute(
            select(Command).where(
                Command.project_id == project_id,
                Command.idempotency_key == f"native-mutation:{request_id}",
            )
        )
    ).scalar_one_or_none()
    if prior_command is not None:
        if prior_command.action != ACTION or prior_command.payload.get("intent") != intent:
            raise ConflictError("native mutation request ID was reused for different content")
        return prior_command, stream
    if stream.phase != "ACTIVE" or stream.executor_agent_id is None:
        raise ConflictError("native scheduler is not connected with current source authority")
    expected = None
    native_id = None
    if operation == "create":
        if schedule_id is not None or observed_control_token is not None:
            raise ValidationError("create cannot name an existing schedule")
    else:
        row = (
            await session.execute(
                select(Schedule)
                .where(
                    Schedule.id == schedule_id,
                    Schedule.project_id == project_id,
                    Schedule.external_stream_id == stream.id,
                    Schedule.external_epoch_uuid == stream.current_epoch_uuid,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if row is None:
            raise NotFoundError("native schedule not found in the current source snapshot")
        if operation == "trigger" and row.paused_at is not None:
            raise ConflictError("schedule is on hold; release it before triggering")
        if row.source == "celery-beat:static" and operation != "trigger":
            raise ConflictError(
                "static Beat schedules are read-only; edit application configuration"
            )
        if observed_control_token is None or row.control_token != observed_control_token:
            raise ConflictError("schedule changed since it was displayed; refresh before editing")
        expected = _business_projection(row)
        native_id = row.external_source_key
    control = (
        await session.execute(
            select(ScheduleExternalControlOperation.id)
            .where(
                ScheduleExternalControlOperation.stream_id == stream.id,
                ScheduleExternalControlOperation.status.in_(("PENDING", "CLAIMED", "AMBIGUOUS")),
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    pending = (
        await session.execute(
            select(Command.id)
            .where(
                Command.project_id == project_id,
                Command.action == ACTION,
                Command.target_id == scheduler,
                Command.status.in_((CommandStatus.PENDING, CommandStatus.DISPATCHED)),
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    if control is not None or pending is not None:
        raise ConflictError("another native schedule operation is awaiting confirmation")
    agent = (
        await session.execute(
            select(Agent)
            .where(
                Agent.id == stream.executor_agent_id,
                Agent.project_id == project_id,
                Agent.revoked_at.is_(None),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    required_capability = (
        "trigger_now" if operation == "trigger" else EXTERNAL_SCHEDULE_MUTATION_CAPABILITY
    )
    negotiated = (
        (agent.agent_metadata or {}).get("_z4j_external_capabilities", {}).get(scheduler, {})
        if agent is not None
        else {}
    )
    if agent is None or (
        negotiated.get("epoch_uuid") != str(stream.current_epoch_uuid)
        or negotiated.get("registry_owner_id") != str(stream.executor_registry_owner_id)
        or negotiated.get("session_generation") != stream.executor_session_generation
        or required_capability not in negotiated.get("capabilities", [])
    ):
        raise ConflictError("the connected scheduler does not support atomic native writes")
    operation_capability = "trigger_now" if operation == "trigger" else operation
    if operation == "update" and set(definition) == {"is_enabled"}:
        operation_capability = "enable" if definition["is_enabled"] else "disable"
    if operation_capability not in negotiated.get("capabilities", []):
        raise ConflictError("the connected native scheduler does not support this operation")
    payload = dict(  # noqa: C408 - named wire fields
        intent=intent,
        operation_id=str(request_id),
        scheduler=scheduler,
        owner=scheduler,
        operation=operation,
        schedule_id=native_id,
        definition=definition,
        expected=expected,
        stream_id=str(stream.id),
        epoch_uuid=str(stream.current_epoch_uuid),
        epoch_number=stream.current_epoch_number,
        source_scope=stream.source_scope,
        adapter_instance_id=stream.authorized_adapter_instance_id,
        stable_source=True,
        registry_owner_id=str(stream.executor_registry_owner_id),
        session_generation=stream.executor_session_generation,
        expected_accepted_sequence=stream.accepted_sequence,
    )
    command, _ = await CommandRepository(session).insert(
        project_id=project_id,
        agent_id=agent.id,
        issued_by=user_id,
        action=ACTION,
        target_type="scheduler",
        target_id=scheduler,
        payload=payload,
        idempotency_key=f"native-mutation:{request_id}",
        timeout_at=datetime.now(UTC) + timedelta(seconds=timeout_seconds),
        source_ip=source_ip,
        enforce_payload_identity=True,
    )
    return command, stream


async def status(  # noqa: PLR0911 - explicit confirmation/refusal states
    session: AsyncSession, *, project_id: uuid.UUID, command_id: uuid.UUID
) -> dict[str, Any]:
    command = (
        await session.execute(
            select(Command).where(
                Command.id == command_id,
                Command.project_id == project_id,
                Command.action == ACTION,
            )
        )
    ).scalar_one_or_none()
    if command is None:
        raise NotFoundError("native schedule operation not found")
    result = {
        "id": str(command.id),
        "status": "PENDING",
        "schedule_id": None,
        "error": command.error,
    }
    if command.status in {CommandStatus.FAILED, CommandStatus.TIMEOUT, CommandStatus.CANCELLED}:
        result["status"] = "UNCONFIRMED"
        return result
    receipt = command.result or {}
    # Command results carry their adapter result under `result`.
    if isinstance(receipt.get("result"), dict):
        receipt = receipt["result"]
    if command.status != CommandStatus.COMPLETED or not receipt.get("sequence"):
        return result
    payload = command.payload
    if (
        receipt.get("operation_id") != payload["operation_id"]
        or receipt.get("stream_id") != payload["stream_id"]
        or receipt.get("epoch_uuid") != payload["epoch_uuid"]
        or receipt.get("epoch_number") != payload["epoch_number"]
        or not isinstance(receipt.get("sequence"), int)
        or receipt["sequence"] <= payload["expected_accepted_sequence"]
        or (
            payload["operation"] != "create" and receipt.get("source_key") != payload["schedule_id"]
        )
    ):
        result["status"] = "UNCONFIRMED"
        return result
    projection = (
        await session.execute(
            select(ScheduleExternalProjection).where(
                ScheduleExternalProjection.stream_id == uuid.UUID(payload["stream_id"]),
                ScheduleExternalProjection.epoch_uuid == uuid.UUID(payload["epoch_uuid"]),
                ScheduleExternalProjection.sequence == receipt["sequence"],
            )
        )
    ).scalar_one_or_none()
    if projection is None:
        return result
    frames = (
        (
            await session.execute(
                select(ScheduleExternalSnapshotFrame).where(
                    ScheduleExternalSnapshotFrame.stream_id == projection.stream_id,
                    ScheduleExternalSnapshotFrame.epoch_uuid == projection.epoch_uuid,
                    ScheduleExternalSnapshotFrame.sequence == projection.sequence,
                    ScheduleExternalSnapshotFrame.snapshot_digest == projection.payload_digest,
                    ScheduleExternalSnapshotFrame.frame_kind == "rows",
                )
            )
        )
        .scalars()
        .all()
    )
    observed = next(
        (
            row
            for frame in frames
            for row in frame.schedules
            if row["source_key"] == receipt.get("source_key")
        ),
        None,
    )
    confirmed = (
        observed is None
        if payload["operation"] == "delete"
        else observed is not None
        and external_schedule_configuration(observed) == receipt.get("observed_configuration")
    )
    if observed is not None and payload["operation"] != "delete":
        confirmed = confirmed and _matches_requested_definition(observed, payload["definition"])
    if not confirmed:
        result["status"] = "UNCONFIRMED"
        return result
    if (
        payload["operation"] == "trigger"
        and receipt.get("trigger_result", {}).get("status") != "success"
    ):
        result["status"] = "UNCONFIRMED"
        return result
    result["status"] = "APPLIED"
    row = (
        await session.execute(
            select(Schedule.id).where(
                Schedule.project_id == project_id,
                Schedule.external_stream_id == projection.stream_id,
                Schedule.external_source_key == receipt.get("source_key"),
            )
        )
    ).scalar_one_or_none()
    result["schedule_id"] = str(row) if row else None
    return result
