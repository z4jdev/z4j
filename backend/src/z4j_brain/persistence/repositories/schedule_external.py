"""Sequenced Boundary-D projection path for external scheduler adapters."""

from __future__ import annotations

import hashlib
import hmac
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import null, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from z4j_core.schedule_external import (
    ExternalScheduleProtocolError,
    canonical_external_json,
    external_control_result_matches_desired,
    external_projection_body,
    external_projection_digest,
    external_snapshot_frame_body,
    external_snapshot_frame_digest,
)

from z4j_brain.domain.schedule_cadence import (
    CADENCE_SEMANTICS_VERSION,
    ScheduleCadenceError,
    cadence_runtime_fingerprint,
    canonical_next_run_at,
)
from z4j_brain.domain.schedule_definition import schedule_definition_digest
from z4j_brain.persistence.enums import CommandStatus, ScheduleKind, TaskPriority
from z4j_brain.persistence.models import (
    Agent,
    Command,
    Project,
    Schedule,
    ScheduleChangeLog,
    ScheduleExternalControlOperation,
    ScheduleExternalEpochAllocator,
    ScheduleExternalProjection,
    ScheduleExternalSnapshotFrame,
    ScheduleExternalStream,
    ScheduleExternalStreamEpoch,
    ScheduleOwnerCutover,
    ScheduleTerminalHold,
)
from z4j_brain.persistence.models.schedule_control import (
    SCHEDULE_CHANGE_PROTOCOL_VERSION,
)
from z4j_brain.persistence.models.schedule_external import (
    SCHEDULE_EXTERNAL_EPOCH_SINGLETON_ID,
)
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
    operator_hold_in_force,
    schedule_is_quarantined,
    schedule_snapshot,
)
from z4j_brain.persistence.schedule_external_guard import (
    arm_external_ambiguity,
    arm_external_control_transition,
    arm_external_epoch_allocation,
    arm_external_lifecycle_transition,
    arm_external_projection,
    arm_external_snapshot_frame,
    assert_external_control_consumed,
    assert_external_epoch_allocation_consumed,
    assert_external_lifecycle_consumed,
    assert_external_projection_consumed,
    finish_external_target_cutover,
)
from z4j_brain.persistence.schedule_guard import arm_schedule_transition


class ScheduleExternalProtocolFaultError(ValueError):
    """One epoch/sequence was reused with different canonical content."""


@dataclass(frozen=True, slots=True)
class ExternalProjectionTransition:
    disposition: str
    stream: ScheduleExternalStream | None
    projection: ScheduleExternalProjection | None = None
    inserted: int = 0
    updated: int = 0
    deleted: int = 0


@dataclass(frozen=True, slots=True)
class ExternalSnapshotFrameTransition:
    """Durable staging result for one stable-snapshot frame."""

    disposition: str
    stream: ScheduleExternalStream | None
    projection: ScheduleExternalProjection | None = None
    frame: ScheduleExternalSnapshotFrame | None = None
    inserted: int = 0
    updated: int = 0
    deleted: int = 0


@dataclass(frozen=True, slots=True)
class ExternalControlPlan:
    """Result of planning one external set-to-state operation."""

    disposition: str
    stream: ScheduleExternalStream | None
    schedule: Schedule | None
    operation: ScheduleExternalControlOperation | None = None
    command: Command | None = None


@dataclass(frozen=True, slots=True)
class ExternalControlReceiptTransition:
    """Outcome of one exact control receipt or terminal ambiguity."""

    disposition: str
    stream: ScheduleExternalStream | None
    operation: ScheduleExternalControlOperation | None
    command: Command | None


@dataclass(frozen=True, slots=True)
class ExternalLifecycleTransition:
    """Outcome of one stream drain/seal/retire edge."""

    disposition: str
    stream: ScheduleExternalStream | None
    epoch: ScheduleExternalStreamEpoch | None


@dataclass(frozen=True, slots=True)
class ExternalOwnerCutoverPreview:
    """Canonical owner-cutover preview and its operator-bound digest."""

    manifest: dict[str, Any]
    manifest_digest: str


@dataclass(frozen=True, slots=True)
class ExternalOwnerCutoverTransition:
    """Outcome of one idempotent manifest-bound owner cutover."""

    disposition: str
    cutover: ScheduleOwnerCutover | None
    schedules: tuple[Schedule, ...] = ()


@dataclass(slots=True)
class _Mutation:
    operation: str
    source_key: str
    schedule_id: uuid.UUID
    row: Schedule | None
    values: dict[str, Any] | None
    old_revision: int
    old_token: uuid.UUID | None
    new_token: uuid.UUID | None
    new_revision: int = 0


def _utc(value: datetime) -> datetime:
    return (value.replace(tzinfo=UTC) if value.tzinfo is None else value).astimezone(UTC)


def _parse_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    return _utc(parsed)


def _schedule_values(
    projected: dict[str, Any],
    *,
    stream: ScheduleExternalStream,
    sequence: int,
    control_token: uuid.UUID,
    revision: int | None,
    now: datetime,
) -> dict[str, Any]:
    try:
        kind = ScheduleKind(str(projected["kind"]))
        priority = TaskPriority(str(projected["priority"]))
    except ValueError as exc:
        raise ExternalScheduleProtocolError(
            "external schedule kind or priority is unsupported",
        ) from exc
    values: dict[str, Any] = {
        "project_id": stream.project_id,
        "engine": str(projected["engine"]),
        "scheduler": stream.owner,
        "name": str(projected["name"]),
        "task_name": str(projected["task_name"]),
        "kind": kind,
        "expression": str(projected["expression"]),
        "timezone": str(projected["timezone"]),
        "queue": projected["queue"],
        "priority": priority,
        "args": projected["args"],
        "kwargs": projected["kwargs"],
        "is_enabled": bool(projected["is_enabled"]),
        "last_run_at": _parse_timestamp(projected["last_run_at"]),
        "next_run_at": _parse_timestamp(projected["next_run_at"]),
        "total_runs": int(projected["total_runs"]),
        "external_id": projected["external_id"],
        "catch_up": str(projected["catch_up"]),
        "source": str(projected["source"]),
        "source_hash": projected["source_hash"],
        "control_token": control_token,
        "legacy_fire_control_token": None,
        "schedule_revision": revision,
        "cadence_semantics_version": CADENCE_SEMANTICS_VERSION,
        "cadence_runtime_fingerprint": cadence_runtime_fingerprint(),
        "quarantine_control_token": None,
        "quarantine_code": None,
        "quarantine_detail": None,
        "quarantined_at": None,
        "external_stream_id": stream.id,
        "external_epoch_uuid": stream.current_epoch_uuid,
        "external_epoch_number": stream.current_epoch_number,
        "external_source_key": str(projected["source_key"]),
        "external_source_sequence": sequence,
        "updated_at": now,
    }
    values["definition_digest"] = schedule_definition_digest(values)
    return values


def _business_projection(row: Schedule) -> dict[str, Any]:
    return {
        "engine": row.engine,
        "scheduler": row.scheduler,
        "name": row.name,
        "task_name": row.task_name,
        "kind": row.kind.value,
        "expression": row.expression,
        "timezone": row.timezone,
        "queue": row.queue,
        "priority": row.priority.value,
        "args": row.args,
        "kwargs": row.kwargs,
        "is_enabled": row.is_enabled,
        "last_run_at": (
            _utc(row.last_run_at).isoformat(timespec="microseconds")
            if row.last_run_at is not None
            else None
        ),
        "next_run_at": (
            _utc(row.next_run_at).isoformat(timespec="microseconds")
            if row.next_run_at is not None
            else None
        ),
        "total_runs": row.total_runs,
        "external_id": row.external_id,
        "catch_up": row.catch_up,
        "source": row.source,
        "source_hash": row.source_hash,
        "source_key": row.external_source_key,
    }


def _cutover_projection(
    snapshot: dict[str, Any],
    *,
    source_key: str,
) -> dict[str, Any]:
    """Seal the definition the target adapter is being handed.

    ``is_enabled`` is copied as stored rather than reduced through the hold
    states, because the cutover refuses every row where those two differ. If
    that gate is ever relaxed, this becomes the line that tells a foreign
    scheduler to run something an operator stopped.
    """

    fields = (
        "engine",
        "scheduler",
        "name",
        "task_name",
        "kind",
        "expression",
        "timezone",
        "queue",
        "priority",
        "args",
        "kwargs",
        "is_enabled",
        "last_run_at",
        "next_run_at",
        "total_runs",
        "external_id",
        "catch_up",
        "source",
        "source_hash",
    )
    return {
        **{field: snapshot[field] for field in fields},
        "source_key": source_key,
    }


class ScheduleExternalRepository:
    """Apply external source truth only under its exact next stream epoch."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self._control = ScheduleControlRepository(session)

    async def get_stream(
        self,
        *,
        project_id: uuid.UUID,
        owner: str,
        source_scope: str,
    ) -> ScheduleExternalStream | None:
        result = await self.session.execute(
            select(ScheduleExternalStream).where(
                ScheduleExternalStream.project_id == project_id,
                ScheduleExternalStream.owner == owner,
                ScheduleExternalStream.source_scope == source_scope,
            ),
        )
        return result.scalar_one_or_none()

    async def ensure_activation_epoch(  # noqa: PLR0912, PLR0915
        self,
        *,
        project_id: uuid.UUID,
        owner: str,
        source_scope: str,
        occurred_at: datetime,
        adapter_instance_id: str | None = None,
        executor_agent_id: uuid.UUID | None = None,
        executor_registry_owner_id: uuid.UUID | None = None,
        executor_session_generation: str | None = None,
        executor_worker_id: str | None = None,
        activation_requirement: str | None = None,
        replace_retired: bool = False,
        reactivate_restored: bool = False,
    ) -> ScheduleExternalStream:
        """Return, create, or explicitly replace the Brain-issued current epoch."""

        if replace_retired and reactivate_restored:
            raise ExternalScheduleProtocolError(
                "external epoch replacement reason is ambiguous",
            )
        if not owner or owner == "z4j-scheduler":
            raise ExternalScheduleProtocolError(
                "external stream owner is missing or reserved",
            )
        if adapter_instance_id is not None and not adapter_instance_id.strip():
            raise ExternalScheduleProtocolError(
                "external adapter instance id is empty",
            )
        executor_authority = (
            executor_agent_id,
            executor_registry_owner_id,
            executor_session_generation,
        )
        if (adapter_instance_id is None) != all(value is None for value in executor_authority):
            raise ExternalScheduleProtocolError(
                "external adapter and executor authority must be allocated together",
            )
        if adapter_instance_id is not None and (
            executor_agent_id is None
            or executor_registry_owner_id is None
            or not str(executor_session_generation or "").strip()
        ):
            raise ExternalScheduleProtocolError(
                "external executor authority is incomplete",
            )
        if activation_requirement is not None and (
            not activation_requirement.startswith("OWNER_CUTOVER:")
            or len(activation_requirement) > 100
        ):
            raise ExternalScheduleProtocolError(
                "external activation requirement is unsupported",
            )
        scope_digest = hashlib.sha256(
            source_scope.encode("utf-8"),
        ).hexdigest()
        allocator_result = await self.session.execute(
            select(ScheduleExternalEpochAllocator)
            .where(
                ScheduleExternalEpochAllocator.singleton_id == SCHEDULE_EXTERNAL_EPOCH_SINGLETON_ID,
            )
            .with_for_update(),
        )
        allocator = allocator_result.scalar_one_or_none()
        if allocator is None or allocator.guard_version != 1:
            raise ScheduleExternalProtocolFaultError(
                "external epoch allocator is unavailable",
            )
        existing = (
            await self.session.execute(
                select(ScheduleExternalStream)
                .where(
                    ScheduleExternalStream.project_id == project_id,
                    ScheduleExternalStream.owner == owner,
                    ScheduleExternalStream.source_scope == source_scope,
                )
                .with_for_update(),
            )
        ).scalar_one_or_none()
        if existing is not None and not (replace_retired or reactivate_restored):
            return existing
        if existing is not None:
            required_phase = "RESTORE_REACTIVATION_REQUIRED" if reactivate_restored else "RETIRED"
            if existing.phase != required_phase:
                raise ExternalScheduleProtocolError(
                    "external stream is not held for restore reactivation"
                    if reactivate_restored
                    else "external stream is not retired for replacement",
                )
            if not reactivate_restored:
                remaining = (
                    await self.session.execute(
                        select(Schedule.id)
                        .where(
                            Schedule.external_stream_id == existing.id,
                        )
                        .limit(1),
                    )
                ).scalar_one_or_none()
                if remaining is not None:
                    raise ExternalScheduleProtocolError(
                        "retired external stream still owns schedules",
                    )
        elif reactivate_restored:
            raise ExternalScheduleProtocolError(
                "restored external stream is unavailable for reactivation",
            )
        if allocator.current_epoch_number >= 9_223_372_036_854_775_807:
            raise OverflowError("external epoch allocator is exhausted")

        stream_id = existing.id if existing is not None else uuid.uuid4()
        epoch_uuid = uuid.uuid4()
        old_epoch_number = int(allocator.current_epoch_number)
        epoch_number = old_epoch_number + 1
        now = _utc(occurred_at)
        await arm_external_epoch_allocation(
            self.session,
            stream_id=stream_id,
            epoch_uuid=epoch_uuid,
            epoch_number=epoch_number,
            old_epoch_number=old_epoch_number,
            project_id=project_id,
            owner=owner,
            source_scope_digest=scope_digest,
            adapter_instance_id=adapter_instance_id,
        )
        result = await self.session.execute(
            update(ScheduleExternalEpochAllocator)
            .where(
                ScheduleExternalEpochAllocator.singleton_id == SCHEDULE_EXTERNAL_EPOCH_SINGLETON_ID,
                ScheduleExternalEpochAllocator.current_epoch_number == old_epoch_number,
            )
            .values(current_epoch_number=epoch_number),
        )
        if (result.rowcount or 0) != 1:
            raise ScheduleExternalProtocolFaultError(
                "external epoch allocator did not advance exactly once",
            )
        allocator.current_epoch_number = epoch_number

        epoch = ScheduleExternalStreamEpoch(
            epoch_uuid=epoch_uuid,
            epoch_number=epoch_number,
            stream_id=stream_id,
            phase="ACTIVATING",
            authorized_adapter_instance_id=adapter_instance_id,
            executor_agent_id=executor_agent_id,
            executor_registry_owner_id=executor_registry_owner_id,
            executor_session_generation=executor_session_generation,
            executor_worker_id=executor_worker_id,
            accepted_sequence=0,
            sealed_sequence=None,
            last_snapshot_digest=None,
            last_projection_digest=None,
            activation_requirement=activation_requirement,
            created_at=now,
            activated_at=None,
            sealed_at=None,
            retired_at=None,
        )
        self.session.add(epoch)
        await self.session.flush()
        if existing is None:
            stream = ScheduleExternalStream(
                id=stream_id,
                project_id=project_id,
                owner=owner,
                source_scope=source_scope,
                source_scope_digest=scope_digest,
                current_epoch_uuid=epoch_uuid,
                current_epoch_number=epoch_number,
                phase="ACTIVATING",
                authorized_adapter_instance_id=adapter_instance_id,
                executor_agent_id=executor_agent_id,
                executor_registry_owner_id=(executor_registry_owner_id),
                executor_session_generation=(executor_session_generation),
                executor_worker_id=executor_worker_id,
                accepted_sequence=0,
                sealed_sequence=None,
                last_snapshot_digest=None,
                last_projection_digest=None,
                activation_requirement=activation_requirement,
                created_at=now,
                updated_at=now,
            )
            self.session.add(stream)
        else:
            stream = existing
            stream.current_epoch_uuid = epoch_uuid
            stream.current_epoch_number = epoch_number
            stream.phase = "ACTIVATING"
            stream.authorized_adapter_instance_id = adapter_instance_id
            stream.executor_agent_id = executor_agent_id
            stream.executor_registry_owner_id = executor_registry_owner_id
            stream.executor_session_generation = executor_session_generation
            stream.executor_worker_id = executor_worker_id
            stream.accepted_sequence = 0
            stream.sealed_sequence = None
            stream.last_snapshot_digest = None
            stream.last_projection_digest = None
            stream.activation_requirement = activation_requirement
            stream.updated_at = now
        await self.session.flush()
        await assert_external_epoch_allocation_consumed(self.session)
        return stream

    async def abandon_undelivered_activation(
        self,
        *,
        project_id: uuid.UUID,
        stream_id: uuid.UUID,
        occurred_at: datetime,
    ) -> bool:
        """Retire only an activation whose command was never claimed or delivered."""

        stream = (
            await self.session.execute(
                select(ScheduleExternalStream)
                .where(
                    ScheduleExternalStream.id == stream_id,
                    ScheduleExternalStream.project_id == project_id,
                )
                .with_for_update(),
            )
        ).scalar_one_or_none()
        if (
            stream is None
            or stream.phase != "ACTIVATING"
            or stream.accepted_sequence != 0
            or stream.sealed_sequence is not None
            or stream.last_snapshot_digest is not None
            or stream.last_projection_digest is not None
            or stream.activation_requirement is not None
            or stream.authorized_adapter_instance_id is None
            or stream.executor_agent_id is None
            or stream.executor_registry_owner_id is None
            or not stream.executor_session_generation
        ):
            return False
        epoch = await self._lock_current_epoch(stream)
        candidates = list(
            (
                await self.session.execute(
                    select(Command)
                    .where(
                        Command.project_id == project_id,
                        Command.agent_id == stream.executor_agent_id,
                        Command.action == "schedule.external.activate",
                    )
                    .with_for_update(),
                )
            ).scalars(),
        )
        exact: list[Command] = []
        for command in candidates:
            payload = command.payload
            if not isinstance(payload, dict):
                continue
            if (
                str(payload.get("stream_id") or "") == str(stream.id)
                and str(payload.get("epoch_uuid") or "") == str(stream.current_epoch_uuid)
                and payload.get("epoch_number") == stream.current_epoch_number
                and payload.get("adapter_instance_id") == stream.authorized_adapter_instance_id
                and str(payload.get("registry_owner_id") or "")
                == str(stream.executor_registry_owner_id)
                and str(payload.get("session_generation") or "")
                == stream.executor_session_generation
            ):
                exact.append(command)
        if len(exact) != 1:
            return False
        activation = exact[0]
        if (
            activation.status != CommandStatus.PENDING
            or activation.dispatched_at is not None
            or activation.completed_at is not None
            or activation.result is not None
            or activation.error is not None
            or activation.first_delivery_claimed_at is not None
            or activation.delivery_transport_kind is not None
            or activation.delivery_registry_owner_id is not None
            or activation.delivery_session_generation is not None
            or activation.delivery_claim_token is not None
            or activation.agent_acknowledged_at is not None
        ):
            return False
        remaining_schedule = await self.session.scalar(
            select(Schedule.id).where(Schedule.external_stream_id == stream.id).limit(1),
        )
        if remaining_schedule is not None:
            return False

        now = _utc(occurred_at)
        activation.status = CommandStatus.CANCELLED
        activation.completed_at = now
        activation.error = (
            "activation retired before delivery after its bound WebSocket generation disconnected"
        )
        await self.session.flush()
        await self._transition_stream_lifecycle(
            stream=stream,
            epoch=epoch,
            transition="abandon_activation",
            to_phase="RETIRED",
            occurred_at=now,
        )
        return True

    async def _mark_protocol_fault(
        self,
        *,
        stream: ScheduleExternalStream,
        sequence: int,
        payload_digest: str,
    ) -> ExternalProjectionTransition:
        """Atomically make a conflicting stream non-accepting."""

        adapter_instance_id = stream.authorized_adapter_instance_id
        if not adapter_instance_id:
            raise ScheduleExternalProtocolFaultError(
                "external protocol fault lacks bound adapter authority",
            )
        epoch = (
            await self.session.execute(
                select(ScheduleExternalStreamEpoch)
                .where(
                    ScheduleExternalStreamEpoch.stream_id == stream.id,
                    ScheduleExternalStreamEpoch.epoch_uuid == stream.current_epoch_uuid,
                    ScheduleExternalStreamEpoch.epoch_number == stream.current_epoch_number,
                )
                .with_for_update(),
            )
        ).scalar_one_or_none()
        if epoch is None or epoch.phase != stream.phase:
            raise ScheduleExternalProtocolFaultError(
                "external stream history is inconsistent during protocol fault",
            )
        await arm_external_ambiguity(
            self.session,
            stream_id=stream.id,
            epoch_uuid=stream.current_epoch_uuid,
            epoch_number=stream.current_epoch_number,
            sequence=sequence,
            payload_digest=payload_digest,
            adapter_instance_id=adapter_instance_id,
        )
        epoch.phase = "AMBIGUOUS"
        epoch.activation_requirement = "PROTOCOL_FAULT"
        await self.session.flush()
        stream.phase = "AMBIGUOUS"
        stream.activation_requirement = "PROTOCOL_FAULT"
        await self.session.flush()
        await assert_external_projection_consumed(self.session)
        return ExternalProjectionTransition("protocol_fault", stream)

    async def _lock_current_epoch(
        self,
        stream: ScheduleExternalStream,
    ) -> ScheduleExternalStreamEpoch:
        epoch = (
            await self.session.execute(
                select(ScheduleExternalStreamEpoch)
                .where(
                    ScheduleExternalStreamEpoch.stream_id == stream.id,
                    ScheduleExternalStreamEpoch.epoch_uuid == stream.current_epoch_uuid,
                    ScheduleExternalStreamEpoch.epoch_number == stream.current_epoch_number,
                )
                .with_for_update(),
            )
        ).scalar_one_or_none()
        if epoch is None or epoch.phase != stream.phase:
            raise ScheduleExternalProtocolFaultError(
                "current external stream epoch history is inconsistent",
            )
        return epoch

    async def _transition_stream_lifecycle(
        self,
        *,
        stream: ScheduleExternalStream,
        epoch: ScheduleExternalStreamEpoch,
        transition: str,
        to_phase: str,
        occurred_at: datetime,
        operation_id: uuid.UUID | None = None,
        mutations: list[dict[str, str]] | None = None,
    ) -> None:
        now = _utc(occurred_at)
        sealed_sequence = (
            stream.accepted_sequence
            if to_phase in {"SEALED", "RETIRED"}
            else stream.sealed_sequence
        )
        await arm_external_lifecycle_transition(
            self.session,
            transition=transition,
            operation_id=operation_id,
            stream_id=stream.id,
            epoch_uuid=stream.current_epoch_uuid,
            epoch_number=stream.current_epoch_number,
            accepted_sequence=stream.accepted_sequence,
            from_phase=stream.phase,
            to_phase=to_phase,
            sealed_sequence=sealed_sequence,
            last_snapshot_digest=stream.last_snapshot_digest,
            mutations=mutations or [],
        )
        epoch.phase = to_phase
        epoch.sealed_sequence = sealed_sequence
        if to_phase == "SEALED":
            epoch.sealed_at = now
        elif to_phase == "RETIRED":
            epoch.retired_at = now
        await self.session.flush()
        stream.phase = to_phase
        stream.sealed_sequence = sealed_sequence
        stream.updated_at = now
        await self.session.flush()
        await assert_external_lifecycle_consumed(self.session)

    async def begin_stream_drain(
        self,
        *,
        project_id: uuid.UUID,
        stream_id: uuid.UUID,
        occurred_at: datetime,
    ) -> ExternalLifecycleTransition:
        """Stop new controls while accepting the exact inbound prefix."""

        stream = (
            await self.session.execute(
                select(ScheduleExternalStream)
                .where(
                    ScheduleExternalStream.id == stream_id,
                    ScheduleExternalStream.project_id == project_id,
                )
                .with_for_update(),
            )
        ).scalar_one_or_none()
        if stream is None:
            return ExternalLifecycleTransition(
                "stream_not_found",
                None,
                None,
            )
        epoch = await self._lock_current_epoch(stream)
        if stream.phase == "DRAINING":
            return ExternalLifecycleTransition(
                "exact_replay",
                stream,
                epoch,
            )
        if stream.phase != "ACTIVE":
            return ExternalLifecycleTransition(
                "stream_not_active",
                stream,
                epoch,
            )
        await self._transition_stream_lifecycle(
            stream=stream,
            epoch=epoch,
            transition="drain",
            to_phase="DRAINING",
            occurred_at=occurred_at,
        )
        return ExternalLifecycleTransition("draining", stream, epoch)

    async def seal_drained_stream(  # noqa: PLR0911
        self,
        *,
        project_id: uuid.UUID,
        stream_id: uuid.UUID,
        expected_sequence: int,
        expected_snapshot_digest: str,
        occurred_at: datetime,
    ) -> ExternalLifecycleTransition:
        """Seal only the exact accepted final stable snapshot."""

        stream = (
            await self.session.execute(
                select(ScheduleExternalStream)
                .where(
                    ScheduleExternalStream.id == stream_id,
                    ScheduleExternalStream.project_id == project_id,
                )
                .with_for_update(),
            )
        ).scalar_one_or_none()
        if stream is None:
            return ExternalLifecycleTransition(
                "stream_not_found",
                None,
                None,
            )
        epoch = await self._lock_current_epoch(stream)
        if stream.phase == "SEALED":
            if (
                stream.sealed_sequence == expected_sequence
                and stream.last_snapshot_digest == expected_snapshot_digest
            ):
                return ExternalLifecycleTransition(
                    "exact_replay",
                    stream,
                    epoch,
                )
            return ExternalLifecycleTransition(
                "seal_mismatch",
                stream,
                epoch,
            )
        if stream.phase != "DRAINING":
            return ExternalLifecycleTransition(
                "stream_not_draining",
                stream,
                epoch,
            )
        unresolved = (
            await self.session.execute(
                select(ScheduleExternalControlOperation.id)
                .where(
                    ScheduleExternalControlOperation.stream_id == stream.id,
                    ScheduleExternalControlOperation.status.in_(
                        ("PENDING", "CLAIMED"),
                    ),
                )
                .limit(1),
            )
        ).scalar_one_or_none()
        if unresolved is not None:
            return ExternalLifecycleTransition(
                "control_in_flight",
                stream,
                epoch,
            )
        if (
            stream.accepted_sequence != expected_sequence
            or not expected_snapshot_digest
            or stream.last_snapshot_digest != expected_snapshot_digest
        ):
            return ExternalLifecycleTransition(
                "seal_mismatch",
                stream,
                epoch,
            )
        await self._transition_stream_lifecycle(
            stream=stream,
            epoch=epoch,
            transition="seal",
            to_phase="SEALED",
            occurred_at=occurred_at,
        )
        return ExternalLifecycleTransition("sealed", stream, epoch)

    async def retire_sealed_stream(
        self,
        *,
        project_id: uuid.UUID,
        stream_id: uuid.UUID,
        occurred_at: datetime,
    ) -> ExternalLifecycleTransition:
        """Retire sealed ingress before owner transition exposure."""

        stream = (
            await self.session.execute(
                select(ScheduleExternalStream)
                .where(
                    ScheduleExternalStream.id == stream_id,
                    ScheduleExternalStream.project_id == project_id,
                )
                .with_for_update(),
            )
        ).scalar_one_or_none()
        if stream is None:
            return ExternalLifecycleTransition(
                "stream_not_found",
                None,
                None,
            )
        epoch = await self._lock_current_epoch(stream)
        if stream.phase == "RETIRED":
            return ExternalLifecycleTransition(
                "exact_replay",
                stream,
                epoch,
            )
        if stream.phase != "SEALED":
            return ExternalLifecycleTransition(
                "stream_not_sealed",
                stream,
                epoch,
            )
        await self._transition_stream_lifecycle(
            stream=stream,
            epoch=epoch,
            transition="retire",
            to_phase="RETIRED",
            occurred_at=occurred_at,
        )
        return ExternalLifecycleTransition("retired", stream, epoch)

    async def _external_to_reserved_preview(
        self,
        *,
        project_id: uuid.UUID,
        from_owner: str,
        source_scope: str,
        cursor_policy: str,
        lock_rows: bool,
    ) -> tuple[
        ExternalOwnerCutoverPreview,
        ScheduleExternalStream | None,
        list[Schedule],
    ]:
        if from_owner == "z4j-scheduler":
            raise ExternalScheduleProtocolError(
                "external-to-reserved cutover requires an external source owner",
            )
        if cursor_policy not in {
            "PRESERVE",
            "PRESERVE_FUTURE",
            "RESET_CURSOR",
        }:
            raise ExternalScheduleProtocolError(
                "unsupported owner-cutover cursor policy",
            )
        stream_query = select(ScheduleExternalStream).where(
            ScheduleExternalStream.project_id == project_id,
            ScheduleExternalStream.owner == from_owner,
            ScheduleExternalStream.source_scope == source_scope,
        )
        if lock_rows:
            stream_query = stream_query.with_for_update()
        stream = (await self.session.execute(stream_query)).scalar_one_or_none()
        rows: list[Schedule] = []
        if stream is not None:
            row_query = (
                select(Schedule)
                .where(
                    Schedule.project_id == project_id,
                    Schedule.scheduler == from_owner,
                    Schedule.external_stream_id == stream.id,
                )
                .order_by(Schedule.id)
            )
            if lock_rows:
                row_query = row_query.with_for_update()
            rows = list((await self.session.execute(row_query)).scalars())
        selected_ids = [row.id for row in rows]
        selected_names = [row.name for row in rows]
        collision_query = (
            select(Schedule.id, Schedule.name)
            .where(
                Schedule.project_id == project_id,
                Schedule.scheduler == "z4j-scheduler",
                Schedule.name.in_(selected_names),
            )
            .order_by(Schedule.id)
        )
        if selected_ids:
            collision_query = collision_query.where(
                Schedule.id.not_in(selected_ids),
            )
        collisions = [
            {
                "schedule_id": str(row_id),
                "name": name,
            }
            for row_id, name in (await self.session.execute(collision_query)).all()
        ]
        stream_manifest = (
            {
                "stream_id": str(stream.id),
                "epoch_uuid": str(stream.current_epoch_uuid),
                "epoch_number": int(stream.current_epoch_number),
                "phase": stream.phase,
                "accepted_sequence": int(stream.accepted_sequence),
                "sealed_sequence": stream.sealed_sequence,
                "last_snapshot_digest": stream.last_snapshot_digest,
                "last_projection_digest": stream.last_projection_digest,
                "adapter_instance_id": (stream.authorized_adapter_instance_id),
                "executor_agent_id": (
                    str(stream.executor_agent_id) if stream.executor_agent_id is not None else None
                ),
                "registry_owner_id": (
                    str(stream.executor_registry_owner_id)
                    if stream.executor_registry_owner_id is not None
                    else None
                ),
                "session_generation": (stream.executor_session_generation),
            }
            if stream is not None
            else None
        )
        manifest = {
            "format": "z4j-owner-cutover-preview-v1",
            "project_id": str(project_id),
            "from_owner": from_owner,
            "to_owner": "z4j-scheduler",
            "source_scope": source_scope,
            "cursor_policy": cursor_policy,
            "stream": stream_manifest,
            "schedules": [schedule_snapshot(row)["schedule"] for row in rows],
            "target_collisions": collisions,
        }
        digest = hashlib.sha256(
            canonical_external_json(manifest),
        ).hexdigest()
        return (
            ExternalOwnerCutoverPreview(manifest, digest),
            stream,
            rows,
        )

    async def preview_external_to_reserved_cutover(
        self,
        *,
        project_id: uuid.UUID,
        from_owner: str,
        source_scope: str,
        cursor_policy: str = "PRESERVE",
    ) -> ExternalOwnerCutoverPreview:
        """Return the complete byte-stable manifest an operator must attest."""

        preview, _, _ = await self._external_to_reserved_preview(
            project_id=project_id,
            from_owner=from_owner,
            source_scope=source_scope,
            cursor_policy=cursor_policy,
            lock_rows=False,
        )
        return preview

    async def _append_owner_cutover_envelope(
        self,
        row: Schedule,
        *,
        revision: int,
        overrides: dict[str, Any],
        occurred_at: datetime,
        operation_id: uuid.UUID,
        cursor_policy: str,
    ) -> None:
        to_owner = str(overrides["scheduler"])
        if to_owner == "z4j-scheduler":
            await self._control._append_upsert(
                row,
                revision=revision,
                overrides=overrides,
                occurred_at=occurred_at,
                transition={
                    "kind": "owner_cutover",
                    "operation_id": str(operation_id),
                    "from_owner": row.scheduler,
                    "to_owner": to_owner,
                    "cursor_policy": cursor_policy,
                },
            )
            return
        change_kind = "delete" if row.scheduler == "z4j-scheduler" else "gap"
        self.session.add(
            ScheduleChangeLog(
                revision=revision,
                project_id=row.project_id,
                schedule_id=row.id,
                schedule_owner=row.scheduler,
                change_kind=change_kind,
                protocol_version=SCHEDULE_CHANGE_PROTOCOL_VERSION,
                snapshot=null(),
                occurred_at=occurred_at,
            ),
        )
        await self.session.flush()
        await arm_schedule_transition(
            self.session,
            operation="update",
            schedule_id=row.id,
            old_revision=int(row.schedule_revision or 0),
            new_revision=revision,
            change_kind=change_kind,
            old_token=row.control_token,
            new_token=overrides["control_token"],
        )

    async def finalize_external_to_reserved_cutover(  # noqa: PLR0911, PLR0912, PLR0915
        self,
        *,
        operation_id: uuid.UUID,
        project_id: uuid.UUID,
        from_owner: str,
        source_scope: str,
        preview_manifest_digest: str,
        cursor_policy: str,
        quiescence_attestation: dict[str, Any],
        occurred_at: datetime,
    ) -> ExternalOwnerCutoverTransition:
        """Retire sealed ingress and expose reserved rows in one commit."""

        existing = (
            await self.session.execute(
                select(ScheduleOwnerCutover)
                .where(ScheduleOwnerCutover.id == operation_id)
                .with_for_update(),
            )
        ).scalar_one_or_none()
        attestation_digest = hashlib.sha256(
            canonical_external_json(quiescence_attestation),
        ).hexdigest()
        if existing is not None:
            if (
                existing.project_id != project_id
                or existing.from_owner != from_owner
                or existing.to_owner != "z4j-scheduler"
                or existing.source_scope != source_scope
                or existing.preview_manifest_digest != preview_manifest_digest
                or existing.cursor_policy != cursor_policy
                or existing.quiescence_attestation_digest != attestation_digest
            ):
                return ExternalOwnerCutoverTransition(
                    "operation_conflict",
                    existing,
                )
            return ExternalOwnerCutoverTransition(
                "exact_replay",
                existing,
            )

        preview, stream, rows = await self._external_to_reserved_preview(
            project_id=project_id,
            from_owner=from_owner,
            source_scope=source_scope,
            cursor_policy=cursor_policy,
            lock_rows=True,
        )
        if stream is None:
            return ExternalOwnerCutoverTransition(
                "stream_not_found",
                None,
            )
        epoch = await self._lock_current_epoch(stream)
        if stream.phase != "SEALED":
            return ExternalOwnerCutoverTransition(
                "stream_not_sealed",
                None,
            )
        if (
            stream.sealed_sequence != stream.accepted_sequence
            or stream.last_snapshot_digest is None
        ):
            return ExternalOwnerCutoverTransition(
                "seal_incomplete",
                None,
            )
        if not hmac.compare_digest(
            preview.manifest_digest,
            preview_manifest_digest,
        ):
            return ExternalOwnerCutoverTransition(
                "preview_changed",
                None,
            )
        if preview.manifest["target_collisions"]:
            return ExternalOwnerCutoverTransition(
                "target_collision",
                None,
            )
        attested = (
            quiescence_attestation.get(
                "all_old_and_new_scheduler_replicas_quiesced",
            )
            is True
            and quiescence_attestation.get(
                "preview_manifest_digest",
            )
            == preview_manifest_digest
            and quiescence_attestation.get("stream_id") == str(stream.id)
            and quiescence_attestation.get("epoch_uuid") == str(stream.current_epoch_uuid)
            and quiescence_attestation.get("sealed_sequence") == stream.sealed_sequence
            and quiescence_attestation.get(
                "final_snapshot_digest",
            )
            == stream.last_snapshot_digest
        )
        if not attested:
            return ExternalOwnerCutoverTransition(
                "attestation_required",
                None,
            )
        project = (
            await self.session.execute(
                select(Project).where(Project.id == project_id).with_for_update(),
            )
        ).scalar_one_or_none()
        if project is None:
            return ExternalOwnerCutoverTransition(
                "project_not_found",
                None,
            )
        if (
            project.allowed_schedulers is not None
            and "z4j-scheduler" not in project.allowed_schedulers
        ):
            return ExternalOwnerCutoverTransition(
                "target_owner_not_allowed",
                None,
            )
        schedule_ids = [row.id for row in rows]
        unresolved_hold = (
            await self.session.execute(
                select(ScheduleTerminalHold.id)
                .where(
                    ScheduleTerminalHold.schedule_id.in_(
                        schedule_ids,
                    ),
                    ScheduleTerminalHold.resolved_at.is_(None),
                )
                .limit(1),
            )
        ).scalar_one_or_none()
        # Quarantine only, deliberately, where the cutover to an external
        # owner refuses on either hold. Adoption is the direction that makes a
        # hold meaningful again: the row lands under an owner that honours it
        # and an operator who can lift it, so the hold travels with the row
        # instead of blocking the move. An unrepaired definition has no such
        # story and must be resolved before this brain starts firing it.
        if unresolved_hold is not None or any(schedule_is_quarantined(row) for row in rows):
            return ExternalOwnerCutoverTransition(
                "unresolved_schedule_state",
                None,
            )

        now = _utc(occurred_at)
        prepared: list[tuple[Schedule, dict[str, Any], int]] = []
        result_rows: list[dict[str, Any]] = []
        for row in rows:
            if row.control_token is None or not row.schedule_revision:
                raise ScheduleExternalProtocolFaultError(
                    "cutover schedule lacks current D identity",
                )
            if row.total_runs < 0:
                return ExternalOwnerCutoverTransition(
                    "invalid_counter",
                    None,
                )
            last_run_at = (
                None
                if cursor_policy == "RESET_CURSOR"
                else (_utc(row.last_run_at) if row.last_run_at is not None else None)
            )
            if (
                last_run_at is not None
                and _utc(last_run_at) > now + timedelta(minutes=5)
                and cursor_policy != "PRESERVE_FUTURE"
            ):
                return ExternalOwnerCutoverTransition(
                    "future_cursor_requires_policy",
                    None,
                )
            next_run_at = None
            if row.is_enabled:
                try:
                    next_run_at = canonical_next_run_at(
                        kind=row.kind.value,
                        expression=row.expression,
                        timezone=row.timezone,
                        last_run_at=last_run_at,
                        anchor_at=now,
                    )
                except (ScheduleCadenceError, ValueError):
                    return ExternalOwnerCutoverTransition(
                        "invalid_definition",
                        None,
                    )
                if next_run_at is None and row.kind.value not in {
                    "clocked",
                    "one_shot",
                }:
                    return ExternalOwnerCutoverTransition(
                        "invalid_definition",
                        None,
                    )
            new_token = uuid.uuid4()
            new_revision = await self._control._allocate_revision()
            overrides: dict[str, Any] = {
                "scheduler": "z4j-scheduler",
                "control_token": new_token,
                "legacy_fire_control_token": None,
                "schedule_revision": new_revision,
                "last_run_at": last_run_at,
                "next_run_at": next_run_at,
                "last_fire_id": None,
                "last_cadence_acceptance_control_token": None,
                "last_cadence_acceptance_fire_id": None,
                "last_cadence_acceptance_scheduled_for": None,
                "last_cadence_acceptance_revision": None,
                "cadence_semantics_version": (CADENCE_SEMANTICS_VERSION),
                "cadence_runtime_fingerprint": (cadence_runtime_fingerprint()),
                "quarantine_control_token": None,
                "quarantine_code": None,
                "quarantine_detail": None,
                "quarantined_at": None,
                "external_stream_id": None,
                "external_epoch_uuid": None,
                "external_epoch_number": None,
                "external_source_key": None,
                "external_source_sequence": None,
                "updated_at": now,
            }
            future = schedule_snapshot(
                row,
                overrides=overrides,
            )["schedule"]
            overrides["definition_digest"] = schedule_definition_digest(future)
            prepared.append((row, overrides, new_revision))
            result_rows.append(
                {
                    "schedule_id": str(row.id),
                    "old_revision": int(row.schedule_revision),
                    "new_revision": new_revision,
                    "old_control_token": str(row.control_token),
                    "new_control_token": str(new_token),
                    "last_run_at": future["last_run_at"],
                    "next_run_at": future["next_run_at"],
                    "total_runs": row.total_runs,
                },
            )

        source_stream_manifest = [
            {
                "stream_id": str(stream.id),
                "epoch_uuid": str(stream.current_epoch_uuid),
                "epoch_number": stream.current_epoch_number,
                "sealed_sequence": stream.sealed_sequence,
                "final_snapshot_digest": (stream.last_snapshot_digest),
            },
        ]
        result_manifest = {
            "format": "z4j-owner-cutover-result-v1",
            "operation_id": str(operation_id),
            "project_id": str(project_id),
            "from_owner": from_owner,
            "to_owner": "z4j-scheduler",
            "retired_streams": source_stream_manifest,
            "schedules": result_rows,
        }
        result_digest = hashlib.sha256(
            canonical_external_json(result_manifest),
        ).hexdigest()
        mutations = [
            {
                "schedule_id": str(row.id),
                "from_owner": from_owner,
                "to_owner": "z4j-scheduler",
            }
            for row, _, _ in prepared
        ]
        await arm_external_lifecycle_transition(
            self.session,
            transition="cutover",
            operation_id=operation_id,
            stream_id=stream.id,
            epoch_uuid=stream.current_epoch_uuid,
            epoch_number=stream.current_epoch_number,
            accepted_sequence=stream.accepted_sequence,
            from_phase=stream.phase,
            to_phase="RETIRED",
            sealed_sequence=stream.sealed_sequence,
            last_snapshot_digest=stream.last_snapshot_digest,
            mutations=mutations,
            manifest_digest=preview_manifest_digest,
            project_id=project_id,
            from_owner=from_owner,
            to_owner="z4j-scheduler",
        )
        cutover = ScheduleOwnerCutover(
            id=operation_id,
            project_id=project_id,
            from_owner=from_owner,
            to_owner="z4j-scheduler",
            source_scope=source_scope,
            preview_manifest_digest=preview_manifest_digest,
            preview_manifest=preview.manifest,
            cursor_policy=cursor_policy,
            quiescence_attestation=quiescence_attestation,
            quiescence_attestation_digest=attestation_digest,
            source_stream_manifest=source_stream_manifest,
            target_stream_id=None,
            result_manifest=result_manifest,
            result_manifest_digest=result_digest,
            completed_at=now,
            created_at=now,
        )
        self.session.add(cutover)
        await self.session.flush()
        for row, overrides, revision in prepared:
            await self._append_owner_cutover_envelope(
                row,
                revision=revision,
                overrides=overrides,
                occurred_at=now,
                operation_id=operation_id,
                cursor_policy=cursor_policy,
            )
            for field, value in overrides.items():
                setattr(row, field, value)
            await self.session.flush()
        epoch.phase = "RETIRED"
        epoch.retired_at = now
        await self.session.flush()
        stream.phase = "RETIRED"
        stream.updated_at = now
        await self.session.flush()
        await assert_external_lifecycle_consumed(self.session)
        return ExternalOwnerCutoverTransition(
            "completed",
            cutover,
            tuple(row for row, _, _ in prepared),
        )

    async def _to_external_preview(  # noqa: PLR0912, PLR0915
        self,
        *,
        project_id: uuid.UUID,
        from_owner: str,
        source_scope: str,
        to_owner: str,
        target_source_scope: str,
        schedule_ids: tuple[uuid.UUID, ...],
        cursor_policy: str,
        target_adapter_instance_id: str,
        target_executor_agent_id: uuid.UUID,
        target_executor_registry_owner_id: uuid.UUID,
        target_executor_session_generation: str,
        target_executor_worker_id: str | None,
        lock_rows: bool,
    ) -> tuple[
        ExternalOwnerCutoverPreview,
        ScheduleExternalStream | None,
        list[Schedule],
        ScheduleExternalStream | None,
    ]:
        if not to_owner or to_owner in {"z4j-scheduler", from_owner}:
            raise ExternalScheduleProtocolError(
                "target cutover owner must be a distinct external owner",
            )
        if cursor_policy not in {
            "PRESERVE",
            "PRESERVE_FUTURE",
            "RESET_CURSOR",
        }:
            raise ExternalScheduleProtocolError(
                "unsupported owner-cutover cursor policy",
            )
        if not target_adapter_instance_id.strip() or not target_executor_session_generation.strip():
            raise ExternalScheduleProtocolError(
                "target external executor authority is incomplete",
            )
        normalized_ids = tuple(
            sorted(set(schedule_ids), key=str),
        )
        if len(normalized_ids) != len(schedule_ids):
            raise ExternalScheduleProtocolError(
                "owner-cutover schedule selection contains duplicates",
            )
        source_stream: ScheduleExternalStream | None = None
        if from_owner == "z4j-scheduler":
            if not normalized_ids:
                raise ExternalScheduleProtocolError(
                    "reserved-source cutover requires explicit schedules",
                )
            row_query = (
                select(Schedule)
                .where(
                    Schedule.project_id == project_id,
                    Schedule.scheduler == from_owner,
                    Schedule.id.in_(normalized_ids),
                )
                .order_by(Schedule.id)
            )
            if lock_rows:
                row_query = row_query.with_for_update()
            rows = list(
                (await self.session.execute(row_query)).scalars(),
            )
            if len(rows) != len(normalized_ids):
                raise ExternalScheduleProtocolError(
                    "reserved-source cutover selection changed",
                )
        else:
            if normalized_ids:
                raise ExternalScheduleProtocolError(
                    "external-source cutover selects its complete stream",
                )
            stream_query = select(ScheduleExternalStream).where(
                ScheduleExternalStream.project_id == project_id,
                ScheduleExternalStream.owner == from_owner,
                ScheduleExternalStream.source_scope == source_scope,
            )
            if lock_rows:
                stream_query = stream_query.with_for_update()
            source_stream = (await self.session.execute(stream_query)).scalar_one_or_none()
            rows = []
            if source_stream is not None:
                row_query = (
                    select(Schedule)
                    .where(
                        Schedule.project_id == project_id,
                        Schedule.scheduler == from_owner,
                        Schedule.external_stream_id == source_stream.id,
                    )
                    .order_by(Schedule.id)
                )
                if lock_rows:
                    row_query = row_query.with_for_update()
                rows = list(
                    (await self.session.execute(row_query)).scalars(),
                )
        target_query = select(ScheduleExternalStream).where(
            ScheduleExternalStream.project_id == project_id,
            ScheduleExternalStream.owner == to_owner,
            ScheduleExternalStream.source_scope == target_source_scope,
        )
        if lock_rows:
            target_query = target_query.with_for_update()
        target_stream = (await self.session.execute(target_query)).scalar_one_or_none()
        target_owned_ids: list[uuid.UUID] = []
        if target_stream is not None:
            target_owned_query = (
                select(Schedule.id)
                .where(
                    Schedule.external_stream_id == target_stream.id,
                )
                .order_by(Schedule.id)
            )
            if lock_rows:
                target_owned_query = target_owned_query.with_for_update()
            target_owned_ids = list(
                (
                    await self.session.execute(
                        target_owned_query,
                    )
                ).scalars(),
            )
        selected_ids = [row.id for row in rows]
        selected_names = [row.name for row in rows]
        collision_query = (
            select(Schedule.id, Schedule.name)
            .where(
                Schedule.project_id == project_id,
                Schedule.scheduler == to_owner,
                Schedule.name.in_(selected_names),
            )
            .order_by(Schedule.id)
        )
        if selected_ids:
            collision_query = collision_query.where(
                Schedule.id.not_in(selected_ids),
            )
        collisions = [
            {"schedule_id": str(row_id), "name": name}
            for row_id, name in (await self.session.execute(collision_query)).all()
        ]
        source_manifest = (
            {
                "stream_id": str(source_stream.id),
                "epoch_uuid": str(
                    source_stream.current_epoch_uuid,
                ),
                "epoch_number": (source_stream.current_epoch_number),
                "phase": source_stream.phase,
                "accepted_sequence": (source_stream.accepted_sequence),
                "sealed_sequence": source_stream.sealed_sequence,
                "last_snapshot_digest": (source_stream.last_snapshot_digest),
                "adapter_instance_id": (source_stream.authorized_adapter_instance_id),
                "executor_agent_id": (
                    str(source_stream.executor_agent_id)
                    if source_stream.executor_agent_id is not None
                    else None
                ),
                "registry_owner_id": (
                    str(
                        source_stream.executor_registry_owner_id,
                    )
                    if source_stream.executor_registry_owner_id is not None
                    else None
                ),
                "session_generation": (source_stream.executor_session_generation),
            }
            if source_stream is not None
            else None
        )
        target_existing = (
            {
                "stream_id": str(target_stream.id),
                "epoch_uuid": str(
                    target_stream.current_epoch_uuid,
                ),
                "epoch_number": (target_stream.current_epoch_number),
                "phase": target_stream.phase,
                "owned_schedule_ids": [str(value) for value in target_owned_ids],
            }
            if target_stream is not None
            else None
        )
        manifest = {
            "format": "z4j-owner-cutover-preview-v1",
            "project_id": str(project_id),
            "from_owner": from_owner,
            "to_owner": to_owner,
            "source_scope": source_scope,
            "target_source_scope": target_source_scope,
            "cursor_policy": cursor_policy,
            "source_stream": source_manifest,
            "schedule_ids": [str(value) for value in normalized_ids],
            "schedules": [schedule_snapshot(row)["schedule"] for row in rows],
            "target_executor": {
                "adapter_instance_id": (target_adapter_instance_id),
                "agent_id": str(target_executor_agent_id),
                "registry_owner_id": str(
                    target_executor_registry_owner_id,
                ),
                "session_generation": (target_executor_session_generation),
                "worker_id": target_executor_worker_id,
            },
            "target_existing_stream": target_existing,
            "target_collisions": collisions,
        }
        digest = hashlib.sha256(
            canonical_external_json(manifest),
        ).hexdigest()
        return (
            ExternalOwnerCutoverPreview(manifest, digest),
            source_stream,
            rows,
            target_stream,
        )

    async def preview_to_external_cutover(
        self,
        *,
        project_id: uuid.UUID,
        from_owner: str,
        source_scope: str,
        to_owner: str,
        target_source_scope: str,
        schedule_ids: tuple[uuid.UUID, ...] = (),
        cursor_policy: str = "PRESERVE",
        target_adapter_instance_id: str,
        target_executor_agent_id: uuid.UUID,
        target_executor_registry_owner_id: uuid.UUID,
        target_executor_session_generation: str,
        target_executor_worker_id: str | None = None,
    ) -> ExternalOwnerCutoverPreview:
        """Preview an exact fresh-epoch transition into external ownership."""

        preview, _, _, _ = await self._to_external_preview(
            project_id=project_id,
            from_owner=from_owner,
            source_scope=source_scope,
            to_owner=to_owner,
            target_source_scope=target_source_scope,
            schedule_ids=schedule_ids,
            cursor_policy=cursor_policy,
            target_adapter_instance_id=(target_adapter_instance_id),
            target_executor_agent_id=target_executor_agent_id,
            target_executor_registry_owner_id=(target_executor_registry_owner_id),
            target_executor_session_generation=(target_executor_session_generation),
            target_executor_worker_id=target_executor_worker_id,
            lock_rows=False,
        )
        return preview

    async def finalize_to_external_cutover(  # noqa: PLR0911, PLR0912, PLR0915
        self,
        *,
        operation_id: uuid.UUID,
        project_id: uuid.UUID,
        from_owner: str,
        source_scope: str,
        to_owner: str,
        target_source_scope: str,
        schedule_ids: tuple[uuid.UUID, ...],
        preview_manifest_digest: str,
        cursor_policy: str,
        quiescence_attestation: dict[str, Any],
        target_adapter_instance_id: str,
        target_executor_agent_id: uuid.UUID,
        target_executor_registry_owner_id: uuid.UUID,
        target_executor_session_generation: str,
        target_executor_worker_id: str | None,
        occurred_at: datetime,
    ) -> ExternalOwnerCutoverTransition:
        """Move rows to a fresh non-accepting external target epoch."""

        existing = (
            await self.session.execute(
                select(ScheduleOwnerCutover)
                .where(ScheduleOwnerCutover.id == operation_id)
                .with_for_update(),
            )
        ).scalar_one_or_none()
        attestation_digest = hashlib.sha256(
            canonical_external_json(quiescence_attestation),
        ).hexdigest()
        if existing is not None:
            if (
                existing.project_id != project_id
                or existing.from_owner != from_owner
                or existing.to_owner != to_owner
                or existing.source_scope != source_scope
                or existing.preview_manifest_digest != preview_manifest_digest
                or existing.cursor_policy != cursor_policy
                or existing.quiescence_attestation_digest != attestation_digest
            ):
                return ExternalOwnerCutoverTransition(
                    "operation_conflict",
                    existing,
                )
            return ExternalOwnerCutoverTransition(
                "exact_replay",
                existing,
            )
        preview, source_stream, rows, target_existing = await self._to_external_preview(
            project_id=project_id,
            from_owner=from_owner,
            source_scope=source_scope,
            to_owner=to_owner,
            target_source_scope=target_source_scope,
            schedule_ids=schedule_ids,
            cursor_policy=cursor_policy,
            target_adapter_instance_id=(target_adapter_instance_id),
            target_executor_agent_id=(target_executor_agent_id),
            target_executor_registry_owner_id=(target_executor_registry_owner_id),
            target_executor_session_generation=(target_executor_session_generation),
            target_executor_worker_id=(target_executor_worker_id),
            lock_rows=True,
        )
        if not hmac.compare_digest(
            preview.manifest_digest,
            preview_manifest_digest,
        ):
            return ExternalOwnerCutoverTransition(
                "preview_changed",
                None,
            )
        if target_existing is not None and target_existing.phase != "RETIRED":
            return ExternalOwnerCutoverTransition(
                "target_stream_exists",
                None,
            )
        if (
            preview.manifest["target_existing_stream"] is not None
            and preview.manifest["target_existing_stream"]["owned_schedule_ids"]
        ):
            return ExternalOwnerCutoverTransition(
                "target_stream_not_empty",
                None,
            )
        if preview.manifest["target_collisions"]:
            return ExternalOwnerCutoverTransition(
                "target_collision",
                None,
            )
        source_epoch: ScheduleExternalStreamEpoch | None = None
        if from_owner != "z4j-scheduler":
            if source_stream is None:
                return ExternalOwnerCutoverTransition(
                    "stream_not_found",
                    None,
                )
            source_epoch = await self._lock_current_epoch(
                source_stream,
            )
            if source_stream.phase != "SEALED":
                return ExternalOwnerCutoverTransition(
                    "stream_not_sealed",
                    None,
                )
            if (
                source_stream.sealed_sequence != source_stream.accepted_sequence
                or source_stream.last_snapshot_digest is None
            ):
                return ExternalOwnerCutoverTransition(
                    "seal_incomplete",
                    None,
                )
        attested = (
            quiescence_attestation.get(
                "all_old_and_new_scheduler_replicas_quiesced",
            )
            is True
            and quiescence_attestation.get(
                "preview_manifest_digest",
            )
            == preview_manifest_digest
            and (
                (
                    source_stream is None
                    and quiescence_attestation.get(
                        "source_stream_id",
                    )
                    is None
                )
                or (
                    source_stream is not None
                    and quiescence_attestation.get(
                        "source_stream_id",
                    )
                    == str(source_stream.id)
                    and quiescence_attestation.get(
                        "source_epoch_uuid",
                    )
                    == str(source_stream.current_epoch_uuid)
                    and quiescence_attestation.get(
                        "source_sealed_sequence",
                    )
                    == source_stream.sealed_sequence
                    and quiescence_attestation.get(
                        "source_final_snapshot_digest",
                    )
                    == source_stream.last_snapshot_digest
                )
            )
        )
        if not attested:
            return ExternalOwnerCutoverTransition(
                "attestation_required",
                None,
            )
        project = (
            await self.session.execute(
                select(Project).where(Project.id == project_id).with_for_update(),
            )
        ).scalar_one_or_none()
        if project is None:
            return ExternalOwnerCutoverTransition(
                "project_not_found",
                None,
            )
        if project.allowed_schedulers is not None and to_owner not in project.allowed_schedulers:
            return ExternalOwnerCutoverTransition(
                "target_owner_not_allowed",
                None,
            )
        for row in rows:
            # Both operator holds block the move, for the same reason from
            # opposite ends. A quarantine is a definition nobody has repaired,
            # and handing it to another scheduler hands over the unrepaired
            # definition. A hold is only meaningful while this brain owns the
            # cadence: the target adapter runs its own clock and has no
            # channel to be told to stop, so cutting over either releases the
            # hold silently or strands it, leaving a timestamp on a row that
            # can no longer be resumed because resuming is refused for a
            # foreign owner. Refusing until the operator resolves it is the
            # same answer the schema downgrade gives, and for the same reason.
            if operator_hold_in_force(row):
                return ExternalOwnerCutoverTransition(
                    "unresolved_schedule_state",
                    None,
                )
            if row.scheduler == "z4j-scheduler" and await self._control._legacy_grant_blockers(
                schedule_id=row.id,
            ):
                return ExternalOwnerCutoverTransition(
                    "unresolved_schedule_state",
                    None,
                )
        now = _utc(occurred_at)
        target_stream = await self.ensure_activation_epoch(
            project_id=project_id,
            owner=to_owner,
            source_scope=target_source_scope,
            occurred_at=now,
            adapter_instance_id=target_adapter_instance_id,
            executor_agent_id=target_executor_agent_id,
            executor_registry_owner_id=(target_executor_registry_owner_id),
            executor_session_generation=(target_executor_session_generation),
            executor_worker_id=target_executor_worker_id,
            activation_requirement=f"OWNER_CUTOVER:{operation_id}",
            replace_retired=target_existing is not None,
        )
        prepared: list[tuple[Schedule, dict[str, Any], int]] = []
        result_rows: list[dict[str, Any]] = []
        activation_rows: list[dict[str, Any]] = []
        for row in rows:
            if row.control_token is None or not row.schedule_revision:
                raise ScheduleExternalProtocolFaultError(
                    "cutover schedule lacks current D identity",
                )
            if row.total_runs < 0:
                return ExternalOwnerCutoverTransition(
                    "invalid_counter",
                    None,
                )
            last_run_at = (
                None
                if cursor_policy == "RESET_CURSOR"
                else (_utc(row.last_run_at) if row.last_run_at is not None else None)
            )
            if (
                last_run_at is not None
                and last_run_at > now + timedelta(minutes=5)
                and cursor_policy != "PRESERVE_FUTURE"
            ):
                return ExternalOwnerCutoverTransition(
                    "future_cursor_requires_policy",
                    None,
                )
            source_key = (
                str(row.external_source_key) if row.external_source_key is not None else str(row.id)
            )
            new_token = uuid.uuid4()
            new_revision = await self._control._allocate_revision()
            overrides: dict[str, Any] = {
                "scheduler": to_owner,
                "control_token": new_token,
                "legacy_fire_control_token": None,
                "schedule_revision": new_revision,
                "last_run_at": last_run_at,
                "next_run_at": None,
                "last_fire_id": None,
                "last_cadence_acceptance_control_token": None,
                "last_cadence_acceptance_fire_id": None,
                "last_cadence_acceptance_scheduled_for": None,
                "last_cadence_acceptance_revision": None,
                "cadence_semantics_version": (CADENCE_SEMANTICS_VERSION),
                "cadence_runtime_fingerprint": (cadence_runtime_fingerprint()),
                "quarantine_control_token": None,
                "quarantine_code": None,
                "quarantine_detail": None,
                "quarantined_at": None,
                "external_stream_id": target_stream.id,
                "external_epoch_uuid": (target_stream.current_epoch_uuid),
                "external_epoch_number": (target_stream.current_epoch_number),
                "external_source_key": source_key,
                "external_source_sequence": 0,
                "updated_at": now,
            }
            future = schedule_snapshot(
                row,
                overrides=overrides,
            )["schedule"]
            overrides["definition_digest"] = schedule_definition_digest(future)
            prepared.append((row, overrides, new_revision))
            activation_rows.append(
                _cutover_projection(
                    future,
                    source_key=source_key,
                ),
            )
            result_rows.append(
                {
                    "schedule_id": str(row.id),
                    "old_revision": int(row.schedule_revision),
                    "new_revision": new_revision,
                    "old_control_token": str(row.control_token),
                    "new_control_token": str(new_token),
                    "source_key": source_key,
                    "last_run_at": future["last_run_at"],
                    "next_run_at": None,
                    "total_runs": row.total_runs,
                },
            )
        activation_rows.sort(
            key=lambda item: str(item["source_key"]),
        )
        source_stream_manifest = (
            [
                {
                    "stream_id": str(source_stream.id),
                    "epoch_uuid": str(
                        source_stream.current_epoch_uuid,
                    ),
                    "epoch_number": (source_stream.current_epoch_number),
                    "sealed_sequence": (source_stream.sealed_sequence),
                    "final_snapshot_digest": (source_stream.last_snapshot_digest),
                },
            ]
            if source_stream is not None
            else []
        )
        result_manifest = {
            "format": "z4j-owner-cutover-result-v1",
            "operation_id": str(operation_id),
            "project_id": str(project_id),
            "from_owner": from_owner,
            "to_owner": to_owner,
            "retired_streams": source_stream_manifest,
            "target_stream": {
                "stream_id": str(target_stream.id),
                "epoch_uuid": str(
                    target_stream.current_epoch_uuid,
                ),
                "epoch_number": (target_stream.current_epoch_number),
                "phase": "ACTIVATING",
                "source_scope": target_source_scope,
            },
            "target_activation_schedules": activation_rows,
            "schedules": result_rows,
        }
        result_digest = hashlib.sha256(
            canonical_external_json(result_manifest),
        ).hexdigest()
        mutations = [
            {
                "schedule_id": str(row.id),
                "from_owner": from_owner,
                "to_owner": to_owner,
            }
            for row, _, _ in prepared
        ]
        authority_stream = source_stream or target_stream
        await arm_external_lifecycle_transition(
            self.session,
            transition="cutover",
            operation_id=operation_id,
            stream_id=authority_stream.id,
            epoch_uuid=authority_stream.current_epoch_uuid,
            epoch_number=authority_stream.current_epoch_number,
            accepted_sequence=(authority_stream.accepted_sequence),
            from_phase=(source_stream.phase if source_stream is not None else "ACTIVATING"),
            to_phase=("RETIRED" if source_stream is not None else "ACTIVATING"),
            sealed_sequence=(source_stream.sealed_sequence if source_stream is not None else None),
            last_snapshot_digest=(
                source_stream.last_snapshot_digest if source_stream is not None else None
            ),
            mutations=mutations,
            manifest_digest=preview_manifest_digest,
            project_id=project_id,
            from_owner=from_owner,
            to_owner=to_owner,
        )
        cutover = ScheduleOwnerCutover(
            id=operation_id,
            project_id=project_id,
            from_owner=from_owner,
            to_owner=to_owner,
            source_scope=source_scope,
            preview_manifest_digest=preview_manifest_digest,
            preview_manifest=preview.manifest,
            cursor_policy=cursor_policy,
            quiescence_attestation=quiescence_attestation,
            quiescence_attestation_digest=attestation_digest,
            source_stream_manifest=source_stream_manifest,
            target_stream_id=target_stream.id,
            result_manifest=result_manifest,
            result_manifest_digest=result_digest,
            completed_at=now,
            created_at=now,
        )
        self.session.add(cutover)
        await self.session.flush()
        for row, overrides, revision in prepared:
            await self._append_owner_cutover_envelope(
                row,
                revision=revision,
                overrides=overrides,
                occurred_at=now,
                operation_id=operation_id,
                cursor_policy=cursor_policy,
            )
            for field, value in overrides.items():
                setattr(row, field, value)
            await self.session.flush()
        if source_stream is not None:
            assert source_epoch is not None
            source_epoch.phase = "RETIRED"
            source_epoch.retired_at = now
            await self.session.flush()
            source_stream.phase = "RETIRED"
            source_stream.updated_at = now
            await self.session.flush()
            await assert_external_lifecycle_consumed(
                self.session,
            )
        else:
            await finish_external_target_cutover(
                self.session,
                stream_id=target_stream.id,
                epoch_uuid=target_stream.current_epoch_uuid,
                epoch_number=target_stream.current_epoch_number,
            )
        return ExternalOwnerCutoverTransition(
            "completed",
            cutover,
            tuple(row for row, _, _ in prepared),
        )

    async def _mark_control_protocol_fault(
        self,
        *,
        stream: ScheduleExternalStream,
        operation: ScheduleExternalControlOperation | None,
        sequence: int,
        payload_digest: str,
    ) -> ExternalProjectionTransition:
        """Make both the claimed operation and its stream non-accepting."""

        if operation is not None and operation.status in {
            "PENDING",
            "CLAIMED",
        }:
            await arm_external_control_transition(
                self.session,
                transition="ambiguity",
                operation_id=operation.id,
                stream_id=operation.stream_id,
                epoch_number=operation.epoch_number,
                reserved_sequence=operation.reserved_sequence,
                state_nonce=operation.state_nonce,
                dispatch_lease=operation.dispatch_lease,
                terminal_id=None,
            )
            operation.status = "AMBIGUOUS"
            operation.updated_at = datetime.now(UTC)
            await self.session.flush()
            await assert_external_control_consumed(self.session)
        return await self._mark_protocol_fault(
            stream=stream,
            sequence=sequence,
            payload_digest=payload_digest,
        )

    async def _lock_control_command(
        self,
        *,
        command_id: uuid.UUID,
        project_id: uuid.UUID | None = None,
    ) -> tuple[
        ScheduleExternalStream | None,
        ScheduleExternalControlOperation | None,
        Command | None,
    ]:
        """Lock one control in stream -> operation -> command order."""

        anchor = (
            await self.session.execute(
                select(
                    ScheduleExternalControlOperation.id,
                    ScheduleExternalControlOperation.stream_id,
                ).where(
                    ScheduleExternalControlOperation.command_id == command_id,
                ),
            )
        ).one_or_none()
        if anchor is None:
            return None, None, None
        operation_id, stream_id = anchor
        stream_query = select(ScheduleExternalStream).where(
            ScheduleExternalStream.id == stream_id,
        )
        if project_id is not None:
            stream_query = stream_query.where(
                ScheduleExternalStream.project_id == project_id,
            )
        stream = (
            await self.session.execute(
                stream_query.with_for_update(),
            )
        ).scalar_one_or_none()
        if stream is None:
            return None, None, None
        operation = (
            await self.session.execute(
                select(ScheduleExternalControlOperation)
                .where(
                    ScheduleExternalControlOperation.id == operation_id,
                    ScheduleExternalControlOperation.stream_id == stream.id,
                    ScheduleExternalControlOperation.command_id == command_id,
                )
                .with_for_update(),
            )
        ).scalar_one_or_none()
        if operation is None:
            return stream, None, None
        command = (
            await self.session.execute(
                select(Command)
                .where(
                    Command.id == command_id,
                    Command.action == "schedule.external.control",
                )
                .with_for_update(),
            )
        ).scalar_one_or_none()
        return stream, operation, command

    @staticmethod
    def _control_receipt_is_exact(
        *,
        stream: ScheduleExternalStream,
        operation: ScheduleExternalControlOperation,
        command: Command,
        project_id: uuid.UUID,
        agent_id: uuid.UUID,
        transport_kind: str | None,
        registry_owner_id: uuid.UUID | None,
        session_generation: str | None,
        delivery_claim_token: str | None,
    ) -> bool:
        try:
            claim_token = uuid.UUID(str(delivery_claim_token))
        except (TypeError, ValueError):
            return False
        return (
            transport_kind == "websocket"
            and registry_owner_id is not None
            and session_generation is not None
            and stream.project_id == project_id
            and stream.id == operation.stream_id
            and stream.current_epoch_uuid == operation.epoch_uuid
            and stream.current_epoch_number == operation.epoch_number
            and stream.executor_agent_id == agent_id
            and stream.executor_registry_owner_id == registry_owner_id
            and stream.executor_session_generation == session_generation
            and operation.agent_id == agent_id
            and operation.registry_owner_id == registry_owner_id
            and operation.session_generation == session_generation
            and operation.dispatch_lease == claim_token
            and command.project_id == project_id
            and command.agent_id == agent_id
            and command.delivery_transport_kind == "websocket"
            and command.delivery_registry_owner_id == registry_owner_id
            and command.delivery_session_generation == session_generation
            and command.delivery_claim_token == claim_token
        )

    async def acknowledge_control_delivery(
        self,
        *,
        command_id: uuid.UUID,
        project_id: uuid.UUID,
        agent_id: uuid.UUID,
        transport_kind: str | None,
        registry_owner_id: uuid.UUID | None,
        session_generation: str | None,
        delivery_claim_token: str | None,
        occurred_at: datetime,
    ) -> ExternalControlReceiptTransition:
        """Record an exact ACK without treating it as schedule authority."""

        stream, operation, command = await self._lock_control_command(
            command_id=command_id,
            project_id=project_id,
        )
        if stream is None or operation is None or command is None:
            return ExternalControlReceiptTransition(
                "not_found",
                stream,
                operation,
                command,
            )
        if not self._control_receipt_is_exact(
            stream=stream,
            operation=operation,
            command=command,
            project_id=project_id,
            agent_id=agent_id,
            transport_kind=transport_kind,
            registry_owner_id=registry_owner_id,
            session_generation=session_generation,
            delivery_claim_token=delivery_claim_token,
        ):
            return ExternalControlReceiptTransition(
                "authority_mismatch",
                stream,
                operation,
                command,
            )
        if command.agent_acknowledged_at is None:
            command.agent_acknowledged_at = _utc(occurred_at)
            await self.session.flush()
            return ExternalControlReceiptTransition(
                "acknowledged",
                stream,
                operation,
                command,
            )
        return ExternalControlReceiptTransition(
            "replay",
            stream,
            operation,
            command,
        )

    async def apply_control_result(  # noqa: PLR0911 - explicit protocol dispositions
        self,
        *,
        command_id: uuid.UUID,
        project_id: uuid.UUID,
        agent_id: uuid.UUID,
        status: str,
        result_payload: dict[str, Any] | None,
        error: str | None,
        transport_kind: str | None,
        registry_owner_id: uuid.UUID | None,
        session_generation: str | None,
        delivery_claim_token: str | None,
        occurred_at: datetime,
    ) -> ExternalControlReceiptTransition:
        """Apply one exact agent result; only projection may mutate truth.

        Agent results are limited to ``success`` and ``failed``. ``TIMEOUT`` is
        applied only by :meth:`expire_claimed_control` after the brain-owned
        deadline; accepting it from the wire would let an agent manufacture a
        timer outcome.
        """

        if status not in ("success", "failed"):
            return ExternalControlReceiptTransition(
                "invalid_status",
                None,
                None,
                None,
            )

        stream, operation, command = await self._lock_control_command(
            command_id=command_id,
            project_id=project_id,
        )
        if stream is None or operation is None or command is None:
            return ExternalControlReceiptTransition(
                "not_found",
                stream,
                operation,
                command,
            )
        if not self._control_receipt_is_exact(
            stream=stream,
            operation=operation,
            command=command,
            project_id=project_id,
            agent_id=agent_id,
            transport_kind=transport_kind,
            registry_owner_id=registry_owner_id,
            session_generation=session_generation,
            delivery_claim_token=delivery_claim_token,
        ):
            return ExternalControlReceiptTransition(
                "authority_mismatch",
                stream,
                operation,
                command,
            )
        if command.status not in {
            CommandStatus.DISPATCHED,
            CommandStatus.COMPLETED,
            CommandStatus.FAILED,
            CommandStatus.TIMEOUT,
        }:
            return ExternalControlReceiptTransition(
                "not_claimed",
                stream,
                operation,
                command,
            )
        if command.status in {
            CommandStatus.COMPLETED,
            CommandStatus.FAILED,
            CommandStatus.TIMEOUT,
        }:
            return ExternalControlReceiptTransition(
                "replay",
                stream,
                operation,
                command,
            )

        now = _utc(occurred_at)
        if status == "success":
            command.status = CommandStatus.COMPLETED
            command.result = result_payload
            command.error = None
            command.completed_at = now
            await self.session.flush()
            return ExternalControlReceiptTransition(
                "result_recorded",
                stream,
                operation,
                command,
            )

        if operation.status == "CLAIMED" and stream.phase in {
            "ACTIVATING",
            "ACTIVE",
            "DRAINING",
        }:
            await self._mark_control_protocol_fault(
                stream=stream,
                operation=operation,
                sequence=(operation.reserved_sequence or operation.expected_accepted_sequence + 1),
                payload_digest=operation.desired_projection_digest,
            )
        command.status = CommandStatus.FAILED
        command.result = result_payload
        command.error = (error or "external schedule control failed")[:1024]
        command.completed_at = now
        await self.session.flush()
        return ExternalControlReceiptTransition(
            "ambiguous",
            stream,
            operation,
            command,
        )

    async def list_expired_claimed_controls(
        self,
        *,
        now: datetime,
        limit: int = 200,
    ) -> list[uuid.UUID]:
        """Select claimed controls whose projection deadline elapsed."""

        result = await self.session.execute(
            select(Command.id)
            .join(
                ScheduleExternalControlOperation,
                ScheduleExternalControlOperation.command_id == Command.id,
            )
            .where(
                ScheduleExternalControlOperation.status == "CLAIMED",
                Command.action == "schedule.external.control",
                Command.timeout_at < _utc(now),
            )
            .order_by(
                ScheduleExternalControlOperation.stream_id.asc(),
                ScheduleExternalControlOperation.id.asc(),
            )
            .limit(max(1, min(limit, 1000))),
        )
        return list(result.scalars())

    async def expire_claimed_control(
        self,
        *,
        command_id: uuid.UUID,
        occurred_at: datetime,
    ) -> ExternalControlReceiptTransition:
        """Fail closed when a claimed control lacks its projection by deadline."""

        stream, operation, command = await self._lock_control_command(
            command_id=command_id,
        )
        if stream is None or operation is None or command is None:
            return ExternalControlReceiptTransition(
                "not_found",
                stream,
                operation,
                command,
            )
        now = _utc(occurred_at)
        if operation.status != "CLAIMED" or _utc(command.timeout_at) >= now:
            return ExternalControlReceiptTransition(
                "not_expired",
                stream,
                operation,
                command,
            )
        if stream.phase in {"ACTIVATING", "ACTIVE", "DRAINING"}:
            await self._mark_control_protocol_fault(
                stream=stream,
                operation=operation,
                sequence=(operation.reserved_sequence or operation.expected_accepted_sequence + 1),
                payload_digest=operation.desired_projection_digest,
            )
        elif operation.status == "CLAIMED":
            await arm_external_control_transition(
                self.session,
                transition="ambiguity",
                operation_id=operation.id,
                stream_id=operation.stream_id,
                epoch_number=operation.epoch_number,
                reserved_sequence=operation.reserved_sequence,
                state_nonce=operation.state_nonce,
                dispatch_lease=operation.dispatch_lease,
                terminal_id=None,
            )
            operation.status = "AMBIGUOUS"
            operation.updated_at = now
            await self.session.flush()
            await assert_external_control_consumed(self.session)
        if command.status == CommandStatus.DISPATCHED:
            command.status = CommandStatus.TIMEOUT
            command.error = "external schedule control projection timed out"
            command.completed_at = now
            await self.session.flush()
        return ExternalControlReceiptTransition(
            "ambiguous",
            stream,
            operation,
            command,
        )

    async def mark_claimed_controls_for_executor_loss(
        self,
        *,
        project_id: uuid.UUID,
        agent_id: uuid.UUID,
        registry_owner_id: uuid.UUID,
        session_generation: str,
        occurred_at: datetime,
    ) -> list[uuid.UUID]:
        """Fail closed every claim owned by one disconnected WS generation."""

        candidates = list(
            (
                await self.session.execute(
                    select(
                        ScheduleExternalControlOperation.command_id,
                    )
                    .join(
                        ScheduleExternalStream,
                        ScheduleExternalStream.id == ScheduleExternalControlOperation.stream_id,
                    )
                    .where(
                        ScheduleExternalStream.project_id == project_id,
                        ScheduleExternalControlOperation.status == "CLAIMED",
                        ScheduleExternalControlOperation.agent_id == agent_id,
                        ScheduleExternalControlOperation.registry_owner_id == registry_owner_id,
                        ScheduleExternalControlOperation.session_generation == session_generation,
                    )
                    .order_by(
                        ScheduleExternalControlOperation.stream_id.asc(),
                        ScheduleExternalControlOperation.id.asc(),
                    ),
                )
            ).scalars(),
        )
        changed: list[uuid.UUID] = []
        for command_id in candidates:
            if command_id is None:
                continue
            stream, operation, command = await self._lock_control_command(
                command_id=command_id,
                project_id=project_id,
            )
            if (
                stream is None
                or operation is None
                or command is None
                or operation.status != "CLAIMED"
                or operation.agent_id != agent_id
                or operation.registry_owner_id != registry_owner_id
                or operation.session_generation != session_generation
            ):
                continue
            if stream.phase in {"ACTIVATING", "ACTIVE", "DRAINING"}:
                await self._mark_control_protocol_fault(
                    stream=stream,
                    operation=operation,
                    sequence=(
                        operation.reserved_sequence or operation.expected_accepted_sequence + 1
                    ),
                    payload_digest=operation.desired_projection_digest,
                )
            else:
                await arm_external_control_transition(
                    self.session,
                    transition="ambiguity",
                    operation_id=operation.id,
                    stream_id=operation.stream_id,
                    epoch_number=operation.epoch_number,
                    reserved_sequence=operation.reserved_sequence,
                    state_nonce=operation.state_nonce,
                    dispatch_lease=operation.dispatch_lease,
                    terminal_id=None,
                )
                operation.status = "AMBIGUOUS"
                operation.updated_at = _utc(occurred_at)
                await self.session.flush()
                await assert_external_control_consumed(self.session)
            if command.status == CommandStatus.DISPATCHED:
                command.status = CommandStatus.FAILED
                command.error = "bound external control executor disconnected"
                command.completed_at = _utc(occurred_at)
                await self.session.flush()
            changed.append(operation.id)
        return changed

    async def plan_control_operation(  # noqa: PLR0911
        self,
        *,
        project_id: uuid.UUID,
        stream_id: uuid.UUID,
        schedule_id: uuid.UUID,
        enabled: bool,
        issued_by: uuid.UUID | None,
        source_ip: str | None,
        timeout_at: datetime,
    ) -> ExternalControlPlan:
        """Plan one WebSocket-only set-to-state operation without mutating truth."""

        stream = (
            await self.session.execute(
                select(ScheduleExternalStream)
                .where(
                    ScheduleExternalStream.id == stream_id,
                    ScheduleExternalStream.project_id == project_id,
                )
                .with_for_update(),
            )
        ).scalar_one_or_none()
        if stream is None:
            return ExternalControlPlan("stream_not_found", None, None)
        if (
            stream.phase != "ACTIVE"
            or not stream.authorized_adapter_instance_id
            or stream.executor_agent_id is None
            or stream.executor_registry_owner_id is None
            or not stream.executor_session_generation
        ):
            return ExternalControlPlan(
                "stream_not_executable",
                stream,
                None,
            )

        schedule = (
            await self.session.execute(
                select(Schedule)
                .where(
                    Schedule.id == schedule_id,
                    Schedule.project_id == project_id,
                    Schedule.external_stream_id == stream.id,
                    Schedule.external_epoch_uuid == stream.current_epoch_uuid,
                    Schedule.external_epoch_number == stream.current_epoch_number,
                )
                .with_for_update(),
            )
        ).scalar_one_or_none()
        if schedule is None:
            return ExternalControlPlan(
                "schedule_not_current",
                stream,
                None,
            )
        if (
            schedule.external_source_key is None
            or schedule.schedule_revision is None
            or schedule.control_token is None
            or schedule.external_source_sequence is None
        ):
            return ExternalControlPlan(
                "schedule_not_executable",
                stream,
                schedule,
            )

        existing = (
            await self.session.execute(
                select(ScheduleExternalControlOperation)
                .where(
                    ScheduleExternalControlOperation.stream_id == stream.id,
                    ScheduleExternalControlOperation.status.in_(
                        ("PENDING", "CLAIMED", "AMBIGUOUS"),
                    ),
                )
                .with_for_update(),
            )
        ).scalar_one_or_none()
        if existing is not None:
            disposition = (
                "idempotent_replay"
                if (
                    existing.schedule_id == schedule.id
                    and bool(
                        existing.desired_projection.get(
                            "is_enabled",
                        ),
                    )
                    is enabled
                )
                else "operation_conflict"
            )
            command = (
                await self.session.get(Command, existing.command_id)
                if existing.command_id is not None
                else None
            )
            return ExternalControlPlan(
                disposition,
                stream,
                schedule,
                existing,
                command,
            )
        if schedule.is_enabled is enabled:
            return ExternalControlPlan(
                "already_effective",
                stream,
                schedule,
            )

        prior_projection = _business_projection(schedule)
        desired_projection = dict(prior_projection)
        desired_projection["is_enabled"] = enabled
        prior_digest = hashlib.sha256(
            canonical_external_json(prior_projection),
        ).hexdigest()
        desired_digest = hashlib.sha256(
            canonical_external_json(desired_projection),
        ).hexdigest()
        request_key = (
            f"external-control:{stream.id}:"
            f"{stream.accepted_sequence}:{schedule.id}:"
            f"{'enabled' if enabled else 'disabled'}"
        )
        from z4j_brain.persistence.repositories.commands import (
            CommandRepository,
        )

        # The stream records which established generation used to own the
        # scheduler, but it is not itself revocation authority. Lock the live
        # agent only after the stream and schedule (the established lock order)
        # and immediately before command insertion. Otherwise a failed
        # best-effort socket kick could enqueue fresh control work for a
        # committed tombstone.
        executor = (
            await self.session.execute(
                select(Agent)
                .where(
                    Agent.id == stream.executor_agent_id,
                    Agent.project_id == project_id,
                    Agent.revoked_at.is_(None),
                )
                .with_for_update(),
            )
        ).scalar_one_or_none()
        if executor is None:
            return ExternalControlPlan(
                "stream_not_executable",
                stream,
                schedule,
            )

        operation_id = uuid.uuid4()
        payload = {
            "operation_id": str(operation_id),
            "scheduler": stream.owner,
            "schedule_id": schedule.external_source_key,
            "source_key": schedule.external_source_key,
            "z4j_schedule_id": str(schedule.id),
            "stream_id": str(stream.id),
            "epoch_uuid": str(stream.current_epoch_uuid),
            "epoch_number": stream.current_epoch_number,
            "adapter_instance_id": stream.authorized_adapter_instance_id,
            "expected_accepted_sequence": stream.accepted_sequence,
            "expected_projection_digest": prior_digest,
            "desired_projection": desired_projection,
            "desired_projection_digest": desired_digest,
            "registry_owner_id": str(stream.executor_registry_owner_id),
            "session_generation": stream.executor_session_generation,
        }
        command, created = await CommandRepository(self.session).insert(
            project_id=project_id,
            agent_id=stream.executor_agent_id,
            issued_by=issued_by,
            action="schedule.external.control",
            target_type="schedule",
            target_id=str(schedule.id),
            payload=payload,
            idempotency_key=request_key,
            timeout_at=_utc(timeout_at),
            source_ip=source_ip,
            enforce_payload_identity=True,
        )
        if not created:
            raise ScheduleExternalProtocolFaultError(
                "external control command identity collided",
            )
        operation = ScheduleExternalControlOperation(
            id=operation_id,
            request_idempotency_key=request_key,
            schedule_id=schedule.id,
            command_id=command.id,
            agent_id=stream.executor_agent_id,
            stream_id=stream.id,
            epoch_uuid=stream.current_epoch_uuid,
            epoch_number=stream.current_epoch_number,
            source_key=schedule.external_source_key,
            expected_accepted_sequence=stream.accepted_sequence,
            expected_schedule_revision=schedule.schedule_revision,
            expected_control_token=schedule.control_token,
            prior_projection=prior_projection,
            prior_projection_digest=prior_digest,
            desired_projection=desired_projection,
            desired_projection_digest=desired_digest,
            status="PENDING",
            adapter_instance_id=stream.authorized_adapter_instance_id,
            session_generation=stream.executor_session_generation,
            registry_owner_id=stream.executor_registry_owner_id,
            dispatch_lease=None,
            reserved_sequence=None,
            result_projection_id=None,
            state_nonce=uuid.uuid4(),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        await arm_external_control_transition(
            self.session,
            transition="insert",
            operation_id=operation.id,
            stream_id=operation.stream_id,
            epoch_number=operation.epoch_number,
            reserved_sequence=None,
            state_nonce=operation.state_nonce,
            dispatch_lease=None,
            terminal_id=command.id,
        )
        self.session.add(operation)
        await self.session.flush()
        await assert_external_control_consumed(self.session)
        return ExternalControlPlan(
            "planned",
            stream,
            schedule,
            operation,
            command,
        )

    async def get_control_operation_for_project(
        self,
        *,
        project_id: uuid.UUID,
        operation_id: uuid.UUID,
    ) -> ScheduleExternalControlOperation | None:
        """Return one operation only through its owning external stream."""

        return (
            await self.session.execute(
                select(ScheduleExternalControlOperation)
                .join(
                    ScheduleExternalStream,
                    ScheduleExternalStream.id == ScheduleExternalControlOperation.stream_id,
                )
                .where(
                    ScheduleExternalControlOperation.id == operation_id,
                    ScheduleExternalStream.project_id == project_id,
                ),
            )
        ).scalar_one_or_none()

    async def stage_snapshot_frame(  # noqa: PLR0911, PLR0912
        self,
        *,
        project_id: uuid.UUID,
        stream_id: uuid.UUID,
        epoch_uuid: uuid.UUID,
        epoch_number: int,
        sequence: int,
        owner: str,
        source_scope: str,
        adapter_instance_id: str,
        snapshot_id: uuid.UUID,
        frame_kind: str,
        frame_index: int,
        frame_count: int,
        row_count: int,
        snapshot_digest: str,
        frame_digest: str,
        stable_source: bool,
        schedules: list[dict[str, Any]],
        occurred_at: datetime,
    ) -> ExternalSnapshotFrameTransition:
        """Stage one immutable frame and atomically apply a complete snapshot."""

        canonical_frame = external_snapshot_frame_body(
            stream_id=str(stream_id),
            epoch_uuid=str(epoch_uuid),
            epoch_number=epoch_number,
            sequence=sequence,
            owner=owner,
            source_scope=source_scope,
            adapter_instance_id=adapter_instance_id,
            snapshot_id=str(snapshot_id),
            frame_kind=frame_kind,
            frame_index=frame_index,
            frame_count=frame_count,
            row_count=row_count,
            snapshot_digest=snapshot_digest,
            stable_source=stable_source,
            schedules=schedules,
        )
        if not hmac.compare_digest(
            external_snapshot_frame_digest(canonical_frame),
            frame_digest,
        ):
            raise ExternalScheduleProtocolError(
                "external snapshot frame digest mismatch",
            )

        stream = (
            await self.session.execute(
                select(ScheduleExternalStream)
                .where(ScheduleExternalStream.id == stream_id)
                .with_for_update(),
            )
        ).scalar_one_or_none()
        if stream is None or stream.project_id != project_id:
            return ExternalSnapshotFrameTransition("unknown_stream", stream)
        if (
            stream.owner != owner
            or stream.source_scope != source_scope
            or stream.current_epoch_uuid != epoch_uuid
            or stream.current_epoch_number != epoch_number
            or stream.authorized_adapter_instance_id != adapter_instance_id
        ):
            return ExternalSnapshotFrameTransition("stale_epoch", stream)
        if stream.phase not in {"ACTIVATING", "ACTIVE", "DRAINING"}:
            return ExternalSnapshotFrameTransition("epoch_not_accepting", stream)

        expected_sequence = int(stream.accepted_sequence) + 1
        if sequence < expected_sequence:
            accepted = (
                await self.session.execute(
                    select(ScheduleExternalProjection).where(
                        ScheduleExternalProjection.stream_id == stream_id,
                        ScheduleExternalProjection.epoch_uuid == epoch_uuid,
                        ScheduleExternalProjection.sequence == sequence,
                    ),
                )
            ).scalar_one_or_none()
            if (
                accepted is not None
                and accepted.kind == "snapshot"
                and hmac.compare_digest(
                    accepted.payload_digest,
                    snapshot_digest,
                )
            ):
                return ExternalSnapshotFrameTransition(
                    "exact_replay",
                    stream,
                    projection=accepted,
                )
            fault = await self._mark_protocol_fault(
                stream=stream,
                sequence=sequence,
                payload_digest=snapshot_digest,
            )
            return ExternalSnapshotFrameTransition(
                fault.disposition,
                fault.stream,
            )
        if sequence > expected_sequence:
            return ExternalSnapshotFrameTransition("sequence_gap", stream)
        if stream.phase == "ACTIVATING" and not stable_source:
            return ExternalSnapshotFrameTransition(
                "activation_requires_stable_snapshot",
                stream,
            )

        staged = list(
            (
                await self.session.execute(
                    select(ScheduleExternalSnapshotFrame)
                    .where(
                        ScheduleExternalSnapshotFrame.stream_id == stream_id,
                        ScheduleExternalSnapshotFrame.epoch_uuid == epoch_uuid,
                        ScheduleExternalSnapshotFrame.sequence == sequence,
                    )
                    .order_by(ScheduleExternalSnapshotFrame.frame_index),
                )
            ).scalars(),
        )
        for item in staged:
            if (
                item.snapshot_id != snapshot_id
                or item.frame_count != frame_count
                or item.row_count != row_count
                or item.snapshot_digest != snapshot_digest
                or item.owner != owner
                or item.source_scope != source_scope
                or item.adapter_instance_id != adapter_instance_id
                or item.stable_source is not stable_source
            ):
                fault = await self._mark_protocol_fault(
                    stream=stream,
                    sequence=sequence,
                    payload_digest=snapshot_digest,
                )
                return ExternalSnapshotFrameTransition(
                    fault.disposition,
                    fault.stream,
                )

        current = next(
            (item for item in staged if item.frame_index == frame_index),
            None,
        )
        if current is not None:
            if current.frame_kind != frame_kind or not hmac.compare_digest(
                current.frame_digest, frame_digest
            ):
                fault = await self._mark_protocol_fault(
                    stream=stream,
                    sequence=sequence,
                    payload_digest=snapshot_digest,
                )
                return ExternalSnapshotFrameTransition(
                    fault.disposition,
                    fault.stream,
                )
        else:
            await arm_external_snapshot_frame(
                self.session,
                stream_id=stream_id,
                epoch_uuid=epoch_uuid,
                epoch_number=epoch_number,
                sequence=sequence,
                frame_digest=frame_digest,
                snapshot_id=snapshot_id,
                frame_index=frame_index,
            )
            current = ScheduleExternalSnapshotFrame(
                project_id=project_id,
                stream_id=stream_id,
                epoch_uuid=epoch_uuid,
                epoch_number=epoch_number,
                sequence=sequence,
                snapshot_id=snapshot_id,
                frame_kind=frame_kind,
                frame_index=frame_index,
                frame_count=frame_count,
                row_count=row_count,
                owner=owner,
                source_scope=source_scope,
                adapter_instance_id=adapter_instance_id,
                snapshot_digest=snapshot_digest,
                frame_digest=frame_digest,
                stable_source=stable_source,
                schedules=canonical_frame["schedules"],
                received_at=_utc(occurred_at),
            )
            self.session.add(current)
            await self.session.flush()
            await assert_external_projection_consumed(self.session)
            staged.append(current)

        if frame_kind != "terminal":
            return ExternalSnapshotFrameTransition(
                "staged",
                stream,
                frame=current,
            )

        by_index = {item.frame_index: item for item in staged}
        expected_indices = set(range(frame_count + 1))
        if set(by_index) != expected_indices:
            return ExternalSnapshotFrameTransition(
                "snapshot_incomplete",
                stream,
                frame=current,
            )
        if by_index[frame_count].frame_kind != "terminal" or any(
            by_index[index].frame_kind != "rows" for index in range(frame_count)
        ):
            fault = await self._mark_protocol_fault(
                stream=stream,
                sequence=sequence,
                payload_digest=snapshot_digest,
            )
            return ExternalSnapshotFrameTransition(
                fault.disposition,
                fault.stream,
            )
        assembled_rows = [row for index in range(frame_count) for row in by_index[index].schedules]
        if len(assembled_rows) != row_count:
            fault = await self._mark_protocol_fault(
                stream=stream,
                sequence=sequence,
                payload_digest=snapshot_digest,
            )
            return ExternalSnapshotFrameTransition(
                fault.disposition,
                fault.stream,
            )
        projection_body = external_projection_body(
            stream_id=str(stream_id),
            epoch_uuid=str(epoch_uuid),
            epoch_number=epoch_number,
            sequence=sequence,
            kind="snapshot",
            owner=owner,
            source_scope=source_scope,
            adapter_instance_id=adapter_instance_id,
            schedules=assembled_rows,
            complete=True,
            stable_source=stable_source,
        )
        if not hmac.compare_digest(
            external_projection_digest(projection_body),
            snapshot_digest,
        ):
            fault = await self._mark_protocol_fault(
                stream=stream,
                sequence=sequence,
                payload_digest=snapshot_digest,
            )
            return ExternalSnapshotFrameTransition(
                fault.disposition,
                fault.stream,
            )
        applied = await self.apply_projection(
            project_id=project_id,
            stream_id=stream_id,
            epoch_uuid=epoch_uuid,
            epoch_number=epoch_number,
            sequence=sequence,
            kind="snapshot",
            owner=owner,
            source_scope=source_scope,
            adapter_instance_id=adapter_instance_id,
            schedules=assembled_rows,
            deleted_source_keys=[],
            complete=True,
            stable_source=stable_source,
            payload_digest=snapshot_digest,
            operation_id=None,
            occurred_at=occurred_at,
        )
        return ExternalSnapshotFrameTransition(
            applied.disposition,
            applied.stream,
            projection=applied.projection,
            frame=current,
            inserted=applied.inserted,
            updated=applied.updated,
            deleted=applied.deleted,
        )

    async def apply_projection(  # noqa: PLR0911, PLR0912, PLR0915
        self,
        *,
        project_id: uuid.UUID,
        stream_id: uuid.UUID,
        epoch_uuid: uuid.UUID,
        epoch_number: int,
        sequence: int,
        kind: str,
        owner: str,
        source_scope: str,
        adapter_instance_id: str,
        schedules: list[dict[str, Any]],
        deleted_source_keys: list[str] | None,
        complete: bool,
        stable_source: bool,
        payload_digest: str,
        operation_id: uuid.UUID | None,
        occurred_at: datetime,
    ) -> ExternalProjectionTransition:
        """Apply one exact next source observation in one transaction."""

        body = external_projection_body(
            stream_id=str(stream_id),
            epoch_uuid=str(epoch_uuid),
            epoch_number=epoch_number,
            sequence=sequence,
            kind=kind,
            owner=owner,
            source_scope=source_scope,
            adapter_instance_id=adapter_instance_id,
            schedules=schedules,
            deleted_source_keys=deleted_source_keys,
            complete=complete,
            stable_source=stable_source,
            operation_id=(str(operation_id) if operation_id is not None else None),
        )
        actual_digest = external_projection_digest(body)
        if (
            len(payload_digest) != 64
            or any(character not in "0123456789abcdef" for character in payload_digest)
            or not hmac.compare_digest(actual_digest, payload_digest)
        ):
            raise ExternalScheduleProtocolError(
                "external projection digest mismatch",
            )

        stream_result = await self.session.execute(
            select(ScheduleExternalStream)
            .where(
                ScheduleExternalStream.id == stream_id,
                ScheduleExternalStream.project_id == project_id,
                ScheduleExternalStream.owner == owner,
                ScheduleExternalStream.source_scope == source_scope,
            )
            .with_for_update(),
        )
        stream = stream_result.scalar_one_or_none()
        if stream is None:
            return ExternalProjectionTransition("stream_not_found", None)
        if stream.current_epoch_uuid != epoch_uuid or stream.current_epoch_number != epoch_number:
            return ExternalProjectionTransition("stale_epoch", stream)

        if sequence <= stream.accepted_sequence:
            replay_result = await self.session.execute(
                select(ScheduleExternalProjection).where(
                    ScheduleExternalProjection.stream_id == stream.id,
                    ScheduleExternalProjection.epoch_uuid == epoch_uuid,
                    ScheduleExternalProjection.sequence == sequence,
                ),
            )
            replay = replay_result.scalar_one_or_none()
            if (
                replay is not None
                and replay.payload_digest == payload_digest
                and replay.kind == kind
                and replay.operation_id == operation_id
            ):
                return ExternalProjectionTransition(
                    "exact_replay",
                    stream,
                    replay,
                )
            if replay is not None or sequence == stream.accepted_sequence:
                return await self._mark_protocol_fault(
                    stream=stream,
                    sequence=sequence,
                    payload_digest=payload_digest,
                )
            return ExternalProjectionTransition("stale_sequence", stream)
        if sequence != stream.accepted_sequence + 1:
            return ExternalProjectionTransition("sequence_gap", stream)

        control_operation: ScheduleExternalControlOperation | None = None
        if operation_id is not None:
            control_operation = (
                await self.session.execute(
                    select(ScheduleExternalControlOperation)
                    .where(
                        ScheduleExternalControlOperation.id == operation_id,
                        ScheduleExternalControlOperation.stream_id == stream.id,
                    )
                    .with_for_update(),
                )
            ).scalar_one_or_none()
            control_shape_valid = (
                kind == "control"
                and not complete
                and stable_source
                and len(body["schedules"]) == 1
                and not body["deleted_source_keys"]
            )
            operation_valid = (
                control_shape_valid
                and control_operation is not None
                and control_operation.status == "CLAIMED"
                and control_operation.epoch_uuid == epoch_uuid
                and control_operation.epoch_number == epoch_number
                and control_operation.expected_accepted_sequence == stream.accepted_sequence
                and control_operation.reserved_sequence == sequence
                and control_operation.adapter_instance_id == adapter_instance_id
                and control_operation.agent_id == stream.executor_agent_id
                and control_operation.registry_owner_id == stream.executor_registry_owner_id
                and control_operation.session_generation == stream.executor_session_generation
                and control_operation.dispatch_lease is not None
                and control_operation.source_key == body["schedules"][0]["source_key"]
                and external_control_result_matches_desired(
                    control_operation.desired_projection,
                    body["schedules"][0],
                )
                and hmac.compare_digest(
                    control_operation.desired_projection_digest,
                    hashlib.sha256(
                        canonical_external_json(
                            control_operation.desired_projection,
                        ),
                    ).hexdigest(),
                )
            )
            if not control_shape_valid or not operation_valid:
                return await self._mark_control_protocol_fault(
                    stream=stream,
                    operation=control_operation,
                    sequence=sequence,
                    payload_digest=payload_digest,
                )
        elif kind == "control":
            return await self._mark_control_protocol_fault(
                stream=stream,
                operation=None,
                sequence=sequence,
                payload_digest=payload_digest,
            )

        activating = stream.phase == "ACTIVATING"
        activation_cutover: ScheduleOwnerCutover | None = None
        if activating:
            if not (sequence == 1 and kind == "snapshot" and complete and stable_source):
                return ExternalProjectionTransition(
                    "activation_snapshot_required",
                    stream,
                )
            if stream.activation_requirement is not None:
                prefix = "OWNER_CUTOVER:"
                if not stream.activation_requirement.startswith(
                    prefix,
                ):
                    return ExternalProjectionTransition(
                        "upgrade_required",
                        stream,
                    )
                try:
                    cutover_id = uuid.UUID(
                        stream.activation_requirement[len(prefix) :],
                    )
                except ValueError:
                    return ExternalProjectionTransition(
                        "activation_manifest_mismatch",
                        stream,
                    )
                activation_cutover = (
                    await self.session.execute(
                        select(ScheduleOwnerCutover)
                        .where(
                            ScheduleOwnerCutover.id == cutover_id,
                            ScheduleOwnerCutover.target_stream_id == stream.id,
                            ScheduleOwnerCutover.to_owner == stream.owner,
                        )
                        .with_for_update(),
                    )
                ).scalar_one_or_none()
                expected_schedules = (
                    activation_cutover.result_manifest.get(
                        "target_activation_schedules",
                    )
                    if activation_cutover is not None
                    else None
                )
                if (
                    not isinstance(expected_schedules, list)
                    or body["deleted_source_keys"]
                    or not hmac.compare_digest(
                        canonical_external_json(
                            expected_schedules,
                        ),
                        canonical_external_json(
                            body["schedules"],
                        ),
                    )
                ):
                    return ExternalProjectionTransition(
                        "activation_manifest_mismatch",
                        stream,
                    )
            if stream.authorized_adapter_instance_id not in {
                None,
                adapter_instance_id,
            }:
                return ExternalProjectionTransition(
                    "adapter_mismatch",
                    stream,
                )
        elif stream.phase not in {"ACTIVE", "DRAINING"}:
            return ExternalProjectionTransition(
                "stream_not_accepting",
                stream,
            )
        elif stream.authorized_adapter_instance_id != adapter_instance_id:
            return ExternalProjectionTransition(
                "adapter_mismatch",
                stream,
            )

        epoch_result = await self.session.execute(
            select(ScheduleExternalStreamEpoch)
            .where(
                ScheduleExternalStreamEpoch.stream_id == stream.id,
                ScheduleExternalStreamEpoch.epoch_uuid == epoch_uuid,
                ScheduleExternalStreamEpoch.epoch_number == epoch_number,
            )
            .with_for_update(),
        )
        epoch = epoch_result.scalar_one_or_none()
        if epoch is None or epoch.phase != stream.phase:
            raise ScheduleExternalProtocolFaultError(
                "current external stream epoch history is inconsistent",
            )

        rows = list(
            (
                await self.session.execute(
                    select(Schedule)
                    .where(Schedule.external_stream_id == stream.id)
                    .order_by(Schedule.id)
                    .with_for_update(),
                )
            ).scalars(),
        )
        existing = {
            str(row.external_source_key): row for row in rows if row.external_source_key is not None
        }
        incoming = {str(item["source_key"]): item for item in body["schedules"]}
        delete_keys = set(body["deleted_source_keys"])
        if control_operation is not None:
            controlled_schedule = existing.get(
                control_operation.source_key,
            )
            current_projection = (
                _business_projection(controlled_schedule)
                if controlled_schedule is not None
                else None
            )
            current_projection_digest = (
                hashlib.sha256(
                    canonical_external_json(current_projection),
                ).hexdigest()
                if current_projection is not None
                else None
            )
            if (
                controlled_schedule is None
                or controlled_schedule.id != control_operation.schedule_id
                or controlled_schedule.schedule_revision
                != control_operation.expected_schedule_revision
                or controlled_schedule.control_token != control_operation.expected_control_token
                or current_projection != control_operation.prior_projection
                or current_projection_digest != control_operation.prior_projection_digest
            ):
                return await self._mark_control_protocol_fault(
                    stream=stream,
                    operation=control_operation,
                    sequence=sequence,
                    payload_digest=payload_digest,
                )
        if kind == "snapshot" and complete and stable_source:
            delete_keys.update(set(existing) - set(incoming))

        now = _utc(occurred_at)
        mutations: list[_Mutation] = []
        force_rotation = (activating and activation_cutover is None) or operation_id is not None
        for source_key, projected in incoming.items():
            row = existing.get(source_key)
            schedule_id = row.id if row is not None else uuid.uuid4()
            business_changed = row is None or _business_projection(row) != projected
            token = uuid.uuid4() if force_rotation or business_changed else row.control_token
            if token is None:
                raise ScheduleExternalProtocolFaultError(
                    "external schedule lacks a control token",
                )
            values = _schedule_values(
                projected,
                stream=stream,
                sequence=sequence,
                control_token=token,
                revision=None,
                now=now,
            )
            mutations.append(
                _Mutation(
                    operation="insert" if row is None else "update",
                    source_key=source_key,
                    schedule_id=schedule_id,
                    row=row,
                    values=values,
                    old_revision=int(row.schedule_revision or 0) if row is not None else 0,
                    old_token=row.control_token if row is not None else None,
                    new_token=token,
                ),
            )
        for source_key in sorted(delete_keys):
            row = existing.get(source_key)
            if row is None:
                continue
            mutations.append(
                _Mutation(
                    operation="delete",
                    source_key=source_key,
                    schedule_id=row.id,
                    row=row,
                    values=None,
                    old_revision=int(row.schedule_revision or 0),
                    old_token=row.control_token,
                    new_token=None,
                ),
            )
        mutations.sort(key=lambda item: str(item.schedule_id))

        for mutation in mutations:
            mutation.new_revision = await self._control._allocate_revision()
            if mutation.values is not None:
                mutation.values["schedule_revision"] = mutation.new_revision

        mutation_manifest = [
            {
                "operation": mutation.operation,
                "source_key": mutation.source_key,
                "schedule_id": str(mutation.schedule_id),
                "old_revision": mutation.old_revision,
                "new_revision": mutation.new_revision,
                "old_control_token": (
                    str(mutation.old_token) if mutation.old_token is not None else None
                ),
                "new_control_token": (
                    str(mutation.new_token) if mutation.new_token is not None else None
                ),
                "definition_digest": (
                    mutation.values["definition_digest"] if mutation.values is not None else None
                ),
            }
            for mutation in mutations
        ]
        mutation_digest = hashlib.sha256(
            canonical_external_json({"mutations": mutation_manifest}),
        ).hexdigest()
        await arm_external_projection(
            self.session,
            stream_id=stream.id,
            epoch_uuid=epoch_uuid,
            epoch_number=epoch_number,
            sequence=sequence,
            payload_digest=payload_digest,
            adapter_instance_id=adapter_instance_id,
            operation_id=operation_id,
            mutations=[
                {
                    "operation": mutation.operation,
                    "source_key": mutation.source_key,
                    "schedule_id": str(mutation.schedule_id),
                }
                for mutation in mutations
            ],
        )

        counts = {"insert": 0, "update": 0, "delete": 0}
        for mutation in mutations:
            self.session.add(
                ScheduleChangeLog(
                    revision=mutation.new_revision,
                    project_id=stream.project_id,
                    schedule_id=mutation.schedule_id,
                    schedule_owner=stream.owner,
                    change_kind="gap",
                    protocol_version=SCHEDULE_CHANGE_PROTOCOL_VERSION,
                    snapshot=null(),
                    occurred_at=now,
                ),
            )
            await self.session.flush()
            await arm_schedule_transition(
                self.session,
                operation=mutation.operation,
                schedule_id=mutation.schedule_id,
                old_revision=mutation.old_revision,
                new_revision=mutation.new_revision,
                change_kind="gap",
                old_token=mutation.old_token,
                new_token=mutation.new_token,
            )
            if mutation.operation == "insert":
                assert mutation.values is not None
                row = Schedule(
                    id=mutation.schedule_id,
                    created_at=now,
                    **mutation.values,
                )
                self.session.add(row)
            elif mutation.operation == "update":
                assert mutation.row is not None
                assert mutation.values is not None
                for field, value in mutation.values.items():
                    setattr(mutation.row, field, value)
            else:
                assert mutation.row is not None
                await self.session.delete(mutation.row)
            await self.session.flush()
            counts[mutation.operation] += 1

        projection = ScheduleExternalProjection(
            id=uuid.uuid4(),
            stream_id=stream.id,
            epoch_uuid=epoch_uuid,
            epoch_number=epoch_number,
            sequence=sequence,
            kind=kind,
            payload_digest=payload_digest,
            source_keys=sorted(set(incoming) | delete_keys),
            mutation_digest=mutation_digest,
            operation_id=operation_id,
            accepted_at=now,
        )
        self.session.add(projection)
        await self.session.flush()
        if control_operation is not None:
            await arm_external_control_transition(
                self.session,
                transition="apply",
                operation_id=control_operation.id,
                stream_id=control_operation.stream_id,
                epoch_number=control_operation.epoch_number,
                reserved_sequence=control_operation.reserved_sequence,
                state_nonce=control_operation.state_nonce,
                dispatch_lease=control_operation.dispatch_lease,
                terminal_id=projection.id,
            )
            control_operation.status = "APPLIED"
            control_operation.result_projection_id = projection.id
            control_operation.updated_at = now
            await self.session.flush()
            await assert_external_control_consumed(self.session)

        next_phase = "ACTIVE" if activating else stream.phase
        last_snapshot_digest = (
            payload_digest if kind == "snapshot" and complete else stream.last_snapshot_digest
        )
        epoch.accepted_sequence = sequence
        epoch.last_projection_digest = payload_digest
        epoch.last_snapshot_digest = last_snapshot_digest
        epoch.phase = next_phase
        epoch.authorized_adapter_instance_id = adapter_instance_id
        epoch.activation_requirement = None
        if activating:
            epoch.activated_at = now
        await self.session.flush()

        stream.accepted_sequence = sequence
        stream.last_projection_digest = payload_digest
        stream.last_snapshot_digest = last_snapshot_digest
        stream.phase = next_phase
        stream.authorized_adapter_instance_id = adapter_instance_id
        stream.activation_requirement = None
        stream.updated_at = now
        await self.session.flush()
        await assert_external_projection_consumed(self.session)
        return ExternalProjectionTransition(
            "applied",
            stream,
            projection,
            inserted=counts["insert"],
            updated=counts["update"],
            deleted=counts["delete"],
        )


__all__ = [
    "ExternalControlReceiptTransition",
    "ExternalLifecycleTransition",
    "ExternalProjectionTransition",
    "ScheduleExternalProtocolFaultError",
    "ScheduleExternalRepository",
]
