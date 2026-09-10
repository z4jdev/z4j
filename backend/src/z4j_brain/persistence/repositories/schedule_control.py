"""Single guarded write path for Boundary-D schedule control state."""

from __future__ import annotations

import hmac
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    delete,
    exists,
    null,
    or_,
    select,
    update,
)
from sqlalchemy import (
    inspect as sa_inspect,
)
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.domain.schedule_cadence import (
    CADENCE_SEMANTICS_VERSION,
    ScheduleCadenceError,
    cadence_runtime_fingerprint,
    canonical_next_run_at,
)
from z4j_brain.domain.schedule_definition import (
    CONTROL_FIELDS,
    schedule_definition_digest,
)
from z4j_brain.domain.schedule_fire_authority import (
    SCHEDULE_FIRE_PROTOCOL_MARKER,
    derive_execution_fire_id,
    derive_scheduler_fire_id,
    normalized_schedule_slot,
)
from z4j_brain.persistence.enums import (
    CommandStatus,
    ScheduleKind,
    TaskPriority,
)
from z4j_brain.persistence.models import (
    Command,
    PendingFire,
    Schedule,
    ScheduleChangeLog,
    ScheduleFire,
    ScheduleOccurrenceResolution,
    ScheduleRevisionState,
    ScheduleTerminalHold,
)
from z4j_brain.persistence.models.schedule_control import (
    SCHEDULE_CHANGE_PROTOCOL_VERSION,
    SCHEDULE_REVISION_SINGLETON_ID,
)
from z4j_brain.persistence.schedule_guard import (
    arm_change_log_prune,
    arm_evidence_delete,
    arm_evidence_transition,
    arm_revision_allocation,
    arm_schedule_transition,
    assert_change_log_prune_consumed,
    assert_evidence_delete_consumed,
    assert_evidence_transition_consumed,
    assert_revision_allocation_consumed,
)

if TYPE_CHECKING:
    from z4j_brain.persistence.repositories.schedule_runtime_rollback import (
        RuntimeRollbackPlan,
        RuntimeRollbackPreparation,
    )


_MANAGEMENT_FIELDS = frozenset(
    {
        "name",
        "source",
        "source_hash",
        "external_id",
    },
)
_CADENCE_FIELDS = frozenset({"kind", "expression", "timezone", "catch_up"})
_ALLOWED_UPDATE_FIELDS = frozenset(CONTROL_FIELDS) | _MANAGEMENT_FIELDS
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_MAX_CURSOR_FUTURE_SKEW = timedelta(minutes=5)


def schedule_is_quarantined(row: Schedule) -> bool:
    """Is this row's own definition under an unresolved quarantine?

    The control token is required to be present because a legacy row carries
    neither token, and two absent tokens are not a quarantine.
    """
    return row.control_token is not None and row.quarantine_control_token == row.control_token


def operator_hold_in_force(row: Schedule) -> bool:
    """Is a stop in force that only an operator can lift?

    - quarantine token matching the control token: the definition is under
      quarantine and must not run until an operator repairs it.
    - ``paused_at`` set: held during an incident, and resumable only while
      this brain owns the cadence.

    One predicate rather than two lists, because a hold has to be honoured by
    every path that decides whether this schedule may run *and* by every path
    that hands it to somebody else. Keeping those enumerated separately is how
    a hold came to be refused at fire time and silently released by an
    ownership cutover.

    ``is_enabled`` is deliberately not one of them. A retired schedule is a
    definition an adapter is meant to carry across, not an unresolved state an
    operator has to clear first.
    """
    return schedule_is_quarantined(row) or row.paused_at is not None


def _effectively_enabled(row: Schedule) -> bool:
    """May this schedule fire or advance its cursor right now?

    Retirement and the operator holds are refused identically so a new fire
    path cannot check one and forget the other. That is exactly what happened
    to ``paused_at``: every acceptance site checked ``is_enabled`` and
    quarantine, a hold was recorded and reported to the operator, and the
    schedule kept firing on every path.
    """
    return row.is_enabled and not operator_hold_in_force(row)


def _not_enabled_reason(row: Schedule) -> str:
    """Say WHICH of the three stops is in force, for the refusal message.

    The current protocol refuses a hold by raising
    ``ScheduleControlConflictError``, and the gRPC handler turns any of those
    into ``error_code="fire_conflict"`` carrying this text. The schedule row is
    not in scope in that handler, so a reason not carried in the message is not
    carried at all: an operator whose paused schedule stopped running was told
    only that acceptance "requires an effectively enabled schedule", which is
    true of all three states and useful for none.

    A previous attempt at this added the three states to the current path's
    refusal mapper. That mapper's only caller receives its transition from
    ``accept_current_fire_progress``, which never returns them, so the entries
    were unreachable. This is where the distinction is actually available.
    """
    if row.paused_at is not None:
        return (
            "fire acceptance requires an effectively enabled schedule: "
            "the schedule is paused; resume it to let it fire"
        )
    if row.quarantine_control_token is not None and (
        row.quarantine_control_token == row.control_token
    ):
        return (
            "fire acceptance requires an effectively enabled schedule: "
            "the schedule is quarantined; an operator must repair the "
            "definition before it can fire"
        )
    return "fire acceptance requires an effectively enabled schedule: the schedule is disabled"


class ScheduleControlStateUnavailableError(RuntimeError):
    """The authenticated D revision singleton is absent or malformed."""


class ScheduleControlConflictError(ValueError):
    """A caller's observed schedule authority no longer matches."""


@dataclass(frozen=True, slots=True)
class CursorTransition:
    disposition: str
    schedule: Schedule | None
    committed_revision: int | None = None


@dataclass(frozen=True, slots=True)
class QuarantineTransition:
    outcome: str
    schedule: Schedule | None


@dataclass(frozen=True, slots=True)
class PauseTransition:
    """Outcome of a pause or resume.

    ``outcome`` is one of ``applied``, ``already_applied``, ``not_found``, or
    ``foreign_owner``. The last one exists because a hold is only meaningful
    for a schedule this brain fires: see :meth:`ScheduleControlRepository.
    set_paused`.
    """

    outcome: str
    schedule: Schedule | None


@dataclass(frozen=True, slots=True)
class StableScheduleSnapshot:
    watermark: int
    rows: tuple[Schedule, ...]


@dataclass(frozen=True, slots=True)
class FireProgressTransition:
    disposition: str
    schedule: Schedule | None
    acceptance_revision: int | None = None
    execution_fire_id: uuid.UUID | None = None


@dataclass(frozen=True, slots=True)
class ScheduleDeleteTransition:
    """One observable schedule tombstone plus historical closures."""

    disposition: str
    schedule_id: uuid.UUID
    committed_revision: int | None = None
    evidence_closed: int = 0


@dataclass(frozen=True, slots=True)
class TerminalFireTransition:
    disposition: str
    schedule: Schedule | None
    command: Command | None
    hold: ScheduleTerminalHold | None = None
    committed_revision: int | None = None
    hold_created: bool = False
    command_transitioned: bool = False


@dataclass(frozen=True, slots=True)
class LegacyGrantTransition:
    disposition: str
    schedule: Schedule | None
    committed_revision: int | None = None
    blockers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class OccurrenceResolutionTransition:
    disposition: str
    schedule: Schedule | None
    command: Command | None
    hold: ScheduleTerminalHold | None = None
    resolution: ScheduleOccurrenceResolution | None = None
    committed_revision: int | None = None
    grant_carried: bool = False
    changed: bool = False


def _utc(value: datetime) -> datetime:
    return (value.replace(tzinfo=UTC) if value.tzinfo is None else value).astimezone(UTC)


def _same_time(left: datetime | None, right: datetime | None) -> bool:
    if left is None or right is None:
        return left is right
    return _utc(left) == _utc(right)


def _is_current_cadence_candidate(command: Command | None) -> bool:
    return (
        command is not None
        and command.action == "schedule.fire"
        and command.schedule_protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER
        and command.schedule_id is not None
    )


def _complete_current_delivery_command(command: Command) -> bool:
    return (
        _is_current_cadence_candidate(command)
        and command.schedule_state_nonce is not None
        and command.schedule_fire_id is not None
        and command.schedule_scheduled_for is not None
        and command.schedule_receipt_control_token is not None
        and command.schedule_execution_fire_id is not None
        and command.schedule_acceptance_revision is not None
        and command.schedule_definition_digest is not None
        and command.schedule_expected_revision is not None
        and command.schedule_expected_next_run_at is not None
        and command.cadence_initial_claim_deadline is not None
        and command.first_delivery_claimed_at is not None
        and command.cadence_redelivery_deadline is not None
        and command.delivery_transport_kind is not None
        and command.delivery_registry_owner_id is not None
        and command.delivery_session_generation is not None
        and command.delivery_claim_token is not None
    )


def _delivery_receipt_is_authorized(
    command: Command,
    *,
    transport_kind: str | None,
    registry_owner_id: uuid.UUID | None,
    session_generation: str | None,
    delivery_claim_token: str | None,
) -> bool:
    stored_token = command.delivery_claim_token
    if stored_token is None:
        return False
    if delivery_claim_token is not None:
        return hmac.compare_digest(
            str(stored_token),
            delivery_claim_token,
        )
    return (
        transport_kind is not None
        and registry_owner_id is not None
        and session_generation is not None
        and command.delivery_transport_kind == transport_kind
        and command.delivery_registry_owner_id == registry_owner_id
        and hmac.compare_digest(
            command.delivery_session_generation or "",
            session_generation,
        )
    )


def _current_fire_matches_command(
    fire: ScheduleFire,
    command: Command,
) -> bool:
    return (
        fire.protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER
        and fire.state_write_nonce is not None
        and fire.command_id == command.id
        and fire.schedule_id == command.schedule_id
        and fire.project_id == command.project_id
        and fire.fire_id == command.schedule_fire_id
        and _same_time(fire.scheduled_for, command.schedule_scheduled_for)
        and fire.observed_control_token == command.schedule_observed_control_token
        and fire.receipt_control_token == command.schedule_receipt_control_token
        and fire.acceptance_revision == command.schedule_acceptance_revision
        and fire.definition_digest == command.schedule_definition_digest
        and fire.expected_schedule_revision == command.schedule_expected_revision
        and _same_time(
            fire.expected_last_run_at,
            command.schedule_expected_last_run_at,
        )
        and _same_time(
            fire.expected_next_run_at,
            command.schedule_expected_next_run_at,
        )
        and _same_time(
            fire.prepared_next_run_at,
            command.schedule_next_run_at,
        )
    )


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return _utc(value).isoformat(timespec="microseconds")
    if isinstance(value, uuid.UUID):
        return str(value)
    if hasattr(value, "value"):
        return value.value
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _pending_value(schedule: Schedule, name: str) -> Any:
    """Read one column as it will be persisted, not as the row holds it now.

    A create builds its envelope from a row that has not been flushed yet, so
    a column it leaves to the model default still reads as ``None``. Logging
    that would put a NULL in the immutable evidence for a row the database
    then stores with its default: an envelope that disagrees with the row it
    claims to describe. Only scalar defaults are substituted, and every column
    that has one is NOT NULL, so this can never overwrite a real NULL.
    """

    value = getattr(schedule, name)
    if value is not None:
        return value
    default = Schedule.__table__.c[name].default
    return default.arg if default is not None and default.is_scalar else None


#: Every mapped column, taken from the model rather than restated here. The
#: envelope is the whole of what a watching scheduler learns about the row, so
#: a column this list forgets is a column the scheduler decides without. That
#: is what happened to ``paused_at``: the hold reached the row, never reached
#: the envelope, and every scheduler that learns state by watching kept
#: ticking a held schedule.
_SNAPSHOT_FIELDS: tuple[str, ...] = tuple(
    attribute.key for attribute in sa_inspect(Schedule).mapper.column_attrs
)


def schedule_snapshot(
    schedule: Schedule,
    *,
    overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the complete canonical V2 row payload stored in the log."""

    override = overrides or {}

    def read(name: str) -> Any:
        return override[name] if name in override else _pending_value(schedule, name)

    return {
        "format": "z4j-schedule-snapshot-v1",
        "schedule": {field: _json_value(read(field)) for field in _SNAPSHOT_FIELDS},
    }


def _planner_anchor_transition_descriptor(
    schedule: Schedule,
    *,
    revision: int,
    overrides: dict[str, Any],
    anchor_reason: str,
) -> dict[str, Any]:
    """Bind a cadence-planning anchor to its complete Boundary-D snapshot."""

    before = schedule_snapshot(schedule)["schedule"]
    after = schedule_snapshot(schedule, overrides=overrides)["schedule"]
    if anchor_reason == "create":
        changed_fields = sorted(after)
    else:
        changed_fields = sorted(name for name, value in after.items() if before.get(name) != value)
    cadence_fields = (
        "kind",
        "expression",
        "timezone",
        "catch_up",
        "is_enabled",
        "last_run_at",
        "next_run_at",
        "cadence_semantics_version",
        "cadence_runtime_fingerprint",
        "definition_digest",
    )
    return {
        "kind": "planner_anchor",
        "planner_anchor": True,
        "anchor_reason": anchor_reason,
        "changed_fields": changed_fields,
        "schedule_id": str(schedule.id),
        "revision": revision,
        "definition_digest": after["definition_digest"],
        "cadence_definition": {name: after[name] for name in cadence_fields},
    }


def _cursor_transition_descriptor(
    *,
    observed_control_token: uuid.UUID,
    definition_digest: str,
    expected_revision: int,
    expected_last_run_at: datetime | None,
    expected_next_run_at: datetime,
    skipped_through: datetime,
    prepared_next_run_at: datetime | None,
    cadence_semantics_version: int,
    cadence_fingerprint: str,
) -> dict[str, Any]:
    """Canonical immutable evidence for one zero-work cursor transition."""

    return {
        "kind": "skip_no_work",
        "observed_control_token": str(observed_control_token),
        "definition_digest": definition_digest,
        "expected_revision": expected_revision,
        "expected_last_run_at": _json_value(expected_last_run_at),
        "expected_next_run_at": _json_value(expected_next_run_at),
        "skipped_through": _json_value(skipped_through),
        "prepared_next_run_at": _json_value(prepared_next_run_at),
        "cadence_semantics_version": cadence_semantics_version,
        "cadence_runtime_fingerprint": cadence_fingerprint,
    }


def _fire_transition_descriptor(
    *,
    fire_id: uuid.UUID,
    scheduled_for: datetime,
    observed_control_token: uuid.UUID,
    definition_digest: str,
    expected_revision: int,
    expected_last_run_at: datetime | None,
    expected_next_run_at: datetime,
    prepared_next_run_at: datetime | None,
    cadence_semantics_version: int,
    cadence_fingerprint: str,
) -> dict[str, Any]:
    return {
        "kind": "accept_fire",
        "fire_id": str(fire_id),
        "scheduled_for": _json_value(scheduled_for),
        "observed_control_token": str(observed_control_token),
        "definition_digest": definition_digest,
        "expected_revision": expected_revision,
        "expected_last_run_at": _json_value(expected_last_run_at),
        "expected_next_run_at": _json_value(expected_next_run_at),
        "prepared_next_run_at": _json_value(prepared_next_run_at),
        "cadence_semantics_version": cadence_semantics_version,
        "cadence_runtime_fingerprint": cadence_fingerprint,
    }


def _legacy_fire_transition_descriptor(
    *,
    fire_id: uuid.UUID,
    scheduled_for: datetime,
    receipt_control_token: uuid.UUID,
    definition_digest: str,
    expected_revision: int,
    expected_last_run_at: datetime | None,
    expected_next_run_at: datetime,
    prepared_next_run_at: datetime | None,
) -> dict[str, Any]:
    return {
        "kind": "accept_legacy_fire",
        "fire_id": str(fire_id),
        "scheduled_for": _json_value(scheduled_for),
        "receipt_control_token": str(receipt_control_token),
        "definition_digest": definition_digest,
        "expected_revision": expected_revision,
        "expected_last_run_at": _json_value(expected_last_run_at),
        "expected_next_run_at": _json_value(expected_next_run_at),
        "prepared_next_run_at": _json_value(prepared_next_run_at),
        "cadence_semantics_version": CADENCE_SEMANTICS_VERSION,
        "cadence_runtime_fingerprint": cadence_runtime_fingerprint(),
    }


def _terminal_transition_descriptor(
    *,
    command: Command,
    terminal_status: str,
) -> dict[str, Any]:
    return {
        "kind": "terminal_fire",
        "command_id": str(command.id),
        "fire_id": str(command.schedule_fire_id),
        "scheduled_for": _json_value(command.schedule_scheduled_for),
        "observed_control_token": str(
            command.schedule_observed_control_token,
        ),
        "receipt_control_token": str(
            command.schedule_receipt_control_token,
        ),
        "acceptance_revision": command.schedule_acceptance_revision,
        "terminal_status": terminal_status,
    }


def _legacy_grant_transition_descriptor(
    *,
    observed_control_token: uuid.UUID,
    granted_control_token: uuid.UUID | None,
    attestation_version: int,
) -> dict[str, Any]:
    return {
        "kind": "legacy_fire_grant",
        "observed_control_token": str(observed_control_token),
        "granted_control_token": (
            str(granted_control_token) if granted_control_token is not None else None
        ),
        "attestation_version": attestation_version,
    }


def _definition_quarantine_transition_descriptor(
    *,
    observed_control_token: uuid.UUID,
    reason_code: str,
) -> dict[str, Any]:
    return {
        "kind": "definition_quarantine",
        "observed_control_token": str(observed_control_token),
        "reason_code": reason_code,
    }


def _occurrence_resolution_transition_descriptor(
    *,
    command: Command,
    observed_control_token: uuid.UUID,
    new_control_token: uuid.UUID,
    resolution_evidence_id: uuid.UUID,
    enabled_after_resolution: bool,
    grant_carried: bool,
) -> dict[str, Any]:
    return {
        "kind": "resolve_occurrence",
        "command_id": str(command.id),
        "fire_id": str(command.schedule_fire_id),
        "scheduled_for": _json_value(command.schedule_scheduled_for),
        "command_status": command.status.value,
        "command_state_nonce": (
            str(command.schedule_state_nonce) if command.schedule_state_nonce is not None else None
        ),
        "observed_control_token": str(observed_control_token),
        "receipt_control_token": (
            str(command.schedule_receipt_control_token)
            if command.schedule_receipt_control_token is not None
            else None
        ),
        "new_control_token": str(new_control_token),
        "resolution_evidence_id": str(resolution_evidence_id),
        "resolution_disposition": "OPERATOR_SKIPPED",
        "enabled_after_resolution": enabled_after_resolution,
        "grant_carried": grant_carried,
    }


def _legacy_evidence_resolution_transition_descriptor(
    *,
    evidence_kind: str,
    evidence_id: uuid.UUID,
    fire_id: uuid.UUID,
    scheduled_for: datetime,
    observed_control_token: uuid.UUID,
    new_control_token: uuid.UUID,
    enabled_after_resolution: bool,
) -> dict[str, Any]:
    return {
        "kind": "resolve_legacy_evidence",
        "source_evidence_kind": evidence_kind,
        "source_evidence_id": str(evidence_id),
        "fire_id": str(fire_id),
        "scheduled_for": _json_value(scheduled_for),
        "observed_control_token": str(observed_control_token),
        "new_control_token": str(new_control_token),
        "resolution_disposition": "OPERATOR_SKIPPED",
        "enabled_after_resolution": enabled_after_resolution,
    }


class ScheduleControlRepository:
    """Allocate one revision and envelope for every approved mutation."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def _flush_evidence_transition(
        self,
        *,
        table_name: str,
        operation: str,
        row_id: uuid.UUID,
        nonce: uuid.UUID,
        reason: str,
    ) -> None:
        guard_active = await arm_evidence_transition(
            self.session,
            table_name=table_name,
            operation=operation,
            row_id=row_id,
            nonce=nonce,
            reason=reason,
        )
        await self.session.flush()
        await assert_evidence_transition_consumed(
            self.session,
            active=guard_active,
        )

    async def control_is_active(self) -> bool:
        """Return false only for the deliberate pre-activation state.

        A present but malformed singleton is never interpreted as legacy mode:
        that would reopen all 1.7 writers exactly when a damaged D activation
        most needs to fail closed.
        """

        state = await self.session.get(
            ScheduleRevisionState,
            SCHEDULE_REVISION_SINGLETON_ID,
        )
        if state is None:
            return False
        if (
            state.current_revision < 0
            or state.change_log_pruned_through < 0
            or state.change_log_pruned_through > state.current_revision
        ):
            raise ScheduleControlStateUnavailableError(
                "schedule revision state is malformed",
            )
        return True

    async def begin_stable_read(self) -> None:
        """Pin subsequent reads to one database snapshot.

        PostgreSQL's default READ COMMITTED isolation gives each statement a
        new MVCC view, which can pair an old revision watermark with rows after
        a concurrent delete. SQLite fixes its read view on the first SELECT;
        requesting SERIALIZABLE before that SELECT makes this precondition
        explicit and prevents a caller from accidentally starting the session
        with an unrelated read.
        """

        if self.session.in_transaction():
            raise ScheduleControlStateUnavailableError(
                "stable schedule read must begin before any database operation",
            )
        dialect = self.session.get_bind().dialect.name
        isolation_level = "REPEATABLE READ" if dialect == "postgresql" else "SERIALIZABLE"
        await self.session.connection(
            execution_options={"isolation_level": isolation_level},
        )

    async def require_revision_state(self) -> ScheduleRevisionState:
        state = await self.session.get(
            ScheduleRevisionState,
            SCHEDULE_REVISION_SINGLETON_ID,
        )
        if (
            state is None
            or state.current_revision < 0
            or state.change_log_pruned_through < 0
            or state.change_log_pruned_through > state.current_revision
        ):
            raise ScheduleControlStateUnavailableError(
                "schedule revision state is missing or malformed",
            )
        return state

    async def stable_snapshot(
        self,
        *,
        project_id: uuid.UUID | None,
        allowed_project_ids: set[uuid.UUID] | None = None,
    ) -> StableScheduleSnapshot:
        """Read one watermark-bounded reserved-owner snapshot."""

        await self.begin_stable_read()
        state = await self.require_revision_state()
        watermark = int(state.current_revision)
        predicates = [
            Schedule.scheduler == "z4j-scheduler",
            Schedule.schedule_revision <= watermark,
        ]
        if project_id is not None:
            predicates.append(Schedule.project_id == project_id)
        elif allowed_project_ids is not None:
            predicates.append(Schedule.project_id.in_(allowed_project_ids))
        result = await self.session.execute(
            select(Schedule).where(*predicates).order_by(Schedule.id),
        )
        rows = tuple(result.scalars().all())
        for row in rows:
            if (
                row.control_token is None
                or not row.schedule_revision
                or not row.definition_digest
                or not row.cadence_semantics_version
                or not row.cadence_runtime_fingerprint
            ):
                raise ScheduleControlStateUnavailableError(
                    "reserved schedule lacks complete current identity",
                )
        return StableScheduleSnapshot(watermark=watermark, rows=rows)

    async def plan_runtime_rollback(
        self,
        *,
        lock_rows: bool = False,
    ) -> RuntimeRollbackPlan:
        """Preflight the sealed 1.8.2 compatibility target without writes."""

        from z4j_brain.persistence.repositories.schedule_runtime_rollback import (
            plan_runtime_rollback,
        )

        return await plan_runtime_rollback(self, lock_rows=lock_rows)

    async def prepare_runtime_rollback(
        self,
        *,
        target_release: str,
        target_image: str,
        operation_id: uuid.UUID,
        expected_row_set_digest: str,
        quiescence_challenge_sha256: str,
        target_durable_evidence_sha256: str,
        target_release_evidence_index: dict[str, Any],
        target_evidence_terminal_stage: str,
        occurred_at: datetime,
    ) -> RuntimeRollbackPreparation:
        """Normalize all reserved rows through ordinary Boundary-D revisions."""

        from z4j_brain.persistence.repositories.schedule_runtime_rollback import (
            prepare_runtime_rollback,
        )

        return await prepare_runtime_rollback(
            self,
            target_release=target_release,
            target_image=target_image,
            operation_id=operation_id,
            expected_row_set_digest=expected_row_set_digest,
            quiescence_challenge_sha256=quiescence_challenge_sha256,
            target_durable_evidence_sha256=target_durable_evidence_sha256,
            target_release_evidence_index=target_release_evidence_index,
            target_evidence_terminal_stage=target_evidence_terminal_stage,
            occurred_at=occurred_at,
        )

    async def prune_change_log(
        self,
        *,
        through_revision: int,
    ) -> int:
        """Atomically delete one complete prefix and retain its boundary."""

        if through_revision < 0:
            raise ValueError("schedule change-log prune boundary is negative")
        state_result = await self.session.execute(
            select(ScheduleRevisionState)
            .where(
                ScheduleRevisionState.singleton_id == SCHEDULE_REVISION_SINGLETON_ID,
            )
            .with_for_update(),
        )
        state = state_result.scalar_one_or_none()
        if (
            state is None
            or state.guard_version is None
            or state.current_revision < state.change_log_pruned_through
        ):
            raise ScheduleControlStateUnavailableError(
                "schedule revision state is missing or inactive",
            )
        old_boundary = int(state.change_log_pruned_through)
        new_boundary = min(
            int(through_revision),
            int(state.current_revision),
        )
        if new_boundary <= old_boundary:
            return 0

        rows_statement = (
            select(ScheduleChangeLog.revision)
            .where(ScheduleChangeLog.revision <= new_boundary)
            .order_by(ScheduleChangeLog.revision)
        )
        if self.session.get_bind().dialect.name == "postgresql":
            rows_statement = rows_statement.with_for_update()
        revisions = list(
            (await self.session.execute(rows_statement)).scalars(),
        )
        guard_active = await arm_change_log_prune(
            self.session,
            old_boundary=old_boundary,
            new_boundary=new_boundary,
            expected_count=len(revisions),
        )
        if not guard_active:
            raise ScheduleControlStateUnavailableError(
                "schedule change-log guard is not active",
            )
        deleted = await self.session.execute(
            delete(ScheduleChangeLog).where(
                ScheduleChangeLog.revision <= new_boundary,
            ),
        )
        if (deleted.rowcount or 0) != len(revisions):
            raise ScheduleControlStateUnavailableError(
                "schedule change-log prefix changed during prune",
            )
        advanced = await self.session.execute(
            update(ScheduleRevisionState)
            .where(
                ScheduleRevisionState.singleton_id == SCHEDULE_REVISION_SINGLETON_ID,
                ScheduleRevisionState.current_revision == state.current_revision,
                ScheduleRevisionState.change_log_pruned_through == old_boundary,
            )
            .values(change_log_pruned_through=new_boundary),
        )
        if (advanced.rowcount or 0) != 1:
            raise ScheduleControlStateUnavailableError(
                "schedule prune boundary did not advance exactly once",
            )
        await assert_change_log_prune_consumed(
            self.session,
            active=guard_active,
        )
        state.change_log_pruned_through = new_boundary
        return len(revisions)

    async def _allocate_revision(self) -> int:
        guard_active = await arm_revision_allocation(self.session)
        result = await self.session.execute(
            update(ScheduleRevisionState)
            .where(
                ScheduleRevisionState.singleton_id == SCHEDULE_REVISION_SINGLETON_ID,
                ScheduleRevisionState.current_revision
                >= ScheduleRevisionState.change_log_pruned_through,
            )
            .values(
                current_revision=ScheduleRevisionState.current_revision + 1,
            )
            .returning(ScheduleRevisionState.current_revision),
        )
        revision = result.scalar_one_or_none()
        if revision is None or revision <= 0:
            raise ScheduleControlStateUnavailableError(
                "schedule revision state is missing or malformed",
            )
        await assert_revision_allocation_consumed(
            self.session,
            active=guard_active,
        )
        return int(revision)

    async def _append_upsert(
        self,
        schedule: Schedule,
        *,
        revision: int,
        overrides: dict[str, Any],
        occurred_at: datetime,
        transition: dict[str, Any] | None = None,
    ) -> None:
        schedule_state = sa_inspect(schedule)
        operation = "insert" if schedule_state.transient else "update"
        old_revision = 0 if operation == "insert" else int(schedule.schedule_revision or 0)
        old_token = None if operation == "insert" else schedule.control_token
        new_token = overrides.get(
            "control_token",
            schedule.control_token,
        )
        snapshot = schedule_snapshot(schedule, overrides=overrides)
        if transition is not None:
            snapshot["transition"] = _json_value(transition)
        self.session.add(
            ScheduleChangeLog(
                revision=revision,
                project_id=schedule.project_id,
                schedule_id=schedule.id,
                schedule_owner=schedule.scheduler,
                change_kind="upsert",
                protocol_version=SCHEDULE_CHANGE_PROTOCOL_VERSION,
                snapshot=snapshot,
                occurred_at=occurred_at,
            ),
        )
        await self.session.flush()
        await arm_schedule_transition(
            self.session,
            operation=operation,
            schedule_id=schedule.id,
            old_revision=old_revision,
            new_revision=revision,
            change_kind="upsert",
            old_token=old_token,
            new_token=new_token,
        )

    async def create_current(
        self,
        *,
        project_id: uuid.UUID,
        data: dict[str, Any],
        planning_at: datetime,
    ) -> Schedule:
        """Create one fully planned current-protocol reserved-owner row."""

        planned_at = _utc(planning_at)
        scheduler = str(data.get("scheduler", "z4j-scheduler"))
        if scheduler != "z4j-scheduler":
            raise ValueError("current schedule creation requires reserved ownership")
        name = str(data.get("name", "")).strip()
        task_name = str(data.get("task_name", "")).strip()
        if not name or not task_name:
            raise ValueError("schedule name and task_name are required")
        kind = ScheduleKind(str(data.get("kind", "")))
        priority = TaskPriority(str(data.get("priority", TaskPriority.NORMAL.value)))
        row = Schedule(
            id=uuid.uuid4(),
            project_id=project_id,
            engine=str(data.get("engine", "celery")),
            scheduler=scheduler,
            name=name,
            task_name=task_name,
            kind=kind,
            expression=str(data.get("expression", "")),
            timezone=str(data.get("timezone", "UTC")) or "UTC",
            queue=data.get("queue"),
            priority=priority,
            args=data.get("args") or [],
            kwargs=data.get("kwargs") or {},
            is_enabled=bool(data.get("is_enabled", True)),
            last_run_at=None,
            next_run_at=None,
            total_runs=0,
            external_id=data.get("external_id"),
            catch_up=str(data.get("catch_up", "skip")),
            source=str(data.get("source", "dashboard")),
            source_hash=data.get("source_hash"),
            last_fire_id=None,
            control_token=uuid.uuid4(),
            legacy_fire_control_token=None,
            schedule_revision=None,
            definition_digest=None,
            cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
            cadence_runtime_fingerprint=cadence_runtime_fingerprint(),
            quarantine_control_token=None,
            quarantine_code=None,
            quarantine_detail=None,
            quarantined_at=None,
            created_at=planned_at,
            updated_at=planned_at,
        )
        if row.is_enabled:
            row.next_run_at = canonical_next_run_at(
                kind=kind.value,
                expression=row.expression,
                timezone=row.timezone,
                last_run_at=None,
                anchor_at=planned_at,
            )
            if row.next_run_at is None and kind not in {
                ScheduleKind.CLOCKED,
            }:
                raise ScheduleCadenceError(
                    "enabled repeating schedule has no canonical next cursor",
                )
        row.definition_digest = schedule_definition_digest(row)
        revision = await self._allocate_revision()
        row.schedule_revision = revision
        await self._append_upsert(
            row,
            revision=revision,
            overrides={},
            occurred_at=planned_at,
            transition=_planner_anchor_transition_descriptor(
                row,
                revision=revision,
                overrides={},
                anchor_reason="create",
            ),
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def update_current(  # noqa: PLR0912 - exhaustive control transition
        self,
        *,
        project_id: uuid.UUID,
        schedule_id: uuid.UUID,
        data: dict[str, Any],
        planning_at: datetime,
    ) -> Schedule | None:
        """Apply a guarded generic current-row update or an exact no-op."""

        result = await self.session.execute(
            select(Schedule)
            .where(
                Schedule.project_id == project_id,
                Schedule.id == schedule_id,
                Schedule.scheduler == "z4j-scheduler",
            )
            .with_for_update(),
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        if row.control_token is None or not row.schedule_revision:
            raise ScheduleControlStateUnavailableError(
                "reserved schedule lacks D identity",
            )
        if "project_id" in data or "id" in data:
            raise ValueError("schedule identity is immutable")
        if "scheduler" in data and data["scheduler"] != row.scheduler:
            raise ScheduleControlConflictError(
                "schedule ownership changes require the Promote cutover action",
            )

        changes: dict[str, Any] = {}
        for field in _ALLOWED_UPDATE_FIELDS:
            if field not in data:
                continue
            value = data[field]
            if field == "kind":
                value = ScheduleKind(str(value))
            elif field == "priority":
                value = TaskPriority(str(value))
            if getattr(row, field) != value:
                changes[field] = value
        if not changes:
            return row

        now = _utc(planning_at)
        control_changed = any(field in CONTROL_FIELDS for field in changes)
        cadence_changed = any(field in _CADENCE_FIELDS for field in changes)
        overrides = dict(changes)
        overrides["updated_at"] = now
        if control_changed:
            overrides.update(
                control_token=uuid.uuid4(),
                legacy_fire_control_token=None,
                quarantine_control_token=None,
                quarantine_code=None,
                quarantine_detail=None,
                quarantined_at=None,
            )
            future = schedule_snapshot(row, overrides=overrides)["schedule"]
            overrides["definition_digest"] = schedule_definition_digest(future)
        if cadence_changed or changes.get("is_enabled") is True:
            effective_kind = overrides.get("kind", row.kind)
            effective_expression = str(overrides.get("expression", row.expression))
            effective_timezone = str(overrides.get("timezone", row.timezone))
            enabled = bool(overrides.get("is_enabled", row.is_enabled))
            if enabled:
                next_run_at = canonical_next_run_at(
                    kind=(
                        effective_kind.value
                        if hasattr(effective_kind, "value")
                        else str(effective_kind)
                    ),
                    expression=effective_expression,
                    timezone=effective_timezone,
                    # SQLite drops timezone metadata on round-trip. Normalize
                    # the persistence value at the cadence-domain boundary,
                    # just as the external-schedule repository does.
                    last_run_at=(_utc(row.last_run_at) if row.last_run_at is not None else None),
                    anchor_at=now,
                )
                if next_run_at is None and effective_kind not in {
                    ScheduleKind.CLOCKED,
                    "clocked",
                    "one_shot",
                }:
                    raise ScheduleCadenceError(
                        "enabled repeating schedule has no canonical next cursor",
                    )
                overrides["next_run_at"] = next_run_at

        revision = await self._allocate_revision()
        overrides["schedule_revision"] = revision
        planner_anchor_reason = (
            "reenable" if changes.get("is_enabled") is True else "cadence_change"
        )
        transition = (
            _planner_anchor_transition_descriptor(
                row,
                revision=revision,
                overrides=overrides,
                anchor_reason=planner_anchor_reason,
            )
            if cadence_changed or changes.get("is_enabled") is True
            else None
        )
        await self._append_upsert(
            row,
            revision=revision,
            overrides=overrides,
            occurred_at=now,
            transition=transition,
        )
        for field, value in overrides.items():
            setattr(row, field, value)
        await self.session.flush()
        return row

    async def delete_current(  # noqa: PLR0912, PLR0915
        self,
        *,
        project_id: uuid.UUID,
        schedule_id: uuid.UUID,
        occurred_at: datetime,
    ) -> ScheduleDeleteTransition:
        """Delete one reserved schedule with a tombstone and truthful exits."""

        result = await self.session.execute(
            select(Schedule)
            .where(
                Schedule.project_id == project_id,
                Schedule.id == schedule_id,
                Schedule.scheduler == "z4j-scheduler",
            )
            .with_for_update(),
        )
        row = result.scalar_one_or_none()
        if row is None:
            return ScheduleDeleteTransition("not_found", schedule_id)
        if row.control_token is None or not row.schedule_revision:
            raise ScheduleControlStateUnavailableError(
                "reserved schedule lacks D identity",
            )

        pending_rows = list(
            (
                await self.session.execute(
                    select(PendingFire)
                    .where(PendingFire.schedule_id == schedule_id)
                    .order_by(PendingFire.id)
                    .with_for_update(),
                )
            ).scalars(),
        )
        fire_rows = list(
            (
                await self.session.execute(
                    select(ScheduleFire)
                    .where(ScheduleFire.schedule_id == schedule_id)
                    .order_by(
                        ScheduleFire.scheduled_for,
                        ScheduleFire.id,
                    )
                    .with_for_update(),
                )
            ).scalars(),
        )
        command_rows = list(
            (
                await self.session.execute(
                    select(Command)
                    .where(
                        Command.schedule_id == schedule_id,
                        Command.action == "schedule.fire",
                    )
                    .order_by(Command.id)
                    .with_for_update(),
                )
            ).scalars(),
        )
        hold_rows = list(
            (
                await self.session.execute(
                    select(ScheduleTerminalHold)
                    .where(
                        ScheduleTerminalHold.schedule_id == schedule_id,
                    )
                    .order_by(ScheduleTerminalHold.id)
                    .with_for_update(),
                )
            ).scalars(),
        )
        resolution_rows = list(
            (
                await self.session.execute(
                    select(ScheduleOccurrenceResolution)
                    .where(
                        ScheduleOccurrenceResolution.schedule_id == schedule_id,
                    )
                    .with_for_update(),
                )
            ).scalars(),
        )

        revision = await self._allocate_revision()
        now = _utc(occurred_at)
        self.session.add(
            ScheduleChangeLog(
                revision=revision,
                project_id=row.project_id,
                schedule_id=row.id,
                schedule_owner=row.scheduler,
                change_kind="delete",
                protocol_version=SCHEDULE_CHANGE_PROTOCOL_VERSION,
                snapshot=null(),
                occurred_at=now,
            ),
        )
        await self.session.flush()

        closed = 0
        for hold in hold_rows:
            if hold.resolved_at is not None:
                continue
            old_nonce = hold.state_write_nonce
            hold.resolved_at = now
            hold.resolved_by = None
            hold.resolution_disposition = "SCHEDULE_DELETED"
            hold.resolution_source = "SCHEDULE_DELETE"
            hold.work_may_have_executed = True
            hold.resolution_control_token = None
            hold.deletion_tombstone_revision = revision
            hold.state_write_nonce = uuid.uuid4()
            await self._flush_evidence_transition(
                table_name="schedule_terminal_holds",
                operation="update",
                row_id=hold.id,
                nonce=old_nonce,
                reason="schedule_delete",
            )
            closed += 1

        resolutions_by_source = {
            (resolution.source_evidence_kind, resolution.source_evidence_id): resolution
            for resolution in resolution_rows
        }
        pending_identity = {
            (
                pending.fire_id,
                _utc(pending.scheduled_for),
                pending.receipt_control_token,
            )
            for pending in pending_rows
        }
        for command in command_rows:
            needs_exit = command.schedule_receipt_control_token is None or (
                command.schedule_observed_control_token is None
                and command.status
                in {
                    CommandStatus.COMPLETED,
                    CommandStatus.FAILED,
                    CommandStatus.CANCELLED,
                    CommandStatus.TIMEOUT,
                }
            )
            if not needs_exit:
                continue
            existing = resolutions_by_source.get(
                ("COMMAND", command.id),
            )
            if existing is not None:
                continue
            if command.schedule_fire_id is None or command.schedule_scheduled_for is None:
                raise ScheduleControlStateUnavailableError(
                    "schedule deletion found incomplete legacy command evidence",
                )
            receipt = command.schedule_receipt_control_token
            resolution = ScheduleOccurrenceResolution(
                id=uuid.uuid4(),
                project_id=project_id,
                schedule_id=schedule_id,
                fire_id=command.schedule_fire_id,
                scheduled_for=command.schedule_scheduled_for,
                command_id=command.id,
                source_evidence_kind="COMMAND",
                source_evidence_id=command.id,
                authority_kind=("LEGACY_NULL" if receipt is None else "TOKEN"),
                observed_control_token=(command.schedule_observed_control_token),
                receipt_control_token=receipt,
                command_status=command.status.value,
                work_may_have_executed=(command.status != CommandStatus.PENDING),
                resolution_disposition="SCHEDULE_DELETED",
                resolved_at=now,
                resolved_by=None,
                resolution_source="SCHEDULE_DELETE",
                resolution_control_token=None,
                deletion_tombstone_revision=revision,
                state_write_nonce=uuid.uuid4(),
            )
            self.session.add(resolution)
            await self._flush_evidence_transition(
                table_name="schedule_occurrence_resolutions",
                operation="insert",
                row_id=resolution.id,
                nonce=resolution.state_write_nonce,
                reason="schedule_delete",
            )
            resolutions_by_source[("COMMAND", command.id)] = resolution
            closed += 1

        for pending in pending_rows:
            existing = resolutions_by_source.get(
                ("PENDING_FIRE", pending.id),
            )
            if existing is None:
                receipt = pending.receipt_control_token
                resolution = ScheduleOccurrenceResolution(
                    id=uuid.uuid4(),
                    project_id=project_id,
                    schedule_id=schedule_id,
                    fire_id=pending.fire_id,
                    scheduled_for=pending.scheduled_for,
                    command_id=None,
                    source_evidence_kind="PENDING_FIRE",
                    source_evidence_id=pending.id,
                    authority_kind=("LEGACY_NULL" if receipt is None else "TOKEN"),
                    observed_control_token=pending.observed_control_token,
                    receipt_control_token=receipt,
                    command_status="buffered",
                    work_may_have_executed=False,
                    resolution_disposition="SCHEDULE_DELETED",
                    resolved_at=now,
                    resolved_by=None,
                    resolution_source="SCHEDULE_DELETE",
                    resolution_control_token=None,
                    deletion_tombstone_revision=revision,
                    state_write_nonce=uuid.uuid4(),
                )
                self.session.add(resolution)
                await self._flush_evidence_transition(
                    table_name="schedule_occurrence_resolutions",
                    operation="insert",
                    row_id=resolution.id,
                    nonce=resolution.state_write_nonce,
                    reason="schedule_delete",
                )
                resolutions_by_source[("PENDING_FIRE", pending.id)] = resolution
                closed += 1

        for fire in fire_rows:
            if fire.command_id is not None:
                continue
            identity = (
                fire.fire_id,
                _utc(fire.scheduled_for),
                fire.receipt_control_token,
            )
            if identity in pending_identity:
                continue
            existing = resolutions_by_source.get(
                ("SCHEDULE_FIRE", fire.id),
            )
            if existing is not None:
                continue
            receipt = fire.receipt_control_token
            resolution = ScheduleOccurrenceResolution(
                id=uuid.uuid4(),
                project_id=project_id,
                schedule_id=schedule_id,
                fire_id=fire.fire_id,
                scheduled_for=fire.scheduled_for,
                command_id=None,
                source_evidence_kind="SCHEDULE_FIRE",
                source_evidence_id=fire.id,
                authority_kind=("LEGACY_NULL" if receipt is None else "TOKEN"),
                observed_control_token=fire.observed_control_token,
                receipt_control_token=receipt,
                command_status=fire.status,
                work_may_have_executed=(
                    fire.status
                    not in {
                        "pending",
                        "buffered",
                        "failed",
                        "buffer_expired",
                        "buffer_stale",
                    }
                ),
                resolution_disposition="SCHEDULE_DELETED",
                resolved_at=now,
                resolved_by=None,
                resolution_source="SCHEDULE_DELETE",
                resolution_control_token=None,
                deletion_tombstone_revision=revision,
                state_write_nonce=uuid.uuid4(),
            )
            self.session.add(resolution)
            await self._flush_evidence_transition(
                table_name="schedule_occurrence_resolutions",
                operation="insert",
                row_id=resolution.id,
                nonce=resolution.state_write_nonce,
                reason="schedule_delete",
            )
            resolutions_by_source[("SCHEDULE_FIRE", fire.id)] = resolution
            closed += 1

        await self.session.flush()
        for pending in pending_rows:
            if pending.state_write_nonce is None:
                raise ScheduleControlStateUnavailableError(
                    "schedule deletion found unmarked pending evidence",
                )
            guard_active = await arm_evidence_delete(
                self.session,
                table_name="pending_fires",
                row_id=pending.id,
                old_nonce=pending.state_write_nonce,
                reason="schedule_delete",
            )
            await self.session.delete(pending)
            await self.session.flush()
            await assert_evidence_delete_consumed(
                self.session,
                active=guard_active,
            )

        await arm_schedule_transition(
            self.session,
            operation="delete",
            schedule_id=row.id,
            old_revision=int(row.schedule_revision),
            new_revision=revision,
            change_kind="delete",
            old_token=row.control_token,
            new_token=None,
        )
        await self.session.delete(row)
        await self.session.flush()
        return ScheduleDeleteTransition(
            "deleted",
            schedule_id,
            revision,
            closed,
        )

    async def quarantine(
        self,
        *,
        project_id: uuid.UUID,
        schedule_id: uuid.UUID,
        observed_control_token: uuid.UUID,
        reason_code: str,
        detail: str,
        occurred_at: datetime,
    ) -> QuarantineTransition:
        result = await self.session.execute(
            select(Schedule)
            .where(
                Schedule.project_id == project_id,
                Schedule.id == schedule_id,
                Schedule.scheduler == "z4j-scheduler",
            )
            .with_for_update(),
        )
        row = result.scalar_one_or_none()
        if row is None:
            return QuarantineTransition("not_found", None)
        if row.control_token != observed_control_token:
            return QuarantineTransition("stale_control", row)
        code = reason_code.strip()
        if not code or len(code) > 64:
            raise ValueError("quarantine reason code must contain 1..64 characters")
        safe_detail = _CONTROL_CHARACTERS.sub("", detail).strip()[:500]
        if (
            row.quarantine_control_token == observed_control_token
            and row.quarantine_code == code
            and row.quarantine_detail == safe_detail
        ):
            return QuarantineTransition("already_applied", row)
        now = _utc(occurred_at)
        revision = await self._allocate_revision()
        overrides = {
            "is_enabled": False,
            "quarantine_control_token": observed_control_token,
            "quarantine_code": code,
            "quarantine_detail": safe_detail,
            "quarantined_at": now,
            "schedule_revision": revision,
            "updated_at": now,
        }
        await self._append_upsert(
            row,
            revision=revision,
            overrides=overrides,
            occurred_at=now,
            transition=_definition_quarantine_transition_descriptor(
                observed_control_token=observed_control_token,
                reason_code=code,
            ),
        )
        for field, value in overrides.items():
            setattr(row, field, value)
        await self.session.flush()
        return QuarantineTransition("applied", row)

    async def set_paused(
        self,
        *,
        project_id: uuid.UUID,
        schedule_id: uuid.UUID,
        paused: bool,
        occurred_at: datetime,
    ) -> PauseTransition:
        """Hold or release one schedule, as an authenticated D transition.

        Pausing is not disabling. Disabling retires a schedule and is
        propagated to the owning adapter; pausing holds it during an incident
        and keeps the timestamp saying how long the hold has run. Both are
        refused at fire time, and reported distinctly so an operator can tell
        which one is in force.

        The hold is only offered for schedules this brain fires. A schedule
        owned by celery-beat or any other external scheduler keeps its own
        cadence, and this brain has no channel to tell it to stop, so a hold
        recorded here would be a promise nothing keeps. Those return
        ``foreign_owner`` rather than a timestamp that means nothing.

        Every field written here goes through the same revision allocation and
        change-log envelope as any other schedule transition, because Boundary
        D refuses a direct write. ``control_token`` is deliberately not
        rotated: a hold does not change the definition, and the guard permits a
        same-token transition for exactly the fields that do not.
        """

        result = await self.session.execute(
            select(Schedule)
            .where(
                Schedule.project_id == project_id,
                Schedule.id == schedule_id,
            )
            .with_for_update(),
        )
        row = result.scalar_one_or_none()
        if row is None:
            return PauseTransition("not_found", None)
        if row.scheduler != "z4j-scheduler":
            return PauseTransition("foreign_owner", row)

        now = _utc(occurred_at)
        # Idempotent in both directions, so a retry never needs a guard, and a
        # second click during an incident does not erase how long the hold has
        # run.
        if paused and row.paused_at is not None:
            return PauseTransition("already_applied", row)
        if not paused and row.paused_at is None:
            return PauseTransition("already_applied", row)

        revision = await self._allocate_revision()
        overrides: dict[str, Any] = {
            "paused_at": now if paused else None,
            "schedule_revision": revision,
            "updated_at": now,
        }
        await self._append_upsert(
            row,
            revision=revision,
            overrides=overrides,
            occurred_at=now,
        )
        for field, value in overrides.items():
            setattr(row, field, value)
        await self.session.flush()
        return PauseTransition("applied", row)

    async def set_legacy_fire_grant(
        self,
        *,
        project_id: uuid.UUID,
        schedule_id: uuid.UUID,
        observed_control_token: uuid.UUID,
        allow: bool,
        all_replicas_quiesced_and_resynced: bool,
        occurred_at: datetime,
    ) -> LegacyGrantTransition:
        """Grant/revoke tokenless 1.7 cadence for one locked generation."""

        if allow and not all_replicas_quiesced_and_resynced:
            raise ValueError(
                "legacy cadence grant requires the all-replica quiesce/full-sync attestation",
            )
        result = await self.session.execute(
            select(Schedule)
            .where(
                Schedule.project_id == project_id,
                Schedule.id == schedule_id,
                Schedule.scheduler == "z4j-scheduler",
            )
            .with_for_update(),
        )
        row = result.scalar_one_or_none()
        if row is None:
            return LegacyGrantTransition("not_found", None)
        if row.control_token is None or not row.schedule_revision:
            raise ScheduleControlStateUnavailableError(
                "reserved schedule lacks D identity",
            )
        if row.control_token != observed_control_token:
            return LegacyGrantTransition("stale_control", row)

        blockers = await self._legacy_grant_blockers(schedule_id=row.id) if allow else ()
        if blockers:
            return LegacyGrantTransition(
                "blocked_unresolved_evidence",
                row,
                blockers=blockers,
            )

        desired = row.control_token if allow else None
        if row.legacy_fire_control_token == desired:
            return LegacyGrantTransition("already_applied", row)

        now = _utc(occurred_at)
        revision = await self._allocate_revision()
        overrides = {
            "legacy_fire_control_token": desired,
            "schedule_revision": revision,
            "updated_at": now,
        }
        await self._append_upsert(
            row,
            revision=revision,
            overrides=overrides,
            occurred_at=now,
            transition=_legacy_grant_transition_descriptor(
                observed_control_token=observed_control_token,
                granted_control_token=desired,
                attestation_version=1,
            ),
        )
        for field, value in overrides.items():
            setattr(row, field, value)
        await self.session.flush()
        return LegacyGrantTransition(
            "granted" if allow else "revoked",
            row,
            revision,
        )

    async def _legacy_grant_blockers(
        self,
        *,
        schedule_id: uuid.UUID,
    ) -> tuple[str, ...]:
        blockers: list[str] = []
        unresolved_hold = await self.session.scalar(
            select(
                exists().where(
                    ScheduleTerminalHold.schedule_id == schedule_id,
                    ScheduleTerminalHold.resolved_at.is_(None),
                ),
            ),
        )
        if unresolved_hold:
            blockers.append("terminal_hold")

        resolved_command = exists().where(
            ScheduleOccurrenceResolution.command_id == Command.id,
        )
        unresolved_command = await self.session.scalar(
            select(
                exists().where(
                    Command.schedule_id == schedule_id,
                    Command.action == "schedule.fire",
                    or_(
                        Command.schedule_receipt_control_token.is_(None),
                        (
                            Command.schedule_observed_control_token.is_(None)
                            & Command.status.in_(
                                (
                                    CommandStatus.COMPLETED,
                                    CommandStatus.FAILED,
                                    CommandStatus.CANCELLED,
                                    CommandStatus.TIMEOUT,
                                ),
                            )
                        ),
                    ),
                    ~resolved_command,
                ),
            ),
        )
        if unresolved_command:
            blockers.append("cadence_command")

        resolved_fire = exists().where(
            ScheduleOccurrenceResolution.schedule_id == ScheduleFire.schedule_id,
            ScheduleOccurrenceResolution.fire_id == ScheduleFire.fire_id,
            ScheduleOccurrenceResolution.scheduled_for == ScheduleFire.scheduled_for,
        )
        unresolved_fire = await self.session.scalar(
            select(
                exists().where(
                    ScheduleFire.schedule_id == schedule_id,
                    ScheduleFire.receipt_control_token.is_(None),
                    ~resolved_fire,
                ),
            ),
        )
        if unresolved_fire:
            blockers.append("receipt_null_fire")

        resolved_pending = exists().where(
            ScheduleOccurrenceResolution.source_evidence_kind == "PENDING_FIRE",
            ScheduleOccurrenceResolution.source_evidence_id == PendingFire.id,
        )
        unresolved_pending = await self.session.scalar(
            select(
                exists().where(
                    PendingFire.schedule_id == schedule_id,
                    PendingFire.receipt_control_token.is_(None),
                    ~resolved_pending,
                ),
            ),
        )
        if unresolved_pending:
            blockers.append("receipt_null_pending")
        return tuple(blockers)

    async def resolve_terminal_occurrence(  # noqa: PLR0911, PLR0912, PLR0915
        self,
        *,
        project_id: uuid.UUID,
        schedule_id: uuid.UUID,
        fire_id: uuid.UUID,
        command_id: uuid.UUID,
        expected_status: CommandStatus,
        observed_control_token: uuid.UUID,
        resolved_by: uuid.UUID,
        work_may_have_executed: bool,
        enabled_after_resolution: bool,
        occurred_at: datetime,
    ) -> OccurrenceResolutionTransition:
        """Skip one exact terminal/legacy occurrence and rotate authority."""

        if not work_may_have_executed:
            raise ValueError(
                "occurrence resolution requires explicit confirmation that work may have executed",
            )
        candidate = await self.session.get(Command, command_id)
        if (
            candidate is None
            or candidate.action != "schedule.fire"
            or candidate.schedule_id != schedule_id
            or candidate.project_id != project_id
            or candidate.schedule_fire_id != fire_id
            or candidate.schedule_scheduled_for is None
        ):
            return OccurrenceResolutionTransition(
                "not_found",
                None,
                candidate,
            )
        if candidate.status != expected_status:
            return OccurrenceResolutionTransition(
                "status_conflict",
                None,
                candidate,
            )

        existing_resolution = await self.session.scalar(
            select(ScheduleOccurrenceResolution).where(
                ScheduleOccurrenceResolution.command_id == command_id,
            ),
        )
        if existing_resolution is not None:
            if (
                existing_resolution.project_id != project_id
                or existing_resolution.schedule_id != schedule_id
                or existing_resolution.fire_id != fire_id
                or existing_resolution.command_status != expected_status.value
            ):
                raise ScheduleControlStateUnavailableError(
                    "occurrence resolution identity is divergent",
                )
            return OccurrenceResolutionTransition(
                (
                    "already_deleted"
                    if existing_resolution.resolution_disposition == "SCHEDULE_DELETED"
                    else "already_resolved"
                ),
                None,
                candidate,
                resolution=existing_resolution,
            )

        existing_hold = await self.session.scalar(
            select(ScheduleTerminalHold).where(
                ScheduleTerminalHold.command_id == command_id,
            ),
        )
        if existing_hold is not None and existing_hold.resolved_at is not None:
            if (
                existing_hold.project_id != project_id
                or existing_hold.schedule_id != schedule_id
                or existing_hold.fire_id != fire_id
                or existing_hold.terminal_status != expected_status.value
            ):
                raise ScheduleControlStateUnavailableError(
                    "terminal hold resolution identity is divergent",
                )
            return OccurrenceResolutionTransition(
                (
                    "already_deleted"
                    if existing_hold.resolution_disposition == "SCHEDULE_DELETED"
                    else "already_resolved"
                ),
                None,
                candidate,
                hold=existing_hold,
            )

        schedule_result = await self.session.execute(
            select(Schedule)
            .where(
                Schedule.id == schedule_id,
                Schedule.project_id == project_id,
                Schedule.scheduler == "z4j-scheduler",
            )
            .with_for_update(),
        )
        schedule = schedule_result.scalar_one_or_none()
        if schedule is None:
            return OccurrenceResolutionTransition(
                "schedule_not_found",
                None,
                candidate,
            )
        if schedule.control_token is None or not schedule.schedule_revision:
            raise ScheduleControlStateUnavailableError(
                "reserved schedule lacks D identity",
            )

        fire_predicates = [
            ScheduleFire.schedule_id == schedule_id,
            ScheduleFire.fire_id == fire_id,
            ScheduleFire.scheduled_for == candidate.schedule_scheduled_for,
        ]
        if candidate.schedule_receipt_control_token is None:
            fire_predicates.append(
                ScheduleFire.receipt_control_token.is_(None),
            )
        else:
            fire_predicates.append(
                ScheduleFire.receipt_control_token == candidate.schedule_receipt_control_token,
            )
        fire_result = await self.session.execute(
            select(ScheduleFire).where(*fire_predicates).with_for_update(),
        )
        fire = fire_result.scalar_one_or_none()

        command_result = await self.session.execute(
            select(Command).where(Command.id == command_id).with_for_update(),
        )
        command = command_result.scalar_one_or_none()
        if command is None:
            raise ScheduleControlStateUnavailableError(
                "cadence command disappeared after schedule/fire locks",
            )
        if (
            command.action != "schedule.fire"
            or command.project_id != project_id
            or command.schedule_id != schedule_id
            or command.schedule_fire_id != fire_id
            or command.schedule_scheduled_for is None
            or command.status != expected_status
        ):
            return OccurrenceResolutionTransition(
                "status_or_identity_conflict",
                schedule,
                command,
            )
        if fire is not None and (
            fire.command_id not in {None, command.id}
            or fire.project_id != command.project_id
            or fire.schedule_id != command.schedule_id
            or fire.fire_id != command.schedule_fire_id
            or not _same_time(
                fire.scheduled_for,
                command.schedule_scheduled_for,
            )
            or fire.observed_control_token != command.schedule_observed_control_token
            or fire.receipt_control_token != command.schedule_receipt_control_token
        ):
            raise ScheduleControlStateUnavailableError(
                "retained fire history diverges from occurrence evidence",
            )

        hold_result = await self.session.execute(
            select(ScheduleTerminalHold)
            .where(ScheduleTerminalHold.command_id == command_id)
            .with_for_update(),
        )
        hold = hold_result.scalar_one_or_none()
        resolution_result = await self.session.execute(
            select(ScheduleOccurrenceResolution)
            .where(
                ScheduleOccurrenceResolution.command_id == command_id,
            )
            .with_for_update(),
        )
        resolution = resolution_result.scalar_one_or_none()
        if resolution is not None:
            return OccurrenceResolutionTransition(
                (
                    "already_deleted"
                    if resolution.resolution_disposition == "SCHEDULE_DELETED"
                    else "already_resolved"
                ),
                schedule,
                command,
                resolution=resolution,
            )
        if hold is not None:
            if (
                hold.resolved_at is not None
                or hold.project_id != project_id
                or hold.schedule_id != schedule_id
                or hold.fire_id != fire_id
                or hold.command_id != command.id
                or hold.terminal_status != command.status.value
                or not _same_time(
                    hold.scheduled_for,
                    command.schedule_scheduled_for,
                )
                or hold.observed_control_token != command.schedule_observed_control_token
                or hold.receipt_control_token != command.schedule_receipt_control_token
            ):
                raise ScheduleControlStateUnavailableError(
                    "terminal hold identity is divergent",
                )
        else:
            legacy_null = (
                command.schedule_observed_control_token is None
                and command.schedule_receipt_control_token is None
            )
            granted_terminal = (
                command.schedule_observed_control_token is None
                and command.schedule_receipt_control_token is not None
                and command.status
                in {
                    CommandStatus.FAILED,
                    CommandStatus.CANCELLED,
                    CommandStatus.TIMEOUT,
                }
            )
            if not legacy_null and not granted_terminal:
                return OccurrenceResolutionTransition(
                    "hold_required",
                    schedule,
                    command,
                )

        if schedule.control_token != observed_control_token:
            return OccurrenceResolutionTransition(
                "stale_control",
                schedule,
                command,
                hold=hold,
            )
        old_token = schedule.control_token
        receipt = command.schedule_receipt_control_token
        grant_carried = (
            receipt is not None
            and receipt == old_token
            and schedule.legacy_fire_control_token == old_token
        )
        new_token = uuid.uuid4()
        slot = _utc(command.schedule_scheduled_for)
        advances_slot = receipt is None or receipt == old_token
        resolved_last = schedule.last_run_at
        resolved_next = schedule.next_run_at
        if advances_slot:
            if resolved_last is None or _utc(resolved_last) < slot:
                resolved_last = slot
            resolved_next = canonical_next_run_at(
                kind=schedule.kind.value,
                expression=schedule.expression,
                timezone=schedule.timezone,
                last_run_at=_utc(resolved_last),
                anchor_at=_utc(resolved_last),
            )

        now = _utc(occurred_at)
        if hold is not None:
            old_nonce = hold.state_write_nonce
            hold.resolved_at = now
            hold.resolved_by = resolved_by
            hold.resolution_disposition = "OPERATOR_SKIPPED"
            hold.resolution_source = "OPERATOR"
            hold.work_may_have_executed = True
            hold.resolution_control_token = new_token
            hold.deletion_tombstone_revision = None
            hold.state_write_nonce = uuid.uuid4()
            await self._flush_evidence_transition(
                table_name="schedule_terminal_holds",
                operation="update",
                row_id=hold.id,
                nonce=old_nonce,
                reason="operator_resolution",
            )
            resolution_evidence_id = hold.id
        else:
            authority_kind = "LEGACY_NULL" if receipt is None else "TOKEN"
            resolution = ScheduleOccurrenceResolution(
                id=uuid.uuid4(),
                project_id=project_id,
                schedule_id=schedule_id,
                fire_id=fire_id,
                scheduled_for=command.schedule_scheduled_for,
                command_id=command.id,
                source_evidence_kind="COMMAND",
                source_evidence_id=command.id,
                authority_kind=authority_kind,
                observed_control_token=(command.schedule_observed_control_token),
                receipt_control_token=receipt,
                command_status=command.status.value,
                work_may_have_executed=True,
                resolution_disposition="OPERATOR_SKIPPED",
                resolved_at=now,
                resolved_by=resolved_by,
                resolution_source="OPERATOR",
                resolution_control_token=new_token,
                deletion_tombstone_revision=None,
                state_write_nonce=uuid.uuid4(),
            )
            self.session.add(resolution)
            await self._flush_evidence_transition(
                table_name="schedule_occurrence_resolutions",
                operation="insert",
                row_id=resolution.id,
                nonce=resolution.state_write_nonce,
                reason="operator_resolution",
            )
            resolution_evidence_id = resolution.id

        # Current receipts retain their immutable terminal outcome. The hold
        # (or occurrence resolution) records the operator's decision separately;
        # only migrated receipt-NULL history permits an operator_skipped status.
        if fire is not None and fire.receipt_control_token is None:
            fire.status = "operator_skipped"
            fire.error_code = "operator_skipped"
            fire.error_message = (
                "operator confirmed this occurrence may have executed "
                "and advanced cadence without retry"
            )
            if fire.state_write_nonce is not None:
                fire.state_write_nonce = uuid.uuid4()

        revision = await self._allocate_revision()
        overrides = {
            "control_token": new_token,
            "legacy_fire_control_token": (new_token if grant_carried else None),
            "is_enabled": enabled_after_resolution,
            "last_run_at": resolved_last,
            "next_run_at": resolved_next,
            "quarantine_control_token": None,
            "quarantine_code": None,
            "quarantine_detail": None,
            "quarantined_at": None,
            "schedule_revision": revision,
            "updated_at": now,
        }
        await self._append_upsert(
            schedule,
            revision=revision,
            overrides=overrides,
            occurred_at=now,
            transition=_occurrence_resolution_transition_descriptor(
                command=command,
                observed_control_token=observed_control_token,
                new_control_token=new_token,
                resolution_evidence_id=resolution_evidence_id,
                enabled_after_resolution=enabled_after_resolution,
                grant_carried=grant_carried,
            ),
        )
        for field, value in overrides.items():
            setattr(schedule, field, value)
        await self.session.flush()
        return OccurrenceResolutionTransition(
            "resolved",
            schedule,
            command,
            hold=hold,
            resolution=resolution,
            committed_revision=revision,
            grant_carried=grant_carried,
            changed=True,
        )

    async def resolve_legacy_evidence(  # noqa: PLR0911, PLR0912, PLR0915
        self,
        *,
        project_id: uuid.UUID,
        schedule_id: uuid.UUID,
        fire_id: uuid.UUID,
        source_evidence_kind: str,
        source_evidence_id: uuid.UUID,
        observed_control_token: uuid.UUID,
        resolved_by: uuid.UUID,
        work_may_have_executed: bool,
        enabled_after_resolution: bool,
        occurred_at: datetime,
    ) -> OccurrenceResolutionTransition:
        """Resolve one exact receipt-NULL pending/fire evidence source."""

        if source_evidence_kind not in {
            "PENDING_FIRE",
            "SCHEDULE_FIRE",
        }:
            raise ValueError(
                "legacy evidence kind must be PENDING_FIRE or SCHEDULE_FIRE",
            )
        if not work_may_have_executed:
            raise ValueError(
                "legacy evidence resolution requires explicit confirmation "
                "that work may have executed",
            )
        existing = await self.session.scalar(
            select(ScheduleOccurrenceResolution).where(
                ScheduleOccurrenceResolution.source_evidence_kind == source_evidence_kind,
                ScheduleOccurrenceResolution.source_evidence_id == source_evidence_id,
            ),
        )
        if existing is not None:
            if (
                existing.project_id != project_id
                or existing.schedule_id != schedule_id
                or existing.fire_id != fire_id
            ):
                raise ScheduleControlStateUnavailableError(
                    "legacy evidence resolution identity is divergent",
                )
            return OccurrenceResolutionTransition(
                (
                    "already_deleted"
                    if existing.resolution_disposition == "SCHEDULE_DELETED"
                    else "already_resolved"
                ),
                None,
                None,
                resolution=existing,
            )

        candidate_pending: PendingFire | None = None
        candidate_fire: ScheduleFire | None = None
        if source_evidence_kind == "PENDING_FIRE":
            candidate_pending = await self.session.get(
                PendingFire,
                source_evidence_id,
            )
            if candidate_pending is None:
                return OccurrenceResolutionTransition(
                    "not_found",
                    None,
                    None,
                )
            candidate_schedule_id = candidate_pending.schedule_id
            candidate_project_id = candidate_pending.project_id
            candidate_fire_id = candidate_pending.fire_id
            candidate_slot = candidate_pending.scheduled_for
        else:
            candidate_fire = await self.session.get(
                ScheduleFire,
                source_evidence_id,
            )
            if candidate_fire is None:
                return OccurrenceResolutionTransition(
                    "not_found",
                    None,
                    None,
                )
            candidate_schedule_id = candidate_fire.schedule_id
            candidate_project_id = candidate_fire.project_id
            candidate_fire_id = candidate_fire.fire_id
            candidate_slot = candidate_fire.scheduled_for
        if (
            candidate_schedule_id != schedule_id
            or candidate_project_id != project_id
            or candidate_fire_id != fire_id
        ):
            return OccurrenceResolutionTransition(
                "identity_conflict",
                None,
                None,
            )

        existing_identity = await self.session.scalar(
            select(ScheduleOccurrenceResolution).where(
                ScheduleOccurrenceResolution.schedule_id == schedule_id,
                ScheduleOccurrenceResolution.fire_id == fire_id,
                ScheduleOccurrenceResolution.scheduled_for == candidate_slot,
                ScheduleOccurrenceResolution.authority_kind == "LEGACY_NULL",
                ScheduleOccurrenceResolution.command_id.is_(None),
            ),
        )
        if existing_identity is not None:
            return OccurrenceResolutionTransition(
                (
                    "already_deleted"
                    if existing_identity.resolution_disposition == "SCHEDULE_DELETED"
                    else "already_resolved"
                ),
                None,
                None,
                resolution=existing_identity,
            )

        schedule_result = await self.session.execute(
            select(Schedule)
            .where(
                Schedule.id == schedule_id,
                Schedule.project_id == project_id,
                Schedule.scheduler == "z4j-scheduler",
            )
            .with_for_update(),
        )
        schedule = schedule_result.scalar_one_or_none()
        if schedule is None:
            return OccurrenceResolutionTransition(
                "schedule_not_found",
                None,
                None,
            )
        if schedule.control_token is None or not schedule.schedule_revision:
            raise ScheduleControlStateUnavailableError(
                "reserved schedule lacks D identity",
            )

        pending: PendingFire | None = None
        fire: ScheduleFire | None = None
        if source_evidence_kind == "PENDING_FIRE":
            pending_result = await self.session.execute(
                select(PendingFire).where(PendingFire.id == source_evidence_id).with_for_update(),
            )
            pending = pending_result.scalar_one_or_none()
            if (
                pending is None
                or pending.schedule_id != schedule_id
                or pending.project_id != project_id
                or pending.fire_id != fire_id
                or pending.receipt_control_token is not None
            ):
                return OccurrenceResolutionTransition(
                    "identity_conflict",
                    schedule,
                    None,
                )
            fire_result = await self.session.execute(
                select(ScheduleFire)
                .where(
                    ScheduleFire.schedule_id == schedule_id,
                    ScheduleFire.fire_id == fire_id,
                    ScheduleFire.scheduled_for == pending.scheduled_for,
                    ScheduleFire.receipt_control_token.is_(None),
                )
                .with_for_update(),
            )
            fire = fire_result.scalar_one_or_none()
        else:
            fire_result = await self.session.execute(
                select(ScheduleFire)
                .where(
                    ScheduleFire.id == source_evidence_id,
                    ScheduleFire.receipt_control_token.is_(None),
                )
                .with_for_update(),
            )
            fire = fire_result.scalar_one_or_none()
            if (
                fire is None
                or fire.schedule_id != schedule_id
                or fire.project_id != project_id
                or fire.fire_id != fire_id
            ):
                return OccurrenceResolutionTransition(
                    "identity_conflict",
                    schedule,
                    None,
                )
            pending_exists = await self.session.scalar(
                select(
                    exists().where(
                        PendingFire.schedule_id == schedule_id,
                        PendingFire.fire_id == fire_id,
                        PendingFire.scheduled_for == fire.scheduled_for,
                        PendingFire.receipt_control_token.is_(None),
                    ),
                ),
            )
            if pending_exists:
                return OccurrenceResolutionTransition(
                    "pending_evidence_requires_resolution",
                    schedule,
                    None,
                )
        if fire is not None and fire.command_id is not None:
            return OccurrenceResolutionTransition(
                "command_evidence_requires_resolution",
                schedule,
                None,
            )
        if schedule.control_token != observed_control_token:
            return OccurrenceResolutionTransition(
                "stale_control",
                schedule,
                None,
            )

        locked_existing = await self.session.scalar(
            select(ScheduleOccurrenceResolution)
            .where(
                ScheduleOccurrenceResolution.schedule_id == schedule_id,
                ScheduleOccurrenceResolution.fire_id == fire_id,
                ScheduleOccurrenceResolution.scheduled_for == candidate_slot,
                ScheduleOccurrenceResolution.authority_kind == "LEGACY_NULL",
                ScheduleOccurrenceResolution.command_id.is_(None),
            )
            .with_for_update(),
        )
        if locked_existing is not None:
            return OccurrenceResolutionTransition(
                "already_resolved",
                schedule,
                None,
                resolution=locked_existing,
            )

        slot = _utc(candidate_slot)
        resolved_last = schedule.last_run_at
        if resolved_last is None or _utc(resolved_last) < slot:
            resolved_last = slot
        resolved_next = canonical_next_run_at(
            kind=schedule.kind.value,
            expression=schedule.expression,
            timezone=schedule.timezone,
            last_run_at=_utc(resolved_last),
            anchor_at=_utc(resolved_last),
        )
        now = _utc(occurred_at)
        new_token = uuid.uuid4()
        resolution = ScheduleOccurrenceResolution(
            id=uuid.uuid4(),
            project_id=project_id,
            schedule_id=schedule_id,
            fire_id=fire_id,
            scheduled_for=candidate_slot,
            command_id=None,
            source_evidence_kind=source_evidence_kind,
            source_evidence_id=source_evidence_id,
            authority_kind="LEGACY_NULL",
            observed_control_token=None,
            receipt_control_token=None,
            command_status=(
                "buffered"
                if pending is not None
                else str(fire.status if fire is not None else "unknown")
            ),
            work_may_have_executed=True,
            resolution_disposition="OPERATOR_SKIPPED",
            resolved_at=now,
            resolved_by=resolved_by,
            resolution_source="OPERATOR",
            resolution_control_token=new_token,
            deletion_tombstone_revision=None,
            state_write_nonce=uuid.uuid4(),
        )
        self.session.add(resolution)
        await self._flush_evidence_transition(
            table_name="schedule_occurrence_resolutions",
            operation="insert",
            row_id=resolution.id,
            nonce=resolution.state_write_nonce,
            reason="operator_resolution",
        )
        if pending is not None:
            guard_active = await arm_evidence_delete(
                self.session,
                table_name="pending_fires",
                row_id=pending.id,
                old_nonce=pending.state_write_nonce,
                reason="legacy_resolution",
            )
            await self.session.delete(pending)
        else:
            guard_active = False
        if fire is not None:
            fire.status = "operator_skipped"
            fire.error_code = "operator_skipped"
            fire.error_message = "operator resolved receipt-NULL legacy evidence without retry"
            if fire.state_write_nonce is not None:
                fire.state_write_nonce = uuid.uuid4()
        await self.session.flush()
        await assert_evidence_delete_consumed(
            self.session,
            active=guard_active,
        )

        revision = await self._allocate_revision()
        overrides = {
            "control_token": new_token,
            "legacy_fire_control_token": None,
            "is_enabled": enabled_after_resolution,
            "last_run_at": resolved_last,
            "next_run_at": resolved_next,
            "quarantine_control_token": None,
            "quarantine_code": None,
            "quarantine_detail": None,
            "quarantined_at": None,
            "schedule_revision": revision,
            "updated_at": now,
        }
        await self._append_upsert(
            schedule,
            revision=revision,
            overrides=overrides,
            occurred_at=now,
            transition=_legacy_evidence_resolution_transition_descriptor(
                evidence_kind=source_evidence_kind,
                evidence_id=source_evidence_id,
                fire_id=fire_id,
                scheduled_for=candidate_slot,
                observed_control_token=observed_control_token,
                new_control_token=new_token,
                enabled_after_resolution=enabled_after_resolution,
            ),
        )
        for field, value in overrides.items():
            setattr(schedule, field, value)
        await self.session.flush()
        return OccurrenceResolutionTransition(
            "resolved",
            schedule,
            None,
            resolution=resolution,
            committed_revision=revision,
            changed=True,
        )

    async def advance_cursor(  # noqa: PLR0912 - explicit protocol state machine
        self,
        *,
        project_id: uuid.UUID,
        schedule_id: uuid.UUID,
        observed_control_token: uuid.UUID,
        definition_digest: str,
        expected_revision: int,
        expected_last_run_at: datetime | None,
        expected_next_run_at: datetime,
        skipped_through: datetime,
        prepared_next_run_at: datetime | None,
        cadence_semantics_version: int,
        cadence_fingerprint: str,
        occurred_at: datetime,
    ) -> CursorTransition:
        result = await self.session.execute(
            select(Schedule)
            .where(
                Schedule.project_id == project_id,
                Schedule.id == schedule_id,
                Schedule.scheduler == "z4j-scheduler",
            )
            .with_for_update(),
        )
        row = result.scalar_one_or_none()
        if row is None:
            return CursorTransition("not_found", None)
        now = _utc(occurred_at)
        expected_next = _utc(expected_next_run_at)
        skipped = _utc(skipped_through)
        prepared_next = _utc(prepared_next_run_at) if prepared_next_run_at is not None else None
        if expected_revision <= 0 or not definition_digest:
            raise ScheduleControlConflictError(
                "cursor transition requires current definition identity",
            )
        if skipped < expected_next:
            raise ScheduleControlConflictError(
                "skipped-through cursor cannot precede the expected next slot",
            )
        if skipped > now + _MAX_CURSOR_FUTURE_SKEW:
            raise ScheduleControlConflictError(
                "skipped-through cursor exceeds the Brain clock-skew bound",
            )
        if prepared_next is not None and prepared_next <= skipped:
            raise ScheduleControlConflictError(
                "prepared next cursor must be strictly after skipped-through",
            )
        if (
            cadence_semantics_version != CADENCE_SEMANTICS_VERSION
            or cadence_fingerprint != cadence_runtime_fingerprint()
        ):
            return CursorTransition("cadence_semantics_mismatch", row)
        if not _effectively_enabled(row):
            raise ScheduleControlConflictError(
                "cursor transition requires an effectively enabled schedule",
            )

        transition_descriptor = _cursor_transition_descriptor(
            observed_control_token=observed_control_token,
            definition_digest=definition_digest,
            expected_revision=expected_revision,
            expected_last_run_at=(
                _utc(expected_last_run_at) if expected_last_run_at is not None else None
            ),
            expected_next_run_at=expected_next,
            skipped_through=skipped,
            prepared_next_run_at=prepared_next,
            cadence_semantics_version=cadence_semantics_version,
            cadence_fingerprint=cadence_fingerprint,
        )
        if (
            row.control_token != observed_control_token
            or row.definition_digest != definition_digest
            or row.schedule_revision != expected_revision
            or not _same_time(row.last_run_at, expected_last_run_at)
            or not _same_time(row.next_run_at, expected_next)
        ):
            if (
                row.control_token == observed_control_token
                and row.definition_digest == definition_digest
                and row.schedule_revision is not None
                and _same_time(row.last_run_at, skipped)
                and _same_time(row.next_run_at, prepared_next)
            ):
                replay_result = await self.session.execute(
                    select(ScheduleChangeLog).where(
                        ScheduleChangeLog.revision == row.schedule_revision,
                        ScheduleChangeLog.schedule_id == row.id,
                        ScheduleChangeLog.change_kind == "upsert",
                    ),
                )
                replay_envelope = replay_result.scalar_one_or_none()
                if (
                    replay_envelope is not None
                    and replay_envelope.snapshot is not None
                    and replay_envelope.snapshot.get("transition") == transition_descriptor
                ):
                    return CursorTransition(
                        "idempotent",
                        row,
                        int(row.schedule_revision),
                    )
            if (
                row.control_token == observed_control_token
                and row.definition_digest == definition_digest
                and row.last_run_at is not None
                and _utc(row.last_run_at) > skipped
            ):
                return CursorTransition("slot_resolved_refresh", row)
            return CursorTransition("stale_control_refresh", row)

        expected_successor = canonical_next_run_at(
            kind=row.kind.value,
            expression=row.expression,
            timezone=row.timezone,
            last_run_at=skipped,
            anchor_at=skipped,
        )
        if not _same_time(expected_successor, prepared_next):
            raise ScheduleControlConflictError(
                "prepared next cursor disagrees with Brain cadence authority",
            )
        revision = await self._allocate_revision()
        overrides = {
            "last_run_at": skipped,
            "next_run_at": prepared_next,
            "schedule_revision": revision,
            "updated_at": now,
        }
        await self._append_upsert(
            row,
            revision=revision,
            overrides=overrides,
            occurred_at=now,
            transition=transition_descriptor,
        )
        for field, value in overrides.items():
            setattr(row, field, value)
        await self.session.flush()
        return CursorTransition("applied", row, revision)

    async def accept_current_fire_progress(  # noqa: PLR0911, PLR0912 - protocol state machine
        self,
        *,
        project_id: uuid.UUID | None,
        schedule_id: uuid.UUID,
        fire_id: uuid.UUID,
        scheduled_for: datetime,
        observed_control_token: uuid.UUID,
        definition_digest: str,
        expected_revision: int,
        expected_last_run_at: datetime | None,
        expected_next_run_at: datetime,
        prepared_next_run_at: datetime | None,
        cadence_semantics_version: int,
        cadence_fingerprint: str,
        occurred_at: datetime,
    ) -> FireProgressTransition:
        """CAS one current-protocol cadence slot into durable Brain progress.

        Command/fire/pending evidence is inserted by the caller in this same
        transaction.  If any later persistence step fails, the schedule update,
        revision allocation, and envelope roll back with it.

        This method answers whether a slot may be committed, never whether the
        peer asking is entitled to the schedule; it has no view of the caller
        at all.  Its first act is to allocate a revision and append an
        envelope, and several of the refusals it raises on the way (slot
        identity, the clock-skew bound, a row without D identity) are decided
        before the project column is ever read, so a caller that authorises
        afterwards has both written and answered on behalf of a peer it had
        not yet checked.  Resolve the schedule, authorise the peer for its
        project, then call this with that project.  ``project_id=None`` skips
        the project predicate on the CAS and is for callers that are
        themselves the authority, such as the migration-era and test seams.
        """

        predicates = [
            Schedule.id == schedule_id,
            Schedule.scheduler == "z4j-scheduler",
        ]
        if project_id is not None:
            predicates.append(Schedule.project_id == project_id)
        result = await self.session.execute(
            select(Schedule).where(*predicates).with_for_update(),
        )
        row = result.scalar_one_or_none()
        if row is None:
            return FireProgressTransition("not_found", None)
        if row.control_token is None or not row.schedule_revision:
            raise ScheduleControlStateUnavailableError(
                "reserved schedule lacks D identity",
            )

        now = _utc(occurred_at)
        slot = normalized_schedule_slot(scheduled_for)
        expected_last = _utc(expected_last_run_at) if expected_last_run_at is not None else None
        expected_next = _utc(expected_next_run_at)
        prepared_next = _utc(prepared_next_run_at) if prepared_next_run_at is not None else None
        if derive_scheduler_fire_id(schedule_id, slot) != fire_id:
            raise ScheduleControlConflictError(
                "fire_id does not identify the submitted schedule slot",
            )
        if slot > now + _MAX_CURSOR_FUTURE_SKEW:
            raise ScheduleControlConflictError(
                "fire slot exceeds the Brain clock-skew bound",
            )
        if (
            cadence_semantics_version != CADENCE_SEMANTICS_VERSION
            or cadence_fingerprint != cadence_runtime_fingerprint()
        ):
            return FireProgressTransition("cadence_semantics_mismatch", row)

        transition_descriptor = _fire_transition_descriptor(
            fire_id=fire_id,
            scheduled_for=slot,
            observed_control_token=observed_control_token,
            definition_digest=definition_digest,
            expected_revision=expected_revision,
            expected_last_run_at=expected_last,
            expected_next_run_at=expected_next,
            prepared_next_run_at=prepared_next,
            cadence_semantics_version=cadence_semantics_version,
            cadence_fingerprint=cadence_fingerprint,
        )
        execution_fire_id = derive_execution_fire_id(
            fire_id,
            observed_control_token,
        )

        # Exact response-loss retry of the latest acceptance.  Its immutable
        # envelope proves the same request installed the current fence.
        if (
            row.control_token == observed_control_token
            and row.definition_digest == definition_digest
            and row.last_cadence_acceptance_control_token == observed_control_token
            and row.last_cadence_acceptance_fire_id == fire_id
            and _same_time(row.last_cadence_acceptance_scheduled_for, slot)
            and row.last_cadence_acceptance_revision is not None
        ):
            replay = await self.session.get(
                ScheduleChangeLog,
                row.last_cadence_acceptance_revision,
            )
            if (
                replay is not None
                and replay.schedule_id == row.id
                and replay.snapshot is not None
                and replay.snapshot.get("transition") == transition_descriptor
            ):
                return FireProgressTransition(
                    "idempotent",
                    row,
                    int(row.last_cadence_acceptance_revision),
                    execution_fire_id,
                )
            raise ScheduleControlStateUnavailableError(
                "latest cadence acceptance lacks matching immutable evidence",
            )

        if (
            row.control_token != observed_control_token
            or row.definition_digest != definition_digest
        ):
            return FireProgressTransition("stale_control_refresh", row)
        if (
            row.schedule_revision != expected_revision
            or not _same_time(row.last_run_at, expected_last)
            or not _same_time(row.next_run_at, expected_next)
        ):
            if row.last_run_at is not None and _utc(row.last_run_at) >= slot:
                return FireProgressTransition("slot_resolved_refresh", row)
            return FireProgressTransition("stale_control_refresh", row)
        if not _effectively_enabled(row):
            raise ScheduleControlConflictError(_not_enabled_reason(row))
        if slot < expected_next:
            raise ScheduleControlConflictError(
                "fire slot cannot precede the authoritative next cursor",
            )

        # Prove that the submitted slot is reachable on the locked definition.
        reachable = expected_next
        for _ in range(10_000):
            if _same_time(reachable, slot):
                break
            if reachable > slot:
                raise ScheduleControlConflictError(
                    "fire slot is not a canonical occurrence",
                )
            successor = canonical_next_run_at(
                kind=row.kind.value,
                expression=row.expression,
                timezone=row.timezone,
                last_run_at=reachable,
                anchor_at=reachable,
            )
            if successor is None:
                raise ScheduleControlConflictError(
                    "fire slot is beyond an exhausted definition",
                )
            reachable = _utc(successor)
        else:
            raise ScheduleControlConflictError(
                "fire slot exceeds the bounded canonical catch-up horizon",
            )

        canonical_successor = canonical_next_run_at(
            kind=row.kind.value,
            expression=row.expression,
            timezone=row.timezone,
            last_run_at=slot,
            anchor_at=slot,
        )
        if not _same_time(canonical_successor, prepared_next):
            raise ScheduleControlConflictError(
                "prepared next cursor disagrees with Brain cadence authority",
            )

        revision = await self._allocate_revision()
        overrides = {
            "last_run_at": slot,
            "next_run_at": prepared_next,
            "total_runs": row.total_runs + 1,
            "last_fire_id": fire_id,
            "last_cadence_acceptance_control_token": observed_control_token,
            "last_cadence_acceptance_fire_id": fire_id,
            "last_cadence_acceptance_scheduled_for": slot,
            "last_cadence_acceptance_revision": revision,
            "schedule_revision": revision,
            "updated_at": now,
        }
        await self._append_upsert(
            row,
            revision=revision,
            overrides=overrides,
            occurred_at=now,
            transition=transition_descriptor,
        )
        for field, value in overrides.items():
            setattr(row, field, value)
        await self.session.flush()
        return FireProgressTransition(
            "applied",
            row,
            revision,
            execution_fire_id,
        )

    async def accept_legacy_fire_progress(  # noqa: PLR0911, PLR0912, PLR0915
        self,
        *,
        project_id: uuid.UUID | None,
        schedule_id: uuid.UUID,
        fire_id: uuid.UUID,
        scheduled_for: datetime,
        occurred_at: datetime,
    ) -> FireProgressTransition:
        """Accept one explicitly granted tokenless 1.7 cadence occurrence."""

        predicates = [
            Schedule.id == schedule_id,
            Schedule.scheduler == "z4j-scheduler",
        ]
        if project_id is not None:
            predicates.append(Schedule.project_id == project_id)
        result = await self.session.execute(
            select(Schedule).where(*predicates).with_for_update(),
        )
        row = result.scalar_one_or_none()
        if row is None:
            return FireProgressTransition("not_found", None)
        token = row.control_token
        if (
            token is None
            or not row.schedule_revision
            or row.definition_digest is None
            or not row.cadence_semantics_version
            or not row.cadence_runtime_fingerprint
        ):
            # COMPLETENESS, not equality, which is what the message below says
            # and what the equivalent check in stable_snapshot already does.
            #
            # This compared the row's stored cadence identity against what the
            # Brain computes NOW. Nothing re-stamps that column, so the test
            # was really "was this row created by a Brain running the exact
            # same cadence dependencies and Python version" -- and it fails for
            # every pre-existing row the moment any of those move, which is a
            # staleness check wearing a completeness error message. Agreement
            # between the two processes is checked where it belongs, on the
            # submitted values, in the current fire and cursor paths.
            raise ScheduleControlStateUnavailableError(
                "reserved schedule lacks complete D identity",
            )

        now = _utc(occurred_at)
        slot = normalized_schedule_slot(scheduled_for)
        if derive_scheduler_fire_id(schedule_id, slot) != fire_id:
            raise ScheduleControlConflictError(
                "fire_id does not identify the submitted schedule slot",
            )
        if slot > now + _MAX_CURSOR_FUTURE_SKEW:
            raise ScheduleControlConflictError(
                "fire slot exceeds the Brain clock-skew bound",
            )

        resolved = await self.session.scalar(
            select(
                exists().where(
                    ScheduleOccurrenceResolution.schedule_id == row.id,
                    ScheduleOccurrenceResolution.fire_id == fire_id,
                    ScheduleOccurrenceResolution.scheduled_for == slot,
                    ScheduleOccurrenceResolution.resolution_disposition == "OPERATOR_SKIPPED",
                    ScheduleOccurrenceResolution.resolution_control_token == token,
                ),
            ),
        )
        resolved_hold = await self.session.scalar(
            select(
                exists().where(
                    ScheduleTerminalHold.schedule_id == row.id,
                    ScheduleTerminalHold.fire_id == fire_id,
                    ScheduleTerminalHold.scheduled_for == slot,
                    ScheduleTerminalHold.resolution_disposition == "OPERATOR_SKIPPED",
                    ScheduleTerminalHold.resolution_control_token == token,
                ),
            ),
        )
        if resolved or resolved_hold:
            return FireProgressTransition("slot_resolved_refresh", row)

        hold = await self.session.scalar(
            select(
                exists().where(
                    ScheduleTerminalHold.schedule_id == row.id,
                    ScheduleTerminalHold.fire_id == fire_id,
                    ScheduleTerminalHold.scheduled_for == slot,
                    ScheduleTerminalHold.resolved_at.is_(None),
                ),
            ),
        )
        if hold:
            return FireProgressTransition("terminal_quarantined", row)

        if await self._has_unresolved_legacy_occurrence(
            schedule_id=row.id,
            fire_id=fire_id,
            scheduled_for=slot,
        ):
            return FireProgressTransition(
                "legacy_operator_resolution_required",
                row,
            )
        if not row.is_enabled or row.quarantine_control_token == token:
            return FireProgressTransition("schedule_disabled", row)
        if row.paused_at is not None:
            # Reported distinctly from disabled so an operator reading a
            # scheduler's logs can tell a hold from a retirement.
            return FireProgressTransition("schedule_paused", row)
        if row.legacy_fire_control_token != token:
            return FireProgressTransition("legacy_upgrade_required", row)

        execution_fire_id = derive_execution_fire_id(fire_id, token)
        if (
            row.last_cadence_acceptance_control_token == token
            and row.last_cadence_acceptance_fire_id == fire_id
            and _same_time(
                row.last_cadence_acceptance_scheduled_for,
                slot,
            )
            and row.last_cadence_acceptance_revision is not None
        ):
            replay = await self.session.get(
                ScheduleChangeLog,
                row.last_cadence_acceptance_revision,
            )
            replay_transition = (
                replay.snapshot.get("transition")
                if replay is not None and replay.snapshot is not None
                else None
            )
            if (
                replay is not None
                and replay.schedule_id == row.id
                and isinstance(replay_transition, dict)
                and replay_transition.get("kind") == "accept_legacy_fire"
                and replay_transition.get("fire_id") == str(fire_id)
                and replay_transition.get("scheduled_for") == _json_value(slot)
                and replay_transition.get("receipt_control_token") == str(token)
                and replay_transition.get("definition_digest") == row.definition_digest
            ):
                return FireProgressTransition(
                    "idempotent",
                    row,
                    int(row.last_cadence_acceptance_revision),
                    execution_fire_id,
                )
            raise ScheduleControlStateUnavailableError(
                "latest legacy acceptance lacks matching immutable evidence",
            )

        expected_revision = int(row.schedule_revision)
        expected_last = _utc(row.last_run_at) if row.last_run_at is not None else None
        expected_next = _utc(row.next_run_at) if row.next_run_at is not None else None
        if expected_next is None:
            raise ScheduleControlStateUnavailableError(
                "enabled legacy-compatible schedule lacks a next cursor",
            )
        prepared_next = canonical_next_run_at(
            kind=row.kind.value,
            expression=row.expression,
            timezone=row.timezone,
            last_run_at=slot,
            anchor_at=slot,
        )
        transition_descriptor = _legacy_fire_transition_descriptor(
            fire_id=fire_id,
            scheduled_for=slot,
            receipt_control_token=token,
            definition_digest=row.definition_digest,
            expected_revision=expected_revision,
            expected_last_run_at=expected_last,
            expected_next_run_at=expected_next,
            prepared_next_run_at=prepared_next,
        )
        if slot < expected_next:
            if expected_last is not None and expected_last >= slot:
                return FireProgressTransition("slot_resolved_refresh", row)
            raise ScheduleControlConflictError(
                "legacy fire slot precedes the authoritative next cursor",
            )
        reachable = expected_next
        for _ in range(10_000):
            if _same_time(reachable, slot):
                break
            if reachable > slot:
                raise ScheduleControlConflictError(
                    "legacy fire slot is not a canonical occurrence",
                )
            successor = canonical_next_run_at(
                kind=row.kind.value,
                expression=row.expression,
                timezone=row.timezone,
                last_run_at=reachable,
                anchor_at=reachable,
            )
            if successor is None:
                raise ScheduleControlConflictError(
                    "legacy fire slot is beyond an exhausted definition",
                )
            reachable = _utc(successor)
        else:
            raise ScheduleControlConflictError(
                "legacy fire exceeds the bounded canonical catch-up horizon",
            )

        revision = await self._allocate_revision()
        overrides = {
            "last_run_at": slot,
            "next_run_at": prepared_next,
            "total_runs": row.total_runs + 1,
            "last_fire_id": fire_id,
            "last_cadence_acceptance_control_token": token,
            "last_cadence_acceptance_fire_id": fire_id,
            "last_cadence_acceptance_scheduled_for": slot,
            "last_cadence_acceptance_revision": revision,
            "schedule_revision": revision,
            "updated_at": now,
        }
        await self._append_upsert(
            row,
            revision=revision,
            overrides=overrides,
            occurred_at=now,
            transition=transition_descriptor,
        )
        for field, value in overrides.items():
            setattr(row, field, value)
        await self.session.flush()
        return FireProgressTransition(
            "applied",
            row,
            revision,
            execution_fire_id,
        )

    async def _has_unresolved_legacy_occurrence(
        self,
        *,
        schedule_id: uuid.UUID,
        fire_id: uuid.UUID,
        scheduled_for: datetime,
    ) -> bool:
        command_resolution = exists().where(
            ScheduleOccurrenceResolution.command_id == Command.id,
        )
        if await self.session.scalar(
            select(
                exists().where(
                    Command.schedule_id == schedule_id,
                    Command.schedule_fire_id == fire_id,
                    Command.schedule_scheduled_for == scheduled_for,
                    Command.schedule_receipt_control_token.is_(None),
                    ~command_resolution,
                ),
            ),
        ):
            return True
        fire_resolution = exists().where(
            ScheduleOccurrenceResolution.schedule_id == ScheduleFire.schedule_id,
            ScheduleOccurrenceResolution.fire_id == ScheduleFire.fire_id,
            ScheduleOccurrenceResolution.scheduled_for == ScheduleFire.scheduled_for,
        )
        if await self.session.scalar(
            select(
                exists().where(
                    ScheduleFire.schedule_id == schedule_id,
                    ScheduleFire.fire_id == fire_id,
                    ScheduleFire.scheduled_for == scheduled_for,
                    ScheduleFire.receipt_control_token.is_(None),
                    ~fire_resolution,
                ),
            ),
        ):
            return True
        pending_resolution = exists().where(
            ScheduleOccurrenceResolution.source_evidence_kind == "PENDING_FIRE",
            ScheduleOccurrenceResolution.source_evidence_id == PendingFire.id,
        )
        return bool(
            await self.session.scalar(
                select(
                    exists().where(
                        PendingFire.schedule_id == schedule_id,
                        PendingFire.fire_id == fire_id,
                        PendingFire.scheduled_for == scheduled_for,
                        PendingFire.receipt_control_token.is_(None),
                        ~pending_resolution,
                    ),
                ),
            ),
        )

    async def acknowledge_current_agent_delivery(
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
    ) -> TerminalFireTransition:
        """Record the write-once agent ACK without claiming execution."""

        candidate = await self.session.get(Command, command_id)
        if not _is_current_cadence_candidate(candidate):
            return TerminalFireTransition("not_current", None, candidate)
        assert candidate is not None
        assert candidate.schedule_id is not None
        schedule_result = await self.session.execute(
            select(Schedule).where(Schedule.id == candidate.schedule_id).with_for_update(),
        )
        schedule = schedule_result.scalar_one_or_none()
        command_result = await self.session.execute(
            select(Command).where(Command.id == command_id).with_for_update(),
        )
        command = command_result.scalar_one_or_none()
        if command is None:
            raise ScheduleControlStateUnavailableError(
                "cadence command disappeared after schedule lock",
            )
        if (
            not _complete_current_delivery_command(command)
            or command.project_id != project_id
            or command.agent_id != agent_id
        ):
            return TerminalFireTransition(
                "unauthorized_or_incomplete",
                schedule,
                command,
            )
        if not _delivery_receipt_is_authorized(
            command,
            transport_kind=transport_kind,
            registry_owner_id=registry_owner_id,
            session_generation=session_generation,
            delivery_claim_token=delivery_claim_token,
        ):
            return TerminalFireTransition("unauthorized", schedule, command)
        from z4j_brain.persistence.enums import CommandStatus

        if command.status not in {
            CommandStatus.DISPATCHED,
            CommandStatus.COMPLETED,
            CommandStatus.FAILED,
            CommandStatus.CANCELLED,
            CommandStatus.TIMEOUT,
        }:
            return TerminalFireTransition(
                "retryable_or_ambiguous",
                schedule,
                command,
            )
        if command.agent_acknowledged_at is not None:
            return TerminalFireTransition(
                "already_acknowledged",
                schedule,
                command,
            )
        command.agent_acknowledged_at = _utc(occurred_at)
        command.schedule_state_nonce = uuid.uuid4()
        await self.session.flush()
        return TerminalFireTransition(
            "acknowledged",
            schedule,
            command,
            command_transitioned=True,
        )

    async def apply_current_agent_result(  # noqa: PLR0911, PLR0912, PLR0915
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
    ) -> TerminalFireTransition:
        """Apply one authenticated agent result under schedule-first order."""

        candidate = await self.session.get(Command, command_id)
        if not _is_current_cadence_candidate(candidate):
            return TerminalFireTransition("not_current", None, candidate)
        assert candidate is not None
        if status not in {"success", "failed"}:
            return TerminalFireTransition("invalid_status", None, candidate)
        assert candidate.schedule_id is not None
        schedule_result = await self.session.execute(
            select(Schedule).where(Schedule.id == candidate.schedule_id).with_for_update(),
        )
        schedule = schedule_result.scalar_one_or_none()

        # Retained fire history is locked after schedule and before command.
        # It is optional: retention may legitimately have removed it.
        fire: ScheduleFire | None = None
        if (
            candidate.schedule_fire_id is not None
            and candidate.schedule_receipt_control_token is not None
        ):
            fire_result = await self.session.execute(
                select(ScheduleFire)
                .where(
                    ScheduleFire.fire_id == candidate.schedule_fire_id,
                    ScheduleFire.receipt_control_token == candidate.schedule_receipt_control_token,
                )
                .with_for_update(),
            )
            fire = fire_result.scalar_one_or_none()
        command_result = await self.session.execute(
            select(Command).where(Command.id == command_id).with_for_update(),
        )
        command = command_result.scalar_one_or_none()
        if command is None:
            raise ScheduleControlStateUnavailableError(
                "cadence command disappeared after schedule/fire locks",
            )
        if (
            not _complete_current_delivery_command(command)
            or command.project_id != project_id
            or command.agent_id != agent_id
        ):
            return TerminalFireTransition(
                "unauthorized_or_incomplete",
                schedule,
                command,
            )
        if fire is not None and not _current_fire_matches_command(
            fire,
            command,
        ):
            raise ScheduleControlStateUnavailableError(
                "retained fire history diverges from cadence command",
            )
        if not _delivery_receipt_is_authorized(
            command,
            transport_kind=transport_kind,
            registry_owner_id=registry_owner_id,
            session_generation=session_generation,
            delivery_claim_token=delivery_claim_token,
        ):
            return TerminalFireTransition("unauthorized", schedule, command)

        from z4j_brain.persistence.enums import CommandStatus

        requested_status = CommandStatus.COMPLETED if status == "success" else CommandStatus.FAILED
        if command.status == requested_status:
            if requested_status == CommandStatus.COMPLETED:
                return TerminalFireTransition(
                    "completed",
                    schedule,
                    command,
                )
            existing_hold = await self._lock_exact_terminal_hold(
                schedule=schedule,
                command=command,
            )
            return TerminalFireTransition(
                ("terminal_quarantined" if existing_hold is not None else requested_status.value),
                schedule,
                command,
                existing_hold,
                (
                    int(schedule.schedule_revision or 0)
                    if existing_hold is not None and schedule is not None
                    else None
                ),
            )
        if command.status != CommandStatus.DISPATCHED:
            return TerminalFireTransition(
                "retryable_or_ambiguous",
                schedule,
                command,
            )

        now = _utc(occurred_at)
        command.status = requested_status
        command.completed_at = now
        command.result = result_payload
        command.error = (
            None
            if requested_status == CommandStatus.COMPLETED
            else (error or "agent reported failure")[:1024]
        )
        command.schedule_state_nonce = uuid.uuid4()
        if fire is not None:
            fire.status = f"terminal_{requested_status.value}"
            fire.error_code = (
                None if requested_status == CommandStatus.COMPLETED else "command_failed"
            )
            fire.error_message = (
                None if requested_status == CommandStatus.COMPLETED else command.error
            )
            fire.state_write_nonce = uuid.uuid4()

        if requested_status == CommandStatus.COMPLETED:
            await self.session.flush()
            return TerminalFireTransition(
                "completed",
                schedule,
                command,
                command_transitioned=True,
            )
        if schedule is None:
            await self.session.flush()
            return TerminalFireTransition(
                "failed_history_only",
                None,
                command,
                command_transitioned=True,
            )
        receipt = command.schedule_receipt_control_token
        observed = command.schedule_observed_control_token
        latest_matches = (
            schedule.control_token == observed
            and schedule.control_token == receipt
            and schedule.last_cadence_acceptance_control_token == receipt
            and schedule.last_cadence_acceptance_fire_id == command.schedule_fire_id
            and _same_time(
                schedule.last_cadence_acceptance_scheduled_for,
                command.schedule_scheduled_for,
            )
            and schedule.last_cadence_acceptance_revision == command.schedule_acceptance_revision
        )
        if not latest_matches:
            await self.session.flush()
            return TerminalFireTransition(
                "failed_history_only",
                schedule,
                command,
                command_transitioned=True,
            )

        existing_hold = await self._lock_exact_terminal_hold(
            schedule=schedule,
            command=command,
        )
        if existing_hold is not None:
            await self.session.flush()
            return TerminalFireTransition(
                "terminal_quarantined",
                schedule,
                command,
                existing_hold,
                int(schedule.schedule_revision or 0),
                command_transitioned=True,
            )
        assert command.schedule_fire_id is not None
        assert command.schedule_scheduled_for is not None
        assert observed is not None
        assert receipt is not None
        assert command.schedule_acceptance_revision is not None
        hold = ScheduleTerminalHold(
            id=uuid.uuid4(),
            project_id=command.project_id,
            schedule_id=schedule.id,
            fire_id=command.schedule_fire_id,
            scheduled_for=command.schedule_scheduled_for,
            command_id=command.id,
            observed_control_token=observed,
            receipt_control_token=receipt,
            acceptance_revision=command.schedule_acceptance_revision,
            terminal_status=command.status.value,
            terminal_detail=command.error,
            state_write_nonce=uuid.uuid4(),
            created_at=now,
        )
        revision = await self._allocate_revision()
        overrides = {
            "is_enabled": False,
            "schedule_revision": revision,
            "updated_at": now,
        }
        await self._append_upsert(
            schedule,
            revision=revision,
            overrides=overrides,
            occurred_at=now,
            transition=_terminal_transition_descriptor(
                command=command,
                terminal_status=command.status.value,
            ),
        )
        for field, value in overrides.items():
            setattr(schedule, field, value)
        self.session.add(hold)
        await self._flush_evidence_transition(
            table_name="schedule_terminal_holds",
            operation="insert",
            row_id=hold.id,
            nonce=hold.state_write_nonce,
            reason="terminal_hold",
        )
        return TerminalFireTransition(
            "terminal_quarantined",
            schedule,
            command,
            hold,
            revision,
            True,
            True,
        )

    async def _lock_exact_terminal_hold(
        self,
        *,
        schedule: Schedule | None,
        command: Command,
    ) -> ScheduleTerminalHold | None:
        if schedule is None:
            return None
        result = await self.session.execute(
            select(ScheduleTerminalHold)
            .where(
                ScheduleTerminalHold.schedule_id == schedule.id,
                ScheduleTerminalHold.resolved_at.is_(None),
            )
            .with_for_update(),
        )
        hold = result.scalar_one_or_none()
        if hold is None:
            return None
        exact = (
            hold.project_id == command.project_id
            and hold.fire_id == command.schedule_fire_id
            and _same_time(hold.scheduled_for, command.schedule_scheduled_for)
            and hold.command_id == command.id
            and hold.observed_control_token == command.schedule_observed_control_token
            and hold.receipt_control_token == command.schedule_receipt_control_token
            and hold.acceptance_revision == command.schedule_acceptance_revision
            and hold.terminal_status == command.status.value
        )
        if not exact:
            raise ScheduleControlStateUnavailableError(
                "schedule has a divergent unresolved terminal hold",
            )
        return hold

    async def expire_current_schedule_delivery(  # noqa: PLR0911, PLR0912, PLR0915
        self,
        *,
        command_id: uuid.UUID,
        occurred_at: datetime,
    ) -> TerminalFireTransition:
        """Terminalize one elapsed cadence delivery without a generic shortcut.

        The unlocked command read identifies the schedule only.  Mutation then
        follows the global schedule -> retained fire -> command -> hold order
        and rechecks both immutable deadlines under those locks.
        """

        from z4j_brain.persistence.enums import CommandStatus

        candidate = await self.session.get(Command, command_id)
        if not _is_current_cadence_candidate(candidate):
            return TerminalFireTransition("not_current", None, candidate)
        assert candidate is not None
        assert candidate.schedule_id is not None

        schedule_result = await self.session.execute(
            select(Schedule).where(Schedule.id == candidate.schedule_id).with_for_update(),
        )
        schedule = schedule_result.scalar_one_or_none()

        fire: ScheduleFire | None = None
        if (
            candidate.schedule_fire_id is not None
            and candidate.schedule_receipt_control_token is not None
        ):
            fire_result = await self.session.execute(
                select(ScheduleFire)
                .where(
                    ScheduleFire.fire_id == candidate.schedule_fire_id,
                    ScheduleFire.receipt_control_token == candidate.schedule_receipt_control_token,
                )
                .with_for_update(),
            )
            fire = fire_result.scalar_one_or_none()

        command_result = await self.session.execute(
            select(Command).where(Command.id == command_id).with_for_update(),
        )
        command = command_result.scalar_one_or_none()
        if command is None:
            raise ScheduleControlStateUnavailableError(
                "cadence command disappeared after schedule/fire locks",
            )
        accepted_complete = (
            _is_current_cadence_candidate(command)
            and command.schedule_state_nonce is not None
            and command.schedule_fire_id is not None
            and command.schedule_scheduled_for is not None
            and command.schedule_receipt_control_token is not None
            and command.schedule_execution_fire_id is not None
            and command.schedule_acceptance_revision is not None
            and command.schedule_definition_digest is not None
            and command.schedule_expected_revision is not None
            and command.schedule_expected_next_run_at is not None
            and command.cadence_initial_claim_deadline is not None
        )
        if not accepted_complete:
            return TerminalFireTransition(
                "legacy_operator_resolution_required",
                schedule,
                command,
            )
        if fire is not None and not _current_fire_matches_command(
            fire,
            command,
        ):
            raise ScheduleControlStateUnavailableError(
                "retained fire history diverges from cadence command",
            )

        now = _utc(occurred_at)
        never_claimed = command.status == CommandStatus.PENDING
        if never_claimed:
            malformed_claim = any(
                value is not None
                for value in (
                    command.first_delivery_claimed_at,
                    command.cadence_redelivery_deadline,
                    command.delivery_transport_kind,
                    command.delivery_registry_owner_id,
                    command.delivery_session_generation,
                    command.delivery_claim_token,
                    command.agent_acknowledged_at,
                )
            )
            initial_deadline = command.cadence_initial_claim_deadline
            assert initial_deadline is not None
            if malformed_claim:
                return TerminalFireTransition(
                    "retryable_or_ambiguous",
                    schedule,
                    command,
                )
            if now < _utc(initial_deadline):
                return TerminalFireTransition("not_due", schedule, command)
            timeout_code = "initial_claim_timeout"
            timeout_detail = "cadence delivery initial claim deadline expired before any send"
        elif command.status == CommandStatus.DISPATCHED:
            if not _complete_current_delivery_command(command):
                return TerminalFireTransition(
                    "retryable_or_ambiguous",
                    schedule,
                    command,
                )
            redelivery_deadline = command.cadence_redelivery_deadline
            assert redelivery_deadline is not None
            if now < _utc(redelivery_deadline) and now < _utc(command.timeout_at):
                return TerminalFireTransition("not_due", schedule, command)
            if command.agent_acknowledged_at is None:
                timeout_code = "delivery_ambiguous_timeout"
                timeout_detail = (
                    "cadence delivery recovery deadline expired without "
                    "an authenticated agent result"
                )
            else:
                timeout_code = "acknowledged_result_timeout"
                timeout_detail = (
                    "cadence command result deadline expired after agent acknowledgement"
                )
        else:
            return TerminalFireTransition(
                (
                    command.status.value
                    if command.status
                    in {
                        CommandStatus.COMPLETED,
                        CommandStatus.FAILED,
                        CommandStatus.CANCELLED,
                        CommandStatus.TIMEOUT,
                    }
                    else "retryable_or_ambiguous"
                ),
                schedule,
                command,
            )

        command.status = CommandStatus.TIMEOUT
        command.completed_at = now
        command.result = None
        command.error = timeout_detail
        command.schedule_state_nonce = uuid.uuid4()
        if fire is not None:
            fire.status = "terminal_timeout"
            fire.error_code = timeout_code
            fire.error_message = timeout_detail
            fire.state_write_nonce = uuid.uuid4()

        if schedule is None:
            await self.session.flush()
            return TerminalFireTransition(
                "timeout_history_only",
                None,
                command,
                command_transitioned=True,
            )

        observed = command.schedule_observed_control_token
        receipt = command.schedule_receipt_control_token
        if observed is None or receipt is None:
            await self.session.flush()
            return TerminalFireTransition(
                "legacy_operator_resolution_required",
                schedule,
                command,
                command_transitioned=True,
            )
        if schedule.control_token != observed or schedule.control_token != receipt:
            await self.session.flush()
            return TerminalFireTransition(
                "stale_control_refresh",
                schedule,
                command,
                command_transitioned=True,
            )
        latest_matches = (
            schedule.last_cadence_acceptance_control_token == receipt
            and schedule.last_cadence_acceptance_fire_id == command.schedule_fire_id
            and _same_time(
                schedule.last_cadence_acceptance_scheduled_for,
                command.schedule_scheduled_for,
            )
            and schedule.last_cadence_acceptance_revision == command.schedule_acceptance_revision
        )
        if not latest_matches:
            await self.session.flush()
            return TerminalFireTransition(
                "slot_resolved_refresh",
                schedule,
                command,
                command_transitioned=True,
            )

        existing_hold = await self._lock_exact_terminal_hold(
            schedule=schedule,
            command=command,
        )
        if existing_hold is not None:
            await self.session.flush()
            return TerminalFireTransition(
                "terminal_quarantined",
                schedule,
                command,
                existing_hold,
                int(schedule.schedule_revision or 0),
                command_transitioned=True,
            )

        assert command.schedule_fire_id is not None
        assert command.schedule_scheduled_for is not None
        assert command.schedule_acceptance_revision is not None
        hold = ScheduleTerminalHold(
            id=uuid.uuid4(),
            project_id=command.project_id,
            schedule_id=schedule.id,
            fire_id=command.schedule_fire_id,
            scheduled_for=command.schedule_scheduled_for,
            command_id=command.id,
            observed_control_token=observed,
            receipt_control_token=receipt,
            acceptance_revision=command.schedule_acceptance_revision,
            terminal_status=CommandStatus.TIMEOUT.value,
            terminal_detail=timeout_detail,
            state_write_nonce=uuid.uuid4(),
            created_at=now,
        )
        revision = await self._allocate_revision()
        overrides = {
            "is_enabled": False,
            "schedule_revision": revision,
            "updated_at": now,
        }
        await self._append_upsert(
            schedule,
            revision=revision,
            overrides=overrides,
            occurred_at=now,
            transition=_terminal_transition_descriptor(
                command=command,
                terminal_status=CommandStatus.TIMEOUT.value,
            ),
        )
        for field, value in overrides.items():
            setattr(schedule, field, value)
        self.session.add(hold)
        await self._flush_evidence_transition(
            table_name="schedule_terminal_holds",
            operation="insert",
            row_id=hold.id,
            nonce=hold.state_write_nonce,
            reason="terminal_hold",
        )
        return TerminalFireTransition(
            "terminal_quarantined",
            schedule,
            command,
            hold,
            revision,
            True,
            True,
        )

    async def terminalize_current_fire(  # noqa: PLR0911, PLR0912
        self,
        *,
        command_id: uuid.UUID,
        occurred_at: datetime,
    ) -> TerminalFireTransition:
        """Install/reuse one current receipt-authorized terminal hold."""

        candidate = await self.session.get(Command, command_id)
        if (
            candidate is None
            or candidate.action != "schedule.fire"
            or candidate.schedule_id is None
        ):
            return TerminalFireTransition("not_found", None, candidate)
        schedule_result = await self.session.execute(
            select(Schedule)
            .where(
                Schedule.id == candidate.schedule_id,
                Schedule.scheduler == "z4j-scheduler",
            )
            .with_for_update(),
        )
        schedule = schedule_result.scalar_one_or_none()
        if schedule is None:
            return TerminalFireTransition(
                "slot_resolved_refresh",
                None,
                candidate,
            )
        fire: ScheduleFire | None = None
        if (
            candidate.schedule_fire_id is not None
            and candidate.schedule_receipt_control_token is not None
        ):
            fire_result = await self.session.execute(
                select(ScheduleFire)
                .where(
                    ScheduleFire.fire_id == candidate.schedule_fire_id,
                    ScheduleFire.receipt_control_token == candidate.schedule_receipt_control_token,
                )
                .with_for_update(),
            )
            fire = fire_result.scalar_one_or_none()
        command_result = await self.session.execute(
            select(Command).where(Command.id == command_id).with_for_update(),
        )
        command = command_result.scalar_one_or_none()
        if command is None:
            raise ScheduleControlStateUnavailableError(
                "cadence command disappeared after schedule lock",
            )

        from z4j_brain.domain.schedule_fire_authority import (
            SCHEDULE_FIRE_PROTOCOL_MARKER,
        )
        from z4j_brain.persistence.enums import CommandStatus

        terminal_statuses = {
            CommandStatus.FAILED,
            CommandStatus.CANCELLED,
            CommandStatus.TIMEOUT,
        }
        if command.status == CommandStatus.COMPLETED:
            return TerminalFireTransition("completed", schedule, command)
        if command.status == CommandStatus.PENDING:
            return TerminalFireTransition("pending", schedule, command)
        if command.status == CommandStatus.DISPATCHED:
            return TerminalFireTransition("dispatched", schedule, command)
        if command.status not in terminal_statuses:
            return TerminalFireTransition("retryable_or_ambiguous", schedule, command)
        complete = (
            command.schedule_protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER
            and command.schedule_id == schedule.id
            and command.schedule_fire_id is not None
            and command.schedule_scheduled_for is not None
            and command.schedule_observed_control_token is not None
            and command.schedule_receipt_control_token is not None
            and command.schedule_execution_fire_id is not None
            and command.schedule_acceptance_revision is not None
            and command.schedule_definition_digest is not None
            and command.schedule_expected_revision is not None
            and command.schedule_expected_next_run_at is not None
            and command.cadence_initial_claim_deadline is not None
        )
        if not complete:
            return TerminalFireTransition(
                "legacy_operator_resolution_required",
                schedule,
                command,
            )

        if fire is not None and not _current_fire_matches_command(
            fire,
            command,
        ):
            raise ScheduleControlStateUnavailableError(
                "retained fire history diverges from cadence command",
            )
        existing_hold = await self._lock_exact_terminal_hold(
            schedule=schedule,
            command=command,
        )
        if existing_hold is not None:
            return TerminalFireTransition(
                "terminal_quarantined",
                schedule,
                command,
                existing_hold,
                int(schedule.schedule_revision or 0),
            )

        receipt = command.schedule_receipt_control_token
        observed = command.schedule_observed_control_token
        if schedule.control_token != observed or schedule.control_token != receipt:
            return TerminalFireTransition(
                "stale_control_refresh",
                schedule,
                command,
            )
        latest_matches = (
            schedule.last_cadence_acceptance_control_token == receipt
            and schedule.last_cadence_acceptance_fire_id == command.schedule_fire_id
            and _same_time(
                schedule.last_cadence_acceptance_scheduled_for,
                command.schedule_scheduled_for,
            )
            and schedule.last_cadence_acceptance_revision == command.schedule_acceptance_revision
        )
        if not latest_matches:
            return TerminalFireTransition(
                "slot_resolved_refresh",
                schedule,
                command,
            )

        now = _utc(occurred_at)
        hold = ScheduleTerminalHold(
            id=uuid.uuid4(),
            project_id=command.project_id,
            schedule_id=schedule.id,
            fire_id=command.schedule_fire_id,
            scheduled_for=command.schedule_scheduled_for,
            command_id=command.id,
            observed_control_token=observed,
            receipt_control_token=receipt,
            acceptance_revision=command.schedule_acceptance_revision,
            terminal_status=command.status.value,
            terminal_detail=(command.error or "")[:1024] or None,
            state_write_nonce=uuid.uuid4(),
            created_at=now,
        )
        if fire is not None:
            fire.status = f"terminal_{command.status.value}"
            fire.error_code = f"command_{command.status.value}"
            fire.error_message = (command.error or "")[:2000] or None
            fire.state_write_nonce = uuid.uuid4()

        revision = await self._allocate_revision()
        overrides = {
            "is_enabled": False,
            "schedule_revision": revision,
            "updated_at": now,
        }
        await self._append_upsert(
            schedule,
            revision=revision,
            overrides=overrides,
            occurred_at=now,
            transition=_terminal_transition_descriptor(
                command=command,
                terminal_status=command.status.value,
            ),
        )
        for field, value in overrides.items():
            setattr(schedule, field, value)
        self.session.add(hold)
        await self._flush_evidence_transition(
            table_name="schedule_terminal_holds",
            operation="insert",
            row_id=hold.id,
            nonce=hold.state_write_nonce,
            reason="terminal_hold",
        )
        return TerminalFireTransition(
            "terminal_quarantined",
            schedule,
            command,
            hold,
            revision,
            True,
        )


__all__ = [
    "CursorTransition",
    "FireProgressTransition",
    "LegacyGrantTransition",
    "OccurrenceResolutionTransition",
    "QuarantineTransition",
    "ScheduleControlConflictError",
    "ScheduleControlRepository",
    "ScheduleControlStateUnavailableError",
    "ScheduleDeleteTransition",
    "StableScheduleSnapshot",
    "TerminalFireTransition",
    "operator_hold_in_force",
    "schedule_is_quarantined",
    "schedule_snapshot",
]
