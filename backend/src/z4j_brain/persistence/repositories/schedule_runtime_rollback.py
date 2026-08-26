"""Transactional Boundary-D preparation for the one supported rollback target."""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select, text

from z4j_brain.domain.runtime_rollback import (
    ROLLBACK_TARGET_RELEASE,
    SEALED_TARGET_CADENCE_FINGERPRINT,
    SEALED_TARGET_CADENCE_PAYLOAD,
    RuntimeRollbackRefused,
    object_sha256,
    require_finalized_target_image,
)
from z4j_brain.domain.schedule_cadence import canonical_next_run_at
from z4j_brain.domain.schedule_definition import schedule_definition_digest
from z4j_brain.persistence.enums import CommandStatus
from z4j_brain.persistence.models import (
    Command,
    PendingFire,
    Schedule,
    ScheduleChangeLog,
    ScheduleFire,
    ScheduleRevisionState,
    ScheduleTerminalHold,
)
from z4j_brain.persistence.models.schedule_control import SCHEDULE_REVISION_SINGLETON_ID
from z4j_brain.schema_transition import SCHEMA_TRANSITION_ADVISORY_LOCK_KEY

if TYPE_CHECKING:
    from z4j_brain.persistence.repositories.schedule_control import ScheduleControlRepository

_RESERVED_OWNER = "z4j-scheduler"
_SUPPORTED_SEMANTICS = {1}
_ANCHOR_FIELDS = ("kind", "expression", "timezone", "catch_up")
_ANCHOR_CADENCE_FIELDS = (
    *_ANCHOR_FIELDS,
    "is_enabled",
    "last_run_at",
    "next_run_at",
    "cadence_semantics_version",
    "cadence_runtime_fingerprint",
    "definition_digest",
)
_PLANNER_ANCHOR_KEYS = {
    "anchor_reason",
    "cadence_definition",
    "changed_fields",
    "definition_digest",
    "kind",
    "planner_anchor",
    "revision",
    "schedule_id",
}
_OWNER_CUTOVER_KEYS = {
    "cursor_policy",
    "from_owner",
    "kind",
    "operation_id",
    "to_owner",
}
_OWNER_CUTOVER_CURSOR_POLICIES = {"PRESERVE", "PRESERVE_FUTURE", "RESET_CURSOR"}
_PRE_1_9_SNAPSHOT_FIELDS = frozenset({"overlap_policy", "paused_at"})
_FINGERPRINT_PATTERN = re.compile(r"[0-9a-f]{64}")
_NONTERMINAL_FIRE_STATUSES = {"pending", "accepted", "delivered", "buffered"}
_TERMINAL_COMMAND_STATUSES = {
    CommandStatus.COMPLETED,
    CommandStatus.FAILED,
    CommandStatus.CANCELLED,
    CommandStatus.TIMEOUT,
}


@dataclass(frozen=True, slots=True)
class RuntimeRollbackRowPlan:
    """One fully preflighted reserved row and its target cursor decision."""

    schedule_id: uuid.UUID
    project_id: uuid.UUID
    schedule_revision: int
    changed: bool
    source_semantics_version: int
    source_runtime_fingerprint: str
    cursor_policy: str
    anchor_kind: str
    anchor_at: datetime | None
    old_next_run_at: datetime | None
    new_next_run_at: datetime | None
    definition_digest: str
    _schedule: Schedule = field(repr=False, compare=False)

    def receipt(self) -> dict[str, Any]:
        return {
            "schedule_id": str(self.schedule_id),
            "project_id": str(self.project_id),
            "schedule_revision": self.schedule_revision,
            "changed": self.changed,
            "source_cadence_semantics_version": self.source_semantics_version,
            "source_cadence_runtime_fingerprint": self.source_runtime_fingerprint,
            "cursor_policy": self.cursor_policy,
            "anchor_kind": self.anchor_kind,
            "anchor_at": _json_time(self.anchor_at),
            "old_next_run_at": _json_time(self.old_next_run_at),
            "new_next_run_at": _json_time(self.new_next_run_at),
            "definition_digest": self.definition_digest,
        }


@dataclass(frozen=True, slots=True)
class RuntimeRollbackPlan:
    row_set_digest: str
    current_revision: int
    pruned_through: int
    rows: tuple[RuntimeRollbackRowPlan, ...]
    external_schedule_count: int

    @property
    def changed_count(self) -> int:
        return sum(row.changed for row in self.rows)

    @property
    def noop_count(self) -> int:
        return len(self.rows) - self.changed_count


@dataclass(frozen=True, slots=True)
class RuntimeRollbackPreparation:
    operation_id: uuid.UUID
    target_image: str
    row_set_digest: str
    changed_count: int
    noop_count: int
    external_schedule_count: int
    schedule_revision_watermark: int
    change_log_pruned_through: int
    revisions: tuple[tuple[uuid.UUID, int], ...]
    rows: tuple[dict[str, Any], ...]


def _utc_aware(value: datetime) -> datetime:
    """Normalize a stored timestamp to an aware UTC datetime.

    SQLite has no timezone type, so a column declared ``DateTime(timezone=True)``
    round-trips through it NAIVE while the same column on PostgreSQL comes back
    aware. ``canonical_next_run_at`` refuses a naive input, so handing it a
    stored value directly raised for every schedule that had ever fired, on
    SQLite only, and took the whole rollback preparation down with it. The
    change-log path already normalized; this names that normalization so both
    paths share one definition.
    """

    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _json_time(value: datetime | None) -> str | None:
    if value is None:
        return None
    aware = value.replace(tzinfo=UTC) if value.tzinfo is None else value
    return aware.astimezone(UTC).isoformat(timespec="microseconds")


def _same_time(left: datetime | None, right: datetime | None) -> bool:
    return _json_time(left) == _json_time(right)


def _kind(row: Schedule) -> str:
    return row.kind.value if hasattr(row.kind, "value") else str(row.kind)


def _snapshot_schedule(change: ScheduleChangeLog) -> dict[str, Any]:
    snapshot = change.snapshot
    if (
        change.change_kind != "upsert"
        or not isinstance(snapshot, dict)
        or snapshot.get("format") != "z4j-schedule-snapshot-v1"
        or not isinstance(snapshot.get("schedule"), dict)
    ):
        raise RuntimeRollbackRefused(
            f"schedule {change.schedule_id} revision {change.revision} "
            "does not retain a complete upsert snapshot",
        )
    return snapshot["schedule"]


def _latest_snapshot_matches(
    *,
    row: Schedule,
    latest: ScheduleChangeLog,
    schedule_snapshot: Any,
) -> None:
    if int(latest.revision) != int(row.schedule_revision or 0):
        raise RuntimeRollbackRefused(
            f"schedule {row.id} current revision is not its latest retained upsert",
        )
    stored = _snapshot_schedule(latest)
    current = schedule_snapshot(row)["schedule"]
    missing = set(current).difference(stored)
    extra = set(stored).difference(current)
    if extra or not missing.issubset(_PRE_1_9_SNAPSHOT_FIELDS):
        raise RuntimeRollbackRefused(
            f"schedule {row.id} latest snapshot field set is incomplete",
        )
    # 1.9 adds these default-only columns without changing the D revision.
    if "overlap_policy" in missing and row.overlap_policy != "allow":
        raise RuntimeRollbackRefused(
            f"schedule {row.id} has non-default overlap state absent from its snapshot",
        )
    if "paused_at" in missing and row.paused_at is not None:
        raise RuntimeRollbackRefused(
            f"schedule {row.id} has a pause absent from its snapshot",
        )
    projected = {key: value for key, value in current.items() if key in stored}
    if projected != stored:
        raise RuntimeRollbackRefused(
            f"schedule {row.id} differs from its latest retained upsert snapshot",
        )


def _explicit_planner_anchor(
    *,
    row: Schedule,
    change: ScheduleChangeLog,
    current: dict[str, Any],
    previous: dict[str, Any] | None,
) -> bool:
    """Validate a repository-authored planner marker; reject forged variants."""

    snapshot = change.snapshot
    transition = snapshot.get("transition") if isinstance(snapshot, dict) else None
    if not isinstance(transition, dict) or transition.get("kind") != "planner_anchor":
        return False
    if set(transition) != _PLANNER_ANCHOR_KEYS:
        raise RuntimeRollbackRefused(
            f"schedule {row.id} revision {change.revision} has a malformed planner anchor",
        )
    if (
        transition.get("planner_anchor") is not True
        or transition.get("schedule_id") != str(row.id)
        or transition.get("revision") != int(change.revision)
        or current.get("schedule_revision") != int(change.revision)
        or transition.get("definition_digest") != current.get("definition_digest")
        or transition.get("cadence_definition")
        != {name: current.get(name) for name in _ANCHOR_CADENCE_FIELDS}
    ):
        raise RuntimeRollbackRefused(
            f"schedule {row.id} revision {change.revision} has a forged planner anchor",
        )
    reason = transition.get("anchor_reason")
    changed_fields = transition.get("changed_fields")
    if (
        reason not in {"create", "cadence_change", "reenable"}
        or not isinstance(changed_fields, list)
        or any(not isinstance(name, str) for name in changed_fields)
        or changed_fields != sorted(set(changed_fields))
    ):
        raise RuntimeRollbackRefused(
            f"schedule {row.id} revision {change.revision} has invalid planner metadata",
        )
    if reason == "create":
        if (
            previous is not None
            or changed_fields != sorted(current)
            or current.get("last_run_at") is not None
            or current.get("created_at") != _json_time(change.occurred_at)
        ):
            raise RuntimeRollbackRefused(
                f"schedule {row.id} revision {change.revision} has a false create anchor",
            )
        return True
    if previous is None:
        raise RuntimeRollbackRefused(
            f"schedule {row.id} planner anchor lacks its adjacent prior snapshot",
        )
    observed_changes = sorted(
        name for name, value in current.items() if previous.get(name) != value
    )
    if changed_fields != observed_changes:
        raise RuntimeRollbackRefused(
            f"schedule {row.id} planner anchor changed-fields proof differs",
        )
    if reason == "cadence_change" and not any(
        previous.get(name) != current.get(name) for name in _ANCHOR_FIELDS
    ):
        raise RuntimeRollbackRefused(
            f"schedule {row.id} cadence-change anchor changed no cadence field",
        )
    if reason == "reenable" and not (
        previous.get("is_enabled") is False and current.get("is_enabled") is True
    ):
        raise RuntimeRollbackRefused(
            f"schedule {row.id} re-enable anchor did not enable the schedule",
        )
    return True


def _owner_cutover_anchor(
    *,
    row: Schedule,
    change: ScheduleChangeLog,
    current: dict[str, Any],
    previous: dict[str, Any] | None,
) -> bool:
    """Accept only the exact repository-authored external-owner envelope."""

    snapshot = change.snapshot
    transition = snapshot.get("transition") if isinstance(snapshot, dict) else None
    if not isinstance(transition, dict) or transition.get("kind") != "owner_cutover":
        return False
    operation_id = transition.get("operation_id")
    try:
        parsed_operation = uuid.UUID(str(operation_id))
    except (AttributeError, TypeError, ValueError) as exc:
        raise RuntimeRollbackRefused(
            f"schedule {row.id} revision {change.revision} has a malformed owner-cutover anchor",
        ) from exc
    if (
        set(transition) != _OWNER_CUTOVER_KEYS
        or previous is None
        or not isinstance(operation_id, str)
        or str(parsed_operation) != operation_id
        or not isinstance(transition.get("from_owner"), str)
        or transition.get("from_owner") == _RESERVED_OWNER
        or transition.get("from_owner") != previous.get("scheduler")
        or transition.get("to_owner") != _RESERVED_OWNER
        or transition.get("to_owner") != current.get("scheduler")
        or transition.get("cursor_policy") not in _OWNER_CUTOVER_CURSOR_POLICIES
        or current.get("schedule_revision") != int(change.revision)
    ):
        raise RuntimeRollbackRefused(
            f"schedule {row.id} revision {change.revision} has a malformed owner-cutover anchor",
        )
    return True


def _recover_planning_anchor(
    *,
    row: Schedule,
    history: list[ScheduleChangeLog],
    pruned_through: int,
) -> datetime:
    """Recover the exact no-last-run planner anchor from adjacent snapshots."""

    previous: dict[str, Any] | None = None
    anchor: datetime | None = None
    for index, change in enumerate(history):
        if change.change_kind != "upsert":
            continue
        current = _snapshot_schedule(change)
        if not {*_ANCHOR_FIELDS, "is_enabled"}.issubset(current):
            raise RuntimeRollbackRefused(
                f"schedule {row.id} has an incomplete cadence history snapshot",
            )
        explicit_anchor = _explicit_planner_anchor(
            row=row, change=change, current=current, previous=previous
        )
        created = previous is None and index == 0 and pruned_through == 0
        owner_cutover = _owner_cutover_anchor(
            row=row,
            change=change,
            current=current,
            previous=previous,
        )
        cadence_change = previous is not None and any(
            previous.get(name) != current.get(name) for name in _ANCHOR_FIELDS
        )
        enabled_again = (
            previous is not None
            and previous.get("is_enabled") is False
            and current.get("is_enabled") is True
        )
        if explicit_anchor or created or owner_cutover or cadence_change or enabled_again:
            anchor = change.occurred_at
        previous = current
    if anchor is None:
        raise RuntimeRollbackRefused(
            f"schedule {row.id} has no unambiguous retained planning anchor",
        )
    return _utc_aware(anchor)


def _cursor_plan(
    *,
    row: Schedule,
    history: list[ScheduleChangeLog],
    pruned_through: int,
    inflight: bool,
) -> tuple[str, str, datetime | None, datetime | None]:
    old_next = row.next_run_at
    if not row.is_enabled:
        return "disabled_preserved", "disabled", None, old_next

    if row.last_run_at is not None:
        anchor = _utc_aware(row.last_run_at)
        target_next = canonical_next_run_at(
            kind=_kind(row),
            expression=row.expression,
            timezone=row.timezone,
            last_run_at=anchor,
            anchor_at=anchor,
        )
        anchor_kind = "last_run_at"
        policy = (
            "validated_from_last_run"
            if _same_time(old_next, target_next)
            else "recomputed_from_last_run"
        )
    else:
        anchor = _recover_planning_anchor(
            row=row,
            history=history,
            pruned_through=pruned_through,
        )
        target_next = canonical_next_run_at(
            kind=_kind(row),
            expression=row.expression,
            timezone=row.timezone,
            last_run_at=None,
            anchor_at=anchor,
        )
        anchor_kind = "change_log_occurred_at"
        policy = (
            "validated_from_change_log"
            if _same_time(old_next, target_next)
            else "recomputed_from_change_log"
        )

    repeating = _kind(row) not in {"clocked", "one_shot"}
    if target_next is None and repeating:
        raise RuntimeRollbackRefused(
            f"enabled repeating schedule {row.id} has no target-runtime successor",
        )
    if old_next is None and target_next is not None:
        raise RuntimeRollbackRefused(
            f"enabled schedule {row.id} has a null cursor but is not exhausted "
            "under the target runtime",
        )
    if target_next is None:
        policy = "exhausted_validated"
        anchor_kind = "exhausted"
    if not _same_time(old_next, target_next) and inflight:
        raise RuntimeRollbackRefused(
            f"schedule {row.id} requires cursor repair while unresolved fire evidence exists",
        )
    return policy, anchor_kind, anchor, target_next


async def _load_evidence(
    repository: ScheduleControlRepository,
    *,
    schedule_ids: list[uuid.UUID],
    lock_rows: bool,
) -> tuple[set[uuid.UUID], dict[str, Any]]:
    if not schedule_ids:
        return set(), {
            "pending_fires": [],
            "schedule_fires": [],
            "commands": [],
            "terminal_holds": [],
        }
    session = repository.session

    async def rows(statement: Any) -> list[Any]:
        if lock_rows:
            statement = statement.with_for_update()
        return list((await session.execute(statement)).scalars())

    pending = await rows(
        select(PendingFire)
        .where(PendingFire.schedule_id.in_(schedule_ids))
        .order_by(PendingFire.schedule_id, PendingFire.id),
    )
    fires = await rows(
        select(ScheduleFire)
        .where(ScheduleFire.schedule_id.in_(schedule_ids))
        .order_by(ScheduleFire.schedule_id, ScheduleFire.scheduled_for, ScheduleFire.id),
    )
    commands = await rows(
        select(Command)
        .where(Command.schedule_id.in_(schedule_ids), Command.action == "schedule.fire")
        .order_by(Command.schedule_id, Command.id),
    )
    holds = await rows(
        select(ScheduleTerminalHold)
        .where(ScheduleTerminalHold.schedule_id.in_(schedule_ids))
        .order_by(ScheduleTerminalHold.schedule_id, ScheduleTerminalHold.id),
    )
    inflight = {row.schedule_id for row in pending}
    inflight.update(row.schedule_id for row in fires if row.status in _NONTERMINAL_FIRE_STATUSES)
    inflight.update(
        row.schedule_id for row in commands if row.status not in _TERMINAL_COMMAND_STATUSES
    )
    inflight.update(row.schedule_id for row in holds if row.resolved_at is None)
    evidence = {
        "pending_fires": [
            {
                "id": str(row.id),
                "schedule_id": str(row.schedule_id),
                "fire_id": str(row.fire_id),
                "state_write_nonce": str(row.state_write_nonce) if row.state_write_nonce else None,
            }
            for row in pending
        ],
        "schedule_fires": [
            {
                "id": str(row.id),
                "schedule_id": str(row.schedule_id),
                "fire_id": str(row.fire_id),
                "status": row.status,
                "state_write_nonce": str(row.state_write_nonce) if row.state_write_nonce else None,
            }
            for row in fires
        ],
        "commands": [
            {
                "id": str(row.id),
                "schedule_id": str(row.schedule_id),
                "status": row.status.value,
                "state_write_nonce": str(row.schedule_state_nonce)
                if row.schedule_state_nonce
                else None,
            }
            for row in commands
        ],
        "terminal_holds": [
            {
                "id": str(row.id),
                "schedule_id": str(row.schedule_id),
                "resolved_at": _json_time(row.resolved_at),
                "state_write_nonce": str(row.state_write_nonce),
            }
            for row in holds
        ],
    }
    return inflight, evidence


async def plan_runtime_rollback(  # noqa: PLR0912 - explicit refusal matrix
    repository: ScheduleControlRepository,
    *,
    lock_rows: bool = False,
) -> RuntimeRollbackPlan:
    """Preflight all rows without changing one byte of schedule state."""

    from z4j_brain.persistence.repositories.schedule_control import (
        schedule_is_quarantined,
        schedule_snapshot,
    )

    session = repository.session
    dialect = session.get_bind().dialect.name
    if (
        lock_rows
        and dialect == "sqlite"
        and not session.sync_session.info.get(
            "z4j_sqlite_immediate",
        )
    ):
        raise RuntimeRollbackRefused(
            "SQLite rollback apply requires DatabaseManager.session(write=True) "
            "so the complete preflight and write use BEGIN IMMEDIATE",
        )
    if lock_rows and dialect == "postgresql":
        await session.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": SCHEMA_TRANSITION_ADVISORY_LOCK_KEY},
        )

    state_statement = select(ScheduleRevisionState).where(
        ScheduleRevisionState.singleton_id == SCHEDULE_REVISION_SINGLETON_ID,
    )
    if lock_rows:
        state_statement = state_statement.with_for_update()
    state = (await session.execute(state_statement)).scalar_one_or_none()
    if (
        state is None
        or state.guard_version != 1
        or state.current_revision < state.change_log_pruned_through
    ):
        raise RuntimeRollbackRefused(
            "Boundary-D revision state is missing, inactive, or malformed",
        )

    schedule_statement = select(Schedule).order_by(Schedule.id)
    if lock_rows:
        schedule_statement = schedule_statement.with_for_update()
    all_rows = list((await session.execute(schedule_statement)).scalars())
    reserved = [row for row in all_rows if row.scheduler == _RESERVED_OWNER]
    external = [row for row in all_rows if row.scheduler != _RESERVED_OWNER]
    schedule_ids = [row.id for row in reserved]

    history_rows: list[ScheduleChangeLog] = []
    if schedule_ids:
        history_statement = (
            select(ScheduleChangeLog)
            .where(ScheduleChangeLog.schedule_id.in_(schedule_ids))
            .order_by(ScheduleChangeLog.schedule_id, ScheduleChangeLog.revision)
        )
        if lock_rows:
            history_statement = history_statement.with_for_update()
        history_rows = list((await session.execute(history_statement)).scalars())
    history_by_schedule: dict[uuid.UUID, list[ScheduleChangeLog]] = defaultdict(list)
    for change in history_rows:
        history_by_schedule[change.schedule_id].append(change)

    inflight, evidence_manifest = await _load_evidence(
        repository,
        schedule_ids=schedule_ids,
        lock_rows=lock_rows,
    )
    planned: list[RuntimeRollbackRowPlan] = []
    for row in reserved:
        if (
            row.control_token is None
            or not row.schedule_revision
            or not row.definition_digest
            or row.cadence_semantics_version not in _SUPPORTED_SEMANTICS
            or not row.cadence_runtime_fingerprint
            or _FINGERPRINT_PATTERN.fullmatch(row.cadence_runtime_fingerprint) is None
        ):
            raise RuntimeRollbackRefused(
                f"schedule {row.id} lacks complete current Boundary-D identity",
            )
        if row.paused_at is not None:
            raise RuntimeRollbackRefused(
                f"schedule {row.id} is paused; resume it before rollback",
            )
        if schedule_is_quarantined(row):
            raise RuntimeRollbackRefused(
                f"schedule {row.id} has an unresolved definition quarantine",
            )
        if schedule_definition_digest(row) != row.definition_digest:
            raise RuntimeRollbackRefused(
                f"schedule {row.id} definition digest does not match its row",
            )
        history = history_by_schedule[row.id]
        if not history:
            raise RuntimeRollbackRefused(
                f"schedule {row.id} has no retained Boundary-D history",
            )
        _latest_snapshot_matches(
            row=row,
            latest=history[-1],
            schedule_snapshot=schedule_snapshot,
        )
        policy, anchor_kind, anchor_at, target_next = _cursor_plan(
            row=row,
            history=history,
            pruned_through=int(state.change_log_pruned_through),
            inflight=row.id in inflight,
        )
        already_target = (
            row.cadence_semantics_version == SEALED_TARGET_CADENCE_PAYLOAD["semantics_version"]
            and row.cadence_runtime_fingerprint == SEALED_TARGET_CADENCE_FINGERPRINT
        )
        if already_target and not _same_time(row.next_run_at, target_next):
            raise RuntimeRollbackRefused(
                f"target-stamped schedule {row.id} has a non-target cursor",
            )
        planned.append(
            RuntimeRollbackRowPlan(
                schedule_id=row.id,
                project_id=row.project_id,
                schedule_revision=int(row.schedule_revision),
                changed=not already_target,
                source_semantics_version=int(row.cadence_semantics_version),
                source_runtime_fingerprint=row.cadence_runtime_fingerprint,
                cursor_policy="already_target" if already_target else policy,
                anchor_kind=anchor_kind,
                anchor_at=anchor_at,
                old_next_run_at=row.next_run_at,
                new_next_run_at=target_next,
                definition_digest=row.definition_digest,
                _schedule=row,
            ),
        )

    row_set_manifest = {
        "format": "z4j-runtime-rollback-row-set-v1",
        "revision_state": {
            "current_revision": int(state.current_revision),
            "change_log_pruned_through": int(state.change_log_pruned_through),
            "guard_version": state.guard_version,
            "activation_id": str(state.activation_id),
            "activation_manifest_digest": state.activation_manifest_digest,
        },
        "schedules": [schedule_snapshot(row)["schedule"] for row in all_rows],
        "change_log": [
            {
                "revision": int(change.revision),
                "schedule_id": str(change.schedule_id),
                "schedule_owner": change.schedule_owner,
                "change_kind": change.change_kind,
                "snapshot": change.snapshot,
                "occurred_at": _json_time(change.occurred_at),
            }
            for change in history_rows
        ],
        "evidence": evidence_manifest,
        "plans": [row.receipt() for row in planned],
        "external_schedule_ids": [str(row.id) for row in external],
    }
    return RuntimeRollbackPlan(
        row_set_digest=object_sha256(row_set_manifest),
        current_revision=int(state.current_revision),
        pruned_through=int(state.change_log_pruned_through),
        rows=tuple(planned),
        external_schedule_count=len(external),
    )


async def prepare_runtime_rollback(
    repository: ScheduleControlRepository,
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
    """Restamp every changed reserved row after one all-row preflight."""

    if target_release != ROLLBACK_TARGET_RELEASE:
        raise RuntimeRollbackRefused(
            f"unsupported rollback target release: {target_release!r}",
        )
    target_authority = require_finalized_target_image(target_image)
    target_image_digest = target_authority["index"]["digest"]
    if _FINGERPRINT_PATTERN.fullmatch(quiescence_challenge_sha256) is None:
        raise RuntimeRollbackRefused("quiescence challenge hash is malformed")
    if _FINGERPRINT_PATTERN.fullmatch(target_durable_evidence_sha256) is None:
        raise RuntimeRollbackRefused("durable rollback evidence hash is malformed")
    if target_evidence_terminal_stage not in {"promotion", "recovery"}:
        raise RuntimeRollbackRefused("durable rollback evidence terminal stage differs")
    if (
        not isinstance(target_release_evidence_index, dict)
        or set(target_release_evidence_index) != {"sha256", "size", "completion"}
        or _FINGERPRINT_PATTERN.fullmatch(
            str(target_release_evidence_index.get("sha256", "")),
        )
        is None
        or not isinstance(target_release_evidence_index.get("size"), int)
        or isinstance(target_release_evidence_index.get("size"), bool)
        or target_release_evidence_index["size"] <= 0
        or not isinstance(target_release_evidence_index.get("completion"), dict)
    ):
        raise RuntimeRollbackRefused(
            "durable rollback release-evidence index projection differs",
        )
    plan = await plan_runtime_rollback(repository, lock_rows=True)
    if plan.row_set_digest != expected_row_set_digest:
        raise RuntimeRollbackRefused(
            "database row set changed after preview; discard the challenge "
            "and produce a new preview",
        )

    now = (
        occurred_at.replace(tzinfo=UTC)
        if occurred_at.tzinfo is None
        else occurred_at.astimezone(UTC)
    )
    revisions: list[tuple[uuid.UUID, int]] = []
    receipts: list[dict[str, Any]] = []
    target_semantics = int(SEALED_TARGET_CADENCE_PAYLOAD["semantics_version"])
    for item in plan.rows:
        receipt = item.receipt()
        if not item.changed:
            receipts.append({**receipt, "new_revision": None})
            continue
        revision = await repository._allocate_revision()
        overrides: dict[str, Any] = {
            "cadence_semantics_version": target_semantics,
            "cadence_runtime_fingerprint": SEALED_TARGET_CADENCE_FINGERPRINT,
            "schedule_revision": revision,
            "updated_at": now,
        }
        if not _same_time(item.old_next_run_at, item.new_next_run_at):
            overrides["next_run_at"] = item.new_next_run_at
        transition = {
            "kind": "prepare_runtime_rollback",
            "target_release": target_release,
            "target_image": target_image,
            "target_image_digest": target_image_digest,
            "target_image_manifest_sha256": target_authority["manifest_sha256"],
            "target_image_platforms": target_authority["platforms"],
            "target_image_release_receipt_sha256": target_authority["release_receipt_sha256"],
            "target_durable_evidence_sha256": target_durable_evidence_sha256,
            "target_release_evidence_index": target_release_evidence_index,
            "target_evidence_terminal_stage": target_evidence_terminal_stage,
            "source_cadence_semantics_version": item.source_semantics_version,
            "source_cadence_runtime_fingerprint": item.source_runtime_fingerprint,
            "target_cadence_semantics_version": target_semantics,
            "target_cadence_runtime_fingerprint": SEALED_TARGET_CADENCE_FINGERPRINT,
            "cursor_policy": item.cursor_policy,
            "anchor_kind": item.anchor_kind,
            "anchor_at": _json_time(item.anchor_at),
            "old_next_run_at": _json_time(item.old_next_run_at),
            "new_next_run_at": _json_time(item.new_next_run_at),
            "definition_digest": item.definition_digest,
            "quiescence_challenge_sha256": quiescence_challenge_sha256,
            "operation_id": str(operation_id),
        }
        await repository._append_upsert(
            item._schedule,
            revision=revision,
            overrides=overrides,
            occurred_at=now,
            transition=transition,
        )
        for name, value in overrides.items():
            setattr(item._schedule, name, value)
        await repository.session.flush()
        revisions.append((item.schedule_id, revision))
        receipts.append({**receipt, "new_revision": revision})

    return RuntimeRollbackPreparation(
        operation_id=operation_id,
        target_image=target_image,
        row_set_digest=plan.row_set_digest,
        changed_count=plan.changed_count,
        noop_count=plan.noop_count,
        external_schedule_count=plan.external_schedule_count,
        schedule_revision_watermark=(revisions[-1][1] if revisions else plan.current_revision),
        change_log_pruned_through=plan.pruned_through,
        revisions=tuple(revisions),
        rows=tuple(receipts),
    )


__all__ = [
    "RuntimeRollbackPlan",
    "RuntimeRollbackPreparation",
    "RuntimeRollbackRowPlan",
    "plan_runtime_rollback",
    "prepare_runtime_rollback",
]
