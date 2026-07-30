"""Repair pre-release Boundary-D cursors seeded from 1.7 wall-clock fires.

Revision ID: v1_8_schedule_cursor_repair
Revises: v1_8_schedule_control_activate
Create Date: 2026-07-28

The original Boundary-D activation copied a 1.7 ``last_run_at`` value with
microsecond precision into the authoritative cadence cursor.  Current-protocol
fire identities are whole-second slots, so an already-activated schedule could
reject every future occurrence.  This migration gives databases that reached
the affected pre-release head an automatic, guarded repair path.  Fresh
upgrades are already normalized by the preceding activation and therefore make
no data changes here.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from alembic import op
from alembic.util import CommandError
from z4j_brain.domain.audit_chain import normalize_timestamp
from z4j_brain.domain.schedule_cadence import (
    ScheduleCadenceError,
    canonical_next_run_at,
)
from z4j_brain.persistence.models import (
    Schedule,
    ScheduleChangeLog,
    ScheduleRevisionState,
)
from z4j_brain.persistence.schedule_guard import (
    register_sqlite_schedule_guard,
)

revision: str = "v1_8_schedule_cursor_repair"
down_revision: str | Sequence[str] | None = "v1_8_schedule_control_activate"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

compat = {
    "min_z4j_version": "1.8.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_8_schedule_control_activate",
    "downgrade_to": None,
}

_STATE_ID = "schedule-revision"
_PROTOCOL_VERSION = 1
_SNAPSHOT_FIELDS = (
    "id",
    "project_id",
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
    "last_fire_id",
    "control_token",
    "legacy_fire_control_token",
    "schedule_revision",
    "definition_digest",
    "cadence_semantics_version",
    "cadence_runtime_fingerprint",
    "quarantine_control_token",
    "quarantine_code",
    "quarantine_detail",
    "quarantined_at",
    "last_cadence_acceptance_control_token",
    "last_cadence_acceptance_fire_id",
    "last_cadence_acceptance_scheduled_for",
    "last_cadence_acceptance_revision",
    "external_stream_id",
    "external_epoch_uuid",
    "external_epoch_number",
    "external_source_key",
    "external_source_sequence",
    "created_at",
    "updated_at",
)


def _kind_text(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return normalize_timestamp(value).isoformat(timespec="microseconds")
    if isinstance(value, uuid.UUID):
        return str(value)
    if hasattr(value, "value"):
        return value.value
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _snapshot(
    row: Mapping[str, Any],
    *,
    overrides: Mapping[str, Any],
    transition: Mapping[str, Any],
) -> dict[str, Any]:
    values = {
        field: _json_value(
            overrides[field] if field in overrides else row[field],
        )
        for field in _SNAPSHOT_FIELDS
    }
    return {
        "format": "z4j-schedule-snapshot-v1",
        "schedule": values,
        "transition": _json_value(dict(transition)),
    }


def _arm_revision_allocation(bind: sa.engine.Connection) -> None:
    if bind.dialect.name == "sqlite":
        bind.execute(
            sa.text(
                "SELECT z4j_schedule_guard('arm_allocation', '', '', 0, 0, '', '', '')",
            ),
        )
        return
    bind.execute(
        sa.text(
            "SELECT set_config('z4j.schedule_allocation_guard', 'armed', true)",
        ),
    )


def _assert_revision_allocation_consumed(
    bind: sa.engine.Connection,
) -> None:
    if bind.dialect.name == "sqlite":
        bind.execute(
            sa.text(
                "SELECT z4j_schedule_guard('check_allocation', '', '', 0, 0, '', '', '')",
            ),
        )
        return
    remaining = bind.scalar(
        sa.text(
            "SELECT current_setting('z4j.schedule_allocation_guard', true)",
        ),
    )
    if remaining:
        raise CommandError("schedule cursor repair allocation was not consumed")


def _arm_schedule_transition(
    bind: sa.engine.Connection,
    *,
    schedule_id: uuid.UUID,
    old_revision: int,
    new_revision: int,
    control_token: uuid.UUID,
) -> None:
    descriptor = {
        "operation": "update",
        "schedule_id": str(schedule_id),
        "old_revision": old_revision,
        "new_revision": new_revision,
        "change_kind": "upsert",
        "old_token": str(control_token),
        "new_token": str(control_token),
    }
    if bind.dialect.name == "sqlite":
        bind.execute(
            sa.text(
                "SELECT z4j_schedule_guard("
                "'arm_transition', :operation, :schedule_id, "
                ":old_revision, :new_revision, :change_kind, "
                ":old_token, :new_token)",
            ),
            descriptor,
        )
        return
    encoded = json.dumps(
        descriptor,
        sort_keys=True,
        separators=(",", ":"),
    )
    bind.execute(
        sa.text(
            "SELECT set_config('z4j.schedule_transition_guard', :descriptor, true)",
        ),
        {"descriptor": encoded},
    )


def _assert_schedule_transition_consumed(
    bind: sa.engine.Connection,
) -> None:
    if bind.dialect.name == "sqlite":
        bind.execute(
            sa.text(
                "SELECT z4j_schedule_guard('check_transition', '', '', 0, 0, '', '', '')",
            ),
        )
        return
    remaining = bind.scalar(
        sa.text(
            "SELECT current_setting('z4j.schedule_transition_guard', true)",
        ),
    )
    if remaining:
        raise CommandError("schedule cursor repair transition was not consumed")


def _allocate_revision(
    bind: sa.engine.Connection,
    *,
    expected_revision: int,
) -> int:
    _arm_revision_allocation(bind)
    new_revision = bind.scalar(
        ScheduleRevisionState.__table__.update()
        .where(
            ScheduleRevisionState.__table__.c.singleton_id == _STATE_ID,
            ScheduleRevisionState.__table__.c.current_revision == expected_revision,
            ScheduleRevisionState.__table__.c.current_revision
            >= ScheduleRevisionState.__table__.c.change_log_pruned_through,
        )
        .values(
            current_revision=ScheduleRevisionState.__table__.c.current_revision + 1,
        )
        .returning(ScheduleRevisionState.__table__.c.current_revision),
    )
    if new_revision is None or int(new_revision) != expected_revision + 1:
        raise CommandError(
            "schedule cursor repair failed to allocate exactly one revision",
        )
    _assert_revision_allocation_consumed(bind)
    return int(new_revision)


def _repair_values(
    row: Mapping[str, Any],
) -> tuple[datetime, datetime | None] | None:
    legacy_last = row["last_run_at"]
    if legacy_last is None:
        return None
    normalized_last = normalize_timestamp(legacy_last).replace(microsecond=0)
    legacy_next = row["next_run_at"]
    next_is_subsecond = (
        legacy_next is not None and normalize_timestamp(legacy_next).microsecond != 0
    )
    if normalize_timestamp(legacy_last).microsecond == 0 and not next_is_subsecond:
        return None

    # Boundary-D activation deliberately disables and quarantines a reserved
    # schedule whose legacy definition cannot be parsed.  The affected RC kept
    # the old ``next_run_at`` on that path, so an already-activated database can
    # reach this repair with both a fractional cursor and an intentionally
    # invalid expression.  Re-parsing that expression would strand the database
    # at the old migration head forever.  Validate the exact quarantine identity
    # instead, normalize the last observed cursor, and park the disabled
    # schedule with no runnable successor.
    if row["quarantine_code"] == "migration_definition_invalid":
        if (
            bool(row["is_enabled"])
            or row["quarantine_control_token"] is None
            or row["quarantine_control_token"] != row["control_token"]
        ):
            raise CommandError(
                "legacy cursor repair found an invalid quarantine identity",
            )
        return normalized_last, None

    normalized_next = None
    if legacy_next is not None:
        normalized_next = canonical_next_run_at(
            kind=_kind_text(row["kind"]),
            expression=str(row["expression"]),
            timezone=str(row["timezone"]),
            last_run_at=normalized_last,
            anchor_at=normalized_last,
        )
    repeating = _kind_text(row["kind"]) not in {"clocked", "one_shot"}
    if bool(row["is_enabled"]) and repeating and normalized_next is None:
        raise CommandError(
            "enabled repeating schedule has no successor during cursor repair",
        )
    return normalized_last, normalized_next


def upgrade() -> None:
    context = op.get_context()
    if context.as_sql:
        raise CommandError(
            "Boundary-D cursor repair requires a live guarded database",
        )
    bind = op.get_bind()
    if bind.dialect.name not in {"sqlite", "postgresql"}:
        raise CommandError(
            f"unsupported Boundary-D database: {bind.dialect.name}",
        )
    if bind.dialect.name == "postgresql":
        bind.execute(
            sa.text(
                "LOCK TABLE schedule_revision_state, schedule_change_log, "
                "schedules IN SHARE ROW EXCLUSIVE MODE",
            ),
        )
    else:
        register_sqlite_schedule_guard(
            bind.connection.dbapi_connection,
        )

    state_statement = sa.select(ScheduleRevisionState.__table__).where(
        ScheduleRevisionState.__table__.c.singleton_id == _STATE_ID,
    )
    if bind.dialect.name == "postgresql":
        state_statement = state_statement.with_for_update()
    state = bind.execute(state_statement).mappings().one_or_none()
    if (
        state is None
        or state["guard_version"] != 1
        or state["activation_id"] is None
        or state["activation_manifest_digest"] is None
        or state["activation_audit_id"] is None
    ):
        raise CommandError(
            "Boundary-D cursor repair requires authenticated schedule authority",
        )

    schedule_table = Schedule.__table__
    rows = (
        bind.execute(
            sa.select(schedule_table)
            .where(
                schedule_table.c.scheduler == "z4j-scheduler",
                schedule_table.c.last_run_at.is_not(None),
                schedule_table.c.last_cadence_acceptance_revision.is_(None),
            )
            .order_by(schedule_table.c.id),
        )
        .mappings()
        .all()
    )
    current_revision = int(state["current_revision"])
    occurred_at = datetime.now(UTC)
    for row in rows:
        try:
            repaired = _repair_values(row)
        except (ScheduleCadenceError, ValueError, TypeError) as exc:
            raise CommandError(
                f"cannot repair legacy cursor for schedule {row['id']}",
            ) from exc
        if repaired is None:
            continue
        normalized_last, normalized_next = repaired
        old_revision = int(row["schedule_revision"])
        control_token = row["control_token"]
        if old_revision <= 0 or control_token is None:
            raise CommandError(
                "legacy cursor repair found an incomplete schedule identity",
            )
        new_revision = _allocate_revision(
            bind,
            expected_revision=current_revision,
        )
        overrides = {
            "last_run_at": normalized_last,
            "next_run_at": normalized_next,
            "schedule_revision": new_revision,
            "updated_at": occurred_at,
        }
        transition = {
            "kind": "repair_legacy_cursor_seed",
            "migration_revision": revision,
            "old_last_run_at": row["last_run_at"],
            "old_next_run_at": row["next_run_at"],
            "repaired_last_run_at": normalized_last,
            "repaired_next_run_at": normalized_next,
        }
        bind.execute(
            ScheduleChangeLog.__table__.insert().values(
                revision=new_revision,
                project_id=row["project_id"],
                schedule_id=row["id"],
                schedule_owner=row["scheduler"],
                change_kind="upsert",
                protocol_version=_PROTOCOL_VERSION,
                snapshot=_snapshot(
                    row,
                    overrides=overrides,
                    transition=transition,
                ),
                occurred_at=occurred_at,
            ),
        )
        _arm_schedule_transition(
            bind,
            schedule_id=row["id"],
            old_revision=old_revision,
            new_revision=new_revision,
            control_token=control_token,
        )
        updated = bind.execute(
            schedule_table.update()
            .where(
                schedule_table.c.id == row["id"],
                schedule_table.c.schedule_revision == old_revision,
                schedule_table.c.control_token == control_token,
            )
            .values(**overrides),
        )
        if updated.rowcount != 1:
            raise CommandError(
                "legacy cursor repair did not update exactly one schedule",
            )
        _assert_schedule_transition_consumed(bind)
        current_revision = new_revision


def downgrade() -> None:
    raise CommandError(
        "refusing downgrade below Boundary D while schedule authority exists",
    )
