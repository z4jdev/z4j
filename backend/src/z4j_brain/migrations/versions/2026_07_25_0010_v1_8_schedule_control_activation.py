"""Activate authenticated Boundary-D schedule-control state.

Revision ID: v1_8_schedule_control_activate
Revises: v1_8_audit_chain_activate
Create Date: 2026-07-25

This is the data-bearing, fail-closed cutover.  It authenticates Boundary F,
backfills distinct schedule generations and the legacy evidence markers,
installs backend-native one-shot write fences, and appends one signed v2 audit
row in the same transaction.  Downgrade is deliberately unsupported.
"""

from __future__ import annotations

import hashlib
import hmac
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from alembic import op
from alembic.util import CommandError
from sqlalchemy.orm import Session
from z4j_brain.domain.audit_chain import (
    AUDIT_ROW_HMAC_VERSION,
    authenticate_state,
    build_audit_keyring,
    canonical_json,
    canonical_row_payload,
    compute_row_hmac,
    compute_state_mac,
    normalize_timestamp,
    strictly_later_audit_key,
)
from z4j_brain.domain.schedule_cadence import (
    CADENCE_SEMANTICS_VERSION,
    ScheduleCadenceError,
    cadence_runtime_fingerprint,
    canonical_next_run_at,
)
from z4j_brain.domain.schedule_definition import schedule_definition_digest
from z4j_brain.migrations import settings_from_context
from z4j_brain.persistence.models import (
    AuditChainState,
    AuditLog,
    Command,
    PendingFire,
    Schedule,
    ScheduleChangeLog,
    ScheduleExternalControlOperation,
    ScheduleExternalEpochAllocator,
    ScheduleExternalProjection,
    ScheduleExternalSnapshotFrame,
    ScheduleExternalStream,
    ScheduleExternalStreamEpoch,
    ScheduleFire,
    ScheduleOccurrenceResolution,
    ScheduleOwnerCutover,
    ScheduleRevisionState,
    ScheduleTerminalHold,
)
from z4j_brain.persistence.models.schedule_external import (
    SCHEDULE_EXTERNAL_EPOCH_SINGLETON_ID,
)
from z4j_brain.persistence.repositories.audit_log import (
    AUDIT_CHAIN_ADVISORY_LOCK_KEY,
)
from z4j_brain.persistence.schedule_guard import (
    SCHEDULE_GUARD_VERSION,
    register_sqlite_schedule_guard,
)

revision: str = "v1_8_schedule_control_activate"
down_revision: str | Sequence[str] | None = "v1_8_audit_chain_activate"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

compat = {
    "min_z4j_version": "1.8.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_8_audit_chain_activate",
    "downgrade_to": None,
}

_STATE_ID = "schedule-revision"
_ACTIVATION_ACTION = "schedule.control_migration_activated"
_ACTIVATION_TARGET = "schedule_control"


def _table_exists(bind: sa.engine.Connection, name: str) -> bool:
    return name in sa.inspect(bind).get_table_names()


def _column_names(bind: sa.engine.Connection, table: str) -> set[str]:
    return {str(column["name"]) for column in sa.inspect(bind).get_columns(table)}


def _copy_column(
    column: sa.Column[Any],
    *,
    nullable: bool = True,
) -> sa.Column[Any]:
    return sa.Column(
        column.name,
        column.type,
        nullable=nullable,
    )


def _ensure_table(
    bind: sa.engine.Connection,
    table: sa.Table,
) -> None:
    if not _table_exists(bind, table.name):
        table.create(bind)


def _ensure_columns(
    bind: sa.engine.Connection,
    table: sa.Table,
    names: Sequence[str],
) -> None:
    existing = _column_names(bind, table.name)
    for name in names:
        if name in existing:
            continue
        op.add_column(
            table.name,
            _copy_column(table.c[name]),
        )
        existing.add(name)


def _foreign_keys_for(
    bind: sa.engine.Connection,
    table: str,
) -> list[dict[str, Any]]:
    return list(sa.inspect(bind).get_foreign_keys(table))


def _drop_mutating_foreign_keys(
    bind: sa.engine.Connection,
    *,
    table: str,
    columns: set[str],
) -> None:
    targets = [
        foreign_key
        for foreign_key in _foreign_keys_for(bind, table)
        if tuple(foreign_key.get("constrained_columns") or ()) in {(column,) for column in columns}
    ]
    if not targets:
        return
    if bind.dialect.name == "sqlite":
        naming = {
            "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
        }
        with op.batch_alter_table(
            table,
            naming_convention=naming,
        ) as batch:
            for foreign_key in targets:
                name = foreign_key.get("name")
                if not name:
                    constrained = foreign_key["constrained_columns"]
                    referred = foreign_key["referred_table"]
                    name = f"fk_{table}_{'_'.join(constrained)}_{referred}"
                batch.drop_constraint(str(name), type_="foreignkey")
        return
    for foreign_key in targets:
        name = foreign_key.get("name")
        if not name:
            raise CommandError(
                f"cannot identify mutating {table} foreign key",
            )
        op.drop_constraint(str(name), table, type_="foreignkey")


def _unique_constraints(
    bind: sa.engine.Connection,
    table: str,
) -> list[dict[str, Any]]:
    return list(sa.inspect(bind).get_unique_constraints(table))


def _index_names(bind: sa.engine.Connection, table: str) -> set[str]:
    return {
        str(index["name"]) for index in sa.inspect(bind).get_indexes(table) if index.get("name")
    }


def _install_generation_uniqueness(  # noqa: PLR0912
    bind: sa.engine.Connection,
) -> None:
    fire_uniques = _unique_constraints(bind, "schedule_fires")
    fire_old = [
        item
        for item in fire_uniques
        if tuple(item.get("column_names") or ()) in {("fire_id",), ("fire_id", "scheduled_for")}
    ]
    fire_current = any(
        tuple(item.get("column_names") or ())
        in {
            ("fire_id", "receipt_control_token"),
            ("fire_id", "receipt_control_token", "scheduled_for"),
        }
        for item in fire_uniques
    )
    if fire_old or not fire_current:
        if bind.dialect.name == "sqlite":
            with op.batch_alter_table("schedule_fires") as batch:
                for item in fire_old:
                    name = item.get("name")
                    if not name:
                        raise CommandError(
                            "cannot identify legacy schedule-fire unique",
                        )
                    batch.drop_constraint(str(name), type_="unique")
                if not fire_current:
                    batch.create_unique_constraint(
                        "uq_schedule_fires_fire_receipt",
                        ["fire_id", "receipt_control_token"],
                    )
        else:
            for item in fire_old:
                name = item.get("name")
                if not name:
                    raise CommandError(
                        "cannot identify legacy schedule-fire unique",
                    )
                op.drop_constraint(
                    str(name),
                    "schedule_fires",
                    type_="unique",
                )
            if not fire_current:
                op.create_unique_constraint(
                    "uq_schedule_fires_fire_receipt",
                    "schedule_fires",
                    [
                        "fire_id",
                        "receipt_control_token",
                        "scheduled_for",
                    ],
                )
    if "uq_schedule_fires_legacy_fire" not in _index_names(
        bind,
        "schedule_fires",
    ):
        op.create_index(
            "uq_schedule_fires_legacy_fire",
            "schedule_fires",
            (["fire_id"] if bind.dialect.name == "sqlite" else ["fire_id", "scheduled_for"]),
            unique=True,
            sqlite_where=sa.text("receipt_control_token IS NULL"),
            postgresql_where=sa.text("receipt_control_token IS NULL"),
        )

    pending_uniques = _unique_constraints(bind, "pending_fires")
    pending_old = [
        item for item in pending_uniques if tuple(item.get("column_names") or ()) == ("fire_id",)
    ]
    pending_current = any(
        tuple(item.get("column_names") or ()) == ("fire_id", "receipt_control_token")
        for item in pending_uniques
    )
    if pending_old or not pending_current:
        if bind.dialect.name == "sqlite":
            with op.batch_alter_table("pending_fires") as batch:
                for item in pending_old:
                    name = item.get("name")
                    if not name:
                        raise CommandError(
                            "cannot identify legacy pending-fire unique",
                        )
                    batch.drop_constraint(str(name), type_="unique")
                if not pending_current:
                    batch.create_unique_constraint(
                        "uq_pending_fires_fire_receipt",
                        ["fire_id", "receipt_control_token"],
                    )
        else:
            for item in pending_old:
                name = item.get("name")
                if not name:
                    raise CommandError(
                        "cannot identify legacy pending-fire unique",
                    )
                op.drop_constraint(
                    str(name),
                    "pending_fires",
                    type_="unique",
                )
            if not pending_current:
                op.create_unique_constraint(
                    "uq_pending_fires_fire_receipt",
                    "pending_fires",
                    ["fire_id", "receipt_control_token"],
                )
    if "uq_pending_fires_legacy_fire" not in _index_names(
        bind,
        "pending_fires",
    ):
        op.create_index(
            "uq_pending_fires_legacy_fire",
            "pending_fires",
            ["fire_id"],
            unique=True,
            sqlite_where=sa.text("receipt_control_token IS NULL"),
            postgresql_where=sa.text("receipt_control_token IS NULL"),
        )


def _ensure_d_shapes(bind: sa.engine.Connection) -> None:
    for table in (
        ScheduleRevisionState.__table__,
        ScheduleChangeLog.__table__,
        ScheduleTerminalHold.__table__,
        ScheduleOccurrenceResolution.__table__,
        ScheduleExternalStream.__table__,
        ScheduleExternalStreamEpoch.__table__,
        ScheduleExternalProjection.__table__,
        ScheduleExternalSnapshotFrame.__table__,
        ScheduleExternalControlOperation.__table__,
        ScheduleOwnerCutover.__table__,
        ScheduleExternalEpochAllocator.__table__,
    ):
        _ensure_table(bind, table)

    _ensure_columns(
        bind,
        Schedule.__table__,
        (
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
        ),
    )
    _ensure_columns(
        bind,
        ScheduleRevisionState.__table__,
        (
            "guard_version",
            "activation_id",
            "activation_manifest_digest",
            "activation_audit_id",
        ),
    )
    executor_columns = (
        "executor_agent_id",
        "executor_registry_owner_id",
        "executor_session_generation",
        "executor_worker_id",
    )
    _ensure_columns(
        bind,
        ScheduleExternalStream.__table__,
        executor_columns,
    )
    _ensure_columns(
        bind,
        ScheduleExternalStreamEpoch.__table__,
        executor_columns,
    )
    _ensure_executor_authority_constraints(bind)
    _ensure_columns(
        bind,
        Command.__table__,
        (
            "schedule_protocol_marker",
            "schedule_state_nonce",
            "schedule_id",
            "schedule_fire_id",
            "schedule_scheduled_for",
            "schedule_observed_control_token",
            "schedule_receipt_control_token",
            "schedule_execution_fire_id",
            "schedule_acceptance_revision",
            "schedule_definition_digest",
            "schedule_expected_revision",
            "schedule_expected_last_run_at",
            "schedule_expected_next_run_at",
            "schedule_next_run_at",
            "cadence_initial_claim_deadline",
            "first_delivery_claimed_at",
            "cadence_redelivery_deadline",
            "delivery_transport_kind",
            "delivery_registry_owner_id",
            "delivery_session_generation",
            "delivery_claim_token",
            "agent_acknowledged_at",
        ),
    )
    _ensure_columns(
        bind,
        ScheduleFire.__table__,
        (
            "scheduler_ack_status",
            "scheduler_acknowledged_at",
            "scheduler_ack_task_id",
            "scheduler_ack_error_code",
            "scheduler_ack_error_message",
            "protocol_marker",
            "state_write_nonce",
            "observed_control_token",
            "receipt_control_token",
            "acceptance_revision",
            "definition_digest",
            "expected_schedule_revision",
            "expected_last_run_at",
            "expected_next_run_at",
            "prepared_next_run_at",
        ),
    )
    _ensure_columns(
        bind,
        PendingFire.__table__,
        (
            "protocol_marker",
            "state_write_nonce",
            "observed_control_token",
            "receipt_control_token",
            "definition_digest",
            "expected_schedule_revision",
            "expected_last_run_at",
            "expected_next_run_at",
            "prepared_next_run_at",
            "acceptance_revision",
            "execution_fire_id",
        ),
    )

    _drop_mutating_foreign_keys(
        bind,
        table="commands",
        columns={"project_id", "agent_id"},
    )
    _drop_mutating_foreign_keys(
        bind,
        table="schedule_fires",
        columns={"schedule_id", "project_id", "command_id"},
    )
    _install_generation_uniqueness(bind)
    _ensure_change_log_gap_constraints(bind)
    if "uq_schedule_external_control_unresolved" not in _index_names(
        bind,
        "schedule_external_control_operations",
    ):
        op.create_index(
            "uq_schedule_external_control_unresolved",
            "schedule_external_control_operations",
            ["stream_id"],
            unique=True,
            sqlite_where=sa.text(
                "status IN ('PENDING', 'CLAIMED', 'AMBIGUOUS')",
            ),
            postgresql_where=sa.text(
                "status IN ('PENDING', 'CLAIMED', 'AMBIGUOUS')",
            ),
        )


def _ensure_executor_authority_constraints(
    bind: sa.engine.Connection,
) -> None:
    """Install the all-null/all-present executor invariant on partial shapes."""

    expression = (
        "("
        "authorized_adapter_instance_id IS NULL "
        "AND executor_agent_id IS NULL "
        "AND executor_registry_owner_id IS NULL "
        "AND executor_session_generation IS NULL"
        ") OR ("
        "authorized_adapter_instance_id IS NOT NULL "
        "AND executor_agent_id IS NOT NULL "
        "AND executor_registry_owner_id IS NOT NULL "
        "AND executor_session_generation IS NOT NULL"
        ")"
    )
    for table_name, constraint_name in (
        (
            "schedule_external_streams",
            "ck_schedule_external_stream_executor_authority",
        ),
        (
            "schedule_external_stream_epochs",
            "ck_schedule_external_epoch_executor_authority",
        ),
    ):
        existing = sa.inspect(bind).get_check_constraints(table_name)
        has_equivalent = any(
            constraint_name == str(item.get("name"))
            or all(
                token in str(item.get("sqltext") or "").lower()
                for token in (
                    "authorized_adapter_instance_id",
                    "executor_agent_id",
                    "executor_registry_owner_id",
                    "executor_session_generation",
                )
            )
            for item in existing
        )
        if has_equivalent:
            continue
        if bind.dialect.name == "sqlite":
            with op.batch_alter_table(table_name) as batch:
                batch.create_check_constraint(
                    constraint_name,
                    expression,
                )
        else:
            op.create_check_constraint(
                constraint_name,
                table_name,
                expression,
            )


def _ensure_change_log_gap_constraints(
    bind: sa.engine.Connection,
) -> None:
    checks = {
        str(item.get("name")): str(item.get("sqltext") or "").lower()
        for item in sa.inspect(bind).get_check_constraints(
            "schedule_change_log",
        )
        if item.get("name")
    }
    kind_name = next(
        (
            name
            for name in checks
            if name == "ck_schedule_change_log_kind"
            or name.endswith("_ck_schedule_change_log_kind")
        ),
        None,
    )
    payload_name = next(
        (
            name
            for name in checks
            if name == "ck_schedule_change_log_payload"
            or name.endswith("_ck_schedule_change_log_payload")
        ),
        None,
    )
    kind_current = kind_name is not None and "'gap'" in checks[kind_name]
    payload_current = payload_name is not None and "'gap'" in checks[payload_name]
    if kind_current and payload_current:
        return
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("schedule_change_log") as batch:
            if kind_name is not None:
                batch.drop_constraint(
                    kind_name,
                    type_="check",
                )
            if payload_name is not None:
                batch.drop_constraint(
                    payload_name,
                    type_="check",
                )
            batch.create_check_constraint(
                "ck_schedule_change_log_kind",
                "change_kind IN ('upsert', 'delete', 'gap')",
            )
            batch.create_check_constraint(
                "ck_schedule_change_log_payload",
                "(change_kind = 'upsert' AND snapshot IS NOT NULL) "
                "OR (change_kind IN ('delete', 'gap') "
                "AND snapshot IS NULL)",
            )
        return
    if kind_name is not None:
        op.drop_constraint(
            kind_name,
            "schedule_change_log",
            type_="check",
        )
    if payload_name is not None:
        op.drop_constraint(
            payload_name,
            "schedule_change_log",
            type_="check",
        )
    op.create_check_constraint(
        "ck_schedule_change_log_kind",
        "schedule_change_log",
        "change_kind IN ('upsert', 'delete', 'gap')",
    )
    op.create_check_constraint(
        "ck_schedule_change_log_payload",
        "schedule_change_log",
        "(change_kind = 'upsert' AND snapshot IS NOT NULL) "
        "OR (change_kind IN ('delete', 'gap') AND snapshot IS NULL)",
    )


def _kind_text(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _normalized_legacy_cursor(value: datetime | None) -> datetime | None:
    """Translate a 1.7 wall-clock cursor into the 1.8 slot domain."""

    if value is None:
        return None
    normalized = normalize_timestamp(value)
    if op.get_context().config.attributes.get(
        "z4j_test_preserve_legacy_cursor_precision",
        False,
    ):
        return normalized
    return normalized.replace(microsecond=0)


def _migration_schedule_values(
    row: Mapping[str, Any],
    *,
    cutoff: datetime,
    revision_number: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    token = uuid.uuid4()
    future = dict(row)
    future.update(
        {
            "control_token": token,
            "legacy_fire_control_token": None,
            "schedule_revision": revision_number,
            "cadence_semantics_version": CADENCE_SEMANTICS_VERSION,
            "cadence_runtime_fingerprint": cadence_runtime_fingerprint(),
            "quarantine_control_token": None,
            "quarantine_code": None,
            "quarantine_detail": None,
            "quarantined_at": None,
            "last_cadence_acceptance_control_token": None,
            "last_cadence_acceptance_fire_id": None,
            "last_cadence_acceptance_scheduled_for": None,
            "last_cadence_acceptance_revision": None,
        }
    )
    classification = "external"
    legacy_cursor_normalized = False
    if row["scheduler"] == "z4j-scheduler":
        classification = "reserved-valid"
        normalized_last = _normalized_legacy_cursor(row["last_run_at"])
        legacy_cursor_normalized = normalized_last != row["last_run_at"]
        future["last_run_at"] = normalized_last
        try:
            successor = canonical_next_run_at(
                kind=_kind_text(row["kind"]),
                expression=str(row["expression"]),
                timezone=str(row["timezone"]),
                last_run_at=normalized_last,
                anchor_at=cutoff,
            )
            if (
                bool(row["is_enabled"])
                and successor is None
                and _kind_text(row["kind"]) not in {"clocked", "one_shot"}
            ):
                raise ScheduleCadenceError(  # noqa: TRY301
                    "enabled repeating schedule has no canonical successor",
                )
            if bool(row["is_enabled"]):
                future["next_run_at"] = successor
        except (ScheduleCadenceError, ValueError, TypeError):
            classification = "reserved-invalid-quarantined"
            future.update(
                {
                    "is_enabled": False,
                    "quarantine_control_token": token,
                    "quarantine_code": "migration_definition_invalid",
                    "quarantine_detail": (
                        "Definition could not be validated during Boundary-D activation"
                    ),
                    "quarantined_at": cutoff,
                }
            )
    future["definition_digest"] = schedule_definition_digest(future)
    values = {
        key: future[key]
        for key in (
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
        )
    }
    if "next_run_at" in future and future["next_run_at"] != row["next_run_at"]:
        values["next_run_at"] = future["next_run_at"]
    if future["last_run_at"] != row["last_run_at"]:
        values["last_run_at"] = future["last_run_at"]
    if future["is_enabled"] != row["is_enabled"]:
        values["is_enabled"] = future["is_enabled"]
    manifest = {
        "schedule_id": str(row["id"]),
        "project_id": str(row["project_id"]),
        "scheduler": str(row["scheduler"]),
        "classification": classification,
        "control_token": str(token),
        "schedule_revision": revision_number,
        "definition_digest": future["definition_digest"],
        "quarantine_code": future["quarantine_code"],
        "legacy_cursor_normalized": legacy_cursor_normalized,
        "last_run_at": (
            normalize_timestamp(future["last_run_at"]).isoformat(
                timespec="microseconds",
            )
            if future.get("last_run_at") is not None
            else None
        ),
        "next_run_at": (
            normalize_timestamp(future["next_run_at"]).isoformat(
                timespec="microseconds",
            )
            if future.get("next_run_at") is not None
            else None
        ),
    }
    return values, manifest


def _backfill_schedules(
    bind: sa.engine.Connection,
    *,
    cutoff: datetime,
) -> tuple[int, list[dict[str, Any]]]:
    table = Schedule.__table__
    rows = (
        bind.execute(
            sa.select(table).order_by(table.c.id),
        )
        .mappings()
        .all()
    )
    manifest_rows: list[dict[str, Any]] = []
    for revision_number, row in enumerate(rows, start=1):
        if any(
            row[name] is not None
            for name in (
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
            )
        ):
            raise CommandError(
                "schedule already carries partial Boundary-D authority",
            )
        values, manifest = _migration_schedule_values(
            row,
            cutoff=cutoff,
            revision_number=revision_number,
        )
        result = bind.execute(
            table.update().where(table.c.id == row["id"]).values(**values),
        )
        if result.rowcount != 1:
            raise CommandError("schedule backfill did not update exactly one row")
        manifest_rows.append(manifest)
    return len(rows), manifest_rows


def _external_scope(owner: str) -> tuple[str, str]:
    payload = {
        "kind": "scheduler-owner",
        "owner": owner,
        "version": 1,
    }
    encoded = canonical_json(payload)
    return encoded.decode("utf-8"), hashlib.sha256(encoded).hexdigest()


def _backfill_external_authority(
    bind: sa.engine.Connection,
    *,
    cutoff: datetime,
    schedule_manifest: list[dict[str, Any]],
) -> tuple[int, list[dict[str, Any]]]:
    """Bind every legacy external owner to an inert Brain-issued epoch.

    The epoch is intentionally left ``ACTIVATING`` with no authorized adapter
    and a visible ``legacy_emitters_must_be_quiesced`` requirement.  Existing
    unsequenced events therefore cannot acquire authority merely because the
    schema now has epoch columns.
    """

    schedule_table = Schedule.__table__
    rows = (
        bind.execute(
            sa.select(schedule_table)
            .where(schedule_table.c.scheduler != "z4j-scheduler")
            .order_by(
                schedule_table.c.project_id,
                schedule_table.c.scheduler,
                schedule_table.c.name,
                schedule_table.c.id,
            ),
        )
        .mappings()
        .all()
    )
    groups: dict[tuple[uuid.UUID, str], list[Mapping[str, Any]]] = {}
    for row in rows:
        groups.setdefault(
            (row["project_id"], str(row["scheduler"])),
            [],
        ).append(row)

    manifests_by_id = {str(item["schedule_id"]): item for item in schedule_manifest}
    stream_manifests: list[dict[str, Any]] = []
    for epoch_number, ((project_id, owner), members) in enumerate(
        sorted(
            groups.items(),
            key=lambda item: (str(item[0][0]), item[0][1]),
        ),
        start=1,
    ):
        stream_id = uuid.uuid4()
        epoch_uuid = uuid.uuid4()
        source_scope, source_scope_digest = _external_scope(owner)
        requirement = "legacy_emitters_must_be_quiesced"
        bind.execute(
            ScheduleExternalStream.__table__.insert().values(
                id=stream_id,
                project_id=project_id,
                owner=owner,
                source_scope=source_scope,
                source_scope_digest=source_scope_digest,
                current_epoch_uuid=epoch_uuid,
                current_epoch_number=epoch_number,
                phase="ACTIVATING",
                authorized_adapter_instance_id=None,
                accepted_sequence=0,
                sealed_sequence=None,
                last_snapshot_digest=None,
                last_projection_digest=None,
                activation_requirement=requirement,
                created_at=cutoff,
                updated_at=cutoff,
            ),
        )
        bind.execute(
            ScheduleExternalStreamEpoch.__table__.insert().values(
                epoch_uuid=epoch_uuid,
                epoch_number=epoch_number,
                stream_id=stream_id,
                phase="ACTIVATING",
                authorized_adapter_instance_id=None,
                accepted_sequence=0,
                sealed_sequence=None,
                last_snapshot_digest=None,
                last_projection_digest=None,
                activation_requirement=requirement,
                created_at=cutoff,
                activated_at=None,
                sealed_at=None,
                retired_at=None,
            ),
        )
        member_manifest: list[dict[str, Any]] = []
        for member in members:
            source_key = str(member["name"])
            result = bind.execute(
                schedule_table.update()
                .where(schedule_table.c.id == member["id"])
                .values(
                    external_stream_id=stream_id,
                    external_epoch_uuid=epoch_uuid,
                    external_epoch_number=epoch_number,
                    external_source_key=source_key,
                    external_source_sequence=0,
                ),
            )
            if result.rowcount != 1:
                raise CommandError(
                    "external schedule backfill did not update exactly one row",
                )
            binding = {
                "schedule_id": str(member["id"]),
                "source_key": source_key,
            }
            member_manifest.append(binding)
            schedule_item = manifests_by_id[str(member["id"])]
            schedule_item.update(
                {
                    "external_stream_id": str(stream_id),
                    "external_epoch_uuid": str(epoch_uuid),
                    "external_epoch_number": epoch_number,
                    "external_source_key": source_key,
                    "external_source_sequence": 0,
                },
            )
        stream_manifests.append(
            {
                "stream_id": str(stream_id),
                "project_id": str(project_id),
                "owner": owner,
                "source_scope": source_scope,
                "source_scope_digest": source_scope_digest,
                "epoch_uuid": str(epoch_uuid),
                "epoch_number": epoch_number,
                "phase": "ACTIVATING",
                "accepted_sequence": 0,
                "activation_requirement": requirement,
                "schedules": member_manifest,
            },
        )
    return len(groups), stream_manifests


def _backfill_evidence(bind: sa.engine.Connection) -> dict[str, int]:
    command_table = Command.__table__
    fire_table = ScheduleFire.__table__
    pending_table = PendingFire.__table__

    legacy_commands = (
        bind.execute(
            sa.select(command_table.c.id).where(
                command_table.c.action == "schedule.fire",
            ),
        )
        .scalars()
        .all()
    )
    for command_id in legacy_commands:
        values: dict[str, Any] = {
            "schedule_protocol_marker": 1,
            "schedule_state_nonce": uuid.uuid4(),
        }
        linked = (
            bind.execute(
                sa.select(
                    fire_table.c.schedule_id,
                    fire_table.c.fire_id,
                    fire_table.c.scheduled_for,
                ).where(fire_table.c.command_id == command_id),
            )
            .mappings()
            .all()
        )
        if len(linked) == 1:
            values.update(
                {
                    "schedule_id": linked[0]["schedule_id"],
                    "schedule_fire_id": linked[0]["fire_id"],
                    "schedule_scheduled_for": linked[0]["scheduled_for"],
                }
            )
        bind.execute(
            command_table.update().where(command_table.c.id == command_id).values(**values),
        )

    fire_ids = bind.execute(sa.select(fire_table.c.id)).scalars().all()
    for row_id in fire_ids:
        bind.execute(
            fire_table.update()
            .where(fire_table.c.id == row_id)
            .values(
                protocol_marker=1,
                state_write_nonce=uuid.uuid4(),
            ),
        )
    pending_ids = bind.execute(sa.select(pending_table.c.id)).scalars().all()
    for row_id in pending_ids:
        bind.execute(
            pending_table.update()
            .where(pending_table.c.id == row_id)
            .values(
                protocol_marker=1,
                state_write_nonce=uuid.uuid4(),
            ),
        )
    return {
        "schedule_fire_commands": len(legacy_commands),
        "schedule_fires": len(fire_ids),
        "pending_fires": len(pending_ids),
    }


def _enforce_schedule_identity_constraints(
    bind: sa.engine.Connection,
) -> None:
    names = (
        "control_token",
        "schedule_revision",
        "definition_digest",
        "cadence_semantics_version",
        "cadence_runtime_fingerprint",
    )
    pairing_expression = (
        "("
        "scheduler = 'z4j-scheduler' "
        "AND external_stream_id IS NULL "
        "AND external_epoch_uuid IS NULL "
        "AND external_epoch_number IS NULL "
        "AND external_source_key IS NULL "
        "AND external_source_sequence IS NULL"
        ") OR ("
        "scheduler <> 'z4j-scheduler' "
        "AND external_stream_id IS NOT NULL "
        "AND external_epoch_uuid IS NOT NULL "
        "AND external_epoch_number > 0 "
        "AND external_source_key IS NOT NULL "
        "AND length(external_source_key) > 0 "
        "AND external_source_sequence >= 0"
        ")"
    )
    check_names = {
        str(item.get("name"))
        for item in sa.inspect(bind).get_check_constraints("schedules")
        if item.get("name")
    }
    pairing_missing = "ck_schedules_external_authority_pairing" not in check_names
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("schedules") as batch:
            for name in names:
                batch.alter_column(
                    name,
                    existing_type=Schedule.__table__.c[name].type,
                    nullable=False,
                    server_default=None,
                )
            if pairing_missing:
                batch.create_check_constraint(
                    "ck_schedules_external_authority_pairing",
                    pairing_expression,
                )
    else:
        for name in names:
            op.alter_column(
                "schedules",
                name,
                existing_type=Schedule.__table__.c[name].type,
                nullable=False,
                server_default=None,
            )
        if pairing_missing:
            op.create_check_constraint(
                "ck_schedules_external_authority_pairing",
                "schedules",
                pairing_expression,
            )
    if "uq_schedules_external_stream_source_key" not in _index_names(
        bind,
        "schedules",
    ):
        op.create_index(
            "uq_schedules_external_stream_source_key",
            "schedules",
            ["external_stream_id", "external_source_key"],
            unique=True,
            sqlite_where=sa.text("external_stream_id IS NOT NULL"),
            postgresql_where=sa.text("external_stream_id IS NOT NULL"),
        )


def _prepare_revision_state(
    bind: sa.engine.Connection,
    *,
    backfill_revision: int,
) -> None:
    table = ScheduleRevisionState.__table__
    rows = bind.execute(sa.select(table)).mappings().all()
    if not rows:
        bind.execute(
            table.insert().values(
                singleton_id=_STATE_ID,
                current_revision=backfill_revision,
                change_log_pruned_through=backfill_revision,
                guard_version=None,
                activation_id=None,
                activation_manifest_digest=None,
                activation_audit_id=None,
            ),
        )
        return
    if len(rows) != 1 or rows[0]["singleton_id"] != _STATE_ID:
        raise CommandError("schedule revision state is malformed before activation")
    row = rows[0]
    if (
        row["guard_version"] is not None
        or row["activation_id"] is not None
        or row["activation_manifest_digest"] is not None
        or row["activation_audit_id"] is not None
    ):
        raise CommandError("schedule revision state is already activated or partial")
    if row["current_revision"] not in {0, backfill_revision}:
        raise CommandError("pre-activation schedule revision state is nonempty")
    bind.execute(
        table.update()
        .where(table.c.singleton_id == _STATE_ID)
        .values(
            current_revision=backfill_revision,
            change_log_pruned_through=backfill_revision,
        ),
    )


def _manifest(
    *,
    cutoff: datetime,
    schedules: list[dict[str, Any]],
    evidence_counts: dict[str, int],
    external_streams: list[dict[str, Any]],
) -> tuple[dict[str, Any], str]:
    body = {
        "format": "z4j-schedule-control-activation-v1",
        "boundary": "D",
        "revision": revision,
        "guard_version": SCHEDULE_GUARD_VERSION,
        "cutoff": cutoff.isoformat(timespec="microseconds"),
        "backfill_revision": len(schedules),
        "change_log_pruned_through": len(schedules),
        "schedule_count": len(schedules),
        "schedule_classifications": dict(
            sorted(Counter(row["classification"] for row in schedules).items())
        ),
        "evidence_counts": evidence_counts,
        "external_epoch_allocator": len(external_streams),
        "external_stream_count": len(external_streams),
        "external_streams": external_streams,
        "schedules": schedules,
        "constraint_version": 2,
        "trigger_version": 2,
    }
    digest = hashlib.sha256(canonical_json(body)).hexdigest()
    return body, digest


def _audit_keyring() -> tuple[str, dict[str, bytes]]:
    settings = settings_from_context()
    secrets = settings.all_audit_chain_secrets_for_verification()
    if not secrets:
        raise CommandError(
            "Boundary-D activation requires the authenticated audit key",
        )
    return build_audit_keyring(secrets[0], secrets[1:])


def _row_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return canonical_row_payload(
        row_id=row["id"],
        action=row["action"],
        target_type=row["target_type"],
        target_id=row["target_id"],
        result=row["result"],
        outcome=row["outcome"],
        event_id=row["event_id"],
        user_id=row["user_id"],
        api_key_id=row["api_key_id"],
        project_id=row["project_id"],
        source_ip=(str(row["source_ip"]) if row["source_ip"] is not None else None),
        user_agent=row["user_agent"],
        metadata=row["metadata"],
        occurred_at=row["occurred_at"],
        prev_row_hmac=row["prev_row_hmac"],
        hmac_key_id=row["hmac_key_id"],
        chain_generation=row["chain_generation"],
    )


def _arm_activation_audit_transition(
    bind: sa.engine.Connection,
) -> None:
    if bind.dialect.name == "postgresql":
        bind.execute(
            sa.text(
                "SELECT set_config('z4j.audit_transition', 'append-v1', true)",
            ),
        )
    else:
        bind.execute(
            sa.text("SELECT z4j_audit_guard('arm', 'append-v1')"),
        )


def _append_activation_audit(
    bind: sa.engine.Connection,
    *,
    activation_id: uuid.UUID,
    manifest: dict[str, Any],
    manifest_digest: str,
) -> uuid.UUID:
    current_key_id, keyring = _audit_keyring()
    with Session(bind=bind, expire_on_commit=False) as session:
        states = list(
            session.execute(
                sa.select(AuditChainState).with_for_update(),
            ).scalars()
        )
        if len(states) != 1:
            raise CommandError(
                "Boundary F is not authenticated and active before D",
            )
        state = states[0]
        try:
            state_payload = authenticate_state(state, keyring)
        except Exception as exc:
            raise CommandError(
                "Boundary-F state failed authentication before D",
            ) from exc
        if state_payload["state_key_id"] != current_key_id:
            raise CommandError(
                "configured current audit key differs from authenticated state",
            )
        current_secret = keyring[current_key_id]

        active_rows = list(
            session.execute(
                sa.select(AuditLog)
                .where(
                    AuditLog.legacy_frozen.is_(False),
                    AuditLog.chain_generation == state.generation,
                )
                .order_by(AuditLog.occurred_at, AuditLog.id)
                .with_for_update(),
            ).scalars()
        )
        if len(active_rows) != state.active_row_count:
            raise CommandError(
                "active audit row count differs from authenticated state",
            )
        actual_counts = dict(
            Counter(row.hmac_key_id for row in active_rows if row.hmac_key_id is not None)
        )
        if actual_counts != state.active_key_counts:
            raise CommandError(
                "active audit key counts differ from authenticated state",
            )
        head = active_rows[-1] if active_rows else None
        if head is None:
            raise CommandError(
                "Boundary-F active generation has no signed genesis",
            )
        if (
            head.row_hmac != state.head_row_hmac
            or head.hmac_key_id != state.head_hmac_key_id
            or normalize_timestamp(head.occurred_at) != normalize_timestamp(state.head_occurred_at)
            or head.id != state.head_id
        ):
            raise CommandError(
                "live audit head differs from authenticated state",
            )
        head_secret = keyring.get(str(head.hmac_key_id))
        if head_secret is None:
            raise CommandError("active audit head key is unavailable")
        head_mapping = {
            column.name: getattr(head, column.name)
            for column in AuditLog.__table__.columns
            if column.name != "metadata"
        }
        head_mapping["metadata"] = head.audit_metadata
        expected_head_hmac = compute_row_hmac(
            head_secret,
            _row_payload(head_mapping),
        )
        if (
            head.row_hmac is None
            or len(head.row_hmac) != len(expected_head_hmac)
            or not hmac.compare_digest(head.row_hmac, expected_head_hmac)
        ):
            raise CommandError("live audit head HMAC does not authenticate")

        _arm_activation_audit_transition(bind)

        row_id = uuid.uuid4()
        occurred_at = strictly_later_audit_key(
            datetime.now(UTC),
            row_id,
            prior_timestamp=state.head_occurred_at,
            prior_id=state.head_id,
        )
        metadata = {
            "activation_id": str(activation_id),
            "manifest_digest": manifest_digest,
            "manifest": manifest,
        }
        payload = canonical_row_payload(
            row_id=row_id,
            action=_ACTIVATION_ACTION,
            target_type=_ACTIVATION_TARGET,
            target_id=str(activation_id),
            result="success",
            outcome="allow",
            event_id=None,
            user_id=None,
            api_key_id=None,
            project_id=None,
            source_ip=None,
            user_agent=None,
            metadata=metadata,
            occurred_at=occurred_at,
            prev_row_hmac=state.head_row_hmac,
            hmac_key_id=current_key_id,
            chain_generation=state.generation,
        )
        row_hmac = compute_row_hmac(current_secret, payload)
        bind.execute(
            AuditLog.__table__.insert().values(
                id=row_id,
                action=_ACTIVATION_ACTION,
                target_type=_ACTIVATION_TARGET,
                target_id=str(activation_id),
                result="success",
                outcome="allow",
                event_id=None,
                user_id=None,
                api_key_id=None,
                project_id=None,
                source_ip=None,
                user_agent=None,
                metadata=metadata,
                occurred_at=occurred_at,
                prev_row_hmac=state.head_row_hmac,
                row_hmac=row_hmac,
                legacy_frozen=False,
                hmac_version=AUDIT_ROW_HMAC_VERSION,
                hmac_key_id=current_key_id,
                legacy_integrity_class=None,
                legacy_origin=None,
                chain_generation=state.generation,
            ),
        )
        persisted = (
            bind.execute(
                sa.select(AuditLog.__table__).where(
                    AuditLog.__table__.c.id == row_id,
                ),
            )
            .mappings()
            .one()
        )
        if canonical_json(_row_payload(persisted)) != canonical_json(payload):
            raise CommandError(
                "database normalized the signed D activation row differently",
            )

        counts = dict(state.active_key_counts)
        counts[current_key_id] = counts.get(current_key_id, 0) + 1
        next_state = {
            **state_payload,
            "head_row_hmac": row_hmac,
            "head_hmac_key_id": current_key_id,
            "head_occurred_at": persisted["occurred_at"],
            "head_id": row_id,
            "active_row_count": state.active_row_count + 1,
            "active_key_counts": counts,
        }
        state_mac = compute_state_mac(current_secret, next_state)
        result = bind.execute(
            AuditChainState.__table__.update()
            .where(
                AuditChainState.__table__.c.singleton_id == state.singleton_id,
            )
            .values(
                head_row_hmac=row_hmac,
                head_hmac_key_id=current_key_id,
                head_occurred_at=persisted["occurred_at"],
                head_id=row_id,
                active_row_count=state.active_row_count + 1,
                active_key_counts=counts,
                state_mac=state_mac,
            ),
        )
        if result.rowcount != 1:
            raise CommandError(
                "authenticated audit state did not advance exactly once",
            )
    return row_id


def _install_sqlite_schedule_guards() -> None:
    statements = (
        """
        CREATE TRIGGER z4j_schedule_revision_state_update_guard_v1
        BEFORE UPDATE ON schedule_revision_state
        FOR EACH ROW
        WHEN OLD.guard_version = 1
        BEGIN
          SELECT CASE
            WHEN z4j_schedule_guard(
                   'is_reset', '', '', 0, 0, '', '', ''
                 ) = 1
              AND (
                NEW.singleton_id <> OLD.singleton_id
                OR NEW.guard_version <> OLD.guard_version
                OR NEW.activation_id <> OLD.activation_id
                OR NEW.activation_manifest_digest
                     <> OLD.activation_manifest_digest
                OR NEW.activation_audit_id <> OLD.activation_audit_id
                OR NEW.current_revision <> OLD.current_revision + 1
                OR NEW.change_log_pruned_through
                     <> NEW.current_revision
              )
            THEN RAISE(ABORT, 'invalid schedule reset barrier')
            WHEN z4j_schedule_guard(
                   'is_restore', '', '', 0, 0, '', '', ''
                 ) = 1
              AND (
                NEW.singleton_id <> OLD.singleton_id
                OR NEW.guard_version <> OLD.guard_version
                OR NEW.activation_id <> OLD.activation_id
                OR NEW.activation_manifest_digest
                     <> OLD.activation_manifest_digest
                OR NEW.activation_audit_id <> OLD.activation_audit_id
              )
            THEN RAISE(ABORT, 'invalid schedule restore barrier')
            WHEN z4j_schedule_guard(
                   'is_reset', '', '', 0, 0, '', '', ''
                 ) = 0
              AND z4j_schedule_guard(
                    'is_restore', '', '', 0, 0, '', '', ''
                  ) = 0
              AND (
              NEW.singleton_id <> OLD.singleton_id
              OR NEW.guard_version <> OLD.guard_version
              OR NEW.activation_id <> OLD.activation_id
              OR NEW.activation_manifest_digest
                   <> OLD.activation_manifest_digest
              OR NEW.activation_audit_id <> OLD.activation_audit_id
              OR NOT (
                (
                  NEW.current_revision = OLD.current_revision + 1
                  AND NEW.change_log_pruned_through
                    = OLD.change_log_pruned_through
                )
                OR (
                  NEW.current_revision = OLD.current_revision
                  AND NEW.change_log_pruned_through
                    > OLD.change_log_pruned_through
                  AND NEW.change_log_pruned_through
                    <= OLD.current_revision
                )
              )
              )
            THEN RAISE(ABORT, 'invalid schedule revision allocation')
          END;
          SELECT CASE
            WHEN z4j_schedule_guard(
                   'is_reset', '', '', 0, 0, '', '', ''
                 ) = 0
              AND z4j_schedule_guard(
                    'is_restore', '', '', 0, 0, '', '', ''
                  ) = 0
              AND NEW.current_revision = OLD.current_revision + 1
            THEN z4j_schedule_guard(
              'consume_allocation', '', '', 0, 0, '', '', ''
            )
          END;
          SELECT CASE
            WHEN z4j_schedule_guard(
                   'is_reset', '', '', 0, 0, '', '', ''
                 ) = 0
              AND z4j_schedule_guard(
                    'is_restore', '', '', 0, 0, '', '', ''
                  ) = 0
              AND NEW.current_revision = OLD.current_revision
            THEN z4j_schedule_guard(
              'finalize_prune',
              OLD.change_log_pruned_through,
              NEW.change_log_pruned_through,
              0,
              0,
              '',
              '',
              ''
            )
          END;
          SELECT CASE
            WHEN z4j_schedule_guard(
                   'is_reset', '', '', 0, 0, '', '', ''
                 ) = 1
            THEN z4j_schedule_guard(
              'consume_reset_revision', '', '',
              OLD.current_revision, NEW.current_revision, '', '', ''
            )
          END;
          SELECT CASE
            WHEN z4j_schedule_guard(
                   'is_restore', '', '', 0, 0, '', '', ''
                 ) = 1
            THEN z4j_schedule_guard(
              'consume_restore_revision',
              OLD.change_log_pruned_through,
              NEW.change_log_pruned_through,
              OLD.current_revision,
              NEW.current_revision,
              '',
              '',
              ''
            )
          END;
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_revision_state_insert_guard_v1
        BEFORE INSERT ON schedule_revision_state
        FOR EACH ROW
        WHEN EXISTS (
          SELECT 1 FROM schedule_revision_state
          WHERE singleton_id = 'schedule-revision' AND guard_version = 1
        )
        BEGIN
          SELECT RAISE(ABORT, 'schedule revision state is a singleton');
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_revision_state_delete_guard_v1
        BEFORE DELETE ON schedule_revision_state
        FOR EACH ROW
        WHEN OLD.guard_version = 1
        BEGIN
          SELECT RAISE(ABORT, 'schedule revision state is protected');
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_insert_guard_v1
        BEFORE INSERT ON schedules
        FOR EACH ROW
        WHEN (
          SELECT guard_version FROM schedule_revision_state
          WHERE singleton_id = 'schedule-revision'
        ) = 1
          AND z4j_schedule_guard(
            'is_reset', '', '', 0, 0, '', '', ''
          ) = 0
        BEGIN
          SELECT CASE
            WHEN NEW.control_token IS NULL
              OR NEW.schedule_revision IS NULL
              OR NEW.schedule_revision <= 0
              OR NEW.definition_digest IS NULL
              OR NEW.cadence_semantics_version IS NULL
              OR NEW.cadence_runtime_fingerprint IS NULL
            THEN RAISE(ABORT, 'schedule D identity is incomplete')
          END;
          SELECT CASE
            WHEN (
              SELECT COUNT(*) FROM schedule_change_log
              WHERE revision = NEW.schedule_revision
                AND schedule_id = NEW.id
                AND project_id = NEW.project_id
                AND change_kind = CASE
                  WHEN NEW.scheduler = 'z4j-scheduler'
                  THEN 'upsert' ELSE 'gap'
                END
                AND protocol_version = 1
                AND (
                  (
                    NEW.scheduler = 'z4j-scheduler'
                    AND CAST(
                      json_extract(
                        snapshot,
                        '$.schedule.schedule_revision'
                      ) AS INTEGER
                    ) = NEW.schedule_revision
                  )
                  OR (
                    NEW.scheduler <> 'z4j-scheduler'
                    AND snapshot IS NULL
                  )
                )
            ) <> 1
            THEN RAISE(ABORT, 'schedule insert lacks exact change envelope')
          END;
          SELECT z4j_schedule_guard(
            'consume_transition', 'insert', NEW.id, 0,
            NEW.schedule_revision,
            CASE WHEN NEW.scheduler = 'z4j-scheduler'
              THEN 'upsert' ELSE 'gap' END,
            '', NEW.control_token
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_update_guard_v1
        BEFORE UPDATE ON schedules
        FOR EACH ROW
        WHEN (
          SELECT guard_version FROM schedule_revision_state
          WHERE singleton_id = 'schedule-revision'
        ) = 1
          AND z4j_schedule_guard(
            'is_reset', '', '', 0, 0, '', '', ''
          ) = 0
        BEGIN
          SELECT CASE
            WHEN NEW.id <> OLD.id
              OR NEW.project_id <> OLD.project_id
              OR NEW.control_token IS NULL
              OR NEW.schedule_revision IS NULL
              OR NEW.schedule_revision <= OLD.schedule_revision
              OR NEW.definition_digest IS NULL
              OR NEW.cadence_semantics_version IS NULL
              OR NEW.cadence_runtime_fingerprint IS NULL
            THEN RAISE(ABORT, 'invalid schedule transition identity')
          END;
          SELECT CASE
            WHEN (
              SELECT COUNT(*) FROM schedule_change_log
              WHERE revision = NEW.schedule_revision
                AND schedule_id = NEW.id
                AND project_id = NEW.project_id
                AND change_kind = CASE
                  WHEN OLD.scheduler = 'z4j-scheduler'
                    AND NEW.scheduler <> 'z4j-scheduler'
                  THEN 'delete'
                  WHEN NEW.scheduler = 'z4j-scheduler'
                  THEN 'upsert' ELSE 'gap'
                END
                AND protocol_version = 1
                AND (
                  (
                    NEW.scheduler = 'z4j-scheduler'
                    AND CAST(
                      json_extract(
                        snapshot,
                        '$.schedule.schedule_revision'
                      ) AS INTEGER
                    ) = NEW.schedule_revision
                  )
                  OR (
                    NEW.scheduler <> 'z4j-scheduler'
                    AND snapshot IS NULL
                  )
                )
            ) <> 1
            THEN RAISE(ABORT, 'schedule update lacks exact change envelope')
          END;
          SELECT CASE
            WHEN NEW.control_token = OLD.control_token
              AND (
                NEW.definition_digest IS NOT OLD.definition_digest
                OR NEW.is_enabled IS NOT OLD.is_enabled
                OR NEW.legacy_fire_control_token
                     IS NOT OLD.legacy_fire_control_token
                OR NEW.quarantine_control_token
                     IS NOT OLD.quarantine_control_token
                OR NEW.quarantine_code IS NOT OLD.quarantine_code
                OR NEW.quarantine_detail IS NOT OLD.quarantine_detail
                OR NEW.quarantined_at IS NOT OLD.quarantined_at
              )
              AND COALESCE((
                SELECT json_extract(snapshot, '$.transition.kind')
                FROM schedule_change_log
                WHERE revision = NEW.schedule_revision
              ), '') NOT IN (
                'accept_fire',
                'accept_legacy_fire',
                'skip_no_work',
                'terminal_fire',
                'legacy_fire_grant',
                'definition_quarantine',
                'resolve_occurrence',
                'database_restore_rebase'
              )
            THEN RAISE(ABORT, 'unnamed same-token schedule transition')
          END;
          SELECT CASE
            WHEN NEW.control_token <> OLD.control_token
              AND COALESCE((
                SELECT json_extract(snapshot, '$.transition.kind')
                FROM schedule_change_log
                WHERE revision = NEW.schedule_revision
              ), '') <> 'resolve_occurrence'
              AND (
                NEW.legacy_fire_control_token IS NOT NULL
                OR NEW.quarantine_control_token IS NOT NULL
                OR NEW.quarantine_code IS NOT NULL
                OR NEW.quarantine_detail IS NOT NULL
                OR NEW.quarantined_at IS NOT NULL
              )
            THEN RAISE(ABORT, 'control rotation retained stale authority')
          END;
          SELECT z4j_schedule_guard(
            CASE
              WHEN z4j_schedule_guard(
                'is_restore', '', '', 0, 0, '', '', ''
              ) = 1
              THEN 'consume_restore_schedule'
              ELSE 'consume_transition'
            END,
            'update', NEW.id,
            OLD.schedule_revision, NEW.schedule_revision,
            CASE
              WHEN OLD.scheduler = 'z4j-scheduler'
                AND NEW.scheduler <> 'z4j-scheduler'
              THEN 'delete'
              WHEN NEW.scheduler = 'z4j-scheduler'
              THEN 'upsert' ELSE 'gap'
            END,
            OLD.control_token, NEW.control_token
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_delete_guard_v1
        BEFORE DELETE ON schedules
        FOR EACH ROW
        WHEN (
          SELECT guard_version FROM schedule_revision_state
          WHERE singleton_id = 'schedule-revision'
        ) = 1
          AND z4j_schedule_guard(
            'is_reset', '', '', 0, 0, '', '', ''
          ) = 0
        BEGIN
          SELECT CASE
            WHEN (
              SELECT COUNT(*) FROM schedule_change_log
              WHERE schedule_id = OLD.id
                AND project_id = OLD.project_id
                AND change_kind = CASE
                  WHEN OLD.scheduler = 'z4j-scheduler'
                  THEN 'delete' ELSE 'gap'
                END
                AND protocol_version = 1
                AND revision > OLD.schedule_revision
            ) <> 1
            THEN RAISE(ABORT, 'schedule delete lacks exact tombstone')
          END;
          SELECT z4j_schedule_guard(
            'consume_transition', 'delete', OLD.id,
            OLD.schedule_revision,
            (
              SELECT revision FROM schedule_change_log
              WHERE schedule_id = OLD.id
                AND project_id = OLD.project_id
                AND change_kind = CASE
                  WHEN OLD.scheduler = 'z4j-scheduler'
                  THEN 'delete' ELSE 'gap'
                END
                AND revision > OLD.schedule_revision
            ),
            CASE WHEN OLD.scheduler = 'z4j-scheduler'
              THEN 'delete' ELSE 'gap' END,
            OLD.control_token, ''
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_change_log_update_guard_v1
        BEFORE UPDATE ON schedule_change_log
        FOR EACH ROW
        BEGIN
          SELECT RAISE(ABORT, 'schedule change log is immutable');
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_change_log_delete_guard_v1
        BEFORE DELETE ON schedule_change_log
        FOR EACH ROW
        WHEN z4j_schedule_guard(
          'is_reset', '', '', 0, 0, '', '', ''
        ) = 0
        BEGIN
          SELECT z4j_schedule_guard(
            'consume_prune',
            '',
            '',
            OLD.revision,
            0,
            '',
            '',
            ''
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_reset_schedule_delete_guard_v1
        BEFORE DELETE ON schedules
        FOR EACH ROW
        WHEN z4j_schedule_guard(
          'is_reset', '', '', 0, 0, '', '', ''
        ) = 1
        BEGIN
          SELECT z4j_schedule_guard(
            'consume_reset_row', 'schedules', OLD.id, 0, 0, '', '', ''
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_reset_change_log_delete_guard_v1
        BEFORE DELETE ON schedule_change_log
        FOR EACH ROW
        WHEN z4j_schedule_guard(
          'is_reset', '', '', 0, 0, '', '', ''
        ) = 1
        BEGIN
          SELECT z4j_schedule_guard(
            'consume_reset_row', 'schedule_change_log', OLD.revision,
            0, 0, '', '', ''
          );
        END
        """,
    )
    for statement in statements:
        op.execute(sa.text(statement))


def _complete_command_tuple(prefix: str) -> str:
    fields = (
        "schedule_id",
        "schedule_fire_id",
        "schedule_scheduled_for",
        "schedule_receipt_control_token",
        "schedule_execution_fire_id",
        "schedule_acceptance_revision",
        "schedule_definition_digest",
        "schedule_expected_revision",
        "schedule_expected_next_run_at",
        "cadence_initial_claim_deadline",
    )
    return " AND ".join(f"{prefix}.{field} IS NOT NULL" for field in fields)


def _complete_fire_tuple(prefix: str) -> str:
    fields = (
        "receipt_control_token",
        "acceptance_revision",
        "definition_digest",
        "expected_schedule_revision",
        "expected_next_run_at",
    )
    return " AND ".join(f"{prefix}.{field} IS NOT NULL" for field in fields)


def _complete_pending_tuple(prefix: str) -> str:
    fields = (
        "receipt_control_token",
        "definition_digest",
        "expected_schedule_revision",
        "expected_next_run_at",
        "acceptance_revision",
        "execution_fire_id",
    )
    return " AND ".join(f"{prefix}.{field} IS NOT NULL" for field in fields)


def _install_sqlite_evidence_guards() -> None:
    command_complete = _complete_command_tuple("NEW")
    fire_complete = _complete_fire_tuple("NEW")
    pending_complete = _complete_pending_tuple("NEW")
    statements = (
        f"""
        CREATE TRIGGER z4j_schedule_command_insert_guard_v1
        BEFORE INSERT ON commands
        FOR EACH ROW
        WHEN NEW.action = 'schedule.fire'
        BEGIN
          SELECT CASE
            WHEN NEW.schedule_protocol_marker IS NOT 1
              OR NEW.schedule_state_nonce IS NULL
            THEN RAISE(ABORT, 'schedule command protocol marker required')
          END;
          SELECT CASE
            WHEN NEW.schedule_receipt_control_token IS NULL
              OR NOT ({command_complete})
            THEN RAISE(
              ABORT,
              'current schedule command receipt tuple is required'
            )
          END;
        END
        """,
        f"""
        CREATE TRIGGER z4j_schedule_command_update_guard_v1
        BEFORE UPDATE ON commands
        FOR EACH ROW
        WHEN OLD.action = 'schedule.fire'
          AND OLD.schedule_protocol_marker = 1
          AND z4j_schedule_guard(
            'is_reset', '', '', 0, 0, '', '', ''
          ) = 0
        BEGIN
          SELECT CASE
            WHEN NEW.action <> OLD.action
              OR NEW.schedule_protocol_marker IS NOT 1
              OR NEW.schedule_state_nonce IS NULL
              OR NEW.schedule_state_nonce = OLD.schedule_state_nonce
              OR NEW.id <> OLD.id
              OR NEW.project_id <> OLD.project_id
              OR NEW.target_type <> OLD.target_type
              OR NEW.target_id IS NOT OLD.target_id
              OR NEW.payload IS NOT OLD.payload
              OR NEW.idempotency_key IS NOT OLD.idempotency_key
              OR NEW.issued_at IS NOT OLD.issued_at
              OR NEW.source_ip IS NOT OLD.source_ip
              OR NEW.bulk_retry_child_id IS NOT OLD.bulk_retry_child_id
              OR NOT (
                NEW.issued_by IS OLD.issued_by
                OR (
                  OLD.issued_by IS NOT NULL
                  AND NEW.issued_by IS NULL
                )
              )
              OR NEW.schedule_id IS NOT OLD.schedule_id
              OR NEW.schedule_fire_id IS NOT OLD.schedule_fire_id
              OR NEW.schedule_scheduled_for IS NOT OLD.schedule_scheduled_for
              OR NEW.schedule_observed_control_token
                   IS NOT OLD.schedule_observed_control_token
              OR NEW.schedule_receipt_control_token
                   IS NOT OLD.schedule_receipt_control_token
              OR NEW.schedule_execution_fire_id
                   IS NOT OLD.schedule_execution_fire_id
              OR NEW.schedule_acceptance_revision
                   IS NOT OLD.schedule_acceptance_revision
              OR NEW.schedule_definition_digest
                   IS NOT OLD.schedule_definition_digest
              OR NEW.schedule_expected_revision
                   IS NOT OLD.schedule_expected_revision
              OR NEW.schedule_expected_last_run_at
                   IS NOT OLD.schedule_expected_last_run_at
              OR NEW.schedule_expected_next_run_at
                   IS NOT OLD.schedule_expected_next_run_at
              OR NEW.schedule_next_run_at IS NOT OLD.schedule_next_run_at
              OR NEW.cadence_initial_claim_deadline
                   IS NOT OLD.cadence_initial_claim_deadline
              OR (
                (
                  NEW.first_delivery_claimed_at
                    IS NOT OLD.first_delivery_claimed_at
                  OR NEW.cadence_redelivery_deadline
                    IS NOT OLD.cadence_redelivery_deadline
                  OR NEW.delivery_transport_kind
                    IS NOT OLD.delivery_transport_kind
                  OR NEW.delivery_registry_owner_id
                    IS NOT OLD.delivery_registry_owner_id
                  OR NEW.delivery_session_generation
                    IS NOT OLD.delivery_session_generation
                  OR NEW.delivery_claim_token
                    IS NOT OLD.delivery_claim_token
                )
                AND NOT (
                  OLD.status = 'pending'
                  AND NEW.status = 'dispatched'
                  AND OLD.first_delivery_claimed_at IS NULL
                  AND OLD.cadence_redelivery_deadline IS NULL
                  AND OLD.delivery_transport_kind IS NULL
                  AND OLD.delivery_registry_owner_id IS NULL
                  AND OLD.delivery_session_generation IS NULL
                  AND OLD.delivery_claim_token IS NULL
                  AND NEW.first_delivery_claimed_at IS NOT NULL
                  AND NEW.cadence_redelivery_deadline IS NOT NULL
                  AND NEW.delivery_transport_kind IN (
                    'websocket',
                    'longpoll'
                  )
                  AND NEW.delivery_registry_owner_id IS NOT NULL
                  AND NEW.delivery_session_generation IS NOT NULL
                  AND NEW.delivery_claim_token IS NOT NULL
                )
              )
              OR (
                NEW.agent_acknowledged_at
                  IS NOT OLD.agent_acknowledged_at
                AND NOT (
                  OLD.agent_acknowledged_at IS NULL
                  AND NEW.agent_acknowledged_at IS NOT NULL
                  AND OLD.status IN (
                    'dispatched',
                    'completed',
                    'failed',
                    'cancelled',
                    'timeout'
                  )
                  AND NEW.status IN (
                    'dispatched',
                    'completed',
                    'failed',
                    'cancelled',
                    'timeout'
                  )
                )
              )
              OR (
                NEW.agent_id IS NOT OLD.agent_id
                AND NOT (
                  OLD.status = 'pending'
                  AND NEW.status = 'pending'
                  AND OLD.first_delivery_claimed_at IS NULL
                  AND NEW.first_delivery_claimed_at IS NULL
                  AND OLD.delivery_claim_token IS NULL
                  AND NEW.delivery_claim_token IS NULL
                )
              )
              OR NOT (
                NEW.status = OLD.status
                OR (
                  OLD.status = 'pending'
                  AND NEW.status IN ('dispatched', 'timeout')
                )
                OR (
                  OLD.status = 'dispatched'
                  AND NEW.status IN (
                    'completed',
                    'failed',
                    'cancelled',
                    'timeout'
                  )
                )
              )
              OR (
                NEW.timeout_at IS NOT OLD.timeout_at
                AND NOT (
                  OLD.status = 'pending'
                  AND NEW.status = 'dispatched'
                )
              )
              OR (
                NEW.dispatched_at IS NOT OLD.dispatched_at
                AND NOT (
                  (
                    OLD.status = 'pending'
                    AND NEW.status = 'dispatched'
                    AND OLD.dispatched_at IS NULL
                    AND NEW.dispatched_at IS NOT NULL
                  )
                  OR (
                    OLD.status = 'dispatched'
                    AND NEW.status = 'dispatched'
                    AND OLD.dispatched_at IS NOT NULL
                    AND NEW.dispatched_at IS NOT NULL
                    AND OLD.agent_acknowledged_at IS NULL
                  )
                )
              )
              OR (
                (
                  NEW.completed_at IS NOT OLD.completed_at
                  OR NEW.result IS NOT OLD.result
                  OR NEW.error IS NOT OLD.error
                )
                AND NOT (
                  NEW.status IN (
                    'completed',
                    'failed',
                    'cancelled',
                    'timeout'
                  )
                  AND NEW.status <> OLD.status
                  AND NEW.completed_at IS NOT NULL
                )
              )
              OR (
                NEW.schedule_receipt_control_token IS NOT NULL
                AND NOT ({command_complete})
              )
            THEN RAISE(ABORT, 'invalid schedule command transition')
          END;
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_command_delete_guard_v1
        BEFORE DELETE ON commands
        FOR EACH ROW
        WHEN OLD.action = 'schedule.fire'
          AND OLD.schedule_protocol_marker = 1
        BEGIN
          SELECT z4j_schedule_guard(
            'consume_evidence',
            'commands:delete',
            OLD.id,
            OLD.schedule_state_nonce,
            0,
            '',
            '',
            ''
          );
        END
        """,
        f"""
        CREATE TRIGGER z4j_schedule_fire_insert_guard_v1
        BEFORE INSERT ON schedule_fires
        FOR EACH ROW
        BEGIN
          SELECT CASE
            WHEN NEW.protocol_marker IS NOT 1
              OR NEW.state_write_nonce IS NULL
            THEN RAISE(ABORT, 'schedule fire protocol marker required')
          END;
          SELECT CASE
            WHEN NEW.receipt_control_token IS NULL
              OR NOT ({fire_complete})
            THEN RAISE(
              ABORT,
              'current schedule fire receipt tuple is required'
            )
          END;
        END
        """,
        f"""
        CREATE TRIGGER z4j_schedule_fire_update_guard_v1
        BEFORE UPDATE ON schedule_fires
        FOR EACH ROW
        WHEN OLD.protocol_marker = 1
          AND z4j_schedule_guard(
            'is_reset', '', '', 0, 0, '', '', ''
          ) = 0
        BEGIN
          SELECT CASE
            WHEN NEW.protocol_marker IS NOT 1
              OR NEW.state_write_nonce IS NULL
              OR NEW.state_write_nonce = OLD.state_write_nonce
              OR NEW.id <> OLD.id
              OR NEW.fire_id <> OLD.fire_id
              OR NEW.schedule_id <> OLD.schedule_id
              OR NEW.project_id <> OLD.project_id
              OR NEW.fired_at <> OLD.fired_at
              OR NEW.scheduled_for <> OLD.scheduled_for
              OR NOT (
                NEW.triggered_by_user_id
                  IS OLD.triggered_by_user_id
                OR (
                  OLD.triggered_by_user_id IS NOT NULL
                  AND NEW.triggered_by_user_id IS NULL
                )
              )
              OR NEW.observed_control_token IS NOT OLD.observed_control_token
              OR NEW.receipt_control_token IS NOT OLD.receipt_control_token
              OR NEW.acceptance_revision IS NOT OLD.acceptance_revision
              OR NEW.definition_digest IS NOT OLD.definition_digest
              OR NEW.expected_schedule_revision
                   IS NOT OLD.expected_schedule_revision
              OR NEW.expected_last_run_at IS NOT OLD.expected_last_run_at
              OR NEW.expected_next_run_at IS NOT OLD.expected_next_run_at
              OR NEW.prepared_next_run_at IS NOT OLD.prepared_next_run_at
              OR (
                NEW.command_id IS NOT OLD.command_id
                AND NOT (
                  OLD.command_id IS NULL
                  AND NEW.command_id IS NOT NULL
                  AND OLD.receipt_control_token IS NOT NULL
                  AND NEW.receipt_control_token
                    IS OLD.receipt_control_token
                )
              )
              OR NOT (
                NEW.status = OLD.status
                OR (
                  OLD.receipt_control_token IS NOT NULL
                  AND OLD.status = 'buffered'
                  AND NEW.status IN (
                    'accepted',
                    'buffer_expired',
                    'buffer_stale'
                  )
                )
                OR (
                  OLD.receipt_control_token IS NOT NULL
                  AND OLD.status = 'accepted'
                  AND NEW.status IN (
                    'terminal_completed',
                    'terminal_failed',
                    'terminal_cancelled',
                    'terminal_timeout'
                  )
                )
                OR (
                  OLD.receipt_control_token IS NULL
                  AND NEW.status = 'operator_skipped'
                )
              )
              OR (
                NEW.scheduler_ack_status
                  IS NOT OLD.scheduler_ack_status
                AND NOT (
                  (
                    OLD.scheduler_ack_status IS NULL
                    AND NEW.scheduler_ack_status IN (
                      'success',
                      'failed'
                    )
                  )
                  OR (
                    OLD.scheduler_ack_status = 'failed'
                    AND NEW.scheduler_ack_status = 'success'
                  )
                )
              )
              OR (
                (
                  NEW.scheduler_acknowledged_at
                    IS NOT OLD.scheduler_acknowledged_at
                  OR NEW.scheduler_ack_task_id
                    IS NOT OLD.scheduler_ack_task_id
                  OR NEW.scheduler_ack_error_code
                    IS NOT OLD.scheduler_ack_error_code
                  OR NEW.scheduler_ack_error_message
                    IS NOT OLD.scheduler_ack_error_message
                )
                AND NEW.scheduler_ack_status
                  IS OLD.scheduler_ack_status
              )
              OR (
                (
                  NEW.acked_at IS NOT OLD.acked_at
                  OR NEW.latency_ms IS NOT OLD.latency_ms
                  OR NEW.error_code IS NOT OLD.error_code
                  OR NEW.error_message IS NOT OLD.error_message
                )
                AND NEW.status = OLD.status
                AND NEW.scheduler_ack_status
                  IS OLD.scheduler_ack_status
              )
              OR (
                NEW.receipt_control_token IS NOT NULL
                AND NOT ({fire_complete})
              )
            THEN RAISE(ABORT, 'invalid schedule fire transition')
          END;
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_fire_delete_guard_v1
        BEFORE DELETE ON schedule_fires
        FOR EACH ROW
        WHEN OLD.protocol_marker = 1
          AND z4j_schedule_guard(
            'is_reset', '', '', 0, 0, '', '', ''
          ) = 0
        BEGIN
          SELECT z4j_schedule_guard(
            'consume_evidence',
            'schedule_fires:delete',
            OLD.id,
            OLD.state_write_nonce,
            0,
            '',
            '',
            ''
          );
        END
        """,
        f"""
        CREATE TRIGGER z4j_pending_fire_insert_guard_v1
        BEFORE INSERT ON pending_fires
        FOR EACH ROW
        BEGIN
          SELECT CASE
            WHEN NEW.protocol_marker IS NOT 1
              OR NEW.state_write_nonce IS NULL
            THEN RAISE(ABORT, 'pending fire protocol marker required')
          END;
          SELECT CASE
            WHEN NEW.receipt_control_token IS NULL
              OR NOT ({pending_complete})
            THEN RAISE(
              ABORT,
              'current pending fire receipt tuple is required'
            )
          END;
        END
        """,
        """
        CREATE TRIGGER z4j_pending_fire_update_guard_v1
        BEFORE UPDATE ON pending_fires
        FOR EACH ROW
        WHEN OLD.protocol_marker = 1
        BEGIN
          SELECT RAISE(ABORT, 'invalid pending fire transition');
        END
        """,
        """
        CREATE TRIGGER z4j_pending_fire_delete_guard_v1
        BEFORE DELETE ON pending_fires
        FOR EACH ROW
        WHEN OLD.protocol_marker = 1
        BEGIN
          SELECT z4j_schedule_guard(
            'consume_evidence',
            'pending_fires:delete',
            OLD.id,
            OLD.state_write_nonce,
            0,
            '',
            '',
            ''
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_terminal_hold_insert_guard_v1
        BEFORE INSERT ON schedule_terminal_holds
        FOR EACH ROW
        BEGIN
          SELECT CASE
            WHEN NEW.state_write_nonce IS NULL
              OR NEW.resolved_at IS NOT NULL
              OR NEW.resolved_by IS NOT NULL
              OR NEW.resolution_disposition IS NOT NULL
              OR NEW.resolution_source IS NOT NULL
              OR NEW.work_may_have_executed IS NOT NULL
              OR NEW.resolution_control_token IS NOT NULL
              OR NEW.deletion_tombstone_revision IS NOT NULL
            THEN RAISE(ABORT, 'invalid terminal hold creation')
          END;
          SELECT z4j_schedule_guard(
            'consume_evidence',
            'schedule_terminal_holds:insert',
            NEW.id,
            NEW.state_write_nonce,
            0,
            '',
            '',
            ''
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_terminal_hold_update_guard_v1
        BEFORE UPDATE ON schedule_terminal_holds
        FOR EACH ROW
        BEGIN
          SELECT CASE
            WHEN OLD.resolved_at IS NOT NULL
              OR NEW.resolved_at IS NULL
              OR NEW.state_write_nonce IS NULL
              OR NEW.state_write_nonce = OLD.state_write_nonce
              OR NEW.id <> OLD.id
              OR NEW.project_id <> OLD.project_id
              OR NEW.schedule_id <> OLD.schedule_id
              OR NEW.fire_id <> OLD.fire_id
              OR NEW.scheduled_for <> OLD.scheduled_for
              OR NEW.command_id <> OLD.command_id
              OR NEW.observed_control_token
                   <> OLD.observed_control_token
              OR NEW.receipt_control_token
                   <> OLD.receipt_control_token
              OR NEW.acceptance_revision <> OLD.acceptance_revision
              OR NEW.terminal_status <> OLD.terminal_status
              OR NEW.terminal_detail IS NOT OLD.terminal_detail
              OR NEW.created_at <> OLD.created_at
            THEN RAISE(ABORT, 'invalid terminal hold resolution')
          END;
          SELECT z4j_schedule_guard(
            'consume_evidence',
            'schedule_terminal_holds:update',
            OLD.id,
            OLD.state_write_nonce,
            0,
            '',
            '',
            ''
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_terminal_hold_delete_guard_v1
        BEFORE DELETE ON schedule_terminal_holds
        FOR EACH ROW
        WHEN z4j_schedule_guard(
          'is_reset', '', '', 0, 0, '', '', ''
        ) = 0
        BEGIN
          SELECT z4j_schedule_guard(
            'consume_evidence',
            'schedule_terminal_holds:delete',
            OLD.id,
            OLD.state_write_nonce,
            0,
            '',
            '',
            ''
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_occurrence_resolution_insert_guard_v1
        BEFORE INSERT ON schedule_occurrence_resolutions
        FOR EACH ROW
        BEGIN
          SELECT CASE
            WHEN NEW.state_write_nonce IS NULL
            THEN RAISE(ABORT, 'resolution nonce is required')
          END;
          SELECT z4j_schedule_guard(
            'consume_evidence',
            'schedule_occurrence_resolutions:insert',
            NEW.id,
            NEW.state_write_nonce,
            0,
            '',
            '',
            ''
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_occurrence_resolution_update_guard_v1
        BEFORE UPDATE ON schedule_occurrence_resolutions
        FOR EACH ROW
        BEGIN
          SELECT RAISE(ABORT, 'occurrence resolution is immutable');
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_occurrence_resolution_delete_guard_v1
        BEFORE DELETE ON schedule_occurrence_resolutions
        FOR EACH ROW
        WHEN z4j_schedule_guard(
          'is_reset', '', '', 0, 0, '', '', ''
        ) = 0
        BEGIN
          SELECT z4j_schedule_guard(
            'consume_evidence',
            'schedule_occurrence_resolutions:delete',
            OLD.id,
            OLD.state_write_nonce,
            0,
            '',
            '',
            ''
          );
        END
        """,
    )
    for statement in statements:
        # Every statement is a literal in the closed tuple above.
        literal_statement = sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
            statement,
        )
        op.execute(literal_statement)
    for table_name, key_column in (
        ("commands", "id"),
        ("schedule_fires", "id"),
        ("pending_fires", "id"),
        ("schedule_terminal_holds", "id"),
        ("schedule_occurrence_resolutions", "id"),
    ):
        op.execute(
            sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                f"""
                CREATE TRIGGER z4j_reset_{table_name}_delete_guard_v1
                BEFORE DELETE ON {table_name}
                FOR EACH ROW
                WHEN z4j_schedule_guard(
                  'is_reset', '', '', 0, 0, '', '', ''
                ) = 1
                BEGIN
                  SELECT z4j_schedule_guard(
                    'consume_reset_row', '{table_name}', OLD.{key_column},
                    0, 0, '', '', ''
                  );
                END
                """,
            ),
        )


def _install_sqlite_external_guards() -> None:
    statements = (
        """
        CREATE TRIGGER z4j_schedule_external_insert_guard_v1
        BEFORE INSERT ON schedules
        FOR EACH ROW
        WHEN NEW.scheduler <> 'z4j-scheduler'
          AND (
            SELECT guard_version FROM schedule_revision_state
            WHERE singleton_id = 'schedule-revision'
          ) = 1
        BEGIN
          SELECT CASE WHEN (
            SELECT COUNT(*) FROM schedule_external_streams
            WHERE id = NEW.external_stream_id
              AND project_id = NEW.project_id
              AND owner = NEW.scheduler
              AND current_epoch_uuid = NEW.external_epoch_uuid
              AND current_epoch_number = NEW.external_epoch_number
              AND accepted_sequence + 1
                    = NEW.external_source_sequence
              AND phase IN ('ACTIVATING', 'ACTIVE', 'DRAINING')
          ) <> 1
          THEN RAISE(ABORT, 'external schedule insert is not current')
          END;
          SELECT z4j_schedule_external_guard(
            'consume_schedule',
            NEW.external_stream_id,
            NEW.external_epoch_uuid,
            NEW.external_epoch_number,
            NEW.external_source_sequence,
            NEW.id,
            NEW.external_source_key,
            'insert'
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_update_guard_v1
        BEFORE UPDATE ON schedules
        FOR EACH ROW
        WHEN NEW.scheduler <> 'z4j-scheduler'
          AND OLD.scheduler = NEW.scheduler
          AND (
            SELECT guard_version FROM schedule_revision_state
            WHERE singleton_id = 'schedule-revision'
          ) = 1
        BEGIN
          SELECT CASE WHEN OLD.scheduler = 'z4j-scheduler'
            OR NEW.external_stream_id IS NOT OLD.external_stream_id
            OR NEW.external_source_key IS NOT OLD.external_source_key
          THEN RAISE(
            ABORT,
            'external owner transition requires cutover authority'
          ) END;
          SELECT CASE WHEN (
            SELECT COUNT(*) FROM schedule_external_streams
            WHERE id = NEW.external_stream_id
              AND project_id = NEW.project_id
              AND owner = NEW.scheduler
              AND current_epoch_uuid = NEW.external_epoch_uuid
              AND current_epoch_number = NEW.external_epoch_number
              AND accepted_sequence + 1
                    = NEW.external_source_sequence
              AND phase IN ('ACTIVATING', 'ACTIVE', 'DRAINING')
          ) <> 1
          THEN RAISE(ABORT, 'external schedule update is not current')
          END;
          SELECT z4j_schedule_external_guard(
            'consume_schedule',
            NEW.external_stream_id,
            NEW.external_epoch_uuid,
            NEW.external_epoch_number,
            NEW.external_source_sequence,
            NEW.id,
            NEW.external_source_key,
            'update'
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_owner_cutover_row_guard_v1
        BEFORE UPDATE ON schedules
        FOR EACH ROW
        WHEN OLD.scheduler <> NEW.scheduler
          AND (
            SELECT guard_version FROM schedule_revision_state
            WHERE singleton_id = 'schedule-revision'
          ) = 1
        BEGIN
          SELECT CASE WHEN NEW.scheduler <> 'z4j-scheduler'
            AND (
              SELECT COUNT(*) FROM schedule_external_streams
              WHERE id = NEW.external_stream_id
                AND project_id = NEW.project_id
                AND owner = NEW.scheduler
                AND current_epoch_uuid = NEW.external_epoch_uuid
                AND current_epoch_number = NEW.external_epoch_number
                AND accepted_sequence = 0
                AND phase = 'ACTIVATING'
            ) <> 1
          THEN RAISE(
            ABORT,
            'external cutover target is not activating'
          ) END;
          SELECT CASE WHEN NEW.scheduler <> 'z4j-scheduler'
            AND NEW.external_source_sequence <> 0
          THEN RAISE(
            ABORT,
            'external cutover target sequence is not zero'
          ) END;
          SELECT z4j_schedule_external_guard(
            'consume_lifecycle_schedule',
            CASE WHEN OLD.scheduler <> 'z4j-scheduler'
              THEN OLD.external_stream_id
              ELSE NEW.external_stream_id
            END,
            CASE WHEN OLD.scheduler <> 'z4j-scheduler'
              THEN OLD.external_epoch_uuid
              ELSE NEW.external_epoch_uuid
            END,
            CASE WHEN OLD.scheduler <> 'z4j-scheduler'
              THEN OLD.external_epoch_number
              ELSE NEW.external_epoch_number
            END,
            0,
            NEW.id,
            OLD.scheduler,
            NEW.scheduler
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_delete_guard_v1
        BEFORE DELETE ON schedules
        FOR EACH ROW
        WHEN OLD.scheduler <> 'z4j-scheduler'
          AND (
            SELECT guard_version FROM schedule_revision_state
            WHERE singleton_id = 'schedule-revision'
          ) = 1
          AND z4j_schedule_guard(
            'is_reset', '', '', 0, 0, '', '', ''
          ) = 0
        BEGIN
          SELECT CASE WHEN (
            SELECT COUNT(*) FROM schedule_external_streams
            WHERE id = OLD.external_stream_id
              AND project_id = OLD.project_id
              AND owner = OLD.scheduler
              AND current_epoch_uuid = OLD.external_epoch_uuid
              AND current_epoch_number = OLD.external_epoch_number
              AND phase IN ('ACTIVATING', 'ACTIVE', 'DRAINING')
          ) <> 1
          THEN RAISE(ABORT, 'external schedule delete is not current')
          END;
          SELECT z4j_schedule_external_guard(
            'consume_schedule',
            OLD.external_stream_id,
            OLD.external_epoch_uuid,
            OLD.external_epoch_number,
            0,
            OLD.id,
            OLD.external_source_key,
            'delete'
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_projection_insert_guard_v1
        BEFORE INSERT ON schedule_external_projections
        FOR EACH ROW
        BEGIN
          SELECT CASE WHEN (
            SELECT COUNT(*) FROM schedule_external_streams
            WHERE id = NEW.stream_id
              AND current_epoch_uuid = NEW.epoch_uuid
              AND current_epoch_number = NEW.epoch_number
              AND accepted_sequence + 1 = NEW.sequence
              AND phase IN ('ACTIVATING', 'ACTIVE', 'DRAINING')
          ) <> 1
          THEN RAISE(ABORT, 'external projection is not exact next')
          END;
          SELECT z4j_schedule_external_guard(
            'consume_ledger',
            NEW.stream_id,
            NEW.epoch_uuid,
            NEW.epoch_number,
            NEW.sequence,
            NEW.payload_digest,
            COALESCE(NEW.operation_id, ''),
            NEW.kind
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_projection_update_guard_v1
        BEFORE UPDATE ON schedule_external_projections
        FOR EACH ROW BEGIN
          SELECT RAISE(ABORT, 'external projection ledger is immutable');
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_projection_delete_guard_v1
        BEFORE DELETE ON schedule_external_projections
        FOR EACH ROW
        WHEN z4j_schedule_guard(
          'is_reset', '', '', 0, 0, '', '', ''
        ) = 0
        BEGIN
          SELECT RAISE(ABORT, 'external projection ledger is retained');
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_snapshot_frame_insert_guard_v1
        BEFORE INSERT ON schedule_external_snapshot_frames
        FOR EACH ROW
        BEGIN
          SELECT CASE WHEN (
            SELECT COUNT(*) FROM schedule_external_streams
            WHERE id = NEW.stream_id
              AND project_id = NEW.project_id
              AND owner = NEW.owner
              AND source_scope = NEW.source_scope
              AND current_epoch_uuid = NEW.epoch_uuid
              AND current_epoch_number = NEW.epoch_number
              AND authorized_adapter_instance_id
                    IS NEW.adapter_instance_id
              AND accepted_sequence + 1 = NEW.sequence
              AND phase IN ('ACTIVATING', 'ACTIVE', 'DRAINING')
          ) <> 1
          THEN RAISE(ABORT, 'external snapshot frame is not current')
          END;
          SELECT z4j_schedule_external_guard(
            'consume_snapshot_frame',
            NEW.stream_id,
            NEW.epoch_uuid,
            NEW.epoch_number,
            NEW.sequence,
            NEW.frame_digest,
            NEW.snapshot_id,
            NEW.frame_index
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_snapshot_frame_update_guard_v1
        BEFORE UPDATE ON schedule_external_snapshot_frames
        FOR EACH ROW BEGIN
          SELECT RAISE(ABORT, 'external snapshot frame is immutable');
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_snapshot_frame_delete_guard_v1
        BEFORE DELETE ON schedule_external_snapshot_frames
        FOR EACH ROW
        WHEN z4j_schedule_guard(
          'is_reset', '', '', 0, 0, '', '', ''
        ) = 0
        BEGIN
          SELECT RAISE(ABORT, 'external snapshot frame is retained');
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_control_insert_guard_v1
        BEFORE INSERT ON schedule_external_control_operations
        FOR EACH ROW
        BEGIN
          SELECT CASE WHEN NEW.status <> 'PENDING'
            OR NEW.command_id IS NULL
            OR NEW.session_generation IS NULL
            OR NEW.dispatch_lease IS NOT NULL
            OR NEW.reserved_sequence IS NOT NULL
            OR NEW.result_projection_id IS NOT NULL
          THEN RAISE(ABORT, 'external control insert is malformed')
          END;
          SELECT CASE WHEN (
            SELECT COUNT(*) FROM schedule_external_streams AS stream
            JOIN schedules AS schedule
              ON schedule.id = NEW.schedule_id
             AND schedule.project_id = stream.project_id
             AND schedule.external_stream_id = stream.id
             AND schedule.external_epoch_uuid = stream.current_epoch_uuid
             AND schedule.external_epoch_number = stream.current_epoch_number
             AND schedule.external_source_key = NEW.source_key
             AND schedule.schedule_revision
                   = NEW.expected_schedule_revision
             AND schedule.control_token = NEW.expected_control_token
            JOIN commands AS command
              ON command.id = NEW.command_id
             AND command.project_id = stream.project_id
             AND command.agent_id = NEW.agent_id
             AND command.action = 'schedule.external.control'
             AND command.status = 'pending'
             AND replace(
                   json_extract(command.payload, '$.operation_id'),
                   '-',
                   ''
                 ) = replace(CAST(NEW.id AS TEXT), '-', '')
            WHERE stream.id = NEW.stream_id
              AND stream.current_epoch_uuid = NEW.epoch_uuid
              AND stream.current_epoch_number = NEW.epoch_number
              AND stream.accepted_sequence
                    = NEW.expected_accepted_sequence
              AND stream.phase = 'ACTIVE'
              AND stream.authorized_adapter_instance_id
                    = NEW.adapter_instance_id
              AND stream.executor_agent_id = NEW.agent_id
              AND stream.executor_registry_owner_id
                    = NEW.registry_owner_id
              AND stream.executor_session_generation
                    = NEW.session_generation
          ) <> 1
          THEN RAISE(ABORT, 'external control insert is not current')
          END;
          SELECT z4j_schedule_external_guard(
            'consume_control_insert',
            NEW.id,
            NEW.stream_id,
            NEW.epoch_number,
            0,
            NEW.state_nonce,
            '',
            NEW.command_id
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_control_update_guard_v1
        BEFORE UPDATE ON schedule_external_control_operations
        FOR EACH ROW
        BEGIN
          SELECT CASE WHEN
            NEW.id IS NOT OLD.id
            OR NEW.request_idempotency_key
                 IS NOT OLD.request_idempotency_key
            OR NEW.schedule_id IS NOT OLD.schedule_id
            OR NEW.command_id IS NOT OLD.command_id
            OR NEW.agent_id IS NOT OLD.agent_id
            OR NEW.stream_id IS NOT OLD.stream_id
            OR NEW.epoch_uuid IS NOT OLD.epoch_uuid
            OR NEW.epoch_number IS NOT OLD.epoch_number
            OR NEW.source_key IS NOT OLD.source_key
            OR NEW.expected_accepted_sequence
                 IS NOT OLD.expected_accepted_sequence
            OR NEW.expected_schedule_revision
                 IS NOT OLD.expected_schedule_revision
            OR NEW.expected_control_token
                 IS NOT OLD.expected_control_token
            OR NEW.prior_projection IS NOT OLD.prior_projection
            OR NEW.prior_projection_digest
                 IS NOT OLD.prior_projection_digest
            OR NEW.desired_projection IS NOT OLD.desired_projection
            OR NEW.desired_projection_digest
                 IS NOT OLD.desired_projection_digest
            OR NEW.adapter_instance_id IS NOT OLD.adapter_instance_id
            OR NEW.session_generation IS NOT OLD.session_generation
            OR NEW.registry_owner_id IS NOT OLD.registry_owner_id
            OR NEW.state_nonce IS NOT OLD.state_nonce
            OR NEW.created_at IS NOT OLD.created_at
          THEN RAISE(ABORT, 'external control identity is immutable')
          END;
          SELECT CASE WHEN NOT (
            (
              OLD.status = 'PENDING'
              AND NEW.status = 'CLAIMED'
              AND OLD.dispatch_lease IS NULL
              AND NEW.dispatch_lease IS NOT NULL
              AND OLD.reserved_sequence IS NULL
              AND NEW.reserved_sequence
                    = NEW.expected_accepted_sequence + 1
              AND NEW.result_projection_id IS NULL
            )
            OR (
              OLD.status = 'CLAIMED'
              AND NEW.status = 'APPLIED'
              AND NEW.dispatch_lease IS OLD.dispatch_lease
              AND NEW.reserved_sequence IS OLD.reserved_sequence
              AND NEW.result_projection_id IS NOT NULL
            )
            OR (
              OLD.status IN ('PENDING', 'CLAIMED')
              AND NEW.status = 'AMBIGUOUS'
              AND NEW.dispatch_lease IS OLD.dispatch_lease
              AND NEW.reserved_sequence IS OLD.reserved_sequence
              AND NEW.result_projection_id
                    IS OLD.result_projection_id
            )
          )
          THEN RAISE(ABORT, 'external control transition is invalid')
          END;
          SELECT z4j_schedule_external_guard(
            CASE NEW.status
              WHEN 'CLAIMED' THEN 'consume_control_claim'
              WHEN 'APPLIED' THEN 'consume_control_apply'
              ELSE 'consume_control_ambiguity'
            END,
            NEW.id,
            NEW.stream_id,
            NEW.epoch_number,
            COALESCE(NEW.reserved_sequence, 0),
            NEW.state_nonce,
            COALESCE(NEW.dispatch_lease, ''),
            CASE NEW.status
              WHEN 'CLAIMED' THEN NEW.command_id
              WHEN 'APPLIED' THEN NEW.result_projection_id
              ELSE ''
            END
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_control_delete_guard_v1
        BEFORE DELETE ON schedule_external_control_operations
        FOR EACH ROW
        WHEN z4j_schedule_guard(
          'is_reset', '', '', 0, 0, '', '', ''
        ) = 0
        BEGIN
          SELECT RAISE(ABORT, 'external control evidence is retained');
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_owner_cutover_insert_guard_v1
        BEFORE INSERT ON schedule_owner_cutovers
        FOR EACH ROW
        BEGIN
          SELECT z4j_schedule_external_guard(
            'consume_lifecycle_cutover',
            NEW.id,
            NEW.project_id,
            0,
            0,
            NEW.preview_manifest_digest,
            NEW.from_owner,
            NEW.to_owner
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_owner_cutover_update_guard_v1
        BEFORE UPDATE ON schedule_owner_cutovers
        FOR EACH ROW BEGIN
          SELECT RAISE(ABORT, 'owner cutover evidence is immutable');
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_owner_cutover_delete_guard_v1
        BEFORE DELETE ON schedule_owner_cutovers
        FOR EACH ROW
        WHEN z4j_schedule_guard(
          'is_reset', '', '', 0, 0, '', '', ''
        ) = 0
        BEGIN
          SELECT RAISE(ABORT, 'owner cutover evidence is retained');
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_epoch_update_guard_v1
        BEFORE UPDATE ON schedule_external_stream_epochs
        FOR EACH ROW
        BEGIN
          SELECT CASE
          WHEN NEW.epoch_uuid = OLD.epoch_uuid
            AND NEW.epoch_number = OLD.epoch_number
            AND NEW.stream_id = OLD.stream_id
            AND NEW.authorized_adapter_instance_id
                  IS OLD.authorized_adapter_instance_id
            AND NEW.executor_agent_id IS OLD.executor_agent_id
            AND NEW.executor_registry_owner_id
                  IS OLD.executor_registry_owner_id
            AND NEW.executor_session_generation
                  IS OLD.executor_session_generation
            AND NEW.executor_worker_id IS OLD.executor_worker_id
            AND NEW.accepted_sequence = OLD.accepted_sequence
            AND NEW.last_snapshot_digest IS OLD.last_snapshot_digest
            AND NEW.last_projection_digest IS OLD.last_projection_digest
            AND NEW.activation_requirement IS OLD.activation_requirement
            AND NEW.created_at IS OLD.created_at
            AND NEW.activated_at IS OLD.activated_at
            AND (
              (
                OLD.phase = 'ACTIVE'
                AND NEW.phase = 'DRAINING'
                AND NEW.sealed_sequence IS OLD.sealed_sequence
                AND NEW.sealed_at IS OLD.sealed_at
                AND NEW.retired_at IS OLD.retired_at
              )
              OR (
                OLD.phase = 'ACTIVATING'
                AND NEW.phase = 'RETIRED'
                AND OLD.accepted_sequence = 0
                AND NEW.sealed_sequence = 0
                AND NEW.sealed_at IS OLD.sealed_at
                AND NEW.retired_at IS NOT NULL
                AND OLD.retired_at IS NULL
              )
              OR (
                OLD.phase = 'DRAINING'
                AND NEW.phase = 'SEALED'
                AND NEW.sealed_sequence = NEW.accepted_sequence
                AND NEW.last_snapshot_digest IS NOT NULL
                AND NEW.sealed_at IS NOT NULL
                AND OLD.sealed_at IS NULL
                AND NEW.retired_at IS OLD.retired_at
              )
              OR (
                OLD.phase = 'SEALED'
                AND NEW.phase = 'RETIRED'
                AND NEW.sealed_sequence IS OLD.sealed_sequence
                AND NEW.sealed_at IS OLD.sealed_at
                AND NEW.retired_at IS NOT NULL
                AND OLD.retired_at IS NULL
              )
              OR (
                OLD.phase IN (
                  'ACTIVATING', 'ACTIVE', 'DRAINING',
                  'SEALED', 'AMBIGUOUS'
                )
                AND NEW.phase = 'RESTORE_REACTIVATION_REQUIRED'
                AND NEW.sealed_sequence IS OLD.sealed_sequence
                AND NEW.sealed_at IS OLD.sealed_at
                AND NEW.retired_at IS OLD.retired_at
              )
            )
          THEN 1
          WHEN NEW.phase = 'AMBIGUOUS'
            AND OLD.phase IN ('ACTIVATING', 'ACTIVE', 'DRAINING')
            AND NEW.epoch_uuid = OLD.epoch_uuid
            AND NEW.epoch_number = OLD.epoch_number
            AND NEW.stream_id = OLD.stream_id
            AND NEW.authorized_adapter_instance_id
                  IS OLD.authorized_adapter_instance_id
            AND NEW.executor_agent_id IS OLD.executor_agent_id
            AND NEW.executor_registry_owner_id
                  IS OLD.executor_registry_owner_id
            AND NEW.executor_session_generation
                  IS OLD.executor_session_generation
            AND NEW.executor_worker_id IS OLD.executor_worker_id
            AND NEW.accepted_sequence = OLD.accepted_sequence
            AND NEW.sealed_sequence IS OLD.sealed_sequence
            AND NEW.last_snapshot_digest IS OLD.last_snapshot_digest
            AND NEW.last_projection_digest IS OLD.last_projection_digest
            AND NEW.activation_requirement = 'PROTOCOL_FAULT'
          THEN 1
          WHEN NEW.epoch_uuid <> OLD.epoch_uuid
            OR NEW.epoch_number <> OLD.epoch_number
            OR NEW.stream_id <> OLD.stream_id
            OR NEW.executor_agent_id IS NOT OLD.executor_agent_id
            OR NEW.executor_registry_owner_id
                  IS NOT OLD.executor_registry_owner_id
            OR NEW.executor_session_generation
                  IS NOT OLD.executor_session_generation
            OR NEW.executor_worker_id IS NOT OLD.executor_worker_id
            OR (
              OLD.phase = 'ACTIVATING'
              AND OLD.authorized_adapter_instance_id IS NULL
              AND NEW.authorized_adapter_instance_id IS NULL
            )
            OR (
              NOT (
                OLD.phase = 'ACTIVATING'
                AND OLD.authorized_adapter_instance_id IS NULL
              )
              AND NEW.authorized_adapter_instance_id
                    IS NOT OLD.authorized_adapter_instance_id
            )
            OR (
              OLD.phase = 'ACTIVATING'
              AND NEW.activation_requirement IS NOT NULL
            )
            OR (
              OLD.phase <> 'ACTIVATING'
              AND NEW.activation_requirement
                    IS NOT OLD.activation_requirement
            )
            OR NEW.accepted_sequence <> OLD.accepted_sequence + 1
            OR NEW.phase NOT IN ('ACTIVE', 'DRAINING', 'SEALED')
            OR (
              OLD.phase = 'ACTIVATING' AND NEW.phase <> 'ACTIVE'
            )
            OR (
              OLD.phase = 'ACTIVE'
              AND NEW.phase NOT IN ('ACTIVE', 'DRAINING')
            )
            OR (
              OLD.phase = 'DRAINING'
              AND NEW.phase NOT IN ('DRAINING', 'SEALED')
            )
            OR OLD.phase NOT IN ('ACTIVATING', 'ACTIVE', 'DRAINING')
          THEN RAISE(ABORT, 'invalid external epoch projection')
          END;
          SELECT z4j_schedule_external_guard(
            CASE
              WHEN NEW.phase = 'AMBIGUOUS'
                THEN 'consume_ambiguity_epoch'
              WHEN NEW.accepted_sequence = OLD.accepted_sequence
                THEN 'consume_lifecycle_epoch'
              ELSE 'consume_epoch'
            END,
            NEW.stream_id,
            NEW.epoch_uuid,
            NEW.epoch_number,
            NEW.accepted_sequence,
            CASE
              WHEN NEW.accepted_sequence = OLD.accepted_sequence
                THEN NEW.phase
              ELSE NEW.last_projection_digest
            END,
            CASE
              WHEN NEW.phase = 'AMBIGUOUS'
                THEN NEW.authorized_adapter_instance_id
              WHEN NEW.accepted_sequence = OLD.accepted_sequence
                THEN COALESCE(NEW.last_snapshot_digest, '')
              ELSE NEW.authorized_adapter_instance_id
            END,
            CASE
              WHEN NEW.accepted_sequence = OLD.accepted_sequence
                THEN COALESCE(NEW.sealed_sequence, 0)
              ELSE NEW.phase
            END
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_epoch_insert_guard_v1
        BEFORE INSERT ON schedule_external_stream_epochs
        FOR EACH ROW
        WHEN EXISTS (SELECT 1 FROM schedule_external_epoch_allocator)
        BEGIN
          SELECT CASE WHEN NEW.phase <> 'ACTIVATING'
            OR NEW.accepted_sequence <> 0
            OR NEW.sealed_sequence IS NOT NULL
            OR NEW.last_snapshot_digest IS NOT NULL
            OR NEW.last_projection_digest IS NOT NULL
          THEN RAISE(ABORT, 'invalid allocated external epoch')
          END;
          SELECT z4j_schedule_external_guard(
            'consume_allocation_epoch',
            NEW.stream_id,
            NEW.epoch_uuid,
            NEW.epoch_number,
            0,
            '',
            COALESCE(NEW.authorized_adapter_instance_id, ''),
            ''
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_epoch_delete_guard_v1
        BEFORE DELETE ON schedule_external_stream_epochs
        FOR EACH ROW
        WHEN z4j_schedule_guard(
          'is_reset', '', '', 0, 0, '', '', ''
        ) = 0
        BEGIN
          SELECT RAISE(ABORT, 'external epoch history is retained');
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_stream_update_guard_v1
        BEFORE UPDATE ON schedule_external_streams
        FOR EACH ROW
        WHEN NEW.current_epoch_uuid = OLD.current_epoch_uuid
        BEGIN
          SELECT CASE
          WHEN NEW.id = OLD.id
            AND NEW.project_id = OLD.project_id
            AND NEW.owner = OLD.owner
            AND NEW.source_scope = OLD.source_scope
            AND NEW.source_scope_digest = OLD.source_scope_digest
            AND NEW.current_epoch_uuid = OLD.current_epoch_uuid
            AND NEW.current_epoch_number = OLD.current_epoch_number
            AND NEW.authorized_adapter_instance_id
                  IS OLD.authorized_adapter_instance_id
            AND NEW.executor_agent_id IS OLD.executor_agent_id
            AND NEW.executor_registry_owner_id
                  IS OLD.executor_registry_owner_id
            AND NEW.executor_session_generation
                  IS OLD.executor_session_generation
            AND NEW.executor_worker_id IS OLD.executor_worker_id
            AND NEW.accepted_sequence = OLD.accepted_sequence
            AND NEW.last_snapshot_digest IS OLD.last_snapshot_digest
            AND NEW.last_projection_digest IS OLD.last_projection_digest
            AND NEW.activation_requirement IS OLD.activation_requirement
            AND NEW.created_at IS OLD.created_at
            AND (
              (
                OLD.phase = 'ACTIVE'
                AND NEW.phase = 'DRAINING'
                AND NEW.sealed_sequence IS OLD.sealed_sequence
              )
              OR (
                OLD.phase = 'ACTIVATING'
                AND NEW.phase = 'RETIRED'
                AND OLD.accepted_sequence = 0
                AND NEW.sealed_sequence = 0
              )
              OR (
                OLD.phase = 'DRAINING'
                AND NEW.phase = 'SEALED'
                AND NEW.sealed_sequence = NEW.accepted_sequence
                AND NEW.last_snapshot_digest IS NOT NULL
              )
              OR (
                OLD.phase = 'SEALED'
                AND NEW.phase = 'RETIRED'
                AND NEW.sealed_sequence IS OLD.sealed_sequence
              )
              OR (
                OLD.phase IN (
                  'ACTIVATING', 'ACTIVE', 'DRAINING',
                  'SEALED', 'AMBIGUOUS'
                )
                AND NEW.phase = 'RESTORE_REACTIVATION_REQUIRED'
                AND NEW.sealed_sequence IS OLD.sealed_sequence
              )
            )
          THEN 1
          WHEN NEW.phase = 'AMBIGUOUS'
            AND OLD.phase IN ('ACTIVATING', 'ACTIVE', 'DRAINING')
            AND NEW.id = OLD.id
            AND NEW.project_id = OLD.project_id
            AND NEW.owner = OLD.owner
            AND NEW.source_scope = OLD.source_scope
            AND NEW.source_scope_digest = OLD.source_scope_digest
            AND NEW.current_epoch_uuid = OLD.current_epoch_uuid
            AND NEW.current_epoch_number = OLD.current_epoch_number
            AND NEW.authorized_adapter_instance_id
                  IS OLD.authorized_adapter_instance_id
            AND NEW.executor_agent_id IS OLD.executor_agent_id
            AND NEW.executor_registry_owner_id
                  IS OLD.executor_registry_owner_id
            AND NEW.executor_session_generation
                  IS OLD.executor_session_generation
            AND NEW.executor_worker_id IS OLD.executor_worker_id
            AND NEW.accepted_sequence = OLD.accepted_sequence
            AND NEW.sealed_sequence IS OLD.sealed_sequence
            AND NEW.last_snapshot_digest IS OLD.last_snapshot_digest
            AND NEW.last_projection_digest IS OLD.last_projection_digest
            AND NEW.activation_requirement = 'PROTOCOL_FAULT'
          THEN 1
          WHEN NEW.id <> OLD.id
            OR NEW.project_id <> OLD.project_id
            OR NEW.owner <> OLD.owner
            OR NEW.source_scope <> OLD.source_scope
            OR NEW.source_scope_digest <> OLD.source_scope_digest
            OR NEW.current_epoch_uuid <> OLD.current_epoch_uuid
            OR NEW.current_epoch_number <> OLD.current_epoch_number
            OR NEW.executor_agent_id IS NOT OLD.executor_agent_id
            OR NEW.executor_registry_owner_id
                  IS NOT OLD.executor_registry_owner_id
            OR NEW.executor_session_generation
                  IS NOT OLD.executor_session_generation
            OR NEW.executor_worker_id IS NOT OLD.executor_worker_id
            OR (
              OLD.phase = 'ACTIVATING'
              AND OLD.authorized_adapter_instance_id IS NULL
              AND NEW.authorized_adapter_instance_id IS NULL
            )
            OR (
              NOT (
                OLD.phase = 'ACTIVATING'
                AND OLD.authorized_adapter_instance_id IS NULL
              )
              AND NEW.authorized_adapter_instance_id
                    IS NOT OLD.authorized_adapter_instance_id
            )
            OR (
              OLD.phase = 'ACTIVATING'
              AND NEW.activation_requirement IS NOT NULL
            )
            OR (
              OLD.phase <> 'ACTIVATING'
              AND NEW.activation_requirement
                    IS NOT OLD.activation_requirement
            )
            OR NEW.accepted_sequence <> OLD.accepted_sequence + 1
            OR NEW.phase NOT IN ('ACTIVE', 'DRAINING', 'SEALED')
            OR (
              OLD.phase = 'ACTIVATING' AND NEW.phase <> 'ACTIVE'
            )
            OR (
              OLD.phase = 'ACTIVE'
              AND NEW.phase NOT IN ('ACTIVE', 'DRAINING')
            )
            OR (
              OLD.phase = 'DRAINING'
              AND NEW.phase NOT IN ('DRAINING', 'SEALED')
            )
            OR OLD.phase NOT IN ('ACTIVATING', 'ACTIVE', 'DRAINING')
          THEN RAISE(ABORT, 'invalid external stream projection')
          END;
          SELECT CASE WHEN (
            SELECT COUNT(*) FROM schedule_external_stream_epochs
            WHERE stream_id = NEW.id
              AND epoch_uuid = NEW.current_epoch_uuid
              AND epoch_number = NEW.current_epoch_number
              AND phase = NEW.phase
              AND authorized_adapter_instance_id
                    IS NEW.authorized_adapter_instance_id
              AND executor_agent_id IS NEW.executor_agent_id
              AND executor_registry_owner_id
                    IS NEW.executor_registry_owner_id
              AND executor_session_generation
                    IS NEW.executor_session_generation
              AND executor_worker_id IS NEW.executor_worker_id
              AND accepted_sequence = NEW.accepted_sequence
              AND last_snapshot_digest
                    IS NEW.last_snapshot_digest
              AND last_projection_digest
                    IS NEW.last_projection_digest
          ) <> 1
          THEN RAISE(ABORT, 'external stream/epoch projection mismatch')
          END;
          SELECT z4j_schedule_external_guard(
            CASE
              WHEN NEW.phase = 'AMBIGUOUS'
                THEN 'consume_ambiguity_stream'
              WHEN NEW.accepted_sequence = OLD.accepted_sequence
                THEN 'consume_lifecycle_stream'
              ELSE 'consume_stream'
            END,
            NEW.id,
            NEW.current_epoch_uuid,
            NEW.current_epoch_number,
            NEW.accepted_sequence,
            CASE
              WHEN NEW.accepted_sequence = OLD.accepted_sequence
                THEN NEW.phase
              ELSE NEW.last_projection_digest
            END,
            CASE
              WHEN NEW.phase = 'AMBIGUOUS'
                THEN NEW.authorized_adapter_instance_id
              WHEN NEW.accepted_sequence = OLD.accepted_sequence
                THEN COALESCE(NEW.last_snapshot_digest, '')
              ELSE NEW.authorized_adapter_instance_id
            END,
            CASE
              WHEN NEW.accepted_sequence = OLD.accepted_sequence
                THEN COALESCE(NEW.sealed_sequence, 0)
              ELSE NEW.phase
            END
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_stream_reactivation_guard_v1
        BEFORE UPDATE ON schedule_external_streams
        FOR EACH ROW
        WHEN NEW.current_epoch_uuid <> OLD.current_epoch_uuid
        BEGIN
          SELECT CASE WHEN OLD.phase NOT IN (
            'RETIRED',
            'RESTORE_REACTIVATION_REQUIRED'
          )
            OR NEW.id <> OLD.id
            OR NEW.project_id <> OLD.project_id
            OR NEW.owner <> OLD.owner
            OR NEW.source_scope <> OLD.source_scope
            OR NEW.source_scope_digest <> OLD.source_scope_digest
            OR NEW.current_epoch_number <= OLD.current_epoch_number
            OR NEW.phase <> 'ACTIVATING'
            OR NEW.accepted_sequence <> 0
            OR NEW.sealed_sequence IS NOT NULL
            OR NEW.last_snapshot_digest IS NOT NULL
            OR NEW.last_projection_digest IS NOT NULL
            OR NEW.created_at IS NOT OLD.created_at
          THEN RAISE(
            ABORT,
            'invalid external stream reactivation'
          ) END;
          SELECT CASE WHEN (
            SELECT COUNT(*) FROM schedule_external_stream_epochs
            WHERE stream_id = NEW.id
              AND epoch_uuid = NEW.current_epoch_uuid
              AND epoch_number = NEW.current_epoch_number
              AND phase = NEW.phase
              AND authorized_adapter_instance_id
                    IS NEW.authorized_adapter_instance_id
              AND executor_agent_id IS NEW.executor_agent_id
              AND executor_registry_owner_id
                    IS NEW.executor_registry_owner_id
              AND executor_session_generation
                    IS NEW.executor_session_generation
              AND executor_worker_id IS NEW.executor_worker_id
              AND accepted_sequence = 0
          ) <> 1
          THEN RAISE(
            ABORT,
            'reactivated external executor mismatch'
          ) END;
          SELECT z4j_schedule_external_guard(
            'consume_allocation_stream',
            NEW.id,
            NEW.current_epoch_uuid,
            NEW.current_epoch_number,
            0,
            NEW.source_scope_digest,
            NEW.owner,
            NEW.project_id
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_stream_insert_guard_v1
        BEFORE INSERT ON schedule_external_streams
        FOR EACH ROW
        WHEN EXISTS (SELECT 1 FROM schedule_external_epoch_allocator)
        BEGIN
          SELECT CASE WHEN NEW.phase <> 'ACTIVATING'
            OR NEW.accepted_sequence <> 0
            OR NEW.sealed_sequence IS NOT NULL
            OR NEW.last_snapshot_digest IS NOT NULL
            OR NEW.last_projection_digest IS NOT NULL
          THEN RAISE(ABORT, 'invalid allocated external stream')
          END;
          SELECT CASE WHEN (
            SELECT COUNT(*) FROM schedule_external_stream_epochs
            WHERE stream_id = NEW.id
              AND epoch_uuid = NEW.current_epoch_uuid
              AND epoch_number = NEW.current_epoch_number
              AND phase = NEW.phase
              AND authorized_adapter_instance_id
                    IS NEW.authorized_adapter_instance_id
              AND executor_agent_id IS NEW.executor_agent_id
              AND executor_registry_owner_id
                    IS NEW.executor_registry_owner_id
              AND executor_session_generation
                    IS NEW.executor_session_generation
              AND executor_worker_id IS NEW.executor_worker_id
              AND accepted_sequence = NEW.accepted_sequence
          ) <> 1
          THEN RAISE(ABORT, 'allocated external executor mismatch')
          END;
          SELECT z4j_schedule_external_guard(
            'consume_allocation_stream',
            NEW.id,
            NEW.current_epoch_uuid,
            NEW.current_epoch_number,
            0,
            NEW.source_scope_digest,
            NEW.owner,
            NEW.project_id
          );
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_stream_delete_guard_v1
        BEFORE DELETE ON schedule_external_streams
        FOR EACH ROW
        WHEN z4j_schedule_guard(
          'is_reset', '', '', 0, 0, '', '', ''
        ) = 0
        BEGIN
          SELECT RAISE(ABORT, 'external stream identity is retained');
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_allocator_insert_guard_v1
        BEFORE INSERT ON schedule_external_epoch_allocator
        FOR EACH ROW
        WHEN EXISTS (SELECT 1 FROM schedule_external_epoch_allocator)
        BEGIN
          SELECT RAISE(ABORT, 'external epoch allocator is a singleton');
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_allocator_update_guard_v1
        BEFORE UPDATE ON schedule_external_epoch_allocator
        FOR EACH ROW BEGIN
          SELECT CASE WHEN (
            NEW.singleton_id <> OLD.singleton_id
            OR NEW.guard_version <> OLD.guard_version
            OR NEW.activation_id <> OLD.activation_id
            OR NEW.activation_manifest_digest
                 <> OLD.activation_manifest_digest
            OR NEW.activation_audit_id <> OLD.activation_audit_id
            OR (
              z4j_schedule_guard(
                'is_reset', '', '', 0, 0, '', '', ''
              ) = 0
              AND z4j_schedule_guard(
                'is_restore', '', '', 0, 0, '', '', ''
              ) = 0
              AND NEW.current_epoch_number
                   <> OLD.current_epoch_number + 1
            )
            OR (
              z4j_schedule_guard(
                'is_reset', '', '', 0, 0, '', '', ''
              ) = 1
              AND NEW.current_epoch_number <= OLD.current_epoch_number
            )
          )
          THEN RAISE(ABORT, 'invalid external epoch allocation')
          END;
          SELECT CASE
            WHEN z4j_schedule_guard(
              'is_reset', '', '', 0, 0, '', '', ''
            ) = 0
              AND z4j_schedule_guard(
                'is_restore', '', '', 0, 0, '', '', ''
              ) = 0
            THEN z4j_schedule_external_guard(
              'consume_allocation_allocator',
              '',
              '',
              NEW.current_epoch_number,
              OLD.current_epoch_number,
              '',
              '',
              ''
            )
          END;
          SELECT CASE
            WHEN z4j_schedule_guard(
              'is_reset', '', '', 0, 0, '', '', ''
            ) = 1
            THEN z4j_schedule_guard(
              'consume_reset_epoch', '', '',
              OLD.current_epoch_number, NEW.current_epoch_number,
              '', '', ''
            )
          END;
          SELECT CASE
            WHEN z4j_schedule_guard(
              'is_restore', '', '', 0, 0, '', '', ''
            ) = 1
            THEN z4j_schedule_guard(
              'consume_restore_epoch', '', '',
              OLD.current_epoch_number, NEW.current_epoch_number,
              '', '', ''
            )
          END;
        END
        """,
        """
        CREATE TRIGGER z4j_schedule_external_allocator_delete_guard_v1
        BEFORE DELETE ON schedule_external_epoch_allocator
        FOR EACH ROW BEGIN
          SELECT RAISE(ABORT, 'external epoch allocator is protected');
        END
        """,
    )
    for statement in statements:
        op.execute(sa.text(statement))
    for table_name, key_column in (
        ("schedule_external_projections", "id"),
        ("schedule_external_snapshot_frames", "id"),
        ("schedule_external_control_operations", "id"),
        ("schedule_owner_cutovers", "id"),
        ("schedule_external_stream_epochs", "epoch_uuid"),
        ("schedule_external_streams", "id"),
    ):
        op.execute(
            sa.text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                f"""
                CREATE TRIGGER z4j_reset_{table_name}_delete_guard_v1
                BEFORE DELETE ON {table_name}
                FOR EACH ROW
                WHEN z4j_schedule_guard(
                  'is_reset', '', '', 0, 0, '', '', ''
                ) = 1
                BEGIN
                  SELECT z4j_schedule_guard(
                    'consume_reset_row', '{table_name}', OLD.{key_column},
                    0, 0, '', '', ''
                  );
                END
                """,
            ),
        )


def _install_postgresql_schedule_guards() -> None:
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION z4j_schedule_reset_active_v1()
            RETURNS boolean AS $$
            DECLARE
              raw_guard text;
            BEGIN
              raw_guard := current_setting(
                'z4j.schedule_reset_guard',
                true
              );
              RETURN raw_guard IS NOT NULL AND raw_guard <> '';
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION z4j_schedule_restore_active_v1()
            RETURNS boolean AS $$
            DECLARE
              raw_guard text;
            BEGIN
              raw_guard := current_setting(
                'z4j.schedule_restore_guard',
                true
              );
              RETURN raw_guard IS NOT NULL AND raw_guard <> '';
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_consume_schedule_restore_revision_v1(
                p_old_pruned bigint,
                p_new_pruned bigint,
                p_old_revision bigint,
                p_new_revision bigint
              )
            RETURNS void AS $$
            DECLARE
              descriptor jsonb;
            BEGIN
              descriptor := current_setting(
                'z4j.schedule_restore_guard',
                true
              )::jsonb;
              IF COALESCE(
                   (descriptor->>'revision_consumed')::boolean,
                   false
                 )
                 OR (descriptor->>'restored_revision')::bigint
                      IS DISTINCT FROM p_old_pruned
                 OR (descriptor->>'barrier_revision')::bigint
                      IS DISTINCT FROM p_new_pruned
                 OR (descriptor->>'restored_revision')::bigint
                      IS DISTINCT FROM p_old_revision
                 OR (descriptor->>'final_revision')::bigint
                      IS DISTINCT FROM p_new_revision THEN
                RAISE EXCEPTION
                  'schedule restore revision barrier mismatch';
              END IF;
              descriptor := jsonb_set(
                descriptor,
                '{revision_consumed}',
                'true'::jsonb,
                true
              );
              PERFORM set_config(
                'z4j.schedule_restore_guard',
                descriptor::text,
                true
              );
            EXCEPTION WHEN OTHERS THEN
              IF SQLERRM = 'schedule restore revision barrier mismatch' THEN
                RAISE;
              END IF;
              RAISE EXCEPTION
                'schedule restore descriptor is malformed';
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_consume_schedule_restore_epoch_v1(
                p_old_epoch bigint,
                p_new_epoch bigint
              )
            RETURNS void AS $$
            DECLARE
              descriptor jsonb;
            BEGIN
              descriptor := current_setting(
                'z4j.schedule_restore_guard',
                true
              )::jsonb;
              IF COALESCE(
                   (descriptor->>'epoch_consumed')::boolean,
                   false
                 )
                 OR (descriptor->>'restored_epoch')::bigint
                      IS DISTINCT FROM p_old_epoch
                 OR (descriptor->>'epoch_barrier')::bigint
                      IS DISTINCT FROM p_new_epoch THEN
                RAISE EXCEPTION
                  'schedule restore epoch barrier mismatch';
              END IF;
              descriptor := jsonb_set(
                descriptor,
                '{epoch_consumed}',
                'true'::jsonb,
                true
              );
              PERFORM set_config(
                'z4j.schedule_restore_guard',
                descriptor::text,
                true
              );
            EXCEPTION WHEN OTHERS THEN
              IF SQLERRM = 'schedule restore epoch barrier mismatch' THEN
                RAISE;
              END IF;
              RAISE EXCEPTION
                'schedule restore descriptor is malformed';
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_consume_schedule_restore_row_v1(
                p_operation text,
                p_schedule_id uuid,
                p_old_revision bigint,
                p_new_revision bigint,
                p_change_kind text,
                p_old_token uuid,
                p_new_token uuid
              )
            RETURNS void AS $$
            DECLARE
              descriptor jsonb;
              expected jsonb;
              expected_index integer;
              matching integer;
            BEGIN
              descriptor := current_setting(
                'z4j.schedule_restore_guard',
                true
              )::jsonb;
              SELECT COUNT(*), MIN(ordinality)::integer
                INTO matching, expected_index
              FROM jsonb_array_elements(
                descriptor->'schedules'
              ) WITH ORDINALITY AS item(value, ordinality)
              WHERE replace(value->>'schedule_id', '-', '')
                    = replace(p_schedule_id::text, '-', '');
              SELECT value INTO expected
              FROM jsonb_array_elements(
                descriptor->'schedules'
              ) WITH ORDINALITY AS item(value, ordinality)
              WHERE replace(value->>'schedule_id', '-', '')
                    = replace(p_schedule_id::text, '-', '')
              LIMIT 1;
              IF matching <> 1
                 OR p_operation <> 'update'
                 OR (expected->>'old_revision')::bigint
                      IS DISTINCT FROM p_old_revision
                 OR (expected->>'new_revision')::bigint
                      IS DISTINCT FROM p_new_revision
                 OR p_change_kind NOT IN ('upsert', 'gap')
                 OR replace(expected->>'control_token', '-', '')
                      IS DISTINCT FROM
                        replace(p_old_token::text, '-', '')
                 OR p_old_token IS DISTINCT FROM p_new_token THEN
                RAISE EXCEPTION
                  'schedule restore row is outside the manifest';
              END IF;
              descriptor := jsonb_set(
                descriptor,
                '{schedules}',
                (descriptor->'schedules') - (expected_index - 1),
                true
              );
              PERFORM set_config(
                'z4j.schedule_restore_guard',
                descriptor::text,
                true
              );
            EXCEPTION WHEN OTHERS THEN
              IF SQLERRM =
                   'schedule restore row is outside the manifest' THEN
                RAISE;
              END IF;
              RAISE EXCEPTION
                'schedule restore descriptor is malformed';
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_finalize_schedule_restore_v1(
                p_manifest_digest text,
                p_attestation_digest text
              )
            RETURNS void AS $$
            DECLARE
              descriptor jsonb;
            BEGIN
              descriptor := current_setting(
                'z4j.schedule_restore_guard',
                true
              )::jsonb;
              IF descriptor->>'manifest_digest'
                   IS DISTINCT FROM p_manifest_digest
                 OR descriptor->>'attestation_digest'
                   IS DISTINCT FROM p_attestation_digest
                 OR NOT COALESCE(
                      (descriptor->>'revision_consumed')::boolean,
                      false
                    )
                 OR NOT COALESCE(
                      (descriptor->>'epoch_consumed')::boolean,
                      false
                    )
                 OR jsonb_array_length(descriptor->'schedules') <> 0 THEN
                RAISE EXCEPTION
                  'schedule restore descriptor was not consumed';
              END IF;
              PERFORM set_config(
                'z4j.schedule_restore_guard',
                '',
                true
              );
            EXCEPTION WHEN OTHERS THEN
              IF SQLERRM =
                   'schedule restore descriptor was not consumed' THEN
                RAISE;
              END IF;
              RAISE EXCEPTION
                'schedule restore descriptor is malformed';
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_consume_schedule_reset_row_v1(p_table_name text)
            RETURNS void AS $$
            DECLARE
              raw_guard text;
              descriptor jsonb;
              expected_count bigint;
              consumed_count bigint;
            BEGIN
              raw_guard := current_setting(
                'z4j.schedule_reset_guard',
                true
              );
              IF raw_guard IS NULL OR raw_guard = '' THEN
                RAISE EXCEPTION 'schedule reset is not armed';
              END IF;
              BEGIN
                descriptor := raw_guard::jsonb;
                expected_count := (
                  descriptor->'expected_counts'->>p_table_name
                )::bigint;
                consumed_count := COALESCE(
                  (
                    descriptor->'consumed_counts'->>p_table_name
                  )::bigint,
                  0
                );
              EXCEPTION WHEN OTHERS THEN
                RAISE EXCEPTION
                  'schedule reset descriptor is malformed';
              END;
              IF expected_count IS NULL
                 OR consumed_count >= expected_count THEN
                RAISE EXCEPTION
                  'schedule reset row is outside the manifest';
              END IF;
              descriptor := jsonb_set(
                descriptor,
                ARRAY['consumed_counts', p_table_name],
                to_jsonb(consumed_count + 1),
                true
              );
              PERFORM set_config(
                'z4j.schedule_reset_guard',
                descriptor::text,
                true
              );
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_consume_schedule_reset_revision_v1(
                p_old_revision bigint,
                p_new_revision bigint
              )
            RETURNS void AS $$
            DECLARE
              descriptor jsonb;
            BEGIN
              descriptor := current_setting(
                'z4j.schedule_reset_guard',
                true
              )::jsonb;
              IF COALESCE(
                   (descriptor->>'revision_consumed')::boolean,
                   false
                 )
                 OR (descriptor->>'old_revision')::bigint
                      IS DISTINCT FROM p_old_revision
                 OR (descriptor->>'new_revision')::bigint
                      IS DISTINCT FROM p_new_revision THEN
                RAISE EXCEPTION
                  'schedule reset revision barrier mismatch';
              END IF;
              descriptor := jsonb_set(
                descriptor,
                '{revision_consumed}',
                'true'::jsonb,
                true
              );
              PERFORM set_config(
                'z4j.schedule_reset_guard',
                descriptor::text,
                true
              );
            EXCEPTION
              WHEN invalid_text_representation OR null_value_not_allowed THEN
                RAISE EXCEPTION
                  'schedule reset descriptor is malformed';
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_consume_schedule_reset_epoch_v1(
                p_old_epoch bigint,
                p_new_epoch bigint
              )
            RETURNS void AS $$
            DECLARE
              descriptor jsonb;
            BEGIN
              descriptor := current_setting(
                'z4j.schedule_reset_guard',
                true
              )::jsonb;
              IF COALESCE(
                   (descriptor->>'epoch_consumed')::boolean,
                   false
                 )
                 OR (descriptor->>'old_epoch')::bigint
                      IS DISTINCT FROM p_old_epoch
                 OR (descriptor->>'new_epoch')::bigint
                      IS DISTINCT FROM p_new_epoch THEN
                RAISE EXCEPTION
                  'schedule reset epoch barrier mismatch';
              END IF;
              descriptor := jsonb_set(
                descriptor,
                '{epoch_consumed}',
                'true'::jsonb,
                true
              );
              PERFORM set_config(
                'z4j.schedule_reset_guard',
                descriptor::text,
                true
              );
            EXCEPTION
              WHEN invalid_text_representation OR null_value_not_allowed THEN
                RAISE EXCEPTION
                  'schedule reset descriptor is malformed';
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_finalize_schedule_reset_v1(
                p_manifest_digest text,
                p_attestation_digest text
              )
            RETURNS void AS $$
            DECLARE
              descriptor jsonb;
            BEGIN
              descriptor := current_setting(
                'z4j.schedule_reset_guard',
                true
              )::jsonb;
              IF descriptor->>'manifest_digest'
                   IS DISTINCT FROM p_manifest_digest
                 OR descriptor->>'attestation_digest'
                   IS DISTINCT FROM p_attestation_digest
                 OR NOT COALESCE(
                   (descriptor->>'revision_consumed')::boolean,
                   false
                 )
                 OR NOT COALESCE(
                   (descriptor->>'epoch_consumed')::boolean,
                   false
                 )
                 OR descriptor->'expected_counts'
                   IS DISTINCT FROM descriptor->'consumed_counts' THEN
                RAISE EXCEPTION
                  'schedule reset descriptor was not consumed';
              END IF;
              PERFORM set_config(
                'z4j.schedule_reset_guard',
                '',
                true
              );
            EXCEPTION
              WHEN invalid_text_representation OR null_value_not_allowed THEN
                RAISE EXCEPTION
                  'schedule reset descriptor is malformed';
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_consume_schedule_prune_row_v1(p_revision bigint)
            RETURNS void AS $$
            DECLARE
              raw_guard text;
              descriptor jsonb;
              new_boundary bigint;
              expected_count bigint;
              consumed_count bigint;
            BEGIN
              raw_guard := current_setting(
                'z4j.schedule_prune_guard',
                true
              );
              IF raw_guard IS NULL OR raw_guard = '' THEN
                RAISE EXCEPTION
                  'schedule change-log prune is not armed';
              END IF;
              BEGIN
                descriptor := raw_guard::jsonb;
                new_boundary :=
                  (descriptor ->> 'new_boundary')::bigint;
                expected_count :=
                  (descriptor ->> 'expected_count')::bigint;
                consumed_count :=
                  (descriptor ->> 'consumed_count')::bigint;
              EXCEPTION WHEN OTHERS THEN
                RAISE EXCEPTION
                  'schedule change-log prune descriptor is malformed';
              END;
              IF p_revision <= 0
                 OR p_revision > new_boundary
                 OR consumed_count >= expected_count THEN
                RAISE EXCEPTION
                  'schedule change-log prune row mismatch';
              END IF;
              descriptor := jsonb_set(
                descriptor,
                '{consumed_count}',
                to_jsonb(consumed_count + 1),
                false
              );
              PERFORM set_config(
                'z4j.schedule_prune_guard',
                descriptor::text,
                true
              );
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_consume_external_cutover_schedule_guard_v1(
                p_stream_id uuid,
                p_epoch_uuid uuid,
                p_epoch_number bigint,
                p_schedule_id uuid,
                p_from_owner text,
                p_to_owner text
              )
            RETURNS void AS $$
            DECLARE
              raw text;
              descriptor jsonb;
              mutation jsonb;
              matches bigint;
            BEGIN
              raw := current_setting(
                'z4j.schedule_external_lifecycle_guard',
                true
              );
              IF raw IS NULL OR raw = '' THEN
                RAISE EXCEPTION
                  'external lifecycle transition is not armed';
              END IF;
              descriptor := raw::jsonb;
              IF descriptor->>'transition' <> 'cutover'
                 OR replace(
                      descriptor->>'stream_id', '-', ''
                    ) <> replace(p_stream_id::text, '-', '')
                 OR replace(
                      descriptor->>'epoch_uuid', '-', ''
                    ) <> replace(p_epoch_uuid::text, '-', '')
                 OR (descriptor->>'epoch_number')::bigint
                      <> p_epoch_number THEN
                RAISE EXCEPTION
                  'external lifecycle schedule stream mismatch';
              END IF;
              mutation := jsonb_build_object(
                'schedule_id', p_schedule_id::text,
                'from_owner', p_from_owner,
                'to_owner', p_to_owner
              );
              SELECT COUNT(*) INTO matches
              FROM jsonb_array_elements(
                descriptor->'mutations'
              ) AS item
              WHERE replace(
                      item->>'schedule_id',
                      '-',
                      ''
                    ) = replace(p_schedule_id::text, '-', '')
                AND item->>'from_owner' = p_from_owner
                AND item->>'to_owner' = p_to_owner;
              IF matches <> 1 THEN
                RAISE EXCEPTION
                  'external lifecycle schedule is not manifested';
              END IF;
              descriptor := jsonb_set(
                descriptor,
                '{mutations}',
                (
                  SELECT COALESCE(
                    jsonb_agg(item),
                    '[]'::jsonb
                  )
                  FROM jsonb_array_elements(
                    descriptor->'mutations'
                  ) AS item
                  WHERE NOT (
                    replace(
                      item->>'schedule_id',
                      '-',
                      ''
                    ) = replace(p_schedule_id::text, '-', '')
                    AND item->>'from_owner' = p_from_owner
                    AND item->>'to_owner' = p_to_owner
                  )
                ),
                true
              );
              PERFORM set_config(
                'z4j.schedule_external_lifecycle_guard',
                descriptor::text,
                true
              );
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_consume_external_cutover_evidence_guard_v1(
                p_operation_id uuid,
                p_project_id uuid,
                p_manifest_digest text,
                p_from_owner text,
                p_to_owner text
              )
            RETURNS void AS $$
            DECLARE
              raw text;
              descriptor jsonb;
            BEGIN
              raw := current_setting(
                'z4j.schedule_external_lifecycle_guard',
                true
              );
              IF raw IS NULL OR raw = '' THEN
                RAISE EXCEPTION
                  'external lifecycle transition is not armed';
              END IF;
              descriptor := raw::jsonb;
              IF descriptor->>'transition' <> 'cutover'
                 OR COALESCE(
                      (descriptor->>'cutover')::boolean,
                      false
                    )
                 OR replace(
                      descriptor->>'operation_id', '-', ''
                    ) <> replace(p_operation_id::text, '-', '')
                 OR replace(
                      descriptor->>'project_id', '-', ''
                    ) <> replace(p_project_id::text, '-', '')
                 OR descriptor->>'manifest_digest'
                      <> p_manifest_digest
                 OR descriptor->>'from_owner' <> p_from_owner
                 OR descriptor->>'to_owner' <> p_to_owner THEN
                RAISE EXCEPTION
                  'external cutover evidence descriptor mismatch';
              END IF;
              descriptor := jsonb_set(
                descriptor,
                '{cutover}',
                'true'::jsonb,
                true
              );
              PERFORM set_config(
                'z4j.schedule_external_lifecycle_guard',
                descriptor::text,
                true
              );
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_finish_external_target_cutover_guard_v1(
                p_stream_id uuid,
                p_epoch_uuid uuid,
                p_epoch_number bigint
              )
            RETURNS void AS $$
            DECLARE
              raw text;
              descriptor jsonb;
            BEGIN
              raw := current_setting(
                'z4j.schedule_external_lifecycle_guard',
                true
              );
              IF raw IS NULL OR raw = '' THEN
                RAISE EXCEPTION
                  'external lifecycle transition is not armed';
              END IF;
              descriptor := raw::jsonb;
              IF descriptor->>'transition' <> 'cutover'
                 OR descriptor->>'from_owner' <> 'z4j-scheduler'
                 OR descriptor->>'to_owner' = 'z4j-scheduler'
                 OR descriptor->>'from_phase' <> 'ACTIVATING'
                 OR descriptor->>'to_phase' <> 'ACTIVATING'
                 OR replace(
                      descriptor->>'stream_id', '-', ''
                    ) <> replace(p_stream_id::text, '-', '')
                 OR replace(
                      descriptor->>'epoch_uuid', '-', ''
                    ) <> replace(p_epoch_uuid::text, '-', '')
                 OR (descriptor->>'epoch_number')::bigint
                      <> p_epoch_number
                 OR jsonb_array_length(descriptor->'mutations') <> 0
                 OR NOT COALESCE(
                      (descriptor->>'cutover')::boolean,
                      false
                    )
                 OR COALESCE(
                      (descriptor->>'epoch')::boolean,
                      false
                    ) THEN
                RAISE EXCEPTION
                  'external target cutover transition is incomplete';
              END IF;
              PERFORM set_config(
                'z4j.schedule_external_lifecycle_guard',
                '',
                true
              );
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_finalize_schedule_prune_v1(
                p_old_boundary bigint,
                p_new_boundary bigint
              )
            RETURNS void AS $$
            DECLARE
              raw_guard text;
              descriptor jsonb;
            BEGIN
              raw_guard := current_setting(
                'z4j.schedule_prune_guard',
                true
              );
              IF raw_guard IS NULL OR raw_guard = '' THEN
                RAISE EXCEPTION
                  'schedule change-log prune is not armed';
              END IF;
              BEGIN
                descriptor := raw_guard::jsonb;
              EXCEPTION WHEN OTHERS THEN
                RAISE EXCEPTION
                  'schedule change-log prune descriptor is malformed';
              END;
              IF (descriptor ->> 'old_boundary')::bigint
                   IS DISTINCT FROM p_old_boundary
                 OR (descriptor ->> 'new_boundary')::bigint
                   IS DISTINCT FROM p_new_boundary
                 OR (descriptor ->> 'expected_count')::bigint
                   IS DISTINCT FROM
                     (descriptor ->> 'consumed_count')::bigint THEN
                RAISE EXCEPTION
                  'schedule change-log prune descriptor mismatch';
              END IF;
              PERFORM set_config(
                'z4j.schedule_prune_guard',
                '',
                true
              );
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION z4j_schedule_revision_guard_v1()
            RETURNS trigger AS $$
            BEGIN
              IF TG_OP = 'INSERT' THEN
                RAISE EXCEPTION 'schedule revision state is a singleton';
              END IF;
              IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'schedule revision state is protected';
              END IF;
              IF OLD.guard_version = 1 THEN
                IF NEW.singleton_id IS DISTINCT FROM OLD.singleton_id
                   OR NEW.guard_version IS DISTINCT FROM OLD.guard_version
                   OR NEW.activation_id IS DISTINCT FROM OLD.activation_id
                   OR NEW.activation_manifest_digest
                        IS DISTINCT FROM OLD.activation_manifest_digest
                   OR NEW.activation_audit_id
                        IS DISTINCT FROM OLD.activation_audit_id THEN
                  RAISE EXCEPTION 'invalid schedule revision allocation';
                END IF;
                IF z4j_schedule_reset_active_v1() THEN
                  IF NEW.current_revision <> OLD.current_revision + 1
                     OR NEW.change_log_pruned_through
                       <> NEW.current_revision THEN
                    RAISE EXCEPTION
                      'invalid schedule reset barrier';
                  END IF;
                  PERFORM z4j_consume_schedule_reset_revision_v1(
                    OLD.current_revision,
                    NEW.current_revision
                  );
                ELSIF z4j_schedule_restore_active_v1() THEN
                  PERFORM z4j_consume_schedule_restore_revision_v1(
                    OLD.change_log_pruned_through,
                    NEW.change_log_pruned_through,
                    OLD.current_revision,
                    NEW.current_revision
                  );
                ELSIF NEW.current_revision = OLD.current_revision + 1
                   AND NEW.change_log_pruned_through
                     = OLD.change_log_pruned_through THEN
                  IF current_setting(
                       'z4j.schedule_allocation_guard',
                       true
                     ) IS DISTINCT FROM 'armed' THEN
                    RAISE EXCEPTION
                      'invalid schedule revision allocation';
                  END IF;
                  PERFORM set_config(
                    'z4j.schedule_allocation_guard',
                    '',
                    true
                  );
                ELSIF NEW.current_revision = OLD.current_revision
                   AND NEW.change_log_pruned_through
                     > OLD.change_log_pruned_through
                   AND NEW.change_log_pruned_through
                     <= OLD.current_revision THEN
                  PERFORM z4j_finalize_schedule_prune_v1(
                    OLD.change_log_pruned_through,
                    NEW.change_log_pruned_through
                  );
                ELSE
                  RAISE EXCEPTION
                    'invalid schedule revision allocation';
                END IF;
              END IF;
              RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE TRIGGER z4j_schedule_revision_state_guard_v1
            BEFORE INSERT OR UPDATE OR DELETE ON schedule_revision_state
            FOR EACH ROW EXECUTE FUNCTION z4j_schedule_revision_guard_v1()
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION z4j_schedule_row_guard_v1()
            RETURNS trigger AS $$
            DECLARE
              descriptor jsonb;
              log_revision bigint;
              log_count bigint;
              transition_kind text;
              expected_operation text;
              old_revision bigint;
              new_revision bigint;
              old_token text;
              new_token text;
              row_id uuid;
              row_project_id uuid;
              visibility_kind text;
            BEGIN
              IF (
                SELECT guard_version FROM schedule_revision_state
                WHERE singleton_id = 'schedule-revision'
              ) IS DISTINCT FROM 1 THEN
                RETURN COALESCE(NEW, OLD);
              END IF;
              IF TG_OP = 'DELETE'
                 AND z4j_schedule_reset_active_v1() THEN
                PERFORM z4j_consume_schedule_reset_row_v1(
                  'schedules'
                );
                RETURN OLD;
              END IF;

              expected_operation := lower(TG_OP);
              row_id := COALESCE(NEW.id, OLD.id);
              row_project_id := COALESCE(NEW.project_id, OLD.project_id);
              old_revision := CASE
                WHEN TG_OP = 'INSERT' THEN 0 ELSE OLD.schedule_revision
              END;
              old_token := CASE
                WHEN TG_OP = 'INSERT' THEN NULL ELSE OLD.control_token::text
              END;

              IF TG_OP = 'DELETE' THEN
                SELECT COUNT(*), MAX(revision)
                  INTO log_count, log_revision
                FROM schedule_change_log
                WHERE schedule_id = OLD.id
                  AND project_id = OLD.project_id
                  AND change_kind = CASE
                    WHEN OLD.scheduler = 'z4j-scheduler'
                    THEN 'delete' ELSE 'gap'
                  END
                  AND protocol_version = 1
                  AND revision > OLD.schedule_revision;
                IF log_count <> 1 THEN
                  RAISE EXCEPTION
                    'schedule delete lacks exact tombstone';
                END IF;
                new_revision := log_revision;
                new_token := NULL;
                visibility_kind := CASE
                  WHEN OLD.scheduler = 'z4j-scheduler'
                  THEN 'delete' ELSE 'gap'
                END;
              ELSE
                IF NEW.control_token IS NULL
                   OR NEW.schedule_revision IS NULL
                   OR NEW.schedule_revision <= 0
                   OR NEW.definition_digest IS NULL
                   OR NEW.cadence_semantics_version IS NULL
                   OR NEW.cadence_runtime_fingerprint IS NULL THEN
                  RAISE EXCEPTION 'schedule D identity is incomplete';
                END IF;
                IF TG_OP = 'UPDATE' AND (
                  NEW.id IS DISTINCT FROM OLD.id
                  OR NEW.project_id IS DISTINCT FROM OLD.project_id
                  OR NEW.schedule_revision <= OLD.schedule_revision
                ) THEN
                  RAISE EXCEPTION 'invalid schedule transition identity';
                END IF;
                SELECT COUNT(*),
                       MAX(snapshot->'transition'->>'kind')
                  INTO log_count, transition_kind
                FROM schedule_change_log
                WHERE revision = NEW.schedule_revision
                  AND schedule_id = NEW.id
                  AND project_id = NEW.project_id
                  AND change_kind = CASE
                    WHEN TG_OP = 'UPDATE'
                      AND OLD.scheduler = 'z4j-scheduler'
                      AND NEW.scheduler <> 'z4j-scheduler'
                    THEN 'delete'
                    WHEN NEW.scheduler = 'z4j-scheduler'
                    THEN 'upsert' ELSE 'gap'
                  END
                  AND protocol_version = 1
                  AND (
                    (
                      NEW.scheduler = 'z4j-scheduler'
                      AND (
                        snapshot->'schedule'->>'schedule_revision'
                      )::bigint = NEW.schedule_revision
                    )
                    OR (
                      NEW.scheduler <> 'z4j-scheduler'
                      AND snapshot IS NULL
                    )
                  );
                IF log_count <> 1 THEN
                  RAISE EXCEPTION
                    'schedule transition lacks exact change envelope';
                END IF;
                IF TG_OP = 'UPDATE'
                   AND NEW.control_token = OLD.control_token
                   AND (
                     NEW.definition_digest
                       IS DISTINCT FROM OLD.definition_digest
                     OR NEW.is_enabled IS DISTINCT FROM OLD.is_enabled
                     OR NEW.legacy_fire_control_token
                       IS DISTINCT FROM OLD.legacy_fire_control_token
                     OR NEW.quarantine_control_token
                       IS DISTINCT FROM OLD.quarantine_control_token
                     OR NEW.quarantine_code
                       IS DISTINCT FROM OLD.quarantine_code
                     OR NEW.quarantine_detail
                       IS DISTINCT FROM OLD.quarantine_detail
                     OR NEW.quarantined_at
                       IS DISTINCT FROM OLD.quarantined_at
                   )
                   AND COALESCE(transition_kind, '') NOT IN (
                     'accept_fire',
                     'accept_legacy_fire',
                     'skip_no_work',
                     'terminal_fire',
                     'legacy_fire_grant',
                     'definition_quarantine',
                     'resolve_occurrence',
                     'database_restore_rebase'
                   ) THEN
                  RAISE EXCEPTION
                    'unnamed same-token schedule transition';
                END IF;
                IF TG_OP = 'UPDATE'
                   AND NEW.control_token <> OLD.control_token
                   AND COALESCE(transition_kind, '')
                       <> 'resolve_occurrence'
                   AND (
                     NEW.legacy_fire_control_token IS NOT NULL
                     OR NEW.quarantine_control_token IS NOT NULL
                     OR NEW.quarantine_code IS NOT NULL
                     OR NEW.quarantine_detail IS NOT NULL
                     OR NEW.quarantined_at IS NOT NULL
                   ) THEN
                  RAISE EXCEPTION
                    'control rotation retained stale authority';
                END IF;
                new_revision := NEW.schedule_revision;
                new_token := NEW.control_token::text;
                visibility_kind := CASE
                  WHEN TG_OP = 'UPDATE'
                    AND OLD.scheduler = 'z4j-scheduler'
                    AND NEW.scheduler <> 'z4j-scheduler'
                  THEN 'delete'
                  WHEN NEW.scheduler = 'z4j-scheduler'
                  THEN 'upsert' ELSE 'gap'
                END;
              END IF;

              IF TG_OP = 'UPDATE'
                 AND z4j_schedule_restore_active_v1() THEN
                PERFORM z4j_consume_schedule_restore_row_v1(
                  expected_operation,
                  row_id,
                  old_revision,
                  new_revision,
                  visibility_kind,
                  old_token::uuid,
                  new_token::uuid
                );
                RETURN NEW;
              END IF;

              BEGIN
                descriptor := current_setting(
                  'z4j.schedule_transition_guard', true
                )::jsonb;
              EXCEPTION WHEN OTHERS THEN
                RAISE EXCEPTION
                  'schedule transition descriptor is absent or malformed';
              END;
              IF descriptor->>'operation'
                    IS DISTINCT FROM expected_operation
                 OR replace(descriptor->>'schedule_id', '-', '')
                    IS DISTINCT FROM replace(row_id::text, '-', '')
                 OR (descriptor->>'old_revision')::bigint
                    IS DISTINCT FROM old_revision
                 OR (descriptor->>'new_revision')::bigint
                    IS DISTINCT FROM new_revision
                 OR descriptor->>'change_kind'
                    IS DISTINCT FROM visibility_kind
                 OR replace(
                      COALESCE(descriptor->>'old_token', ''), '-', ''
                    ) IS DISTINCT FROM replace(
                      COALESCE(old_token, ''), '-', ''
                    )
                 OR replace(
                      COALESCE(descriptor->>'new_token', ''), '-', ''
                    ) IS DISTINCT FROM replace(
                      COALESCE(new_token, ''), '-', ''
                    ) THEN
                RAISE EXCEPTION 'schedule transition descriptor mismatch';
              END IF;
              PERFORM set_config(
                'z4j.schedule_transition_guard', '', true
              );
              RETURN COALESCE(NEW, OLD);
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE TRIGGER z4j_schedule_row_guard_v1
            BEFORE INSERT OR UPDATE OR DELETE ON schedules
            FOR EACH ROW EXECUTE FUNCTION z4j_schedule_row_guard_v1()
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION z4j_schedule_change_log_guard_v1()
            RETURNS trigger AS $$
            BEGIN
              IF TG_OP = 'UPDATE' THEN
                RAISE EXCEPTION
                  'schedule change log is immutable';
              END IF;
              IF z4j_schedule_reset_active_v1() THEN
                PERFORM z4j_consume_schedule_reset_row_v1(
                  'schedule_change_log'
                );
                RETURN OLD;
              END IF;
              PERFORM z4j_consume_schedule_prune_row_v1(
                OLD.revision
              );
              RETURN OLD;
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE TRIGGER z4j_schedule_change_log_guard_v1
            BEFORE UPDATE OR DELETE ON schedule_change_log
            FOR EACH ROW EXECUTE FUNCTION z4j_schedule_change_log_guard_v1()
            """
        )
    )


def _install_postgresql_evidence_guards() -> None:
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_consume_schedule_evidence_guard_v1(
                p_scope text,
                p_row_id text,
                p_old_nonce text
              )
            RETURNS void AS $$
            DECLARE
              raw_guard text;
              descriptor jsonb;
              reason text;
            BEGIN
              raw_guard := current_setting(
                'z4j.schedule_evidence_guard',
                true
              );
              IF raw_guard IS NULL OR raw_guard = '' THEN
                RAISE EXCEPTION
                  'schedule evidence transition is not armed';
              END IF;
              BEGIN
                descriptor := raw_guard::jsonb;
              EXCEPTION WHEN OTHERS THEN
                RAISE EXCEPTION
                  'schedule evidence transition descriptor is malformed';
              END;
              reason := descriptor ->> 'reason';
              IF descriptor ->> 'scope' IS DISTINCT FROM p_scope
                 OR descriptor ->> 'row_id' IS DISTINCT FROM p_row_id
                 OR descriptor ->> 'old_nonce' IS DISTINCT FROM p_old_nonce
                 OR NOT (
                   (
                     p_scope = 'commands:delete'
                     AND reason IN (
                       'command_retention',
                       'legacy_resolution',
                       'reset'
                     )
                   )
                   OR (
                     p_scope = 'schedule_fires:delete'
                     AND reason IN (
                       'history_retention',
                       'legacy_resolution',
                       'reset'
                     )
                   )
                   OR (
                     p_scope = 'pending_fires:delete'
                     AND reason IN (
                       'pending_expiry',
                       'pending_replay',
                       'pending_stale',
                       'legacy_resolution',
                       'schedule_delete',
                       'reset'
                     )
                   )
                   OR (
                     p_scope = 'schedule_terminal_holds:insert'
                     AND reason = 'terminal_hold'
                   )
                   OR (
                     p_scope = 'schedule_terminal_holds:update'
                     AND reason IN (
                       'operator_resolution',
                       'schedule_delete'
                     )
                   )
                   OR (
                     p_scope = 'schedule_terminal_holds:delete'
                     AND reason IN ('hold_retention', 'reset')
                   )
                   OR (
                     p_scope =
                       'schedule_occurrence_resolutions:insert'
                     AND reason IN (
                       'operator_resolution',
                       'schedule_delete'
                     )
                   )
                   OR (
                     p_scope =
                       'schedule_occurrence_resolutions:delete'
                     AND reason IN ('resolution_retention', 'reset')
                   )
                 ) THEN
                RAISE EXCEPTION
                  'schedule evidence transition descriptor mismatch';
              END IF;
              PERFORM set_config(
                'z4j.schedule_evidence_guard',
                '',
                true
              );
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION z4j_schedule_command_guard_v1()
            RETURNS trigger AS $$
            BEGIN
              IF TG_OP = 'DELETE'
                 AND z4j_schedule_reset_active_v1() THEN
                PERFORM z4j_consume_schedule_reset_row_v1(
                  'commands'
                );
                RETURN OLD;
              END IF;
              IF TG_OP = 'INSERT' AND NEW.action <> 'schedule.fire' THEN
                RETURN NEW;
              END IF;
              IF TG_OP <> 'INSERT' AND (
                OLD.action <> 'schedule.fire'
                OR OLD.schedule_protocol_marker IS DISTINCT FROM 1
              ) THEN
                RETURN COALESCE(NEW, OLD);
              END IF;
              IF TG_OP = 'DELETE' THEN
                PERFORM z4j_consume_schedule_evidence_guard_v1(
                  'commands:delete',
                  OLD.id::text,
                  OLD.schedule_state_nonce::text
                );
                RETURN OLD;
              END IF;
              IF TG_OP = 'INSERT' THEN
                IF NEW.schedule_protocol_marker IS DISTINCT FROM 1
                   OR NEW.schedule_state_nonce IS NULL THEN
                  RAISE EXCEPTION
                    'schedule command protocol marker required';
                END IF;
                IF NEW.schedule_receipt_control_token IS NULL THEN
                  RAISE EXCEPTION
                    'current schedule command receipt tuple is required';
                END IF;
              ELSE
                IF NEW.action IS DISTINCT FROM OLD.action
                   OR NEW.schedule_protocol_marker IS DISTINCT FROM 1
                   OR NEW.schedule_state_nonce IS NULL
                   OR NEW.schedule_state_nonce
                        IS NOT DISTINCT FROM OLD.schedule_state_nonce
                   OR NEW.id IS DISTINCT FROM OLD.id
                   OR NEW.project_id IS DISTINCT FROM OLD.project_id
                   OR NEW.target_type IS DISTINCT FROM OLD.target_type
                   OR NEW.target_id IS DISTINCT FROM OLD.target_id
                   OR NEW.payload IS DISTINCT FROM OLD.payload
                   OR NEW.idempotency_key
                        IS DISTINCT FROM OLD.idempotency_key
                   OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
                   OR NEW.source_ip IS DISTINCT FROM OLD.source_ip
                   OR NEW.bulk_retry_child_id
                        IS DISTINCT FROM OLD.bulk_retry_child_id
                   OR NOT (
                     NEW.issued_by IS NOT DISTINCT FROM OLD.issued_by
                     OR (
                       OLD.issued_by IS NOT NULL
                       AND NEW.issued_by IS NULL
                     )
                   )
                   OR NEW.schedule_id IS DISTINCT FROM OLD.schedule_id
                   OR NEW.schedule_fire_id
                        IS DISTINCT FROM OLD.schedule_fire_id
                   OR NEW.schedule_scheduled_for
                        IS DISTINCT FROM OLD.schedule_scheduled_for
                   OR NEW.schedule_observed_control_token
                        IS DISTINCT FROM OLD.schedule_observed_control_token
                   OR NEW.schedule_receipt_control_token
                        IS DISTINCT FROM OLD.schedule_receipt_control_token
                   OR NEW.schedule_execution_fire_id
                        IS DISTINCT FROM OLD.schedule_execution_fire_id
                   OR NEW.schedule_acceptance_revision
                        IS DISTINCT FROM OLD.schedule_acceptance_revision
                   OR NEW.schedule_definition_digest
                        IS DISTINCT FROM OLD.schedule_definition_digest
                   OR NEW.schedule_expected_revision
                        IS DISTINCT FROM OLD.schedule_expected_revision
                   OR NEW.schedule_expected_last_run_at
                        IS DISTINCT FROM OLD.schedule_expected_last_run_at
                   OR NEW.schedule_expected_next_run_at
                        IS DISTINCT FROM OLD.schedule_expected_next_run_at
                   OR NEW.schedule_next_run_at
                        IS DISTINCT FROM OLD.schedule_next_run_at
                   OR NEW.cadence_initial_claim_deadline
                        IS DISTINCT FROM OLD.cadence_initial_claim_deadline
                   OR (
                     (
                       NEW.first_delivery_claimed_at
                         IS DISTINCT FROM OLD.first_delivery_claimed_at
                       OR NEW.cadence_redelivery_deadline
                         IS DISTINCT FROM OLD.cadence_redelivery_deadline
                       OR NEW.delivery_transport_kind
                         IS DISTINCT FROM OLD.delivery_transport_kind
                       OR NEW.delivery_registry_owner_id
                         IS DISTINCT FROM OLD.delivery_registry_owner_id
                       OR NEW.delivery_session_generation
                         IS DISTINCT FROM OLD.delivery_session_generation
                       OR NEW.delivery_claim_token
                         IS DISTINCT FROM OLD.delivery_claim_token
                     )
                     AND NOT (
                       OLD.status = 'pending'
                       AND NEW.status = 'dispatched'
                       AND OLD.first_delivery_claimed_at IS NULL
                       AND OLD.cadence_redelivery_deadline IS NULL
                       AND OLD.delivery_transport_kind IS NULL
                       AND OLD.delivery_registry_owner_id IS NULL
                       AND OLD.delivery_session_generation IS NULL
                       AND OLD.delivery_claim_token IS NULL
                       AND NEW.first_delivery_claimed_at IS NOT NULL
                       AND NEW.cadence_redelivery_deadline IS NOT NULL
                       AND NEW.delivery_transport_kind IN (
                         'websocket',
                         'longpoll'
                       )
                       AND NEW.delivery_registry_owner_id IS NOT NULL
                       AND NEW.delivery_session_generation IS NOT NULL
                       AND NEW.delivery_claim_token IS NOT NULL
                     )
                   )
                   OR (
                     NEW.agent_acknowledged_at
                       IS DISTINCT FROM OLD.agent_acknowledged_at
                     AND NOT (
                       OLD.agent_acknowledged_at IS NULL
                       AND NEW.agent_acknowledged_at IS NOT NULL
                       AND OLD.status IN (
                         'dispatched',
                         'completed',
                         'failed',
                         'cancelled',
                         'timeout'
                       )
                       AND NEW.status IN (
                         'dispatched',
                         'completed',
                         'failed',
                         'cancelled',
                         'timeout'
                       )
                     )
                   )
                   OR (
                     NEW.agent_id IS DISTINCT FROM OLD.agent_id
                     AND NOT (
                       OLD.status = 'pending'
                       AND NEW.status = 'pending'
                       AND OLD.first_delivery_claimed_at IS NULL
                       AND NEW.first_delivery_claimed_at IS NULL
                       AND OLD.delivery_claim_token IS NULL
                       AND NEW.delivery_claim_token IS NULL
                     )
                   )
                   OR NOT (
                     NEW.status = OLD.status
                     OR (
                       OLD.status = 'pending'
                       AND NEW.status IN ('dispatched', 'timeout')
                     )
                     OR (
                       OLD.status = 'dispatched'
                       AND NEW.status IN (
                         'completed',
                         'failed',
                         'cancelled',
                         'timeout'
                       )
                     )
                   )
                   OR (
                     NEW.timeout_at IS DISTINCT FROM OLD.timeout_at
                     AND NOT (
                       OLD.status = 'pending'
                       AND NEW.status = 'dispatched'
                     )
                   )
                   OR (
                     NEW.dispatched_at IS DISTINCT FROM OLD.dispatched_at
                     AND NOT (
                       (
                         OLD.status = 'pending'
                         AND NEW.status = 'dispatched'
                         AND OLD.dispatched_at IS NULL
                         AND NEW.dispatched_at IS NOT NULL
                       )
                       OR (
                         OLD.status = 'dispatched'
                         AND NEW.status = 'dispatched'
                         AND OLD.dispatched_at IS NOT NULL
                         AND NEW.dispatched_at IS NOT NULL
                         AND OLD.agent_acknowledged_at IS NULL
                       )
                     )
                   )
                   OR (
                     (
                       NEW.completed_at IS DISTINCT FROM OLD.completed_at
                       OR NEW.result IS DISTINCT FROM OLD.result
                       OR NEW.error IS DISTINCT FROM OLD.error
                     )
                     AND NOT (
                       NEW.status IN (
                         'completed',
                         'failed',
                         'cancelled',
                         'timeout'
                       )
                       AND NEW.status <> OLD.status
                       AND NEW.completed_at IS NOT NULL
                     )
                   ) THEN
                  RAISE EXCEPTION 'invalid schedule command transition';
                END IF;
              END IF;
              IF NEW.schedule_receipt_control_token IS NOT NULL AND (
                NEW.schedule_id IS NULL
                OR NEW.schedule_fire_id IS NULL
                OR NEW.schedule_scheduled_for IS NULL
                OR NEW.schedule_execution_fire_id IS NULL
                OR NEW.schedule_acceptance_revision IS NULL
                OR NEW.schedule_definition_digest IS NULL
                OR NEW.schedule_expected_revision IS NULL
                OR NEW.schedule_expected_next_run_at IS NULL
                OR NEW.cadence_initial_claim_deadline IS NULL
              ) THEN
                RAISE EXCEPTION
                  'current schedule command tuple is incomplete';
              END IF;
              RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE TRIGGER z4j_schedule_command_guard_v1
            BEFORE INSERT OR UPDATE OR DELETE ON commands
            FOR EACH ROW
            EXECUTE FUNCTION z4j_schedule_command_guard_v1()
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION z4j_schedule_fire_guard_v1()
            RETURNS trigger AS $$
            BEGIN
              IF TG_OP = 'DELETE'
                 AND z4j_schedule_reset_active_v1() THEN
                PERFORM z4j_consume_schedule_reset_row_v1(
                  'schedule_fires'
                );
                RETURN OLD;
              END IF;
              IF TG_OP = 'DELETE' THEN
                PERFORM z4j_consume_schedule_evidence_guard_v1(
                  'schedule_fires:delete',
                  OLD.id::text,
                  OLD.state_write_nonce::text
                );
                RETURN OLD;
              END IF;
              IF NEW.protocol_marker IS DISTINCT FROM 1
                 OR NEW.state_write_nonce IS NULL THEN
                RAISE EXCEPTION 'schedule fire protocol marker required';
              END IF;
              IF TG_OP = 'INSERT'
                 AND NEW.receipt_control_token IS NULL THEN
                RAISE EXCEPTION
                  'current schedule fire receipt tuple is required';
              END IF;
              IF TG_OP = 'UPDATE' AND (
                NEW.state_write_nonce
                  IS NOT DISTINCT FROM OLD.state_write_nonce
                OR NEW.id IS DISTINCT FROM OLD.id
                OR NEW.fire_id IS DISTINCT FROM OLD.fire_id
                OR NEW.schedule_id IS DISTINCT FROM OLD.schedule_id
                OR NEW.project_id IS DISTINCT FROM OLD.project_id
                OR NEW.fired_at IS DISTINCT FROM OLD.fired_at
                OR NEW.scheduled_for IS DISTINCT FROM OLD.scheduled_for
                OR NOT (
                  NEW.triggered_by_user_id
                    IS NOT DISTINCT FROM OLD.triggered_by_user_id
                  OR (
                    OLD.triggered_by_user_id IS NOT NULL
                    AND NEW.triggered_by_user_id IS NULL
                  )
                )
                OR NEW.observed_control_token
                  IS DISTINCT FROM OLD.observed_control_token
                OR NEW.receipt_control_token
                  IS DISTINCT FROM OLD.receipt_control_token
                OR NEW.acceptance_revision
                  IS DISTINCT FROM OLD.acceptance_revision
                OR NEW.definition_digest
                  IS DISTINCT FROM OLD.definition_digest
                OR NEW.expected_schedule_revision
                  IS DISTINCT FROM OLD.expected_schedule_revision
                OR NEW.expected_last_run_at
                  IS DISTINCT FROM OLD.expected_last_run_at
                OR NEW.expected_next_run_at
                  IS DISTINCT FROM OLD.expected_next_run_at
                OR NEW.prepared_next_run_at
                  IS DISTINCT FROM OLD.prepared_next_run_at
                OR (
                  NEW.command_id IS DISTINCT FROM OLD.command_id
                  AND NOT (
                    OLD.command_id IS NULL
                    AND NEW.command_id IS NOT NULL
                    AND OLD.receipt_control_token IS NOT NULL
                    AND NEW.receipt_control_token
                      IS NOT DISTINCT FROM OLD.receipt_control_token
                  )
                )
                OR NOT (
                  NEW.status = OLD.status
                  OR (
                    OLD.receipt_control_token IS NOT NULL
                    AND OLD.status = 'buffered'
                    AND NEW.status IN (
                      'accepted',
                      'buffer_expired',
                      'buffer_stale'
                    )
                  )
                  OR (
                    OLD.receipt_control_token IS NOT NULL
                    AND OLD.status = 'accepted'
                    AND NEW.status IN (
                      'terminal_completed',
                      'terminal_failed',
                      'terminal_cancelled',
                      'terminal_timeout'
                    )
                  )
                  OR (
                    OLD.receipt_control_token IS NULL
                    AND NEW.status = 'operator_skipped'
                  )
                )
                OR (
                  NEW.scheduler_ack_status
                    IS DISTINCT FROM OLD.scheduler_ack_status
                  AND NOT (
                    (
                      OLD.scheduler_ack_status IS NULL
                      AND NEW.scheduler_ack_status IN (
                        'success',
                        'failed'
                      )
                    )
                    OR (
                      OLD.scheduler_ack_status = 'failed'
                      AND NEW.scheduler_ack_status = 'success'
                    )
                  )
                )
                OR (
                  (
                    NEW.scheduler_acknowledged_at
                      IS DISTINCT FROM OLD.scheduler_acknowledged_at
                    OR NEW.scheduler_ack_task_id
                      IS DISTINCT FROM OLD.scheduler_ack_task_id
                    OR NEW.scheduler_ack_error_code
                      IS DISTINCT FROM OLD.scheduler_ack_error_code
                    OR NEW.scheduler_ack_error_message
                      IS DISTINCT FROM OLD.scheduler_ack_error_message
                  )
                  AND NEW.scheduler_ack_status
                    IS NOT DISTINCT FROM OLD.scheduler_ack_status
                )
                OR (
                  (
                    NEW.acked_at IS DISTINCT FROM OLD.acked_at
                    OR NEW.latency_ms IS DISTINCT FROM OLD.latency_ms
                    OR NEW.error_code IS DISTINCT FROM OLD.error_code
                    OR NEW.error_message IS DISTINCT FROM OLD.error_message
                  )
                  AND NEW.status = OLD.status
                  AND NEW.scheduler_ack_status
                    IS NOT DISTINCT FROM OLD.scheduler_ack_status
                )
              ) THEN
                RAISE EXCEPTION 'invalid schedule fire transition';
              END IF;
              IF NEW.receipt_control_token IS NOT NULL AND (
                NEW.acceptance_revision IS NULL
                OR NEW.definition_digest IS NULL
                OR NEW.expected_schedule_revision IS NULL
                OR NEW.expected_next_run_at IS NULL
              ) THEN
                RAISE EXCEPTION 'current schedule fire tuple is incomplete';
              END IF;
              RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE TRIGGER z4j_schedule_fire_guard_v1
            BEFORE INSERT OR UPDATE OR DELETE ON schedule_fires
            FOR EACH ROW EXECUTE FUNCTION z4j_schedule_fire_guard_v1()
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION z4j_pending_fire_guard_v1()
            RETURNS trigger AS $$
            BEGIN
              IF TG_OP = 'DELETE'
                 AND z4j_schedule_reset_active_v1() THEN
                PERFORM z4j_consume_schedule_reset_row_v1(
                  'pending_fires'
                );
                RETURN OLD;
              END IF;
              IF TG_OP = 'DELETE' THEN
                PERFORM z4j_consume_schedule_evidence_guard_v1(
                  'pending_fires:delete',
                  OLD.id::text,
                  OLD.state_write_nonce::text
                );
                RETURN OLD;
              END IF;
              IF TG_OP = 'UPDATE' THEN
                RAISE EXCEPTION 'invalid pending fire transition';
              END IF;
              IF NEW.protocol_marker IS DISTINCT FROM 1
                 OR NEW.state_write_nonce IS NULL THEN
                RAISE EXCEPTION 'pending fire protocol marker required';
              END IF;
              IF NEW.receipt_control_token IS NULL THEN
                RAISE EXCEPTION
                  'current pending fire receipt tuple is required';
              END IF;
              IF NEW.receipt_control_token IS NOT NULL AND (
                NEW.definition_digest IS NULL
                OR NEW.expected_schedule_revision IS NULL
                OR NEW.expected_next_run_at IS NULL
                OR NEW.acceptance_revision IS NULL
                OR NEW.execution_fire_id IS NULL
              ) THEN
                RAISE EXCEPTION 'current pending fire tuple is incomplete';
              END IF;
              RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE TRIGGER z4j_pending_fire_guard_v1
            BEFORE INSERT OR UPDATE OR DELETE ON pending_fires
            FOR EACH ROW EXECUTE FUNCTION z4j_pending_fire_guard_v1()
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_schedule_terminal_hold_guard_v1()
            RETURNS trigger AS $$
            BEGIN
              IF TG_OP = 'DELETE'
                 AND z4j_schedule_reset_active_v1() THEN
                PERFORM z4j_consume_schedule_reset_row_v1(
                  'schedule_terminal_holds'
                );
                RETURN OLD;
              END IF;
              IF TG_OP = 'DELETE' THEN
                PERFORM z4j_consume_schedule_evidence_guard_v1(
                  'schedule_terminal_holds:delete',
                  OLD.id::text,
                  OLD.state_write_nonce::text
                );
                RETURN OLD;
              END IF;
              IF TG_OP = 'INSERT' THEN
                IF NEW.state_write_nonce IS NULL
                   OR NEW.resolved_at IS NOT NULL
                   OR NEW.resolved_by IS NOT NULL
                   OR NEW.resolution_disposition IS NOT NULL
                   OR NEW.resolution_source IS NOT NULL
                   OR NEW.work_may_have_executed IS NOT NULL
                   OR NEW.resolution_control_token IS NOT NULL
                   OR NEW.deletion_tombstone_revision IS NOT NULL THEN
                  RAISE EXCEPTION 'invalid terminal hold creation';
                END IF;
                PERFORM z4j_consume_schedule_evidence_guard_v1(
                  'schedule_terminal_holds:insert',
                  NEW.id::text,
                  NEW.state_write_nonce::text
                );
                RETURN NEW;
              END IF;
              IF OLD.resolved_at IS NOT NULL
                 OR NEW.resolved_at IS NULL
                 OR NEW.state_write_nonce IS NULL
                 OR NEW.state_write_nonce
                      IS NOT DISTINCT FROM OLD.state_write_nonce
                 OR NEW.id IS DISTINCT FROM OLD.id
                 OR NEW.project_id IS DISTINCT FROM OLD.project_id
                 OR NEW.schedule_id IS DISTINCT FROM OLD.schedule_id
                 OR NEW.fire_id IS DISTINCT FROM OLD.fire_id
                 OR NEW.scheduled_for IS DISTINCT FROM OLD.scheduled_for
                 OR NEW.command_id IS DISTINCT FROM OLD.command_id
                 OR NEW.observed_control_token
                      IS DISTINCT FROM OLD.observed_control_token
                 OR NEW.receipt_control_token
                      IS DISTINCT FROM OLD.receipt_control_token
                 OR NEW.acceptance_revision
                      IS DISTINCT FROM OLD.acceptance_revision
                 OR NEW.terminal_status
                      IS DISTINCT FROM OLD.terminal_status
                 OR NEW.terminal_detail
                      IS DISTINCT FROM OLD.terminal_detail
                 OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'invalid terminal hold resolution';
              END IF;
              PERFORM z4j_consume_schedule_evidence_guard_v1(
                'schedule_terminal_holds:update',
                OLD.id::text,
                OLD.state_write_nonce::text
              );
              RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE TRIGGER z4j_schedule_terminal_hold_guard_v1
            BEFORE INSERT OR UPDATE OR DELETE
            ON schedule_terminal_holds
            FOR EACH ROW
            EXECUTE FUNCTION z4j_schedule_terminal_hold_guard_v1()
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_schedule_occurrence_resolution_guard_v1()
            RETURNS trigger AS $$
            BEGIN
              IF TG_OP = 'DELETE'
                 AND z4j_schedule_reset_active_v1() THEN
                PERFORM z4j_consume_schedule_reset_row_v1(
                  'schedule_occurrence_resolutions'
                );
                RETURN OLD;
              END IF;
              IF TG_OP = 'UPDATE' THEN
                RAISE EXCEPTION 'occurrence resolution is immutable';
              END IF;
              IF TG_OP = 'DELETE' THEN
                PERFORM z4j_consume_schedule_evidence_guard_v1(
                  'schedule_occurrence_resolutions:delete',
                  OLD.id::text,
                  OLD.state_write_nonce::text
                );
                RETURN OLD;
              END IF;
              IF NEW.state_write_nonce IS NULL THEN
                RAISE EXCEPTION 'resolution nonce is required';
              END IF;
              PERFORM z4j_consume_schedule_evidence_guard_v1(
                'schedule_occurrence_resolutions:insert',
                NEW.id::text,
                NEW.state_write_nonce::text
              );
              RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE TRIGGER z4j_schedule_occurrence_resolution_guard_v1
            BEFORE INSERT OR UPDATE OR DELETE
            ON schedule_occurrence_resolutions
            FOR EACH ROW
            EXECUTE FUNCTION
              z4j_schedule_occurrence_resolution_guard_v1()
            """
        )
    )


def _install_postgresql_external_guards() -> None:
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_consume_external_allocation_guard_v1(
                p_mode text,
                p_stream_id uuid,
                p_epoch_uuid uuid,
                p_epoch_number bigint,
                p_old_epoch_number bigint,
                p_source_scope_digest text,
                p_owner text,
                p_project_id uuid,
                p_adapter_instance_id text
              )
            RETURNS void AS $$
            DECLARE
              raw_guard text;
              descriptor jsonb;
            BEGIN
              raw_guard := current_setting(
                'z4j.schedule_external_allocation_guard',
                true
              );
              IF raw_guard IS NULL OR raw_guard = '' THEN
                RAISE EXCEPTION
                  'external epoch allocation is not armed';
              END IF;
              BEGIN
                descriptor := raw_guard::jsonb;
              EXCEPTION WHEN OTHERS THEN
                RAISE EXCEPTION
                  'external epoch allocation descriptor is malformed';
              END;
              IF (descriptor->>'epoch_number')::bigint
                   IS DISTINCT FROM p_epoch_number THEN
                RAISE EXCEPTION
                  'external epoch allocation number mismatch';
              END IF;
              IF p_mode = 'allocator' THEN
                IF COALESCE(
                     (descriptor->>'allocator')::boolean,
                     false
                   )
                   OR (descriptor->>'old_epoch_number')::bigint
                     IS DISTINCT FROM p_old_epoch_number THEN
                  RAISE EXCEPTION
                    'external allocator transition mismatch';
                END IF;
                descriptor := jsonb_set(
                  descriptor,
                  '{allocator}',
                  'true'::jsonb,
                  true
                );
              ELSE
                IF replace(descriptor->>'stream_id', '-', '')
                     IS DISTINCT FROM
                       replace(p_stream_id::text, '-', '')
                   OR replace(descriptor->>'epoch_uuid', '-', '')
                     IS DISTINCT FROM
                       replace(p_epoch_uuid::text, '-', '') THEN
                  RAISE EXCEPTION
                    'external allocation identity mismatch';
                END IF;
                IF p_mode = 'epoch' THEN
                  IF COALESCE(
                       (descriptor->>'epoch')::boolean,
                       false
                     )
                     OR COALESCE(
                       descriptor->>'adapter_instance_id',
                       ''
                     ) IS DISTINCT FROM COALESCE(
                       p_adapter_instance_id,
                       ''
                     ) THEN
                    RAISE EXCEPTION
                      'external allocated epoch already consumed';
                  END IF;
                  descriptor := jsonb_set(
                    descriptor,
                    '{epoch}',
                    'true'::jsonb,
                    true
                  );
                ELSIF p_mode = 'stream' THEN
                  IF NOT COALESCE(
                       (descriptor->>'allocator')::boolean,
                       false
                     )
                     OR NOT COALESCE(
                       (descriptor->>'epoch')::boolean,
                       false
                     )
                     OR replace(
                       descriptor->>'project_id',
                       '-',
                       ''
                     ) IS DISTINCT FROM replace(
                       p_project_id::text,
                       '-',
                       ''
                     )
                     OR descriptor->>'owner'
                       IS DISTINCT FROM p_owner
                     OR descriptor->>'source_scope_digest'
                       IS DISTINCT FROM p_source_scope_digest THEN
                    RAISE EXCEPTION
                      'external stream allocation is incomplete';
                  END IF;
                  PERFORM set_config(
                    'z4j.schedule_external_allocation_guard',
                    '',
                    true
                  );
                  RETURN;
                ELSE
                  RAISE EXCEPTION
                    'unknown external allocation guard operation';
                END IF;
              END IF;
              PERFORM set_config(
                'z4j.schedule_external_allocation_guard',
                descriptor::text,
                true
              );
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_consume_external_projection_guard_v1(
                p_mode text,
                p_stream_id uuid,
                p_epoch_uuid uuid,
                p_epoch_number bigint,
                p_sequence bigint,
                p_digest text,
                p_source_key text,
                p_operation text
              )
            RETURNS void AS $$
            DECLARE
              raw_guard text;
              descriptor jsonb;
              mutation_index integer;
              mutation_count integer;
            BEGIN
              raw_guard := current_setting(
                'z4j.schedule_external_projection_guard',
                true
              );
              IF raw_guard IS NULL OR raw_guard = '' THEN
                RAISE EXCEPTION 'external projection is not armed';
              END IF;
              BEGIN
                descriptor := raw_guard::jsonb;
              EXCEPTION WHEN OTHERS THEN
                RAISE EXCEPTION
                  'external projection descriptor is malformed';
              END;
              IF replace(descriptor->>'stream_id', '-', '')
                   IS DISTINCT FROM replace(p_stream_id::text, '-', '')
                 OR replace(descriptor->>'epoch_uuid', '-', '')
                   IS DISTINCT FROM replace(p_epoch_uuid::text, '-', '')
                 OR (descriptor->>'epoch_number')::bigint
                   IS DISTINCT FROM p_epoch_number THEN
                RAISE EXCEPTION
                  'external projection descriptor mismatch';
              END IF;

              IF p_mode = 'snapshot_frame' THEN
                IF descriptor->>'guard_kind' <> 'snapshot_frame'
                   OR (descriptor->>'sequence')::bigint
                     IS DISTINCT FROM p_sequence
                   OR descriptor->>'payload_digest'
                     IS DISTINCT FROM p_digest
                   OR replace(descriptor->>'snapshot_id', '-', '')
                     IS DISTINCT FROM replace(p_source_key, '-', '')
                   OR (descriptor->>'frame_index')::integer
                     IS DISTINCT FROM p_operation::integer THEN
                  RAISE EXCEPTION
                    'external snapshot frame descriptor mismatch';
                END IF;
                PERFORM set_config(
                  'z4j.schedule_external_projection_guard',
                  '',
                  true
                );
                RETURN;
              END IF;
              IF p_mode IN (
                'ambiguity_epoch',
                'ambiguity_stream'
              ) THEN
                IF COALESCE(
                     descriptor->>'guard_kind',
                     'projection'
                   ) <> 'ambiguity'
                   OR descriptor->>'adapter_instance_id'
                     IS DISTINCT FROM p_source_key THEN
                  RAISE EXCEPTION
                    'external ambiguity descriptor mismatch';
                END IF;
                IF p_mode = 'ambiguity_epoch' THEN
                  IF COALESCE(
                       (descriptor->>'epoch')::boolean,
                       false
                     ) THEN
                    RAISE EXCEPTION
                      'external epoch ambiguity already consumed';
                  END IF;
                  descriptor := jsonb_set(
                    descriptor,
                    '{epoch}',
                    'true'::jsonb,
                    true
                  );
                  PERFORM set_config(
                    'z4j.schedule_external_projection_guard',
                    descriptor::text,
                    true
                  );
                  RETURN;
                END IF;
                IF NOT COALESCE(
                     (descriptor->>'epoch')::boolean,
                     false
                   ) THEN
                  RAISE EXCEPTION
                    'external ambiguity transition is incomplete';
                END IF;
                PERFORM set_config(
                  'z4j.schedule_external_projection_guard',
                  '',
                  true
                );
                RETURN;
              END IF;
              IF COALESCE(
                   descriptor->>'guard_kind',
                   'projection'
                 ) <> 'projection' THEN
                RAISE EXCEPTION
                  'external projection guard kind mismatch';
              END IF;

              IF p_mode = 'schedule' THEN
                IF p_sequence NOT IN (
                  0,
                  (descriptor->>'sequence')::bigint
                ) THEN
                  RAISE EXCEPTION
                    'external schedule sequence mismatch';
                END IF;
                SELECT COUNT(*), MIN(ordinality::integer - 1)
                  INTO mutation_count, mutation_index
                FROM jsonb_array_elements(
                  descriptor->'mutations'
                ) WITH ORDINALITY AS entry(item, ordinality)
                WHERE item->>'operation' = p_operation
                  AND item->>'source_key' = p_source_key
                  AND replace(item->>'schedule_id', '-', '')
                    = replace(p_digest, '-', '');
                IF mutation_count <> 1 THEN
                  RAISE EXCEPTION
                    'external schedule mutation is not manifested';
                END IF;
                descriptor := jsonb_set(
                  descriptor,
                  '{mutations}',
                  (descriptor->'mutations') - mutation_index,
                  false
                );
              ELSE
                IF (descriptor->>'sequence')::bigint
                     IS DISTINCT FROM p_sequence
                   OR descriptor->>'payload_digest'
                     IS DISTINCT FROM p_digest THEN
                  RAISE EXCEPTION
                    'external projection header mismatch';
                END IF;
                IF p_mode IN ('epoch', 'stream')
                   AND descriptor->>'adapter_instance_id'
                     IS DISTINCT FROM p_source_key THEN
                  RAISE EXCEPTION
                    'external projection adapter mismatch';
                END IF;
                IF p_mode = 'ledger' THEN
                  IF COALESCE(
                       (descriptor->>'ledger')::boolean,
                       false
                     )
                     OR replace(
                       COALESCE(descriptor->>'operation_id', ''),
                       '-',
                       ''
                     ) IS DISTINCT FROM replace(
                       COALESCE(p_source_key, ''),
                       '-',
                       ''
                     ) THEN
                    RAISE EXCEPTION
                      'external projection ledger identity mismatched or already consumed';
                  END IF;
                  descriptor := jsonb_set(
                    descriptor,
                    '{ledger}',
                    'true'::jsonb,
                    true
                  );
                ELSIF p_mode = 'epoch' THEN
                  IF COALESCE(
                       (descriptor->>'epoch')::boolean,
                       false
                     ) THEN
                    RAISE EXCEPTION
                      'external epoch projection already consumed';
                  END IF;
                  descriptor := jsonb_set(
                    descriptor,
                    '{epoch}',
                    'true'::jsonb,
                    true
                  );
                ELSIF p_mode = 'stream' THEN
                  IF jsonb_array_length(
                       descriptor->'mutations'
                     ) <> 0
                     OR NOT COALESCE(
                       (descriptor->>'ledger')::boolean,
                       false
                     )
                     OR NOT COALESCE(
                       (descriptor->>'epoch')::boolean,
                       false
                     ) THEN
                    RAISE EXCEPTION
                      'external projection mutation set is incomplete';
                  END IF;
                  PERFORM set_config(
                    'z4j.schedule_external_projection_guard',
                    '',
                    true
                  );
                  RETURN;
                ELSE
                  RAISE EXCEPTION
                    'unknown external projection guard operation';
                END IF;
              END IF;
              PERFORM set_config(
                'z4j.schedule_external_projection_guard',
                descriptor::text,
                true
              );
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_schedule_external_row_guard_v1()
            RETURNS trigger AS $$
            DECLARE
              row_stream_id uuid;
              row_epoch_uuid uuid;
              row_epoch_number bigint;
              row_sequence bigint;
              row_source_key text;
              row_id uuid;
              matching_streams bigint;
            BEGIN
              IF (
                SELECT guard_version FROM schedule_revision_state
                WHERE singleton_id = 'schedule-revision'
              ) IS DISTINCT FROM 1 THEN
                RETURN COALESCE(NEW, OLD);
              END IF;
              IF TG_OP = 'DELETE'
                 AND z4j_schedule_reset_active_v1() THEN
                RETURN OLD;
              END IF;
              IF TG_OP = 'UPDATE'
                 AND OLD.scheduler IS DISTINCT FROM NEW.scheduler THEN
                IF NEW.scheduler <> 'z4j-scheduler' THEN
                  SELECT COUNT(*) INTO matching_streams
                  FROM schedule_external_streams
                  WHERE id = NEW.external_stream_id
                    AND project_id = NEW.project_id
                    AND owner = NEW.scheduler
                    AND current_epoch_uuid = NEW.external_epoch_uuid
                    AND current_epoch_number
                      = NEW.external_epoch_number
                    AND accepted_sequence = 0
                    AND phase = 'ACTIVATING';
                  IF matching_streams <> 1
                     OR NEW.external_source_sequence <> 0 THEN
                    RAISE EXCEPTION
                      'external cutover target is not activating';
                  END IF;
                END IF;
                PERFORM
                  z4j_consume_external_cutover_schedule_guard_v1(
                    CASE WHEN OLD.scheduler <> 'z4j-scheduler'
                      THEN OLD.external_stream_id
                      ELSE NEW.external_stream_id
                    END,
                    CASE WHEN OLD.scheduler <> 'z4j-scheduler'
                      THEN OLD.external_epoch_uuid
                      ELSE NEW.external_epoch_uuid
                    END,
                    CASE WHEN OLD.scheduler <> 'z4j-scheduler'
                      THEN OLD.external_epoch_number
                      ELSE NEW.external_epoch_number
                    END,
                    NEW.id,
                    OLD.scheduler,
                    NEW.scheduler
                  );
                RETURN NEW;
              END IF;
              IF (
                CASE WHEN TG_OP = 'DELETE'
                  THEN OLD.scheduler ELSE NEW.scheduler
                END
              ) = 'z4j-scheduler' THEN
                RETURN COALESCE(NEW, OLD);
              END IF;
              IF TG_OP = 'UPDATE' AND (
                OLD.scheduler = 'z4j-scheduler'
                OR NEW.external_stream_id
                  IS DISTINCT FROM OLD.external_stream_id
                OR NEW.external_source_key
                  IS DISTINCT FROM OLD.external_source_key
              ) THEN
                RAISE EXCEPTION
                  'external owner transition requires cutover authority';
              END IF;
              row_stream_id := CASE WHEN TG_OP = 'DELETE'
                THEN OLD.external_stream_id
                ELSE NEW.external_stream_id
              END;
              row_epoch_uuid := CASE WHEN TG_OP = 'DELETE'
                THEN OLD.external_epoch_uuid
                ELSE NEW.external_epoch_uuid
              END;
              row_epoch_number := CASE WHEN TG_OP = 'DELETE'
                THEN OLD.external_epoch_number
                ELSE NEW.external_epoch_number
              END;
              row_sequence := CASE WHEN TG_OP = 'DELETE'
                THEN 0 ELSE NEW.external_source_sequence
              END;
              row_source_key := CASE WHEN TG_OP = 'DELETE'
                THEN OLD.external_source_key
                ELSE NEW.external_source_key
              END;
              row_id := CASE WHEN TG_OP = 'DELETE'
                THEN OLD.id ELSE NEW.id
              END;
              SELECT COUNT(*) INTO matching_streams
              FROM schedule_external_streams
              WHERE id = row_stream_id
                AND project_id = CASE WHEN TG_OP = 'DELETE'
                  THEN OLD.project_id ELSE NEW.project_id
                END
                AND owner = CASE WHEN TG_OP = 'DELETE'
                  THEN OLD.scheduler ELSE NEW.scheduler
                END
                AND current_epoch_uuid = row_epoch_uuid
                AND current_epoch_number = row_epoch_number
                AND (
                  TG_OP = 'DELETE'
                  OR accepted_sequence + 1 = row_sequence
                )
                AND phase IN ('ACTIVATING', 'ACTIVE', 'DRAINING');
              IF matching_streams <> 1 THEN
                RAISE EXCEPTION
                  'external schedule mutation is not current';
              END IF;
              PERFORM z4j_consume_external_projection_guard_v1(
                'schedule',
                row_stream_id,
                row_epoch_uuid,
                row_epoch_number,
                row_sequence,
                row_id::text,
                row_source_key,
                lower(TG_OP)
              );
              RETURN COALESCE(NEW, OLD);
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE TRIGGER z4j_schedule_external_row_guard_v1
            BEFORE INSERT OR UPDATE OR DELETE ON schedules
            FOR EACH ROW
            EXECUTE FUNCTION z4j_schedule_external_row_guard_v1()
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_schedule_external_projection_guard_v1()
            RETURNS trigger AS $$
            DECLARE
              matching_streams bigint;
            BEGIN
              IF TG_OP = 'DELETE'
                 AND z4j_schedule_reset_active_v1() THEN
                PERFORM z4j_consume_schedule_reset_row_v1(
                  'schedule_external_projections'
                );
                RETURN OLD;
              END IF;
              IF TG_OP <> 'INSERT' THEN
                RAISE EXCEPTION
                  'external projection ledger is immutable';
              END IF;
              SELECT COUNT(*) INTO matching_streams
              FROM schedule_external_streams
              WHERE id = NEW.stream_id
                AND current_epoch_uuid = NEW.epoch_uuid
                AND current_epoch_number = NEW.epoch_number
                AND accepted_sequence + 1 = NEW.sequence
                AND phase IN ('ACTIVATING', 'ACTIVE', 'DRAINING');
              IF matching_streams <> 1 THEN
                RAISE EXCEPTION
                  'external projection is not exact next';
              END IF;
              PERFORM z4j_consume_external_projection_guard_v1(
                'ledger',
                NEW.stream_id,
                NEW.epoch_uuid,
                NEW.epoch_number,
                NEW.sequence,
                NEW.payload_digest,
                COALESCE(NEW.operation_id::text, ''),
                NEW.kind
              );
              RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE TRIGGER z4j_schedule_external_projection_guard_v1
            BEFORE INSERT OR UPDATE OR DELETE
            ON schedule_external_projections
            FOR EACH ROW
            EXECUTE FUNCTION
              z4j_schedule_external_projection_guard_v1()
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_schedule_external_snapshot_frame_guard_v1()
            RETURNS trigger AS $$
            DECLARE
              matching_streams bigint;
            BEGIN
              IF TG_OP = 'DELETE'
                 AND z4j_schedule_reset_active_v1() THEN
                PERFORM z4j_consume_schedule_reset_row_v1(
                  'schedule_external_snapshot_frames'
                );
                RETURN OLD;
              END IF;
              IF TG_OP <> 'INSERT' THEN
                RAISE EXCEPTION
                  'external snapshot frame is immutable';
              END IF;
              SELECT COUNT(*) INTO matching_streams
              FROM schedule_external_streams
              WHERE id = NEW.stream_id
                AND project_id = NEW.project_id
                AND owner = NEW.owner
                AND source_scope = NEW.source_scope
                AND current_epoch_uuid = NEW.epoch_uuid
                AND current_epoch_number = NEW.epoch_number
                AND authorized_adapter_instance_id
                  IS NOT DISTINCT FROM NEW.adapter_instance_id
                AND accepted_sequence + 1 = NEW.sequence
                AND phase IN ('ACTIVATING', 'ACTIVE', 'DRAINING');
              IF matching_streams <> 1 THEN
                RAISE EXCEPTION
                  'external snapshot frame is not current';
              END IF;
              PERFORM z4j_consume_external_projection_guard_v1(
                'snapshot_frame',
                NEW.stream_id,
                NEW.epoch_uuid,
                NEW.epoch_number,
                NEW.sequence,
                NEW.frame_digest,
                NEW.snapshot_id::text,
                NEW.frame_index::text
              );
              RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE TRIGGER z4j_schedule_external_snapshot_frame_guard_v1
            BEFORE INSERT OR UPDATE OR DELETE
            ON schedule_external_snapshot_frames
            FOR EACH ROW
            EXECUTE FUNCTION
              z4j_schedule_external_snapshot_frame_guard_v1()
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_consume_external_control_guard_v1(
                p_transition text,
                p_operation_id uuid,
                p_stream_id uuid,
                p_epoch_number bigint,
                p_reserved_sequence bigint,
                p_state_nonce uuid,
                p_dispatch_lease uuid,
                p_terminal_id uuid
              )
            RETURNS void AS $$
            DECLARE
              raw_guard text;
              descriptor jsonb;
            BEGIN
              raw_guard := current_setting(
                'z4j.schedule_external_control_guard',
                true
              );
              IF raw_guard IS NULL OR raw_guard = '' THEN
                RAISE EXCEPTION
                  'external control transition is not armed';
              END IF;
              BEGIN
                descriptor := raw_guard::jsonb;
              EXCEPTION WHEN OTHERS THEN
                RAISE EXCEPTION
                  'external control descriptor is malformed';
              END;
              IF descriptor->>'transition'
                   IS DISTINCT FROM p_transition
                 OR replace(
                   descriptor->>'operation_id',
                   '-',
                   ''
                 ) IS DISTINCT FROM replace(
                   p_operation_id::text,
                   '-',
                   ''
                 )
                 OR replace(
                   descriptor->>'stream_id',
                   '-',
                   ''
                 ) IS DISTINCT FROM replace(
                   p_stream_id::text,
                   '-',
                   ''
                 )
                 OR (descriptor->>'epoch_number')::bigint
                   IS DISTINCT FROM p_epoch_number
                 OR (descriptor->>'reserved_sequence')::bigint
                   IS DISTINCT FROM p_reserved_sequence
                 OR replace(
                   descriptor->>'state_nonce',
                   '-',
                   ''
                 ) IS DISTINCT FROM replace(
                   p_state_nonce::text,
                   '-',
                   ''
                 )
                 OR replace(
                   COALESCE(descriptor->>'dispatch_lease', ''),
                   '-',
                   ''
                 ) IS DISTINCT FROM replace(
                   COALESCE(p_dispatch_lease::text, ''),
                   '-',
                   ''
                 )
                 OR replace(
                   COALESCE(descriptor->>'terminal_id', ''),
                   '-',
                   ''
                 ) IS DISTINCT FROM replace(
                   COALESCE(p_terminal_id::text, ''),
                   '-',
                   ''
                 ) THEN
                RAISE EXCEPTION
                  'external control transition descriptor mismatch';
              END IF;
              PERFORM set_config(
                'z4j.schedule_external_control_guard',
                '',
                true
              );
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_schedule_external_control_guard_v1()
            RETURNS trigger AS $$
            DECLARE
              matching_rows bigint;
            BEGIN
              IF TG_OP = 'DELETE'
                 AND z4j_schedule_reset_active_v1() THEN
                PERFORM z4j_consume_schedule_reset_row_v1(
                  'schedule_external_control_operations'
                );
                RETURN OLD;
              END IF;
              IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION
                  'external control evidence is retained';
              END IF;
              IF TG_OP = 'INSERT' THEN
                IF NEW.status <> 'PENDING'
                   OR NEW.command_id IS NULL
                   OR NEW.session_generation IS NULL
                   OR NEW.dispatch_lease IS NOT NULL
                   OR NEW.reserved_sequence IS NOT NULL
                   OR NEW.result_projection_id IS NOT NULL THEN
                  RAISE EXCEPTION
                    'external control insert is malformed';
                END IF;
                SELECT COUNT(*) INTO matching_rows
                FROM schedule_external_streams AS stream
                JOIN schedules AS schedule
                  ON schedule.id = NEW.schedule_id
                 AND schedule.project_id = stream.project_id
                 AND schedule.external_stream_id = stream.id
                 AND schedule.external_epoch_uuid
                       = stream.current_epoch_uuid
                 AND schedule.external_epoch_number
                       = stream.current_epoch_number
                 AND schedule.external_source_key = NEW.source_key
                 AND schedule.schedule_revision
                       = NEW.expected_schedule_revision
                 AND schedule.control_token
                       = NEW.expected_control_token
                JOIN commands AS command
                  ON command.id = NEW.command_id
                 AND command.project_id = stream.project_id
                 AND command.agent_id = NEW.agent_id
                 AND command.action = 'schedule.external.control'
                 AND command.status = 'pending'
                 AND command.payload->>'operation_id'
                       = NEW.id::text
                WHERE stream.id = NEW.stream_id
                  AND stream.current_epoch_uuid = NEW.epoch_uuid
                  AND stream.current_epoch_number = NEW.epoch_number
                  AND stream.accepted_sequence
                        = NEW.expected_accepted_sequence
                  AND stream.phase = 'ACTIVE'
                  AND stream.authorized_adapter_instance_id
                        = NEW.adapter_instance_id
                  AND stream.executor_agent_id = NEW.agent_id
                  AND stream.executor_registry_owner_id
                        = NEW.registry_owner_id
                  AND stream.executor_session_generation
                        = NEW.session_generation;
                IF matching_rows <> 1 THEN
                  RAISE EXCEPTION
                    'external control insert is not current';
                END IF;
                PERFORM z4j_consume_external_control_guard_v1(
                  'insert',
                  NEW.id,
                  NEW.stream_id,
                  NEW.epoch_number,
                  0,
                  NEW.state_nonce,
                  NULL,
                  NEW.command_id
                );
                RETURN NEW;
              END IF;

              IF NEW.id IS DISTINCT FROM OLD.id
                 OR NEW.request_idempotency_key
                   IS DISTINCT FROM OLD.request_idempotency_key
                 OR NEW.schedule_id IS DISTINCT FROM OLD.schedule_id
                 OR NEW.command_id IS DISTINCT FROM OLD.command_id
                 OR NEW.agent_id IS DISTINCT FROM OLD.agent_id
                 OR NEW.stream_id IS DISTINCT FROM OLD.stream_id
                 OR NEW.epoch_uuid IS DISTINCT FROM OLD.epoch_uuid
                 OR NEW.epoch_number IS DISTINCT FROM OLD.epoch_number
                 OR NEW.source_key IS DISTINCT FROM OLD.source_key
                 OR NEW.expected_accepted_sequence
                   IS DISTINCT FROM OLD.expected_accepted_sequence
                 OR NEW.expected_schedule_revision
                   IS DISTINCT FROM OLD.expected_schedule_revision
                 OR NEW.expected_control_token
                   IS DISTINCT FROM OLD.expected_control_token
                 OR NEW.prior_projection
                   IS DISTINCT FROM OLD.prior_projection
                 OR NEW.prior_projection_digest
                   IS DISTINCT FROM OLD.prior_projection_digest
                 OR NEW.desired_projection
                   IS DISTINCT FROM OLD.desired_projection
                 OR NEW.desired_projection_digest
                   IS DISTINCT FROM OLD.desired_projection_digest
                 OR NEW.adapter_instance_id
                   IS DISTINCT FROM OLD.adapter_instance_id
                 OR NEW.session_generation
                   IS DISTINCT FROM OLD.session_generation
                 OR NEW.registry_owner_id
                   IS DISTINCT FROM OLD.registry_owner_id
                 OR NEW.state_nonce IS DISTINCT FROM OLD.state_nonce
                 OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION
                  'external control identity is immutable';
              END IF;
              IF OLD.status = 'PENDING'
                 AND NEW.status = 'CLAIMED'
                 AND OLD.dispatch_lease IS NULL
                 AND NEW.dispatch_lease IS NOT NULL
                 AND OLD.reserved_sequence IS NULL
                 AND NEW.reserved_sequence
                       = NEW.expected_accepted_sequence + 1
                 AND NEW.result_projection_id IS NULL THEN
                PERFORM z4j_consume_external_control_guard_v1(
                  'claim',
                  NEW.id,
                  NEW.stream_id,
                  NEW.epoch_number,
                  NEW.reserved_sequence,
                  NEW.state_nonce,
                  NEW.dispatch_lease,
                  NEW.command_id
                );
              ELSIF OLD.status = 'CLAIMED'
                 AND NEW.status = 'APPLIED'
                 AND NEW.dispatch_lease
                   IS NOT DISTINCT FROM OLD.dispatch_lease
                 AND NEW.reserved_sequence
                   IS NOT DISTINCT FROM OLD.reserved_sequence
                 AND NEW.result_projection_id IS NOT NULL THEN
                PERFORM z4j_consume_external_control_guard_v1(
                  'apply',
                  NEW.id,
                  NEW.stream_id,
                  NEW.epoch_number,
                  NEW.reserved_sequence,
                  NEW.state_nonce,
                  NEW.dispatch_lease,
                  NEW.result_projection_id
                );
              ELSIF OLD.status IN ('PENDING', 'CLAIMED')
                 AND NEW.status = 'AMBIGUOUS'
                 AND NEW.dispatch_lease
                   IS NOT DISTINCT FROM OLD.dispatch_lease
                 AND NEW.reserved_sequence
                   IS NOT DISTINCT FROM OLD.reserved_sequence
                 AND NEW.result_projection_id
                   IS NOT DISTINCT FROM OLD.result_projection_id THEN
                PERFORM z4j_consume_external_control_guard_v1(
                  'ambiguity',
                  NEW.id,
                  NEW.stream_id,
                  NEW.epoch_number,
                  COALESCE(NEW.reserved_sequence, 0),
                  NEW.state_nonce,
                  NEW.dispatch_lease,
                  NULL
                );
              ELSE
                RAISE EXCEPTION
                  'external control transition is invalid';
              END IF;
              RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE TRIGGER z4j_schedule_external_control_guard_v1
            BEFORE INSERT OR UPDATE OR DELETE
            ON schedule_external_control_operations
            FOR EACH ROW
            EXECUTE FUNCTION
              z4j_schedule_external_control_guard_v1()
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_consume_external_lifecycle_guard_v1(
                p_mode text,
                p_stream_id uuid,
                p_epoch_uuid uuid,
                p_epoch_number bigint,
                p_accepted_sequence bigint,
                p_to_phase text,
                p_last_snapshot_digest text,
                p_sealed_sequence bigint
              )
            RETURNS void AS $$
            DECLARE
              raw text;
              descriptor jsonb;
            BEGIN
              raw := current_setting(
                'z4j.schedule_external_lifecycle_guard',
                true
              );
              IF raw IS NULL OR raw = '' THEN
                RAISE EXCEPTION
                  'external lifecycle transition is not armed';
              END IF;
              descriptor := raw::jsonb;
              IF replace(
                   descriptor->>'stream_id', '-', ''
                 ) <> replace(p_stream_id::text, '-', '')
                 OR replace(
                   descriptor->>'epoch_uuid', '-', ''
                 ) <> replace(p_epoch_uuid::text, '-', '')
                 OR (descriptor->>'epoch_number')::bigint
                      <> p_epoch_number
                 OR (descriptor->>'accepted_sequence')::bigint
                      <> p_accepted_sequence
                 OR descriptor->>'to_phase' <> p_to_phase
                 OR COALESCE(
                      descriptor->>'last_snapshot_digest',
                      ''
                    ) <> COALESCE(p_last_snapshot_digest, '')
                 OR COALESCE(
                      (descriptor->>'sealed_sequence')::bigint,
                      0
                    ) <> COALESCE(p_sealed_sequence, 0) THEN
                RAISE EXCEPTION
                  'external lifecycle descriptor mismatch';
              END IF;
              IF p_mode = 'epoch' THEN
                IF COALESCE(
                     (descriptor->>'epoch')::boolean,
                     false
                   ) THEN
                  RAISE EXCEPTION
                    'external lifecycle epoch already consumed';
                END IF;
                descriptor := jsonb_set(
                  descriptor,
                  '{epoch}',
                  'true'::jsonb,
                  true
                );
                PERFORM set_config(
                  'z4j.schedule_external_lifecycle_guard',
                  descriptor::text,
                  true
                );
                RETURN;
              END IF;
              IF p_mode = 'stream' THEN
                IF NOT COALESCE(
                     (descriptor->>'epoch')::boolean,
                     false
                   )
                   OR jsonb_array_length(
                        descriptor->'mutations'
                      ) <> 0
                   OR (
                     descriptor->>'transition' = 'cutover'
                     AND NOT COALESCE(
                       (descriptor->>'cutover')::boolean,
                       false
                     )
                   ) THEN
                  RAISE EXCEPTION
                    'external lifecycle transition is incomplete';
                END IF;
                PERFORM set_config(
                  'z4j.schedule_external_lifecycle_guard',
                  '',
                  true
                );
                RETURN;
              END IF;
              RAISE EXCEPTION
                'unknown external lifecycle guard operation';
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_schedule_owner_cutover_guard_v1()
            RETURNS trigger AS $$
            BEGIN
              IF TG_OP = 'DELETE'
                 AND z4j_schedule_reset_active_v1() THEN
                PERFORM z4j_consume_schedule_reset_row_v1(
                  'schedule_owner_cutovers'
                );
                RETURN OLD;
              END IF;
              IF TG_OP = 'INSERT' THEN
                PERFORM
                  z4j_consume_external_cutover_evidence_guard_v1(
                    NEW.id,
                    NEW.project_id,
                    NEW.preview_manifest_digest,
                    NEW.from_owner,
                    NEW.to_owner
                  );
                RETURN NEW;
              END IF;
              IF TG_OP = 'UPDATE' THEN
                RAISE EXCEPTION
                  'owner cutover evidence is immutable';
              END IF;
              RAISE EXCEPTION
                'owner cutover evidence is retained';
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE TRIGGER z4j_schedule_owner_cutover_guard_v1
            BEFORE INSERT OR UPDATE OR DELETE
            ON schedule_owner_cutovers
            FOR EACH ROW
            EXECUTE FUNCTION
              z4j_schedule_owner_cutover_guard_v1()
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_schedule_external_epoch_guard_v1()
            RETURNS trigger AS $$
            BEGIN
              IF TG_OP = 'DELETE'
                 AND z4j_schedule_reset_active_v1() THEN
                PERFORM z4j_consume_schedule_reset_row_v1(
                  'schedule_external_stream_epochs'
                );
                RETURN OLD;
              END IF;
              IF TG_OP = 'INSERT' THEN
                IF NEW.phase <> 'ACTIVATING'
                   OR NEW.accepted_sequence <> 0
                   OR NEW.sealed_sequence IS NOT NULL
                   OR NEW.last_snapshot_digest IS NOT NULL
                   OR NEW.last_projection_digest IS NOT NULL THEN
                  RAISE EXCEPTION
                    'invalid allocated external epoch';
                END IF;
                PERFORM z4j_consume_external_allocation_guard_v1(
                  'epoch',
                  NEW.stream_id,
                  NEW.epoch_uuid,
                  NEW.epoch_number,
                  0,
                  '',
                  '',
                  NULL,
                  NEW.authorized_adapter_instance_id
                );
                RETURN NEW;
              END IF;
              IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION
                  'external epoch history is retained';
              END IF;
              IF NEW.epoch_uuid = OLD.epoch_uuid
                 AND NEW.epoch_number = OLD.epoch_number
                 AND NEW.stream_id = OLD.stream_id
                 AND NEW.authorized_adapter_instance_id
                   IS NOT DISTINCT FROM
                     OLD.authorized_adapter_instance_id
                 AND NEW.executor_agent_id
                   IS NOT DISTINCT FROM OLD.executor_agent_id
                 AND NEW.executor_registry_owner_id
                   IS NOT DISTINCT FROM
                     OLD.executor_registry_owner_id
                 AND NEW.executor_session_generation
                   IS NOT DISTINCT FROM
                     OLD.executor_session_generation
                 AND NEW.executor_worker_id
                   IS NOT DISTINCT FROM OLD.executor_worker_id
                 AND NEW.accepted_sequence = OLD.accepted_sequence
                 AND NEW.last_snapshot_digest
                   IS NOT DISTINCT FROM OLD.last_snapshot_digest
                 AND NEW.last_projection_digest
                   IS NOT DISTINCT FROM OLD.last_projection_digest
                 AND NEW.activation_requirement
                   IS NOT DISTINCT FROM OLD.activation_requirement
                 AND NEW.created_at = OLD.created_at
                 AND NEW.activated_at
                   IS NOT DISTINCT FROM OLD.activated_at
                 AND (
                   (
                     OLD.phase = 'ACTIVE'
                     AND NEW.phase = 'DRAINING'
                     AND NEW.sealed_sequence
                       IS NOT DISTINCT FROM OLD.sealed_sequence
                     AND NEW.sealed_at
                       IS NOT DISTINCT FROM OLD.sealed_at
                     AND NEW.retired_at
                       IS NOT DISTINCT FROM OLD.retired_at
                   )
                   OR (
                     OLD.phase = 'ACTIVATING'
                     AND NEW.phase = 'RETIRED'
                     AND OLD.accepted_sequence = 0
                     AND NEW.sealed_sequence = 0
                     AND NEW.sealed_at
                       IS NOT DISTINCT FROM OLD.sealed_at
                     AND OLD.retired_at IS NULL
                     AND NEW.retired_at IS NOT NULL
                   )
                   OR (
                     OLD.phase = 'DRAINING'
                     AND NEW.phase = 'SEALED'
                     AND NEW.sealed_sequence
                       = NEW.accepted_sequence
                     AND NEW.last_snapshot_digest IS NOT NULL
                     AND OLD.sealed_at IS NULL
                     AND NEW.sealed_at IS NOT NULL
                     AND NEW.retired_at
                       IS NOT DISTINCT FROM OLD.retired_at
                   )
                   OR (
                     OLD.phase = 'SEALED'
                     AND NEW.phase = 'RETIRED'
                     AND NEW.sealed_sequence
                       IS NOT DISTINCT FROM OLD.sealed_sequence
                     AND NEW.sealed_at
                       IS NOT DISTINCT FROM OLD.sealed_at
                     AND OLD.retired_at IS NULL
                     AND NEW.retired_at IS NOT NULL
                   )
                   OR (
                     OLD.phase IN (
                       'ACTIVATING', 'ACTIVE', 'DRAINING',
                       'SEALED', 'AMBIGUOUS'
                     )
                     AND NEW.phase
                       = 'RESTORE_REACTIVATION_REQUIRED'
                     AND NEW.sealed_sequence
                       IS NOT DISTINCT FROM OLD.sealed_sequence
                     AND NEW.sealed_at
                       IS NOT DISTINCT FROM OLD.sealed_at
                     AND NEW.retired_at
                       IS NOT DISTINCT FROM OLD.retired_at
                   )
                 ) THEN
                PERFORM z4j_consume_external_lifecycle_guard_v1(
                  'epoch',
                  NEW.stream_id,
                  NEW.epoch_uuid,
                  NEW.epoch_number,
                  NEW.accepted_sequence,
                  NEW.phase,
                  NEW.last_snapshot_digest,
                  COALESCE(NEW.sealed_sequence, 0)
                );
                RETURN NEW;
              END IF;
              IF NEW.phase = 'AMBIGUOUS'
                 AND OLD.phase IN ('ACTIVATING', 'ACTIVE', 'DRAINING')
                 AND NEW.epoch_uuid = OLD.epoch_uuid
                 AND NEW.epoch_number = OLD.epoch_number
                 AND NEW.stream_id = OLD.stream_id
                 AND NEW.authorized_adapter_instance_id
                   IS NOT DISTINCT FROM
                     OLD.authorized_adapter_instance_id
                 AND NEW.executor_agent_id
                   IS NOT DISTINCT FROM OLD.executor_agent_id
                 AND NEW.executor_registry_owner_id
                   IS NOT DISTINCT FROM
                     OLD.executor_registry_owner_id
                 AND NEW.executor_session_generation
                   IS NOT DISTINCT FROM
                     OLD.executor_session_generation
                 AND NEW.executor_worker_id
                   IS NOT DISTINCT FROM OLD.executor_worker_id
                 AND NEW.accepted_sequence = OLD.accepted_sequence
                 AND NEW.sealed_sequence
                   IS NOT DISTINCT FROM OLD.sealed_sequence
                 AND NEW.last_snapshot_digest
                   IS NOT DISTINCT FROM OLD.last_snapshot_digest
                 AND NEW.last_projection_digest
                   IS NOT DISTINCT FROM OLD.last_projection_digest
                 AND NEW.activation_requirement = 'PROTOCOL_FAULT' THEN
                PERFORM z4j_consume_external_projection_guard_v1(
                  'ambiguity_epoch',
                  NEW.stream_id,
                  NEW.epoch_uuid,
                  NEW.epoch_number,
                  NEW.accepted_sequence,
                  NEW.last_projection_digest,
                  NEW.authorized_adapter_instance_id,
                  NEW.phase
                );
                RETURN NEW;
              END IF;
              IF NEW.epoch_uuid IS DISTINCT FROM OLD.epoch_uuid
                 OR NEW.epoch_number IS DISTINCT FROM OLD.epoch_number
                 OR NEW.stream_id IS DISTINCT FROM OLD.stream_id
                 OR NEW.executor_agent_id
                   IS DISTINCT FROM OLD.executor_agent_id
                 OR NEW.executor_registry_owner_id
                   IS DISTINCT FROM OLD.executor_registry_owner_id
                 OR NEW.executor_session_generation
                   IS DISTINCT FROM OLD.executor_session_generation
                 OR NEW.executor_worker_id
                   IS DISTINCT FROM OLD.executor_worker_id
                 OR (
                   OLD.phase = 'ACTIVATING'
                   AND OLD.authorized_adapter_instance_id IS NULL
                   AND NEW.authorized_adapter_instance_id IS NULL
                 )
                 OR (
                   NOT (
                     OLD.phase = 'ACTIVATING'
                     AND OLD.authorized_adapter_instance_id IS NULL
                   )
                   AND NEW.authorized_adapter_instance_id
                     IS DISTINCT FROM OLD.authorized_adapter_instance_id
                 )
                 OR (
                   OLD.phase = 'ACTIVATING'
                   AND NEW.activation_requirement IS NOT NULL
                 )
                 OR (
                   OLD.phase <> 'ACTIVATING'
                   AND NEW.activation_requirement
                     IS DISTINCT FROM OLD.activation_requirement
                 )
                 OR NEW.accepted_sequence <> OLD.accepted_sequence + 1
                 OR (
                   OLD.phase = 'ACTIVATING' AND NEW.phase <> 'ACTIVE'
                 )
                 OR (
                   OLD.phase = 'ACTIVE'
                   AND NEW.phase NOT IN ('ACTIVE', 'DRAINING')
                 )
                 OR (
                   OLD.phase = 'DRAINING'
                   AND NEW.phase NOT IN ('DRAINING', 'SEALED')
                 )
                 OR OLD.phase NOT IN (
                   'ACTIVATING', 'ACTIVE', 'DRAINING'
                 ) THEN
                RAISE EXCEPTION 'invalid external epoch projection';
              END IF;
              PERFORM z4j_consume_external_projection_guard_v1(
                'epoch',
                NEW.stream_id,
                NEW.epoch_uuid,
                NEW.epoch_number,
                NEW.accepted_sequence,
                NEW.last_projection_digest,
                NEW.authorized_adapter_instance_id,
                NEW.phase
              );
              RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE TRIGGER z4j_schedule_external_epoch_guard_v1
            BEFORE INSERT OR UPDATE OR DELETE
            ON schedule_external_stream_epochs
            FOR EACH ROW
            EXECUTE FUNCTION z4j_schedule_external_epoch_guard_v1()
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_schedule_external_stream_guard_v1()
            RETURNS trigger AS $$
            DECLARE
              matching_epochs bigint;
            BEGIN
              IF TG_OP = 'DELETE'
                 AND z4j_schedule_reset_active_v1() THEN
                PERFORM z4j_consume_schedule_reset_row_v1(
                  'schedule_external_streams'
                );
                RETURN OLD;
              END IF;
              IF TG_OP = 'INSERT' THEN
                IF NEW.phase <> 'ACTIVATING'
                   OR NEW.accepted_sequence <> 0
                   OR NEW.sealed_sequence IS NOT NULL
                   OR NEW.last_snapshot_digest IS NOT NULL
                   OR NEW.last_projection_digest IS NOT NULL THEN
                  RAISE EXCEPTION
                    'invalid allocated external stream';
                END IF;
                SELECT COUNT(*) INTO matching_epochs
                FROM schedule_external_stream_epochs
                WHERE stream_id = NEW.id
                  AND epoch_uuid = NEW.current_epoch_uuid
                  AND epoch_number = NEW.current_epoch_number
                  AND phase = NEW.phase
                  AND authorized_adapter_instance_id
                    IS NOT DISTINCT FROM
                      NEW.authorized_adapter_instance_id
                  AND executor_agent_id
                    IS NOT DISTINCT FROM NEW.executor_agent_id
                  AND executor_registry_owner_id
                    IS NOT DISTINCT FROM
                      NEW.executor_registry_owner_id
                  AND executor_session_generation
                    IS NOT DISTINCT FROM
                      NEW.executor_session_generation
                  AND executor_worker_id
                    IS NOT DISTINCT FROM NEW.executor_worker_id
                  AND accepted_sequence = NEW.accepted_sequence;
                IF matching_epochs <> 1 THEN
                  RAISE EXCEPTION
                    'allocated external executor mismatch';
                END IF;
                PERFORM z4j_consume_external_allocation_guard_v1(
                  'stream',
                  NEW.id,
                  NEW.current_epoch_uuid,
                  NEW.current_epoch_number,
                  0,
                  NEW.source_scope_digest,
                  NEW.owner,
                  NEW.project_id,
                  NEW.authorized_adapter_instance_id
                );
                RETURN NEW;
              END IF;
              IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION
                  'external stream identity is retained';
              END IF;
              IF NEW.current_epoch_uuid
                   IS DISTINCT FROM OLD.current_epoch_uuid THEN
                IF OLD.phase NOT IN (
                     'RETIRED',
                     'RESTORE_REACTIVATION_REQUIRED'
                   )
                   OR NEW.id IS DISTINCT FROM OLD.id
                   OR NEW.project_id IS DISTINCT FROM OLD.project_id
                   OR NEW.owner IS DISTINCT FROM OLD.owner
                   OR NEW.source_scope
                     IS DISTINCT FROM OLD.source_scope
                   OR NEW.source_scope_digest
                     IS DISTINCT FROM OLD.source_scope_digest
                   OR NEW.current_epoch_number
                     <= OLD.current_epoch_number
                   OR NEW.phase <> 'ACTIVATING'
                   OR NEW.accepted_sequence <> 0
                   OR NEW.sealed_sequence IS NOT NULL
                   OR NEW.last_snapshot_digest IS NOT NULL
                   OR NEW.last_projection_digest IS NOT NULL
                   OR NEW.created_at IS DISTINCT FROM OLD.created_at
                THEN
                  RAISE EXCEPTION
                    'invalid external stream reactivation';
                END IF;
                SELECT COUNT(*) INTO matching_epochs
                FROM schedule_external_stream_epochs
                WHERE stream_id = NEW.id
                  AND epoch_uuid = NEW.current_epoch_uuid
                  AND epoch_number = NEW.current_epoch_number
                  AND phase = NEW.phase
                  AND authorized_adapter_instance_id
                    IS NOT DISTINCT FROM
                      NEW.authorized_adapter_instance_id
                  AND executor_agent_id
                    IS NOT DISTINCT FROM NEW.executor_agent_id
                  AND executor_registry_owner_id
                    IS NOT DISTINCT FROM
                      NEW.executor_registry_owner_id
                  AND executor_session_generation
                    IS NOT DISTINCT FROM
                      NEW.executor_session_generation
                  AND executor_worker_id
                    IS NOT DISTINCT FROM NEW.executor_worker_id
                  AND accepted_sequence = 0;
                IF matching_epochs <> 1 THEN
                  RAISE EXCEPTION
                    'reactivated external executor mismatch';
                END IF;
                PERFORM z4j_consume_external_allocation_guard_v1(
                  'stream',
                  NEW.id,
                  NEW.current_epoch_uuid,
                  NEW.current_epoch_number,
                  0,
                  NEW.source_scope_digest,
                  NEW.owner,
                  NEW.project_id,
                  NEW.authorized_adapter_instance_id
                );
                RETURN NEW;
              END IF;
              IF NEW.id = OLD.id
                 AND NEW.project_id = OLD.project_id
                 AND NEW.owner = OLD.owner
                 AND NEW.source_scope = OLD.source_scope
                 AND NEW.source_scope_digest
                   = OLD.source_scope_digest
                 AND NEW.current_epoch_uuid
                   = OLD.current_epoch_uuid
                 AND NEW.current_epoch_number
                   = OLD.current_epoch_number
                 AND NEW.authorized_adapter_instance_id
                   IS NOT DISTINCT FROM
                     OLD.authorized_adapter_instance_id
                 AND NEW.executor_agent_id
                   IS NOT DISTINCT FROM OLD.executor_agent_id
                 AND NEW.executor_registry_owner_id
                   IS NOT DISTINCT FROM
                     OLD.executor_registry_owner_id
                 AND NEW.executor_session_generation
                   IS NOT DISTINCT FROM
                     OLD.executor_session_generation
                 AND NEW.executor_worker_id
                   IS NOT DISTINCT FROM OLD.executor_worker_id
                 AND NEW.accepted_sequence = OLD.accepted_sequence
                 AND NEW.last_snapshot_digest
                   IS NOT DISTINCT FROM OLD.last_snapshot_digest
                 AND NEW.last_projection_digest
                   IS NOT DISTINCT FROM OLD.last_projection_digest
                 AND NEW.activation_requirement
                   IS NOT DISTINCT FROM OLD.activation_requirement
                 AND NEW.created_at = OLD.created_at
                 AND (
                   (
                     OLD.phase = 'ACTIVE'
                     AND NEW.phase = 'DRAINING'
                     AND NEW.sealed_sequence
                       IS NOT DISTINCT FROM OLD.sealed_sequence
                   )
                   OR (
                     OLD.phase = 'ACTIVATING'
                     AND NEW.phase = 'RETIRED'
                     AND OLD.accepted_sequence = 0
                     AND NEW.sealed_sequence = 0
                   )
                   OR (
                     OLD.phase = 'DRAINING'
                     AND NEW.phase = 'SEALED'
                     AND NEW.sealed_sequence
                       = NEW.accepted_sequence
                     AND NEW.last_snapshot_digest IS NOT NULL
                   )
                   OR (
                     OLD.phase = 'SEALED'
                     AND NEW.phase = 'RETIRED'
                     AND NEW.sealed_sequence
                       IS NOT DISTINCT FROM OLD.sealed_sequence
                   )
                   OR (
                     OLD.phase IN (
                       'ACTIVATING', 'ACTIVE', 'DRAINING',
                       'SEALED', 'AMBIGUOUS'
                     )
                     AND NEW.phase
                       = 'RESTORE_REACTIVATION_REQUIRED'
                     AND NEW.sealed_sequence
                       IS NOT DISTINCT FROM OLD.sealed_sequence
                   )
                 ) THEN
                SELECT COUNT(*) INTO matching_epochs
                FROM schedule_external_stream_epochs
                WHERE stream_id = NEW.id
                  AND epoch_uuid = NEW.current_epoch_uuid
                  AND epoch_number = NEW.current_epoch_number
                  AND phase = NEW.phase
                  AND authorized_adapter_instance_id
                    IS NOT DISTINCT FROM
                      NEW.authorized_adapter_instance_id
                  AND executor_agent_id
                    IS NOT DISTINCT FROM NEW.executor_agent_id
                  AND executor_registry_owner_id
                    IS NOT DISTINCT FROM
                      NEW.executor_registry_owner_id
                  AND executor_session_generation
                    IS NOT DISTINCT FROM
                      NEW.executor_session_generation
                  AND executor_worker_id
                    IS NOT DISTINCT FROM NEW.executor_worker_id
                  AND accepted_sequence = NEW.accepted_sequence
                  AND sealed_sequence
                    IS NOT DISTINCT FROM NEW.sealed_sequence
                  AND last_snapshot_digest
                    IS NOT DISTINCT FROM NEW.last_snapshot_digest
                  AND last_projection_digest
                    IS NOT DISTINCT FROM NEW.last_projection_digest;
                IF matching_epochs <> 1 THEN
                  RAISE EXCEPTION
                    'external stream/epoch lifecycle mismatch';
                END IF;
                PERFORM z4j_consume_external_lifecycle_guard_v1(
                  'stream',
                  NEW.id,
                  NEW.current_epoch_uuid,
                  NEW.current_epoch_number,
                  NEW.accepted_sequence,
                  NEW.phase,
                  NEW.last_snapshot_digest,
                  COALESCE(NEW.sealed_sequence, 0)
                );
                RETURN NEW;
              END IF;
              IF NEW.phase = 'AMBIGUOUS'
                 AND OLD.phase IN ('ACTIVATING', 'ACTIVE', 'DRAINING')
                 AND NEW.id = OLD.id
                 AND NEW.project_id = OLD.project_id
                 AND NEW.owner = OLD.owner
                 AND NEW.source_scope = OLD.source_scope
                 AND NEW.source_scope_digest = OLD.source_scope_digest
                 AND NEW.current_epoch_uuid = OLD.current_epoch_uuid
                 AND NEW.current_epoch_number = OLD.current_epoch_number
                 AND NEW.authorized_adapter_instance_id
                   IS NOT DISTINCT FROM
                     OLD.authorized_adapter_instance_id
                 AND NEW.executor_agent_id
                   IS NOT DISTINCT FROM OLD.executor_agent_id
                 AND NEW.executor_registry_owner_id
                   IS NOT DISTINCT FROM
                     OLD.executor_registry_owner_id
                 AND NEW.executor_session_generation
                   IS NOT DISTINCT FROM
                     OLD.executor_session_generation
                 AND NEW.executor_worker_id
                   IS NOT DISTINCT FROM OLD.executor_worker_id
                 AND NEW.accepted_sequence = OLD.accepted_sequence
                 AND NEW.sealed_sequence
                   IS NOT DISTINCT FROM OLD.sealed_sequence
                 AND NEW.last_snapshot_digest
                   IS NOT DISTINCT FROM OLD.last_snapshot_digest
                 AND NEW.last_projection_digest
                   IS NOT DISTINCT FROM OLD.last_projection_digest
                 AND NEW.activation_requirement = 'PROTOCOL_FAULT' THEN
                SELECT COUNT(*) INTO matching_epochs
                FROM schedule_external_stream_epochs
                WHERE stream_id = NEW.id
                  AND epoch_uuid = NEW.current_epoch_uuid
                  AND epoch_number = NEW.current_epoch_number
                  AND phase = 'AMBIGUOUS'
                  AND authorized_adapter_instance_id
                    IS NOT DISTINCT FROM
                      NEW.authorized_adapter_instance_id
                  AND executor_agent_id
                    IS NOT DISTINCT FROM NEW.executor_agent_id
                  AND executor_registry_owner_id
                    IS NOT DISTINCT FROM
                      NEW.executor_registry_owner_id
                  AND executor_session_generation
                    IS NOT DISTINCT FROM
                      NEW.executor_session_generation
                  AND executor_worker_id
                    IS NOT DISTINCT FROM NEW.executor_worker_id
                  AND accepted_sequence = NEW.accepted_sequence
                  AND last_snapshot_digest
                    IS NOT DISTINCT FROM NEW.last_snapshot_digest
                  AND last_projection_digest
                    IS NOT DISTINCT FROM NEW.last_projection_digest;
                IF matching_epochs <> 1 THEN
                  RAISE EXCEPTION
                    'external stream/epoch ambiguity mismatch';
                END IF;
                PERFORM z4j_consume_external_projection_guard_v1(
                  'ambiguity_stream',
                  NEW.id,
                  NEW.current_epoch_uuid,
                  NEW.current_epoch_number,
                  NEW.accepted_sequence,
                  NEW.last_projection_digest,
                  NEW.authorized_adapter_instance_id,
                  NEW.phase
                );
                RETURN NEW;
              END IF;
              IF NEW.id IS DISTINCT FROM OLD.id
                 OR NEW.project_id IS DISTINCT FROM OLD.project_id
                 OR NEW.owner IS DISTINCT FROM OLD.owner
                 OR NEW.source_scope IS DISTINCT FROM OLD.source_scope
                 OR NEW.source_scope_digest
                   IS DISTINCT FROM OLD.source_scope_digest
                 OR NEW.current_epoch_uuid
                   IS DISTINCT FROM OLD.current_epoch_uuid
                 OR NEW.current_epoch_number
                   IS DISTINCT FROM OLD.current_epoch_number
                 OR NEW.executor_agent_id
                   IS DISTINCT FROM OLD.executor_agent_id
                 OR NEW.executor_registry_owner_id
                   IS DISTINCT FROM OLD.executor_registry_owner_id
                 OR NEW.executor_session_generation
                   IS DISTINCT FROM OLD.executor_session_generation
                 OR NEW.executor_worker_id
                   IS DISTINCT FROM OLD.executor_worker_id
                 OR (
                   OLD.phase = 'ACTIVATING'
                   AND OLD.authorized_adapter_instance_id IS NULL
                   AND NEW.authorized_adapter_instance_id IS NULL
                 )
                 OR (
                   NOT (
                     OLD.phase = 'ACTIVATING'
                     AND OLD.authorized_adapter_instance_id IS NULL
                   )
                   AND NEW.authorized_adapter_instance_id
                     IS DISTINCT FROM OLD.authorized_adapter_instance_id
                 )
                 OR (
                   OLD.phase = 'ACTIVATING'
                   AND NEW.activation_requirement IS NOT NULL
                 )
                 OR (
                   OLD.phase <> 'ACTIVATING'
                   AND NEW.activation_requirement
                     IS DISTINCT FROM OLD.activation_requirement
                 )
                 OR NEW.accepted_sequence <> OLD.accepted_sequence + 1
                 OR (
                   OLD.phase = 'ACTIVATING' AND NEW.phase <> 'ACTIVE'
                 )
                 OR (
                   OLD.phase = 'ACTIVE'
                   AND NEW.phase NOT IN ('ACTIVE', 'DRAINING')
                 )
                 OR (
                   OLD.phase = 'DRAINING'
                   AND NEW.phase NOT IN ('DRAINING', 'SEALED')
                 )
                 OR OLD.phase NOT IN (
                   'ACTIVATING', 'ACTIVE', 'DRAINING'
                 ) THEN
                RAISE EXCEPTION 'invalid external stream projection';
              END IF;
              SELECT COUNT(*) INTO matching_epochs
              FROM schedule_external_stream_epochs
              WHERE stream_id = NEW.id
                AND epoch_uuid = NEW.current_epoch_uuid
                AND epoch_number = NEW.current_epoch_number
                AND phase = NEW.phase
                AND authorized_adapter_instance_id
                  IS NOT DISTINCT FROM
                    NEW.authorized_adapter_instance_id
                AND executor_agent_id
                  IS NOT DISTINCT FROM NEW.executor_agent_id
                AND executor_registry_owner_id
                  IS NOT DISTINCT FROM
                    NEW.executor_registry_owner_id
                AND executor_session_generation
                  IS NOT DISTINCT FROM
                    NEW.executor_session_generation
                AND executor_worker_id
                  IS NOT DISTINCT FROM NEW.executor_worker_id
                AND accepted_sequence = NEW.accepted_sequence
                AND last_snapshot_digest
                  IS NOT DISTINCT FROM NEW.last_snapshot_digest
                AND last_projection_digest
                  IS NOT DISTINCT FROM NEW.last_projection_digest;
              IF matching_epochs <> 1 THEN
                RAISE EXCEPTION
                  'external stream/epoch projection mismatch';
              END IF;
              PERFORM z4j_consume_external_projection_guard_v1(
                'stream',
                NEW.id,
                NEW.current_epoch_uuid,
                NEW.current_epoch_number,
                NEW.accepted_sequence,
                NEW.last_projection_digest,
                NEW.authorized_adapter_instance_id,
                NEW.phase
              );
              RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE TRIGGER z4j_schedule_external_stream_guard_v1
            BEFORE INSERT OR UPDATE OR DELETE
            ON schedule_external_streams
            FOR EACH ROW
            EXECUTE FUNCTION z4j_schedule_external_stream_guard_v1()
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION
              z4j_schedule_external_allocator_guard_v1()
            RETURNS trigger AS $$
            BEGIN
              IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION
                  'external epoch allocator is protected';
              END IF;
              IF TG_OP = 'UPDATE' THEN
                IF NEW.singleton_id IS DISTINCT FROM OLD.singleton_id
                   OR NEW.guard_version IS DISTINCT FROM OLD.guard_version
                   OR NEW.activation_id IS DISTINCT FROM OLD.activation_id
                   OR NEW.activation_manifest_digest
                     IS DISTINCT FROM OLD.activation_manifest_digest
                   OR NEW.activation_audit_id
                     IS DISTINCT FROM OLD.activation_audit_id THEN
                  RAISE EXCEPTION
                    'invalid external epoch allocation';
                END IF;
                IF z4j_schedule_reset_active_v1() THEN
                  IF NEW.current_epoch_number
                       <= OLD.current_epoch_number THEN
                    RAISE EXCEPTION
                      'invalid external reset epoch barrier';
                  END IF;
                  PERFORM z4j_consume_schedule_reset_epoch_v1(
                    OLD.current_epoch_number,
                    NEW.current_epoch_number
                  );
                  RETURN NEW;
                END IF;
                IF z4j_schedule_restore_active_v1() THEN
                  PERFORM z4j_consume_schedule_restore_epoch_v1(
                    OLD.current_epoch_number,
                    NEW.current_epoch_number
                  );
                  RETURN NEW;
                END IF;
                IF NEW.current_epoch_number
                     <> OLD.current_epoch_number + 1 THEN
                  RAISE EXCEPTION
                    'invalid external epoch allocation';
                END IF;
                PERFORM z4j_consume_external_allocation_guard_v1(
                  'allocator',
                  NULL,
                  NULL,
                  NEW.current_epoch_number,
                  OLD.current_epoch_number,
                  '',
                  '',
                  NULL,
                  NULL
                );
                RETURN NEW;
              END IF;
              IF EXISTS (
                SELECT 1 FROM schedule_external_epoch_allocator
              ) THEN
                RAISE EXCEPTION
                  'external epoch allocator is a singleton';
              END IF;
              RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE TRIGGER z4j_schedule_external_allocator_guard_v1
            BEFORE INSERT OR UPDATE OR DELETE
            ON schedule_external_epoch_allocator
            FOR EACH ROW
            EXECUTE FUNCTION z4j_schedule_external_allocator_guard_v1()
            """
        )
    )


def _install_guards(bind: sa.engine.Connection) -> None:
    if bind.dialect.name == "sqlite":
        # SQLite runs same-timing triggers in reverse creation order.  Install
        # the external supplement first so an unmodified N-1 connection still
        # reaches the original general D guard first and fails closed on the
        # long-established ``z4j_schedule_guard`` absence.
        _install_sqlite_external_guards()
        _install_sqlite_schedule_guards()
        _install_sqlite_evidence_guards()
        return
    if bind.dialect.name == "postgresql":
        _install_postgresql_schedule_guards()
        _install_postgresql_evidence_guards()
        _install_postgresql_external_guards()
        return
    raise CommandError(
        f"unsupported Boundary-D database: {bind.dialect.name}",
    )


def _activate_revision_state(
    bind: sa.engine.Connection,
    *,
    activation_id: uuid.UUID,
    manifest_digest: str,
    audit_id: uuid.UUID,
) -> None:
    table = ScheduleRevisionState.__table__
    result = bind.execute(
        table.update()
        .where(
            table.c.singleton_id == _STATE_ID,
            table.c.guard_version.is_(None),
            table.c.activation_id.is_(None),
            table.c.activation_manifest_digest.is_(None),
            table.c.activation_audit_id.is_(None),
        )
        .values(
            guard_version=SCHEDULE_GUARD_VERSION,
            activation_id=activation_id,
            activation_manifest_digest=manifest_digest,
            activation_audit_id=audit_id,
        ),
    )
    if result.rowcount != 1:
        raise CommandError(
            "schedule guard activation did not bind exactly one singleton",
        )


def _activate_external_epoch_allocator(
    bind: sa.engine.Connection,
    *,
    current_epoch_number: int,
    activation_id: uuid.UUID,
    manifest_digest: str,
    audit_id: uuid.UUID,
) -> None:
    if (
        bind.execute(
            sa.select(sa.func.count()).select_from(
                ScheduleExternalEpochAllocator.__table__,
            ),
        ).scalar_one()
        != 0
    ):
        raise CommandError(
            "external epoch allocator already exists before activation",
        )
    bind.execute(
        ScheduleExternalEpochAllocator.__table__.insert().values(
            singleton_id=SCHEDULE_EXTERNAL_EPOCH_SINGLETON_ID,
            current_epoch_number=current_epoch_number,
            guard_version=SCHEDULE_GUARD_VERSION,
            activation_id=activation_id,
            activation_manifest_digest=manifest_digest,
            activation_audit_id=audit_id,
        ),
    )


def _catalog_verify(bind: sa.engine.Connection) -> None:
    inspector = sa.inspect(bind)
    required_tables = {
        "schedule_revision_state",
        "schedule_change_log",
        "schedule_terminal_holds",
        "schedule_occurrence_resolutions",
        "schedule_external_epoch_allocator",
        "schedule_external_streams",
        "schedule_external_stream_epochs",
        "schedule_external_projections",
        "schedule_external_snapshot_frames",
        "schedule_external_control_operations",
        "schedule_owner_cutovers",
    }
    missing_tables = required_tables - set(inspector.get_table_names())
    if missing_tables:
        raise CommandError(
            f"Boundary-D activation is missing tables: {sorted(missing_tables)}",
        )
    if bind.dialect.name == "sqlite":
        triggers = {
            str(row[0])
            for row in bind.execute(
                sa.text(
                    "SELECT name FROM sqlite_master WHERE type='trigger'",
                ),
            )
        }
        required_triggers = {
            "audit_log_boundary_f_no_insert",
            "audit_log_boundary_f_no_update",
            "audit_log_boundary_f_no_delete",
            "audit_chain_state_boundary_f_no_update",
            "audit_chain_state_boundary_f_no_delete",
            "z4j_schedule_revision_state_update_guard_v1",
            "z4j_schedule_insert_guard_v1",
            "z4j_schedule_update_guard_v1",
            "z4j_schedule_delete_guard_v1",
            "z4j_schedule_command_insert_guard_v1",
            "z4j_schedule_fire_insert_guard_v1",
            "z4j_pending_fire_insert_guard_v1",
            "z4j_schedule_terminal_hold_insert_guard_v1",
            "z4j_schedule_occurrence_resolution_insert_guard_v1",
            "z4j_schedule_external_insert_guard_v1",
            "z4j_schedule_external_update_guard_v1",
            "z4j_schedule_owner_cutover_row_guard_v1",
            "z4j_schedule_external_delete_guard_v1",
            "z4j_schedule_external_projection_insert_guard_v1",
            "z4j_schedule_external_snapshot_frame_insert_guard_v1",
            "z4j_schedule_external_control_insert_guard_v1",
            "z4j_schedule_external_control_update_guard_v1",
            "z4j_schedule_owner_cutover_insert_guard_v1",
            "z4j_schedule_external_epoch_update_guard_v1",
            "z4j_schedule_external_stream_update_guard_v1",
            "z4j_schedule_external_stream_reactivation_guard_v1",
            "z4j_schedule_external_allocator_update_guard_v1",
        }
    else:
        triggers = {
            str(row[0])
            for row in bind.execute(
                sa.text(
                    "SELECT tgname FROM pg_trigger WHERE NOT tgisinternal",
                ),
            )
        }
        required_triggers = {
            "z4j_schedule_revision_state_guard_v1",
            "z4j_schedule_row_guard_v1",
            "z4j_schedule_command_guard_v1",
            "z4j_schedule_fire_guard_v1",
            "z4j_pending_fire_guard_v1",
            "z4j_schedule_terminal_hold_guard_v1",
            "z4j_schedule_occurrence_resolution_guard_v1",
            "z4j_schedule_external_row_guard_v1",
            "z4j_schedule_external_projection_guard_v1",
            "z4j_schedule_external_snapshot_frame_guard_v1",
            "z4j_schedule_external_control_guard_v1",
            "z4j_schedule_owner_cutover_guard_v1",
            "z4j_schedule_external_epoch_guard_v1",
            "z4j_schedule_external_stream_guard_v1",
            "z4j_schedule_external_allocator_guard_v1",
        }
    missing_triggers = required_triggers - triggers
    if missing_triggers:
        raise CommandError(
            f"Boundary-D activation is missing guards: {sorted(missing_triggers)}",
        )


def upgrade() -> None:
    context = op.get_context()
    if context.as_sql:
        raise CommandError(
            "Boundary-D activation requires a live authenticated database",
        )
    bind = op.get_bind()
    if bind.dialect.name not in {"sqlite", "postgresql"}:
        raise CommandError(
            f"unsupported Boundary-D database: {bind.dialect.name}",
        )
    if bind.dialect.name == "postgresql":
        bind.execute(
            sa.text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": AUDIT_CHAIN_ADVISORY_LOCK_KEY},
        )
        bind.execute(
            sa.text(
                "LOCK TABLE audit_chain_state, audit_log, schedules, "
                "commands, schedule_fires, pending_fires "
                "IN SHARE ROW EXCLUSIVE MODE",
            ),
        )
    else:
        register_sqlite_schedule_guard(
            bind.connection.dbapi_connection,
        )

    # Authenticate F before the first D schema or data mutation.  The helper
    # also refuses a key-rotation mismatch; the signed append below repeats the
    # live head/count/HMAC checks after the backfill while all target rows are
    # still locked by this transaction.
    current_key_id, keyring = _audit_keyring()
    with Session(bind=bind) as session:
        states = list(session.execute(sa.select(AuditChainState)).scalars())
        if len(states) != 1:
            raise CommandError(
                "Boundary F must be active before Boundary D",
            )
        try:
            payload = authenticate_state(states[0], keyring)
        except Exception as exc:
            raise CommandError(
                "Boundary F failed authentication before Boundary D",
            ) from exc
        if payload["state_key_id"] != current_key_id:
            raise CommandError(
                "configured current audit key differs from authenticated state",
            )

    _ensure_d_shapes(bind)
    cutoff = datetime.now(UTC)
    backfill_revision, schedule_manifest = _backfill_schedules(
        bind,
        cutoff=cutoff,
    )
    external_stream_count, external_stream_manifest = _backfill_external_authority(
        bind,
        cutoff=cutoff,
        schedule_manifest=schedule_manifest,
    )
    evidence_counts = _backfill_evidence(bind)
    _enforce_schedule_identity_constraints(bind)
    _prepare_revision_state(
        bind,
        backfill_revision=backfill_revision,
    )
    manifest, manifest_digest = _manifest(
        cutoff=cutoff,
        schedules=schedule_manifest,
        evidence_counts=evidence_counts,
        external_streams=external_stream_manifest,
    )
    activation_id = uuid.uuid4()
    _install_guards(bind)
    audit_id = _append_activation_audit(
        bind,
        activation_id=activation_id,
        manifest=manifest,
        manifest_digest=manifest_digest,
    )
    _activate_revision_state(
        bind,
        activation_id=activation_id,
        manifest_digest=manifest_digest,
        audit_id=audit_id,
    )
    _activate_external_epoch_allocator(
        bind,
        current_epoch_number=external_stream_count,
        activation_id=activation_id,
        manifest_digest=manifest_digest,
        audit_id=audit_id,
    )
    _catalog_verify(bind)

    if context.config.attributes.get(
        "z4j_test_fail_schedule_activation_after_state",
        False,
    ):
        raise RuntimeError(
            "injected Boundary-D activation failure after state",
        )


def downgrade() -> None:
    raise CommandError(
        "refusing downgrade below Boundary D while schedule authority exists",
    )
