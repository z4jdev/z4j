"""Shared expectations for comparing the ORM models with a migrated database.

The models and the migrations describe one schema. Alembic's
``compare_metadata`` between ``Base.metadata`` and a database at the migration
head must report nothing beyond the differences listed here, each of which is
deliberate or an artifact of the comparison itself. A new entry in the
comparison is drift: declare the object in the model (or, if it is
deliberately migration-only, list it here with the reason and on the
database-schema page).
"""

from __future__ import annotations

from typing import Any

#: Boundary-F and Boundary-D activation set these columns NOT NULL only after
#: classifying or backfilling the rows an upgraded database already holds.
#: The models keep the pre-activation nullability: the activation migrations
#: add the columns from the model definitions, and a nullable model column is
#: what lets them do that on a populated table.
ACTIVATION_NOT_NULL: frozenset[tuple[str, str, str]] = frozenset(
    {
        ("modify_nullable", "audit_log", "legacy_frozen"),
        ("modify_nullable", "schedules", "control_token"),
        ("modify_nullable", "schedules", "schedule_revision"),
        ("modify_nullable", "schedules", "definition_digest"),
        ("modify_nullable", "schedules", "cadence_semantics_version"),
        ("modify_nullable", "schedules", "cadence_runtime_fingerprint"),
    }
)

#: Comparison artifacts on SQLite, not schema differences: Alembic cannot read
#: a descending column back from a SQLite index, and it reports any
#: empty-string server default on SQLite as changed. A table created from the
#: models alone reproduces both.
SQLITE_COMPARISON_ARTIFACTS: frozenset[tuple[str, str, str]] = frozenset(
    {
        ("remove_index", "audit_log", "ix_audit_log_action_pattern"),
        ("add_index", "audit_log", "ix_audit_log_action_pattern"),
        ("remove_index", "notification_deliveries", "ix_notification_deliveries_project_sent"),
        ("add_index", "notification_deliveries", "ix_notification_deliveries_project_sent"),
        ("remove_index", "notification_deliveries", "ix_notification_deliveries_recipient_sent"),
        ("add_index", "notification_deliveries", "ix_notification_deliveries_recipient_sent"),
        ("modify_default", "events", "task_id"),
    }
)

#: PostgreSQL-only objects the initial migration creates and the models do not
#: declare, because SQLite has no equivalent (GIN and trigram indexes) or the
#: model-level declaration would be created twice by that migration.
POSTGRES_ONLY_INDEXES: frozenset[tuple[str, str, str]] = frozenset(
    {
        ("remove_index", "commands", "ix_commands_pending_timeout"),
        ("remove_index", "events", "ix_events_payload_gin"),
        ("remove_index", "projects", "ix_projects_active_partial"),
        ("remove_index", "schedules", "ix_schedules_next_run"),
        ("remove_index", "sessions", "ix_sessions_user_active"),
        ("remove_index", "tasks", "ix_tasks_args_gin"),
        ("remove_index", "tasks", "ix_tasks_kwargs_gin"),
        ("remove_index", "tasks", "ix_tasks_search"),
        ("remove_index", "users", "ix_users_active_partial"),
    }
)

#: ``schedule_fires`` is range-partitioned on PostgreSQL by ``scheduled_for``,
#: and a unique index on a partitioned table must include the partition key,
#: so both unique keys carry it there.
POSTGRES_PARTITION_KEYED_UNIQUES: frozenset[tuple[str, str, str]] = frozenset(
    {
        ("remove_constraint", "schedule_fires", "uq_schedule_fires_fire_receipt"),
        ("add_constraint", "schedule_fires", "uq_schedule_fires_fire_receipt"),
        ("remove_index", "schedule_fires", "uq_schedule_fires_legacy_fire"),
        ("add_index", "schedule_fires", "uq_schedule_fires_legacy_fire"),
    }
)

SQLITE_EXPECTED = ACTIVATION_NOT_NULL | SQLITE_COMPARISON_ARTIFACTS
POSTGRES_EXPECTED = ACTIVATION_NOT_NULL | POSTGRES_ONLY_INDEXES | POSTGRES_PARTITION_KEYED_UNIQUES


def _is_postgres_generated_id_default(change: tuple[Any, ...]) -> bool:
    """PostgreSQL gives every ``id`` key a database default the models leave
    to the application (``gen_random_uuid()``, or a sequence for a bigint key)."""
    kind, _schema, _table, column = change[:4]
    if kind != "modify_default" or column != "id":
        return False
    reflected = getattr(getattr(change[5], "arg", None), "text", str(change[5]))
    return "gen_random_uuid()" in reflected or str(reflected).startswith("nextval(")


def diff_keys(diffs: list[Any], *, postgres: bool) -> set[tuple[str, str, str]]:
    """Reduce ``compare_metadata`` output to ``(kind, table, name)`` keys."""
    keys: set[tuple[str, str, str]] = set()
    for diff in diffs:
        changes = diff if isinstance(diff, list) else [diff]
        for change in changes:
            kind = change[0]
            if kind.startswith("modify_"):
                if postgres and _is_postgres_generated_id_default(change):
                    continue
                keys.add((kind, change[2], change[3]))
            else:
                obj = change[1]
                keys.add((kind, obj.table.name, str(obj.name)))
    return keys


def compare_models_with(sync_connection: Any) -> list[Any]:
    """Run Alembic's comparison of ``Base.metadata`` with the database."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext
    from z4j_brain.persistence import models  # noqa: F401
    from z4j_brain.persistence.base import Base

    model_tables = set(Base.metadata.tables)

    def include_object(obj, name, type_, reflected, compare_to) -> bool:  # type: ignore[no-untyped-def]
        # Partition children and alembic_version are not model tables.
        return not (type_ == "table" and reflected and name not in model_tables)

    context = MigrationContext.configure(
        sync_connection,
        opts={
            "compare_type": True,
            "compare_server_default": True,
            "include_object": include_object,
        },
    )
    return compare_metadata(context, Base.metadata)
