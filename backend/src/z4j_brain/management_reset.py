"""Offline, manifest-bound full-install generation reset.

The ordinary reset retains the authenticated installation identity and both
Boundary-D monotonic namespaces.  Everything else is deleted only after the
exact migration-head schema and row manifest have been frozen under one writer
transaction.  Audit history is replaced last by one signed reset genesis.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.domain.audit_chain import canonical_json
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import (
    AuditChainState,
    ScheduleExternalControlOperation,
    ScheduleExternalEpochAllocator,
    ScheduleExternalStream,
    ScheduleExternalStreamEpoch,
    ScheduleRevisionState,
)
from z4j_brain.persistence.models.schedule_control import (
    SCHEDULE_REVISION_SINGLETON_ID,
)
from z4j_brain.persistence.models.schedule_external import (
    SCHEDULE_EXTERNAL_EPOCH_SINGLETON_ID,
)
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.persistence.schedule_guard import (
    arm_generation_reset,
    finalize_generation_reset,
)
from z4j_brain.schema_transition import (
    RELEASE_MIGRATION_HEAD,
    SCHEMA_TRANSITION_ADVISORY_LOCK_KEY,
)
from z4j_brain.settings import Settings

RESET_MANIFEST_VERSION = 1
RESET_MIGRATION_HEAD = RELEASE_MIGRATION_HEAD
_MAX_BIGINT = (1 << 63) - 1
_PRESERVED_POSTGRES_SEQUENCES = frozenset(
    {
        "agent_status_history_id_seq",
        "schedule_change_log_revision_seq",
    },
)
SQLITE_RELEASE_SCHEMA_CONTRACT_DIGEST = (
    "e9699a59170cbc24e95d9d700adc8f9037f2dcd0ecb20e4884bdf109be31550b"
)
# Derived per major from a clean migration-head database driven by that
# major's OWN client. 16 and 17 agree because their catalog representation
# of these objects is identical; 18 differs and is derived separately.
# Column positions are live-column ranks rather than raw attnums, so a
# database carrying dropped-column slots derives the same value as a clean one.
_POSTGRES_SCHEMA_CONTRACT_DIGESTS = {
    16: "84182859137c63caffc9398178d2246e11862426af4cd9b17f9d322dfc689f99",
    17: "84182859137c63caffc9398178d2246e11862426af4cd9b17f9d322dfc689f99",
    18: "f829cde1b62a437972b938439386ae8344d89101482b8fa4059ee001b81bdcee",
}

# SQLite batch ALTER rebuilt these three tables while removing the post-1.8
# compatibility columns.  That path adds quotes around the table name and
# parentheses around CURRENT_* defaults even though both spellings have the
# same SQLite semantics.  Keep the immutable prior-release digest stable by
# canonicalising only the known compatibility rebuilds; older migrations have
# their own frozen physical spellings and remain exact evidence.
_SQLITE_COMPATIBILITY_REBUILT_TABLES = frozenset(
    {"automation_rules", "notification_deliveries", "projects"},
)

# Reviewed with RESET_MIGRATION_HEAD.  Base.metadata is checked against this
# frozen contract so merely importing a new model cannot silently teach reset
# to destroy a new table.
RESET_ORM_TABLES = frozenset(
    {
        "agent_offline_alerts",
        "agent_status_history",
        "agent_workers",
        "agents",
        "api_keys",
        "audit_chain_preparation",
        "audit_chain_state",
        "audit_log",
        "automation_firing_outbox",
        "automation_rule_admissions",
        "automation_rules",
        "bulk_retry_request_children",
        "bulk_retry_requests",
        "commands",
        "events",
        "export_jobs",
        "extension_store",
        "feature_flags",
        "first_boot_tokens",
        "invitations",
        "memberships",
        "mfa_recovery_codes",
        "misfire_alerts",
        "notification_channels",
        "notification_deliveries",
        "password_reset_tokens",
        "pending_fires",
        "project_config",
        "project_default_subscriptions",
        "projects",
        "queues",
        "saved_views",
        "schedule_change_log",
        "schedule_external_control_operations",
        "schedule_external_epoch_allocator",
        "schedule_external_projections",
        "schedule_external_snapshot_frames",
        "schedule_external_stream_epochs",
        "schedule_external_streams",
        "schedule_fires",
        "schedule_occurrence_resolutions",
        "schedule_owner_cutovers",
        "schedule_revision_state",
        "schedule_terminal_holds",
        "scheduler_rate_buckets",
        "schedules",
        "sessions",
        "task_annotations",
        "tasks",
        "trusted_devices",
        "user_channels",
        "user_notifications",
        "user_preferences",
        "user_subscriptions",
        "users",
        "workers",
        "z4j_meta",
    },
)
_PROTECTED_TRANSITION_TABLES = frozenset(
    {
        "audit_chain_state",
        "schedule_revision_state",
        "schedule_external_epoch_allocator",
    },
)
_MUST_BE_EMPTY_TABLES = frozenset({"audit_chain_preparation"})
_AUDIT_TABLE = "audit_log"
_D_RESET_GUARDED_TABLES = frozenset(
    {
        "commands",
        "pending_fires",
        "schedule_change_log",
        "schedule_external_control_operations",
        "schedule_external_projections",
        "schedule_external_snapshot_frames",
        "schedule_external_stream_epochs",
        "schedule_external_streams",
        "schedule_fires",
        "schedule_occurrence_resolutions",
        "schedule_owner_cutovers",
        "schedule_terminal_holds",
        "schedules",
    },
)


class GenerationResetRefused(RuntimeError):  # noqa: N818  reads naturally at CLI boundary
    """The offline reset preconditions did not prove one safe transition."""


def _normalize_manifest_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise GenerationResetRefused("reset manifest contains non-finite data")
        return value
    # PostgreSQL INET values include typed addresses from session records.
    # Canonical string conversion preserves their address and any netmask.
    if isinstance(
        value,
        (
            uuid.UUID,
            datetime,
            ipaddress.IPv4Address,
            ipaddress.IPv6Address,
            ipaddress.IPv4Interface,
            ipaddress.IPv6Interface,
        ),
    ):
        result = str(value)
        if isinstance(value, datetime):
            if value.tzinfo is not None and value.utcoffset() is not None:
                value = value.astimezone(UTC)
            result = value.isoformat(timespec="microseconds")
        return result
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, Mapping):
        return {
            str(key): _normalize_manifest_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_normalize_manifest_value(item) for item in value]
    raise GenerationResetRefused(
        f"reset manifest cannot canonicalize {type(value).__name__}",
    )


def _digest(payload: Any) -> str:
    canonical = canonical_json({"value": payload})
    if isinstance(canonical, str):
        canonical = canonical.encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _deletion_order(targets: set[str]) -> tuple[str, ...]:
    """Return children before parents without relying on cascade side effects."""

    dependencies = {
        name: {
            foreign_key.column.table.name
            for foreign_key in Base.metadata.tables[name].foreign_keys
            if foreign_key.column.table.name in targets and foreign_key.column.table.name != name
        }
        for name in targets
    }
    remaining = set(targets)
    ordered: list[str] = []
    while remaining:
        leaves = sorted(
            name
            for name in remaining
            if not any(name in dependencies[other] for other in remaining if other != name)
        )
        if not leaves:
            raise GenerationResetRefused(
                "reset table contract contains an unresolved dependency cycle",
            )
        ordered.extend(leaves)
        remaining.difference_update(leaves)
    return tuple(ordered)


async def _sqlite_schema_contract(session: AsyncSession) -> dict[str, str]:
    rows = (
        await session.execute(
            text(
                "SELECT name, type FROM sqlite_schema "
                "WHERE name NOT LIKE 'sqlite_%' "
                "AND type IN ('table', 'view') "
                "ORDER BY type, name",
            ),
        )
    ).all()
    return {str(row.name): str(row.type) for row in rows}


def _normalize_sqlite_schema_definition(
    object_type: str,
    definition: str | None,
) -> str | dict[str, Any] | None:
    if definition is None:
        return None
    lines = [" ".join(line.split()) for line in definition.splitlines() if line.strip()]
    if (
        object_type == "table"
        and len(lines) >= 3
        and lines[0].upper().startswith("CREATE TABLE ")
        and lines[-1] == ")"
    ):
        # Split the table body by SQL structure, not by physical lines.
        # SQLite implements ``ALTER TABLE ... ADD COLUMN`` by editing the
        # stored CREATE statement in ``sqlite_schema``.  The added declaration
        # is appended to the previous physical line, while the same column in
        # a freshly-created table occupies its own line.  Treating lines as
        # columns therefore gave semantically identical fresh and upgraded
        # databases different contract digests.
        body = _split_sqlite_table_items(" ".join(lines[1:-1]))
        constraints = [
            line
            for line in body
            if line.upper().startswith(
                ("CONSTRAINT ", "PRIMARY KEY ", "FOREIGN KEY ", "UNIQUE ", "CHECK "),
            )
        ]
        header = lines[0]
        quoted_header = re.fullmatch(
            r'CREATE TABLE "([A-Za-z_][A-Za-z0-9_]*)" \(',
            header,
            flags=re.IGNORECASE,
        )
        columns = [line for line in body if line not in constraints]
        if (
            quoted_header is not None
            and quoted_header.group(1) in _SQLITE_COMPATIBILITY_REBUILT_TABLES
        ):
            header = f"CREATE TABLE {quoted_header.group(1)} ("
            columns = [
                re.sub(
                    r"\bDEFAULT \((CURRENT_(?:DATE|TIME|TIMESTAMP))\)",
                    r"DEFAULT \1",
                    line,
                    flags=re.IGNORECASE,
                )
                for line in columns
            ]
        return {
            # SQLite's table-rebuild ALTER path quotes a simple identifier
            # even when the original CREATE statement did not.  The names
            # are the same SQL identifier, so retain one spelling in the
            # schema contract.
            "header": header,
            "columns": columns,
            # SQLite may rewrite an otherwise equivalent table with table-level
            # constraints in a different textual order. Their declarations are
            # conjunctive, so compare that portion as a set.
            "constraints": sorted(constraints),
        }
    return " ".join(lines)


def _split_sqlite_table_items(  # noqa: PLR0912  one explicit SQL lexical state machine
    body: str,
) -> list[str]:
    """Return top-level column and constraint declarations from ``body``.

    Commas inside expressions, quoted defaults, or table constraints are not
    separators.  The result deliberately preserves declaration order while
    removing formatting-only differences in SQLite's stored CREATE text.
    """

    items: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    index = 0
    while index < len(body):
        char = body[index]
        if quote is not None:
            if quote == "[":
                if char == "]":
                    quote = None
            elif char == quote:
                # SQL quotes escape themselves by doubling.  Consume the
                # second quote instead of treating it as the end delimiter.
                if index + 1 < len(body) and body[index + 1] == quote:
                    index += 1
                else:
                    quote = None
        elif char in {"'", '"', "`", "["}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            item = " ".join(body[start:index].split())
            if item:
                items.append(item)
            start = index + 1
        index += 1

    item = " ".join(body[start:].split())
    if item:
        items.append(item)
    return items


async def _sqlite_exact_schema_contract(
    session: AsyncSession,
) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            text(
                "SELECT type, name, tbl_name, sql FROM sqlite_schema "
                "WHERE name NOT LIKE 'sqlite_%' "
                "AND type IN ('table', 'index', 'trigger', 'view') "
                "ORDER BY type, name",
            ),
        )
    ).all()
    return [
        {
            "type": str(row.type),
            "name": str(row.name),
            "table_name": str(row.tbl_name),
            "definition": _normalize_sqlite_schema_definition(
                str(row.type),
                None if row.sql is None else str(row.sql),
            ),
        }
        for row in rows
    ]


async def _postgres_schema_contract(
    session: AsyncSession,
) -> tuple[dict[str, Any], ...]:
    rows = (
        (
            await session.execute(
                text(
                    "SELECT child.relname AS name, child.relkind AS kind, "
                    "child.oid::bigint AS relation_oid, "
                    "child.relispartition AS is_partition, "
                    "namespace.nspname AS schema_name, "
                    "owner_role.rolname AS owner, "
                    "parent.relname AS parent_name, "
                    "parent.oid::bigint AS parent_oid, "
                    "pg_get_partkeydef(child.oid) AS partition_key, "
                    "pg_get_expr(child.relpartbound, child.oid, true) "
                    "AS partition_bound, "
                    "(SELECT pg_get_constraintdef(pk.oid, true) "
                    "FROM pg_constraint pk "
                    "WHERE pk.conrelid = child.oid AND pk.contype = 'p' "
                    "ORDER BY pk.conname LIMIT 1) AS primary_key_definition, "
                    "EXISTS (SELECT 1 FROM pg_inherits nested "
                    "WHERE nested.inhparent = child.oid) AS has_children "
                    "FROM pg_class child "
                    "JOIN pg_namespace namespace "
                    "ON namespace.oid = child.relnamespace "
                    "JOIN pg_roles owner_role "
                    "ON owner_role.oid = child.relowner "
                    "LEFT JOIN pg_inherits inheritance "
                    "ON inheritance.inhrelid = child.oid "
                    "LEFT JOIN pg_class parent "
                    "ON parent.oid = inheritance.inhparent "
                    "WHERE namespace.nspname = current_schema() "
                    "AND child.relkind IN ('r', 'p', 'S', 'v', 'm', 'f') "
                    "ORDER BY child.relname",
                ),
            )
        )
        .mappings()
        .all()
    )
    normalized: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        if isinstance(item["kind"], bytes):
            item["kind"] = item["kind"].decode("ascii")
        normalized.append(item)
    return tuple(normalized)


def _normalize_postgres_catalog_rows(
    rows: Any,
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for row in rows:
        item: dict[str, Any] = {}
        for key, value in dict(row).items():
            normalized_value = value.decode("ascii") if isinstance(value, bytes) else value
            if normalized_value == "\x00":
                # asyncpg exposes PostgreSQL's internal blank "char" as NUL;
                # psycopg exposes the same catalog value as an empty string.
                normalized_value = ""
            if key in {"default_expression", "definition"} and isinstance(normalized_value, str):
                # pg_dump/reparse may move the text coercion from the
                # ARRAY expression onto each varchar literal.  PostgreSQL
                # proves these forms equivalent, so make the catalog
                # signature stable across a coherent dump/restore.
                normalized_value = normalized_value.replace(
                    "::character varying::text",
                    "::character varying",
                ).replace(
                    "]::text[]",
                    "]",
                )
            item[str(key)] = normalized_value
        normalized.append(item)
    return normalized


def _dense_column_ordinals(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Replace each column's physical ``attnum`` with its live position.

    PostgreSQL never reuses a dropped column's ``attnum``: DROP COLUMN leaves
    an ``attisdropped`` slot behind and a later ADD COLUMN takes the next
    number.  A supported downgrade and re-upgrade therefore reaches the head
    with the same columns in the same order under higher physical numbers,
    while pg_restore numbers every table densely again.  The contract binds
    the order of live columns, which a real reordering still changes, not
    that history.  Without dropped slots the position equals ``attnum``, so
    such a database keeps exactly the manifest and pinned digest it had.
    """

    live_attnums: dict[str, list[int]] = {}
    for row in rows:
        live_attnums.setdefault(str(row["table_name"]), []).append(int(row["attnum"]))
    for attnums in live_attnums.values():
        attnums.sort()
    dense: list[dict[str, Any]] = []
    for row in rows:
        ordered = live_attnums[str(row["table_name"])]
        # ``ordinal`` takes the place ``attnum`` held, so key order is unchanged.
        dense.append(
            {
                ("ordinal" if key == "attnum" else key): (
                    ordered.index(int(value)) + 1 if key == "attnum" else value
                )
                for key, value in row.items()
            },
        )
    return dense


async def _postgres_exact_schema_contract(
    session: AsyncSession,
) -> dict[str, list[dict[str, Any]]]:
    columns = (
        (
            await session.execute(
                text(
                    """
                    SELECT table_class.relname AS table_name,
                           attribute.attnum AS attnum,
                           attribute.attname AS column_name,
                           format_type(
                               attribute.atttypid,
                               attribute.atttypmod
                           ) AS data_type,
                           attribute.attnotnull AS not_null,
                           pg_get_expr(
                               default_row.adbin,
                               default_row.adrelid,
                               true
                           ) AS default_expression,
                           attribute.attidentity AS identity_kind,
                           attribute.attgenerated AS generated_kind,
                           COALESCE(
                               collation_row.collname,
                               ''
                           ) AS collation
                    FROM pg_class table_class
                    JOIN pg_namespace namespace
                      ON namespace.oid = table_class.relnamespace
                    JOIN pg_attribute attribute
                      ON attribute.attrelid = table_class.oid
                    LEFT JOIN pg_attrdef default_row
                      ON default_row.adrelid = table_class.oid
                     AND default_row.adnum = attribute.attnum
                    LEFT JOIN pg_collation collation_row
                      ON collation_row.oid = attribute.attcollation
                    WHERE namespace.nspname = current_schema()
                      AND table_class.relkind IN ('r', 'p')
                      AND NOT table_class.relispartition
                      AND attribute.attnum > 0
                      AND NOT attribute.attisdropped
                    ORDER BY table_class.relname, attribute.attnum
                    """,
                ),
            )
        )
        .mappings()
        .all()
    )
    constraints = (
        (
            await session.execute(
                text(
                    """
                    SELECT table_class.relname AS table_name,
                           constraint_row.conname AS constraint_name,
                           constraint_row.contype AS constraint_type,
                           pg_get_constraintdef(
                               constraint_row.oid,
                               true
                           ) AS definition,
                           constraint_row.condeferrable AS deferrable,
                           constraint_row.condeferred AS initially_deferred,
                           constraint_row.convalidated AS validated,
                           constraint_row.connoinherit AS no_inherit
                    FROM pg_constraint constraint_row
                    JOIN pg_class table_class
                      ON table_class.oid = constraint_row.conrelid
                    JOIN pg_namespace namespace
                      ON namespace.oid = table_class.relnamespace
                    WHERE namespace.nspname = current_schema()
                      AND table_class.relkind IN ('r', 'p')
                      AND NOT table_class.relispartition
                    ORDER BY table_class.relname, constraint_row.conname
                    """,
                ),
            )
        )
        .mappings()
        .all()
    )
    indexes = (
        (
            await session.execute(
                text(
                    """
                    SELECT table_class.relname AS table_name,
                           index_class.relname AS index_name,
                           index_class.relkind AS index_kind,
                           pg_get_indexdef(
                               index_class.oid,
                               0,
                               true
                           ) AS definition,
                           index_row.indisunique AS is_unique,
                           index_row.indisprimary AS is_primary,
                           index_row.indisvalid AS is_valid,
                           index_row.indisready AS is_ready
                    FROM pg_index index_row
                    JOIN pg_class table_class
                      ON table_class.oid = index_row.indrelid
                    JOIN pg_class index_class
                      ON index_class.oid = index_row.indexrelid
                    JOIN pg_namespace namespace
                      ON namespace.oid = table_class.relnamespace
                    WHERE namespace.nspname = current_schema()
                      AND table_class.relkind IN ('r', 'p')
                      AND NOT table_class.relispartition
                    ORDER BY table_class.relname, index_class.relname
                    """,
                ),
            )
        )
        .mappings()
        .all()
    )
    triggers = (
        (
            await session.execute(
                text(
                    """
                    SELECT table_class.relname AS table_name,
                           trigger_row.tgname AS trigger_name,
                           trigger_row.tgenabled AS enabled,
                           pg_get_triggerdef(
                               trigger_row.oid,
                               true
                           ) AS definition
                    FROM pg_trigger trigger_row
                    JOIN pg_class table_class
                      ON table_class.oid = trigger_row.tgrelid
                    JOIN pg_namespace namespace
                      ON namespace.oid = table_class.relnamespace
                    WHERE namespace.nspname = current_schema()
                      AND table_class.relkind IN ('r', 'p')
                      AND NOT table_class.relispartition
                      AND NOT trigger_row.tgisinternal
                    ORDER BY table_class.relname, trigger_row.tgname
                    """,
                ),
            )
        )
        .mappings()
        .all()
    )
    sequences = (
        (
            await session.execute(
                text(
                    """
                    SELECT sequence_class.relname AS sequence_name,
                           format_type(
                               sequence_row.seqtypid,
                               NULL
                           ) AS data_type,
                           sequence_row.seqstart AS start_value,
                           sequence_row.seqincrement AS increment_by,
                           sequence_row.seqmax AS max_value,
                           sequence_row.seqmin AS min_value,
                           sequence_row.seqcache AS cache_size,
                           sequence_row.seqcycle AS cycles,
                           owner_table.relname AS owned_by_table,
                           owner_attribute.attname AS owned_by_column
                    FROM pg_sequence sequence_row
                    JOIN pg_class sequence_class
                      ON sequence_class.oid = sequence_row.seqrelid
                    JOIN pg_namespace namespace
                      ON namespace.oid = sequence_class.relnamespace
                    LEFT JOIN pg_depend dependency
                      ON dependency.objid = sequence_class.oid
                     AND dependency.deptype IN ('a', 'i')
                    LEFT JOIN pg_class owner_table
                      ON owner_table.oid = dependency.refobjid
                    LEFT JOIN pg_attribute owner_attribute
                      ON owner_attribute.attrelid = dependency.refobjid
                     AND owner_attribute.attnum = dependency.refobjsubid
                    WHERE namespace.nspname = current_schema()
                    ORDER BY sequence_class.relname
                    """,
                ),
            )
        )
        .mappings()
        .all()
    )
    return {
        "columns": _dense_column_ordinals(_normalize_postgres_catalog_rows(columns)),
        "constraints": _normalize_postgres_catalog_rows(constraints),
        "indexes": _normalize_postgres_catalog_rows(indexes),
        "triggers": _normalize_postgres_catalog_rows(triggers),
        "sequences": _normalize_postgres_catalog_rows(sequences),
    }


async def _lock_postgres_reset_domain(session: AsyncSession) -> None:
    await session.execute(
        text("SELECT pg_advisory_xact_lock(:lock_id)"),
        {"lock_id": SCHEMA_TRANSITION_ADVISORY_LOCK_KEY},
    )
    await session.execute(
        text("LOCK TABLE alembic_version IN SHARE ROW EXCLUSIVE MODE"),
    )
    # Recursive parent locks cover every currently attached leaf and exclude
    # CREATE/ATTACH/DETACH/DROP PARTITION while the catalog is frozen.
    await session.execute(
        text(
            "LOCK TABLE events, schedule_fires IN ACCESS EXCLUSIVE MODE",
        ),
    )
    audit_objects = {
        "audit_chain_preparation",
        "audit_chain_state",
        "audit_log",
    }
    lock_targets = sorted(
        RESET_ORM_TABLES - audit_objects - {"events", "schedule_fires"},
    )
    preparer = session.get_bind().dialect.identifier_preparer
    for table_name in lock_targets:
        await session.execute(
            text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                f"LOCK TABLE {preparer.quote(table_name)} IN SHARE ROW EXCLUSIVE MODE",
            ),
        )


async def _assert_schema_contract(  # noqa: PLR0912  one closed dialect contract
    session: AsyncSession,
) -> str:
    metadata_tables = frozenset(Base.metadata.tables)
    if metadata_tables != RESET_ORM_TABLES:
        missing = sorted(RESET_ORM_TABLES - metadata_tables)
        added = sorted(metadata_tables - RESET_ORM_TABLES)
        raise GenerationResetRefused(
            f"reset ORM contract drift (missing={missing}, added={added})",
        )
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        actual = await _sqlite_schema_contract(session)
        expected = RESET_ORM_TABLES | {"alembic_version"}
        actual_tables = {name for name, kind in actual.items() if kind == "table"}
        unknown_objects = sorted(name for name, kind in actual.items() if kind != "table")
        if actual_tables != expected or unknown_objects:
            raise GenerationResetRefused(
                "reset schema contract mismatch "
                f"(missing={sorted(expected - actual_tables)}, "
                f"unknown={sorted(actual_tables - expected)}, "
                f"unsupported_objects={unknown_objects})",
            )
        schema_digest = _digest(await _sqlite_exact_schema_contract(session))
        if schema_digest != SQLITE_RELEASE_SCHEMA_CONTRACT_DIGEST:
            raise GenerationResetRefused(
                "reset SQLite migration-head schema signature mismatch "
                f"(observed={schema_digest}, "
                f"expected={SQLITE_RELEASE_SCHEMA_CONTRACT_DIGEST})",
            )
    elif dialect == "postgresql":
        await _lock_postgres_reset_domain(session)
        server_version_number = int(
            await session.scalar(
                text("SELECT current_setting('server_version_num')"),
            ),
        )
        server_major = server_version_number // 10_000
        expected_schema_digest = _POSTGRES_SCHEMA_CONTRACT_DIGESTS.get(
            server_major,
        )
        if expected_schema_digest is None:
            raise GenerationResetRefused(
                "reset PostgreSQL major version is not in the reviewed "
                f"schema contract set: {server_major}",
            )
        relations = await _postgres_schema_contract(session)
        root_relations = {str(row["name"]): row for row in relations if not row["is_partition"]}
        partitions = [row for row in relations if bool(row["is_partition"])]
        expected_roots = (
            RESET_ORM_TABLES
            | {
                "alembic_version",
            }
            | _PRESERVED_POSTGRES_SEQUENCES
        )
        if set(root_relations) != expected_roots:
            raise GenerationResetRefused(
                "reset PostgreSQL relation contract mismatch "
                f"(missing={sorted(expected_roots - set(root_relations))}, "
                f"unknown={sorted(set(root_relations) - expected_roots)})",
            )
        current_user = str(await session.scalar(text("SELECT current_user")))
        if {str(row["owner"]) for row in relations} != {current_user}:
            raise GenerationResetRefused(
                "reset PostgreSQL relation owner mismatch",
            )
        for name, relation in root_relations.items():
            expected_kind = (
                "S"
                if name in _PRESERVED_POSTGRES_SEQUENCES
                else "p"
                if name in {"events", "schedule_fires"}
                else "r"
            )
            if relation["kind"] != expected_kind:
                raise GenerationResetRefused(
                    "reset PostgreSQL relation kind mismatch for "
                    f"{name}: {relation['kind']!r} != {expected_kind!r}",
                )
            expected_partition_key = {
                "events": "RANGE (occurred_at)",
                "schedule_fires": "RANGE (scheduled_for)",
            }.get(name)
            if relation["partition_key"] != expected_partition_key:
                raise GenerationResetRefused(
                    "reset PostgreSQL partition-key mismatch for "
                    f"{name}: {relation['partition_key']!r} != "
                    f"{expected_partition_key!r}",
                )
        for partition in partitions:
            expected_primary_key = {
                "events": "PRIMARY KEY (project_id, occurred_at, id)",
                "schedule_fires": "PRIMARY KEY (id, scheduled_for)",
            }.get(str(partition["parent_name"]))
            if (
                partition["kind"] != "r"
                or partition["parent_name"] not in {"events", "schedule_fires"}
                or partition["has_children"]
                or not partition["partition_bound"]
                or partition["primary_key_definition"] != expected_primary_key
            ):
                raise GenerationResetRefused(
                    f"reset PostgreSQL partition classification mismatch for {partition['name']}",
                )
        schema_digest = _digest(await _postgres_exact_schema_contract(session))
        if schema_digest != expected_schema_digest:
            raise GenerationResetRefused(
                "reset PostgreSQL migration-head schema signature mismatch "
                f"(major={server_major}, observed={schema_digest}, "
                f"expected={expected_schema_digest})",
            )
    else:
        raise GenerationResetRefused(
            f"unsupported reset database backend: {dialect}",
        )
    heads = (await session.execute(text("SELECT version_num FROM alembic_version"))).scalars().all()
    if heads != [RESET_MIGRATION_HEAD]:
        raise GenerationResetRefused(
            f"reset requires exact migration head {RESET_MIGRATION_HEAD}",
        )
    return schema_digest


async def _table_manifest(
    session: AsyncSession,
    table_name: str,
) -> dict[str, Any]:
    table = Base.metadata.tables[table_name]
    primary_key = tuple(column.name for column in table.primary_key.columns)
    if not primary_key:
        raise GenerationResetRefused(
            f"reset target {table_name} has no primary key contract",
        )
    statement = select(table)
    statement = statement.order_by(*(table.c[name] for name in primary_key))
    rows = (await session.execute(statement)).mappings().all()
    normalized_rows = [
        {column.name: _normalize_manifest_value(row[column.name]) for column in table.columns}
        for row in rows
    ]
    if table_name in _PROTECTED_TRANSITION_TABLES:
        classification = "protected_transition"
    elif table_name in _MUST_BE_EMPTY_TABLES:
        classification = "must_be_empty"
    else:
        classification = "delete"
    return {
        "classification": classification,
        "primary_key": list(primary_key),
        "row_count": len(normalized_rows),
        "content_digest": _digest(normalized_rows),
    }


async def _postgres_partition_manifests(
    session: AsyncSession,
) -> dict[str, dict[str, Any]]:
    relations = await _postgres_schema_contract(session)
    partitions = [row for row in relations if bool(row["is_partition"])]
    preparer = session.get_bind().dialect.identifier_preparer
    result: dict[str, dict[str, Any]] = {}
    for partition in partitions:
        name = str(partition["name"])
        parent_name = str(partition["parent_name"])
        parent = Base.metadata.tables[parent_name]
        column_names = tuple(column.name for column in parent.columns)
        primary_key = tuple(column.name for column in parent.primary_key.columns)
        quoted_columns = ", ".join(preparer.quote(column_name) for column_name in column_names)
        ordering = ", ".join(preparer.quote(column_name) for column_name in primary_key)
        rows = (
            (
                await session.execute(
                    text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                        f"SELECT {quoted_columns} FROM "  # noqa: S608  catalog-proved, dialect-quoted identifier
                        f"{preparer.quote(name)} ORDER BY {ordering}",
                    ),
                )
            )
            .mappings()
            .all()
        )
        normalized_rows = [
            {
                column_name: _normalize_manifest_value(row[column_name])
                for column_name in column_names
            }
            for row in rows
        ]
        result[name] = {
            "classification": "attached_partition_delete",
            "relation_oid": int(partition["relation_oid"]),
            "parent_relation_oid": int(partition["parent_oid"]),
            "schema": str(partition["schema_name"]),
            "parent": parent_name,
            "partition_bound": str(partition["partition_bound"]),
            "owner": str(partition["owner"]),
            "primary_key_definition": str(partition["primary_key_definition"]),
            "primary_key": list(primary_key),
            "row_count": len(normalized_rows),
            "content_digest": _digest(normalized_rows),
        }
    return result


async def _freeze_manifest(session: AsyncSession) -> dict[str, Any]:
    schema_contract_digest = await _assert_schema_contract(session)
    tables = {
        table_name: await _table_manifest(session, table_name)
        for table_name in sorted(RESET_ORM_TABLES)
    }
    if tables["audit_chain_preparation"]["row_count"] != 0:
        raise GenerationResetRefused(
            "audit activation preparation is unresolved",
        )
    manifest = {
        "manifest_version": RESET_MANIFEST_VERSION,
        "migration_head": RESET_MIGRATION_HEAD,
        "schema_contract_digest": schema_contract_digest,
        "backend": session.get_bind().dialect.name,
        "tables": tables,
    }
    if session.get_bind().dialect.name == "postgresql":
        manifest["physical_partitions"] = await _postgres_partition_manifests(
            session,
        )
    return manifest


async def _external_authority_manifest(
    session: AsyncSession,
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    tables = manifest["tables"]
    stream_rows = (
        (
            await session.execute(
                select(ScheduleExternalStream).order_by(
                    ScheduleExternalStream.id,
                ),
            )
        )
        .scalars()
        .all()
    )
    epoch_rows = (
        (
            await session.execute(
                select(ScheduleExternalStreamEpoch).order_by(
                    ScheduleExternalStreamEpoch.epoch_number,
                    ScheduleExternalStreamEpoch.epoch_uuid,
                ),
            )
        )
        .scalars()
        .all()
    )
    operation_rows = (
        (
            await session.execute(
                select(ScheduleExternalControlOperation)
                .where(
                    ScheduleExternalControlOperation.status.in_(
                        ("PENDING", "CLAIMED", "AMBIGUOUS"),
                    ),
                )
                .order_by(ScheduleExternalControlOperation.id),
            )
        )
        .scalars()
        .all()
    )
    streams = [
        {
            "stream_id": str(row.id),
            "epoch_uuid": str(row.current_epoch_uuid),
            "epoch_number": int(row.current_epoch_number),
            "phase": row.phase,
            "adapter_instance_id": row.authorized_adapter_instance_id,
            "agent_id": (str(row.executor_agent_id) if row.executor_agent_id is not None else None),
            "registry_owner_id": (
                str(row.executor_registry_owner_id)
                if row.executor_registry_owner_id is not None
                else None
            ),
            "session_generation": row.executor_session_generation,
            "worker_id": row.executor_worker_id,
        }
        for row in stream_rows
        if row.authorized_adapter_instance_id is not None
        or row.executor_agent_id is not None
        or row.executor_registry_owner_id is not None
        or row.executor_session_generation is not None
    ]
    epochs = [
        {
            "stream_id": str(row.stream_id),
            "epoch_uuid": str(row.epoch_uuid),
            "epoch_number": int(row.epoch_number),
            "phase": row.phase,
            "adapter_instance_id": row.authorized_adapter_instance_id,
            "agent_id": (str(row.executor_agent_id) if row.executor_agent_id is not None else None),
            "registry_owner_id": (
                str(row.executor_registry_owner_id)
                if row.executor_registry_owner_id is not None
                else None
            ),
            "session_generation": row.executor_session_generation,
            "worker_id": row.executor_worker_id,
        }
        for row in epoch_rows
        if row.authorized_adapter_instance_id is not None
        or row.executor_agent_id is not None
        or row.executor_registry_owner_id is not None
        or row.executor_session_generation is not None
    ]
    operations = [
        {
            "operation_id": str(row.id),
            "command_id": str(row.command_id),
            "stream_id": str(row.stream_id),
            "epoch_uuid": str(row.epoch_uuid),
            "epoch_number": int(row.epoch_number),
            "status": row.status,
            "adapter_instance_id": row.adapter_instance_id,
            "agent_id": str(row.agent_id),
            "registry_owner_id": str(row.registry_owner_id),
            "session_generation": row.session_generation,
            "dispatch_lease": (str(row.dispatch_lease) if row.dispatch_lease is not None else None),
        }
        for row in operation_rows
    ]
    return {
        "allocator_digest": tables["schedule_external_epoch_allocator"]["content_digest"],
        "stream_digest": tables["schedule_external_streams"]["content_digest"],
        "epoch_digest": tables["schedule_external_stream_epochs"]["content_digest"],
        "operation_digest": tables["schedule_external_control_operations"]["content_digest"],
        "stream_count": tables["schedule_external_streams"]["row_count"],
        "epoch_count": tables["schedule_external_stream_epochs"]["row_count"],
        "operation_count": tables["schedule_external_control_operations"]["row_count"],
        "executor_authority": {
            "streams": streams,
            "epochs": epochs,
            "unresolved_operations": operations,
        },
        "requires_stopped_executor_attestation": bool(
            streams or epochs or operations,
        ),
    }


async def build_generation_reset_preview(
    session: AsyncSession,
    settings: Settings,
) -> dict[str, Any]:
    """Freeze and verify the exact operator-attestation challenge."""

    from z4j_brain.domain.audit_verifier import (
        verify_active_audit_generation,
    )

    if session.bind is None:
        raise GenerationResetRefused("reset preview session is not bound")
    if session.bind.dialect.name == "sqlite" and not session.sync_session.info.get(
        "z4j_sqlite_immediate",
    ):
        raise GenerationResetRefused(
            "SQLite reset preview did not begin with an immediate writer transaction",
        )
    if session.bind.dialect.name == "postgresql":
        await _assert_schema_contract(session)
        await AuditLogRepository(session).acquire_chain_lock()
        await session.execute(text("LOCK TABLE audit_log IN EXCLUSIVE MODE"))
        await session.execute(
            text(
                "LOCK TABLE audit_chain_preparation, audit_chain_state IN SHARE ROW EXCLUSIVE MODE",
            ),
        )
    manifest = await _freeze_manifest(session)
    report = await verify_active_audit_generation(
        session,
        settings,
        page_size=5000,
    )
    if not report.clean:
        raise GenerationResetRefused(
            f"authenticated audit state is not clean enough to reset: {list(report.mismatches)}",
        )
    if await _freeze_manifest(session) != manifest:
        raise GenerationResetRefused(
            "reset manifest changed while building the preview",
        )
    manifest_digest = _digest(manifest)
    external_manifest = await _external_authority_manifest(
        session,
        manifest,
    )
    challenge = _digest(
        {
            "version": 1,
            "kind": "stopped_all_manifested_external_executors",
            "destruction_manifest_digest": manifest_digest,
            "external_authority_manifest": external_manifest,
        },
    )
    return {
        "preview_version": 1,
        "reset_manifest_version": RESET_MANIFEST_VERSION,
        "migration_head": RESET_MIGRATION_HEAD,
        "destruction_manifest_digest": manifest_digest,
        "stopped_executor_attestation_challenge": challenge,
        "requires_stopped_executor_attestation": external_manifest[
            "requires_stopped_executor_attestation"
        ],
        "external_authority_manifest": external_manifest,
        "destruction_manifest": manifest,
    }


async def perform_generation_reset(  # noqa: PLR0912, PLR0915  one atomic cross-boundary ceremony
    session: AsyncSession,
    settings: Settings,
    *,
    stopped_executor_attestation: str | None = None,
) -> dict[str, Any]:
    """Perform one atomic ordinary reset and return its signed manifest data."""

    if session.bind is None:
        raise GenerationResetRefused("reset session is not bound")
    if session.bind.dialect.name == "sqlite" and not session.sync_session.info.get(
        "z4j_sqlite_immediate",
    ):
        raise GenerationResetRefused(
            "SQLite reset did not begin with an immediate writer transaction",
        )

    if session.bind.dialect.name == "postgresql":
        # Domain/schema locks precede the chain lock.  Audit relations are
        # intentionally absent from the earlier lock phase.
        await _assert_schema_contract(session)
        await AuditLogRepository(session).acquire_chain_lock()
        await session.execute(
            text(
                "LOCK TABLE audit_log IN EXCLUSIVE MODE",
            ),
        )
        await session.execute(
            text(
                "LOCK TABLE audit_chain_preparation, audit_chain_state IN SHARE ROW EXCLUSIVE MODE",
            ),
        )
    manifest = await _freeze_manifest(session)
    # Recheck the complete schema and row manifest under the same SQLite writer
    # lock immediately before arming destruction.
    if await _freeze_manifest(session) != manifest:
        raise GenerationResetRefused(
            "reset manifest changed before destruction",
        )
    manifest_digest = _digest(manifest)
    external_manifest = await _external_authority_manifest(
        session,
        manifest,
    )
    attestation_challenge = _digest(
        {
            "version": 1,
            "kind": "stopped_all_manifested_external_executors",
            "destruction_manifest_digest": manifest_digest,
            "external_authority_manifest": external_manifest,
        },
    )
    if external_manifest["requires_stopped_executor_attestation"]:
        if stopped_executor_attestation != attestation_challenge:
            raise GenerationResetRefused(
                "external executor authority exists; reset requires "
                "the exact stopped-executor attestation challenge "
                f"{attestation_challenge}",
            )
        attestation = {
            "version": 1,
            "kind": "stopped_all_manifested_external_executors",
            "challenge": attestation_challenge,
            "external_authority_manifest": external_manifest,
        }
    else:
        if stopped_executor_attestation is not None:
            raise GenerationResetRefused(
                "a stopped-executor attestation was supplied but the "
                "finalized manifest contains no executor authority",
            )
        attestation = {
            "version": 1,
            "kind": "no_external_executor_authority",
            "external_authority_manifest": external_manifest,
        }
    attestation_digest = _digest(attestation)

    revision_state = (
        await session.execute(
            select(ScheduleRevisionState)
            .where(
                ScheduleRevisionState.singleton_id == SCHEDULE_REVISION_SINGLETON_ID,
            )
            .with_for_update(),
        )
    ).scalar_one_or_none()
    epoch_allocator = (
        await session.execute(
            select(ScheduleExternalEpochAllocator)
            .where(
                ScheduleExternalEpochAllocator.singleton_id == SCHEDULE_EXTERNAL_EPOCH_SINGLETON_ID,
            )
            .with_for_update(),
        )
    ).scalar_one_or_none()
    audit_state = (
        await session.execute(
            select(AuditChainState).with_for_update(),
        )
    ).scalar_one_or_none()
    if (
        revision_state is None
        or revision_state.guard_version != 1
        or epoch_allocator is None
        or epoch_allocator.guard_version != 1
        or audit_state is None
    ):
        raise GenerationResetRefused(
            "reset protected transition state is missing or inactive",
        )
    old_revision = int(revision_state.current_revision)
    old_pruned_through = int(revision_state.change_log_pruned_through)
    old_epoch = int(epoch_allocator.current_epoch_number)
    old_audit_generation = str(audit_state.generation)
    old_audit_state_mac = audit_state.state_mac
    installation_id = str(audit_state.installation_id)
    if old_revision >= _MAX_BIGINT or old_epoch >= _MAX_BIGINT:
        raise GenerationResetRefused(
            "reset monotonic namespace is exhausted",
        )
    new_revision = old_revision + 1
    new_epoch = old_epoch + 1
    guarded_counts = {
        table_name: int(manifest["tables"][table_name]["row_count"])
        for table_name in sorted(_D_RESET_GUARDED_TABLES)
    }
    reset_armed = await arm_generation_reset(
        session,
        expected_counts=guarded_counts,
        manifest_digest=manifest_digest,
        old_revision=old_revision,
        new_revision=new_revision,
        old_epoch=old_epoch,
        new_epoch=new_epoch,
        attestation_digest=attestation_digest,
    )
    if not reset_armed:
        raise GenerationResetRefused(
            "Boundary-D reset guard is not active",
        )

    delete_targets = (
        set(RESET_ORM_TABLES)
        - _PROTECTED_TRANSITION_TABLES
        - _MUST_BE_EMPTY_TABLES
        - {_AUDIT_TABLE}
    )
    wiped_rows = 0
    for table_name in _deletion_order(delete_targets):
        expected_count = int(manifest["tables"][table_name]["row_count"])
        result = await session.execute(delete(Base.metadata.tables[table_name]))
        if (result.rowcount or 0) != expected_count:
            raise GenerationResetRefused(
                f"reset delete count changed for {table_name}",
            )
        wiped_rows += expected_count
    if session.bind.dialect.name == "postgresql":
        preparer = session.get_bind().dialect.identifier_preparer
        for partition_name in sorted(manifest["physical_partitions"]):
            remaining = await session.scalar(
                text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                    f"SELECT COUNT(*) FROM {preparer.quote(partition_name)}",  # noqa: S608  catalog-proved, dialect-quoted identifier
                ),
            )
            if int(remaining or 0) != 0:
                raise GenerationResetRefused(
                    f"reset PostgreSQL partition was not emptied: {partition_name}",
                )

    revision_result = await session.execute(
        update(ScheduleRevisionState)
        .where(
            ScheduleRevisionState.singleton_id == SCHEDULE_REVISION_SINGLETON_ID,
            ScheduleRevisionState.current_revision == old_revision,
        )
        .values(
            current_revision=new_revision,
            change_log_pruned_through=new_revision,
        ),
    )
    epoch_result = await session.execute(
        update(ScheduleExternalEpochAllocator)
        .where(
            ScheduleExternalEpochAllocator.singleton_id == SCHEDULE_EXTERNAL_EPOCH_SINGLETON_ID,
            ScheduleExternalEpochAllocator.current_epoch_number == old_epoch,
        )
        .values(current_epoch_number=new_epoch),
    )
    if (revision_result.rowcount or 0) != 1 or (epoch_result.rowcount or 0) != 1:
        raise GenerationResetRefused(
            "reset monotonic barriers did not advance exactly once",
        )
    await finalize_generation_reset(
        session,
        active=reset_armed,
        manifest_digest=manifest_digest,
        attestation_digest=attestation_digest,
    )

    retired_binding_digest = (
        _digest(audit_state.retired_recovery_binding)
        if audit_state.retired_recovery_binding is not None
        else None
    )
    marker = await AuditService(settings).reset_generation(
        AuditLogRepository(session),
        metadata={
            "reset_manifest_version": RESET_MANIFEST_VERSION,
            "migration_head": RESET_MIGRATION_HEAD,
            "destruction_manifest_digest": manifest_digest,
            "external_authority_manifest": external_manifest,
            "executor_attestation_digest": attestation_digest,
            "installation_id": installation_id,
            "retired_recovery_binding_digest": retired_binding_digest,
            "old_audit_generation": old_audit_generation,
            "old_audit_state_mac": old_audit_state_mac,
            "old_schedule_revision": old_revision,
            "new_schedule_revision": new_revision,
            "old_change_log_pruned_through": old_pruned_through,
            "new_change_log_pruned_through": new_revision,
            "old_external_epoch": old_epoch,
            "new_external_epoch": new_epoch,
            "wiped_domain_rows": wiped_rows,
        },
    )
    return {
        "manifest_digest": manifest_digest,
        "marker_id": str(marker.id),
        "wiped_domain_rows": wiped_rows,
        "old_revision": old_revision,
        "new_revision": new_revision,
        "old_epoch": old_epoch,
        "new_epoch": new_epoch,
    }


async def assert_release_schema_contract(
    session: AsyncSession,
) -> str:
    """Prove the exact release-head schema and return its digest."""

    return await _assert_schema_contract(session)


async def release_schema_contract_manifest(
    session: AsyncSession,
) -> dict[str, Any]:
    """Return the canonical exact-schema manifest for the active dialect."""

    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        return await _postgres_exact_schema_contract(session)
    if dialect == "sqlite":
        return await _sqlite_exact_schema_contract(session)
    raise GenerationResetRefused(
        f"unsupported schema manifest backend: {dialect}",
    )


async def freeze_release_manifest(
    session: AsyncSession,
) -> dict[str, Any]:
    """Freeze the exact release-head schema and data manifest."""

    return await _freeze_manifest(session)


async def external_authority_manifest(
    session: AsyncSession,
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the executor authorities bound to one frozen manifest."""

    return await _external_authority_manifest(session, manifest)


def release_manifest_digest(payload: Any) -> str:
    """Return the canonical digest used by release management ceremonies."""

    return _digest(payload)


__all__ = [
    "RESET_MANIFEST_VERSION",
    "RESET_MIGRATION_HEAD",
    "GenerationResetRefused",
    "assert_release_schema_contract",
    "build_generation_reset_preview",
    "external_authority_manifest",
    "freeze_release_manifest",
    "perform_generation_reset",
    "release_manifest_digest",
    "release_schema_contract_manifest",
]
