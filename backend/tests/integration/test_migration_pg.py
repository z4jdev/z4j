"""Integration test: ``alembic upgrade head`` against Postgres 18.

The unit-suite migration test runs against SQLite which silently
skips every Postgres-only branch. This test exercises the WHOLE
migration on real Postgres so the regex CHECK, the ENUM types,
the partial indexes, the GIN indexes, the partition pre-create,
and the audit_log triggers all run for real.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine


pytestmark = pytest.mark.asyncio


class TestMigrationStructure:
    async def test_every_table_present(self, migrated_engine: AsyncEngine) -> None:
        async with migrated_engine.connect() as conn:
            rows = await conn.execute(
                text(
                    "SELECT tablename FROM pg_tables "
                    "WHERE schemaname = 'public' "
                    "ORDER BY tablename",
                ),
            )
            tables = {r[0] for r in rows.all()}
        # Core tables, the partitioned events parent, and one of
        # the pre-created daily partitions should all exist.
        expected_core = {
            "users",
            "projects",
            "memberships",
            "agents",
            "queues",
            "workers",
            "tasks",
            "events",
            "schedules",
            "commands",
            "audit_log",
            "first_boot_tokens",
            "sessions",
            "alembic_version",
        }
        assert expected_core.issubset(tables)
        assert any(t.startswith("events_20") for t in tables), (
            "expected at least one daily events partition pre-created"
        )

    async def test_enum_types_present(self, migrated_engine: AsyncEngine) -> None:
        async with migrated_engine.connect() as conn:
            rows = await conn.execute(
                text(
                    "SELECT typname FROM pg_type "
                    "WHERE typtype = 'e' AND typnamespace = "
                    "(SELECT oid FROM pg_namespace WHERE nspname = 'public') "
                    "ORDER BY typname",
                ),
            )
            enums = {r[0] for r in rows.all()}
        assert {
            "agent_state",
            "command_status",
            "project_role",
            "schedule_kind",
            "task_state",
            "worker_state",
        }.issubset(enums)

    async def test_extensions_installed(self, migrated_engine: AsyncEngine) -> None:
        async with migrated_engine.connect() as conn:
            rows = await conn.execute(
                text("SELECT extname FROM pg_extension"),
            )
            extensions = {r[0] for r in rows.all()}
        # The migration installs three.
        assert {"pgcrypto", "citext", "pg_trgm"}.issubset(extensions)

    async def test_partial_indexes_present(
        self, migrated_engine: AsyncEngine,
    ) -> None:
        """Partial indexes that SQLite cannot represent."""
        async with migrated_engine.connect() as conn:
            rows = await conn.execute(
                text(
                    "SELECT indexname FROM pg_indexes "
                    "WHERE schemaname = 'public'",
                ),
            )
            indexes = {r[0] for r in rows.all()}
        for expected in (
            "ix_users_active_partial",
            "ix_projects_active_partial",
            "ix_commands_pending_timeout",
            "ix_schedules_next_run",
            "ix_tasks_args_gin",
            "ix_tasks_kwargs_gin",
            "ix_tasks_search",
            "ix_sessions_user_active",
        ):
            assert expected in indexes, f"missing index {expected}"

    async def test_events_is_partitioned(
        self, migrated_engine: AsyncEngine,
    ) -> None:
        async with migrated_engine.connect() as conn:
            row = (
                await conn.execute(
                    text(
                        "SELECT relkind::text FROM pg_class "
                        "WHERE relname = 'events' AND relnamespace = "
                        "(SELECT oid FROM pg_namespace WHERE nspname = 'public')",
                    ),
                )
            ).scalar_one()
        # 'p' = partitioned table. We cast relkind::text in the
        # query because asyncpg returns the raw 1-byte ``"char"``
        # type as bytes rather than str.
        assert row == "p"

    async def test_audit_log_triggers_present(
        self, migrated_engine: AsyncEngine,
    ) -> None:
        async with migrated_engine.connect() as conn:
            rows = await conn.execute(
                text(
                    "SELECT tgname FROM pg_trigger "
                    "WHERE tgrelid = 'audit_log'::regclass "
                    "AND NOT tgisinternal",
                ),
            )
            triggers = {r[0] for r in rows.all()}
        assert {"audit_log_no_update", "audit_log_no_delete"} <= triggers

    async def test_slug_check_constraint_enforced(
        self, migrated_engine: AsyncEngine,
    ) -> None:
        """The CHECK regex on projects.slug must reject bad input."""
        async with migrated_engine.begin() as conn:
            try:
                await conn.execute(
                    text(
                        "INSERT INTO projects (slug, name) "
                        "VALUES ('BAD_UPPER', 'X')",
                    ),
                )
                bad_accepted = True
            except Exception:  # noqa: BLE001
                bad_accepted = False
        assert bad_accepted is False

        async with migrated_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO projects (slug, name) "
                    "VALUES ('valid-slug', 'X')",
                ),
            )
        # Cleanup so the next test sees a clean table.
        async with migrated_engine.begin() as conn:
            await conn.execute(
                text("DELETE FROM projects WHERE slug = 'valid-slug'"),
            )
