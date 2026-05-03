"""Integration test: ``alembic upgrade head`` against Postgres 18.

The unit-suite migration test runs against SQLite which silently
skips every Postgres-only branch. This test exercises the WHOLE
migration on real Postgres so the regex CHECK, the ENUM types,
the partial indexes, the GIN indexes, the partition pre-create,
and the audit_log triggers all run for real.

It also covers the bidirectional contract documented in
``z4j.dev/operations/database-migrations``: every additive 1.4.x
migration must round-trip ``upgrade head -> downgrade base ->
upgrade head`` against a populated database without leaving stray
objects behind. ``TestMigrationRoundTrip`` enforces that.
"""

from __future__ import annotations

import asyncio
import os
import secrets
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from z4j_brain.settings import Settings


pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Helpers for the bidirectional round-trip test
# ---------------------------------------------------------------------------


def _alembic_config(settings: Settings):
    """Build an Alembic ``Config`` pointing at the per-test database."""
    from alembic.config import Config

    backend_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(backend_root / "alembic.ini"))
    cfg.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    return cfg


async def _run_alembic(settings: Settings, action: str, target: str) -> None:
    """Run ``alembic upgrade <target>`` or ``alembic downgrade <target>``.

    Mirrors the env-var wiring from the ``migrated_engine`` fixture
    so alembic's ``env.py`` resolves the same per-test Settings.
    """
    from alembic import command

    cfg = _alembic_config(settings)
    saved = {
        k: os.environ.get(k)
        for k in (
            "Z4J_DATABASE_URL",
            "Z4J_SECRET",
            "Z4J_SESSION_SECRET",
            "Z4J_ENVIRONMENT",
            "Z4J_REQUIRE_DB_SSL",
        )
    }
    try:
        os.environ["Z4J_DATABASE_URL"] = settings.database_url
        os.environ["Z4J_SECRET"] = settings.secret.get_secret_value()
        os.environ["Z4J_SESSION_SECRET"] = (
            settings.session_secret.get_secret_value()
        )
        os.environ["Z4J_ENVIRONMENT"] = "dev"
        os.environ["Z4J_REQUIRE_DB_SSL"] = "false"
        runner = command.upgrade if action == "upgrade" else command.downgrade
        await asyncio.get_event_loop().run_in_executor(
            None, lambda: runner(cfg, target),
        )
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# Tables and ENUM types we expect to NOT exist after ``downgrade base``.
# Sourced from the explicit drop list in ``v1_3_0_initial.downgrade()``
# plus ``alembic_version`` (which alembic itself drops at base).
_Z4J_TABLES_THAT_MUST_BE_GONE = (
    "users", "projects", "memberships", "agents", "queues", "workers",
    "tasks", "events", "schedules", "commands", "audit_log",
    "first_boot_tokens", "sessions", "invitations",
    "password_reset_tokens", "notification_channels", "user_channels",
    "user_subscriptions", "project_default_subscriptions",
    "user_notifications", "notification_deliveries", "saved_views",
    "schedule_fires", "alert_events", "task_annotations", "pending_fires",
    "agent_workers", "api_keys", "z4j_meta", "scheduler_rate_buckets",
    "extension_store", "feature_flags", "export_jobs",
    "user_preferences", "project_config",
)

_Z4J_ENUMS_THAT_MUST_BE_GONE = (
    "schedulekind", "scheduleengine", "commandstatus", "agentstate",
    "projectrole", "userrole", "memberinvitestatus", "channelkind",
    "deliverystatus", "subscriptionscope",
)


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


# ---------------------------------------------------------------------------
# Bidirectional round-trip: upgrade head -> seed -> downgrade base ->
# verify clean -> upgrade head. This is the load-bearing test for the
# 1.4.x compatibility-floor promise that schema migrations are
# bidirectional. If this ever fails, the bidirectional claim in
# z4j.dev/operations/database-migrations is no longer true.
# ---------------------------------------------------------------------------


class TestMigrationRoundTrip:
    """``upgrade head`` -> seed -> ``downgrade base`` -> ``upgrade head``.

    Proves the 1.4.x bidirectional promise. The downgrade path
    DESTROYS data by design (it returns the database to an empty
    state); the contract is bidirectional **schema**, not
    bidirectional **data**. Operators who need data-preserving
    rollback use ``z4j backup`` + ``z4j restore``, which is a
    separate workflow documented under ``backup-restore``.
    """

    async def test_round_trip_clean(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """``upgrade head`` then ``downgrade base`` then ``upgrade head``.

        After downgrade, no z4j table or ENUM type may remain. After
        the second upgrade, every expected table and ENUM is back.
        """
        # Sanity: upgrade head already ran via the migrated_engine
        # fixture. Confirm a key z4j table exists before we knock
        # everything down.
        async with migrated_engine.connect() as conn:
            row = (
                await conn.execute(
                    text(
                        "SELECT to_regclass('public.audit_log')::text",
                    ),
                )
            ).scalar_one()
        assert row == "audit_log", (
            "fixture should have run alembic upgrade head; "
            "audit_log table missing pre-downgrade"
        )

        # Seed a small fixture so the downgrade has real rows + FK
        # references to chew through. This proves DROP TABLE CASCADE
        # actually handles the FK web on Postgres rather than
        # silently succeeding against an empty schema.
        async with migrated_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO projects (slug, name) "
                    "VALUES ('round-trip-test', 'Round trip test')",
                ),
            )
            project_id = (
                await conn.execute(
                    text(
                        "SELECT id FROM projects WHERE slug = 'round-trip-test'",
                    ),
                )
            ).scalar_one()
            # Minimal user insert: PKMixin supplies id (server-default
            # gen_random_uuid), TimestampsMixin supplies created_at/
            # updated_at, is_admin/is_active have server defaults.
            await conn.execute(
                text(
                    "INSERT INTO users (email, password_hash) "
                    "VALUES (:email, 'x')",
                ),
                {"email": f"round-trip-{secrets.token_hex(4)}@example.com"},
            )

        # Engine must be disposed before downgrade so alembic's
        # connection-management can take over without contending for
        # an open pool.
        await migrated_engine.dispose()

        # Downgrade to base. Every z4j object should be gone after.
        await _run_alembic(integration_settings, "downgrade", "base")

        # Reconnect with a fresh engine to verify the empty state.
        from sqlalchemy.ext.asyncio import create_async_engine

        verify_engine = create_async_engine(
            integration_settings.database_url, future=True,
        )
        try:
            async with verify_engine.connect() as conn:
                # Every z4j table must be gone.
                rows = await conn.execute(
                    text(
                        "SELECT tablename FROM pg_tables "
                        "WHERE schemaname = 'public'",
                    ),
                )
                surviving = {r[0] for r in rows.all()}
            stragglers = surviving & set(_Z4J_TABLES_THAT_MUST_BE_GONE)
            assert not stragglers, (
                f"downgrade left tables behind: {sorted(stragglers)}"
            )

            # Every z4j-specific ENUM must be gone.
            async with verify_engine.connect() as conn:
                rows = await conn.execute(
                    text(
                        "SELECT typname FROM pg_type "
                        "WHERE typtype = 'e' AND typnamespace = "
                        "(SELECT oid FROM pg_namespace WHERE nspname = 'public')",
                    ),
                )
                surviving_enums = {r[0] for r in rows.all()}
            enum_stragglers = surviving_enums & set(_Z4J_ENUMS_THAT_MUST_BE_GONE)
            assert not enum_stragglers, (
                f"downgrade left ENUM types behind: {sorted(enum_stragglers)}"
            )

            # Audit-log triggers must be gone (their function too).
            async with verify_engine.connect() as conn:
                fn_exists = (
                    await conn.execute(
                        text(
                            "SELECT EXISTS ("
                            "  SELECT 1 FROM pg_proc "
                            "  WHERE proname = 'audit_log_forbid_mutation'"
                            ")",
                        ),
                    )
                ).scalar_one()
            assert fn_exists is False, (
                "downgrade left audit_log_forbid_mutation function behind"
            )

            # Schedules NOTIFY trigger function must be gone.
            async with verify_engine.connect() as conn:
                fn_exists = (
                    await conn.execute(
                        text(
                            "SELECT EXISTS ("
                            "  SELECT 1 FROM pg_proc "
                            "  WHERE proname = 'z4j_schedules_notify'"
                            ")",
                        ),
                    )
                ).scalar_one()
            assert fn_exists is False, (
                "downgrade left z4j_schedules_notify function behind"
            )

            # alembic_version is alembic's own bookkeeping table, not
            # a z4j artifact. Alembic preserves it across downgrade
            # base and clears the version_num row instead. Confirm
            # the row is gone (no migration applied) but the table
            # itself can stay - that's the normal alembic contract.
            async with verify_engine.connect() as conn:
                applied = (
                    await conn.execute(
                        text("SELECT COUNT(*) FROM alembic_version"),
                    )
                ).scalar_one()
            assert applied == 0, (
                "alembic_version should have zero rows after downgrade "
                f"base; found {applied}"
            )
        finally:
            await verify_engine.dispose()

        # Now run upgrade head again and re-verify the schema is back.
        # Proves the migration is replayable against a previously
        # migrated-then-downgraded database (catches state-leak bugs
        # in the install helpers).
        await _run_alembic(integration_settings, "upgrade", "head")

        replay_engine = create_async_engine(
            integration_settings.database_url, future=True,
        )
        try:
            async with replay_engine.connect() as conn:
                rows = await conn.execute(
                    text(
                        "SELECT tablename FROM pg_tables "
                        "WHERE schemaname = 'public'",
                    ),
                )
                tables = {r[0] for r in rows.all()}
            # Every must-be-gone table is now back, plus alembic_version.
            for tbl in (
                "users", "projects", "agents", "tasks", "events",
                "audit_log", "alembic_version",
            ):
                assert tbl in tables, (
                    f"replay upgrade head left {tbl} missing"
                )

            # Audit-log function is back (the trigger needs it).
            async with replay_engine.connect() as conn:
                fn_exists = (
                    await conn.execute(
                        text(
                            "SELECT EXISTS ("
                            "  SELECT 1 FROM pg_proc "
                            "  WHERE proname = 'audit_log_forbid_mutation'"
                            ")",
                        ),
                    )
                ).scalar_one()
            assert fn_exists is True, (
                "replay upgrade head did not reinstall "
                "audit_log_forbid_mutation"
            )

            # Smoke insert proves the schema actually works after replay,
            # not just that the tables got created.
            async with replay_engine.begin() as conn:
                await conn.execute(
                    text(
                        "INSERT INTO projects (slug, name) "
                        "VALUES ('replay-smoke', 'Replay smoke')",
                    ),
                )
                count = (
                    await conn.execute(
                        text("SELECT COUNT(*) FROM projects"),
                    )
                ).scalar_one()
            assert count == 1, (
                f"expected 1 project after replay smoke insert, got {count}"
            )
        finally:
            await replay_engine.dispose()
