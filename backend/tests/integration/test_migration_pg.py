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
        os.environ["Z4J_SESSION_SECRET"] = settings.session_secret.get_secret_value()
        os.environ["Z4J_ENVIRONMENT"] = "dev"
        os.environ["Z4J_REQUIRE_DB_SSL"] = "false"
        runner = command.upgrade if action == "upgrade" else command.downgrade
        await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: runner(cfg, target),
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
    "invitations",
    "password_reset_tokens",
    "notification_channels",
    "user_channels",
    "user_subscriptions",
    "project_default_subscriptions",
    "user_notifications",
    "notification_deliveries",
    "saved_views",
    "schedule_fires",
    "alert_events",
    "task_annotations",
    "pending_fires",
    "agent_workers",
    "api_keys",
    "z4j_meta",
    "scheduler_rate_buckets",
    "extension_store",
    "feature_flags",
    "export_jobs",
    "user_preferences",
    "project_config",
    # 1.7 rule engine: dropped by the consolidated v1_7_schema.downgrade()
    # (its _down_automation_rules step) on the way down to base.
    "automation_rules",
    # 1.7 automation firing outbox: dropped by v1_7_schema.downgrade()
    # (its _down_automation_firing_outbox step) on the way to base.
    "automation_firing_outbox",
    # 1.7 durable misfire dedup: dropped by v1_7_schema.downgrade()
    # (its _down_misfire_alerts step).
    "misfire_alerts",
)

# The seven native enum types the baseline actually creates. The old
# list used stale 1.0-era names that were never created, so the
# downgrade assertion below passed VACUOUSLY (empty intersection) and
# could not catch the real types being orphaned -- which they were,
# until the migration's _SQL_ENUM_NAMES was corrected to match these.
_Z4J_ENUMS_THAT_MUST_BE_GONE = (
    "agent_state",
    "command_status",
    "project_role",
    "schedule_kind",
    "task_priority",
    "task_state",
    "worker_state",
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
            "task_priority",
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
        self,
        migrated_engine: AsyncEngine,
    ) -> None:
        """Partial indexes that SQLite cannot represent."""
        async with migrated_engine.connect() as conn:
            rows = await conn.execute(
                text(
                    "SELECT indexname FROM pg_indexes WHERE schemaname = 'public'",
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
        self,
        migrated_engine: AsyncEngine,
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

    async def test_schedule_fires_is_partitioned(
        self,
        migrated_engine: AsyncEngine,
    ) -> None:
        """A5: schedule_fires is RANGE-partitioned by scheduled_for, with the
        DEFAULT partition, at least one daily, and the composite PK + unique
        Postgres requires for the partition key."""
        async with migrated_engine.connect() as conn:
            relkind = (
                await conn.execute(
                    text(
                        "SELECT relkind::text FROM pg_class "
                        "WHERE relname = 'schedule_fires' AND relnamespace = "
                        "(SELECT oid FROM pg_namespace WHERE nspname = 'public')",
                    ),
                )
            ).scalar_one()
            assert relkind == "p"

            parts = {
                r[0]
                for r in (
                    await conn.execute(
                        text(
                            "SELECT tablename FROM pg_tables WHERE schemaname='public' "
                            "AND tablename LIKE 'schedule_fires\\_%'",
                        ),
                    )
                ).all()
            }
            assert "schedule_fires_default" in parts
            assert any(p[:16].startswith("schedule_fires_2") for p in parts), (
                "expected at least one daily schedule_fires partition"
            )

            uq = (
                await conn.execute(
                    text(
                        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                        "WHERE conname = 'uq_schedule_fires_fire_id' "
                        "AND conrelid = 'schedule_fires'::regclass",
                    ),
                )
            ).scalar_one()
            assert "(fire_id, scheduled_for)" in uq
            pk = (
                await conn.execute(
                    text(
                        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                        "WHERE conname = 'pk_schedule_fires' "
                        "AND conrelid = 'schedule_fires'::regclass",
                    ),
                )
            ).scalar_one()
            assert "(id, scheduled_for)" in pk

    async def test_schedule_fires_partition_worker_drops_expired(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """The partition worker drops a daily partition older than retention
        (MAX-bounded: an empty old partition is safe to drop)."""
        from z4j_brain.domain.workers.schedule_fires_partition import (
            ScheduleFiresPartitionWorker,
        )
        from z4j_brain.persistence.database import DatabaseManager

        async with migrated_engine.begin() as conn:
            await conn.execute(
                text(
                    "CREATE TABLE IF NOT EXISTS schedule_fires_2019_01_02 "
                    "PARTITION OF schedule_fires "
                    "FOR VALUES FROM ('2019-01-02') TO ('2019-01-03')",
                ),
            )
        worker = ScheduleFiresPartitionWorker(
            db=DatabaseManager(migrated_engine),
            settings=integration_settings,
        )
        await worker.tick()
        async with migrated_engine.connect() as conn:
            still = (
                await conn.execute(
                    text("SELECT to_regclass('public.schedule_fires_2019_01_02')"),
                )
            ).scalar()
        assert still is None  # dropped by DROP-PARTITION retention

    async def test_audit_log_triggers_present(
        self,
        migrated_engine: AsyncEngine,
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
        self,
        migrated_engine: AsyncEngine,
    ) -> None:
        """The CHECK regex on projects.slug must reject bad input."""
        async with migrated_engine.begin() as conn:
            try:
                await conn.execute(
                    text(
                        "INSERT INTO projects (slug, name) VALUES ('BAD_UPPER', 'X')",
                    ),
                )
                bad_accepted = True
            except Exception:
                bad_accepted = False
        assert bad_accepted is False

        async with migrated_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO projects (slug, name) VALUES ('valid-slug', 'X')",
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
            "fixture should have run alembic upgrade head; audit_log table missing pre-downgrade"
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
            _project_id = (
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
                    "INSERT INTO users (email, password_hash) VALUES (:email, 'x')",
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
            integration_settings.database_url,
            future=True,
        )
        try:
            async with verify_engine.connect() as conn:
                # Every z4j table must be gone.
                rows = await conn.execute(
                    text(
                        "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
                    ),
                )
                surviving = {r[0] for r in rows.all()}
            stragglers = surviving & set(_Z4J_TABLES_THAT_MUST_BE_GONE)
            assert not stragglers, f"downgrade left tables behind: {sorted(stragglers)}"

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
            assert fn_exists is False, "downgrade left audit_log_forbid_mutation function behind"

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
            assert fn_exists is False, "downgrade left z4j_schedules_notify function behind"

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
                f"alembic_version should have zero rows after downgrade base; found {applied}"
            )
        finally:
            await verify_engine.dispose()

        # Now run upgrade head again and re-verify the schema is back.
        # Proves the migration is replayable against a previously
        # migrated-then-downgraded database (catches state-leak bugs
        # in the install helpers).
        await _run_alembic(integration_settings, "upgrade", "head")

        replay_engine = create_async_engine(
            integration_settings.database_url,
            future=True,
        )
        try:
            async with replay_engine.connect() as conn:
                rows = await conn.execute(
                    text(
                        "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
                    ),
                )
                tables = {r[0] for r in rows.all()}
            # Every must-be-gone table is now back, plus alembic_version.
            for tbl in (
                "users",
                "projects",
                "agents",
                "tasks",
                "events",
                "audit_log",
                "alembic_version",
            ):
                assert tbl in tables, f"replay upgrade head left {tbl} missing"

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
                "replay upgrade head did not reinstall audit_log_forbid_mutation"
            )

            # Smoke insert proves the schema actually works after replay,
            # not just that the tables got created.
            async with replay_engine.begin() as conn:
                await conn.execute(
                    text(
                        "INSERT INTO projects (slug, name) VALUES ('replay-smoke', 'Replay smoke')",
                    ),
                )
                count = (
                    await conn.execute(
                        text("SELECT COUNT(*) FROM projects"),
                    )
                ).scalar_one()
            assert count == 1, f"expected 1 project after replay smoke insert, got {count}"
        finally:
            await replay_engine.dispose()

    async def test_kill_switch_column_round_trip(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """The 1.7 kill-switch change is bidirectional at the COLUMN level:
        ``projects.automation_enabled`` drops when the consolidated
        ``v1_7_schema`` migration is downgraded to the v1_6_6 floor (the
        whole 1.7 delta, which includes the kill-switch column) and returns
        on re-upgrade.

        Complements the full base round-trip above by exercising the
        ADD/DROP COLUMN path specifically (a column drop is a different
        Postgres code path from a table drop). The thirteen dev-time 1.7
        migrations are now one atomic revision, so the only downgrade
        boundary below the kill-switch column is the v1_6_6 floor.
        """
        from sqlalchemy.ext.asyncio import create_async_engine

        async def _column_exists() -> bool:
            eng = create_async_engine(
                integration_settings.database_url,
                future=True,
            )
            try:
                async with eng.connect() as conn:
                    return bool(
                        (
                            await conn.execute(
                                text(
                                    "SELECT EXISTS (SELECT 1 FROM "
                                    "information_schema.columns WHERE "
                                    "table_name = 'projects' AND "
                                    "column_name = 'automation_enabled')",
                                ),
                            )
                        ).scalar_one()
                    )
            finally:
                await eng.dispose()

        # The fixture already upgraded to head, which includes the column.
        await migrated_engine.dispose()
        assert await _column_exists() is True

        # Downgrade the whole 1.7 delta to the v1_6_6 floor: the
        # kill-switch column is dropped along with the rest of the delta.
        await _run_alembic(
            integration_settings,
            "downgrade",
            "v1_6_6_scrub_worker_conf",
        )
        assert await _column_exists() is False

        # Re-upgrade restores it (idempotent add-column guard).
        await _run_alembic(integration_settings, "upgrade", "head")
        assert await _column_exists() is True

    async def test_schedule_fires_partition_data_round_trip(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """Populated-DB round-trip across the consolidated ``v1_7_schema``.

        The consolidated migration's partition step recreates
        ``schedule_fires`` as a RANGE-partitioned table and copies every
        row across with an explicit column list (upgrade), then copies
        back into the plain table (downgrade). The structural tests above
        prove the SHAPE survives; this test proves REAL rows survive both
        copies with identical values.

        The thirteen dev-time 1.7 migrations are now one atomic revision,
        so the only downgrade boundary below the partition step is the
        v1_6_6 floor. At that floor ``schedule_fires`` is the plain
        (id)-PK table WITHOUT ``triggered_by_user_id`` -- that column is
        added by the same consolidated migration, so we seed the twelve
        floor columns and let the migration backfill the new column NULL
        as it partitions:

        1. downgrade the whole 1.7 delta to the v1_6_6 floor (plain
           schedule_fires, no ``triggered_by_user_id``),
        2. seed a project + user + schedule + fires whose
           ``scheduled_for`` spans a recent daily partition, a future
           daily, and a row old enough that it can ONLY land in the
           DEFAULT partition,
        3. upgrade head (runs the recreate-and-copy) and assert every
           seeded column of every row survived, the new
           ``triggered_by_user_id`` column is present and backfilled
           NULL, and each row landed in the expected partition,
        4. downgrade to the v1_6_6 floor again (copy-back) and assert the
           plain table holds the same rows.
        """
        import uuid
        from datetime import UTC, datetime, timedelta

        from sqlalchemy.ext.asyncio import create_async_engine

        # The twelve schedule_fires columns present at the v1_6_6 floor
        # (the migration's _COLUMNS copy list MINUS triggered_by_user_id,
        # which the same consolidated migration adds). snapshot() selects
        # exactly these so it works against both the plain floor table and
        # the partitioned head table.
        fire_columns = (
            "id",
            "fire_id",
            "schedule_id",
            "project_id",
            "command_id",
            "status",
            "scheduled_for",
            "fired_at",
            "acked_at",
            "latency_ms",
            "error_code",
            "error_message",
        )
        col_list = ", ".join(fire_columns)

        project_id = uuid.uuid4()
        user_id = uuid.uuid4()
        schedule_id = uuid.uuid4()
        now = datetime.now(UTC)

        # scheduled_for spread: the upgrade pre-creates daily
        # partitions for CURRENT_DATE-31 .. CURRENT_DATE+7 only, so
        # the 400-day-old row can only land in the DEFAULT partition
        # while the recent/future rows land in droppable dailies.
        fires: list[dict] = [
            {
                "id": uuid.uuid4(),
                "fire_id": uuid.uuid4(),
                "status": "delivered",
                "scheduled_for": now,
                "fired_at": now + timedelta(milliseconds=250),
                "acked_at": now + timedelta(seconds=1),
                "latency_ms": 42,
                "error_code": None,
                "error_message": None,
            },
            {
                "id": uuid.uuid4(),
                "fire_id": uuid.uuid4(),
                "status": "failed",
                "scheduled_for": now - timedelta(days=3),
                "fired_at": now - timedelta(days=3) + timedelta(seconds=2),
                "acked_at": None,
                "latency_ms": None,
                "error_code": "dispatch_timeout",
                "error_message": "agent did not ack within deadline",
            },
            {
                # Older than the pre-created daily window: DEFAULT
                # partition is the only possible landing spot.
                "id": uuid.uuid4(),
                "fire_id": uuid.uuid4(),
                "status": "acked_success",
                "scheduled_for": now - timedelta(days=400),
                "fired_at": now - timedelta(days=400, milliseconds=-5),
                "acked_at": now - timedelta(days=400, seconds=-3),
                "latency_ms": 3120,
                "error_code": None,
                "error_message": None,
            },
            {
                "id": uuid.uuid4(),
                "fire_id": uuid.uuid4(),
                "status": "buffered",
                "scheduled_for": now + timedelta(days=3),
                "fired_at": now,
                "acked_at": None,
                "latency_ms": None,
                "error_code": None,
                "error_message": None,
            },
        ]
        default_partition_fire_id = fires[2]["id"]

        def expected_row(fire: dict) -> tuple:
            """The seeded column tuple a survived row must equal (the twelve
            floor columns, in ``fire_columns`` order)."""
            return (
                fire["id"],
                fire["fire_id"],
                schedule_id,
                project_id,
                None,  # command_id stays NULL throughout
                fire["status"],
                fire["scheduled_for"],
                fire["fired_at"],
                fire["acked_at"],
                fire["latency_ms"],
                fire["error_code"],
                fire["error_message"],
            )

        async def snapshot() -> tuple[str, dict, dict]:
            """(relkind, rows-by-id, partition-placement-by-id)."""
            eng = create_async_engine(
                integration_settings.database_url,
                future=True,
            )
            try:
                async with eng.connect() as conn:
                    kind = (
                        await conn.execute(
                            text(
                                "SELECT relkind::text FROM pg_class "
                                "WHERE relname = 'schedule_fires' AND relnamespace = "
                                "(SELECT oid FROM pg_namespace WHERE nspname = 'public')",
                            ),
                        )
                    ).scalar_one()
                    rows = (
                        await conn.execute(
                            text(f"SELECT {col_list} FROM schedule_fires"),
                        )
                    ).all()
                    placement = (
                        await conn.execute(
                            text(
                                "SELECT id, tableoid::regclass::text FROM schedule_fires",
                            ),
                        )
                    ).all()
                return (
                    kind,
                    {row[0]: tuple(row) for row in rows},
                    {row[0]: row[1] for row in placement},
                )
            finally:
                await eng.dispose()

        # The fixture upgraded to head. Downgrade the whole 1.7 delta to
        # the v1_6_6 floor so schedule_fires is the plain (id)-PK table
        # without triggered_by_user_id (the only boundary below the
        # partition step now that the 1.7 chain is one revision).
        await migrated_engine.dispose()
        await _run_alembic(
            integration_settings,
            "downgrade",
            "v1_6_6_scrub_worker_conf",
        )

        seed_engine = create_async_engine(
            integration_settings.database_url,
            future=True,
        )
        try:
            async with seed_engine.begin() as conn:
                await conn.execute(
                    text(
                        "INSERT INTO projects (id, slug, name) "
                        "VALUES (:id, 'fires-round-trip', 'Fires round trip')",
                    ),
                    {"id": project_id},
                )
                await conn.execute(
                    text(
                        "INSERT INTO users (id, email, password_hash) VALUES (:id, :email, 'x')",
                    ),
                    {
                        "id": user_id,
                        "email": f"fires-rt-{secrets.token_hex(4)}@example.com",
                    },
                )
                await conn.execute(
                    text(
                        "INSERT INTO schedules "
                        "(id, project_id, engine, scheduler, name, "
                        " task_name, kind, expression) "
                        "VALUES (:id, :project_id, 'celery', 'celery-beat', "
                        "'fires-round-trip', 'app.tasks.noop', 'cron', "
                        "'*/5 * * * *')",
                    ),
                    {"id": schedule_id, "project_id": project_id},
                )
                for fire in fires:
                    await conn.execute(
                        text(
                            f"INSERT INTO schedule_fires ({col_list}) VALUES "
                            "(:id, :fire_id, :schedule_id, :project_id, NULL, "
                            ":status, :scheduled_for, :fired_at, :acked_at, "
                            ":latency_ms, :error_code, :error_message)",
                        ),
                        {
                            **fire,
                            "schedule_id": schedule_id,
                            "project_id": project_id,
                        },
                    )
        finally:
            await seed_engine.dispose()

        pre_kind, pre_rows, _ = await snapshot()
        assert pre_kind == "r", "expected the plain table below the partition migration"
        assert len(pre_rows) == len(fires)

        # Upgrade THROUGH the partition migration: recreate-and-copy.
        await _run_alembic(integration_settings, "upgrade", "head")

        part_kind, part_rows, placement = await snapshot()
        assert part_kind == "p", "upgrade should have partitioned schedule_fires"
        assert len(part_rows) == len(fires), (
            f"partition copy lost rows: expected {len(fires)}, got {len(part_rows)}"
        )
        for fire in fires:
            assert part_rows[fire["id"]] == expected_row(fire), (
                f"fire {fire['id']} changed across the partition copy"
            )
        assert placement[default_partition_fire_id] == "schedule_fires_default", (
            "the 400-day-old fire should land in the DEFAULT partition"
        )
        for fire in fires:
            if fire["id"] == default_partition_fire_id:
                continue
            assert placement[fire["id"]].startswith("schedule_fires_2"), (
                f"fire {fire['id']} expected in a daily partition, found in {placement[fire['id']]}"
            )

        # The consolidated migration also ADDED triggered_by_user_id as
        # part of the same upgrade: it must exist on the partitioned table
        # and be backfilled NULL for every copied row.
        add_col_engine = create_async_engine(
            integration_settings.database_url,
            future=True,
        )
        try:
            async with add_col_engine.connect() as conn:
                nulls = (
                    await conn.execute(
                        text(
                            "SELECT count(*) FROM schedule_fires "
                            "WHERE triggered_by_user_id IS NOT NULL",
                        ),
                    )
                ).scalar_one()
            assert nulls == 0, (
                "upgrade should backfill triggered_by_user_id NULL on every copied row"
            )
        finally:
            await add_col_engine.dispose()

        # Downgrade the whole 1.7 delta to the v1_6_6 floor: the copy-back
        # into the plain table must preserve the rows too.
        await _run_alembic(
            integration_settings,
            "downgrade",
            "v1_6_6_scrub_worker_conf",
        )

        post_kind, post_rows, post_placement = await snapshot()
        assert post_kind == "r", "downgrade should restore the plain table"
        assert len(post_rows) == len(fires), (
            f"downgrade copy-back lost rows: expected {len(fires)}, got {len(post_rows)}"
        )
        for fire in fires:
            assert post_rows[fire["id"]] == expected_row(fire), (
                f"fire {fire['id']} changed across the downgrade copy-back"
            )
        # No partitions remain; every row lives in the plain table.
        assert set(post_placement.values()) == {"schedule_fires"}

        # Re-upgrade to head with the table POPULATED: the partition
        # migration must also apply cleanly on the way back up (this
        # is the 1.6 -> 1.7 upgrade path operators actually take).
        await _run_alembic(integration_settings, "upgrade", "head")
        final_kind, final_rows, _ = await snapshot()
        assert final_kind == "p"
        assert len(final_rows) == len(fires)

    async def test_upgrade_head_twice_is_idempotent(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """``alembic upgrade head`` a second time is a clean no-op.

        The ``migrated_engine`` fixture already ran ``upgrade head`` once.
        Running it again must exit cleanly and leave the schema
        byte-identical (same tables + enum types). Catches a migration
        that fails to stamp its version -- and would thus re-execute its
        DDL on every boot -- or that is unsafe to re-apply against an
        already-migrated database. The events partitions must not
        multiply either (the partition-creator path is idempotent).
        """
        from sqlalchemy.ext.asyncio import create_async_engine

        async def _snapshot() -> tuple[frozenset[str], frozenset[str]]:
            eng = create_async_engine(
                integration_settings.database_url,
                future=True,
            )
            try:
                async with eng.connect() as conn:
                    tables = {
                        r[0]
                        for r in (
                            await conn.execute(
                                text(
                                    "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
                                ),
                            )
                        ).all()
                    }
                    enums = {
                        r[0]
                        for r in (
                            await conn.execute(
                                text(
                                    "SELECT typname FROM pg_type "
                                    "WHERE typtype = 'e' AND typnamespace = "
                                    "(SELECT oid FROM pg_namespace WHERE "
                                    "nspname = 'public')",
                                ),
                            )
                        ).all()
                    }
                    return frozenset(tables), frozenset(enums)
            finally:
                await eng.dispose()

        # The fixture already upgraded to head.
        await migrated_engine.dispose()
        before = await _snapshot()
        assert any(t.startswith("events_20") for t in before[0])

        # Second upgrade head: must be a clean no-op.
        await _run_alembic(integration_settings, "upgrade", "head")
        after = await _snapshot()

        assert after == before, (
            "second `alembic upgrade head` changed the schema "
            f"(added tables: {sorted(after[0] - before[0])}; "
            f"added enums: {sorted(after[1] - before[1])}) -- a migration "
            "is re-executing DDL instead of no-opping at head"
        )
