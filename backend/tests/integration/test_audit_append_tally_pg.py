"""Exact append accounting must survive rollback and refuse unmaintained state."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID

import pytest
from sqlalchemy import event, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from z4j_brain.domain.audit_chain import AuditChainIntegrityError
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.audit_verifier import verify_active_audit_generation
from z4j_brain.management_reset import build_generation_reset_preview
from z4j_brain.management_restore import authenticated_database_snapshot
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import AuditChainState
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.settings import Settings

pytestmark = pytest.mark.asyncio


async def _record(session: AsyncSession, settings: Settings) -> None:
    await AuditService(settings).record(
        AuditLogRepository(session),
        action="tally.test",
        target_type="test",
    )


async def _counts(session: AsyncSession) -> tuple[int, int, int]:
    return tuple(
        (
            await session.execute(
                text(
                    "SELECT active_row_count, observed_active_row_count, "
                    "(SELECT count(*) FROM audit_log WHERE legacy_frozen IS FALSE) "
                    "FROM audit_chain_state",
                )
            )
        ).one()
    )


async def test_append_uses_constant_size_accounting_and_full_verifier_recounts(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    statements: list[str] = []

    def capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(" ".join(statement.lower().split()))

    event.listen(migrated_engine.sync_engine, "before_cursor_execute", capture)
    try:
        async with AsyncSession(migrated_engine) as session:
            await _record(session, integration_settings)
            assert any("count(*)" in sql and "from audit_log" in sql for sql in statements)
            statements.clear()
            for _ in range(4):
                await _record(session, integration_settings)
            await session.commit()
            append_statements = list(statements)
            assert await _counts(session) == (7, 7, 7)
        assert any("observed_active_row_count" in sql for sql in append_statements)
        assert not any("count(*)" in sql and "from audit_log" in sql for sql in append_statements)
        statements.clear()
        async with AsyncSession(migrated_engine) as session:
            report = await verify_active_audit_generation(
                session, integration_settings, page_size=2
            )
        assert report.clean
        assert report.verified_active_rows == 7
        assert any("count(*)" in sql and "from audit_log" in sql for sql in statements)
    finally:
        event.remove(migrated_engine.sync_engine, "before_cursor_execute", capture)


async def test_tally_and_signed_head_rollback_together(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    async with AsyncSession(migrated_engine) as session:
        initial_mac = await session.scalar(select(AuditChainState.state_mac))
        await _record(session, integration_settings)
        assert await _counts(session) == (3, 3, 3)
        await session.rollback()
        assert await _counts(session) == (2, 2, 2)
        assert await session.scalar(select(AuditChainState.state_mac)) == initial_mac
        await _record(session, integration_settings)
        nested = await session.begin_nested()
        await _record(session, integration_settings)
        assert await _counts(session) == (4, 4, 4)
        await nested.rollback()
        assert await _counts(session) == (3, 3, 3)
        await _record(session, integration_settings)
        await session.commit()
    async with AsyncSession(migrated_engine) as session:
        assert await _counts(session) == (4, 4, 4)
        assert (
            await verify_active_audit_generation(session, integration_settings, page_size=2)
        ).clean


async def test_concurrent_appends_preserve_exact_tally(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    async def append() -> None:
        async with AsyncSession(migrated_engine) as session:
            for _ in range(3):
                await _record(session, integration_settings)
            await session.commit()

    await asyncio.wait_for(asyncio.gather(*(append() for _ in range(8))), timeout=15)
    async with AsyncSession(migrated_engine) as session:
        assert await _counts(session) == (26, 26, 26)
        assert (
            await verify_active_audit_generation(session, integration_settings, page_size=3)
        ).clean


@pytest.mark.parametrize("replica", [False, True])
async def test_direct_tally_forgery_is_refused_even_with_transition_guc(
    migrated_engine: AsyncEngine,
    replica: bool,
) -> None:
    async with migrated_engine.connect() as conn:
        await conn.execute(text("SET LOCAL z4j.audit_transition = 'append-v1'"))
        if replica:
            await conn.execute(text("SET LOCAL session_replication_role = replica"))
        with pytest.raises(DBAPIError, match="tally is maintained"):
            await conn.execute(
                text(
                    "UPDATE audit_chain_state SET observed_active_row_count = active_row_count + 1",
                )
            )
        await conn.rollback()


@pytest.mark.parametrize("replica", [False, True])
async def test_unsigned_row_deletion_changes_tally_and_refuses_append(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    replica: bool,
) -> None:
    async with migrated_engine.begin() as conn:
        await conn.execute(text("SET LOCAL z4j.audit_transition = 'retention-v1'"))
        if replica:
            await conn.execute(text("SET LOCAL session_replication_role = replica"))
        await conn.execute(
            text(
                "DELETE FROM audit_log WHERE action = 'audit.chain_generation_started'",
            )
        )
    async with AsyncSession(migrated_engine) as session:
        assert await _counts(session) == (2, 1, 1)
        with pytest.raises(AuditChainIntegrityError, match="count does not match"):
            await _record(session, integration_settings)
    async with AsyncSession(migrated_engine) as session:
        assert not (
            await verify_active_audit_generation(session, integration_settings, page_size=2)
        ).clean


@pytest.mark.parametrize(
    "trigger, table",
    [
        ("audit_log_tally_rows", "audit_log"),
        ("audit_log_tally_truncate", "audit_log"),
        ("audit_chain_state_protect_tally", "audit_chain_state"),
    ],
)
@pytest.mark.parametrize("mode", ["DISABLE", "ENABLE"])
async def test_append_refuses_disabled_or_replica_bypassable_guards(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    trigger: str,
    table: str,
    mode: str,
) -> None:
    async with migrated_engine.begin() as conn:
        await conn.execute(text(f"ALTER TABLE {table} {mode} TRIGGER {trigger}"))
    async with AsyncSession(migrated_engine) as session:
        with pytest.raises(AuditChainIntegrityError, match="maintenance guards"):
            await _record(session, integration_settings)
    async with AsyncSession(migrated_engine) as session:
        assert not (
            await verify_active_audit_generation(session, integration_settings, page_size=2)
        ).clean
        assert await _counts(session) == (2, 2, 2)


async def test_full_verifier_detects_tally_tampered_through_owner_ddl(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    # The table owner can change DDL. Full verification must still count rows
    # independently even if the owner restores the maintenance trigger later.
    async with migrated_engine.begin() as conn:
        await conn.execute(text("SET LOCAL z4j.audit_transition = 'append-v1'"))
        await conn.execute(
            text("ALTER TABLE audit_chain_state DISABLE TRIGGER audit_chain_state_protect_tally")
        )
        await conn.execute(text("UPDATE audit_chain_state SET observed_active_row_count = 3"))
        await conn.execute(
            text(
                "ALTER TABLE audit_chain_state ENABLE ALWAYS TRIGGER audit_chain_state_protect_tally"
            )
        )
    async with AsyncSession(migrated_engine) as session:
        report = await verify_active_audit_generation(session, integration_settings, page_size=2)
        assert not report.clean
        assert any(
            "maintained audit row count does not match physical rows" in value
            for value in report.mismatches
        )


async def test_append_recounts_after_owner_disables_and_reenables_maintenance(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    async with AsyncSession(migrated_engine) as session:
        await _record(session, integration_settings)
        await session.commit()
    async with migrated_engine.begin() as conn:
        await conn.execute(text("SET LOCAL z4j.audit_transition = 'retention-v1'"))
        await conn.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_tally_rows"))
        await conn.execute(
            text("DELETE FROM audit_log WHERE action = 'audit.chain_generation_started'")
        )
        await conn.execute(text("ALTER TABLE audit_log ENABLE ALWAYS TRIGGER audit_log_tally_rows"))
    async with AsyncSession(migrated_engine) as session:
        assert await _counts(session) == (3, 3, 2)
        with pytest.raises(AuditChainIntegrityError, match="does not match physical"):
            await _record(session, integration_settings)


async def test_replica_mode_cannot_silently_move_active_rows_to_other_generation(
    migrated_engine: AsyncEngine,
) -> None:
    async with migrated_engine.connect() as conn:
        await conn.execute(text("SET LOCAL session_replication_role = replica"))
        with pytest.raises(DBAPIError, match="cannot change generation"):
            await conn.execute(
                text(
                    "UPDATE audit_log SET chain_generation = gen_random_uuid() WHERE action = 'audit.chain_generation_started'"
                )
            )
        await conn.rollback()


@pytest.mark.parametrize("replace_existing_function", [False, True])
async def test_catalog_change_cannot_hide_nested_trigger_tally_forgery(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    replace_existing_function: bool,
) -> None:
    async with migrated_engine.begin() as conn:
        await conn.execute(text("CREATE SCHEMA tally_attack"))
        await conn.execute(text("CREATE TABLE tally_attack.input (delta integer)"))
        await conn.execute(
            text(
                "CREATE FUNCTION tally_attack.f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$"
            )
        )
        if replace_existing_function:
            await conn.execute(
                text(
                    "CREATE TRIGGER attack BEFORE INSERT ON tally_attack.input FOR EACH ROW EXECUTE FUNCTION tally_attack.f()"
                )
            )
    async with AsyncSession(migrated_engine) as session:
        await _record(session, integration_settings)
        await session.commit()
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "CREATE OR REPLACE FUNCTION tally_attack.f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE public.audit_chain_state SET observed_active_row_count = observed_active_row_count + NEW.delta; RETURN NEW; END $$"
            )
        )
        if not replace_existing_function:
            await conn.execute(
                text(
                    "CREATE TRIGGER attack BEFORE INSERT ON tally_attack.input FOR EACH ROW EXECUTE FUNCTION tally_attack.f()"
                )
            )
        await conn.execute(text("SET LOCAL z4j.audit_transition = 'retention-v1'"))
        await conn.execute(
            text("DELETE FROM audit_log WHERE action = 'audit.chain_generation_started'")
        )
        # pg_trigger_depth alone cannot distinguish this owner-created trigger
        # from genuine maintenance. The process-local catalog baseline must.
        await conn.execute(text("INSERT INTO tally_attack.input VALUES (1)"))
    async with AsyncSession(migrated_engine) as session:
        assert await _counts(session) == (3, 3, 2)
        with pytest.raises(AuditChainIntegrityError, match="does not match physical"):
            await _record(session, integration_settings)


async def test_tally_migration_round_trip_preserves_signed_authority(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    from tests.integration.test_migration_pg import _run_alembic

    async with AsyncSession(migrated_engine) as session:
        await _record(session, integration_settings)
        await session.commit()
        before = await session.scalar(select(AuditChainState.state_mac))
    await _run_alembic(integration_settings, "downgrade", "v1_9_audit_action_pattern")
    await _run_alembic(integration_settings, "upgrade", "head")
    async with AsyncSession(migrated_engine) as session:
        assert await _counts(session) == (3, 3, 3)
        assert await session.scalar(select(AuditChainState.state_mac)) == before
        assert (
            await verify_active_audit_generation(session, integration_settings, page_size=2)
        ).clean


async def test_tally_round_trip_keeps_reset_and_restore_schema_contract(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    """A downgraded and re-upgraded installation stays resettable and restorable.

    PostgreSQL never reuses a dropped column's attnum, so the re-added tally
    column sits one physical slot later than on a clean install. Reset and
    every PostgreSQL restore phase authenticate the installation through the
    release schema contract, which has to bind live column order rather than
    the table's DDL history.
    """
    from tests.integration.test_migration_pg import _run_alembic

    tally_attnum = text(
        "SELECT attnum FROM pg_attribute "
        "WHERE attrelid = 'audit_chain_state'::regclass "
        "AND attname = 'observed_active_row_count' AND NOT attisdropped",
    )
    async with migrated_engine.connect() as conn:
        clean_attnum = await conn.scalar(tally_attnum)
    before = await authenticated_database_snapshot(
        integration_settings.database_url,
        integration_settings,
    )
    digest = before["schema_contract_digest"]

    await _run_alembic(integration_settings, "downgrade", "v1_9_audit_action_pattern")
    await _run_alembic(integration_settings, "upgrade", "head")

    async with migrated_engine.connect() as conn:
        # The dropped slot is real, so the contract below is computed over a
        # different physical layout rather than the clean one again.
        assert await conn.scalar(tally_attnum) > clean_attnum
    after = await authenticated_database_snapshot(
        integration_settings.database_url,
        integration_settings,
    )
    assert after["schema_contract_manifest"] == before["schema_contract_manifest"]
    assert after["schema_contract_digest"] == digest
    database = DatabaseManager(migrated_engine)
    async with database.session(write=True) as session:
        preview = await build_generation_reset_preview(session, integration_settings)
        await session.rollback()
    assert preview["destruction_manifest"]["schema_contract_digest"] == digest


@pytest.mark.parametrize(
    "conflicting_sql",
    [
        "CREATE TABLE ix_commands_schedule_fire_receipt (id integer)",
        "CREATE INDEX ix_commands_schedule_fire_receipt ON audit_log (id)",
        "CREATE INDEX ix_commands_schedule_fire_receipt ON commands (schedule_fire_id, schedule_id, schedule_receipt_control_token)",
        "CREATE UNIQUE INDEX ix_commands_schedule_fire_receipt ON commands (schedule_id, schedule_fire_id, schedule_receipt_control_token)",
        "CREATE INDEX ix_commands_schedule_fire_receipt ON commands (schedule_id, schedule_fire_id, schedule_receipt_control_token) WHERE action = 'schedule.fire'",
    ],
)
async def test_tally_upgrade_refuses_conflicting_receipt_index_without_schema_changes(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    conflicting_sql: str,
) -> None:
    from alembic.util import CommandError

    from tests.integration.test_migration_pg import _run_alembic

    await _run_alembic(integration_settings, "downgrade", "v1_9_audit_action_pattern")
    async with migrated_engine.begin() as conn:
        await conn.execute(text(conflicting_sql))
    with pytest.raises(CommandError, match="unexpected definition"):
        await _run_alembic(integration_settings, "upgrade", "head")
    async with migrated_engine.connect() as conn:
        assert (
            await conn.scalar(text("SELECT version_num FROM alembic_version"))
            == "v1_9_audit_action_pattern"
        )
        assert (
            await conn.scalar(
                text(
                    "SELECT count(*) FROM information_schema.columns WHERE table_name = 'audit_chain_state' AND column_name = 'observed_active_row_count'"
                )
            )
            == 0
        )


async def test_seek_paging_verifies_every_row_across_equal_timestamp_boundaries(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from z4j_brain.persistence.models import AuditLog

    fixed = datetime.now(UTC) + timedelta(days=1)

    class FrozenClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed

    ids = [UUID(int=i) for i in range(1, 10)]
    iterator = iter(ids)
    monkeypatch.setattr("z4j_brain.domain.audit_service.datetime", FrozenClock)
    monkeypatch.setattr(
        "z4j_brain.domain.audit_service.uuid",
        SimpleNamespace(uuid4=lambda: next(iterator), UUID=UUID),
    )
    async with AsyncSession(migrated_engine) as session:
        for _ in ids:
            await _record(session, integration_settings)
        await session.commit()
        assert list(
            await session.scalars(select(AuditLog.occurred_at).where(AuditLog.id.in_(ids)))
        ) == [fixed] * len(ids)
        report = await verify_active_audit_generation(session, integration_settings, page_size=3)
        assert report.clean
        assert report.verified_active_rows == 11
        repository = AuditLogRepository(session)
        seen = []
        cursor = {}
        while rows := await repository.stream_for_verify(chunk=3, **cursor):
            seen.extend(row.id for row in rows)
            cursor = {"after_occurred_at": rows[-1].occurred_at, "after_id": rows[-1].id}
        assert len(seen) == len(set(seen)) == 11
        assert seen[-9:] == ids
