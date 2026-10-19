"""Frozen export transactions and crash recovery on isolated real PostgreSQL databases."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from z4j_brain.configuration import configuration_snapshot_from_values
from z4j_brain.domain import audit_frozen_export as frozen
from z4j_brain.domain.audit_activation import build_activation_manifest
from z4j_brain.domain.audit_chain import AuditChainIntegrityError, authenticate_state
from z4j_brain.domain.audit_service import AuditEntry, AuditService
from z4j_brain.domain.audit_verifier import verify_active_audit_generation
from z4j_brain.persistence.models import AuditChainState, AuditLog

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def frozen_pg_install(integration_engine, integration_settings, tmp_path):
    """Seed through real legacy migration/activation, never bypassing live triggers.

    The shared integration fixtures give this test its own randomly named
    database, then drop only that exact database when this fixture finishes.
    """
    engine = integration_engine
    settings = integration_settings
    assert engine.dialect.name == "postgresql"
    assert engine.url.database.startswith("z4j_test_")
    backend_root = Path(__file__).resolve().parents[2]  # noqa: ASYNC240  isolated fixture setup
    cfg = Config(str(backend_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend_root / "src/z4j_brain/migrations"))
    cfg.attributes["z4j_configuration_snapshot"] = configuration_snapshot_from_values(
        {
            "Z4J_DATABASE_URL": settings.database_url,
            "Z4J_SECRET": settings.secret.get_secret_value(),
            "Z4J_SESSION_SECRET": settings.session_secret.get_secret_value(),
            "Z4J_AUDIT_CHAIN_SECRET": settings.audit_chain_secret.get_secret_value(),
            "Z4J_REQUIRE_DB_SSL": "false",
            "Z4J_ENVIRONMENT": "dev",
        },
        source="isolated-postgres-frozen-export-test",
    )
    await asyncio.to_thread(command.upgrade, cfg, "v1_8_bulk_retry_requests")
    row_id = uuid.uuid4()
    entry = AuditEntry(
        id=row_id,
        action="legacy.frozen-export-test",
        target_type="test",
        target_id=str(row_id),
        result="success",
        outcome="allow",
        event_id=None,
        user_id=None,
        project_id=None,
        source_ip=None,
        user_agent=None,
        metadata={"legacy": True},
        occurred_at=datetime(2026, 7, 1, 12, tzinfo=UTC),
        prev_row_hmac=None,
        api_key_id=None,
    )
    async with engine.begin() as connection:
        await connection.execute(
            AuditLog.__table__.insert().values(
                id=entry.id,
                action=entry.action,
                target_type=entry.target_type,
                target_id=entry.target_id,
                result=entry.result,
                outcome=entry.outcome,
                metadata=entry.metadata,
                occurred_at=entry.occurred_at,
                row_hmac=AuditService(settings)._compute_hmac(entry),
                prev_row_hmac=None,
                event_id=None,
                user_id=None,
                project_id=None,
                api_key_id=None,
                source_ip=None,
                user_agent=None,
            )
        )
    await asyncio.to_thread(command.upgrade, cfg, "v1_8_audit_chain_prepare")
    async with engine.begin() as connection:
        manifest = await connection.run_sync(
            lambda sync_connection: build_activation_manifest(
                sync_connection, settings, legacy_key_window_complete=True
            )
        )
    assert manifest["frozen_row_count"] == 1
    assert not manifest["requires_ambiguity_attestation"]
    cfg.attributes["z4j_audit_activation_manifest"] = manifest
    await asyncio.to_thread(command.upgrade, cfg, "head")
    await engine.dispose()
    arguments = {
        "engine": engine,
        "settings": settings,
        "private_root": tmp_path / "private",
        "operation_id": uuid.uuid4(),
        "destination": tmp_path / "retained.json",
    }
    before = await _invariants(arguments, frozen_rows=1, markers=0)
    return arguments, row_id, before


async def _invariants(arguments, *, frozen_rows, markers):
    service = AuditService(arguments["settings"])
    async with AsyncSession(arguments["engine"], expire_on_commit=False) as session:
        report = await verify_active_audit_generation(session, arguments["settings"], page_size=1)
        assert report.clean, report.mismatches
        assert report.verified_frozen_rows == frozen_rows
        state = (await session.execute(select(AuditChainState))).scalar_one()
        payload = authenticate_state(state, service._audit_keyring)
        assert payload["frozen_row_count"] == frozen_rows
        persisted = list(
            (await session.scalars(select(AuditLog).where(AuditLog.legacy_frozen.is_(True)))).all()
        )
        assert len(persisted) == frozen_rows
        exports = list(
            (
                await session.scalars(
                    select(AuditLog).where(AuditLog.action == "audit.frozen_history_exported")
                )
            ).all()
        )
        assert len(exports) == markers
        for marker in exports:
            assert service.verify_row(marker)
            assert marker.target_id == str(arguments["operation_id"])
            assert marker.audit_metadata["frozen_row_count"] == 1
            assert marker.audit_metadata["destination"] == str(arguments["destination"])
        return payload


async def test_postgres_export_commits_one_signed_marker_and_retries(frozen_pg_install):
    arguments, row_id, before = frozen_pg_install
    result = await frozen.export_and_delete_frozen(**arguments)
    assert result["phase"] == "DATABASE_COMMITTED"
    after = await _invariants(arguments, frozen_rows=0, markers=1)
    assert after["active_row_count"] == before["active_row_count"] + 1
    document = json.loads(arguments["destination"].read_text())
    assert document["manifest"]["ordered_ids"] == [str(row_id)]
    assert len(document["rows"]) == 1
    assert (await frozen.export_and_delete_frozen(**arguments))["export_sha256"] == result[
        "export_sha256"
    ]
    assert await _invariants(arguments, frozen_rows=0, markers=1) == after
    with pytest.raises(AuditChainIntegrityError, match="acknowledgement"):
        await frozen.export_and_delete_frozen(
            **arguments, acknowledge_destination_digest="0" * 64, cleanup=True
        )
    assert await _invariants(arguments, frozen_rows=0, markers=1) == after


@pytest.mark.parametrize("stage", ["spool", "phase", "directory"])
async def test_postgres_cleanup_retry_proves_commit_without_redeletion(
    frozen_pg_install, monkeypatch, stage
):
    arguments, _, _ = frozen_pg_install
    result = await frozen.export_and_delete_frozen(**arguments)
    after = await _invariants(arguments, frozen_rows=0, markers=1)
    directory = arguments["private_root"] / str(arguments["operation_id"])
    cleanup = {
        **arguments,
        "acknowledge_destination_digest": result["export_sha256"],
        "cleanup": True,
    }
    retained = arguments["destination"].read_bytes()
    interrupted = False
    unlink = frozen.os.unlink
    rmdir = Path.rmdir

    def crash_unlink(name, *args, **kwargs):
        nonlocal interrupted
        unlink(name, *args, **kwargs)
        target = frozen._SPOOL_FILE if stage == "spool" else frozen._PHASE_FILE
        if stage != "directory" and name == target and not interrupted:
            interrupted = True
            raise OSError("injected crash after committed cleanup unlink")

    def crash_rmdir(path):
        nonlocal interrupted
        rmdir(path)
        if stage == "directory" and path == directory and not interrupted:
            interrupted = True
            raise OSError("injected crash after committed cleanup directory removal")

    with monkeypatch.context() as patch:
        patch.setattr(frozen.os, "unlink", crash_unlink)
        patch.setattr(Path, "rmdir", crash_rmdir)
        with pytest.raises(OSError, match="injected crash"):
            await frozen.export_and_delete_frozen(**cleanup)
    assert interrupted
    assert await _invariants(arguments, frozen_rows=0, markers=1) == after
    with pytest.raises(AuditChainIntegrityError, match="acknowledgement"):
        await frozen.export_and_delete_frozen(
            **{**cleanup, "acknowledge_destination_digest": "0" * 64}
        )
    assert (await frozen.export_and_delete_frozen(**cleanup))["phase"] == "CLEANED"
    assert not directory.exists()
    assert arguments["destination"].read_bytes() == retained
    assert await _invariants(arguments, frozen_rows=0, markers=1) == after


async def test_postgres_foreign_destination_refuses_before_delete(frozen_pg_install):
    arguments, _, before = frozen_pg_install
    destination = arguments["destination"]
    destination.write_bytes(b"unrelated retained file")
    destination.chmod(0o600)
    identity = destination.stat().st_ino
    with pytest.raises(AuditChainIntegrityError, match="does not equal"):
        await frozen.export_and_delete_frozen(**arguments)
    assert destination.read_bytes() == b"unrelated retained file"
    assert destination.stat().st_ino == identity
    assert await _invariants(arguments, frozen_rows=1, markers=0) == before


async def test_postgres_cleanup_proof_refuses_replaced_destination(frozen_pg_install):
    arguments, _, _ = frozen_pg_install
    result = await frozen.export_and_delete_frozen(**arguments)
    cleanup = {
        **arguments,
        "acknowledge_destination_digest": result["export_sha256"],
        "cleanup": True,
    }
    await frozen.export_and_delete_frozen(**cleanup)
    after = await _invariants(arguments, frozen_rows=0, markers=1)
    destination = arguments["destination"]
    retained = destination.read_bytes()
    replacement = destination.with_suffix(".replacement")
    replacement.write_bytes(retained)
    replacement.chmod(0o600)
    replacement.replace(destination)
    with pytest.raises(AuditChainIntegrityError, match="signed marker"):
        await frozen.export_and_delete_frozen(**cleanup)
    assert destination.read_bytes() == retained
    assert await _invariants(arguments, frozen_rows=0, markers=1) == after


async def test_postgres_marker_insert_failure_rolls_back_frozen_delete(frozen_pg_install):
    arguments, _, before = frozen_pg_install
    engine = arguments["engine"]
    async with engine.begin() as connection:
        await connection.execute(
            text("""
                CREATE FUNCTION test_refuse_frozen_export_marker() RETURNS trigger AS $$
                BEGIN
                  IF NEW.action = 'audit.frozen_history_exported' THEN
                    RAISE EXCEPTION 'injected frozen export marker refusal';
                  END IF;
                  RETURN NEW;
                END;
                $$ LANGUAGE plpgsql
            """)
        )
        await connection.execute(
            text("""
                CREATE TRIGGER test_refuse_frozen_export_marker
                BEFORE INSERT ON audit_log FOR EACH ROW
                EXECUTE FUNCTION test_refuse_frozen_export_marker()
            """)
        )
    with pytest.raises(DBAPIError, match="injected frozen export marker refusal"):
        await frozen.export_and_delete_frozen(**arguments)
    assert await _invariants(arguments, frozen_rows=1, markers=0) == before
    async with engine.begin() as connection:
        await connection.execute(text("DROP TRIGGER test_refuse_frozen_export_marker ON audit_log"))
        await connection.execute(text("DROP FUNCTION test_refuse_frozen_export_marker()"))
    assert (await frozen.export_and_delete_frozen(**arguments))["phase"] == "DATABASE_COMMITTED"
    await _invariants(arguments, frozen_rows=0, markers=1)
