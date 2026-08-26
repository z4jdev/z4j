"""Restore compatibility for a database staged at the configured prior head.

The source database is built by migrating the *current checkout* down to the
configured head.  This proves the present migration/restore path and Boundary-D
metadata handling.  It does not execute a previously shipped wheel or container,
so it must not be cited as proof that a genuine prior-release artifact restores.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import uuid
from pathlib import Path

import asyncpg
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from z4j_brain import management_restore_postgres as postgres_restore_module
from z4j_brain.backup import backup_postgres, restore_postgres
from z4j_brain.main import create_app
from z4j_brain.management_restore import _PREVIOUS_RELEASE_HEAD
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import AuditLog, Project
from z4j_brain.schema_transition import RELEASE_MIGRATION_HEAD
from z4j_brain.settings import Settings

pytestmark = pytest.mark.asyncio


def _require_pinned_clients(monkeypatch: pytest.MonkeyPatch) -> None:
    """Put the operator-documented versioned client directory first on PATH."""

    pg_client_bin = os.environ.get("Z4J_TEST_PG_CLIENT_BIN")
    if pg_client_bin:
        monkeypatch.setenv(
            "PATH",
            f"{pg_client_bin}{os.pathsep}{os.environ.get('PATH', '')}",
        )
    if shutil.which("pg_dump") is None or shutil.which("pg_restore") is None:
        pytest.skip("PostgreSQL client tools are unavailable")


def _export_brain_environment(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    *,
    database_url: str,
) -> None:
    monkeypatch.setenv("Z4J_DATABASE_URL", database_url)
    monkeypatch.setenv("Z4J_SECRET", settings.secret.get_secret_value())
    monkeypatch.setenv(
        "Z4J_SESSION_SECRET",
        settings.session_secret.get_secret_value(),
    )
    assert settings.audit_chain_secret is not None
    monkeypatch.setenv(
        "Z4J_AUDIT_CHAIN_SECRET",
        settings.audit_chain_secret.get_secret_value(),
    )
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.setenv("Z4J_REQUIRE_DB_SSL", "false")


async def _drop_database(admin_url: str, database: str) -> None:
    admin = await asyncpg.connect(admin_url)
    try:
        await admin.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname = $1 AND pid <> pg_backend_pid()",
            database,
        )
        await admin.execute(f'DROP DATABASE IF EXISTS "{database}"')
    finally:
        await admin.close()


async def test_current_checkout_prior_head_archive_restores_upgrades_and_starts(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    postgres_admin_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A current-checkout archive staged at the prior head upgrades and starts."""

    _require_pinned_clients(monkeypatch)

    source_database = f"z4j_prev_head_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(postgres_admin_url)
    try:
        await admin.execute(f'CREATE DATABASE "{source_database}"')
    finally:
        await admin.close()
    source_url = f"{postgres_admin_url.rsplit('/', 1)[0]}/{source_database}"
    source_async_url = source_url.replace(
        "postgresql://",
        "postgresql+asyncpg://",
        1,
    )
    backend_root = Path(__file__).resolve().parents[2]  # noqa: ASYNC240
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )

    archive = tmp_path / "previous-release-head.dump"
    source_project_id = uuid.uuid4()
    source_project_slug = f"prev-head-{source_project_id.hex[:12]}"
    try:
        _export_brain_environment(
            monkeypatch,
            integration_settings,
            database_url=source_async_url,
        )
        await asyncio.to_thread(
            command.upgrade,
            config,
            _PREVIOUS_RELEASE_HEAD,
        )
        # Written with explicit SQL, not the ORM: the release models carry
        # columns the previous head's schema does not have yet, and the point
        # of this row is to be exactly what an operator's data looked like
        # when the backup was taken.
        source_engine = create_async_engine(source_async_url)
        try:
            async with source_engine.begin() as connection:
                head = (
                    await connection.execute(
                        text("SELECT version_num FROM alembic_version"),
                    )
                ).scalar_one()
                assert head == _PREVIOUS_RELEASE_HEAD
                await connection.execute(
                    text(
                        "INSERT INTO projects (id, slug, name) VALUES (:id, :slug, :name)",
                    ),
                    {
                        "id": source_project_id,
                        "slug": source_project_slug,
                        "name": "Previous release head",
                    },
                )
                revision = (
                    await connection.execute(
                        text(
                            "SELECT current_revision, guard_version FROM schedule_revision_state",
                        ),
                    )
                ).one()
                allocator = (
                    await connection.execute(
                        text(
                            "SELECT current_epoch_number, guard_version "
                            "FROM schedule_external_epoch_allocator",
                        ),
                    )
                ).one()
                # The constraint that forbids reusing the pre-Boundary-D
                # legacy shortcut for this head: D is already activated here.
                assert revision.guard_version == 1
                assert allocator.guard_version == 1
                source_revision = int(revision.current_revision)
                source_epoch = int(allocator.current_epoch_number)
        finally:
            await source_engine.dispose()
        await asyncio.to_thread(backup_postgres, source_async_url, archive)
    finally:
        await _drop_database(postgres_admin_url, source_database)

    private_home = tmp_path / "previous-head-restore-home"
    private_home.mkdir(mode=0o700)
    private_home.chmod(0o700)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    _export_brain_environment(
        monkeypatch,
        integration_settings,
        database_url=integration_settings.database_url,
    )
    await migrated_engine.dispose()

    expected_source_digest = postgres_restore_module._file_digest(archive)[1]
    result = await asyncio.to_thread(
        restore_postgres,
        integration_settings.database_url,
        archive,
        expected_sha256=expected_source_digest,
    )
    assert result["backend"] == "postgres"

    verify_engine = create_async_engine(integration_settings.database_url)
    verify_database = DatabaseManager(verify_engine)
    try:
        async with verify_database.session() as session:
            installed_head = (
                await session.execute(
                    text("SELECT version_num FROM alembic_version"),
                )
            ).scalar_one()
            assert installed_head == RELEASE_MIGRATION_HEAD

            restored_project = await session.get(Project, source_project_id)
            assert restored_project is not None
            assert restored_project.slug == source_project_slug

            # All three release columns must be present on the restored
            # database. This proves the upgrade actually ran rather than the
            # archive being finalized at the head it arrived with.
            release_columns = set(
                (
                    await session.execute(
                        text(
                            "SELECT table_name, column_name "
                            "FROM information_schema.columns "
                            "WHERE table_schema = current_schema() "
                            "AND ((table_name = 'schedules' "
                            "AND column_name IN ('overlap_policy', 'paused_at')) "
                            "OR (table_name = 'agents' AND column_name = 'revoked_at'))",
                        ),
                    )
                ).all(),
            )
            assert release_columns == {
                ("agents", "revoked_at"),
                ("schedules", "overlap_policy"),
                ("schedules", "paused_at"),
            }

            marker = (
                await session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "audit.database_restored",
                    ),
                )
            ).scalar_one()
            assert marker.audit_metadata["source_migration_head"] == (_PREVIOUS_RELEASE_HEAD)
            assert marker.audit_metadata["migration_head"] == (RELEASE_MIGRATION_HEAD)
            assert marker.audit_metadata["source_provenance"] == {
                "kind": "operator_expected_sha256",
                "expected_sha256": expected_source_digest,
                "verified_digest": expected_source_digest,
            }
            assert marker.audit_metadata["revision_rebase"]["restored_revision"] == source_revision
            assert marker.audit_metadata["epoch_rebase"]["restored_epoch"] == source_epoch
    finally:
        await verify_database.dispose()

    app = create_app(integration_settings, engine=None)
    with TestClient(app) as client:
        ready = client.get("/api/v1/health/ready")
        assert ready.status_code == 200, ready.text
        assert ready.json()["status"] == "ready"


async def test_current_checkout_prior_head_archive_derives_boundary_d_authority(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    postgres_admin_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The current-checkout staged archive is read, never stubbed at zero."""

    _require_pinned_clients(monkeypatch)

    source_database = f"z4j_prev_auth_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(postgres_admin_url)
    try:
        await admin.execute(f'CREATE DATABASE "{source_database}"')
    finally:
        await admin.close()
    source_url = f"{postgres_admin_url.rsplit('/', 1)[0]}/{source_database}"
    source_async_url = source_url.replace(
        "postgresql://",
        "postgresql+asyncpg://",
        1,
    )
    backend_root = Path(__file__).resolve().parents[2]  # noqa: ASYNC240
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )

    archive = tmp_path / "previous-release-authority.dump"
    try:
        _export_brain_environment(
            monkeypatch,
            integration_settings,
            database_url=source_async_url,
        )
        await asyncio.to_thread(
            command.upgrade,
            config,
            _PREVIOUS_RELEASE_HEAD,
        )
        source_engine = create_async_engine(source_async_url)
        try:
            async with source_engine.connect() as connection:
                revision = (
                    await connection.execute(
                        text(
                            "SELECT current_revision, guard_version FROM schedule_revision_state",
                        ),
                    )
                ).one()
                allocator = (
                    await connection.execute(
                        text(
                            "SELECT current_epoch_number, guard_version "
                            "FROM schedule_external_epoch_allocator",
                        ),
                    )
                ).one()
                assert revision.guard_version == 1
                assert allocator.guard_version == 1
                source_revision = int(revision.current_revision)
                source_epoch = int(allocator.current_epoch_number)
        finally:
            await source_engine.dispose()
        await asyncio.to_thread(backup_postgres, source_async_url, archive)
    finally:
        await _drop_database(postgres_admin_url, source_database)

    private_home = tmp_path / "previous-head-authority-home"
    private_home.mkdir(mode=0o700)
    private_home.chmod(0o700)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    await migrated_engine.dispose()

    pg_restore = postgres_restore_module._resolve_tool("pg_restore")
    source_head = await asyncio.to_thread(
        postgres_restore_module._archive_source_head,
        pg_restore,
        archive,
    )
    assert source_head == _PREVIOUS_RELEASE_HEAD

    _, toc_digest = await asyncio.to_thread(
        postgres_restore_module._inspect_toc,
        pg_restore,
        archive,
        source_head=source_head,
    )
    archive_digest = postgres_restore_module._file_digest(archive)[1]
    authority = await asyncio.to_thread(
        postgres_restore_module._archive_source_authority,
        pg_restore,
        archive,
        source_head=source_head,
        archive_digest=archive_digest,
        toc_digest=toc_digest,
    )

    # The pre-Boundary-D shortcut hardcodes revision 0, epoch 0, an empty
    # external-authority manifest and a ``revision_classification`` label.
    # This head shipped D activated, so every one of those has to come out of
    # the archive instead.
    allocator_rows = await asyncio.to_thread(
        postgres_restore_module._extract_table,
        pg_restore,
        archive,
        "schedule_external_epoch_allocator",
    )
    assert len(allocator_rows) == 1
    assert authority["source_head"] == _PREVIOUS_RELEASE_HEAD
    assert authority["revision"] == source_revision
    assert authority["epoch"] == source_epoch
    assert "revision_classification" not in authority
    assert authority["manifest_digest"]
    assert authority["external_authority_manifest"]["allocator_digest"] == (
        postgres_restore_module.release_manifest_digest(allocator_rows)
    )
    assert authority["external_authority_manifest"]["allocator_digest"] != (
        postgres_restore_module.release_manifest_digest([])
    )

    # Resume re-derives the attestation challenge from this manifest, so a
    # second derivation of the same staged archive must be byte-identical.
    repeated = await asyncio.to_thread(
        postgres_restore_module._archive_source_authority,
        pg_restore,
        archive,
        source_head=source_head,
        archive_digest=archive_digest,
        toc_digest=toc_digest,
    )
    assert repeated == authority
    assert list(repeated) == list(authority)
    assert repeated["manifest_digest"] == authority["manifest_digest"]


async def test_unactivated_previous_head_archive_leaves_the_target_intact(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    postgres_admin_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A previous-head archive that never activated Boundary D is refused.

    The refusal has to land before anything destructive.  ``pg_restore
    --clean --if-exists`` replaces the live database wholesale, and the only
    later place this state is noticed is the authenticated snapshot taken over
    the already replaced database, which turns a source that should never have
    been accepted into a destroyed database and a retained fence.  The SQLite
    backend refuses the same archive with nothing touched.
    """

    _require_pinned_clients(monkeypatch)

    source_database = f"z4j_prev_unact_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(postgres_admin_url)
    try:
        await admin.execute(f'CREATE DATABASE "{source_database}"')
    finally:
        await admin.close()
    source_url = f"{postgres_admin_url.rsplit('/', 1)[0]}/{source_database}"
    source_async_url = source_url.replace(
        "postgresql://",
        "postgresql+asyncpg://",
        1,
    )
    backend_root = Path(__file__).resolve().parents[2]  # noqa: ASYNC240
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )

    archive = tmp_path / "unactivated-previous-head.dump"
    try:
        _export_brain_environment(
            monkeypatch,
            integration_settings,
            database_url=source_async_url,
        )
        await asyncio.to_thread(
            command.upgrade,
            config,
            _PREVIOUS_RELEASE_HEAD,
        )
        source_engine = create_async_engine(source_async_url)
        try:
            async with source_engine.begin() as connection:
                await connection.execute(
                    text(
                        "INSERT INTO projects (id, slug, name) VALUES (:id, :slug, :name)",
                    ),
                    {
                        "id": uuid.uuid4(),
                        "slug": f"archived-{uuid.uuid4().hex[:12]}",
                        "name": "Archived project",
                    },
                )
                # The unactivated shape this head's own CHECK constraint
                # permits, so the archive schema stays byte-identical to a real
                # previous-head archive and pg_restore would load it without a
                # single violation.
                await connection.execute(
                    text("ALTER TABLE schedule_revision_state DISABLE TRIGGER USER"),
                )
                await connection.execute(
                    text(
                        "UPDATE schedule_revision_state SET guard_version = NULL, "
                        "activation_id = NULL, activation_manifest_digest = NULL, "
                        "activation_audit_id = NULL",
                    ),
                )
                await connection.execute(
                    text("ALTER TABLE schedule_revision_state ENABLE TRIGGER USER"),
                )
                unactivated = (
                    await connection.execute(
                        text("SELECT guard_version FROM schedule_revision_state"),
                    )
                ).scalar_one()
                assert unactivated is None
        finally:
            await source_engine.dispose()
        await asyncio.to_thread(backup_postgres, source_async_url, archive)
    finally:
        await _drop_database(postgres_admin_url, source_database)

    # Keep the private base short: the durable operation path adds a 64-byte
    # target key, UUID, and staged filename, which otherwise crosses Win32's
    # legacy MAX_PATH boundary before pg_restore can inspect the archive.
    private_home = tmp_path / "unactivated-home"
    private_home.mkdir(mode=0o700)
    private_home.chmod(0o700)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    _export_brain_environment(
        monkeypatch,
        integration_settings,
        database_url=integration_settings.database_url,
    )

    live_slug = f"live-{uuid.uuid4().hex[:12]}"
    async with migrated_engine.begin() as connection:
        await connection.execute(
            text("INSERT INTO projects (id, slug, name) VALUES (:id, :slug, :name)"),
            {
                "id": uuid.uuid4(),
                "slug": live_slug,
                "name": "Live production project",
            },
        )
    await migrated_engine.dispose()

    with pytest.raises(
        postgres_restore_module.DatabaseRestoreRefused,
        match="schedule_revision_state is not Boundary-D activated",
    ):
        await asyncio.to_thread(
            restore_postgres,
            integration_settings.database_url,
            archive,
            expected_sha256=postgres_restore_module._file_digest(archive)[1],
        )

    verify_engine = create_async_engine(integration_settings.database_url)
    try:
        async with verify_engine.connect() as connection:
            assert (
                await connection.execute(
                    text("SELECT version_num FROM alembic_version"),
                )
            ).scalar_one() == RELEASE_MIGRATION_HEAD
            surviving = set(
                (
                    await connection.execute(
                        text("SELECT slug FROM projects"),
                    )
                )
                .scalars()
                .all(),
            )
            assert live_slug in surviving
            # A refusal that still fenced the database would have left the
            # operator with a live installation they cannot start.
            fence = (
                await connection.execute(
                    text(
                        "SELECT setconfig FROM pg_catalog.pg_db_role_setting "
                        "WHERE setdatabase = (SELECT oid FROM pg_catalog.pg_database "
                        "WHERE datname = current_database()) AND setrole = 0",
                    ),
                )
            ).all()
            assert fence == []
    finally:
        await verify_engine.dispose()
