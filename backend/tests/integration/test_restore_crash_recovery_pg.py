"""Real-PostgreSQL crash windows where a side effect outruns its record.

The catalog fence stops every connection to the database, so an operation an
operator cannot finish is a brain that does not start. Three windows are
pinned here, all of the same shape: something durable happens, and the record
that says it happened lands afterwards.

* The recovery dump. The fence commits first, and the dump that follows is
  skipped on resume whenever its pathname is present. pg_dump leaves partial
  output behind when it fails, so those bytes claimed a dump that had not
  happened, while rollback demanded a complete archive of them.

* The finalization marker. It commits inside the database and the fence
  learns of it one statement later, so in between the database holds a
  finished restore that the fence describes as an emptied one. Reading only
  the fence, the resume did the destructive half again and threw the signed
  marker away with it.

* The fence removal itself. The coordinator can reach finalization already
  owning a transaction, and a session bound to a connection does not commit a
  transaction it did not open. The rebases and the marker then became durable
  after the fence came down rather than before, so the crash between the two
  left a database that starts, was replaced, and was never rebased, with the
  marker rolled back and both supported exits refusing.

Every test interrupts the real ceremony against a real server, then asks the
next command to finish the job. Nothing here stands in for the database, the
client tools, or the fence.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

import asyncpg
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from z4j_brain import management_restore_postgres as postgres_restore_module
from z4j_brain.backup import (
    backup_postgres,
    restore_postgres,
    rollback_restore,
)
from z4j_brain.main import create_app
from z4j_brain.management_restore import DatabaseRestorePending
from z4j_brain.persistence.database import (
    DatabaseManager,
    create_engine_from_settings,
)
from z4j_brain.persistence.models import AuditLog, Project
from z4j_brain.settings import Settings

pytestmark = pytest.mark.asyncio

#: The head an archive predating the authenticated audit boundary lands at.
_LEGACY_ARCHIVE_HEAD = "v1_7_security_hardening"


class _SimulatedPowerLoss(RuntimeError):  # noqa: N818  not an error, a crash
    """Stands in for the process dying at one exact statement."""


def _require_client_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    pg_client_bin = os.environ.get("Z4J_TEST_PG_CLIENT_BIN")
    if pg_client_bin:
        monkeypatch.setenv(
            "PATH",
            f"{pg_client_bin}{os.pathsep}{os.environ.get('PATH', '')}",
        )
    if shutil.which("pg_dump") is None or shutil.which("pg_restore") is None:
        pytest.skip("PostgreSQL client tools are unavailable")


def _ceremony_environment(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    private_home: Path,
) -> None:
    """The environment the ceremony builds its own Settings from."""

    private_home.mkdir(mode=0o700)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.setenv("Z4J_DATABASE_URL", settings.database_url)
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


def _read_fence_off_loop(database_url: str) -> dict[str, Any] | None:
    """Read the catalog fence on the client's own pinned loop.

    The pinned psycopg client refuses the loop pytest-asyncio supplies on
    Windows, and every ceremony entry point already runs on a loop of its own
    choosing. Borrow the same runner rather than teaching this test a second
    way to reach the database.
    """

    target = postgres_restore_module._parse_target(database_url)
    return postgres_restore_module._run_pinned_client(
        postgres_restore_module._read_fence(target),
    )


def _phase(private_home: Path) -> tuple[Path, dict[str, Any]]:
    phase_paths = list(
        (private_home / ".z4j-restore" / "postgres").glob("*/*/phase.json"),
    )
    assert len(phase_paths) == 1, f"expected one operation, found {phase_paths}"
    return phase_paths[0].parent, json.loads(phase_paths[0].read_text())


def _fail_the_recovery_dump(
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Any]:
    """Make the recovery dump fail the way a real one does: partially written.

    pg_dump writes as it goes and leaves what it managed behind when it stops,
    so the failure that matters is not an absent file but an incomplete one.
    """

    original_runner = postgres_restore_module._run_identity_bound
    state: dict[str, Any] = {"failed": False, "path": None}

    def run(
        tool: object,
        arguments: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        if getattr(tool, "name", None) == "pg_dump" and "--file" in arguments:
            destination = Path(arguments[arguments.index("--file") + 1])
            destination.write_bytes(b"PGDMP\x00partial recovery dump")
            state["failed"] = True
            state["path"] = destination
            return subprocess.CompletedProcess(
                ["pg_dump"],
                1,
                "",
                "injected recovery dump failure",
            )
        return original_runner(tool, arguments, **kwargs)  # type: ignore[arg-type,return-value]

    monkeypatch.setattr(
        postgres_restore_module,
        "_run_identity_bound",
        run,
    )
    state["original"] = original_runner
    return state


@pytest.mark.parametrize("resolution", ["resume", "rollback"])
async def test_a_failed_recovery_dump_leaves_both_exits_open(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    resolution: str,
) -> None:
    """A dump that fails has fenced the brain without touching the target.

    Nothing destructive has run at that point: the managed tables are dropped
    only in the same transaction that advances the fence past FENCED. So both
    exits have to work, and neither may depend on a recovery archive that was
    never produced.
    """
    _require_client_tools(monkeypatch)
    private_home = tmp_path / "failed-dump-home"
    _ceremony_environment(monkeypatch, integration_settings, private_home)

    # Two rows that tell the outcomes apart: the archive holds only the first,
    # the live target holds both.
    database = DatabaseManager(migrated_engine)
    in_archive = f"archived-{uuid.uuid4().hex[:12]}"
    async with database.session(write=True) as session:
        session.add(Project(id=uuid.uuid4(), slug=in_archive, name="in the archive"))
        await session.commit()

    archive = tmp_path / "restore-source.dump"
    await asyncio.to_thread(
        backup_postgres,
        integration_settings.database_url,
        archive,
    )
    only_live = f"livealone-{uuid.uuid4().hex[:12]}"
    async with database.session(write=True) as session:
        session.add(Project(id=uuid.uuid4(), slug=only_live, name="after the archive"))
        await session.commit()
    await migrated_engine.dispose()

    injected = _fail_the_recovery_dump(monkeypatch)
    with pytest.raises(
        postgres_restore_module.DatabaseRestoreRefused,
        match="target recovery dump failed",
    ):
        await asyncio.to_thread(
            restore_postgres,
            integration_settings.database_url,
            archive,
        )
    assert injected["failed"]
    monkeypatch.setattr(
        postgres_restore_module,
        "_run_identity_bound",
        injected["original"],
    )

    operation_dir, phase = _phase(private_home)
    assert phase["state"] == "DATABASE_FENCED"
    assert not (operation_dir / "target-recovery.dump").exists(), (
        "bytes on their way to becoming a recovery dump were published under "
        "the name a resume reads as a finished one, so the dump is skipped "
        "forever and rollback demands an archive that does not exist"
    )
    fence = await asyncio.to_thread(
        _read_fence_off_loop,
        integration_settings.database_url,
    )
    assert fence is not None and fence["state"] == "FENCED"

    if resolution == "resume":
        result = await asyncio.to_thread(
            restore_postgres,
            integration_settings.database_url,
            archive,
            operation=phase["operation_id"],
        )
        # Resume re-took the dump it never got and carried the restore through,
        # so the database is now the archive and nothing else.
        expected = {in_archive}
        forbidden = {only_live}
    else:
        result = await asyncio.to_thread(
            rollback_restore,
            integration_settings.database_url,
            operation=phase["operation_id"],
        )
        assert result["rolled_back"] is True
        # Rollback retired an operation that never reached the target, so the
        # live database is untouched, including the row the archive predates.
        expected = {in_archive, only_live}
        forbidden = set()

    assert result["operation_id"] == phase["operation_id"]
    assert (
        await asyncio.to_thread(
            _read_fence_off_loop,
            integration_settings.database_url,
        )
    ) is None, "the operation ended but its catalog fence is still up"

    verify_engine = create_engine_from_settings(integration_settings)
    verify = DatabaseManager(verify_engine)
    try:
        async with verify.session() as session:
            slugs = set(
                (await session.execute(select(Project.slug))).scalars().all(),
            )
    finally:
        await verify.dispose()
    assert expected <= slugs
    assert not (forbidden & slugs)


async def test_a_restore_that_committed_its_marker_is_not_run_a_second_time(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The signed marker commits before the fence records that it did.

    Between those two the database already holds a finished restore and the
    fence still says the target is merely cleared. Reading the fence alone,
    the resume ran the destructive half again, which discards signed audit
    history that was already committed and, against a database whose
    partitions are back in place, is refused outright by pg_restore --clean:
    the operation could then be neither finished nor abandoned.
    """
    _require_client_tools(monkeypatch)
    private_home = tmp_path / "marker-crash-home"
    _ceremony_environment(monkeypatch, integration_settings, private_home)

    database = DatabaseManager(migrated_engine)
    from_archive = f"kept-{uuid.uuid4().hex[:12]}"
    async with database.session(write=True) as session:
        session.add(Project(id=uuid.uuid4(), slug=from_archive, name="in archive"))
        await session.commit()
    archive = tmp_path / "restore-source.dump"
    await asyncio.to_thread(
        backup_postgres,
        integration_settings.database_url,
        archive,
    )
    async with database.session(write=True) as session:
        session.add(
            Project(
                id=uuid.uuid4(),
                slug=f"gone-{uuid.uuid4().hex[:12]}",
                name="after archive",
            ),
        )
        await session.commit()
    await migrated_engine.dispose()

    original_set_fence = postgres_restore_module._set_fence
    crashed = False

    async def stop_before_the_fence_learns(
        target: object,
        envelope: dict[str, object],
    ) -> None:
        nonlocal crashed
        if not crashed and envelope.get("state") == "MARKER_COMMITTED":
            crashed = True
            raise _SimulatedPowerLoss("after the signed finalization marker")
        await original_set_fence(target, envelope)  # type: ignore[arg-type]

    monkeypatch.setattr(
        postgres_restore_module,
        "_set_fence",
        stop_before_the_fence_learns,
    )
    with pytest.raises(_SimulatedPowerLoss):
        await asyncio.to_thread(
            restore_postgres,
            integration_settings.database_url,
            archive,
        )
    assert crashed
    monkeypatch.setattr(
        postgres_restore_module,
        "_set_fence",
        original_set_fence,
    )

    _, phase = _phase(private_home)
    operation = phase["operation_id"]
    direct_url = integration_settings.database_url.replace(
        "postgresql+asyncpg://",
        "postgresql://",
        1,
    )
    direct = await asyncpg.connect(direct_url)
    try:
        committed_marker_id = await direct.fetchval(
            "SELECT id::text FROM audit_log "
            "WHERE action = 'audit.database_restored' AND target_id = $1",
            operation,
        )
    finally:
        await direct.close()
    assert committed_marker_id is not None, (
        "the crash was supposed to land after the signed marker committed, so "
        "this run proved nothing about the window it is here for"
    )
    fence = await asyncio.to_thread(
        _read_fence_off_loop,
        integration_settings.database_url,
    )
    assert fence is not None and fence["state"] == "TARGET_CLEARED"

    original_runner = postgres_restore_module._run_identity_bound
    replayed: list[list[str]] = []

    def count_destructive_work(
        tool: object,
        arguments: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        if getattr(tool, "name", None) == "pg_restore" and "--dbname" in arguments:
            replayed.append(list(arguments))
        return original_runner(tool, arguments, **kwargs)  # type: ignore[arg-type,return-value]

    monkeypatch.setattr(
        postgres_restore_module,
        "_run_identity_bound",
        count_destructive_work,
    )
    result = await asyncio.to_thread(
        restore_postgres,
        integration_settings.database_url,
        archive,
        operation=operation,
    )

    assert result["operation_id"] == operation
    assert result["marker_id"] == committed_marker_id, (
        "the completed restore must adopt the marker the crashed attempt "
        "committed, not discard it and sign another"
    )
    assert replayed == [], (
        "the archive was restored over the database a second time, which "
        "throws away the signed marker and rebases already committed"
    )
    assert (
        await asyncio.to_thread(
            _read_fence_off_loop,
            integration_settings.database_url,
        )
    ) is None, "the restore completed but its catalog fence is still up"

    verify_engine = create_engine_from_settings(integration_settings)
    verify = DatabaseManager(verify_engine)
    try:
        async with verify.session() as session:
            markers = (
                (
                    await session.execute(
                        select(AuditLog).where(
                            AuditLog.action == "audit.database_restored",
                            AuditLog.target_id == operation,
                        ),
                    )
                )
                .scalars()
                .all()
            )
            assert len(markers) == 1
            assert str(markers[0].id) == committed_marker_id
            slugs = set(
                (await session.execute(select(Project.slug))).scalars().all(),
            )
    finally:
        await verify.dispose()
    assert from_archive in slugs
    assert not [slug for slug in slugs if slug.startswith("gone-")]

    # The property the operator lost: a database that admits connections.
    startable = create_engine_from_settings(integration_settings)
    try:
        async with startable.connect():
            pass
    except DatabaseRestorePending:  # pragma: no cover - the defect's symptom
        pytest.fail("the completed restore still fences every connection")
    finally:
        await startable.dispose()


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


def _alembic_config() -> Config:
    backend_root = Path(__file__).resolve().parents[2]
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    return config


async def _legacy_archive(
    postgres_admin_url: str,
    integration_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    destination: Path,
) -> str:
    """Take a real archive of a database at the pre-authenticated-audit head.

    Restoring one of these is the only ceremony that stops part way, hands the
    operator an activation manifest, and is then resumed. That resumed run is
    the one whose upgrade has nothing left to apply, which is what leaves the
    coordinator holding a transaction when finalization writes into it.
    """

    database = f"z4j_legacy_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(postgres_admin_url)
    try:
        await admin.execute(f'CREATE DATABASE "{database}"')
    finally:
        await admin.close()
    source_url = f"{postgres_admin_url.rsplit('/', 1)[0]}/{database}".replace(
        "postgresql://",
        "postgresql+asyncpg://",
        1,
    )
    project_id = uuid.uuid4()
    slug = f"legacy-{project_id.hex[:12]}"
    try:
        monkeypatch.setenv("Z4J_DATABASE_URL", source_url)
        await asyncio.to_thread(
            command.upgrade,
            _alembic_config(),
            _LEGACY_ARCHIVE_HEAD,
        )
        # Explicit SQL, not the ORM: the release models carry columns this
        # head does not have, and the row has to be what the operator's data
        # actually looked like when the backup was taken.
        engine = create_async_engine(source_url)
        try:
            async with engine.begin() as connection:
                head = (
                    await connection.execute(
                        text("SELECT version_num FROM alembic_version"),
                    )
                ).scalar_one()
                assert head == _LEGACY_ARCHIVE_HEAD
                await connection.execute(
                    text(
                        "INSERT INTO projects (id, slug, name) VALUES (:id, :slug, :name)",
                    ),
                    {"id": project_id, "slug": slug, "name": "Legacy archive"},
                )
        finally:
            await engine.dispose()
        await asyncio.to_thread(backup_postgres, source_url, destination)
    finally:
        monkeypatch.setenv("Z4J_DATABASE_URL", integration_settings.database_url)
        await _drop_database(postgres_admin_url, database)
    return slug


def _activate_the_fenced_restore(
    integration_settings: Settings,
    operation: str,
) -> None:
    """Run the activation that the restore's own refusal tells operators to run."""

    manifest = postgres_restore_module.build_restore_activation_manifest(
        integration_settings.database_url,
        operation=operation,
        settings=integration_settings,
        legacy_key_window_complete=True,
        known_head=None,
    )
    postgres_restore_module.apply_restore_activation_manifest(
        integration_settings.database_url,
        operation=operation,
        settings=integration_settings,
        manifest=manifest,
        attestation=(
            str(manifest["manifest_digest"]) if manifest["requires_ambiguity_attestation"] else None
        ),
    )


async def test_a_restore_interrupted_at_the_fence_removal_still_has_an_exit(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    postgres_admin_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Killing the process between the fence clear and the commit is survivable.

    The clear is a catalog write on its own connection, so it is durable the
    moment it returns. If the rebases and the signed marker are still sitting
    in the coordinator's transaction at that point, this crash takes them back
    while leaving the replaced database unfenced: the brain starts on data
    that was never rebased, resume refuses for the marker it cannot find, and
    rollback refuses for the fence that is no longer there.
    """

    _require_client_tools(monkeypatch)
    private_home = tmp_path / "fence-removal-home"
    _ceremony_environment(monkeypatch, integration_settings, private_home)

    archive = tmp_path / "legacy-source.dump"
    archived_slug = await _legacy_archive(
        postgres_admin_url,
        integration_settings,
        monkeypatch,
        archive,
    )

    database = DatabaseManager(migrated_engine)
    displaced = f"displaced-{uuid.uuid4().hex[:12]}"
    async with database.session(write=True) as session:
        session.add(Project(id=uuid.uuid4(), slug=displaced, name="not in the archive"))
        await session.commit()
    await migrated_engine.dispose()

    with pytest.raises(
        postgres_restore_module.DatabaseRestoreRefused,
        match="awaiting manifest-bound audit activation",
    ):
        await asyncio.to_thread(
            restore_postgres,
            integration_settings.database_url,
            archive,
        )
    _, phase = _phase(private_home)
    operation = str(phase["operation_id"])
    assert phase["state"] == "AWAITING_AUDIT_ACTIVATION"
    await asyncio.to_thread(
        _activate_the_fenced_restore,
        integration_settings,
        operation,
    )

    original_clear_fence = postgres_restore_module._clear_fence
    cleared = False

    async def stop_once_the_fence_is_down(target: object) -> None:
        """Die at the instant the fence stops protecting the database."""

        nonlocal cleared
        await original_clear_fence(target)  # type: ignore[arg-type]
        if not cleared:
            cleared = True
            raise _SimulatedPowerLoss("after the durable fence removal")

    monkeypatch.setattr(
        postgres_restore_module,
        "_clear_fence",
        stop_once_the_fence_is_down,
    )
    with pytest.raises(_SimulatedPowerLoss):
        await asyncio.to_thread(
            restore_postgres,
            integration_settings.database_url,
            archive,
            operation=operation,
        )
    assert cleared
    monkeypatch.setattr(
        postgres_restore_module,
        "_clear_fence",
        original_clear_fence,
    )

    assert (
        await asyncio.to_thread(
            _read_fence_off_loop,
            integration_settings.database_url,
        )
    ) is None, "the crash was supposed to land after the fence came down"
    _, phase = _phase(private_home)
    assert phase["state"] == "MARKER_COMMITTED"
    crashed_marker_id = str(phase["fence"]["marker_id"])

    direct_url = integration_settings.database_url.replace(
        "postgresql+asyncpg://",
        "postgresql://",
        1,
    )
    direct = await asyncpg.connect(direct_url)
    try:
        survivor = await direct.fetchval(
            "SELECT id::text FROM audit_log "
            "WHERE action = 'audit.database_restored' AND target_id = $1",
            operation,
        )
    finally:
        await direct.close()
    assert survivor == crashed_marker_id, (
        "the fence came down while the marker and the rebases it describes "
        "were still inside the coordinator's transaction, so the crash took "
        "them back and left an unfenced database that was never rebased"
    )

    # The whole point of the window: an operator still has a command to run.
    result = await asyncio.to_thread(
        restore_postgres,
        integration_settings.database_url,
        archive,
        operation=operation,
    )
    assert result["operation_id"] == operation
    assert result["marker_id"] == crashed_marker_id

    verify_engine = create_engine_from_settings(integration_settings)
    verify = DatabaseManager(verify_engine)
    try:
        async with verify.session() as session:
            slugs = set(
                (await session.execute(select(Project.slug))).scalars().all(),
            )
            markers = (
                (
                    await session.execute(
                        select(AuditLog).where(
                            AuditLog.action == "audit.database_restored",
                            AuditLog.target_id == operation,
                        ),
                    )
                )
                .scalars()
                .all()
            )
            installed_head = (
                await session.execute(
                    text("SELECT version_num FROM alembic_version"),
                )
            ).scalar_one()
    finally:
        await verify.dispose()
    assert archived_slug in slugs
    assert displaced not in slugs
    assert len(markers) == 1
    assert str(markers[0].id) == crashed_marker_id
    assert installed_head == postgres_restore_module.RELEASE_MIGRATION_HEAD

    app = create_app(integration_settings, engine=None)
    with TestClient(app) as client:
        ready = client.get("/api/v1/health/ready")
        assert ready.status_code == 200, ready.text
        assert ready.json()["status"] == "ready"
