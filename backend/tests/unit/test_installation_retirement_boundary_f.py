"""Executable packaged-installation retirement gates for Boundary F."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain import cli
from z4j_brain import management_restore as restore_module
from z4j_brain import management_retirement as retirement_module
from z4j_brain.backup import backup_sqlite, restore_sqlite
from z4j_brain.configuration import (
    capture_configuration,
    overlay_runtime_environment,
    settings_from_snapshot,
)
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import AuditChainState, AuditLog
from z4j_brain.secret_store import (
    audit_bootstrap_coordinator,
    ensure_secret_store_directory,
    read_secret_store,
)


def _clear_z4j_environment(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Clear ``Z4J_*`` without asking monkeypatch to put it back.

    ``monkeypatch.delenv`` is deliberately NOT used here. These tests call the
    real snapshot exporter (``cli._capture_serve_configuration``), which writes
    ``Z4J_SECRET``, ``Z4J_SESSION_SECRET``, ``Z4J_AUDIT_CHAIN_SECRET``,
    ``Z4J_DATABASE_URL``, ``Z4J_METRICS_AUTH_TOKEN`` and
    ``Z4J_REGISTRY_BACKEND`` straight into ``os.environ``. A later
    ``monkeypatch.delenv`` on those keys records the exported values as the
    "original" to restore, and monkeypatch's undo runs AFTER the
    ``_restore_process_configuration`` fixture in conftest has already wiped
    the environment. The net effect was that undo re-published a live
    ``Z4J_AUDIT_CHAIN_SECRET`` into the process after the guard had cleaned up.

    Every later ``Settings()`` then picked that key up even when constructed
    with explicit kwargs, which flips the audit service onto the v2 signer and
    makes it demand a chain-state row that unit-test databases never seed. The
    result was 117 order-dependent failures across the suite, all reporting
    "audit chain state is missing or duplicated; refusing to sign", every one
    of which passed when its file was run alone.

    Popping directly is safe precisely because that conftest fixture snapshots
    the true pre-test environment and restores it at teardown.
    """
    for key in tuple(os.environ):
        if key.startswith("Z4J_"):
            os.environ.pop(key, None)


def _state(home: Path) -> AuditChainState:
    snapshot = capture_configuration(home=home, cwd=home)
    if not snapshot.values.get("Z4J_DATABASE_URL"):
        snapshot = overlay_runtime_environment(
            snapshot,
            {
                "Z4J_DATABASE_URL": (f"sqlite+aiosqlite:///{home / 'z4j.db'}"),
            },
        )
    settings = settings_from_snapshot(snapshot)

    async def _read() -> AuditChainState:
        engine = create_async_engine(settings.database_url)
        database = DatabaseManager(engine)
        try:
            async with database.session() as session:
                state = await session.get(AuditChainState, "audit-chain")
                assert state is not None
                session.expunge(state)
                return state
        finally:
            await database.dispose()

    return asyncio.run(_read())


def _generation_start_metadata(home: Path) -> dict[str, object]:
    snapshot = capture_configuration(home=home, cwd=home)
    if not snapshot.values.get("Z4J_DATABASE_URL"):
        snapshot = overlay_runtime_environment(
            snapshot,
            {
                "Z4J_DATABASE_URL": (f"sqlite+aiosqlite:///{home / 'z4j.db'}"),
            },
        )
    settings = settings_from_snapshot(snapshot)

    async def _read() -> dict[str, object]:
        engine = create_async_engine(settings.database_url)
        database = DatabaseManager(engine)
        try:
            async with database.session() as session:
                marker = (
                    await session.execute(
                        select(AuditLog).where(
                            AuditLog.action == "audit.chain_generation_started",
                        ),
                    )
                ).scalar_one()
                return dict(marker.audit_metadata)
        finally:
            await database.dispose()

    return asyncio.run(_read())


def _bootstrap_packaged(
    home: Path,
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.chdir(home)
    _clear_z4j_environment(monkeypatch)
    monkeypatch.setenv("Z4J_HOME", str(home))
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.setenv(
        "Z4J_ALLOWED_HOSTS",
        '["localhost","127.0.0.1"]',
    )
    with audit_bootstrap_coordinator(home):
        cli._capture_serve_configuration()
        cli._auto_migrate()


def _management_environment(
    home: Path,
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    _clear_z4j_environment(monkeypatch)
    monkeypatch.setenv("Z4J_HOME", str(home))
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.setenv(
        "Z4J_ALLOWED_HOSTS",
        '["localhost","127.0.0.1"]',
    )


def test_fresh_management_bootstrap_creates_home_before_retirement_fence(
    tmp_path: Path,
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    home = tmp_path / "fresh-z4j-home"
    monkeypatch.chdir(tmp_path)
    _clear_z4j_environment(monkeypatch)
    monkeypatch.setenv("Z4J_HOME", str(home))
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    expected_database_url = f"sqlite+aiosqlite:///{home / 'z4j.db'}"
    monkeypatch.setenv(
        "Z4J_DATABASE_URL",
        expected_database_url,
    )
    monkeypatch.setenv("Z4J_SECRET", "management-bootstrap-primary-secret")
    monkeypatch.setenv("Z4J_SESSION_SECRET", "management-bootstrap-session-secret")
    monkeypatch.setenv(
        "Z4J_METRICS_AUTH_TOKEN",
        "management-bootstrap-metrics-token",
    )
    monkeypatch.setenv(
        "Z4J_AUDIT_CHAIN_SECRET",
        "management-bootstrap-independent-audit-secret",
    )

    assert not home.exists()
    snapshot = cli._bootstrap_env_for_management_commands()

    assert snapshot.values["Z4J_DATABASE_URL"] == expected_database_url
    assert home.is_dir()
    assert not any(home.iterdir())
    if os.name == "posix":
        assert home.stat().st_mode & 0o777 == 0o700


def test_packaged_nuke_retires_pair_and_destroy_requires_signed_binding(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:  # type: ignore[no-untyped-def]
    home = tmp_path / "z4j-home"
    ensure_secret_store_directory(home)
    monkeypatch.chdir(home)
    _clear_z4j_environment(monkeypatch)
    monkeypatch.setenv("Z4J_HOME", str(home))
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.setenv(
        "Z4J_ALLOWED_HOSTS",
        '["localhost","127.0.0.1"]',
    )

    with audit_bootstrap_coordinator(home):
        cli._capture_serve_configuration()
        cli._auto_migrate()
    old_store = read_secret_store(home / "secret.env").values
    old_state = _state(home)

    # A real management command starts in a new process and therefore does
    # not inherit the safe-store values exported by the earlier serve.
    _clear_z4j_environment(monkeypatch)
    monkeypatch.setenv("Z4J_HOME", str(home))
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.setenv(
        "Z4J_ALLOWED_HOSTS",
        '["localhost","127.0.0.1"]',
    )

    assert cli.main(["reset", "--force", "--nuke-secrets"]) == 0
    output = capsys.readouterr().out
    assert "recoverable retirement bundle" in output

    new_store = read_secret_store(home / "secret.env").values
    new_state = _state(home)
    binding = new_state.retired_recovery_binding
    assert binding is not None
    assert binding["status"] == "RECOVERABLE"
    assert binding["replacement_installation_id"] == str(
        new_state.installation_id,
    )
    assert new_state.installation_id != old_state.installation_id
    assert new_store["Z4J_SECRET"] != old_store["Z4J_SECRET"]
    assert new_store["Z4J_AUDIT_CHAIN_SECRET"] != old_store["Z4J_AUDIT_CHAIN_SECRET"]

    operation = binding["operation_id"]
    bundle = home / "retired-installations" / operation
    assert (bundle / "z4j.db").is_file()
    assert (bundle / "secret.env").is_file()
    assert (bundle / "bundle-manifest.json").is_file()
    genesis_retirement = _generation_start_metadata(home)["installation_retirement"]
    assert isinstance(genesis_retirement, dict)
    assert genesis_retirement["operation_id"] == operation
    assert genesis_retirement["old_bundle_manifest_digest"] == binding["old_bundle_manifest_digest"]

    _clear_z4j_environment(monkeypatch)
    monkeypatch.setenv("Z4J_HOME", str(home))
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.setenv(
        "Z4J_ALLOWED_HOSTS",
        '["localhost","127.0.0.1"]',
    )
    assert cli.main(["reset", "--force"]) == 0
    assert _state(home).retired_recovery_binding == binding
    _management_environment(home, monkeypatch)
    assert cli.main(["reset", "--force", "--nuke-secrets"]) == 1
    assert bundle.is_dir()

    assert (
        cli.main(
            [
                "recovery",
                "destroy-retired-installation",
                "--operation",
                operation,
                "--confirm-manifest-digest",
                "0" * 64,
            ],
        )
        == 1
    )
    assert bundle.is_dir()

    assert (
        cli.main(
            [
                "recovery",
                "destroy-retired-installation",
                "--operation",
                operation,
                "--confirm-manifest-digest",
                binding["old_bundle_manifest_digest"],
            ],
        )
        == 0
    )
    assert not bundle.exists()
    assert _state(home).retired_recovery_binding is None
    assert "logical removal complete" in capsys.readouterr().out


@pytest.mark.parametrize(
    "crash_edge",
    ["after_first_move", "before_new_bootstrap"],
)
def test_packaged_nuke_resumes_exact_journal_after_crash(
    tmp_path: Path,
    monkeypatch,
    crash_edge: str,
) -> None:  # type: ignore[no-untyped-def]
    home = tmp_path / "z4j-home"
    ensure_secret_store_directory(home)
    _bootstrap_packaged(home, monkeypatch)
    _management_environment(home, monkeypatch)

    real_write = retirement_module._write_canonical_json
    crashed = False

    def crash_after_durable_edge(
        path: Path,
        value: dict[str, object],
    ) -> None:
        nonlocal crashed
        real_write(path, value)
        moved = value.get("moved")
        should_crash = (
            crash_edge == "after_first_move"
            and value.get("state") == "RETIRING"
            and isinstance(moved, list)
            and len(moved) == 1
        ) or (crash_edge == "before_new_bootstrap" and value.get("state") == "BOOTSTRAPPING_NEW")
        if should_crash and not crashed:
            crashed = True
            raise RuntimeError(f"injected {crash_edge}")

    monkeypatch.setattr(
        retirement_module,
        "_write_canonical_json",
        crash_after_durable_edge,
    )
    assert cli.main(["reset", "--force", "--nuke-secrets"]) == 1
    assert crashed
    with pytest.raises(
        retirement_module.InstallationRetirementRefused,
        match="unfinished",
    ):
        retirement_module.assert_no_pending_installation_retirement(home)

    monkeypatch.setattr(
        retirement_module,
        "_write_canonical_json",
        real_write,
    )
    _management_environment(home, monkeypatch)
    assert cli.main(["reset", "--force", "--nuke-secrets"]) == 0
    binding = _state(home).retired_recovery_binding
    assert binding is not None
    assert binding["status"] == "RECOVERABLE"
    assert (home / "retired-installations" / binding["operation_id"] / "z4j.db").is_file()


def test_retired_destruction_resumes_after_manifested_unlink_crash(
    tmp_path: Path,
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    home = tmp_path / "z4j-home"
    ensure_secret_store_directory(home)
    _bootstrap_packaged(home, monkeypatch)
    _management_environment(home, monkeypatch)
    assert cli.main(["reset", "--force", "--nuke-secrets"]) == 0
    binding = _state(home).retired_recovery_binding
    assert binding is not None
    operation = binding["operation_id"]
    digest = binding["old_bundle_manifest_digest"]
    _management_environment(home, monkeypatch)

    real_unlink = retirement_module._unlink_retired_artifact
    crashed = False

    def crash_after_unlink(path: Path) -> None:
        nonlocal crashed
        real_unlink(path)
        if not crashed:
            crashed = True
            raise RuntimeError("injected unlink crash")

    monkeypatch.setattr(
        retirement_module,
        "_unlink_retired_artifact",
        crash_after_unlink,
    )
    assert (
        cli.main(
            [
                "recovery",
                "destroy-retired-installation",
                "--operation",
                operation,
                "--confirm-manifest-digest",
                digest,
            ],
        )
        == 1
    )
    assert crashed
    destroying = _state(home).retired_recovery_binding
    assert destroying is not None
    assert destroying["status"] == "DESTROYING"

    monkeypatch.setattr(
        retirement_module,
        "_unlink_retired_artifact",
        real_unlink,
    )
    _management_environment(home, monkeypatch)
    assert (
        cli.main(
            [
                "recovery",
                "destroy-retired-installation",
                "--operation",
                operation,
                "--confirm-manifest-digest",
                digest,
            ],
        )
        == 0
    )
    assert _state(home).retired_recovery_binding is None


def test_retired_destruction_reconciles_after_signed_completion_crash(
    tmp_path: Path,
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    home = tmp_path / "z4j-home"
    ensure_secret_store_directory(home)
    _bootstrap_packaged(home, monkeypatch)
    _management_environment(home, monkeypatch)
    assert cli.main(["reset", "--force", "--nuke-secrets"]) == 0
    binding = _state(home).retired_recovery_binding
    assert binding is not None
    operation = binding["operation_id"]
    digest = binding["old_bundle_manifest_digest"]
    destruction_name = f"{retirement_module.DESTRUCTION_JOURNAL_PREFIX}{operation}.json"

    real_unlink = retirement_module._unlink_exact_file
    crashed = False

    def crash_before_outside_journal_cleanup(
        path: Path,
        *,
        expected_identity: tuple[int, int] | None = None,
        missing_ok: bool = False,
    ) -> bool:
        nonlocal crashed
        if path.name == destruction_name and not crashed:
            crashed = True
            raise RuntimeError("injected after signed completion")
        return real_unlink(
            path,
            expected_identity=expected_identity,
            missing_ok=missing_ok,
        )

    monkeypatch.setattr(
        retirement_module,
        "_unlink_exact_file",
        crash_before_outside_journal_cleanup,
    )
    _management_environment(home, monkeypatch)
    args = [
        "recovery",
        "destroy-retired-installation",
        "--operation",
        operation,
        "--confirm-manifest-digest",
        digest,
    ]
    assert cli.main(args) == 1
    assert crashed
    assert _state(home).retired_recovery_binding is None
    assert not (home / "retired-installations" / operation).exists()
    assert (home / destruction_name).is_file()

    monkeypatch.setattr(
        retirement_module,
        "_unlink_exact_file",
        real_unlink,
    )
    _management_environment(home, monkeypatch)
    assert cli.main(args) == 0
    assert not (home / destruction_name).exists()


def test_restore_and_second_nuke_refuse_unresolved_recovery_binding(
    tmp_path: Path,
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    home = tmp_path / "z4j-home"
    ensure_secret_store_directory(home)
    _bootstrap_packaged(home, monkeypatch)
    _management_environment(home, monkeypatch)
    assert cli.main(["reset", "--force", "--nuke-secrets"]) == 0
    binding = _state(home).retired_recovery_binding
    assert binding is not None

    database_url = f"sqlite+aiosqlite:///{home / 'z4j.db'}"
    backup = tmp_path / "replacement-source.db"
    backup_sqlite(database_url, backup)
    before = restore_module._file_digest(home / "z4j.db")
    with pytest.raises(
        restore_module.DatabaseRestoreRefused,
        match="retired installation recovery binding is unresolved",
    ):
        restore_sqlite(database_url, backup)
    assert restore_module._file_digest(home / "z4j.db") == before

    _management_environment(home, monkeypatch)
    assert cli.main(["reset", "--force", "--nuke-secrets"]) == 1
    assert (home / "retired-installations" / binding["operation_id"]).is_dir()


def test_packaged_nuke_refuses_explicit_secret_before_mutation(
    tmp_path: Path,
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    home = tmp_path / "z4j-home"
    ensure_secret_store_directory(home)
    _bootstrap_packaged(home, monkeypatch)
    database_before = restore_module._file_digest(home / "z4j.db")
    store_before = read_secret_store(home / "secret.env").values
    _management_environment(home, monkeypatch)
    monkeypatch.setenv("Z4J_SECRET", "explicit-override-" + "x" * 48)

    assert cli.main(["reset", "--force", "--nuke-secrets"]) == 1
    assert restore_module._file_digest(home / "z4j.db") == database_before
    assert read_secret_store(home / "secret.env").values == store_before
    assert not (home / retirement_module.RETIREMENT_JOURNAL_NAME).exists()


@pytest.mark.parametrize(
    "database_url",
    [
        "sqlite+aiosqlite:///{custom}",
        "postgresql+asyncpg://z4j:secret@127.0.0.1/z4j",
    ],
)
def test_packaged_nuke_refuses_external_database_before_mutation(
    tmp_path: Path,
    monkeypatch,
    database_url: str,
) -> None:  # type: ignore[no-untyped-def]
    home = ensure_secret_store_directory(tmp_path / "z4j-home")
    _bootstrap_packaged(home, monkeypatch)
    database_before = restore_module._file_digest(home / "z4j.db")
    store_before = read_secret_store(home / "secret.env").values
    _management_environment(home, monkeypatch)
    monkeypatch.setenv(
        "Z4J_DATABASE_URL",
        database_url.format(custom=tmp_path / "custom.db"),
    )

    assert cli.main(["reset", "--force", "--nuke-secrets"]) == 1
    assert restore_module._file_digest(home / "z4j.db") == database_before
    assert read_secret_store(home / "secret.env").values == store_before
    assert not (home / retirement_module.RETIREMENT_JOURNAL_NAME).exists()


def test_retired_destroy_refuses_unexpected_entry_before_signed_intent(
    tmp_path: Path,
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    home = tmp_path / "z4j-home"
    ensure_secret_store_directory(home)
    _bootstrap_packaged(home, monkeypatch)
    _management_environment(home, monkeypatch)
    assert cli.main(["reset", "--force", "--nuke-secrets"]) == 0
    binding = _state(home).retired_recovery_binding
    assert binding is not None
    bundle = home / "retired-installations" / binding["operation_id"]
    unexpected = bundle / "unexpected"
    unexpected.write_bytes(b"must survive refusal")
    unexpected.chmod(0o600)
    _management_environment(home, monkeypatch)

    assert (
        cli.main(
            [
                "recovery",
                "destroy-retired-installation",
                "--operation",
                binding["operation_id"],
                "--confirm-manifest-digest",
                binding["old_bundle_manifest_digest"],
            ],
        )
        == 1
    )
    assert unexpected.read_bytes() == b"must survive refusal"
    assert _state(home).retired_recovery_binding == binding


@pytest.mark.parametrize(
    "mutation",
    ["changed", "symlink", "live-hardlink-alias"],
)
def test_retired_destroy_refuses_changed_or_aliased_artifact(
    tmp_path: Path,
    monkeypatch,
    mutation: str,
) -> None:  # type: ignore[no-untyped-def]
    home = ensure_secret_store_directory(tmp_path / "z4j-home")
    _bootstrap_packaged(home, monkeypatch)
    _management_environment(home, monkeypatch)
    assert cli.main(["reset", "--force", "--nuke-secrets"]) == 0
    binding = _state(home).retired_recovery_binding
    assert binding is not None
    retired_database = home / "retired-installations" / binding["operation_id"] / "z4j.db"
    live_database = home / "z4j.db"
    live_before = live_database.read_bytes()
    if mutation == "changed":
        retired_database.write_bytes(b"changed retired database")
        retired_database.chmod(0o600)
    else:
        retired_database.unlink()
        if mutation == "symlink":
            retired_database.symlink_to(live_database)
        else:
            os.link(live_database, retired_database)
    _management_environment(home, monkeypatch)

    assert (
        cli.main(
            [
                "recovery",
                "destroy-retired-installation",
                "--operation",
                binding["operation_id"],
                "--confirm-manifest-digest",
                binding["old_bundle_manifest_digest"],
            ],
        )
        == 1
    )
    assert live_database.read_bytes() == live_before
    assert _state(home).retired_recovery_binding == binding
