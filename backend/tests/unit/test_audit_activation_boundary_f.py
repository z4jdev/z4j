"""Executable gates for the manifest-bound Boundary-F cutover."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import stat
import subprocess
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text, update
from sqlalchemy.exc import IntegrityError, OperationalError
from z4j_brain import cli
from z4j_brain.configuration import capture_configuration
from z4j_brain.domain import audit_activation
from z4j_brain.domain.audit_activation import (
    _manifest_digest,
    read_activation_manifest,
    write_activation_manifest,
)
from z4j_brain.domain.audit_chain import (
    AuditChainIntegrityError,
    canonical_audit_key_id,
)
from z4j_brain.domain.audit_service import AuditEntry, AuditService
from z4j_brain.persistence.models import AuditLog
from z4j_brain.settings import Settings

from tests.migration_head import code_head

_SQLITE_AUDIT_UPDATE_TRIGGER_SQL = """
CREATE TRIGGER audit_log_boundary_f_no_update
BEFORE UPDATE ON audit_log
FOR EACH ROW
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only');
END
"""


def _io_test_manifest() -> dict[str, object]:
    payload: dict[str, object] = {"format_version": 1, "io_oracle": True}
    return {**payload, "manifest_digest": _manifest_digest(payload)}


@pytest.mark.skipif(os.name != "nt", reason="native Windows ACL oracle")
def test_windows_activation_manifest_uses_private_handle_relative_io(
    tmp_path: Path,
) -> None:
    subprocess.run(
        [
            "icacls.exe",
            str(tmp_path),
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)(F)",
            "*S-1-5-32-544:(OI)(CI)(F)",
            "*S-1-3-4:(OI)(CI)(F)",
        ],
        check=True,
        capture_output=True,
    )
    manifest_path = tmp_path / "activation.json"

    write_activation_manifest(manifest_path, _io_test_manifest())

    assert read_activation_manifest(manifest_path)["io_oracle"] is True


@pytest.mark.skipif(os.name != "nt", reason="native Windows ACL oracle")
def test_windows_activation_manifest_rejects_broad_parent(tmp_path: Path) -> None:
    subprocess.run(
        [
            "icacls.exe",
            str(tmp_path),
            "/grant",
            "*S-1-1-0:(OI)(CI)(F)",
        ],
        check=True,
        capture_output=True,
    )
    manifest_path = tmp_path / "activation.json"

    with pytest.raises(OSError, match="non-owner trustee"):
        write_activation_manifest(manifest_path, _io_test_manifest())

    assert not manifest_path.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission oracle")
def test_activation_manifest_read_rejects_parent_made_permissive(
    tmp_path: Path,
) -> None:
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir(mode=0o700)
    manifest_path = manifest_dir / "activation.json"
    write_activation_manifest(manifest_path, _io_test_manifest())
    manifest_dir.chmod(0o755)

    with pytest.raises(AuditChainIntegrityError, match=r"parent.*owner-private"):
        read_activation_manifest(manifest_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor oracle")
def test_activation_manifest_write_rejects_ancestor_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir(mode=0o700)
    moved_dir = tmp_path / "moved"
    replacement_dir = tmp_path / "replacement"
    replacement_dir.mkdir(mode=0o700)
    manifest_path = manifest_dir / "activation.json"
    real_open = audit_activation.os.open
    swapped = False

    def swapping_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        fd = real_open(path, flags, mode, dir_fd=dir_fd)
        if not swapped and dir_fd is not None and path == manifest_dir.name:
            swapped = True
            manifest_dir.rename(moved_dir)
            manifest_dir.symlink_to(replacement_dir, target_is_directory=True)
        return fd

    monkeypatch.setattr(audit_activation.os, "open", swapping_open)

    with pytest.raises(AuditChainIntegrityError, match="parent changed"):
        write_activation_manifest(manifest_path, _io_test_manifest())

    assert not (moved_dir / manifest_path.name).exists()
    assert not (replacement_dir / manifest_path.name).exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor oracle")
def test_activation_manifest_rejects_symlinked_ancestor(tmp_path: Path) -> None:
    real_ancestor = tmp_path / "real"
    real_ancestor.mkdir(mode=0o700)
    manifest_dir = real_ancestor / "manifests"
    manifest_dir.mkdir(mode=0o700)
    manifest_path = manifest_dir / "activation.json"
    write_activation_manifest(manifest_path, _io_test_manifest())
    linked_ancestor = tmp_path / "linked"
    linked_ancestor.symlink_to(real_ancestor, target_is_directory=True)
    linked_manifest = linked_ancestor / "manifests" / manifest_path.name

    with pytest.raises(AuditChainIntegrityError, match=r"parent path.*real directories"):
        read_activation_manifest(linked_manifest)
    with pytest.raises(AuditChainIntegrityError, match=r"parent path.*real directories"):
        write_activation_manifest(
            linked_manifest.with_name("second.json"),
            _io_test_manifest(),
        )

    assert not (manifest_dir / "second.json").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor oracle")
def test_activation_parent_walk_consumes_close_attempts_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened_fds = iter((100, 101, 102))
    close_calls: list[int] = []

    def succeeding_open(
        _path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        _flags: int,
        _mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        del dir_fd
        return next(opened_fds)

    def failing_close(file_descriptor: int) -> None:
        close_calls.append(file_descriptor)
        if file_descriptor in {101, 102}:
            raise OSError(f"forced close failure {file_descriptor}")

    monkeypatch.setattr(audit_activation.os, "open", succeeding_open)
    monkeypatch.setattr(audit_activation.os, "close", failing_close)

    with pytest.raises(OSError, match="forced close failure 101"):
        audit_activation._open_activation_parent_walk(Path("/first/second"))

    assert close_calls == [101, 100, 102]
    assert len(close_calls) == len(set(close_calls))

    primary_open_calls = 0
    primary_close_calls: list[int] = []

    def primary_failing_open(
        _path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        _flags: int,
        _mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal primary_open_calls
        del dir_fd
        primary_open_calls += 1
        if primary_open_calls == 3:
            raise OSError("forced primary open failure")
        return 199 + primary_open_calls

    def cleanup_failing_close(file_descriptor: int) -> None:
        primary_close_calls.append(file_descriptor)
        raise OSError(f"forced cleanup close failure {file_descriptor}")

    monkeypatch.setattr(audit_activation.os, "open", primary_failing_open)
    monkeypatch.setattr(audit_activation.os, "close", cleanup_failing_close)

    with pytest.raises(OSError, match="forced primary open failure"):
        audit_activation._open_activation_parent_walk(Path("/first/second"))

    assert primary_close_calls == [201, 200]
    assert len(primary_close_calls) == len(set(primary_close_calls))


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor oracle")
def test_activation_manifest_read_rejects_entry_swap_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir(mode=0o700)
    manifest_path = manifest_dir / "activation.json"
    write_activation_manifest(manifest_path, _io_test_manifest())
    replacement = manifest_dir / "replacement.json"
    replacement.write_bytes(manifest_path.read_bytes())
    replacement.chmod(0o600)
    displaced = manifest_dir / "displaced.json"
    real_open = audit_activation.os.open
    swapped = False

    def swapping_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        fd = real_open(path, flags, mode, dir_fd=dir_fd)
        if not swapped and dir_fd is not None and path == manifest_path.name:
            swapped = True
            manifest_path.rename(displaced)
            replacement.rename(manifest_path)
        return fd

    monkeypatch.setattr(audit_activation.os, "open", swapping_open)

    with pytest.raises(AuditChainIntegrityError, match="pathname changed"):
        read_activation_manifest(manifest_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO oracle")
def test_activation_manifest_read_rejects_fifo_swap_without_blocking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir(mode=0o700)
    manifest_path = manifest_dir / "activation.json"
    write_activation_manifest(manifest_path, _io_test_manifest())
    displaced = manifest_dir / "displaced.json"
    real_open = audit_activation.os.open
    swapped = False
    observed_nonblocking = False

    def swapping_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal observed_nonblocking, swapped
        if not swapped and dir_fd is not None and path == manifest_path.name:
            swapped = True
            observed_nonblocking = bool(flags & os.O_NONBLOCK)
            manifest_path.rename(displaced)
            os.mkfifo(manifest_path, mode=0o600)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(audit_activation.os, "open", swapping_open)

    with pytest.raises(AuditChainIntegrityError, match="descriptor was acquired"):
        read_activation_manifest(manifest_path)

    assert observed_nonblocking
    assert stat.S_ISFIFO(manifest_path.lstat().st_mode)


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-link oracle")
def test_activation_manifest_read_rejects_hard_link(tmp_path: Path) -> None:
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir(mode=0o700)
    manifest_path = manifest_dir / "activation.json"
    write_activation_manifest(manifest_path, _io_test_manifest())
    os.link(manifest_path, manifest_dir / "second-link.json")

    with pytest.raises(AuditChainIntegrityError, match="single-link"):
        read_activation_manifest(manifest_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX write oracle")
def test_activation_manifest_zero_progress_write_is_retained_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir(mode=0o700)
    manifest_path = manifest_dir / "activation.json"
    monkeypatch.setattr(audit_activation.os, "write", lambda _fd, _payload: 0)

    with pytest.raises(AuditChainIntegrityError, match="made no progress"):
        write_activation_manifest(manifest_path, _io_test_manifest())

    retained = manifest_path.lstat()
    assert stat.S_ISREG(retained.st_mode)
    assert stat.S_IMODE(retained.st_mode) == 0o600
    assert retained.st_nlink == 1
    assert retained.st_size == 0
    with pytest.raises(FileExistsError):
        write_activation_manifest(manifest_path, _io_test_manifest())


@pytest.mark.skipif(os.name != "posix", reason="POSIX durability oracle")
def test_activation_manifest_directory_fsync_failure_retains_unreadable_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir(mode=0o700)
    manifest_path = manifest_dir / "activation.json"
    real_fsync = audit_activation.os.fsync

    def failing_directory_fsync(file_descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(file_descriptor).st_mode):
            raise OSError("forced activation-directory fsync failure")
        real_fsync(file_descriptor)

    monkeypatch.setattr(audit_activation.os, "fsync", failing_directory_fsync)

    with pytest.raises(OSError, match="activation-directory fsync failure"):
        write_activation_manifest(manifest_path, _io_test_manifest())

    retained = manifest_path.lstat()
    assert stat.S_ISREG(retained.st_mode)
    assert stat.S_IMODE(retained.st_mode) == 0o600
    assert retained.st_nlink == 1
    assert retained.st_size == 0
    with pytest.raises(AuditChainIntegrityError, match="not strict JSON"):
        read_activation_manifest(manifest_path)
    with pytest.raises(FileExistsError):
        write_activation_manifest(manifest_path, _io_test_manifest())


@pytest.mark.skipif(os.name != "posix", reason="POSIX durability oracle")
def test_activation_manifest_write_rechecks_entry_after_directory_fsync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir(mode=0o700)
    manifest_path = manifest_dir / "activation.json"
    replacement = manifest_dir / "replacement.json"
    replacement.write_bytes(b"attacker replacement\n")
    replacement.chmod(0o600)
    displaced = manifest_dir / "displaced.json"
    real_fsync = audit_activation.os.fsync
    swapped = False

    def swapping_directory_fsync(file_descriptor: int) -> None:
        nonlocal swapped
        real_fsync(file_descriptor)
        if not swapped and stat.S_ISDIR(os.fstat(file_descriptor).st_mode):
            swapped = True
            manifest_path.rename(displaced)
            replacement.rename(manifest_path)

    monkeypatch.setattr(audit_activation.os, "fsync", swapping_directory_fsync)

    with pytest.raises(AuditChainIntegrityError, match="durably finalized"):
        write_activation_manifest(manifest_path, _io_test_manifest())

    # Failure handling never unlinks by pathname: POSIX cannot make an
    # identity-conditional unlink atomic, so it must not delete the replacement.
    assert manifest_path.read_bytes() == b"attacker replacement\n"
    assert displaced.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX parent ctime oracle")
def test_activation_manifest_read_rejects_parent_metadata_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir(mode=0o700)
    manifest_path = manifest_dir / "activation.json"
    write_activation_manifest(manifest_path, _io_test_manifest())
    real_read = audit_activation.os.read
    changed = False

    def changing_read(file_descriptor: int, length: int) -> bytes:
        nonlocal changed
        chunk = real_read(file_descriptor, length)
        if not changed:
            changed = True
            transient = manifest_dir / "transient"
            transient.write_bytes(b"x")
            transient.unlink()
        return chunk

    monkeypatch.setattr(audit_activation.os, "read", changing_read)

    with pytest.raises(AuditChainIntegrityError, match="parent changed"):
        read_activation_manifest(manifest_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file ctime oracle")
def test_activation_manifest_read_rejects_restored_file_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir(mode=0o700)
    manifest_path = manifest_dir / "activation.json"
    write_activation_manifest(manifest_path, _io_test_manifest())
    real_read = audit_activation.os.read
    changed = False

    def changing_read(file_descriptor: int, length: int) -> bytes:
        nonlocal changed
        chunk = real_read(file_descriptor, length)
        if not changed:
            changed = True
            manifest_path.chmod(0o400)
            manifest_path.chmod(0o600)
        return chunk

    monkeypatch.setattr(audit_activation.os, "read", changing_read)

    with pytest.raises(AuditChainIntegrityError, match="changed while read"):
        read_activation_manifest(manifest_path)


@pytest.fixture
def activation_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[Config, str, Path]]:
    private_home = Path(
        tempfile.mkdtemp(prefix="z4j-activation-", dir="/tmp"),
    )
    private_home.chmod(0o700)
    db_path = private_home / "z4j.db"
    sync_url = f"sqlite:///{db_path}"
    async_url = f"sqlite+aiosqlite:///{db_path}"
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir(mode=0o700)

    backend_root = Path(__file__).resolve().parents[2]
    alembic_ini = backend_root / "alembic.ini"
    monkeypatch.setenv("Z4J_ALEMBIC_INI", str(alembic_ini))
    monkeypatch.setenv("Z4J_DATABASE_URL", async_url)
    monkeypatch.setenv("Z4J_SECRET", "x" * 64)
    monkeypatch.setenv("Z4J_SESSION_SECRET", "y" * 64)
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", "a" * 64)
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.chdir(backend_root)

    cfg = Config(str(alembic_ini))
    cfg.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    try:
        yield cfg, sync_url, manifest_dir
    finally:
        shutil.rmtree(private_home, ignore_errors=True)


def _insert_linked_legacy_genesis(sync_url: str) -> uuid.UUID:
    row_id = uuid.uuid4()
    occurred_at = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)
    settings = Settings()  # type: ignore[call-arg]
    entry = AuditEntry(
        id=row_id,
        action="legacy.test",
        target_type="test",
        target_id="one",
        result="success",
        outcome="allow",
        event_id=None,
        user_id=None,
        project_id=None,
        source_ip=None,
        user_agent=None,
        metadata={"legacy": True},
        occurred_at=occurred_at,
        prev_row_hmac=None,
        api_key_id=None,
    )
    row_hmac = AuditService(settings)._compute_hmac(entry)
    engine = create_engine(sync_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                AuditLog.__table__.insert().values(
                    id=row_id,
                    action=entry.action,
                    target_type=entry.target_type,
                    target_id=entry.target_id,
                    result=entry.result,
                    metadata=entry.metadata,
                    occurred_at=occurred_at,
                    outcome=entry.outcome,
                    event_id=None,
                    row_hmac=row_hmac,
                    prev_row_hmac=None,
                    project_id=None,
                    user_id=None,
                    api_key_id=None,
                    source_ip=None,
                    user_agent=None,
                ),
            )
    finally:
        engine.dispose()
    return row_id


def _legacy_values(
    *,
    action: str,
    occurred_at: datetime,
    prev_row_hmac: str | None,
) -> tuple[AuditEntry, dict[str, object]]:
    settings = Settings()  # type: ignore[call-arg]
    entry = AuditEntry(
        id=uuid.uuid4(),
        action=action,
        target_type="test",
        target_id=action,
        result="success",
        outcome="allow",
        event_id=None,
        user_id=None,
        project_id=None,
        source_ip=None,
        user_agent=None,
        metadata={"legacy": action},
        occurred_at=occurred_at,
        prev_row_hmac=prev_row_hmac,
        api_key_id=None,
    )
    row_hmac = AuditService(settings)._compute_hmac(entry)
    return entry, {
        "id": entry.id,
        "project_id": None,
        "user_id": None,
        "api_key_id": None,
        "action": entry.action,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "result": entry.result,
        "metadata": entry.metadata,
        "source_ip": None,
        "user_agent": None,
        "occurred_at": entry.occurred_at,
        "outcome": entry.outcome,
        "event_id": None,
        "row_hmac": row_hmac,
        "prev_row_hmac": entry.prev_row_hmac,
    }


def _insert_fork_quarantine_fixture(
    sync_url: str,
    *,
    include_api_key_id: bool,
    duplicate_id: bool = False,
) -> uuid.UUID:
    base_time = datetime(2026, 7, 2, 12, 0, tzinfo=UTC)
    genesis, genesis_values = _legacy_values(
        action="legacy.genesis",
        occurred_at=base_time,
        prev_row_hmac=None,
    )
    genesis_hmac = str(genesis_values["row_hmac"])
    _main_child, main_values = _legacy_values(
        action="legacy.main-child",
        occurred_at=base_time + timedelta(seconds=1),
        prev_row_hmac=genesis_hmac,
    )
    fork, fork_values = _legacy_values(
        action="legacy.fork-child",
        occurred_at=base_time + timedelta(seconds=2),
        prev_row_hmac=genesis_hmac,
    )
    fork_id = fork.id
    if duplicate_id:
        fork_values["id"] = genesis.id
        fork_id = genesis.id

    columns_15 = (
        "project_id",
        "user_id",
        "action",
        "target_type",
        "target_id",
        "result",
        "metadata",
        "source_ip",
        "user_agent",
        "occurred_at",
        "outcome",
        "event_id",
        "row_hmac",
        "prev_row_hmac",
        "id",
    )
    columns = (
        ("project_id", "user_id", "api_key_id", *columns_15[2:])
        if include_api_key_id
        else columns_15
    )
    engine = create_engine(sync_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                AuditLog.__table__.insert(),
                [genesis_values, main_values],
            )
            column_sql = ", ".join(columns)
            connection.exec_driver_sql(
                "CREATE TABLE audit_log_legacy_forks AS "
                f"SELECT {column_sql} FROM audit_log WHERE 1=0",
            )
            persisted_fork = {
                key: (
                    json.dumps(value)
                    if key == "metadata"
                    else value.isoformat(timespec="microseconds")
                    if key == "occurred_at"
                    else str(value)
                    if key == "id"
                    else value
                )
                for key, value in fork_values.items()
                if key in columns
            }
            placeholders = ", ".join("?" for _ in columns)
            connection.exec_driver_sql(
                f"INSERT INTO audit_log_legacy_forks ({column_sql}) VALUES ({placeholders})",
                tuple(persisted_fork[column] for column in columns),
            )
    finally:
        engine.dispose()
    assert fork_id is not None
    return fork_id


def _prepare(cfg: Config) -> None:
    command.upgrade(cfg, "v1_8_bulk_retry_requests")


def _finish_preparation(cfg: Config) -> None:
    command.upgrade(cfg, "v1_8_audit_chain_prepare")


def test_supplied_snapshot_is_the_only_migration_key_source(
    activation_install: tuple[Config, str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg, sync_url, _manifest_dir = activation_install
    supplied_audit_secret = "snapshot-audit-key-" + "s" * 48
    ambient_audit_secret = "ambient-audit-key-" + "a" * 48
    home = Path(os.environ["Z4J_HOME"])
    snapshot = capture_configuration(
        home=home,
        cwd=home,
        process_environment={
            "Z4J_DATABASE_URL": sync_url.replace("sqlite:///", "sqlite+aiosqlite:///"),
            "Z4J_SECRET": "x" * 64,
            "Z4J_SESSION_SECRET": "y" * 64,
            "Z4J_AUDIT_CHAIN_SECRET": supplied_audit_secret,
            "Z4J_ENVIRONMENT": "dev",
        },
        include_secret_store=False,
    )
    cfg.attributes["z4j_configuration_snapshot"] = snapshot
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", ambient_audit_secret)

    command.upgrade(cfg, "v1_8_audit_chain_prepare")

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            persisted_key_id = connection.execute(
                text("SELECT audit_key_id FROM audit_chain_preparation"),
            ).scalar_one()
    finally:
        engine.dispose()
    assert persisted_key_id == canonical_audit_key_id(supplied_audit_secret.encode())
    assert persisted_key_id != canonical_audit_key_id(ambient_audit_secret.encode())


def test_supplied_snapshot_remains_bound_through_fresh_activation(
    activation_install: tuple[Config, str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg, sync_url, _manifest_dir = activation_install
    supplied_audit_secret = "snapshot-activation-key-" + "s" * 48
    ambient_audit_secret = "ambient-activation-key-" + "a" * 48
    home = Path(os.environ["Z4J_HOME"])
    snapshot = capture_configuration(
        home=home,
        cwd=home,
        process_environment={
            "Z4J_DATABASE_URL": sync_url.replace("sqlite:///", "sqlite+aiosqlite:///"),
            "Z4J_SECRET": "x" * 64,
            "Z4J_SESSION_SECRET": "y" * 64,
            "Z4J_AUDIT_CHAIN_SECRET": supplied_audit_secret,
            "Z4J_ENVIRONMENT": "dev",
        },
        include_secret_store=False,
    )
    cfg.attributes["z4j_configuration_snapshot"] = snapshot
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", ambient_audit_secret)

    command.upgrade(cfg, "head")

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            version = connection.execute(
                text("SELECT version_num FROM alembic_version"),
            ).scalar_one()
            state_key_id = connection.execute(
                text("SELECT state_key_id FROM audit_chain_state"),
            ).scalar_one()
    finally:
        engine.dispose()
    assert version == code_head()
    assert state_key_id == canonical_audit_key_id(supplied_audit_secret.encode())
    assert state_key_id != canonical_audit_key_id(ambient_audit_secret.encode())


def test_activated_sqlite_blocks_actual_pre18_append_and_retention_delete(
    activation_install: tuple[Config, str, Path],
) -> None:
    cfg, sync_url, _manifest_dir = activation_install
    command.upgrade(cfg, "head")
    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            trigger_names = {
                str(row[0])
                for row in connection.execute(
                    text(
                        "SELECT name FROM sqlite_schema "
                        "WHERE type = 'trigger' "
                        "AND tbl_name IN ('audit_log', 'audit_chain_state')",
                    ),
                )
            }
            rows_before = int(
                connection.execute(text("SELECT COUNT(*) FROM audit_log")).scalar_one(),
            )
            state_before = connection.execute(
                text(
                    "SELECT generation, active_row_count, state_mac FROM audit_chain_state",
                ),
            ).one()

        assert {
            "audit_log_boundary_f_no_insert",
            "audit_log_boundary_f_no_update",
            "audit_log_boundary_f_no_delete",
            "audit_chain_state_boundary_f_no_update",
            "audit_chain_state_boundary_f_no_delete",
        } <= trigger_names

        # This is the SQL shape issued by the pre-1.8 retention writer.  The
        # old process has no Boundary-F connection-local transition function,
        # so an activated database must reject it before one row commits.
        with (
            pytest.raises(
                OperationalError,
                match=r"z4j_audit_guard|signer-managed",
            ),
            engine.begin() as connection,
        ):
            connection.execute(
                text(
                    "DELETE FROM audit_log WHERE id IN (SELECT id FROM audit_log LIMIT 1)",
                ),
            )

        with (
            pytest.raises(
                OperationalError,
                match=r"z4j_audit_guard|signer-managed",
            ),
            engine.begin() as connection,
        ):
            connection.execute(
                text(
                    "INSERT INTO audit_log "
                    "(id, action, target_type, result, metadata, occurred_at) "
                    "VALUES (:id, 'legacy.append', 'test', 'success', "
                    "'{}', :occurred_at)",
                ),
                {
                    "id": uuid.uuid4().hex,
                    "occurred_at": datetime.now(UTC).isoformat(),
                },
            )

        with (
            pytest.raises(
                IntegrityError,
                match="audit_log is append-only",
            ),
            engine.begin() as connection,
        ):
            connection.execute(
                text(
                    "UPDATE audit_log SET action = 'legacy.tamper' "
                    "WHERE id = (SELECT id FROM audit_log LIMIT 1)",
                ),
            )

        for statement in (
            "UPDATE audit_chain_state SET active_row_count = active_row_count + 1",
            "DELETE FROM audit_chain_state",
        ):
            with (
                pytest.raises(
                    OperationalError,
                    match=r"z4j_audit_guard|signer-managed",
                ),
                engine.begin() as connection,
            ):
                connection.execute(text(statement))

        with engine.connect() as connection:
            assert (
                int(connection.execute(text("SELECT COUNT(*) FROM audit_log")).scalar_one())
                == rows_before
            )
            assert (
                connection.execute(
                    text(
                        "SELECT generation, active_row_count, state_mac FROM audit_chain_state",
                    ),
                ).one()
                == state_before
            )
    finally:
        engine.dispose()


def test_linked_manifest_applies_and_full_verifies(
    activation_install: tuple[Config, str, Path],
) -> None:
    cfg, sync_url, manifest_dir = activation_install
    _prepare(cfg)
    legacy_id = _insert_linked_legacy_genesis(sync_url)
    _finish_preparation(cfg)
    manifest_path = manifest_dir / "linked.json"

    assert (
        cli.main(
            [
                "audit",
                "activate-chain-state",
                "--manifest",
                str(manifest_path),
            ],
        )
        == 0
    )
    manifest = read_activation_manifest(manifest_path)
    assert manifest["requires_ambiguity_attestation"] is False
    assert manifest["classification_failures"] == []
    assert len(manifest["classifications"]) == 1
    classification = manifest["classifications"][0]
    assert classification["hmac_key_id"] == canonical_audit_key_id(b"x" * 64)
    assert classification["hmac_version"] == 1
    assert classification["id"] == str(legacy_id)
    assert classification["legacy_integrity_class"] == "legacy-linked-verified"
    assert classification["legacy_origin"] == "audit-log:preparation-v1"
    assert classification["frozen_snapshot"]["id"] == str(legacy_id)

    assert (
        cli.main(
            [
                "audit",
                "activate-chain-state",
                "--manifest",
                str(manifest_path),
                "--apply",
            ],
        )
        == 0
    )

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT version_num FROM alembic_version"),
                ).scalar_one()
                == code_head()
            )
            frozen = connection.execute(
                AuditLog.__table__.select()
                .with_only_columns(
                    AuditLog.__table__.c.legacy_frozen,
                    AuditLog.__table__.c.legacy_integrity_class,
                )
                .where(AuditLog.__table__.c.id == legacy_id),
            ).one()
            assert tuple(frozen) == (1, "legacy-linked-verified")
            assert (
                connection.execute(
                    text("SELECT frozen_row_count FROM audit_chain_state"),
                ).scalar_one()
                == 1
            )
    finally:
        engine.dispose()


def _activate_one_frozen_row(
    cfg: Config,
    sync_url: str,
    manifest_dir: Path,
    *,
    manifest_name: str,
) -> uuid.UUID:
    _prepare(cfg)
    legacy_id = _insert_linked_legacy_genesis(sync_url)
    _finish_preparation(cfg)
    manifest_path = manifest_dir / manifest_name
    assert (
        cli.main(
            ["audit", "activate-chain-state", "--manifest", str(manifest_path)],
        )
        == 0
    )
    assert (
        cli.main(
            [
                "audit",
                "activate-chain-state",
                "--manifest",
                str(manifest_path),
                "--apply",
            ],
        )
        == 0
    )
    return legacy_id


def test_frozen_export_delete_is_signed_resumable_and_acknowledged(
    activation_install: tuple[Config, str, Path],
) -> None:
    cfg, sync_url, manifest_dir = activation_install
    legacy_id = _activate_one_frozen_row(
        cfg,
        sync_url,
        manifest_dir,
        manifest_name="export-linked.json",
    )
    operation_id = uuid.uuid4()
    destination = manifest_dir / "frozen-export.json"
    argv = [
        "audit",
        "export-and-delete-frozen",
        "--operation",
        str(operation_id),
        "--destination",
        str(destination),
    ]

    assert cli.main(argv) == 0
    exported = json.loads(destination.read_text())
    assert exported["manifest"]["ordered_ids"] == [str(legacy_id)]
    assert [row["id"] for row in exported["rows"]] == [str(legacy_id)]

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT frozen_row_count FROM audit_chain_state"),
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    text("SELECT COUNT(*) FROM audit_log WHERE legacy_frozen = 1"),
                ).scalar_one()
                == 0
            )
            marker = connection.execute(
                text(
                    "SELECT metadata FROM audit_log WHERE action='audit.frozen_history_exported'",
                ),
            ).scalar_one()
            marker_metadata = json.loads(marker) if isinstance(marker, str) else marker
            assert marker_metadata["operation_id"] == str(operation_id)
            assert marker_metadata["frozen_row_count"] == 1
    finally:
        engine.dispose()

    operation_path = Path(os.environ["Z4J_HOME"]) / "audit-frozen-exports" / str(operation_id)
    phase = json.loads((operation_path / "phase.json").read_text())
    assert phase["phase"] == "DATABASE_COMMITTED"
    assert (operation_path / "frozen-audit-export.json").exists()

    assert (
        cli.main(
            [
                *argv,
                "--acknowledge-destination-digest",
                "0" * 64,
            ],
        )
        == 1
    )
    assert operation_path.exists()
    assert (
        cli.main(
            [
                *argv,
                "--acknowledge-destination-digest",
                phase["export_sha256"],
                "--cleanup",
            ],
        )
        == 0
    )
    assert not operation_path.exists()
    assert destination.exists()


def test_frozen_export_recovers_crash_after_database_commit_without_redelete(
    activation_install: tuple[Config, str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from z4j_brain.domain import audit_frozen_export

    cfg, sync_url, manifest_dir = activation_install
    _activate_one_frozen_row(
        cfg,
        sync_url,
        manifest_dir,
        manifest_name="export-crash.json",
    )
    operation_id = uuid.uuid4()
    destination = manifest_dir / "frozen-crash-export.json"
    argv = [
        "audit",
        "export-and-delete-frozen",
        "--operation",
        str(operation_id),
        "--destination",
        str(destination),
    ]
    original_replace = audit_frozen_export._replace_phase
    injected = False

    def _crash_after_commit(*args: object, **kwargs: object) -> None:
        nonlocal injected
        phase = args[-1]
        if not injected and isinstance(phase, dict) and phase.get("phase") == "DATABASE_COMMITTED":
            injected = True
            raise OSError("injected crash after database commit")
        original_replace(*args, **kwargs)

    monkeypatch.setattr(
        audit_frozen_export,
        "_replace_phase",
        _crash_after_commit,
    )
    assert cli.main(argv) == 1
    monkeypatch.setattr(
        audit_frozen_export,
        "_replace_phase",
        original_replace,
    )

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM audit_log "
                        "WHERE action='audit.frozen_history_exported'",
                    ),
                ).scalar_one()
                == 1
            )
            assert (
                connection.execute(
                    text("SELECT COUNT(*) FROM audit_log WHERE legacy_frozen = 1"),
                ).scalar_one()
                == 0
            )
    finally:
        engine.dispose()

    assert cli.main(argv) == 0
    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM audit_log "
                        "WHERE action='audit.frozen_history_exported'",
                    ),
                ).scalar_one()
                == 1
            )
    finally:
        engine.dispose()


def test_frozen_export_rechecks_every_row_before_delete(
    activation_install: tuple[Config, str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from z4j_brain.domain import audit_frozen_export

    cfg, sync_url, manifest_dir = activation_install
    _activate_one_frozen_row(
        cfg,
        sync_url,
        manifest_dir,
        manifest_name="export-recheck.json",
    )
    operation_id = uuid.uuid4()
    destination = manifest_dir / "frozen-recheck-export.json"
    original_commit = audit_frozen_export._commit_frozen_delete
    injected = False

    async def _mutate_before_transition(*args: object, **kwargs: object) -> bool:
        nonlocal injected
        engine = args[0]
        if not injected:
            injected = True
            async with engine.begin() as connection:
                # Bypass the database guard deliberately so this independent
                # defense-in-depth test still reaches the export signer's
                # authenticated recheck immediately before deletion.
                await connection.execute(
                    text("DROP TRIGGER audit_log_boundary_f_no_update"),
                )
                await connection.execute(
                    update(AuditLog)
                    .where(AuditLog.legacy_frozen.is_(True))
                    .values(audit_metadata={"mutated": True}),
                )
                await connection.execute(
                    text(_SQLITE_AUDIT_UPDATE_TRIGGER_SQL),
                )
        return await original_commit(*args, **kwargs)

    monkeypatch.setattr(
        audit_frozen_export,
        "_commit_frozen_delete",
        _mutate_before_transition,
    )
    assert (
        cli.main(
            [
                "audit",
                "export-and-delete-frozen",
                "--operation",
                str(operation_id),
                "--destination",
                str(destination),
            ],
        )
        == 1
    )

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT COUNT(*) FROM audit_log WHERE legacy_frozen = 1"),
                ).scalar_one()
                == 1
            )
            assert (
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM audit_log "
                        "WHERE action='audit.frozen_history_exported'",
                    ),
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    text("SELECT frozen_row_count FROM audit_chain_state"),
                ).scalar_one()
                == 1
            )
    finally:
        engine.dispose()


def test_frozen_spool_is_not_bounded_by_the_phase_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from z4j_brain.domain import audit_frozen_export

    private_dir = tmp_path / "streaming-spool"
    private_dir.mkdir(mode=0o700)
    operation_id = uuid.uuid4()
    destination_dir = tmp_path / "destination"
    destination_dir.mkdir()
    if os.name == "nt":
        subprocess.run(
            [
                "icacls.exe",
                str(destination_dir),
                "/grant",
                "*S-1-1-0:(OI)(CI)(F)",
            ],
            check=True,
            capture_output=True,
        )
    destination = destination_dir / "streamed-export.json"
    rows = [
        {
            "id": str(uuid.uuid4()),
            "legacy_integrity_class": "legacy-unsigned",
            "padding": "x" * 513,
        },
    ]
    manifest = audit_frozen_export._manifest_from_rows(
        operation_id=operation_id,
        destination=destination,
        state_payload={
            "installation_id": str(uuid.uuid4()),
            "generation": str(uuid.uuid4()),
        },
        rows=rows,
    )
    directory_fd, directory_identity = audit_frozen_export._open_private_directory(
        private_dir,
        create=False,
    )
    spool_fd = -1
    destination_fd = -1
    destination_parent_fd = -1
    try:
        # Make the distinction executable without allocating a 64 MiB test
        # fixture: journal reads remain bounded, while the export spool must
        # traverse as many chunks as necessary.
        monkeypatch.setattr(audit_frozen_export, "_MAX_JOURNAL_BYTES", 32)
        monkeypatch.setattr(audit_frozen_export, "_IO_CHUNK_BYTES", 31)
        created_identity = audit_frozen_export._write_export_spool(
            directory_fd,
            private_dir,
            directory_identity,
            manifest=manifest,
            rows=rows,
        )
        opened = audit_frozen_export._open_export_spool(
            directory_fd,
            private_dir,
            directory_identity,
            required=True,
        )
        assert opened is not None
        (
            spool_fd,
            parsed_manifest,
            parsed_rows,
            spool_identity,
            export_size,
            export_digest,
        ) = opened
        assert spool_identity == created_identity
        assert export_size > audit_frozen_export._MAX_JOURNAL_BYTES
        assert parsed_manifest == manifest
        assert parsed_rows == rows

        (
            destination_fd,
            _destination_identity,
            destination_size,
            destination_digest,
            destination_parent_fd,
            _destination_parent_identity,
        ) = audit_frozen_export._populate_destination(
            destination,
            spool_fd=spool_fd,
            expected_digest=export_digest,
            expected_size=export_size,
            spool_identity=spool_identity,
        )
        assert destination_size == export_size
        assert destination_digest == export_digest
        assert (
            destination.read_bytes() == (private_dir / audit_frozen_export._SPOOL_FILE).read_bytes()
        )
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        if destination_parent_fd >= 0:
            os.close(destination_parent_fd)
        if spool_fd >= 0:
            os.close(spool_fd)
        os.close(directory_fd)


def test_legacy_restore_refuses_boundary_f_before_mutation(
    activation_install: tuple[Config, str, Path],
) -> None:
    import sqlite3

    cfg, sync_url, manifest_dir = activation_install
    _activate_one_frozen_row(
        cfg,
        sync_url,
        manifest_dir,
        manifest_name="management-refusal.json",
    )
    replacement = manifest_dir / "unsafe-replacement.db"
    with closing(sqlite3.connect(replacement)) as connection:
        connection.execute("CREATE TABLE replacement_marker (id INTEGER)")
        connection.execute("INSERT INTO replacement_marker VALUES (1)")
        connection.commit()

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            old_audit_count = connection.execute(
                text("SELECT COUNT(*) FROM audit_log"),
            ).scalar_one()
    finally:
        engine.dispose()

    assert cli.main(["restore", str(replacement), "--force"]) == 1

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT COUNT(*) FROM audit_chain_state"),
                ).scalar_one()
                == 1
            )
            assert (
                connection.execute(
                    text("SELECT COUNT(*) FROM audit_log"),
                ).scalar_one()
                == old_audit_count
            )
            assert (
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM sqlite_schema "
                        "WHERE type='table' AND name='replacement_marker'",
                    ),
                ).scalar_one()
                == 0
            )
    finally:
        engine.dispose()


def test_generation_reset_signs_marker_and_preserves_d_namespaces(
    activation_install: tuple[Config, str, Path],
) -> None:
    from sqlalchemy.ext.asyncio import create_async_engine
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.models import Project
    from z4j_brain.persistence.repositories.schedule_control import (
        ScheduleControlRepository,
    )

    cfg, sync_url, manifest_dir = activation_install
    _activate_one_frozen_row(
        cfg,
        sync_url,
        manifest_dir,
        manifest_name="generation-reset.json",
    )
    command.upgrade(cfg, "head")
    async_url = os.environ["Z4J_DATABASE_URL"]
    project_id = uuid.uuid4()

    async def _seed() -> None:
        async_engine = create_async_engine(async_url)
        database = DatabaseManager(async_engine)
        try:
            async with database.session(write=True) as session:
                session.add(
                    Project(
                        id=project_id,
                        slug="generation-reset",
                        name="Generation reset",
                    ),
                )
                await session.flush()
                await ScheduleControlRepository(
                    session,
                ).create_current(
                    project_id=project_id,
                    data={
                        "name": "generation-reset",
                        "task_name": "jobs.generation_reset",
                        "engine": "celery",
                        "scheduler": "z4j-scheduler",
                        "kind": "interval",
                        "expression": "5m",
                        "timezone": "UTC",
                        "queue": None,
                        "priority": "normal",
                        "args": [],
                        "kwargs": {},
                        "is_enabled": True,
                        "catch_up": "skip",
                        "source": "dashboard",
                    },
                    planning_at=datetime(
                        2026,
                        7,
                        26,
                        9,
                        0,
                        tzinfo=UTC,
                    ),
                )
                await session.commit()
        finally:
            await database.dispose()

    asyncio.run(_seed())
    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            old_generation = connection.execute(
                text("SELECT generation FROM audit_chain_state"),
            ).scalar_one()
            old_installation = connection.execute(
                text(
                    "SELECT installation_id FROM audit_chain_state",
                ),
            ).scalar_one()
            old_revision = connection.execute(
                text(
                    "SELECT current_revision FROM schedule_revision_state",
                ),
            ).scalar_one()
            old_epoch = connection.execute(
                text(
                    "SELECT current_epoch_number FROM schedule_external_epoch_allocator",
                ),
            ).scalar_one()
    finally:
        engine.dispose()

    assert cli.main(["reset", "--force"]) == 0

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT COUNT(*) FROM projects"),
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    text("SELECT COUNT(*) FROM schedules"),
                ).scalar_one()
                == 0
            )
            marker = connection.execute(
                text(
                    "SELECT action, metadata, chain_generation FROM audit_log",
                ),
            ).one()
            assert marker.action == "audit.chain_generation_reset"
            assert marker.chain_generation != old_generation
            state = connection.execute(
                text(
                    "SELECT generation, installation_id, active_row_count FROM audit_chain_state",
                ),
            ).one()
            assert state.generation == marker.chain_generation
            assert state.installation_id == old_installation
            assert state.active_row_count == 1
            revision = connection.execute(
                text(
                    "SELECT current_revision, "
                    "change_log_pruned_through "
                    "FROM schedule_revision_state",
                ),
            ).one()
            assert revision.current_revision > old_revision
            assert revision.change_log_pruned_through == revision.current_revision
            assert (
                connection.execute(
                    text(
                        "SELECT current_epoch_number FROM schedule_external_epoch_allocator",
                    ),
                ).scalar_one()
                > old_epoch
            )
    finally:
        engine.dispose()


def test_generation_reset_refuses_unknown_schema_before_mutation(
    activation_install: tuple[Config, str, Path],
) -> None:
    cfg, sync_url, manifest_dir = activation_install
    _activate_one_frozen_row(
        cfg,
        sync_url,
        manifest_dir,
        manifest_name="generation-reset-unknown-schema.json",
    )
    command.upgrade(cfg, "head")
    engine = create_engine(sync_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("CREATE TABLE unclassified_survivor (id INTEGER PRIMARY KEY)"),
            )
            connection.execute(
                text("INSERT INTO unclassified_survivor VALUES (1)"),
            )
        with engine.connect() as connection:
            old_generation = connection.execute(
                text("SELECT generation FROM audit_chain_state"),
            ).scalar_one()
            old_revision = connection.execute(
                text("SELECT current_revision FROM schedule_revision_state"),
            ).scalar_one()
            old_audit_count = connection.execute(
                text("SELECT COUNT(*) FROM audit_log"),
            ).scalar_one()
    finally:
        engine.dispose()

    assert cli.main(["reset", "--force"]) == 1

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT COUNT(*) FROM unclassified_survivor"),
                ).scalar_one()
                == 1
            )
            assert (
                connection.execute(
                    text("SELECT generation FROM audit_chain_state"),
                ).scalar_one()
                == old_generation
            )
            assert (
                connection.execute(
                    text("SELECT current_revision FROM schedule_revision_state"),
                ).scalar_one()
                == old_revision
            )
            assert (
                connection.execute(
                    text("SELECT COUNT(*) FROM audit_log"),
                ).scalar_one()
                == old_audit_count
            )
    finally:
        engine.dispose()


def test_generation_reset_refuses_migration_head_schema_signature_drift(
    activation_install: tuple[Config, str, Path],
) -> None:
    cfg, sync_url, manifest_dir = activation_install
    _activate_one_frozen_row(
        cfg,
        sync_url,
        manifest_dir,
        manifest_name="generation-reset-schema-signature.json",
    )
    command.upgrade(cfg, "head")
    project_id = uuid.uuid4()
    engine = create_engine(sync_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO projects (id, slug, name) "
                    "VALUES (:id, 'schema-drift-survivor', 'Schema drift survivor')",
                ),
                {"id": project_id.hex},
            )
            connection.exec_driver_sql("DROP INDEX ix_projects_active")

        assert cli.main(["reset", "--force"]) == 1

        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT COUNT(*) FROM projects WHERE id = :id"),
                    {"id": project_id.hex},
                ).scalar_one()
                == 1
            )
    finally:
        engine.dispose()


def test_destructive_sync_refuses_authenticated_database_before_stamp_or_drop(
    activation_install: tuple[Config, str, Path],
) -> None:
    cfg, sync_url, manifest_dir = activation_install
    _activate_one_frozen_row(
        cfg,
        sync_url,
        manifest_dir,
        manifest_name="destructive-sync-fence.json",
    )
    engine = create_engine(sync_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("UPDATE alembic_version SET version_num = 'future_revision'"),
            )

        assert (
            cli._run_migrate_sync(
                Path(str(cfg.config_file_name)),
                allow_future=True,
                confirm_destructive=True,
            )
            == 1
        )

        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT version_num FROM alembic_version"),
                ).scalar_one()
                == "future_revision"
            )
            assert inspect(connection).has_table("audit_chain_state")
            assert inspect(connection).has_table("audit_log")
    finally:
        engine.dispose()


def test_generation_reset_rolls_back_when_old_audit_chain_is_tampered(
    activation_install: tuple[Config, str, Path],
) -> None:
    from sqlalchemy.ext.asyncio import create_async_engine
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.models import Project

    cfg, sync_url, manifest_dir = activation_install
    _activate_one_frozen_row(
        cfg,
        sync_url,
        manifest_dir,
        manifest_name="generation-reset-tamper.json",
    )
    command.upgrade(cfg, "head")
    project_id = uuid.uuid4()

    async def _seed() -> None:
        database = DatabaseManager(
            create_async_engine(os.environ["Z4J_DATABASE_URL"]),
        )
        try:
            async with database.session(write=True) as session:
                session.add(
                    Project(
                        id=project_id,
                        slug="reset-tamper",
                        name="Reset tamper",
                    ),
                )
                await session.commit()
        finally:
            await database.dispose()

    asyncio.run(_seed())
    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            old_generation = connection.execute(
                text("SELECT generation FROM audit_chain_state"),
            ).scalar_one()
            old_revision = connection.execute(
                text("SELECT current_revision FROM schedule_revision_state"),
            ).scalar_one()
        with engine.begin() as connection:
            # Bypass the database guard deliberately so the reset ceremony's
            # own authenticated-chain refusal remains independently covered.
            connection.execute(
                text("DROP TRIGGER audit_log_boundary_f_no_update"),
            )
            connection.execute(
                text(
                    "UPDATE audit_log SET action = 'tampered' "
                    "WHERE id = (SELECT id FROM audit_log "
                    "ORDER BY occurred_at, id LIMIT 1)",
                ),
            )
            connection.execute(
                text(_SQLITE_AUDIT_UPDATE_TRIGGER_SQL),
            )
    finally:
        engine.dispose()

    assert cli.main(["reset", "--force"]) == 1

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT COUNT(*) FROM projects WHERE id = :id"),
                    {"id": project_id.hex},
                ).scalar_one()
                == 1
            )
            assert (
                connection.execute(
                    text("SELECT generation FROM audit_chain_state"),
                ).scalar_one()
                == old_generation
            )
            assert (
                connection.execute(
                    text("SELECT current_revision FROM schedule_revision_state"),
                ).scalar_one()
                == old_revision
            )
    finally:
        engine.dispose()


def test_generation_reset_requires_exact_external_authority_attestation(
    activation_install: tuple[Config, str, Path],
) -> None:
    from sqlalchemy.ext.asyncio import create_async_engine
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.models import Project
    from z4j_brain.persistence.repositories.schedule_external import (
        ScheduleExternalRepository,
    )

    cfg, sync_url, manifest_dir = activation_install
    _activate_one_frozen_row(
        cfg,
        sync_url,
        manifest_dir,
        manifest_name="generation-reset-external-authority.json",
    )
    command.upgrade(cfg, "head")
    project_id = uuid.uuid4()

    async def _seed() -> None:
        database = DatabaseManager(
            create_async_engine(os.environ["Z4J_DATABASE_URL"]),
        )
        try:
            async with database.session(write=True) as session:
                session.add(
                    Project(
                        id=project_id,
                        slug="reset-external",
                        name="Reset external",
                    ),
                )
                await session.flush()
                await ScheduleExternalRepository(
                    session,
                ).ensure_activation_epoch(
                    project_id=project_id,
                    owner="celery-beat",
                    source_scope="app.beat",
                    occurred_at=datetime(2026, 7, 26, 9, 0, tzinfo=UTC),
                    adapter_instance_id="reset-external-adapter",
                    executor_agent_id=uuid.uuid4(),
                    executor_registry_owner_id=uuid.uuid4(),
                    executor_session_generation="reset-session-generation",
                    executor_worker_id="reset-worker",
                )
                await session.commit()
        finally:
            await database.dispose()

    asyncio.run(_seed())
    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            old_epoch = connection.execute(
                text(
                    "SELECT current_epoch_number FROM schedule_external_epoch_allocator",
                ),
            ).scalar_one()
            old_generation = connection.execute(
                text("SELECT generation FROM audit_chain_state"),
            ).scalar_one()
    finally:
        engine.dispose()

    assert cli.main(["reset", "--force"]) == 1

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT COUNT(*) FROM schedule_external_streams"),
                ).scalar_one()
                == 1
            )
            assert (
                connection.execute(
                    text(
                        "SELECT current_epoch_number FROM schedule_external_epoch_allocator",
                    ),
                ).scalar_one()
                == old_epoch
            )
            assert (
                connection.execute(
                    text("SELECT generation FROM audit_chain_state"),
                ).scalar_one()
                == old_generation
            )
    finally:
        engine.dispose()

    preview_path = manifest_dir / "generation-reset-preview.json"
    assert (
        cli.main(
            [
                "reset",
                "--force",
                "--preview-manifest",
                str(preview_path),
            ],
        )
        == 0
    )
    preview = json.loads(preview_path.read_text(encoding="utf-8"))
    assert preview["requires_stopped_executor_attestation"] is True
    challenge = preview["stopped_executor_attestation_challenge"]
    assert isinstance(challenge, str) and len(challenge) == 64

    assert (
        cli.main(
            [
                "reset",
                "--force",
                "--attest-stopped-executors",
                challenge,
            ],
        )
        == 0
    )

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT COUNT(*) FROM schedule_external_streams"),
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    text(
                        "SELECT current_epoch_number FROM schedule_external_epoch_allocator",
                    ),
                ).scalar_one()
                > old_epoch
            )
            assert (
                connection.execute(
                    text("SELECT action FROM audit_log"),
                ).scalar_one()
                == "audit.chain_generation_reset"
            )
    finally:
        engine.dispose()


def test_cli_password_change_is_atomic_with_signed_non_secret_audit(
    activation_install: tuple[Config, str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sqlalchemy.orm import Session as SyncSession
    from z4j_brain.auth.passwords import PasswordHasher
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.models import User

    cfg, sync_url, manifest_dir = activation_install
    _activate_one_frozen_row(
        cfg,
        sync_url,
        manifest_dir,
        manifest_name="cli-password.json",
    )
    settings = Settings()  # type: ignore[call-arg]
    hasher = PasswordHasher(settings)
    user_id = uuid.uuid4()
    old_password = "Old-Cli-Password-2026!"
    new_password = "New-Cli-Password-2026!"
    engine = create_engine(sync_url)
    try:
        with SyncSession(engine) as session:
            session.add(
                User(
                    id=user_id,
                    email="cli-audit@example.com",
                    password_hash=hasher.hash(old_password),
                    is_admin=True,
                    is_active=True,
                ),
            )
            session.commit()

        original_record = AuditService.record

        async def _fail_audit(*args: object, **kwargs: object) -> None:
            raise RuntimeError("injected audit failure")

        monkeypatch.setattr(AuditService, "record", _fail_audit)
        with pytest.raises(RuntimeError, match="injected audit failure"):
            cli.main(
                [
                    "changepassword",
                    "cli-audit@example.com",
                    "--password",
                    new_password,
                ],
            )
        monkeypatch.setattr(AuditService, "record", original_record)

        with SyncSession(engine) as session:
            user = session.get(User, user_id)
            assert user is not None
            assert hasher.verify(user.password_hash, old_password)
            assert not hasher.verify(user.password_hash, new_password)

        assert (
            cli.main(
                [
                    "changepassword",
                    "cli-audit@example.com",
                    "--password",
                    new_password,
                ],
            )
            == 0
        )
        with engine.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT metadata FROM audit_log WHERE action='user.password.changed_by_cli'",
                ),
            ).scalar_one()
            metadata = json.loads(row) if isinstance(row, str) else row
            assert set(metadata) == {"operator_uid", "revoked_sessions"}
            assert metadata["revoked_sessions"] == 0
            assert old_password not in str(metadata)
            assert new_password not in str(metadata)
        with SyncSession(engine) as session:
            user = session.get(User, user_id)
            assert user is not None
            assert hasher.verify(user.password_hash, new_password)
    finally:
        engine.dispose()


def test_existing_empty_history_requires_exact_digest_attestation(
    activation_install: tuple[Config, str, Path],
) -> None:
    cfg, sync_url, manifest_dir = activation_install
    _prepare(cfg)
    _finish_preparation(cfg)
    manifest_path = manifest_dir / "empty.json"
    assert (
        cli.main(
            ["audit", "activate-chain-state", "--manifest", str(manifest_path)],
        )
        == 0
    )
    manifest = read_activation_manifest(manifest_path)
    assert manifest["classification_failures"] == ["existing-empty-audit-table"]

    assert (
        cli.main(
            [
                "audit",
                "activate-chain-state",
                "--manifest",
                str(manifest_path),
                "--apply",
            ],
        )
        == 1
    )
    assert (
        cli.main(
            [
                "audit",
                "activate-chain-state",
                "--manifest",
                str(manifest_path),
                "--apply",
                "--attest-manifest-digest",
                manifest["manifest_digest"],
            ],
        )
        == 0
    )

    engine = create_engine(sync_url)
    try:
        assert inspect(engine).has_table("audit_chain_state")
    finally:
        engine.dispose()


def test_cutover_known_head_current_match_is_bound_into_marker(
    activation_install: tuple[Config, str, Path],
) -> None:
    cfg, sync_url, manifest_dir = activation_install
    _prepare(cfg)
    legacy_id = _insert_linked_legacy_genesis(sync_url)
    _finish_preparation(cfg)
    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            row_hmac = connection.execute(
                AuditLog.__table__.select()
                .with_only_columns(AuditLog.__table__.c.row_hmac)
                .where(AuditLog.__table__.c.id == legacy_id),
            ).scalar_one()
    finally:
        engine.dispose()
    known_head = {
        "row_hmac": row_hmac,
        "hmac_version": 1,
        "id": str(legacy_id),
    }
    manifest_path = manifest_dir / "known-current.json"
    assert (
        cli.main(
            [
                "audit",
                "activate-chain-state",
                "--manifest",
                str(manifest_path),
                "--known-head",
                json.dumps(known_head),
            ],
        )
        == 0
    )
    manifest = read_activation_manifest(manifest_path)
    assert manifest["known_head"] == known_head
    assert manifest["known_head_result"] == "CURRENT_MATCH"
    assert manifest["classification_failures"] == []
    assert (
        cli.main(
            [
                "audit",
                "activate-chain-state",
                "--manifest",
                str(manifest_path),
                "--apply",
            ],
        )
        == 0
    )

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            raw_metadata = connection.execute(
                text(
                    "SELECT metadata FROM audit_log WHERE action='audit.chain_generation_started'",
                ),
            ).scalar_one()
            metadata = json.loads(raw_metadata) if isinstance(raw_metadata, str) else raw_metadata
            assert metadata["known_head"] == known_head
            assert metadata["known_head_result"] == "CURRENT_MATCH"
    finally:
        engine.dispose()


def test_invalid_cutover_known_head_requires_manifest_attestation(
    activation_install: tuple[Config, str, Path],
) -> None:
    cfg, sync_url, manifest_dir = activation_install
    _prepare(cfg)
    _insert_linked_legacy_genesis(sync_url)
    _finish_preparation(cfg)
    manifest_path = manifest_dir / "known-invalid.json"
    assert (
        cli.main(
            [
                "audit",
                "activate-chain-state",
                "--manifest",
                str(manifest_path),
                "--known-head",
                '{"row_hmac":"not-a-hmac"}',
            ],
        )
        == 0
    )
    manifest = read_activation_manifest(manifest_path)
    assert manifest["known_head"] == {"__invalid__": True}
    assert manifest["known_head_result"] == "INVALID"
    assert "known-head:INVALID" in manifest["classification_failures"]
    assert (
        cli.main(
            [
                "audit",
                "activate-chain-state",
                "--manifest",
                str(manifest_path),
                "--apply",
            ],
        )
        == 1
    )
    assert (
        cli.main(
            [
                "audit",
                "activate-chain-state",
                "--manifest",
                str(manifest_path),
                "--apply",
                "--attest-manifest-digest",
                manifest["manifest_digest"],
            ],
        )
        == 0
    )


@pytest.mark.parametrize("include_api_key_id", [False, True])
def test_shipped_fork_quarantine_shape_imports_losslessly(
    activation_install: tuple[Config, str, Path],
    *,
    include_api_key_id: bool,
) -> None:
    cfg, sync_url, manifest_dir = activation_install
    _prepare(cfg)
    fork_id = _insert_fork_quarantine_fixture(
        sync_url,
        include_api_key_id=include_api_key_id,
    )
    _finish_preparation(cfg)
    suffix = "16" if include_api_key_id else "15"
    manifest_path = manifest_dir / f"fork-{suffix}.json"
    assert (
        cli.main(
            ["audit", "activate-chain-state", "--manifest", str(manifest_path)],
        )
        == 0
    )
    manifest = read_activation_manifest(manifest_path)
    assert manifest["requires_ambiguity_attestation"] is True
    expected_shape = "audit-log-v1-api-key-16" if include_api_key_id else "audit-log-v1-15"
    assert manifest["auxiliary_source"]["shape_id"] == expected_shape
    fork_classification = next(
        item for item in manifest["classifications"] if item["id"] == str(fork_id)
    )
    assert fork_classification["legacy_integrity_class"] == "legacy-fork-verified"
    assert fork_classification["legacy_origin"] == f"fork-quarantine:{expected_shape}"
    assert tuple(item["name"] for item in fork_classification["source_envelope"]) == tuple(
        manifest["auxiliary_source"]["ordered_columns"],
    )

    assert (
        cli.main(
            [
                "audit",
                "activate-chain-state",
                "--manifest",
                str(manifest_path),
                "--apply",
                "--attest-manifest-digest",
                manifest["manifest_digest"],
            ],
        )
        == 0
    )

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert not inspect(connection).has_table(
                "audit_log_legacy_forks",
            )
            fork_row = connection.execute(
                AuditLog.__table__.select()
                .with_only_columns(
                    AuditLog.__table__.c.legacy_frozen,
                    AuditLog.__table__.c.legacy_integrity_class,
                    AuditLog.__table__.c.legacy_origin,
                )
                .where(AuditLog.__table__.c.id == fork_id),
            ).one()
            assert tuple(fork_row) == (
                True,
                "legacy-fork-verified",
                f"fork-quarantine:{expected_shape}",
            )
            assert (
                connection.execute(
                    text("SELECT frozen_row_count FROM audit_chain_state"),
                ).scalar_one()
                == 3
            )
    finally:
        engine.dispose()


def test_duplicate_fork_id_refuses_without_dropping_source(
    activation_install: tuple[Config, str, Path],
) -> None:
    cfg, sync_url, manifest_dir = activation_install
    _prepare(cfg)
    _insert_fork_quarantine_fixture(
        sync_url,
        include_api_key_id=True,
        duplicate_id=True,
    )
    _finish_preparation(cfg)
    manifest_path = manifest_dir / "duplicate-id.json"

    assert (
        cli.main(
            ["audit", "activate-chain-state", "--manifest", str(manifest_path)],
        )
        == 1
    )
    assert not manifest_path.exists()
    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert inspect(connection).has_table("audit_log_legacy_forks")
            assert (
                connection.execute(
                    text("SELECT version_num FROM alembic_version"),
                ).scalar_one()
                == "v1_8_audit_chain_prepare"
            )
    finally:
        engine.dispose()


def test_unknown_fork_shape_refuses_without_dropping_source(
    activation_install: tuple[Config, str, Path],
) -> None:
    cfg, sync_url, manifest_dir = activation_install
    _prepare(cfg)
    _insert_fork_quarantine_fixture(
        sync_url,
        include_api_key_id=True,
    )
    _finish_preparation(cfg)
    engine = create_engine(sync_url)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER TABLE audit_log_legacy_forks ADD COLUMN unexpected TEXT",
            )
    finally:
        engine.dispose()
    manifest_path = manifest_dir / "unknown-shape.json"

    assert (
        cli.main(
            ["audit", "activate-chain-state", "--manifest", str(manifest_path)],
        )
        == 1
    )
    engine = create_engine(sync_url)
    try:
        assert inspect(engine).has_table("audit_log_legacy_forks")
    finally:
        engine.dispose()


def test_row_change_after_manifest_aborts_without_partial_activation(
    activation_install: tuple[Config, str, Path],
) -> None:
    cfg, sync_url, manifest_dir = activation_install
    _prepare(cfg)
    legacy_id = _insert_linked_legacy_genesis(sync_url)
    _finish_preparation(cfg)
    manifest_path = manifest_dir / "changed.json"
    assert (
        cli.main(
            ["audit", "activate-chain-state", "--manifest", str(manifest_path)],
        )
        == 0
    )

    engine = create_engine(sync_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                AuditLog.__table__.update()
                .where(AuditLog.__table__.c.id == legacy_id)
                .values(action="changed"),
            )
        assert (
            cli.main(
                [
                    "audit",
                    "activate-chain-state",
                    "--manifest",
                    str(manifest_path),
                    "--apply",
                ],
            )
            == 1
        )
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT version_num FROM alembic_version"),
                ).scalar_one()
                == "v1_8_audit_chain_prepare"
            )
            assert not inspect(connection).has_table("audit_chain_state")
            markers = connection.execute(
                AuditLog.__table__.select()
                .with_only_columns(
                    AuditLog.__table__.c.legacy_frozen,
                    AuditLog.__table__.c.hmac_version,
                    AuditLog.__table__.c.hmac_key_id,
                )
                .where(AuditLog.__table__.c.id == legacy_id),
            ).one()
            assert tuple(markers) == (None, None, None)
    finally:
        engine.dispose()


def test_preparation_tamper_after_manifest_aborts(
    activation_install: tuple[Config, str, Path],
) -> None:
    cfg, sync_url, manifest_dir = activation_install
    _prepare(cfg)
    _insert_linked_legacy_genesis(sync_url)
    _finish_preparation(cfg)
    manifest_path = manifest_dir / "prep-tamper.json"
    assert (
        cli.main(
            ["audit", "activate-chain-state", "--manifest", str(manifest_path)],
        )
        == 0
    )

    engine = create_engine(sync_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE audit_chain_preparation SET preparation_mac=:mac",
                ),
                {"mac": "0" * 64},
            )
        assert (
            cli.main(
                [
                    "audit",
                    "activate-chain-state",
                    "--manifest",
                    str(manifest_path),
                    "--apply",
                ],
            )
            == 1
        )
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT version_num FROM alembic_version"),
                ).scalar_one()
                == "v1_8_audit_chain_prepare"
            )
            assert not inspect(connection).has_table("audit_chain_state")
    finally:
        engine.dispose()


def test_legacy_audit_management_refuses_after_preparation(
    activation_install: tuple[Config, str, Path],
) -> None:
    cfg, _sync_url, manifest_dir = activation_install
    _prepare(cfg)
    _finish_preparation(cfg)

    assert cli.main(["audit", "fork-cleanup", "--apply", "--no-backup"]) == 1
    assert (
        cli.main(
            [
                "audit",
                "reseal-watermark",
                "--i-have-verified-the-chain",
            ],
        )
        == 1
    )
    assert not any(manifest_dir.iterdir())


def test_reset_setup_preserves_evidence_and_appends_signed_record(
    activation_install: tuple[Config, str, Path],
) -> None:
    cfg, sync_url, _manifest_dir = activation_install
    command.upgrade(cfg, "head")

    from z4j_brain.persistence.database import (
        DatabaseManager,
        create_engine_from_settings,
    )
    from z4j_brain.persistence.models import FirstBootToken
    from z4j_brain.persistence.repositories import AuditLogRepository

    settings = Settings()  # type: ignore[call-arg]

    async def _seed() -> None:
        engine = create_engine_from_settings(settings)
        db = DatabaseManager(engine)
        try:
            async with db.session(write=True) as session:
                session.add(
                    FirstBootToken(
                        token_hash="f" * 64,
                        expires_at=datetime.now(UTC) + timedelta(minutes=15),
                        created_at=datetime.now(UTC),
                    ),
                )
                await AuditService(settings).record(
                    AuditLogRepository(session),
                    action="setup.prior_evidence",
                    target_type="first_boot",
                    result="success",
                    outcome="allow",
                )
                await session.commit()
        finally:
            await db.dispose()

    asyncio.run(_seed())
    assert cli.main(["reset-setup", "--force"]) == 0

    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT COUNT(*) FROM first_boot_tokens"),
                ).scalar_one()
                == 0
            )
            actions = list(
                connection.execute(
                    text(
                        "SELECT action FROM audit_log "
                        "WHERE action LIKE 'setup.%' ORDER BY occurred_at, id",
                    ),
                ).scalars(),
            )
            assert actions == [
                "setup.prior_evidence",
                "setup.tokens_reset",
            ]
    finally:
        engine.dispose()
