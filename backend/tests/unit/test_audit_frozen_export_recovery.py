"""Retry frozen-export operations across interrupted publication and cleanup."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import uuid
from itertools import chain
from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import create_engine, text
from z4j_brain import cli
from z4j_brain.domain import audit_frozen_export as frozen
from z4j_brain.domain.audit_chain import AuditChainIntegrityError

from tests.unit import test_audit_activation_boundary_f as activation


@pytest.fixture
def activation_install(tmp_path, monkeypatch):
    if os.name != "nt":
        yield from activation.activation_install.__wrapped__(tmp_path, monkeypatch)
        return

    from z4j_brain._windows_secure_io import ensure_private_directory

    with tempfile.TemporaryDirectory(prefix="z4j-frozen-recovery-") as temporary:
        private_home = Path(temporary) / "private"
        ensure_private_directory(private_home)
        manifest_dir = private_home / "manifests"
        ensure_private_directory(manifest_dir)
        db_path = private_home / "z4j.db"
        backend_root = Path(activation.__file__).resolve().parents[2]
        alembic_ini = backend_root / "alembic.ini"
        monkeypatch.setenv("Z4J_ALEMBIC_INI", str(alembic_ini))
        monkeypatch.setenv("Z4J_DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
        monkeypatch.setenv("Z4J_SECRET", "x" * 64)
        monkeypatch.setenv("Z4J_SESSION_SECRET", "y" * 64)
        monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", "a" * 64)
        monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
        monkeypatch.setenv("Z4J_HOME", str(private_home))
        monkeypatch.chdir(backend_root)
        cfg = Config(str(alembic_ini))
        cfg.set_main_option("script_location", str(backend_root / "src/z4j_brain/migrations"))
        yield cfg, f"sqlite:///{db_path}", manifest_dir


def _operation(activation_install):
    cfg, sync_url, manifest_dir = activation_install
    activation._activate_one_frozen_row(
        cfg, sync_url, manifest_dir, manifest_name="activate-recovery.json"
    )
    operation = uuid.uuid4()
    destination = manifest_dir / "frozen-recovery.json"
    argv = [
        "audit",
        "export-and-delete-frozen",
        "--operation",
        str(operation),
        "--destination",
        str(destination),
    ]
    directory = Path(os.environ["Z4J_HOME"]) / "audit-frozen-exports" / str(operation)
    return sync_url, destination, argv, directory


def _counts(sync_url):
    engine = create_engine(sync_url)
    try:
        with engine.connect() as connection:
            frozen_rows = connection.execute(
                text("SELECT COUNT(*) FROM audit_log WHERE legacy_frozen=1")
            ).scalar_one()
            markers = connection.execute(
                text("SELECT COUNT(*) FROM audit_log WHERE action='audit.frozen_history_exported'")
            ).scalar_one()
            return frozen_rows, markers
    finally:
        engine.dispose()


def _interrupt_write(patch, should_interrupt, prefix_size):
    """Leave actual partial bytes, as abrupt process death would on either OS."""
    if os.name == "nt":
        from z4j_brain import _windows_secure_io as windows

        create = windows.create_relative_stream_file

        def create_partial(parent, name, chunks):
            chunks = iter(chunks)
            first = next(chunks, b"")
            if should_interrupt(first):
                handle, _, _ = create(parent, name, (first[:prefix_size],))
                windows.close_handle(handle)
                raise OSError("injected interrupted native file write")
            return create(parent, name, chain((first,), chunks))

        patch.setattr(windows, "create_relative_stream_file", create_partial)
    else:
        write = frozen._write_all

        def write_partial(fd, payload):
            if should_interrupt(payload):
                write(fd, payload[:prefix_size])
                raise OSError("injected interrupted file write")
            write(fd, payload)

        patch.setattr(frozen, "_write_all", write_partial)


@pytest.mark.parametrize("write_number", [1, 2], ids=["spool", "destination"])
def test_resume_after_partial_export_write(activation_install, monkeypatch, write_number):
    sync_url, destination, argv, _directory = _operation(activation_install)
    writes = 0

    def interrupt(payload):
        nonlocal writes
        if bytes(payload).startswith(b'{"format_version":1,"manifest":'):
            writes += 1
            return writes == write_number
        return False

    with monkeypatch.context() as patch:
        _interrupt_write(patch, interrupt, 10)
        assert cli.main(argv) == 1
    assert writes == write_number
    assert _counts(sync_url) == (1, 0)
    assert cli.main(argv) == 0
    assert len(json.loads(destination.read_text())["rows"]) == 1
    assert _counts(sync_url) == (0, 1)


@pytest.mark.skipif(os.name != "posix", reason="POSIX syscall interruption oracle")
@pytest.mark.parametrize("stage", ["spool", "phase", "directory"])
def test_resume_after_cleanup_removal(activation_install, monkeypatch, stage):
    sync_url, destination, argv, directory = _operation(activation_install)
    assert cli.main(argv) == 0
    phase = json.loads((directory / "phase.json").read_text())
    cleanup = [*argv, "--acknowledge-destination-digest", phase["export_sha256"], "--cleanup"]
    saved = destination.read_bytes()
    interrupted = False
    real_unlink = frozen.os.unlink
    real_rmdir = Path.rmdir

    def unlink(name, *args, **kwargs):
        nonlocal interrupted
        real_unlink(name, *args, **kwargs)
        target = frozen._SPOOL_FILE if stage == "spool" else frozen._PHASE_FILE
        if stage != "directory" and name == target and not interrupted:
            interrupted = True
            raise OSError("injected crash after cleanup unlink")

    def rmdir(path):
        nonlocal interrupted
        real_rmdir(path)
        if stage == "directory" and path == directory and not interrupted:
            interrupted = True
            raise OSError("injected crash after operation directory removal")

    with monkeypatch.context() as patch:
        patch.setattr(frozen.os, "unlink", unlink)
        patch.setattr(Path, "rmdir", rmdir)
        assert cli.main(cleanup) == 1
    assert interrupted
    assert _counts(sync_url) == (0, 1)
    assert cli.main(cleanup) == 0
    assert not directory.exists()
    assert destination.read_bytes() == saved
    assert _counts(sync_url) == (0, 1)


@pytest.mark.parametrize("phase_name", ["INITIAL", "DATABASE_COMMITTED"])
def test_partial_phase_stage_is_recovered_and_removed(activation_install, monkeypatch, phase_name):
    sync_url, destination, argv, directory = _operation(activation_install)
    interrupted = False

    def interrupt(payload):
        nonlocal interrupted
        if not interrupted and f'"phase":"{phase_name}"'.encode() in payload:
            interrupted = True
            return True
        return False

    with monkeypatch.context() as patch:
        _interrupt_write(patch, interrupt, 20)
        assert cli.main(argv) == 1
    assert interrupted
    assert cli.main(argv) == 0
    phase = json.loads((directory / "phase.json").read_text())
    assert (
        cli.main([*argv, "--acknowledge-destination-digest", phase["export_sha256"], "--cleanup"])
        == 0
    )
    assert not directory.exists()
    assert destination.exists()
    assert _counts(sync_url) == (0, 1)


@pytest.mark.parametrize(
    "fault", ["wrong_ack", "missing_ack", "destination_replaced", "unknown_entry"]
)
def test_cleanup_recovery_refuses_changed_authority(activation_install, monkeypatch, fault):
    sync_url, destination, argv, directory = _operation(activation_install)
    assert cli.main(argv) == 0
    phase = json.loads((directory / "phase.json").read_text())
    cleanup = [*argv, "--acknowledge-destination-digest", phase["export_sha256"], "--cleanup"]
    with monkeypatch.context() as patch:
        if os.name == "nt":
            from z4j_brain import _windows_secure_io as windows

            delete = windows.delete_relative

            def remove(parent, name, **kwargs):
                delete(parent, name, **kwargs)
                if name == frozen._PHASE_FILE:
                    raise OSError("injected lost phase after acknowledgement")

            patch.setattr(windows, "delete_relative", remove)
        else:
            real_unlink = frozen.os.unlink

            def unlink(name, *args, **kwargs):
                real_unlink(name, *args, **kwargs)
                if name == frozen._PHASE_FILE:
                    raise OSError("injected lost phase after acknowledgement")

            patch.setattr(frozen.os, "unlink", unlink)
        assert cli.main(cleanup) == 1
    assert not (directory / "phase.json").exists()
    original_bytes = destination.read_bytes()
    if fault == "wrong_ack":
        cleanup[-2] = "0" * 64
    elif fault == "missing_ack":
        cleanup = [*argv, "--cleanup"]
    elif fault == "destination_replaced":
        replacement = destination.with_suffix(".replacement")
        replacement.write_bytes(original_bytes)
        replacement.chmod(0o600)
        replacement.replace(destination)
    else:
        (directory / "foreign.txt").write_text("preserve unrelated content")
    assert cli.main(cleanup) == 1
    assert directory.exists()
    assert destination.read_bytes() == original_bytes
    if fault == "unknown_entry":
        assert (directory / "foreign.txt").read_text() == "preserve unrelated content"
    assert _counts(sync_url) == (0, 1)


@pytest.mark.parametrize("target", ["phase_stage", "spool_stage", "destination"])
def test_foreign_file_is_never_replaced(activation_install, target):
    sync_url, destination, argv, directory = _operation(activation_install)
    if target == "destination":
        foreign = destination
    else:
        directory.parent.mkdir(mode=0o700, exist_ok=True)
        directory.mkdir(mode=0o700)
        foreign = directory / (
            frozen._PHASE_STAGE if target == "phase_stage" else frozen._SPOOL_STAGE
        )
    foreign.write_bytes(b"unrelated private file")
    foreign.chmod(0o600)
    identity = (foreign.stat().st_dev, foreign.stat().st_ino)
    assert cli.main(argv) == 1
    assert foreign.read_bytes() == b"unrelated private file"
    assert (foreign.stat().st_dev, foreign.stat().st_ino) == identity
    assert _counts(sync_url) == (1, 0)


@pytest.mark.skipif(os.name != "posix", reason="POSIX staging identity oracle")
@pytest.mark.parametrize("fault", ["symlink", "hardlink", "broad_mode", "swapped_inode"])
def test_staging_recovery_rejects_unowned_or_replaced_files(tmp_path, monkeypatch, fault):
    directory = tmp_path / "operation"
    directory.mkdir(mode=0o700)
    stage = directory / frozen._SPOOL_STAGE
    other = tmp_path / "other"
    other.write_bytes(b"expected prefix")
    other.chmod(0o600)
    if fault == "symlink":
        stage.symlink_to(other)
    elif fault == "hardlink":
        stage.hardlink_to(other)
    else:
        stage.write_bytes(b"expected")
        stage.chmod(0o644 if fault == "broad_mode" else 0o600)
    original_read = frozen.os.read
    swapped = False

    def read(fd, count):
        nonlocal swapped
        value = original_read(fd, count)
        if fault == "swapped_inode" and not swapped:
            swapped = True
            stage.rename(directory / "retained-original")
            stage.write_bytes(b"unrelated replacement")
            stage.chmod(0o600)
        return value

    directory_fd, identity = frozen._open_private_directory(directory, create=False)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(frozen.os, "read", read)
            with pytest.raises((AuditChainIntegrityError, OSError)):
                frozen._discard_matching_stage(
                    directory_fd, directory, identity, stage.name, iter((b"expected prefix",))
                )
    finally:
        os.close(directory_fd)
    assert stage.exists()
    assert other.read_bytes() == b"expected prefix"
    if fault == "swapped_inode":
        assert stage.read_bytes() == b"unrelated replacement"
        assert (directory / "retained-original").read_bytes() == b"expected"


@pytest.mark.skipif(os.name != "posix", reason="POSIX atomic no-replace publication oracle")
def test_destination_arriving_at_publication_is_not_clobbered(activation_install, monkeypatch):
    from z4j_brain import management_retirement

    sync_url, destination, argv, _directory = _operation(activation_install)
    rename = management_retirement._rename_no_replace

    def competing_file(source_fd, source_name, destination_fd, destination_name):
        if destination_name == destination.name:
            destination.write_bytes(b"foreign arrival")
            destination.chmod(0o600)
        rename(source_fd, source_name, destination_fd, destination_name)

    monkeypatch.setattr(management_retirement, "_rename_no_replace", competing_file)
    assert cli.main(argv) == 1
    assert destination.read_bytes() == b"foreign arrival"
    assert _counts(sync_url) == (1, 0)


@pytest.mark.skipif(os.name != "nt", reason="native Windows handle deletion oracle")
@pytest.mark.parametrize("stage", ["spool", "phase", "directory"])
def test_windows_resume_after_cleanup_removal(activation_install, monkeypatch, stage):
    from z4j_brain import _windows_secure_io as windows

    sync_url, destination, argv, directory = _operation(activation_install)
    assert cli.main(argv) == 0
    phase = json.loads((directory / "phase.json").read_text())
    cleanup = [*argv, "--acknowledge-destination-digest", phase["export_sha256"], "--cleanup"]
    saved = destination.read_bytes()
    interrupted = False
    helper = "delete_relative_directory" if stage == "directory" else "delete_relative"
    delete = getattr(windows, helper)
    target = {
        "spool": frozen._SPOOL_FILE,
        "phase": frozen._PHASE_FILE,
        "directory": directory.name,
    }[stage]

    def remove(parent, name, **kwargs):
        nonlocal interrupted
        delete(parent, name, **kwargs)
        if name == target and not interrupted:
            interrupted = True
            raise OSError("injected crash after Windows handle deletion")

    with monkeypatch.context() as patch:
        patch.setattr(windows, helper, remove)
        assert cli.main(cleanup) == 1
    assert interrupted
    assert _counts(sync_url) == (0, 1)
    assert cli.main(cleanup) == 0
    assert not directory.exists()
    assert destination.read_bytes() == saved
    assert _counts(sync_url) == (0, 1)


@pytest.mark.skipif(os.name != "nt", reason="native Windows atomic no-replace oracle")
def test_windows_destination_arriving_at_publication_is_not_clobbered(
    activation_install, monkeypatch
):
    from z4j_brain import _windows_secure_io as windows

    sync_url, destination, argv, _directory = _operation(activation_install)
    rename = windows.replace_open_handle

    def competing_file(source, parent, name, **kwargs):
        if name == destination.name:
            destination.write_bytes(b"foreign arrival")
        rename(source, parent, name, **kwargs)

    monkeypatch.setattr(windows, "replace_open_handle", competing_file)
    assert cli.main(argv) == 1
    assert destination.read_bytes() == b"foreign arrival"
    assert _counts(sync_url) == (1, 0)


@pytest.mark.skipif(os.name != "nt", reason="native Windows staging hardlink oracle")
def test_windows_staging_recovery_refuses_hardlink(activation_install):
    _, _, directory = activation_install
    other = directory / "original"
    other.write_bytes(b"expected prefix")
    stage = directory / frozen._SPOOL_STAGE
    stage.hardlink_to(other)
    directory_fd, identity = frozen._open_private_directory(directory, create=False)
    try:
        with pytest.raises(AuditChainIntegrityError, match="unaliased regular file"):
            frozen._discard_matching_stage(
                directory_fd, directory, identity, stage.name, iter((b"expected prefix",))
            )
    finally:
        os.close(directory_fd)
    assert stage.read_bytes() == other.read_bytes() == b"expected prefix"


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO refusal oracle")
@pytest.mark.parametrize("reader", ["stage", "phase", "spool", "destination"])
def test_existing_file_readers_refuse_fifo_without_waiting(tmp_path, reader):
    code = """
import os, sys
from pathlib import Path
from z4j_brain.domain import audit_frozen_export as frozen
from z4j_brain.domain.audit_chain import AuditChainIntegrityError
directory = Path(sys.argv[1])
reader = sys.argv[2]
name = frozen._SPOOL_FILE if reader == 'spool' else 'unexpected'
target = directory / name
os.mkfifo(target, 0o600)
fd, identity = frozen._open_private_directory(directory, create=False)
try:
    try:
        if reader == 'stage':
            frozen._discard_matching_stage(fd, directory, identity, name, iter((b'expected',)))
        elif reader == 'phase':
            frozen._read_relative(fd, directory, identity, name, required=True)
        elif reader == 'spool':
            frozen._open_export_spool(fd, directory, identity, required=True)
        else:
            frozen._open_and_hash_destination(target, fd, identity)
    except AuditChainIntegrityError as exc:
        assert 'regular file' in str(exc), str(exc)
    else:
        raise AssertionError('FIFO accepted')
finally:
    os.close(fd)
assert target.exists()
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path), reader],
        timeout=5,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode()
