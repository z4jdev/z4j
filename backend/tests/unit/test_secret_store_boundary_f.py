from __future__ import annotations

import contextlib
import os
import select
import shutil
import signal
import stat
import subprocess
import tempfile
from collections.abc import Iterator
from multiprocessing.synchronize import Event as EventType
from pathlib import Path

import pytest
from z4j_brain.secret_store import (
    SecretStoreError,
    audit_bootstrap_coordinator,
    delete_secret_store,
    ensure_secret_store_directory,
    protect_secret_store_directory,
    read_secret_store,
    update_secret_store,
)

# This is only a runaway-process safety ceiling. Negative mutual-exclusion
# probes below stay subsecond and assert the actual serialization edges. A
# ten-second lifecycle ceiling races Python's spawn/import startup when the
# full suite saturates WSL.
_PROCESS_LIFECYCLE_TIMEOUT_SECONDS = 60


def _hold_store_lock(
    state: str,
    ready: EventType,
    release: EventType,
) -> None:
    from z4j_brain.secret_store import (
        _LOCK_NAME,
        _close_directory,
        _exclusive_named_lock,
        _open_directory,
    )

    directory_fd, _ = _open_directory(Path(state))
    try:
        with _exclusive_named_lock(directory_fd, _LOCK_NAME):
            ready.set()
            assert release.wait(_PROCESS_LIFECYCLE_TIMEOUT_SECONDS)
    finally:
        _close_directory(directory_fd)


def _update_store_child(
    secret_path: str,
    started: EventType,
    finished: EventType,
) -> None:
    started.set()
    update_secret_store(
        Path(secret_path),
        {"Z4J_AUDIT_CHAIN_SECRET": "a" * 48},
    )
    finished.set()


def _hold_bootstrap_coordinator(
    state: str,
    ready: EventType,
    release: EventType,
) -> None:
    try:
        with audit_bootstrap_coordinator(Path(state)):
            ready.set()
            assert release.wait(_PROCESS_LIFECYCLE_TIMEOUT_SECONDS)
    except SecretStoreError:
        # Replacing the diagnostic lock pathname is still reported when the
        # holder exits. Mutual exclusion must remain intact until this point.
        pass


def _enter_bootstrap_coordinator(
    state: str,
    entered: EventType,
    release: EventType,
) -> None:
    with audit_bootstrap_coordinator(Path(state)):
        entered.set()
        assert release.wait(_PROCESS_LIFECYCLE_TIMEOUT_SECONDS)


def _fork_child_then_exit_coordinator_owner(
    state: str,
    owner_ready: EventType,
    release_owner: EventType,
    child_started: EventType,
    child_entered: EventType,
    child_exited: EventType,
    child_failed: EventType,
) -> None:
    with audit_bootstrap_coordinator(Path(state)):
        child_pid = os.fork()
        if child_pid == 0:
            try:
                child_started.set()
                with audit_bootstrap_coordinator(Path(state)):
                    child_entered.set()
                child_exited.set()
                os._exit(0)
            except BaseException:
                child_failed.set()
                os._exit(1)

        child_pid_path = Path(state) / ".fork-child.pid"
        child_pid_path.write_text(str(child_pid), encoding="ascii")
        child_pid_path.chmod(0o600)
        owner_ready.set()
        assert release_owner.wait(_PROCESS_LIFECYCLE_TIMEOUT_SECONDS)
        os._exit(0)


@pytest.fixture
def private_home() -> Iterator[Path]:
    path = Path(tempfile.mkdtemp(prefix="z4j-secret-store-", dir="/tmp"))
    protect_secret_store_directory(path)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
        shutil.rmtree(path.with_name(path.name + "-moved"), ignore_errors=True)


def test_update_preserves_whole_document_and_rereads_winner(
    private_home: Path,
) -> None:
    path = private_home / "secret.env"
    first = update_secret_store(
        path,
        {
            "Z4J_SECRET": "s" * 48,
            "Z4J_SESSION_SECRET": "t" * 48,
        },
    )
    second = update_secret_store(
        path,
        {"Z4J_AUDIT_CHAIN_SECRET": "a" * 48},
    )
    assert first.values["Z4J_SECRET"] == "s" * 48
    assert second.values == {
        "Z4J_AUDIT_CHAIN_SECRET": "a" * 48,
        "Z4J_SECRET": "s" * 48,
        "Z4J_SESSION_SECRET": "t" * 48,
    }
    assert read_secret_store(path).values == second.values
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX lock-inode mutation")
def test_coordinator_detects_lock_path_replacement_while_held(
    private_home: Path,
) -> None:
    lock = private_home / ".z4j-bootstrap-coordinator.lock"
    with (
        pytest.raises(
            SecretStoreError,
            match="lock pathname changed while held",
        ),
        audit_bootstrap_coordinator(private_home),
    ):
        lock.unlink()
        lock.write_bytes(b"replacement inode")
        lock.chmod(0o600)


@pytest.mark.skipif(os.name != "posix", reason="POSIX lock-inode mutation")
def test_coordinator_replacement_cannot_create_concurrent_authority(
    private_home: Path,
) -> None:
    """A replacement lock inode cannot enter while the original is held."""
    import multiprocessing

    context = multiprocessing.get_context("spawn")
    first_ready = context.Event()
    release_first = context.Event()
    second_entered = context.Event()
    release_second = context.Event()
    first = context.Process(
        target=_hold_bootstrap_coordinator,
        args=(str(private_home), first_ready, release_first),
    )
    second = context.Process(
        target=_enter_bootstrap_coordinator,
        args=(str(private_home), second_entered, release_second),
    )
    first.start()
    try:
        assert first_ready.wait(_PROCESS_LIFECYCLE_TIMEOUT_SECONDS)
        lock = private_home / ".z4j-bootstrap-coordinator.lock"
        lock.unlink()
        lock.write_bytes(b"replacement inode")
        lock.chmod(0o600)
        second.start()
        assert not second_entered.wait(0.75)
        release_first.set()
        assert second_entered.wait(_PROCESS_LIFECYCLE_TIMEOUT_SECONDS)
    finally:
        release_first.set()
        release_second.set()
        first.join(_PROCESS_LIFECYCLE_TIMEOUT_SECONDS)
        if second.pid is not None:
            second.join(_PROCESS_LIFECYCLE_TIMEOUT_SECONDS)
    assert first.exitcode == 0
    assert second.exitcode == 0


@pytest.mark.skipif(not hasattr(os, "fork"), reason="real POSIX fork inheritance")
def test_forked_child_cannot_inherit_coordinator_authority(
    private_home: Path,
) -> None:
    """A forked child must reacquire authority after the parent releases it."""
    read_fd, write_fd = os.pipe()
    child_pid: int | None = None
    child_reaped = False
    try:
        with audit_bootstrap_coordinator(private_home):
            child_pid = os.fork()
            if child_pid == 0:
                try:
                    os.close(read_fd)
                    with audit_bootstrap_coordinator(private_home):
                        os.write(write_fd, b"entered")
                    os.close(write_fd)
                    os._exit(0)
                except BaseException:
                    with contextlib.suppress(OSError):
                        os.write(write_fd, b"error")
                    os._exit(1)

            os.close(write_fd)
            write_fd = -1
            ready, _, _ = select.select([read_fd], [], [], 0.75)
            premature = os.read(read_fd, 64) if ready else b""
            assert not ready, (
                "forked child inherited bootstrap authority while the parent "
                f"still held it: {premature!r}"
            )

        ready, _, _ = select.select(
            [read_fd],
            [],
            [],
            _PROCESS_LIFECYCLE_TIMEOUT_SECONDS,
        )
        assert ready, "forked child did not enter after the parent released authority"
        assert os.read(read_fd, 64) == b"entered"
        waited_pid, status = os.waitpid(child_pid, 0)
        child_reaped = True
        assert waited_pid == child_pid
        assert os.waitstatus_to_exitcode(status) == 0
    finally:
        with contextlib.suppress(OSError):
            os.close(read_fd)
        if write_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(write_fd)
        if child_pid is not None and not child_reaped:
            waited_pid, _ = os.waitpid(child_pid, os.WNOHANG)
            if waited_pid == 0:
                with contextlib.suppress(ProcessLookupError):
                    os.kill(child_pid, signal.SIGKILL)
                os.waitpid(child_pid, 0)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="real POSIX fork inheritance")
def test_forked_child_reacquires_after_owner_exits_without_cleanup(
    private_home: Path,
) -> None:
    """The child must not retain lock descriptors when its owner exits."""
    import multiprocessing

    context = multiprocessing.get_context("spawn")
    owner_ready = context.Event()
    release_owner = context.Event()
    child_started = context.Event()
    child_entered = context.Event()
    child_exited = context.Event()
    child_failed = context.Event()
    owner = context.Process(
        target=_fork_child_then_exit_coordinator_owner,
        args=(
            str(private_home),
            owner_ready,
            release_owner,
            child_started,
            child_entered,
            child_exited,
            child_failed,
        ),
    )
    child_pid: int | None = None
    owner.start()
    try:
        assert owner_ready.wait(_PROCESS_LIFECYCLE_TIMEOUT_SECONDS)
        child_pid = int((private_home / ".fork-child.pid").read_text(encoding="ascii"))
        assert child_started.wait(_PROCESS_LIFECYCLE_TIMEOUT_SECONDS)
        assert not child_entered.wait(0.75)
        release_owner.set()
        owner.join(_PROCESS_LIFECYCLE_TIMEOUT_SECONDS)
        assert owner.exitcode == 0
        assert child_entered.wait(_PROCESS_LIFECYCLE_TIMEOUT_SECONDS), (
            "forked child retained the owner's inherited lock descriptors after the owner exited"
        )
        assert child_exited.wait(_PROCESS_LIFECYCLE_TIMEOUT_SECONDS)
        assert not child_failed.is_set()
    finally:
        release_owner.set()
        owner.join(_PROCESS_LIFECYCLE_TIMEOUT_SECONDS)
        if owner.is_alive():
            owner.terminate()
            owner.join(_PROCESS_LIFECYCLE_TIMEOUT_SECONDS)
        if child_pid is not None and not child_exited.is_set():
            with contextlib.suppress(ProcessLookupError):
                os.kill(child_pid, signal.SIGKILL)


@pytest.mark.skipif(os.name != "posix", reason="POSIX nested lock ordering")
def test_coordinator_reuses_directory_authority_for_store_write(
    private_home: Path,
) -> None:
    """Coordinator -> safe-store nesting does not reacquire its directory lock."""
    secret = private_home / "secret.env"
    with audit_bootstrap_coordinator(private_home):
        winner = update_secret_store(
            secret,
            {"Z4J_AUDIT_CHAIN_SECRET": "a" * 48},
        )
    assert winner.values["Z4J_AUDIT_CHAIN_SECRET"] == "a" * 48


@pytest.mark.skipif(os.name != "nt", reason="native Windows lock-path oracle")
def test_windows_coordinator_denies_lock_path_replacement_while_held(
    private_home: Path,
) -> None:
    lock = private_home / ".z4j-bootstrap-coordinator.lock"
    with audit_bootstrap_coordinator(private_home):
        with pytest.raises(PermissionError):
            lock.unlink()
        assert lock.is_file()


def test_fresh_directory_is_created_private_and_delete_is_identity_bound() -> None:
    root = Path(tempfile.mkdtemp(prefix="z4j-secret-parent-", dir="/tmp"))
    state = root / "state"
    try:
        assert ensure_secret_store_directory(state) == state
        secret = state / "secret.env"
        update_secret_store(secret, {"Z4J_SECRET": "s" * 48})
        assert delete_secret_store(secret)
        assert not secret.exists()
        assert not delete_secret_store(secret)
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode repair")
def test_existing_owned_legacy_directory_is_tightened() -> None:
    """A packaged 1.7 volume at 0755 must be safely upgraded to 0700."""
    root = Path(tempfile.mkdtemp(prefix="z4j-secret-legacy-", dir="/tmp"))
    state = root / "state"
    try:
        state.mkdir(mode=0o755)
        state.chmod(0o755)

        assert ensure_secret_store_directory(state) == state

        assert stat.S_IMODE(state.stat().st_mode) == 0o700
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_process_lock_serializes_whole_document_updates(
    private_home: Path,
) -> None:
    import multiprocessing

    secret = private_home / "secret.env"
    update_secret_store(
        secret,
        {"Z4J_METRICS_AUTH_TOKEN": "metrics-winner"},
    )
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    release = context.Event()
    started = context.Event()
    finished = context.Event()
    holder = context.Process(
        target=_hold_store_lock,
        args=(str(private_home), ready, release),
    )
    updater = context.Process(
        target=_update_store_child,
        args=(str(secret), started, finished),
    )
    holder.start()
    try:
        assert ready.wait(_PROCESS_LIFECYCLE_TIMEOUT_SECONDS)
        updater.start()
        assert started.wait(_PROCESS_LIFECYCLE_TIMEOUT_SECONDS)
        assert not finished.wait(0.5)
    finally:
        release.set()
        holder.join(_PROCESS_LIFECYCLE_TIMEOUT_SECONDS)
        if updater.pid is not None:
            updater.join(_PROCESS_LIFECYCLE_TIMEOUT_SECONDS)
    assert holder.exitcode == 0
    assert updater.exitcode == 0
    assert finished.is_set()
    winner = read_secret_store(secret).values
    assert winner["Z4J_METRICS_AUTH_TOKEN"] == "metrics-winner"
    assert winner["Z4J_AUDIT_CHAIN_SECRET"] == "a" * 48


@pytest.mark.skipif(os.name != "nt", reason="native Windows ACL oracle")
def test_windows_permissive_directory_refuses() -> None:
    path = Path(tempfile.mkdtemp(prefix="z4j-secret-permissive-", dir="/tmp"))
    try:
        subprocess.run(
            [
                "icacls.exe",
                str(path),
                "/grant",
                "*S-1-1-0:(OI)(CI)(F)",
            ],
            check=True,
            capture_output=True,
        )
        with pytest.raises(SecretStoreError, match="non-owner trustee"):
            read_secret_store(path / "secret.env")
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.mark.skipif(os.name != "nt", reason="native Windows ACL oracle")
def test_windows_owner_rights_acl_is_owner_private(tmp_path: Path) -> None:
    """OWNER RIGHTS grants only the already-verified object owner access."""
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
    secret = tmp_path / "secret.env"

    update_secret_store(secret, {"Z4J_SECRET": "s" * 48})

    assert read_secret_store(secret).values["Z4J_SECRET"] == "s" * 48


def test_unknown_duplicate_and_malformed_lines_refuse(
    private_home: Path,
) -> None:
    path = private_home / "secret.env"
    for content in (
        "Z4J_DATABASE_URL=sqlite:///attacker\n",
        "Z4J_SECRET=x\nZ4J_SECRET=y\n",
        "not-an-assignment\n",
    ):
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)
        with pytest.raises(SecretStoreError):
            read_secret_store(path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX link/mode oracle")
def test_symlink_and_permissive_file_refuse(
    private_home: Path,
) -> None:
    target = private_home / "target"
    target.write_text("Z4J_SECRET=" + "s" * 48 + "\n", encoding="utf-8")
    target.chmod(0o600)
    path = private_home / "secret.env"
    path.symlink_to(target)
    with pytest.raises(SecretStoreError):
        read_secret_store(path)
    path.unlink()
    path.write_text("Z4J_SECRET=" + "s" * 48 + "\n", encoding="utf-8")
    path.chmod(0o644)
    with pytest.raises(SecretStoreError, match="owner-private"):
        read_secret_store(path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory oracle")
def test_directory_swap_is_rejected(private_home: Path, monkeypatch) -> None:
    path = private_home / "secret.env"
    update_secret_store(path, {"Z4J_SECRET": "s" * 48})

    original = os.replace
    swapped = False

    def swap_after_file_replace(src, dst, *args, **kwargs):
        nonlocal swapped
        result = original(src, dst, *args, **kwargs)
        if not swapped and kwargs.get("dst_dir_fd") is not None:
            swapped = True
            moved = private_home.with_name(private_home.name + "-moved")
            original(private_home, moved)
            private_home.mkdir(mode=0o700)
        return result

    monkeypatch.setattr(os, "replace", swap_after_file_replace)
    with pytest.raises(
        SecretStoreError,
        match=r"(directory pathname changed|pathname changed after read)",
    ):
        update_secret_store(path, {"Z4J_SESSION_SECRET": "t" * 48})


@pytest.mark.skipif(os.name != "nt", reason="native Windows handle oracle")
def test_windows_held_directory_prevents_parent_swap(
    private_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from z4j_brain import _windows_secure_io as windows_io

    path = private_home / "secret.env"
    update_secret_store(path, {"Z4J_SECRET": "s" * 48})
    original = windows_io.replace_open_handle
    swap_refused = False

    def swap_after_file_replace(
        source_handle: int,
        directory_handle: int,
        destination_name: str,
    ) -> None:
        nonlocal swap_refused
        original(source_handle, directory_handle, destination_name)
        moved = private_home.with_name(private_home.name + "-moved")
        try:
            private_home.replace(moved)
        except PermissionError:
            swap_refused = True
            return
        private_home.mkdir()
        protect_secret_store_directory(private_home)

    monkeypatch.setattr(windows_io, "replace_open_handle", swap_after_file_replace)
    update_secret_store(path, {"Z4J_SESSION_SECRET": "t" * 48})

    assert swap_refused
    assert read_secret_store(path).values["Z4J_SESSION_SECRET"] == "t" * 48
