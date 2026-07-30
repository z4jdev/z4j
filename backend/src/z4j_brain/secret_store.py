"""Identity-bound, process-locked storage for packaged z4j secrets.

This module is the only supported reader/writer for ``secret.env``.  It keeps
the complete allowed-key document under one OS lock, rejects links and
permissive POSIX ownership/modes, and performs an fsynced atomic replacement
followed by a winner reread.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import stat
import threading
from collections.abc import Iterable, Iterator, Mapping
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

ALLOWED_SECRET_STORE_KEYS = frozenset(
    {
        "Z4J_SECRET",
        "Z4J_SESSION_SECRET",
        "Z4J_METRICS_AUTH_TOKEN",
        "Z4J_AUDIT_CHAIN_SECRET",
        "Z4J_AUDIT_CHAIN_PREVIOUS_SECRETS",
    }
)
_MAX_SECRET_STORE_BYTES = 128 * 1024
_LOCK_NAME = ".z4j-secret-store.lock"
_COORDINATOR_LOCK_NAME = ".z4j-bootstrap-coordinator.lock"
_active_coordinator: ContextVar[tuple[int, Path, tuple[int, int]] | None] = ContextVar(
    "z4j_active_bootstrap_coordinator",
    default=None,
)
_active_posix_directory_locks: ContextVar[tuple[tuple[int, int, int], ...]] = ContextVar(
    "z4j_active_posix_secret_store_directory_locks",
    default=(),
)
_posix_lock_registry_guard = threading.Lock()
_posix_lock_fds: set[int] = set()


def _prepare_posix_fork() -> None:
    _posix_lock_registry_guard.acquire()


def _resume_posix_parent_after_fork() -> None:
    _posix_lock_registry_guard.release()


def _reset_posix_child_after_fork() -> None:
    """Drop inherited lock capabilities before child code can reuse them."""

    try:
        for fd in tuple(_posix_lock_fds):
            with contextlib.suppress(OSError):
                os.close(fd)
        _posix_lock_fds.clear()
        _active_coordinator.set(None)
        _active_posix_directory_locks.set(())
    finally:
        _posix_lock_registry_guard.release()


if os.name == "posix" and hasattr(os, "register_at_fork"):
    os.register_at_fork(
        before=_prepare_posix_fork,
        after_in_parent=_resume_posix_parent_after_fork,
        after_in_child=_reset_posix_child_after_fork,
    )


class SecretStoreError(RuntimeError):
    """The secret store could not be proved safe or internally consistent."""


@dataclass(frozen=True, slots=True)
class SecretStoreSnapshot:
    values: dict[str, str]
    path: Path
    directory_identity: tuple[int, int]
    file_identity: tuple[int, int] | None


def _identity(st: os.stat_result) -> tuple[int, int]:
    return (int(st.st_dev), int(st.st_ino))


def _validate_directory(path: Path) -> tuple[int, int]:
    if os.name == "nt":
        try:
            from z4j_brain._windows_secure_io import directory_path_identity

            return directory_path_identity(path)
        except OSError as exc:
            raise SecretStoreError(
                f"cannot prove owner-private Windows secret-store directory {path}: {exc}",
            ) from exc

    try:
        st = path.lstat()
    except OSError as exc:
        raise SecretStoreError(f"cannot inspect secret-store directory {path}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise SecretStoreError(
            f"secret-store directory must be a real directory, not a link: {path}",
        )
    if os.name == "posix":
        if st.st_uid != os.getuid():
            raise SecretStoreError(
                f"secret-store directory is not owned by the current uid: {path}",
            )
        if st.st_mode & 0o077:
            raise SecretStoreError(
                f"secret-store directory must be owner-private (chmod 700 {path})",
            )
    return _identity(st)


def _open_directory(path: Path) -> tuple[int, tuple[int, int]]:
    before = _validate_directory(path)
    if os.name == "nt":
        try:
            from z4j_brain._windows_secure_io import open_directory

            handle, opened_identity = open_directory(path)
        except OSError as exc:
            raise SecretStoreError(
                f"cannot safely open secret-store directory {path}: {exc}",
            ) from exc
        after = _validate_directory(path)
        if before != opened_identity or opened_identity != after:
            from z4j_brain._windows_secure_io import close_handle

            close_handle(handle)
            raise SecretStoreError(
                "secret-store directory identity changed while it was opened",
            )
        return handle, opened_identity

    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise SecretStoreError(f"cannot safely open secret-store directory {path}: {exc}") from exc
    opened = os.fstat(fd)
    after = _validate_directory(path)
    if before != _identity(opened) or _identity(opened) != after:
        os.close(fd)
        raise SecretStoreError(
            "secret-store directory identity changed while it was opened",
        )
    return fd, _identity(opened)


def _close_directory(directory_fd: int) -> None:
    if os.name == "nt":
        from z4j_brain._windows_secure_io import close_handle

        close_handle(directory_fd)
        return
    os.close(directory_fd)


def _parse_document(raw: bytes) -> dict[str, str]:
    if len(raw) > _MAX_SECRET_STORE_BYTES:
        raise SecretStoreError("secret.env exceeds the 128 KiB safety bound")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SecretStoreError("secret.env is not valid UTF-8") from exc
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise SecretStoreError(
                f"secret.env line {line_number} is malformed (missing '=')",
            )
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key not in ALLOWED_SECRET_STORE_KEYS:
            raise SecretStoreError(
                f"secret.env line {line_number} contains unsupported key {key!r}; "
                "put non-secret settings in config.env",
            )
        if key in values:
            raise SecretStoreError(
                f"secret.env contains duplicate key {key!r}",
            )
        if not value:
            raise SecretStoreError(
                f"secret.env key {key!r} has an empty value",
            )
        if "\x00" in value:
            raise SecretStoreError(
                f"secret.env key {key!r} contains a NUL byte",
            )
        values[key] = value
    return values


def _serialize_document(values: Mapping[str, str]) -> bytes:
    unknown = set(values) - ALLOWED_SECRET_STORE_KEYS
    if unknown:
        raise SecretStoreError(
            f"refusing unsupported secret-store keys: {sorted(unknown)!r}",
        )
    lines: list[str] = []
    for key in sorted(values):
        value = values[key]
        if not value or "\n" in value or "\r" in value or "\x00" in value:
            raise SecretStoreError(f"secret-store value for {key} is malformed")
        lines.append(f"{key}={value}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _read_relative(  # noqa: PLR0912  platform-specific identity validation
    directory_fd: int,
    directory_path: Path,
    name: str,
) -> tuple[dict[str, str], tuple[int, int] | None]:
    if os.name == "nt":
        try:
            from z4j_brain._windows_secure_io import read_relative

            raw, file_identity = read_relative(
                directory_fd,
                name,
                maximum_bytes=_MAX_SECRET_STORE_BYTES,
            )
        except OSError as exc:
            raise SecretStoreError(
                f"cannot safely open {directory_path / name}: {exc}",
            ) from exc
        if file_identity is None:
            return {}, None
        return _parse_document(raw), file_identity

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        return {}, None
    except OSError as exc:
        raise SecretStoreError(f"cannot safely open {directory_path / name}: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise SecretStoreError("secret.env must be a regular file")
        if os.name == "posix":
            if before.st_uid != os.getuid():
                raise SecretStoreError("secret.env is not owned by the current uid")
            if before.st_mode & 0o077:
                raise SecretStoreError(
                    "secret.env must be owner-private (chmod 600)",
                )
        chunks: list[bytes] = []
        remaining = _MAX_SECRET_STORE_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if _identity(before) != _identity(after) or before.st_size != after.st_size:
            raise SecretStoreError("secret.env changed while it was read")
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    try:
        path_st = (directory_path / name).lstat()
    except OSError as exc:
        raise SecretStoreError("secret.env pathname changed after read") from exc
    if stat.S_ISLNK(path_st.st_mode) or _identity(path_st) != _identity(after):
        raise SecretStoreError("secret.env pathname no longer names the opened file")
    return _parse_document(raw), _identity(after)


@contextlib.contextmanager
def _exclusive_posix_directory_lock(
    directory_fd: int,
) -> Iterator[None]:
    """Serialize lock-file acquisition on the held directory inode."""

    import fcntl

    owner_pid = os.getpid()
    try:
        directory_st = os.fstat(directory_fd)
    except OSError as exc:
        raise SecretStoreError(
            f"cannot inspect secret-store lock directory: {exc}",
        ) from exc
    if not stat.S_ISDIR(directory_st.st_mode):
        raise SecretStoreError("secret-store lock directory is not a directory")
    directory_identity = (os.getpid(), *_identity(directory_st))
    active = _active_posix_directory_locks.get()
    if directory_identity in active:
        yield
        return
    with _posix_lock_registry_guard:
        _posix_lock_fds.add(directory_fd)
    try:
        fcntl.flock(directory_fd, fcntl.LOCK_EX)
    except OSError as exc:
        with _posix_lock_registry_guard:
            _posix_lock_fds.discard(directory_fd)
        raise SecretStoreError(
            f"cannot acquire stable secret-store directory lock: {exc}",
        ) from exc
    token = _active_posix_directory_locks.set((*active, directory_identity))
    try:
        yield
    finally:
        if os.getpid() == owner_pid:
            _active_posix_directory_locks.reset(token)
            with _posix_lock_registry_guard:
                with contextlib.suppress(OSError):
                    fcntl.flock(directory_fd, fcntl.LOCK_UN)
                _posix_lock_fds.discard(directory_fd)


def _posix_named_lock_path_changed(
    directory_fd: int,
    name: str,
    lock_identity: tuple[int, int] | None,
) -> bool:
    if lock_identity is None:
        return False
    try:
        final_path_st = os.stat(
            name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except OSError:
        return True
    return stat.S_ISLNK(final_path_st.st_mode) or _identity(final_path_st) != lock_identity


@contextlib.contextmanager
def _exclusive_posix_named_lock(
    directory_fd: int,
    name: str,
) -> Iterator[None]:
    owner_pid = os.getpid()
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    with _posix_lock_registry_guard:
        fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
        _posix_lock_fds.add(fd)
    lock_identity: tuple[int, int] | None = None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SecretStoreError("secret-store lock is not a regular file")
        if os.name == "posix":
            if st.st_uid != os.getuid():
                raise SecretStoreError(
                    "secret-store lock is not owned by the current uid",
                )
            if st.st_mode & 0o077:
                raise SecretStoreError(
                    "secret-store lock must be owner-private (chmod 600)",
                )
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
        lock_identity = _identity(st)
        try:
            path_st = os.stat(
                name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise SecretStoreError(
                "secret-store lock pathname changed while acquiring",
            ) from exc
        if stat.S_ISLNK(path_st.st_mode) or _identity(path_st) != lock_identity:
            raise SecretStoreError(
                "secret-store lock pathname no longer names the locked inode",
            )
        yield
    finally:
        if os.getpid() == owner_pid:
            pathname_changed = _posix_named_lock_path_changed(
                directory_fd,
                name,
                lock_identity,
            )
            import fcntl

            with _posix_lock_registry_guard:
                with contextlib.suppress(OSError):
                    fcntl.flock(fd, fcntl.LOCK_UN)
                try:
                    os.close(fd)
                finally:
                    _posix_lock_fds.discard(fd)
            if pathname_changed:
                raise SecretStoreError(
                    "secret-store lock pathname changed while held",
                )


@contextlib.contextmanager
def _exclusive_named_lock(
    directory_fd: int,
    name: str,
) -> Iterator[None]:
    if os.name == "nt":
        lock_stack = contextlib.ExitStack()
        try:
            from z4j_brain._windows_secure_io import exclusive_relative_lock

            lock_stack.enter_context(exclusive_relative_lock(directory_fd, name))
        except OSError as exc:
            lock_stack.close()
            raise SecretStoreError(
                f"cannot acquire owner-private Windows safe-store lock {name}: {exc}",
            ) from exc
        with lock_stack:
            yield
        return

    # A flock on a named file does not survive replacement of that pathname:
    # another process can otherwise open and lock the replacement inode while
    # this process still owns the original. The already identity-pinned state
    # directory provides one stable acquisition authority for both lock names;
    # the surrounding path-identity checks still reject replacement of the
    # directory itself. Context-local nesting lets coordinator -> safe-store
    # ordering reuse that authority without self-deadlocking.
    with (
        _exclusive_posix_directory_lock(directory_fd),
        _exclusive_posix_named_lock(directory_fd, name),
    ):
        yield


@contextlib.contextmanager
def audit_bootstrap_coordinator(directory: Path) -> Iterator[None]:
    """Hold the process-wide SQLite bootstrap/migration coordinator.

    Nested migration code observes the live context variable and reuses the
    caller's authority instead of recursively acquiring the OS lock.
    """

    owner_pid = os.getpid()
    active = _active_coordinator.get()
    if active is not None:
        active_pid, active_path, active_identity = active
        if active_pid != owner_pid:
            raise SecretStoreError(
                "bootstrap coordinator authority was inherited across fork",
            )
        if active_path != directory or _validate_directory(directory) != active_identity:
            raise SecretStoreError(
                "nested bootstrap coordinator targets a different state directory",
            )
        yield
        return

    directory_fd, directory_identity = _open_directory(directory)
    token = None
    try:
        with _exclusive_named_lock(directory_fd, _COORDINATOR_LOCK_NAME):
            if _validate_directory(directory) != directory_identity:
                raise SecretStoreError("bootstrap coordinator directory pathname changed")
            token = _active_coordinator.set((owner_pid, directory, directory_identity))
            try:
                yield
            finally:
                if (
                    os.getpid() == owner_pid
                    and _validate_directory(directory) != directory_identity
                ):
                    raise SecretStoreError(
                        "bootstrap coordinator directory pathname changed",
                    )
    finally:
        if os.getpid() == owner_pid:
            if token is not None:
                _active_coordinator.reset(token)
            _close_directory(directory_fd)


def read_secret_store(path: Path) -> SecretStoreSnapshot:
    """Read and validate the complete store without following a pathname link."""

    directory_fd, directory_identity = _open_directory(path.parent)
    try:
        values, file_identity = _read_relative(
            directory_fd,
            path.parent,
            path.name,
        )
        if _validate_directory(path.parent) != directory_identity:
            raise SecretStoreError("secret-store directory pathname changed")
        return SecretStoreSnapshot(
            values=values,
            path=path,
            directory_identity=directory_identity,
            file_identity=file_identity,
        )
    finally:
        _close_directory(directory_fd)


def update_secret_store(  # noqa: PLR0912, PLR0915  platform-specific atomic writer
    path: Path,
    updates: Mapping[str, str],
    *,
    remove: Iterable[str] = (),
) -> SecretStoreSnapshot:
    """Merge updates under the common lock and return the persisted winner."""

    removals = tuple(remove)
    unknown_removals = set(removals) - ALLOWED_SECRET_STORE_KEYS
    if unknown_removals:
        raise SecretStoreError(
            f"refusing unsupported secret-store removals: {sorted(unknown_removals)!r}",
        )
    overlap = set(updates) & set(removals)
    if overlap:
        raise SecretStoreError(
            f"secret-store keys cannot be updated and removed together: {sorted(overlap)!r}",
        )
    directory_fd, directory_identity = _open_directory(path.parent)
    try:
        with _exclusive_named_lock(directory_fd, _LOCK_NAME):
            current, _ = _read_relative(directory_fd, path.parent, path.name)
            merged = {**current, **dict(updates)}
            for key in removals:
                merged.pop(key, None)
            payload = _serialize_document(merged)
            temp_name = f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
            if os.name == "nt":
                from z4j_brain._windows_secure_io import (
                    close_handle,
                    create_relative_file,
                    replace_open_handle,
                )

                temp_handle = create_relative_file(
                    directory_fd,
                    temp_name,
                    payload,
                )
                try:
                    replace_open_handle(
                        temp_handle,
                        directory_fd,
                        path.name,
                    )
                finally:
                    close_handle(temp_handle)
            else:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                temp_fd = os.open(temp_name, flags, 0o600, dir_fd=directory_fd)
                try:
                    offset = 0
                    while offset < len(payload):
                        offset += os.write(temp_fd, payload[offset:])
                    os.fsync(temp_fd)
                except BaseException:
                    with contextlib.suppress(OSError):
                        os.unlink(temp_name, dir_fd=directory_fd)
                    raise
                finally:
                    os.close(temp_fd)
                try:
                    os.replace(
                        temp_name,
                        path.name,
                        src_dir_fd=directory_fd,
                        dst_dir_fd=directory_fd,
                    )
                    with contextlib.suppress(OSError):
                        os.fsync(directory_fd)
                except BaseException:
                    with contextlib.suppress(OSError):
                        os.unlink(temp_name, dir_fd=directory_fd)
                    raise
            winner, file_identity = _read_relative(
                directory_fd,
                path.parent,
                path.name,
            )
            if winner != merged:
                raise SecretStoreError(
                    "secret-store winner differs from the fsynced replacement",
                )
        if _validate_directory(path.parent) != directory_identity:
            raise SecretStoreError("secret-store directory pathname changed")
        return SecretStoreSnapshot(
            values=winner,
            path=path,
            directory_identity=directory_identity,
            file_identity=file_identity,
        )
    finally:
        _close_directory(directory_fd)


def delete_secret_store(path: Path) -> bool:
    """Remove the validated store under the common writer lock."""

    directory_fd, directory_identity = _open_directory(path.parent)
    try:
        with _exclusive_named_lock(directory_fd, _LOCK_NAME):
            _, file_identity = _read_relative(
                directory_fd,
                path.parent,
                path.name,
            )
            if file_identity is None:
                return False
            try:
                if os.name == "nt":
                    from z4j_brain._windows_secure_io import delete_relative

                    delete_relative(
                        directory_fd,
                        path.name,
                        expected_identity=file_identity,
                    )
                else:
                    os.unlink(path.name, dir_fd=directory_fd)
                    with contextlib.suppress(OSError):
                        os.fsync(directory_fd)
            except OSError as exc:
                raise SecretStoreError(f"cannot remove {path}: {exc}") from exc
        if _validate_directory(path.parent) != directory_identity:
            raise SecretStoreError("secret-store directory pathname changed")
        return True
    finally:
        _close_directory(directory_fd)


def protect_secret_store_directory(path: Path) -> None:
    """Apply the platform's owner-private state-directory protection."""

    if os.name == "nt":
        try:
            from z4j_brain._windows_secure_io import protect_directory

            protect_directory(path)
        except OSError as exc:
            raise SecretStoreError(
                f"cannot install owner-private Windows ACL on {path}: {exc}",
            ) from exc
        return
    path.chmod(0o700)


def _tighten_owned_posix_directory(path: Path) -> None:
    """Safely tighten an existing owner directory through its open handle.

    Packaged 1.7 images created ``/data`` as mode 0755.  A 1.8 management
    container must be able to bring that same owned volume up to the 0700
    invariant before it reads any secret or database file.  Opening with
    ``O_NOFOLLOW`` and checking the inode before and after the handle-based
    chmod prevents a pathname swap from turning this compatibility repair
    into a chmod primitive for another directory.
    """

    try:
        before = path.lstat()
    except OSError as exc:
        raise SecretStoreError(
            f"cannot inspect secret-store directory {path}: {exc}",
        ) from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise SecretStoreError(
            f"secret-store directory must be a real directory, not a link: {path}",
        )
    if before.st_uid != os.getuid():
        raise SecretStoreError(
            f"secret-store directory is not owned by the current uid: {path}",
        )
    if not before.st_mode & 0o077:
        return

    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        directory_fd = os.open(path, flags)
    except OSError as exc:
        raise SecretStoreError(
            f"cannot safely open legacy secret-store directory {path}: {exc}",
        ) from exc
    try:
        opened = os.fstat(directory_fd)
        after_open = path.lstat()
        expected_identity = _identity(before)
        if (
            _identity(opened) != expected_identity
            or _identity(after_open) != expected_identity
            or not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.getuid()
        ):
            raise SecretStoreError(
                "secret-store directory identity changed before mode repair",
            )
        os.fchmod(directory_fd, 0o700)
        with contextlib.suppress(OSError):
            os.fsync(directory_fd)
        hardened = os.fstat(directory_fd)
        after = path.lstat()
        if (
            _identity(hardened) != expected_identity
            or _identity(after) != expected_identity
            or hardened.st_mode & 0o077
            or after.st_mode & 0o077
        ):
            raise SecretStoreError(
                "secret-store directory identity changed during mode repair",
            )
    except OSError as exc:
        raise SecretStoreError(
            f"cannot make legacy secret-store directory owner-private {path}: {exc}",
        ) from exc
    finally:
        os.close(directory_fd)


def ensure_secret_store_directory(path: Path) -> Path:
    """Create or validate the owner-private safe-store directory."""

    if os.name == "nt":
        try:
            from z4j_brain._windows_secure_io import ensure_private_directory

            ensure_private_directory(path)
        except OSError as exc:
            raise SecretStoreError(
                f"cannot create/validate owner-private Windows directory {path}: {exc}",
            ) from exc
    else:
        try:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise SecretStoreError(
                f"cannot create secret-store directory {path}: {exc}",
            ) from exc
        _tighten_owned_posix_directory(path)
        _validate_directory(path)
    return path


__all__ = [
    "ALLOWED_SECRET_STORE_KEYS",
    "SecretStoreError",
    "SecretStoreSnapshot",
    "audit_bootstrap_coordinator",
    "delete_secret_store",
    "ensure_secret_store_directory",
    "protect_secret_store_directory",
    "read_secret_store",
    "update_secret_store",
]
