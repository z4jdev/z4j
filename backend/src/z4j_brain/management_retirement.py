"""Crash-resumable packaged-SQLite installation retirement.

The old database, SQLite sidecars, and complete safe-store document move as
one journaled authority bundle before a fresh packaged bootstrap is allowed.
The retained bundle can be removed only by the replacement installation whose
authenticated audit state carries the exact recovery binding.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import errno
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import uuid
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

from sqlalchemy.engine import make_url

from z4j_brain.configuration import (
    capture_configuration,
    merge_secret_store_snapshot,
    overlay_runtime_environment,
    settings_from_snapshot,
)
from z4j_brain.domain.audit_chain import (
    AuditChainIntegrityError,
    authenticate_state,
    build_audit_keyring,
    canonical_json,
    canonical_retired_recovery_binding,
    canonical_state_payload,
    compute_state_mac,
)
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.audit_verifier import verify_active_audit_generation
from z4j_brain.management_reset import release_manifest_digest
from z4j_brain.persistence.database import (
    DatabaseManager,
    create_async_engine_from_url,
)
from z4j_brain.persistence.models import AuditChainState
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.secret_store import (
    ALLOWED_SECRET_STORE_KEYS,
    _close_directory,
    _exclusive_named_lock,
    _open_directory,
    _validate_directory,
    audit_bootstrap_coordinator,
    ensure_secret_store_directory,
    read_secret_store,
)
from z4j_brain.settings import Settings

RETIREMENT_JOURNAL_NAME = ".z4j-installation-retirement.json"
RETIREMENT_JOURNAL_VERSION = 1
RECOVERY_ROOT_NAME = "retired-installations"
BUNDLE_MANIFEST_NAME = "bundle-manifest.json"
DESTRUCTION_JOURNAL_PREFIX = ".z4j-retired-destruction-"
_SECRET_LOCK_NAME = ".z4j-secret-store.lock"  # noqa: S105  lock filename, not a secret
_MAX_JOURNAL_BYTES = 4 * 1024 * 1024
_REQUIRED_PACKAGED_SECRETS = frozenset(
    {
        "Z4J_SECRET",
        "Z4J_SESSION_SECRET",
        "Z4J_METRICS_AUTH_TOKEN",
        "Z4J_AUDIT_CHAIN_SECRET",
    },
)


class InstallationRetirementRefused(RuntimeError):  # noqa: N818  refusal signal
    """The requested retirement or destruction lacks exact authority."""


def _identity(st: os.stat_result) -> tuple[int, int]:
    return (int(st.st_dev), int(st.st_ino))


def _lexical_absolute(path: Path) -> Path:
    """Make a path absolute without following its final symlink/reparse point."""

    return Path(os.path.abspath(os.fspath(path.expanduser())))  # noqa: PTH100


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_bytes_relative(
    directory_fd: int,
    directory_path: Path,
    name: str,
    *,
    maximum_bytes: int,
) -> tuple[bytes, tuple[int, int]]:
    if os.name == "nt":
        from z4j_brain._windows_secure_io import read_relative

        raw, identity = read_relative(
            directory_fd,
            name,
            maximum_bytes=maximum_bytes,
        )
        if identity is None:
            raise FileNotFoundError(directory_path / name)
        return raw, identity

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(name, flags, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_mode & 0o077
        ):
            raise InstallationRetirementRefused(
                f"retirement metadata must be an owner-private regular file: "
                f"{directory_path / name}",
            )
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if (
        len(raw) > maximum_bytes
        or _identity(before) != _identity(after)
        or before.st_size != after.st_size
    ):
        raise InstallationRetirementRefused(
            f"retirement metadata changed while read: {directory_path / name}",
        )
    path_st = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if stat.S_ISLNK(path_st.st_mode) or _identity(path_st) != _identity(after):
        raise InstallationRetirementRefused(
            f"retirement metadata pathname changed: {directory_path / name}",
        )
    return raw, _identity(after)


def _write_canonical_json(path: Path, value: Mapping[str, Any]) -> None:
    ensure_secret_store_directory(path.parent)
    payload = canonical_json(dict(value)) + b"\n"
    if len(payload) > _MAX_JOURNAL_BYTES:
        raise InstallationRetirementRefused(
            f"retirement metadata exceeds {_MAX_JOURNAL_BYTES} bytes",
        )
    directory_fd, directory_identity = _open_directory(path.parent)
    temp_name = f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    try:
        if os.name == "nt":
            from z4j_brain._windows_secure_io import (
                close_handle,
                create_relative_file,
                delete_relative,
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
            except BaseException:
                with contextlib.suppress(OSError):
                    delete_relative(directory_fd, temp_name)
                raise
            finally:
                close_handle(temp_handle)
        else:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(temp_name, flags, 0o600, dir_fd=directory_fd)
            try:
                offset = 0
                while offset < len(payload):
                    offset += os.write(fd, payload[offset:])
                os.fsync(fd)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(temp_name, dir_fd=directory_fd)
                raise
            finally:
                os.close(fd)
            os.replace(
                temp_name,
                path.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            with contextlib.suppress(OSError):
                os.fsync(directory_fd)
        winner, _ = _read_bytes_relative(
            directory_fd,
            path.parent,
            path.name,
            maximum_bytes=_MAX_JOURNAL_BYTES,
        )
        if winner != payload:
            raise InstallationRetirementRefused(
                f"retirement metadata winner differs after replace: {path}",
            )
        if _validate_directory(path.parent) != directory_identity:
            raise InstallationRetirementRefused(
                f"retirement metadata parent pathname changed: {path.parent}",
            )
    finally:
        _close_directory(directory_fd)


def _read_canonical_json(path: Path) -> dict[str, Any]:
    directory_fd, directory_identity = _open_directory(path.parent)
    try:
        try:
            raw, _ = _read_bytes_relative(
                directory_fd,
                path.parent,
                path.name,
                maximum_bytes=_MAX_JOURNAL_BYTES,
            )
        except OSError as exc:
            raise InstallationRetirementRefused(
                f"cannot inspect retirement metadata {path}: {exc}",
            ) from exc
        final_directory_identity = _validate_directory(path.parent)
    finally:
        _close_directory(directory_fd)
    if final_directory_identity != directory_identity:
        raise InstallationRetirementRefused(
            f"retirement metadata parent pathname changed: {path.parent}",
        )

    def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise InstallationRetirementRefused(
                    f"retirement metadata contains duplicate key {key!r}",
                )
            result[key] = item
        return result

    try:
        value = json.loads(raw, object_pairs_hook=_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallationRetirementRefused(
            f"retirement metadata is not canonical JSON: {path}",
        ) from exc
    if not isinstance(value, dict) or canonical_json(value) + b"\n" != raw:
        raise InstallationRetirementRefused(
            f"retirement metadata is not canonically encoded: {path}",
        )
    return value


def _file_digest_and_identity(path: Path) -> dict[str, Any]:
    directory_fd, directory_identity = _open_directory(path.parent)
    try:
        if os.name == "nt":
            from z4j_brain._windows_secure_io import digest_relative_file

            identity, size, digest, link_count = digest_relative_file(
                directory_fd,
                path.name,
            )
            mode = 0
        else:
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(path.name, flags, dir_fd=directory_fd)
            hasher = hashlib.sha256()
            size = 0
            try:
                before = os.fstat(fd)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_uid != os.getuid()
                    or before.st_mode & 0o077
                ):
                    raise InstallationRetirementRefused(
                        f"retirement artifact must be owner-private: {path}",
                    )
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    size += len(chunk)
                after = os.fstat(fd)
            finally:
                os.close(fd)
            final_path_st = os.stat(
                path.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if (
                stat.S_ISLNK(final_path_st.st_mode)
                or _identity(before) != _identity(after)
                or _identity(after) != _identity(final_path_st)
                or before.st_size != after.st_size
                or size != after.st_size
            ):
                raise InstallationRetirementRefused(
                    f"retirement artifact changed while read: {path}",
                )
            identity = _identity(after)
            digest = hasher.hexdigest()
            link_count = int(after.st_nlink)
            mode = int(stat.S_IMODE(after.st_mode))
        if link_count != 1:
            raise InstallationRetirementRefused(
                f"retirement artifact has a hard-link alias: {path}",
            )
        if _validate_directory(path.parent) != directory_identity:
            raise InstallationRetirementRefused(
                f"retirement artifact parent pathname changed: {path.parent}",
            )
    except OSError as exc:
        raise InstallationRetirementRefused(
            f"cannot inspect retirement artifact {path}: {exc}",
        ) from exc
    finally:
        _close_directory(directory_fd)
    return {
        "name": path.name,
        "device": identity[0],
        "inode": identity[1],
        "size": size,
        "sha256": digest,
        "mode": mode,
    }


def _entry_matches(path: Path, entry: Mapping[str, Any]) -> bool:
    try:
        observed = _file_digest_and_identity(path)
    except (FileNotFoundError, InstallationRetirementRefused):
        return False
    return all(
        observed.get(key) == entry.get(key)
        for key in ("name", "device", "inode", "size", "sha256", "mode")
    )


def _regular_file_identity(path: Path) -> tuple[int, int] | None:
    directory_fd, directory_identity = _open_directory(path.parent)
    try:
        if os.name == "nt":
            from z4j_brain._windows_secure_io import relative_file_identity

            identity = relative_file_identity(directory_fd, path.name)
        else:
            try:
                observed = os.stat(
                    path.name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                identity = None
            else:
                if (
                    stat.S_ISLNK(observed.st_mode)
                    or not stat.S_ISREG(observed.st_mode)
                    or observed.st_uid != os.getuid()
                    or observed.st_mode & 0o077
                ):
                    raise InstallationRetirementRefused(
                        f"retirement path is not an owner-private regular file: {path}",
                    )
                identity = _identity(observed)
        if _validate_directory(path.parent) != directory_identity:
            raise InstallationRetirementRefused(
                f"retirement parent pathname changed: {path.parent}",
            )
        return identity
    finally:
        _close_directory(directory_fd)


def _rename_no_replace(
    source_fd: int,
    source_name: str,
    destination_fd: int,
    destination_name: str,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise InstallationRetirementRefused(
            "this POSIX platform cannot prove a no-overwrite retirement rename",
        )
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        source_fd,
        os.fsencode(source_name),
        destination_fd,
        os.fsencode(destination_name),
        1,  # RENAME_NOREPLACE
    )
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(error, os.strerror(error), destination_name)
        raise OSError(error, os.strerror(error), source_name)


def _move_exact_file(
    source: Path,
    destination: Path,
    *,
    expected_identity: tuple[int, int],
) -> None:
    source_fd, source_parent_identity = _open_directory(source.parent)
    destination_fd, destination_parent_identity = _open_directory(
        destination.parent,
    )
    try:
        if os.name == "nt":
            from z4j_brain._windows_secure_io import move_relative_file

            move_relative_file(
                source_fd,
                source.name,
                destination_fd,
                destination.name,
                expected_identity=expected_identity,
            )
        else:
            observed = os.stat(
                source.name,
                dir_fd=source_fd,
                follow_symlinks=False,
            )
            if stat.S_ISLNK(observed.st_mode) or _identity(observed) != expected_identity:
                raise InstallationRetirementRefused(
                    f"retirement source identity changed: {source}",
                )
            _rename_no_replace(
                source_fd,
                source.name,
                destination_fd,
                destination.name,
            )
            with contextlib.suppress(OSError):
                os.fsync(source_fd)
            with contextlib.suppress(OSError):
                os.fsync(destination_fd)
        if (
            _validate_directory(source.parent) != source_parent_identity
            or _validate_directory(destination.parent) != destination_parent_identity
        ):
            raise InstallationRetirementRefused(
                "retirement move parent pathname changed",
            )
    finally:
        _close_directory(destination_fd)
        _close_directory(source_fd)


def _unlink_exact_file(
    path: Path,
    *,
    expected_identity: tuple[int, int] | None = None,
    missing_ok: bool = False,
) -> bool:
    directory_fd, directory_identity = _open_directory(path.parent)
    try:
        observed = _regular_file_identity(path)
        if observed is None:
            if missing_ok:
                return False
            raise FileNotFoundError(path)
        if expected_identity is not None and observed != expected_identity:
            raise InstallationRetirementRefused(
                f"retirement unlink identity changed: {path}",
            )
        if os.name == "nt":
            from z4j_brain._windows_secure_io import delete_relative

            delete_relative(
                directory_fd,
                path.name,
                expected_identity=observed,
            )
        else:
            current = os.stat(
                path.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if stat.S_ISLNK(current.st_mode) or _identity(current) != observed:
                raise InstallationRetirementRefused(
                    f"retirement unlink pathname changed: {path}",
                )
            os.unlink(path.name, dir_fd=directory_fd)
            with contextlib.suppress(OSError):
                os.fsync(directory_fd)
        if _validate_directory(path.parent) != directory_identity:
            raise InstallationRetirementRefused(
                f"retirement unlink parent pathname changed: {path.parent}",
            )
        return True
    finally:
        _close_directory(directory_fd)


def _ensure_private_child_directory(parent: Path, name: str) -> Path:
    child = parent / name
    parent_fd, parent_identity = _open_directory(parent)
    try:
        if os.name == "nt":
            from z4j_brain._windows_secure_io import (
                create_relative_directory,
                relative_directory_identity,
            )

            identity = relative_directory_identity(parent_fd, name)
            if identity is None:
                identity = create_relative_directory(parent_fd, name)
        else:
            with contextlib.suppress(FileExistsError):
                os.mkdir(name, mode=0o700, dir_fd=parent_fd)
            identity = _validate_directory(child)
        if _validate_directory(parent) != parent_identity or _validate_directory(child) != identity:
            raise InstallationRetirementRefused(
                f"retirement directory pathname changed: {child}",
            )
        return child
    finally:
        _close_directory(parent_fd)


def _directory_identity_optional(path: Path) -> tuple[int, int] | None:
    parent_fd, parent_identity = _open_directory(path.parent)
    try:
        if os.name == "nt":
            from z4j_brain._windows_secure_io import relative_directory_identity

            identity = relative_directory_identity(parent_fd, path.name)
        else:
            try:
                observed = os.stat(
                    path.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                identity = None
            else:
                if (
                    stat.S_ISLNK(observed.st_mode)
                    or not stat.S_ISDIR(observed.st_mode)
                    or observed.st_uid != os.getuid()
                    or observed.st_mode & 0o077
                ):
                    raise InstallationRetirementRefused(
                        f"retirement path is not an owner-private directory: {path}",
                    )
                identity = _identity(observed)
        if _validate_directory(path.parent) != parent_identity:
            raise InstallationRetirementRefused(
                f"retirement parent pathname changed: {path.parent}",
            )
        return identity
    finally:
        _close_directory(parent_fd)


def _remove_exact_empty_directory(path: Path) -> None:
    parent_fd, parent_identity = _open_directory(path.parent)
    expected = _validate_directory(path)
    try:
        if os.name == "nt":
            from z4j_brain._windows_secure_io import (
                delete_relative_directory,
                relative_directory_identity,
            )

            if relative_directory_identity(parent_fd, path.name) != expected:
                raise InstallationRetirementRefused(
                    f"retirement directory identity changed: {path}",
                )
            delete_relative_directory(
                parent_fd,
                path.name,
                expected_identity=expected,
            )
        else:
            observed = os.stat(
                path.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            if stat.S_ISLNK(observed.st_mode) or _identity(observed) != expected:
                raise InstallationRetirementRefused(
                    f"retirement directory identity changed: {path}",
                )
            os.rmdir(path.name, dir_fd=parent_fd)
            with contextlib.suppress(OSError):
                os.fsync(parent_fd)
        if _validate_directory(path.parent) != parent_identity:
            raise InstallationRetirementRefused(
                f"retirement parent pathname changed: {path.parent}",
            )
    finally:
        _close_directory(parent_fd)


def _safe_directory_names(path: Path) -> set[str]:
    directory_fd, directory_identity = _open_directory(path)
    try:
        names = {entry.name for entry in path.iterdir()}
        if any(not name or name in {".", ".."} or "/" in name or "\\" in name for name in names):
            raise InstallationRetirementRefused(
                f"retirement directory contains an unsafe entry: {path}",
            )
        if _validate_directory(path) != directory_identity:
            raise InstallationRetirementRefused(
                f"retirement directory pathname changed: {path}",
            )
        return names
    finally:
        _close_directory(directory_fd)


def _parent_identity_digest(path: Path) -> str:
    identity = _validate_directory(path)
    return release_manifest_digest(
        {
            "version": 1,
            "device": identity[0],
            "inode": identity[1],
        },
    )


def _lock_identities(home: Path) -> dict[str, list[int]]:
    identities: dict[str, list[int]] = {}
    for name in (
        ".z4j-bootstrap-coordinator.lock",
        _SECRET_LOCK_NAME,
    ):
        path = home / name
        try:
            identity = _regular_file_identity(path)
        except (OSError, InstallationRetirementRefused) as exc:
            raise InstallationRetirementRefused(
                f"stable retirement lock is unsafe: {path}",
            ) from exc
        if identity is None:
            raise InstallationRetirementRefused(
                f"stable retirement lock is missing: {path}",
            )
        identities[name] = [identity[0], identity[1]]
    return identities


def _assert_lock_identities(
    home: Path,
    expected: Mapping[str, Any],
) -> None:
    if _lock_identities(home) != expected:
        raise InstallationRetirementRefused(
            "stable retirement lock identity changed",
        )


def _packaged_authority(
    home: Path,
) -> tuple[Settings, Path, dict[str, str]]:
    preliminary = capture_configuration(
        home=home,
        include_secret_store=False,
    )
    overrides = sorted(key for key in ALLOWED_SECRET_STORE_KEYS if key in preliminary.values)
    if overrides:
        raise InstallationRetirementRefused(
            "packaged retirement cannot replace explicitly configured "
            f"secret authority: {overrides!r}",
        )
    default_database = home / "z4j.db"
    database_url = preliminary.values.get(
        "Z4J_DATABASE_URL",
        f"sqlite+aiosqlite:///{default_database}",
    )
    try:
        parsed = make_url(database_url)
    except Exception as exc:
        raise InstallationRetirementRefused(
            "packaged retirement database URL is malformed",
        ) from exc
    if (
        not parsed.drivername.startswith("sqlite")
        or not parsed.database
        or _lexical_absolute(Path(parsed.database)) != default_database
    ):
        raise InstallationRetirementRefused(
            "--nuke-secrets is available only for the packaged default "
            f"SQLite database {default_database}",
        )
    store = read_secret_store(home / "secret.env")
    missing = sorted(_REQUIRED_PACKAGED_SECRETS - set(store.values))
    if store.file_identity is None or missing:
        raise InstallationRetirementRefused(
            f"packaged retirement requires the complete persisted safe store; missing {missing!r}",
        )
    snapshot = overlay_runtime_environment(
        preliminary,
        {"Z4J_DATABASE_URL": database_url},
    )
    snapshot = merge_secret_store_snapshot(snapshot, store.values)
    return settings_from_snapshot(snapshot), default_database, store.values


async def _authenticated_state_payload(
    settings: Settings,
) -> dict[str, Any]:
    engine = create_async_engine_from_url(settings.database_url)
    database = DatabaseManager(engine)
    try:
        async with database.session(write=True) as session:
            report = await verify_active_audit_generation(
                session,
                settings,
                page_size=5000,
            )
            if not report.clean:
                raise InstallationRetirementRefused(
                    f"current installation audit authority is not clean: {list(report.mismatches)}",
                )
            state = await session.get(AuditChainState, "audit-chain")
            if state is None:
                raise InstallationRetirementRefused(
                    "current installation lacks authenticated audit state",
                )
            return {
                **canonical_state_payload(state),
                "state_mac": state.state_mac,
            }
    finally:
        await database.dispose()


@contextlib.contextmanager
def _hold_database_path(database: Path) -> Iterator[None]:
    expected = _regular_file_identity(database)
    if expected is None:
        raise InstallationRetirementRefused(
            f"packaged SQLite database does not exist: {database}",
        )
    directory_fd, directory_identity = _open_directory(database.parent)
    file_fd: int | None = None
    try:
        if os.name == "nt":
            from z4j_brain._windows_secure_io import hold_relative_file_stable

            with hold_relative_file_stable(
                directory_fd,
                database.name,
                expected_identity=expected,
            ):
                yield
        else:
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            file_fd = os.open(database.name, flags, dir_fd=directory_fd)
            observed = os.fstat(file_fd)
            if _identity(observed) != expected:
                raise InstallationRetirementRefused(
                    "packaged SQLite identity changed before quiescence proof",
                )
            yield
            final_path = os.stat(
                database.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if (
                stat.S_ISLNK(final_path.st_mode)
                or _identity(final_path) != expected
                or _identity(os.fstat(file_fd)) != expected
            ):
                raise InstallationRetirementRefused(
                    "packaged SQLite pathname changed during quiescence proof",
                )
        if _validate_directory(database.parent) != directory_identity:
            raise InstallationRetirementRefused(
                "packaged SQLite parent pathname changed during quiescence proof",
            )
    finally:
        if file_fd is not None:
            os.close(file_fd)
        _close_directory(directory_fd)


def _prove_quiescent_database(database: Path) -> None:
    try:
        with _hold_database_path(database):
            connection = sqlite3.connect(
                f"{database.as_uri()}?mode=rw",
                timeout=0,
                isolation_level=None,
                uri=True,
            )
            try:
                connection.execute("BEGIN EXCLUSIVE")
                if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                    raise InstallationRetirementRefused(
                        "packaged SQLite database failed quick_check",
                    )
                connection.execute("ROLLBACK")
            finally:
                connection.close()
    except sqlite3.Error as exc:
        raise InstallationRetirementRefused(
            "packaged SQLite database has a live writer or is unreadable",
        ) from exc


def _capture_bundle_manifest(
    *,
    home: Path,
    database: Path,
    operation_id: uuid.UUID,
    old_state: Mapping[str, Any],
) -> dict[str, Any]:
    candidates = [
        database,
        Path(f"{database}-wal"),
        Path(f"{database}-shm"),
        Path(f"{database}-journal"),
        home / "secret.env",
    ]
    entries: list[dict[str, Any]] = []
    for path in candidates:
        if _regular_file_identity(path) is not None:
            entries.append(_file_digest_and_identity(path))
    names = {entry["name"] for entry in entries}
    if database.name not in names or "secret.env" not in names:
        raise InstallationRetirementRefused(
            "retirement manifest lacks the old database or safe store",
        )
    manifest = {
        "version": 1,
        "operation_id": str(operation_id),
        "old_installation_id": old_state["installation_id"],
        "old_generation": old_state["generation"],
        "old_state_mac": old_state["state_mac"],
        "entries": entries,
    }
    return {
        **manifest,
        "manifest_digest": release_manifest_digest(manifest),
    }


def _validate_manifest(manifest: Mapping[str, Any], operation_id: uuid.UUID) -> None:
    required = {
        "version",
        "operation_id",
        "old_installation_id",
        "old_generation",
        "old_state_mac",
        "entries",
        "manifest_digest",
    }
    if (
        set(manifest) != required
        or manifest.get("version") != 1
        or manifest.get("operation_id") != str(operation_id)
        or not isinstance(manifest.get("entries"), list)
    ):
        raise InstallationRetirementRefused(
            "retired bundle manifest schema is invalid",
        )
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_digest"}
    if release_manifest_digest(unsigned) != manifest["manifest_digest"]:
        raise InstallationRetirementRefused(
            "retired bundle manifest digest is invalid",
        )
    names: set[str] = set()
    for entry in manifest["entries"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"name", "device", "inode", "size", "sha256", "mode"}
            or entry["name"] in names
            or entry["name"]
            not in {
                "z4j.db",
                "z4j.db-wal",
                "z4j.db-shm",
                "z4j.db-journal",
                "secret.env",
            }
        ):
            raise InstallationRetirementRefused(
                "retired bundle contains an invalid artifact entry",
            )
        names.add(entry["name"])
    if not {"z4j.db", "secret.env"}.issubset(names):
        raise InstallationRetirementRefused(
            "retired bundle manifest omits required authority",
        )


def _retirement_journal_path(home: Path) -> Path:
    return home / RETIREMENT_JOURNAL_NAME


def _bundle_directory(home: Path, operation_id: uuid.UUID) -> Path:
    return home / RECOVERY_ROOT_NAME / str(operation_id)


def _destruction_journal_path(home: Path, operation_id: uuid.UUID) -> Path:
    return home / f"{DESTRUCTION_JOURNAL_PREFIX}{operation_id}.json"


def _unlink_retired_artifact(path: Path) -> None:
    """Separate crash-injection edge for one manifested logical unlink."""

    _unlink_exact_file(path)


def _load_retirement_journal(home: Path) -> dict[str, Any] | None:
    path = _retirement_journal_path(home)
    if _regular_file_identity(path) is None:
        return None
    journal = _read_canonical_json(path)
    required = {
        "version",
        "operation_id",
        "state",
        "manifest",
        "retained_parent_identity_digest",
        "lock_identities",
        "moved",
    }
    if (
        set(journal) != required
        or journal.get("version") != RETIREMENT_JOURNAL_VERSION
        or journal.get("state")
        not in {
            "RETIRING",
            "OLD_PAIR_BUNDLED",
            "BOOTSTRAPPING_NEW",
        }
        or not isinstance(journal.get("moved"), list)
        or not isinstance(journal.get("lock_identities"), dict)
    ):
        raise InstallationRetirementRefused(
            "installation-retirement journal schema is invalid",
        )
    try:
        operation_id = uuid.UUID(str(journal["operation_id"]))
    except (TypeError, ValueError, AttributeError) as exc:
        raise InstallationRetirementRefused(
            "installation-retirement operation id is invalid",
        ) from exc
    _validate_manifest(journal["manifest"], operation_id)
    return journal


def assert_no_pending_installation_retirement(home: Path) -> None:
    """Fence ordinary entry before it can bootstrap from a partial pair."""

    journal = _load_retirement_journal(home)
    if journal is not None:
        raise InstallationRetirementRefused(
            "packaged installation retirement is unfinished; resume "
            "`z4j reset --force --nuke-secrets` for operation "
            f"{journal['operation_id']}",
        )


def _move_manifested_pair(
    *,
    home: Path,
    bundle: Path,
    journal: dict[str, Any],
) -> dict[str, Any]:
    moved = set(journal["moved"])
    entries = journal["manifest"]["entries"]
    for entry in entries:
        _assert_lock_identities(home, journal["lock_identities"])
        name = str(entry["name"])
        source = home / name
        destination = bundle / name
        source_matches = _entry_matches(source, entry)
        destination_matches = _entry_matches(destination, entry)
        if source_matches and destination_matches:
            raise InstallationRetirementRefused(
                f"retirement artifact exists at both live and bundle paths: {name}",
            )
        if destination_matches:
            moved.add(name)
        elif source_matches:
            _move_exact_file(
                source,
                destination,
                expected_identity=(
                    int(entry["device"]),
                    int(entry["inode"]),
                ),
            )
            if not _entry_matches(destination, entry):
                raise InstallationRetirementRefused(
                    f"retirement move changed artifact identity: {name}",
                )
            moved.add(name)
        else:
            raise InstallationRetirementRefused(
                f"retirement artifact is missing or changed: {name}",
            )
        journal = {
            **journal,
            "moved": sorted(moved),
        }
        _write_canonical_json(_retirement_journal_path(home), journal)
    expected = {str(entry["name"]) for entry in entries}
    if moved != expected:
        raise InstallationRetirementRefused(
            "retirement bundle did not capture every manifested artifact",
        )
    return {
        **journal,
        "state": "OLD_PAIR_BUNDLED",
        "moved": sorted(moved),
    }


async def _install_recovery_binding(
    settings: Settings,
    *,
    manifest: Mapping[str, Any],
    retained_parent_identity_digest: str,
) -> dict[str, Any]:
    secrets = settings.all_audit_chain_secrets_for_verification()
    if not secrets:
        raise InstallationRetirementRefused(
            "replacement installation lacks its audit key",
        )
    current_secret = secrets[0]
    _, keyring = build_audit_keyring(current_secret, secrets[1:])
    engine = create_async_engine_from_url(settings.database_url)
    database = DatabaseManager(engine)
    try:
        async with database.session(write=True) as session:
            repo = AuditLogRepository(session)
            state = await repo.get_chain_state_for_update()
            authenticate_state(state, keyring)
            binding = canonical_retired_recovery_binding(
                {
                    "version": 1,
                    "operation_id": manifest["operation_id"],
                    "old_bundle_manifest_digest": manifest["manifest_digest"],
                    "retained_parent_identity_digest": (retained_parent_identity_digest),
                    "replacement_installation_id": str(
                        state.installation_id,
                    ),
                    "status": "RECOVERABLE",
                    "destruction_journal_digest": None,
                },
            )
            assert binding is not None
            if str(state.installation_id) == manifest["old_installation_id"]:
                raise InstallationRetirementRefused(
                    "fresh bootstrap reused the retired installation id",
                )
            if (
                canonical_retired_recovery_binding(
                    state.retired_recovery_binding,
                )
                != binding
            ):
                raise InstallationRetirementRefused(
                    "fresh activation did not atomically install the exact "
                    "retired-recovery binding",
                )
            return binding
    except AuditChainIntegrityError as exc:
        raise InstallationRetirementRefused(
            f"replacement audit authority is invalid: {exc}",
        ) from exc
    finally:
        await database.dispose()


def retire_packaged_sqlite_installation(  # noqa: PLR0912, PLR0915
    home: Path,
    *,
    bootstrap: Callable[[dict[str, Any]], Settings],
) -> dict[str, Any]:
    """Retire or resume one packaged SQLite database/safe-store pair."""

    home = _lexical_absolute(home)
    ensure_secret_store_directory(home)
    with audit_bootstrap_coordinator(home):
        journal = _load_retirement_journal(home)
        if journal is None:
            settings, database, _ = _packaged_authority(home)
            if _regular_file_identity(database) is None:
                raise InstallationRetirementRefused(
                    f"packaged SQLite database does not exist: {database}",
                )
            old_state = asyncio.run(_authenticated_state_payload(settings))
            if old_state["retired_recovery_binding"] is not None:
                raise InstallationRetirementRefused(
                    "another retired installation is unresolved",
                )
            operation_id = uuid.uuid4()
            recovery_root = _ensure_private_child_directory(
                home,
                RECOVERY_ROOT_NAME,
            )
            bundle = _ensure_private_child_directory(
                recovery_root,
                str(operation_id),
            )
            if (
                _validate_directory(home)[0]
                != _validate_directory(
                    recovery_root,
                )[0]
            ):
                raise InstallationRetirementRefused(
                    "retirement recovery directory is on another filesystem",
                )
            parent_digest = _parent_identity_digest(recovery_root)
            home_fd, home_identity = _open_directory(home)
            try:
                with _exclusive_named_lock(home_fd, _SECRET_LOCK_NAME):
                    if _validate_directory(home) != home_identity:
                        raise InstallationRetirementRefused(
                            "packaged state-directory identity changed",
                        )
                    _prove_quiescent_database(database)
                    manifest = _capture_bundle_manifest(
                        home=home,
                        database=database,
                        operation_id=operation_id,
                        old_state=old_state,
                    )
                    required_capacity = sum(
                        int(entry["size"]) for entry in manifest["entries"]
                    ) + max(
                        16 * 1024 * 1024,
                        next(
                            int(entry["size"])
                            for entry in manifest["entries"]
                            if entry["name"] == database.name
                        ),
                    )
                    if shutil.disk_usage(recovery_root).free < required_capacity:
                        raise InstallationRetirementRefused(
                            "insufficient same-filesystem capacity for retirement",
                        )
                    _write_canonical_json(
                        bundle / BUNDLE_MANIFEST_NAME,
                        manifest,
                    )
                    journal = {
                        "version": RETIREMENT_JOURNAL_VERSION,
                        "operation_id": str(operation_id),
                        "state": "RETIRING",
                        "manifest": manifest,
                        "retained_parent_identity_digest": parent_digest,
                        "lock_identities": _lock_identities(home),
                        "moved": [],
                    }
                    _write_canonical_json(
                        _retirement_journal_path(home),
                        journal,
                    )
                    journal = _move_manifested_pair(
                        home=home,
                        bundle=bundle,
                        journal=journal,
                    )
                    _write_canonical_json(
                        _retirement_journal_path(home),
                        journal,
                    )
            finally:
                _close_directory(home_fd)
        else:
            operation_id = uuid.UUID(str(journal["operation_id"]))
            recovery_root = _ensure_private_child_directory(
                home,
                RECOVERY_ROOT_NAME,
            )
            bundle = _ensure_private_child_directory(
                recovery_root,
                str(operation_id),
            )
            if _parent_identity_digest(recovery_root) != journal["retained_parent_identity_digest"]:
                raise InstallationRetirementRefused(
                    "retirement recovery-parent identity changed",
                )
            _assert_lock_identities(home, journal["lock_identities"])
            if journal["state"] == "RETIRING":
                home_fd, home_identity = _open_directory(home)
                try:
                    with _exclusive_named_lock(home_fd, _SECRET_LOCK_NAME):
                        if _validate_directory(home) != home_identity:
                            raise InstallationRetirementRefused(
                                "packaged state-directory identity changed",
                            )
                        journal = _move_manifested_pair(
                            home=home,
                            bundle=bundle,
                            journal=journal,
                        )
                        _write_canonical_json(
                            _retirement_journal_path(home),
                            journal,
                        )
                finally:
                    _close_directory(home_fd)

        if journal["state"] == "OLD_PAIR_BUNDLED":
            _assert_lock_identities(home, journal["lock_identities"])
            journal = {
                **journal,
                "state": "BOOTSTRAPPING_NEW",
            }
            _write_canonical_json(
                _retirement_journal_path(home),
                journal,
            )
        if journal["state"] != "BOOTSTRAPPING_NEW":
            raise InstallationRetirementRefused(
                f"retirement cannot resume from {journal['state']!r}",
            )
        _assert_lock_identities(home, journal["lock_identities"])
        settings = bootstrap(
            {
                "version": 1,
                "operation_id": journal["operation_id"],
                "old_bundle_manifest_digest": (journal["manifest"]["manifest_digest"]),
                "retained_parent_identity_digest": (journal["retained_parent_identity_digest"]),
            },
        )
        binding = asyncio.run(
            _install_recovery_binding(
                settings,
                manifest=journal["manifest"],
                retained_parent_identity_digest=(journal["retained_parent_identity_digest"]),
            ),
        )
        _unlink_exact_file(_retirement_journal_path(home))
        return {
            "operation_id": str(operation_id),
            "bundle": str(bundle),
            "manifest_digest": journal["manifest"]["manifest_digest"],
            "binding": binding,
        }


def _validated_bundle(  # noqa: PLR0912
    *,
    home: Path,
    operation_id: uuid.UUID,
    manifest_digest: str,
    retained_parent_identity_digest: str,
    allow_absent: bool,
    authoritative_manifest: Mapping[str, Any] | None = None,
) -> tuple[Path, dict[str, Any] | None]:
    recovery_root = home / RECOVERY_ROOT_NAME
    if _parent_identity_digest(recovery_root) != retained_parent_identity_digest:
        raise InstallationRetirementRefused(
            "retired recovery-parent identity changed",
        )
    bundle = _bundle_directory(home, operation_id)
    if _directory_identity_optional(bundle) is None:
        if allow_absent:
            return bundle, None
        raise InstallationRetirementRefused(
            "retired installation bundle is missing",
        )
    manifest_path = bundle / BUNDLE_MANIFEST_NAME
    if _regular_file_identity(manifest_path) is not None:
        manifest = _read_canonical_json(manifest_path)
        if authoritative_manifest is not None and manifest != authoritative_manifest:
            raise InstallationRetirementRefused(
                "bundle manifest differs from the outside destruction journal",
            )
    elif authoritative_manifest is not None and allow_absent:
        manifest = dict(authoritative_manifest)
    else:
        raise InstallationRetirementRefused(
            "retired installation bundle manifest is missing",
        )
    _validate_manifest(manifest, operation_id)
    if manifest["manifest_digest"] != manifest_digest:
        raise InstallationRetirementRefused(
            "retired installation manifest digest differs from confirmation",
        )
    expected_names = {
        *(str(entry["name"]) for entry in manifest["entries"]),
        BUNDLE_MANIFEST_NAME,
    }
    observed_names = _safe_directory_names(bundle)
    if (not allow_absent and observed_names != expected_names) or (
        allow_absent and not observed_names.issubset(expected_names)
    ):
        raise InstallationRetirementRefused(
            "retired installation bundle has missing or unexpected entries",
        )
    live_identities = set()
    for live_path in (
        home / "z4j.db",
        home / "secret.env",
        home / ".z4j-bootstrap-coordinator.lock",
        home / _SECRET_LOCK_NAME,
    ):
        live_identity = _regular_file_identity(live_path)
        if live_identity is not None:
            live_identities.add(live_identity)
    for entry in manifest["entries"]:
        artifact = bundle / str(entry["name"])
        artifact_identity = _regular_file_identity(artifact)
        if artifact_identity is None and allow_absent:
            continue
        if not _entry_matches(artifact, entry):
            raise InstallationRetirementRefused(
                f"retired installation artifact changed: {artifact.name}",
            )
        if artifact_identity in live_identities:
            raise InstallationRetirementRefused(
                f"retired installation artifact aliases a live path: {artifact.name}",
            )
    return bundle, manifest


async def _transition_destruction_binding(
    settings: Settings,
    *,
    operation_id: uuid.UUID,
    manifest_digest: str,
    journal_digest: str,
    complete: bool,
) -> dict[str, Any] | None:
    secrets = settings.all_audit_chain_secrets_for_verification()
    if not secrets:
        raise InstallationRetirementRefused(
            "replacement installation lacks its audit key",
        )
    current_secret = secrets[0]
    _, keyring = build_audit_keyring(current_secret, secrets[1:])
    engine = create_async_engine_from_url(settings.database_url)
    database = DatabaseManager(engine)
    try:
        async with database.session(write=True) as session:
            repo = AuditLogRepository(session)
            state = await repo.get_chain_state_for_update()
            authenticate_state(state, keyring)
            binding = canonical_retired_recovery_binding(
                state.retired_recovery_binding,
            )
            if binding is None:
                raise InstallationRetirementRefused(
                    "replacement installation has no retired-recovery binding",
                )
            if (
                binding["operation_id"] != str(operation_id)
                or binding["old_bundle_manifest_digest"] != manifest_digest
                or binding["replacement_installation_id"] != str(state.installation_id)
            ):
                raise InstallationRetirementRefused(
                    "retired-recovery binding does not authorize this target",
                )
            if complete:
                if (
                    binding["status"] != "DESTROYING"
                    or binding["destruction_journal_digest"] != journal_digest
                ):
                    raise InstallationRetirementRefused(
                        "retired destruction completion lacks its signed intent",
                    )
                await AuditService(settings).record(
                    repo,
                    action="audit.retired_installation_destruction_completed",
                    target_type="installation",
                    target_id=str(operation_id),
                    result="success",
                    outcome="allow",
                    metadata={
                        "operation_id": str(operation_id),
                        "old_bundle_manifest_digest": manifest_digest,
                        "destruction_journal_digest": journal_digest,
                        "removal_semantics": "logical_unlink_not_physical_erasure",
                    },
                )
                state.retired_recovery_binding = None
                state.state_mac = compute_state_mac(current_secret, state)
                await session.flush()
                await session.commit()
                return None
            destroying = canonical_retired_recovery_binding(
                {
                    **binding,
                    "status": "DESTROYING",
                    "destruction_journal_digest": journal_digest,
                },
            )
            assert destroying is not None
            if binding["status"] == "DESTROYING":
                if binding != destroying:
                    raise InstallationRetirementRefused(
                        "a different retired destruction is already pending",
                    )
                return binding
            await AuditService(settings).record(
                repo,
                action="audit.retired_installation_destruction_started",
                target_type="installation",
                target_id=str(operation_id),
                result="pending",
                outcome="allow",
                metadata={
                    "operation_id": str(operation_id),
                    "old_bundle_manifest_digest": manifest_digest,
                    "destruction_journal_digest": journal_digest,
                },
            )
            state.retired_recovery_binding = destroying
            state.state_mac = compute_state_mac(current_secret, state)
            await session.flush()
            await session.commit()
            return destroying
    except AuditChainIntegrityError as exc:
        raise InstallationRetirementRefused(
            f"replacement audit authority is invalid: {exc}",
        ) from exc
    finally:
        await database.dispose()


async def _read_authenticated_binding(
    settings: Settings,
) -> tuple[dict[str, Any] | None, str]:
    secrets = settings.all_audit_chain_secrets_for_verification()
    if not secrets:
        raise InstallationRetirementRefused(
            "replacement installation lacks its audit key",
        )
    _, keyring = build_audit_keyring(secrets[0], secrets[1:])
    engine = create_async_engine_from_url(settings.database_url)
    database = DatabaseManager(engine)
    try:
        async with database.session(write=True) as session:
            state = await session.get(AuditChainState, "audit-chain")
            if state is None:
                raise InstallationRetirementRefused(
                    "replacement installation lacks authenticated state",
                )
            authenticate_state(state, keyring)
            binding = canonical_retired_recovery_binding(
                state.retired_recovery_binding,
            )
            return binding, str(state.installation_id)
    finally:
        await database.dispose()


def destroy_retired_installation(  # noqa: PLR0912, PLR0915
    home: Path,
    *,
    operation: str,
    confirm_manifest_digest: str,
) -> dict[str, Any]:
    """Logically unlink one exact state-authorized retired installation."""

    home = _lexical_absolute(home)
    try:
        operation_id = uuid.UUID(operation)
    except (TypeError, ValueError, AttributeError) as exc:
        raise InstallationRetirementRefused(
            "--operation must be a canonical UUID",
        ) from exc
    if (
        len(confirm_manifest_digest) != 64
        or confirm_manifest_digest.lower() != confirm_manifest_digest
    ):
        raise InstallationRetirementRefused(
            "--confirm-manifest-digest must be 64 lowercase hexadecimal characters",
        )
    try:
        bytes.fromhex(confirm_manifest_digest)
    except ValueError as exc:
        raise InstallationRetirementRefused(
            "--confirm-manifest-digest must be 64 lowercase hexadecimal characters",
        ) from exc

    with audit_bootstrap_coordinator(home):
        settings, _, _ = _packaged_authority(home)
        binding, installation_id = asyncio.run(
            _read_authenticated_binding(settings),
        )
        destruction_path = _destruction_journal_path(home, operation_id)
        if binding is None:
            if _regular_file_identity(destruction_path) is None:
                raise InstallationRetirementRefused(
                    "replacement installation has no retired-recovery binding",
                )
            destruction = _read_canonical_json(destruction_path)
            if (
                set(destruction)
                != {
                    "version",
                    "operation_id",
                    "old_bundle_manifest_digest",
                    "retained_parent_identity_digest",
                    "replacement_installation_id",
                    "manifest",
                }
                or destruction.get("version") != 1
                or destruction.get("operation_id") != str(operation_id)
                or destruction.get("old_bundle_manifest_digest") != confirm_manifest_digest
                or destruction.get("replacement_installation_id") != installation_id
            ):
                raise InstallationRetirementRefused(
                    "completed destruction journal does not match this "
                    "authenticated installation and typed target",
                )
            _validate_manifest(destruction["manifest"], operation_id)
            if (
                destruction["manifest"]["manifest_digest"] != confirm_manifest_digest
                or _parent_identity_digest(home / RECOVERY_ROOT_NAME)
                != destruction["retained_parent_identity_digest"]
                or _directory_identity_optional(
                    _bundle_directory(home, operation_id),
                )
                is not None
            ):
                raise InstallationRetirementRefused(
                    "completed destruction cannot be reconciled while its "
                    "retired bundle or parent authority differs",
                )
            _unlink_exact_file(destruction_path)
            return {
                "operation_id": str(operation_id),
                "manifest_digest": confirm_manifest_digest,
                "logical_removal_complete": True,
                "physical_erasure_guaranteed": False,
            }
        if (
            binding["operation_id"] != str(operation_id)
            or binding["old_bundle_manifest_digest"] != confirm_manifest_digest
            or binding["replacement_installation_id"] != installation_id
        ):
            raise InstallationRetirementRefused(
                "typed operation/digest does not match the authenticated retired-recovery binding",
            )
        if binding["status"] == "RECOVERABLE":
            bundle, manifest = _validated_bundle(
                home=home,
                operation_id=operation_id,
                manifest_digest=confirm_manifest_digest,
                retained_parent_identity_digest=(binding["retained_parent_identity_digest"]),
                allow_absent=False,
            )
            assert manifest is not None
            destruction = {
                "version": 1,
                "operation_id": str(operation_id),
                "old_bundle_manifest_digest": confirm_manifest_digest,
                "retained_parent_identity_digest": (binding["retained_parent_identity_digest"]),
                "replacement_installation_id": installation_id,
                "manifest": manifest,
            }
            _write_canonical_json(destruction_path, destruction)
            journal_digest = hashlib.sha256(
                canonical_json(destruction) + b"\n",
            ).hexdigest()
            asyncio.run(
                _transition_destruction_binding(
                    settings,
                    operation_id=operation_id,
                    manifest_digest=confirm_manifest_digest,
                    journal_digest=journal_digest,
                    complete=False,
                ),
            )
        else:
            destruction = _read_canonical_json(destruction_path)
            if (
                set(destruction)
                != {
                    "version",
                    "operation_id",
                    "old_bundle_manifest_digest",
                    "retained_parent_identity_digest",
                    "replacement_installation_id",
                    "manifest",
                }
                or destruction.get("version") != 1
                or destruction.get("operation_id") != str(operation_id)
                or destruction.get("old_bundle_manifest_digest") != confirm_manifest_digest
                or destruction.get("retained_parent_identity_digest")
                != binding["retained_parent_identity_digest"]
                or destruction.get("replacement_installation_id") != installation_id
            ):
                raise InstallationRetirementRefused(
                    "outside destruction journal schema or binding is invalid",
                )
            _validate_manifest(destruction["manifest"], operation_id)
            journal_digest = hashlib.sha256(
                canonical_json(destruction) + b"\n",
            ).hexdigest()
            if journal_digest != binding["destruction_journal_digest"]:
                raise InstallationRetirementRefused(
                    "outside destruction journal differs from signed intent",
                )
            bundle, manifest = _validated_bundle(
                home=home,
                operation_id=operation_id,
                manifest_digest=confirm_manifest_digest,
                retained_parent_identity_digest=(binding["retained_parent_identity_digest"]),
                allow_absent=True,
                authoritative_manifest=destruction["manifest"],
            )

        bundle_exists = _directory_identity_optional(bundle) is not None
        if bundle_exists:
            assert manifest is not None
            for entry in manifest["entries"]:
                artifact = bundle / str(entry["name"])
                artifact_identity = _regular_file_identity(artifact)
                if artifact_identity is not None:
                    if not _entry_matches(artifact, entry):
                        raise InstallationRetirementRefused(
                            f"retired artifact changed before unlink: {artifact.name}",
                        )
                    _unlink_retired_artifact(artifact)
            manifest_path = bundle / BUNDLE_MANIFEST_NAME
            if _regular_file_identity(manifest_path) is not None:
                _unlink_retired_artifact(manifest_path)
            _remove_exact_empty_directory(bundle)
        asyncio.run(
            _transition_destruction_binding(
                settings,
                operation_id=operation_id,
                manifest_digest=confirm_manifest_digest,
                journal_digest=journal_digest,
                complete=True,
            ),
        )
        _unlink_exact_file(destruction_path, missing_ok=True)
        return {
            "operation_id": str(operation_id),
            "manifest_digest": confirm_manifest_digest,
            "logical_removal_complete": True,
            "physical_erasure_guaranteed": False,
        }


__all__ = [
    "InstallationRetirementRefused",
    "assert_no_pending_installation_retirement",
    "destroy_retired_installation",
    "retire_packaged_sqlite_installation",
]
