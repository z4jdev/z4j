"""Crash-resumable export and deletion of frozen pre-1.8 audit history.

Frozen rows are deliberately outside the active Boundary-F chain.  This
module implements the only non-reset path allowed to delete them:

* a deterministic, owner-private local spool is finalized first;
* a distinct local destination is populated and read back from that spool;
* the database transition reauthenticates state and rechecks every frozen
  row under the audit writer/table exclusion;
* deletion, the signed active-chain marker, and the state update commit
  atomically; and
* the spool remains the crash authority until the operator explicitly
  acknowledges the destination digest and requests cleanup.

Security-critical file opens, reads, writes, and spool deletion use POSIX
directory-relative no-follow operations or the native Windows handle/ACL
implementation. Cleanup is not wholly pathname-free: it performs bounded
directory enumeration and final empty-directory removal by pathname, bracketed
by held-directory identity checks. Those cleanup operations never select or
recursively remove unverified file content.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from z4j_brain.domain.audit_chain import (
    AuditChainIntegrityError,
    authenticate_state,
    canonical_frozen_row_snapshot,
    canonical_json,
    compute_state_mac,
    frozen_snapshot_digest,
)
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.persistence.models import AuditChainState, AuditLog
from z4j_brain.persistence.models.audit_chain import AUDIT_CHAIN_SINGLETON_ID
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.persistence.repositories.audit_log import (
    AUDIT_CHAIN_ADVISORY_LOCK_KEY,
)
from z4j_brain.settings import Settings

_FORMAT_VERSION = 1
_MANIFEST_DOMAIN = b"z4j/audit-frozen-export-manifest/v1\x00"
_MAX_JOURNAL_BYTES = 4 * 1024 * 1024
_IO_CHUNK_BYTES = 1024 * 1024
_PHASE_FILE = "phase.json"
_SPOOL_FILE = "frozen-audit-export.json"
_PHASES = {
    "INITIAL",
    "SPOOLED",
    "DESTINATION_VERIFIED",
    "DATABASE_COMMITTED",
    "DESTINATION_ACKNOWLEDGED",
}


def _identity(value: os.stat_result) -> tuple[int, int]:
    return (int(value.st_dev), int(value.st_ino))


def _is_reparse(value: os.stat_result) -> bool:
    attributes = int(getattr(value, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & reparse_flag)


def _require_secure_directory_io() -> None:
    if os.name != "nt" and not os.supports_dir_fd:
        raise AuditChainIntegrityError(
            "frozen audit export requires directory-relative no-follow I/O",
        )


def _windows_handle(fd: int) -> int:
    import msvcrt

    return int(msvcrt.get_osfhandle(fd))


def _windows_fd(handle: int, flags: int) -> int:
    import msvcrt

    from z4j_brain._windows_secure_io import close_handle

    try:
        return int(
            msvcrt.open_osfhandle(
                handle,
                flags | getattr(os, "O_BINARY", 0),
            ),
        )
    except BaseException:
        close_handle(handle)
        raise


def _fd_identity(fd: int) -> tuple[int, int]:
    if os.name == "nt":
        from z4j_brain._windows_secure_io import handle_identity

        return handle_identity(_windows_handle(fd))
    return _identity(os.fstat(fd))


def _flush_directory(directory_fd: int) -> None:
    if os.name != "nt":
        os.fsync(directory_fd)


def _validate_private_mode(value: os.stat_result, *, directory: bool, label: str) -> None:
    if hasattr(os, "getuid") and value.st_uid != os.getuid():
        raise AuditChainIntegrityError(f"{label} is not owned by the current user")
    forbidden = stat.S_IRWXG | stat.S_IRWXO
    if value.st_mode & forbidden:
        required = "0700" if directory else "0600"
        raise AuditChainIntegrityError(
            f"{label} must be owner-private (chmod {required})",
        )


def _open_private_directory(
    path: Path,
    *,
    create: bool,
) -> tuple[int, tuple[int, int]]:
    if os.name == "nt":
        from z4j_brain._windows_secure_io import (
            directory_path_identity,
            ensure_private_directory,
            open_directory,
        )

        if create:
            ensure_private_directory(path)
        before = directory_path_identity(path, require_private=True)
        handle, opened = open_directory(path, require_private=True)
        try:
            after = directory_path_identity(path, require_private=True)
            if before != opened or opened != after:
                raise AuditChainIntegrityError(  # noqa: TRY301
                    f"private directory identity changed while opening: {path}",
                )
        except Exception:
            from z4j_brain._windows_secure_io import close_handle

            close_handle(handle)
            raise
        return _windows_fd(handle, os.O_RDONLY), opened

    if create:
        with suppress(FileExistsError):
            path.mkdir(mode=0o700)
    before = path.lstat()
    if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode) or _is_reparse(before):
        raise AuditChainIntegrityError(f"unsafe private directory: {path}")
    _validate_private_mode(before, directory=True, label=str(path))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        after = path.lstat()
        if _identity(before) != _identity(opened) or _identity(opened) != _identity(after):
            raise AuditChainIntegrityError(  # noqa: TRY301
                f"private directory identity changed while opening: {path}",
            )
        return fd, _identity(opened)
    except Exception:
        os.close(fd)
        raise


def _recheck_directory(
    path: Path,
    expected: tuple[int, int],
    *,
    require_private: bool = True,
) -> None:
    if os.name == "nt":
        from z4j_brain._windows_secure_io import directory_path_identity

        if directory_path_identity(path, require_private=require_private) != expected:
            raise AuditChainIntegrityError(
                f"directory pathname no longer names the held directory: {path}",
            )
        return

    observed = path.lstat()
    if (
        not stat.S_ISDIR(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or _is_reparse(observed)
        or _identity(observed) != expected
    ):
        raise AuditChainIntegrityError(
            f"directory pathname no longer names the held directory: {path}",
        )


def _strict_json(raw: bytes, *, label: str) -> Any:
    def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=_object)
    except (UnicodeDecodeError, ValueError) as exc:
        raise AuditChainIntegrityError(f"{label} is not strict JSON") from exc


def _read_relative(
    directory_fd: int,
    directory_path: Path,
    directory_identity: tuple[int, int],
    name: str,
    *,
    required: bool,
) -> tuple[bytes, tuple[int, int], int] | None:
    if os.name == "nt":
        from z4j_brain._windows_secure_io import read_relative

        raw, identity = read_relative(
            _windows_handle(directory_fd),
            name,
            maximum_bytes=_MAX_JOURNAL_BYTES,
            require_private=True,
        )
        if identity is None:
            if not required:
                return None
            raise FileNotFoundError(directory_path / name)
        _recheck_directory(directory_path, directory_identity)
        return raw, identity, len(raw)

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        if not required:
            return None
        raise
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or _is_reparse(before):
            raise AuditChainIntegrityError(
                f"{directory_path / name} is not a safe regular file",
            )
        _validate_private_mode(
            before,
            directory=False,
            label=str(directory_path / name),
        )
        if before.st_size > _MAX_JOURNAL_BYTES:
            raise AuditChainIntegrityError(
                f"{directory_path / name} exceeds the 4 MiB journal bound",
            )
        chunks: list[bytes] = []
        remaining = int(before.st_size)
        while remaining:
            chunk = os.read(fd, min(_IO_CHUNK_BYTES, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining:
            raise AuditChainIntegrityError(
                f"{directory_path / name} ended before its recorded size",
            )
        after = os.fstat(fd)
        path_state = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            _identity(before) != _identity(after)
            or before.st_size != after.st_size
            or _identity(after) != _identity(path_state)
        ):
            raise AuditChainIntegrityError(
                f"{directory_path / name} changed while it was read",
            )
        _recheck_directory(directory_path, directory_identity)
        return b"".join(chunks), _identity(after), int(after.st_size)
    finally:
        os.close(fd)


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset:])
        if written <= 0:
            raise OSError("short file write")
        offset += written


def _write_exclusive_relative(
    directory_fd: int,
    directory_path: Path,
    directory_identity: tuple[int, int],
    name: str,
    payload: bytes,
) -> tuple[int, int]:
    if os.name == "nt":
        from z4j_brain._windows_secure_io import (
            close_handle,
            create_relative_file,
            handle_identity,
        )

        handle = create_relative_file(
            _windows_handle(directory_fd),
            name,
            payload,
        )
        try:
            final_identity = handle_identity(handle)
        finally:
            close_handle(handle)
        _recheck_directory(directory_path, directory_identity)
        reread = _read_relative(
            directory_fd,
            directory_path,
            directory_identity,
            name,
            required=True,
        )
        assert reread is not None
        observed, observed_identity, _ = reread
        if observed != payload or observed_identity != final_identity:
            raise AuditChainIntegrityError(
                f"flushed file did not read back identically: {directory_path / name}",
            )
        return observed_identity

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        _write_all(fd, payload)
        os.fsync(fd)
        final_state = os.fstat(fd)
    finally:
        os.close(fd)
    _flush_directory(directory_fd)
    _recheck_directory(directory_path, directory_identity)
    reread = _read_relative(
        directory_fd,
        directory_path,
        directory_identity,
        name,
        required=True,
    )
    assert reread is not None
    observed, observed_identity, _ = reread
    if observed != payload or observed_identity != _identity(final_state):
        raise AuditChainIntegrityError(
            f"fsynced file did not read back identically: {directory_path / name}",
        )
    return observed_identity


def _replace_phase(
    directory_fd: int,
    directory_path: Path,
    directory_identity: tuple[int, int],
    phase: Mapping[str, Any],
) -> None:
    payload = canonical_json(phase) + b"\n"
    temp_name = f".phase-{uuid.uuid4()}.tmp"
    if os.name == "nt":
        from z4j_brain._windows_secure_io import (
            close_handle,
            create_relative_file,
            delete_relative,
            replace_open_handle,
        )

        temp_handle = create_relative_file(
            _windows_handle(directory_fd),
            temp_name,
            payload,
        )
        try:
            replace_open_handle(
                temp_handle,
                _windows_handle(directory_fd),
                _PHASE_FILE,
            )
        except Exception:
            with suppress(OSError):
                delete_relative(_windows_handle(directory_fd), temp_name)
            raise
        finally:
            close_handle(temp_handle)
        _recheck_directory(directory_path, directory_identity)
        reread = _read_relative(
            directory_fd,
            directory_path,
            directory_identity,
            _PHASE_FILE,
            required=True,
        )
        assert reread is not None
        if reread[0] != payload:
            raise AuditChainIntegrityError("phase journal replace did not read back")
        return

    _write_exclusive_relative(
        directory_fd,
        directory_path,
        directory_identity,
        temp_name,
        payload,
    )
    try:
        os.replace(
            temp_name,
            _PHASE_FILE,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        _flush_directory(directory_fd)
    except Exception:
        with suppress(FileNotFoundError):
            os.unlink(temp_name, dir_fd=directory_fd)
        raise
    reread = _read_relative(
        directory_fd,
        directory_path,
        directory_identity,
        _PHASE_FILE,
        required=True,
    )
    assert reread is not None
    if reread[0] != payload:
        raise AuditChainIntegrityError("phase journal replace did not read back")


def _load_phase(
    directory_fd: int,
    directory_path: Path,
    directory_identity: tuple[int, int],
) -> dict[str, Any] | None:
    result = _read_relative(
        directory_fd,
        directory_path,
        directory_identity,
        _PHASE_FILE,
        required=False,
    )
    if result is None:
        return None
    parsed = _strict_json(result[0], label="frozen export phase journal")
    if not isinstance(parsed, dict):
        raise AuditChainIntegrityError("frozen export phase root must be an object")
    return parsed


def _validate_phase(
    phase: Mapping[str, Any],
    *,
    operation_id: uuid.UUID,
    destination: Path,
) -> None:
    if (
        phase.get("format_version") != _FORMAT_VERSION
        or phase.get("operation_id") != str(operation_id)
        or phase.get("destination") != str(destination)
        or phase.get("phase") not in _PHASES
    ):
        raise AuditChainIntegrityError(
            "frozen export phase does not match this operation and destination",
        )


def _manifest_from_rows(
    *,
    operation_id: uuid.UUID,
    destination: Path,
    state_payload: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    classifications = dict(
        sorted(
            Counter(str(row["legacy_integrity_class"]) for row in rows).items(),
        ),
    )
    base = {
        "format_version": _FORMAT_VERSION,
        "operation_id": str(operation_id),
        "destination": str(destination),
        "installation_id": state_payload["installation_id"],
        "generation": state_payload["generation"],
        "ordered_ids": [str(row["id"]) for row in rows],
        "frozen_row_count": len(rows),
        "frozen_snapshot_digest": frozen_snapshot_digest(rows),
        "classification_counts": classifications,
    }
    digest = hashlib.sha256(
        _MANIFEST_DOMAIN + canonical_json(base),
    ).hexdigest()
    return {**base, "manifest_digest": digest}


def _iter_export_document(
    *,
    manifest: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
) -> Iterator[bytes]:
    """Yield the canonical export without materializing the whole document."""

    yield b'{"format_version":1,"manifest":'
    yield canonical_json(dict(manifest))
    yield b',"rows":['
    for index, row in enumerate(rows):
        if index:
            yield b","
        yield canonical_json(row)
    yield b"]}\n"


def _parse_export_value(parsed: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if (
        not isinstance(parsed, dict)
        or parsed.get("format_version") != _FORMAT_VERSION
        or not isinstance(parsed.get("manifest"), dict)
        or not isinstance(parsed.get("rows"), list)
        or any(not isinstance(row, dict) for row in parsed["rows"])
    ):
        raise AuditChainIntegrityError("frozen audit export has an invalid shape")
    manifest = dict(parsed["manifest"])
    rows = [dict(row) for row in parsed["rows"]]
    manifest_base = dict(manifest)
    supplied_digest = manifest_base.pop("manifest_digest", None)
    expected_digest = hashlib.sha256(
        _MANIFEST_DOMAIN + canonical_json(manifest_base),
    ).hexdigest()
    if supplied_digest != expected_digest:
        raise AuditChainIntegrityError("frozen export manifest digest mismatch")
    if (
        manifest.get("ordered_ids") != [row.get("id") for row in rows]
        or manifest.get("frozen_row_count") != len(rows)
        or manifest.get("frozen_snapshot_digest") != frozen_snapshot_digest(rows)
        or manifest.get("classification_counts")
        != dict(
            sorted(
                Counter(str(row.get("legacy_integrity_class")) for row in rows).items(),
            ),
        )
    ):
        raise AuditChainIntegrityError(
            "frozen export rows do not match their finalized manifest",
        )
    return manifest, rows


def _parse_export_fd(fd: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    os.lseek(fd, 0, os.SEEK_SET)
    try:
        with os.fdopen(os.dup(fd), "rb") as stream:
            parsed = json.load(stream, object_pairs_hook=_object)
    except (UnicodeDecodeError, ValueError) as exc:
        raise AuditChainIntegrityError(
            "frozen audit export spool is not strict JSON",
        ) from exc
    finally:
        os.lseek(fd, 0, os.SEEK_SET)
    return _parse_export_value(parsed)


def _read_exact(fd: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(fd, min(_IO_CHUNK_BYTES, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _verify_export_fd(
    fd: int,
    *,
    manifest: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
) -> tuple[int, str]:
    """Require the retained spool to equal the canonical stream byte-for-byte."""

    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    for expected in _iter_export_document(manifest=manifest, rows=rows):
        observed = _read_exact(fd, len(expected))
        if observed != expected:
            raise AuditChainIntegrityError(
                "frozen audit export spool is not canonical",
            )
        digest.update(observed)
        total += len(observed)
    if os.read(fd, 1):
        raise AuditChainIntegrityError(
            "frozen audit export spool has trailing bytes",
        )
    os.lseek(fd, 0, os.SEEK_SET)
    return total, digest.hexdigest()


def _write_export_spool(
    directory_fd: int,
    directory_path: Path,
    directory_identity: tuple[int, int],
    *,
    manifest: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
) -> tuple[int, int]:
    if os.name == "nt":
        from z4j_brain._windows_secure_io import (
            close_handle,
            create_relative_stream_file,
        )

        handle, identity, _ = create_relative_stream_file(
            _windows_handle(directory_fd),
            _SPOOL_FILE,
            _iter_export_document(manifest=manifest, rows=rows),
        )
        close_handle(handle)
        _recheck_directory(directory_path, directory_identity)
        return identity

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(_SPOOL_FILE, flags, 0o600, dir_fd=directory_fd)
    try:
        for chunk in _iter_export_document(manifest=manifest, rows=rows):
            _write_all(fd, chunk)
        os.fsync(fd)
        final_state = os.fstat(fd)
    finally:
        os.close(fd)
    _flush_directory(directory_fd)
    _recheck_directory(directory_path, directory_identity)
    return _identity(final_state)


def _open_export_spool(
    directory_fd: int,
    directory_path: Path,
    directory_identity: tuple[int, int],
    *,
    required: bool,
) -> (
    tuple[
        int,
        dict[str, Any],
        list[dict[str, Any]],
        tuple[int, int],
        int,
        str,
    ]
    | None
):
    if os.name == "nt":
        from z4j_brain._windows_secure_io import open_relative_file

        opened = open_relative_file(
            _windows_handle(directory_fd),
            _SPOOL_FILE,
            require_private=True,
        )
        if opened is None:
            if not required:
                return None
            raise FileNotFoundError(directory_path / _SPOOL_FILE)
        handle, before_identity, before_size = opened
        fd = _windows_fd(handle, os.O_RDONLY)
    else:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(_SPOOL_FILE, flags, dir_fd=directory_fd)
        except FileNotFoundError:
            if not required:
                return None
            raise
        before = os.fstat(fd)
        before_identity = _identity(before)
        before_size = int(before.st_size)
    try:
        if os.name != "nt":
            if not stat.S_ISREG(before.st_mode) or _is_reparse(before):
                raise AuditChainIntegrityError(  # noqa: TRY301
                    f"{directory_path / _SPOOL_FILE} is not a safe regular file",
                )
            _validate_private_mode(
                before,
                directory=False,
                label=str(directory_path / _SPOOL_FILE),
            )
        manifest, rows = _parse_export_fd(fd)
        export_size, export_digest = _verify_export_fd(
            fd,
            manifest=manifest,
            rows=rows,
        )
        after = os.fstat(fd)
        after_identity = _fd_identity(fd)
        if os.name == "nt":
            from z4j_brain._windows_secure_io import relative_file_identity

            path_identity = relative_file_identity(
                _windows_handle(directory_fd),
                _SPOOL_FILE,
            )
        else:
            path_state = os.stat(
                _SPOOL_FILE,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            path_identity = _identity(path_state)
        if (
            before_identity != after_identity
            or before_size != after.st_size
            or export_size != after.st_size
            or after_identity != path_identity
        ):
            raise AuditChainIntegrityError(  # noqa: TRY301
                f"{directory_path / _SPOOL_FILE} changed while it was verified",
            )
        _recheck_directory(directory_path, directory_identity)
        return (
            fd,
            manifest,
            rows,
            after_identity,
            export_size,
            export_digest,
        )
    except Exception:
        os.close(fd)
        raise


async def _capture_frozen_snapshot(
    engine: AsyncEngine,
    settings: Settings,
    *,
    operation_id: uuid.UUID,
    destination: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    service = AuditService(settings)
    async with engine.connect() as connection:
        if connection.dialect.name == "postgresql":
            await connection.execution_options(isolation_level="REPEATABLE READ")
        await connection.begin()
        session = AsyncSession(bind=connection, expire_on_commit=False)
        try:
            states = list(
                (
                    await session.execute(
                        select(AuditChainState).where(
                            AuditChainState.singleton_id == AUDIT_CHAIN_SINGLETON_ID,
                        ),
                    )
                )
                .scalars()
                .all()
            )
            if len(states) != 1:
                raise AuditChainIntegrityError(
                    "authenticated audit-chain state is missing or duplicated",
                )
            state_payload = authenticate_state(states[0], service._audit_keyring)
            persisted_rows = list(
                (
                    await session.execute(
                        select(AuditLog)
                        .where(AuditLog.legacy_frozen.is_(True))
                        .order_by(AuditLog.occurred_at, AuditLog.id),
                    )
                )
                .scalars()
                .all()
            )
            rows = [canonical_frozen_row_snapshot(row) for row in persisted_rows]
            observed_digest = frozen_snapshot_digest(rows)
            if (
                state_payload["frozen_row_count"] != len(rows)
                or state_payload["frozen_snapshot_digest"] != observed_digest
            ):
                raise AuditChainIntegrityError(
                    "frozen rows do not match authenticated audit-chain state",
                )
            if not rows:
                raise AuditChainIntegrityError(
                    "authenticated state contains no frozen history to export",
                )
            return (
                _manifest_from_rows(
                    operation_id=operation_id,
                    destination=destination,
                    state_payload=state_payload,
                    rows=rows,
                ),
                rows,
            )
        finally:
            await session.close()
            await connection.rollback()


def _validate_manifest_for_operation(
    manifest: Mapping[str, Any],
    *,
    operation_id: uuid.UUID,
    destination: Path,
) -> None:
    if (
        manifest.get("format_version") != _FORMAT_VERSION
        or manifest.get("operation_id") != str(operation_id)
        or manifest.get("destination") != str(destination)
    ):
        raise AuditChainIntegrityError(
            "frozen export spool belongs to a different operation",
        )


def _open_destination_parent(
    destination: Path,
) -> tuple[int, tuple[int, int]]:
    parent = destination.parent
    if os.name == "nt":
        from z4j_brain._windows_secure_io import (
            close_handle,
            directory_path_identity,
            open_directory,
        )

        before = directory_path_identity(parent, require_private=False)
        handle, opened = open_directory(parent, require_private=False)
        try:
            after = directory_path_identity(parent, require_private=False)
            if before != opened or opened != after:
                raise AuditChainIntegrityError(  # noqa: TRY301
                    "destination parent identity changed while opening",
                )
        except Exception:
            close_handle(handle)
            raise
        return _windows_fd(handle, os.O_RDONLY), opened

    before = parent.lstat()
    if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode) or _is_reparse(before):
        raise AuditChainIntegrityError("destination parent is not a safe directory")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(parent, flags)
    try:
        opened = os.fstat(fd)
        after = parent.lstat()
        if _identity(before) != _identity(opened) or _identity(opened) != _identity(after):
            raise AuditChainIntegrityError(  # noqa: TRY301
                "destination parent identity changed while opening",
            )
        return fd, _identity(opened)
    except Exception:
        os.close(fd)
        raise


def _open_and_hash_destination(
    destination: Path,
    parent_fd: int,
    parent_identity: tuple[int, int],
) -> tuple[int, tuple[int, int], int, str]:
    if os.name == "nt":
        from z4j_brain._windows_secure_io import open_relative_file

        opened = open_relative_file(
            _windows_handle(parent_fd),
            destination.name,
            require_private=True,
        )
        if opened is None:
            raise FileNotFoundError(destination)
        handle, before_identity, before_size = opened
        fd = _windows_fd(handle, os.O_RDONLY)
    else:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(destination.name, flags, dir_fd=parent_fd)
        before = os.fstat(fd)
        before_identity = _identity(before)
        before_size = int(before.st_size)
    try:
        if os.name != "nt":
            if not stat.S_ISREG(before.st_mode) or _is_reparse(before):
                raise AuditChainIntegrityError(  # noqa: TRY301
                    "destination is not a safe regular file",
                )
            _validate_private_mode(
                before,
                directory=False,
                label=str(destination),
            )
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(fd)
        after_identity = _fd_identity(fd)
        if os.name == "nt":
            from z4j_brain._windows_secure_io import relative_file_identity

            path_identity = relative_file_identity(
                _windows_handle(parent_fd),
                destination.name,
            )
        else:
            path_state = os.stat(
                destination.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            path_identity = _identity(path_state)
        if (
            before_identity != after_identity
            or before_size != after.st_size
            or after_identity != path_identity
            or total != after.st_size
        ):
            raise AuditChainIntegrityError(  # noqa: TRY301
                "destination changed while verifying",
            )
        _recheck_directory(
            destination.parent,
            parent_identity,
            require_private=False,
        )
        os.lseek(fd, 0, os.SEEK_SET)
        return fd, after_identity, int(after.st_size), digest.hexdigest()
    except Exception:
        os.close(fd)
        raise


def _spool_chunks(spool_fd: int) -> Iterator[bytes]:
    while True:
        chunk = os.read(spool_fd, _IO_CHUNK_BYTES)
        if not chunk:
            return
        yield chunk


def _validate_spool_copy(
    *,
    spool_fd: int,
    expected_size: int,
    spool_identity: tuple[int, int],
) -> os.stat_result:
    spool_state = os.fstat(spool_fd)
    if _fd_identity(spool_fd) != spool_identity or spool_state.st_size != expected_size:
        raise AuditChainIntegrityError(
            "retained spool changed before destination copy",
        )
    return spool_state


def _validate_completed_spool_copy(
    *,
    spool_fd: int,
    before: os.stat_result,
    copied: int,
    expected_size: int,
    spool_identity: tuple[int, int],
) -> None:
    after = os.fstat(spool_fd)
    os.lseek(spool_fd, 0, os.SEEK_SET)
    if (
        copied != expected_size
        or _fd_identity(spool_fd) != spool_identity
        or before.st_size != after.st_size
    ):
        raise AuditChainIntegrityError(
            "retained spool changed during destination copy",
        )


def _create_destination_windows(
    destination: Path,
    *,
    parent_fd: int,
    spool_fd: int,
    expected_size: int,
    spool_identity: tuple[int, int],
) -> None:
    from z4j_brain._windows_secure_io import (
        close_handle,
        create_relative_stream_file,
        relative_file_identity,
    )

    if (
        relative_file_identity(
            _windows_handle(parent_fd),
            destination.name,
            require_private=False,
        )
        is not None
    ):
        return
    spool_before = _validate_spool_copy(
        spool_fd=spool_fd,
        expected_size=expected_size,
        spool_identity=spool_identity,
    )
    os.lseek(spool_fd, 0, os.SEEK_SET)
    destination_handle, _, copied = create_relative_stream_file(
        _windows_handle(parent_fd),
        destination.name,
        _spool_chunks(spool_fd),
    )
    close_handle(destination_handle)
    _validate_completed_spool_copy(
        spool_fd=spool_fd,
        before=spool_before,
        copied=copied,
        expected_size=expected_size,
        spool_identity=spool_identity,
    )


def _create_destination_posix(
    destination: Path,
    *,
    parent_fd: int,
    spool_fd: int,
    expected_size: int,
    spool_identity: tuple[int, int],
) -> None:
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        destination_fd = os.open(
            destination.name,
            flags,
            0o600,
            dir_fd=parent_fd,
        )
    except FileExistsError:
        return
    try:
        spool_before = _validate_spool_copy(
            spool_fd=spool_fd,
            expected_size=expected_size,
            spool_identity=spool_identity,
        )
        os.lseek(spool_fd, 0, os.SEEK_SET)
        copied = 0
        for chunk in _spool_chunks(spool_fd):
            _write_all(destination_fd, chunk)
            copied += len(chunk)
        _validate_completed_spool_copy(
            spool_fd=spool_fd,
            before=spool_before,
            copied=copied,
            expected_size=expected_size,
            spool_identity=spool_identity,
        )
        os.fsync(destination_fd)
    finally:
        os.close(destination_fd)
    _flush_directory(parent_fd)


def _populate_destination(
    destination: Path,
    *,
    spool_fd: int,
    expected_digest: str,
    expected_size: int,
    spool_identity: tuple[int, int],
) -> tuple[int, tuple[int, int], int, str, int, tuple[int, int]]:
    parent_fd, parent_identity = _open_destination_parent(destination)
    try:
        create = _create_destination_windows if os.name == "nt" else _create_destination_posix
        create(
            destination,
            parent_fd=parent_fd,
            spool_fd=spool_fd,
            expected_size=expected_size,
            spool_identity=spool_identity,
        )
        fd, identity, size, digest = _open_and_hash_destination(
            destination,
            parent_fd,
            parent_identity,
        )
        if digest != expected_digest or size != expected_size:
            os.close(fd)
            raise AuditChainIntegrityError(  # noqa: TRY301
                "existing destination does not equal the finalized spool",
            )
        if identity == spool_identity:
            os.close(fd)
            raise AuditChainIntegrityError(  # noqa: TRY301
                "destination aliases the private export spool",
            )
        return fd, identity, size, digest, parent_fd, parent_identity
    except Exception:
        os.close(parent_fd)
        raise


def _phase_from_export(
    initial: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    export_digest: str,
    export_size: int,
    spool_identity: tuple[int, int],
    phase_name: str,
) -> dict[str, Any]:
    return {
        **dict(initial),
        "phase": phase_name,
        "manifest_digest": manifest["manifest_digest"],
        "export_sha256": export_digest,
        "export_size": export_size,
        "spool_identity": list(spool_identity),
    }


def _validate_phase_export(
    phase: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    export_digest: str,
    export_size: int,
    spool_identity: tuple[int, int],
) -> None:
    if phase.get("phase") == "INITIAL":
        return
    if (
        phase.get("manifest_digest") != manifest["manifest_digest"]
        or phase.get("export_sha256") != export_digest
        or phase.get("export_size") != export_size
        or phase.get("spool_identity") != list(spool_identity)
    ):
        raise AuditChainIntegrityError(
            "phase journal no longer matches the retained export spool",
        )


async def _commit_frozen_delete(  # noqa: PLR0912, PLR0915
    engine: AsyncEngine,
    settings: Settings,
    *,
    manifest: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    export_digest: str,
    export_size: int,
    spool_identity: tuple[int, int],
    destination_identity: tuple[int, int],
) -> bool:
    """Commit the exact frozen deletion, or prove its prior signed commit."""

    service = AuditService(settings)
    operation_id = str(manifest["operation_id"])
    async with engine.connect() as connection:
        if connection.dialect.name == "sqlite":
            await connection.exec_driver_sql("BEGIN EXCLUSIVE")
        else:
            await connection.begin()
            await connection.execute(
                text("SELECT pg_advisory_xact_lock(:lock_id)"),
                {"lock_id": AUDIT_CHAIN_ADVISORY_LOCK_KEY},
            )
            await connection.execute(
                text("LOCK TABLE audit_log IN SHARE ROW EXCLUSIVE MODE"),
            )
        session = AsyncSession(bind=connection, expire_on_commit=False)
        if connection.dialect.name == "sqlite":
            session.sync_session.info["z4j_sqlite_immediate"] = True
        try:
            repo = AuditLogRepository(session)
            if connection.dialect.name == "postgresql":
                await repo.set_chain_transition("frozen-export-delete-v1")
            states = list(
                (
                    await session.execute(
                        select(AuditChainState)
                        .where(
                            AuditChainState.singleton_id == AUDIT_CHAIN_SINGLETON_ID,
                        )
                        .with_for_update(),
                    )
                )
                .scalars()
                .all()
            )
            if len(states) != 1:
                raise AuditChainIntegrityError(  # noqa: TRY301
                    "authenticated audit-chain state is missing or duplicated",
                )
            state = states[0]
            state_payload = authenticate_state(state, service._audit_keyring)
            if (
                state_payload["installation_id"] != manifest["installation_id"]
                or state_payload["generation"] != manifest["generation"]
            ):
                raise AuditChainIntegrityError(  # noqa: TRY301
                    "audit installation/generation changed after export finalization",
                )

            persisted = list(
                (
                    await session.execute(
                        select(AuditLog)
                        .where(AuditLog.legacy_frozen.is_(True))
                        .order_by(AuditLog.occurred_at, AuditLog.id)
                        .with_for_update(),
                    )
                )
                .scalars()
                .all()
            )
            current_rows = [canonical_frozen_row_snapshot(row) for row in persisted]
            if not current_rows:
                markers = list(
                    (
                        await session.execute(
                            select(AuditLog)
                            .where(
                                AuditLog.legacy_frozen.is_(False),
                                AuditLog.action == "audit.frozen_history_exported",
                            )
                            .order_by(
                                AuditLog.occurred_at.desc(),
                                AuditLog.id.desc(),
                            ),
                        )
                    )
                    .scalars()
                    .all()
                )
                for marker in markers:
                    metadata = marker.audit_metadata
                    if (
                        metadata.get("operation_id") == operation_id
                        and metadata.get("manifest_digest") == manifest["manifest_digest"]
                        and metadata.get("export_sha256") == export_digest
                        and service.verify_row(marker)
                    ):
                        await connection.rollback()
                        return False
                raise AuditChainIntegrityError(  # noqa: TRY301
                    "frozen rows vanished without this operation's signed marker",
                )

            if (
                current_rows != list(rows)
                or state_payload["frozen_row_count"] != manifest["frozen_row_count"]
                or state_payload["frozen_snapshot_digest"] != manifest["frozen_snapshot_digest"]
            ):
                raise AuditChainIntegrityError(  # noqa: TRY301
                    "frozen rows changed after export finalization",
                )

            exact_ids = [uuid.UUID(str(value)) for value in manifest["ordered_ids"]]
            await repo.set_chain_transition("frozen-export-delete-v1")
            result = await session.execute(
                delete(AuditLog).where(
                    AuditLog.legacy_frozen.is_(True),
                    AuditLog.id.in_(exact_ids),
                ),
            )
            affected = getattr(result, "rowcount", None)
            if affected is None or int(affected) != len(exact_ids):
                raise AuditChainIntegrityError(  # noqa: TRY301
                    "frozen audit deletion affected an unexpected row count",
                )
            state.frozen_row_count = 0
            state.frozen_snapshot_digest = None
            state_secret = service._audit_keyring.get(state.state_key_id)
            if state_secret is None:
                raise AuditChainIntegrityError(  # noqa: TRY301
                    "authenticated state key is unavailable during deletion",
                )
            state.state_mac = compute_state_mac(state_secret, state)
            await session.flush()

            marker = await service.record(
                repo,
                action="audit.frozen_history_exported",
                target_type="audit_chain",
                target_id=operation_id,
                result="success",
                outcome="allow",
                metadata={
                    "operation_id": operation_id,
                    "destination": manifest["destination"],
                    "manifest_digest": manifest["manifest_digest"],
                    "export_sha256": export_digest,
                    "export_size": export_size,
                    "frozen_row_count": manifest["frozen_row_count"],
                    "frozen_snapshot_digest": manifest["frozen_snapshot_digest"],
                    "classification_counts": manifest["classification_counts"],
                    "spool_identity": list(spool_identity),
                    "destination_identity": list(destination_identity),
                },
            )
            if marker.target_id != operation_id:
                raise AuditChainIntegrityError(  # noqa: TRY301
                    "frozen export marker identity changed before insert",
                )
            await session.flush()
            await connection.commit()
            return True
        except Exception:
            await connection.rollback()
            raise
        finally:
            await session.close()


async def export_and_delete_frozen(  # noqa: PLR0912, PLR0915
    *,
    engine: AsyncEngine,
    settings: Settings,
    private_root: Path,
    operation_id: uuid.UUID,
    destination: Path,
    acknowledge_destination_digest: str | None = None,
    cleanup: bool = False,
) -> dict[str, Any]:
    """Run or resume one exact frozen export/delete operation."""

    _require_secure_directory_io()
    destination = destination.expanduser().resolve()  # noqa: ASYNC240
    private_root = private_root.expanduser().resolve()  # noqa: ASYNC240
    if destination == private_root or private_root in destination.parents:
        raise AuditChainIntegrityError(
            "destination may not be inside the private phase namespace",
        )

    root_fd, root_identity = _open_private_directory(private_root, create=True)
    operation_path = private_root / str(operation_id)
    try:
        operation_fd, operation_identity = _open_private_directory(
            operation_path,
            create=True,
        )
    finally:
        os.close(root_fd)
    spool_fd = -1
    try:
        initial = {
            "format_version": _FORMAT_VERSION,
            "operation_id": str(operation_id),
            "destination": str(destination),
            "phase": "INITIAL",
        }
        phase = _load_phase(
            operation_fd,
            operation_path,
            operation_identity,
        )
        if phase is None:
            _replace_phase(
                operation_fd,
                operation_path,
                operation_identity,
                initial,
            )
            phase = dict(initial)
        _validate_phase(
            phase,
            operation_id=operation_id,
            destination=destination,
        )

        spool_result = _open_export_spool(
            operation_fd,
            operation_path,
            operation_identity,
            required=False,
        )
        if spool_result is None:
            if phase["phase"] != "INITIAL":
                raise AuditChainIntegrityError(
                    "retained export spool is missing before acknowledgement",
                )
            manifest, rows = await _capture_frozen_snapshot(
                engine,
                settings,
                operation_id=operation_id,
                destination=destination,
            )
            created_spool_identity = _write_export_spool(
                operation_fd,
                operation_path,
                operation_identity,
                manifest=manifest,
                rows=rows,
            )
            spool_result = _open_export_spool(
                operation_fd,
                operation_path,
                operation_identity,
                required=True,
            )
            assert spool_result is not None
            if spool_result[3] != created_spool_identity:
                os.close(spool_result[0])
                raise AuditChainIntegrityError(
                    "new export spool identity changed during finalization",
                )
        (
            spool_fd,
            manifest,
            rows,
            spool_identity,
            export_size,
            export_digest,
        ) = spool_result
        _validate_manifest_for_operation(
            manifest,
            operation_id=operation_id,
            destination=destination,
        )
        _validate_phase_export(
            phase,
            manifest=manifest,
            export_digest=export_digest,
            export_size=export_size,
            spool_identity=spool_identity,
        )
        if phase["phase"] == "INITIAL":
            phase = _phase_from_export(
                initial,
                manifest=manifest,
                export_digest=export_digest,
                export_size=export_size,
                spool_identity=spool_identity,
                phase_name="SPOOLED",
            )
            _replace_phase(
                operation_fd,
                operation_path,
                operation_identity,
                phase,
            )

        (
            destination_fd,
            destination_identity,
            destination_size,
            destination_digest,
            destination_parent_fd,
            destination_parent_identity,
        ) = _populate_destination(
            destination,
            spool_fd=spool_fd,
            expected_digest=export_digest,
            expected_size=export_size,
            spool_identity=spool_identity,
        )
        try:
            if destination_size != export_size or destination_digest != export_digest:
                raise AuditChainIntegrityError(
                    "destination verification differs from the retained spool",
                )
            if phase["phase"] in {"SPOOLED", "INITIAL"}:
                phase = {
                    **phase,
                    "phase": "DESTINATION_VERIFIED",
                    "destination_identity": list(destination_identity),
                }
                _replace_phase(
                    operation_fd,
                    operation_path,
                    operation_identity,
                    phase,
                )
            elif phase.get("destination_identity") != list(destination_identity):
                raise AuditChainIntegrityError(
                    "destination identity changed after it was finalized",
                )

            # Retain both safely opened file identities through the short
            # database transition.  All hashing/read-back finished above.
            transition_spool_state = os.fstat(spool_fd)
            if (
                _fd_identity(spool_fd) != spool_identity
                or transition_spool_state.st_size != export_size
            ):
                raise AuditChainIntegrityError(
                    "spool identity changed before database transition",
                )
            if phase["phase"] in {
                "DESTINATION_VERIFIED",
                "DATABASE_COMMITTED",
            }:
                await _commit_frozen_delete(
                    engine,
                    settings,
                    manifest=manifest,
                    rows=rows,
                    export_digest=export_digest,
                    export_size=export_size,
                    spool_identity=spool_identity,
                    destination_identity=destination_identity,
                )
                if phase["phase"] != "DATABASE_COMMITTED":
                    phase = {**phase, "phase": "DATABASE_COMMITTED"}
                    _replace_phase(
                        operation_fd,
                        operation_path,
                        operation_identity,
                        phase,
                    )

            if acknowledge_destination_digest is not None:
                if acknowledge_destination_digest != export_digest:
                    raise AuditChainIntegrityError(
                        "destination acknowledgement must equal the exact "
                        f"ceremony digest {export_digest}",
                    )
                phase = {
                    **phase,
                    "phase": "DESTINATION_ACKNOWLEDGED",
                    "acknowledged_destination_digest": export_digest,
                }
                _replace_phase(
                    operation_fd,
                    operation_path,
                    operation_identity,
                    phase,
                )

            if cleanup:
                if phase["phase"] != "DESTINATION_ACKNOWLEDGED":
                    raise AuditChainIntegrityError(
                        "cleanup requires exact destination-digest acknowledgement",
                    )
                if _fd_identity(destination_fd) != destination_identity:
                    raise AuditChainIntegrityError(
                        "destination identity changed before cleanup",
                    )
                if os.name == "nt":
                    from z4j_brain._windows_secure_io import (
                        delete_relative,
                        delete_relative_directory,
                        relative_file_identity,
                    )

                    observed_spool_identity = relative_file_identity(
                        _windows_handle(operation_fd),
                        _SPOOL_FILE,
                    )
                    if (
                        observed_spool_identity is not None
                        and observed_spool_identity != spool_identity
                    ):
                        raise AuditChainIntegrityError(
                            "cleanup spool identity does not match the journal",
                        )
                    if observed_spool_identity is not None:
                        os.close(spool_fd)
                        spool_fd = -1
                        delete_relative(
                            _windows_handle(operation_fd),
                            _SPOOL_FILE,
                            expected_identity=spool_identity,
                        )
                    _recheck_directory(operation_path, operation_identity)
                    entries = sorted(entry.name for entry in operation_path.iterdir())
                    _recheck_directory(operation_path, operation_identity)
                    if entries != [_PHASE_FILE]:
                        raise AuditChainIntegrityError(
                            "unexpected private phase entries prevent cleanup",
                        )
                    delete_relative(
                        _windows_handle(operation_fd),
                        _PHASE_FILE,
                    )
                    _recheck_directory(operation_path, operation_identity)
                    os.close(operation_fd)
                    operation_fd = -1
                    root_fd, root_identity = _open_private_directory(
                        private_root,
                        create=False,
                    )
                    try:
                        delete_relative_directory(
                            _windows_handle(root_fd),
                            str(operation_id),
                            expected_identity=operation_identity,
                        )
                        _recheck_directory(private_root, root_identity)
                    finally:
                        os.close(root_fd)
                else:
                    try:
                        spool_state = os.stat(
                            _SPOOL_FILE,
                            dir_fd=operation_fd,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        spool_state = None
                    if spool_state is not None:
                        if _identity(spool_state) != spool_identity:
                            raise AuditChainIntegrityError(
                                "cleanup spool identity does not match the journal",
                            )
                        os.unlink(_SPOOL_FILE, dir_fd=operation_fd)
                        _flush_directory(operation_fd)
                    entries = sorted(os.listdir(operation_fd))  # noqa: PTH208  retained directory fd is the authority
                    if entries != [_PHASE_FILE]:
                        raise AuditChainIntegrityError(
                            "unexpected private phase entries prevent cleanup",
                        )
                    os.unlink(_PHASE_FILE, dir_fd=operation_fd)
                    _flush_directory(operation_fd)
                    _recheck_directory(operation_path, operation_identity)
                    os.close(operation_fd)
                    operation_fd = -1
                    operation_path.rmdir()
                    root_fd, root_identity = _open_private_directory(
                        private_root,
                        create=False,
                    )
                    try:
                        _flush_directory(root_fd)
                        _recheck_directory(private_root, root_identity)
                    finally:
                        os.close(root_fd)
                return {
                    "operation_id": str(operation_id),
                    "phase": "CLEANED",
                    "manifest_digest": manifest["manifest_digest"],
                    "export_sha256": export_digest,
                    "destination": str(destination),
                }

            return {
                "operation_id": str(operation_id),
                "phase": phase["phase"],
                "manifest_digest": manifest["manifest_digest"],
                "export_sha256": export_digest,
                "destination": str(destination),
                "spool": str(operation_path / _SPOOL_FILE),
            }
        finally:
            os.close(destination_fd)
            os.close(destination_parent_fd)
            _recheck_directory(
                destination.parent,
                destination_parent_identity,
                require_private=False,
            )
    finally:
        if spool_fd >= 0:
            os.close(spool_fd)
        if operation_fd >= 0:
            os.close(operation_fd)


__all__ = ["export_and_delete_frozen"]
