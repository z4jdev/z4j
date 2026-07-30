"""Crash-resumable authenticated database replacement.

SQLite restore is deliberately a management ceremony rather than a file copy.
The source is staged once into owner-private storage, the current target is
captured with SQLite's backup API, both databases are fully authenticated, and
the candidate receives Boundary-D monotonic barriers plus one signed restore
marker before it can replace the live pathname.

PostgreSQL uses a separate durable database-fence ceremony and is intentionally
not represented by this module.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import stat
import uuid
from collections.abc import AsyncIterator, Iterator, Mapping
from contextlib import asynccontextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import create_engine, event, select, text, update
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)

from z4j_brain.domain.audit_chain import (
    AuditChainIntegrityError,
    canonical_json,
)
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.audit_verifier import (
    verify_active_audit_generation,
)
from z4j_brain.management_reset import (
    _normalize_sqlite_schema_definition,
    assert_release_schema_contract,
    external_authority_manifest,
    freeze_release_manifest,
    release_manifest_digest,
    release_schema_contract_manifest,
)
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import (
    AuditChainState,
    AuditLog,
    Schedule,
    ScheduleChangeLog,
    ScheduleExternalControlOperation,
    ScheduleExternalEpochAllocator,
    ScheduleExternalStream,
    ScheduleExternalStreamEpoch,
    ScheduleRevisionState,
)
from z4j_brain.persistence.models.schedule_control import (
    SCHEDULE_CHANGE_PROTOCOL_VERSION,
    SCHEDULE_REVISION_SINGLETON_ID,
)
from z4j_brain.persistence.models.schedule_external import (
    SCHEDULE_EXTERNAL_EPOCH_SINGLETON_ID,
)
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
    schedule_snapshot,
)
from z4j_brain.persistence.schedule_external_guard import (
    arm_external_control_transition,
    arm_external_lifecycle_transition,
    assert_external_control_consumed,
    assert_external_lifecycle_consumed,
)
from z4j_brain.persistence.schedule_guard import (
    arm_restore_rebase,
    finalize_restore_rebase,
)
from z4j_brain.schema_transition import RELEASE_MIGRATION_HEAD
from z4j_brain.secret_store import (
    audit_bootstrap_coordinator,
    ensure_secret_store_directory,
)
from z4j_brain.settings import Settings

RESTORE_PHASE_VERSION = 1
_LEGACY_SOURCE_HEAD = "v1_7_security_hardening"
_AUDIT_PREPARATION_HEAD = "v1_8_audit_chain_prepare"
# The legacy value is an external oracle captured from the immutable 6b12719c
# release baseline.  It must never be derived by running current migrations.
_SQLITE_SOURCE_SCHEMA_DIGESTS = {
    RELEASE_MIGRATION_HEAD: ("bc99362d610d37ae64ea3002dc249670911830d4d712ecbf127312253fd8a770"),
    _LEGACY_SOURCE_HEAD: ("f41f542e03cf81562c1eb3167041549fff0623eca9de919c1d0ffd91619933c8"),
}
_PHASE_ROOT_NAME = ".z4j-restore"
_PHASE_FILE_NAME = "phase.json"
_MAX_PHASE_BYTES = 64 * 1024 * 1024
_MAX_BIGINT = (1 << 63) - 1
_restore_allowance: ContextVar[frozenset[Path]] = ContextVar(
    "z4j_restore_allowance",
    default=frozenset(),
)


class DatabaseRestoreRefused(RuntimeError):  # noqa: N818
    """Restore could not prove one required authority or transition."""


class DatabaseRestorePending(RuntimeError):  # noqa: N818
    """Normal startup or migration encountered an unfinished restore."""


def _sqlite_path_from_url(database_url: str) -> Path:
    parsed = urlparse(database_url)
    raw = parsed.path
    if raw.startswith("//") and os.name != "nt":
        # Four-slash SQLAlchemy URLs encode one local POSIX root slash.
        # Retaining both makes SQLite URI consumers interpret the first
        # component as a network authority and also breaks lexical identity
        # comparisons against the ordinary ``/path`` spelling.
        return Path(raw[1:])
    if raw.startswith("/"):
        return Path(raw[1:]) if not raw.startswith("//") else Path(raw)
    return Path(raw)


def _async_sqlite_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{_lexical_absolute(path)}"


def _identity(st: os.stat_result) -> tuple[int, int]:
    return int(st.st_dev), int(st.st_ino)


def _lexical_absolute(path: Path) -> Path:
    """Make a path absolute without following its final filesystem object."""

    return Path(os.path.abspath(os.fspath(path.expanduser())))  # noqa: PTH100


def _validate_private_directory(path: Path) -> tuple[int, int]:
    if os.name == "nt":
        try:
            from z4j_brain._windows_secure_io import directory_path_identity

            return directory_path_identity(path)
        except OSError as exc:
            raise DatabaseRestoreRefused(
                f"restore state directory is not owner-private: {path}: {exc}",
            ) from exc
    try:
        observed = path.lstat()
    except OSError as exc:
        raise DatabaseRestoreRefused(
            f"restore state directory cannot be inspected: {path}",
        ) from exc
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(
        observed.st_mode,
    ):
        raise DatabaseRestoreRefused(
            f"restore state directory is not a real directory: {path}",
        )
    if os.name == "posix" and (observed.st_uid != os.getuid() or observed.st_mode & 0o077):
        raise DatabaseRestoreRefused(
            f"restore state directory must be owner-private (chmod 700 {path})",
        )
    return _identity(observed)


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


def _replace_phase(  # noqa: PLR0915  platform-specific durable writer
    path: Path,
    phase: Mapping[str, Any],
) -> None:
    """Atomic implementation kept separate for mutation tests."""

    _validate_private_directory(path.parent)
    payload = canonical_json(dict(phase)) + b"\n"
    if len(payload) > _MAX_PHASE_BYTES:
        raise DatabaseRestoreRefused(
            "restore phase exceeds the 64 MiB safety bound",
        )
    if os.name == "nt":
        from z4j_brain._windows_secure_io import (
            close_handle,
            create_relative_file,
            directory_path_identity,
            open_directory,
            read_relative,
            replace_open_handle,
        )

        directory_handle, directory_identity = open_directory(path.parent)
        temp_name = f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
        try:
            temp_handle = create_relative_file(
                directory_handle,
                temp_name,
                payload,
            )
            try:
                replace_open_handle(
                    temp_handle,
                    directory_handle,
                    path.name,
                )
            finally:
                close_handle(temp_handle)
            winner, _ = read_relative(
                directory_handle,
                path.name,
                maximum_bytes=_MAX_PHASE_BYTES,
            )
            if winner != payload or directory_path_identity(path.parent) != directory_identity:
                raise DatabaseRestoreRefused(
                    "restore phase winner or parent identity changed",
                )
            return
        except OSError as exc:
            raise DatabaseRestoreRefused(
                f"restore phase cannot be safely replaced: {exc}",
            ) from exc
        finally:
            close_handle(directory_handle)

    directory_fd = os.open(path.parent, os.O_RDONLY)
    temp_name = f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
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
        os.fsync(directory_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp_name, dir_fd=directory_fd)
        raise
    finally:
        os.close(directory_fd)


def _read_phase(path: Path) -> dict[str, Any]:  # noqa: PLR0912
    if os.name == "nt":
        from z4j_brain._windows_secure_io import (
            close_handle,
            directory_path_identity,
            open_directory,
            read_relative,
        )

        directory_handle, directory_identity = open_directory(path.parent)
        try:
            raw, file_identity = read_relative(
                directory_handle,
                path.name,
                maximum_bytes=_MAX_PHASE_BYTES,
            )
            if file_identity is None or directory_path_identity(path.parent) != directory_identity:
                raise DatabaseRestoreRefused(
                    "restore phase or parent identity changed while read",
                )
        except OSError as exc:
            raise DatabaseRestoreRefused(
                f"restore phase cannot be safely read: {exc}",
            ) from exc
        finally:
            close_handle(directory_handle)
    else:
        before_path = path.lstat()
        if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(
            before_path.st_mode,
        ):
            raise DatabaseRestoreRefused(
                "restore phase is not a regular file",
            )
        if before_path.st_uid != os.getuid() or before_path.st_mode & 0o077:
            raise DatabaseRestoreRefused(
                "restore phase must be owner-private (chmod 600)",
            )
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        try:
            before = os.fstat(fd)
            raw = os.read(fd, _MAX_PHASE_BYTES + 1)
            after = os.fstat(fd)
        finally:
            os.close(fd)
        if len(raw) > _MAX_PHASE_BYTES:
            raise DatabaseRestoreRefused(
                "restore phase exceeds the 64 MiB safety bound",
            )
        if (
            _identity(before) != _identity(after)
            or before.st_size != after.st_size
            or _identity(after) != _identity(path.lstat())
        ):
            raise DatabaseRestoreRefused(
                "restore phase changed while it was read",
            )

    def _strict_object(
        pairs: list[tuple[str, Any]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DatabaseRestoreRefused(
                    f"restore phase contains duplicate key {key!r}",
                )
            result[key] = value
        return result

    try:
        parsed = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DatabaseRestoreRefused(
            "restore phase is not canonical JSON",
        ) from exc
    if not isinstance(parsed, dict):
        raise DatabaseRestoreRefused("restore phase must be an object")
    if canonical_json(parsed) + b"\n" != raw:
        raise DatabaseRestoreRefused(
            "restore phase is not canonically encoded",
        )
    return parsed


def _phase_root(target: Path) -> Path:
    return target.parent / _PHASE_ROOT_NAME


def _phase_path(target: Path, operation_id: uuid.UUID) -> Path:
    return _phase_root(target) / str(operation_id) / _PHASE_FILE_NAME


@contextlib.contextmanager
def allow_database_restore(
    database_url: str,
) -> Iterator[None]:
    """Bounded internal allowance for the matching restore coordinator."""

    target = _lexical_absolute(_sqlite_path_from_url(database_url))
    token = _restore_allowance.set(
        _restore_allowance.get() | {target},
    )
    try:
        yield
    finally:
        _restore_allowance.reset(token)


def assert_database_restore_not_pending(database_url: str) -> None:
    """Fence normal SQLite startup and migration on any pending phase."""

    if not database_url.startswith(("sqlite", "sqlite+aiosqlite")):
        return
    target = _lexical_absolute(_sqlite_path_from_url(database_url))
    if target in _restore_allowance.get():
        return
    root = _phase_root(target)
    try:
        root_st = root.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(root_st.st_mode) or not stat.S_ISDIR(root_st.st_mode):
        raise DatabaseRestorePending(
            f"restore fence path is not a real directory: {root}",
        )
    _validate_private_directory(root)
    for operation_dir in sorted(root.iterdir(), key=lambda item: item.name):
        try:
            operation_st = operation_dir.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(operation_st.st_mode) or not stat.S_ISDIR(
            operation_st.st_mode,
        ):
            raise DatabaseRestorePending(
                f"restore operation path is unsafe: {operation_dir}",
            )
        phase_path = operation_dir / _PHASE_FILE_NAME
        try:
            phase = _read_phase(phase_path)
        except FileNotFoundError:
            raise DatabaseRestorePending(
                f"restore operation lacks its durable phase: {operation_dir}",
            ) from None
        if phase.get("target_path") == str(target) and phase.get("state") not in {
            "COMPLETE",
            "ROLLED_BACK",
        }:
            raise DatabaseRestorePending(
                f"database restore is pending; resume operation {phase.get('operation_id')}",
            )


def install_database_restore_fence_engine_hook(
    engine: AsyncEngine,
    database_url: str,
) -> None:
    """Reject every new normal PostgreSQL connection under a DB fence."""

    if not database_url.startswith("postgresql"):
        return

    async def inspect_catalog_fence(
        driver_connection: Any,
    ) -> None:
        row = await driver_connection.fetchrow(
            """
            SELECT setconfig
            FROM pg_catalog.pg_db_role_setting
            WHERE setdatabase = (
              SELECT oid
              FROM pg_catalog.pg_database
              WHERE datname = current_database()
            )
              AND setrole = 0
            """,
        )
        settings = [] if row is None else list(row["setconfig"] or [])
        matches = [
            str(value).removeprefix("z4j.restore_pending=")
            for value in settings
            if str(value).startswith("z4j.restore_pending=")
        ]
        if not matches:
            return
        if len(matches) != 1:
            raise DatabaseRestorePending(
                "PostgreSQL restore fence has duplicate catalog entries",
            )
        try:
            envelope = json.loads(matches[0])
        except json.JSONDecodeError as exc:
            raise DatabaseRestorePending(
                "PostgreSQL restore fence is malformed",
            ) from exc
        required = {
            "operation_id",
            "source_digest",
            "state",
            "target_identity_digest",
            "toc_digest",
            "version",
        }
        if (
            not isinstance(envelope, dict)
            or not required.issubset(envelope)
            or envelope.get("version") != 1
        ):
            raise DatabaseRestorePending(
                "PostgreSQL restore fence has an invalid envelope",
            )
        raise DatabaseRestorePending(
            "PostgreSQL database restore is unfinished; resume operation "
            f"{envelope['operation_id']}",
        )

    def reject_pending_restore(
        dbapi_connection: Any,
        connection_record: Any,
    ) -> None:
        try:
            dbapi_connection.run_async(inspect_catalog_fence)
        except DatabaseRestorePending:
            # A connect-event failure happens after the driver connection has
            # been assigned to a pool record but before that record finishes
            # initializing.  Terminate and detach it directly: normal record
            # invalidation is not yet available at this point.
            dbapi_connection.terminate()
            connection_record.dbapi_connection = None
            raise

    event.listen(
        engine.sync_engine,
        "connect",
        reject_pending_restore,
    )


def _stage_source(  # noqa: PLR0912, PLR0915
    source: Path,
    destination: Path,
    *,
    expected_sha256: str | None,
) -> tuple[int, str]:
    """Read the operator source once into private staged authority."""

    # Preserve the lexical operator pathname until after lstat/open.  Resolving
    # first would dereference a symlink and make the later O_NOFOLLOW check
    # certify the link target instead of rejecting the supplied link.
    source_path = Path(
        os.path.abspath(  # noqa: PTH100  no-follow requires lexical identity
            os.fspath(source.expanduser()),
        ),
    )
    if os.name == "nt":
        from z4j_brain._windows_secure_io import (
            close_handle,
            copy_relative_file,
            delete_relative,
            directory_path_identity,
            open_directory,
        )

        try:
            source_lstat = source_path.lstat()
        except OSError as exc:
            raise DatabaseRestoreRefused(
                "restore source must be a regular file, not a link",
            ) from exc
        if stat.S_ISLNK(source_lstat.st_mode) or not stat.S_ISREG(
            source_lstat.st_mode,
        ):
            raise DatabaseRestoreRefused(
                "restore source must be a regular file, not a link",
            )
        source_directory, source_parent_identity = open_directory(
            source_path.parent,
            require_private=False,
        )
        destination_directory, destination_parent_identity = open_directory(
            destination.parent,
        )
        try:
            size, observed_digest = copy_relative_file(
                source_directory,
                source_path.name,
                destination_directory,
                destination.name,
            )
            if (
                directory_path_identity(
                    source_path.parent,
                    require_private=False,
                )
                != source_parent_identity
                or directory_path_identity(destination.parent) != destination_parent_identity
            ):
                with contextlib.suppress(OSError):
                    delete_relative(destination_directory, destination.name)
                raise DatabaseRestoreRefused(
                    "restore source or staging parent identity changed",
                )
            if expected_sha256 is not None and expected_sha256 != observed_digest:
                delete_relative(destination_directory, destination.name)
                raise DatabaseRestoreRefused(
                    "restore source digest does not match --expected-sha256",
                )
            return size, observed_digest
        except OSError as exc:
            raise DatabaseRestoreRefused(
                f"restore source cannot be securely staged: {exc}",
            ) from exc
        finally:
            close_handle(destination_directory)
            close_handle(source_directory)

    source_lstat = source_path.lstat()
    if stat.S_ISLNK(source_lstat.st_mode) or not stat.S_ISREG(
        source_lstat.st_mode,
    ):
        raise DatabaseRestoreRefused(
            "restore source must be a regular file, not a link",
        )
    source_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
    source_fd = os.open(source_path, source_flags)
    destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        destination_flags |= os.O_NOFOLLOW
    destination_fd = os.open(destination, destination_flags, 0o600)
    digest = hashlib.sha256()
    size = 0
    try:
        before = os.fstat(source_fd)
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            offset = 0
            while offset < len(chunk):
                offset += os.write(destination_fd, chunk[offset:])
        os.fsync(destination_fd)
        after = os.fstat(source_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            destination.unlink()
        raise
    finally:
        os.close(destination_fd)
        os.close(source_fd)
    if (
        _identity(before) != _identity(after)
        or before.st_size != after.st_size
        or size != before.st_size
        or _identity(after) != _identity(source_path.lstat())
    ):
        with contextlib.suppress(OSError):
            destination.unlink()
        raise DatabaseRestoreRefused(
            "restore source changed while it was staged",
        )
    observed_digest = digest.hexdigest()
    if expected_sha256 is not None and expected_sha256 != observed_digest:
        with contextlib.suppress(OSError):
            destination.unlink()
        raise DatabaseRestoreRefused(
            "restore source digest does not match --expected-sha256",
        )
    _fsync_directory(destination.parent)
    return size, observed_digest


def _file_digest(path: Path) -> tuple[int, str]:
    if os.name == "nt":
        from z4j_brain._windows_secure_io import (
            close_handle,
            digest_relative_file,
            directory_path_identity,
            open_directory,
        )

        directory_handle, directory_identity = open_directory(
            path.parent,
            require_private=False,
        )
        try:
            _, size, digest, link_count = digest_relative_file(
                directory_handle,
                path.name,
            )
            if link_count != 1:
                raise DatabaseRestoreRefused(
                    f"restore artifact has a hard-link alias: {path}",
                )
            if (
                directory_path_identity(
                    path.parent,
                    require_private=False,
                )
                != directory_identity
            ):
                raise DatabaseRestoreRefused(
                    f"restore artifact parent changed while read: {path}",
                )
            return size, digest
        except OSError as exc:
            raise DatabaseRestoreRefused(
                f"restore artifact cannot be safely read: {path}: {exc}",
            ) from exc
        finally:
            close_handle(directory_handle)

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    digest = hashlib.sha256()
    size = 0
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise DatabaseRestoreRefused(
                f"restore artifact is not regular: {path}",
            )
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if (
        _identity(before) != _identity(after)
        or before.st_size != after.st_size
        or size != before.st_size
        or _identity(after) != _identity(path.lstat())
    ):
        raise DatabaseRestoreRefused(
            f"restore artifact changed while read: {path}",
        )
    return size, digest.hexdigest()


def _sqlite_schema_contract_digest(
    manifest: list[dict[str, Any]],
) -> str:
    payload = canonical_json({"value": manifest})
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _empty_external_authority_manifest() -> dict[str, Any]:
    empty_digest = release_manifest_digest([])
    return {
        "allocator_digest": empty_digest,
        "stream_digest": empty_digest,
        "epoch_digest": empty_digest,
        "operation_digest": empty_digest,
        "stream_count": 0,
        "epoch_count": 0,
        "operation_count": 0,
        "executor_authority": {
            "streams": [],
            "epochs": [],
            "unresolved_operations": [],
        },
        "requires_stopped_executor_attestation": False,
    }


def _immutable_sqlite_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        f"{_lexical_absolute(path).as_uri()}?mode=ro&immutable=1",
        uri=True,
        timeout=0,
    )
    connection.row_factory = sqlite3.Row
    connection.enable_load_extension(False)
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    return connection


def _sqlite_source_authority(
    path: Path,
    *,
    source_digest: str,
) -> dict[str, Any]:
    """Prove one exact supported standalone SQLite source without mutation."""

    sidecars = tuple(Path(f"{path}{suffix}") for suffix in ("-wal", "-shm", "-journal"))
    if any(sidecar.exists() for sidecar in sidecars):
        raise DatabaseRestoreRefused(
            "staged SQLite source unexpectedly has a sidecar",
        )
    connection = _immutable_sqlite_connection(path)
    try:
        databases = connection.execute(
            "PRAGMA database_list",
        ).fetchall()
        if len(databases) != 1 or str(databases[0]["name"]) != "main":
            raise DatabaseRestoreRefused(
                "staged SQLite source has an attached database",
            )
        integrity = connection.execute(
            "PRAGMA integrity_check",
        ).fetchall()
        if len(integrity) != 1 or str(integrity[0][0]).lower() != "ok":
            raise DatabaseRestoreRefused(
                "staged SQLite source failed integrity_check",
            )
        versions = connection.execute(
            "SELECT version_num FROM alembic_version",
        ).fetchall()
        if (
            len(versions) != 1
            or str(versions[0]["version_num"]) not in _SQLITE_SOURCE_SCHEMA_DIGESTS
        ):
            raise DatabaseRestoreRefused(
                "staged SQLite source has an unsupported migration head",
            )
        source_head = str(versions[0]["version_num"])
        schema_rows = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' "
            "AND type IN ('table', 'index', 'trigger', 'view') "
            "ORDER BY type, name",
        ).fetchall()
        schema_manifest = [
            {
                "type": str(row["type"]),
                "name": str(row["name"]),
                "table_name": str(row["tbl_name"]),
                "definition": _normalize_sqlite_schema_definition(
                    str(row["type"]),
                    None if row["sql"] is None else str(row["sql"]),
                ),
            }
            for row in schema_rows
        ]
        schema_digest = _sqlite_schema_contract_digest(
            schema_manifest,
        )
        expected_digest = _SQLITE_SOURCE_SCHEMA_DIGESTS[source_head]
        if schema_digest != expected_digest:
            raise DatabaseRestoreRefused(
                "staged SQLite source schema signature mismatch "
                f"(observed={schema_digest}, expected={expected_digest})",
            )

        authority: dict[str, Any] = {
            "source_head": source_head,
            "schema_contract_digest": schema_digest,
            "source_digest": source_digest,
        }
        if source_head == _LEGACY_SOURCE_HEAD:
            # Boundary D did not exist at the supported 1.7 source head.
            # Historical migration replay must therefore contain no revision
            # singleton to inspect; its restore rebase starts at revision zero.
            revision = 0
            revision_classification = "pre_d_empty"
            external = _empty_external_authority_manifest()
            source_manifest = {
                **authority,
                "revision": revision,
                "revision_classification": revision_classification,
                "epoch": 0,
                "external_authority_manifest": external,
            }
            authority = {
                **source_manifest,
                "manifest_digest": release_manifest_digest(
                    source_manifest,
                ),
            }
        return authority
    except sqlite3.DatabaseError as exc:
        raise DatabaseRestoreRefused(
            f"staged SQLite source preflight failed: {exc}",
        ) from exc
    finally:
        connection.close()
        if any(sidecar.exists() for sidecar in sidecars):
            raise DatabaseRestoreRefused(
                "staged SQLite source preflight created a sidecar",
            )


def _sqlite_preparation(path: Path) -> dict[str, Any] | None:
    connection = _immutable_sqlite_connection(path)
    try:
        head = connection.execute(
            "SELECT version_num FROM alembic_version",
        ).fetchall()
        if len(head) != 1 or str(head[0]["version_num"]) != (_AUDIT_PREPARATION_HEAD):
            return None
        rows = connection.execute(
            "SELECT preparation_id, audit_key_id, "
            "preparation_revision, target_activation_revision, "
            "preparation_mac FROM audit_chain_preparation",
        ).fetchall()
        if len(rows) != 1:
            return None
        preparation = dict(rows[0])
        preparation["preparation_id"] = str(
            uuid.UUID(str(preparation["preparation_id"])),
        )
        return preparation
    except sqlite3.DatabaseError:
        return None
    finally:
        connection.close()


def _upgrade_sqlite_database(
    path: Path,
    *,
    activation_manifest: dict[str, Any] | None = None,
    activation_attestation: str | None = None,
) -> None:
    """Run release migrations on the exact restore-owned SQLite file."""

    from alembic import command
    from alembic.config import Config

    backend_root = Path(__file__).resolve().parents[2]
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    engine = create_engine(f"sqlite:///{_lexical_absolute(path)}")
    try:
        with engine.connect() as connection:
            config.attributes["z4j_restore_connection"] = connection
            if activation_manifest is not None:
                config.attributes["z4j_audit_activation_manifest"] = activation_manifest
                config.attributes["z4j_audit_activation_attestation"] = activation_attestation
            command.upgrade(config, "head")
    finally:
        engine.dispose()


def _sqlite_installed_identity(path: Path) -> dict[str, Any]:
    observed = path.lstat()
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(
        observed.st_mode,
    ):
        raise DatabaseRestoreRefused(
            "installed SQLite restore target is not a regular file",
        )
    if os.name == "posix" and (observed.st_uid != os.getuid() or observed.st_mode & 0o077):
        raise DatabaseRestoreRefused(
            "installed SQLite restore target is not owner-private",
        )
    size, digest = _file_digest(path)
    return {
        "path": str(path),
        "device": int(observed.st_dev),
        "inode": int(observed.st_ino),
        "size": size,
        "digest": digest,
        "parent_identity": list(
            _validate_private_directory(path.parent),
        ),
    }


def _discard_working_database(path: Path) -> None:
    """Remove only one phase-local, never-installed SQLite work set."""

    for artifact in (
        path,
        Path(f"{path}-wal"),
        Path(f"{path}-shm"),
        Path(f"{path}-journal"),
    ):
        with contextlib.suppress(FileNotFoundError):
            artifact.unlink()
    _fsync_directory(path.parent)


def _cleanup_completed_operation(operation_dir: Path) -> None:
    for artifact_name in (
        "source-staged.db",
        "source-staged.db-wal",
        "source-staged.db-shm",
        "source-staged.db-journal",
        "target-recovery.db",
        "target-recovery.db-wal",
        "target-recovery.db-shm",
        "target-recovery.db-journal",
        "candidate.db",
        "candidate.db-wal",
        "candidate.db-shm",
        "candidate.db-journal",
        "displaced-main.db",
        "displaced-wal",
        "displaced-shm",
        "displaced-journal",
        "rollback-candidate.db",
        "rollback-candidate.db-wal",
        "rollback-candidate.db-shm",
        "rollback-candidate.db-journal",
        "rollback-rejected-main.db",
        "rollback-rejected-wal",
        "rollback-rejected-shm",
        "rollback-rejected-journal",
    ):
        artifact = operation_dir / artifact_name
        with contextlib.suppress(FileNotFoundError):
            artifact.unlink()
    _fsync_directory(operation_dir)


def _sqlite_backup(source: Path, destination: Path) -> None:
    if destination.exists():
        raise DatabaseRestoreRefused(
            f"restore artifact already exists: {destination}",
        )
    source_connection = sqlite3.connect(
        f"{_lexical_absolute(source).as_uri()}?mode=ro",
        uri=True,
    )
    destination_connection = sqlite3.connect(destination)
    try:
        source_connection.backup(destination_connection)
        destination_connection.commit()
        result = destination_connection.execute(
            "PRAGMA quick_check",
        ).fetchall()
        quick_check_clean = result == [("ok",)]
    except BaseException:
        destination_connection.close()
        source_connection.close()
        with contextlib.suppress(OSError):
            destination.unlink()
        raise
    finally:
        with contextlib.suppress(Exception):
            destination_connection.close()
        with contextlib.suppress(Exception):
            source_connection.close()
    if not quick_check_clean:
        with contextlib.suppress(OSError):
            destination.unlink()
        raise DatabaseRestoreRefused(
            f"SQLite backup quick_check failed: {result!r}",
        )
    destination.chmod(0o600)
    artifact_fd = os.open(
        destination,
        os.O_RDWR if os.name == "nt" else os.O_RDONLY,
    )
    try:
        os.fsync(artifact_fd)
    finally:
        os.close(artifact_fd)
    _fsync_directory(destination.parent)


@asynccontextmanager
async def _restore_session(
    *,
    database: DatabaseManager | None,
    connection: AsyncConnection | None,
    session: AsyncSession | None = None,
    write: bool = False,
) -> AsyncIterator[AsyncSession]:
    """Open a management session on the held PG coordinator when supplied."""

    if session is not None:
        yield session
        return
    if connection is not None:
        async with AsyncSession(
            bind=connection,
            expire_on_commit=False,
        ) as connection_session:
            yield connection_session
        return
    if database is None:
        raise DatabaseRestoreRefused(
            "restore session lacks database authority",
        )
    async with database.session(write=write) as database_session:
        yield database_session


def _portable_restore_manifest_digest(
    manifest: Mapping[str, Any],
) -> str:
    """Digest logical data without PostgreSQL's recreated catalog OIDs."""

    portable = dict(manifest)
    if "physical_partitions" in portable:
        partitions = portable["physical_partitions"]
        if isinstance(partitions, Mapping):
            portable["physical_partitions"] = {
                name: {
                    key: value
                    for key, value in partition.items()
                    if key not in {"relation_oid", "parent_relation_oid"}
                }
                for name, partition in partitions.items()
            }
    return release_manifest_digest(portable)


async def authenticated_database_snapshot(
    database_url: str,
    settings: Settings,
    *,
    connection: AsyncConnection | None = None,
    session: AsyncSession | None = None,
) -> dict[str, Any]:
    if connection is not None and session is not None:
        raise DatabaseRestoreRefused(
            "restore snapshot received both a connection and a session",
        )
    engine = create_async_engine(database_url) if connection is None and session is None else None
    database = DatabaseManager(engine) if engine is not None else None
    try:
        async with _restore_session(
            database=database,
            connection=connection,
            session=session,
            write=True,
        ) as snapshot_session:
            if snapshot_session.get_bind().dialect.name == "postgresql":
                # PostgreSQL catalog renderers such as pg_get_expr() format
                # timestamptz partition bounds in the current session zone.
                # The preflight asyncpg session and the pinned psycopg restore
                # coordinator can otherwise digest different strings for the
                # same physical bounds. Keep this transaction's complete
                # authenticated snapshot on one explicit canonical zone.
                await snapshot_session.execute(text("SET LOCAL TIME ZONE 'UTC'"))
            schema_manifest = await release_schema_contract_manifest(
                snapshot_session,
            )
            schema_digest = await assert_release_schema_contract(
                snapshot_session,
            )
            report = await verify_active_audit_generation(
                snapshot_session,
                settings,
                page_size=5000,
            )
            if not report.clean:
                raise DatabaseRestoreRefused(
                    f"restore database audit state is not clean: {list(report.mismatches)}",
                )
            audit_state = await snapshot_session.get(
                AuditChainState,
                "audit-chain",
            )
            if audit_state is None or audit_state.retired_recovery_binding is not None:
                raise DatabaseRestoreRefused(
                    "restore refuses while a retired installation recovery binding is unresolved",
                )
            manifest = await freeze_release_manifest(snapshot_session)
            revision = await snapshot_session.get(
                ScheduleRevisionState,
                SCHEDULE_REVISION_SINGLETON_ID,
            )
            allocator = await snapshot_session.get(
                ScheduleExternalEpochAllocator,
                SCHEDULE_EXTERNAL_EPOCH_SINGLETON_ID,
            )
            if (
                revision is None
                or revision.guard_version != 1
                or allocator is None
                or allocator.guard_version != 1
            ):
                raise DatabaseRestoreRefused(
                    "restore database lacks activated Boundary-D authority",
                )
            authorities = await external_authority_manifest(
                snapshot_session,
                manifest,
            )
            return {
                "migration_head": RELEASE_MIGRATION_HEAD,
                "schema_contract_digest": schema_digest,
                "schema_contract_manifest": schema_manifest,
                "manifest": manifest,
                "manifest_digest": release_manifest_digest(manifest),
                "portable_manifest_digest": (_portable_restore_manifest_digest(manifest)),
                "revision": int(revision.current_revision),
                "pruned_through": int(
                    revision.change_log_pruned_through,
                ),
                "epoch": int(allocator.current_epoch_number),
                "external_authority_manifest": authorities,
            }
    finally:
        if database is not None:
            await database.dispose()


async def _authenticated_snapshot(
    path: Path,
    settings: Settings,
) -> dict[str, Any]:
    return await authenticated_database_snapshot(
        _async_sqlite_url(path),
        settings,
    )


def _attestation_envelope(
    *,
    source_snapshot: Mapping[str, Any],
    target_snapshot: Mapping[str, Any],
) -> tuple[dict[str, Any], str, bool]:
    envelope = {
        "version": 1,
        "kind": "stopped_all_restore_external_executors",
        "source_manifest_digest": source_snapshot["manifest_digest"],
        "target_manifest_digest": target_snapshot["manifest_digest"],
        "source_external_authority_manifest": source_snapshot["external_authority_manifest"],
        "target_external_authority_manifest": target_snapshot["external_authority_manifest"],
    }
    challenge = release_manifest_digest(envelope)
    required = bool(
        source_snapshot["external_authority_manifest"]["requires_stopped_executor_attestation"]
        or target_snapshot["external_authority_manifest"]["requires_stopped_executor_attestation"]
    )
    return envelope, challenge, required


async def finalize_restored_database(  # noqa: PLR0912, PLR0915
    database_url: str,
    settings: Settings,
    *,
    connection: AsyncConnection | None = None,
    operation_id: uuid.UUID,
    source_digest: str,
    source_snapshot: Mapping[str, Any],
    target_recovery_digest: str,
    target_snapshot: Mapping[str, Any],
    attestation: Mapping[str, Any],
    attestation_digest: str,
    known_head: Mapping[str, Any] | None,
    ceremony_metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    engine = create_async_engine(database_url) if connection is None else None
    database = DatabaseManager(engine) if engine is not None else None
    try:
        async with _restore_session(
            database=database,
            connection=connection,
            write=True,
        ) as session:
            observed_schema = await assert_release_schema_contract(
                session,
            )
            if observed_schema != source_snapshot["schema_contract_digest"]:
                raise DatabaseRestoreRefused(
                    "candidate schema no longer matches staged source",
                )
            report = await verify_active_audit_generation(
                session,
                settings,
                page_size=5000,
                known_head=known_head,
            )
            if not report.clean:
                raise DatabaseRestoreRefused(
                    f"candidate audit state is not clean: {list(report.mismatches)}",
                )
            known_head_result = (
                report.known_head_result if known_head is not None else "ROLLBACK_NOT_ASSESSED"
            )
            current_manifest = await freeze_release_manifest(session)
            if release_manifest_digest(current_manifest) != source_snapshot["manifest_digest"]:
                raise DatabaseRestoreRefused(
                    "candidate changed after staged-source preflight",
                )

            revision_state = (
                await session.execute(
                    select(ScheduleRevisionState)
                    .where(
                        ScheduleRevisionState.singleton_id == SCHEDULE_REVISION_SINGLETON_ID,
                    )
                    .with_for_update(),
                )
            ).scalar_one()
            allocator = (
                await session.execute(
                    select(ScheduleExternalEpochAllocator)
                    .where(
                        ScheduleExternalEpochAllocator.singleton_id
                        == SCHEDULE_EXTERNAL_EPOCH_SINGLETON_ID,
                    )
                    .with_for_update(),
                )
            ).scalar_one()
            restored_revision = int(revision_state.current_revision)
            restored_epoch = int(allocator.current_epoch_number)
            target_revision = int(target_snapshot["revision"])
            target_epoch = int(target_snapshot["epoch"])
            barrier_revision = (
                max(
                    restored_revision,
                    target_revision,
                )
                + 1
            )
            epoch_barrier = max(restored_epoch, target_epoch) + 1
            if barrier_revision > _MAX_BIGINT or epoch_barrier > _MAX_BIGINT:
                raise DatabaseRestoreRefused(
                    "restore monotonic namespace is exhausted",
                )

            schedules = tuple(
                (
                    await session.execute(
                        select(Schedule).order_by(Schedule.id),
                    )
                ).scalars()
            )
            if barrier_revision + len(schedules) > _MAX_BIGINT:
                raise DatabaseRestoreRefused(
                    "restore schedule revision namespace is exhausted",
                )
            descriptor_rows = [
                {
                    "schedule_id": str(row.id),
                    "old_revision": int(row.schedule_revision or 0),
                    "new_revision": barrier_revision + index,
                    "control_token": str(row.control_token),
                }
                for index, row in enumerate(schedules, start=1)
            ]
            if any(
                row.schedule_revision is None
                or int(row.schedule_revision) <= 0
                or row.control_token is None
                for row in schedules
            ):
                raise DatabaseRestoreRefused(
                    "restored schedule lacks complete D identity",
                )
            final_revision = barrier_revision + len(schedules)

            deleted_logs = await ScheduleControlRepository(
                session,
            ).prune_change_log(
                through_revision=restored_revision,
            )
            # prune_change_log mirrors its Core UPDATE onto the loaded ORM
            # singleton.  Clear that redundant dirty attribute before arming
            # the multi-row restore descriptor; otherwise PostgreSQL
            # autoflush attempts an unmanifested second boundary update.
            session.expire(
                revision_state,
                ["change_log_pruned_through"],
            )
            await session.flush()
            await arm_restore_rebase(
                session,
                manifest_digest=source_snapshot["manifest_digest"],
                attestation_digest=attestation_digest,
                restored_revision=restored_revision,
                barrier_revision=barrier_revision,
                final_revision=final_revision,
                restored_epoch=restored_epoch,
                epoch_barrier=epoch_barrier,
                schedules=descriptor_rows,
            )
            revision_result = await session.execute(
                update(ScheduleRevisionState)
                .where(
                    ScheduleRevisionState.singleton_id == SCHEDULE_REVISION_SINGLETON_ID,
                    ScheduleRevisionState.current_revision == restored_revision,
                    ScheduleRevisionState.change_log_pruned_through == restored_revision,
                )
                .values(
                    current_revision=final_revision,
                    change_log_pruned_through=barrier_revision,
                ),
            )
            epoch_result = await session.execute(
                update(ScheduleExternalEpochAllocator)
                .where(
                    ScheduleExternalEpochAllocator.singleton_id
                    == SCHEDULE_EXTERNAL_EPOCH_SINGLETON_ID,
                    ScheduleExternalEpochAllocator.current_epoch_number == restored_epoch,
                )
                .values(current_epoch_number=epoch_barrier),
            )
            if (revision_result.rowcount or 0) != 1 or (epoch_result.rowcount or 0) != 1:
                raise DatabaseRestoreRefused(
                    "restore barriers did not advance exactly once",
                )

            schedule_digest_rows: list[dict[str, Any]] = []
            for descriptor, row in zip(
                descriptor_rows,
                schedules,
                strict=True,
            ):
                new_revision = int(descriptor["new_revision"])
                change_kind = "upsert" if row.scheduler == "z4j-scheduler" else "gap"
                snapshot = (
                    {
                        **schedule_snapshot(
                            row,
                            overrides={
                                "schedule_revision": new_revision,
                            },
                        ),
                        "transition": {
                            "kind": "database_restore_rebase",
                            "operation_id": str(operation_id),
                        },
                    }
                    if change_kind == "upsert"
                    else None
                )
                await session.execute(
                    ScheduleChangeLog.__table__.insert().values(
                        revision=new_revision,
                        project_id=row.project_id,
                        schedule_id=row.id,
                        schedule_owner=row.scheduler,
                        change_kind=change_kind,
                        protocol_version=(SCHEDULE_CHANGE_PROTOCOL_VERSION),
                        snapshot=snapshot,
                        occurred_at=datetime.now(UTC),
                    ),
                )
                updated = await session.execute(
                    Schedule.__table__.update()
                    .where(
                        Schedule.id == row.id,
                        Schedule.schedule_revision == descriptor["old_revision"],
                        Schedule.control_token == row.control_token,
                    )
                    .values(schedule_revision=new_revision),
                )
                if (updated.rowcount or 0) != 1:
                    raise DatabaseRestoreRefused(
                        "restored schedule did not rebase exactly once",
                    )
                schedule_digest_rows.append(
                    {
                        "schedule_id": str(row.id),
                        "old_revision": descriptor["old_revision"],
                        "new_revision": new_revision,
                    },
                )
            await finalize_restore_rebase(
                session,
                manifest_digest=source_snapshot["manifest_digest"],
                attestation_digest=attestation_digest,
            )

            streams = tuple(
                (
                    await session.execute(
                        select(ScheduleExternalStream)
                        .order_by(ScheduleExternalStream.id)
                        .with_for_update(),
                    )
                ).scalars()
            )
            held_streams: list[str] = []
            for stream in streams:
                if stream.phase in {
                    "RETIRED",
                    "RESTORE_REACTIVATION_REQUIRED",
                }:
                    continue
                epoch = (
                    await session.execute(
                        select(ScheduleExternalStreamEpoch)
                        .where(
                            ScheduleExternalStreamEpoch.stream_id == stream.id,
                            ScheduleExternalStreamEpoch.epoch_uuid == stream.current_epoch_uuid,
                            ScheduleExternalStreamEpoch.epoch_number == stream.current_epoch_number,
                        )
                        .with_for_update(),
                    )
                ).scalar_one()
                await arm_external_lifecycle_transition(
                    session,
                    transition="restore_hold",
                    operation_id=operation_id,
                    stream_id=stream.id,
                    epoch_uuid=stream.current_epoch_uuid,
                    epoch_number=stream.current_epoch_number,
                    accepted_sequence=stream.accepted_sequence,
                    from_phase=stream.phase,
                    to_phase="RESTORE_REACTIVATION_REQUIRED",
                    sealed_sequence=stream.sealed_sequence,
                    last_snapshot_digest=stream.last_snapshot_digest,
                    mutations=[],
                )
                epoch_updated = await session.execute(
                    ScheduleExternalStreamEpoch.__table__.update()
                    .where(
                        ScheduleExternalStreamEpoch.epoch_uuid == epoch.epoch_uuid,
                        ScheduleExternalStreamEpoch.phase == epoch.phase,
                    )
                    .values(
                        phase="RESTORE_REACTIVATION_REQUIRED",
                    ),
                )
                stream_updated = await session.execute(
                    ScheduleExternalStream.__table__.update()
                    .where(
                        ScheduleExternalStream.id == stream.id,
                        ScheduleExternalStream.phase == stream.phase,
                    )
                    .values(
                        phase="RESTORE_REACTIVATION_REQUIRED",
                    ),
                )
                if (epoch_updated.rowcount or 0) != 1 or (stream_updated.rowcount or 0) != 1:
                    raise DatabaseRestoreRefused(
                        "external restore hold did not apply exactly once",
                    )
                await assert_external_lifecycle_consumed(session)
                held_streams.append(str(stream.id))

            unresolved = tuple(
                (
                    await session.execute(
                        select(ScheduleExternalControlOperation)
                        .where(
                            ScheduleExternalControlOperation.status.in_(
                                ("PENDING", "CLAIMED"),
                            ),
                        )
                        .order_by(
                            ScheduleExternalControlOperation.id,
                        )
                        .with_for_update(),
                    )
                ).scalars()
            )
            ambiguous_operations: list[str] = []
            for operation in unresolved:
                await arm_external_control_transition(
                    session,
                    transition="ambiguity",
                    operation_id=operation.id,
                    stream_id=operation.stream_id,
                    epoch_number=operation.epoch_number,
                    reserved_sequence=operation.reserved_sequence,
                    state_nonce=operation.state_nonce,
                    dispatch_lease=operation.dispatch_lease,
                    terminal_id=None,
                )
                result = await session.execute(
                    ScheduleExternalControlOperation.__table__.update()
                    .where(
                        ScheduleExternalControlOperation.id == operation.id,
                        ScheduleExternalControlOperation.status == operation.status,
                    )
                    .values(status="AMBIGUOUS"),
                )
                if (result.rowcount or 0) != 1:
                    raise DatabaseRestoreRefused(
                        "external control operation did not become ambiguous exactly once",
                    )
                await assert_external_control_consumed(session)
                ambiguous_operations.append(str(operation.id))

            revision_rebase = {
                "captured_target_revision": target_revision,
                "restored_revision": restored_revision,
                "barrier_revision": barrier_revision,
                "final_revision": final_revision,
                "schedule_count": len(schedules),
            }
            epoch_rebase = {
                "captured_target_epoch": target_epoch,
                "restored_epoch": restored_epoch,
                "barrier_epoch": epoch_barrier,
            }
            marker = await AuditService(settings).record(
                AuditLogRepository(session),
                action="audit.database_restored",
                target_type="database",
                target_id=str(operation_id),
                result="success",
                outcome="allow",
                metadata={
                    "restore_phase_version": RESTORE_PHASE_VERSION,
                    "operation_id": str(operation_id),
                    "migration_head": RELEASE_MIGRATION_HEAD,
                    "schema_contract_digest": observed_schema,
                    "source_stage_digest": source_digest,
                    "source_manifest_digest": source_snapshot["manifest_digest"],
                    "target_recovery_digest": target_recovery_digest,
                    "target_manifest_digest": target_snapshot["manifest_digest"],
                    "executor_attestation": dict(attestation),
                    "executor_attestation_digest": attestation_digest,
                    "known_head": (dict(known_head) if known_head is not None else None),
                    "known_head_result": known_head_result,
                    "revision_rebase": revision_rebase,
                    "epoch_rebase": epoch_rebase,
                    "schedule_rebase_digest": release_manifest_digest(
                        schedule_digest_rows,
                    ),
                    "deleted_restored_change_log_rows": deleted_logs,
                    "restore_held_streams": held_streams,
                    "ambiguous_control_operations": (ambiguous_operations),
                    **dict(ceremony_metadata or {}),
                },
            )
            await session.commit()

        async with _restore_session(
            database=database,
            connection=connection,
            write=True,
        ) as session:
            post_report = await verify_active_audit_generation(
                session,
                settings,
                page_size=5000,
            )
            if not post_report.clean:
                raise DatabaseRestoreRefused(
                    "finalized candidate audit verification failed: "
                    f"{list(post_report.mismatches)}",
                )
            final_schema = await assert_release_schema_contract(
                session,
            )
            if final_schema != observed_schema:
                raise DatabaseRestoreRefused(
                    "candidate schema changed during finalization",
                )
        return {
            "marker_id": str(marker.id),
            "revision_rebase": revision_rebase,
            "epoch_rebase": epoch_rebase,
            "schema_contract_digest": observed_schema,
            "known_head_result": known_head_result,
        }
    except AuditChainIntegrityError as exc:
        raise DatabaseRestoreRefused(
            f"candidate audit finalization failed: {exc}",
        ) from exc
    finally:
        if database is not None:
            await database.dispose()


def _checkpoint_sqlite(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        row = connection.execute(
            "PRAGMA wal_checkpoint(TRUNCATE)",
        ).fetchone()
        if row is not None and int(row[0]) != 0:
            raise DatabaseRestoreRefused(
                f"SQLite WAL checkpoint remained busy: {row!r}",
            )
        connection.commit()
    finally:
        connection.close()


def _install_candidate(
    *,
    target: Path,
    candidate: Path,
    operation_dir: Path,
    expected_candidate_digest: str,
    phase_path: Path,
    phase: dict[str, Any],
) -> dict[str, Any]:
    """Move the target sidecar set and atomically install the candidate."""

    if phase.get("state") != "INSTALLING":
        phase = {
            **phase,
            "state": "INSTALLING",
            "candidate_digest": expected_candidate_digest,
        }
        _replace_phase(phase_path, phase)
    if target.exists():
        _, live_digest = _file_digest(target)
        if live_digest == expected_candidate_digest:
            return {
                **phase,
                "state": "INSTALLED",
                "displaced": phase.get("displaced", {}),
            }
        if (operation_dir / "displaced-main.db").exists():
            raise DatabaseRestoreRefused(
                "an unexpected target appeared during restore installation",
            )
    displaced: dict[str, str] = {}
    for suffix, name in (
        ("", "displaced-main.db"),
        ("-wal", "displaced-wal"),
        ("-shm", "displaced-shm"),
        ("-journal", "displaced-journal"),
    ):
        live = Path(f"{target}{suffix}")
        destination = operation_dir / name
        if live.exists():
            if destination.exists():
                raise DatabaseRestoreRefused(
                    f"restore displaced artifact already exists: {destination}",
                )
            live.replace(destination)
            displaced[suffix or "main"] = name
    _fsync_directory(target.parent)
    if not candidate.exists():
        if target.exists():
            _, installed_digest = _file_digest(target)
            if installed_digest == expected_candidate_digest:
                return {
                    **phase,
                    "state": "INSTALLED",
                    "displaced": displaced,
                }
        raise DatabaseRestoreRefused(
            "restore candidate disappeared before installation",
        )
    candidate.replace(target)
    target.chmod(0o600)
    _fsync_directory(target.parent)
    _, installed_digest = _file_digest(target)
    if installed_digest != expected_candidate_digest:
        raise DatabaseRestoreRefused(
            "installed SQLite target digest differs from candidate",
        )
    return {
        **phase,
        "state": "INSTALLED",
        "displaced": displaced,
    }


def _same_installed_sqlite_target(
    expected: Mapping[str, Any],
    observed: Mapping[str, Any],
    *,
    include_content: bool,
) -> bool:
    keys = {
        "path",
        "device",
        "inode",
        "parent_identity",
    }
    if include_content:
        keys.update({"size", "digest"})
    return all(expected.get(key) == observed.get(key) for key in keys)


def _sqlite_head(path: Path) -> str | None:
    connection = _immutable_sqlite_connection(path)
    try:
        rows = connection.execute(
            "SELECT version_num FROM alembic_version",
        ).fetchall()
        if len(rows) != 1:
            return None
        return str(rows[0]["version_num"])
    except sqlite3.DatabaseError:
        return None
    finally:
        connection.close()


async def _authenticated_activation_snapshot(
    path: Path,
    settings: Settings,
) -> tuple[dict[str, Any], str]:
    snapshot = await _authenticated_snapshot(path, settings)
    engine = create_async_engine(_async_sqlite_url(path))
    database = DatabaseManager(engine)
    try:
        async with database.session() as session:
            state = await session.get(
                AuditChainState,
                "audit-chain",
            )
            if state is None:
                raise DatabaseRestoreRefused(
                    "activated SQLite restore lacks audit-chain state",
                )
            rows = tuple(
                (
                    await session.execute(
                        select(AuditLog).where(
                            AuditLog.action == "audit.chain_generation_started",
                            AuditLog.chain_generation == state.generation,
                            AuditLog.legacy_frozen.is_(False),
                        ),
                    )
                ).scalars()
            )
            if len(rows) != 1:
                raise DatabaseRestoreRefused(
                    "activated SQLite restore lacks one generation-start row",
                )
            manifest_digest = rows[0].audit_metadata.get(
                "manifest_digest",
            )
            if not isinstance(manifest_digest, str):
                raise DatabaseRestoreRefused(
                    "activated SQLite restore lacks its manifest binding",
                )
            return snapshot, manifest_digest
    finally:
        await database.dispose()


async def _recover_sqlite_committed_finalization(
    path: Path,
    settings: Settings,
    *,
    operation_id: uuid.UUID,
    source_digest: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    snapshot = await _authenticated_snapshot(path, settings)
    engine = create_async_engine(_async_sqlite_url(path))
    database = DatabaseManager(engine)
    try:
        async with database.session() as session:
            markers = tuple(
                (
                    await session.execute(
                        select(AuditLog).where(
                            AuditLog.action == "audit.database_restored",
                            AuditLog.target_id == str(operation_id),
                        ),
                    )
                ).scalars()
            )
            if len(markers) != 1:
                raise DatabaseRestoreRefused(
                    "SQLite restore marker is missing or duplicated",
                )
            marker = markers[0]
            metadata = marker.audit_metadata
            if (
                metadata.get("operation_id") != str(operation_id)
                or metadata.get("source_stage_digest") != source_digest
                or metadata.get("migration_head") != RELEASE_MIGRATION_HEAD
                or metadata.get("schema_contract_digest") != snapshot["schema_contract_digest"]
            ):
                raise DatabaseRestoreRefused(
                    "SQLite restore marker does not bind this operation",
                )
            revision_rebase = metadata.get("revision_rebase")
            epoch_rebase = metadata.get("epoch_rebase")
            known_head_result = metadata.get("known_head_result")
            if not isinstance(revision_rebase, dict) or not isinstance(
                epoch_rebase,
                dict,
            ):
                raise DatabaseRestoreRefused(
                    "SQLite restore marker lacks rebase evidence",
                )
            if not isinstance(known_head_result, str):
                raise DatabaseRestoreRefused(
                    "SQLite restore marker lacks rollback-assessment evidence",
                )
            return (
                {
                    "marker_id": str(marker.id),
                    "revision_rebase": revision_rebase,
                    "epoch_rebase": epoch_rebase,
                    "schema_contract_digest": snapshot["schema_contract_digest"],
                    "known_head_result": known_head_result,
                },
                snapshot,
            )
    finally:
        await database.dispose()


def _sqlite_restore_activation_phase(
    database_url: str,
    operation_id: uuid.UUID,
) -> tuple[Path, Path, dict[str, Any]]:
    if not database_url.startswith(("sqlite", "sqlite+aiosqlite")):
        raise DatabaseRestoreRefused(
            "SQLite restore-bound activation received a non-SQLite URL",
        )
    target = _lexical_absolute(_sqlite_path_from_url(database_url))
    phase_path = _phase_path(target, operation_id)
    phase = _read_phase(phase_path)
    if (
        phase.get("phase_version") != RESTORE_PHASE_VERSION
        or phase.get("operation_id") != str(operation_id)
        or phase.get("target_path") != str(target)
        or phase.get("state")
        not in {
            "AWAITING_AUDIT_ACTIVATION",
            "AUDIT_ACTIVATED",
        }
    ):
        raise DatabaseRestoreRefused(
            "restore-bound audit activation requires its exact SQLite phase",
        )
    return target, phase_path, phase


def build_restore_activation_manifest(
    database_url: str,
    *,
    operation: str,
    settings: Settings,
    legacy_key_window_complete: bool,
    known_head: dict[str, Any] | None,
) -> dict[str, Any]:
    """Finalize the manifest for one exact fenced SQLite legacy restore."""

    from z4j_brain.domain.audit_activation import (
        build_activation_manifest,
    )

    operation_id = uuid.UUID(operation)
    target = _lexical_absolute(_sqlite_path_from_url(database_url))
    with audit_bootstrap_coordinator(target.parent):
        target, _, phase = _sqlite_restore_activation_phase(
            database_url,
            operation_id,
        )
        if phase["state"] != "AWAITING_AUDIT_ACTIVATION":
            raise DatabaseRestoreRefused(
                "restore-bound SQLite audit activation is already committed",
            )
        phase_known_head = phase.get("known_head")
        if known_head is not None and known_head != phase_known_head:
            raise DatabaseRestoreRefused(
                "restore-bound SQLite known-head differs from its durable phase",
            )
        known_head = phase_known_head
        observed_identity = _sqlite_installed_identity(target)
        if not _same_installed_sqlite_target(
            phase["installed_target_identity"],
            observed_identity,
            include_content=True,
        ):
            raise DatabaseRestoreRefused(
                "restore-bound SQLite activation target changed",
            )
        preparation = _sqlite_preparation(target)
        if preparation != phase["audit_preparation"]:
            raise DatabaseRestoreRefused(
                "restore-bound SQLite audit preparation changed",
            )
        engine = create_engine(f"sqlite:///{target}")
        try:
            with engine.connect() as connection:
                connection.exec_driver_sql("BEGIN EXCLUSIVE")
                try:
                    manifest = build_activation_manifest(
                        connection,
                        settings,
                        legacy_key_window_complete=(legacy_key_window_complete),
                        known_head=known_head,
                    )
                finally:
                    connection.rollback()
        finally:
            engine.dispose()
        if (
            manifest["preparation_id"] != preparation["preparation_id"]
            or manifest["preparation_audit_key_id"] != preparation["audit_key_id"]
        ):
            raise DatabaseRestoreRefused(
                "activation manifest does not bind the SQLite restore preparation",
            )
        return manifest


def apply_restore_activation_manifest(
    database_url: str,
    *,
    operation: str,
    settings: Settings,
    manifest: dict[str, Any],
    attestation: str | None,
) -> dict[str, Any]:
    """Apply one exact manifest to its fenced SQLite legacy restore."""

    import asyncio

    operation_id = uuid.UUID(operation)
    target = _lexical_absolute(_sqlite_path_from_url(database_url))
    with audit_bootstrap_coordinator(target.parent):
        target, phase_path, phase = _sqlite_restore_activation_phase(
            database_url,
            operation_id,
        )
        if phase["state"] == "AUDIT_ACTIVATED":
            if phase.get("activation_manifest_digest") != manifest.get(
                "manifest_digest",
            ):
                raise DatabaseRestoreRefused(
                    "committed SQLite restore activation used a different manifest",
                )
            return phase
        preparation = phase["audit_preparation"]
        if manifest.get("known_head") != phase.get("known_head"):
            raise DatabaseRestoreRefused(
                "activation manifest does not bind the SQLite restore known-head",
            )
        if (
            manifest.get("preparation_id") != preparation["preparation_id"]
            or manifest.get("preparation_audit_key_id") != preparation["audit_key_id"]
        ):
            raise DatabaseRestoreRefused(
                "activation manifest does not bind the SQLite restore preparation",
            )
        observed_identity = _sqlite_installed_identity(target)
        if not _same_installed_sqlite_target(
            phase["installed_target_identity"],
            observed_identity,
            include_content=False,
        ):
            raise DatabaseRestoreRefused(
                "restore-bound SQLite activation target identity changed",
            )
        observed_preparation = _sqlite_preparation(target)
        if observed_preparation is not None:
            if observed_preparation != preparation or not _same_installed_sqlite_target(
                phase["installed_target_identity"],
                observed_identity,
                include_content=True,
            ):
                raise DatabaseRestoreRefused(
                    "restore-bound SQLite audit preparation changed",
                )
            _upgrade_sqlite_database(
                target,
                activation_manifest=manifest,
                activation_attestation=attestation,
            )
            _checkpoint_sqlite(target)
        elif _sqlite_head(target) != RELEASE_MIGRATION_HEAD:
            raise DatabaseRestoreRefused(
                "SQLite restore activation target is neither prepared nor fully activated",
            )
        snapshot, committed_manifest_digest = asyncio.run(
            _authenticated_activation_snapshot(target, settings),
        )
        if committed_manifest_digest != manifest.get("manifest_digest"):
            raise DatabaseRestoreRefused(
                "committed SQLite activation does not match the supplied manifest",
            )
        phase = {
            **phase,
            "state": "AUDIT_ACTIVATED",
            "activation_manifest_digest": committed_manifest_digest,
            "activation_attestation": attestation,
            "activated_snapshot_digest": snapshot["manifest_digest"],
            "activated_target_identity": _sqlite_installed_identity(
                target,
            ),
        }
        _replace_phase(phase_path, phase)
        return phase


def restore_sqlite_database(  # noqa: PLR0912, PLR0915
    database_url: str,
    source: Path,
    *,
    operation: str | uuid.UUID | None = None,
    expected_sha256: str | None = None,
    stopped_executor_attestation: str | None = None,
    known_head: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run or resume the authenticated current/legacy SQLite ceremony."""

    if not database_url.startswith(("sqlite", "sqlite+aiosqlite")):
        raise DatabaseRestoreRefused(
            "SQLite restore received a non-SQLite database URL",
        )
    target = _lexical_absolute(_sqlite_path_from_url(database_url))
    supplied_source_path = Path(
        os.path.abspath(  # noqa: PTH100  resume must not reopen staged source
            os.fspath(source.expanduser()),
        ),
    )
    if known_head is not None:
        if not isinstance(known_head, dict):
            raise DatabaseRestoreRefused("--known-head must be a JSON object")
        canonical_json(known_head)
        known_head = dict(known_head)
    if expected_sha256 is not None and (
        len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise DatabaseRestoreRefused(
            "--expected-sha256 must be 64 lowercase hexadecimal characters",
        )
    operation_id = (
        operation
        if isinstance(operation, uuid.UUID)
        else uuid.UUID(str(operation))
        if operation is not None
        else uuid.uuid4()
    )

    ensure_secret_store_directory(target.parent)
    root = _phase_root(target)
    ensure_secret_store_directory(root)
    operation_dir = root / str(operation_id)
    ensure_secret_store_directory(operation_dir)
    phase_path = _phase_path(target, operation_id)

    with audit_bootstrap_coordinator(target.parent):
        settings = Settings()  # type: ignore[call-arg]
        try:
            target_lstat = target.lstat()
        except FileNotFoundError:
            target_present = False
        else:
            if stat.S_ISLNK(target_lstat.st_mode) or not stat.S_ISREG(
                target_lstat.st_mode,
            ):
                raise DatabaseRestoreRefused(
                    "restore target must be a regular file, not a link",
                )
            target_present = True
        if target_present and _sqlite_head(target) == RELEASE_MIGRATION_HEAD:
            import asyncio

            asyncio.run(_authenticated_snapshot(target, settings))
        if phase_path.exists():
            phase = _read_phase(phase_path)
            if (
                phase.get("phase_version") != RESTORE_PHASE_VERSION
                or phase.get("operation_id") != str(operation_id)
                or phase.get("target_path") != str(target)
            ):
                raise DatabaseRestoreRefused(
                    "restore phase identity does not match this operation",
                )
            if phase.get("state") == "COMPLETE":
                _cleanup_completed_operation(operation_dir)
                return dict(phase["result"])
            if phase.get("state") == "ROLLED_BACK":
                raise DatabaseRestoreRefused(
                    "restore operation was rolled back and is terminal",
                )
            source_path = Path(
                str(phase["source_provenance"]["supplied_path"]),
            )
            recorded_expected_digest = phase["source_provenance"].get(
                "expected_sha256",
            )
            if expected_sha256 is not None and expected_sha256 != recorded_expected_digest:
                raise DatabaseRestoreRefused(
                    "SQLite restore resume supplied different provenance",
                )
            recorded_known_head = phase.get("known_head")
            if known_head is not None and known_head != recorded_known_head:
                raise DatabaseRestoreRefused(
                    "SQLite restore resume supplied a different known-head",
                )
            known_head = recorded_known_head
        else:
            if not target.exists():
                raise DatabaseRestoreRefused(
                    "authenticated restore currently requires an existing "
                    "release-head SQLite target",
                )
            source_path = supplied_source_path
            if source_path == target:
                raise DatabaseRestoreRefused(
                    "restore source and target are the same file",
                )
            phase = {
                "phase_version": RESTORE_PHASE_VERSION,
                "operation_id": str(operation_id),
                "target_path": str(target),
                "source_provenance": {
                    "supplied_path": str(source_path),
                    "kind": (
                        "operator_expected_sha256"
                        if expected_sha256 is not None
                        else "local_digest_only"
                    ),
                    "expected_sha256": expected_sha256,
                },
                "known_head": known_head,
                "state": "CREATED",
            }
            _replace_phase(phase_path, phase)

        staged_source = operation_dir / "source-staged.db"
        if phase["state"] == "CREATED":
            _discard_working_database(staged_source)
            source_size, source_digest = _stage_source(
                source_path,
                staged_source,
                expected_sha256=expected_sha256,
            )
            phase = {
                **phase,
                "state": "SOURCE_STAGED",
                "source_size": source_size,
                "source_digest": source_digest,
            }
            _replace_phase(phase_path, phase)
        else:
            source_size, source_digest = _file_digest(staged_source)
            if source_size != phase.get("source_size") or source_digest != phase.get(
                "source_digest"
            ):
                raise DatabaseRestoreRefused(
                    "staged restore source no longer matches its phase",
                )
            if expected_sha256 is not None and source_digest != expected_sha256:
                raise DatabaseRestoreRefused(
                    "staged source differs from --expected-sha256",
                )

        recovery = operation_dir / "target-recovery.db"
        if phase["state"] == "SOURCE_STAGED":
            source_authority = _sqlite_source_authority(
                staged_source,
                source_digest=source_digest,
            )
            if source_authority["source_head"] == RELEASE_MIGRATION_HEAD:
                import asyncio

                verification_copy = operation_dir / "source-authentication.db"
                _discard_working_database(verification_copy)
                _stage_source(
                    staged_source,
                    verification_copy,
                    expected_sha256=source_digest,
                )
                try:
                    source_snapshot: dict[str, Any] | None = asyncio.run(
                        _authenticated_snapshot(
                            verification_copy,
                            settings,
                        ),
                    )
                finally:
                    _discard_working_database(verification_copy)
                if (
                    source_snapshot["schema_contract_digest"]
                    != source_authority["schema_contract_digest"]
                ):
                    raise DatabaseRestoreRefused(
                        "SQLite source authority changed after immutable preflight",
                    )
            else:
                source_snapshot = None
            _discard_working_database(recovery)
            _sqlite_backup(target, recovery)
            recovery_size, recovery_digest = _file_digest(recovery)
            import asyncio

            target_snapshot = asyncio.run(
                _authenticated_snapshot(recovery, settings),
            )
            attestation_source = (
                source_snapshot if source_snapshot is not None else source_authority
            )
            envelope, challenge, attestation_required = _attestation_envelope(
                source_snapshot=attestation_source,
                target_snapshot=target_snapshot,
            )
            phase = {
                **phase,
                "state": "PREFLIGHT_COMPLETE",
                "source_authority": source_authority,
                "source_snapshot": source_snapshot,
                "target_recovery_size": recovery_size,
                "target_recovery_digest": recovery_digest,
                "target_snapshot": target_snapshot,
                "stopped_executor_attestation_challenge": challenge,
                "requires_stopped_executor_attestation": (attestation_required),
                "attestation_envelope": envelope,
            }
            _replace_phase(phase_path, phase)

        challenge = str(
            phase["stopped_executor_attestation_challenge"],
        )
        if phase["requires_stopped_executor_attestation"]:
            accepted_challenge = phase.get(
                "accepted_stopped_executor_attestation",
            )
            if accepted_challenge is None:
                if stopped_executor_attestation != challenge:
                    raise DatabaseRestoreRefused(
                        "restore is staged and requires the exact "
                        "stopped-executor attestation challenge "
                        f"{challenge}; resume with --operation {operation_id} "
                        f"--attest-stopped-executors {challenge}",
                    )
                phase = {
                    **phase,
                    "accepted_stopped_executor_attestation": challenge,
                }
                _replace_phase(phase_path, phase)
            elif accepted_challenge != challenge or stopped_executor_attestation not in {
                None,
                challenge,
            }:
                raise DatabaseRestoreRefused(
                    "SQLite restore stopped-executor attestation binding changed during resume",
                )
            attestation = {
                **phase["attestation_envelope"],
                "challenge": challenge,
            }
        else:
            if stopped_executor_attestation is not None:
                raise DatabaseRestoreRefused(
                    "a stopped-executor attestation was supplied but "
                    "neither source nor target contains executor authority",
                )
            attestation = {
                "version": 1,
                "kind": "no_restore_external_executor_authority",
                "source_manifest_digest": (phase["source_snapshot"] or phase["source_authority"])[
                    "manifest_digest"
                ],
                "target_manifest_digest": phase["target_snapshot"]["manifest_digest"],
            }
        attestation_digest = release_manifest_digest(attestation)

        candidate = operation_dir / "candidate.db"
        if phase["state"] == "PREFLIGHT_COMPLETE":
            _discard_working_database(candidate)
            _sqlite_backup(staged_source, candidate)
            if phase["source_authority"]["source_head"] == _LEGACY_SOURCE_HEAD:
                from alembic.util import CommandError

                try:
                    _upgrade_sqlite_database(candidate)
                except CommandError as exc:
                    _checkpoint_sqlite(candidate)
                    preparation = _sqlite_preparation(candidate)
                    if preparation is None:
                        raise DatabaseRestoreRefused(
                            "legacy SQLite restore migration failed outside "
                            "the authenticated audit preparation boundary",
                        ) from exc
                else:
                    raise DatabaseRestoreRefused(
                        "legacy SQLite restore bypassed manifest-bound audit activation",
                    )
                candidate_size, candidate_digest = _file_digest(
                    candidate,
                )
                phase = {
                    **phase,
                    "state": "CANDIDATE_AUDIT_PREPARED",
                    "candidate_mode": "legacy_awaiting_activation",
                    "candidate_size": candidate_size,
                    "candidate_digest": candidate_digest,
                    "audit_preparation": preparation,
                    "attestation_digest": attestation_digest,
                }
            else:
                import asyncio

                finalization = asyncio.run(
                    finalize_restored_database(
                        _async_sqlite_url(candidate),
                        settings,
                        operation_id=operation_id,
                        source_digest=source_digest,
                        source_snapshot=phase["source_snapshot"],
                        target_recovery_digest=phase["target_recovery_digest"],
                        target_snapshot=phase["target_snapshot"],
                        attestation=attestation,
                        attestation_digest=attestation_digest,
                        known_head=known_head,
                        ceremony_metadata={
                            "source_provenance": {
                                "kind": phase["source_provenance"]["kind"],
                                "expected_sha256": phase["source_provenance"].get(
                                    "expected_sha256"
                                ),
                                "verified_digest": source_digest,
                            },
                            "source_migration_head": phase["source_snapshot"]["migration_head"],
                            "source_schema_contract_digest": phase["source_snapshot"][
                                "schema_contract_digest"
                            ],
                            "target_recovery_migration_head": phase["target_snapshot"][
                                "migration_head"
                            ],
                            "target_recovery_schema_contract_digest": phase["target_snapshot"][
                                "schema_contract_digest"
                            ],
                        },
                    ),
                )
                _checkpoint_sqlite(candidate)
                candidate_size, candidate_digest = _file_digest(
                    candidate,
                )
                phase = {
                    **phase,
                    "state": "CANDIDATE_FINALIZED",
                    "candidate_mode": "current_finalized",
                    "candidate_size": candidate_size,
                    "candidate_digest": candidate_digest,
                    "finalization": finalization,
                    "attestation_digest": attestation_digest,
                }
            _replace_phase(phase_path, phase)

        if phase["state"] in {
            "CANDIDATE_FINALIZED",
            "CANDIDATE_AUDIT_PREPARED",
            "INSTALLING",
        }:
            import asyncio

            if phase["state"] in {
                "CANDIDATE_FINALIZED",
                "CANDIDATE_AUDIT_PREPARED",
            }:
                live_snapshot = asyncio.run(
                    _authenticated_snapshot(target, settings),
                )
                if live_snapshot["manifest_digest"] != phase["target_snapshot"]["manifest_digest"]:
                    raise DatabaseRestoreRefused(
                        "live target changed after its recovery snapshot; "
                        "restore remains pending before installation",
                    )
                _checkpoint_sqlite(target)
            phase = _install_candidate(
                target=target,
                candidate=candidate,
                operation_dir=operation_dir,
                expected_candidate_digest=phase["candidate_digest"],
                phase_path=phase_path,
                phase=phase,
            )
            _replace_phase(phase_path, phase)

        if phase["state"] in {"INSTALLING", "INSTALLED"}:
            _, installed_digest = _file_digest(target)
            if installed_digest != phase["candidate_digest"]:
                raise DatabaseRestoreRefused(
                    "installed target does not match finalized candidate",
                )
            if phase.get("candidate_mode") == "legacy_awaiting_activation":
                preparation = _sqlite_preparation(target)
                if preparation != phase["audit_preparation"]:
                    raise DatabaseRestoreRefused(
                        "installed SQLite audit preparation differs from "
                        "the restore-bound candidate",
                    )
                phase = {
                    **phase,
                    "state": "AWAITING_AUDIT_ACTIVATION",
                    "installed_target_identity": (_sqlite_installed_identity(target)),
                }
                _replace_phase(phase_path, phase)
                raise DatabaseRestoreRefused(
                    "legacy SQLite restore is awaiting manifest-bound audit "
                    "activation; run `z4j audit activate-chain-state "
                    f"--restore-operation {operation_id} ...`",
                )
            import asyncio

            installed_snapshot = asyncio.run(
                _authenticated_snapshot(target, settings),
            )
            marker_engine = sqlite3.connect(
                f"{_lexical_absolute(target).as_uri()}?mode=ro",
                uri=True,
            )
            try:
                marker_count = int(
                    marker_engine.execute(
                        "SELECT COUNT(*) FROM audit_log "
                        "WHERE action = 'audit.database_restored' "
                        "AND target_id = ?",
                        (str(operation_id),),
                    ).fetchone()[0],
                )
            finally:
                marker_engine.close()
            if marker_count != 1:
                raise DatabaseRestoreRefused(
                    "installed restore marker is missing or duplicated",
                )
            result = {
                "backend": "sqlite",
                "operation_id": str(operation_id),
                "source": str(source_path),
                "source_digest": source_digest,
                "installed_manifest_digest": installed_snapshot["manifest_digest"],
                **phase["finalization"],
            }
            phase = {
                **phase,
                "state": "COMPLETE",
                "result": result,
            }
            _replace_phase(phase_path, phase)
            _cleanup_completed_operation(operation_dir)
            return result

        if phase["state"] == "AWAITING_AUDIT_ACTIVATION":
            raise DatabaseRestoreRefused(
                "legacy SQLite restore is awaiting manifest-bound audit "
                "activation; run `z4j audit activate-chain-state "
                f"--restore-operation {operation_id} ...`",
            )

        if phase["state"] in {
            "AUDIT_ACTIVATED",
            "MARKER_COMMITTED",
        }:
            import asyncio

            marker_connection = _immutable_sqlite_connection(target)
            try:
                marker_count = int(
                    marker_connection.execute(
                        "SELECT COUNT(*) FROM audit_log "
                        "WHERE action = 'audit.database_restored' "
                        "AND target_id = ?",
                        (str(operation_id),),
                    ).fetchone()[0],
                )
            finally:
                marker_connection.close()
            if marker_count > 1:
                raise DatabaseRestoreRefused(
                    "SQLite restore marker is duplicated",
                )
            if marker_count == 0:
                if phase["state"] != "AUDIT_ACTIVATED":
                    raise DatabaseRestoreRefused(
                        "SQLite restore phase claims a missing committed marker",
                    )
                observed_identity = _sqlite_installed_identity(target)
                if not _same_installed_sqlite_target(
                    phase["activated_target_identity"],
                    observed_identity,
                    include_content=True,
                ):
                    raise DatabaseRestoreRefused(
                        "activated SQLite restore target changed before finalization",
                    )
                source_snapshot, activation_digest = asyncio.run(
                    _authenticated_activation_snapshot(
                        target,
                        settings,
                    ),
                )
                if (
                    source_snapshot["manifest_digest"] != phase["activated_snapshot_digest"]
                    or activation_digest != phase["activation_manifest_digest"]
                ):
                    raise DatabaseRestoreRefused(
                        "activated SQLite restore authority changed before finalization",
                    )
                finalization = asyncio.run(
                    finalize_restored_database(
                        _async_sqlite_url(target),
                        settings,
                        operation_id=operation_id,
                        source_digest=source_digest,
                        source_snapshot=source_snapshot,
                        target_recovery_digest=phase["target_recovery_digest"],
                        target_snapshot=phase["target_snapshot"],
                        attestation=attestation,
                        attestation_digest=attestation_digest,
                        known_head=known_head,
                        ceremony_metadata={
                            "source_provenance": {
                                "kind": phase["source_provenance"]["kind"],
                                "expected_sha256": phase["source_provenance"].get(
                                    "expected_sha256"
                                ),
                                "verified_digest": source_digest,
                            },
                            "source_migration_head": phase["source_authority"]["source_head"],
                            "source_schema_contract_digest": phase["source_authority"][
                                "schema_contract_digest"
                            ],
                            "activated_migration_head": (source_snapshot["migration_head"]),
                            "activated_schema_contract_digest": (
                                source_snapshot["schema_contract_digest"]
                            ),
                            "target_recovery_migration_head": phase["target_snapshot"][
                                "migration_head"
                            ],
                            "target_recovery_schema_contract_digest": phase["target_snapshot"][
                                "schema_contract_digest"
                            ],
                            "activation_manifest_digest": phase["activation_manifest_digest"],
                        },
                    ),
                )
                phase = {
                    **phase,
                    "state": "MARKER_COMMITTED",
                    "finalization": finalization,
                }
                _replace_phase(phase_path, phase)
            finalization, installed_snapshot = asyncio.run(
                _recover_sqlite_committed_finalization(
                    target,
                    settings,
                    operation_id=operation_id,
                    source_digest=source_digest,
                ),
            )
            _checkpoint_sqlite(target)
            result = {
                "backend": "sqlite",
                "operation_id": str(operation_id),
                "source": str(source_path),
                "source_digest": source_digest,
                "installed_manifest_digest": installed_snapshot["manifest_digest"],
                **finalization,
            }
            phase = {
                **phase,
                "state": "COMPLETE",
                "finalization": finalization,
                "result": result,
            }
            _replace_phase(phase_path, phase)
            _cleanup_completed_operation(operation_dir)
            return result

        raise DatabaseRestoreRefused(
            f"restore phase cannot resume from state {phase['state']!r}",
        )


async def _record_database_rollback_marker(
    database_url: str,
    settings: Settings,
    *,
    operation_id: uuid.UUID,
    source_digest: str,
    recovery_digest: str,
    target_snapshot: Mapping[str, Any],
) -> str:
    engine = create_async_engine(database_url)
    database = DatabaseManager(engine)
    try:
        async with database.session(write=True) as session:
            schema_digest = await assert_release_schema_contract(
                session,
            )
            marker = await AuditService(settings).record(
                AuditLogRepository(session),
                action="audit.database_restore_rolled_back",
                target_type="database",
                target_id=str(operation_id),
                result="success",
                outcome="allow",
                metadata={
                    "restore_phase_version": RESTORE_PHASE_VERSION,
                    "operation_id": str(operation_id),
                    "rejected_source_stage_digest": source_digest,
                    "target_recovery_digest": recovery_digest,
                    "target_manifest_digest": target_snapshot["manifest_digest"],
                    "schema_contract_digest": schema_digest,
                },
            )
            await session.commit()
        async with database.session() as session:
            report = await verify_active_audit_generation(
                session,
                settings,
                page_size=5000,
            )
            if not report.clean:
                raise DatabaseRestoreRefused(
                    f"SQLite rollback marker verification failed: {list(report.mismatches)}",
                )
        return str(marker.id)
    finally:
        await database.dispose()


async def _recover_sqlite_committed_rollback_marker(
    target: Path,
    settings: Settings,
    *,
    operation_id: uuid.UUID,
    source_digest: str,
    recovery_digest: str,
    target_snapshot: Mapping[str, Any],
) -> str | None:
    """Return one already-committed rollback marker bound to this phase."""

    engine = create_async_engine(_async_sqlite_url(target))
    database = DatabaseManager(engine)
    try:
        async with database.session(write=True) as session:
            snapshot = await authenticated_database_snapshot(
                _async_sqlite_url(target),
                settings,
                session=session,
            )
            markers = tuple(
                (
                    await session.execute(
                        select(AuditLog).where(
                            AuditLog.action == "audit.database_restore_rolled_back",
                            AuditLog.target_id == str(operation_id),
                        ),
                    )
                ).scalars()
            )
            if not markers:
                return None
            if len(markers) != 1:
                raise DatabaseRestoreRefused(
                    "SQLite rollback marker is duplicated",
                )
            marker = markers[0]
            metadata = marker.audit_metadata
            if (
                marker.target_type != "database"
                or marker.result != "success"
                or marker.outcome != "allow"
                or metadata.get("restore_phase_version") != RESTORE_PHASE_VERSION
                or metadata.get("operation_id") != str(operation_id)
                or metadata.get("rejected_source_stage_digest") != source_digest
                or metadata.get("target_recovery_digest") != recovery_digest
                or metadata.get("target_manifest_digest") != target_snapshot["manifest_digest"]
                or metadata.get("schema_contract_digest")
                != target_snapshot["schema_contract_digest"]
            ):
                raise DatabaseRestoreRefused(
                    "SQLite rollback marker does not bind this phase",
                )
            expected_tables = target_snapshot["manifest"]["tables"]
            observed_tables = snapshot["manifest"]["tables"]
            marker_changed_tables = {
                "audit_chain_state",
                "audit_log",
            }
            if (
                snapshot["migration_head"] != target_snapshot["migration_head"]
                or snapshot["schema_contract_digest"] != target_snapshot["schema_contract_digest"]
                or snapshot["revision"] != target_snapshot["revision"]
                or snapshot["pruned_through"] != target_snapshot["pruned_through"]
                or snapshot["epoch"] != target_snapshot["epoch"]
                or snapshot["external_authority_manifest"]
                != target_snapshot["external_authority_manifest"]
                or any(
                    observed_tables[table_name] != expected_manifest
                    for table_name, expected_manifest in expected_tables.items()
                    if table_name not in marker_changed_tables
                )
                or observed_tables["audit_log"]["row_count"]
                != expected_tables["audit_log"]["row_count"] + 1
                or observed_tables["audit_chain_state"]["row_count"]
                != expected_tables["audit_chain_state"]["row_count"]
            ):
                raise DatabaseRestoreRefused(
                    "SQLite rollback marker names a changed target",
                )
            return str(marker.id)
    finally:
        await database.dispose()


def _install_sqlite_recovery(  # noqa: PLR0912
    *,
    target: Path,
    recovery: Path,
    operation_dir: Path,
    phase_path: Path,
    phase: dict[str, Any],
) -> dict[str, Any]:
    candidate = operation_dir / "rollback-candidate.db"
    if phase.get("state") not in {
        "ROLLBACK_INSTALLING",
        "ROLLBACK_INSTALLED",
    }:
        _discard_working_database(candidate)
        _sqlite_backup(recovery, candidate)
        _checkpoint_sqlite(candidate)
        candidate_size, candidate_digest = _file_digest(candidate)
        phase = {
            **phase,
            "state": "ROLLBACK_INSTALLING",
            "rollback_candidate_size": candidate_size,
            "rollback_candidate_digest": candidate_digest,
        }
        _replace_phase(phase_path, phase)
    else:
        expected_size = int(phase["rollback_candidate_size"])
        expected_digest = str(phase["rollback_candidate_digest"])
        if phase["state"] == "ROLLBACK_INSTALLED":
            if candidate.exists():
                raise DatabaseRestoreRefused(
                    "SQLite rollback has both an installed target and a candidate",
                )
            if not target.exists():
                raise DatabaseRestoreRefused(
                    "SQLite rollback installed target disappeared during resume",
                )
            installed_size, installed_digest = _file_digest(target)
            if installed_size != expected_size or installed_digest != expected_digest:
                raise DatabaseRestoreRefused(
                    "SQLite rollback installed target changed during resume",
                )
            return dict(phase)
        if candidate.exists():
            candidate_size, candidate_digest = _file_digest(candidate)
            if candidate_size != expected_size or candidate_digest != expected_digest:
                raise DatabaseRestoreRefused(
                    "SQLite rollback candidate changed during resume",
                )
        else:
            if target.exists():
                installed_size, installed_digest = _file_digest(target)
                if installed_size == expected_size and installed_digest == expected_digest:
                    return {
                        **phase,
                        "state": "ROLLBACK_INSTALLED",
                    }
            raise DatabaseRestoreRefused(
                "SQLite rollback candidate disappeared before install completed",
            )

    if target.exists():
        live_size, live_digest = _file_digest(target)
        if (
            live_size == phase["rollback_candidate_size"]
            and live_digest == phase["rollback_candidate_digest"]
        ):
            return {**phase, "state": "ROLLBACK_INSTALLED"}
    for suffix, name in (
        ("", "rollback-rejected-main.db"),
        ("-wal", "rollback-rejected-wal"),
        ("-shm", "rollback-rejected-shm"),
        ("-journal", "rollback-rejected-journal"),
    ):
        live = Path(f"{target}{suffix}")
        destination = operation_dir / name
        if live.exists():
            if destination.exists():
                raise DatabaseRestoreRefused(
                    "SQLite rollback found both live and displaced "
                    f"components for {suffix or 'main'}",
                )
            live.replace(destination)
            _fsync_directory(target.parent)
    if candidate.exists():
        candidate.replace(target)
        target.chmod(0o600)
        _fsync_directory(target.parent)
    elif not target.exists():
        raise DatabaseRestoreRefused(
            "SQLite rollback candidate disappeared before install",
        )
    installed_size, installed_digest = _file_digest(target)
    if (
        installed_size != phase["rollback_candidate_size"]
        or installed_digest != phase["rollback_candidate_digest"]
    ):
        raise DatabaseRestoreRefused(
            "SQLite rollback installed an unexpected target",
        )
    return {**phase, "state": "ROLLBACK_INSTALLED"}


def _complete_sqlite_rollback_phase(
    *,
    operation_id: uuid.UUID,
    source_digest: str,
    recovery_digest: str,
    marker_id: str,
    phase: Mapping[str, Any],
    phase_path: Path,
    operation_dir: Path,
) -> dict[str, Any]:
    result = {
        "backend": "sqlite",
        "operation_id": str(operation_id),
        "rolled_back": True,
        "marker_id": marker_id,
        "source_digest": source_digest,
        "target_recovery_digest": recovery_digest,
    }
    completed_phase = {
        **phase,
        "state": "ROLLED_BACK",
        "rollback_marker_id": marker_id,
        "result": result,
    }
    _replace_phase(phase_path, completed_phase)
    _cleanup_completed_operation(operation_dir)
    return result


def rollback_sqlite_database(
    database_url: str,
    *,
    operation: str | uuid.UUID,
) -> dict[str, Any]:
    """Restore the captured pre-operation SQLite database."""

    if not database_url.startswith(("sqlite", "sqlite+aiosqlite")):
        raise DatabaseRestoreRefused(
            "SQLite rollback received a non-SQLite database URL",
        )
    operation_id = operation if isinstance(operation, uuid.UUID) else uuid.UUID(str(operation))
    target = _lexical_absolute(_sqlite_path_from_url(database_url))
    operation_dir = _phase_root(target) / str(operation_id)
    ensure_secret_store_directory(_phase_root(target))
    ensure_secret_store_directory(operation_dir)
    phase_path = operation_dir / _PHASE_FILE_NAME
    with audit_bootstrap_coordinator(target.parent):
        phase = _read_phase(phase_path)
        if (
            phase.get("phase_version") != RESTORE_PHASE_VERSION
            or phase.get("operation_id") != str(operation_id)
            or phase.get("target_path") != str(target)
        ):
            raise DatabaseRestoreRefused(
                "SQLite rollback phase identity mismatch",
            )
        if phase.get("state") == "ROLLED_BACK":
            _cleanup_completed_operation(operation_dir)
            return dict(phase["result"])
        if phase.get("state") == "COMPLETE":
            raise DatabaseRestoreRefused(
                "SQLite restore is complete; its rollback authority has been retired",
            )
        if phase.get("state") in {"CREATED", "SOURCE_STAGED"}:
            result = {
                "backend": "sqlite",
                "operation_id": str(operation_id),
                "rolled_back": True,
                "marker_id": None,
            }
            phase = {
                **phase,
                "state": "ROLLED_BACK",
                "result": result,
            }
            _replace_phase(phase_path, phase)
            _cleanup_completed_operation(operation_dir)
            return result

        recovery = operation_dir / "target-recovery.db"
        recovery_size, recovery_digest = _file_digest(recovery)
        if recovery_size != phase.get("target_recovery_size") or recovery_digest != phase.get(
            "target_recovery_digest"
        ):
            raise DatabaseRestoreRefused(
                "SQLite rollback recovery identity changed",
            )
        source_digest = str(phase["source_digest"])
        settings = Settings()  # type: ignore[call-arg]
        import asyncio

        if phase.get("state") == "ROLLBACK_INSTALLED":
            committed_marker_id = asyncio.run(
                _recover_sqlite_committed_rollback_marker(
                    target,
                    settings,
                    operation_id=operation_id,
                    source_digest=source_digest,
                    recovery_digest=recovery_digest,
                    target_snapshot=phase["target_snapshot"],
                ),
            )
            if committed_marker_id is not None:
                return _complete_sqlite_rollback_phase(
                    operation_id=operation_id,
                    source_digest=source_digest,
                    recovery_digest=recovery_digest,
                    marker_id=committed_marker_id,
                    phase=phase,
                    phase_path=phase_path,
                    operation_dir=operation_dir,
                )

        if phase.get("state") in {
            "PREFLIGHT_COMPLETE",
            "CANDIDATE_FINALIZED",
            "CANDIDATE_AUDIT_PREPARED",
        }:
            live_snapshot = asyncio.run(
                _authenticated_snapshot(target, settings),
            )
            if live_snapshot["manifest_digest"] != phase["target_snapshot"]["manifest_digest"]:
                raise DatabaseRestoreRefused(
                    "SQLite target changed before rollback cancellation",
                )
        else:
            phase = _install_sqlite_recovery(
                target=target,
                recovery=recovery,
                operation_dir=operation_dir,
                phase_path=phase_path,
                phase=phase,
            )
            _replace_phase(phase_path, phase)

        restored_snapshot = asyncio.run(
            _authenticated_snapshot(target, settings),
        )
        if (
            restored_snapshot["manifest_digest"] != phase["target_snapshot"]["manifest_digest"]
            or restored_snapshot["revision"] != phase["target_snapshot"]["revision"]
            or restored_snapshot["epoch"] != phase["target_snapshot"]["epoch"]
        ):
            raise DatabaseRestoreRefused(
                "SQLite rollback did not reproduce the captured target",
            )
        marker_id = asyncio.run(
            _record_database_rollback_marker(
                _async_sqlite_url(target),
                settings,
                operation_id=operation_id,
                source_digest=source_digest,
                recovery_digest=recovery_digest,
                target_snapshot=phase["target_snapshot"],
            ),
        )
        return _complete_sqlite_rollback_phase(
            operation_id=operation_id,
            source_digest=source_digest,
            recovery_digest=recovery_digest,
            marker_id=marker_id,
            phase=phase,
            phase_path=phase_path,
            operation_dir=operation_dir,
        )


__all__ = [
    "DatabaseRestorePending",
    "DatabaseRestoreRefused",
    "allow_database_restore",
    "apply_restore_activation_manifest",
    "assert_database_restore_not_pending",
    "authenticated_database_snapshot",
    "build_restore_activation_manifest",
    "finalize_restored_database",
    "install_database_restore_fence_engine_hook",
    "restore_sqlite_database",
    "rollback_sqlite_database",
]
