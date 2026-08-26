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
from collections.abc import AsyncIterator, Callable, Iterable, Iterator, Mapping
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
    SQLITE_RELEASE_SCHEMA_CONTRACT_DIGEST,
    _normalize_sqlite_schema_definition,
    assert_release_schema_contract,
    external_authority_manifest,
    freeze_release_manifest,
    release_manifest_digest,
    release_schema_contract_manifest,
)
from z4j_brain.persistence.database import (
    DatabaseManager,
    create_async_engine_from_url,
)
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
#: The head shipped by the previous release. Kept restorable so a backup
#: taken before this upgrade can still be restored after it.
_PREVIOUS_RELEASE_HEAD = "v1_8_schedule_cursor_repair"
_AUDIT_PREPARATION_HEAD = "v1_8_audit_chain_prepare"
# The legacy value is an external oracle captured from the immutable 6b12719c
# release baseline.  It must never be derived by running current migrations.
#: Exact SQLite schema signature accepted per restorable head.
#:
#: A restore is refused unless the staged database matches one of these
#: byte-for-byte, which is what stops a subtly different schema being
#: restored into a brain that assumes otherwise. Adding a migration
#: therefore means adding its head here with a freshly computed digest,
#: and keeping the PREVIOUS release head so a backup taken before the
#: upgrade is still restorable afterwards. Dropping the old entry would
#: silently invalidate every existing backup.
_SQLITE_SOURCE_SCHEMA_DIGESTS = {
    RELEASE_MIGRATION_HEAD: SQLITE_RELEASE_SCHEMA_CONTRACT_DIGEST,
    _PREVIOUS_RELEASE_HEAD: ("0778f20252e9b32f7a859d85e2de29c446409e40b602fa63cd2ec143ac537640"),
    _LEGACY_SOURCE_HEAD: ("f41f542e03cf81562c1eb3167041549fff0623eca9de919c1d0ffd91619933c8"),
}
_PHASE_ROOT_NAME = ".z4j-restore"
_PHASE_FILE_NAME = "phase.json"

#: Phase states that provably precede ``_install_candidate``, which is the
#: first step that moves the live database aside. Everything else, including
#: the marker commit and the audit activation (both of which run against the
#: already-installed candidate), gets the cautious message instead. Kept as an
#: allowlist so a state added later defaults to caution rather than to a
#: reassurance that would be false.
#:
#: These justify "not displaced or replaced by installation". They do NOT
#: justify "untouched", and an earlier version of this comment said they did.
#: An abandoned rollback commits its marker row into the LIVE database before
#: the phase recording it reaches disk, so a crash in that window leaves a
#: pre-install phase beside a database that is one audit row different from
#: the one the operator started with. The file is intact and startable; it is
#: not byte-identical. Promising more than that is how a true statement turns
#: into a false one.
_PRE_INSTALL_PHASE_STATES = frozenset(
    {
        "CREATED",
        "SOURCE_STAGED",
        "PREFLIGHT_COMPLETE",
        "CANDIDATE_AUDIT_PREPARED",
        "CANDIDATE_FINALIZED",
    },
)
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


def _restore_migration_config() -> Any:
    """Load only the migration assets bundled beside this installed module.

    Restore is allowed to replace the live database, so it must not inherit an
    operator's working directory or a source-checkout layout when selecting
    the code that upgrades the candidate.  Wheels install ``alembic.ini`` and
    ``migrations`` directly inside ``z4j_brain``; source and editable installs
    expose that same package layout.  Refuse before opening the candidate when
    any member of that bundle is absent, substituted by a symlink, or has the
    wrong filesystem type.
    """

    from alembic.config import Config

    try:
        package_directory = Path(__file__).resolve(strict=True).parent
    except (OSError, RuntimeError) as exc:
        raise DatabaseRestoreRefused(
            "bundled restore migration module cannot be resolved",
        ) from exc

    config_path = package_directory / "alembic.ini"
    migrations_path = package_directory / "migrations"
    required_assets = (
        (config_path, "regular file", stat.S_ISREG),
        (migrations_path, "directory", stat.S_ISDIR),
        (migrations_path / "env.py", "regular file", stat.S_ISREG),
        (migrations_path / "versions", "directory", stat.S_ISDIR),
    )
    for asset, expected_type, predicate in required_assets:
        try:
            observed = asset.lstat()
        except OSError as exc:
            raise DatabaseRestoreRefused(
                f"bundled restore migration asset is missing: {asset}",
            ) from exc
        if stat.S_ISLNK(observed.st_mode) or not predicate(observed.st_mode):
            raise DatabaseRestoreRefused(
                f"bundled restore migration asset must be a real {expected_type}: {asset}",
            )

    config = Config(str(config_path))
    config.set_main_option("script_location", str(migrations_path))
    return config


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


def _absent_directories(path: Path) -> list[Path]:
    """The directories on the way to ``path`` that do not exist yet.

    Deepest first. Ask BEFORE creating anything: afterwards there is no way
    to tell which names the process is responsible for persisting.
    """

    absent: list[Path] = []
    probe = path
    while not probe.exists():
        absent.append(probe)
        if probe.parent == probe:
            break
        probe = probe.parent
    return absent


def _fsync_new_directory_names(absent: Iterable[Path]) -> None:
    """Persist the entry for each directory that was just created.

    Fsyncing a new directory persists what gets written inside it and nothing
    about the entry in the parent that reaches it, so a crash can return a
    parent with no such child. Shallowest first, because each fsync persists
    the entry that the next directory in the chain lives in.
    """

    for created in reversed(list(absent)):
        _fsync_directory(created.parent)


def _ensure_durable_directory(path: Path) -> Path:
    """Create ``path`` so its own name survives a crash, not just its contents.

    That distinction decides whether a restore is survivable: the live
    database is moved INTO the operation directory before the replacement is
    installed, so a parent that comes back without that entry has taken the
    live database and its only recovery copy with it.
    """

    absent = _absent_directories(path)
    ensure_secret_store_directory(path)
    _fsync_new_directory_names(absent)
    return path


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


def _phase_file_present(phase_path: Path) -> bool:
    """True when a phase file exists at ``phase_path``.

    Asked separately from reading it because the readers do not agree on how
    absence arrives: the POSIX reader raises ``FileNotFoundError`` and the
    Windows one turns every OS error into a refusal, so a caller that
    branches on the exception type gets a different answer per platform for
    the same missing file. ``_read_phase`` remains the authority on whether
    a file that IS there is acceptable.
    """
    try:
        phase_path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        # Unreadable is not absent; let the reader refuse with its own words.
        return True
    return True


def _operation_directory_is_empty(operation_dir: Path) -> bool:
    """True when a restore operation directory holds nothing at all."""

    try:
        return not any(operation_dir.iterdir())
    except OSError:
        # A directory that cannot be listed is not one we may call harmless.
        return False


def _require_rollbackable_operation(
    phase_path: Path,
    operation_id: uuid.UUID,
) -> None:
    """Refuse a rollback of an operation that was never written down.

    Rollback reads a phase somebody else wrote, so it creates nothing.
    Creating the operation directory first meant a mistyped id left an
    operation behind with no phase in it, and startup refuses to boot past
    one of those: the command an operator runs to clear a fence could raise
    one instead. Refusing in these words also beats the bare
    ``FileNotFoundError`` the reader would otherwise surface.
    """
    if not _phase_file_present(phase_path):
        raise DatabaseRestoreRefused(
            f"no restore operation {operation_id} to roll back",
        )


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
        if not _phase_file_present(phase_path):
            # No phase means no ceremony: the phase is written before the
            # first artifact and before the target is touched, so a
            # directory without one describes nothing that happened. An
            # empty one is the crash window between creating the directory
            # and writing the phase, and refusing to start on it was a stop
            # with no exit -- rollback reads the same phase file that is
            # missing, so neither of the two remedies the operator is
            # offered can clear it.
            if _operation_directory_is_empty(operation_dir):
                continue
            # Artifacts without a phase are a different animal: the phase
            # was written and then lost, so what is in there, and what was
            # done to the target, is exactly what cannot be established.
            raise DatabaseRestorePending(
                f"restore operation kept its artifacts without its durable "
                f"phase: {operation_dir}. Move that directory somewhere safe "
                f"(it may hold the only copy of the pre-restore database) to "
                f"return the brain to service.",
            )
        phase = _read_phase(phase_path)
        if phase.get("target_path") == str(target) and phase.get("state") not in {
            "COMPLETE",
            "ROLLED_BACK",
        }:
            operation_id = phase.get("operation_id")
            # Name BOTH exits. A restore that refused mid-flight leaves this
            # fence up, and resuming re-enters the same refusal, so an operator
            # told only to resume has been handed a loop: the brain will not
            # start and the one command that clears it is not mentioned
            # anywhere in the message they are reading.
            # The reassurance below is only true BEFORE installation begins.
            # It used to be appended unconditionally, which meant that after a
            # crash during install the operator was told the database was
            # untouched at the exact moment it had been moved aside or already
            # replaced. That is the worst direction for this message to be
            # wrong in: it invites deleting the operation directory, which is
            # holding the only copy of the pre-restore database.
            #
            # Deliberately an ALLOWLIST of states proven to precede
            # installation, not a denylist of the installing ones. A denylist
            # defaults every state it does not know about to "untouched",
            # which is the dangerous answer, and it silently mis-reports any
            # state added later. Post-install states include more than the
            # obvious two: the marker commit and the audit activation both
            # happen against the already-installed candidate.
            state = phase.get("state")
            if state in _PRE_INSTALL_PHASE_STATES:
                disposition = (
                    f"The live database has not been displaced or replaced: "
                    f"this operation stopped at {state}, before installation "
                    f"begins. An abandoned rollback of this operation can "
                    f"have committed one audit row to it, so it may not be "
                    f"byte-identical to the file you started with."
                )
            else:
                disposition = (
                    f"The live database may already have been displaced by "
                    f"this operation (state {state}), so do not assume it is "
                    f"the file you started with. The pre-restore copy is "
                    f"inside {operation_dir}: do not delete that directory."
                )
            raise DatabaseRestorePending(
                f"database restore is pending; resume operation {operation_id} "
                f"with `z4j restore --force --operation {operation_id}`, or "
                f"abandon it with `z4j restore --force --rollback-operation "
                f"{operation_id}` to return the brain to service. "
                f"{disposition}",
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
        # Name BOTH exits, in the words an operator can paste. A refusal
        # mid-ceremony leaves this fence up on every connection the brain
        # opens, and an operator told only that a restore is "unfinished" has
        # nothing to type: neither command appeared anywhere they were looking.
        operation_id = envelope["operation_id"]
        raise DatabaseRestorePending(
            f"PostgreSQL database restore is unfinished; resume operation "
            f"{operation_id} with `z4j restore --force --operation "
            f"{operation_id}`, or abandon it with `z4j restore --force "
            f"--rollback-operation {operation_id}` to return the brain to "
            f"service.",
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


def _preflight_supported_source_head(source_path: Path) -> None:
    """Refuse a source this release cannot restore, before an operation exists.

    Read-only and best effort. A file that cannot be opened or read here is not
    refused: staging below computes the authoritative digest and head, and this
    check exists to avoid stranding the operator, not to be a second gate.
    """
    try:
        connection = _immutable_sqlite_connection(source_path)
    except Exception:
        return
    try:
        rows = connection.execute("SELECT version_num FROM alembic_version").fetchall()
    except Exception:
        return
    finally:
        connection.close()
    if len(rows) != 1:
        return
    head = str(rows[0][0])
    if head in _SQLITE_SOURCE_SCHEMA_DIGESTS:
        return
    raise DatabaseRestoreRefused(
        f"this release cannot restore a backup taken at migration head "
        f"{head!r}. Supported heads are "
        f"{', '.join(sorted(_SQLITE_SOURCE_SCHEMA_DIGESTS))}. Install the z4j "
        f"release matching that head, restore there, then upgrade.",
    )


# Every statement below fixes its own row order. The manifest these rows
# feed is what the stopped-executor attestation challenge is derived from,
# and a resumed operation re-derives that challenge, so reading in SQLite's
# physical order would let a page rewrite between two runs of the same
# operation produce a different challenge and strand the operator mid
# ceremony with no way to finish it.
_SOURCE_REVISION_STATE_QUERY = "SELECT * FROM schedule_revision_state ORDER BY singleton_id"
_SOURCE_EPOCH_ALLOCATOR_QUERY = (
    "SELECT * FROM schedule_external_epoch_allocator ORDER BY singleton_id"
)
_SOURCE_EXTERNAL_STREAM_QUERY = "SELECT * FROM schedule_external_streams ORDER BY id"
_SOURCE_EXTERNAL_EPOCH_QUERY = (
    "SELECT * FROM schedule_external_stream_epochs ORDER BY epoch_number, epoch_uuid"
)
# Resolved control operations carry no live executor authority, so the
# PostgreSQL archive reader counts and digests only the unresolved ones.
# Filtering in SQL keeps the two backends describing the same rows.
_SOURCE_EXTERNAL_OPERATION_QUERY = (
    "SELECT * FROM schedule_external_control_operations "
    "WHERE status IN ('PENDING', 'CLAIMED', 'AMBIGUOUS') "
    "ORDER BY id"
)
_EXECUTOR_AUTHORITY_COLUMNS = (
    "authorized_adapter_instance_id",
    "executor_agent_id",
    "executor_registry_owner_id",
    "executor_session_generation",
)


def _json_scalar(value: Any) -> Any:
    """Render one raw SQLite column value as a canonical-JSON scalar."""

    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    return str(value)


def _sqlite_manifest_rows(
    connection: sqlite3.Connection,
    statement: str,
) -> list[dict[str, Any]]:
    """Read one ordered table of a staged source into manifest rows."""

    rows = connection.execute(statement).fetchall()
    return [{key: _json_scalar(row[key]) for key in row.keys()} for row in rows]  # noqa: SIM118


def _uuid_text(value: Any, column: str) -> str | None:
    """Render a stored identifier the way both backends spell it.

    SQLite keeps these as bare 32-character hex while PostgreSQL renders the
    dashed form. Normalizing here is what lets the two backends describe the
    same logical database identically.
    """

    if value is None:
        return None
    try:
        return str(uuid.UUID(str(value)))
    except (AttributeError, TypeError, ValueError) as exc:
        raise DatabaseRestoreRefused(
            f"staged SQLite source has a malformed identifier in {column}",
        ) from exc


def _sqlite_singleton_int(
    rows: list[dict[str, Any]],
    column: str,
    table_name: str,
) -> int:
    if len(rows) != 1 or rows[0].get(column) is None:
        raise DatabaseRestoreRefused(
            f"staged SQLite source {table_name} singleton is malformed",
        )
    return int(str(rows[0][column]))


def _assert_activated_boundary_singleton(
    rows: list[dict[str, Any]],
    table_name: str,
) -> None:
    """Refuse a source claiming an activated head without activated state."""

    if len(rows) != 1 or rows[0].get("guard_version") != 1:
        raise DatabaseRestoreRefused(
            f"staged SQLite source {table_name} is not Boundary-D activated",
        )


def _carries_executor_authority(row: Mapping[str, Any]) -> bool:
    return any(row.get(column) is not None for column in _EXECUTOR_AUTHORITY_COLUMNS)


def _legacy_source_boundary_authority(
    connection: sqlite3.Connection,
) -> dict[str, Any]:
    """Describe the Boundary-D authority of the supported 1.7 source head.

    The connection is unused but kept for one uniform builder signature.

    Boundary D did not exist at that head. Historical migration replay must
    therefore contain no revision singleton to inspect; its restore rebase
    starts at revision zero.
    """

    return {
        "revision": 0,
        "revision_classification": "pre_d_empty",
        "epoch": 0,
        "external_authority_manifest": _empty_external_authority_manifest(),
    }


def _activated_source_boundary_authority(
    connection: sqlite3.Connection,
) -> dict[str, Any]:
    """Derive the real Boundary-D authority of an already-activated source.

    This mirrors the PostgreSQL archive reader so both backends describe the
    same logical database the same way. Nothing here may be stubbed out to
    the pre-Boundary-D shape: the derived
    ``requires_stopped_executor_attestation`` is what decides whether the
    operator has to prove every external executor is stopped, so reporting an
    empty external authority for a source that does carry one would silently
    drop that ceremony and let a live executor race the restored database.
    """

    revisions = _sqlite_manifest_rows(connection, _SOURCE_REVISION_STATE_QUERY)
    allocators = _sqlite_manifest_rows(connection, _SOURCE_EPOCH_ALLOCATOR_QUERY)
    _assert_activated_boundary_singleton(revisions, "schedule_revision_state")
    _assert_activated_boundary_singleton(
        allocators,
        "schedule_external_epoch_allocator",
    )
    streams = _sqlite_manifest_rows(connection, _SOURCE_EXTERNAL_STREAM_QUERY)
    epochs = _sqlite_manifest_rows(connection, _SOURCE_EXTERNAL_EPOCH_QUERY)
    operations = _sqlite_manifest_rows(
        connection,
        _SOURCE_EXTERNAL_OPERATION_QUERY,
    )
    stream_authority = [
        {
            "stream_id": _uuid_text(row.get("id"), "schedule_external_streams.id"),
            "epoch_uuid": _uuid_text(
                row.get("current_epoch_uuid"),
                "schedule_external_streams.current_epoch_uuid",
            ),
            "epoch_number": int(str(row["current_epoch_number"])),
            "phase": row.get("phase"),
            "adapter_instance_id": row.get(
                "authorized_adapter_instance_id",
            ),
            "agent_id": _uuid_text(
                row.get("executor_agent_id"),
                "schedule_external_streams.executor_agent_id",
            ),
            "registry_owner_id": _uuid_text(
                row.get("executor_registry_owner_id"),
                "schedule_external_streams.executor_registry_owner_id",
            ),
            "session_generation": row.get(
                "executor_session_generation",
            ),
            "worker_id": row.get("executor_worker_id"),
        }
        for row in streams
        if _carries_executor_authority(row)
    ]
    epoch_authority = [
        {
            "stream_id": _uuid_text(
                row.get("stream_id"),
                "schedule_external_stream_epochs.stream_id",
            ),
            "epoch_uuid": _uuid_text(
                row.get("epoch_uuid"),
                "schedule_external_stream_epochs.epoch_uuid",
            ),
            "epoch_number": int(str(row["epoch_number"])),
            "phase": row.get("phase"),
            "adapter_instance_id": row.get(
                "authorized_adapter_instance_id",
            ),
            "agent_id": _uuid_text(
                row.get("executor_agent_id"),
                "schedule_external_stream_epochs.executor_agent_id",
            ),
            "registry_owner_id": _uuid_text(
                row.get("executor_registry_owner_id"),
                "schedule_external_stream_epochs.executor_registry_owner_id",
            ),
            "session_generation": row.get(
                "executor_session_generation",
            ),
            "worker_id": row.get("executor_worker_id"),
        }
        for row in epochs
        if _carries_executor_authority(row)
    ]
    operation_authority = [
        {
            "operation_id": _uuid_text(
                row.get("id"),
                "schedule_external_control_operations.id",
            ),
            "command_id": _uuid_text(
                row.get("command_id"),
                "schedule_external_control_operations.command_id",
            ),
            "stream_id": _uuid_text(
                row.get("stream_id"),
                "schedule_external_control_operations.stream_id",
            ),
            "epoch_uuid": _uuid_text(
                row.get("epoch_uuid"),
                "schedule_external_control_operations.epoch_uuid",
            ),
            "epoch_number": int(str(row["epoch_number"])),
            "status": row.get("status"),
            "adapter_instance_id": row.get("adapter_instance_id"),
            "agent_id": _uuid_text(
                row.get("agent_id"),
                "schedule_external_control_operations.agent_id",
            ),
            "registry_owner_id": _uuid_text(
                row.get("registry_owner_id"),
                "schedule_external_control_operations.registry_owner_id",
            ),
            "session_generation": row.get("session_generation"),
            "dispatch_lease": _uuid_text(
                row.get("dispatch_lease"),
                "schedule_external_control_operations.dispatch_lease",
            ),
        }
        for row in operations
    ]
    external = {
        "allocator_digest": release_manifest_digest(allocators),
        "stream_digest": release_manifest_digest(streams),
        "epoch_digest": release_manifest_digest(epochs),
        "operation_digest": release_manifest_digest(operations),
        "stream_count": len(streams),
        "epoch_count": len(epochs),
        "operation_count": len(operations),
        "executor_authority": {
            "streams": stream_authority,
            "epochs": epoch_authority,
            "unresolved_operations": operation_authority,
        },
        "requires_stopped_executor_attestation": bool(
            stream_authority or epoch_authority or operation_authority,
        ),
    }
    return {
        "revision": _sqlite_singleton_int(
            revisions,
            "current_revision",
            "schedule_revision_state",
        ),
        "pruned_through": _sqlite_singleton_int(
            revisions,
            "change_log_pruned_through",
            "schedule_revision_state",
        ),
        "epoch": _sqlite_singleton_int(
            allocators,
            "current_epoch_number",
            "schedule_external_epoch_allocator",
        ),
        "external_authority_manifest": external,
    }


#: How each restorable pre-current head describes its own source authority.
#:
#: The current head is deliberately absent: its manifest arrives later, from
#: the authenticated snapshot taken over a copy of the staged source, and it
#: is the only head that can be snapshotted directly because it is the only
#: one this release's ORM already matches.
_SQLITE_SOURCE_MANIFEST_BUILDERS: dict[
    str,
    Callable[[sqlite3.Connection], dict[str, Any]],
] = {
    _LEGACY_SOURCE_HEAD: _legacy_source_boundary_authority,
    _PREVIOUS_RELEASE_HEAD: _activated_source_boundary_authority,
}

#: How a candidate staged at each pre-current head reaches the current head.
#:
#: ``audit_preparation`` sources stop at the authenticated audit-preparation
#: boundary and need a separate operator activation ceremony to continue.
#: ``direct`` sources are already audit- and Boundary-D activated, so the
#: remaining release migrations apply straight through.
_SQLITE_SOURCE_UPGRADE_MODES = {
    _LEGACY_SOURCE_HEAD: "audit_preparation",
    _PREVIOUS_RELEASE_HEAD: "direct",
}


def _assert_source_heads_are_consumed() -> None:
    """Refuse to import while a restorable head has no code behind it.

    Declaring a head in the digest allowlist is what makes preflight promise
    the operator that their backup can be restored. Bumping the release head
    without also teaching these two registries about the head it displaced
    would leave that promise unbacked: the displaced head would pass every
    gate and then fail deep inside the ceremony on a manifest nobody built.
    Failing at import instead turns that into a test-suite failure on the
    commit that causes it.
    """

    restorable = set(_SQLITE_SOURCE_SCHEMA_DIGESTS)
    if RELEASE_MIGRATION_HEAD not in restorable:
        raise RuntimeError(
            "SQLite restore allowlist does not contain the current release head",
        )
    # The current head needs neither registry entry, so exclude it from both
    # directions of the comparison rather than special-casing one side.
    pre_current = restorable - {RELEASE_MIGRATION_HEAD}
    for registry_name, registry in (
        ("manifest builder", set(_SQLITE_SOURCE_MANIFEST_BUILDERS)),
        ("upgrade mode", set(_SQLITE_SOURCE_UPGRADE_MODES)),
    ):
        missing = sorted(pre_current - registry)
        if missing:
            raise RuntimeError(
                f"restorable SQLite source heads without a {registry_name}: {', '.join(missing)}",
            )
        stale = sorted(registry - pre_current)
        if stale:
            raise RuntimeError(
                f"SQLite {registry_name} entries for unrestorable heads: {', '.join(stale)}",
            )


_assert_source_heads_are_consumed()


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
        build_manifest = _SQLITE_SOURCE_MANIFEST_BUILDERS.get(source_head)
        if build_manifest is not None:
            # Every head older than the current one needs its full manifest
            # built right here, over this same immutable connection: the
            # attestation envelope is assembled from it before anything is
            # allowed to touch the candidate.
            source_manifest = {
                **authority,
                **build_manifest(connection),
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

    config = _restore_migration_config()
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


#: Boundary-D facts a release migration carries forward without rewriting.
#:
#: Migrating a restored source up to the current head moves rows between
#: schemas; it does not allocate revisions or epochs, so every one of these
#: has to read back off the migrated candidate exactly as the source
#: derivation declared it.
_MIGRATED_SOURCE_AUTHORITY_FIELDS = ("revision", "pruned_through", "epoch")


def _assert_candidate_matches_source_authority(
    source_authority: Mapping[str, Any],
    upgraded_snapshot: Mapping[str, Any],
) -> None:
    """Refuse unless the migrated candidate is the source that was attested.

    The source authority is derived by reading the staged file with raw SQL at
    its own older schema, because this release's ORM cannot open that schema.
    Everything the operator sees and everything the ceremony signs is built
    from that derivation: the stopped-executor challenge, the attestation
    envelope, and the source half of the restore marker. Nothing downstream
    re-reads the source, so a derivation that describes the wrong database, or
    describes the right one wrongly, would simply be believed all the way to a
    signed marker.

    Re-reading the same facts off the migrated candidate through the ORM is
    what turns that derivation from trusted into checked, and it is the SQLite
    counterpart of the PostgreSQL check that the restored D singletons match
    the staged archive preflight.
    """

    disagreements: list[str] = []
    for field in _MIGRATED_SOURCE_AUTHORITY_FIELDS:
        restored = upgraded_snapshot[field]
        # A builder that omits the field entirely is as wrong as one that
        # reports the wrong value, so read it without assuming it is there.
        declared = source_authority.get(field)
        if declared != restored:
            disagreements.append(
                f"{field} (source authority {declared!r}, restored {restored!r})",
            )
    declared_external = source_authority.get("external_authority_manifest") or {}
    restored_external = upgraded_snapshot["external_authority_manifest"]
    if declared_external.get("executor_authority") != restored_external["executor_authority"]:
        # This one decides whether the operator had to prove every external
        # executor was stopped, so an under-reported source authority here
        # silently drops that ceremony.
        disagreements.append("external executor authority")
    if disagreements:
        raise DatabaseRestoreRefused(
            "restored SQLite source authority differs from the migrated "
            f"candidate: {', '.join(disagreements)}",
        )


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
    engine = (
        create_async_engine_from_url(database_url)
        if connection is None and session is None
        else None
    )
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
    engine = create_async_engine_from_url(database_url) if connection is None else None
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
            # A rename crosses two directories and each one holds half of it.
            # The destination is persisted first: what must never be lost is
            # the new name of the live database, because until the candidate
            # is installed the displaced copy is the only one there is.
            _fsync_directory(operation_dir)
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
    _fsync_directory(operation_dir)
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
    engine = create_async_engine_from_url(_async_sqlite_url(path))
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
    engine = create_async_engine_from_url(_async_sqlite_url(path))
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


def staged_restore_source(
    database_url: str,
    *,
    operation: str | uuid.UUID,
) -> Path:
    """Return the source path one already-staged SQLite operation carries.

    A resume reads its source from the durable phase and never reopens the
    operator's file, which is why the fence advertises ``--operation`` on its
    own. Handing that recorded path back lets the command an operator is told
    to run be the command they can run, without teaching the positional
    argument a second meaning it would then have to be checked for.
    """

    if not database_url.startswith(("sqlite", "sqlite+aiosqlite")):
        raise DatabaseRestoreRefused(
            "SQLite restore received a non-SQLite database URL",
        )
    operation_id = operation if isinstance(operation, uuid.UUID) else uuid.UUID(str(operation))
    target = _lexical_absolute(_sqlite_path_from_url(database_url))
    phase_path = _phase_path(target, operation_id)
    if not _phase_file_present(phase_path):
        raise DatabaseRestoreRefused(
            f"there is no staged restore operation {operation_id}; supply the "
            f"backup PATH to start one",
        )
    phase = _read_phase(phase_path)
    if phase.get("operation_id") != str(operation_id) or phase.get("target_path") != str(target):
        raise DatabaseRestoreRefused(
            "restore phase identity does not match this operation",
        )
    return Path(str(phase["source_provenance"]["supplied_path"]))


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

    _ensure_durable_directory(target.parent)
    root = _phase_root(target)
    _ensure_durable_directory(root)
    operation_dir = root / str(operation_id)
    # The operation directory is created where the phase is written, not
    # here. Startup treats an operation directory as an unfinished restore,
    # so creating one before the refusals below have had their say fenced a
    # healthy brain on an operation that never began.
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
            # Refuse an unsupportable source BEFORE any phase exists on disk.
            # Every phase state other than COMPLETE and ROLLED_BACK raises the
            # startup fence, so a refusal that happens after the phase is
            # written stops the brain booting, and resuming re-enters the same
            # refusal forever. The authoritative head check still runs below
            # against the staged copy; this one only decides whether it is
            # worth creating an operation at all.
            _preflight_supported_source_head(source_path)
            # Everything that can refuse this operation has now spoken, so
            # the operation gets a home and its phase in the same breath.
            _ensure_durable_directory(operation_dir)
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
                        f"{challenge}; resume with `z4j restore --force "
                        f"--operation {operation_id} "
                        f"--attest-stopped-executors {challenge}`",
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
            source_head = str(phase["source_authority"]["source_head"])
            upgrade_mode = _SQLITE_SOURCE_UPGRADE_MODES.get(source_head)
            if upgrade_mode == "audit_preparation":
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
            elif upgrade_mode == "direct":
                import asyncio

                # A previous-release source is already audit- and Boundary-D
                # activated, so the remaining release migrations must apply
                # cleanly. This is the exact opposite of the legacy arm above,
                # which requires the upgrade to stop at the audit-preparation
                # boundary, and reusing that arm here would refuse every
                # previous-release restore.
                try:
                    _upgrade_sqlite_database(candidate)
                except Exception as exc:
                    # A candidate that will not migrate is an ordinary refusal,
                    # and the operator has to be told which archive could not
                    # be carried forward and why. Letting the alembic failure
                    # out raw makes a restore that stopped safely look like a
                    # crash in the restore code itself.
                    raise DatabaseRestoreRefused(
                        f"SQLite restore could not migrate its {source_head} "
                        f"candidate to {RELEASE_MIGRATION_HEAD}: {exc}",
                    ) from exc
                _checkpoint_sqlite(candidate)
                # Everything downstream compares the candidate against the
                # source snapshot, and the pre-upgrade authority carries the
                # older release's schema contract and manifest. Re-authenticate
                # the migrated candidate so those comparisons describe what the
                # candidate actually is now. The attestation challenge stays
                # bound to the pre-upgrade authority, which is what the
                # operator was shown and what a resume re-derives.
                upgraded_snapshot = asyncio.run(
                    _authenticated_snapshot(candidate, settings),
                )
                _assert_candidate_matches_source_authority(
                    phase["source_authority"],
                    upgraded_snapshot,
                )
                finalization = asyncio.run(
                    finalize_restored_database(
                        _async_sqlite_url(candidate),
                        settings,
                        operation_id=operation_id,
                        source_digest=source_digest,
                        source_snapshot=upgraded_snapshot,
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
                            # The signed marker records where the data came
                            # from, not where the ceremony left it, so these
                            # two stay on the pre-upgrade head.
                            "source_migration_head": source_head,
                            "source_schema_contract_digest": phase["source_authority"][
                                "schema_contract_digest"
                            ],
                            "upgraded_migration_head": (upgraded_snapshot["migration_head"]),
                            "upgraded_schema_contract_digest": (
                                upgraded_snapshot["schema_contract_digest"]
                            ),
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
                    "candidate_mode": "upgraded_finalized",
                    "candidate_size": candidate_size,
                    "candidate_digest": candidate_digest,
                    "upgraded_snapshot": upgraded_snapshot,
                    "finalization": finalization,
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
                    f"--restore-operation {operation_id} --manifest PATH`, "
                    "then the same command again with --apply added",
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
                f"--restore-operation {operation_id} --manifest PATH`, "
                "then the same command again with --apply added",
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
    engine = create_async_engine_from_url(database_url)
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

    engine = create_async_engine_from_url(_async_sqlite_url(target))
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
            # Destination first: the rejected live set is evidence an operator
            # may still need, and only the operation directory names it.
            _fsync_directory(operation_dir)
            _fsync_directory(target.parent)
    if candidate.exists():
        candidate.replace(target)
        target.chmod(0o600)
        _fsync_directory(target.parent)
        _fsync_directory(operation_dir)
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
    phase_path = operation_dir / _PHASE_FILE_NAME
    _require_rollbackable_operation(phase_path, operation_id)
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

        # The rollback marker commits into the live database before the phase
        # that records it, and committing it moves the live manifest by exactly
        # one audit row. Every state below then compares that manifest against
        # the captured one, so the marker's own effect reads as the target
        # having changed underfoot. Ask the database whether this operation's
        # marker is already there before any of those comparisons speak: the
        # pre-install states are where it bit hardest, because there the live
        # target IS the captured one and the crash left an operation that
        # neither retry nor resume could finish.
        if phase.get("state") in {
            "PREFLIGHT_COMPLETE",
            "CANDIDATE_FINALIZED",
            "CANDIDATE_AUDIT_PREPARED",
            "ROLLBACK_INSTALLED",
        }:
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
    "staged_restore_source",
]
