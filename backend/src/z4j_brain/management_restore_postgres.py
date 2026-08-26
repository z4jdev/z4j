"""Durable PostgreSQL database-restore coordinator.

The database-level ``z4j.restore_pending`` default is the cross-host restart
fence.  A separately secured local phase binds the staged archive, physical
database identity, trusted client executables, recovery dump, and the exact
operation UUID.  The shared schema-transition advisory lock stays held across
the external restore process and authenticated D/F finalization.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import threading
import uuid
from collections.abc import Callable, Coroutine, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)
from z4j_core.paths import z4j_home

from z4j_brain.domain.audit_chain import canonical_json
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.audit_verifier import (
    verify_active_audit_generation,
)
from z4j_brain.management_reset import (
    RESET_ORM_TABLES,
    release_manifest_digest,
    release_schema_contract_manifest,
)
from z4j_brain.management_restore import (
    _PREVIOUS_RELEASE_HEAD,
    _SQLITE_SOURCE_SCHEMA_DIGESTS,
    DatabaseRestoreRefused,
    _absent_directories,
    _attestation_envelope,
    _ensure_durable_directory,
    _file_digest,
    _fsync_directory,
    _fsync_new_directory_names,
    _read_phase,
    _replace_phase,
    _restore_migration_config,
    _stage_source,
    authenticated_database_snapshot,
    finalize_restored_database,
)
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.schema_transition import (
    RELEASE_MIGRATION_HEAD,
    SCHEMA_TRANSITION_ADVISORY_LOCK_KEY,
)
from z4j_brain.secret_store import (
    audit_bootstrap_coordinator,
    ensure_secret_store_directory,
)
from z4j_brain.settings import Settings

_DANGEROUS_TOC_CLASSES = (
    " DATABASE ",
    " DATABASE PROPERTIES ",
    " EVENT TRIGGER ",
    " PUBLICATION ",
    " SUBSCRIPTION ",
    " SERVER ",
    " USER MAPPING ",
    " FOREIGN DATA WRAPPER ",
    " PROCEDURAL LANGUAGE ",
)
_TOC_LINE = re.compile(r"^\d+;\s+\d+\s+\d+\s+(.+)$")
_COPY_HEADER = re.compile(
    r"^COPY public\.([a-z0-9_]+) \(([^)]+)\) FROM stdin;$",
)
#: Name the recovery dump is written under while it is still being produced.
#: Nothing reads it, which is the point: see ``_run_restore``. Deliberately
#: SHORTER than the finished name -- the operation directory already spends a
#: 64-character target key and a UUID, and a longer one put pg_dump's output
#: path past the 260-character limit Windows still applies to it.
_RECOVERY_PARTIAL_NAME = "recovery.part"
_MAX_COPY_EXTRACT_BYTES = 32 * 1024 * 1024
_MAX_SCHEMA_EXTRACT_BYTES = 16 * 1024 * 1024
_RELEASE_EXTENSIONS = frozenset({"citext", "pg_trgm", "pgcrypto"})
_RELEASE_TYPES = frozenset(
    {
        "agent_state",
        "command_status",
        "project_role",
        "schedule_kind",
        "task_priority",
        "task_state",
        "worker_state",
    },
)
_RELEASE_FUNCTION_SIGNATURES = frozenset(
    {
        "audit_chain_state_forbid_mutation()",
        "audit_log_forbid_mutation()",
        (
            "z4j_consume_external_allocation_guard_v1"
            "(text, uuid, uuid, bigint, bigint, text, text, uuid, text)"
        ),
        (
            "z4j_consume_external_control_guard_v1"
            "(text, uuid, uuid, bigint, bigint, uuid, uuid, uuid)"
        ),
        ("z4j_consume_external_cutover_evidence_guard_v1(uuid, uuid, text, text, text)"),
        ("z4j_consume_external_cutover_schedule_guard_v1(uuid, uuid, bigint, uuid, text, text)"),
        (
            "z4j_consume_external_lifecycle_guard_v1"
            "(text, uuid, uuid, bigint, bigint, text, text, bigint)"
        ),
        (
            "z4j_consume_external_projection_guard_v1"
            "(text, uuid, uuid, bigint, bigint, text, text, text)"
        ),
        "z4j_consume_schedule_evidence_guard_v1(text, text, text)",
        "z4j_consume_schedule_prune_row_v1(bigint)",
        "z4j_consume_schedule_reset_epoch_v1(bigint, bigint)",
        "z4j_consume_schedule_reset_revision_v1(bigint, bigint)",
        "z4j_consume_schedule_reset_row_v1(text)",
        "z4j_consume_schedule_restore_epoch_v1(bigint, bigint)",
        ("z4j_consume_schedule_restore_revision_v1(bigint, bigint, bigint, bigint)"),
        ("z4j_consume_schedule_restore_row_v1(text, uuid, bigint, bigint, text, uuid, uuid)"),
        "z4j_finalize_schedule_prune_v1(bigint, bigint)",
        "z4j_finalize_schedule_reset_v1(text, text)",
        "z4j_finalize_schedule_restore_v1(text, text)",
        ("z4j_finish_external_target_cutover_guard_v1(uuid, uuid, bigint)"),
        "z4j_pending_fire_guard_v1()",
        "z4j_schedule_change_log_guard_v1()",
        "z4j_schedule_command_guard_v1()",
        "z4j_schedule_external_allocator_guard_v1()",
        "z4j_schedule_external_control_guard_v1()",
        "z4j_schedule_external_epoch_guard_v1()",
        "z4j_schedule_external_projection_guard_v1()",
        "z4j_schedule_external_row_guard_v1()",
        "z4j_schedule_external_snapshot_frame_guard_v1()",
        "z4j_schedule_external_stream_guard_v1()",
        "z4j_schedule_fire_guard_v1()",
        "z4j_schedule_occurrence_resolution_guard_v1()",
        "z4j_schedule_owner_cutover_guard_v1()",
        "z4j_schedule_reset_active_v1()",
        "z4j_schedule_restore_active_v1()",
        "z4j_schedule_revision_guard_v1()",
        "z4j_schedule_row_guard_v1()",
        "z4j_schedule_terminal_hold_guard_v1()",
        "z4j_schedules_notify()",
    },
)
_RELEASE_FUNCTION_DEFINITIONS_DIGEST = (
    "46c33b9745272b9cf04b72f17476af102d2915d434d472d77f79c4bffc2745de"
)
_LEGACY_SOURCE_HEAD = "v1_7_security_hardening"
_LEGACY_FUNCTION_SIGNATURES = frozenset(
    {
        "audit_log_forbid_mutation()",
        "z4j_schedules_notify()",
    },
)
_LEGACY_FUNCTION_DEFINITIONS_DIGEST = (
    "496c3b62cfb58a15fc1d8453df3d4ccde33b3c00a77bd8e6eefce7cf602daaeb"
)
# These contracts come from clean migration-head databases archived and
# inspected by matching-major client/server pairs.  A converted or cross-major
# archive is not valid derivation evidence for this fail-closed map.
_RELEASE_SCHEMA_DEFINITIONS_DIGESTS = {
    16: "320359d69d4cea4683da5e37d575d9989ce78b7d9563b3ab63b364d832eb6546",
    17: "320359d69d4cea4683da5e37d575d9989ce78b7d9563b3ab63b364d832eb6546",
    18: "9a77a23a38b979712a5b1650732ff020e5d7ed05c115ca426362f6df4a5d08d0",
}
# The previous release head, derived the same way: a database migrated to that
# head on a live server of each major, archived by the matching-major pinned
# client.  Cross-checked against the immutable published release image, which
# is an oracle no current source tree can talk itself into agreeing with.
_PREVIOUS_SCHEMA_DEFINITIONS_DIGESTS = {
    16: "dbeb00b3791e608e895ce8da3edf04f17580b0d1aae978c5d8135c74bdf2bef8",
    17: "dbeb00b3791e608e895ce8da3edf04f17580b0d1aae978c5d8135c74bdf2bef8",
    18: "cccd4a1651106141697c0b8d247d35dd679bc65e7360bb913a956d6ca556ca56",
}
# These legacy values are external oracles captured by matching-major clients
# from the immutable 6b12719c release baseline, never from current migrations.
_LEGACY_SCHEMA_DEFINITIONS_DIGESTS = {
    16: "570e8353d0bc9bec897fa9bda2dbee1b5ad1a71329e984095d5bef6bb4e02d91",
    17: "570e8353d0bc9bec897fa9bda2dbee1b5ad1a71329e984095d5bef6bb4e02d91",
    18: "052ea06f4769c42eb75bdd38b81606ce94c8ddfe3001809cbef61c7751c3e6cb",
}
#: The exact head every hardcoded map above was measured at, spelled out.
#:
#: ``RELEASE_MIGRATION_HEAD`` and ``_PREVIOUS_RELEASE_HEAD`` are imported names
#: that move on the next release, while each digest above was captured by hand
#: from one real database at one exact head.  Binding a moving name to fixed
#: evidence without pinning the head means the next head bump silently
#: re-points measured evidence at an unmeasured head: every restore of the
#: displaced head is then refused for a schema mismatch whose cause is
#: invisible, and the Boundary-D set below adopts a head nobody confirmed
#: shipped D activated.  The literals here turn that into an import failure, so
#: the commit that bumps the head is the commit that has to re-derive.
_MEASURED_RELEASE_HEAD = "v1_9_audit_action_pattern"
_MEASURED_PREVIOUS_RELEASE_HEAD = "v1_8_schedule_cursor_repair"
_SCHEMA_DEFINITIONS_DIGESTS_BY_HEAD = {
    RELEASE_MIGRATION_HEAD: _RELEASE_SCHEMA_DEFINITIONS_DIGESTS,
    _PREVIOUS_RELEASE_HEAD: _PREVIOUS_SCHEMA_DEFINITIONS_DIGESTS,
    _LEGACY_SOURCE_HEAD: _LEGACY_SCHEMA_DEFINITIONS_DIGESTS,
}
#: Heads whose archives carry an activated Boundary D, so their schedule
#: authority is read out of the archive rather than assumed.  The previous
#: release head belongs here: it shipped Boundary D already activated, and
#: treating it like the pre-D legacy head would hardcode revision 0, epoch 0
#: and an empty external-authority manifest over real rows, which silently
#: drops the stopped-executor ceremony for an operator who has executors.
_BOUNDARY_D_SOURCE_HEADS = frozenset(
    {
        RELEASE_MIGRATION_HEAD,
        _PREVIOUS_RELEASE_HEAD,
    },
)
#: Every head this release can accept as a restore source.  The previous
#: release head shares the current executable-function contract: the delta
#: between them is additive table columns and one CHECK, so no function body
#: or signature moved.  Its static schema text does differ, which is why only
#: the schema-definitions map above gains a per-major entry.
_SUPPORTED_SOURCE_HEADS = frozenset(_SCHEMA_DEFINITIONS_DIGESTS_BY_HEAD)


def _assert_source_head_evidence_is_current() -> None:
    """Refuse to import while a head moved out from under its evidence.

    Every claim this module makes about a source head is hand-derived and
    head-specific, so a head that moves without its evidence being re-derived
    is not a smaller version of a working restore: it is a restore that
    refuses every real archive for an unrelated-looking reason.  Failing at
    import turns that into a test-suite failure on the commit that causes it.

    The allowlist comparison is the other half.  The two backends restore the
    same logical database, so an operator told by one backend that their
    backup is restorable must not be told otherwise by the other; letting the
    allowlists drift apart is how that promise gets broken silently.
    """

    for imported, measured, role in (
        (RELEASE_MIGRATION_HEAD, _MEASURED_RELEASE_HEAD, "release"),
        (
            _PREVIOUS_RELEASE_HEAD,
            _MEASURED_PREVIOUS_RELEASE_HEAD,
            "previous release",
        ),
    ):
        if imported != measured:
            raise RuntimeError(
                f"PostgreSQL restore {role} head moved to {imported!r} while its "
                f"per-major schema-definition digests and its Boundary-D "
                f"activation were measured at {measured!r}: re-derive both from a "
                f"real server of every supported major, then pin the new head.",
            )
    unconfirmed = sorted(
        _BOUNDARY_D_SOURCE_HEADS - {_MEASURED_RELEASE_HEAD, _MEASURED_PREVIOUS_RELEASE_HEAD},
    )
    if unconfirmed:
        raise RuntimeError(
            "PostgreSQL restore reads Boundary-D authority out of archives at "
            f"heads with no confirmed activated release behind them: {', '.join(unconfirmed)}",
        )
    if frozenset(_SQLITE_SOURCE_SCHEMA_DIGESTS) != _SUPPORTED_SOURCE_HEADS:
        raise RuntimeError(
            "PostgreSQL and SQLite restore source allowlists disagree: "
            f"postgres={sorted(_SUPPORTED_SOURCE_HEADS)}, "
            f"sqlite={sorted(_SQLITE_SOURCE_SCHEMA_DIGESTS)}",
        )


_assert_source_head_evidence_is_current()

_RUNTIME_PARTITION = re.compile(
    r"^(?:events|schedule_fires)(?:_default|_\d{4}_\d{2}_\d{2})$",
)
_RUNTIME_SCHEMA_OBJECT = re.compile(
    r"^(?:events|schedule_fires)"
    r"(?:_default|_\d{4}_\d{2}_\d{2})(?:_|$)",
)
_SCHEMA_BLOCK_HEADER = re.compile(
    r"^-- Name: (.*); Type: ([^;]+); Schema: ([^;]+); Owner: (.*)$",
)
_LIBPQ_ENVIRONMENT_LOCK = threading.Lock()
_LIBPQ_AMBIENT_KEYS = frozenset(
    {
        "KRB5CCNAME",
        "KRB5_CONFIG",
        "OPENSSL_CONF",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
    },
)


@dataclass(frozen=True, slots=True)
class _Target:
    database_url: str
    libpq_url: str
    host: str
    hostaddr: str
    port: int
    database: str
    username: str
    password: str | None
    sslmode: str
    sslrootcert: str | None
    sslcert: str | None
    sslkey: str | None


@dataclass(frozen=True, slots=True)
class _Tool:
    name: str
    path: Path
    digest: str
    identity: tuple[int, int, int]
    version: str
    major: int


class _PinnedConnection:
    """Small asyncpg-shaped adapter over one libpq-pinned psycopg session."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    @staticmethod
    def _parameters(
        query: str,
        arguments: tuple[Any, ...],
    ) -> tuple[str, tuple[Any, ...]]:
        indices = [int(match.group(1)) for match in re.finditer(r"\$(\d+)", query)]
        if not indices:
            return query, ()
        if any(index < 1 or index > len(arguments) for index in indices):
            raise DatabaseRestoreRefused(
                "internal pinned PostgreSQL query parameter mismatch",
            )
        translated = re.sub(r"\$\d+", "%s", query)
        return translated, tuple(arguments[index - 1] for index in indices)

    async def execute(self, query: str, *arguments: Any) -> None:
        translated, parameters = self._parameters(query, arguments)
        async with self._connection.cursor() as cursor:
            await cursor.execute(translated, parameters)

    async def fetchrow(
        self,
        query: str,
        *arguments: Any,
    ) -> dict[str, Any] | None:
        translated, parameters = self._parameters(query, arguments)
        async with self._connection.cursor() as cursor:
            await cursor.execute(translated, parameters)
            row = await cursor.fetchone()
        return None if row is None else dict(row)

    async def close(self) -> None:
        await self._connection.close()


def _sha256_file(path: Path) -> str:
    return _file_digest(path)[1]


def _assert_trusted_path(path: Path) -> None:
    observed = path.lstat()
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(
        observed.st_mode,
    ):
        # Debian and Ubuntu ship /usr/bin/pg_dump, pg_restore and psql as
        # symlinks to /usr/share/postgresql-common/pg_wrapper, a dispatcher
        # that picks a versioned binary at run time. Refusing it is correct:
        # this ceremony pins the executable by device, inode, size and digest
        # so a swapped binary is detected, and a dispatcher chooses its target
        # AFTER that pin is taken. But `apt install postgresql-client` is how
        # almost everyone gets these tools, so the bare refusal read as a bug
        # with no remedy. Name the remedy instead.
        hint = ""
        if stat.S_ISLNK(observed.st_mode):
            try:
                target = str(path.readlink())
            except OSError:  # pragma: no cover - defensive
                target = "<unreadable>"
            hint = f" (symlink to {target})"
            if "pg_wrapper" in target:
                hint += (
                    ". This is the Debian/Ubuntu postgresql-client-common "
                    "wrapper. Put the versioned directory first on PATH, for "
                    "example PATH=/usr/lib/postgresql/18/bin:$PATH, so the "
                    "real binary is resolved. Its major version must match "
                    "the server's"
                )
        raise DatabaseRestoreRefused(
            f"PostgreSQL client is not a real regular file: {path}{hint}",
        )
    if os.name == "posix":
        if observed.st_uid not in {0, os.getuid()}:
            raise DatabaseRestoreRefused(
                f"PostgreSQL client has an untrusted owner: {path}",
            )
        if observed.st_mode & 0o022:
            raise DatabaseRestoreRefused(
                f"PostgreSQL client is group/world writable: {path}",
            )
        current = path.parent
        while True:
            ancestor = current.lstat()
            if stat.S_ISLNK(ancestor.st_mode) or not stat.S_ISDIR(
                ancestor.st_mode,
            ):
                raise DatabaseRestoreRefused(
                    f"PostgreSQL client ancestor is unsafe: {current}",
                )
            if ancestor.st_uid not in {0, os.getuid()}:
                raise DatabaseRestoreRefused(
                    f"PostgreSQL client ancestor has an untrusted owner: {current}",
                )
            if ancestor.st_mode & 0o022:
                raise DatabaseRestoreRefused(
                    f"PostgreSQL client ancestor is writable by another principal: {current}",
                )
            if current == current.parent:
                break
            current = current.parent


def _minimal_process_environment() -> dict[str, str]:
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
    }
    if os.name == "nt":
        for key in ("SYSTEMROOT", "WINDIR"):
            value = os.environ.get(key)
            if value:
                environment[key] = value
    return environment


def _run_identity_bound(
    tool: _Tool,
    arguments: list[str],
    *,
    environment: dict[str, str],
    text_output: bool,
) -> subprocess.CompletedProcess[Any]:
    before = tool.path.stat()
    if (
        int(before.st_dev),
        int(before.st_ino),
        int(before.st_size),
    ) != tool.identity or _sha256_file(tool.path) != tool.digest:
        raise DatabaseRestoreRefused(
            f"{tool.name} identity changed before execution",
        )
    result = subprocess.run(  # noqa: S603  fixed identity-bound executable, shell=False
        [str(tool.path), *arguments],
        env=environment,
        capture_output=True,
        text=text_output,
        check=False,
    )
    after = tool.path.stat()
    if (int(after.st_dev), int(after.st_ino), int(after.st_size)) != tool.identity or _sha256_file(
        tool.path
    ) != tool.digest:
        raise DatabaseRestoreRefused(
            f"{tool.name} identity changed during execution",
        )
    return result


def _resolve_tool(name: str) -> _Tool:
    candidate = shutil.which(name)
    if candidate is None:
        raise DatabaseRestoreRefused(
            f"restore: {name} was not found on PATH",
        )
    path = Path(candidate)
    _assert_trusted_path(path)
    observed = path.stat()
    try:
        digest = _sha256_file(path)
    except DatabaseRestoreRefused as refusal:
        # ``_sha256_file`` reaches ``_file_digest``, whose Windows arm is the
        # owner-private reader written for restore ARTEFACTS. A PostgreSQL
        # client installed the ordinary way is a shared system binary: not
        # owned by the invoking user and readable by others, so it fails that
        # rule and the operator is told their "restore artifact" cannot be
        # read, about a tool they did not choose the location of.
        #
        # The rule is not relaxed here. What changes is that the refusal says
        # which file it means, why a system binary trips it, and the one thing
        # that resolves it, because the alternative is an operator reading
        # "artifact" and looking at their backup.
        if os.name != "nt":
            raise
        message = (
            f"restore: {name} at {path} could not be verified. z4j reads the "
            f"PostgreSQL client binaries under the same owner-private rule it "
            f"uses for restore artefacts, and a client installed the usual way "
            f"on Windows does not meet it ({refusal}). Copy the PostgreSQL "
            f"client binaries into a directory you own privately and put that "
            f"directory first on PATH."
        )
        raise DatabaseRestoreRefused(message) from refusal
    probe = subprocess.run(  # noqa: S603  path identity was validated above
        [str(path), "--version"],
        env=_minimal_process_environment(),
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        raise DatabaseRestoreRefused(
            f"restore: {name} --version failed",
        )
    match = re.search(
        r"\(PostgreSQL\)\s+(\d+)(?:\.\d+)*",
        probe.stdout,
    )
    if match is None:
        raise DatabaseRestoreRefused(
            f"restore: {name} returned an unrecognized version",
        )
    return _Tool(
        name=name,
        path=path,
        digest=digest,
        identity=(
            int(observed.st_dev),
            int(observed.st_ino),
            int(observed.st_size),
        ),
        version=probe.stdout.strip(),
        major=int(match.group(1)),
    )


def _parse_target(database_url: str) -> _Target:
    url = make_url(database_url)
    if not url.drivername.startswith("postgresql"):
        raise DatabaseRestoreRefused(
            "PostgreSQL restore received a non-PostgreSQL URL",
        )
    if not url.host or "," in url.host or not url.database or not url.username:
        raise DatabaseRestoreRefused(
            "PostgreSQL restore requires one explicit host, database, "
            "and user; multi-host/service targets are refused",
        )
    unsupported_query = set(url.query) - {
        "sslmode",
        "sslrootcert",
        "sslcert",
        "sslkey",
    }
    if unsupported_query:
        raise DatabaseRestoreRefused(
            f"PostgreSQL restore cannot pin these URL options: {sorted(unsupported_query)}",
        )
    sslmode = str(url.query.get("sslmode", "disable"))
    if sslmode not in {
        "disable",
        "require",
        "verify-ca",
        "verify-full",
    }:
        raise DatabaseRestoreRefused(
            f"PostgreSQL restore cannot prove sslmode={sslmode!r}",
        )
    sslrootcert = url.query.get("sslrootcert")
    sslcert = url.query.get("sslcert")
    sslkey = url.query.get("sslkey")
    if sslmode in {"verify-ca", "verify-full"} and not sslrootcert:
        raise DatabaseRestoreRefused(
            f"PostgreSQL restore requires an explicit sslrootcert for sslmode={sslmode}",
        )
    if bool(sslcert) != bool(sslkey):
        raise DatabaseRestoreRefused(
            "PostgreSQL restore requires sslcert and sslkey together",
        )
    for raw_path in (sslrootcert, sslcert, sslkey):
        if raw_path is None:
            continue
        tls_path = Path(str(raw_path)).expanduser().resolve(strict=True)
        _assert_trusted_path(tls_path)
        if raw_path == sslkey and tls_path.stat().st_mode & 0o077:
            raise DatabaseRestoreRefused(
                "PostgreSQL TLS private key must be owner-private",
            )
    port = int(url.port or 5432)
    try:
        route_probe = socket.create_connection(
            (url.host, port),
            timeout=15,
        )
    except OSError as exc:
        raise DatabaseRestoreRefused(
            "PostgreSQL restore could not pin the target network route",
        ) from exc
    try:
        hostaddr = str(route_probe.getpeername()[0])
    finally:
        route_probe.close()
    return _Target(
        database_url=database_url,
        libpq_url=database_url.replace(
            "postgresql+asyncpg://",
            "postgresql://",
            1,
        ),
        host=url.host,
        hostaddr=hostaddr,
        port=port,
        database=url.database,
        username=url.username,
        password=url.password,
        sslmode=sslmode,
        sslrootcert=(
            str(Path(str(sslrootcert)).expanduser().resolve()) if sslrootcert is not None else None
        ),
        sslcert=(str(Path(str(sslcert)).expanduser().resolve()) if sslcert is not None else None),
        sslkey=(str(Path(str(sslkey)).expanduser().resolve()) if sslkey is not None else None),
    )


def _pinned_connection_parameters(
    target: _Target,
    *,
    autocommit: bool,
    row_factory: Any = None,
) -> dict[str, Any]:
    parameters: dict[str, Any] = {
        "host": target.host,
        "hostaddr": target.hostaddr,
        "port": target.port,
        "dbname": target.database,
        "user": target.username,
        "password": target.password,
        "sslmode": target.sslmode,
        # The reset manifest is compared across asyncpg snapshot reads and
        # this independently pinned psycopg coordinator.  Pin the latter
        # explicitly so a non-UTC server/database default cannot render the
        # same timestamptz instant with a different textual offset.
        "options": "-c timezone=UTC",
        "gssencmode": "disable",
        "autocommit": autocommit,
        "connect_timeout": 15,
        "application_name": "z4j-restore",
    }
    if target.sslrootcert is not None:
        parameters["sslrootcert"] = target.sslrootcert
    if target.sslcert is not None:
        parameters["sslcert"] = target.sslcert
    if target.sslkey is not None:
        parameters["sslkey"] = target.sslkey
    if row_factory is not None:
        parameters["row_factory"] = row_factory
    return parameters


async def _raw_pinned_connection(
    target: _Target,
    *,
    autocommit: bool,
    row_factory: Any = None,
) -> Any:
    from psycopg import AsyncConnection

    parameters = _pinned_connection_parameters(
        target,
        autocommit=autocommit,
        row_factory=row_factory,
    )
    await asyncio.to_thread(_LIBPQ_ENVIRONMENT_LOCK.acquire)
    ambient_keys = {key for key in os.environ if key.startswith("PG") or key in _LIBPQ_AMBIENT_KEYS}
    saved_environment = {key: os.environ[key] for key in ambient_keys}
    try:
        for key in ambient_keys:
            os.environ.pop(key, None)
        connection = await AsyncConnection.connect(**parameters)
    finally:
        for key in ambient_keys:
            os.environ.pop(key, None)
        os.environ.update(saved_environment)
        _LIBPQ_ENVIRONMENT_LOCK.release()
    return connection


async def _connect(target: _Target) -> _PinnedConnection:
    from psycopg.rows import dict_row

    connection = await _raw_pinned_connection(
        target,
        autocommit=True,
        row_factory=dict_row,
    )
    return _PinnedConnection(connection)


def _pinned_coordinator_engine(target: _Target) -> AsyncEngine:
    async def connect() -> Any:
        return await _raw_pinned_connection(
            target,
            autocommit=False,
        )

    return create_async_engine(
        "postgresql+psycopg://",
        pool_size=1,
        max_overflow=0,
        async_creator=connect,
    )


def _tls_file_manifest(path: str | None) -> dict[str, Any] | None:
    if path is None:
        return None
    file_path = Path(path)
    observed = file_path.stat()
    return {
        "path": path,
        "digest": _sha256_file(file_path),
        "identity": [
            int(observed.st_dev),
            int(observed.st_ino),
            int(observed.st_size),
        ],
    }


async def _target_identity(target: _Target) -> dict[str, Any]:
    connection = await _connect(target)
    try:
        row = await connection.fetchrow(
            """
            SELECT
              current_database() AS database_name,
              (
                SELECT oid::bigint FROM pg_database
                WHERE datname = current_database()
              ) AS database_oid,
              current_setting('server_version_num')::bigint
                AS server_version_num,
              (pg_control_system()).system_identifier::text
                AS system_identifier,
              host(inet_server_addr()) AS server_address,
              inet_server_port() AS server_port
            """,
        )
        if row is None:
            raise DatabaseRestoreRefused(
                "PostgreSQL physical target identity is unavailable",
            )
        tls_files = {
            name: _tls_file_manifest(path)
            for name, path in (
                ("root_certificate", target.sslrootcert),
                ("client_certificate", target.sslcert),
                ("client_key", target.sslkey),
            )
        }
        return {
            "database_name": str(row["database_name"]),
            "database_oid": int(row["database_oid"]),
            "server_version_num": int(
                row["server_version_num"],
            ),
            "server_major": int(row["server_version_num"]) // 10000,
            "system_identifier": str(row["system_identifier"]),
            "server_address": str(row["server_address"]),
            "server_port": int(row["server_port"]),
            "client_host": target.host,
            "client_hostaddr": target.hostaddr,
            "client_port": target.port,
            "client_user": target.username,
            "tls": {
                "mode": target.sslmode,
                "certificate_hostname": target.host,
                "files": tls_files,
            },
        }
    finally:
        await connection.close()


def _passfile_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace(":", "\\:")


def _write_passfile(path: Path, target: _Target) -> None:
    """Write the short-lived libpq password file.

    The bytes are flushed but the directory entry deliberately is not. Every
    caller removes this file in a ``finally``, so a crash that loses the name
    loses a copy of the database password, which is the outcome to prefer.
    """

    if target.password is None:
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    payload = (
        ":".join(
            _passfile_value(value)
            for value in (
                target.host,
                str(target.port),
                target.database,
                target.username,
                target.password,
            )
        )
        + "\n"
    ).encode()
    fd = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(fd, payload[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)


def _connection_environment(
    target: _Target,
    *,
    passfile: Path,
    hostaddr: str,
) -> dict[str, str]:
    environment = _minimal_process_environment()
    environment.update(
        {
            "PGHOST": target.host,
            "PGHOSTADDR": hostaddr,
            "PGPORT": str(target.port),
            "PGDATABASE": target.database,
            "PGUSER": target.username,
            "PGSSLMODE": target.sslmode,
            "PGCONNECT_TIMEOUT": "15",
        },
    )
    if target.password is not None:
        environment["PGPASSFILE"] = str(passfile)
    if target.sslrootcert is not None:
        environment["PGSSLROOTCERT"] = target.sslrootcert
    if target.sslcert is not None:
        environment["PGSSLCERT"] = target.sslcert
    if target.sslkey is not None:
        environment["PGSSLKEY"] = target.sslkey
    return environment


def _tool_manifest(tool: _Tool) -> dict[str, Any]:
    return {
        "name": tool.name,
        "path": str(tool.path),
        "digest": tool.digest,
        "identity": list(tool.identity),
        "version": tool.version,
        "major": tool.major,
    }


def _inspect_function_definitions(
    pg_restore: _Tool,
    archive: Path,
    *,
    expected_digest: str,
) -> str:
    result = _run_identity_bound(
        pg_restore,
        ["--schema-only", "--file=-", str(archive)],
        environment=_minimal_process_environment(),
        text_output=False,
    )
    if result.returncode != 0:
        stderr = bytes(result.stderr).decode(errors="replace")
        raise DatabaseRestoreRefused(
            f"restore archive schema extraction failed: {stderr.strip()}",
        )
    raw = bytes(result.stdout)
    if len(raw) > _MAX_SCHEMA_EXTRACT_BYTES:
        raise DatabaseRestoreRefused(
            "restore archive schema extraction is oversized",
        )
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise DatabaseRestoreRefused(
            "restore archive schema extraction is not UTF-8",
        ) from exc
    definitions: list[str] = []
    capture = False
    for line in lines:
        if line.startswith("CREATE FUNCTION public."):
            if capture:
                raise DatabaseRestoreRefused(
                    "restore archive has nested function definitions",
                )
            capture = True
        if capture:
            definitions.append(line)
            if "$$;" in line:
                capture = False
    if capture:
        raise DatabaseRestoreRefused(
            "restore archive has an unterminated function definition",
        )
    canonical = "\n".join(definitions) + "\n"
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    if digest != expected_digest:
        raise DatabaseRestoreRefused(
            "restore archive executable function definitions do not "
            "match the release-head contract",
        )
    return digest


def _inspect_schema_definitions(
    pg_restore: _Tool,
    archive: Path,
    *,
    expected_digest: str,
) -> str:
    """Hash every static schema definition, excluding runtime partitions."""

    result = _run_identity_bound(
        pg_restore,
        ["--schema-only", "--file=-", str(archive)],
        environment=_minimal_process_environment(),
        text_output=False,
    )
    if result.returncode != 0:
        stderr = bytes(result.stderr).decode(errors="replace")
        raise DatabaseRestoreRefused(
            f"restore archive schema extraction failed: {stderr.strip()}",
        )
    raw = bytes(result.stdout)
    if len(raw) > _MAX_SCHEMA_EXTRACT_BYTES:
        raise DatabaseRestoreRefused(
            "restore archive schema extraction is oversized",
        )
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise DatabaseRestoreRefused(
            "restore archive schema extraction is not UTF-8",
        ) from exc

    blocks: list[str] = []
    block_identity: tuple[str, str, str] | None = None
    block_lines: list[str] = []

    def finish_block() -> None:
        if block_identity is None:
            return
        name, object_type, schema = block_identity
        if any(_RUNTIME_SCHEMA_OBJECT.match(token) for token in name.split()):
            return
        normalized: list[str] = []
        for line in block_lines:
            canonical_line = " ".join(line.split())
            if (
                not canonical_line
                or canonical_line.startswith("--")
                or canonical_line.startswith("\\restrict")
                or canonical_line.startswith("\\unrestrict")
                or " OWNER TO " in f" {canonical_line} "
            ):
                continue
            normalized.append(canonical_line)
        blocks.append(
            f"{object_type}|{schema}|{name}\n" + "\n".join(normalized),
        )

    for line in lines:
        header = _SCHEMA_BLOCK_HEADER.match(line)
        if header is not None:
            finish_block()
            block_identity = (
                header.group(1),
                header.group(2),
                header.group(3),
            )
            block_lines = []
        elif block_identity is not None:
            block_lines.append(line)
    finish_block()
    canonical = "\n\n".join(blocks) + "\n"
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    if digest != expected_digest:
        # Report both sides. The reset path already does, and without it an
        # operator (or a maintainer adding a migration) is told only that a
        # fail-closed contract refused them, with no way to see what was
        # actually observed. The digest is a hash of public schema text, not
        # a secret.
        raise DatabaseRestoreRefused(
            "restore archive static schema definitions do not match "
            f"the recognized migration-head contract "
            f"(observed={digest}, expected={expected_digest})",
        )
    return digest


def _toc_public_object(entry: str, prefix: str) -> str:
    remainder = entry.removeprefix(prefix)
    if remainder == entry or not remainder:
        raise DatabaseRestoreRefused(
            f"restore archive has malformed TOC entry: {entry}",
        )
    return remainder.rsplit(" ", 1)[0]


def _inspect_toc(  # noqa: PLR0912, PLR0915
    pg_restore: _Tool,
    archive: Path,
    *,
    source_head: str,
) -> tuple[str, str]:
    result = _run_identity_bound(
        pg_restore,
        ["--list", str(archive)],
        environment=_minimal_process_environment(),
        text_output=True,
    )
    if result.returncode != 0:
        raise DatabaseRestoreRefused(
            f"restore source is not a readable custom-format archive: {str(result.stderr).strip()}",
        )
    entries: list[str] = []
    for raw_line in str(result.stdout).splitlines():
        if not raw_line or raw_line.startswith(";"):
            continue
        match = _TOC_LINE.match(raw_line)
        if match is None:
            raise DatabaseRestoreRefused(
                "restore archive TOC contains an unrecognized entry",
            )
        entry = " ".join(match.group(1).split())
        upper = f" {entry.upper()} "
        if any(token in upper for token in _DANGEROUS_TOC_CLASSES):
            raise DatabaseRestoreRefused(
                f"restore archive contains forbidden TOC entry: {entry}",
            )
        if " SCHEMA " in upper and not (
            entry.endswith(" public") or entry.startswith("SCHEMA - public ")
        ):
            raise DatabaseRestoreRefused(
                f"restore archive contains a non-public schema: {entry}",
            )
        entries.append(entry)
    functions: set[str] = set()
    extensions: set[str] = set()
    types: set[str] = set()
    allowed_tables = RESET_ORM_TABLES | {"alembic_version"}
    for entry in entries:
        if entry.startswith("EXTENSION - "):
            extensions.add(entry.removeprefix("EXTENSION - ").split()[0])
            continue
        if entry.startswith("COMMENT - EXTENSION "):
            extension = entry.removeprefix("COMMENT - EXTENSION ").split()[0]
            if extension not in _RELEASE_EXTENSIONS:
                raise DatabaseRestoreRefused(
                    f"restore archive has an unknown extension comment: {entry}",
                )
            continue
        if entry.startswith("TYPE public "):
            types.add(_toc_public_object(entry, "TYPE public "))
            continue
        if entry.startswith("FUNCTION public "):
            functions.add(_toc_public_object(entry, "FUNCTION public "))
            continue
        table_prefix = next(
            (
                prefix
                for prefix in (
                    "TABLE DATA public ",
                    "TABLE ATTACH public ",
                    "TABLE public ",
                )
                if entry.startswith(prefix)
            ),
            None,
        )
        if table_prefix is not None:
            table_name = _toc_public_object(entry, table_prefix)
            if (
                table_name not in allowed_tables
                and _RUNTIME_PARTITION.fullmatch(table_name) is None
            ):
                raise DatabaseRestoreRefused(
                    f"restore archive has an unknown table: {table_name}",
                )
            continue
        if entry.startswith(
            (
                "CONSTRAINT public ",
                "DEFAULT public ",
                "FK CONSTRAINT public ",
                "INDEX public ",
                "INDEX ATTACH public ",
                "SEQUENCE OWNED BY public ",
                "SEQUENCE SET public ",
                "SEQUENCE public ",
                "TRIGGER public ",
            ),
        ):
            continue
        raise DatabaseRestoreRefused(
            f"restore archive has an unclassified TOC entry: {entry}",
        )
    if extensions != _RELEASE_EXTENSIONS:
        raise DatabaseRestoreRefused(
            "restore archive extension manifest differs from release head",
        )
    if types != _RELEASE_TYPES:
        raise DatabaseRestoreRefused(
            "restore archive type manifest differs from release head",
        )
    boundary_d_head = source_head in _BOUNDARY_D_SOURCE_HEADS
    expected_functions = (
        _RELEASE_FUNCTION_SIGNATURES if boundary_d_head else _LEGACY_FUNCTION_SIGNATURES
    )
    if functions != expected_functions:
        raise DatabaseRestoreRefused(
            "restore archive function manifest differs from its recognized head",
        )
    _inspect_function_definitions(
        pg_restore,
        archive,
        expected_digest=(
            _RELEASE_FUNCTION_DEFINITIONS_DIGEST
            if boundary_d_head
            else _LEGACY_FUNCTION_DEFINITIONS_DIGEST
        ),
    )
    schema_definition_digests = _SCHEMA_DEFINITIONS_DIGESTS_BY_HEAD.get(source_head)
    if schema_definition_digests is None:
        raise DatabaseRestoreRefused(
            f"restore archive migration head has no schema contract: {source_head}",
        )
    expected_schema_definitions_digest = schema_definition_digests.get(
        pg_restore.major,
    )
    if expected_schema_definitions_digest is None:
        raise DatabaseRestoreRefused(
            "restore PostgreSQL client major is not in the reviewed "
            f"archive schema contract set: {pg_restore.major}",
        )
    schema_definitions_digest = _inspect_schema_definitions(
        pg_restore,
        archive,
        expected_digest=expected_schema_definitions_digest,
    )
    required = ("TABLE DATA public alembic_version",)
    if boundary_d_head:
        required += (
            "TABLE public audit_chain_state",
            "TABLE public schedule_revision_state",
            "TABLE public schedule_external_epoch_allocator",
        )
    if any(not any(fragment in entry for entry in entries) for fragment in required):
        raise DatabaseRestoreRefused(
            f"restore archive lacks objects required at head {source_head}",
        )
    canonical = (
        "\n".join(sorted(entries)) + "\nSCHEMA DEFINITIONS SHA256 " + schema_definitions_digest
    )
    return canonical, hashlib.sha256(canonical.encode()).hexdigest()


def _copy_unescape(value: str) -> str | None:
    if value == r"\N":
        return None
    output: list[str] = []
    index = 0
    escapes = {
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "\\": "\\",
    }
    while index < len(value):
        character = value[index]
        if character != "\\":
            output.append(character)
            index += 1
            continue
        index += 1
        if index >= len(value):
            raise DatabaseRestoreRefused(
                "restore archive COPY field ends in an escape",
            )
        escaped = value[index]
        if escaped in escapes:
            output.append(escapes[escaped])
            index += 1
            continue
        if escaped.isdigit():
            digits = value[index : index + 3]
            if not digits or any(digit not in "01234567" for digit in digits):
                raise DatabaseRestoreRefused(
                    "restore archive COPY field has a malformed octal escape",
                )
            output.append(chr(int(digits, 8)))
            index += len(digits)
            continue
        output.append(escaped)
        index += 1
    return "".join(output)


#: The canonical row order of every archive table that feeds the manifest.
#:
#: These mirror the ``ORDER BY`` the SQLite backend reads the same tables with,
#: so the two backends describe the same logical database in the same order.
_ARCHIVE_TABLE_ORDER_COLUMNS: dict[str, tuple[str, ...]] = {
    "alembic_version": ("version_num",),
    "schedule_revision_state": ("singleton_id",),
    "schedule_external_epoch_allocator": ("singleton_id",),
    "schedule_external_streams": ("id",),
    "schedule_external_stream_epochs": ("epoch_number", "epoch_uuid"),
    "schedule_external_control_operations": ("id",),
}
#: Columns whose COPY text is a number, so ``10`` sorts after ``9``.
_ARCHIVE_NUMERIC_ORDER_COLUMNS = frozenset({"epoch_number"})


def _order_component(column: str, value: str | None) -> tuple[int, int, str]:
    """Rank one column value so absent, numeric and text never compare."""

    if value is None:
        return (0, 0, "")
    if column in _ARCHIVE_NUMERIC_ORDER_COLUMNS:
        try:
            return (1, int(value), "")
        except ValueError:
            return (2, 0, value)
    return (2, 0, value)


def _archive_row_order_key(
    table_name: str,
    row: dict[str, str | None],
) -> tuple[tuple[int, int, str], ...]:
    """Return one total, value-derived order key for an extracted row."""

    key = tuple(
        _order_component(column, row.get(column))
        for column in _ARCHIVE_TABLE_ORDER_COLUMNS.get(table_name, ())
    )
    # The declared columns are unique in a well-formed source, but a malformed
    # one must still order totally rather than fall back to physical order, so
    # the whole canonical row is the last component.
    return (*key, (2, 0, canonical_json(row).decode()))


def _extract_table(
    pg_restore: _Tool,
    archive: Path,
    table_name: str,
) -> list[dict[str, str | None]]:
    """Read one archive table in a fixed, value-derived row order.

    pg_restore replays a table in physical order, so a VACUUM FULL or any row
    rewrite between two dumps of the same logical database reorders it.  The
    manifest built from these rows is what the stopped-executor attestation
    challenge is derived from, and a resumed operation re-derives that
    challenge, so an unordered read would let the same source produce a
    different challenge on the second run and strand the operator mid ceremony
    with no way to finish it.
    """

    result = _run_identity_bound(
        pg_restore,
        [
            "--data-only",
            f"--table={table_name}",
            "--file=-",
            str(archive),
        ],
        environment=_minimal_process_environment(),
        text_output=False,
    )
    if result.returncode != 0:
        stderr = bytes(result.stderr).decode(errors="replace")
        raise DatabaseRestoreRefused(
            f"restore archive table extraction failed for {table_name}: {stderr.strip()}",
        )
    raw = bytes(result.stdout)
    if len(raw) > _MAX_COPY_EXTRACT_BYTES:
        raise DatabaseRestoreRefused(
            f"restore archive extraction is oversized for {table_name}",
        )
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise DatabaseRestoreRefused(
            f"restore archive table {table_name} is not UTF-8",
        ) from exc
    rows: list[dict[str, str | None]] = []
    columns: list[str] | None = None
    for line in lines:
        match = _COPY_HEADER.match(line)
        if match is not None:
            if match.group(1) != table_name or columns is not None:
                raise DatabaseRestoreRefused(
                    f"restore archive COPY header is ambiguous for {table_name}",
                )
            columns = [column.strip() for column in match.group(2).split(",")]
            continue
        if columns is None:
            continue
        if line == r"\.":
            columns = None
            continue
        values = line.split("\t")
        if len(values) != len(columns):
            raise DatabaseRestoreRefused(
                f"restore archive COPY row is malformed for {table_name}",
            )
        rows.append(
            {column: _copy_unescape(value) for column, value in zip(columns, values, strict=True)},
        )
    if columns is not None:
        raise DatabaseRestoreRefused(
            f"restore archive COPY stream is unterminated for {table_name}",
        )
    rows.sort(key=lambda row: _archive_row_order_key(table_name, row))
    return rows


def _single_int(
    rows: list[dict[str, str | None]],
    column: str,
    table_name: str,
) -> int:
    if len(rows) != 1 or rows[0].get(column) is None:
        raise DatabaseRestoreRefused(
            f"restore archive {table_name} singleton is malformed",
        )
    return int(str(rows[0][column]))


def _assert_activated_boundary_singleton(
    rows: list[dict[str, str | None]],
    table_name: str,
) -> None:
    """Refuse a source claiming an activated head without activated state.

    This has to run here, at preflight, and not on the restored database.  The
    only other place the unactivated state is noticed is the authenticated
    snapshot taken after ``pg_restore --clean --if-exists`` has already
    overwritten the live target, which turns a source that should never have
    been accepted into a destroyed database plus a retained fence.  The SQLite
    backend refuses the same archive with nothing touched, and the two
    backends have to agree about the same logical database.

    ``guard_version`` arrives from the archive as COPY text, so the activated
    value is the text PostgreSQL prints for the integer 1.
    """

    if len(rows) != 1 or rows[0].get("guard_version") != "1":
        raise DatabaseRestoreRefused(
            f"restore archive {table_name} is not Boundary-D activated",
        )


def _archive_source_head(
    pg_restore: _Tool,
    archive: Path,
) -> str:
    versions = _extract_table(pg_restore, archive, "alembic_version")
    if len(versions) != 1 or set(versions[0]) != {"version_num"}:
        raise DatabaseRestoreRefused(
            "restore archive has a malformed migration head",
        )
    head = str(versions[0]["version_num"])
    if head not in _SUPPORTED_SOURCE_HEADS:
        raise DatabaseRestoreRefused(
            f"this release cannot restore a backup taken at migration head "
            f"{head!r}. Supported heads are "
            f"{', '.join(sorted(_SUPPORTED_SOURCE_HEADS))}. Install the z4j "
            f"release matching that head, restore there, then upgrade.",
        )
    return head


def _archive_source_authority(
    pg_restore: _Tool,
    archive: Path,
    *,
    source_head: str,
    archive_digest: str,
    toc_digest: str,
) -> dict[str, Any]:
    if source_head not in _SUPPORTED_SOURCE_HEADS:
        raise DatabaseRestoreRefused(
            f"restore archive migration head has no source authority: {source_head}",
        )
    revisions = _extract_table(
        pg_restore,
        archive,
        "schedule_revision_state",
    )
    if source_head not in _BOUNDARY_D_SOURCE_HEADS:
        # Only the pre-Boundary-D legacy head takes the stub. Every other
        # supported head shipped D activated, so its revision, epoch and
        # external-executor authority are read out of the archive below.
        legacy_revision = (
            0
            if not revisions
            else _single_int(
                revisions,
                "current_revision",
                "schedule_revision_state",
            )
        )
        external = {
            "allocator_digest": release_manifest_digest([]),
            "stream_digest": release_manifest_digest([]),
            "epoch_digest": release_manifest_digest([]),
            "operation_digest": release_manifest_digest([]),
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
        source_manifest = {
            "archive_digest": archive_digest,
            "toc_digest": toc_digest,
            "source_head": source_head,
            "revision": legacy_revision,
            "revision_classification": ("pre_d_empty" if not revisions else "legacy_singleton"),
            "epoch": 0,
            "external_authority_manifest": external,
        }
        return {
            **source_manifest,
            "manifest_digest": release_manifest_digest(source_manifest),
        }
    allocators = _extract_table(
        pg_restore,
        archive,
        "schedule_external_epoch_allocator",
    )
    _assert_activated_boundary_singleton(revisions, "schedule_revision_state")
    _assert_activated_boundary_singleton(
        allocators,
        "schedule_external_epoch_allocator",
    )
    streams = _extract_table(
        pg_restore,
        archive,
        "schedule_external_streams",
    )
    epochs = _extract_table(
        pg_restore,
        archive,
        "schedule_external_stream_epochs",
    )
    operations = [
        row
        for row in _extract_table(
            pg_restore,
            archive,
            "schedule_external_control_operations",
        )
        if row.get("status") in {"PENDING", "CLAIMED", "AMBIGUOUS"}
    ]

    def executor(row: dict[str, str | None]) -> bool:
        return any(
            row.get(column) is not None
            for column in (
                "authorized_adapter_instance_id",
                "executor_agent_id",
                "executor_registry_owner_id",
                "executor_session_generation",
            )
        )

    stream_authority = [
        {
            "stream_id": row.get("id"),
            "epoch_uuid": row.get("current_epoch_uuid"),
            "epoch_number": int(str(row["current_epoch_number"])),
            "phase": row.get("phase"),
            "adapter_instance_id": row.get(
                "authorized_adapter_instance_id",
            ),
            "agent_id": row.get("executor_agent_id"),
            "registry_owner_id": row.get(
                "executor_registry_owner_id",
            ),
            "session_generation": row.get(
                "executor_session_generation",
            ),
            "worker_id": row.get("executor_worker_id"),
        }
        for row in streams
        if executor(row)
    ]
    epoch_authority = [
        {
            "stream_id": row.get("stream_id"),
            "epoch_uuid": row.get("epoch_uuid"),
            "epoch_number": int(str(row["epoch_number"])),
            "phase": row.get("phase"),
            "adapter_instance_id": row.get(
                "authorized_adapter_instance_id",
            ),
            "agent_id": row.get("executor_agent_id"),
            "registry_owner_id": row.get(
                "executor_registry_owner_id",
            ),
            "session_generation": row.get(
                "executor_session_generation",
            ),
            "worker_id": row.get("executor_worker_id"),
        }
        for row in epochs
        if executor(row)
    ]
    operation_authority = [
        {
            "operation_id": row.get("id"),
            "command_id": row.get("command_id"),
            "stream_id": row.get("stream_id"),
            "epoch_uuid": row.get("epoch_uuid"),
            "epoch_number": int(str(row["epoch_number"])),
            "status": row.get("status"),
            "adapter_instance_id": row.get("adapter_instance_id"),
            "agent_id": row.get("agent_id"),
            "registry_owner_id": row.get("registry_owner_id"),
            "session_generation": row.get("session_generation"),
            "dispatch_lease": row.get("dispatch_lease"),
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
            stream_authority or epoch_authority or operation_authority
        ),
    }
    source_manifest = {
        "archive_digest": archive_digest,
        "toc_digest": toc_digest,
        "source_head": source_head,
        "revision": _single_int(
            revisions,
            "current_revision",
            "schedule_revision_state",
        ),
        "epoch": _single_int(
            allocators,
            "current_epoch_number",
            "schedule_external_epoch_allocator",
        ),
        "external_authority_manifest": external,
    }
    return {
        **source_manifest,
        "manifest_digest": release_manifest_digest(source_manifest),
    }


def _fence_literal(payload: dict[str, Any]) -> str:
    encoded = canonical_json(payload).decode()
    if len(encoded) > 16_384:
        raise DatabaseRestoreRefused(
            "PostgreSQL restore fence envelope is oversized",
        )
    return encoded.replace("'", "''")


async def _set_fence(
    target: _Target,
    envelope: dict[str, Any],
) -> None:
    connection = await _connect(target)
    try:
        quoted_database = target.database.replace('"', '""')
        literal = _fence_literal(envelope)
        await connection.execute(
            f"ALTER DATABASE \"{quoted_database}\" SET z4j.restore_pending = '{literal}'",
        )
    finally:
        await connection.close()
    await _verify_fence(target, envelope)


async def _read_fence(target: _Target) -> dict[str, Any] | None:
    connection = await _connect(target)
    try:
        row = await connection.fetchrow(
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
    finally:
        await connection.close()
    settings = [] if row is None else list(row["setconfig"] or [])
    matches = [
        str(value).removeprefix("z4j.restore_pending=")
        for value in settings
        if str(value).startswith("z4j.restore_pending=")
    ]
    if not matches:
        return None
    if len(matches) != 1:
        raise DatabaseRestoreRefused(
            "PostgreSQL restore fence has duplicate catalog entries",
        )
    raw = matches[0]
    try:
        parsed = json.loads(str(raw))
    except json.JSONDecodeError as exc:
        raise DatabaseRestoreRefused(
            "PostgreSQL restore fence is malformed",
        ) from exc
    if not isinstance(parsed, dict):
        raise DatabaseRestoreRefused(
            "PostgreSQL restore fence is not an object",
        )
    return parsed


async def _verify_fence(
    target: _Target,
    envelope: dict[str, Any],
) -> None:
    observed = await _read_fence(target)
    if observed != envelope:
        raise DatabaseRestoreRefused(
            "PostgreSQL restore fence read-back mismatch",
        )


async def _clear_fence(target: _Target) -> None:
    connection = await _connect(target)
    try:
        quoted_database = target.database.replace('"', '""')
        await connection.execute(
            f'ALTER DATABASE "{quoted_database}" RESET z4j.restore_pending',
        )
    finally:
        await connection.close()
    if await _read_fence(target) is not None:
        raise DatabaseRestoreRefused(
            "PostgreSQL restore fence remained after RESET",
        )


async def _recover_committed_finalization(
    target: _Target,
    *,
    marker_id: str,
    operation_id: uuid.UUID,
    source_digest: str,
    settings: Settings | None = None,
    connection: AsyncConnection | None = None,
) -> dict[str, Any]:
    active_settings = settings or Settings()
    if connection is None:
        engine = _pinned_coordinator_engine(target)
        try:
            async with engine.connect() as owned_connection:
                return await _recover_committed_finalization(
                    target,
                    marker_id=marker_id,
                    operation_id=operation_id,
                    source_digest=source_digest,
                    settings=active_settings,
                    connection=owned_connection,
                )
        finally:
            await engine.dispose()
    if connection.in_transaction():
        raise DatabaseRestoreRefused(
            "PostgreSQL committed restore recovery lacks a fresh authentication transaction",
        )

    isolated = await connection.execution_options(
        isolation_level="REPEATABLE READ",
    )
    async with isolated.begin():
        result = await isolated.execute(
            text(
                """
                SELECT
                  CAST(id AS text) AS marker_id,
                  action,
                  target_id,
                  CAST(metadata AS text) AS metadata
                FROM audit_log
                WHERE id = CAST(:marker_id AS uuid)
                FOR SHARE
                """
            ),
            {"marker_id": marker_id},
        )
        row = result.mappings().one_or_none()
        # The marker row is locked but still untrusted. Authenticate the entire
        # active audit generation in this same repeatable-read transaction
        # before consulting any marker field. A delete/reinsert, HMAC edit, or
        # chain-state forgery left by the crash window must therefore fail
        # closed and can never authorize fence removal.
        await authenticated_database_snapshot(
            target.database_url,
            active_settings,
            connection=isolated,
        )
        return _validate_committed_finalization_marker(
            row,
            marker_id=marker_id,
            operation_id=operation_id,
            source_digest=source_digest,
        )


async def _assert_coordinator_still_owns_the_ceremony(
    connection: _PinnedConnection,
) -> None:
    """Refuse unless the running coordinator still holds the schema lock.

    Committing part way through a ceremony is only safe while the lock
    outlives a transaction, which the session-scoped form does and the
    transaction-scoped form does not. A second session is the only one that
    can tell the two apart: it succeeds in taking the lock precisely when the
    coordinator has stopped holding it.
    """

    taken = await connection.fetchrow(
        "SELECT pg_try_advisory_lock($1) AS taken",
        SCHEMA_TRANSITION_ADVISORY_LOCK_KEY,
    )
    if taken is None or not bool(taken["taken"]):
        return
    # Session-scoped, so closing this connection is what releases it; do it
    # explicitly anyway rather than leaving the lifetime to the pool.
    with contextlib.suppress(Exception):
        await connection.execute(
            "SELECT pg_advisory_unlock($1)",
            SCHEMA_TRANSITION_ADVISORY_LOCK_KEY,
        )
    raise DatabaseRestoreRefused(
        "PostgreSQL restore coordinator no longer holds the schema transition lock",
    )


async def _assert_finalization_is_durable(
    target: _Target,
    *,
    finalization: Mapping[str, Any],
    operation_id: uuid.UUID,
    source_digest: str,
) -> None:
    """Prove the finalization outlived its commit, from a second connection.

    A connection can see its own uncommitted work, so the coordinator is the
    one place in the system that cannot answer whether the rebases and the
    signed marker are durable. Put the question to a connection that has no
    such privilege, and require it to describe the same finalization the
    caller is about to publish: anything less and the startup fence would come
    down on the strength of writes a crash can still take back.

    Deliberately a plain read rather than the authenticated recovery used on
    resume. The audit generation was already authenticated by finalization
    itself, and the reader that would repeat that here has to take the
    schema-transition lock this coordinator is still holding, which is a wait
    that never ends. What no earlier check could establish, and what this one
    does, is that the writes are visible outside the transaction that made
    them.
    """

    revision_rebase = finalization["revision_rebase"]
    epoch_rebase = finalization["epoch_rebase"]
    connection = await _connect(target)
    try:
        await _assert_coordinator_still_owns_the_ceremony(connection)
        row = await connection.fetchrow(
            """
            SELECT
              marker.action AS action,
              marker.target_id AS target_id,
              marker.metadata::text AS metadata,
              revision.current_revision AS current_revision,
              revision.change_log_pruned_through AS pruned_through,
              allocator.current_epoch_number AS current_epoch
            FROM audit_log AS marker
            CROSS JOIN schedule_revision_state AS revision
            CROSS JOIN schedule_external_epoch_allocator AS allocator
            WHERE marker.id = $1::uuid
            """,
            str(finalization["marker_id"]),
        )
    finally:
        await connection.close()
    if row is None:
        raise DatabaseRestoreRefused(
            "PostgreSQL restore finalization did not survive its own commit",
        )
    try:
        metadata = json.loads(str(row["metadata"]))
    except json.JSONDecodeError as exc:
        raise DatabaseRestoreRefused(
            "PostgreSQL committed restore marker metadata is malformed",
        ) from exc
    if (
        str(row["action"]) != "audit.database_restored"
        or str(row["target_id"]) != str(operation_id)
        or metadata.get("operation_id") != str(operation_id)
        or metadata.get("source_stage_digest") != source_digest
        or metadata.get("migration_head") != RELEASE_MIGRATION_HEAD
        or metadata.get("schema_contract_digest") != finalization["schema_contract_digest"]
        or metadata.get("known_head_result") != finalization["known_head_result"]
        or metadata.get("revision_rebase") != revision_rebase
        or metadata.get("epoch_rebase") != epoch_rebase
    ):
        raise DatabaseRestoreRefused(
            "PostgreSQL committed restore marker differs from the one being published",
        )
    # The marker is one row of the finalization transaction. These are the
    # rows the restore exists to move, so a committed marker beside stale
    # boundaries would mean a torn write, not a finished restore.
    if (
        int(row["current_revision"]) != int(revision_rebase["final_revision"])
        or int(row["pruned_through"]) != int(revision_rebase["barrier_revision"])
        or int(row["current_epoch"]) != int(epoch_rebase["barrier_epoch"])
    ):
        raise DatabaseRestoreRefused(
            "PostgreSQL committed restore boundaries do not match the signed marker",
        )


async def _assert_restored_activation_is_durable(target: _Target) -> None:
    """Prove the restore-bound activation reached the release head, durably."""

    connection = await _connect(target)
    try:
        await _assert_coordinator_still_owns_the_ceremony(connection)
        row = await connection.fetchrow(
            "SELECT version_num FROM alembic_version",
        )
    finally:
        await connection.close()
    if row is None or str(row["version_num"]) != RELEASE_MIGRATION_HEAD:
        raise DatabaseRestoreRefused(
            "PostgreSQL restore-bound audit activation did not survive its own commit",
        )


async def _assert_rollback_marker_is_durable(
    target: _Target,
    *,
    marker_id: str,
    operation_id: uuid.UUID,
    binding: Mapping[str, Any],
    recovered_revision: int,
    recovered_epoch: int,
) -> None:
    """Prove the rollback marker outlived its commit, from a second connection.

    Same reason as the restore side, and the same shape: the connection that
    wrote the marker is the one connection whose answer means nothing, and the
    fence comes down next.
    """

    connection = await _connect(target)
    try:
        await _assert_coordinator_still_owns_the_ceremony(connection)
        row = await connection.fetchrow(
            """
            SELECT
              marker.metadata::text AS metadata,
              revision.current_revision AS current_revision,
              allocator.current_epoch_number AS current_epoch
            FROM audit_log AS marker
            CROSS JOIN schedule_revision_state AS revision
            CROSS JOIN schedule_external_epoch_allocator AS allocator
            WHERE marker.id = $1::uuid
              AND marker.action = 'audit.database_restore_rolled_back'
              AND marker.target_id = $2
            """,
            marker_id,
            str(operation_id),
        )
    finally:
        await connection.close()
    if row is None:
        raise DatabaseRestoreRefused(
            "PostgreSQL rollback marker did not survive its own commit",
        )
    try:
        metadata = json.loads(str(row["metadata"]))
    except json.JSONDecodeError as exc:
        raise DatabaseRestoreRefused(
            "PostgreSQL committed rollback marker metadata is malformed",
        ) from exc
    if any(metadata.get(field) != value for field, value in binding.items()):
        raise DatabaseRestoreRefused(
            "PostgreSQL committed rollback marker binding is invalid",
        )
    if (
        int(row["current_revision"]) != recovered_revision
        or int(row["current_epoch"]) != recovered_epoch
    ):
        raise DatabaseRestoreRefused(
            "PostgreSQL committed rollback boundaries do not match the recovered target",
        )


async def _committed_finalization_marker_id(
    connection: AsyncConnection,
    *,
    operation_id: uuid.UUID,
) -> str | None:
    """Name the restore marker this operation already committed, if any.

    The marker commits inside ``finalize_restored_database`` and the fence
    only learns of it afterwards, so between those two the row itself is the
    only record that the restore succeeded. It therefore has to be found by
    the operation it names rather than by an id the fence never got to store.
    Nothing here trusts the row: ``_recover_committed_finalization`` is what
    authenticates it before any field of it is believed.
    """

    await connection.rollback()
    if not (
        await connection.execute(
            text("SELECT to_regclass('public.audit_log') IS NOT NULL"),
        )
    ).scalar_one():
        await connection.rollback()
        return None
    marker_ids = (
        (
            await connection.execute(
                text(
                    """
                    SELECT CAST(id AS text) AS marker_id
                    FROM audit_log
                    WHERE action = 'audit.database_restored'
                      AND target_id = :operation_id
                    """,
                ),
                {"operation_id": str(operation_id)},
            )
        )
        .scalars()
        .all()
    )
    await connection.rollback()
    if not marker_ids:
        return None
    if len(marker_ids) != 1:
        raise DatabaseRestoreRefused(
            "PostgreSQL committed restore marker is duplicated",
        )
    return str(marker_ids[0])


def _validate_committed_finalization_marker(
    row: Any,
    *,
    marker_id: str,
    operation_id: uuid.UUID,
    source_digest: str,
) -> dict[str, Any]:
    """Validate fields only after the enclosing audit snapshot authenticated."""
    try:
        action = str(row["action"])
        target_id = str(row["target_id"])
    except (KeyError, TypeError):
        action = ""
        target_id = ""
    if row is None or action != "audit.database_restored" or target_id != str(operation_id):
        raise DatabaseRestoreRefused(
            "PostgreSQL committed restore marker is missing or mismatched",
        )
    try:
        metadata = json.loads(str(row["metadata"]))
    except json.JSONDecodeError as exc:
        raise DatabaseRestoreRefused(
            "PostgreSQL committed restore marker metadata is malformed",
        ) from exc
    if (
        metadata.get("operation_id") != str(operation_id)
        or metadata.get("source_stage_digest") != source_digest
        or metadata.get("migration_head") != RELEASE_MIGRATION_HEAD
    ):
        raise DatabaseRestoreRefused(
            "PostgreSQL committed restore marker binding is invalid",
        )
    known_head_result = metadata.get("known_head_result")
    if not isinstance(known_head_result, str):
        raise DatabaseRestoreRefused(
            "PostgreSQL committed restore marker lacks rollback-assessment evidence",
        )
    return {
        "marker_id": marker_id,
        "revision_rebase": metadata["revision_rebase"],
        "epoch_rebase": metadata["epoch_rebase"],
        "schema_contract_digest": metadata["schema_contract_digest"],
        "known_head_result": known_head_result,
    }


async def _clear_managed_target(
    connection: AsyncConnection,
    target: _Target,
    *,
    fence: dict[str, Any],
    next_state: str = "TARGET_CLEARED",
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Remove the exact proved table set and advance the catalog fence."""

    rows = (
        (
            await connection.execute(
                text(
                    """
                SELECT
                  c.relname AS name,
                  EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_inherits i
                    WHERE i.inhrelid = c.oid
                  ) AS is_partition
                FROM pg_catalog.pg_class c
                JOIN pg_catalog.pg_namespace n
                  ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND c.relkind IN ('r', 'p')
                ORDER BY c.relname
                """,
                ),
            )
        )
        .mappings()
        .all()
    )
    roots = {str(row["name"]) for row in rows if not bool(row["is_partition"])}
    expected_roots = set(RESET_ORM_TABLES) | {"alembic_version"}
    if roots != expected_roots:
        raise DatabaseRestoreRefused(
            "PostgreSQL restore cleanup relation contract changed "
            f"(missing={sorted(expected_roots - roots)}, "
            f"unknown={sorted(roots - expected_roots)})",
        )
    table_names = [str(row["name"]) for row in rows]
    if not table_names:
        raise DatabaseRestoreRefused(
            "PostgreSQL restore cleanup found no managed tables",
        )
    preparer = connection.dialect.identifier_preparer
    qualified = ", ".join(f"public.{preparer.quote(name)}" for name in table_names)
    cleanup_manifest = {
        "version": 1,
        "relations": [
            {
                "name": str(row["name"]),
                "is_partition": bool(row["is_partition"]),
            }
            for row in rows
        ],
    }
    cleared_fence = {
        **fence,
        "state": next_state,
        "cleanup_manifest_digest": release_manifest_digest(
            cleanup_manifest,
        ),
    }
    quoted_database = target.database.replace('"', '""')
    literal = _fence_literal(cleared_fence)
    try:
        await connection.execute(
            text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                f"DROP TABLE {qualified} CASCADE",
            ),
        )
        await connection.exec_driver_sql(
            f"ALTER DATABASE \"{quoted_database}\" SET z4j.restore_pending = '{literal}'",
        )
        await connection.commit()
    except BaseException:
        await connection.rollback()
        raise
    remaining = int(
        (
            await connection.execute(
                text(
                    """
                    SELECT count(*)
                    FROM pg_catalog.pg_class c
                    JOIN pg_catalog.pg_namespace n
                      ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public'
                      AND c.relkind IN ('r', 'p')
                    """,
                ),
            )
        ).scalar_one(),
    )
    await connection.rollback()
    if remaining != 0:
        raise DatabaseRestoreRefused(
            "PostgreSQL restore cleanup did not reach an empty table set",
        )
    await _verify_fence(target, cleared_fence)
    return cleared_fence, cleanup_manifest


async def _advance_empty_target_fence(
    connection: AsyncConnection,
    target: _Target,
    *,
    fence: dict[str, Any],
    next_state: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    row_count = int(
        (
            await connection.execute(
                text(
                    """
                    SELECT count(*)
                    FROM pg_catalog.pg_class c
                    JOIN pg_catalog.pg_namespace n
                      ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public'
                      AND c.relkind IN ('r', 'p')
                    """,
                ),
            )
        ).scalar_one(),
    )
    await connection.rollback()
    if row_count != 0:
        raise DatabaseRestoreRefused(
            "PostgreSQL rollback target is not the proved empty shape",
        )
    cleanup_manifest: dict[str, Any] = {
        "version": 1,
        "relations": [],
    }
    advanced = {
        **fence,
        "state": next_state,
        "cleanup_manifest_digest": release_manifest_digest(
            cleanup_manifest,
        ),
    }
    quoted_database = target.database.replace('"', '""')
    literal = _fence_literal(advanced)
    try:
        await connection.exec_driver_sql(
            f"ALTER DATABASE \"{quoted_database}\" SET z4j.restore_pending = '{literal}'",
        )
        await connection.commit()
    except BaseException:
        await connection.rollback()
        raise
    await _verify_fence(target, advanced)
    return advanced, cleanup_manifest


async def _schema_manifest_on_connection(
    connection: AsyncConnection,
) -> dict[str, Any]:
    async with AsyncSession(
        bind=connection,
        expire_on_commit=False,
    ) as session:
        return await release_schema_contract_manifest(session)


async def _upgrade_restored_database(
    connection: AsyncConnection,
    *,
    activation_manifest: dict[str, Any] | None = None,
    activation_attestation: str | None = None,
) -> None:
    """Run release migrations on the already-locked physical coordinator."""

    from alembic import command

    await connection.rollback()

    def upgrade(sync_connection: Any) -> None:
        config = _restore_migration_config()
        config.attributes["z4j_restore_connection"] = sync_connection
        if activation_manifest is not None:
            config.attributes["z4j_audit_activation_manifest"] = activation_manifest
            config.attributes["z4j_audit_activation_attestation"] = activation_attestation
        command.upgrade(config, "head")

    await connection.run_sync(upgrade)


def _target_phase_root(
    target: _Target,
    *,
    create: bool,
) -> Path:
    home = _ensure_durable_directory(z4j_home())
    root = home / ".z4j-restore"
    if not create and not root.exists():
        raise DatabaseRestoreRefused(
            "PostgreSQL restore state directory does not exist",
        )
    _ensure_durable_directory(root)
    postgres_root = root / "postgres"
    if not create and not postgres_root.exists():
        raise DatabaseRestoreRefused(
            "PostgreSQL restore state directory does not exist",
        )
    _ensure_durable_directory(postgres_root)
    target_key = hashlib.sha256(
        canonical_json(
            {
                "host": target.host,
                "port": target.port,
                "database": target.database,
                "username": target.username,
            },
        ),
    ).hexdigest()
    target_root = postgres_root / target_key
    if not create and not target_root.exists():
        raise DatabaseRestoreRefused(
            "PostgreSQL restore target has no recorded operations",
        )
    _ensure_durable_directory(target_root)
    return target_root


def _phase_directory(
    target: _Target,
    operation_id: uuid.UUID,
    *,
    create: bool = True,
) -> Path:
    target_root = _target_phase_root(target, create=create)
    operation_dir = target_root / str(operation_id)
    if not create and not operation_dir.exists():
        raise DatabaseRestoreRefused(
            "PostgreSQL rollback lacks its exact restore phase",
        )
    _ensure_durable_directory(operation_dir)
    return operation_dir


def _fsync_file(path: Path) -> None:
    """Persist one archive's bytes before anything publishes its name."""

    # Windows refuses to flush a handle opened read-only, and POSIX is happy
    # either way, so the mode is chosen per platform rather than per caller.
    flags = os.O_RDWR if os.name == "nt" else os.O_RDONLY
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _cleanup_operation_artifacts(operation_dir: Path) -> None:
    for name in (
        "pgpass",
        "source-staged.dump",
        "target-recovery.dump",
        _RECOVERY_PARTIAL_NAME,
    ):
        with contextlib.suppress(FileNotFoundError):
            (operation_dir / name).unlink()
    _fsync_directory(operation_dir)


def _read_back_archive(path: Path) -> tuple[int, str]:
    """Measure a delivered archive by reopening and rereading its bytes.

    Deliberately not ``_file_digest``: that helper demands an owner-private
    file, which the operator's chosen ``--output`` directory has no reason
    to be.  This only needs the bytes, so it asks for nothing more.
    """

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    flags |= getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    digest = hashlib.sha256()
    size = 0
    try:
        observed = os.fstat(fd)
        if not stat.S_ISREG(observed.st_mode):
            raise DatabaseRestoreRefused(
                "PostgreSQL backup copy is not a regular file",
            )
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    finally:
        os.close(fd)
    return size, digest.hexdigest()


def _stream_archive_bytes(source_fd: int, destination_fd: int) -> tuple[int, str]:
    """Copy one descriptor into another, measuring what actually crossed."""

    digest = hashlib.sha256()
    copied = 0
    while True:
        chunk = os.read(source_fd, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        copied += len(chunk)
        offset = 0
        while offset < len(chunk):
            offset += os.write(destination_fd, chunk[offset:])
    os.fsync(destination_fd)
    return copied, digest.hexdigest()


def _copy_backup_to_destination(
    source: Path,
    destination: Path,
    *,
    expected_size: int,
    expected_digest: str,
) -> None:
    """Copy the staged archive out and prove the copy is byte-identical.

    ``expected_size``/``expected_digest`` come from an independent read of
    the stage, so the checks below compare the delivered archive against a
    separate measurement rather than against the copy's own bookkeeping.
    """

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    # Windows ``os.open`` defaults to text mode if neither O_TEXT nor
    # O_BINARY is specified: a read then stops dead at the first 0x1A
    # byte and a write expands ``\n`` to ``\r\n``.  A compressed pg_dump
    # archive is full of both, so without this the operator is handed a
    # silently truncated backup.  POSIX defines O_BINARY as 0 (or absent)
    # so this is a no-op there.
    flags |= getattr(os, "O_BINARY", 0)
    source_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
    source_flags |= getattr(os, "O_BINARY", 0)
    source_fd = os.open(source, source_flags)
    try:
        destination_fd = os.open(destination, flags, 0o600)
    except BaseException:
        os.close(source_fd)
        raise
    # Past this point the destination is ours (O_EXCL created it), so every
    # failure below has to take it back out again.
    try:
        try:
            before = os.fstat(source_fd)
            if not stat.S_ISREG(before.st_mode):
                raise DatabaseRestoreRefused(
                    "PostgreSQL backup stage is not a regular file",
                )
            copied = _stream_archive_bytes(source_fd, destination_fd)
            after = os.fstat(source_fd)
            if (before.st_dev, before.st_ino, before.st_size) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
            ):
                raise DatabaseRestoreRefused(
                    "PostgreSQL backup stage changed while it was copied",
                )
            # A truncating read is the failure that matters here, and it
            # is invisible to the identity check above because that
            # compares the stage to itself.  Weigh what actually crossed
            # the descriptor instead.
            if copied != (expected_size, expected_digest):
                raise DatabaseRestoreRefused(
                    "PostgreSQL backup stage did not read back as it was written",
                )
        finally:
            # Windows will not unlink a file that still has an open
            # handle, so both descriptors close before the cleanup below
            # tries to remove a backup nobody should keep.
            os.close(destination_fd)
            os.close(source_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            destination.unlink()
        raise
    _fsync_directory(destination.parent)
    # Prove the delivered file by reading it back rather than by trusting
    # the descriptor that just wrote it.  An archive that cannot be
    # reproduced byte-for-byte has to fail here, while the database is
    # still healthy, instead of at the restore that was counting on it.
    try:
        written = _read_back_archive(destination)
    except BaseException:
        with contextlib.suppress(OSError):
            destination.unlink()
        _fsync_directory(destination.parent)
        raise
    if written != (expected_size, expected_digest):
        with contextlib.suppress(OSError):
            destination.unlink()
        _fsync_directory(destination.parent)
        raise DatabaseRestoreRefused(
            "PostgreSQL backup copy does not match the staged archive",
        )


async def _run_backup(
    database_url: str,
    output: Path,
) -> None:
    target = _parse_target(database_url)
    target_identity = await _target_identity(target)
    pg_dump = _resolve_tool("pg_dump")
    if pg_dump.major != target_identity["server_major"]:
        raise DatabaseRestoreRefused(
            "PostgreSQL backup client/server major versions differ",
        )

    destination = output.expanduser().resolve()  # noqa: ASYNC240
    # An archive is only as durable as the entries that reach it, and a backup
    # written into directories created for the occasion is exactly the file
    # whose survival is the point of taking it. The privacy-enforcing helper
    # is deliberately not used here: this is the operator's chosen output
    # location, not restore state, and it is not this command's to lock down.
    absent_output_directories = _absent_directories(destination.parent)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _fsync_new_directory_names(absent_output_directories)
    if destination.exists():
        raise FileExistsError(
            f"backup: refusing to overwrite existing file at {destination}",
        )

    home = ensure_secret_store_directory(z4j_home())
    root = home / ".z4j-backup"
    if not root.exists():
        root.mkdir(mode=0o700)
        _fsync_directory(home)
    ensure_secret_store_directory(root)
    operation_dir = root / str(uuid.uuid4())
    operation_dir.mkdir(mode=0o700)
    _fsync_directory(root)
    ensure_secret_store_directory(operation_dir)
    stage = operation_dir / "backup.dump"
    passfile = operation_dir / "pgpass"
    try:
        _write_passfile(passfile, target)
        environment = _connection_environment(
            target,
            passfile=passfile,
            hostaddr=target.hostaddr,
        )
        result = await asyncio.to_thread(
            _run_identity_bound,
            pg_dump,
            [
                "-Fc",
                "-Z",
                "6",
                "--no-owner",
                "--no-acl",
                "--file",
                str(stage),
                "--dbname",
                target.database,
            ],
            environment=environment,
            text_output=True,
        )
        if result.returncode != 0:
            raise DatabaseRestoreRefused(
                f"PostgreSQL backup failed: {str(result.stderr).strip()}",
            )
        stage.chmod(0o600)
        stage_size, stage_digest = _file_digest(stage)
        if await _target_identity(target) != target_identity:
            raise DatabaseRestoreRefused(
                "PostgreSQL physical target changed during backup",
            )
        _copy_backup_to_destination(
            stage,
            destination,
            expected_size=stage_size,
            expected_digest=stage_digest,
        )
    finally:
        for path in (passfile, stage):
            with contextlib.suppress(FileNotFoundError):
                path.unlink()
        with contextlib.suppress(OSError):
            operation_dir.rmdir()
            _fsync_directory(root)


#: Return type of one pinned-client ceremony.
_PinnedT = TypeVar("_PinnedT")


def _pinned_client_loop_factory() -> Callable[[], asyncio.AbstractEventLoop] | None:
    """Pick an event loop the pinned psycopg client will accept.

    psycopg refuses Windows' ProactorEventLoop, and a console entry point gets
    exactly that from a bare ``asyncio.run``. That is why a Windows operator
    could neither back up nor restore PostgreSQL, while anyone whose entry point
    happened to supply a selector loop (uvicorn does) saw nothing wrong.

    Installing a process-wide selector policy would buy the CLI its fix by
    dragging every application that embeds z4j onto a loop with no subprocess
    support, so the loop is chosen per operation instead. ``None`` off Windows
    leaves stock ``asyncio.run`` behaviour untouched on the platforms that never
    had the problem.

    It lives beside the psycopg client rather than in one caller, because every
    entry point in this module has the same constraint and the next one added
    should inherit it rather than rediscover it.
    """
    if os.name == "nt":
        return asyncio.SelectorEventLoop
    return None


def _run_pinned_client(coroutine: Coroutine[Any, Any, _PinnedT]) -> _PinnedT:
    """Drive one pinned-client ceremony on a loop of our own choosing."""

    with asyncio.Runner(loop_factory=_pinned_client_loop_factory()) as runner:
        return runner.run(coroutine)


def backup_postgres_database(
    database_url: str,
    output: Path,
) -> None:
    """Create a custom archive through the trusted pinned client runner."""

    _run_pinned_client(_run_backup(database_url, output))


async def _run_restore(  # noqa: PLR0912, PLR0915
    database_url: str,
    source: Path,
    *,
    operation: str | None,
    expected_sha256: str | None,
    stopped_executor_attestation: str | None,
    known_head: dict[str, Any] | None,
) -> dict[str, Any]:
    target = _parse_target(database_url)
    operation_id = uuid.UUID(operation) if operation is not None else uuid.uuid4()
    operation_dir = _phase_directory(target, operation_id)
    phase_path = operation_dir / "phase.json"
    staged_source = operation_dir / "source-staged.dump"
    recovery = operation_dir / "target-recovery.dump"
    passfile = operation_dir / "pgpass"
    settings = Settings()  # type: ignore[call-arg]
    if known_head is not None:
        if not isinstance(known_head, dict):
            raise DatabaseRestoreRefused("--known-head must be a JSON object")
        canonical_json(known_head)
        known_head = dict(known_head)
    target_identity = await _target_identity(target)
    if phase_path.exists():
        phase = _read_phase(phase_path)
        if (
            phase.get("operation_id") != str(operation_id)
            or phase.get("target_identity") != target_identity
        ):
            raise DatabaseRestoreRefused(
                "PostgreSQL restore phase identity mismatch",
            )
        if phase.get("state") == "COMPLETE":
            _cleanup_operation_artifacts(operation_dir)
            return dict(phase["result"])
        source_path = Path(
            str(phase["source_provenance"]["supplied_path"]),
        )
        recorded_expected_digest = phase["source_provenance"].get(
            "expected_sha256",
        )
        if expected_sha256 is not None and expected_sha256 != recorded_expected_digest:
            raise DatabaseRestoreRefused(
                "PostgreSQL restore resume supplied different provenance",
            )
        recorded_known_head = phase.get("known_head")
        if known_head is not None and known_head != recorded_known_head:
            raise DatabaseRestoreRefused(
                "PostgreSQL restore resume supplied a different known-head",
            )
        known_head = recorded_known_head
    else:
        source_path = Path(
            os.path.abspath(  # noqa: ASYNC240, PTH100  lexical no-follow capture
                os.fspath(source.expanduser()),  # noqa: ASYNC240
            ),
        )
        phase = {}

    pg_dump = _resolve_tool("pg_dump")
    pg_restore = _resolve_tool("pg_restore")
    if (
        pg_dump.major != target_identity["server_major"]
        or pg_restore.major != target_identity["server_major"]
    ):
        raise DatabaseRestoreRefused(
            "PostgreSQL client/server major versions differ",
        )
    if phase and phase.get("tools") != {
        "pg_dump": _tool_manifest(pg_dump),
        "pg_restore": _tool_manifest(pg_restore),
    }:
        raise DatabaseRestoreRefused(
            "PostgreSQL client identity differs from the staged operation",
        )
    if not phase:
        phase = {
            "phase_version": 1,
            "backend": "postgres",
            "operation_id": str(operation_id),
            "state": "CREATED",
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
            "target_identity": target_identity,
            "tools": {
                "pg_dump": _tool_manifest(pg_dump),
                "pg_restore": _tool_manifest(pg_restore),
            },
        }
        _replace_phase(phase_path, phase)

    try:
        with contextlib.suppress(FileNotFoundError):
            passfile.unlink()
        _write_passfile(passfile, target)
        connection_environment = _connection_environment(
            target,
            passfile=passfile,
            hostaddr=target.hostaddr,
        )
        if phase["state"] == "CREATED":
            with contextlib.suppress(FileNotFoundError):
                staged_source.unlink()
            source_size, source_digest = _stage_source(
                source_path,
                staged_source,
                expected_sha256=expected_sha256,
            )
            source_head = await asyncio.to_thread(
                _archive_source_head,
                pg_restore,
                staged_source,
            )
            toc, toc_digest = await asyncio.to_thread(
                _inspect_toc,
                pg_restore,
                staged_source,
                source_head=source_head,
            )
            source_authority = await asyncio.to_thread(
                _archive_source_authority,
                pg_restore,
                staged_source,
                source_head=source_head,
                archive_digest=source_digest,
                toc_digest=toc_digest,
            )
            target_snapshot = await authenticated_database_snapshot(
                database_url,
                settings,
            )
            source_attestation_snapshot = {
                "manifest_digest": source_authority["manifest_digest"],
                "external_authority_manifest": source_authority["external_authority_manifest"],
            }
            envelope, challenge, required = _attestation_envelope(
                source_snapshot=source_attestation_snapshot,
                target_snapshot=target_snapshot,
            )
            phase = {
                **phase,
                "state": "PREFLIGHT_COMPLETE",
                "source_size": source_size,
                "source_digest": source_digest,
                "toc_digest": toc_digest,
                "toc_entry_count": len(toc.splitlines()),
                "source_authority": source_authority,
                "target_snapshot": target_snapshot,
                "attestation_envelope": envelope,
                "stopped_executor_attestation_challenge": challenge,
                "requires_stopped_executor_attestation": required,
            }
            _replace_phase(phase_path, phase)
        else:
            source_size, source_digest = _file_digest(staged_source)
            if source_size != phase["source_size"] or source_digest != phase["source_digest"]:
                raise DatabaseRestoreRefused(
                    "staged PostgreSQL archive changed after preflight",
                )

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
                        "PostgreSQL restore requires the exact "
                        "stopped-executor challenge "
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
                    "PostgreSQL restore stopped-executor attestation binding changed during resume",
                )
            attestation = {
                **phase["attestation_envelope"],
                "challenge": challenge,
            }
        else:
            if stopped_executor_attestation is not None:
                raise DatabaseRestoreRefused(
                    "stopped-executor attestation was supplied without "
                    "manifested executor authority",
                )
            attestation = {
                "version": 1,
                "kind": "no_restore_external_executor_authority",
                "source_manifest_digest": phase["source_authority"]["manifest_digest"],
                "target_manifest_digest": phase["target_snapshot"]["manifest_digest"],
            }
        attestation_digest = release_manifest_digest(attestation)

        fence = {
            "version": 1,
            "operation_id": str(operation_id),
            "state": "FENCED",
            "source_digest": source_digest,
            "toc_digest": phase["toc_digest"],
            "target_identity_digest": release_manifest_digest(
                target_identity,
            ),
        }
        observed_fence = await _read_fence(target)
        if observed_fence is None and phase.get("state") == "MARKER_COMMITTED":
            finalization = await _recover_committed_finalization(
                target,
                marker_id=str(phase["fence"]["marker_id"]),
                operation_id=operation_id,
                source_digest=source_digest,
                settings=settings,
            )
            installed_snapshot = await authenticated_database_snapshot(
                database_url,
                settings,
            )
            if (
                installed_snapshot["schema_contract_digest"]
                != finalization["schema_contract_digest"]
            ):
                raise DatabaseRestoreRefused(
                    "PostgreSQL finalized restore schema changed before phase cleanup",
                )
            result = {
                "backend": "postgres",
                "operation_id": str(operation_id),
                "source": str(source_path),
                "source_digest": source_digest,
                **finalization,
            }
            phase = {
                **phase,
                "state": "COMPLETE",
                "finalization": finalization,
                "result": result,
            }
            _replace_phase(phase_path, phase)
            _cleanup_operation_artifacts(operation_dir)
            return result
        if observed_fence is None:
            await _set_fence(target, fence)
            observed_fence = fence
        elif (
            observed_fence.get("version") != fence["version"]
            or observed_fence.get("operation_id") != fence["operation_id"]
            or observed_fence.get("source_digest") != fence["source_digest"]
            or observed_fence.get("toc_digest") != fence["toc_digest"]
            or observed_fence.get("target_identity_digest") != fence["target_identity_digest"]
            or observed_fence.get("state")
            not in {
                "FENCED",
                "TARGET_CLEARED",
                "AWAITING_AUDIT_ACTIVATION",
                "AUDIT_ACTIVATED",
                "MARKER_COMMITTED",
            }
        ):
            raise DatabaseRestoreRefused(
                "a different PostgreSQL restore fence is active",
            )
        if observed_fence["state"] == "FENCED":
            phase = {
                **phase,
                "state": "DATABASE_FENCED",
                "fence": observed_fence,
            }
            _replace_phase(phase_path, phase)

        coordinator_engine = _pinned_coordinator_engine(target)
        coordinator: AsyncConnection | None = None
        lock_owned = False
        try:
            coordinator = await coordinator_engine.connect()
            await coordinator.execute(
                text(
                    "SELECT pg_advisory_lock(:lock_id)",
                ),
                {"lock_id": SCHEMA_TRANSITION_ADVISORY_LOCK_KEY},
            )
            await coordinator.commit()
            lock_owned = True
            if await _target_identity(target) != target_identity:
                raise DatabaseRestoreRefused(
                    "PostgreSQL physical target changed after fencing",
                )
            await _verify_fence(target, observed_fence)

            if observed_fence["state"] == "FENCED":
                locked_target_snapshot = await authenticated_database_snapshot(
                    database_url,
                    settings,
                    connection=coordinator,
                )
                if (
                    locked_target_snapshot["manifest_digest"]
                    != phase["target_snapshot"]["manifest_digest"]
                ):
                    raise DatabaseRestoreRefused(
                        "PostgreSQL target changed between preflight and "
                        "the restore coordinator lock",
                    )
                if not recovery.exists():
                    # pg_dump leaves its partial output behind when it fails,
                    # and the recovery pathname is the whole record of whether
                    # a dump happened: resume skips the dump when the name is
                    # there, and rollback demands a complete archive under it.
                    # Some bytes on their way to becoming one satisfied the
                    # first and failed the second, so a failed dump fenced the
                    # brain with no way forward and no way back. The archive
                    # therefore grows under a name nothing consults and only
                    # takes the real one once it is whole and on the platter.
                    partial = operation_dir / _RECOVERY_PARTIAL_NAME
                    with contextlib.suppress(FileNotFoundError):
                        partial.unlink()
                    dump_result = await asyncio.to_thread(
                        _run_identity_bound,
                        pg_dump,
                        [
                            "-Fc",
                            "-Z",
                            "6",
                            "--no-owner",
                            "--no-acl",
                            "--file",
                            str(partial),
                            "--dbname",
                            target.database,
                        ],
                        environment=connection_environment,
                        text_output=True,
                    )
                    if dump_result.returncode != 0:
                        with contextlib.suppress(FileNotFoundError):
                            partial.unlink()
                        _fsync_directory(operation_dir)
                        raise DatabaseRestoreRefused(
                            "PostgreSQL target recovery dump failed: "
                            f"{str(dump_result.stderr).strip()}",
                        )
                    partial.chmod(0o600)
                    _fsync_file(partial)
                    partial.replace(recovery)
                    _fsync_directory(operation_dir)
                recovery_size, recovery_digest = _file_digest(recovery)
                recovery_toc, recovery_toc_digest = await asyncio.to_thread(
                    _inspect_toc,
                    pg_restore,
                    recovery,
                    source_head=RELEASE_MIGRATION_HEAD,
                )
                phase = {
                    **phase,
                    "state": "TARGET_RECOVERY_STAGED",
                    "target_recovery_size": recovery_size,
                    "target_recovery_digest": recovery_digest,
                    "target_recovery_toc_digest": (recovery_toc_digest),
                    "target_recovery_toc_entry_count": len(
                        recovery_toc.splitlines(),
                    ),
                }
                _replace_phase(phase_path, phase)
                observed_fence, cleanup_manifest = await _clear_managed_target(
                    coordinator,
                    target,
                    fence=fence,
                )
                phase = {
                    **phase,
                    "state": "TARGET_CLEARED",
                    "fence": observed_fence,
                    "cleanup_manifest": cleanup_manifest,
                }
                _replace_phase(phase_path, phase)
            else:
                recovery_size, recovery_digest = _file_digest(
                    recovery,
                )
                if (
                    recovery_size != phase["target_recovery_size"]
                    or recovery_digest != phase["target_recovery_digest"]
                ):
                    raise DatabaseRestoreRefused(
                        "PostgreSQL target recovery archive changed during resume",
                    )

            # The marker commits before the fence records that it did, so an
            # interrupted run can leave a finished restore whose fence still
            # calls the target merely cleared. Ask the database which of the
            # two is right before re-deriving anything: reading the fence
            # alone, the resume ran the destructive half again, which throws
            # away signed audit history that was already committed and, on a
            # database whose partitions are already back, is refused outright
            # by pg_restore --clean.
            committed_marker_id = (
                str(observed_fence["marker_id"])
                if observed_fence["state"] == "MARKER_COMMITTED"
                else await _committed_finalization_marker_id(
                    coordinator,
                    operation_id=operation_id,
                )
            )
            if committed_marker_id is not None:
                finalization = phase.get("finalization") or await _recover_committed_finalization(
                    target,
                    marker_id=committed_marker_id,
                    operation_id=operation_id,
                    source_digest=source_digest,
                    settings=settings,
                    connection=coordinator,
                )
                marker_fence = {
                    **observed_fence,
                    "state": "MARKER_COMMITTED",
                    "marker_id": committed_marker_id,
                }
                if observed_fence != marker_fence:
                    await _set_fence(target, marker_fence)
                observed_fence = marker_fence
                phase = {
                    **phase,
                    "state": "MARKER_COMMITTED",
                    "fence": marker_fence,
                    "finalization": finalization,
                }
                _replace_phase(phase_path, phase)
            else:
                if observed_fence["state"] not in {
                    "AWAITING_AUDIT_ACTIVATION",
                    "AUDIT_ACTIVATED",
                }:
                    restore_result = await asyncio.to_thread(
                        _run_identity_bound,
                        pg_restore,
                        [
                            "--clean",
                            "--if-exists",
                            "--exit-on-error",
                            "--no-owner",
                            "--no-acl",
                            "--single-transaction",
                            "--dbname",
                            target.database,
                            str(staged_source),
                        ],
                        environment=connection_environment,
                        text_output=True,
                    )
                    if restore_result.returncode != 0:
                        raise DatabaseRestoreRefused(
                            "PostgreSQL source restore failed with its durable "
                            "fence retained: "
                            f"{str(restore_result.stderr).strip()}",
                        )
                    if await _target_identity(target) != target_identity:
                        raise DatabaseRestoreRefused(
                            "PostgreSQL physical target changed after pg_restore",
                        )
                    await _verify_fence(target, observed_fence)
                restored_source_head = str(
                    phase["source_authority"]["source_head"],
                )
                if restored_source_head == _LEGACY_SOURCE_HEAD:
                    try:
                        await _upgrade_restored_database(coordinator)
                    except Exception as exc:
                        from alembic.util import CommandError

                        if not isinstance(exc, CommandError):
                            raise
                        await coordinator.rollback()
                        preparation = (
                            (
                                await coordinator.execute(
                                    text(
                                        """
                                    SELECT
                                      preparation_id::text,
                                      audit_key_id,
                                      preparation_revision,
                                      target_activation_revision,
                                      preparation_mac
                                    FROM audit_chain_preparation
                                    """
                                    ),
                                )
                            )
                            .mappings()
                            .one_or_none()
                        )
                        head = (
                            await coordinator.execute(
                                text(
                                    "SELECT version_num FROM alembic_version",
                                ),
                            )
                        ).scalar_one_or_none()
                        await coordinator.rollback()
                        if preparation is None or head != "v1_8_audit_chain_prepare":
                            raise DatabaseRestoreRefused(
                                "legacy restore migration failed outside "
                                "the authenticated audit preparation boundary",
                            ) from exc
                        awaiting_fence = {
                            **observed_fence,
                            "state": "AWAITING_AUDIT_ACTIVATION",
                            "preparation_id": preparation["preparation_id"],
                            "audit_key_id": preparation["audit_key_id"],
                        }
                        await _set_fence(target, awaiting_fence)
                        observed_fence = awaiting_fence
                        phase = {
                            **phase,
                            "state": "AWAITING_AUDIT_ACTIVATION",
                            "fence": awaiting_fence,
                            "audit_preparation": dict(preparation),
                            "installed_target_identity": target_identity,
                        }
                        _replace_phase(phase_path, phase)
                        raise DatabaseRestoreRefused(
                            "legacy restore is awaiting manifest-bound audit "
                            "activation; run `z4j audit activate-chain-state "
                            f"--restore-operation {operation_id} "
                            "--manifest PATH`, then the same command again "
                            "with --apply added",
                        ) from exc
                elif restored_source_head != RELEASE_MIGRATION_HEAD:
                    # A previous-release archive lands at its own head, so it
                    # is migrated up inside the same held coordinator lock,
                    # before anything reads the release schema contract or
                    # signs the marker. There is no authenticated-audit
                    # continuation to fall into here: the audit chain was
                    # already activated when this archive was taken, so a
                    # migration failure is just a failure and keeps the fence.
                    await _upgrade_restored_database(coordinator)
                restored_schema_manifest = await _schema_manifest_on_connection(coordinator)
                phase = {
                    **phase,
                    "observed_restored_schema_contract_manifest": (restored_schema_manifest),
                }
                _replace_phase(phase_path, phase)
                if restored_schema_manifest != phase["target_snapshot"]["schema_contract_manifest"]:
                    raise DatabaseRestoreRefused(
                        "pg_restore did not reproduce the canonical release schema contract",
                    )
                restored_snapshot = await authenticated_database_snapshot(
                    database_url,
                    settings,
                    connection=coordinator,
                )
                if (
                    restored_snapshot["revision"] != phase["source_authority"]["revision"]
                    or restored_snapshot["epoch"] != phase["source_authority"]["epoch"]
                ):
                    raise DatabaseRestoreRefused(
                        "restored PostgreSQL D singletons differ from the staged archive preflight",
                    )
                phase = {
                    **phase,
                    "state": "SOURCE_RESTORED",
                    "restored_snapshot": restored_snapshot,
                }
                _replace_phase(phase_path, phase)
                finalization = await finalize_restored_database(
                    database_url,
                    settings,
                    connection=coordinator,
                    operation_id=operation_id,
                    source_digest=source_digest,
                    source_snapshot=restored_snapshot,
                    target_recovery_digest=recovery_digest,
                    target_snapshot=phase["target_snapshot"],
                    attestation=attestation,
                    attestation_digest=attestation_digest,
                    known_head=known_head,
                    ceremony_metadata={
                        "source_provenance": {
                            "kind": phase["source_provenance"]["kind"],
                            "expected_sha256": phase["source_provenance"].get("expected_sha256"),
                            "verified_digest": source_digest,
                        },
                        # The head the archive was TAKEN at, captured at
                        # preflight and never rewritten by the upgrade above.
                        # The marker's own ``migration_head`` says where the
                        # data now lives; this says where it came from, and an
                        # operator reading the audit trail needs both.
                        "source_migration_head": restored_source_head,
                        "source_toc_digest": phase["toc_digest"],
                        "target_recovery_toc_digest": phase["target_recovery_toc_digest"],
                        "target_recovery_migration_head": (
                            phase["target_snapshot"]["migration_head"]
                        ),
                        "target_recovery_schema_contract_digest": (
                            phase["target_snapshot"]["schema_contract_digest"]
                        ),
                        "target_cleanup_manifest_digest": (
                            release_manifest_digest(
                                phase["cleanup_manifest"],
                            )
                        ),
                        "physical_target": target_identity,
                    },
                )
                # Finalization writes through a session BOUND to this
                # connection, and a session that joins a transaction it did
                # not open does not end one either: its commit flushes and
                # returns without a COMMIT reaching the server. The
                # coordinator can be holding such a transaction here, because
                # an upgrade with no steps left to apply still reads the
                # version table and leaves that read's transaction open. So
                # end it here, and then prove from a connection that cannot
                # see uncommitted work that the marker survived. Everything
                # below publishes or removes the startup fence, and a fence
                # removed before the work it fenced is durable leaves a
                # database that starts, was replaced, and was never rebased.
                await coordinator.commit()
                await _assert_finalization_is_durable(
                    target,
                    finalization=finalization,
                    operation_id=operation_id,
                    source_digest=source_digest,
                )
                marker_fence = {
                    **observed_fence,
                    "state": "MARKER_COMMITTED",
                    "marker_id": finalization["marker_id"],
                }
                await _set_fence(target, marker_fence)
                observed_fence = marker_fence
                phase = {
                    **phase,
                    "state": "MARKER_COMMITTED",
                    "fence": marker_fence,
                    "finalization": finalization,
                }
                _replace_phase(phase_path, phase)

            await _verify_fence(target, observed_fence)
            await _clear_fence(target)
            unlocked = (
                await coordinator.execute(
                    text(
                        "SELECT pg_advisory_unlock(:lock_id)",
                    ),
                    {
                        "lock_id": (SCHEMA_TRANSITION_ADVISORY_LOCK_KEY),
                    },
                )
            ).scalar_one()
            await coordinator.commit()
            if unlocked is not True:
                raise DatabaseRestoreRefused(
                    "PostgreSQL schema coordinator did not unlock once",
                )
            lock_owned = False
        finally:
            if coordinator is not None:
                if lock_owned:
                    with contextlib.suppress(Exception):
                        await coordinator.rollback()
                    with contextlib.suppress(Exception):
                        await coordinator.execute(
                            text(
                                "SELECT pg_advisory_unlock(:lock_id)",
                            ),
                            {
                                "lock_id": (SCHEMA_TRANSITION_ADVISORY_LOCK_KEY),
                            },
                        )
                        await coordinator.commit()
                with contextlib.suppress(Exception):
                    await coordinator.close()
            await coordinator_engine.dispose()

        result = {
            "backend": "postgres",
            "operation_id": str(operation_id),
            "source": str(source_path),
            "source_digest": source_digest,
            **phase["finalization"],
        }
        phase = {**phase, "state": "COMPLETE", "result": result}
        _replace_phase(phase_path, phase)
        _cleanup_operation_artifacts(operation_dir)
        return result
    finally:
        with contextlib.suppress(FileNotFoundError):
            passfile.unlink()


async def _retire_untouched_operation(
    target: _Target,
    *,
    operation_id: uuid.UUID,
    phase: dict[str, Any],
    phase_path: Path,
    operation_dir: Path,
    fence: dict[str, Any] | None,
) -> dict[str, Any]:
    """Retire an operation that never reached the target, fence included.

    Clearing the fence is deliberately not conditional on the live database
    still matching its preflight snapshot. Nothing on this path writes to the
    target, so the clear is safe whatever the database now holds, and a
    rollback that can refuse is not an exit: refusing would leave the operator
    in the state this path exists to end. No signed marker is written for the
    same reason the SQLite ceremony writes none for its pre-staging states:
    there is nothing about the target to attest to.
    """

    if fence is not None:
        engine = _pinned_coordinator_engine(target)
        coordinator: AsyncConnection | None = None
        lock_owned = False
        try:
            coordinator = await engine.connect()
            await coordinator.execute(
                text("SELECT pg_advisory_lock(:lock_id)"),
                {"lock_id": SCHEMA_TRANSITION_ADVISORY_LOCK_KEY},
            )
            await coordinator.commit()
            lock_owned = True
            # Re-read under the lock. A fence that moved between the read
            # above and here belongs to a coordinator that is still running,
            # and its work is not this command's to discard.
            await _verify_fence(target, fence)
            await _clear_fence(target)
            unlocked = (
                await coordinator.execute(
                    text("SELECT pg_advisory_unlock(:lock_id)"),
                    {"lock_id": SCHEMA_TRANSITION_ADVISORY_LOCK_KEY},
                )
            ).scalar_one()
            await coordinator.commit()
            if unlocked is not True:
                raise DatabaseRestoreRefused(
                    "PostgreSQL rollback coordinator did not unlock once",
                )
            lock_owned = False
        finally:
            if coordinator is not None:
                if lock_owned:
                    with contextlib.suppress(Exception):
                        await coordinator.rollback()
                    with contextlib.suppress(Exception):
                        await coordinator.execute(
                            text("SELECT pg_advisory_unlock(:lock_id)"),
                            {
                                "lock_id": (SCHEMA_TRANSITION_ADVISORY_LOCK_KEY),
                            },
                        )
                        await coordinator.commit()
                with contextlib.suppress(Exception):
                    await coordinator.close()
            await engine.dispose()
    result = {
        "backend": "postgres",
        "operation_id": str(operation_id),
        "rolled_back": True,
        "marker_id": None,
        "source_digest": phase.get("source_digest"),
        "target_recovery_digest": None,
    }
    _replace_phase(
        phase_path,
        {**phase, "state": "ROLLED_BACK", "result": result},
    )
    _cleanup_operation_artifacts(operation_dir)
    return result


async def _run_rollback(  # noqa: PLR0912, PLR0915
    database_url: str,
    *,
    operation: str,
) -> dict[str, Any]:
    target = _parse_target(database_url)
    operation_id = uuid.UUID(operation)
    operation_dir = _phase_directory(
        target,
        operation_id,
        create=False,
    )
    phase_path = operation_dir / "phase.json"
    try:
        phase = _read_phase(phase_path)
    except FileNotFoundError as exc:
        raise DatabaseRestoreRefused(
            "PostgreSQL rollback lacks its exact restore phase",
        ) from exc
    if phase.get("backend") != "postgres" or phase.get("operation_id") != str(operation_id):
        raise DatabaseRestoreRefused(
            "PostgreSQL rollback phase binding is invalid",
        )
    if phase.get("state") == "ROLLED_BACK":
        _cleanup_operation_artifacts(operation_dir)
        return dict(phase["result"])
    if phase.get("state") == "COMPLETE":
        raise DatabaseRestoreRefused(
            "PostgreSQL restore is complete; its rollback authority has been retired",
        )

    staged_source = operation_dir / "source-staged.dump"
    recovery = operation_dir / "target-recovery.dump"
    passfile = operation_dir / "pgpass"
    target_identity = await _target_identity(target)
    if phase.get("target_identity") != target_identity:
        raise DatabaseRestoreRefused(
            "PostgreSQL rollback physical target identity changed",
        )
    pg_dump = _resolve_tool("pg_dump")
    pg_restore = _resolve_tool("pg_restore")
    if phase.get("tools") != {
        "pg_dump": _tool_manifest(pg_dump),
        "pg_restore": _tool_manifest(pg_restore),
    }:
        raise DatabaseRestoreRefused(
            "PostgreSQL rollback client identity changed",
        )
    observed_fence = await _read_fence(target)
    if observed_fence is not None and (
        observed_fence.get("operation_id") != str(operation_id)
        or observed_fence.get("target_identity_digest") != release_manifest_digest(target_identity)
        # Against the phase's recorded digest, because the staged archive that
        # the full path below re-measures may not exist yet. That re-measured
        # comparison still runs; this one only makes the early exit hold the
        # same binding.
        or observed_fence.get("source_digest") != phase.get("source_digest")
    ):
        raise DatabaseRestoreRefused(
            "PostgreSQL rollback catalog fence does not match its phase",
        )
    # Dropping the managed tables and advancing the fence out of FENCED commit
    # in one transaction, so a fence that is absent or still FENCED proves the
    # target was never touched. An operation in that state has to retire
    # WITHOUT a recovery archive, because the crash window it covers is
    # precisely the one where no complete archive was ever produced: requiring
    # one first is what left a failed recovery dump holding a fence that
    # neither exit could clear.
    if (observed_fence is None or observed_fence.get("state") == "FENCED") and phase.get(
        "target_recovery_digest"
    ) is None:
        return await _retire_untouched_operation(
            target,
            operation_id=operation_id,
            phase=phase,
            phase_path=phase_path,
            operation_dir=operation_dir,
            fence=observed_fence,
        )
    # Past this point the phase recorded a staged recovery archive, or the
    # fence itself proves the restore got far enough to have staged one.
    source_size, source_digest = _file_digest(staged_source)
    recovery_size, recovery_digest = _file_digest(recovery)
    if (
        source_size != phase.get("source_size")
        or source_digest != phase.get("source_digest")
        or recovery_size != phase.get("target_recovery_size")
        or recovery_digest != phase.get("target_recovery_digest")
    ):
        raise DatabaseRestoreRefused(
            "PostgreSQL rollback artifact identity changed",
        )
    _, recovery_toc_digest = await asyncio.to_thread(
        _inspect_toc,
        pg_restore,
        recovery,
        source_head=RELEASE_MIGRATION_HEAD,
    )
    if recovery_toc_digest != phase.get("target_recovery_toc_digest"):
        raise DatabaseRestoreRefused(
            "PostgreSQL rollback recovery TOC changed",
        )
    if observed_fence is None and phase.get("state") == "TARGET_RECOVERED":
        marker_id = str(phase.get("rollback_marker_id", ""))
        verification_connection = await _connect(target)
        try:
            marker_row = await verification_connection.fetchrow(
                """
                SELECT id::text AS marker_id, metadata::text AS metadata
                FROM audit_log
                WHERE id = $1::uuid
                  AND action = 'audit.database_restore_rolled_back'
                  AND target_id = $2
                """,
                marker_id,
                str(operation_id),
            )
        finally:
            await verification_connection.close()
        if marker_row is None:
            raise DatabaseRestoreRefused(
                "PostgreSQL rollback fence cleared without its signed marker",
            )
        marker_metadata = json.loads(str(marker_row["metadata"]))
        if (
            marker_metadata.get("operation_id") != str(operation_id)
            or marker_metadata.get("rejected_source_stage_digest") != source_digest
            or marker_metadata.get("target_recovery_digest") != recovery_digest
            or marker_metadata.get("physical_target") != target_identity
        ):
            raise DatabaseRestoreRefused(
                "PostgreSQL cleared rollback marker binding is invalid",
            )
        recovered = await authenticated_database_snapshot(
            database_url,
            Settings(),  # type: ignore[call-arg]
        )
        if (
            recovered["revision"] != phase["target_snapshot"]["revision"]
            or recovered["epoch"] != phase["target_snapshot"]["epoch"]
            or recovered["schema_contract_digest"]
            != phase["target_snapshot"]["schema_contract_digest"]
        ):
            raise DatabaseRestoreRefused(
                "PostgreSQL cleared rollback target changed",
            )
        result = {
            "backend": "postgres",
            "operation_id": str(operation_id),
            "rolled_back": True,
            "marker_id": marker_id,
            "source_digest": source_digest,
            "target_recovery_digest": recovery_digest,
        }
        phase = {
            **phase,
            "state": "ROLLED_BACK",
            "result": result,
        }
        _replace_phase(phase_path, phase)
        _cleanup_operation_artifacts(operation_dir)
        return result
    if (
        observed_fence is None
        or observed_fence.get("operation_id") != str(operation_id)
        or observed_fence.get("source_digest") != source_digest
        or observed_fence.get("target_identity_digest") != release_manifest_digest(target_identity)
        or observed_fence.get("state")
        not in {
            "FENCED",
            "TARGET_CLEARED",
            "AWAITING_AUDIT_ACTIVATION",
            "AUDIT_ACTIVATED",
            "MARKER_COMMITTED",
            "ROLLBACK_TARGET_CLEARED",
            "TARGET_RECOVERED",
        }
    ):
        raise DatabaseRestoreRefused(
            "PostgreSQL rollback catalog fence does not match its phase",
        )

    with contextlib.suppress(FileNotFoundError):
        passfile.unlink()
    _write_passfile(passfile, target)
    environment = _connection_environment(
        target,
        passfile=passfile,
        hostaddr=target.hostaddr,
    )
    settings = Settings()  # type: ignore[call-arg]
    coordinator_engine = _pinned_coordinator_engine(target)
    coordinator: AsyncConnection | None = None
    lock_owned = False
    try:
        coordinator = await coordinator_engine.connect()
        await coordinator.execute(
            text("SELECT pg_advisory_lock(:lock_id)"),
            {"lock_id": SCHEMA_TRANSITION_ADVISORY_LOCK_KEY},
        )
        await coordinator.commit()
        lock_owned = True
        if await _target_identity(target) != target_identity:
            raise DatabaseRestoreRefused(
                "PostgreSQL rollback target changed after locking",
            )
        await _verify_fence(target, observed_fence)

        audit_log_exists = (
            await coordinator.execute(
                text("SELECT to_regclass('public.audit_log') IS NOT NULL"),
            )
        ).scalar_one()
        committed_rows = (
            (
                await coordinator.execute(
                    text(
                        """
                        SELECT id::text AS marker_id, metadata
                        FROM audit_log
                        WHERE action =
                          'audit.database_restore_rolled_back'
                          AND target_id = :operation_id
                        ORDER BY occurred_at, id
                        """,
                    ),
                    {"operation_id": str(operation_id)},
                )
            )
            .mappings()
            .all()
            if audit_log_exists
            else []
        )
        await coordinator.rollback()
        if committed_rows:
            if len(committed_rows) != 1:
                raise DatabaseRestoreRefused(
                    "PostgreSQL rollback marker is duplicated",
                )
            committed_marker = committed_rows[0]
            metadata = committed_marker["metadata"]
            if not isinstance(metadata, dict):
                raise DatabaseRestoreRefused(
                    "PostgreSQL rollback marker metadata is malformed",
                )
            if (
                metadata.get("operation_id") != str(operation_id)
                or metadata.get("rejected_source_stage_digest") != source_digest
                or metadata.get("target_recovery_digest") != recovery_digest
                or metadata.get("target_manifest_digest")
                != phase["target_snapshot"]["manifest_digest"]
                or metadata.get("physical_target") != target_identity
            ):
                raise DatabaseRestoreRefused(
                    "PostgreSQL rollback marker does not bind this phase",
                )
            recovered = await authenticated_database_snapshot(
                database_url,
                settings,
                connection=coordinator,
            )
            if (
                recovered["revision"] != phase["target_snapshot"]["revision"]
                or recovered["epoch"] != phase["target_snapshot"]["epoch"]
                or recovered["schema_contract_digest"]
                != phase["target_snapshot"]["schema_contract_digest"]
            ):
                raise DatabaseRestoreRefused(
                    "PostgreSQL rollback marker names a changed target",
                )
            marker_id = str(committed_marker["marker_id"])
            recovered_fence = {
                **observed_fence,
                "state": "TARGET_RECOVERED",
                "rollback_marker_id": marker_id,
            }
            if observed_fence != recovered_fence:
                await _set_fence(target, recovered_fence)
            phase = {
                **phase,
                "state": "TARGET_RECOVERED",
                "fence": recovered_fence,
                "rollback_marker_id": marker_id,
            }
            _replace_phase(phase_path, phase)
            await _clear_fence(target)
            unlocked = (
                await coordinator.execute(
                    text("SELECT pg_advisory_unlock(:lock_id)"),
                    {"lock_id": SCHEMA_TRANSITION_ADVISORY_LOCK_KEY},
                )
            ).scalar_one()
            await coordinator.commit()
            if unlocked is not True:
                raise DatabaseRestoreRefused(
                    "PostgreSQL rollback coordinator did not unlock once",
                )
            lock_owned = False
            result = {
                "backend": "postgres",
                "operation_id": str(operation_id),
                "rolled_back": True,
                "marker_id": marker_id,
                "source_digest": source_digest,
                "target_recovery_digest": recovery_digest,
            }
            phase = {
                **phase,
                "state": "ROLLED_BACK",
                "result": result,
            }
            _replace_phase(phase_path, phase)
            _cleanup_operation_artifacts(operation_dir)
            return result

        table_count = int(
            (
                await coordinator.execute(
                    text(
                        """
                        SELECT count(*)
                        FROM pg_catalog.pg_class c
                        JOIN pg_catalog.pg_namespace n
                          ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public'
                          AND c.relkind IN ('r', 'p')
                        """,
                    ),
                )
            ).scalar_one(),
        )
        await coordinator.rollback()
        target_is_original = False
        if table_count:
            live_snapshot = await authenticated_database_snapshot(
                database_url,
                settings,
                connection=coordinator,
            )
            target_is_original = (
                live_snapshot["portable_manifest_digest"]
                == phase["target_snapshot"]["portable_manifest_digest"]
            )
            if not target_is_original:
                observed_fence, cleanup_manifest = await _clear_managed_target(
                    coordinator,
                    target,
                    fence=observed_fence,
                    next_state="ROLLBACK_TARGET_CLEARED",
                )
        else:
            observed_fence, cleanup_manifest = await _advance_empty_target_fence(
                coordinator,
                target,
                fence=observed_fence,
                next_state="ROLLBACK_TARGET_CLEARED",
            )

        if not target_is_original:
            restore_result = await asyncio.to_thread(
                _run_identity_bound,
                pg_restore,
                [
                    "--clean",
                    "--if-exists",
                    "--exit-on-error",
                    "--no-owner",
                    "--no-acl",
                    "--single-transaction",
                    "--dbname",
                    target.database,
                    str(recovery),
                ],
                environment=environment,
                text_output=True,
            )
            if restore_result.returncode != 0:
                raise DatabaseRestoreRefused(
                    "PostgreSQL rollback pg_restore failed with its "
                    "durable fence retained: "
                    f"{str(restore_result.stderr).strip()}",
                )
            recovered = await authenticated_database_snapshot(
                database_url,
                settings,
                connection=coordinator,
            )
            if (
                recovered["portable_manifest_digest"]
                != phase["target_snapshot"]["portable_manifest_digest"]
                or recovered["revision"] != phase["target_snapshot"]["revision"]
                or recovered["epoch"] != phase["target_snapshot"]["epoch"]
            ):
                raise DatabaseRestoreRefused(
                    "PostgreSQL rollback did not reproduce the captured target manifest",
                )
        else:
            recovered = live_snapshot
            cleanup_manifest = {
                "version": 1,
                "relations": [],
                "target_already_original": True,
            }

        async with AsyncSession(
            bind=coordinator,
            expire_on_commit=False,
        ) as session:
            marker = await AuditService(settings).record(
                AuditLogRepository(session),
                action="audit.database_restore_rolled_back",
                target_type="database",
                target_id=str(operation_id),
                result="success",
                outcome="allow",
                metadata={
                    "restore_phase_version": 1,
                    "operation_id": str(operation_id),
                    "migration_head": RELEASE_MIGRATION_HEAD,
                    "rejected_source_stage_digest": source_digest,
                    "rejected_source_provenance": {
                        "kind": phase["source_provenance"]["kind"],
                        "expected_sha256": phase["source_provenance"].get("expected_sha256"),
                        "verified_digest": source_digest,
                    },
                    "target_recovery_digest": recovery_digest,
                    "target_recovery_toc_digest": phase["target_recovery_toc_digest"],
                    "target_recovery_migration_head": phase["target_snapshot"]["migration_head"],
                    "target_recovery_schema_contract_digest": phase["target_snapshot"][
                        "schema_contract_digest"
                    ],
                    "target_manifest_digest": phase["target_snapshot"]["manifest_digest"],
                    "schema_contract_digest": recovered["schema_contract_digest"],
                    "cleanup_manifest_digest": (release_manifest_digest(cleanup_manifest)),
                    "physical_target": target_identity,
                },
            )
            await session.commit()
        # The marker was written through a session bound to this connection,
        # which does not commit a transaction it did not open. Nothing below
        # may run on a marker a crash can still take back: the fence comes
        # down two statements from here, and a rollback whose fence is gone
        # and whose marker never landed is one no supported command can
        # finish. So end the transaction here rather than at the far side of
        # the fence removal.
        await coordinator.commit()
        async with AsyncSession(
            bind=coordinator,
            expire_on_commit=False,
        ) as session:
            report = await verify_active_audit_generation(
                session,
                settings,
                page_size=5000,
            )
            if not report.clean:
                raise DatabaseRestoreRefused(
                    f"PostgreSQL rollback marker verification failed: {list(report.mismatches)}",
                )
        await _assert_rollback_marker_is_durable(
            target,
            marker_id=str(marker.id),
            operation_id=operation_id,
            binding={
                "operation_id": str(operation_id),
                "rejected_source_stage_digest": source_digest,
                "target_recovery_digest": recovery_digest,
                "target_manifest_digest": (phase["target_snapshot"]["manifest_digest"]),
                "physical_target": target_identity,
            },
            recovered_revision=int(recovered["revision"]),
            recovered_epoch=int(recovered["epoch"]),
        )

        recovered_fence = {
            **observed_fence,
            "state": "TARGET_RECOVERED",
            "rollback_marker_id": str(marker.id),
        }
        await _set_fence(target, recovered_fence)
        phase = {
            **phase,
            "state": "TARGET_RECOVERED",
            "fence": recovered_fence,
            "rollback_marker_id": str(marker.id),
            "rollback_cleanup_manifest": cleanup_manifest,
        }
        _replace_phase(phase_path, phase)
        await _clear_fence(target)
        unlocked = (
            await coordinator.execute(
                text("SELECT pg_advisory_unlock(:lock_id)"),
                {"lock_id": SCHEMA_TRANSITION_ADVISORY_LOCK_KEY},
            )
        ).scalar_one()
        await coordinator.commit()
        if unlocked is not True:
            raise DatabaseRestoreRefused(
                "PostgreSQL rollback coordinator did not unlock once",
            )
        lock_owned = False
        result = {
            "backend": "postgres",
            "operation_id": str(operation_id),
            "rolled_back": True,
            "marker_id": str(marker.id),
            "source_digest": source_digest,
            "target_recovery_digest": recovery_digest,
        }
        phase = {
            **phase,
            "state": "ROLLED_BACK",
            "result": result,
        }
        _replace_phase(phase_path, phase)
        _cleanup_operation_artifacts(operation_dir)
        return result
    finally:
        if coordinator is not None:
            if lock_owned:
                with contextlib.suppress(Exception):
                    await coordinator.rollback()
                with contextlib.suppress(Exception):
                    await coordinator.execute(
                        text("SELECT pg_advisory_unlock(:lock_id)"),
                        {
                            "lock_id": (SCHEMA_TRANSITION_ADVISORY_LOCK_KEY),
                        },
                    )
                    await coordinator.commit()
            with contextlib.suppress(Exception):
                await coordinator.close()
        await coordinator_engine.dispose()
        with contextlib.suppress(FileNotFoundError):
            passfile.unlink()


async def _restore_activation_phase(
    database_url: str,
    operation_id: uuid.UUID,
) -> tuple[_Target, Path, dict[str, Any], dict[str, Any]]:
    target = _parse_target(database_url)
    operation_dir = _phase_directory(
        target,
        operation_id,
        create=False,
    )
    phase_path = operation_dir / "phase.json"
    phase = _read_phase(phase_path)
    if (
        phase.get("backend") != "postgres"
        or phase.get("operation_id") != str(operation_id)
        or phase.get("state")
        not in {
            "AWAITING_AUDIT_ACTIVATION",
            "AUDIT_ACTIVATED",
        }
    ):
        raise DatabaseRestoreRefused(
            "restore-bound audit activation requires its exact awaiting phase",
        )
    target_identity = await _target_identity(target)
    if phase.get("target_identity") != target_identity:
        raise DatabaseRestoreRefused(
            "restore-bound audit activation target identity changed",
        )
    fence = await _read_fence(target)
    if (
        fence is None
        or fence.get("operation_id") != str(operation_id)
        or fence.get("source_digest") != phase.get("source_digest")
        or fence.get("state")
        not in {
            "AWAITING_AUDIT_ACTIVATION",
            "AUDIT_ACTIVATED",
        }
    ):
        raise DatabaseRestoreRefused(
            "restore-bound audit activation catalog fence mismatch",
        )
    return target, phase_path, phase, fence


async def _build_restore_activation_manifest(
    database_url: str,
    *,
    operation_id: uuid.UUID,
    settings: Settings,
    legacy_key_window_complete: bool,
    known_head: dict[str, Any] | None,
) -> dict[str, Any]:
    from z4j_brain.domain.audit_activation import (
        build_activation_manifest,
    )
    from z4j_brain.persistence.repositories.audit_log import (
        AUDIT_CHAIN_ADVISORY_LOCK_KEY,
    )

    target, _, phase, fence = await _restore_activation_phase(
        database_url,
        operation_id,
    )
    if phase["state"] != "AWAITING_AUDIT_ACTIVATION":
        raise DatabaseRestoreRefused(
            "restore-bound audit activation is already committed",
        )
    phase_known_head = phase.get("known_head")
    if known_head is not None and known_head != phase_known_head:
        raise DatabaseRestoreRefused(
            "restore-bound PostgreSQL known-head differs from its durable phase",
        )
    known_head = phase_known_head
    engine = _pinned_coordinator_engine(target)
    connection: AsyncConnection | None = None
    lock_owned = False
    try:
        connection = await engine.connect()
        await connection.execute(
            text("SELECT pg_advisory_lock(:lock_id)"),
            {"lock_id": SCHEMA_TRANSITION_ADVISORY_LOCK_KEY},
        )
        await connection.commit()
        lock_owned = True
        await _verify_fence(target, fence)
        await connection.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": AUDIT_CHAIN_ADVISORY_LOCK_KEY},
        )
        await connection.execute(
            text(
                "LOCK TABLE audit_log, audit_chain_preparation IN SHARE ROW EXCLUSIVE MODE",
            ),
        )
        manifest = await connection.run_sync(
            lambda sync_connection: build_activation_manifest(
                sync_connection,
                settings,
                legacy_key_window_complete=legacy_key_window_complete,
                known_head=known_head,
            ),
        )
        preparation = phase["audit_preparation"]
        if (
            manifest["preparation_id"] != preparation["preparation_id"]
            or manifest["preparation_audit_key_id"] != preparation["audit_key_id"]
        ):
            raise DatabaseRestoreRefused(
                "activation manifest does not bind the restore preparation",
            )
        await connection.rollback()
        return manifest
    finally:
        if connection is not None:
            if lock_owned:
                with contextlib.suppress(Exception):
                    await connection.rollback()
                    await connection.execute(
                        text("SELECT pg_advisory_unlock(:lock_id)"),
                        {"lock_id": SCHEMA_TRANSITION_ADVISORY_LOCK_KEY},
                    )
                    await connection.commit()
            with contextlib.suppress(Exception):
                await connection.close()
        await engine.dispose()


async def _apply_restore_activation_manifest(
    database_url: str,
    *,
    operation_id: uuid.UUID,
    settings: Settings,
    manifest: dict[str, Any],
    attestation: str | None,
) -> dict[str, Any]:
    target, phase_path, phase, fence = await _restore_activation_phase(
        database_url,
        operation_id,
    )
    if manifest.get("known_head") != phase.get("known_head"):
        raise DatabaseRestoreRefused(
            "activation manifest does not bind the PostgreSQL restore known-head",
        )
    if phase["state"] == "AUDIT_ACTIVATED":
        if phase.get("activation_manifest_digest") != manifest.get(
            "manifest_digest",
        ):
            raise DatabaseRestoreRefused(
                "committed restore activation used a different manifest",
            )
        return phase
    preparation = phase["audit_preparation"]
    if (
        manifest.get("preparation_id") != preparation["preparation_id"]
        or manifest.get("preparation_audit_key_id") != preparation["audit_key_id"]
    ):
        raise DatabaseRestoreRefused(
            "activation manifest does not bind the restore preparation",
        )
    engine = _pinned_coordinator_engine(target)
    connection: AsyncConnection | None = None
    lock_owned = False
    try:
        connection = await engine.connect()
        await connection.execute(
            text("SELECT pg_advisory_lock(:lock_id)"),
            {"lock_id": SCHEMA_TRANSITION_ADVISORY_LOCK_KEY},
        )
        await connection.commit()
        lock_owned = True
        await _verify_fence(target, fence)
        await _upgrade_restored_database(
            connection,
            activation_manifest=manifest,
            activation_attestation=attestation,
        )
        # The migration runner owns its own transactions, but this function
        # ends by rolling this connection back, so anything still open here
        # would be discarded after the fence had already announced it. Close
        # the transaction and prove the activation from a connection that
        # cannot see uncommitted work, before the fence says it happened.
        await connection.commit()
        await _assert_restored_activation_is_durable(target)
        snapshot = await authenticated_database_snapshot(
            database_url,
            settings,
            connection=connection,
        )
        activated_fence = {
            **fence,
            "state": "AUDIT_ACTIVATED",
            "activation_manifest_digest": manifest["manifest_digest"],
        }
        await _set_fence(target, activated_fence)
        phase = {
            **phase,
            "state": "AUDIT_ACTIVATED",
            "fence": activated_fence,
            "activation_manifest_digest": manifest["manifest_digest"],
            "activation_attestation": attestation,
            "activated_snapshot_digest": snapshot["manifest_digest"],
        }
        _replace_phase(phase_path, phase)
        return phase
    finally:
        if connection is not None:
            if lock_owned:
                with contextlib.suppress(Exception):
                    await connection.rollback()
                    await connection.execute(
                        text("SELECT pg_advisory_unlock(:lock_id)"),
                        {"lock_id": SCHEMA_TRANSITION_ADVISORY_LOCK_KEY},
                    )
                    await connection.commit()
            with contextlib.suppress(Exception):
                await connection.close()
        await engine.dispose()


def build_restore_activation_manifest(
    database_url: str,
    *,
    operation: str,
    settings: Settings,
    legacy_key_window_complete: bool,
    known_head: dict[str, Any] | None,
) -> dict[str, Any]:
    """Finalize the manifest for one exact fenced legacy restore."""

    operation_id = uuid.UUID(operation)
    target = _parse_target(database_url)
    target_root = _target_phase_root(target, create=False)
    with audit_bootstrap_coordinator(target_root):
        return _run_pinned_client(
            _build_restore_activation_manifest(
                database_url,
                operation_id=operation_id,
                settings=settings,
                legacy_key_window_complete=legacy_key_window_complete,
                known_head=known_head,
            ),
        )


def apply_restore_activation_manifest(
    database_url: str,
    *,
    operation: str,
    settings: Settings,
    manifest: dict[str, Any],
    attestation: str | None,
) -> dict[str, Any]:
    """Apply one exact manifest to its fenced legacy restore."""

    operation_id = uuid.UUID(operation)
    target = _parse_target(database_url)
    target_root = _target_phase_root(target, create=False)
    with audit_bootstrap_coordinator(target_root):
        return _run_pinned_client(
            _apply_restore_activation_manifest(
                database_url,
                operation_id=operation_id,
                settings=settings,
                manifest=manifest,
                attestation=attestation,
            ),
        )


def restore_postgres_database(
    database_url: str,
    source: Path,
    *,
    operation: str | None = None,
    expected_sha256: str | None = None,
    stopped_executor_attestation: str | None = None,
    known_head: dict[str, Any] | None = None,
) -> dict[str, Any]:
    target = _parse_target(database_url)
    operation_id = uuid.UUID(operation) if operation is not None else uuid.uuid4()
    target_root = _target_phase_root(target, create=True)
    with audit_bootstrap_coordinator(target_root):
        return _run_pinned_client(
            _run_restore(
                database_url,
                source,
                operation=str(operation_id),
                expected_sha256=expected_sha256,
                stopped_executor_attestation=(stopped_executor_attestation),
                known_head=known_head,
            ),
        )


def staged_restore_source(
    database_url: str,
    *,
    operation: str | uuid.UUID,
) -> Path:
    """Return the source path one already-staged PostgreSQL operation carries.

    A resume reads its source from the durable phase and never reopens the
    operator's archive, which is why the refusals advertise ``--operation`` on
    its own. Handing that recorded path back lets the command an operator is
    told to run be the command they can run.
    """

    operation_id = operation if isinstance(operation, uuid.UUID) else uuid.UUID(str(operation))
    target = _parse_target(database_url)
    operation_dir = _phase_directory(target, operation_id, create=False)
    phase_path = operation_dir / "phase.json"
    try:
        phase = _read_phase(phase_path)
    except FileNotFoundError as exc:
        raise DatabaseRestoreRefused(
            f"there is no staged restore operation {operation_id}; supply the "
            f"backup PATH to start one",
        ) from exc
    if phase.get("backend") != "postgres" or phase.get("operation_id") != str(operation_id):
        raise DatabaseRestoreRefused(
            "PostgreSQL restore phase identity mismatch",
        )
    return Path(str(phase["source_provenance"]["supplied_path"]))


def rollback_postgres_database(
    database_url: str,
    *,
    operation: str,
) -> dict[str, Any]:
    operation_id = uuid.UUID(operation)
    target = _parse_target(database_url)
    target_root = _target_phase_root(target, create=False)
    operation_dir = target_root / str(operation_id)
    if not operation_dir.is_dir():
        raise DatabaseRestoreRefused(
            "PostgreSQL rollback lacks its exact restore phase",
        )
    ensure_secret_store_directory(operation_dir)
    with audit_bootstrap_coordinator(target_root):
        return _run_pinned_client(
            _run_rollback(
                database_url,
                operation=str(operation_id),
            ),
        )


__all__ = [
    "apply_restore_activation_manifest",
    "backup_postgres_database",
    "build_restore_activation_manifest",
    "restore_postgres_database",
    "rollback_postgres_database",
    "staged_restore_source",
]
