"""Backup + restore the brain's database.

Two backends, one operator surface:

- **SQLite**: uses ``VACUUM INTO`` from a separate connection to produce a
  consistent snapshot file. The helper does not quiesce the brain and is
  not lock-free: it participates in SQLite's normal transaction locking,
  so concurrent traffic may delay the backup, be delayed itself, or make
  the operation fail. Use a maintenance window when predictable completion
  matters. Restore is a sanity-checked file replacement with the live DB
  stopped.
- **PostgreSQL**: shells out to ``pg_dump`` / ``pg_restore``, since
  reimplementing those tools is folly. The brain does not need to be
  stopped for a dump.

Both produce a single output file that can be moved off-host with
``scp`` / object storage / your existing backup tooling.

The CLI surface (``z4j backup`` / ``z4j restore``) lives in cli.py;
this module is the engine. Kept separate so the CLI test surface
stays small and so a future scheduled-backup worker can call into
this module without going through argparse.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlparse

from z4j_core.redaction import redact_url_password

_T = TypeVar("_T")

#: A snapshot carries users, API keys, sessions, task history and the audit
#: chain in the clear, so it is exactly as sensitive as the live database and
#: must never be legible to anyone but the operator who took it.
_BACKUP_FILE_MODE = 0o600


def detect_backend(database_url: str) -> str:
    """Return ``"sqlite"`` or ``"postgres"`` for a given async DB URL."""
    if database_url.startswith(("sqlite", "sqlite+aiosqlite")):
        return "sqlite"
    if database_url.startswith(("postgresql", "postgres")):
        return "postgres"
    # Redacted even though an unsupported scheme is unlikely to be a real DSN:
    # this message reaches an operator's terminal and their ticket, and a
    # mistyped URL is still a URL with the password in it.
    raise ValueError(
        f"backup: unsupported database URL scheme - "
        f"only sqlite and postgresql are supported "
        f"(got {redact_url_password(database_url)!r})",
    )


# ---------------------------------------------------------------------------
# SQLite
# ---------------------------------------------------------------------------


def _sqlite_path_from_url(database_url: str) -> Path:
    """Pull the on-disk path out of an async SQLAlchemy SQLite URL.

    Handles ``sqlite:////absolute/path``, ``sqlite+aiosqlite:////abs``,
    and the rare relative form ``sqlite:///./relative.db``.
    """
    # SQLAlchemy URLs use 4 slashes for absolute paths on Unix:
    # sqlite+aiosqlite:////root/.z4j/z4j.db -> /root/.z4j/z4j.db
    parsed = urlparse(database_url)
    raw = parsed.path
    if raw.startswith("/"):
        return Path(raw[1:]) if raw.startswith("//") is False else Path(raw)
    return Path(raw)


def backup_sqlite(database_url: str, output: Path) -> None:
    """Snapshot a SQLite DB to ``output`` using ``VACUUM INTO``.

    ``VACUUM INTO`` produces a consistent point-in-time copy, but it is
    not a lock-free online-backup protocol. This helper opens a separate
    SQLite connection without coordinating or quiescing the brain; normal
    SQLite read/write locks still apply, so concurrent requests and the
    backup can contend or fail on a busy database. The output is a fully
    self-contained SQLite file (no WAL, no journal). Restore is a plain
    file copy performed while the live database is stopped.

    On POSIX the snapshot is created mode 0600 before data is written. On
    Windows the file inherits the destination directory's DACL, so callers
    must choose a directory restricted to the backup identity and intended
    administrators.
    """
    src = _sqlite_path_from_url(database_url)
    if not src.exists():
        raise FileNotFoundError(
            f"backup: source SQLite file does not exist: {src}",
        )
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    # Reserve the path ourselves instead of letting VACUUM INTO create it.
    # Left to SQLite the snapshot is born with the process umask, which is
    # 0644 on an ordinary host, and a chmod afterwards would still publish
    # the database contents for the whole length of the vacuum. O_EXCL also
    # makes the refusal below atomic rather than a check some other writer
    # can win a race against.
    try:
        reserved = os.open(
            output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            _BACKUP_FILE_MODE,
        )
    except FileExistsError as exists:
        raise FileExistsError(
            f"backup: refusing to overwrite existing file at {output}. "
            f"Move/delete it first, or pick a different --output path.",
        ) from exists
    os.close(reserved)
    # Use stdlib sqlite3 - no async needed, we just want the
    # synchronous VACUUM INTO. The async aiosqlite layer is for
    # request handling, not maintenance ops.
    import sqlite3

    try:
        conn = sqlite3.connect(src)
        try:
            # str(output) needed because SQLite's parameter binding
            # does not handle Path; embed the literal path safely
            # via single-quote escaping.
            safe_path = str(output).replace("'", "''")
            conn.execute(f"VACUUM INTO '{safe_path}'")
            conn.commit()
        finally:
            conn.close()
        # Backstop for a SQLite build that unlinks the reservation and
        # recreates the target rather than writing into the inode we made:
        # whatever the provenance of the file that lands here, it leaves
        # private.
        output.chmod(_BACKUP_FILE_MODE)
    except BaseException:
        # A vacuum that failed leaves either our empty reservation or a
        # half-written database. Both block the operator's retry with the
        # refusal above, and the second one sits on disk looking like a
        # usable backup.
        with contextlib.suppress(OSError):
            output.unlink()
        raise


def restore_sqlite(
    database_url: str,
    source: Path,
    *,
    operation: str | None = None,
    expected_sha256: str | None = None,
    stopped_executor_attestation: str | None = None,
    known_head: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the authenticated crash-resumable SQLite restore ceremony."""

    from z4j_brain.management_restore import restore_sqlite_database

    return restore_sqlite_database(
        database_url,
        source,
        operation=operation,
        expected_sha256=expected_sha256,
        stopped_executor_attestation=stopped_executor_attestation,
        known_head=known_head,
    )


# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------


# The pinned-loop runner lives beside the psycopg client in
# management_restore_postgres, because every entry point there needs it and a
# copy here would drift from the one that matters.


def backup_postgres(database_url: str, output: Path) -> None:
    """Snapshot PostgreSQL through the trusted pinned client runner."""

    from z4j_brain.management_restore_postgres import _run_backup, _run_pinned_client

    # The ceremony's own synchronous wrapper reaches straight for
    # ``asyncio.run``, so the loop it runs on is not the caller's to pick.
    # Drive the coroutine from here instead, which keeps the selector loop
    # Windows needs scoped to this single operation.
    _run_pinned_client(_run_backup(database_url, output))


def restore_postgres(
    database_url: str,
    source: Path,
    *,
    operation: str | None = None,
    expected_sha256: str | None = None,
    stopped_executor_attestation: str | None = None,
    known_head: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the durable PostgreSQL replacement ceremony."""

    from z4j_brain.management_restore_postgres import (
        restore_postgres_database,
    )

    return restore_postgres_database(
        database_url,
        source,
        operation=operation,
        expected_sha256=expected_sha256,
        stopped_executor_attestation=stopped_executor_attestation,
        known_head=known_head,
    )


def rollback_restore(
    database_url: str,
    *,
    operation: str,
) -> dict[str, Any]:
    """Roll back one exact pending database-replacement operation."""

    backend = detect_backend(database_url)
    if backend == "postgres":
        from z4j_brain.management_restore_postgres import (
            rollback_postgres_database,
        )

        return rollback_postgres_database(
            database_url,
            operation=operation,
        )
    from z4j_brain.management_restore import (
        rollback_sqlite_database,
    )

    return rollback_sqlite_database(
        database_url,
        operation=operation,
    )


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def backup(database_url: str, output: Path) -> dict[str, Any]:
    """Dispatch to the right backend. Returns metadata about the result."""
    backend = detect_backend(database_url)
    if backend == "sqlite":
        backup_sqlite(database_url, output)
    else:
        backup_postgres(database_url, output)
    out = output.expanduser().resolve()
    return {
        "backend": backend,
        "path": str(out),
        "size_bytes": out.stat().st_size if out.exists() else 0,
    }


def restore(
    database_url: str,
    source: Path,
    *,
    operation: str | None = None,
    expected_sha256: str | None = None,
    stopped_executor_attestation: str | None = None,
    known_head: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Dispatch to the right backend. Returns metadata about the result."""
    backend = detect_backend(database_url)
    if backend == "sqlite":
        return restore_sqlite(
            database_url,
            source,
            operation=operation,
            expected_sha256=expected_sha256,
            stopped_executor_attestation=(stopped_executor_attestation),
            known_head=known_head,
        )
    return restore_postgres(
        database_url,
        source,
        operation=operation,
        expected_sha256=expected_sha256,
        stopped_executor_attestation=stopped_executor_attestation,
        known_head=known_head,
    )


__all__ = [
    "backup",
    "backup_postgres",
    "backup_sqlite",
    "detect_backend",
    "restore",
    "restore_postgres",
    "restore_sqlite",
]
