"""Backup + restore the brain's database.

Two backends, one operator surface:

- **SQLite**: uses SQLite's online ``VACUUM INTO`` to produce a consistent
  snapshot file without stopping the brain. Restore is a sanity-checked
  file replacement (with the live DB stopped).
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

from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def detect_backend(database_url: str) -> str:
    """Return ``"sqlite"`` or ``"postgres"`` for a given async DB URL."""
    if database_url.startswith(("sqlite", "sqlite+aiosqlite")):
        return "sqlite"
    if database_url.startswith(("postgresql", "postgres")):
        return "postgres"
    raise ValueError(
        f"backup: unsupported database URL scheme - "
        f"only sqlite and postgresql are supported (got {database_url!r})",
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

    VACUUM INTO produces a consistent point-in-time copy without
    locking the source DB - the brain can keep serving requests
    throughout. The output is a fully self-contained SQLite file
    (no WAL, no journal). Restore is a plain file copy.
    """
    src = _sqlite_path_from_url(database_url)
    if not src.exists():
        raise FileNotFoundError(
            f"backup: source SQLite file does not exist: {src}",
        )
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(
            f"backup: refusing to overwrite existing file at {output}. "
            f"Move/delete it first, or pick a different --output path.",
        )
    # Use stdlib sqlite3 - no async needed, we just want the
    # synchronous VACUUM INTO. The async aiosqlite layer is for
    # request handling, not maintenance ops.
    import sqlite3

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


def backup_postgres(database_url: str, output: Path) -> None:
    """Snapshot PostgreSQL through the trusted pinned client runner."""

    from z4j_brain.management_restore_postgres import (
        backup_postgres_database,
    )

    backup_postgres_database(database_url, output)


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
