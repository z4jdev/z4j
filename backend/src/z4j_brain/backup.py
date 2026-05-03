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

import shutil
import subprocess
import sys
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


def restore_sqlite(database_url: str, source: Path) -> None:
    """Restore a SQLite DB from ``source``.

    The brain's process MUST be stopped before calling this (the file
    needs an exclusive write). The CLI driver enforces this by
    refusing to run if it can detect a live brain process; this
    function trusts the caller and just does the file ops.
    """
    src = source.expanduser().resolve()
    if not src.exists():
        raise FileNotFoundError(f"restore: source file does not exist: {src}")
    dst = _sqlite_path_from_url(database_url)
    dst.parent.mkdir(parents=True, exist_ok=True)
    # Move existing DB (if any) to a .pre-restore-bak so the operator
    # can roll back if the new file turns out to be wrong.
    if dst.exists():
        bak = dst.with_suffix(dst.suffix + ".pre-restore-bak")
        if bak.exists():
            bak.unlink()
        dst.replace(bak)
    shutil.copy2(src, dst)


# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------


def _pg_libpq_url(database_url: str) -> str:
    """Convert ``postgresql+asyncpg://`` to libpq form for pg_dump."""
    return database_url.replace("postgresql+asyncpg://", "postgresql://", 1)


def backup_postgres(database_url: str, output: Path) -> None:
    """Snapshot a PostgreSQL DB via ``pg_dump`` to ``output``.

    Uses the custom format (``-Fc``) which is compressible and
    selective-restore-able, the format ``pg_restore`` was built for.
    Requires ``pg_dump`` on the operator's PATH.
    """
    if shutil.which("pg_dump") is None:
        raise RuntimeError(
            "backup: pg_dump not found on PATH. Install postgresql-client "
            "(Debian/Ubuntu: `apt install postgresql-client`; macOS: "
            "`brew install libpq && brew link --force libpq`).",
        )
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(
            f"backup: refusing to overwrite existing file at {output}",
        )
    libpq_url = _pg_libpq_url(database_url)
    # -Fc: custom format. -Z6: gzip compression. --no-owner / --no-acl
    # for portability across environments.
    result = subprocess.run(
        [
            "pg_dump",
            "-Fc",
            "-Z", "6",
            "--no-owner",
            "--no-acl",
            "-f", str(output),
            libpq_url,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        # Strip the URL from any error output - it carries the password.
        stderr = result.stderr.replace(libpq_url, "<DATABASE_URL>")
        raise RuntimeError(f"backup: pg_dump failed (rc={result.returncode}): {stderr}")


def restore_postgres(database_url: str, source: Path) -> None:
    """Restore a PostgreSQL DB from a ``pg_dump -Fc`` file via ``pg_restore``.

    Uses ``--clean --if-exists`` so the restore is idempotent against
    a partially-populated target DB. Operator must arrange to stop
    the brain (or at least quiesce writes) before calling - we don't
    detect that here.
    """
    if shutil.which("pg_restore") is None:
        raise RuntimeError(
            "restore: pg_restore not found on PATH. Install postgresql-client.",
        )
    src = source.expanduser().resolve()
    if not src.exists():
        raise FileNotFoundError(f"restore: source file does not exist: {src}")
    libpq_url = _pg_libpq_url(database_url)
    result = subprocess.run(
        [
            "pg_restore",
            "--clean",
            "--if-exists",
            "--no-owner",
            "--no-acl",
            "-d", libpq_url,
            str(src),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        stderr = result.stderr.replace(libpq_url, "<DATABASE_URL>")
        raise RuntimeError(
            f"restore: pg_restore failed (rc={result.returncode}): {stderr}",
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


def restore(database_url: str, source: Path) -> dict[str, Any]:
    """Dispatch to the right backend. Returns metadata about the result."""
    backend = detect_backend(database_url)
    if backend == "sqlite":
        restore_sqlite(database_url, source)
    else:
        restore_postgres(database_url, source)
    return {"backend": backend, "source": str(source.expanduser().resolve())}


__all__ = [
    "backup",
    "backup_postgres",
    "backup_sqlite",
    "detect_backend",
    "restore",
    "restore_postgres",
    "restore_sqlite",
]
