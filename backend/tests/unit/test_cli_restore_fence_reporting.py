"""``z4j status`` and ``z4j migrate current --check-heads`` report a restore fence.

An interrupted restore leaves a phase file beside the SQLite database, and the
fence in ``create_engine_from_settings`` and alembic's ``env.py`` refuses every
normal engine until the operation is resumed or rolled back. ``status`` used to
die on that refusal as a traceback (on PostgreSQL, whose fence sits on the
connection, it was swallowed into ``n/a`` row counts instead), and
``migrate current --check-heads`` printed the raw ``DatabaseRestorePending``
traceback. Both now print the fence's one line, which names the operation and
both exits, and return 2. The unfenced database is the positive control.
"""

from __future__ import annotations

import os
import secrets
import shutil
import uuid
from pathlib import Path

# Imported at collection time on purpose. ``alembic.config.Config`` binds its
# default ``stdout=sys.stdout`` when the module is first imported; if that
# first import happens inside a ``capsys`` test, every later alembic run in the
# session writes to that test's closed capture stream and dies with
# "I/O operation on closed file". Collection-time import binds the session
# stream, which stays open.
import alembic.config  # noqa: F401
import pytest
from z4j_brain import cli
from z4j_brain.domain.audit_chain import canonical_json
from z4j_brain.management_restore import _lexical_absolute, _sqlite_path_from_url
from z4j_brain.secret_store import ensure_secret_store_directory

_PHASE_ROOT = ".z4j-restore"


@pytest.fixture
def live_database(
    migrated_sqlite_template: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """A database at the release head in a private home, with the CLI env set."""
    home = tmp_path / "z4j-home"
    ensure_secret_store_directory(home)
    database = home / "z4j.db"
    shutil.copyfile(migrated_sqlite_template, database)
    for key in tuple(os.environ):
        if key.startswith("Z4J_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("Z4J_DATABASE_URL", f"sqlite+aiosqlite:///{database.as_posix()}")
    monkeypatch.setenv("Z4J_HOME", str(home))
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.setenv("Z4J_SECRET", secrets.token_hex(32))
    monkeypatch.setenv("Z4J_SESSION_SECRET", secrets.token_hex(32))
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", secrets.token_hex(32))
    monkeypatch.setenv("Z4J_ALLOWED_HOSTS", '["localhost","127.0.0.1"]')
    # alembic's env hook captures configuration from the current directory.
    monkeypatch.chdir(tmp_path)
    return database


def _fence(database: Path, *, state: str = "INSTALLING") -> uuid.UUID:
    """Write a pending phase for this database, the way the fence reads it."""
    operation_id = uuid.uuid4()
    root = ensure_secret_store_directory(database.parent / _PHASE_ROOT)
    operation_dir = ensure_secret_store_directory(root / str(operation_id))
    target = _lexical_absolute(_sqlite_path_from_url(os.environ["Z4J_DATABASE_URL"]))
    phase = {
        "operation_id": str(operation_id),
        "state": state,
        "target_path": str(target),
    }
    # O_BINARY: on Windows a text-mode descriptor rewrites the trailing "\n"
    # as "\r\n", and the fence reads the phase byte-for-byte canonically.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(operation_dir / "phase.json", flags, 0o600)
    try:
        os.write(fd, canonical_json(phase) + b"\n")
    finally:
        os.close(fd)
    return operation_id


def _one_line(err: str) -> str:
    lines = [line for line in err.splitlines() if line.strip()]
    assert len(lines) == 1, err
    assert "Traceback" not in err
    return lines[0]


def test_status_reports_the_fence_with_both_exits(
    live_database: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    operation_id = _fence(live_database)

    rc = cli.main(["status"])

    captured = capsys.readouterr()
    assert rc == 2
    line = _one_line(captured.err)
    assert line.startswith("z4j status: database restore is pending")
    assert f"z4j restore --force --operation {operation_id}" in line
    assert f"z4j restore --force --rollback-operation {operation_id}" in line
    assert "n/a" not in captured.out
    assert "row counts" not in captured.out


def test_status_on_the_unfenced_database_still_reports(
    live_database: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = cli.main(["status"])

    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert "alembic revision" in captured.out
    assert "row counts" in captured.out
    assert "restore is pending" not in captured.err


def test_check_heads_reports_the_fence_in_one_line(
    live_database: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    operation_id = _fence(live_database, state="CREATED")

    rc = cli.main(["migrate", "current", "--check-heads"])

    captured = capsys.readouterr()
    assert rc == 2
    line = _one_line(captured.err)
    assert line.startswith("z4j migrate: database restore is pending")
    assert f"--operation {operation_id}" in line
    assert f"--rollback-operation {operation_id}" in line
    assert "DatabaseRestorePending" not in captured.err


def test_check_heads_on_the_unfenced_database_passes(
    live_database: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = cli.main(["migrate", "current", "--check-heads"])

    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert "restore is pending" not in captured.err
