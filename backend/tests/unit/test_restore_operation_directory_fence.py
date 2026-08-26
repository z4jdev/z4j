"""A refused restore must not leave a fence the operator cannot clear.

Startup reads every directory under ``.z4j-restore/`` as an unfinished
restore. The operation directory used to be created before the refusals that
decide whether an operation should exist at all, so refusing a source left a
directory with no phase file in it -- and a directory with no phase is the
one state neither exit can clear: resume re-enters the same refusal, and
rollback reads the same phase file that is not there. A healthy live database
could not be started again.

The two halves are pinned separately: a refusal leaves nothing behind, and a
phase-less directory that does turn up (the crash window between creating the
directory and writing the phase) is survivable rather than terminal. The
second half has its own negative control, because "startup no longer refuses"
would also be true of deleting the fence.
"""

from __future__ import annotations

import os
import secrets
import shutil
import sqlite3
import uuid
from pathlib import Path

import pytest
from z4j_brain.management_restore import (
    DatabaseRestorePending,
    DatabaseRestoreRefused,
    assert_database_restore_not_pending,
    restore_sqlite_database,
    rollback_sqlite_database,
)
from z4j_brain.secret_store import ensure_secret_store_directory

_PHASE_ROOT = ".z4j-restore"


def _database_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path}"


def _operations(target: Path) -> list[Path]:
    root = target.parent / _PHASE_ROOT
    return sorted(root.iterdir()) if root.exists() else []


@pytest.fixture
def target(migrated_sqlite_template: Path, tmp_path: Path) -> Path:
    """A live database at the release head, in its own private directory."""

    home = tmp_path / "z4j-home"
    ensure_secret_store_directory(home)
    database = home / "z4j.db"
    shutil.copyfile(migrated_sqlite_template, database)
    return database


@pytest.fixture
def restore_environment(
    monkeypatch: pytest.MonkeyPatch,
    target: Path,
    migrated_audit_chain_secret: str,
) -> None:
    """The environment the ceremony reads its own Settings from.

    ``restore_sqlite_database`` constructs ``Settings()`` from the process
    environment, exactly as the CLI leaves it, and the audit-chain key has to
    be the one the target was activated with or the refusal under test is
    reached for the wrong reason.
    """
    for key in list(os.environ):
        if key.startswith("Z4J_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("Z4J_DATABASE_URL", _database_url(target))
    monkeypatch.setenv("Z4J_HOME", str(target.parent))
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.setenv("Z4J_SECRET", secrets.token_hex(32))
    monkeypatch.setenv("Z4J_SESSION_SECRET", secrets.token_hex(32))
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", migrated_audit_chain_secret)


def test_a_refused_source_leaves_no_operation_behind(
    target: Path,
    tmp_path: Path,
    restore_environment: None,
) -> None:
    """Refusing the source must not create the operation it refused.

    An archive taken at a migration head this release cannot carry forward
    is the refusal an operator actually meets: it is the reason the
    up-front head check exists, and it fires before anything is staged.
    """
    source = tmp_path / "from-a-future-release.db"
    with sqlite3.connect(source) as archive:
        archive.execute("CREATE TABLE alembic_version (version_num TEXT)")
        archive.execute(
            "INSERT INTO alembic_version (version_num) VALUES ('v9_9_from_the_future')",
        )

    with pytest.raises(DatabaseRestoreRefused, match="cannot restore a backup"):
        restore_sqlite_database(_database_url(target), source)

    assert _operations(target) == [], (
        "a refused restore left an operation directory, and startup reads "
        "one of those as a restore in flight"
    )
    # The live database is untouched and startable, which is the property
    # the operator actually lost.
    assert_database_restore_not_pending(_database_url(target))


def test_an_empty_operation_directory_is_survivable(target: Path) -> None:
    """The crash window between the directory and its phase is not fatal."""

    root = ensure_secret_store_directory(target.parent / _PHASE_ROOT)
    ensure_secret_store_directory(root / str(uuid.uuid4()))

    assert_database_restore_not_pending(_database_url(target))


def test_an_operation_directory_with_artifacts_still_fences(target: Path) -> None:
    """The negative control for the case above.

    A phase that was written and then lost leaves artifacts behind, and what
    was done to the target is then exactly what cannot be established. That
    still has to stop startup, or the previous test would be satisfied by
    removing the fence altogether.
    """
    root = ensure_secret_store_directory(target.parent / _PHASE_ROOT)
    operation_dir = ensure_secret_store_directory(root / str(uuid.uuid4()))
    (operation_dir / "target-recovery.db").write_bytes(b"artifact")

    with pytest.raises(DatabaseRestorePending):
        assert_database_restore_not_pending(_database_url(target))


def test_rolling_back_an_unknown_operation_creates_nothing(target: Path) -> None:
    """The command that clears a fence must not be able to raise one.

    ``--rollback-operation`` takes an id from the operator's terminal. A
    mistyped one used to create its own operation directory before reading
    the phase that was not in it, so a typo fenced a healthy brain.
    """
    unknown = uuid.uuid4()

    with pytest.raises(DatabaseRestoreRefused):
        rollback_sqlite_database(_database_url(target), operation=unknown)

    assert _operations(target) == []
    assert_database_restore_not_pending(_database_url(target))
