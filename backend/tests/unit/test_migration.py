"""Tests for the alembic initial migration.

Runs ``alembic upgrade head`` against an in-memory SQLite database.
The Postgres-only branches are dialect-guarded, so SQLite skips
extensions, ENUM types, partitioning, triggers, and GIN indexes -
the test still proves that the SQLAlchemy ``create_all`` half of
the migration is internally consistent and that downgrade reverses
cleanly.

Postgres-specific behaviour is exercised by the integration suite
(B7) against a real Postgres 18 container.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


@pytest.fixture
def alembic_cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Config:
    db_path = tmp_path / "brain.sqlite"
    sync_url = f"sqlite:///{db_path}"

    # Settings reads Z4J_DATABASE_URL - we point env.py at the
    # async-sqlite version, but the migration test uses the sync
    # variant via a forced override below.
    monkeypatch.setenv("Z4J_DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("Z4J_SECRET", "x" * 64)
    monkeypatch.setenv("Z4J_SESSION_SECRET", "y" * 64)
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")

    backend_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(backend_root / "alembic.ini"))
    cfg.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    # We expose the sync URL for the test only - env.py normally
    # uses the async one.
    cfg.attributes["test_sync_url"] = sync_url
    return cfg


def test_migration_runs_on_sqlite(alembic_cfg: Config) -> None:
    """``alembic upgrade head`` should produce all 12 tables on SQLite."""
    command.upgrade(alembic_cfg, "head")

    sync_url = alembic_cfg.attributes["test_sync_url"]
    engine = create_engine(sync_url)
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
    finally:
        engine.dispose()

    assert tables >= {
        "users",
        "projects",
        "memberships",
        "agents",
        "queues",
        "workers",
        "tasks",
        "events",
        "schedules",
        "commands",
        "audit_log",
        "first_boot_tokens",
        # alembic's own bookkeeping table
        "alembic_version",
    }


def test_migration_downgrade_runs(alembic_cfg: Config) -> None:
    """upgrade → downgrade is a clean round-trip on SQLite."""
    command.upgrade(alembic_cfg, "head")
    command.downgrade(alembic_cfg, "base")

    sync_url = alembic_cfg.attributes["test_sync_url"]
    engine = create_engine(sync_url)
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
    finally:
        engine.dispose()

    # Only the alembic bookkeeping table should remain.
    assert tables <= {"alembic_version"}
