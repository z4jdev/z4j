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


def test_v1_6_6_scrub_worker_conf_strips_existing_rows_r7_h1(
    alembic_cfg: Config,
) -> None:
    """R7-H1: pre-1.6.6 worker rows carrying credentialed Celery conf
    must be scrubbed when ``alembic upgrade head`` runs.

    The migration is dialect-aware; this test covers the SQLite branch
    by stamping to the pre-1.6.6 head, manually inserting a
    representative ``workers`` row, then running ``upgrade head`` and
    asserting the JSON column no longer contains the secret values.
    The Postgres branch is exercised by ``test_migration_pg.py``.
    """
    import json
    import uuid

    from sqlalchemy import text as _text

    # Bring the schema up to just before 1.6.6 so the workers table
    # exists and we can pre-populate it.
    command.upgrade(alembic_cfg, "v1_6_mfa_totp")

    sync_url = alembic_cfg.attributes["test_sync_url"]
    engine = create_engine(sync_url)
    project_id = uuid.uuid4()
    worker_id = uuid.uuid4()
    leaky_metadata = {
        "stats": {"pool": {"max-concurrency": 2}},
        "active": [],
        "active_queues": [{"name": "celery"}],
        "registered": ["myapp.task"],
        "conf": {
            "broker_url": "redis://:LEAKED_CRED@redis.internal/0",
            "result_backend": "db+postgresql://u:LEAKED_PG@db/celery",
            "broker_transport_options": {"aws_secret_access_key": "LEAKED_AWS"},
            "task_serializer": "json",
        },
    }
    try:
        with engine.begin() as conn:
            # Insert a project parent so the FK is satisfied (the
            # workers row carries a project_id NOT NULL FK).
            conn.execute(
                _text(
                    "INSERT INTO projects (id, slug, name, created_at) "
                    "VALUES (:id, :slug, :name, datetime('now'))",
                ),
                {"id": str(project_id), "slug": "p1", "name": "P1"},
            )
            conn.execute(
                _text(
                    "INSERT INTO workers (id, project_id, engine, name, "
                    "state, last_heartbeat, metadata, created_at, updated_at) "
                    "VALUES (:id, :project_id, 'celery', 'celery@w1', "
                    "'online', datetime('now'), :md, datetime('now'), "
                    "datetime('now'))",
                ),
                {
                    "id": str(worker_id),
                    "project_id": str(project_id),
                    "md": json.dumps(leaky_metadata),
                },
            )

        # Now run the new migration.
        command.upgrade(alembic_cfg, "head")

        with engine.connect() as conn:
            row = conn.execute(
                _text("SELECT metadata FROM workers WHERE id = :id"),
                {"id": str(worker_id)},
            ).fetchone()
            assert row is not None
            md = json.loads(row[0]) if isinstance(row[0], str) else row[0]
            assert isinstance(md, dict)
            # conf was scrubbed to empty object.
            assert md.get("conf") == {}
            # Other sub-keys are untouched.
            assert md.get("stats", {}).get("pool", {}).get("max-concurrency") == 2
            assert md.get("registered") == ["myapp.task"]
            # And the raw secret values must not be anywhere in the JSON.
            blob = json.dumps(md)
            for needle in ("LEAKED_CRED", "LEAKED_PG", "LEAKED_AWS"):
                assert needle not in blob, (
                    "R7-H1 migration left %r in workers.metadata" % (needle,)
                )
    finally:
        engine.dispose()
