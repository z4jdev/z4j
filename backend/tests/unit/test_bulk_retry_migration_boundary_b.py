"""Boundary-B migration and rollback refusal on real SQLite."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.util import CommandError
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session
from z4j_brain.domain.bulk_retry import canonicalize_request
from z4j_brain.persistence.models import BulkRetryRequest, Project
from z4j_brain.secret_store import protect_secret_store_directory


@pytest.fixture
def boundary_b_alembic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Config:
    db_path = tmp_path / "boundary-b-migration.sqlite"
    sync_url = f"sqlite:///{db_path}"
    monkeypatch.setenv("Z4J_DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("Z4J_SECRET", "x" * 64)
    monkeypatch.setenv("Z4J_SESSION_SECRET", "y" * 64)
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", "a" * 64)
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    private_home = tmp_path / "z4j-home"
    private_home.mkdir(mode=0o700)
    protect_secret_store_directory(private_home)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.chdir(tmp_path)

    backend_root = Path(__file__).resolve().parents[2]
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    config.attributes["test_sync_url"] = sync_url
    return config


def test_upgrade_materializes_boundary_and_empty_roundtrip(
    boundary_b_alembic: Config,
) -> None:
    command.upgrade(boundary_b_alembic, "v1_8_bulk_retry_requests")
    engine = create_engine(boundary_b_alembic.attributes["test_sync_url"])
    try:
        inspector = inspect(engine)
        assert {
            "bulk_retry_requests",
            "bulk_retry_request_children",
        } <= set(inspector.get_table_names())
        assert "bulk_retry_child_id" in {
            column["name"] for column in inspector.get_columns("commands")
        }
        assert any(
            index["name"] == "ux_commands_bulk_retry_child" and index["unique"]
            for index in inspector.get_indexes("commands")
        )
    finally:
        engine.dispose()

    command.downgrade(boundary_b_alembic, "v1_7_security_hardening")
    command.upgrade(boundary_b_alembic, "v1_8_bulk_retry_requests")


def test_downgrade_refuses_while_any_durable_parent_exists(
    boundary_b_alembic: Config,
) -> None:
    command.upgrade(boundary_b_alembic, "v1_8_bulk_retry_requests")
    engine = create_engine(boundary_b_alembic.attributes["test_sync_url"])
    canonical = canonicalize_request({"filter": {"state": "failure"}})
    project_id = uuid.uuid4()
    try:
        with Session(engine) as session:
            session.add(Project(id=project_id, slug="rollback-fence", name="Fence"))
            session.commit()
            session.add(
                BulkRetryRequest(
                    id=uuid.uuid4(),
                    project_id=project_id,
                    idempotency_key="do-not-drop",
                    canonicalizer_version=canonical.version,
                    canonical_request=canonical.exact_bytes,
                    canonical_digest=canonical.digest,
                    effective_request=canonical.effective,
                    plan_digest="0" * 64,
                    child_count=0,
                    max_in_flight=8,
                    deadline_at=datetime.now(UTC) + timedelta(minutes=15),
                )
            )
            session.commit()
    finally:
        engine.dispose()

    with pytest.raises(CommandError, match="refusing downgrade"):
        command.downgrade(boundary_b_alembic, "v1_7_security_hardening")

    engine = create_engine(boundary_b_alembic.attributes["test_sync_url"])
    try:
        assert "bulk_retry_requests" in inspect(engine).get_table_names()
        with Session(engine) as session:
            assert session.query(BulkRetryRequest).count() == 1
    finally:
        engine.dispose()
