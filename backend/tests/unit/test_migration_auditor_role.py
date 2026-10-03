"""``v1_12_auditor_role`` in both directions on SQLite.

The revision adds the ``auditor`` label to the PostgreSQL ``project_role``
enum and is a no-op on SQLite, where the column is a plain ``VARCHAR``.
What this module proves on SQLite is the part that is engine-neutral:
the revision applies and reverts cleanly, a membership can hold the role
once it is applied, and the downgrade refuses while such a row exists
rather than leaving the previous brain a row it cannot read.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.util import CommandError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import Membership, Project, User

REVISION = "v1_12_auditor_role"
PREVIOUS = "v1_12_export_jobs_sink"


@pytest.fixture
def alembic_cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Config]:
    db_path = tmp_path / "brain.sqlite"
    sync_url = f"sqlite:///{db_path}"
    monkeypatch.setenv("Z4J_DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("Z4J_SECRET", "x" * 64)
    monkeypatch.setenv("Z4J_SESSION_SECRET", "y" * 64)
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", "a" * 64)
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    private_home = tmp_path / "home"
    private_home.mkdir()
    private_home.chmod(0o700)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.chdir(tmp_path)

    backend_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(backend_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend_root / "src" / "z4j_brain" / "migrations"))
    cfg.attributes["test_sync_url"] = sync_url
    cfg.attributes["test_db_path"] = db_path
    yield cfg


def _version(cfg: Config) -> str:
    engine = create_engine(cfg.attributes["test_sync_url"])
    try:
        with engine.connect() as connection:
            return str(
                connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
            )
    finally:
        engine.dispose()


def _add_member(cfg: Config, role: ProjectRole) -> uuid.UUID:
    engine = create_engine(cfg.attributes["test_sync_url"])
    try:
        with Session(engine) as session:
            project = Project(id=uuid.uuid4(), slug="default", name="Default")
            user = User(
                id=uuid.uuid4(),
                email=f"{uuid.uuid4().hex[:10]}@example.com",
                password_hash="x",
                is_admin=False,
                is_active=True,
            )
            session.add_all([project, user])
            session.flush()
            membership = Membership(user_id=user.id, project_id=project.id, role=role)
            session.add(membership)
            session.commit()
            return membership.id
    finally:
        engine.dispose()


def _roles_held(cfg: Config) -> list[str]:
    engine = create_engine(cfg.attributes["test_sync_url"])
    try:
        with engine.connect() as connection:
            return [
                str(row[0])
                for row in connection.exec_driver_sql(
                    "SELECT role FROM memberships ORDER BY role"
                ).all()
            ]
    finally:
        engine.dispose()


def _delete_memberships(cfg: Config) -> None:
    engine = create_engine(cfg.attributes["test_sync_url"])
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("DELETE FROM memberships")
    finally:
        engine.dispose()


def test_revision_chains_from_the_newest_wave_two_revision(alembic_cfg: Config) -> None:
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(alembic_cfg)
    revision = script.get_revision(REVISION)
    assert revision is not None
    assert revision.down_revision == PREVIOUS


def test_upgrade_then_downgrade_round_trips(alembic_cfg: Config) -> None:
    command.upgrade(alembic_cfg, REVISION)
    assert _version(alembic_cfg) == REVISION

    # The column accepts the new role once the revision is applied.
    _add_member(alembic_cfg, ProjectRole.AUDITOR)
    assert _roles_held(alembic_cfg) == ["auditor"]

    # Reverting with the role in use is refused and leaves the head alone.
    with pytest.raises(CommandError, match="auditor"):
        command.downgrade(alembic_cfg, PREVIOUS)
    assert _version(alembic_cfg) == REVISION
    assert _roles_held(alembic_cfg) == ["auditor"]

    # Move the member off the role and the revert goes through.
    _delete_memberships(alembic_cfg)
    command.downgrade(alembic_cfg, PREVIOUS)
    assert _version(alembic_cfg) == PREVIOUS

    # And forward again.
    command.upgrade(alembic_cfg, REVISION)
    assert _version(alembic_cfg) == REVISION


def test_other_roles_do_not_block_the_downgrade(alembic_cfg: Config) -> None:
    command.upgrade(alembic_cfg, REVISION)
    _add_member(alembic_cfg, ProjectRole.OPERATOR)
    command.downgrade(alembic_cfg, PREVIOUS)
    assert _version(alembic_cfg) == PREVIOUS
    assert _roles_held(alembic_cfg) == ["operator"]
