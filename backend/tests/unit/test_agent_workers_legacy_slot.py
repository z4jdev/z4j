"""Cross-dialect contract tests for the legacy agent-worker slot."""

from __future__ import annotations

import asyncio
import importlib
import os
import secrets
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from z4j_brain.persistence import models  # noqa: F401  register all metadata
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import Agent, AgentWorker, Project
from z4j_brain.persistence.repositories import AgentWorkerRepository

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def sqlite_engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{tmp_path / 'agent-workers.db'}",
        connect_args={"timeout": 30},
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


async def _seed_agent(engine: AsyncEngine) -> tuple[uuid.UUID, uuid.UUID]:
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as session:
        project = Project(
            slug=f"agent-workers-{uuid.uuid4().hex[:8]}",
            name="Agent workers",
        )
        session.add(project)
        await session.flush()
        agent = Agent(
            project_id=project.id,
            name="legacy-agent",
            token_hash=uuid.uuid4().hex,
            protocol_version="1",
            framework_adapter="bare",
        )
        session.add(agent)
        await session.commit()
        return project.id, agent.id


async def _seed_prior_revision_agent(engine: AsyncEngine) -> tuple[uuid.UUID, uuid.UUID]:
    """Seed through the historical schema, without current ORM-only columns."""

    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    async with engine.begin() as connection:
        await connection.execute(
            text("INSERT INTO projects (id, slug, name) VALUES (:id, :slug, :name)"),
            {
                "id": project_id.hex,
                "slug": f"agent-workers-{uuid.uuid4().hex[:8]}",
                "name": "Agent workers",
            },
        )
        await connection.execute(
            text(
                """
                INSERT INTO agents (
                    id, project_id, name, token_hash,
                    protocol_version, framework_adapter
                ) VALUES (
                    :id, :project_id, :name, :token_hash,
                    :protocol_version, :framework_adapter
                )
                """,
            ),
            {
                "id": agent_id.hex,
                "project_id": project_id.hex,
                "name": "legacy-agent",
                "token_hash": uuid.uuid4().hex,
                "protocol_version": "1",
                "framework_adapter": "bare",
            },
        )
    return project_id, agent_id


async def test_concurrent_sqlite_legacy_reconnects_share_one_row(
    sqlite_engine: AsyncEngine,
) -> None:
    project_id, agent_id = await _seed_agent(sqlite_engine)
    sessions = async_sessionmaker(sqlite_engine, expire_on_commit=False)
    start = asyncio.Event()

    async def reconnect(number: int) -> None:
        await start.wait()
        async with sessions() as session:
            await AgentWorkerRepository(session).register_or_refresh(
                agent_id=agent_id,
                project_id=project_id,
                worker_id=None,
                role=f"legacy-{number}",
                pid=10_000 + number,
            )
            await session.commit()

    attempts = [asyncio.create_task(reconnect(number)) for number in range(8)]
    start.set()
    await asyncio.gather(*attempts)

    async with sessions() as session:
        rows = list(
            (
                await session.execute(
                    select(AgentWorker).where(
                        AgentWorker.agent_id == agent_id,
                        AgentWorker.worker_id.is_(None),
                    ),
                )
            ).scalars(),
        )
        assert len(rows) == 1
        assert rows[0].state == "online"
        assert rows[0].pid in range(10_000, 10_008)

        # The database constraint, not only the UPSERT, is authoritative.
        session.add(
            AgentWorker(
                agent_id=agent_id,
                project_id=project_id,
                worker_id=None,
                state="online",
            ),
        )
        with pytest.raises(IntegrityError):
            await session.flush()


async def test_non_null_worker_ids_keep_composite_upsert_semantics(
    sqlite_engine: AsyncEngine,
) -> None:
    project_id, agent_id = await _seed_agent(sqlite_engine)
    sessions = async_sessionmaker(sqlite_engine, expire_on_commit=False)

    async with sessions() as session:
        repo = AgentWorkerRepository(session)
        await repo.register_or_refresh(
            agent_id=agent_id,
            project_id=project_id,
            worker_id="worker-a",
            pid=1,
        )
        await repo.register_or_refresh(
            agent_id=agent_id,
            project_id=project_id,
            worker_id="worker-b",
            pid=2,
        )
        await repo.register_or_refresh(
            agent_id=agent_id,
            project_id=project_id,
            worker_id="worker-a",
            pid=3,
        )
        await session.commit()

    async with sessions() as session:
        rows = list(
            (
                await session.execute(
                    select(AgentWorker)
                    .where(AgentWorker.agent_id == agent_id)
                    .order_by(AgentWorker.worker_id),
                )
            ).scalars(),
        )
    assert [(row.worker_id, row.pid) for row in rows] == [
        ("worker-a", 3),
        ("worker-b", 2),
    ]


async def test_upgrade_deduplicates_to_newest_legacy_observation(
    tmp_path: Path,
) -> None:
    """Exercise the migration's portable cleanup against pre-index SQLite."""

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'legacy.db'}")
    migration = importlib.import_module(
        "z4j_brain.migrations.versions.2026_08_12_0013_v1_9_agent_worker_legacy_slot",
    )
    now = datetime.now(UTC)
    agent_id = str(uuid.uuid4())
    older_id = str(uuid.uuid4())
    newer_id = str(uuid.uuid4())
    try:
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    """
                    CREATE TABLE agent_workers (
                        id TEXT PRIMARY KEY,
                        agent_id TEXT NOT NULL,
                        worker_id TEXT NULL,
                        last_connect_at DATETIME NULL,
                        last_seen_at DATETIME NULL,
                        created_at DATETIME NOT NULL,
                        updated_at DATETIME NOT NULL
                    )
                    """,
                ),
            )
            await connection.execute(
                text(
                    """
                    INSERT INTO agent_workers (
                        id, agent_id, worker_id, last_connect_at, last_seen_at,
                        created_at, updated_at
                    ) VALUES
                        (:older_id, :agent_id, NULL, :older_seen, :older_seen,
                         :older_seen, :older_seen),
                        (:newer_id, :agent_id, NULL, :newer_seen, :newer_seen,
                         :newer_seen, :newer_seen)
                    """,
                ),
                {
                    "older_id": older_id,
                    "newer_id": newer_id,
                    "agent_id": agent_id,
                    "older_seen": now - timedelta(minutes=1),
                    "newer_seen": now,
                },
            )
            await connection.run_sync(migration._deduplicate_legacy_slots)

            survivor = (
                await connection.execute(
                    select(func.count()).select_from(text("agent_workers")),
                )
            ).scalar_one()
            kept_id = (await connection.execute(text("SELECT id FROM agent_workers"))).scalar_one()
        assert survivor == 1
        assert kept_id == newer_id
    finally:
        await engine.dispose()


async def _upgrade_sqlite_database(
    database_path: Path,
    target: str,
    *,
    working_directory: Path,
) -> None:
    """Run the real Alembic chain with isolated settings."""

    backend_root = Path(__file__).resolve().parents[2]  # noqa: ASYNC240  test setup only
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    home = working_directory / "home"
    home.mkdir(mode=0o700, exist_ok=True)
    if os.name == "posix":
        home.chmod(0o700)
    keys = (
        "Z4J_DATABASE_URL",
        "Z4J_HOME",
        "Z4J_SECRET",
        "Z4J_SESSION_SECRET",
        "Z4J_AUDIT_CHAIN_SECRET",
        "Z4J_ENVIRONMENT",
    )
    saved = {key: os.environ.get(key) for key in keys}
    try:
        os.environ.update(
            {
                "Z4J_DATABASE_URL": f"sqlite+aiosqlite:///{database_path}",
                "Z4J_HOME": str(home),
                "Z4J_SECRET": secrets.token_urlsafe(48),
                "Z4J_SESSION_SECRET": secrets.token_urlsafe(48),
                "Z4J_AUDIT_CHAIN_SECRET": secrets.token_urlsafe(48),
                "Z4J_ENVIRONMENT": "dev",
            },
        )

        def _upgrade() -> None:
            previous_directory = Path.cwd()
            try:
                os.chdir(working_directory)
                command.upgrade(config, target)
            finally:
                os.chdir(previous_directory)

        await asyncio.get_running_loop().run_in_executor(None, _upgrade)
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


async def test_fresh_alembic_chain_reuses_metadata_created_partial_index(
    tmp_path: Path,
) -> None:
    """The consolidated baseline uses current metadata before revision 0013."""

    database_path = tmp_path / "fresh-chain.db"
    await _upgrade_sqlite_database(database_path, "head", working_directory=tmp_path)
    engine = create_async_engine(f"sqlite+aiosqlite:///{database_path}")
    try:
        async with engine.connect() as connection:
            indexes = (await connection.execute(text("PRAGMA index_list('agent_workers')"))).all()
            target = [row for row in indexes if row[1] == "ux_agent_workers_legacy_agent"]
            assert len(target) == 1
            assert target[0][2] == 1  # unique
            assert target[0][4] == 1  # partial
    finally:
        await engine.dispose()


async def test_prior_revision_upgrade_deduplicates_then_creates_index(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "prior-revision.db"
    await _upgrade_sqlite_database(
        database_path,
        "v1_9_schedule_control_columns",
        working_directory=tmp_path,
    )
    engine = create_async_engine(f"sqlite+aiosqlite:///{database_path}")
    project_id, agent_id = await _seed_prior_revision_agent(engine)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    # A real database upgraded from a previous release lacks the index.  The
    # IF EXISTS also keeps this fixture valid against transitional consolidated
    # baselines that briefly inherited the current model's partial index.
    async with engine.begin() as connection:
        await connection.execute(text("DROP INDEX IF EXISTS ux_agent_workers_legacy_agent"))
    async with sessions() as session:
        session.add_all(
            [
                AgentWorker(
                    agent_id=agent_id,
                    project_id=project_id,
                    worker_id=None,
                    role="older",
                    last_connect_at=now - timedelta(seconds=1),
                ),
                AgentWorker(
                    agent_id=agent_id,
                    project_id=project_id,
                    worker_id=None,
                    role="newer",
                    last_connect_at=now,
                ),
            ],
        )
        await session.commit()
    await engine.dispose()

    await _upgrade_sqlite_database(database_path, "head", working_directory=tmp_path)
    engine = create_async_engine(f"sqlite+aiosqlite:///{database_path}")
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with sessions() as session:
            rows = list(
                (
                    await session.execute(
                        select(AgentWorker).where(
                            AgentWorker.agent_id == agent_id,
                            AgentWorker.worker_id.is_(None),
                        ),
                    )
                ).scalars(),
            )
            assert len(rows) == 1
            assert rows[0].role == "newer"
    finally:
        await engine.dispose()
