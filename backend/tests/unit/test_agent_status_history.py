"""Tests for the 1.5.0 ``agent_status_history`` plumbing.

Covers, top-to-bottom:

- ORM model: round-trip insert + read of every column.
- Repository: ``insert`` / ``recent_for_agent`` ordering / bounded
  ``delete_older_than``.
- Frame router: an ``agent_status`` frame goes through
  ``FrameRouter.dispatch`` and lands in the table with the right
  project_id / agent_id / captured_at / payload.
- Retention sweep: the ``AuditRetentionSweeper`` purges old
  ``agent_status_history`` rows on the same pass that prunes
  audit_log, using ``event_retention_days`` as the cutoff.

All tests run against in-memory SQLite (the brain's portable
adapter); the Postgres-only paths (BIGSERIAL, JSONB indexes) are
exercised by the integration suite.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from z4j_brain.audit_retention import AuditRetentionSweeper
from z4j_brain.persistence import models  # noqa: F401  - register mappers
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import (
    Agent,
    AgentStatusHistory,
    Project,
)
from z4j_brain.persistence.repositories import AgentStatusHistoryRepository
from z4j_brain.settings import Settings
from z4j_brain.websocket.frame_router import FrameRouter
from z4j_core.transport.frames import AgentStatusFrame, AgentStatusPayload


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def settings() -> Settings:
    """Brain settings with both retention knobs in scope."""
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        # Both retentions in scope; the agent_status sweep uses
        # event_retention_days, the audit sweep uses
        # audit_retention_days.
        event_retention_days=14,
        audit_retention_days=30,
        audit_retention_sweep_batch_size=100,
    )


@pytest.fixture
async def db_manager() -> DatabaseManager:
    """An async SQLite DatabaseManager with the full schema applied."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    db = DatabaseManager(engine)
    yield db
    await engine.dispose()


@pytest.fixture
async def project_and_agent(
    db_manager: DatabaseManager,
) -> tuple[uuid.UUID, uuid.UUID]:
    """Seed one project + one agent so FK constraints are satisfied."""
    factory = sessionmaker(
        db_manager._engine, class_=AsyncSession, expire_on_commit=False,
    )
    async with factory() as s:
        p = Project(slug="status-test", name="Status Test")
        s.add(p)
        await s.flush()
        project_id = p.id

        a = Agent(
            project_id=project_id,
            name="status-test-agent",
            token_hash="t" * 64,
            protocol_version="2",
            framework_adapter="bare",
        )
        s.add(a)
        await s.flush()
        agent_id = a.id
        await s.commit()
    return project_id, agent_id


def _payload_dict() -> dict:
    """A representative AgentStatusPayload as a JSON-friendly dict."""
    return AgentStatusPayload(
        auth_failure_streak=0,
        protocol_failure_streak=1,
        connection_failure_streak=2,
        last_successful_connect_at=datetime(2026, 5, 1, 12, 0, tzinfo=UTC),
        current_session_age_seconds=3600.5,
        buffer_depth=12,
        buffer_oldest_age_seconds=4.2,
        agent_version="1.5.0",
        protocol_version="2",
        engines=["celery", "rq"],
        schedulers=["celery-beat"],
    ).model_dump(mode="json")


# ---------------------------------------------------------------------------
# 1) ORM model round-trip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestModelRoundTrip:
    async def test_insert_and_read_back(
        self,
        db_manager: DatabaseManager,
        project_and_agent: tuple[uuid.UUID, uuid.UUID],
    ) -> None:
        project_id, agent_id = project_and_agent
        captured = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
        payload = _payload_dict()

        async with db_manager.session() as session:
            row = AgentStatusHistory(
                project_id=project_id,
                agent_id=agent_id,
                captured_at=captured,
                payload=payload,
            )
            session.add(row)
            await session.commit()
            row_id = row.id

        # row_id must be a positive autoincrement int.
        assert isinstance(row_id, int) and row_id > 0

        async with db_manager.session() as session:
            fetched = await session.get(AgentStatusHistory, row_id)
            assert fetched is not None
            assert fetched.project_id == project_id
            assert fetched.agent_id == agent_id
            # SQLite returns naive datetimes; compare on the
            # wall-clock fields rather than tz-aware equality.
            assert fetched.captured_at.replace(tzinfo=UTC) == captured or (
                fetched.captured_at == captured
            )
            assert fetched.payload["auth_failure_streak"] == 0
            assert fetched.payload["agent_version"] == "1.5.0"


# ---------------------------------------------------------------------------
# 2) Repository methods
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestRepository:
    async def test_insert_round_trip(
        self,
        db_manager: DatabaseManager,
        project_and_agent: tuple[uuid.UUID, uuid.UUID],
    ) -> None:
        project_id, agent_id = project_and_agent
        captured = datetime(2026, 5, 2, 9, 0, tzinfo=UTC)

        async with db_manager.session() as session:
            repo = AgentStatusHistoryRepository(session)
            row = await repo.insert(
                project_id=project_id,
                agent_id=agent_id,
                captured_at=captured,
                payload=_payload_dict(),
            )
            await session.commit()
            assert row.id is not None
            assert row.payload["engines"] == ["celery", "rq"]

    async def test_recent_for_agent_ordering(
        self,
        db_manager: DatabaseManager,
        project_and_agent: tuple[uuid.UUID, uuid.UUID],
    ) -> None:
        """``recent_for_agent`` must return rows newest-first and bounded
        by ``limit``."""
        project_id, agent_id = project_and_agent
        base_ts = datetime(2026, 5, 1, 0, 0, tzinfo=UTC)

        async with db_manager.session() as session:
            repo = AgentStatusHistoryRepository(session)
            for offset in range(10):
                await repo.insert(
                    project_id=project_id,
                    agent_id=agent_id,
                    captured_at=base_ts + timedelta(minutes=offset),
                    payload={"i": offset},
                )
            await session.commit()

        async with db_manager.session() as session:
            repo = AgentStatusHistoryRepository(session)
            rows = await repo.recent_for_agent(
                agent_id=agent_id, limit=5,
            )
            assert len(rows) == 5
            # Newest first: payload["i"] descends from 9 to 5.
            assert [r.payload["i"] for r in rows] == [9, 8, 7, 6, 5]

    async def test_recent_for_agent_limit_bounds(
        self,
        db_manager: DatabaseManager,
        project_and_agent: tuple[uuid.UUID, uuid.UUID],
    ) -> None:
        """``limit`` outside [1, 1000] must raise ValueError."""
        _, agent_id = project_and_agent
        async with db_manager.session() as session:
            repo = AgentStatusHistoryRepository(session)
            with pytest.raises(ValueError):
                await repo.recent_for_agent(agent_id=agent_id, limit=0)
            with pytest.raises(ValueError):
                await repo.recent_for_agent(agent_id=agent_id, limit=2000)

    async def test_delete_older_than_purges_only_old_rows(
        self,
        db_manager: DatabaseManager,
        project_and_agent: tuple[uuid.UUID, uuid.UUID],
    ) -> None:
        project_id, agent_id = project_and_agent
        now = datetime.now(UTC)

        async with db_manager.session() as session:
            repo = AgentStatusHistoryRepository(session)
            # 3 ancient rows + 2 fresh rows
            for i in range(3):
                await repo.insert(
                    project_id=project_id,
                    agent_id=agent_id,
                    captured_at=now - timedelta(days=30 + i),
                    payload={"old": i},
                )
            for i in range(2):
                await repo.insert(
                    project_id=project_id,
                    agent_id=agent_id,
                    captured_at=now - timedelta(hours=i),
                    payload={"fresh": i},
                )
            await session.commit()

        async with db_manager.session() as session:
            repo = AgentStatusHistoryRepository(session)
            cutoff = now - timedelta(days=14)
            deleted = await repo.delete_older_than(cutoff=cutoff)
            await session.commit()
            assert deleted == 3

        async with db_manager.session() as session:
            remaining = (
                await session.execute(select(AgentStatusHistory))
            ).scalars().all()
            assert len(remaining) == 2
            for r in remaining:
                assert "fresh" in r.payload

    async def test_delete_older_than_batch_bounds(
        self,
        db_manager: DatabaseManager,
    ) -> None:
        """``batch_size`` outside [1, 100_000] must raise."""
        async with db_manager.session() as session:
            repo = AgentStatusHistoryRepository(session)
            with pytest.raises(ValueError):
                await repo.delete_older_than(
                    cutoff=datetime.now(UTC), batch_size=0,
                )
            with pytest.raises(ValueError):
                await repo.delete_older_than(
                    cutoff=datetime.now(UTC), batch_size=200_000,
                )


# ---------------------------------------------------------------------------
# 3) FrameRouter integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestFrameRouterIntegration:
    """The full ingest path: AgentStatusFrame → router.dispatch → DB row."""

    async def test_agent_status_frame_lands_in_table(
        self,
        db_manager: DatabaseManager,
        project_and_agent: tuple[uuid.UUID, uuid.UUID],
    ) -> None:
        project_id, agent_id = project_and_agent
        captured = datetime(2026, 5, 5, 12, 30, tzinfo=UTC)

        frame = AgentStatusFrame(
            id=str(uuid.uuid4()),
            ts=captured,
            payload=AgentStatusPayload(
                auth_failure_streak=2,
                protocol_failure_streak=0,
                connection_failure_streak=5,
                last_successful_connect_at=captured - timedelta(hours=4),
                current_session_age_seconds=14_400.0,
                buffer_depth=42,
                buffer_oldest_age_seconds=12.5,
                agent_version="1.5.0",
                protocol_version="2",
                engines=["celery"],
                schedulers=[],
            ),
        )

        router = FrameRouter(
            db=db_manager,
            ingestor=None,  # not used for agent_status
            dispatcher=None,
            project_id=project_id,
            agent_id=agent_id,
            dashboard_hub=None,
            worker_id=None,
        )

        # ---- THE CALL UNDER TEST ----
        # Goes through dispatch() so the type-routing branch is
        # exercised, not just the raw handler.
        await router.dispatch(frame)

        async with db_manager.session() as session:
            rows = (
                await session.execute(select(AgentStatusHistory))
            ).scalars().all()
            assert len(rows) == 1
            row = rows[0]
            assert row.project_id == project_id
            assert row.agent_id == agent_id
            # captured_at must be the frame's ``ts`` (agent clock),
            # not datetime.now() (brain clock).
            assert row.captured_at.replace(tzinfo=UTC) == captured or (
                row.captured_at == captured
            )
            assert row.payload["auth_failure_streak"] == 2
            assert row.payload["connection_failure_streak"] == 5
            assert row.payload["buffer_depth"] == 42
            assert row.payload["agent_version"] == "1.5.0"
            assert row.payload["engines"] == ["celery"]

    async def test_agent_status_persist_failure_does_not_raise(
        self,
        db_manager: DatabaseManager,
        project_and_agent: tuple[uuid.UUID, uuid.UUID],
    ) -> None:
        """A DB failure during agent_status insert must be swallowed.

        The agent_status path is observability data; a transient DB
        hiccup must not flap the WS connection (the dispatch loop
        relies on this contract per the audit fix in the heartbeat
        path).
        """
        project_id, agent_id = project_and_agent

        # Frame with an agent_id that has no FK target in agents.
        # The router uses self._agent_id, not the frame, so we
        # construct the router with a bogus agent_id to force the
        # FK violation.
        bogus_agent_id = uuid.uuid4()
        router = FrameRouter(
            db=db_manager,
            ingestor=None,
            dispatcher=None,
            project_id=project_id,
            agent_id=bogus_agent_id,
            dashboard_hub=None,
            worker_id=None,
        )
        frame = AgentStatusFrame(
            id=str(uuid.uuid4()),
            ts=datetime.now(UTC),
            payload=AgentStatusPayload(),
        )

        # Must NOT raise - the handler swallows the integrity error.
        await router.dispatch(frame)


# ---------------------------------------------------------------------------
# 4) Retention sweep extension
# ---------------------------------------------------------------------------


async def _seed_status_rows(
    db_manager: DatabaseManager,
    *,
    project_id: uuid.UUID,
    agent_id: uuid.UUID,
    when: list[datetime],
) -> None:
    async with db_manager.session() as session:
        repo = AgentStatusHistoryRepository(session)
        for ts in when:
            await repo.insert(
                project_id=project_id,
                agent_id=agent_id,
                captured_at=ts,
                payload={"ts": ts.isoformat()},
            )
        await session.commit()


@pytest.mark.asyncio
class TestRetentionSweep:
    async def test_sweeper_purges_old_status_rows(
        self,
        db_manager: DatabaseManager,
        project_and_agent: tuple[uuid.UUID, uuid.UUID],
        settings: Settings,
    ) -> None:
        project_id, agent_id = project_and_agent
        now = datetime.now(UTC)
        # 4 ancient rows (well past event_retention_days=14) + 2 fresh.
        await _seed_status_rows(
            db_manager,
            project_id=project_id,
            agent_id=agent_id,
            when=[
                now - timedelta(days=30),
                now - timedelta(days=20),
                now - timedelta(days=15),
                now - timedelta(days=14, hours=1),
                now - timedelta(hours=1),
                now,
            ],
        )

        sweeper = AuditRetentionSweeper()
        sweeper._db = db_manager
        sweeper._settings = settings
        # sweep_once returns the audit_log delete count (0 here);
        # the agent_status count lives on its own attribute.
        await sweeper.sweep_once()
        assert sweeper.last_agent_status_deleted == 4
        assert sweeper.total_agent_status_deleted == 4

        async with db_manager.session() as session:
            remaining = (
                await session.execute(select(AgentStatusHistory))
            ).scalars().all()
            assert len(remaining) == 2

    async def test_sweeper_keeps_recent_status_rows(
        self,
        db_manager: DatabaseManager,
        project_and_agent: tuple[uuid.UUID, uuid.UUID],
        settings: Settings,
    ) -> None:
        """Rows newer than event_retention_days must survive the sweep."""
        project_id, agent_id = project_and_agent
        now = datetime.now(UTC)
        await _seed_status_rows(
            db_manager,
            project_id=project_id,
            agent_id=agent_id,
            when=[
                now - timedelta(days=settings.event_retention_days - 1),
                now - timedelta(hours=2),
                now,
            ],
        )

        sweeper = AuditRetentionSweeper()
        sweeper._db = db_manager
        sweeper._settings = settings
        await sweeper.sweep_once()
        assert sweeper.last_agent_status_deleted == 0

        async with db_manager.session() as session:
            remaining = (
                await session.execute(select(AgentStatusHistory))
            ).scalars().all()
            assert len(remaining) == 3

    async def test_sweeper_disabled_when_event_retention_zero(
        self,
        db_manager: DatabaseManager,
        project_and_agent: tuple[uuid.UUID, uuid.UUID],
        settings: Settings,
    ) -> None:
        """``event_retention_days <= 0`` must short-circuit the sweep.

        Pydantic gates the field at >=1, but the sweeper's runtime
        guard exists in case an operator forces the field via raw
        attribute assignment (or a future setting flips the default
        to 0). We assert the guard explicitly.
        """
        project_id, agent_id = project_and_agent
        now = datetime.now(UTC)
        await _seed_status_rows(
            db_manager,
            project_id=project_id,
            agent_id=agent_id,
            when=[now - timedelta(days=365)],
        )
        # Force-set 0 to exercise the runtime guard.
        object.__setattr__(settings, "event_retention_days", 0)

        sweeper = AuditRetentionSweeper()
        sweeper._db = db_manager
        sweeper._settings = settings
        await sweeper.sweep_once()
        assert sweeper.last_agent_status_deleted == 0

        async with db_manager.session() as session:
            remaining = (
                await session.execute(select(AgentStatusHistory))
            ).scalars().all()
            assert len(remaining) == 1  # ancient row survives

    async def test_sweeper_batches_large_backlog(
        self,
        db_manager: DatabaseManager,
        project_and_agent: tuple[uuid.UUID, uuid.UUID],
        settings: Settings,
    ) -> None:
        """A backlog larger than batch_size must drain across multiple
        batches in one pass."""
        project_id, agent_id = project_and_agent
        # 250 ancient rows; batch_size=100 from the fixture means
        # the inner loop runs 3 times (100 + 100 + 50).
        now = datetime.now(UTC)
        await _seed_status_rows(
            db_manager,
            project_id=project_id,
            agent_id=agent_id,
            when=[
                now - timedelta(days=30, seconds=i)
                for i in range(250)
            ],
        )

        sweeper = AuditRetentionSweeper()
        sweeper._db = db_manager
        sweeper._settings = settings
        await sweeper.sweep_once()
        assert sweeper.last_agent_status_deleted == 250

        async with db_manager.session() as session:
            remaining = (
                await session.execute(select(AgentStatusHistory))
            ).scalars().all()
            assert remaining == []
