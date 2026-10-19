"""Exercise configured retention caps against real persisted deletion results.

The schema is deliberately create_all: the legacy/keyless path cannot run
on an activated schema. The v2 cases still use genuine AuditService rows and
signed state, with an old clock so the automatic retention cutoff reaches them.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.audit_retention import AuditRetentionSweeper, RetentionCutoffs
from z4j_brain.domain.audit_chain import authenticate_state, make_empty_chain_state
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import (
    Agent,
    AgentStatusHistory,
    AuditChainState,
    AuditLog,
    Project,
)
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.settings import Settings

AUDIT = "audit-retention-limits-key-independent-000000000"
BACKLOG = 2005


async def _seed(db, settings, stream, monkeypatch):
    old = datetime.now(UTC) - timedelta(days=90)
    async with db.session() as session:
        if stream == "authenticated":

            class OldClock(datetime):
                @classmethod
                def now(cls, tz=None):
                    return old if tz is not None else old.replace(tzinfo=None)

            monkeypatch.setattr("z4j_brain.domain.audit_service.datetime", OldClock)
            await session.execute(text("BEGIN IMMEDIATE"))
            session.sync_session.info["z4j_sqlite_immediate"] = True
            session.add(make_empty_chain_state(secret=AUDIT.encode()))
            await session.flush()
            service = AuditService(settings)
            repo = AuditLogRepository(session)
            for _ in range(BACKLOG):
                await service.record(repo, action="test.retention", target_type="test")
        elif stream == "legacy":
            session.add_all(
                [
                    AuditLog(
                        action="test.retention",
                        target_type="test",
                        result="success",
                        occurred_at=old,
                    )
                    for _ in range(BACKLOG)
                ]
            )
        else:
            project = Project(slug="retention-limits", name="Retention Limits")
            session.add(project)
            await session.flush()
            agent = Agent(
                project_id=project.id,
                name="test",
                token_hash="t" * 64,
                protocol_version="2",
                framework_adapter="bare",
            )
            session.add(agent)
            await session.flush()
            session.add_all(
                [
                    AgentStatusHistory(
                        project_id=project.id, agent_id=agent.id, captured_at=old, payload={}
                    )
                    for _ in range(BACKLOG)
                ]
            )
        await session.commit()


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", ["legacy", "authenticated", "agent_status"])
@pytest.mark.parametrize("batch, cap", [(5000, 1000), (1000, 1500)])
async def test_automatic_pass_respects_configured_cap(stream, batch, cap, monkeypatch):
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret="master-retention-limits-independent-000000000",
        session_secret="session-retention-limits-independent-0000000",
        audit_chain_secret=AUDIT if stream == "authenticated" else None,
        audit_retention_days=30,
        event_retention_days=30,
        audit_retention_sweep_batch_size=batch,
        audit_retention_sweep_max_per_pass=cap,
        environment="dev",
    )
    engine = create_async_engine(settings.database_url)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        db = DatabaseManager(engine)
        await _seed(db, settings, stream, monkeypatch)
        sweeper = AuditRetentionSweeper()
        sweeper.bind(db=db, settings=settings)
        deleted = (
            await sweeper._do_sweep_agent_status()
            if stream == "agent_status"
            else await sweeper.sweep_once()
        )
        assert deleted == cap
        model = AgentStatusHistory if stream == "agent_status" else AuditLog
        async with db.session() as session:
            assert await session.scalar(select(func.count()).select_from(model)) == BACKLOG - cap
            if stream == "authenticated":
                state = (await session.scalars(select(AuditChainState))).one()
                authenticate_state(state, {state.state_key_id: AUDIT.encode()})
                assert state.active_row_count == BACKLOG - cap
                oldest = (
                    await session.scalars(
                        select(AuditLog).order_by(AuditLog.occurred_at, AuditLog.id).limit(1)
                    )
                ).one()
                assert oldest.prev_row_hmac == state.prune_row_hmac
        # Manual prune must keep going through capped passes, including when
        # the configured batch is larger than the pass cap.
        if stream == "authenticated":
            cutoffs = RetentionCutoffs.from_settings(settings, datetime.now(UTC))
            assert await sweeper.prune_authenticated(cutoffs=cutoffs) == BACKLOG - cap
            async with db.session() as session:
                assert await session.scalar(select(func.count()).select_from(AuditLog)) == 0
    finally:
        await engine.dispose()
