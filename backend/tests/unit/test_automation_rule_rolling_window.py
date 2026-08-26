"""SQLite arbitration for exact automation-rule rolling windows."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.persistence import models  # noqa: F401  register metadata
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import (
    AutomationRule,
    AutomationRuleAdmission,
    Project,
)
from z4j_brain.persistence.repositories import (
    AutomationRuleRepository,
    CircuitDecision,
    dispatch_candidate,
)


@pytest.mark.asyncio
async def test_sqlite_concurrent_claims_share_one_exact_budget(tmp_path: Path) -> None:
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{tmp_path / 'automation-window.db'}",
        connect_args={"timeout": 30},
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    db = DatabaseManager(engine)
    try:
        async with db.session(write=True) as session:
            project = Project(
                slug=f"automation-{uuid.uuid4().hex[:8]}",
                name="Automation",
            )
            session.add(project)
            await session.flush()
            rule = AutomationRule(
                project_id=project.id,
                name="bounded",
                trigger="task.failed",
                conditions={},
                actions=[{"type": "notify"}],
                max_executions_per_window=3,
                window_seconds=3600,
            )
            session.add(rule)
            await session.commit()
            candidate = dispatch_candidate(
                rule,
                project_revision=project.automation_revision,
            )

        start = asyncio.Event()
        at = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)

        async def claim_once() -> CircuitDecision:
            await start.wait()
            # DatabaseManager's BEGIN IMMEDIATE is SQLite's write arbiter,
            # matching every production executor call.
            async with db.session(write=True) as session:
                decision, _ = await AutomationRuleRepository(session).claim_execution(
                    candidate=candidate,
                    now=at,
                )
                await session.commit()
                return decision

        tasks = [asyncio.create_task(claim_once()) for _ in range(16)]
        await asyncio.sleep(0)
        start.set()
        decisions = await asyncio.gather(*tasks)

        assert decisions.count(CircuitDecision.EXECUTE) == 3
        assert decisions.count(CircuitDecision.TRIPPED_NOW) == 1
        assert decisions.count(CircuitDecision.TRIPPED) == 12
        async with db.session() as session:
            count = await session.scalar(
                select(func.count(AutomationRuleAdmission.id)).where(
                    AutomationRuleAdmission.rule_id == candidate.rule_id,
                ),
            )
            persisted = await session.get(AutomationRule, candidate.rule_id)
        assert count == 3
        assert persisted is not None
        assert persisted.cb_execution_count == 3
        assert persisted.cb_tripped is True
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_sqlite_production_clock_retains_subsecond_boundary(
    tmp_path: Path,
) -> None:
    """The non-injected DB clock cannot expire debt before one real second."""

    engine = create_async_engine(
        f"sqlite+aiosqlite:///{tmp_path / 'automation-clock.db'}",
    )
    clock_values = iter(
        [
            "2026-08-12 12:00:00.999",
            "2026-08-12 12:00:01.001",
        ],
    )

    @event.listens_for(engine.sync_engine, "connect")
    def _install_clock(dbapi_connection, _record) -> None:
        dbapi_connection.create_function(
            "strftime",
            2,
            lambda _format, _modifier: next(clock_values),
        )

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    db = DatabaseManager(engine)
    try:
        async with db.session(write=True) as session:
            project = Project(
                slug=f"automation-{uuid.uuid4().hex[:8]}",
                name="Automation clock",
            )
            session.add(project)
            await session.flush()
            rule = AutomationRule(
                project_id=project.id,
                name="subsecond",
                trigger="task.failed",
                conditions={},
                actions=[{"type": "notify"}],
                max_executions_per_window=1,
                window_seconds=1,
            )
            session.add(rule)
            await session.commit()
            candidate = dispatch_candidate(
                rule,
                project_revision=project.automation_revision,
            )

        decisions = []
        for _ in range(2):
            async with db.session(write=True) as session:
                decision, _ = await AutomationRuleRepository(session).claim_execution(
                    candidate=candidate,
                )
                decisions.append(decision)
                await session.commit()

        assert decisions == [CircuitDecision.EXECUTE, CircuitDecision.TRIPPED_NOW]
    finally:
        await engine.dispose()
