"""The audit-list ``action_prefix`` filter must escape LIKE wildcards.

``AuditLog.action.startswith(prefix)`` left ``%`` / ``_`` active, so an
operator filter like ``"task.%"`` or ``"task_"`` behaved as a SQL LIKE
wildcard rather than a literal prefix (a parity gap with activity.py's
M16 fix). The query now uses ``autoescape=True``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import AuditLog


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


async def _seed(session: AsyncSession) -> None:
    for action in ("task.failed", "taskXfailed", "auth.login"):
        session.add(
            AuditLog(
                id=uuid.uuid4(),
                action=action,
                target_type="thing",
                result="success",
                occurred_at=datetime.now(UTC),
            ),
        )
    await session.commit()


def _prefix_stmt(prefix: str):
    return select(AuditLog).where(
        AuditLog.action.startswith(prefix, autoescape=True),
    )


@pytest.mark.asyncio
class TestActionPrefixEscaping:
    async def test_percent_is_literal_not_a_wildcard(
        self,
        session: AsyncSession,
    ) -> None:
        await _seed(session)
        # No action literally starts with the four characters "task%".
        rows = (await session.execute(_prefix_stmt("task%"))).scalars().all()
        assert rows == []

    async def test_underscore_is_literal_not_single_char_wildcard(
        self,
        session: AsyncSession,
    ) -> None:
        await _seed(session)
        # Unescaped, "task_" would match "task.failed" (_ -> ".") AND
        # "taskXfailed" (_ -> "X"). Escaped, it matches neither.
        rows = (await session.execute(_prefix_stmt("task_"))).scalars().all()
        assert rows == []

    async def test_literal_prefix_still_matches(
        self,
        session: AsyncSession,
    ) -> None:
        await _seed(session)
        rows = (await session.execute(_prefix_stmt("task."))).scalars().all()
        assert {r.action for r in rows} == {"task.failed"}
