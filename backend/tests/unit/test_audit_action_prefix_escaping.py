"""The audit-list ``action_prefix`` filter must escape LIKE wildcards.

``AuditLog.action.startswith(prefix)`` left ``%`` / ``_`` active, so an
operator filter like ``"task.%"`` or ``"task_"`` behaved as a SQL LIKE
wildcard rather than a literal prefix (a parity gap with activity.py's
M16 fix). The query now uses ``autoescape=True``.

Runs against a MIGRATED database. Boundary F refuses a direct INSERT into
``audit_log``, so the rows under test are written the way an operator's
rows are written, through ``AuditService``.
"""

from __future__ import annotations

import secrets

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.models import AuditLog
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.settings import Settings


@pytest.fixture
def settings(migrated_db_url: str, migrated_audit_chain_secret: str) -> Settings:
    return Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        audit_chain_secret=migrated_audit_chain_secret,  # type: ignore[arg-type]
        environment="dev",
    )


@pytest.fixture
async def session(settings: Settings):
    engine = create_async_engine(settings.database_url)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


async def _seed(session: AsyncSession, settings: Settings) -> None:
    audit = AuditService(settings)
    repo = AuditLogRepository(session)
    for action in ("task.failed", "taskXfailed", "auth.login"):
        await audit.record(
            repo,
            action=action,
            target_type="thing",
            result="success",
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
        settings: Settings,
    ) -> None:
        await _seed(session, settings)
        # No action literally starts with the four characters "task%".
        rows = (await session.execute(_prefix_stmt("task%"))).scalars().all()
        assert rows == []

    async def test_underscore_is_literal_not_single_char_wildcard(
        self,
        session: AsyncSession,
        settings: Settings,
    ) -> None:
        await _seed(session, settings)
        # Unescaped, "task_" would match "task.failed" (_ -> ".") AND
        # "taskXfailed" (_ -> "X"). Escaped, it matches neither.
        rows = (await session.execute(_prefix_stmt("task_"))).scalars().all()
        assert rows == []

    async def test_literal_prefix_still_matches(
        self,
        session: AsyncSession,
        settings: Settings,
    ) -> None:
        await _seed(session, settings)
        rows = (await session.execute(_prefix_stmt("task."))).scalars().all()
        assert {r.action for r in rows} == {"task.failed"}
