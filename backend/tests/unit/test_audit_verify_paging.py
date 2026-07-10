"""Regression: ``z4j audit verify`` must page through the WHOLE chain.

The verifier used to load a single fixed slice
(``stream_for_verify(chunk=--limit)``, default 5000) and silently skip
every row past the cap -- exactly the case a compliance audit cares
about on a large log. ``stream_for_verify`` now takes a keyset cursor
``(after_occurred_at, after_id)`` so the CLI pages through everything.
"""

from __future__ import annotations

import secrets

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.settings import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
    )


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


@pytest.fixture
def audit(settings: Settings) -> AuditService:
    return AuditService(settings)


async def _seed_chain(audit: AuditService, session: AsyncSession, n: int) -> None:
    repo = AuditLogRepository(session)
    for i in range(n):
        await audit.record(
            repo,
            action="test.event",
            target_type="thing",
            target_id=str(i),
            result="success",
        )
        # Commit per row so each record() reads a settled chain head and
        # the prev_row_hmac linkage is deterministic (no fork).
        await session.commit()


@pytest.mark.asyncio
class TestStreamForVerifyPaging:
    async def test_pages_through_entire_chain(
        self,
        audit: AuditService,
        session: AsyncSession,
    ) -> None:
        total = 25
        await _seed_chain(audit, session, total)
        repo = AuditLogRepository(session)

        page_size = 10
        collected = []
        cursor_occurred_at = None
        cursor_id = None
        while True:
            page = await repo.stream_for_verify(
                chunk=page_size,
                after_occurred_at=cursor_occurred_at,
                after_id=cursor_id,
            )
            if not page:
                break
            collected.extend(page)
            cursor_occurred_at = page[-1].occurred_at
            cursor_id = page[-1].id
            if len(page) < page_size:
                break

        # Every row covered exactly once.
        assert len(collected) == total
        assert len({r.id for r in collected}) == total

        # The pre-fix single slice would have stopped at the first page;
        # prove paging actually advanced past it.
        first_slice = await repo.stream_for_verify(chunk=page_size)
        assert len(first_slice) == page_size
        assert len(collected) > len(first_slice)

        # The full walked chain verifies clean (HMAC + linkage + genesis).
        ok, reasons = audit.verify_chain(collected)
        assert ok, reasons

    async def test_cursor_is_strictly_after_the_anchor(
        self,
        audit: AuditService,
        session: AsyncSession,
    ) -> None:
        await _seed_chain(audit, session, 5)
        repo = AuditLogRepository(session)

        first = await repo.stream_for_verify(chunk=2)
        assert len(first) == 2
        after = await repo.stream_for_verify(
            chunk=10,
            after_occurred_at=first[-1].occurred_at,
            after_id=first[-1].id,
        )
        after_ids = {r.id for r in after}
        # The anchor row is never returned twice, and the two pages
        # together cover all five rows with no overlap.
        assert first[-1].id not in after_ids
        assert ({r.id for r in first} | after_ids).__len__() == 5
