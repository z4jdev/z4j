"""1.7 security-hardening: audit-log retention prune watermark (R2).

Time-based audit retention deletes the oldest rows, INCLUDING the
genesis row (``prev_row_hmac IS NULL``). Before this fix the chain
verifier then flagged the first surviving row -- which now carries a
non-NULL ``prev_row_hmac`` -- as a permanent chain-truncation MISMATCH
the moment retention was enabled.

The sweeper now records a WATERMARK (the ``row_hmac`` of the newest row
it deleted, stored in ``z4j_meta``). The verifier accepts a first
surviving row whose ``prev_row_hmac`` equals that watermark, while a
genuine tamper (a deleted middle row, an altered ``row_hmac``) still
fails.

These tests drive the REAL ``AuditRetentionSweeper`` over a genuine
HMAC chain seeded through ``AuditService`` and assert:
  * after pruning past the genesis row, ``verify_chain`` PASSES with the
    watermark and (regression proof) FAILS without it;
  * the watermark equals the newest-deleted row's ``row_hmac``;
  * a genuine tamper on a surviving row STILL fails even with the
    watermark.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import update
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.audit_retention import AuditRetentionSweeper
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.persistence import models  # noqa: F401  register mappers
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import AuditLog
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.settings import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        audit_retention_days=30,
        audit_retention_sweep_batch_size=100,
    )


@pytest.fixture
async def db_manager() -> DatabaseManager:  # type: ignore[misc]
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    db = DatabaseManager(engine)
    yield db
    await engine.dispose()


async def _seed_chain(db: DatabaseManager, audit: AuditService, n: int):
    """Write ``n`` genuinely-chained audit rows, one commit per row.

    Returns a list of ``(id, row_hmac)`` in chain order.
    """
    rows: list[tuple] = []
    async with db.session() as session:
        repo = AuditLogRepository(session)
        for i in range(n):
            row = await audit.record(
                repo,
                action="test.event",
                target_type="thing",
                target_id=str(i),
                result="success",
            )
            # Capture id + row_hmac while the row is still live in the
            # session (before commit expires the attributes).
            rows.append((row.id, row.row_hmac))
            await session.commit()
    return rows


async def _backdate(db: DatabaseManager, ids, *, days: int) -> None:
    """Push rows' occurred_at into the past so retention deletes them."""
    old = datetime.now(UTC) - timedelta(days=days)
    async with db.session() as session:
        await session.execute(
            update(AuditLog).where(AuditLog.id.in_(list(ids))).values(occurred_at=old),
        )
        await session.commit()


def _sweeper(db: DatabaseManager, settings: Settings) -> AuditRetentionSweeper:
    sweeper = AuditRetentionSweeper()
    sweeper._db = db
    sweeper._settings = settings
    return sweeper


@pytest.mark.asyncio
class TestAuditPruneWatermark:
    async def test_prune_past_genesis_then_verify_passes_with_watermark(
        self,
        db_manager: DatabaseManager,
        settings: Settings,
    ) -> None:
        audit = AuditService(settings)
        rows = await _seed_chain(db_manager, audit, 6)
        # Age the first three rows (incl. the genesis) past the cutoff.
        await _backdate(db_manager, [rid for rid, _ in rows[:3]], days=100)

        deleted = await _sweeper(db_manager, settings).sweep_once()
        assert deleted == 3

        async with db_manager.session() as session:
            repo = AuditLogRepository(session)
            watermark = await repo.get_prune_watermark()
            surviving = await repo.stream_for_verify(chunk=100)

        # The watermark is the newest-deleted row's row_hmac == the first
        # survivor's prev_row_hmac.
        assert watermark == rows[2][1]
        assert len(surviving) == 3
        assert surviving[0].prev_row_hmac == watermark

        # WITH the watermark the pruned chain verifies clean...
        ok, reasons = audit.verify_chain(surviving, prune_watermark=watermark)
        assert ok, reasons

        # ...and WITHOUT it the old code would have false-positived on the
        # first surviving row's non-null prev_row_hmac.
        ok_without, reasons_without = audit.verify_chain(surviving)
        assert not ok_without
        assert any("genesis" in r or "truncat" in r for r in reasons_without)

    async def test_altered_row_hmac_still_fails_after_prune(
        self,
        db_manager: DatabaseManager,
        settings: Settings,
    ) -> None:
        audit = AuditService(settings)
        rows = await _seed_chain(db_manager, audit, 6)
        await _backdate(db_manager, [rid for rid, _ in rows[:3]], days=100)
        assert await _sweeper(db_manager, settings).sweep_once() == 3

        # Tamper a SURVIVING row's stored row_hmac (verify_row must fail).
        async with db_manager.session() as session:
            await session.execute(
                update(AuditLog).where(AuditLog.id == rows[4][0]).values(row_hmac="deadbeef" * 8),
            )
            await session.commit()

        async with db_manager.session() as session:
            repo = AuditLogRepository(session)
            watermark = await repo.get_prune_watermark()
            surviving = await repo.stream_for_verify(chunk=100)

        ok, reasons = audit.verify_chain(surviving, prune_watermark=watermark)
        assert not ok
        assert reasons

    async def test_deleted_middle_row_still_fails_after_prune(
        self,
        db_manager: DatabaseManager,
        settings: Settings,
    ) -> None:
        audit = AuditService(settings)
        rows = await _seed_chain(db_manager, audit, 6)
        await _backdate(db_manager, [rid for rid, _ in rows[:3]], days=100)
        assert await _sweeper(db_manager, settings).sweep_once() == 3

        # Delete a surviving MIDDLE row: the next survivor's prev anchor
        # now dangles -- a chain break the watermark must NOT paper over.
        from sqlalchemy import delete

        async with db_manager.session() as session:
            await session.execute(delete(AuditLog).where(AuditLog.id == rows[4][0]))
            await session.commit()

        async with db_manager.session() as session:
            repo = AuditLogRepository(session)
            watermark = await repo.get_prune_watermark()
            surviving = await repo.stream_for_verify(chunk=100)

        ok, reasons = audit.verify_chain(surviving, prune_watermark=watermark)
        assert not ok
        assert reasons

    async def test_no_watermark_when_nothing_pruned(
        self,
        db_manager: DatabaseManager,
        settings: Settings,
    ) -> None:
        audit = AuditService(settings)
        await _seed_chain(db_manager, audit, 4)  # all fresh, none eligible

        deleted = await _sweeper(db_manager, settings).sweep_once()
        assert deleted == 0

        async with db_manager.session() as session:
            repo = AuditLogRepository(session)
            watermark = await repo.get_prune_watermark()
            surviving = await repo.stream_for_verify(chunk=100)

        # No prune -> no watermark -> the NULL-genesis anchor is required
        # (and satisfied: the genesis row survives).
        assert watermark is None
        ok, reasons = audit.verify_chain(surviving, prune_watermark=watermark)
        assert ok, reasons
