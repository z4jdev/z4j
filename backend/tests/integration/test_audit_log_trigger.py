"""Integration test: ``audit_log`` append-only triggers.

The audit-chain activation migration installs a trigger function that raises on
any UPDATE or DELETE. This test verifies it actually fires on real PostgreSQL -
SQLite cannot run pl/pgsql so the unit suite never exercises this path.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.persistence.models import AuditLog
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.settings import Settings

pytestmark = pytest.mark.asyncio


async def _insert_audit_row(engine: AsyncEngine, settings: Settings) -> uuid.UUID:
    """Insert one signer-managed audit row and return its id."""
    async with AsyncSession(engine, expire_on_commit=False) as session:
        row = await AuditService(settings).record(
            AuditLogRepository(session),
            action="test.action",
            target_type="test",
        )
        await session.commit()
        return row.id


class TestAppendOnly:
    async def test_unsigned_direct_insert_blocked(
        self,
        migrated_engine: AsyncEngine,
    ) -> None:
        """Activation rejects rows that bypass the signer-managed write path."""
        with pytest.raises(DBAPIError):
            async with migrated_engine.begin() as conn:
                await conn.execute(
                    text(
                        "INSERT INTO audit_log "
                        "(id, action, target_type, result, occurred_at, metadata) "
                        "VALUES (:id, 'test.unsigned', 'test', 'success', "
                        "NOW(), '{}'::jsonb)",
                    ),
                    {"id": uuid.uuid4()},
                )

    async def test_update_blocked(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        row_id = await _insert_audit_row(migrated_engine, integration_settings)
        with pytest.raises(DBAPIError, match="audit_log is append-only"):
            async with migrated_engine.begin() as conn:
                await conn.execute(
                    text("UPDATE audit_log SET action = 'mutated' WHERE id = :id"),
                    {"id": row_id},
                )

    async def test_delete_blocked(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        row_id = await _insert_audit_row(migrated_engine, integration_settings)
        with pytest.raises(DBAPIError, match="audit_log is append-only"):
            async with migrated_engine.begin() as conn:
                await conn.execute(
                    text("DELETE FROM audit_log WHERE id = :id"),
                    {"id": row_id},
                )

    async def test_insert_still_works(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        # Append-only doesn't mean read-only: signer-managed INSERT must work.
        row_id = await _insert_audit_row(migrated_engine, integration_settings)
        async with AsyncSession(migrated_engine) as session:
            row = await session.scalar(select(AuditLog).where(AuditLog.id == row_id))
        assert row is not None
        assert row.legacy_frozen is False
        assert row.row_hmac is not None
