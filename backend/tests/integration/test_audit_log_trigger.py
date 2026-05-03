"""Integration test: ``audit_log`` append-only triggers.

The B2 migration installs a trigger function that raises on any
UPDATE or DELETE. This test verifies it actually fires on real
Postgres - SQLite cannot run pl/pgsql so the unit suite never
exercises this path.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

pytestmark = pytest.mark.asyncio


async def _insert_audit_row(engine: AsyncEngine) -> uuid.UUID:
    """Insert one minimal audit_log row and return its id."""
    row_id = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO audit_log "
                "(id, action, target_type, result, occurred_at, metadata) "
                "VALUES (:id, 'test.action', 'test', 'success', NOW(), '{}'::jsonb)",
            ),
            {"id": row_id},
        )
    return row_id


class TestAppendOnly:
    async def test_update_blocked(self, migrated_engine: AsyncEngine) -> None:
        row_id = await _insert_audit_row(migrated_engine)
        with pytest.raises(Exception) as exc_info:
            async with migrated_engine.begin() as conn:
                await conn.execute(
                    text("UPDATE audit_log SET action = 'mutated' WHERE id = :id"),
                    {"id": row_id},
                )
        assert "append-only" in str(exc_info.value).lower()

    async def test_delete_blocked(self, migrated_engine: AsyncEngine) -> None:
        row_id = await _insert_audit_row(migrated_engine)
        with pytest.raises(Exception) as exc_info:
            async with migrated_engine.begin() as conn:
                await conn.execute(
                    text("DELETE FROM audit_log WHERE id = :id"),
                    {"id": row_id},
                )
        assert "append-only" in str(exc_info.value).lower()

    async def test_insert_still_works(
        self, migrated_engine: AsyncEngine,
    ) -> None:
        # Append-only doesn't mean read-only - INSERT must still work.
        row_id = uuid.uuid4()
        async with migrated_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO audit_log "
                    "(id, action, target_type, result, occurred_at, metadata) "
                    "VALUES (:id, 'test.insert', 'test', 'success', NOW(), '{}'::jsonb)",
                ),
                {"id": row_id},
            )
        async with migrated_engine.connect() as conn:
            count = (
                await conn.execute(
                    text("SELECT count(*) FROM audit_log WHERE id = :id"),
                    {"id": row_id},
                )
            ).scalar_one()
        assert count == 1
