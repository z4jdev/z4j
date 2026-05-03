"""Integration test: ``users.email`` CITEXT case-insensitive uniqueness.

SQLite does not support CITEXT - the unit suite uses plain TEXT
via ``with_variant``. This test verifies the production type does
what the brain depends on: ``Alice@Example.com`` and
``ALICE@EXAMPLE.COM`` cannot both be inserted.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

pytestmark = pytest.mark.asyncio


class TestCitextUniqueness:
    async def test_case_insensitive_unique(
        self, migrated_engine: AsyncEngine,
    ) -> None:
        async with migrated_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO users (id, email, password_hash) "
                    "VALUES (:id, 'Alice@Example.com', 'x')",
                ),
                {"id": uuid.uuid4()},
            )

        # Inserting the same email with different case must fail.
        with pytest.raises(Exception):
            async with migrated_engine.begin() as conn:
                await conn.execute(
                    text(
                        "INSERT INTO users (id, email, password_hash) "
                        "VALUES (:id, 'ALICE@EXAMPLE.COM', 'x')",
                    ),
                    {"id": uuid.uuid4()},
                )

    async def test_select_case_insensitive(
        self, migrated_engine: AsyncEngine,
    ) -> None:
        async with migrated_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO users (id, email, password_hash) "
                    "VALUES (:id, 'Bob@Example.com', 'x')",
                ),
                {"id": uuid.uuid4()},
            )

        # CITEXT comparison is case-insensitive in WHERE clauses too.
        async with migrated_engine.connect() as conn:
            row = (
                await conn.execute(
                    text(
                        "SELECT email FROM users WHERE email = 'BOB@EXAMPLE.COM'",
                    ),
                )
            ).scalar_one_or_none()
        assert row is not None
        # The stored case is preserved.
        assert row == "Bob@Example.com"
