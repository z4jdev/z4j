"""The ORM models and a PostgreSQL database at the migration head agree.

The PostgreSQL counterpart of ``unit/test_models_match_migrations.py``: the
comparison may report only the differences listed in
``tests/model_migration_drift.py`` for PostgreSQL.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.model_migration_drift import POSTGRES_EXPECTED, compare_models_with, diff_keys


@pytest.mark.asyncio
async def test_models_differ_from_the_migrated_postgres_schema_only_as_documented(
    migrated_engine: AsyncEngine,
) -> None:
    async with migrated_engine.connect() as conn:
        diffs = await conn.run_sync(compare_models_with)

    keys = diff_keys(diffs, postgres=True)
    assert keys - POSTGRES_EXPECTED == set(), "drift between the models and the migrations"
    assert POSTGRES_EXPECTED - keys == set(), "a listed difference is gone; update the list"
