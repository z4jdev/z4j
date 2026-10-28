"""The ORM models and a SQLite database at the migration head agree.

Alembic's comparison of ``Base.metadata`` with the migrated database may
report only the deliberate differences and comparison artifacts listed in
``tests/model_migration_drift.py``. Anything else is drift between the models
and the migrations, which is what left two unique indexes out of the models
and the generated schema page.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from tests.model_migration_drift import SQLITE_EXPECTED, compare_models_with, diff_keys


@pytest.mark.asyncio
async def test_models_differ_from_the_migrated_sqlite_schema_only_as_documented(
    migrated_db_url: str,
) -> None:
    engine = create_async_engine(migrated_db_url)
    try:
        async with engine.connect() as conn:
            diffs = await conn.run_sync(compare_models_with)
    finally:
        await engine.dispose()

    keys = diff_keys(diffs, postgres=False)
    assert keys - SQLITE_EXPECTED == set(), "drift between the models and the migrations"
    assert SQLITE_EXPECTED - keys == set(), "a listed difference is gone; update the list"
