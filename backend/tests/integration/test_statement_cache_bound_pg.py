"""On a real connection, one setting sizes both prepared-statement caches.

The unit test pins the connect parameters; this one checks what the asyncpg
connection and SQLAlchemy's adapter actually built from them.
"""

from __future__ import annotations

import pytest
from z4j_brain.persistence.database import create_engine_from_settings
from z4j_brain.settings import Settings


@pytest.mark.asyncio
async def test_both_caches_on_a_live_connection_use_the_setting(
    integration_settings: Settings,
) -> None:
    settings = integration_settings.model_copy(
        update={"database_statement_cache_size": 9},
    )
    engine = create_engine_from_settings(settings)
    try:
        async with engine.connect() as conn:
            raw = await conn.get_raw_connection()
            adapted = raw.dbapi_connection
            # SQLAlchemy's per-connection LRU of prepared statements.
            assert adapted._prepared_statement_cache.capacity == 9
            # asyncpg's own statement cache.
            assert raw.driver_connection._stmt_cache.get_max_size() == 9
    finally:
        await engine.dispose()
