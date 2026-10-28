"""``Z4J_DATABASE_STATEMENT_CACHE_SIZE`` bounds both prepared-statement caches.

asyncpg's own statement cache serves only ``executemany`` and the connection
ping. SQLAlchemy's asyncpg adapter prepares every other statement itself and
keeps it in a per-connection LRU cache of its own
(``prepared_statement_cache_size``, 100 by default), so a setting that reached
only asyncpg left the cache that actually grows unbounded by it.

The test captures the connect parameters the configured engine hands to the
driver, without opening a connection.
"""

from __future__ import annotations

import secrets

import pytest
from sqlalchemy import event
from z4j_brain.persistence.database import create_engine_from_settings
from z4j_brain.settings import Settings


class _StopConnectError(Exception):
    """Raised from ``do_connect`` so no network connection is attempted."""


def _settings(database_url: str, **overrides: object) -> Settings:
    fields: dict[str, object] = {
        "database_url": database_url,
        "secret": secrets.token_urlsafe(48),
        "session_secret": secrets.token_urlsafe(48),
        "environment": "dev",
        "log_json": False,
    }
    fields.update(overrides)
    return Settings(**fields)  # type: ignore[arg-type]


async def _connect_params(settings: Settings) -> dict[str, object]:
    engine = create_engine_from_settings(settings)
    captured: dict[str, object] = {}

    @event.listens_for(engine.sync_engine, "do_connect")
    def _capture(_dialect, _conn_rec, _cargs, cparams) -> None:  # type: ignore[no-untyped-def]
        captured.update(cparams)
        raise _StopConnectError

    try:
        with pytest.raises(_StopConnectError):
            async with engine.connect():
                pass
    finally:
        await engine.dispose()
    return captured


@pytest.mark.asyncio
async def test_the_setting_bounds_asyncpg_and_sqlalchemy_caches() -> None:
    params = await _connect_params(
        _settings(
            "postgresql+asyncpg://u:p@127.0.0.1:1/d",
            database_statement_cache_size=7,
        ),
    )

    assert params["statement_cache_size"] == 7
    assert params["prepared_statement_cache_size"] == 7


@pytest.mark.asyncio
async def test_zero_disables_both_caches() -> None:
    params = await _connect_params(
        _settings(
            "postgresql+asyncpg://u:p@127.0.0.1:1/d",
            database_statement_cache_size=0,
        ),
    )

    assert params["statement_cache_size"] == 0
    assert params["prepared_statement_cache_size"] == 0


@pytest.mark.asyncio
async def test_an_explicit_url_value_wins() -> None:
    params = await _connect_params(
        _settings(
            "postgresql+asyncpg://u:p@127.0.0.1:1/d?prepared_statement_cache_size=3",
            database_statement_cache_size=7,
        ),
    )

    assert params["statement_cache_size"] == 7
    assert params["prepared_statement_cache_size"] == 3
