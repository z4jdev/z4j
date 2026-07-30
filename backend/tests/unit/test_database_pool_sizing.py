"""Pool sizing must be operator-configurable, and its defaults must not move.

Until 1.8.0 ``pool_size`` and ``max_overflow`` were hardcoded in
``create_engine_from_settings``. That made the brain's connection demand
impossible to fit to a server the operator does not control, which is a hard
stop for anyone on managed PostgreSQL with a low connection cap, sharing a
server, or running more than one brain.

The arithmetic is what makes it matter. Each uvicorn worker builds its own
engine and ``z4j serve`` defaults to ``max(1, min(4, cpu_count))`` workers, so
worst-case backend demand is::

    workers * (database_pool_size + database_max_overflow)

At the defaults on a 4-core host that is ``4 * (20 + 10) = 120``, which exceeds
a stock PostgreSQL ``max_connections`` of 100 by itself, leaving nothing for a
second brain, a standalone scheduler, or a superuser slot to debug with.

Two things are pinned here:

1. the settings actually reach the engine, so the knob is real rather than
   decorative; and
2. the defaults are exactly what shipped before, so no existing deployment
   silently changes its connection demand on upgrade.
"""

from __future__ import annotations

import secrets

import pytest
from z4j_brain.settings import Settings

# What was hardcoded before 1.8.0. Changing these changes the connection
# demand of every existing deployment on upgrade, so they are asserted
# literally rather than read back from the model.
_SHIPPED_POOL_SIZE = 20
_SHIPPED_MAX_OVERFLOW = 10

# `z4j serve` default, from cli.py: max(1, min(4, cpu_count)).
_MAX_DEFAULT_WORKERS = 4


def _settings(**overrides: object) -> Settings:
    fields: dict[str, object] = {
        "database_url": "sqlite+aiosqlite:///:memory:",
        "secret": secrets.token_urlsafe(48),
        "session_secret": secrets.token_urlsafe(48),
        "environment": "dev",
        "log_json": False,
    }
    fields.update(overrides)
    return Settings(**fields)  # type: ignore[arg-type]


def test_defaults_match_what_shipped_before_they_were_configurable() -> None:
    settings = _settings()

    assert settings.database_pool_size == _SHIPPED_POOL_SIZE
    assert settings.database_max_overflow == _SHIPPED_MAX_OVERFLOW


def test_worst_case_demand_at_defaults_is_documented_as_120() -> None:
    """The number that makes this setting necessary, pinned so it stays true.

    If a future change alters the defaults or the worker cap, this fails and
    whoever made the change has to look at the sizing guidance in
    docs/DATABASE.md rather than discovering it in production.
    """
    settings = _settings()
    per_worker = settings.database_pool_size + settings.database_max_overflow

    assert per_worker == 30
    assert per_worker * _MAX_DEFAULT_WORKERS == 120
    # The point of the whole exercise: the default exceeds a stock server.
    assert per_worker * _MAX_DEFAULT_WORKERS > 100


@pytest.mark.parametrize(
    ("pool_size", "max_overflow"),
    [
        (1, 0),  # smallest thing that can still serve
        (5, 2),  # a managed instance with a tight cap
        (40, 20),  # scaled up deliberately
    ],
)
def test_settings_reach_the_engine(pool_size: int, max_overflow: int) -> None:
    """The knob must be wired, not merely present on the model.

    Uses a PostgreSQL URL, which is both the faithful case (pool sizing exists
    for a server with a connection cap) and the only one that can be asserted:
    ``sqlite+aiosqlite:///:memory:`` resolves to ``StaticPool``, which rejects
    ``pool_size``/``max_overflow`` outright. ``create_async_engine`` is lazy, so
    no server is contacted.
    """
    from z4j_brain.persistence.database import create_engine_from_settings

    settings = _settings(
        database_url="postgresql+asyncpg://z4j:pw@127.0.0.1:5432/z4j",
        database_pool_size=pool_size,
        database_max_overflow=max_overflow,
    )
    engine = create_engine_from_settings(settings)
    try:
        pool = engine.pool
        assert pool.size() == pool_size
        # SQLAlchemy exposes the configured overflow as a private attribute;
        # there is no public accessor, and asserting it is the only way to
        # prove the value was not silently dropped.
        assert pool._max_overflow == max_overflow
    finally:
        engine.sync_engine.dispose()


def test_environment_variables_drive_the_settings() -> None:
    """Operators set these via Z4J_*, not by editing code."""
    import os
    from unittest.mock import patch

    with patch.dict(
        os.environ,
        {"Z4J_DATABASE_POOL_SIZE": "7", "Z4J_DATABASE_MAX_OVERFLOW": "3"},
        clear=False,
    ):
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
            session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
            environment="dev",
            log_json=False,
        )

    assert settings.database_pool_size == 7
    assert settings.database_max_overflow == 3


def test_bounds_reject_nonsense() -> None:
    with pytest.raises(ValueError, match="database_pool_size"):
        _settings(database_pool_size=0)
    with pytest.raises(ValueError, match="database_max_overflow"):
        _settings(database_max_overflow=-1)
