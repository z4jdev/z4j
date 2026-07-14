"""Round-trip for the ``drop_alert_events`` step of ``v1_7_schema`` on SQLite.

The thirteen 1.7 dev-time migrations were consolidated into the single
``v1_7_schema`` revision; this test drives that revision's extracted
``_up_drop_alert_events`` / ``_down_drop_alert_events`` step helpers
directly against an in-memory SQLite DB via an alembic Operations context:
after the model removal ``create_all`` no longer builds the table,
``_down_drop_alert_events`` recreates it with the exact original columns,
and ``_up_drop_alert_events`` drops it. Both directions are idempotent.
The Postgres full-chain round-trip lives in
``tests/integration/test_migration_pg``.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base

_EXPECTED_COLUMNS = {
    "id",
    "created_at",
    "updated_at",
    "delivery_id",
    "event_type",
    "user_id",
    "note",
    "snooze_until",
}


def _load_migration():
    path = (
        Path(__file__).resolve().parents[2]
        / "src/z4j_brain/migrations/versions"
        / "2026_07_10_0005_v1_7_schema.py"
    )
    spec = importlib.util.spec_from_file_location("mig_v1_7_schema", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(sync_conn, fn) -> None:
    ctx = MigrationContext.configure(sync_conn)
    with Operations.context(ctx):
        fn(sync_conn)


def _has_alert_events(sync_conn) -> bool:
    return inspect(sync_conn).has_table("alert_events")


@pytest.mark.asyncio
async def test_round_trip_drop_and_recreate() -> None:
    mig = _load_migration()
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        # Model removed -> create_all does NOT build alert_events.
        async with engine.connect() as conn:
            assert await conn.run_sync(_has_alert_events) is False

        # downgrade() recreates the table with its original columns.
        async with engine.begin() as conn:
            await conn.run_sync(lambda c: _run(c, mig._down_drop_alert_events))
        async with engine.connect() as conn:
            assert await conn.run_sync(_has_alert_events) is True
            cols = await conn.run_sync(
                lambda c: {col["name"] for col in inspect(c).get_columns("alert_events")},
            )
            assert cols == _EXPECTED_COLUMNS

        # upgrade() drops it again.
        async with engine.begin() as conn:
            await conn.run_sync(lambda c: _run(c, mig._up_drop_alert_events))
        async with engine.connect() as conn:
            assert await conn.run_sync(_has_alert_events) is False
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_upgrade_idempotent_when_absent() -> None:
    mig = _load_migration()
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        # alert_events absent -> upgrade() is a no-op, not an error.
        async with engine.begin() as conn:
            await conn.run_sync(lambda c: _run(c, mig._up_drop_alert_events))
        async with engine.connect() as conn:
            assert await conn.run_sync(_has_alert_events) is False
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_downgrade_idempotent_when_present() -> None:
    mig = _load_migration()
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with engine.begin() as conn:
            await conn.run_sync(lambda c: _run(c, mig._down_drop_alert_events))
        # Second downgrade with the table already present -> no-op.
        async with engine.begin() as conn:
            await conn.run_sync(lambda c: _run(c, mig._down_drop_alert_events))
        async with engine.connect() as conn:
            assert await conn.run_sync(_has_alert_events) is True
    finally:
        await engine.dispose()
