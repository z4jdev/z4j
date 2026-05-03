"""Shared fixtures for the brain integration test suite.

These tests run against a real Postgres 18 container started by
testcontainers - they exercise everything the SQLite unit tests
cannot: partitioning, NOTIFY, triggers, CITEXT, GIN indexes,
real ENUM types, multi-worker LISTEN fan-out.

Skipped automatically when Docker is unavailable so contributors
without Docker on their workstation can still run the unit suite.

Lifecycle:

- One Postgres container per pytest session (slow startup, fast
  per-test teardown).
- Per-test database created with a random suffix and dropped at
  the end of the test, so tests cannot leak state into each other.
- Per-test brain factory points at the test database with the
  ``postgres_notify`` registry backend so the registry path is
  exercised end-to-end.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import uuid
from collections.abc import AsyncIterator, Iterator

import pytest

# Two paths into this suite:
#  1. testcontainers available + Docker reachable → spin a fresh
#     ``postgres:18-trixie`` per session.
#  2. ``Z4J_TEST_POSTGRES_URL`` set → reuse an existing Postgres
#     (the dev-container loop sets this to the shared
#     ``z4j-dev-postgres`` service). Every test still gets its own
#     database via ``CREATE DATABASE``, so cross-test isolation
#     holds either way.
#
# If neither path works we skip rather than fail so unit-only
# contributors are not blocked.
_SHARED_PG_URL = os.environ.get("Z4J_TEST_POSTGRES_URL")

if _SHARED_PG_URL is None:
    testcontainers = pytest.importorskip(
        "testcontainers.postgres",
        reason=(
            "testcontainers not installed and Z4J_TEST_POSTGRES_URL "
            "not set; run `pip install z4j-brain[test-integration]` "
            "or point Z4J_TEST_POSTGRES_URL at a running Postgres."
        ),
    )
    PostgresContainer = testcontainers.PostgresContainer  # type: ignore[attr-defined]
else:
    PostgresContainer = None  # type: ignore[assignment]

import asyncpg
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from z4j_brain.persistence.base import Base
from z4j_brain.persistence import models  # noqa: F401  (registers metadata)
from z4j_brain.settings import Settings


# ---------------------------------------------------------------------------
# Session-scoped Postgres container
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def _postgres_container() -> Iterator[object | None]:
    """Start one ``postgres:18-trixie`` container for the whole test run.

    When :envvar:`Z4J_TEST_POSTGRES_URL` is set this fixture is a
    no-op - the suite reuses that Postgres instead. Otherwise we
    fall back to ``testcontainers`` and skip if Docker is unreachable.
    """
    if _SHARED_PG_URL is not None:
        yield None
        return
    try:
        container = PostgresContainer(
            image="postgres:18-trixie",
            username="z4j",
            password="z4j",
            dbname="z4j",
        )
        container.start()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"docker / postgres container unavailable: {exc}")
    try:
        yield container
    finally:
        try:
            container.stop()
        except Exception:  # noqa: BLE001
            pass


@pytest.fixture(scope="session")
def postgres_admin_url(_postgres_container: object | None) -> str:
    """The asyncpg-style admin URL used to create per-test databases."""
    if _SHARED_PG_URL is not None:
        # The shared-Postgres path. Normalise to the bare
        # ``postgresql://`` scheme asyncpg wants; SQLAlchemy re-adds
        # its own driver tag in ``fresh_database_async_url``.
        raw = _SHARED_PG_URL
    else:
        assert _postgres_container is not None
        raw = _postgres_container.get_connection_url()  # type: ignore[attr-defined]
    # testcontainers returns ``postgresql+psycopg2://...`` - strip the
    # driver tag and rebuild as ``postgresql://`` for asyncpg's
    # connect() and as ``postgresql+asyncpg://`` for SQLAlchemy.
    if raw.startswith("postgresql+psycopg2://"):
        raw = raw.replace("postgresql+psycopg2://", "postgresql://", 1)
    elif raw.startswith("postgresql+psycopg://"):
        raw = raw.replace("postgresql+psycopg://", "postgresql://", 1)
    elif raw.startswith("postgresql+asyncpg://"):
        raw = raw.replace("postgresql+asyncpg://", "postgresql://", 1)
    return raw


# ---------------------------------------------------------------------------
# Per-test database
# ---------------------------------------------------------------------------


@pytest.fixture
async def fresh_database(postgres_admin_url: str) -> AsyncIterator[str]:
    """Create + drop a per-test database. Returns the asyncpg URL."""
    db_name = f"z4j_test_{secrets.token_hex(6)}"
    admin = await asyncpg.connect(dsn=postgres_admin_url)
    try:
        await admin.execute(f'CREATE DATABASE "{db_name}"')
    finally:
        await admin.close()
    # Build the URL to the new database.
    base_no_db = postgres_admin_url.rsplit("/", 1)[0]
    new_url = f"{base_no_db}/{db_name}"
    try:
        yield new_url
    finally:
        # Force-disconnect any lingering sessions, then drop.
        admin = await asyncpg.connect(dsn=postgres_admin_url)
        try:
            await admin.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = $1 AND pid <> pg_backend_pid()",
                db_name,
            )
            await admin.execute(f'DROP DATABASE IF EXISTS "{db_name}"')
        finally:
            await admin.close()


@pytest.fixture
def fresh_database_async_url(fresh_database: str) -> str:
    """SQLAlchemy-asyncpg form of the per-test database URL."""
    return fresh_database.replace("postgresql://", "postgresql+asyncpg://", 1)


# ---------------------------------------------------------------------------
# Per-test brain settings + engine + DB manager
# ---------------------------------------------------------------------------


@pytest.fixture
def integration_settings(fresh_database_async_url: str) -> Settings:
    """A real-Postgres ``Settings`` for the test brain."""
    return Settings(
        database_url=fresh_database_async_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        require_db_ssl=False,
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        login_min_duration_ms=10,
        registry_listener_heartbeat_seconds=1,
        registry_listener_heartbeat_timeout_seconds=5,
        registry_reconcile_interval_seconds=2,
    )


@pytest.fixture
async def integration_engine(
    integration_settings: Settings,
) -> AsyncIterator[AsyncEngine]:
    """An async engine pointing at the per-test database."""
    engine = create_async_engine(integration_settings.database_url, future=True)
    yield engine
    await engine.dispose()


@pytest.fixture
async def migrated_engine(
    integration_engine: AsyncEngine,
    integration_settings: Settings,
) -> AsyncEngine:
    """Run alembic upgrade head against the per-test database.

    Returns the same engine, but the schema is now in place. Most
    integration tests want this fixture, not the bare engine.
    """
    from alembic import command
    from alembic.config import Config
    from pathlib import Path

    backend_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(backend_root / "alembic.ini"))
    cfg.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    # alembic env.py reads Z4J_DATABASE_URL via Settings(), so wire
    # it explicitly through env vars for the duration of upgrade.
    import os

    saved = {
        "Z4J_DATABASE_URL": os.environ.get("Z4J_DATABASE_URL"),
        "Z4J_SECRET": os.environ.get("Z4J_SECRET"),
        "Z4J_SESSION_SECRET": os.environ.get("Z4J_SESSION_SECRET"),
        "Z4J_ENVIRONMENT": os.environ.get("Z4J_ENVIRONMENT"),
        "Z4J_REQUIRE_DB_SSL": os.environ.get("Z4J_REQUIRE_DB_SSL"),
    }
    try:
        os.environ["Z4J_DATABASE_URL"] = integration_settings.database_url
        os.environ["Z4J_SECRET"] = integration_settings.secret.get_secret_value()
        os.environ["Z4J_SESSION_SECRET"] = (
            integration_settings.session_secret.get_secret_value()
        )
        os.environ["Z4J_ENVIRONMENT"] = "dev"
        os.environ["Z4J_REQUIRE_DB_SSL"] = "false"
        # alembic.command.upgrade is sync - run it in an executor so
        # we don't block the asyncio loop.
        await asyncio.get_event_loop().run_in_executor(
            None, lambda: command.upgrade(cfg, "head"),
        )
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return integration_engine


# ---------------------------------------------------------------------------
# Helpers exposed to tests
# ---------------------------------------------------------------------------


def random_email() -> str:
    """Return a random ``user-<hex>@example.com`` email."""
    return f"user-{secrets.token_hex(4)}@example.com"


def random_slug() -> str:
    """Return a random project slug (matches the slug_format regex)."""
    return f"p-{secrets.token_hex(4)}"
