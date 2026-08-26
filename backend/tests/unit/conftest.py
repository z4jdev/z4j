"""Shared pytest fixtures for the brain backend.

Tests build the brain on top of an in-memory ``sqlite+aiosqlite://``
engine - no Postgres required for unit tests. Integration tests in
B7 will use a real Postgres 18 container.
"""

from __future__ import annotations

import os
import secrets
import shutil
import sqlite3
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.main import create_app
from z4j_brain.settings import Settings


@pytest.fixture(autouse=True)
def _restore_process_configuration() -> Iterator[None]:
    """Keep process-global configuration changes inside one test.

    Boundary-F entrypoint tests exercise the real snapshot exporter, which
    must populate ``os.environ`` for child tools.  Some of those keys do not
    exist before the test, so ``monkeypatch.delenv`` cannot register them for
    restoration.  Without an exact before/after boundary, a newly exported
    audit key silently switches every later development fixture to the v2
    signer and turns the complete suite into an order-dependent result.
    """
    from z4j_brain import configuration

    original_environment = {
        key: value for key, value in os.environ.items() if key.startswith("Z4J_")
    }
    original_snapshot = configuration.active_configuration_snapshot()
    try:
        yield
    finally:
        for key in tuple(os.environ):
            if key.startswith("Z4J_"):
                del os.environ[key]
        os.environ.update(original_environment)
        configuration.set_active_configuration_snapshot(original_snapshot)


@pytest.fixture
def brain_settings() -> Settings:
    """A valid Settings instance backed by in-memory SQLite.

    Defaults to ``metrics_public=True`` so unit tests that hit
    ``/metrics`` don't have to wire up the v1.0.13 bearer-token
    flow. Tests that need to exercise the auth gate explicitly
    should override via a tighter fixture.
    """
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        log_json=False,
        environment="dev",
        metrics_public=True,
        # Tests register routes via ``brain_app.include_router``
        # AFTER build time. The SPA catch-all (registered in
        # ``create_app``) would otherwise shadow them.
        disable_spa_fallback=True,
    )


@pytest.fixture
async def brain_app(brain_settings: Settings):
    """Yield a configured FastAPI app on an in-memory SQLite engine."""
    engine = create_async_engine(
        brain_settings.database_url,
        future=True,
    )
    app = create_app(brain_settings, engine=engine)
    # Round-9 audit fix -Bootstrap-MED test support (Apr 2026):
    # the unit-test fixture uses ASGITransport directly without
    # the lifespan wrapper, so ``app.state.lifespan_ready`` is
    # never flipped by the production startup hook. Set it
    # manually so the /health/ready test sees a "ready" brain.
    # Production code goes through the lifespan and gets the
    # ``False → True`` transition for free.
    app.state.lifespan_ready = True
    yield app
    await engine.dispose()


@pytest.fixture(autouse=True)
async def _reset_per_ip_rate_limits() -> None:
    """Reset every per-IP rate-limit bucket between tests.

    All async-client tests share the loopback IP via ASGITransport,
    so a test that makes >N requests will exhaust a bucket and
    cascade spurious 429s into every following test in the same
    process. Resetting prevents test-order coupling.

    1.6.3 specifically added two new buckets (``_openapi_bucket`` at
    10/min/IP and ``_setup_bucket`` at 5/15min/IP) that broke the
    existing ``test_setup_endpoint.py`` and other suites by
    exhausting after a handful of sequential test posts. This
    autouse fixture is the structural fix.
    """
    from z4j_brain.domain import ip_rate_limit as ipl

    for bucket_attr in (
        "_invitation_bucket",
        "_login_bucket",
        "_password_reset_bucket",
        "_channel_test_bucket",
        "_channel_import_bucket",
        "_agent_connect_bucket",
        "_bulk_action_bucket",
        "_mfa_verify_bucket",
        "_openapi_bucket",
        "_setup_bucket",
    ):
        bucket = getattr(ipl, bucket_attr, None)
        if bucket is not None:
            await bucket.prune_idle(idle_seconds=0)


@pytest.fixture
async def client(brain_app) -> AsyncIterator[AsyncClient]:
    """Async HTTPX client wired to the brain app via ASGITransport."""
    transport = ASGITransport(app=brain_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as ac:
        yield ac


# ---------------------------------------------------------------------------
# Migrated schema
#
# Unit tests historically built their schema with ``Base.metadata.create_all``,
# which creates tables and nothing else. Every Boundary-D and Boundary-F guard
# lives inside a migration, so those tests ran with the guards absent: the
# database under test refused nothing, while an operator's database refuses a
# great deal. A feature could therefore pass its whole test file and raise on
# first use in production, which is exactly what happened to schedule pause.
#
# Building the schema the way a real database was built is the only way a test
# can see that. It is affordable: the chain runs once per session (about 1.5s)
# and each test copies the resulting file (about 1ms).
# ---------------------------------------------------------------------------


#: The audit-chain key the migrated template is activated with. Boundary F
#: binds the activated state to the key that signed it, so an app opened
#: against a copy of the template must present this same key or every audit
#: write fails. Fixed rather than random so the two cannot drift apart.
MIGRATED_AUDIT_CHAIN_SECRET = "z4j-test-audit-chain-key-do-not-use-in-production"

#: The migrations directory, resolved from this file so it does not depend on
#: where pytest was started.
_MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "src" / "z4j_brain" / "migrations"


@pytest.fixture
def migrated_audit_chain_secret() -> str:
    """The chain key that matches :func:`migrated_db_url`."""
    return MIGRATED_AUDIT_CHAIN_SECRET


@pytest.fixture(scope="session")
def migrated_sqlite_template(tmp_path_factory) -> Path:
    """One SQLite database at the release head, built once per session.

    Runs from an isolated working directory on purpose. Alembic's env hook
    captures configuration from the current directory, and a repository ``.env``
    whose permissions z4j refuses would otherwise fail the build on a developer
    machine while passing in CI.
    """
    from alembic import command
    from alembic.config import Config
    from z4j_brain.cli import _find_alembic_config_path

    root = tmp_path_factory.mktemp("migrated-template")
    home = root / "home"
    home.mkdir(mode=0o700)
    template = root / "template.db"

    config_path = str(_find_alembic_config_path())
    saved_env = {k: v for k, v in os.environ.items() if k.startswith("Z4J_")}
    saved_cwd = Path.cwd()
    try:
        for key in tuple(os.environ):
            if key.startswith("Z4J_"):
                del os.environ[key]
        os.environ.update(
            {
                "Z4J_DATABASE_URL": f"sqlite+aiosqlite:///{template}",
                "Z4J_HOME": str(home),
                "Z4J_ENVIRONMENT": "dev",
                "Z4J_SECRET": secrets.token_hex(32),
                "Z4J_SESSION_SECRET": secrets.token_hex(32),
                "Z4J_AUDIT_CHAIN_SECRET": MIGRATED_AUDIT_CHAIN_SECRET,
            },
        )
        os.chdir(root)
        config = Config(config_path)
        # Pin script_location absolutely. Two alembic.ini files exist and one
        # of them declares a RELATIVE script_location, which resolves against
        # the current directory. This fixture deliberately runs from a scratch
        # directory (so alembic's configuration capture cannot read a
        # repository .env whose permissions z4j refuses), so a relative
        # location silently pointed at nothing whenever pytest was started from
        # packages/z4j/backend, which has its own pytest.ini and is a perfectly
        # ordinary place to run from. Every migrated test then errored in
        # setup, while the same suite passed from the repository root.
        config.set_main_option("script_location", str(_MIGRATIONS_DIR))
        command.upgrade(config, "head")
    finally:
        os.chdir(saved_cwd)
        for key in tuple(os.environ):
            if key.startswith("Z4J_"):
                del os.environ[key]
        os.environ.update(saved_env)

    # A template without live guards would silently restore the old blind
    # spot, so refuse to hand one out.
    with sqlite3.connect(template) as probe:
        guard_version = probe.execute(
            "SELECT guard_version FROM schedule_revision_state",
        ).fetchone()
    if not guard_version or guard_version[0] != 1:
        msg = f"migrated template has no live Boundary-D guard: {guard_version!r}"
        raise RuntimeError(msg)

    return template


@pytest.fixture
def migrated_db_url(migrated_sqlite_template: Path, tmp_path: Path) -> str:
    """A private copy of the migrated template, as a database URL."""
    database = tmp_path / "z4j.db"
    shutil.copyfile(migrated_sqlite_template, database)
    return f"sqlite+aiosqlite:///{database}"
