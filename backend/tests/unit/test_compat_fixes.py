"""Regression tests for the v1.0.19 compatibility-killers fixes.

This file pins the four behaviour changes that turned z4j-brain
into a fully bidirectionally-compatible package across all
v1.0.19+ versions:

- **C1**: ``startup_version.check_and_update_schema_version`` now
  WARNS when the DB schema is newer than the running code (was
  ``raise SchemaVersionError``). Old code can boot against
  forward-migrated DBs.

- **C2**: ``cli._auto_migrate`` detects an unknown DB head BEFORE
  invoking alembic and raises ``_UnknownDBRevisionError``. The
  serve handler catches this and warns + continues boot. Pre-
  v1.0.19 the brain flap-looped.

- **H1**: The three z4j-scheduler-related periodic workers
  (``pending_fires_replay``, ``schedule_circuit_breaker``,
  ``schedule_fires_prune``) only register when
  ``Z4J_SCHEDULER_GRPC_ENABLED=1``. Default-off operators get
  zero scheduler-worker activity.

- **H2**: ``SubscriptionFilters`` model_config relaxed from
  ``extra="forbid"`` to ``extra="ignore"`` so a newer dashboard
  bundle that adds an unknown filter key can still PATCH against
  an older brain. Security-relevant ``extra=forbid`` schemas
  (BulkDeleteRequest, UserSubscriptionCreate) are NOT relaxed.

- **M2**: SPA fallback ``index.html`` ships ``Cache-Control:
  no-cache, no-store, must-revalidate``. Browsers re-fetch the
  SPA entry point after every brain upgrade.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from z4j_brain.persistence.base import Base
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.models import Z4JMeta
from z4j_brain.startup_version import (
    SchemaVersionError,
    check_and_update_schema_version,
)


# =====================================================================
# C1, schema_version skew warns, doesn't raise
# =====================================================================


@pytest.fixture
async def session():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


@pytest.mark.asyncio
class TestC1SchemaVersionWarnNotRaise:
    async def test_db_newer_than_code_warns_continues(
        self, session, caplog,
    ) -> None:
        """The exact failure mode that bit operators on 1.0.18→1.0.17.

        Pre-v1.0.19: function raised SchemaVersionError → brain
        flap-loop. v1.0.19+: warns + returns cleanly.
        """
        # Stamp a future version into z4j_meta
        session.add(Z4JMeta(key="schema_version", value="9999.0.0"))
        await session.commit()

        # Must NOT raise
        with caplog.at_level("WARNING"):
            await check_and_update_schema_version(session)

        # And the warning must mention the version mismatch so an
        # operator inspecting logs understands why some features
        # are missing.
        warnings = [r for r in caplog.records if r.levelname == "WARNING"]
        assert any(
            "9999.0.0" in r.getMessage() for r in warnings
        ), f"expected version-skew warning, got: {[r.getMessage() for r in warnings]}"

    async def test_db_older_than_code_still_updates_record(
        self, session,
    ) -> None:
        """Forward path unchanged: code newer than DB → update meta."""
        session.add(Z4JMeta(key="schema_version", value="0.0.1"))
        await session.commit()

        await check_and_update_schema_version(session)

        from sqlalchemy import select

        result = await session.execute(
            select(Z4JMeta).where(Z4JMeta.key == "schema_version"),
        )
        meta = result.scalar_one()
        # Should have been bumped to the running code version
        # (which won't be 0.0.1).
        assert meta.value != "0.0.1"

    async def test_first_boot_initializes_meta(self, session) -> None:
        """No z4j_meta row → fresh install path creates one."""
        await check_and_update_schema_version(session)

        from sqlalchemy import select

        result = await session.execute(
            select(Z4JMeta).where(Z4JMeta.key == "schema_version"),
        )
        meta = result.scalar_one()
        assert meta.value  # any non-empty version

    async def test_schema_version_error_class_still_importable(self):
        """Back-compat: subclasses or downstream code that imports
        the exception name must still work even though the brain
        itself never raises it from v1.0.19 onward.
        """
        assert issubclass(SchemaVersionError, RuntimeError)


# =====================================================================
# C2, auto_migrate detects unknown DB head, raises clean error
# =====================================================================


class TestC2AutoMigrateUnknownRevision:
    def test_unknown_db_revision_error_carries_db_head(self):
        """The error type the serve handler catches must expose
        the unknown revision so the warning message is actionable.
        """
        from z4j_brain.cli import _UnknownDBRevisionError

        err = _UnknownDBRevisionError("future_revision_xyz")
        assert err.db_head == "future_revision_xyz"
        assert "future_revision_xyz" in str(err)

    def test_detect_unknown_db_head_returns_none_without_db_url(
        self, monkeypatch,
    ):
        """No Z4J_DATABASE_URL → can't introspect → returns None
        (best-effort) so the regular alembic upgrade path runs.
        """
        from pathlib import Path

        from z4j_brain.cli import _detect_unknown_db_head

        monkeypatch.delenv("Z4J_DATABASE_URL", raising=False)
        # The path doesn't matter when DB url is missing - we
        # bail out before opening any file.
        result = _detect_unknown_db_head(
            Path("/nonexistent/alembic.ini"),
        )
        assert result is None


# =====================================================================
# H1, scheduler workers gated behind Z4J_SCHEDULER_GRPC_ENABLED
# =====================================================================


@pytest.mark.asyncio
class TestH1SchedulerWorkersGated:
    async def test_default_off_no_scheduler_workers(self):
        """Default install has scheduler_grpc_enabled=False → the
        three scheduler workers are NOT registered with the
        supervisor. Verified by introspecting create_app's worker
        list.
        """
        from sqlalchemy.ext.asyncio import create_async_engine

        from z4j_brain.main import create_app
        from z4j_brain.settings import Settings

        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            secret=secrets.token_urlsafe(48),
            session_secret=secrets.token_urlsafe(48),
            log_json=False,
            environment="dev",
            disable_spa_fallback=True,
            scheduler_grpc_enabled=False,
        )
        engine = create_async_engine(settings.database_url, future=True)
        try:
            app = create_app(settings, engine=engine)
            supervisor = app.state.worker_supervisor
            worker_names = {w.name for w in supervisor._workers}
            assert "pending_fires_replay_worker" not in worker_names
            assert "schedule_circuit_breaker_worker" not in worker_names
            assert "schedule_fires_prune_worker" not in worker_names
            # Sanity: the always-on ones are still there.
            assert "command_timeout_worker" in worker_names
            assert "agent_health_worker" in worker_names
        finally:
            await engine.dispose()


# =====================================================================
# H2, SubscriptionFilters extra=ignore (rolling-upgrade safety)
# =====================================================================


class TestH2SubscriptionFiltersExtraIgnore:
    def test_unknown_filter_key_silently_dropped(self):
        """Newer dashboard sends ``{"priority": ["high"], "future_key": "x"}``
        against an older brain - the unknown key must be silently
        dropped (not raise 422).
        """
        from z4j_brain.api.notifications import SubscriptionFilters

        # Must NOT raise
        filters = SubscriptionFilters.model_validate({
            "priority": ["high"],
            "future_filter_key_unknown_to_this_version": "anything",
        })
        # The known field stays; the unknown was ignored.
        assert filters.priority == ["high"]
        # Pydantic dump with exclude_none must NOT contain the
        # unknown key (it was dropped at validate time).
        dumped = filters.model_dump(exclude_none=True)
        assert "future_filter_key_unknown_to_this_version" not in dumped

    def test_security_relevant_forbid_kept(self):
        """The audit-finding-driven ``extra=forbid`` schemas
        (BulkDeleteRequest in tasks.py, UserSubscriptionCreate in
        user_notifications.py) must remain strict, they're not
        typo-detection, they're privilege-controlling-field
        defenses.
        """
        from z4j_brain.api.tasks import BulkDeleteRequest

        with pytest.raises(Exception):  # pydantic ValidationError
            BulkDeleteRequest.model_validate({
                "task_ids": [str(uuid.uuid4())],
                "project_id": str(uuid.uuid4()),  # smuggling attempt
            })

    def test_user_subscription_create_keeps_forbid(self):
        """R3 M11 audit defense still in place."""
        from z4j_brain.api.user_notifications import UserSubscriptionCreate

        with pytest.raises(Exception):  # pydantic ValidationError
            UserSubscriptionCreate.model_validate({
                "project_id": str(uuid.uuid4()),
                "trigger": "task.failed",
                "user_id": str(uuid.uuid4()),  # smuggling attempt
            })


# =====================================================================
# M2, Cache-Control on dashboard SPA fallback
# =====================================================================


@pytest.mark.asyncio
class TestM2DashboardCacheControl:
    async def test_spa_fallback_sends_no_cache_headers(self, tmp_path):
        """``index.html`` from the SPA fallback MUST ship
        no-cache headers so browsers re-fetch after upgrades.
        Hashed assets under /assets/ are mounted via StaticFiles
        and use default (long-lived) caching - that's by design.
        """
        # Build a minimal SPA dist directory so the fallback
        # registers.
        spa = tmp_path / "spa"
        spa.mkdir()
        (spa / "index.html").write_text(
            "<!doctype html><html></html>",
            encoding="utf-8",
        )
        (spa / "assets").mkdir()

        from httpx import ASGITransport, AsyncClient
        from sqlalchemy.ext.asyncio import create_async_engine

        from z4j_brain.main import create_app
        from z4j_brain.settings import Settings

        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            secret=secrets.token_urlsafe(48),
            session_secret=secrets.token_urlsafe(48),
            log_json=False,
            environment="dev",
            dashboard_dist=str(spa),
            disable_spa_fallback=False,  # we WANT it for this test
        )
        engine = create_async_engine(settings.database_url, future=True)
        try:
            app = create_app(settings, engine=engine)
            transport = ASGITransport(app=app)
            async with AsyncClient(
                transport=transport, base_url="http://testserver",
            ) as ac:
                resp = await ac.get("/")
                assert resp.status_code == 200
                cc = resp.headers.get("cache-control", "")
                assert "no-cache" in cc, (
                    f"expected no-cache in Cache-Control, got: {cc!r}"
                )
                assert "no-store" in cc
                assert "must-revalidate" in cc
        finally:
            await engine.dispose()
