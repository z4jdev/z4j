"""End-to-end tests for the B5 API surface.

Covers schedules, audit, stats, projects CRUD, users, memberships,
and metrics. Reuses the same in-memory SQLite + seeded session
pattern as ``test_b4_endpoints``.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import (
    ScheduleKind,
    TaskState,
)
from z4j_brain.persistence.models import (
    AuditLog,
    Project,
    Schedule,
    Session,
    Task,
    User,
)
from z4j_brain.settings import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        login_min_duration_ms=10,
        registry_backend="local",
        # v1.0.13 fail-secure /metrics defaults to 401 without
        # a bearer token. Tests that scrape /metrics need either
        # ``metrics_public=True`` or a configured token.
        metrics_public=True,
        # SPA catch-all would shadow tests that ``include_router``
        # extra endpoints after build time.
        disable_spa_fallback=True,
    )


@pytest.fixture
async def brain_app(settings: Settings):
    engine = create_async_engine(
        settings.database_url,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    yield app
    await engine.dispose()


@pytest.fixture
async def seeded(settings: Settings, brain_app):
    """Insert a project + admin user + admin session."""
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    csrf = secrets.token_urlsafe(32)

    async with db.session() as s:
        project = Project(id=project_id, slug="default", name="Default")
        user = User(
            id=user_id,
            email="admin@example.com",
            password_hash=hasher.hash("correct horse battery staple 9"),
            is_admin=True,
            is_active=True,
        )
        session_row = Session(
            id=session_id,
            user_id=user_id,
            csrf_token=csrf,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            ip_at_issue="127.0.0.1",
            user_agent_at_issue="test",
        )
        s.add_all([project, user])
        await s.flush()
        s.add(session_row)
        await s.commit()

    return {
        "project_id": project_id,
        "user_id": user_id,
        "session_id": session_id,
        "csrf": csrf,
    }


@pytest.fixture
async def client(brain_app, settings: Settings, seeded):
    from httpx import ASGITransport, AsyncClient
    from z4j_brain.auth.csrf import csrf_cookie_name

    transport = ASGITransport(app=brain_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as ac:
        codec = SessionCookieCodec(settings)
        ac.cookies.set(
            cookie_name(environment=settings.environment),
            codec.encode(seeded["session_id"]),
        )
        ac.cookies.set(
            csrf_cookie_name(environment=settings.environment),
            seeded["csrf"],
        )
        yield ac


# ---------------------------------------------------------------------------
# Schedules
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSchedulesRouter:
    async def test_list_empty(self, client) -> None:
        # v1.1.0: response is now ``{items, next_cursor}``.
        r = await client.get("/api/v1/projects/default/schedules")
        assert r.status_code == 200
        body = r.json()
        assert body == {"items": [], "next_cursor": None}

    async def test_list_with_seeded_schedule(
        self,
        brain_app,
        client,
        seeded,
    ) -> None:
        async with brain_app.state.db.session() as s:
            s.add(
                Schedule(
                    project_id=seeded["project_id"],
                    engine="celery",
                    scheduler="celery-beat",
                    name="nightly",
                    task_name="myapp.tasks.cleanup",
                    kind=ScheduleKind.CRON,
                    expression="0 3 * * *",
                ),
            )
            await s.commit()
        r = await client.get("/api/v1/projects/default/schedules")
        assert r.status_code == 200
        body = r.json()
        items = body["items"]
        assert len(items) == 1
        assert items[0]["name"] == "nightly"
        assert items[0]["kind"] == "cron"
        assert body["next_cursor"] is None


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestStatsRouter:
    async def test_empty_project_returns_zeros(self, client) -> None:
        r = await client.get("/api/v1/projects/default/stats")
        assert r.status_code == 200
        body = r.json()
        assert body["tasks_total"] == 0
        assert body["agents_online"] == 0
        assert body["commands_pending"] == 0
        assert body["failure_rate_24h"] == 0.0

    async def test_stats_reflect_seeded_tasks(
        self,
        brain_app,
        client,
        seeded,
    ) -> None:
        async with brain_app.state.db.session() as s:
            now = datetime.now(UTC)
            for i in range(3):
                s.add(
                    Task(
                        project_id=seeded["project_id"],
                        engine="celery",
                        task_id=f"t-{i}",
                        name="x",
                        state=TaskState.SUCCESS if i < 2 else TaskState.FAILURE,
                        finished_at=now,
                    ),
                )
            await s.commit()
        r = await client.get("/api/v1/projects/default/stats")
        assert r.status_code == 200
        body = r.json()
        assert body["tasks_by_state"]["success"] == 2
        assert body["tasks_by_state"]["failure"] == 1
        assert body["tasks_succeeded_24h"] == 2
        assert body["tasks_failed_24h"] == 1
        assert 0.0 < body["failure_rate_24h"] < 1.0


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestAuditRouter:
    async def test_audit_returns_recorded_events(
        self,
        client,
        seeded,
    ) -> None:
        # Issue an action that writes to the audit log first.
        r1 = await client.post(
            "/api/v1/projects/default/agents",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={"name": "w-stats"},
        )
        assert r1.status_code == 201
        # Then read the audit list.
        r = await client.get("/api/v1/projects/default/audit")
        assert r.status_code == 200
        body = r.json()
        actions = {item["action"] for item in body["items"]}
        assert "agent.token.minted" in actions

    async def test_audit_export_csv(
        self,
        brain_app,
        client,
        seeded,
    ) -> None:
        # Seed two audit rows; one has an action value that begins
        # with ``=`` so we also verify CSV-formula injection is
        # neutralised (prefix apostrophe).
        async with brain_app.state.db.session() as s:
            now = datetime.now(UTC)
            for action in ("user.login", "=danger()"):
                s.add(
                    AuditLog(
                        project_id=seeded["project_id"],
                        user_id=seeded["user_id"],
                        action=action,
                        target_type="user",
                        target_id=str(seeded["user_id"]),
                        result="success",
                        outcome="allow",
                        audit_metadata={"ip": "127.0.0.1"},
                        source_ip="127.0.0.1",
                        occurred_at=now,
                    ),
                )
            await s.commit()

        r = await client.get(
            "/api/v1/projects/default/audit?format=csv",
        )
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/csv")
        assert "attachment" in r.headers.get("content-disposition", "")
        assert "z4j-audit-default.csv" in r.headers.get(
            "content-disposition",
            "",
        )
        body = r.text
        assert "action" in body.splitlines()[0]  # header row
        assert "user.login" in body
        # Formula-injection: row must carry the apostrophe prefix,
        # not the raw ``=`` character at field start.
        assert "'=danger()" in body
        assert ",=danger()" not in body

    async def test_audit_export_json_with_field_selection(
        self,
        brain_app,
        client,
        seeded,
    ) -> None:
        async with brain_app.state.db.session() as s:
            s.add(
                AuditLog(
                    project_id=seeded["project_id"],
                    user_id=seeded["user_id"],
                    action="user.login",
                    target_type="user",
                    target_id=str(seeded["user_id"]),
                    result="success",
                    outcome="allow",
                    audit_metadata={},
                    source_ip="127.0.0.1",
                    occurred_at=datetime.now(UTC),
                ),
            )
            await s.commit()

        r = await client.get(
            "/api/v1/projects/default/audit?format=json&fields=action,result",
        )
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/json")
        body = r.json()
        assert isinstance(body, list)
        assert len(body) == 1
        # Only the selected columns should be present.
        assert set(body[0].keys()) == {"action", "result"}

    async def test_audit_export_uses_format_specific_row_caps(
        self,
        brain_app,
        client,
        seeded,
        monkeypatch,
    ) -> None:
        from z4j_brain.api import audit as audit_api

        assert audit_api._export_row_cap("xlsx") == 25_000
        assert audit_api._export_row_cap("csv") == 50_000
        assert audit_api._export_row_cap("json") == 50_000
        operation = brain_app.openapi()["paths"]["/api/v1/projects/{slug}/audit"]["get"]
        format_parameter = next(
            parameter for parameter in operation["parameters"] if parameter["name"] == "format"
        )
        description = format_parameter["description"]
        assert "CSV and JSON are capped at 50 000 rows" in description
        assert "XLSX is capped at 25 000 rows" in description

        async with brain_app.state.db.session() as s:
            now = datetime.now(UTC)
            for index in range(2):
                s.add(
                    AuditLog(
                        project_id=seeded["project_id"],
                        user_id=seeded["user_id"],
                        action=f"cap.test.{index}",
                        target_type="test",
                        result="success",
                        audit_metadata={},
                        occurred_at=now,
                    ),
                )
            await s.commit()

        # Use small ceilings to exercise the route without manufacturing
        # tens of thousands of rows. CSV/JSON retain the larger general cap;
        # XLSX fails at its lower in-memory-workbook cap.
        monkeypatch.setattr(audit_api, "_EXPORT_ROW_CAP", 2)
        monkeypatch.setattr(audit_api, "XLSX_ROW_CAP", 1)

        xlsx = await client.get("/api/v1/projects/default/audit?format=xlsx")
        assert xlsx.status_code == 422
        assert "xlsx audit export is capped at 1 rows" in xlsx.text

        csv = await client.get("/api/v1/projects/default/audit?format=csv")
        assert csv.status_code == 200
        json_response = await client.get("/api/v1/projects/default/audit?format=json")
        assert json_response.status_code == 200


# ---------------------------------------------------------------------------
# Command and issue request validation
# ---------------------------------------------------------------------------


def test_pool_resize_request_accepts_only_real_resize_deltas() -> None:
    from pydantic import ValidationError as PydanticValidationError
    from z4j_brain.api.commands import PoolResizeRequest

    agent_id = uuid.uuid4()
    for delta in (-100, -1, 1, 100):
        request = PoolResizeRequest(
            agent_id=agent_id,
            worker_name="worker-1",
            delta=delta,
        )
        assert request.delta == delta

    with pytest.raises(PydanticValidationError, match="delta must be non-zero"):
        PoolResizeRequest(
            agent_id=agent_id,
            worker_name="worker-1",
            delta=0,
        )


@pytest.mark.asyncio
class TestRequestValidation:
    async def test_pool_resize_zero_is_422(self, client, seeded) -> None:
        response = await client.post(
            "/api/v1/projects/default/commands/pool-resize",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={
                "agent_id": str(uuid.uuid4()),
                "worker_name": "worker-1",
                "delta": 0,
            },
        )
        assert response.status_code == 422
        assert "delta must be non-zero" in response.text

    async def test_issue_status_rejects_unknown_value_instead_of_widening(
        self,
        client,
    ) -> None:
        invalid = await client.get(
            "/api/v1/projects/default/issues?status=not-a-status",
        )
        assert invalid.status_code == 422

        for status in ("ongoing", "recovered"):
            accepted = await client.get(
                f"/api/v1/projects/default/issues?status={status}",
            )
            assert accepted.status_code == 200


def test_command_and_automation_module_contracts_are_current() -> None:
    from z4j_brain.api import automation_rules, commands

    commands_contract = " ".join((commands.__doc__ or "").split())
    assert "worker pool/consumer/rate controls" in commands_contract
    assert "land in B5" not in commands_contract

    bulk_contract = " ".join((commands.BulkRetryRequest.__doc__ or "").split())
    assert "selection keys" in bulk_contract
    assert "ownership-checks" in bulk_contract
    assert "forwarded to the agent verbatim" not in bulk_contract

    automation_contract = " ".join((automation_rules.__doc__ or "").split())
    assert "/automation/settings" in automation_contract
    assert "lands in a follow-up" not in automation_contract


# ---------------------------------------------------------------------------
# Projects CRUD
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestProjectsCRUD:
    async def test_create_project(self, client, seeded) -> None:
        r = await client.post(
            "/api/v1/projects",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={
                "slug": "staging",
                "name": "Staging",
                "environment": "staging",
            },
        )
        assert r.status_code == 201
        assert r.json()["slug"] == "staging"

    async def test_create_project_duplicate_slug_409(
        self,
        client,
        seeded,
    ) -> None:
        r = await client.post(
            "/api/v1/projects",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={"slug": "default", "name": "x"},
        )
        assert r.status_code == 409

    async def test_create_project_bad_slug_409(
        self,
        client,
        seeded,
    ) -> None:
        r = await client.post(
            "/api/v1/projects",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={"slug": "BAD_SLUG", "name": "x"},
        )
        assert r.status_code == 409

    async def test_update_project(self, client, seeded) -> None:
        r = await client.patch(
            "/api/v1/projects/default",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={"name": "Default Updated", "timezone": "Europe/Berlin"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["name"] == "Default Updated"
        assert body["timezone"] == "Europe/Berlin"

    async def test_archive_project(self, client, seeded) -> None:
        # Create a fresh project to archive (don't archive default,
        # since other tests need it).
        await client.post(
            "/api/v1/projects",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={"slug": "scratch", "name": "Scratch"},
        )
        r = await client.delete(
            "/api/v1/projects/scratch",
            headers={"X-CSRF-Token": seeded["csrf"]},
        )
        assert r.status_code == 204
        # Listing should not include it now.
        r2 = await client.get("/api/v1/projects")
        assert all(p["slug"] != "scratch" for p in r2.json())


# ---------------------------------------------------------------------------
# Users (brain admin)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestUsersRouter:
    async def test_list_users_includes_self(self, client) -> None:
        r = await client.get("/api/v1/users")
        assert r.status_code == 200
        emails = {u["email"] for u in r.json()}
        assert "admin@example.com" in emails

    async def test_create_user(self, client, seeded) -> None:
        r = await client.post(
            "/api/v1/users",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={
                "email": "bob@example.com",
                "display_name": "Bob",
                "password": "correct horse battery staple 9",
                "is_admin": False,
            },
        )
        assert r.status_code == 201
        assert r.json()["email"] == "bob@example.com"

    async def test_create_user_weak_password_rejected(
        self,
        client,
        seeded,
    ) -> None:
        r = await client.post(
            "/api/v1/users",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={
                "email": "weak@example.com",
                "password": "short1",
            },
        )
        # PasswordError → 422 from the error middleware mapping
        # for ValidationError. We accept any non-201 here.
        assert r.status_code != 201

    async def test_create_user_duplicate_email_409(
        self,
        client,
        seeded,
    ) -> None:
        r = await client.post(
            "/api/v1/users",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={
                "email": "admin@example.com",
                "password": "correct horse battery staple 9",
            },
        )
        assert r.status_code == 409


# ---------------------------------------------------------------------------
# Memberships
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestMembershipsRouter:
    async def test_list_memberships_initially_empty(
        self,
        client,
    ) -> None:
        r = await client.get("/api/v1/projects/default/memberships")
        assert r.status_code == 200
        # The bootstrap admin has no membership row (global admin
        # bypasses), so the list is empty.
        assert r.json() == []

    async def test_grant_then_list(self, brain_app, client, seeded) -> None:
        # Insert a non-admin user first.
        async with brain_app.state.db.session() as s:
            from z4j_brain.auth.passwords import PasswordHasher

            hasher = PasswordHasher(brain_app.state.settings)
            target = User(
                email="op@example.com",
                password_hash=hasher.hash("correct horse battery staple 9"),
                is_admin=False,
                is_active=True,
            )
            s.add(target)
            await s.commit()
            target_id = target.id

        r = await client.post(
            "/api/v1/projects/default/memberships",
            headers={"X-CSRF-Token": seeded["csrf"]},
            json={"user_id": str(target_id), "role": "operator"},
        )
        assert r.status_code == 201
        body = r.json()
        assert body["role"] == "operator"
        assert body["user_email"] == "op@example.com"

        # And the list reflects it.
        r2 = await client.get("/api/v1/projects/default/memberships")
        assert any(m["role"] == "operator" for m in r2.json())


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def test_metrics_module_contract_describes_fail_secure_default() -> None:
    from z4j_brain.api import metrics

    contract = " ".join((metrics.__doc__ or "").split())
    assert "fail-secure by default" in contract
    assert "Z4J_METRICS_PUBLIC=1" in contract
    assert "fresh self-contained SQLite installation" in contract
    assert "other deployments must configure one explicitly" in contract
    assert 'legacy "open" behaviour' not in contract


@pytest.mark.asyncio
class TestMetricsEndpoint:
    async def test_metrics_returns_prometheus_text(self, client, brain_app) -> None:
        """Default unit-test fixture has metrics_public=True so the
        scrape works without a bearer token. Mirrors a closed-network
        deployment where Prometheus runs on the same host."""
        assert str(brain_app.url_path_for("metrics_endpoint")) == "/metrics"
        r = await client.get("/metrics")
        assert r.status_code == 200
        assert "text/plain" in r.headers.get("content-type", "")
        body = r.text
        assert "z4j_events_ingested_total" in body
        assert "z4j_agents_online" in body

    async def test_metrics_returns_401_without_bearer_when_fail_secure(
        self,
        brain_settings,
    ) -> None:
        """v1.0.13 fail-secure regression test.

        Builds a brain with ``metrics_public=False`` and no
        ``metrics_auth_token``: ``/metrics`` MUST return 401
        unauthenticated. This is the gate the v1.0.13 hardening
        added; this test catches any future regression that
        accidentally re-opens the endpoint to anonymous scrapes.
        """
        from httpx import ASGITransport, AsyncClient
        from sqlalchemy.ext.asyncio import create_async_engine
        from z4j_brain.main import create_app

        # Override: lock down /metrics for this one test.
        secure_settings = brain_settings.model_copy(
            update={"metrics_public": False, "metrics_auth_token": None},
        )
        engine = create_async_engine(secure_settings.database_url, future=True)
        try:
            app = create_app(secure_settings, engine=engine)
            transport = ASGITransport(app=app)
            async with AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as ac:
                r = await ac.get("/metrics")
                assert r.status_code == 401
                # And a wrong bearer also fails.
                r2 = await ac.get(
                    "/metrics",
                    headers={"Authorization": "Bearer wrong-token"},
                )
                assert r2.status_code == 401
        finally:
            await engine.dispose()

    async def test_metrics_accepts_correct_bearer_token(
        self,
        brain_settings,
    ) -> None:
        """Operators with a configured token + matching bearer get 200."""
        from httpx import ASGITransport, AsyncClient
        from pydantic import SecretStr
        from sqlalchemy.ext.asyncio import create_async_engine
        from z4j_brain.main import create_app

        token = "test-token-" + secrets.token_urlsafe(16)
        secure_settings = brain_settings.model_copy(
            update={
                "metrics_public": False,
                "metrics_auth_token": SecretStr(token),
            },
        )
        engine = create_async_engine(secure_settings.database_url, future=True)
        try:
            app = create_app(secure_settings, engine=engine)
            transport = ASGITransport(app=app)
            async with AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as ac:
                r = await ac.get(
                    "/metrics",
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert r.status_code == 200
                assert "z4j_events_ingested_total" in r.text
        finally:
            await engine.dispose()

    async def test_metrics_disabled_removes_route_even_when_public(
        self,
        brain_settings,
    ) -> None:
        """The route-presence switch wins over the public-auth opt-in."""
        from httpx import ASGITransport, AsyncClient
        from sqlalchemy.ext.asyncio import create_async_engine
        from starlette.routing import NoMatchFound
        from z4j_brain.main import create_app

        disabled_settings = brain_settings.model_copy(
            update={"metrics_enabled": False, "metrics_public": True},
        )
        engine = create_async_engine(disabled_settings.database_url, future=True)
        try:
            app = create_app(disabled_settings, engine=engine)
            with pytest.raises(NoMatchFound):
                app.url_path_for("metrics_endpoint")
            transport = ASGITransport(app=app)
            async with AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as ac:
                response = await ac.get("/metrics")
                assert response.status_code == 404
        finally:
            await engine.dispose()


# ---------------------------------------------------------------------------
# /auth/me with memberships
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestAuthMeMemberships:
    async def test_admin_sees_all_projects(self, client) -> None:
        r = await client.get("/api/v1/auth/me")
        assert r.status_code == 200
        body = r.json()
        assert body["is_admin"] is True
        # Global admin gets a synthesized membership for every active project.
        assert any(m["project_slug"] == "default" for m in body["memberships"])
        assert all(m["role"] == "admin" for m in body["memberships"])
