"""Production ASGI/auth/CSRF coverage for the Boundary-B public resource."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.auth.csrf import csrf_cookie_name
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState, ProjectRole, TaskState
from z4j_brain.persistence.models import (
    Agent,
    AuditLog,
    BulkRetryRequest,
    BulkRetryRequestChild,
    Membership,
    Project,
    Session,
    Task,
    User,
)
from z4j_brain.settings import Settings
from z4j_brain.websocket.auth import hash_agent_token
from z4j_core.transport import CURRENT_PROTOCOL


@pytest_asyncio.fixture
async def bulk_http(tmp_path: Any) -> dict[str, Any]:
    """Run the real router against file SQLite and real auth dependencies."""

    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'bulk-http.sqlite'}",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        disable_spa_fallback=True,
    )
    engine = create_async_engine(settings.database_url)

    @event.listens_for(engine.sync_engine, "connect")
    def _foreign_keys(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    project_id = uuid.uuid4()
    other_project_id = uuid.uuid4()
    operator_id = uuid.uuid4()
    viewer_id = uuid.uuid4()
    operator_session_id = uuid.uuid4()
    viewer_session_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    agent_token = "z4j_boundary_b_http_agent"
    operator_csrf = secrets.token_urlsafe(32)
    viewer_csrf = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    async with app.state.db.session() as session:
        session.add_all(
            [
                Project(id=project_id, slug="bulk-http", name="Bulk HTTP"),
                Project(
                    id=other_project_id,
                    slug="bulk-http-other",
                    name="Bulk HTTP Other",
                ),
                User(
                    id=operator_id,
                    email="operator-bulk-http@example.com",
                    password_hash="unused",
                    is_active=True,
                ),
                User(
                    id=viewer_id,
                    email="viewer-bulk-http@example.com",
                    password_hash="unused",
                    is_active=True,
                ),
            ]
        )
        await session.flush()
        session.add_all(
            [
                Agent(
                    id=agent_id,
                    project_id=project_id,
                    name="boundary-b-http-agent",
                    token_hash=hash_agent_token(
                        plaintext=agent_token,
                        secret=settings.secret.get_secret_value().encode("utf-8"),
                    ),
                    protocol_version=CURRENT_PROTOCOL,
                    framework_adapter="bare",
                    engine_adapters=["celery"],
                    scheduler_adapters=[],
                    capabilities={},
                    state=AgentState.ONLINE,
                ),
                Membership(
                    user_id=operator_id,
                    project_id=project_id,
                    role=ProjectRole.OPERATOR,
                ),
                Membership(
                    user_id=operator_id,
                    project_id=other_project_id,
                    role=ProjectRole.OPERATOR,
                ),
                Membership(
                    user_id=viewer_id,
                    project_id=project_id,
                    role=ProjectRole.VIEWER,
                ),
                Session(
                    id=operator_session_id,
                    user_id=operator_id,
                    csrf_token=operator_csrf,
                    issued_at=now,
                    expires_at=now + timedelta(hours=1),
                    last_seen_at=now,
                    ip_at_issue="127.0.0.1",
                    user_agent_at_issue="boundary-b-http",
                ),
                Session(
                    id=viewer_session_id,
                    user_id=viewer_id,
                    csrf_token=viewer_csrf,
                    issued_at=now,
                    expires_at=now + timedelta(hours=1),
                    last_seen_at=now,
                    ip_at_issue="127.0.0.1",
                    user_agent_at_issue="boundary-b-http",
                ),
                Task(
                    project_id=project_id,
                    engine="celery",
                    task_id="failed-task",
                    name="tasks.fail",
                    queue="critical",
                    state=TaskState.FAILURE,
                ),
            ]
        )
        await session.commit()

    def _authenticate(
        client: AsyncClient,
        *,
        session_id: uuid.UUID,
        csrf: str,
    ) -> None:
        client.cookies.set(
            cookie_name(environment=settings.environment),
            SessionCookieCodec(settings).encode(session_id),
        )
        client.cookies.set(
            csrf_cookie_name(environment=settings.environment),
            csrf,
        )

    transport = ASGITransport(app=app)
    async with (
        AsyncClient(
            transport=transport,
            base_url="http://localhost",
        ) as operator_client,
        AsyncClient(
            transport=transport,
            base_url="http://localhost",
        ) as viewer_client,
        AsyncClient(
            transport=transport,
            base_url="http://localhost",
        ) as anonymous_client,
    ):
        _authenticate(
            operator_client,
            session_id=operator_session_id,
            csrf=operator_csrf,
        )
        _authenticate(
            viewer_client,
            session_id=viewer_session_id,
            csrf=viewer_csrf,
        )
        yield {
            "app": app,
            "operator": operator_client,
            "operator_csrf": operator_csrf,
            "viewer": viewer_client,
            "viewer_csrf": viewer_csrf,
            "anonymous": anonymous_client,
            "project_id": project_id,
            "other_project_id": other_project_id,
            "agent_id": agent_id,
            "agent_token": agent_token,
        }
    await engine.dispose()


@pytest.mark.asyncio
async def test_public_resource_enforces_auth_role_and_csrf(
    bulk_http: dict[str, Any],
) -> None:
    path = "/api/v1/projects/bulk-http/bulk-retry-requests"
    body = {
        "idempotency_key": "http-auth",
        "filter": {"engine": "celery", "state": "failure"},
        "max": 10,
    }
    anonymous = await bulk_http["anonymous"].post(path, json=body)
    assert anonymous.status_code == 401
    no_csrf = await bulk_http["operator"].post(path, json=body)
    assert no_csrf.status_code == 403
    viewer = await bulk_http["viewer"].post(
        path,
        headers={"X-CSRF-Token": bulk_http["viewer_csrf"]},
        json=body,
    )
    assert viewer.status_code == 403


@pytest.mark.asyncio
async def test_bulk_retry_coordinator_is_registered_as_a_periodic_worker(
    bulk_http: dict[str, Any],
) -> None:
    """The durable parent scan must run without an incoming HTTP request."""

    app = bulk_http["app"]
    workers = {worker.name: worker for worker in app.state.worker_supervisor._workers}
    worker = workers["bulk_retry_coordinator"]
    assert worker.tick == app.state.bulk_retry_coordinator.tick
    assert worker.interval_seconds == float(app.state.settings.bulk_retry_scan_seconds)


@pytest.mark.asyncio
async def test_post_replay_get_pause_resume_and_location_are_durable(
    bulk_http: dict[str, Any],
) -> None:
    path = "/api/v1/projects/bulk-http/bulk-retry-requests"
    body = {
        "idempotency_key": "http-lifecycle",
        "filter": {"engine": "celery", "state": "failure"},
        "max": 10,
    }
    headers = {"X-CSRF-Token": bulk_http["operator_csrf"]}
    created = await bulk_http["operator"].post(path, headers=headers, json=body)
    assert created.status_code == 202
    location = created.headers["Location"]
    assert location == f"{path}/{created.json()['id']}"

    replay = await bulk_http["operator"].post(path, headers=headers, json=body)
    assert replay.status_code == 202
    assert replay.headers["Location"] == location
    assert replay.json() == created.json()

    fetched = await bulk_http["operator"].get(location)
    assert fetched.status_code == 200
    assert fetched.json()["counts"] == {
        "total": 1,
        "pending": 1,
        "claimed": 0,
        "unobserved": 1,
        "succeeded": 0,
        "failed": 0,
        "unknown": 0,
    }
    paused = await bulk_http["operator"].post(
        f"{location}/pause",
        headers=headers,
    )
    assert paused.status_code == 200
    assert paused.json()["status"] == "paused"
    resumed = await bulk_http["operator"].post(
        f"{location}/resume",
        headers=headers,
    )
    assert resumed.status_code == 200
    assert resumed.json()["status"] == "in_progress"

    async with bulk_http["app"].state.db.session() as session:
        assert (
            await session.scalar(
                select(func.count(BulkRetryRequest.id)).where(
                    BulkRetryRequest.project_id == bulk_http["project_id"]
                )
            )
            == 1
        )
        actions = set(
            (
                await session.execute(
                    select(AuditLog.action).where(
                        AuditLog.project_id == bulk_http["project_id"],
                        AuditLog.action.like("bulk_retry_request.%"),
                    )
                )
            ).scalars()
        )
    assert actions == {
        "bulk_retry_request.sealed",
        "bulk_retry_request.paused",
        "bulk_retry_request.resumed",
    }


@pytest.mark.asyncio
async def test_raw_key_conflict_and_cross_project_resource_lookup_fail_closed(
    bulk_http: dict[str, Any],
) -> None:
    path = "/api/v1/projects/bulk-http/bulk-retry-requests"
    headers = {"X-CSRF-Token": bulk_http["operator_csrf"]}
    created = await bulk_http["operator"].post(
        path,
        headers=headers,
        json={
            "idempotency_key": "http-conflict",
            "filter": {"engine": "celery", "state": "failure"},
            "max": 10,
        },
    )
    assert created.status_code == 202
    conflict = await bulk_http["operator"].post(
        path,
        headers=headers,
        json={
            "idempotency_key": "http-conflict",
            "filter": {"engine": "celery", "state": "success"},
            "max": 10,
        },
    )
    assert conflict.status_code == 409

    cross_project = await bulk_http["operator"].get(
        f"/api/v1/projects/bulk-http-other/bulk-retry-requests/{created.json()['id']}"
    )
    assert cross_project.status_code == 404


@pytest.mark.asyncio
async def test_no_match_is_immediately_terminal_with_stable_replay(
    bulk_http: dict[str, Any],
) -> None:
    path = "/api/v1/projects/bulk-http/bulk-retry-requests"
    headers = {"X-CSRF-Token": bulk_http["operator_csrf"]}
    body = {
        "idempotency_key": "http-no-match",
        "filter": {"engine": "rq", "state": "failure"},
        "max": 10,
    }
    created = await bulk_http["operator"].post(path, headers=headers, json=body)
    assert created.status_code == 200
    assert created.json()["status"] == "no_match"
    replay = await bulk_http["operator"].post(path, headers=headers, json=body)
    assert replay.status_code == 200
    assert replay.headers["Location"] == created.headers["Location"]
    assert replay.json() == created.json()


@pytest.mark.asyncio
async def test_longpoll_claim_is_bound_to_exact_request_nonce_and_contract(
    bulk_http: dict[str, Any],
) -> None:
    path = "/api/v1/projects/bulk-http/bulk-retry-requests"
    created = await bulk_http["operator"].post(
        path,
        headers={"X-CSRF-Token": bulk_http["operator_csrf"]},
        json={
            "idempotency_key": "http-longpoll-edge",
            "filter": {"engine": "celery", "state": "failure"},
            "max": 10,
        },
    )
    assert created.status_code == 202

    nonce = "boundary-b-exact-poll"
    agent_headers = {
        "Authorization": f"Bearer {bulk_http['agent_token']}",
        "X-Z4J-Session-Nonce": nonce,
    }
    no_contract = await bulk_http["anonymous"].get(
        "/api/v1/agent/commands",
        params={"wait": 0, "max_frames": 1},
        headers=agent_headers,
    )
    assert no_contract.status_code == 200
    assert no_contract.json()["frames"] == []

    claimed = await bulk_http["anonymous"].get(
        "/api/v1/agent/commands",
        params={"wait": 0, "max_frames": 1},
        headers={**agent_headers, "X-Z4J-Retry-Contracts": "celery=1"},
    )
    assert claimed.status_code == 200
    assert len(claimed.json()["frames"]) == 1
    expected_generation = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"z4j-longpoll:{bulk_http['agent_id']}:{nonce}",
    )
    async with bulk_http["app"].state.db.session() as session:
        child = await session.scalar(
            select(BulkRetryRequestChild).where(
                BulkRetryRequestChild.parent_id == uuid.UUID(created.json()["id"])
            )
        )
        assert child is not None
        assert child.claimed_agent_id == bulk_http["agent_id"]
        assert child.claimed_generation == expected_generation
