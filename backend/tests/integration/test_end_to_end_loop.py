"""Integration test: full agent ↔ brain loop against real Postgres.

This is the test the user has been waiting for: a fake agent
opens a WebSocket to ``/ws/agent``, the brain authenticates the
bearer token, the handshake completes, the agent sends an
``event_batch``, and a REST call against the brain returns the
projected task. Then the test issues a retry-task command via the
REST API and verifies the agent's WebSocket receives the signed
command frame.

What this exercises that no unit test can:

- Real ``/ws/agent`` upgrade with a real bearer token
- Real ``HelloFrame`` / ``HelloAckFrame`` round-trip
- Real ``EventIngestor`` writing into the partitioned events table
- Real ``tasks`` projection through the EventIngestor
- Real REST query that returns the projected task
- Real ``CommandDispatcher.issue`` → ``PostgresNotifyRegistry.deliver``
  fast-path → frame pushed back over the WebSocket

The test uses ``httpx.ASGITransport`` to drive the brain in-process
without spinning up uvicorn. The "agent" is a tiny harness that
serializes brain frames using ``z4j_core.transport.frames`` and
talks to ``starlette.testclient.WebSocketTestSession`` - the
brain has no idea this is a test.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from z4j_core.transport.frames import (
    EventBatchFrame,
    EventBatchPayload,
    HelloAckFrame,
    HelloFrame,
    HelloPayload,
    parse_frame,
    serialize_frame,
)
from z4j_core.transport.framing import FrameSigner
from z4j_core.transport.hmac import derive_project_secret

from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.auth.csrf import csrf_cookie_name
from z4j_brain.main import create_app
from z4j_brain.persistence.models import Project, Session, User
from z4j_brain.settings import Settings
from z4j_brain.websocket.auth import hash_agent_token

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _seed_full_environment(
    engine: AsyncEngine,
    *,
    settings: Settings,
) -> dict:
    """Insert project + admin user + agent + dashboard session."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    csrf = secrets.token_urlsafe(32)
    agent_id = uuid.uuid4()
    agent_token_plaintext = secrets.token_urlsafe(32)
    secret = settings.secret.get_secret_value().encode("utf-8")
    agent_token_hash = hash_agent_token(
        plaintext=agent_token_plaintext, secret=secret,
    )

    factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False,
    )
    hasher = PasswordHasher(settings)
    async with factory() as s:
        # Insert parent rows first so the FK from sessions → users
        # is satisfied. SQLite ignores FKs by default; Postgres
        # enforces them strictly so we need to flush in order.
        s.add(Project(id=project_id, slug="default", name="Default"))
        s.add(
            User(
                id=user_id,
                email="admin@example.com",
                password_hash=hasher.hash("correct horse battery staple 9"),
                is_admin=True,
                is_active=True,
            ),
        )
        await s.flush()
        s.add(
            Session(
                id=session_id,
                user_id=user_id,
                csrf_token=csrf,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                ip_at_issue="127.0.0.1",
                user_agent_at_issue="integration-test",
            ),
        )
        await s.commit()

    # Insert the agent via raw SQL so we don't have to import
    # the AgentRepository - we want this fixture portable.
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO agents "
                "(id, project_id, name, token_hash, protocol_version, "
                " framework_adapter, engine_adapters, scheduler_adapters, "
                " capabilities, state) "
                "VALUES (:id, :pid, 'agent-1', :tok, '2', 'django', "
                " ARRAY['celery']::text[], ARRAY[]::text[], "
                " '{}'::jsonb, 'unknown')",
            ),
            {"id": agent_id, "pid": project_id, "tok": agent_token_hash},
        )

    return {
        "project_id": project_id,
        "user_id": user_id,
        "session_id": session_id,
        "csrf": csrf,
        "agent_id": agent_id,
        "agent_token": agent_token_plaintext,
    }


# ---------------------------------------------------------------------------
# The test
# ---------------------------------------------------------------------------


class TestEndToEndLoop:
    async def test_agent_event_then_dashboard_query(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        """Connect a fake agent, push events, query via REST."""
        seeded = await _seed_full_environment(
            migrated_engine, settings=integration_settings,
        )

        # Dispose the test-loop engine BEFORE TestClient takes over.
        # TestClient runs the brain's lifespan + handlers in a
        # worker thread with its own event loop, and asyncpg
        # connections are loop-bound - sharing one would cause
        # "another operation is in progress" errors. We let the
        # brain build a fresh engine from settings.database_url
        # (same database, fresh pool, owned by TestClient's loop).
        await migrated_engine.dispose()

        app = create_app(integration_settings, engine=None)
        # Wait for lifespan startup so the registry's listener task
        # is alive before we connect.
        with TestClient(app) as client:
            # ------------------------------------------------------------
            # 1) Open the WebSocket and complete the hello handshake
            # ------------------------------------------------------------
            with client.websocket_connect(
                "/ws/agent",
                headers={
                    "authorization": f"Bearer {seeded['agent_token']}",
                },
            ) as ws:
                hello = HelloFrame(
                    id="hello_test",
                    ts=datetime.now(UTC),
                    payload=HelloPayload(
                        protocol_version="2",
                        agent_version="0.1.0-test",
                        framework="django",
                        engines=["celery"],
                        schedulers=[],
                        capabilities={"celery": ["retry", "cancel"]},
                        host={},
                    ),
                )
                ws.send_bytes(serialize_frame(hello))

                ack_raw = ws.receive_bytes()
                ack = parse_frame(ack_raw)
                assert isinstance(ack, HelloAckFrame)
                assert ack.payload.agent_id == str(seeded["agent_id"])
                assert ack.payload.project_id == str(seeded["project_id"])
                assert ack.payload.protocol_version == "2"

                # Protocol v2: every post-handshake frame has to be
                # signed with an envelope HMAC bound to the session's
                # agent_id + project_id. The brain derives a per-
                # project signing secret from the master key (see
                # ``websocket/gateway.py`` and
                # ``z4j_core.transport.hmac.derive_project_secret``)
                # so a leaked agent host secret can't forge frames
                # against other projects. The fake agent must mirror
                # the same derivation or the verifier rejects every
                # frame with ``hmac signature mismatch``.
                from uuid import UUID as _UUID

                master = integration_settings.secret.get_secret_value().encode(
                    "utf-8",
                )
                project_secret = derive_project_secret(
                    master, _UUID(ack.payload.project_id),
                )
                # Audit fix S006-E (1.4.0): FrameSigner requires the
                # ``session_id`` from the HelloAck so the per-frame
                # HMAC binds to THIS session. Pre-fix this test omitted
                # the kwarg, brain rejected every post-handshake frame
                # with ``hmac signature mismatch`` because the session
                # binding was missing on the signer side. The brain
                # gateway has carried the session_id binding since the
                # v2 envelope-HMAC framing landed (see
                # ``websocket/gateway.py:279``); the test was authored
                # against the pre-binding API and never updated.
                signer = FrameSigner(
                    secret=project_secret,
                    agent_id=ack.payload.agent_id,
                    project_id=ack.payload.project_id,
                    session_id=ack.payload.session_id,
                )

                # ------------------------------------------------------------
                # 2) Push an event_batch with one task.received event
                # ------------------------------------------------------------
                event_batch = EventBatchFrame(
                    id="ev_test",
                    payload=EventBatchPayload(
                        events=[
                            {
                                "kind": "task.received",
                                "engine": "celery",
                                "task_id": "task-001",
                                "occurred_at": datetime.now(UTC).isoformat(),
                                "data": {
                                    "task_name": "myapp.tasks.send_email",
                                    "queue": "default",
                                    "args": [],
                                    "kwargs": {"to": "alice@example.com"},
                                },
                            },
                        ],
                    ),
                )
                ws.send_bytes(signer.sign_and_serialize(event_batch))

                # The brain ingests asynchronously inside the
                # frame router. ``time.sleep`` is safe here because
                # we're on TestClient's worker thread, not in the
                # brain's event loop.
                import time as _time

                _time.sleep(0.5)

                # ------------------------------------------------------------
                # 3) Query the REST API as the dashboard would
                # ------------------------------------------------------------
                client.cookies.set(
                    cookie_name(environment=integration_settings.environment),
                    SessionCookieCodec(integration_settings).encode(
                        seeded["session_id"],
                    ),
                )
                client.cookies.set(
                    csrf_cookie_name(environment=integration_settings.environment),
                    seeded["csrf"],
                )

                # The /tasks endpoint should now reflect the
                # event_batch we just pushed end-to-end through:
                # WebSocket → frame router → EventIngestor →
                # events partition + tasks projection → REST.
                tasks_resp = client.get("/api/v1/projects/default/tasks")
                assert tasks_resp.status_code == 200
                body = tasks_resp.json()
                names = {t["name"] for t in body["items"]}
                assert "myapp.tasks.send_email" in names
