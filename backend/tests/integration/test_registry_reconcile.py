"""Integration tests for the registry's durable-row reconcile sweeper.

``NOTIFY`` is a best-effort post-commit wake-up, not an outbox.  The
reconcile loop closes the gap when publishing fails, a notification is
lost in transit, or the agent connects after a command was issued.  In
all three cases the committed ``status='pending'`` row remains the
delivery authority until reconciliation picks it up.

We test the latter case here because it's the simpler shape:

1. Insert a project + agent + a pending command targeting that
   agent into the database.
2. Start a registry, register the agent locally.
3. Wait long enough for the reconcile sweeper to fire (interval
   is set to 2s in integration_settings).
4. Verify the deliver callback fires for the pre-existing command.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.settings import Settings
from z4j_brain.websocket.registry import PostgresNotifyRegistry

pytestmark = pytest.mark.asyncio


class FakeWebSocket:
    def __init__(self, name: str = "ws") -> None:
        self.name = name


async def _seed_pending_command(
    engine: AsyncEngine,
) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    """Insert project + agent + pending command. Returns ids."""
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    command_id = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO projects (id, slug, name) VALUES (:id, :slug, 'P')"),
            {"id": project_id, "slug": f"p-{uuid.uuid4().hex[:8]}"},
        )
        await conn.execute(
            text(
                "INSERT INTO agents "
                "(id, project_id, name, token_hash, protocol_version, "
                " framework_adapter, engine_adapters, scheduler_adapters, "
                " capabilities, state) "
                "VALUES (:id, :pid, 'a', :tok, '1', 'bare', "
                " ARRAY[]::text[], ARRAY[]::text[], '{}'::jsonb, 'unknown')",
            ),
            {"id": agent_id, "pid": project_id, "tok": uuid.uuid4().hex},
        )
        await conn.execute(
            text(
                "INSERT INTO commands "
                "(id, project_id, agent_id, action, target_type, target_id, "
                " payload, status, timeout_at, issued_at) "
                "VALUES (:id, :pid, :aid, 'retry_task', 'task', 'celery:t1', "
                '        \'{"engine":"celery","task_id":"t1"}\'::jsonb, '
                "        'pending', :tmo, NOW())",
            ),
            {
                "id": command_id,
                "pid": project_id,
                "aid": agent_id,
                "tmo": datetime.now(UTC) + timedelta(minutes=10),
            },
        )
    return project_id, agent_id, command_id


class TestReconcile:
    async def test_failed_wakeup_leaves_pending_row_for_reconciliation(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        project_id, agent_id, command_id = await _seed_pending_command(
            migrated_engine,
        )
        deliver_calls: list[tuple[uuid.UUID, str]] = []
        db = DatabaseManager(migrated_engine)

        async def deliver(cmd_id: uuid.UUID, ws: Any) -> bool:
            deliver_calls.append((cmd_id, ws.name))
            return True

        registry = PostgresNotifyRegistry(
            settings=integration_settings,
            db=db,
            dsn_provider=lambda: integration_settings.database_url,
            deliver_local=deliver,
        )

        async def fail_publish(*_args: object, **_kwargs: object) -> None:
            raise OSError("forced NOTIFY failure")

        # No local connection means deliver() takes the cross-worker wake-up
        # path.  Its failure must not mutate or consume the committed row.
        with monkeypatch.context() as patch:
            patch.setattr(registry, "_publish_command_notify", fail_publish)
            with pytest.raises(OSError, match="forced NOTIFY failure"):
                await registry.deliver(
                    command_id=command_id,
                    agent_id=agent_id,
                    required_retry_engine="celery",
                )

        async with migrated_engine.connect() as connection:
            status = (
                await connection.execute(
                    text("SELECT status FROM commands WHERE id = :id"),
                    {"id": command_id},
                )
            ).scalar_one()
        assert status == "pending"

        await registry.register(
            project_id=project_id,
            agent_id=agent_id,
            ws=FakeWebSocket("reconcile-target"),
            worker_id="current",
            retry_contracts={"celery": 1},
        )
        await registry._reconcile_pending()  # type: ignore[attr-defined]

        assert deliver_calls == [(command_id, "reconcile-target")]

    async def test_pending_command_picked_up_after_register(
        self,
        migrated_engine: AsyncEngine,
        integration_settings: Settings,
    ) -> None:
        project_id, agent_id, command_id = await _seed_pending_command(
            migrated_engine,
        )

        deliver_calls: list[tuple[uuid.UUID, str]] = []
        db = DatabaseManager(migrated_engine)

        async def deliver(cmd_id: uuid.UUID, ws: Any) -> bool:
            deliver_calls.append((cmd_id, ws.name))
            return True

        registry = PostgresNotifyRegistry(
            settings=integration_settings,
            db=db,
            dsn_provider=lambda: integration_settings.database_url,
            deliver_local=deliver,
        )
        await registry.start()
        try:
            # The reconcile sweeper polls for pending commands
            # whose agent_id is in the local map. Register AFTER
            # start so the immediate-on-connect reconcile path
            # would not catch it; only the periodic loop should.
            await registry.register(
                project_id=project_id,
                agent_id=agent_id,
                ws=FakeWebSocket("old-first"),
                worker_id="old",
                retry_contracts={},
            )
            await registry.register(
                project_id=project_id,
                agent_id=agent_id,
                ws=FakeWebSocket("current-second"),
                worker_id="current",
                retry_contracts={"celery": 1},
            )

            # Wait up to 6 seconds - the reconcile interval is 2s
            # in integration settings, so 3 ticks gives us margin.
            for _ in range(60):
                if deliver_calls:
                    break
                await asyncio.sleep(0.1)

            assert deliver_calls, "reconcile sweeper never picked up the command"
            assert deliver_calls[0] == (command_id, "current-second")
        finally:
            await registry.stop()
