"""Frame-router -> automation executor hot-path hookup.

Proves an inbound task-lifecycle event fires matching automation rules
end to end: ``FrameRouter._evaluate_automation`` -> ``AutomationExecutor``
-> ``AutomationActionRunner`` (notify + retry), through a real DB session
and a real ``CommandDispatcher``. The evaluator / executor / runner have
their own focused unit tests; this closes the wiring gap the way
``test_frame_router_heartbeat_e2e`` does for the heartbeat path."""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import uuid
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.command_dispatcher import CommandDispatcher
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import AgentState, ProjectRole
from z4j_brain.persistence.models import (
    Agent,
    AuditLog,
    AutomationRule,
    Command,
    Membership,
    Project,
    Task,
    User,
    UserNotification,
)
from z4j_brain.settings import Settings
from z4j_brain.websocket.frame_router import FrameRouter
from z4j_brain.websocket.registry._protocol import DeliveryResult
from z4j_core.models.event import EventKind


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )


@pytest.fixture
async def db_manager():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    db = DatabaseManager(engine)
    yield db
    await engine.dispose()


class _FakeRegistry:
    """Records deliver() calls so a rule-issued command is observable."""

    def __init__(self) -> None:
        self.calls: list[tuple[uuid.UUID, uuid.UUID]] = []

    async def deliver(
        self,
        *,
        command_id: uuid.UUID,
        agent_id: uuid.UUID,
        required_retry_engine: str | None = None,
    ) -> DeliveryResult:
        self.calls.append((command_id, agent_id))
        return DeliveryResult(
            delivered_locally=False,
            notified_cluster=True,
            agent_was_known=True,
        )


async def _seed(
    db: DatabaseManager,
    *,
    actions: list[dict[str, Any]],
    seed_task: bool = False,
    automation_enabled: bool = True,
    role: ProjectRole = ProjectRole.OPERATOR,
) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    async with db.session() as s:
        project = Project(
            slug=f"p{uuid.uuid4().hex[:8]}",
            name="P",
            automation_enabled=automation_enabled,
        )
        s.add(project)
        await s.flush()
        agent = Agent(
            project_id=project.id,
            name="web-01",
            token_hash=secrets.token_hex(32),
            protocol_version="1",
            framework_adapter="django",
            engine_adapters=["celery"],
            scheduler_adapters=[],
            capabilities={},
            state=AgentState.ONLINE,
        )
        s.add(agent)
        await s.flush()
        user = User(
            email=f"{uuid.uuid4().hex[:8]}@x.io",
            password_hash=secrets.token_hex(8),
        )
        s.add(user)
        await s.flush()
        s.add(
            Membership(
                user_id=user.id,
                project_id=project.id,
                role=role,
            ),
        )
        if seed_task:
            s.add(
                Task(
                    project_id=project.id,
                    engine="celery",
                    task_id="task-9",
                    name="myapp.tasks.send",
                ),
            )
        s.add(
            AutomationRule(
                project_id=project.id,
                name="rule-1",
                trigger="task.failed",
                actions=actions,
                # A destructive rule (retry/cancel) re-checks the creator is
                # still ADMIN at fire time and fails closed on a NULL owner,
                # so attribute the rule to the seeded member.
                created_by=user.id,
            ),
        )
        await s.commit()
        return project.id, agent.id, user.id


def _router(
    db: DatabaseManager,
    settings: Settings,
    registry: _FakeRegistry,
    project_id: uuid.UUID,
    agent_id: uuid.UUID,
) -> FrameRouter:
    dispatcher = CommandDispatcher(
        settings=settings,
        registry=registry,  # type: ignore[arg-type]
        audit=AuditService(settings),
    )
    return FrameRouter(
        db=db,
        ingestor=None,  # type: ignore[arg-type]  # unused on this path
        dispatcher=dispatcher,
        project_id=project_id,
        agent_id=agent_id,
    )


def _failed_event() -> dict[str, Any]:
    return {
        "kind": EventKind.TASK_FAILED.value,
        "task_id": "task-9",
        "engine": "celery",
        "data": {
            "task_name": "myapp.tasks.send",
            "queue": "celery",
            "priority": "high",
            "exception": "boom",
        },
    }


async def _drain(router: FrameRouter) -> None:
    """Run the detached automation dispatch tasks to completion."""
    tasks = list(router._pending_automation_tasks)
    if tasks:
        await asyncio.gather(*tasks)


@pytest.mark.asyncio
async def test_aclose_cancels_pending_automation_tasks(
    db_manager: DatabaseManager,
    settings: Settings,
) -> None:
    # Aclose() must cancel in-flight automation
    # tasks too (not just ack + notify). A leaked task holds a DB-session
    # slot and keeps the router (and its per-connection caps) alive under
    # reconnect churn.
    project_id, agent_id, _ = await _seed(db_manager, actions=[{"type": "notify"}])
    router = _router(db_manager, settings, _FakeRegistry(), project_id, agent_id)

    async def _never() -> None:
        await asyncio.sleep(3600)

    task = asyncio.create_task(_never())
    router._pending_automation_tasks.add(task)

    router.aclose()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    assert task.cancelled()


@pytest.mark.asyncio
async def test_inbound_event_fires_notify_rule(
    db_manager: DatabaseManager,
    settings: Settings,
) -> None:
    project_id, agent_id, _ = await _seed(
        db_manager,
        actions=[{"type": "notify"}],
    )
    registry = _FakeRegistry()
    router = _router(db_manager, settings, registry, project_id, agent_id)

    await router._evaluate_automation([_failed_event()])
    await _drain(router)

    async with db_manager.session() as s:
        notes = (await s.execute(select(UserNotification))).scalars().all()
        fired_result = await s.execute(
            select(AuditLog).where(AuditLog.action == "automation.rule.fired"),
        )
        fired = fired_result.scalars().all()
    assert len(notes) == 1
    assert notes[0].reason == "automation"
    assert len(fired) == 1
    # notify does not touch the command path.
    assert registry.calls == []


@pytest.mark.asyncio
async def test_inbound_event_fires_retry_rule(
    db_manager: DatabaseManager,
    settings: Settings,
) -> None:
    project_id, agent_id, _ = await _seed(
        db_manager,
        actions=[{"type": "retry"}],
        seed_task=True,
        # retry is destructive: the fire-time re-check requires the creator
        # to still hold ADMIN on the project.
        role=ProjectRole.ADMIN,
    )
    registry = _FakeRegistry()
    router = _router(db_manager, settings, registry, project_id, agent_id)

    await router._evaluate_automation([_failed_event()])
    await _drain(router)

    assert len(registry.calls) == 1
    assert registry.calls[0][1] == agent_id
    async with db_manager.session() as s:
        cmds = (await s.execute(select(Command))).scalars().all()
    assert len(cmds) == 1
    assert cmds[0].action == "retry_task"
    assert cmds[0].payload.get("task_name") == "myapp.tasks.send"


@pytest.mark.asyncio
async def test_non_matching_kind_is_ignored(
    db_manager: DatabaseManager,
    settings: Settings,
) -> None:
    project_id, agent_id, _ = await _seed(
        db_manager,
        actions=[{"type": "notify"}],
    )
    registry = _FakeRegistry()
    router = _router(db_manager, settings, registry, project_id, agent_id)

    # A kind with no trigger mapping spawns no dispatch task at all.
    await router._evaluate_automation([{"kind": "worker.heartbeat", "task_id": "x"}])
    assert router._pending_automation_tasks == set()
    await _drain(router)

    async with db_manager.session() as s:
        notes = (await s.execute(select(UserNotification))).scalars().all()
    assert notes == []


@pytest.mark.asyncio
async def test_kill_switch_off_fires_nothing_end_to_end(
    db_manager: DatabaseManager,
    settings: Settings,
) -> None:
    # A project with automation_enabled=False + a live destructive rule:
    # a matching dispatched event must produce no command, no
    # notification, and no fired-audit row (the choke point loads no
    # rules).
    project_id, agent_id, _ = await _seed(
        db_manager,
        actions=[{"type": "retry"}],
        seed_task=True,
        automation_enabled=False,
    )
    registry = _FakeRegistry()
    router = _router(db_manager, settings, registry, project_id, agent_id)

    await router._evaluate_automation([_failed_event()])
    await _drain(router)

    assert registry.calls == []
    async with db_manager.session() as s:
        cmds = (await s.execute(select(Command))).scalars().all()
        notes = (await s.execute(select(UserNotification))).scalars().all()
        fired_result = await s.execute(
            select(AuditLog).where(AuditLog.action == "automation.rule.fired"),
        )
        fired = fired_result.scalars().all()
    assert cmds == []
    assert notes == []
    assert fired == []


@pytest.mark.asyncio
async def test_cross_project_isolation(
    db_manager: DatabaseManager,
    settings: Settings,
) -> None:
    # Two projects each with a notify rule + one member. An event
    # dispatched under project A's connection must fire ONLY A's rule and
    # notify ONLY A's member -- never B's.
    a_project, a_agent, a_user = await _seed(
        db_manager,
        actions=[{"type": "notify"}],
    )
    await _seed(db_manager, actions=[{"type": "notify"}])  # project B
    registry = _FakeRegistry()
    router = _router(db_manager, settings, registry, a_project, a_agent)

    await router._evaluate_automation([_failed_event()])
    await _drain(router)

    async with db_manager.session() as s:
        notes = (await s.execute(select(UserNotification))).scalars().all()
    assert len(notes) == 1
    assert notes[0].project_id == a_project
    assert notes[0].user_id == a_user


def test_is_benign_disconnect_classifier() -> None:
    from z4j_brain.websocket.frame_router import _is_benign_disconnect

    assert _is_benign_disconnect(
        RuntimeError("Cannot call 'send' once a close message has been sent."),
    )
    assert _is_benign_disconnect(
        RuntimeError(
            "Unexpected ASGI message 'websocket.send', after sending 'websocket.close'.",
        ),
    )
    # A real bug is NOT swallowed as a benign disconnect.
    assert not _is_benign_disconnect(ValueError("a genuine outbound-frame bug"))


@pytest.mark.asyncio
async def test_send_frame_safe_swallows_benign_disconnect(
    db_manager: DatabaseManager,
    settings: Settings,
) -> None:
    """A send that fails because the agent already disconnected must NOT
    raise (a missed ack self-heals on reconnect); a real error still
    surfaces via logging but also must not crash the caller."""
    project_id, agent_id, _ = await _seed(db_manager, actions=[{"type": "notify"}])

    async def _closed(_frame):
        raise RuntimeError(
            "Cannot call 'send' once a close message has been sent.",
        )

    dispatcher = CommandDispatcher(
        settings=settings,
        registry=_FakeRegistry(),  # type: ignore[arg-type]
        audit=AuditService(settings),
    )
    router = FrameRouter(
        db=db_manager,
        ingestor=None,  # type: ignore[arg-type]
        dispatcher=dispatcher,
        project_id=project_id,
        agent_id=agent_id,
        send_frame=_closed,
    )
    # Must return normally (benign disconnect swallowed).
    await router._send_frame_safe(object())


@pytest.mark.asyncio
async def test_backpressure_defers_to_outbox_only_when_rules_exist(
    db_manager: DatabaseManager,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Under backpressure the firing is deferred to the durable outbox, but
    ONLY for a trigger the project actually has a rule for (the has-rules
    gate keeps a busy no-rule project from bloating the outbox)."""
    from z4j_brain.persistence.repositories import AutomationFiringOutboxRepository
    from z4j_brain.websocket import frame_router as fr_mod

    # Force the deferred path: pending "full" at 0.
    monkeypatch.setattr(fr_mod, "_MAX_PENDING_NOTIFICATION_TASKS", 0)

    # Seeds a rule for task.failed only.
    project_id, agent_id, _ = await _seed(db_manager, actions=[{"type": "notify"}])
    registry = _FakeRegistry()
    router = _router(db_manager, settings, registry, project_id, agent_id)

    # task.failed HAS a rule -> the deferred firing lands in the outbox.
    await router._evaluate_automation([_failed_event()])
    async with db_manager.session() as s:
        assert await AutomationFiringOutboxRepository(s).count() == 1

    # task.succeeded has NO rule -> the deferred firing is gated out.
    await router._evaluate_automation(
        [{"kind": EventKind.TASK_SUCCEEDED.value, "task_id": "t2", "engine": "celery", "data": {}}],
    )
    async with db_manager.session() as s:
        assert await AutomationFiringOutboxRepository(s).count() == 1
