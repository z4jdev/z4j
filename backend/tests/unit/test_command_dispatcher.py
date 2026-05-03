"""Tests for the brain-side ``CommandDispatcher``."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.command_dispatcher import CommandDispatcher
from z4j_brain.persistence.base import Base
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.enums import AgentState, CommandStatus
from z4j_brain.persistence.models import Agent, Project
from z4j_brain.persistence.repositories import (
    AuditLogRepository,
    CommandRepository,
)
from z4j_brain.settings import Settings
from z4j_brain.websocket.registry._protocol import DeliveryResult


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
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


@pytest.fixture
async def project(session: AsyncSession) -> Project:
    p = Project(slug="default", name="Default")
    session.add(p)
    await session.commit()
    return p


@pytest.fixture
async def agent(session: AsyncSession, project: Project) -> Agent:
    a = Agent(
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
    session.add(a)
    await session.commit()
    return a


class FakeRegistry:
    """Stand-in for BrainRegistry whose ``deliver`` is configurable."""

    def __init__(
        self,
        *,
        delivered_locally: bool = False,
        notified_cluster: bool = False,
        agent_was_known: bool = True,
    ) -> None:
        self.calls: list[tuple[uuid.UUID, uuid.UUID]] = []
        self._result = DeliveryResult(
            delivered_locally=delivered_locally,
            notified_cluster=notified_cluster,
            agent_was_known=agent_was_known,
        )

    async def deliver(
        self,
        *,
        command_id: uuid.UUID,
        agent_id: uuid.UUID,
    ) -> DeliveryResult:
        self.calls.append((command_id, agent_id))
        return self._result


@pytest.mark.asyncio
class TestIssue:
    async def test_issue_persists_command_and_audits(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        settings: Settings,
    ) -> None:
        registry = FakeRegistry(notified_cluster=True, agent_was_known=True)
        audit = AuditService(settings)
        dispatcher = CommandDispatcher(
            settings=settings, registry=registry, audit=audit,
        )

        command = await dispatcher.issue(
            commands=CommandRepository(session),
            audit_log=AuditLogRepository(session),
            project_id=project.id,
            agent_id=agent.id,
            action="retry_task",
            target_type="task",
            target_id="celery:task-001",
            payload={"engine": "celery", "task_id": "task-001"},
            issued_by=None,
            ip="127.0.0.1",
            user_agent=None,
        )
        await session.commit()

        assert command.action == "retry_task"
        assert command.status == CommandStatus.PENDING
        assert registry.calls == [(command.id, agent.id)]

    async def test_issue_to_unknown_agent_raises(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        settings: Settings,
    ) -> None:
        from z4j_brain.errors import AgentOfflineError

        registry = FakeRegistry(
            delivered_locally=False,
            notified_cluster=False,
            agent_was_known=False,
        )
        audit = AuditService(settings)
        dispatcher = CommandDispatcher(
            settings=settings, registry=registry, audit=audit,
        )

        with pytest.raises(AgentOfflineError):
            await dispatcher.issue(
                commands=CommandRepository(session),
                audit_log=AuditLogRepository(session),
                project_id=project.id,
                agent_id=agent.id,
                action="cancel_task",
                target_type="task",
                target_id="celery:task-001",
                payload={},
                issued_by=None,
                ip="127.0.0.1",
                user_agent=None,
            )


@pytest.mark.asyncio
class TestHandleAck:
    async def test_pending_to_dispatched(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        settings: Settings,
    ) -> None:
        registry = FakeRegistry(notified_cluster=True)
        audit = AuditService(settings)
        dispatcher = CommandDispatcher(
            settings=settings, registry=registry, audit=audit,
        )
        commands = CommandRepository(session)
        cmd = await commands.insert(
            project_id=project.id,
            agent_id=agent.id,
            issued_by=None,
            action="retry_task",
            target_type="task",
            target_id="celery:task-001",
            payload={},
            idempotency_key=None,
            timeout_at=datetime.now(UTC) + timedelta(seconds=60),
            source_ip=None,
        )
        await dispatcher.handle_ack(commands=commands, command_id=cmd.id)
        await session.commit()
        await session.refresh(cmd)
        assert cmd.status == CommandStatus.DISPATCHED

    async def test_ack_from_wrong_agent_is_ignored(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        settings: Settings,
    ) -> None:
        registry = FakeRegistry(notified_cluster=True)
        audit = AuditService(settings)
        dispatcher = CommandDispatcher(
            settings=settings, registry=registry, audit=audit,
        )
        other_agent = Agent(
            project_id=project.id,
            name="web-02",
            token_hash=secrets.token_hex(32),
            protocol_version="1",
            framework_adapter="django",
            engine_adapters=["celery"],
            scheduler_adapters=[],
            capabilities={},
            state=AgentState.ONLINE,
        )
        session.add(other_agent)
        await session.flush()
        commands = CommandRepository(session)
        cmd = await commands.insert(
            project_id=project.id,
            agent_id=other_agent.id,
            issued_by=None,
            action="retry_task",
            target_type="task",
            target_id="celery:task-001",
            payload={},
            idempotency_key=None,
            timeout_at=datetime.now(UTC) + timedelta(seconds=60),
            source_ip=None,
        )
        await dispatcher.handle_ack(
            commands=commands,
            command_id=cmd.id,
            project_id=project.id,
            agent_id=agent.id,
        )
        await session.commit()
        await session.refresh(cmd)
        assert cmd.status == CommandStatus.PENDING


@pytest.mark.asyncio
class TestHandleResult:
    async def test_success_marks_completed(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        settings: Settings,
    ) -> None:
        registry = FakeRegistry(notified_cluster=True)
        audit = AuditService(settings)
        dispatcher = CommandDispatcher(
            settings=settings, registry=registry, audit=audit,
        )
        commands = CommandRepository(session)
        cmd = await commands.insert(
            project_id=project.id,
            agent_id=agent.id,
            issued_by=None,
            action="retry_task",
            target_type="task",
            target_id="celery:task-001",
            payload={},
            idempotency_key=None,
            timeout_at=datetime.now(UTC) + timedelta(seconds=60),
            source_ip=None,
        )
        await dispatcher.handle_result(
            commands=commands,
            audit_log=AuditLogRepository(session),
            command_id=cmd.id,
            status="success",
            result_payload={"new_task_id": "task-002"},
            error=None,
        )
        await session.commit()
        await session.refresh(cmd)
        assert cmd.status == CommandStatus.COMPLETED
        assert cmd.result == {"new_task_id": "task-002"}

    async def test_failed_marks_failed(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        settings: Settings,
    ) -> None:
        registry = FakeRegistry(notified_cluster=True)
        audit = AuditService(settings)
        dispatcher = CommandDispatcher(
            settings=settings, registry=registry, audit=audit,
        )
        commands = CommandRepository(session)
        cmd = await commands.insert(
            project_id=project.id,
            agent_id=agent.id,
            issued_by=None,
            action="retry_task",
            target_type="task",
            target_id="celery:task-001",
            payload={},
            idempotency_key=None,
            timeout_at=datetime.now(UTC) + timedelta(seconds=60),
            source_ip=None,
        )
        await dispatcher.handle_result(
            commands=commands,
            audit_log=AuditLogRepository(session),
            command_id=cmd.id,
            status="failed",
            result_payload=None,
            error="task does not exist",
        )
        await session.commit()
        await session.refresh(cmd)
        assert cmd.status == CommandStatus.FAILED
        assert cmd.error == "task does not exist"

    async def test_result_from_wrong_agent_is_ignored(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        settings: Settings,
    ) -> None:
        registry = FakeRegistry(notified_cluster=True)
        audit = AuditService(settings)
        dispatcher = CommandDispatcher(
            settings=settings, registry=registry, audit=audit,
        )
        other_agent = Agent(
            project_id=project.id,
            name="web-02",
            token_hash=secrets.token_hex(32),
            protocol_version="1",
            framework_adapter="django",
            engine_adapters=["celery"],
            scheduler_adapters=[],
            capabilities={},
            state=AgentState.ONLINE,
        )
        session.add(other_agent)
        await session.flush()
        commands = CommandRepository(session)
        cmd = await commands.insert(
            project_id=project.id,
            agent_id=other_agent.id,
            issued_by=None,
            action="retry_task",
            target_type="task",
            target_id="celery:task-001",
            payload={},
            idempotency_key=None,
            timeout_at=datetime.now(UTC) + timedelta(seconds=60),
            source_ip=None,
        )
        await dispatcher.handle_result(
            commands=commands,
            audit_log=AuditLogRepository(session),
            command_id=cmd.id,
            status="success",
            result_payload={"new_task_id": "task-002"},
            error=None,
            project_id=project.id,
            agent_id=agent.id,
        )
        await session.commit()
        await session.refresh(cmd)
        assert cmd.status == CommandStatus.PENDING
        assert cmd.result is None

    async def test_duplicate_result_is_noop(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        settings: Settings,
    ) -> None:
        registry = FakeRegistry(notified_cluster=True)
        audit = AuditService(settings)
        dispatcher = CommandDispatcher(
            settings=settings, registry=registry, audit=audit,
        )
        commands = CommandRepository(session)
        cmd = await commands.insert(
            project_id=project.id,
            agent_id=agent.id,
            issued_by=None,
            action="retry_task",
            target_type="task",
            target_id="celery:task-001",
            payload={},
            idempotency_key=None,
            timeout_at=datetime.now(UTC) + timedelta(seconds=60),
            source_ip=None,
        )
        await dispatcher.handle_result(
            commands=commands,
            audit_log=AuditLogRepository(session),
            command_id=cmd.id,
            status="success",
            result_payload=None,
            error=None,
        )
        await dispatcher.handle_result(
            commands=commands,
            audit_log=AuditLogRepository(session),
            command_id=cmd.id,
            status="success",
            result_payload=None,
            error=None,
        )
        await session.commit()
        # Still completed, no crash from the duplicate.
        await session.refresh(cmd)
        assert cmd.status == CommandStatus.COMPLETED
