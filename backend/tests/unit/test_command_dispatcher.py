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
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
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
        required_retry_engine: str | None = None,
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
            settings=settings,
            registry=registry,
            audit=audit,
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
            settings=settings,
            registry=registry,
            audit=audit,
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

    async def test_synthetic_success_completes_in_place_not_delivered_h1(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        settings: Settings,
    ) -> None:
        # A pre_completed_result command is COMPLETED and NEVER delivered
        # (no committed-PENDING window, no registry push).
        registry = FakeRegistry(delivered_locally=True)
        dispatcher = CommandDispatcher(
            settings=settings, registry=registry, audit=AuditService(settings)
        )
        command = await dispatcher.issue(
            commands=CommandRepository(session),
            audit_log=AuditLogRepository(session),
            project_id=project.id,
            agent_id=agent.id,
            action="bulk_retry",
            target_type="bulk",
            target_id=None,
            payload={"filter": {"task_ids": []}},
            issued_by=None,
            ip="127.0.0.1",
            user_agent=None,
            idempotency_key="noop:key:__noop__",
            pre_completed_result={"no_owned_match": True},
        )
        assert command.status == CommandStatus.COMPLETED
        assert command.result == {"no_owned_match": True}
        assert registry.calls == []  # never delivered

    async def test_synthetic_completion_does_not_hijack_collided_command_h3(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        settings: Settings,
    ) -> None:
        # A request that collides on idempotency_key with an
        # UNRELATED command (different action/target/agent) must NOT return or
        # complete that command -- it now raises a 409 ConflictError, and the
        # unrelated command is left untouched.
        from z4j_core.errors import ConflictError

        registry = FakeRegistry(delivered_locally=True)
        dispatcher = CommandDispatcher(
            settings=settings, registry=registry, audit=AuditService(settings)
        )
        commands = CommandRepository(session)
        # An unrelated in-flight retry_task holding the key.
        existing, created = await commands.insert(
            project_id=project.id,
            agent_id=agent.id,
            issued_by=None,
            action="retry_task",
            target_type="task",
            target_id="celery:task-001",
            payload={"engine": "celery", "task_id": "task-001"},
            idempotency_key="collide",
            timeout_at=datetime.now(UTC) + timedelta(seconds=60),
            source_ip=None,
        )
        await session.commit()
        assert created is True and existing.status == CommandStatus.PENDING

        with pytest.raises(ConflictError):
            await dispatcher.issue(
                commands=commands,
                audit_log=AuditLogRepository(session),
                project_id=project.id,
                agent_id=agent.id,
                action="bulk_retry",
                target_type="bulk",
                target_id=None,
                payload={"filter": {"task_ids": []}},
                issued_by=None,
                ip="127.0.0.1",
                user_agent=None,
                idempotency_key="collide",  # collides with the retry_task above
                pre_completed_result={"no_owned_match": True},
            )
        await session.rollback()
        await session.refresh(existing)
        # The unrelated command is untouched -- still PENDING, still a retry_task.
        assert existing.status == CommandStatus.PENDING
        assert existing.action == "retry_task"

    async def test_idempotent_reissue_of_completed_command_no_offline_raise_h8(
        self,
        session: AsyncSession,
        project: Project,
        agent: Agent,
        settings: Settings,
    ) -> None:
        # Re-issuing a command whose idempotency_key already maps to an
        # already-progressed (COMPLETED) row must return it as success WITHOUT
        # delivering and WITHOUT raising AgentOfflineError (the catch-up-drain
        # wedge). The registry here would raise-worthy: agent unknown, nothing
        # delivered -- yet issue() must NOT reach that branch.
        from z4j_brain.errors import AgentOfflineError

        registry = FakeRegistry(
            delivered_locally=False, notified_cluster=False, agent_was_known=False
        )
        dispatcher = CommandDispatcher(
            settings=settings, registry=registry, audit=AuditService(settings)
        )
        commands = CommandRepository(session)
        first, _ = await commands.insert(
            project_id=project.id,
            agent_id=agent.id,
            issued_by=None,
            action="schedule.fire",
            target_type="schedule",
            target_id="sched-1",
            payload={},
            idempotency_key="schedule:s1:fire:f1",
            timeout_at=datetime.now(UTC) + timedelta(seconds=60),
            source_ip=None,
        )
        await commands.mark_completed(first.id, result_payload={"ok": True})
        await session.commit()

        # Re-issue with the SAME idempotency key (catch-up replay of a dispatched
        # slot). Must not raise, must not deliver.
        try:
            returned = await dispatcher.issue(
                commands=commands,
                audit_log=AuditLogRepository(session),
                project_id=project.id,
                agent_id=agent.id,
                action="schedule.fire",
                target_type="schedule",
                target_id="sched-1",
                payload={},
                issued_by=None,
                ip="127.0.0.1",
                user_agent=None,
                idempotency_key="schedule:s1:fire:f1",
            )
        except AgentOfflineError:
            pytest.fail("idempotent re-issue of a completed command wrongly raised")
        assert returned.id == first.id
        assert returned.status == CommandStatus.COMPLETED
        assert registry.calls == []  # never re-delivered


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
            settings=settings,
            registry=registry,
            audit=audit,
        )
        commands = CommandRepository(session)
        cmd, _ = await commands.insert(
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
            settings=settings,
            registry=registry,
            audit=audit,
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
        cmd, _ = await commands.insert(
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
            settings=settings,
            registry=registry,
            audit=audit,
        )
        commands = CommandRepository(session)
        cmd, _ = await commands.insert(
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
            settings=settings,
            registry=registry,
            audit=audit,
        )
        commands = CommandRepository(session)
        cmd, _ = await commands.insert(
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
            settings=settings,
            registry=registry,
            audit=audit,
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
        cmd, _ = await commands.insert(
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
            settings=settings,
            registry=registry,
            audit=audit,
        )
        commands = CommandRepository(session)
        cmd, _ = await commands.insert(
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


@pytest.mark.asyncio
class TestInsertIdentityGuardRH1:
    """An idempotency-key collision must map to ONE logical command.
    A collision whose stored row is a DIFFERENT command (action/target/agent)
    raises ConflictError instead of returning/delivering the wrong command; a
    genuine repeat (all four identity fields match) still dedups."""

    async def _insert(self, commands, project, agent, **over):
        base = {
            "project_id": project.id,
            "agent_id": agent.id,
            "issued_by": None,
            "action": "retry_task",
            "target_type": "task",
            "target_id": "celery:t1",
            "payload": {"x": 1},
            "idempotency_key": "K",
            "timeout_at": datetime.now(UTC) + timedelta(seconds=60),
            "source_ip": None,
        }
        base.update(over)
        return await commands.insert(**base)

    async def test_same_identity_collision_dedups(
        self, session: AsyncSession, project: Project, agent: Agent
    ) -> None:
        commands = CommandRepository(session)
        row1, created1 = await self._insert(commands, project, agent)
        await session.commit()
        # Same action/target/agent, different payload (HA re-fire) -> dedup.
        row2, created2 = await self._insert(commands, project, agent, payload={"x": 2})
        assert created1 is True and created2 is False
        assert row2.id == row1.id  # returned the existing row

    async def test_cross_command_collision_raises_conflict(
        self, session: AsyncSession, project: Project, agent: Agent
    ) -> None:
        from z4j_core.errors import ConflictError

        commands = CommandRepository(session)
        await self._insert(commands, project, agent, action="retry_task")
        await session.commit()
        # Same key, DIFFERENT action -> conflict, not a wrong-command return.
        with pytest.raises(ConflictError):
            await self._insert(commands, project, agent, action="cancel_task")

    async def test_cross_agent_collision_raises_conflict(
        self, session: AsyncSession, project: Project, agent: Agent
    ) -> None:
        from z4j_core.errors import ConflictError

        commands = CommandRepository(session)
        await self._insert(commands, project, agent)
        await session.commit()
        with pytest.raises(ConflictError):
            await self._insert(commands, project, agent, agent_id=uuid.uuid4())


@pytest.mark.asyncio
class TestInitialDispatchTimeout:
    """A late first delivery gets a full response/redispatch window."""

    async def test_initial_dispatch_refreshes_timeout_from_claim_generation(
        self, session: AsyncSession, project: Project, agent: Agent
    ) -> None:
        commands = CommandRepository(session)
        original_deadline = datetime.now(UTC) - timedelta(seconds=1)
        cmd, _ = await commands.insert(
            project_id=project.id,
            agent_id=agent.id,
            issued_by=None,
            action="schedule.fire",
            target_type="schedule",
            target_id="s1",
            payload={},
            idempotency_key=None,
            timeout_at=original_deadline,
            source_ip=None,
        )

        generation = await commands.mark_dispatched(
            cmd.id,
            timeout_seconds=60,
        )
        assert generation is not None
        await session.commit()
        await session.refresh(cmd)

        timeout_at = (
            cmd.timeout_at
            if cmd.timeout_at.tzinfo is not None
            else cmd.timeout_at.replace(tzinfo=UTC)
        )
        assert timeout_at == generation + timedelta(seconds=60)
        assert timeout_at > original_deadline
        session.expunge(cmd)

        # The old issuance-relative deadline has elapsed, but the command has
        # not yet exhausted the full response window granted at first dispatch.
        assert (
            await commands.sweep_timeouts(
                now=generation + timedelta(seconds=10),
            )
            == 0
        )
        await session.commit()
        after_old_deadline = await commands.get(cmd.id)
        assert after_old_deadline is not None
        assert after_old_deadline.status == CommandStatus.DISPATCHED
        session.expunge(after_old_deadline)

        assert (
            await commands.sweep_timeouts(
                now=timeout_at + timedelta(microseconds=1),
            )
            == 1
        )
        await session.commit()
        after_refreshed_deadline = await commands.get(cmd.id)
        assert after_refreshed_deadline is not None
        assert after_refreshed_deadline.status == CommandStatus.TIMEOUT


@pytest.mark.asyncio
class TestRevertDispatchRH2:
    """A failed WS push reverts the DISPATCHED claim so the row is
    re-deliverable and DISPATCHED keeps meaning 'physically delivered'."""

    async def test_revert_dispatched_to_pending(
        self, session: AsyncSession, project: Project, agent: Agent
    ) -> None:
        commands = CommandRepository(session)
        cmd, _ = await commands.insert(
            project_id=project.id,
            agent_id=agent.id,
            issued_by=None,
            action="retry_task",
            target_type="task",
            target_id="celery:t1",
            payload={},
            idempotency_key=None,
            timeout_at=datetime.now(UTC) + timedelta(seconds=60),
            source_ip=None,
        )
        # mark_dispatched returns the stamped GENERATION (a datetime) on a
        # successful claim, not True.
        assert await commands.mark_dispatched(cmd.id, timeout_seconds=60) is not None
        await session.commit()
        # Revert (the push failed) -> back to PENDING, re-deliverable.
        assert await commands.revert_dispatch(cmd.id) is True
        await session.commit()
        await session.refresh(cmd)
        assert cmd.status == CommandStatus.PENDING
        assert cmd.dispatched_at is None
        # Idempotent: reverting a non-DISPATCHED row is a no-op.
        assert await commands.revert_dispatch(cmd.id) is False


@pytest.mark.asyncio
class TestFireVsOperatorIdentityR7:
    """2: fire re-fires dedup even when re-routed to a different agent;
    operator commands 409 when a key is reused with different parameters."""

    async def test_fire_refire_different_agent_dedups(
        self, session: AsyncSession, project: Project, agent: Agent
    ) -> None:
        agent_b = Agent(
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
        session.add(agent_b)
        await session.commit()
        commands = CommandRepository(session)
        key = "schedule:s1:fire:f1"
        first, c1 = await commands.insert(
            project_id=project.id,
            agent_id=agent.id,
            issued_by=None,
            action="schedule.fire",
            target_type="schedule",
            target_id="s1",
            payload={"fired_at": "t0"},
            idempotency_key=key,
            timeout_at=datetime.now(UTC) + timedelta(seconds=60),
            source_ip=None,
        )
        await session.commit()
        # Re-fire the SAME fire_id but routed to agent B, different fired_at.
        second, c2 = await commands.insert(
            project_id=project.id,
            agent_id=agent_b.id,
            issued_by=None,
            action="schedule.fire",
            target_type="schedule",
            target_id="s1",
            payload={"fired_at": "t1"},
            idempotency_key=key,
            timeout_at=datetime.now(UTC) + timedelta(seconds=60),
            source_ip=None,
        )
        assert c1 is True and c2 is False
        assert second.id == first.id  # deduped, NOT a wedge

    async def test_operator_key_reuse_different_payload_conflicts(
        self, session: AsyncSession, project: Project, agent: Agent
    ) -> None:
        from z4j_core.errors import ConflictError

        commands = CommandRepository(session)
        base = {
            "project_id": project.id,
            "agent_id": agent.id,
            "issued_by": None,
            "action": "retry_task",
            "target_type": "task",
            "target_id": "celery:t1",
            "idempotency_key": "K",
            "timeout_at": datetime.now(UTC) + timedelta(seconds=60),
            "source_ip": None,
            "enforce_payload_identity": True,
        }
        await commands.insert(payload={"override_kwargs": {"x": 1}}, **base)
        await session.commit()
        with pytest.raises(ConflictError):
            await commands.insert(payload={"override_kwargs": {"x": 2}}, **base)
        await session.rollback()
        _row, created = await commands.insert(payload={"override_kwargs": {"x": 1}}, **base)
        assert created is False

    async def test_operator_ignores_fired_at_as_volatile(
        self, session: AsyncSession, project: Project, agent: Agent
    ) -> None:
        commands = CommandRepository(session)
        base = {
            "project_id": project.id,
            "agent_id": agent.id,
            "issued_by": None,
            "action": "retry_task",
            "target_type": "task",
            "target_id": "celery:t1",
            "idempotency_key": "K2",
            "timeout_at": datetime.now(UTC) + timedelta(seconds=60),
            "source_ip": None,
            "enforce_payload_identity": True,
        }
        await commands.insert(payload={"x": 1, "fired_at": "t0"}, **base)
        await session.commit()
        _row, created = await commands.insert(payload={"x": 1, "fired_at": "t9"}, **base)
        assert created is False  # only fired_at differs -> still dedups


@pytest.mark.asyncio
class TestReissueStatusFreshnessR7:
    """4: a re-issue of an existing command is a status+freshness
    decision -- terminal returns idempotently, stale/timeout re-drives."""

    async def _seed(self, commands, project, agent):
        cmd, _ = await commands.insert(
            project_id=project.id,
            agent_id=agent.id,
            issued_by=None,
            action="schedule.fire",
            target_type="schedule",
            target_id="s1",
            payload={},
            idempotency_key="schedule:s1:fire:f1",
            timeout_at=datetime.now(UTC) + timedelta(seconds=60),
            source_ip=None,
        )
        return cmd

    async def _reissue(self, dispatcher, session, project, agent):
        return await dispatcher.issue(
            commands=CommandRepository(session),
            audit_log=AuditLogRepository(session),
            project_id=project.id,
            agent_id=agent.id,
            action="schedule.fire",
            target_type="schedule",
            target_id="s1",
            payload={},
            issued_by=None,
            ip="127.0.0.1",
            user_agent=None,
            idempotency_key="schedule:s1:fire:f1",
        )

    async def test_failed_reissue_returns_without_redeliver(
        self, session, project, agent, settings
    ) -> None:
        commands = CommandRepository(session)
        cmd = await self._seed(commands, project, agent)
        await commands.mark_failed(cmd.id, error="agent ran it and it failed")
        await session.commit()
        registry = FakeRegistry(delivered_locally=True)
        dispatcher = CommandDispatcher(
            settings=settings, registry=registry, audit=AuditService(settings)
        )
        returned = await self._reissue(dispatcher, session, project, agent)
        assert returned.id == cmd.id
        assert returned.status == CommandStatus.FAILED
        assert registry.calls == []  # NOT re-delivered (no double-exec)

    async def test_fresh_dispatched_reissue_returns_without_redeliver(
        self, session, project, agent, settings
    ) -> None:
        commands = CommandRepository(session)
        cmd = await self._seed(commands, project, agent)
        await commands.mark_dispatched(
            cmd.id,
            timeout_seconds=60,
        )  # dispatched_at = now (fresh)
        await session.commit()
        registry = FakeRegistry(delivered_locally=True)
        dispatcher = CommandDispatcher(
            settings=settings, registry=registry, audit=AuditService(settings)
        )
        returned = await self._reissue(dispatcher, session, project, agent)
        assert returned.id == cmd.id
        assert registry.calls == []  # in-flight -> not re-sent

    async def test_stale_dispatched_reissue_redrives(
        self, session, project, agent, settings
    ) -> None:
        from sqlalchemy import update as _update
        from z4j_brain.persistence.models import Command

        commands = CommandRepository(session)
        cmd = await self._seed(commands, project, agent)
        await commands.mark_dispatched(cmd.id, timeout_seconds=60)
        await session.execute(
            _update(Command)
            .where(Command.id == cmd.id)
            .values(dispatched_at=datetime.now(UTC) - timedelta(seconds=3600))
        )
        await session.commit()
        registry = FakeRegistry(delivered_locally=True)
        dispatcher = CommandDispatcher(
            settings=settings, registry=registry, audit=AuditService(settings)
        )
        returned = await self._reissue(dispatcher, session, project, agent)
        assert returned.id == cmd.id
        assert registry.calls == [(cmd.id, agent.id)]  # re-driven


@pytest.mark.asyncio
class TestClaimRedispatchLeaseR8:
    """The DISPATCHED-recovery redispatch is a real LEASE, not a
    concurrent-snapshot tiebreak. At most one re-send per ``min_interval``, and a
    SEQUENTIAL second poll (re-reading the just-bumped dispatched_at) must NOT
    re-win -- the bug that re-sent on every poll."""

    async def _fire_cmd(self, commands: CommandRepository, project: Project, agent: Agent):
        cmd, _ = await commands.insert(
            project_id=project.id,
            agent_id=agent.id,
            issued_by=None,
            action="schedule.fire",
            target_type="schedule",
            target_id="s1",
            payload={},
            idempotency_key=None,
            timeout_at=datetime.now(UTC) + timedelta(seconds=600),
            source_ip=None,
        )
        return cmd

    async def test_lease_caps_resend_to_once_per_interval(
        self, session: AsyncSession, project: Project, agent: Agent
    ) -> None:
        from sqlalchemy import update as _update
        from z4j_brain.persistence.models import Command

        commands = CommandRepository(session)
        cmd = await self._fire_cmd(commands, project, agent)
        await commands.mark_dispatched(cmd.id, timeout_seconds=60)
        # Age the dispatch to 100s ago so it is eligible under a 10s lease.
        await session.execute(
            _update(Command)
            .where(Command.id == cmd.id)
            .values(dispatched_at=datetime.now(UTC) - timedelta(seconds=100))
        )
        await session.commit()
        # First poll: last send was 100s ago (> 10s lease) -> wins, bumps to now.
        assert await commands.claim_redispatch(cmd.id, min_interval_seconds=10.0) is True
        await session.commit()
        # Second SEQUENTIAL poll: dispatched_at is now fresh (< 10s lease) -> loses.
        assert await commands.claim_redispatch(cmd.id, min_interval_seconds=10.0) is False

    async def test_fresh_dispatch_not_resent(
        self, session: AsyncSession, project: Project, agent: Agent
    ) -> None:
        # A just-dispatched command well within the lease is NOT re-sent -- it may
        # still be in flight; a premature re-send would double-deliver.
        commands = CommandRepository(session)
        cmd = await self._fire_cmd(commands, project, agent)
        await commands.mark_dispatched(cmd.id, timeout_seconds=60)
        await session.commit()
        assert await commands.claim_redispatch(cmd.id, min_interval_seconds=60.0) is False


@pytest.mark.asyncio
class TestRevertDispatchR8:
    """(ABA CAS), (rearm clears terminal fields), (ownership
    transfer) on revert_dispatch."""

    async def _dispatched_cmd(self, commands, project, agent, *, action="schedule.fire"):
        cmd, _ = await commands.insert(
            project_id=project.id,
            agent_id=agent.id,
            issued_by=None,
            action=action,
            target_type="schedule",
            target_id="s1",
            payload={},
            idempotency_key=None,
            timeout_at=datetime.now(UTC) + timedelta(seconds=60),
            source_ip=None,
        )
        await commands.mark_dispatched(cmd.id, timeout_seconds=60)
        await commands.session.commit()
        await commands.session.refresh(cmd)
        return cmd

    async def test_cas_rejects_stale_generation(
        self, session: AsyncSession, project: Project, agent: Agent
    ) -> None:
        commands = CommandRepository(session)
        cmd = await self._dispatched_cmd(commands, project, agent)
        stale = cmd.dispatched_at
        # A concurrent rearm+redispatch advances dispatched_at to a NEW value.
        assert await commands.revert_dispatch(cmd.id, timeout_seconds=60) is True
        await commands.mark_dispatched(cmd.id, timeout_seconds=60)
        await session.commit()
        # The delayed reverter holding the STALE dispatched_at must lose the CAS.
        assert await commands.revert_dispatch(cmd.id, expected_dispatched_at=stale) is False
        await session.refresh(cmd)
        assert cmd.status == CommandStatus.DISPATCHED  # not reverted by the stale caller

    async def test_rearm_timeout_clears_terminal_fields(
        self, session: AsyncSession, project: Project, agent: Agent
    ) -> None:
        from sqlalchemy import update as _update
        from z4j_brain.persistence.models import Command

        commands = CommandRepository(session)
        cmd = await self._dispatched_cmd(commands, project, agent)
        # Simulate the CommandTimeoutWorker: TIMEOUT + completed_at + error set.
        await session.execute(
            _update(Command)
            .where(Command.id == cmd.id)
            .values(
                status=CommandStatus.TIMEOUT,
                completed_at=datetime.now(UTC),
                error="timed out",
            )
        )
        await session.commit()
        assert await commands.revert_dispatch(cmd.id, timeout_seconds=60) is True
        await session.commit()
        await session.refresh(cmd)
        assert cmd.status == CommandStatus.PENDING
        assert cmd.completed_at is None  # Not simultaneously completed
        assert cmd.error is None

    async def test_ownership_transfer_reassigns_agent(
        self, session: AsyncSession, project: Project, agent: Agent
    ) -> None:
        commands = CommandRepository(session)
        cmd = await self._dispatched_cmd(commands, project, agent)
        other = Agent(
            id=uuid.uuid4(),
            project_id=project.id,
            name="agent-b",
            token_hash=secrets.token_hex(32),
            protocol_version=1,
            framework_adapter="bare",
            state=AgentState.ONLINE,
            last_seen_at=datetime.now(UTC),
        )
        session.add(other)
        await session.commit()
        assert await commands.revert_dispatch(cmd.id, new_agent_id=other.id) is True
        await session.commit()
        await session.refresh(cmd)
        assert cmd.agent_id == other.id  # Re-driven to the new target

    async def test_mark_dispatched_returns_generation_r9_h5(
        self, session: AsyncSession, project: Project, agent: Agent
    ) -> None:
        # mark_dispatched returns the stamped generation (a datetime) on a
        # successful claim, and None when the row is not PENDING (already claimed).
        commands = CommandRepository(session)
        cmd, _ = await commands.insert(
            project_id=project.id,
            agent_id=agent.id,
            issued_by=None,
            action="schedule.fire",
            target_type="schedule",
            target_id="s1",
            payload={},
            idempotency_key=None,
            timeout_at=datetime.now(UTC) + timedelta(seconds=60),
            source_ip=None,
        )
        gen = await commands.mark_dispatched(cmd.id, timeout_seconds=60)
        assert gen is not None
        await session.commit()
        # A second claim finds no PENDING row -> None.
        assert await commands.mark_dispatched(cmd.id, timeout_seconds=60) is None

    async def test_reassign_pending_owner_r9_m1(
        self, session: AsyncSession, project: Project, agent: Agent
    ) -> None:
        # A PENDING fire is transferred to a re-picked target; guarded to
        # PENDING so a concurrent claim is never clobbered.
        commands = CommandRepository(session)
        cmd, _ = await commands.insert(
            project_id=project.id,
            agent_id=agent.id,
            issued_by=None,
            action="schedule.fire",
            target_type="schedule",
            target_id="s1",
            payload={},
            idempotency_key=None,
            timeout_at=datetime.now(UTC) + timedelta(seconds=60),
            source_ip=None,
        )
        other = Agent(
            id=uuid.uuid4(),
            project_id=project.id,
            name="agent-b",
            token_hash=secrets.token_hex(32),
            protocol_version=1,
            framework_adapter="bare",
            state=AgentState.ONLINE,
            last_seen_at=datetime.now(UTC),
        )
        session.add(other)
        await session.commit()
        assert await commands.reassign_pending_owner(cmd.id, new_agent_id=other.id) is True
        await session.commit()
        await session.refresh(cmd)
        assert cmd.agent_id == other.id
        # Once DISPATCHED (claimed), the PENDING-guarded reassign is a no-op.
        await commands.mark_dispatched(cmd.id, timeout_seconds=60)
        await session.commit()
        assert await commands.reassign_pending_owner(cmd.id, new_agent_id=agent.id) is False


class TestActionClassificationR8:
    """Redeliverability is an ALLOWLIST that fails CLOSED."""

    def test_destructive_actions_not_redeliverable(self) -> None:
        from z4j_brain.persistence.repositories.commands import action_is_redeliverable

        for a in (
            "retry_task",
            "bulk_retry",
            "purge_queue",
            "restart_worker",
            "requeue_dead_letter",
        ):
            assert action_is_redeliverable(a) is False, a

    def test_fires_and_idempotent_actions_redeliverable(self) -> None:
        from z4j_brain.persistence.repositories.commands import action_is_redeliverable

        for a in (
            "schedule.fire",
            "schedule.trigger_now",
            "schedule.trigger_now.via_scheduler",
            "cancel_task",
            "reconcile_task",
            "schedule.resync",
            # A5: enable/disable are idempotent desired-state ops, so a
            # dropped one must be re-driven (else a lost disable keeps the
            # schedule firing while the UI shows it disabled).
            "schedule.enable",
            "schedule.disable",
        ):
            assert action_is_redeliverable(a) is True, a

    def test_r9_h3_fails_closed_for_unknown_and_missed_verbs(self) -> None:
        # The denylist failed OPEN -- these non-idempotent verbs were
        # silently redeliverable. The allowlist now defaults them to at-most-once.
        from z4j_brain.persistence.repositories.commands import action_is_redeliverable

        for a in (
            "pool_grow",
            "pool_shrink",
            "add_consumer",
            "cancel_consumer",
            "schedule.create",
            "schedule.update",
            "schedule.delete",
            "some_new_future_action",
            "",
        ):
            assert action_is_redeliverable(a) is False, a
