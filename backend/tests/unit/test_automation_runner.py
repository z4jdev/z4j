"""Real automation ActionRunner: in-app notify + retry/cancel (R2 wiring)."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.domain.automation import AutomationActionRunner
from z4j_brain.errors import AgentOfflineError
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import (
    Membership,
    Project,
    Task,
    User,
    UserNotification,
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


class _FakeDispatcher:
    def __init__(self, *, offline: bool = False):
        self.calls: list[dict] = []
        self._offline = offline

    async def issue(self, **kw):
        self.calls.append(kw)
        if self._offline:
            raise AgentOfflineError("agent is not connected")


def _rule(project_id, **kw) -> SimpleNamespace:
    kw.setdefault("id", uuid.uuid4())
    kw.setdefault("name", "rule")
    kw.setdefault("trigger", "task.failed")
    kw.setdefault("created_by", None)
    kw["project_id"] = project_id
    return SimpleNamespace(**kw)


async def _project_with_member(
    session: AsyncSession,
    role: ProjectRole = ProjectRole.OPERATOR,
):
    project = Project(id=uuid.uuid4(), slug=f"p{uuid.uuid4().hex[:8]}", name="P")
    user = User(
        id=uuid.uuid4(),
        email=f"{uuid.uuid4().hex[:8]}@x.io",
        password_hash=uuid.uuid4().hex,
    )
    session.add_all([project, user])
    await session.flush()
    session.add(
        Membership(
            user_id=user.id,
            project_id=project.id,
            role=role,
        ),
    )
    await session.flush()
    return project, user


@pytest.mark.asyncio
class TestRunner:
    async def test_notify_creates_inapp_for_members(
        self,
        session: AsyncSession,
    ) -> None:
        project, user = await _project_with_member(session)
        runner = AutomationActionRunner(dispatcher=_FakeDispatcher())
        outcome = await runner.run(
            session=session,
            rule=_rule(project.id, name="alert"),
            action_spec={"type": "notify"},
            fields={"task_id": "t1", "task_name": "myapp.send", "engine": "celery"},
        )
        await session.commit()
        assert outcome == "notified"
        rows = (await session.execute(select(UserNotification))).scalars().all()
        assert len(rows) == 1
        assert rows[0].user_id == user.id
        assert rows[0].reason == "automation"
        assert rows[0].subscription_id is None

    async def test_notify_no_members(self, session: AsyncSession) -> None:
        project = Project(id=uuid.uuid4(), slug="pnm", name="P")
        session.add(project)
        await session.flush()
        runner = AutomationActionRunner(dispatcher=_FakeDispatcher())
        outcome = await runner.run(
            session=session,
            rule=_rule(project.id),
            action_spec={"type": "notify"},
            fields={},
        )
        assert outcome == "no_recipients"

    async def test_retry_issues_command_with_task_name(
        self,
        session: AsyncSession,
    ) -> None:
        project, user = await _project_with_member(session, role=ProjectRole.ADMIN)
        agent_id = uuid.uuid4()
        session.add(
            Task(
                id=uuid.uuid4(),
                project_id=project.id,
                engine="celery",
                task_id="t9",
                name="myapp.tasks.send_email",
            ),
        )
        await session.flush()
        disp = _FakeDispatcher()
        runner = AutomationActionRunner(dispatcher=disp)
        outcome = await runner.run(
            session=session,
            rule=_rule(project.id, name="autoretry", created_by=user.id),
            action_spec={"type": "retry"},
            fields={"task_id": "t9", "engine": "celery", "agent_id": agent_id},
        )
        assert outcome == "issued"
        assert len(disp.calls) == 1
        call = disp.calls[0]
        assert call["action"] == "retry_task"
        assert call["target_id"] == "celery:t9"
        assert call["payload"]["task_name"] == "myapp.tasks.send_email"
        # RQ pickle-safety: no real args in the payload.
        assert "args" not in call["payload"]
        assert call["agent_id"] == agent_id

    async def test_retry_denied_when_creator_deprovisioned(
        self,
        session: AsyncSession,
    ) -> None:
        # Creator is a UUID that is NOT a member of the project -> the
        # fire-time authz re-check denies the destructive command.
        project, _ = await _project_with_member(session)
        ghost_creator = uuid.uuid4()
        session.add(
            Task(
                project_id=project.id,
                engine="celery",
                task_id="t9",
                name="myapp.tasks.send",
            ),
        )
        await session.flush()
        disp = _FakeDispatcher()
        runner = AutomationActionRunner(dispatcher=disp)
        outcome = await runner.run(
            session=session,
            rule=_rule(project.id, name="autoretry", created_by=ghost_creator),
            action_spec={"type": "retry"},
            fields={"task_id": "t9", "engine": "celery", "agent_id": uuid.uuid4()},
        )
        assert outcome == "denied_stale_authz"
        assert disp.calls == []  # no command issued

    async def test_retry_allowed_when_creator_still_admin(
        self,
        session: AsyncSession,
    ) -> None:
        # A destructive (retry) rule requires ADMIN both to arm AND at fire
        # time, so the still-ADMIN creator fires.
        project, user = await _project_with_member(session, role=ProjectRole.ADMIN)
        session.add(
            Task(
                project_id=project.id,
                engine="celery",
                task_id="t9",
                name="myapp.tasks.send",
            ),
        )
        await session.flush()
        disp = _FakeDispatcher()
        runner = AutomationActionRunner(dispatcher=disp)
        outcome = await runner.run(
            session=session,
            rule=_rule(project.id, name="autoretry", created_by=user.id),
            action_spec={"type": "retry"},
            fields={"task_id": "t9", "engine": "celery", "agent_id": uuid.uuid4()},
        )
        assert outcome == "issued"
        assert len(disp.calls) == 1

    async def test_retry_denied_when_creator_demoted_below_admin(
        self,
        session: AsyncSession,
    ) -> None:
        # Creating a destructive rule requires ADMIN; the fire-time re-check
        # must demand the SAME floor. A creator demoted ADMIN -> OPERATOR can
        # no longer edit or re-arm the rule, so their destructive rule must
        # stop firing even though an OPERATOR can issue a retry manually.
        project, user = await _project_with_member(session, role=ProjectRole.OPERATOR)
        session.add(
            Task(
                project_id=project.id,
                engine="celery",
                task_id="t9",
                name="myapp.tasks.send",
            ),
        )
        await session.flush()
        disp = _FakeDispatcher()
        runner = AutomationActionRunner(dispatcher=disp)
        outcome = await runner.run(
            session=session,
            rule=_rule(project.id, name="autoretry", created_by=user.id),
            action_spec={"type": "retry"},
            fields={"task_id": "t9", "engine": "celery", "agent_id": uuid.uuid4()},
        )
        assert outcome == "denied_stale_authz"
        assert disp.calls == []

    async def test_retry_denied_when_creator_deleted_null(
        self,
        session: AsyncSession,
    ) -> None:
        # A hard-deleted creator nulls created_by (FK ON DELETE SET NULL).
        # There is no system/declarative rule path, so NULL means orphaned,
        # not "system authority" -- a destructive rule must FAIL CLOSED and
        # never fire with standing authority.
        project, _ = await _project_with_member(session, role=ProjectRole.ADMIN)
        session.add(
            Task(
                project_id=project.id,
                engine="celery",
                task_id="t9",
                name="myapp.tasks.send",
            ),
        )
        await session.flush()
        disp = _FakeDispatcher()
        runner = AutomationActionRunner(dispatcher=disp)
        outcome = await runner.run(
            session=session,
            rule=_rule(project.id, name="orphaned", created_by=None),
            action_spec={"type": "retry"},
            fields={"task_id": "t9", "engine": "celery", "agent_id": uuid.uuid4()},
        )
        assert outcome == "denied_stale_authz"
        assert disp.calls == []

    async def test_cancel_issues_command(self, session: AsyncSession) -> None:
        project, user = await _project_with_member(session, role=ProjectRole.ADMIN)
        disp = _FakeDispatcher()
        runner = AutomationActionRunner(dispatcher=disp)
        outcome = await runner.run(
            session=session,
            rule=_rule(project.id, created_by=user.id),
            action_spec={"type": "cancel"},
            fields={"task_id": "t1", "engine": "rq", "agent_id": uuid.uuid4()},
        )
        assert outcome == "issued"
        assert disp.calls[0]["action"] == "cancel_task"

    async def test_no_target_when_agent_missing(
        self,
        session: AsyncSession,
    ) -> None:
        runner = AutomationActionRunner(dispatcher=_FakeDispatcher())
        outcome = await runner.run(
            session=session,
            rule=_rule(uuid.uuid4()),
            action_spec={"type": "retry"},
            fields={"task_id": "t1", "engine": "celery"},  # no agent_id
        )
        assert outcome == "no_target"

    async def test_agent_offline(self, session: AsyncSession) -> None:
        project, user = await _project_with_member(session, role=ProjectRole.ADMIN)
        runner = AutomationActionRunner(dispatcher=_FakeDispatcher(offline=True))
        outcome = await runner.run(
            session=session,
            rule=_rule(project.id, created_by=user.id),
            action_spec={"type": "cancel"},
            fields={"task_id": "t1", "engine": "celery", "agent_id": uuid.uuid4()},
        )
        assert outcome == "agent_offline"

    async def test_unsupported_action(self, session: AsyncSession) -> None:
        runner = AutomationActionRunner(dispatcher=_FakeDispatcher())
        outcome = await runner.run(
            session=session,
            rule=_rule(uuid.uuid4()),
            action_spec={"type": "webhook"},
            fields={},
        )
        assert outcome == "unsupported"
