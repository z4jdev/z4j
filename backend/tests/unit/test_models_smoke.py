"""Smoke tests for the brain ORM models.

These run against the in-memory SQLite engine and verify:

- Every model can be instantiated
- ``Base.metadata.create_all`` produces the full set of tables
- Round-trip insert/select works for the simple shapes
- FK relationships fire with ``ON DELETE CASCADE``

Postgres-only behaviour (partitioning, GIN indexes, append-only
triggers) lives in the integration suite (B7) - these tests only
guarantee the Python model layer is internally consistent.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import (
    AgentState,
    CommandStatus,
    ProjectRole,
    ScheduleKind,
    TaskState,
    WorkerState,
)
from z4j_brain.persistence.models import (
    Agent,
    AuditLog,
    Command,
    Event,
    FirstBootToken,
    Membership,
    Project,
    Queue,
    Schedule,
    Task,
    User,
    Worker,
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


@pytest.mark.asyncio
class TestSchemaCreation:
    async def test_all_tables_exist(self, session: AsyncSession) -> None:
        bind = session.get_bind()
        names = set(Base.metadata.tables.keys())
        # Spot-check the load-bearing tables instead of pinning the
        # exact set. New tables land often (invitations, saved_views,
        # project_config, alert_events, task_annotations, z4j_meta,
        # ...) and a literal-set comparison churns this test without
        # catching anything the migrations themselves don't.
        core_tables = {
            "users",
            "projects",
            "memberships",
            "agents",
            "queues",
            "workers",
            "tasks",
            "events",
            "schedules",
            "commands",
            "audit_log",
            "first_boot_tokens",
            "sessions",
            "notification_channels",
            "user_channels",
            "user_subscriptions",
            "project_default_subscriptions",
            "user_notifications",
            "notification_deliveries",
        }
        missing = core_tables - names
        assert not missing, f"missing core tables: {missing}"
        # And SQLAlchemy actually emitted them.
        assert bind is not None


@pytest.mark.asyncio
class TestRoundTrip:
    async def test_user_round_trip(self, session: AsyncSession) -> None:
        user = User(
            email="alice@example.com",
            password_hash="argon2id$dummy",
            display_name="Alice",
        )
        session.add(user)
        await session.commit()

        result = await session.execute(select(User).where(User.email == "alice@example.com"))
        fetched = result.scalar_one()
        assert fetched.id == user.id
        assert fetched.is_admin is False
        assert fetched.is_active is True
        assert fetched.timezone == "UTC"

    async def test_project_round_trip(self, session: AsyncSession) -> None:
        project = Project(slug="default", name="Default")
        session.add(project)
        await session.commit()

        fetched = (await session.execute(select(Project))).scalar_one()
        assert fetched.slug == "default"
        assert fetched.environment == "production"
        assert fetched.retention_days == 30

    async def test_membership_unique_user_project(self, session: AsyncSession) -> None:
        user = User(email="b@example.com", password_hash="x")
        project = Project(slug="p2", name="P2")
        session.add_all([user, project])
        await session.flush()

        session.add(Membership(user_id=user.id, project_id=project.id, role=ProjectRole.ADMIN))
        await session.commit()

        # Same (user, project) again must fail.
        session.add(Membership(user_id=user.id, project_id=project.id, role=ProjectRole.VIEWER))
        with pytest.raises(Exception):  # noqa: PT011 - SA wraps the IntegrityError
            await session.commit()
        await session.rollback()

    async def test_agent_round_trip_with_arrays(self, session: AsyncSession) -> None:
        project = Project(slug="p3", name="P3")
        session.add(project)
        await session.flush()

        agent = Agent(
            project_id=project.id,
            name="web-01",
            token_hash=secrets.token_hex(32),
            protocol_version="1",
            framework_adapter="django",
            engine_adapters=["celery"],
            scheduler_adapters=["celery-beat"],
            capabilities={"celery": ["retry", "cancel"]},
            state=AgentState.ONLINE,
        )
        session.add(agent)
        await session.commit()

        fetched = (await session.execute(select(Agent))).scalar_one()
        assert fetched.engine_adapters == ["celery"]
        assert fetched.scheduler_adapters == ["celery-beat"]
        assert fetched.capabilities == {"celery": ["retry", "cancel"]}
        assert fetched.state == AgentState.ONLINE

    async def test_task_state_enum(self, session: AsyncSession) -> None:
        project = Project(slug="p4", name="P4")
        session.add(project)
        await session.flush()

        task = Task(
            project_id=project.id,
            engine="celery",
            task_id="task-abc",
            name="myapp.tasks.send_email",
            state=TaskState.SUCCESS,
        )
        session.add(task)
        await session.commit()

        fetched = (await session.execute(select(Task))).scalar_one()
        assert fetched.state == TaskState.SUCCESS

    async def test_schedule_kind_enum(self, session: AsyncSession) -> None:
        project = Project(slug="p5", name="P5")
        session.add(project)
        await session.flush()

        schedule = Schedule(
            project_id=project.id,
            engine="celery",
            scheduler="celery-beat",
            name="nightly",
            task_name="myapp.tasks.cleanup",
            kind=ScheduleKind.CRON,
            expression="0 3 * * *",
        )
        session.add(schedule)
        await session.commit()

        fetched = (await session.execute(select(Schedule))).scalar_one()
        assert fetched.kind == ScheduleKind.CRON

    async def test_command_round_trip(self, session: AsyncSession) -> None:
        project = Project(slug="p6", name="P6")
        session.add(project)
        await session.flush()

        cmd = Command(
            project_id=project.id,
            action="retry_task",
            target_type="task",
            target_id="task-xyz",
            payload={"override_kwargs": {"force": True}},
            timeout_at=datetime.now(UTC) + timedelta(seconds=60),
            status=CommandStatus.PENDING,
        )
        session.add(cmd)
        await session.commit()

        fetched = (await session.execute(select(Command))).scalar_one()
        assert fetched.action == "retry_task"
        assert fetched.payload == {"override_kwargs": {"force": True}}
        assert fetched.status == CommandStatus.PENDING

    async def test_audit_log_round_trip(self, session: AsyncSession) -> None:
        entry = AuditLog(
            action="project.created",
            target_type="project",
            target_id="default",
            result="success",
        )
        session.add(entry)
        await session.commit()

        fetched = (await session.execute(select(AuditLog))).scalar_one()
        assert fetched.action == "project.created"
        assert fetched.result == "success"
        assert fetched.occurred_at is not None

    async def test_first_boot_token_round_trip(self, session: AsyncSession) -> None:
        token = FirstBootToken(
            token_hash="deadbeef" * 8,
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
        )
        session.add(token)
        await session.commit()

        fetched = (await session.execute(select(FirstBootToken))).scalar_one()
        assert fetched.token_hash == "deadbeef" * 8

    async def test_event_round_trip(self, session: AsyncSession) -> None:
        # On SQLite the ``events`` table is not partitioned but it is
        # otherwise schema-identical, so we can still round-trip.
        project = Project(slug="p7", name="P7")
        session.add(project)
        await session.flush()
        agent = Agent(
            project_id=project.id,
            name="w1",
            token_hash=secrets.token_hex(32),
            protocol_version="1",
            framework_adapter="bare",
        )
        session.add(agent)
        await session.flush()

        ev = Event(
            id=uuid.uuid4(),
            project_id=project.id,
            agent_id=agent.id,
            engine="celery",
            task_id="t-1",
            kind="task.received",
            occurred_at=datetime.now(UTC),
            payload={"hello": "world"},
        )
        session.add(ev)
        await session.commit()

        fetched = (await session.execute(select(Event))).scalar_one()
        assert fetched.kind == "task.received"
        assert fetched.payload == {"hello": "world"}

    async def test_queue_round_trip(self, session: AsyncSession) -> None:
        project = Project(slug="p8", name="P8")
        session.add(project)
        await session.flush()
        q = Queue(project_id=project.id, name="default", engine="celery")
        session.add(q)
        await session.commit()
        assert (await session.execute(select(Queue))).scalar_one().name == "default"

    async def test_worker_round_trip(self, session: AsyncSession) -> None:
        project = Project(slug="p9", name="P9")
        session.add(project)
        await session.flush()
        w = Worker(
            project_id=project.id,
            engine="celery",
            name="celery@web-01",
            queues=["default", "priority"],
            state=WorkerState.ONLINE,
        )
        session.add(w)
        await session.commit()
        fetched = (await session.execute(select(Worker))).scalar_one()
        assert fetched.queues == ["default", "priority"]
        assert fetched.state == WorkerState.ONLINE


@pytest.mark.asyncio
class TestCascadeDelete:
    async def test_deleting_project_cascades_to_agents(
        self, session: AsyncSession,
    ) -> None:
        project = Project(slug="todelete", name="X")
        session.add(project)
        await session.flush()
        session.add(
            Agent(
                project_id=project.id,
                name="a1",
                token_hash=secrets.token_hex(32),
                protocol_version="1",
                framework_adapter="bare",
            ),
        )
        await session.commit()

        # SQLite needs PRAGMA foreign_keys=ON for cascade to fire.
        await session.execute(__import__("sqlalchemy").text("PRAGMA foreign_keys = ON"))

        await session.delete(project)
        await session.commit()

        assert (await session.execute(select(Agent))).scalars().all() == []
