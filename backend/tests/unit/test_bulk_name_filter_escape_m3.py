"""Literal task-list and bulk-selection substring filters.

User-supplied LIKE metacharacters must match literally so a task list or durable
bulk retry cannot widen beyond the operator's intended selection.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import TaskState
from z4j_brain.persistence.models import Project, Task
from z4j_brain.persistence.repositories.tasks import TaskRepository


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
async def test_name_substring_escapes_like_wildcards(session: AsyncSession) -> None:
    project = Project(slug="p", name="P")
    session.add(project)
    await session.flush()

    base = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
    for i, name in enumerate(
        ("billing%refund", "billingXrefund", "billing_refund", "billingYrefund")
    ):
        session.add(
            Task(
                project_id=project.id,
                engine="celery",
                task_id=f"t-{i}",
                name=name,
                state="failure",
                priority="normal",
                received_at=base,
            )
        )
    await session.flush()
    repo = TaskRepository(session)

    # A literal '%' must match ONLY the task literally named 'billing%refund',
    # NOT 'billingXrefund'/'billingYrefund' (which an unescaped % wildcard would
    # over-match).
    rows = await repo.list_for_project(
        project_id=project.id,
        state=TaskState.FAILURE,
        queue=None,
        name_substring="billing%refund",
        limit=100,
    )
    assert sorted(t.name for t in rows) == ["billing%refund"]

    # A literal '_' must match ONLY 'billing_refund', not any single-char variant.
    rows2 = await repo.list_for_project(
        project_id=project.id,
        state=TaskState.FAILURE,
        queue=None,
        name_substring="billing_refund",
        limit=100,
    )
    assert sorted(t.name for t in rows2) == ["billing_refund"]


@pytest.mark.asyncio
async def test_search_query_treats_metacharacters_as_literal_substrings(
    session: AsyncSession,
) -> None:
    project = Project(slug="search-literals", name="Search literals")
    session.add(project)
    await session.flush()

    base = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
    values = (
        ("percent-match", "Percent%Literal", "queue-a", "worker-a"),
        ("percent-decoy", "PercentXLiteral", "queue-b", "worker-b"),
        ("underscore-match", "name-c", "Queue_Literal", "worker-c"),
        ("underscore-decoy", "name-d", "QueueXLiteral", "worker-d"),
        ("backslash-match", "name-e", "queue-e", r"Worker\Literal"),
        ("backslash-decoy", "name-f", "queue-f", "WorkerXLiteral"),
        ("task/slash-match", "name-g", "queue-g", "worker-g"),
        ("taskXslash-decoy", "name-h", "queue-h", "worker-h"),
    )
    for task_id, name, queue, worker_name in values:
        session.add(
            Task(
                project_id=project.id,
                engine="celery",
                task_id=task_id,
                name=name,
                queue=queue,
                worker_name=worker_name,
                state="failure",
                priority="normal",
                received_at=base,
            )
        )
    await session.flush()
    repo = TaskRepository(session)

    cases = (
        ("%", "percent-match"),
        ("_", "underscore-match"),
        ("\\", "backslash-match"),
        ("/", "task/slash-match"),
    )
    for needle, expected_task_id in cases:
        rows = await repo.list_for_project(
            project_id=project.id,
            state=TaskState.FAILURE,
            search_query=needle,
            limit=100,
        )
        assert [task.task_id for task in rows] == [expected_task_id]


@pytest.mark.asyncio
async def test_search_query_remains_case_insensitive_across_all_fields(
    session: AsyncSession,
) -> None:
    project = Project(slug="search-fields", name="Search fields")
    session.add(project)
    await session.flush()

    base = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
    values = (
        ("name-row", "NameNeedle", "queue-a", "worker-a"),
        ("queue-row", "name-b", "QueueNeedle", "worker-b"),
        ("worker-row", "name-c", "queue-c", "WorkerNeedle"),
        ("TaskIdNeedle", "name-d", "queue-d", "worker-d"),
    )
    for task_id, name, queue, worker_name in values:
        session.add(
            Task(
                project_id=project.id,
                engine="celery",
                task_id=task_id,
                name=name,
                queue=queue,
                worker_name=worker_name,
                state="failure",
                priority="normal",
                received_at=base,
            )
        )
    await session.flush()
    repo = TaskRepository(session)

    for needle, expected_task_id in (
        ("nameneedle", "name-row"),
        ("queueneedle", "queue-row"),
        ("workerneedle", "worker-row"),
        ("taskidneedle", "TaskIdNeedle"),
    ):
        rows = await repo.list_for_project(
            project_id=project.id,
            state=TaskState.FAILURE,
            search_query=needle,
            limit=100,
        )
        assert [task.task_id for task in rows] == [expected_task_id]


class _EmptyResult:
    def scalars(self) -> _EmptyResult:
        return self

    def all(self) -> list[Any]:
        return []


class _RecordingSession:
    statement: Any = None

    async def execute(self, statement: Any) -> _EmptyResult:
        self.statement = statement
        return _EmptyResult()


@pytest.mark.asyncio
async def test_search_query_emits_explicit_escape_for_sqlite_and_postgresql() -> None:
    session = _RecordingSession()
    needle = r"Needle%_\tail/part"
    await TaskRepository(session).list_for_project(  # type: ignore[arg-type]
        project_id=uuid4(),
        search_query=needle,
        limit=1,
    )
    assert session.statement is not None

    escaped = r"Needle/%/_\tail//part"
    for dialect in (sqlite.dialect(), postgresql.dialect()):
        compiled = session.statement.compile(dialect=dialect)
        assert str(compiled).count(" ESCAPE '/'") == 4
        assert list(compiled.params.values()).count(escaped) == 4
