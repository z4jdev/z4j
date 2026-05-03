"""Regression: ``ScheduleRepository.reconcile_snapshot`` 3-way diffs
the brain's view against an agent-supplied full inventory and
returns ``{inserted, updated, deleted}`` counts.

Added in 1.3.3 alongside the new ``EventKind.SCHEDULE_SNAPSHOT`` and
the dashboard *Sync now* button. Closes the long-standing onboarding
gap where existing celery-beat / rq-scheduler / apscheduler schedules
were invisible until the operator edited each one. The agent emits
one snapshot per scheduler adapter at boot, on a periodic timer
(default 15 min), and on demand from the brain's ``schedule.resync``
command, the brain reconciles each into the DB scoped to
``(project, scheduler)``.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import ScheduleKind
from z4j_brain.persistence.models import Project, Schedule
from z4j_brain.persistence.repositories import ScheduleRepository


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False,
    )
    async with factory() as s:
        yield s
    await engine.dispose()


@pytest.fixture
async def project(session: AsyncSession) -> Project:
    p = Project(slug="picker", name="Picker")
    session.add(p)
    await session.commit()
    return p


def _schedule_dict(
    name: str,
    *,
    task_name: str = "myapp.tasks.run",
    expression: str = "*/5 * * * *",
    kind: str = "cron",
    is_enabled: bool = True,
) -> dict[str, object]:
    """Shape that an agent's ``CeleryBeatSchedulerAdapter.list_schedules``
    yields, what arrives in the snapshot event's ``data.schedules``."""
    return {
        "name": name,
        "task_name": task_name,
        "kind": kind,
        "expression": expression,
        "engine": "celery",
        "scheduler": "celery-beat",
        "is_enabled": is_enabled,
        "args": [],
        "kwargs": {},
    }


@pytest.mark.asyncio
class TestReconcileSnapshotInsert:
    async def test_first_snapshot_inserts_every_row(
        self, session: AsyncSession, project: Project,
    ) -> None:
        """The picker case: agent boots for the first time, calls
        ``list_schedules()`` on celery-beat, sends snapshot with 3
        existing PeriodicTask rows. Brain inserts all 3."""
        repo = ScheduleRepository(session)
        snapshot = [
            _schedule_dict("nightly-report"),
            _schedule_dict("hourly-cleanup"),
            _schedule_dict("daily-billing"),
        ]
        summary = await repo.reconcile_snapshot(
            project_id=project.id,
            scheduler="celery-beat",
            schedules=snapshot,
        )
        await session.commit()

        assert summary == {"inserted": 3, "updated": 0, "deleted": 0}

        result = await session.execute(
            select(func.count()).select_from(Schedule).where(
                Schedule.project_id == project.id,
            ),
        )
        assert result.scalar_one() == 3
        names = {
            row[0] for row in (await session.execute(
                select(Schedule.name).where(
                    Schedule.project_id == project.id,
                ),
            )).all()
        }
        assert names == {"nightly-report", "hourly-cleanup", "daily-billing"}

    async def test_empty_snapshot_inserts_nothing(
        self, session: AsyncSession, project: Project,
    ) -> None:
        repo = ScheduleRepository(session)
        summary = await repo.reconcile_snapshot(
            project_id=project.id,
            scheduler="celery-beat",
            schedules=[],
        )
        assert summary == {"inserted": 0, "updated": 0, "deleted": 0}


@pytest.mark.asyncio
class TestReconcileSnapshotUpdate:
    async def test_second_snapshot_updates_existing_rows(
        self, session: AsyncSession, project: Project,
    ) -> None:
        repo = ScheduleRepository(session)
        # First snapshot: 2 rows
        await repo.reconcile_snapshot(
            project_id=project.id,
            scheduler="celery-beat",
            schedules=[
                _schedule_dict("a", expression="0 1 * * *"),
                _schedule_dict("b", expression="0 2 * * *"),
            ],
        )
        await session.commit()

        # Second snapshot: same names, different expressions (operator
        # edited the cron schedule via Django admin; agent picks up the
        # change on the next periodic resync).
        summary = await repo.reconcile_snapshot(
            project_id=project.id,
            scheduler="celery-beat",
            schedules=[
                _schedule_dict("a", expression="0 3 * * *"),
                _schedule_dict("b", expression="0 4 * * *"),
            ],
        )
        await session.commit()

        assert summary == {"inserted": 0, "updated": 2, "deleted": 0}
        result = await session.execute(
            select(Schedule.name, Schedule.expression)
            .where(Schedule.project_id == project.id)
            .order_by(Schedule.name),
        )
        rows = list(result.all())
        assert rows == [("a", "0 3 * * *"), ("b", "0 4 * * *")]


@pytest.mark.asyncio
class TestReconcileSnapshotDelete:
    async def test_missing_rows_get_deleted(
        self, session: AsyncSession, project: Project,
    ) -> None:
        """A schedule deleted via Django admin while the agent was
        offline: it's in the brain's DB but not in the snapshot. The
        reconcile must DELETE it."""
        repo = ScheduleRepository(session)
        await repo.reconcile_snapshot(
            project_id=project.id,
            scheduler="celery-beat",
            schedules=[
                _schedule_dict("a"),
                _schedule_dict("b"),
                _schedule_dict("c"),
            ],
        )
        await session.commit()

        # Operator deleted "b" via Django admin offline. Next snapshot
        # only has a + c.
        summary = await repo.reconcile_snapshot(
            project_id=project.id,
            scheduler="celery-beat",
            schedules=[
                _schedule_dict("a"),
                _schedule_dict("c"),
            ],
        )
        await session.commit()

        assert summary["deleted"] == 1
        result = await session.execute(
            select(Schedule.name)
            .where(Schedule.project_id == project.id)
            .order_by(Schedule.name),
        )
        assert [r[0] for r in result.all()] == ["a", "c"]

    async def test_empty_snapshot_deletes_all_for_that_scheduler(
        self, session: AsyncSession, project: Project,
    ) -> None:
        """Operator nuked celery-beat config and reloaded; agent
        snapshots with zero schedules. Reconcile must remove all
        previously-known rows for THIS scheduler."""
        repo = ScheduleRepository(session)
        await repo.reconcile_snapshot(
            project_id=project.id,
            scheduler="celery-beat",
            schedules=[_schedule_dict("a"), _schedule_dict("b")],
        )
        await session.commit()

        summary = await repo.reconcile_snapshot(
            project_id=project.id,
            scheduler="celery-beat",
            schedules=[],
        )
        await session.commit()

        assert summary == {"inserted": 0, "updated": 0, "deleted": 2}
        result = await session.execute(
            select(func.count()).select_from(Schedule).where(
                Schedule.project_id == project.id,
            ),
        )
        assert result.scalar_one() == 0


@pytest.mark.asyncio
class TestReconcileSnapshotScoping:
    async def test_does_not_cross_prune_other_schedulers(
        self, session: AsyncSession, project: Project,
    ) -> None:
        """A project running BOTH celery-beat AND apscheduler must
        get per-scheduler reconciliation. A snapshot from celery-beat
        must never delete an apscheduler row."""
        repo = ScheduleRepository(session)
        # Land 2 celery-beat schedules + 2 apscheduler schedules.
        # Build apscheduler dicts manually since _schedule_dict
        # hardcodes celery-beat.
        await repo.reconcile_snapshot(
            project_id=project.id,
            scheduler="celery-beat",
            schedules=[_schedule_dict("cb-1"), _schedule_dict("cb-2")],
        )
        await repo.reconcile_snapshot(
            project_id=project.id,
            scheduler="apscheduler",
            schedules=[
                {**_schedule_dict("ap-1"), "scheduler": "apscheduler"},
                {**_schedule_dict("ap-2"), "scheduler": "apscheduler"},
            ],
        )
        await session.commit()

        result = await session.execute(
            select(func.count()).select_from(Schedule).where(
                Schedule.project_id == project.id,
            ),
        )
        assert result.scalar_one() == 4

        # celery-beat sends a NEW snapshot dropping cb-2. apscheduler
        # rows must be untouched.
        summary = await repo.reconcile_snapshot(
            project_id=project.id,
            scheduler="celery-beat",
            schedules=[_schedule_dict("cb-1")],
        )
        await session.commit()

        assert summary == {"inserted": 0, "updated": 1, "deleted": 1}

        # ap-1 + ap-2 + cb-1 = 3 rows still present
        result = await session.execute(
            select(Schedule.name, Schedule.scheduler)
            .where(Schedule.project_id == project.id)
            .order_by(Schedule.name),
        )
        rows = list(result.all())
        assert rows == [
            ("ap-1", "apscheduler"),
            ("ap-2", "apscheduler"),
            ("cb-1", "celery-beat"),
        ]

    async def test_does_not_cross_prune_other_projects(
        self, session: AsyncSession,
    ) -> None:
        """Two projects each running celery-beat: a snapshot for one
        project must never affect the other's rows."""
        repo = ScheduleRepository(session)
        alpha = Project(slug="alpha", name="Alpha")
        beta = Project(slug="beta", name="Beta")
        session.add_all([alpha, beta])
        await session.commit()

        # Each project gets two celery-beat schedules with the
        # SAME names. ``(project_id, name)`` is the row key so this
        # is allowed.
        for proj in (alpha, beta):
            await repo.reconcile_snapshot(
                project_id=proj.id,
                scheduler="celery-beat",
                schedules=[_schedule_dict("a"), _schedule_dict("b")],
            )
        await session.commit()

        # alpha sends a smaller snapshot.
        summary = await repo.reconcile_snapshot(
            project_id=alpha.id,
            scheduler="celery-beat",
            schedules=[_schedule_dict("a")],
        )
        await session.commit()

        assert summary == {"inserted": 0, "updated": 1, "deleted": 1}

        # beta untouched.
        result = await session.execute(
            select(func.count()).select_from(Schedule).where(
                Schedule.project_id == beta.id,
            ),
        )
        assert result.scalar_one() == 2
