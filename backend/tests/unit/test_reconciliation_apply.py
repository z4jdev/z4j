"""End-to-end test for the reconciliation apply path:

CommandResult arrives → CommandDispatcher.handle_result detects
``action == "reconcile_task"`` → TaskRepository.apply_reconciled_state
flips the Task row's state.

This test is the missing link from the worker tests - it proves
the *brain side* of the loop closes correctly when an agent comes
back with an authoritative engine_state.

Additions: the transition matrix. Reconciliation may only
move a task OUT of a non-terminal state; terminal states are
terminal, and stale non-terminal responses (issued before the row's
last observed write) are dropped."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import TaskState
from z4j_brain.persistence.models import Project, Task
from z4j_brain.persistence.repositories import TaskRepository


@pytest.fixture
async def engine():
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest.fixture
async def project_and_task(engine) -> tuple[UUID, str]:
    """Insert a project + a task stuck in 'started'."""
    long_ago = datetime.now(UTC) - timedelta(hours=1)
    async with AsyncSession(engine) as s:
        p = Project(slug="proj", name="Proj")
        s.add(p)
        await s.commit()
        await s.refresh(p)
        project_id = p.id

        s.add(
            Task(
                project_id=project_id,
                engine="celery",
                task_id="stuck-1",
                name="myapp.tasks.flaky",
                state=TaskState.STARTED,
                started_at=long_ago,
            ),
        )
        await s.commit()
    return project_id, "stuck-1"


@pytest.mark.asyncio
async def test_apply_reconciled_state_promotes_started_to_success(
    engine,
    project_and_task,
):
    project_id, task_id = project_and_task

    async with AsyncSession(engine) as s:
        repo = TaskRepository(s)
        finished = datetime.now(UTC)
        changed = await repo.apply_reconciled_state(
            project_id=project_id,
            engine="celery",
            task_id=task_id,
            engine_state="success",
            finished_at=finished,
        )
        await s.commit()
        assert changed is True

    # Re-read in a fresh session to confirm the UPDATE persisted.
    async with AsyncSession(engine) as s:
        row = await TaskRepository(s).get_by_engine_task_id(
            project_id=project_id,
            engine="celery",
            task_id=task_id,
        )
        assert row is not None
        assert row.state == TaskState.SUCCESS
        assert row.finished_at is not None


@pytest.mark.asyncio
async def test_apply_reconciled_state_idempotent(engine, project_and_task):
    """Same call twice → second is a no-op (changed=False)."""
    project_id, task_id = project_and_task
    async with AsyncSession(engine) as s:
        repo = TaskRepository(s)
        first = await repo.apply_reconciled_state(
            project_id=project_id,
            engine="celery",
            task_id=task_id,
            engine_state="failure",
        )
        await s.commit()
        second = await repo.apply_reconciled_state(
            project_id=project_id,
            engine="celery",
            task_id=task_id,
            engine_state="failure",
        )
        assert first is True
        assert second is False  # already matches


@pytest.mark.asyncio
async def test_apply_reconciled_state_unknown_is_noop(engine, project_and_task):
    project_id, task_id = project_and_task
    async with AsyncSession(engine) as s:
        repo = TaskRepository(s)
        changed = await repo.apply_reconciled_state(
            project_id=project_id,
            engine="celery",
            task_id=task_id,
            engine_state="unknown",
        )
        assert changed is False


@pytest.mark.asyncio
async def test_apply_reconciled_state_unknown_task_is_noop(engine, project_and_task):
    """A reconciliation result for a task we never knew about should
    not invent a new row - it just no-ops."""
    project_id, _ = project_and_task
    async with AsyncSession(engine) as s:
        repo = TaskRepository(s)
        changed = await repo.apply_reconciled_state(
            project_id=project_id,
            engine="celery",
            task_id="never-seen",
            engine_state="success",
        )
        assert changed is False


# =====================================================================
# The transition matrix
# =====================================================================


async def _insert_task(
    engine,
    *,
    project_id: UUID,
    task_id: str,
    state: TaskState,
    **columns,
) -> None:
    async with AsyncSession(engine) as s:
        s.add(
            Task(
                project_id=project_id,
                engine="celery",
                task_id=task_id,
                name=f"myapp.tasks.{task_id}",
                state=state,
                **columns,
            ),
        )
        await s.commit()


async def _read_task(engine, *, project_id: UUID, task_id: str) -> Task:
    async with AsyncSession(engine) as s:
        row = await TaskRepository(s).get_by_engine_task_id(
            project_id=project_id,
            engine="celery",
            task_id=task_id,
        )
        assert row is not None
        return row


async def _apply(engine, *, project_id: UUID, task_id: str, engine_state: str, **kw) -> bool:
    async with AsyncSession(engine) as s:
        changed = await TaskRepository(s).apply_reconciled_state(
            project_id=project_id,
            engine="celery",
            task_id=task_id,
            engine_state=engine_state,
            **kw,
        )
        await s.commit()
        return changed


@pytest.mark.asyncio
class TestTerminalIsTerminal:
    """Terminal → anything is rejected outright."""

    async def test_success_plus_late_pending_stays_success(self, engine, project_and_task):
        # THE reproduced H1 regression: SUCCESS + stale "pending"
        # response used to flip the row back to PENDING with
        # finished_at retained.
        project_id, _ = project_and_task
        finished = datetime.now(UTC)
        await _insert_task(
            engine,
            project_id=project_id,
            task_id="done-1",
            state=TaskState.SUCCESS,
            finished_at=finished,
        )
        before = await _read_task(engine, project_id=project_id, task_id="done-1")

        changed = await _apply(
            engine,
            project_id=project_id,
            task_id="done-1",
            engine_state="pending",
        )
        assert changed is False

        after = await _read_task(engine, project_id=project_id, task_id="done-1")
        assert after.state == TaskState.SUCCESS
        assert after.finished_at == before.finished_at

    @pytest.mark.parametrize(
        ("current", "incoming"),
        [
            (TaskState.SUCCESS, "started"),
            (TaskState.SUCCESS, "failure"),
            (TaskState.FAILURE, "pending"),
            (TaskState.FAILURE, "success"),
            (TaskState.REVOKED, "success"),
            (TaskState.REVOKED, "started"),
        ],
    )
    async def test_terminal_source_rejects_all_transitions(
        self,
        engine,
        project_and_task,
        current: TaskState,
        incoming: str,
    ):
        project_id, _ = project_and_task
        task_id = f"t-{current.value}-{incoming}"
        await _insert_task(
            engine,
            project_id=project_id,
            task_id=task_id,
            state=current,
        )
        changed = await _apply(
            engine,
            project_id=project_id,
            task_id=task_id,
            engine_state=incoming,
        )
        assert changed is False
        after = await _read_task(engine, project_id=project_id, task_id=task_id)
        assert after.state == current

    async def test_h1_chain_applies_exactly_once(self, engine, project_and_task):
        # The full H1 sequence at the repository level: terminal
        # correction applies once (True), the stale "pending" is
        # rejected (False, so no orphan fire / no audit row upstream),
        # and the replayed terminal response is the no-op edge (False,
        # so task.orphaned cannot double-fire).
        project_id, task_id = project_and_task
        first = await _apply(
            engine,
            project_id=project_id,
            task_id=task_id,
            engine_state="success",
        )
        stale = await _apply(
            engine,
            project_id=project_id,
            task_id=task_id,
            engine_state="pending",
        )
        replay = await _apply(
            engine,
            project_id=project_id,
            task_id=task_id,
            engine_state="success",
        )
        assert (first, stale, replay) == (True, False, False)
        after = await _read_task(engine, project_id=project_id, task_id=task_id)
        assert after.state == TaskState.SUCCESS


@pytest.mark.asyncio
class TestNonTerminalCorrections:
    """Legitimate corrections out of non-terminal states still apply."""

    async def test_started_to_pending_applies(self, engine, project_and_task):
        project_id, task_id = project_and_task
        changed = await _apply(
            engine,
            project_id=project_id,
            task_id=task_id,
            engine_state="pending",
        )
        assert changed is True
        after = await _read_task(engine, project_id=project_id, task_id=task_id)
        assert after.state == TaskState.PENDING

    async def test_retry_to_pending_applies_despite_finished_at(
        self,
        engine,
        project_and_task,
    ):
        # A retried task legitimately carries finished_at from its
        # earlier failure (TASK_RETRIED does not clear it); that must
        # not block a nonterminal -> nonterminal correction.
        project_id, _ = project_and_task
        await _insert_task(
            engine,
            project_id=project_id,
            task_id="retry-1",
            state=TaskState.RETRY,
            finished_at=datetime.now(UTC) - timedelta(minutes=30),
            exception="boom",
        )
        changed = await _apply(
            engine,
            project_id=project_id,
            task_id="retry-1",
            engine_state="pending",
        )
        assert changed is True
        after = await _read_task(engine, project_id=project_id, task_id="retry-1")
        assert after.state == TaskState.PENDING

    async def test_finished_at_and_exception_are_kept_when_already_set(
        self,
        engine,
        project_and_task,
    ):
        project_id, _ = project_and_task
        await _insert_task(
            engine,
            project_id=project_id,
            task_id="kept-1",
            state=TaskState.STARTED,
            finished_at=datetime.now(UTC) - timedelta(minutes=30),
            exception="original",
        )
        before = await _read_task(engine, project_id=project_id, task_id="kept-1")
        changed = await _apply(
            engine,
            project_id=project_id,
            task_id="kept-1",
            engine_state="failure",
            finished_at=datetime.now(UTC),
            exception_text="from-probe",
        )
        assert changed is True
        after = await _read_task(engine, project_id=project_id, task_id="kept-1")
        assert after.state == TaskState.FAILURE
        assert after.finished_at == before.finished_at
        assert after.exception == "original"

    async def test_finished_at_and_exception_are_filled_when_missing(
        self,
        engine,
        project_and_task,
    ):
        project_id, task_id = project_and_task
        changed = await _apply(
            engine,
            project_id=project_id,
            task_id=task_id,
            engine_state="failure",
            finished_at=datetime.now(UTC),
            exception_text="from-probe",
        )
        assert changed is True
        after = await _read_task(engine, project_id=project_id, task_id=task_id)
        assert after.finished_at is not None
        assert after.exception == "from-probe"


@pytest.mark.asyncio
class TestStaleResponseGuard:
    """Non-terminal responses that predate the row's last write drop."""

    async def test_stale_nonterminal_response_rejected(self, engine, project_and_task):
        # The row was written at insert time (updated_at = now); a
        # probe issued an hour AGO cannot know anything fresher, so
        # its non-terminal answer is dropped.
        project_id, task_id = project_and_task
        changed = await _apply(
            engine,
            project_id=project_id,
            task_id=task_id,
            engine_state="pending",
            probe_issued_at=datetime.now(UTC) - timedelta(hours=1),
        )
        assert changed is False
        after = await _read_task(engine, project_id=project_id, task_id=task_id)
        assert after.state == TaskState.STARTED

    async def test_fresh_nonterminal_response_applies(self, engine, project_and_task):
        # Probe issued AFTER the row's last write -> not stale.
        project_id, task_id = project_and_task
        changed = await _apply(
            engine,
            project_id=project_id,
            task_id=task_id,
            engine_state="pending",
            probe_issued_at=datetime.now(UTC) + timedelta(hours=1),
        )
        assert changed is True
        after = await _read_task(engine, project_id=project_id, task_id=task_id)
        assert after.state == TaskState.PENDING

    async def test_stale_terminal_response_still_applies(self, engine, project_and_task):
        # Terminal wins regardless of timestamps (same rule as the
        # EventIngestor's out-of-order guard): the task provably
        # finished; a non-terminal row cannot argue.
        project_id, task_id = project_and_task
        changed = await _apply(
            engine,
            project_id=project_id,
            task_id=task_id,
            engine_state="success",
            probe_issued_at=datetime.now(UTC) - timedelta(hours=1),
        )
        assert changed is True
        after = await _read_task(engine, project_id=project_id, task_id=task_id)
        assert after.state == TaskState.SUCCESS


class TestReadToWriteRaceGuard:
    """The staleness check runs against the row as READ, so a
    fresh event committing between that read and the atomic UPDATE
    could still be overwritten by a stale probe. The UPDATE now also
    requires ``updated_at`` to equal the validated snapshot, so the
    write-skew loser matches zero rows.
    """

    @pytest.mark.asyncio
    async def test_fresh_event_between_read_and_update_wins(
        self,
        engine,
        project_and_task,
    ):
        import asyncio

        from sqlalchemy import update as sa_update

        project_id, task_id = project_and_task
        old = datetime.now(UTC) - timedelta(hours=1)
        probe = datetime.now(UTC) - timedelta(seconds=30)
        fresh = datetime.now(UTC)

        # Backdate the row so the probe (issued after it) passes the
        # pre-UPDATE staleness check.
        async with AsyncSession(engine) as s:
            await s.execute(
                sa_update(Task)
                .where(Task.project_id == project_id, Task.task_id == task_id)
                .values(updated_at=old),
            )
            await s.commit()

        read_done = asyncio.Event()
        writer_done = asyncio.Event()

        async with AsyncSession(engine) as apply_session:
            repo = TaskRepository(apply_session)
            original_read = repo.get_by_engine_task_id

            async def paused_read(**kwargs):
                row = await original_read(**kwargs)
                read_done.set()
                await writer_done.wait()
                return row

            repo.get_by_engine_task_id = paused_read  # type: ignore[method-assign]

            async def fresh_event() -> None:
                await read_done.wait()
                async with AsyncSession(engine) as w:
                    await w.execute(
                        sa_update(Task)
                        .where(
                            Task.project_id == project_id,
                            Task.task_id == task_id,
                        )
                        .values(state=TaskState.RETRY, updated_at=fresh),
                    )
                    await w.commit()
                writer_done.set()

            writer = asyncio.create_task(fresh_event())
            changed = await repo.apply_reconciled_state(
                project_id=project_id,
                engine="celery",
                task_id=task_id,
                engine_state="pending",
                probe_issued_at=probe,
            )
            await apply_session.commit()
            await writer

        assert changed is False
        async with AsyncSession(engine) as s:
            row = await TaskRepository(s).get_by_engine_task_id(
                project_id=project_id,
                engine="celery",
                task_id=task_id,
            )
        assert row.state is TaskState.RETRY

    @pytest.mark.asyncio
    async def test_terminal_correction_still_wins_the_same_race(
        self,
        engine,
        project_and_task,
    ):
        # Terminal responses stay exempt from the snapshot guard:
        # a terminal correction racing a fresh NON-terminal event
        # still applies (terminal wins regardless of timestamps).
        import asyncio

        from sqlalchemy import update as sa_update

        project_id, task_id = project_and_task
        probe = datetime.now(UTC)

        read_done = asyncio.Event()
        writer_done = asyncio.Event()

        async with AsyncSession(engine) as apply_session:
            repo = TaskRepository(apply_session)
            original_read = repo.get_by_engine_task_id

            async def paused_read(**kwargs):
                row = await original_read(**kwargs)
                read_done.set()
                await writer_done.wait()
                return row

            repo.get_by_engine_task_id = paused_read  # type: ignore[method-assign]

            async def fresh_event() -> None:
                await read_done.wait()
                async with AsyncSession(engine) as w:
                    await w.execute(
                        sa_update(Task)
                        .where(
                            Task.project_id == project_id,
                            Task.task_id == task_id,
                        )
                        .values(
                            state=TaskState.RETRY,
                            updated_at=datetime.now(UTC),
                        ),
                    )
                    await w.commit()
                writer_done.set()

            writer = asyncio.create_task(fresh_event())
            changed = await repo.apply_reconciled_state(
                project_id=project_id,
                engine="celery",
                task_id=task_id,
                engine_state="failure",
                probe_issued_at=probe,
            )
            await apply_session.commit()
            await writer

        assert changed is True
        async with AsyncSession(engine) as s:
            row = await TaskRepository(s).get_by_engine_task_id(
                project_id=project_id,
                engine="celery",
                task_id=task_id,
            )
        assert row.state is TaskState.FAILURE

    @pytest.mark.asyncio
    async def test_same_state_freshness_write_in_gap_rejects_stale_probe(
        self,
        engine,
        project_and_task,
    ):
        # Round-4 LOW residual: a duplicate TASK_STARTED legitimately
        # keeps state=STARTED while advancing updated_at/started_at.
        # The state-snapshot guard alone cannot see it; the
        # ``updated_at <= probe_issued_at`` predicate must reject the
        # stale probe.
        import asyncio

        from sqlalchemy import update as sa_update

        project_id, task_id = project_and_task
        old = datetime.now(UTC) - timedelta(hours=1)
        probe = datetime.now(UTC) - timedelta(seconds=30)
        fresh = datetime.now(UTC)

        async with AsyncSession(engine) as s:
            await s.execute(
                sa_update(Task)
                .where(Task.project_id == project_id, Task.task_id == task_id)
                .values(updated_at=old),
            )
            await s.commit()

        read_done = asyncio.Event()
        writer_done = asyncio.Event()

        async with AsyncSession(engine) as apply_session:
            repo = TaskRepository(apply_session)
            original_read = repo.get_by_engine_task_id

            async def paused_read(**kwargs):
                row = await original_read(**kwargs)
                read_done.set()
                await writer_done.wait()
                return row

            repo.get_by_engine_task_id = paused_read  # type: ignore[method-assign]

            async def duplicate_started_event() -> None:
                await read_done.wait()
                async with AsyncSession(engine) as w:
                    await w.execute(
                        sa_update(Task)
                        .where(
                            Task.project_id == project_id,
                            Task.task_id == task_id,
                        )
                        # Same state, fresher knowledge.
                        .values(state=TaskState.STARTED, updated_at=fresh),
                    )
                    await w.commit()
                writer_done.set()

            writer = asyncio.create_task(duplicate_started_event())
            changed = await repo.apply_reconciled_state(
                project_id=project_id,
                engine="celery",
                task_id=task_id,
                engine_state="pending",
                probe_issued_at=probe,
            )
            await apply_session.commit()
            await writer

        assert changed is False
        async with AsyncSession(engine) as s:
            row = await TaskRepository(s).get_by_engine_task_id(
                project_id=project_id,
                engine="celery",
                task_id=task_id,
            )
        assert row.state is TaskState.STARTED
