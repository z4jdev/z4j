"""Regression tests for Phase-2 audit findings.

Three fixes landed before declaring Phase 2 done:

- **HIGH-1**: ``lstrip("DNS:")`` in both mTLS interceptors stripped
  a SET of characters instead of the prefix. CNs starting with
  D/N/S/colon were silently mangled. Fixed via ``removeprefix``.
- **HIGH-2**: ``PendingFiresReplayWorker._apply_catch_up`` did one
  ``schedules_repo.get(schedule_id)`` per distinct schedule in the
  replay batch (N+1). Fixed via a single batched
  ``WHERE id IN (...)`` query.
- **MED-1**: The brain trigger route reached into
  ``dispatcher._settings`` (private). Replaced with a proper
  ``Depends(get_settings)`` and a process-wide singleton
  TriggerScheduleClient on ``app.state``.

These tests pin the fix so a future regression fails loudly.

The database-backed test here runs against a MIGRATED schema. Boundary D
refuses a direct INSERT into ``schedules``, so the replay batch is seeded
the way the product seeds it, through ``ScheduleControlRepository``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import ScheduleKind
from z4j_brain.persistence.models import (
    PendingFire,
    Project,
)
from z4j_brain.persistence.repositories import (
    ScheduleRepository,
)
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
)
from z4j_brain.scheduler_grpc.auth import _normalise_cn

# =====================================================================
# HIGH-1: removeprefix vs lstrip
# =====================================================================


class TestInterceptorRemovePrefix:
    """Regression for the ``lstrip("DNS:")`` bug.

    Both interceptors (brain side and scheduler side) used
    ``str.lstrip`` to strip a hypothetical ``DNS:`` URI prefix
    that gRPC sometimes embeds in SAN entries. ``lstrip`` takes a
    SET of characters - so any leading D, N, S, or colon got
    eaten. A CN like ``Scheduler-1`` became ``cheduler-1`` and
    failed the allow-list, locking out a legitimate cert.

    Both interceptors now use ``str.removeprefix``. We test the
    brain side here; the scheduler side uses identical logic and
    is covered by ``packages/z4j-scheduler/tests/unit/test_audit_phase2_fixes.py``.
    """

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Scheduler-1", "Scheduler-1"),
            ("Nightly-Scheduler", "Nightly-Scheduler"),
            ("DDD-cluster", "DDD-cluster"),
            ("DNS:scheduler-1", "scheduler-1"),
            ("IP:127.0.0.1", "127.0.0.1"),
            ("URI:spiffe://scheduler/one", "spiffe://scheduler/one"),
            ("email:scheduler@example.test", "scheduler@example.test"),
            ("  DNS:scheduler-1  ", "DNS:scheduler-1"),
        ],
    )
    def test_production_cn_normaliser(self, raw: str, expected: str) -> None:
        assert _normalise_cn(raw) == expected


# =====================================================================
# HIGH-2: batched schedule lookup in _apply_catch_up
# =====================================================================


class _CountingSession:
    """Wraps an AsyncSession and counts how many .execute calls fire.

    Used to prove _apply_catch_up issues exactly ONE SELECT instead
    of N (one per schedule).
    """

    def __init__(self, real_session) -> None:
        self._real = real_session
        self.execute_calls = 0

    async def execute(self, *args, **kwargs):
        self.execute_calls += 1
        return await self._real.execute(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._real, name)


@pytest.fixture
async def db(migrated_db_url: str):
    # A migrated database, not a create_all() one: the Boundary-D guards
    # that refuse a hand-written schedules row live in a migration, and a
    # DatabaseManager is what installs the guard UDFs those triggers call.
    engine = create_async_engine(migrated_db_url)
    yield DatabaseManager(engine)
    await engine.dispose()


class TestApplyCatchUpBatchedLookup:
    @pytest.mark.asyncio
    async def test_one_select_per_replay_batch_not_per_schedule(
        self,
        db,
    ) -> None:
        """Five distinct schedules + one execute call, not five.

        Builds a 5-schedule replay batch and runs _apply_catch_up
        through a CountingSession. The fix should produce exactly
        ONE SELECT (the batched IN-list lookup).
        """
        from z4j_brain.domain.workers.pending_fires import (
            PendingFiresReplayWorker,
        )

        project_id = uuid.uuid4()
        schedule_ids = []
        async with db.session() as s:
            s.add(Project(id=project_id, slug="proj", name="Proj"))
            await s.flush()
            control = ScheduleControlRepository(s)
            for index in range(5):
                # Through the control repository, because Boundary D refuses
                # a direct INSERT into schedules.
                row = await control.create_current(
                    project_id=project_id,
                    data={
                        "engine": "celery",
                        "scheduler": "z4j-scheduler",
                        "name": f"sched-{index}",
                        "task_name": "t.t",
                        "kind": ScheduleKind.CRON.value,
                        "expression": "0 * * * *",
                        "timezone": "UTC",
                        "is_enabled": True,
                        "catch_up": "fire_all_missed",
                    },
                    planning_at=datetime.now(UTC),
                )
                schedule_ids.append(row.id)
            await s.commit()

        # A synthetic batch of fires across all 5 schedules. These are
        # inputs to the filter, not buffered rows: _apply_catch_up reads
        # ``schedule_id`` and ``fire_id`` off them and queries the DB only
        # for the schedules, so persisting them would add a guarded write
        # that proves nothing about the batching under test.
        now = datetime.now(UTC)
        fires = [
            PendingFire(
                id=uuid.uuid4(),
                fire_id=uuid.uuid4(),
                schedule_id=sid,
                project_id=project_id,
                engine="celery",
                payload={},
                scheduled_for=now,
                enqueued_at=now,
                expires_at=now + timedelta(days=1),
            )
            for sid in schedule_ids
        ]

        async with db.session() as s:
            counting = _CountingSession(s)
            schedules_repo = ScheduleRepository(counting)  # type: ignore[arg-type]
            kept, dropped = await PendingFiresReplayWorker._apply_catch_up(
                fires=fires,
                schedules_repo=schedules_repo,
            )
            # Exactly ONE execute - the batched IN-list lookup.
            # The previous N+1 implementation called .execute 5 times
            # (one .get per schedule via the BaseRepository).
            assert counting.execute_calls == 1
            # Sanity: catch_up=fire_all_missed kept everything and dropped none.
            assert len(kept) == 5
            assert dropped == []


# =====================================================================
# MED-1: the schedule routes never reach into another object's privates
# =====================================================================


class TestScheduleRoutesUseProperDependencies:
    """The schedule routes must NOT reach into ``dispatcher._settings``.

    An earlier implementation read the brain's Settings via
    ``getattr(dispatcher, "_settings", None)``, a private-API access that
    breaks the moment CommandDispatcher's layout changes. Configuration
    arrives through the dependency system or not at all.

    The original form of this class also pinned the gRPC trigger-client
    singleton, which no longer exists: an operator trigger is now dispatched
    by the brain itself in every configuration, because the brain is the fire
    authority and the only side that can see a hold. The surviving invariant
    is the one that was always the point, and the client's absence is now
    asserted rather than its presence.
    """

    def test_dispatcher_underscore_settings_not_referenced(self) -> None:
        import inspect

        from z4j_brain.api import schedules as routes

        source = inspect.getsource(routes)
        assert 'getattr(dispatcher, "_settings"' not in source
        assert "dispatcher._settings" not in source

    def test_a_trigger_opens_no_network_client(self) -> None:
        """A click resolves inside the brain, on the request's own session.

        A route that opened a gRPC channel would be back to sending an
        operator's fire out to a component that cannot see the hold that
        should stop it, and cannot accept the fire either.
        """
        import inspect

        from z4j_brain.api import schedules as routes

        source = inspect.getsource(routes)
        assert not hasattr(routes, "_get_or_build_trigger_client")
        assert "TriggerScheduleClient" not in source
        assert "scheduler_trigger_url" not in source
