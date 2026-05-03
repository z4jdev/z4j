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
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from z4j_brain.persistence.base import Base
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import AgentState, ScheduleKind
from z4j_brain.persistence.models import (
    Agent,
    PendingFire,
    Project,
    Schedule,
)
from z4j_brain.persistence.repositories import (
    PendingFiresRepository,
    ScheduleRepository,
)
from z4j_brain.settings import Settings


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

    def test_cn_starting_with_S_not_mangled(self) -> None:
        # The literal symptom: S gets stripped, "Scheduler-1"
        # becomes "cheduler-1", allow-list match fails.
        assert "Scheduler-1".removeprefix("DNS:") == "Scheduler-1"
        # Whereas the broken behaviour:
        assert "Scheduler-1".lstrip("DNS:") == "cheduler-1"

    def test_dns_prefix_correctly_stripped(self) -> None:
        # When the prefix is actually present, removeprefix removes it.
        assert "DNS:scheduler-1".removeprefix("DNS:") == "scheduler-1"

    def test_no_prefix_leaves_string_alone(self) -> None:
        # Plain CN with no DNS prefix should be unchanged.
        assert "scheduler-1".removeprefix("DNS:") == "scheduler-1"
        assert "Nightly-Scheduler".removeprefix("DNS:") == "Nightly-Scheduler"
        assert "DDD-cluster".removeprefix("DNS:") == "DDD-cluster"

    def test_interceptor_normalisation_uses_removeprefix(self) -> None:
        # Inline the same expression the interceptor uses to ensure
        # both sides stay consistent. If a future refactor switches
        # back to lstrip this assertion catches it.
        from z4j_brain.scheduler_grpc import auth as brain_auth

        # Pull the source of the interceptor module and confirm
        # ``lstrip("DNS:")`` no longer appears.
        # Round-9 audit fix R9-Sched-MED (Apr 2026): the helper now
        # iterates a tuple of prefixes (DNS:, IP:, URI:, email:)
        # using ``removeprefix`` rather than a single literal call;
        # we still assert the substring ``removeprefix`` is present
        # and that ``lstrip`` is absent.
        import inspect

        source = inspect.getsource(brain_auth)
        assert "lstrip(\"DNS:\")" not in source
        assert "lstrip('DNS:')" not in source
        assert "removeprefix" in source
        # And every general-name prefix is in the strip set.
        for prefix in ("DNS:", "IP:", "URI:", "email:"):
            assert prefix in source, (
                f"_normalise_cn must strip {prefix} (R9-Sched-MED)"
            )


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
async def db():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield DatabaseManager(engine)
    await engine.dispose()


class TestApplyCatchUpBatchedLookup:
    @pytest.mark.asyncio
    async def test_one_select_per_replay_batch_not_per_schedule(
        self, db,
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
        schedule_ids = [uuid.uuid4() for _ in range(5)]
        async with db.session() as s:
            s.add(Project(id=project_id, slug="proj", name="Proj"))
            for sid in schedule_ids:
                s.add(
                    Schedule(
                        id=sid,
                        project_id=project_id,
                        engine="celery",
                        scheduler="z4j-scheduler",
                        name=f"sched-{sid.hex[:8]}",
                        task_name="t.t",
                        kind=ScheduleKind.CRON,
                        expression="0 * * * *",
                        timezone="UTC",
                        args=[], kwargs={},
                        is_enabled=True,
                        catch_up="fire_all_missed",
                    ),
                )
            await s.commit()

        # Build a synthetic batch of fires across all 5 schedules.
        async with db.session() as s:
            now = datetime.now(UTC)
            fires = []
            for sid in schedule_ids:
                pf = PendingFire(
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
                s.add(pf)
                fires.append(pf)
            await s.commit()

        async with db.session() as s:
            counting = _CountingSession(s)
            schedules_repo = ScheduleRepository(counting)  # type: ignore[arg-type]
            kept = await PendingFiresReplayWorker._apply_catch_up(
                fires=fires, schedules_repo=schedules_repo,
            )
            # Exactly ONE execute - the batched IN-list lookup.
            # The previous N+1 implementation called .execute 5 times
            # (one .get per schedule via the BaseRepository).
            assert counting.execute_calls == 1
            # Sanity: catch_up=fire_all_missed kept everything.
            assert len(kept) == 5


# =====================================================================
# MED-1: trigger route uses Depends(get_settings)
# =====================================================================


class TestTriggerRouteUsesProperDependency:
    """The trigger route must NOT reach into ``dispatcher._settings``.

    The previous implementation read the brain's Settings via
    ``getattr(dispatcher, "_settings", None)`` - a fragile private-
    API access that breaks the moment CommandDispatcher's __slots__
    or layout changes. The fix injects Settings via Depends.
    """

    def test_dispatcher_underscore_settings_not_referenced(self) -> None:
        import inspect

        from z4j_brain.api import schedules as routes

        source = inspect.getsource(routes)
        # Negative - the broken pattern is gone.
        assert 'getattr(dispatcher, "_settings"' not in source
        assert "dispatcher._settings" not in source
        # Positive - Settings comes via Depends.
        assert "Depends(get_settings)" in source

    def test_singleton_helper_exists(self) -> None:
        # The helper that builds + caches the TriggerScheduleClient
        # on app.state. Pinning its existence so it isn't deleted
        # by accident in a future refactor.
        from z4j_brain.api import schedules as routes

        assert hasattr(routes, "_get_or_build_trigger_client")
