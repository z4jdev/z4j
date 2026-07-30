"""Tests for ``MisfireDetector`` (A4 brain-side misfire detection).

Three layers:

1. Pure cadence helpers (``parse_interval_seconds`` / ``cron_next_fire``).
2. Detection logic with ``dispatcher=None`` (audit-only) - asserts WHICH
   schedules get flagged (interval / cron / grace boundary / dedup /
   disabled / solar+clocked skipped / bad expression skipped / disabled
   sweep) via the ``scheduler.misfire_detected`` audit row.
3. Full automation firing - a misfired schedule fires a
   ``schedule.misfired`` notify rule end to end, and the per-project
   kill switch suppresses it.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.command_dispatcher import CommandDispatcher
from z4j_brain.domain.workers.misfire_detector import (
    MisfireDetector,
    cron_next_fire,
    parse_interval_seconds,
)
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import ProjectRole, ScheduleKind
from z4j_brain.persistence.models import (
    AuditLog,
    AutomationRule,
    Membership,
    Project,
    Schedule,
    User,
    UserNotification,
    UserSubscription,
)
from z4j_brain.settings import Settings
from z4j_brain.websocket.registry._protocol import DeliveryResult

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


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
async def db(engine) -> DatabaseManager:
    return DatabaseManager(engine)


async def _seed_schedule(
    db: DatabaseManager,
    *,
    kind: ScheduleKind = ScheduleKind.INTERVAL,
    expression: str = "60s",
    last_run_at: datetime | None,
    created_at: datetime | None = None,
    enabled: bool = True,
    project_id: uuid.UUID | None = None,
    automation_enabled: bool = True,
) -> tuple[uuid.UUID, uuid.UUID]:
    project_id = project_id or uuid.uuid4()
    schedule_id = uuid.uuid4()
    created = created_at or (NOW - timedelta(days=1))
    async with db.session() as s:
        if (await s.get(Project, project_id)) is None:
            s.add(
                Project(
                    id=project_id,
                    slug=f"p{uuid.uuid4().hex[:8]}",
                    name="P",
                    automation_enabled=automation_enabled,
                ),
            )
        s.add(
            Schedule(
                id=schedule_id,
                project_id=project_id,
                engine="celery",
                scheduler="z4j-scheduler",
                name="sched",
                task_name="myapp.tasks.t",
                kind=kind,
                expression=expression,
                timezone="UTC",
                args=[],
                kwargs={},
                is_enabled=enabled,
                last_run_at=last_run_at,
                created_at=created,
            ),
        )
        await s.commit()
    return project_id, schedule_id


async def _misfire_rows(db: DatabaseManager) -> list[AuditLog]:
    async with db.session() as s:
        rows = await s.execute(
            select(AuditLog).where(
                AuditLog.action == "scheduler.misfire_detected",
            ),
        )
        return list(rows.scalars().all())


def _detector(db: DatabaseManager, settings: Settings, **kw) -> MisfireDetector:
    return MisfireDetector(
        db=db,
        settings=settings,
        audit=AuditService(settings),
        dispatcher=kw.pop("dispatcher", None),
        clock=kw.pop("clock", lambda: NOW),
    )


# =====================================================================
# Pure helpers
# =====================================================================


class TestParseInterval:
    @pytest.mark.parametrize(
        ("expr", "expected"),
        [
            ("30s", 30),
            ("5m", 300),
            ("2h", 7200),
            ("1d", 86400),
            ("120", 120),  # bare int = seconds
            ("  90s ", 90),
            ("0s", None),  # non-positive
            ("", None),
            ("abc", None),
            ("5x", None),  # unknown unit
        ],
    )
    def test_parse(self, expr: str, expected: int | None) -> None:
        assert parse_interval_seconds(expr) == expected


class TestCronNextFire:
    def test_basic_next_is_utc_aware(self) -> None:
        after = datetime(2026, 6, 1, 12, 30, tzinfo=UTC)
        nxt = cron_next_fire("0 * * * *", "UTC", after)  # top of every hour
        assert nxt == datetime(2026, 6, 1, 13, 0, tzinfo=UTC)
        assert nxt.tzinfo is not None

    def test_bad_expression_returns_none(self) -> None:
        assert cron_next_fire("not a cron", "UTC", NOW) is None

    def test_unknown_timezone_falls_back_to_utc(self) -> None:
        # Should not raise; falls back to UTC and still computes.
        nxt = cron_next_fire("0 * * * *", "Not/AZone", NOW)
        assert nxt is not None


# =====================================================================
# Detection logic (dispatcher=None -> audit-only)
# =====================================================================


class TestDetection:
    @pytest.mark.asyncio
    async def test_interval_misfire_detected(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # 60s interval last fired 5 min ago -> expected 4 min ago,
        # well past the 60s grace.
        await _seed_schedule(
            db,
            expression="60s",
            last_run_at=NOW - timedelta(minutes=5),
        )
        await _detector(db, settings).tick()
        rows = await _misfire_rows(db)
        assert len(rows) == 1
        assert rows[0].audit_metadata["kind"] == "interval"
        assert rows[0].audit_metadata["lateness_seconds"] > 0

    @pytest.mark.asyncio
    async def test_cron_misfire_detected(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # Hourly cron last fired ~2h ago -> the next slot after it is
        # ~1h in the past, far beyond grace.
        await _seed_schedule(
            db,
            kind=ScheduleKind.CRON,
            expression="0 * * * *",
            last_run_at=NOW - timedelta(hours=2, minutes=5),
        )
        await _detector(db, settings).tick()
        assert len(await _misfire_rows(db)) == 1

    @pytest.mark.asyncio
    async def test_on_time_not_flagged(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # Fired 30s ago on a 60s interval -> next expected 30s in the
        # FUTURE. Not a misfire.
        await _seed_schedule(
            db,
            expression="60s",
            last_run_at=NOW - timedelta(seconds=30),
        )
        await _detector(db, settings).tick()
        assert await _misfire_rows(db) == []

    @pytest.mark.asyncio
    async def test_grace_boundary(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # expected == NOW - grace exactly -> NOT flagged (>= now).
        await _seed_schedule(
            db,
            expression="60s",
            last_run_at=NOW - timedelta(seconds=120),
        )
        await _detector(db, settings).tick()
        assert await _misfire_rows(db) == []
        # One second past the boundary -> flagged.
        await _seed_schedule(
            db,
            expression="60s",
            last_run_at=NOW - timedelta(seconds=121),
        )
        await _detector(db, settings).tick()
        assert len(await _misfire_rows(db)) == 1

    @pytest.mark.asyncio
    async def test_disabled_schedule_skipped(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        await _seed_schedule(
            db,
            expression="60s",
            last_run_at=NOW - timedelta(hours=1),
            enabled=False,
        )
        await _detector(db, settings).tick()
        assert await _misfire_rows(db) == []

    @pytest.mark.asyncio
    async def test_solar_and_clocked_skipped(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        await _seed_schedule(
            db,
            kind=ScheduleKind.SOLAR,
            expression="sunrise",
            last_run_at=NOW - timedelta(days=2),
        )
        await _seed_schedule(
            db,
            kind=ScheduleKind.CLOCKED,
            expression="2020-01-01T00:00:00Z",
            last_run_at=NOW - timedelta(days=2),
        )
        await _detector(db, settings).tick()
        assert await _misfire_rows(db) == []

    @pytest.mark.asyncio
    async def test_bad_interval_expression_skipped(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        await _seed_schedule(
            db,
            expression="garbage",
            last_run_at=NOW - timedelta(hours=1),
        )
        await _detector(db, settings).tick()
        assert await _misfire_rows(db) == []

    @pytest.mark.asyncio
    async def test_per_sweep_cap_spreads_burst_over_ticks(
        self,
        db: DatabaseManager,
        settings: Settings,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # A full-fleet outage must not fan out thousands of audit rows +
        # rule firings in one tick: the per-sweep cap bounds the burst and
        # the remainder self-heals on the next sweep (its dedup key is still
        # unrecorded).
        from z4j_brain.domain.workers import misfire_detector as mod

        monkeypatch.setattr(mod, "_MAX_MISFIRES_PER_SWEEP", 2)
        for _ in range(3):
            await _seed_schedule(
                db,
                expression="60s",
                last_run_at=NOW - timedelta(minutes=10),
            )
        detector = _detector(db, settings)  # ONE instance: dedup persists
        await detector.tick()
        assert len(await _misfire_rows(db)) == 2  # capped this sweep
        await detector.tick()
        assert len(await _misfire_rows(db)) == 3  # remainder picked up

    @pytest.mark.asyncio
    async def test_dedup_is_durable_across_replicas(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # Two SEPARATE detector instances (= two brain replicas sharing one
        # DB, with independent in-memory state) must alert a persistent
        # misfire ONCE, not once each. The claim is durable in misfire_alerts.
        await _seed_schedule(
            db,
            expression="60s",
            last_run_at=NOW - timedelta(minutes=10),
        )
        replica_a = _detector(db, settings)
        replica_b = _detector(db, settings)
        await replica_a.tick()  # A wins the claim + alerts
        await replica_b.tick()  # B sees the claim + skips
        assert len(await _misfire_rows(db)) == 1

    @pytest.mark.asyncio
    async def test_automation_failure_keeps_claim_and_audits_once(
        self,
        db: DatabaseManager,
        settings: Settings,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # schedule.misfired automation raising AFTER
        # the detection audit commits must NOT release the durable claim
        # (which would re-audit the same episode next sweep). The audit is
        # written exactly once; the claim is held.
        await _seed_schedule(
            db,
            expression="60s",
            last_run_at=NOW - timedelta(minutes=10),
        )
        detector = _detector(db, settings)

        async def _boom(schedule, *, expected, now):
            raise RuntimeError("simulated schedule.misfired automation failure")

        monkeypatch.setattr(detector, "_fire_automation", _boom)
        await detector.tick()
        await detector.tick()
        # Exactly ONE detection audit despite the automation failure -- the
        # claim was retained, so the second sweep is a no-op (no duplicate).
        assert len(await _misfire_rows(db)) == 1

    @pytest.mark.asyncio
    async def test_one_alert_failure_does_not_abort_sweep(
        self,
        db: DatabaseManager,
        settings: Settings,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # One schedule's alert raising must not silently abort detection for
        # every schedule after it in the sweep (per-schedule try/except).
        for _ in range(2):
            await _seed_schedule(
                db,
                expression="60s",
                last_run_at=NOW - timedelta(minutes=10),
            )
        detector = _detector(db, settings)
        real_alert = detector._alert_misfire
        calls = {"n": 0}

        async def flaky_alert(schedule, *, expected, now):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("simulated audit write failure")
            return await real_alert(schedule, expected=expected, now=now)

        monkeypatch.setattr(detector, "_alert_misfire", flaky_alert)
        await detector.tick()
        # First raised (caught + logged); the second still recorded.
        assert len(await _misfire_rows(db)) == 1

    @pytest.mark.asyncio
    async def test_never_fired_uses_created_at_anchor(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # Never fired (last_run_at None), created 1h ago, 60s interval
        # -> expected ~59m ago. Misfire with last_run_at=None recorded.
        await _seed_schedule(
            db,
            expression="60s",
            last_run_at=None,
            created_at=NOW - timedelta(hours=1),
        )
        await _detector(db, settings).tick()
        rows = await _misfire_rows(db)
        assert len(rows) == 1
        assert rows[0].audit_metadata["last_run_at"] is None

    @pytest.mark.asyncio
    async def test_sweep_disabled_is_noop(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # Settings is frozen; build a disabled copy.
        disabled = settings.model_copy(
            update={"scheduler_misfire_sweep_seconds": 0},
        )
        await _seed_schedule(
            db,
            expression="60s",
            last_run_at=NOW - timedelta(hours=1),
        )
        await _detector(db, disabled).tick()
        assert await _misfire_rows(db) == []


class TestDedup:
    @pytest.mark.asyncio
    async def test_same_gap_alerts_once(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        await _seed_schedule(
            db,
            expression="60s",
            last_run_at=NOW - timedelta(hours=1),
        )
        detector = _detector(db, settings)
        await detector.tick()
        await detector.tick()  # same last_run_at -> deduped
        assert len(await _misfire_rows(db)) == 1

    @pytest.mark.asyncio
    async def test_new_gap_realerts(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        _pid, sched_id = await _seed_schedule(
            db,
            expression="60s",
            last_run_at=NOW - timedelta(hours=1),
        )
        detector = _detector(db, settings)
        await detector.tick()
        assert len(await _misfire_rows(db)) == 1

        # Simulate a fire that then goes stale again: advance
        # last_run_at (new gap) but still older than cadence+grace.
        from sqlalchemy import update

        async with db.session() as s:
            await s.execute(
                update(Schedule)
                .where(Schedule.id == sched_id)
                .values(last_run_at=NOW - timedelta(minutes=30)),
            )
            await s.commit()
        await detector.tick()  # different last_run_at -> fresh episode
        assert len(await _misfire_rows(db)) == 2


# =====================================================================
# Full automation firing
# =====================================================================


class _FakeRegistry:
    async def deliver(self, *, command_id, agent_id, required_retry_engine=None) -> DeliveryResult:
        return DeliveryResult(
            delivered_locally=False,
            notified_cluster=True,
            agent_was_known=True,
        )


async def _seed_rule_and_member(
    db: DatabaseManager,
    project_id: uuid.UUID,
) -> None:
    async with db.session() as s:
        user = User(
            email=f"{uuid.uuid4().hex[:8]}@x.io",
            password_hash=secrets.token_hex(8),
        )
        s.add(user)
        await s.flush()
        s.add(
            Membership(
                user_id=user.id,
                project_id=project_id,
                role=ProjectRole.OPERATOR,
            ),
        )
        s.add(
            AutomationRule(
                project_id=project_id,
                name="alert-on-misfire",
                trigger="schedule.misfired",
                actions=[{"type": "notify"}],
            ),
        )
        await s.commit()


class TestAutomationFiring:
    @pytest.mark.asyncio
    async def test_misfire_fires_notify_rule(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        project_id, _ = await _seed_schedule(
            db,
            expression="60s",
            last_run_at=NOW - timedelta(hours=1),
        )
        await _seed_rule_and_member(db, project_id)
        dispatcher = CommandDispatcher(
            settings=settings,
            registry=_FakeRegistry(),  # type: ignore[arg-type]
            audit=AuditService(settings),
        )
        await _detector(db, settings, dispatcher=dispatcher).tick()

        async with db.session() as s:
            notes = (await s.execute(select(UserNotification))).scalars().all()
            fired = (
                (
                    await s.execute(
                        select(AuditLog).where(
                            AuditLog.action == "automation.rule.fired",
                        ),
                    )
                )
                .scalars()
                .all()
            )
        assert len(notes) == 1
        assert notes[0].reason == "automation"
        assert len(fired) == 1
        assert fired[0].audit_metadata["trigger"] == "schedule.misfired"

    @pytest.mark.asyncio
    async def test_kill_switch_suppresses_firing(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # automation_enabled=False -> detection audit still written,
        # but no rule fires.
        project_id, _ = await _seed_schedule(
            db,
            expression="60s",
            last_run_at=NOW - timedelta(hours=1),
            automation_enabled=False,
        )
        await _seed_rule_and_member(db, project_id)
        dispatcher = CommandDispatcher(
            settings=settings,
            registry=_FakeRegistry(),  # type: ignore[arg-type]
            audit=AuditService(settings),
        )
        await _detector(db, settings, dispatcher=dispatcher).tick()

        async with db.session() as s:
            notes = (await s.execute(select(UserNotification))).scalars().all()
            fired = (
                (
                    await s.execute(
                        select(AuditLog).where(
                            AuditLog.action == "automation.rule.fired",
                        ),
                    )
                )
                .scalars()
                .all()
            )
        assert notes == []
        assert fired == []
        assert len(await _misfire_rows(db)) == 1  # detection still happened


class TestSubscriptionNotification:
    @pytest.mark.asyncio
    async def test_misfire_notifies_subscriber(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # A user subscribed to schedule.misfired (in-app) gets a bell
        # notification when a schedule misfires -- via the operator-facing
        # subscription channels, independent of automation rules (note
        # dispatcher=None here).
        project_id, _ = await _seed_schedule(
            db,
            expression="60s",
            last_run_at=NOW - timedelta(hours=1),
        )
        async with db.session() as s:
            user = User(
                email=f"{uuid.uuid4().hex[:8]}@x.io",
                password_hash=secrets.token_hex(8),
            )
            s.add(user)
            await s.flush()
            s.add(
                Membership(
                    user_id=user.id,
                    project_id=project_id,
                    role=ProjectRole.OPERATOR,
                ),
            )
            s.add(
                UserSubscription(
                    user_id=user.id,
                    project_id=project_id,
                    trigger="schedule.misfired",
                    filters={},
                    in_app=True,
                    project_channel_ids=[],
                    user_channel_ids=[],
                    cooldown_seconds=0,
                    last_fired_at=None,
                    muted_until=None,
                    is_active=True,
                ),
            )
            await s.commit()

        await _detector(db, settings).tick()

        async with db.session() as s:
            notes = (await s.execute(select(UserNotification))).scalars().all()
        assert len(notes) == 1
        assert notes[0].reason == "subscribed"
        # The bell routes on resource_type; without the stamp a
        # misfire alert deep-links to a nonexistent task page
        # (round-4 LOW).
        assert notes[0].data["resource_type"] == "schedule"
