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

These run against a MIGRATED database rather than a create_all() one.
``schedules`` and ``audit_log`` are both guarded tables whose guards live
in migrations, so a create_all() schema refuses nothing: it would accept
seed rows no operator's database can hold, and the detector's own audit
writes would never meet the Boundary-F chain. The one test that needs a
state the guards forbid keeps its own create_all() engine and says so.
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
from z4j_brain.domain.schedule_cadence import (
    CADENCE_SEMANTICS_VERSION,
    cadence_runtime_fingerprint,
    canonical_next_run_at,
)
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
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
)
from z4j_brain.settings import Settings
from z4j_brain.websocket.registry._protocol import DeliveryResult

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def settings(migrated_db_url: str, migrated_audit_chain_secret: str) -> Settings:
    return Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        # A migrated database has Boundary F activated, so it refuses an audit
        # row that carries no chain authentication. Every assertion in this
        # file reads a ``scheduler.misfire_detected`` audit row, so without the
        # key the detector could not record a single one.
        audit_chain_secret=migrated_audit_chain_secret,  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )


@pytest.fixture
async def engine(settings: Settings):
    eng = create_async_engine(settings.database_url)
    yield eng
    await eng.dispose()


@pytest.fixture
async def db(engine) -> DatabaseManager:
    return DatabaseManager(engine)


@pytest.fixture
async def create_all_db():
    """A guard-free schema, for the one state an activated database forbids.

    See ``test_bad_interval_expression_skipped``: it is the only case here
    that needs a row the product's own creation path refuses to plan.
    """
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield DatabaseManager(eng)
    await eng.dispose()


async def _seed_schedule_directly(
    db: DatabaseManager,
    *,
    expression: str,
    last_run_at: datetime | None,
) -> tuple[uuid.UUID, uuid.UUID]:
    """Write a schedule row straight to the table. ``create_all_db`` only."""

    project_id = uuid.uuid4()
    schedule_id = uuid.uuid4()
    async with db.session() as s:
        s.add(Project(id=project_id, slug=f"p{uuid.uuid4().hex[:8]}", name="P"))
        s.add(
            Schedule(
                id=schedule_id,
                project_id=project_id,
                engine="celery",
                scheduler="z4j-scheduler",
                name="sched",
                task_name="myapp.tasks.t",
                kind=ScheduleKind.INTERVAL,
                expression=expression,
                timezone="UTC",
                args=[],
                kwargs={},
                is_enabled=True,
                last_run_at=last_run_at,
                created_at=NOW - timedelta(days=1),
            ),
        )
        await s.commit()
    return project_id, schedule_id


async def _advance_cursor(
    db: DatabaseManager,
    *,
    project_id: uuid.UUID,
    schedule_id: uuid.UUID,
    to: datetime,
) -> None:
    """Move a schedule's fire cursor to ``to`` the way the scheduler does.

    ``last_run_at`` is a Boundary-D column: an activated database refuses a
    direct UPDATE, and the only path that moves it is a cursor transition
    carrying the full expected-state tuple. Setting the column by hand would
    seed an anchor no operator's database can actually hold.
    """
    async with db.session() as s:
        row = (await s.execute(select(Schedule).where(Schedule.id == schedule_id))).scalar_one()
        transition = await ScheduleControlRepository(s).advance_cursor(
            project_id=project_id,
            schedule_id=schedule_id,
            observed_control_token=row.control_token,
            definition_digest=row.definition_digest,
            expected_revision=row.schedule_revision,
            expected_last_run_at=row.last_run_at,
            expected_next_run_at=row.next_run_at,
            skipped_through=to,
            prepared_next_run_at=canonical_next_run_at(
                kind=row.kind.value,
                expression=row.expression,
                timezone=row.timezone,
                last_run_at=to,
                anchor_at=to,
            ),
            cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
            cadence_fingerprint=cadence_runtime_fingerprint(),
            occurred_at=to,
        )
        assert transition.disposition == "applied", transition.disposition
        await s.commit()


async def _seed_schedule(
    db: DatabaseManager,
    *,
    kind: ScheduleKind = ScheduleKind.INTERVAL,
    expression: str = "60s",
    last_run_at: datetime | None,
    created_at: datetime | None = None,
    enabled: bool = True,
    paused: bool = False,
    project_id: uuid.UUID | None = None,
    automation_enabled: bool = True,
) -> tuple[uuid.UUID, uuid.UUID]:
    project_id = project_id or uuid.uuid4()
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
            await s.flush()
        # Through the control repository, because Boundary D refuses a direct
        # INSERT into schedules. Always planned enabled: a cursor transition
        # is refused for a schedule that cannot fire, so a schedule that is
        # meant to end up disabled is retired after its cursor is placed.
        row = await ScheduleControlRepository(s).create_current(
            project_id=project_id,
            data={
                "engine": "celery",
                "scheduler": "z4j-scheduler",
                "name": "sched",
                "task_name": "myapp.tasks.t",
                "kind": kind.value,
                "expression": expression,
                "timezone": "UTC",
                "args": [],
                "kwargs": {},
                "is_enabled": True,
            },
            planning_at=created,
        )
        schedule_id = row.id
        await s.commit()
    if last_run_at is not None:
        await _advance_cursor(
            db,
            project_id=project_id,
            schedule_id=schedule_id,
            to=last_run_at,
        )
    if not enabled:
        async with db.session() as s:
            await ScheduleControlRepository(s).update_current(
                project_id=project_id,
                schedule_id=schedule_id,
                data={"is_enabled": False},
                planning_at=NOW,
            )
            await s.commit()
    if paused:
        # Through set_paused, not by assigning the column: Boundary D refuses a
        # direct write, and a hold placed any other way is not the hold the
        # product creates.
        async with db.session() as s:
            await ScheduleControlRepository(s).set_paused(
                project_id=project_id,
                schedule_id=schedule_id,
                paused=True,
                occurred_at=NOW,
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
        # The other half of ``test_never_fired_uses_created_at_anchor``. This
        # schedule HAS fired, so the alert must name the fire it went stale
        # after; without this the null branch is the only one anything pins.
        assert rows[0].audit_metadata["last_run_at"] == (NOW - timedelta(minutes=5)).isoformat()

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
        # Anchored on ``created_at`` rather than a placed cursor: neither kind
        # can take a cursor transition (a clocked row that has already fired
        # has no successor slot to expect), and the detector skips on kind
        # before it ever reads the anchor, so the skip is what is under test
        # either way. The solar expression is the real ``event:lat:lon`` form
        # because the cadence domain refuses anything else.
        await _seed_schedule(
            db,
            kind=ScheduleKind.SOLAR,
            expression="sunrise:51.5074:-0.1278",
            last_run_at=None,
            created_at=NOW - timedelta(days=2),
        )
        await _seed_schedule(
            db,
            kind=ScheduleKind.CLOCKED,
            expression="2020-01-01T00:00:00Z",
            last_run_at=None,
            created_at=NOW - timedelta(days=2),
        )
        await _detector(db, settings).tick()
        assert await _misfire_rows(db) == []

    @pytest.mark.asyncio
    async def test_bad_interval_expression_skipped(
        self,
        create_all_db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # Deliberately NOT on the migrated schema. An enabled schedule whose
        # interval expression does not parse is a state the product refuses to
        # create (``create_current`` raises ScheduleCadenceError), so there is
        # no seed path to it on an activated database. The row can still exist
        # in the field -- it predates the guards, or arrived by promotion -- and
        # the detector must skip rather than raise or guess, which is precisely
        # what this pins. Converting it would mean deleting the case.
        await _seed_schedule_directly(
            create_all_db,
            expression="garbage",
            last_run_at=NOW - timedelta(hours=1),
        )
        await _detector(create_all_db, settings).tick()
        assert await _misfire_rows(create_all_db) == []

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
        project_id, sched_id = await _seed_schedule(
            db,
            expression="60s",
            last_run_at=NOW - timedelta(hours=1),
        )
        detector = _detector(db, settings)
        await detector.tick()
        assert len(await _misfire_rows(db)) == 1

        # Simulate a fire that then goes stale again: advance
        # last_run_at (new gap) but still older than cadence+grace.
        await _advance_cursor(
            db,
            project_id=project_id,
            schedule_id=sched_id,
            to=NOW - timedelta(minutes=30),
        )
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


class TestAHeldScheduleIsNotAMisfire:
    """Pausing is an operator saying "stop", not the scheduler failing.

    Pause deliberately leaves is_enabled true and freezes last_run_at, and
    last_run_at is exactly what this detector anchors on. So every hold looked
    like a schedule that had gone stale: an audit row with result "failed", a
    schedule.misfired automation, and fanout to every delivery channel. One
    deliberate action reading as a credible outage, during an incident, which
    is precisely when nobody needs a second alarm.
    """

    @pytest.mark.asyncio
    async def test_a_paused_schedule_raises_no_misfire(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        await _seed_schedule(
            db,
            expression="60s",
            last_run_at=NOW - timedelta(minutes=5),
            paused=True,
        )
        await _detector(db, settings).tick()
        assert await _misfire_rows(db) == []

    @pytest.mark.asyncio
    async def test_the_same_schedule_unheld_does_misfire(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        """The positive control, so the fix suppresses rather than loses."""
        await _seed_schedule(
            db,
            expression="60s",
            last_run_at=NOW - timedelta(minutes=5),
        )
        await _detector(db, settings).tick()
        assert len(await _misfire_rows(db)) == 1


class TestCronNextFireReadsThePinnedTzdb:
    """The detector must resolve zones from the tzdb the scheduler ticks with.

    ``cron_next_fire`` used bare ``ZoneInfo``, which searches the host's
    ``/usr/share/zoneinfo`` before the release-pinned ``tzdata`` wheel, while
    the engine it claims to match (``z4j_scheduler.tick.cron``) and the
    brain's own ``canonical_next_run_at`` both read the wheel only.

    The shipped image really does disagree with the pin:
    ``python:3.14-slim-trixie`` carries IANA 2026b against the wheel's 2026a,
    and measured across every available zone they differ on exactly one,
    ``America/Vancouver``, from 2026-11-01. For that zone this function
    computed an expected fire an hour away from the one the scheduler
    actually produces, so the detector raised
    ``scheduler.misfire_detected`` -- plus a
    ``schedule.misfired`` automation and its delivery fanout -- for a
    schedule that was running exactly on time. The module's headline
    property is "No false positives", and the detector is on by default.

    The assertion is on the SOURCE, not on an offset, for the same reason as
    the equivalent scheduler test: the two tzdbs agree for almost every zone
    and date, so an offset assertion would pass on this machine while the bug
    was live. Windows has an empty TZPATH, which makes an offset check
    meaningless there entirely.
    """

    def test_resolves_through_the_packaged_wheel(self, monkeypatch) -> None:
        import z4j_brain.domain.schedule_runtime as runtime_module

        seen: list[str] = []
        real = runtime_module.packaged_zoneinfo

        def spy(key: str):
            seen.append(key)
            return real(key)

        monkeypatch.setattr(runtime_module, "packaged_zoneinfo", spy)
        assert cron_next_fire("0 * * * *", "America/Vancouver", NOW) is not None
        assert "America/Vancouver" in seen, (
            "cron_next_fire did not resolve through packaged_zoneinfo, so the "
            "misfire bound can diverge from the fire the scheduler produces"
        )

    def test_matches_the_scheduler_engine_including_a_fractional_offset(self) -> None:
        """Detector and engine must agree, and the inputs must be able to tell.

        A first version of this asserted parity over ``0 * * * *`` for
        Vancouver, Casablanca and UTC, and was vacuous: an hourly cron in
        three whole-hour-offset zones yields the identical instant, so the
        assertion held even with the ``timezone`` argument discarded
        entirely. Sabotaging ``cron_next_fire`` to ignore its zone still
        passed it.

        Two changes fix that. ``0 3 * * *`` is a LOCAL wall-clock time, so
        the resulting instant moves with the zone, and ``Asia/Kathmandu`` is
        +05:45, so an implementation that rounds to whole hours or silently
        falls back to UTC cannot coincidentally agree.

        Note what this can and cannot catch. It catches the zone being
        ignored, misapplied, or resolved under a different rule set. It
        CANNOT catch the original tzdb-source bug on a host whose tzdb
        matches the pinned wheel, and at ``NOW`` the two agree about
        Vancouver regardless -- five months before they diverge. Detecting
        the SOURCE is the spy test above; this one guards the arithmetic.
        """
        from z4j_scheduler.tick.cron import next_fire

        for zone in ("Asia/Kathmandu", "America/Vancouver", "Australia/Eucla", "UTC"):
            mine = cron_next_fire("0 3 * * *", zone, NOW)
            theirs = next_fire("0 3 * * *", zone, NOW)
            assert mine == theirs, (
                f"misfire detector and tick engine disagree for {zone}: {mine} vs {theirs}"
            )

    def test_the_parity_inputs_can_actually_discriminate(self) -> None:
        # Guards the guard. If these inputs ever stop distinguishing zones,
        # the parity test above silently goes vacuous again, which is exactly
        # how its first version shipped.
        moments = {
            zone: cron_next_fire("0 3 * * *", zone, NOW)
            for zone in ("Asia/Kathmandu", "America/Vancouver", "Australia/Eucla", "UTC")
        }
        assert len(set(moments.values())) == len(moments), (
            "the parity inputs no longer distinguish timezones, so the test above "
            f"would pass with the zone ignored: {moments}"
        )
