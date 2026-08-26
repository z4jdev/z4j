"""Dead-trigger vapor-kill tests (1.7 trust shell).

Two triggers gained their real emit sites and two were trimmed:

- ``worker.offline`` -- the :class:`AgentHealthWorker` confirms an
  agent-offline EPISODE (no heartbeat past timeout + alert grace),
  writes ONE ``agent.offline_detected`` audit row per episode (durable
  cross-replica dedup, misfire-style), fires ``worker.offline``
  automation rules and fans out to ``agent.offline`` subscriptions.
- ``task.orphaned`` -- the reconciliation apply path
  (``CommandDispatcher._apply_reconciliation_result``) fires
  ``task.orphaned`` rules exactly once when it corrects a stuck task to
  the engine's TERMINAL truth (the idempotent state edge is the dedup).
- ``task.slow`` / ``queue.depth_exceeded`` -- removed from every
  subscribable / selectable surface (they never had an emit site).
  Stored rows carrying the removed strings must fail closed on the
  read path without crashing.

These run against a MIGRATED database rather than a create_all() one. The
offline episode is proven by an ``audit_log`` row, and every Boundary-F
guard on that table lives in a migration: a create_all() schema accepts an
unauthenticated audit row that an operator's database refuses outright.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.command_dispatcher import CommandDispatcher
from z4j_brain.domain.workers.agent_health import AgentHealthWorker
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import AgentState, ProjectRole, TaskState
from z4j_brain.persistence.models import (
    Agent,
    AgentOfflineAlert,
    AuditLog,
    AutomationRule,
    Membership,
    Project,
    Task,
    User,
    UserNotification,
    UserSubscription,
)
from z4j_brain.persistence.repositories import (
    AgentOfflineAlertRepository,
    AuditLogRepository,
    CommandRepository,
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
        # row that carries no chain authentication. Production always has this
        # configured; a test that omits it is not testing production.
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


class _FakeRegistry:
    async def deliver(self, *, command_id, agent_id, required_retry_engine=None) -> DeliveryResult:
        return DeliveryResult(
            delivered_locally=False,
            notified_cluster=True,
            agent_was_known=True,
        )


def _dispatcher(settings: Settings) -> CommandDispatcher:
    return CommandDispatcher(
        settings=settings,
        registry=_FakeRegistry(),  # type: ignore[arg-type]
        audit=AuditService(settings),
    )


async def _seed_agent(
    db: DatabaseManager,
    *,
    state: AgentState = AgentState.OFFLINE,
    last_seen_at: datetime | None,
    project_id: uuid.UUID | None = None,
    automation_enabled: bool = True,
) -> tuple[uuid.UUID, uuid.UUID]:
    project_id = project_id or uuid.uuid4()
    agent_id = uuid.uuid4()
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
        s.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="web-01",
                token_hash=secrets.token_hex(32),
                protocol_version="1",
                framework_adapter="django",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=state,
                last_seen_at=last_seen_at,
            ),
        )
        await s.commit()
    return project_id, agent_id


async def _seed_member_and_rule(
    db: DatabaseManager,
    project_id: uuid.UUID,
    *,
    trigger: str,
) -> uuid.UUID:
    """One OPERATOR member + one enabled notify rule on ``trigger``."""
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
                name=f"on-{trigger}",
                trigger=trigger,
                actions=[{"type": "notify"}],
            ),
        )
        await s.commit()
        return user.id


async def _claim_rows(db: DatabaseManager) -> list[AgentOfflineAlert]:
    async with db.session() as s:
        return list((await s.execute(select(AgentOfflineAlert))).scalars().all())


async def _offline_rows(db: DatabaseManager) -> list[AuditLog]:
    async with db.session() as s:
        rows = await s.execute(
            select(AuditLog).where(
                AuditLog.action == "agent.offline_detected",
            ),
        )
        return list(rows.scalars().all())


async def _fired_rows(db: DatabaseManager) -> list[AuditLog]:
    async with db.session() as s:
        rows = await s.execute(
            select(AuditLog).where(
                AuditLog.action == "automation.rule.fired",
            ),
        )
        return list(rows.scalars().all())


async def _notifications(db: DatabaseManager) -> list[UserNotification]:
    async with db.session() as s:
        return list((await s.execute(select(UserNotification))).scalars().all())


def _worker(db: DatabaseManager, settings: Settings, **kw) -> AgentHealthWorker:
    return AgentHealthWorker(
        db=db,
        settings=settings,
        audit=kw.pop("audit", AuditService(settings)),
        dispatcher=kw.pop("dispatcher", None),
        clock=kw.pop("clock", lambda: NOW),
    )


# =====================================================================
# worker.offline: detection + episode dedup
# =====================================================================


@pytest.mark.asyncio
class TestOfflineDetection:
    async def test_offline_agent_past_grace_alerts_once(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # Marked offline by the gateway close path 10 minutes ago (well
        # past timeout 30s + grace 60s). One episode -> ONE audit row,
        # even across repeated sweeps.
        _, agent_id = await _seed_agent(
            db,
            state=AgentState.OFFLINE,
            last_seen_at=NOW - timedelta(minutes=10),
        )
        worker = _worker(db, settings)
        await worker.tick()
        await worker.tick()
        rows = await _offline_rows(db)
        assert len(rows) == 1
        assert rows[0].target_id == str(agent_id)
        assert rows[0].audit_metadata["name"] == "web-01"
        assert rows[0].audit_metadata["offline_for_seconds"] > 0

    async def test_zombie_online_agent_is_flipped_and_alerted(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # Still state=online (zombie socket / dead brain worker) but the
        # heartbeat is long stale: the SAME tick flips the state AND
        # alerts the episode.
        _, agent_id = await _seed_agent(
            db,
            state=AgentState.ONLINE,
            last_seen_at=NOW - timedelta(minutes=10),
        )
        await _worker(db, settings).tick()
        async with db.session() as s:
            agent = await s.get(Agent, agent_id)
            assert agent.state == AgentState.OFFLINE
        assert len(await _offline_rows(db)) == 1

    async def test_within_alert_grace_not_alerted(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # Past the 30s offline timeout (so the badge flips) but inside
        # timeout + 60s alert grace: a deploy-restart blip, not a page.
        await _seed_agent(
            db,
            state=AgentState.OFFLINE,
            last_seen_at=NOW - timedelta(seconds=60),
        )
        await _worker(db, settings).tick()
        assert await _offline_rows(db) == []

    async def test_never_connected_agent_skipped(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # No heartbeat anchor -> no episode (nothing was ever lost).
        await _seed_agent(
            db,
            state=AgentState.OFFLINE,
            last_seen_at=None,
        )
        await _seed_agent(
            db,
            state=AgentState.UNKNOWN,
            last_seen_at=None,
        )
        await _worker(db, settings).tick()
        assert await _offline_rows(db) == []

    async def test_recovery_then_new_outage_is_fresh_episode(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        _, agent_id = await _seed_agent(
            db,
            state=AgentState.OFFLINE,
            last_seen_at=NOW - timedelta(minutes=30),
        )
        worker = _worker(db, settings)
        await worker.tick()
        assert len(await _offline_rows(db)) == 1

        # The agent reconnected (heartbeats advanced last_seen_at), then
        # died again: the anchor moved -> a fresh episode re-alerts.
        async with db.session() as s:
            await s.execute(
                update(Agent)
                .where(Agent.id == agent_id)
                .values(last_seen_at=NOW - timedelta(minutes=5)),
            )
            await s.commit()
        await worker.tick()
        assert len(await _offline_rows(db)) == 2

    async def test_dedup_is_durable_across_replicas(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # Two worker instances (= two brain replicas sharing one DB,
        # with independent in-memory state) alert a persistent episode
        # ONCE, not once each: the claim is durable in
        # agent_offline_alerts.
        await _seed_agent(
            db,
            state=AgentState.OFFLINE,
            last_seen_at=NOW - timedelta(minutes=10),
        )
        await _worker(db, settings).tick()
        await _worker(db, settings).tick()
        assert len(await _offline_rows(db)) == 1

    async def test_recovered_between_select_and_claim_not_alerted(
        self,
        db: DatabaseManager,
        settings: Settings,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # The worker SELECTs candidates in one session and claims
        # in another. An agent that reconnects in that gap (state back to
        # online, heartbeat anchor advanced) must NOT be minted a claim
        # row or a durable offline alert -- the conditional claim sees
        # the recovered row and inserts nothing.
        _, agent_id = await _seed_agent(
            db,
            state=AgentState.OFFLINE,
            last_seen_at=NOW - timedelta(minutes=10),
        )
        worker = _worker(db, settings)
        real_filter = worker._filter_unclaimed

        async def recover_then_filter(candidates):
            fresh = await real_filter(candidates)
            # The agent reconnects AFTER selection, BEFORE the claim.
            async with db.session() as s:
                await s.execute(
                    update(Agent)
                    .where(Agent.id == agent_id)
                    .values(state=AgentState.ONLINE, last_seen_at=NOW),
                )
                await s.commit()
            return fresh

        monkeypatch.setattr(worker, "_filter_unclaimed", recover_then_filter)
        await worker.tick()
        assert await _offline_rows(db) == []
        assert await _claim_rows(db) == []
        # And the recovered agent stays quiet on later sweeps too.
        await worker.tick()
        assert await _offline_rows(db) == []
        assert await _claim_rows(db) == []

    async def test_anchor_moved_between_select_and_claim_skips_stale_episode(
        self,
        db: DatabaseManager,
        settings: Settings,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Variant: the agent bounced in the gap (reconnected, then
        # died again) -- still offline at claim time but on a NEW anchor.
        # The stale-anchor claim must insert nothing; the CURRENT episode
        # alerts on a later sweep under its own anchor.
        new_anchor = NOW - timedelta(minutes=5)
        _, agent_id = await _seed_agent(
            db,
            state=AgentState.OFFLINE,
            last_seen_at=NOW - timedelta(minutes=30),
        )
        worker = _worker(db, settings)
        real_filter = worker._filter_unclaimed
        bounced = {"done": False}

        async def bounce_then_filter(candidates):
            fresh = await real_filter(candidates)
            if not bounced["done"]:
                bounced["done"] = True
                async with db.session() as s:
                    await s.execute(
                        update(Agent).where(Agent.id == agent_id).values(last_seen_at=new_anchor),
                    )
                    await s.commit()
            return fresh

        monkeypatch.setattr(worker, "_filter_unclaimed", bounce_then_filter)
        await worker.tick()
        assert await _offline_rows(db) == []
        assert await _claim_rows(db) == []

        # Next sweep sees the current episode and alerts it exactly once.
        await worker.tick()
        rows = await _offline_rows(db)
        assert len(rows) == 1
        claims = await _claim_rows(db)
        assert len(claims) == 1
        stored_anchor = claims[0].anchor_at
        if stored_anchor.tzinfo is None:  # SQLite round-trips naive UTC
            stored_anchor = stored_anchor.replace(tzinfo=UTC)
        assert stored_anchor == new_anchor

    async def test_alert_failure_releases_claim_for_retry(
        self,
        db: DatabaseManager,
        settings: Settings,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # A transient audit-write failure must not permanently swallow
        # the episode: the claim is released and the next sweep retries.
        await _seed_agent(
            db,
            state=AgentState.OFFLINE,
            last_seen_at=NOW - timedelta(minutes=10),
        )
        worker = _worker(db, settings)
        real_alert = worker._alert_offline
        calls = {"n": 0}

        async def flaky_alert(agent, *, now):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("simulated audit write failure")
            return await real_alert(agent, now=now)

        monkeypatch.setattr(worker, "_alert_offline", flaky_alert)
        await worker.tick()
        assert await _offline_rows(db) == []
        await worker.tick()
        assert len(await _offline_rows(db)) == 1

    async def test_sweep_only_mode_without_audit(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # No audit service wired (legacy construction): states still
        # flip, nothing alerts.
        _, agent_id = await _seed_agent(
            db,
            state=AgentState.ONLINE,
            last_seen_at=NOW - timedelta(minutes=10),
        )
        worker = AgentHealthWorker(db=db, settings=settings, clock=lambda: NOW)
        await worker.tick()
        async with db.session() as s:
            agent = await s.get(Agent, agent_id)
            assert agent.state == AgentState.OFFLINE
        assert await _offline_rows(db) == []


# =====================================================================
# worker.offline: claim retention (prune) semantics
# =====================================================================


@pytest.mark.asyncio
class TestOfflineClaimRetention:
    async def test_prune_keeps_ongoing_outage_claim_and_never_realerts(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # An agent down for 40 days was alerted once; its claim is
        # now past the 30-day retention window but the outage is UNCHANGED
        # (still offline, same heartbeat anchor). The prune must keep the
        # claim, and later sweeps must not re-alert the same episode.
        await _seed_agent(
            db,
            state=AgentState.OFFLINE,
            last_seen_at=NOW - timedelta(days=40),
        )
        worker = _worker(db, settings)
        await worker.tick()
        assert len(await _offline_rows(db)) == 1
        assert len(await _claim_rows(db)) == 1

        # Age the claim past retention. (created_at is server-set to the
        # test run's wall clock, so backdate it relative to NOW.)
        async with db.session() as s:
            await s.execute(
                update(AgentOfflineAlert).values(
                    created_at=NOW - timedelta(days=31),
                ),
            )
            await s.commit()

        # This sweep runs the prune with the claim age-eligible: the
        # episode is still active, so the claim survives ...
        await worker.tick()
        assert len(await _claim_rows(db)) == 1
        # ... and the sweep AFTER the prune still does not re-alert.
        await worker.tick()
        assert len(await _offline_rows(db)) == 1
        assert len(await _claim_rows(db)) == 1

    async def test_prune_drops_recovered_changed_anchor_and_deleted(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # Aged-out claims ARE dropped once their episode ended, in all
        # three end states: agent recovered, anchor moved (new episode),
        # agent row gone. Only the unchanged ongoing outage keeps its
        # claim.
        old_anchor = NOW - timedelta(days=10)
        stale_created = NOW - timedelta(days=31)

        # Recovered: back online on a fresh heartbeat.
        _, recovered_id = await _seed_agent(
            db,
            state=AgentState.ONLINE,
            last_seen_at=NOW,
        )
        # Bounced: still offline but the anchor moved (a NEW episode).
        _, bounced_id = await _seed_agent(
            db,
            state=AgentState.OFFLINE,
            last_seen_at=NOW - timedelta(days=1),
        )
        # Deleted: production FK enforcement cascades the ledger row before
        # prune runs, while the NOT EXISTS arm remains a harmless fallback for
        # historical databases that already contain an orphan.
        _, deleted_id = await _seed_agent(
            db,
            state=AgentState.OFFLINE,
            last_seen_at=old_anchor,
        )
        # Ongoing: still offline on the claim's exact anchor.
        _, ongoing_id = await _seed_agent(
            db,
            state=AgentState.OFFLINE,
            last_seen_at=old_anchor,
        )
        async with db.session() as s:
            for agent_id in (recovered_id, bounced_id, deleted_id, ongoing_id):
                s.add(
                    AgentOfflineAlert(
                        agent_id=agent_id,
                        anchor_at=old_anchor,
                        created_at=stale_created,
                    ),
                )
            await s.flush()
            await s.execute(delete(Agent).where(Agent.id == deleted_id))
            await s.commit()

        async with db.session() as s:
            pruned = await AgentOfflineAlertRepository(s).prune(
                older_than=NOW - timedelta(days=30),
            )
            await s.commit()

        assert pruned == 2
        remaining = await _claim_rows(db)
        assert [c.agent_id for c in remaining] == [ongoing_id]

    async def test_prune_age_gate_keeps_fresh_ended_episode_claims(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # A claim INSIDE the retention window is never pruned, even when
        # its episode already ended: the age gate is unchanged, recovery
        # alone does not force an early delete.
        _, agent_id = await _seed_agent(
            db,
            state=AgentState.ONLINE,
            last_seen_at=NOW,
        )
        async with db.session() as s:
            s.add(
                AgentOfflineAlert(
                    agent_id=agent_id,
                    anchor_at=NOW - timedelta(days=2),
                    created_at=NOW - timedelta(days=2),
                ),
            )
            await s.commit()

        async with db.session() as s:
            pruned = await AgentOfflineAlertRepository(s).prune(
                older_than=NOW - timedelta(days=30),
            )
            await s.commit()

        assert pruned == 0
        assert len(await _claim_rows(db)) == 1


# =====================================================================
# worker.offline: automation + subscription fan-out
# =====================================================================


@pytest.mark.asyncio
class TestOfflineAutomation:
    async def test_offline_fires_worker_offline_rule(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        project_id, agent_id = await _seed_agent(
            db,
            state=AgentState.OFFLINE,
            last_seen_at=NOW - timedelta(minutes=10),
        )
        await _seed_member_and_rule(db, project_id, trigger="worker.offline")
        await _worker(db, settings, dispatcher=_dispatcher(settings)).tick()

        notes = await _notifications(db)
        fired = await _fired_rows(db)
        assert len(notes) == 1
        assert notes[0].reason == "automation"
        assert notes[0].trigger == "worker.offline"
        assert len(fired) == 1
        assert fired[0].audit_metadata["trigger"] == "worker.offline"
        assert fired[0].audit_metadata["agent_id"] == str(agent_id)

    async def test_kill_switch_suppresses_firing(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        project_id, _ = await _seed_agent(
            db,
            state=AgentState.OFFLINE,
            last_seen_at=NOW - timedelta(minutes=10),
            automation_enabled=False,
        )
        await _seed_member_and_rule(db, project_id, trigger="worker.offline")
        await _worker(db, settings, dispatcher=_dispatcher(settings)).tick()

        assert await _notifications(db) == []
        assert await _fired_rows(db) == []
        # Detection is still audited (the kill switch gates ACTIONS,
        # never visibility).
        assert len(await _offline_rows(db)) == 1


@pytest.mark.asyncio
class TestOfflineSubscription:
    async def test_offline_notifies_agent_offline_subscriber(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # A user subscribed to agent.offline (in-app) gets a bell
        # notification -- via the operator-facing subscription channels,
        # independent of automation rules (dispatcher=None here).
        project_id, agent_id = await _seed_agent(
            db,
            state=AgentState.OFFLINE,
            last_seen_at=NOW - timedelta(minutes=10),
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
                    trigger="agent.offline",
                    filters={},
                    in_app=True,
                    project_channel_ids=[],
                    user_channel_ids=[],
                    cooldown_seconds=0,
                ),
            )
            await s.commit()

        await _worker(db, settings).tick()

        notes = await _notifications(db)
        assert len(notes) == 1
        assert notes[0].reason == "subscribed"
        assert notes[0].trigger == "agent.offline"
        assert notes[0].data["task_id"] == str(agent_id)
        # The bell routes on resource_type; without the stamp an
        # offline alert deep-links to a nonexistent task page
        # (round-4 LOW).
        assert notes[0].data["resource_type"] == "agent"


# =====================================================================
# task.orphaned: reconciliation apply path
# =====================================================================


async def _seed_stuck_task(
    db: DatabaseManager,
    project_id: uuid.UUID,
    *,
    task_id: str = "stuck-1",
    state: TaskState = TaskState.STARTED,
) -> None:
    async with db.session() as s:
        s.add(
            Task(
                project_id=project_id,
                engine="celery",
                task_id=task_id,
                name="myapp.tasks.flaky",
                queue="default",
                state=state,
                started_at=NOW - timedelta(hours=1),
            ),
        )
        await s.commit()


async def _reconcile_result(
    db: DatabaseManager,
    dispatcher: CommandDispatcher,
    *,
    project_id: uuid.UUID,
    agent_id: uuid.UUID,
    task_id: str,
    engine_state: str,
) -> None:
    """Insert a ``reconcile_task`` command and hand its result to the
    dispatcher, exactly as the frame router does.

    The result is applied in its own ``write=True`` session because that is
    what ``FrameRouter._run_control_persist`` opens. On SQLite that session
    begins with BEGIN IMMEDIATE, which the audit chain requires before its
    first read; the older single-plain-session shape here only worked because
    a create_all() database had no chain to satisfy.
    """
    async with db.session() as s:
        cmd, _ = await CommandRepository(s).insert(
            project_id=project_id,
            agent_id=agent_id,
            issued_by=None,
            action="reconcile_task",
            target_type="task",
            target_id=task_id,
            payload={"task_id": task_id, "engine": "celery"},
            idempotency_key=None,
            timeout_at=NOW + timedelta(seconds=60),
            source_ip=None,
        )
        await s.commit()
        command_id = cmd.id

    async with db.session(write=True) as s:
        await dispatcher.handle_result(
            commands=CommandRepository(s),
            audit_log=AuditLogRepository(s),
            command_id=command_id,
            status="success",
            result_payload={
                "engine_state": engine_state,
                "exception": "lost terminal event",
            },
            error=None,
            project_id=project_id,
            agent_id=agent_id,
        )
        await s.commit()


@pytest.mark.asyncio
class TestOrphanedEmission:
    async def test_terminal_reconcile_fires_task_orphaned_rule_once(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        project_id, agent_id = await _seed_agent(
            db,
            state=AgentState.ONLINE,
            last_seen_at=NOW,
        )
        await _seed_stuck_task(db, project_id)
        await _seed_member_and_rule(db, project_id, trigger="task.orphaned")
        dispatcher = _dispatcher(settings)

        await _reconcile_result(
            db,
            dispatcher,
            project_id=project_id,
            agent_id=agent_id,
            task_id="stuck-1",
            engine_state="failure",
        )

        # The stuck task was corrected to the engine's terminal truth...
        async with db.session() as s:
            task = (await s.execute(select(Task).where(Task.task_id == "stuck-1"))).scalars().one()
            assert task.state == TaskState.FAILURE
        # ...the correction is audited, and the task.orphaned rule fired.
        notes = await _notifications(db)
        fired = await _fired_rows(db)
        assert len(notes) == 1
        assert notes[0].reason == "automation"
        assert notes[0].trigger == "task.orphaned"
        assert len(fired) == 1
        assert fired[0].audit_metadata["trigger"] == "task.orphaned"
        assert fired[0].audit_metadata["task_id"] == "stuck-1"

        # REPLAY: a second probe result for the same (now-corrected) task
        # is a no-op edge -> no duplicate firing.
        await _reconcile_result(
            db,
            dispatcher,
            project_id=project_id,
            agent_id=agent_id,
            task_id="stuck-1",
            engine_state="failure",
        )
        assert len(await _notifications(db)) == 1
        assert len(await _fired_rows(db)) == 1

    async def test_nonterminal_reconcile_does_not_fire(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # A probe that finds the task legitimately RUNNING corrects the
        # snapshot (pending -> started) but that is not an orphan.
        project_id, agent_id = await _seed_agent(
            db,
            state=AgentState.ONLINE,
            last_seen_at=NOW,
        )
        await _seed_stuck_task(db, project_id, state=TaskState.PENDING)
        await _seed_member_and_rule(db, project_id, trigger="task.orphaned")

        await _reconcile_result(
            db,
            _dispatcher(settings),
            project_id=project_id,
            agent_id=agent_id,
            task_id="stuck-1",
            engine_state="started",
        )

        async with db.session() as s:
            task = (await s.execute(select(Task).where(Task.task_id == "stuck-1"))).scalars().one()
            assert task.state == TaskState.STARTED
        assert await _notifications(db) == []
        assert await _fired_rows(db) == []

    async def test_stale_pending_response_cannot_regress_terminal_or_refire(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # Pre-fix, a late "pending" probe response overwrote a
        # terminal task back to PENDING (finished_at retained), and the
        # next terminal response then looked like a fresh correction,
        # firing task.orphaned a second time (duplicate destructive
        # retry via automation). Post-fix the terminal row is immutable
        # to reconciliation: no state change, no task.reconciled audit
        # row, no re-fire.
        project_id, agent_id = await _seed_agent(
            db,
            state=AgentState.ONLINE,
            last_seen_at=NOW,
        )
        await _seed_stuck_task(db, project_id)
        await _seed_member_and_rule(db, project_id, trigger="task.orphaned")
        dispatcher = _dispatcher(settings)

        async def _reconciled_audit_rows() -> list[AuditLog]:
            async with db.session() as s:
                rows = await s.execute(
                    select(AuditLog).where(AuditLog.action == "task.reconciled"),
                )
                return list(rows.scalars().all())

        # Probe result 1: the engine's terminal truth. Fires once.
        await _reconcile_result(
            db,
            dispatcher,
            project_id=project_id,
            agent_id=agent_id,
            task_id="stuck-1",
            engine_state="failure",
        )
        assert len(await _fired_rows(db)) == 1
        assert len(await _reconciled_audit_rows()) == 1

        # Probe result 2: a STALE "pending" response arrives after the
        # terminal correction. Terminal is terminal - rejected.
        await _reconcile_result(
            db,
            dispatcher,
            project_id=project_id,
            agent_id=agent_id,
            task_id="stuck-1",
            engine_state="pending",
        )
        async with db.session() as s:
            task = (await s.execute(select(Task).where(Task.task_id == "stuck-1"))).scalars().one()
            assert task.state == TaskState.FAILURE
        assert len(await _fired_rows(db)) == 1
        assert len(await _notifications(db)) == 1
        # The rejection produced NO "correction" audit row.
        assert len(await _reconciled_audit_rows()) == 1

        # Probe result 3: the terminal response replays. Pre-fix this
        # was the double-fire (PENDING -> FAILURE looked fresh); now it
        # is the already-matches no-op edge.
        await _reconcile_result(
            db,
            dispatcher,
            project_id=project_id,
            agent_id=agent_id,
            task_id="stuck-1",
            engine_state="failure",
        )
        async with db.session() as s:
            task = (await s.execute(select(Task).where(Task.task_id == "stuck-1"))).scalars().one()
            assert task.state == TaskState.FAILURE
        assert len(await _fired_rows(db)) == 1
        assert len(await _notifications(db)) == 1
        assert len(await _reconciled_audit_rows()) == 1


# =====================================================================
# Trimmed triggers: rejected at write time, fail closed for stored rows
# =====================================================================


class TestTrimmedTriggersRejected:
    def test_rule_grammar_rejects_trimmed_triggers(self) -> None:
        from z4j_brain.domain.automation import (
            DISPATCHED_TRIGGERS,
            TRIGGER_TYPES,
        )

        for trigger in ("task.slow", "queue.depth_exceeded"):
            assert trigger not in TRIGGER_TYPES
            assert trigger not in DISPATCHED_TRIGGERS
        # Every remaining grammar trigger has a live emit site: the
        # vapor gap (grammar-valid but never dispatched) is closed.
        assert set(TRIGGER_TYPES) == set(DISPATCHED_TRIGGERS)

    def test_rule_api_validator_rejects_trimmed_triggers(self) -> None:
        from z4j_brain.api.automation_rules import _validate_rule_spec
        from z4j_brain.errors import ValidationError

        for trigger in ("task.slow", "queue.depth_exceeded"):
            with pytest.raises(ValidationError):
                _validate_rule_spec(trigger, {}, [{"type": "notify"}])

    def test_rule_api_validator_accepts_newly_wired_triggers(self) -> None:
        from z4j_brain.api.automation_rules import _validate_rule_spec

        for trigger in ("worker.offline", "task.orphaned"):
            _validate_rule_spec(trigger, {}, [{"type": "notify"}])

    def test_subscription_schemas_reject_task_slow(self) -> None:
        import pydantic
        from z4j_brain.api.notifications import DefaultSubscriptionCreate
        from z4j_brain.api.user_notifications import UserSubscriptionCreate

        with pytest.raises(pydantic.ValidationError):
            DefaultSubscriptionCreate(trigger="task.slow")
        with pytest.raises(pydantic.ValidationError):
            UserSubscriptionCreate(
                project_id=uuid.uuid4(),
                trigger="task.slow",
            )
        # The still-real triggers stay accepted.
        DefaultSubscriptionCreate(trigger="agent.offline")
        UserSubscriptionCreate(project_id=uuid.uuid4(), trigger="agent.offline")


@pytest.mark.asyncio
class TestTrimmedTriggersFailClosed:
    async def test_stored_task_slow_rule_never_matches_and_never_crashes(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # A pre-trim rule row still in the DB: it loads fine, is listed
        # fine, and simply never matches any dispatched trigger.
        from z4j_brain.domain.automation import matching_rules

        project_id = uuid.uuid4()
        async with db.session() as s:
            s.add(Project(id=project_id, slug="legacy", name="Legacy"))
            await s.flush()
            s.add(
                AutomationRule(
                    project_id=project_id,
                    name="legacy-slow",
                    trigger="task.slow",
                    actions=[{"type": "notify"}],
                ),
            )
            await s.commit()

        async with db.session() as s:
            rules = (await s.execute(select(AutomationRule))).scalars().all()
        assert len(rules) == 1
        for trigger in ("task.failed", "worker.offline", "task.orphaned"):
            assert matching_rules(rules, trigger, {"task_id": "t"}) == []

    async def test_stored_task_slow_subscription_is_skipped_not_crashed(
        self,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        # A pre-trim subscription row: dispatching any REAL trigger
        # ignores it (trigger-keyed lookup) and nothing raises.
        from z4j_brain.domain.notifications.service import NotificationService

        project_id = uuid.uuid4()
        async with db.session() as s:
            s.add(Project(id=project_id, slug="legacy2", name="Legacy2"))
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
                    trigger="task.slow",
                    filters={},
                    in_app=True,
                    project_channel_ids=[],
                    user_channel_ids=[],
                    cooldown_seconds=0,
                ),
            )
            await s.commit()

        async with db.session() as s:
            dispatched = await NotificationService().evaluate_and_dispatch(
                session=s,
                project_id=project_id,
                trigger="task.failed",
                task_id="t-1",
                task_name="myapp.tasks.t",
            )
        assert dispatched == 0
        assert await _notifications(db) == []
