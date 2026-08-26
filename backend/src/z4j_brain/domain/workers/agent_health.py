"""``AgentHealthWorker`` - marks stale agents offline + alerts on the episode.

Every ``agent_health_sweep_seconds`` (default 10s) this worker:

1. Flips every agent whose ``last_seen_at`` is older than
   ``agent_offline_timeout_seconds`` from ``online`` to ``offline``.
   Single bulk UPDATE per tick. (The gateway's close handler flips
   cleanly-disconnected agents immediately; this sweep covers zombie
   sockets, partitions, and a brain worker that died before running
   its close handler.)
2. Detects confirmed-down offline EPISODES: agents ``offline`` with no
   heartbeat for ``agent_offline_timeout_seconds +
   agent_offline_alert_grace_seconds``, regardless of WHICH path
   flipped their state. For each newly detected episode it writes an
   ``agent.offline_detected`` audit row via the HMAC-chained log,
   fires any ``worker.offline`` automation rule through the same
   governed executor the task-event path uses, and fans the alert out
   to any ``agent.offline`` project subscription across the operator's
   delivery channels + in-app bell. This is the emit site for the
   ``worker.offline`` trigger -- an agent cannot report its own death,
   so detection lives brain-side (same rationale as the
   :class:`MisfireDetector`).

Safety properties (mirroring :class:`MisfireDetector`):

- **No flap alerts.** The grace absorbs deploy restarts and reconnect
  blips: an agent back online within timeout + grace never alerts.
  The dashboard's state flip still happens at the plain timeout.
- **Alert once per offline episode.** Dedup is keyed by
  ``(agent_id, last_seen_at)`` -- the heartbeat anchor is frozen while
  the agent is down and advances only when it reconnects, so the next
  outage is a fresh episode. The claim is DURABLE + shared across
  replicas (``agent_offline_alerts``), so an agent that stays offline
  is alerted exactly once fleet-wide, across sweeps, restarts and HA
  failovers. The claim is also CONDITIONAL on the agents row still
  being offline on the same anchor at claim time, so an agent that
  reconnects between candidate selection and the claim gets no claim
  row and no false alert; and retention only prunes claims of ENDED
  episodes, so an unchanged ongoing outage is never re-alerted no
  matter how long it lasts.
- **Bounded per tick.** At most ``_MAX_OFFLINE_ALERTS_PER_SWEEP`` new
  episodes alert per sweep; the overflow self-heals on later ticks
  (its claim is still unrecorded).
- **Fault isolated.** One agent's audit/automation failure is logged
  and its claim released so the next sweep retries; the rest of the
  sweep continues. Automation firing and the subscription fanout are
  independent best-effort side effects of the committed detection.
- **Kill-switch aware.** Automation firing goes through
  ``AutomationExecutor.run_matching`` whose single rule-loading choke
  point honours the per-project ``automation_enabled`` flag.

Note that the in-memory ``BrainRegistry`` map is the source of
truth for "is the agent's WebSocket alive on this worker right
now"; the ``agents.state`` column is the dashboard's lagging
view of cluster-wide reachability.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

import structlog

if TYPE_CHECKING:
    from collections.abc import Callable

    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings


logger = structlog.get_logger("z4j.brain.workers.agent_health")

#: Cap on how many NEW offline episodes alert per sweep. A network
#: partition can take a whole fleet down at once; without a cap the
#: brain would write hundreds of audit rows and fan out hundreds of
#: rule firings in one tick. The durable claim means the overflow is
#: picked up on subsequent ticks, so nothing is lost -- it is spread
#: over a few sweeps.
_MAX_OFFLINE_ALERTS_PER_SWEEP = 100

#: How long a durable offline-alert claim is retained after its episode
#: ENDS. The prune only ever deletes claims whose episode is over (agent
#: recovered, heartbeat anchor moved, or agent row gone) -- the claim of
#: an unchanged ONGOING outage is kept regardless of age, so an agent
#: down for months still alerts exactly once, never again on claim
#: expiry. Ended-episode claims age out after this window, keeping the
#: ledger bounded. (Matches the misfire detector's retention window. The
#: AgentHygieneWorker now soft-revokes the agent row; that ends the live outage
#: predicate, so this retention sweep can remove the old claim without erasing
#: the agent's historical identity.)
_ALERT_RETENTION_DAYS = 30


class AgentHealthWorker:
    """Periodic agent-offline sweeper + offline-episode alerter."""

    def __init__(
        self,
        *,
        db: DatabaseManager,
        settings: Settings,
        audit: AuditService | None = None,
        dispatcher: object | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        """
        Args:
            db: Shared DatabaseManager.
            settings: Brain settings (timeout + grace + sweep knobs).
            audit: AuditService for the ``agent.offline_detected`` row
                and the automation firing chain. When None the worker
                only sweeps states and alerts nothing (legacy /
                sweep-only mode, used by some tests).
            dispatcher: CommandDispatcher for automation actions. When
                None the worker still DETECTS + audits offline episodes
                and notifies subscribers, but fires no automation rules.
            clock: Wall-clock source. Override in tests.
        """
        self._db = db
        self._settings = settings
        self._audit = audit
        self._dispatcher = dispatcher
        self._clock = clock

    async def tick(self) -> None:
        """One sweep: flip stale agents offline, then alert fresh episodes."""
        from z4j_brain.persistence.repositories import AgentRepository

        now = self._clock()
        cutoff = now - timedelta(
            seconds=self._settings.agent_offline_timeout_seconds,
        )
        async with self._db.session() as session:
            count = await AgentRepository(session).sweep_offline(cutoff=cutoff)
            await session.commit()
        if count:
            logger.info("z4j agent health sweep", marked_offline=count)

        if self._audit is None:
            return  # sweep-only mode: no audit chain to alert through

        await self._alert_offline_episodes(now=now)

    # ------------------------------------------------------------------
    # Offline-episode alerting (the ``worker.offline`` emit site)
    # ------------------------------------------------------------------

    async def _alert_offline_episodes(self, *, now: datetime) -> None:
        from z4j_brain.persistence.repositories import AgentRepository

        alert_cutoff = now - timedelta(
            seconds=(
                self._settings.agent_offline_timeout_seconds
                + self._settings.agent_offline_alert_grace_seconds
            ),
        )
        async with self._db.session() as session:
            candidates = await AgentRepository(session).list_offline_unseen_since(
                cutoff=alert_cutoff,
            )

        # Drop episodes already claimed (durable + shared) BEFORE the cap so
        # the per-sweep burst limit applies to FRESH episodes and the
        # remainder self-heals over subsequent sweeps. Best-effort pre-filter
        # -- the per-episode claim below is still the authoritative
        # cross-replica dedup, so a filter miss can never double-alert.
        fresh = await self._filter_unclaimed(candidates)

        capped = fresh[:_MAX_OFFLINE_ALERTS_PER_SWEEP]
        for agent in capped:
            # The episode key is (agent_id, last_seen_at): the heartbeat
            # anchor is frozen while the agent is down and advances only
            # when it reconnects, so a persistent outage is one episode
            # and the next outage is a fresh one. Only the replica that
            # WINS the durable claim alerts.
            anchor_at = agent.last_seen_at
            try:
                if not await self._claim_episode(agent.id, anchor_at):
                    # Already alerted for this episode, OR the agent
                    # recovered between the candidate SELECT above and
                    # the claim (the episode ended; nothing to alert).
                    continue
            except Exception:
                logger.exception(
                    "z4j agent health: claim failed",
                    agent_id=str(agent.id),
                )
                continue
            try:
                await self._alert_offline(agent, now=now)
                # Operators alert on metrics, not the audit log: bump a
                # counter so a dying fleet is visible on a dashboard, not
                # only by scraping audit rows. Best-effort.
                try:
                    from z4j_brain.api.metrics import (
                        z4j_agents_offline_detected_total,
                    )

                    z4j_agents_offline_detected_total.labels(
                        project=str(agent.project_id),
                    ).inc()
                except Exception:
                    from z4j_brain.api.metrics import record_swallowed

                    record_swallowed("agent_health", "offline_metric")
            except Exception:
                logger.exception(
                    "z4j agent health: failed to alert offline episode",
                    agent_id=str(agent.id),
                )
                # Release the claim so a transient alert failure does not
                # permanently swallow this episode -- next sweep retries.
                await self._release_episode(agent.id, anchor_at)

        # Retention: drop aged-out claims of ENDED episodes so the dedup
        # ledger stays bounded. An ongoing outage keeps its claim so it
        # is never re-alerted, however long it lasts.
        await self._prune_claims(now)

        if capped:
            logger.warning(
                "z4j agent health: %d offline episode(s) alerted this sweep "
                "(%d fresh, %d over per-sweep cap)",
                len(capped),
                len(fresh),
                max(0, len(fresh) - len(capped)),
            )

    async def _filter_unclaimed(self, candidates: list[Any]) -> list[Any]:
        """Drop candidates whose current episode is already claimed."""
        if not candidates:
            return []
        from z4j_brain.persistence.repositories import (
            AgentOfflineAlertRepository,
        )

        agent_ids = {a.id for a in candidates}
        async with self._db.session() as session:
            claimed = await AgentOfflineAlertRepository(session).existing_claims(
                agent_ids=agent_ids,
            )
        return [agent for agent in candidates if (agent.id, agent.last_seen_at) not in claimed]

    async def _claim_episode(self, agent_id: UUID, anchor_at: datetime) -> bool:
        """Durably claim an offline episode across the replica fleet.

        Returns True only for the replica that wins the claim (which then
        alerts); False if another replica or an earlier sweep already
        claimed it, or if the agent recovered since the candidate SELECT
        (the claim is conditional on the agents row still being offline
        on the same anchor, so a reconnect in the gap yields no claim row
        and no false alert). Committed in its own transaction so the
        claim is visible to other replicas immediately.
        """
        from z4j_brain.persistence.repositories import (
            AgentOfflineAlertRepository,
        )

        async with self._db.session() as session:
            claimed = await AgentOfflineAlertRepository(session).claim(
                agent_id=agent_id,
                anchor_at=anchor_at,
            )
            if claimed:
                await session.commit()
            return claimed

    async def _release_episode(self, agent_id: UUID, anchor_at: datetime) -> None:
        """Release a claim after a failed alert so the next sweep retries."""
        from z4j_brain.persistence.repositories import (
            AgentOfflineAlertRepository,
        )

        try:
            async with self._db.session() as session:
                await AgentOfflineAlertRepository(session).release(
                    agent_id=agent_id,
                    anchor_at=anchor_at,
                )
                await session.commit()
        except Exception:
            logger.exception(
                "z4j agent health: failed to release claim",
                agent_id=str(agent_id),
            )

    async def _prune_claims(self, now: datetime) -> None:
        """Best-effort retention: drop aged-out claims of ENDED episodes.

        A claim whose agent is STILL offline on the same heartbeat anchor
        is kept regardless of age -- pruning it would re-alert an
        unchanged ongoing outage on the next sweep.
        """
        from z4j_brain.persistence.repositories import (
            AgentOfflineAlertRepository,
        )

        try:
            async with self._db.session() as session:
                await AgentOfflineAlertRepository(session).prune(
                    older_than=now - timedelta(days=_ALERT_RETENTION_DAYS),
                )
                await session.commit()
        except Exception:
            from z4j_brain.api.metrics import record_swallowed

            record_swallowed("agent_health", "claim_prune")

    async def _alert_offline(self, agent: Any, *, now: datetime) -> None:
        """Write the detection audit row + fire worker.offline rules."""
        from z4j_brain.persistence.repositories import AuditLogRepository

        audit = self._audit
        if audit is None:  # tick() gates this; narrow for the type checker
            return
        last_seen = _as_utc(agent.last_seen_at)
        offline_for = (now - last_seen).total_seconds() if last_seen else None
        async with self._db.session(write=True) as session:
            await audit.record(
                AuditLogRepository(session),
                action="agent.offline_detected",
                target_type="agent",
                target_id=str(agent.id),
                result="failed",
                outcome="error",
                project_id=agent.project_id,
                metadata={
                    "name": agent.name,
                    "framework_adapter": agent.framework_adapter,
                    "engine_adapters": list(agent.engine_adapters or []),
                    "last_seen_at": (last_seen.isoformat() if last_seen else None),
                    "offline_for_seconds": (
                        round(offline_for, 3) if offline_for is not None else None
                    ),
                    "timeout_seconds": self._settings.agent_offline_timeout_seconds,
                    "grace_seconds": self._settings.agent_offline_alert_grace_seconds,
                },
            )
            await session.commit()

        logger.warning(
            "z4j agent health: AGENT OFFLINE agent_id=%s name=%r last_seen=%s",
            agent.id,
            agent.name,
            last_seen.isoformat() if last_seen else None,
        )

        # The detection audit is committed and the episode claim is HELD, so
        # this episode is recorded exactly once. Automation firing and the
        # subscription fanout are INDEPENDENT best-effort side effects: a
        # failure in either must NOT propagate (which would release the
        # claim and write a DUPLICATE audit row next sweep) nor block the
        # other. Same isolation the misfire detector uses.
        try:
            await self._fire_automation(agent, now=now)
        except Exception:
            logger.exception(
                "z4j agent health: worker.offline automation failed (audited; not re-run)",
                agent_id=str(agent.id),
            )
        await self._dispatch_subscription_notification(agent, offline_for=offline_for)

    async def _fire_automation(self, agent: Any, *, now: datetime) -> None:
        """Run ``worker.offline`` automation rules for one agent.

        No-op when no dispatcher is wired (detection-only mode). The
        executor owns its per-rule transaction boundary + the per-project
        kill-switch check, exactly as on the task-event path.
        """
        if self._dispatcher is None:
            return
        from z4j_brain.domain.automation import (
            AutomationActionRunner,
            AutomationExecutor,
        )
        from z4j_brain.persistence.repositories.audit_log import (
            AuditLogRepository,
        )
        from z4j_brain.persistence.repositories.automation_rule import (
            AutomationRuleRepository,
        )

        last_seen = _as_utc(agent.last_seen_at)
        fields: dict[str, Any] = {
            # An offline agent is the ABSENCE of a heartbeat, so there is
            # no task context; retry / cancel actions on a worker.offline
            # rule resolve to "no_target" in the runner. agent_id / the
            # extra agent_* keys are context for notify templates and
            # audit attribution.
            "task_id": None,
            "task_name": None,
            "engine": None,
            "queue": None,
            "priority": None,
            "exception": (
                f"agent '{agent.name}' offline; no heartbeat since "
                f"{last_seen.isoformat() if last_seen else 'unknown'}"
            ),
            "runtime_ms": None,
            "agent_id": agent.id,
            "agent_name": agent.name,
        }
        executor = AutomationExecutor(
            audit=self._audit,
            runner=AutomationActionRunner(dispatcher=self._dispatcher),
        )
        async with self._db.session(write=True) as session:
            await executor.run_matching(
                session=session,
                rules_repo=AutomationRuleRepository(session),
                audit_log=AuditLogRepository(session),
                project_id=agent.project_id,
                trigger="worker.offline",
                fields=fields,
                now=now,
                notify_coalesce_seconds=self._settings.automation_notify_coalesce_seconds,
            )

    async def _dispatch_subscription_notification(
        self,
        agent: Any,
        *,
        offline_for: float | None,
    ) -> None:
        """Fan an ``agent.offline`` alert out to project subscriptions.

        This is the operator-facing path (the 7 delivery channels +
        in-app bell), independent of automation rules and of the command
        dispatcher -- so offline alerting works even in a brain that has
        no automation rules armed. Best-effort: a notification failure
        must never break detection, so it is caught and logged. Its own
        session because ``evaluate_and_dispatch`` opens deliveries that
        can outlast the detection write.
        """
        from z4j_brain.domain.notifications.service import (
            NotificationService,
        )

        try:
            async with self._db.session() as session:
                await NotificationService().evaluate_and_dispatch(
                    session=session,
                    project_id=agent.project_id,
                    trigger="agent.offline",
                    resource_type="agent",
                    # No task is involved; use the agent id + name so the
                    # bell row + deep link resolve to the agent.
                    task_id=str(agent.id),
                    task_name=agent.name,
                    engine=(agent.engine_adapters or [None])[0],
                    state="offline",
                    exception=(
                        f"no heartbeat for {int(offline_for)}s"
                        if offline_for is not None
                        else "no heartbeat"
                    ),
                )
        except Exception:
            logger.exception(
                "z4j agent health: subscription notification dispatch failed",
                agent_id=str(agent.id),
            )


def _as_utc(value: datetime | None) -> datetime | None:
    """Normalise a possibly-naive DB datetime to tz-aware UTC.

    Postgres returns tz-aware datetimes for ``DateTime(timezone=True)``
    columns; SQLite (test + homelab) returns naive ones. Treat naive as
    UTC so lateness math never mixes aware/naive operands.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


__all__ = ["AgentHealthWorker"]
