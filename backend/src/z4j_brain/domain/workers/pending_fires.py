"""``PendingFiresReplayWorker`` - drains the buffered-fire queue.

Phase 2 of the z4j-scheduler integration. When the scheduler fires
a schedule and no agent is online, the FireSchedule handler stores
the fire in :class:`PendingFire` rows instead of returning
``agent_offline``. This worker watches for matching agents coming
online and replays the buffered fires through the normal
:class:`CommandDispatcher.issue` path.

Per-tick algorithm:

1. Sweep expired buffers (``expires_at < now``). Best-effort - this
   is the catch-up window an operator considered acceptable; past
   it we drop.
2. Find ``(project_id, engine)`` pairs that have at least one
   buffered fire AND at least one online agent advertising that
   engine. Anything else can't be replayed yet.
3. For each pair, load buffered fires oldest-first. Apply the
   schedule's ``catch_up`` policy:
   - ``skip``: drop everything (no replay).
   - ``fire_one_missed``: keep only the latest per schedule_id.
   - ``fire_all_missed``: replay every fire in scheduled_for order.
4. Replay each kept fire via ``CommandDispatcher.issue`` using the
   exact same idempotency_key the scheduler originally used. The
   command pipeline naturally dedupes if a stale buffer + a fresh
   FireSchedule retry land at the same time.
5. Delete the buffer row after a successful issue (failed issue
   leaves it for the next tick).

Bounded work per tick: each ``(project, engine)`` pair processes at
most ``PENDING_FIRES_BATCH_SIZE`` buffered rows so a long outage
+ noisy schedules don't stall the worker for the whole sweep
window. Subsequent ticks drain the rest.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.domain.command_dispatcher import CommandDispatcher
    from z4j_brain.persistence.database import DatabaseManager

logger = logging.getLogger("z4j.brain.workers.pending_fires")

# Per-(project, engine) cap. With one online agent per project +
# engine pair this is "fires replayed per tick"; with many pairs
# it's "rows the worker churns through per tick". 200 is generous
# (10s ticks → 1200/min) without being a foot-gun for big batches.
_PENDING_FIRES_BATCH_SIZE = 200


class PendingFiresReplayWorker:
    """Periodic worker that replays buffered fires when agents return."""

    def __init__(
        self,
        *,
        db: DatabaseManager,
        dispatcher: CommandDispatcher,
        audit: AuditService | None = None,
        command_timeout_seconds: int = 60,
    ) -> None:
        self._db = db
        self._dispatcher = dispatcher
        self._audit = audit
        self._command_timeout_seconds = max(command_timeout_seconds, 1)

    async def tick(  # noqa: PLR0912, PLR0915  pending-fire dispatch sweep
        self,
        *,
        now: datetime | None = None,
    ) -> None:
        from sqlalchemy import select

        from z4j_brain.persistence.models import PendingFire
        from z4j_brain.persistence.repositories import (
            AgentRepository,
            AuditLogRepository,
            CommandRepository,
            PendingFiresRepository,
            ScheduleFireRepository,
            ScheduleRepository,
        )

        occurred_at = now or datetime.now(UTC)
        await self._tick_current(occurred_at)

        # Step 1: sweep expired legacy/unmarked buffers. Marked rows were
        # handled individually above; receipt-NULL marked evidence is retained
        # for its explicit operator exit.
        async with self._db.session() as session:
            expired = await PendingFiresRepository(session).delete_expired(
                now=occurred_at,
            )
            await session.commit()
        if expired:
            logger.info(
                "z4j.brain.workers.pending_fires: swept %d expired buffer(s)",
                expired,
            )

        # Step 2: find (project, engine) pairs that have buffered
        # fires. We keep this query small (DISTINCT on the index)
        # then filter against online agents per pair.
        async with self._db.session() as session:
            result = await session.execute(
                select(PendingFire.project_id, PendingFire.engine)
                .where(PendingFire.protocol_marker.is_(None))
                .distinct(),
            )
            pairs = list(result.all())

        if not pairs:
            return

        # Group engines per project so we only call list_online_for_project
        # once per project regardless of how many engines need replay.
        engines_by_project: dict[UUID, list[str]] = defaultdict(list)
        for project_id, engine in pairs:
            engines_by_project[project_id].append(engine)

        replayed_total = 0
        # Per-fire transaction so a crash mid-replay doesn't
        # leave the buffer row + the dispatcher state
        # inconsistent. With one outer session holding the
        # whole loop, ``dispatcher.issue`` commits internally
        # after each call - so each ``delete_by_fire_id`` would
        # run in a NEW unconfirmed transaction (the dispatcher's
        # commit having closed the previous one). A SIGKILL
        # between two successful issues would then leave some
        # buffer rows committed-deleted and others
        # queued-but-not-deleted, to be re-dispatched on next
        # tick. With per-fire commits, every successful
        # issue+delete is atomic from the buffer's perspective.
        for project_id, engines in engines_by_project.items():
            async with self._db.session() as session:
                agents = await AgentRepository(session).list_online_for_project(
                    project_id,
                )
            online_engines: set[str] = set()
            for agent in agents:
                for adapter in agent.engine_adapters or ():
                    online_engines.add(adapter)
            replayable = [e for e in engines if e in online_engines]
            if not replayable:
                # Nothing to do - no online agents for these
                # engines yet. Try again next tick.
                continue

            for engine in replayable:
                # Per-engine session for the list+catch-up read.
                async with self._db.session() as read_session:
                    pending_repo = PendingFiresRepository(read_session)
                    schedules_repo = ScheduleRepository(read_session)
                    fires = await pending_repo.list_for_replay(
                        project_id=project_id,
                        engine=engine,
                        limit=_PENDING_FIRES_BATCH_SIZE,
                    )
                    if not fires:
                        continue
                    fires, dropped_fire_ids = await self._apply_catch_up(
                        fires=fires,
                        schedules_repo=schedules_repo,
                    )

                # Delete the buffer rows the catch_up policy discarded
                # (skip: all; fire_one_missed: all but the latest; unknown
                # policy: all) in their OWN committed transaction. Without
                # this the dropped rows stay buffered and list_for_replay
                # re-surfaces them every tick, so fire_one_missed would
                # re-fire one missed occurrence per tick instead of exactly
                # one -- duplicate dispatch of a non-idempotent scheduled
                # job. A failure here just leaves them for the next tick.
                if dropped_fire_ids:
                    async with self._db.session() as drop_session:
                        drop_repo = PendingFiresRepository(drop_session)
                        for dropped_id in dropped_fire_ids:
                            await drop_repo.delete_by_fire_id(dropped_id)
                        await drop_session.commit()

                for fire in fires:
                    target_agent = next(
                        (a for a in agents if engine in (a.engine_adapters or ())),
                        None,
                    )
                    if target_agent is None:
                        # Lost the agent between the list and now.
                        # Leave the buffer; next tick will retry.
                        break
                    # NEW per-fire session: dispatcher.issue +
                    # delete_by_fire_id commit together. If the
                    # dispatch fails, the delete is rolled back
                    # and the buffer row remains. If both succeed,
                    # both are committed atomically.
                    async with self._db.session(write=True) as fire_session:
                        try:
                            command = await self._dispatcher.issue(
                                commands=CommandRepository(fire_session),
                                audit_log=AuditLogRepository(fire_session),
                                project_id=fire.project_id,
                                agent_id=target_agent.id,
                                action="schedule.fire",
                                target_type="schedule",
                                target_id=str(fire.schedule_id),
                                payload=fire.payload,
                                issued_by=None,
                                ip=None,
                                user_agent=None,
                                idempotency_key=(
                                    f"schedule:{fire.schedule_id}:fire:{fire.fire_id}"
                                ),
                            )
                            # A5: upgrade the buffered schedule_fires row to
                            # delivered on replay so the fire-history view
                            # reflects the dispatch immediately, instead of
                            # sitting at "buffered" until the ack lands.
                            # record() upserts on fire_id (buffered ->
                            # delivered is a valid upgrade; a missing row is
                            # inserted). Same fire_session so it commits
                            # atomically with the issue + buffer delete.
                            await ScheduleFireRepository(fire_session).record(
                                fire_id=fire.fire_id,
                                schedule_id=fire.schedule_id,
                                project_id=fire.project_id,
                                command_id=command.id,
                                status="delivered",
                                scheduled_for=fire.scheduled_for,
                            )
                            await PendingFiresRepository(
                                fire_session,
                            ).delete_by_fire_id(fire.fire_id)
                            await fire_session.commit()
                            replayed_total += 1
                        except Exception:
                            # The dispatcher already logged. Leave
                            # the buffer row; next tick retries
                            # (dedup is handled by
                            # commands.idempotency_key + ScheduleFire
                            # upgrade-on-conflict).
                            logger.exception(
                                "z4j.brain.workers.pending_fires: replay failed for fire_id=%s",
                                fire.fire_id,
                            )
                            await fire_session.rollback()
                            continue

        if replayed_total:
            logger.info(
                "z4j.brain.workers.pending_fires: replayed %d buffered fire(s)",
                replayed_total,
            )

    async def _tick_current(  # noqa: PLR0912
        self,
        occurred_at: datetime,
    ) -> None:
        """Expire/replay marked buffers through their fenced transitions."""

        from z4j_brain.persistence.enums import CommandStatus
        from z4j_brain.persistence.repositories import (
            AgentRepository,
            AuditLogRepository,
            PendingFiresRepository,
        )

        expired_total = 0
        async with self._db.session() as session:
            expired = await PendingFiresRepository(
                session,
            ).list_expired_current(now=occurred_at)
        for pending_id, state_nonce in expired:
            async with self._db.session(write=True) as session:
                transition = await PendingFiresRepository(
                    session,
                ).expire_current(
                    pending_id=pending_id,
                    expected_state_nonce=state_nonce,
                    occurred_at=occurred_at,
                )
                if transition.changed:
                    if self._audit is None:
                        raise RuntimeError(
                            "current pending-fire expiry requires AuditService",
                        )
                    pending = transition.pending
                    assert pending is not None
                    await self._audit.record(
                        AuditLogRepository(session),
                        action="schedule.fire.buffer_expired",
                        target_type="schedule",
                        target_id=str(pending.schedule_id),
                        result="expired",
                        outcome="failure",
                        project_id=pending.project_id,
                        metadata={
                            "fire_id": str(pending.fire_id),
                            "acceptance_revision": (pending.acceptance_revision),
                            "scheduled_for": str(pending.scheduled_for),
                        },
                    )
                    expired_total += 1
                await session.commit()

        async with self._db.session() as session:
            pending_rows = await PendingFiresRepository(
                session,
            ).list_current_for_replay(now=occurred_at)
        if not pending_rows:
            if expired_total:
                logger.info(
                    "z4j.brain.workers.pending_fires: expired %d current buffer(s)",
                    expired_total,
                )
            return

        agents_by_project = {}
        for project_id in {row.project_id for row in pending_rows}:
            async with self._db.session() as session:
                agents_by_project[project_id] = await AgentRepository(
                    session,
                ).list_online_for_project(project_id)

        replayed_total = 0
        stale_total = 0
        for pending in pending_rows:
            if pending.state_write_nonce is None:
                continue
            agent = next(
                (
                    candidate
                    for candidate in agents_by_project.get(
                        pending.project_id,
                        (),
                    )
                    if pending.engine in (candidate.engine_adapters or ())
                ),
                None,
            )
            if agent is None:
                continue
            async with self._db.session(write=True) as session:
                transition = await PendingFiresRepository(
                    session,
                ).replay_current(
                    pending_id=pending.id,
                    expected_state_nonce=pending.state_write_nonce,
                    agent_id=agent.id,
                    command_timeout_seconds=(self._command_timeout_seconds),
                    occurred_at=occurred_at,
                )
                if transition.changed:
                    if self._audit is None:
                        raise RuntimeError(
                            "current pending-fire replay requires AuditService",
                        )
                    consumed = transition.pending
                    assert consumed is not None
                    await self._audit.record(
                        AuditLogRepository(session),
                        action=(
                            "schedule.fire.buffer_replayed"
                            if transition.command is not None
                            else "schedule.fire.buffer_stale"
                        ),
                        target_type="schedule",
                        target_id=str(consumed.schedule_id),
                        result=transition.disposition,
                        outcome=("allow" if transition.command is not None else "failure"),
                        project_id=consumed.project_id,
                        metadata={
                            "fire_id": str(consumed.fire_id),
                            "command_id": (
                                str(transition.command.id)
                                if transition.command is not None
                                else None
                            ),
                            "acceptance_revision": (consumed.acceptance_revision),
                        },
                    )
                    replayed_total += int(
                        transition.command is not None,
                    )
                    stale_total += int(
                        transition.command is None,
                    )
                command = transition.command
                await session.commit()
            if command is not None and command.status == CommandStatus.PENDING:
                try:
                    await self._dispatcher.deliver_persisted(
                        command_id=command.id,
                        agent_id=agent.id,
                        action=command.action,
                        payload=command.payload,
                    )
                except Exception:
                    logger.exception(
                        "z4j.brain.workers.pending_fires: current "
                        "post-commit delivery failed for command_id=%s",
                        command.id,
                    )

        if expired_total or replayed_total or stale_total:
            logger.info(
                "z4j.brain.workers.pending_fires: current transitions "
                "expired=%d replayed=%d stale=%d",
                expired_total,
                replayed_total,
                stale_total,
            )

    @staticmethod
    async def _apply_catch_up(
        *,
        fires: list,
        schedules_repo,
    ) -> tuple[list, list]:
        """Filter the buffered fire list per each schedule's catch_up policy.

        - ``skip``: produce no fires for that schedule.
        - ``fire_one_missed``: produce only the most recent fire.
        - ``fire_all_missed``: produce all fires in order.

        Returns ``(kept, dropped_fire_ids)``. ``kept`` is the fires to
        replay; ``dropped_fire_ids`` are the buffer rows the policy
        discarded, which the caller deletes in a committed transaction so
        a subsequent tick does not re-evaluate them (otherwise a dropped
        occurrence is re-listed and re-fired every tick). Schedules that
        no longer exist are left untouched -- the ``schedule_id`` CASCADE
        or the retention sweep clears them.

        Performance: schedule lookups are batched into ONE query
        (``WHERE id IN (...)``) so a 100-schedule replay batch costs
        one SELECT instead of 100. The previous implementation did
        a per-schedule ``.get()`` which was an O(N) round-trip
        storm at scale - audit-Phase2-1 caught it before Phase 3.
        """
        from sqlalchemy import select

        from z4j_brain.persistence.models import Schedule

        # Group by schedule.
        per_schedule: dict[UUID, list] = defaultdict(list)
        for fire in fires:
            per_schedule[fire.schedule_id].append(fire)

        if not per_schedule:
            return [], []

        # Single batched lookup for every distinct schedule_id in
        # the replay batch. SQLAlchemy turns the IN-list into one
        # parameterized query.
        result = await schedules_repo.session.execute(
            select(Schedule).where(Schedule.id.in_(per_schedule.keys())),
        )
        schedules_by_id = {s.id: s for s in result.scalars().all()}

        kept: list = []
        dropped_fire_ids: list = []
        for schedule_id, schedule_fires in per_schedule.items():
            schedule = schedules_by_id.get(schedule_id)
            if schedule is None:
                # Schedule was deleted while fires were buffered.
                # The CASCADE on schedule_id should have already
                # cleared them; if not, leave them for the sweep.
                continue
            if not getattr(schedule, "is_enabled", True):
                # The operator DISABLED the schedule during the outage.
                # is_enabled is otherwise only enforced at fire/buffer
                # time, so without this a disable would not stop buffered
                # fires from replaying once agents return -- defeating
                # "stop this job now". Drop them regardless of catch_up.
                logger.info(
                    "z4j.brain.workers.pending_fires: schedule %s disabled "
                    "during outage; dropping %d buffered fire(s)",
                    schedule_id,
                    len(schedule_fires),
                )
                dropped_fire_ids.extend(f.fire_id for f in schedule_fires)
                continue
            policy = getattr(schedule, "catch_up", None) or "skip"
            if policy == "skip":
                # Drop everything for this schedule.
                dropped_fire_ids.extend(f.fire_id for f in schedule_fires)
                continue
            if policy == "fire_one_missed":
                kept.append(schedule_fires[-1])  # latest by scheduled_for
                # Every earlier missed occurrence is discarded, not just
                # skipped for this tick.
                dropped_fire_ids.extend(f.fire_id for f in schedule_fires[:-1])
                continue
            if policy == "fire_all_missed":
                kept.extend(schedule_fires)
                continue
            # Unknown policy - default to dropping (loud warning so
            # operators notice a typo in the schedule row).
            logger.warning(
                "z4j.brain.workers.pending_fires: unknown catch_up "
                "policy %r for schedule %s; dropping buffered fires",
                policy,
                schedule_id,
            )
            dropped_fire_ids.extend(f.fire_id for f in schedule_fires)
        return kept, dropped_fire_ids


__all__ = ["PendingFiresReplayWorker"]
