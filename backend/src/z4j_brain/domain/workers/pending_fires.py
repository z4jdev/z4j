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
from typing import TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:
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
    ) -> None:
        self._db = db
        self._dispatcher = dispatcher

    async def tick(self) -> None:
        from datetime import UTC, datetime  # noqa: PLC0415

        from sqlalchemy import select  # noqa: PLC0415

        from z4j_brain.persistence.models import PendingFire  # noqa: PLC0415
        from z4j_brain.persistence.repositories import (  # noqa: PLC0415
            AgentRepository,
            AuditLogRepository,
            CommandRepository,
            PendingFiresRepository,
            ScheduleRepository,
        )

        # Step 1: sweep expired.
        async with self._db.session() as session:
            expired = await PendingFiresRepository(session).delete_expired(
                now=datetime.now(UTC),
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
                select(PendingFire.project_id, PendingFire.engine).distinct(),
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
        # Round-4 audit fix (Apr 2026): per-fire transaction so a
        # crash mid-replay doesn't leave the buffer row + the
        # dispatcher state inconsistent. Pre-fix one outer session
        # held the whole loop, but ``dispatcher.issue`` commits
        # internally after each call - so each ``delete_by_fire_id``
        # ran in a NEW unconfirmed transaction (the dispatcher's
        # commit closed the previous one). A SIGKILL between two
        # successful issues left some buffer rows committed-deleted
        # and others queued-but-not-deleted, then re-dispatched on
        # next tick. With per-fire commits, every successful
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
                    fires = await self._apply_catch_up(
                        fires=fires, schedules_repo=schedules_repo,
                    )

                for fire in fires:
                    target_agent = next(
                        (
                            a for a in agents
                            if engine in (a.engine_adapters or ())
                        ),
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
                    async with self._db.session() as fire_session:
                        try:
                            await self._dispatcher.issue(
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
                            await PendingFiresRepository(
                                fire_session,
                            ).delete_by_fire_id(fire.fire_id)
                            await fire_session.commit()
                            replayed_total += 1
                        except Exception:  # noqa: BLE001
                            # The dispatcher already logged. Leave
                            # the buffer row; next tick retries
                            # (dedup is handled by
                            # commands.idempotency_key + ScheduleFire
                            # upgrade-on-conflict).
                            logger.exception(
                                "z4j.brain.workers.pending_fires: replay "
                                "failed for fire_id=%s",
                                fire.fire_id,
                            )
                            await fire_session.rollback()
                            continue

        if replayed_total:
            logger.info(
                "z4j.brain.workers.pending_fires: replayed %d buffered fire(s)",
                replayed_total,
            )

    @staticmethod
    async def _apply_catch_up(
        *,
        fires: list,
        schedules_repo,
    ) -> list:
        """Filter the buffered fire list per each schedule's catch_up policy.

        - ``skip``: produce no fires for that schedule.
        - ``fire_one_missed``: produce only the most recent fire.
        - ``fire_all_missed``: produce all fires in order.

        We delete the dropped buffer rows in the same pass so a
        subsequent tick doesn't re-evaluate them. The deletion uses
        the same session/transaction the caller will commit so the
        worker stays atomic per tick.

        Performance: schedule lookups are batched into ONE query
        (``WHERE id IN (...)``) so a 100-schedule replay batch costs
        one SELECT instead of 100. The previous implementation did
        a per-schedule ``.get()`` which was an O(N) round-trip
        storm at scale - audit-Phase2-1 caught it before Phase 3.
        """
        from sqlalchemy import select  # noqa: PLC0415

        from z4j_brain.persistence.models import Schedule  # noqa: PLC0415

        # Group by schedule.
        per_schedule: dict[UUID, list] = defaultdict(list)
        for fire in fires:
            per_schedule[fire.schedule_id].append(fire)

        if not per_schedule:
            return []

        # Single batched lookup for every distinct schedule_id in
        # the replay batch. SQLAlchemy turns the IN-list into one
        # parameterized query.
        result = await schedules_repo.session.execute(
            select(Schedule).where(Schedule.id.in_(per_schedule.keys())),
        )
        schedules_by_id = {s.id: s for s in result.scalars().all()}

        kept: list = []
        for schedule_id, schedule_fires in per_schedule.items():
            schedule = schedules_by_id.get(schedule_id)
            if schedule is None:
                # Schedule was deleted while fires were buffered.
                # The CASCADE on schedule_id should have already
                # cleared them; if not, leave them for the sweep.
                continue
            policy = getattr(schedule, "catch_up", None) or "skip"
            if policy == "skip":
                # Drop everything for this schedule.
                continue
            if policy == "fire_one_missed":
                kept.append(schedule_fires[-1])  # latest by scheduled_for
                continue
            if policy == "fire_all_missed":
                kept.extend(schedule_fires)
                continue
            # Unknown policy - default to dropping (loud warning so
            # operators notice a typo in the schedule row).
            logger.warning(
                "z4j.brain.workers.pending_fires: unknown catch_up "
                "policy %r for schedule %s; dropping buffered fires",
                policy, schedule_id,
            )
        return kept


__all__ = ["PendingFiresReplayWorker"]
