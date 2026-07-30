"""Automation firing outbox drain worker.

Replays firings that the frame router could not dispatch inline (its
pending set was full under an event flood) and persisted to
``automation_firing_outbox`` instead of dropping. Each row is re-evaluated
through the executor against the CURRENT rules and deleted on success; a
row that keeps failing is dropped after a cap so a poison row cannot loop
forever. Leader-only in a multi-replica deployment (wired with a per-worker
advisory lock in ``main.py``).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger("z4j.brain.workers.automation_outbox")

#: Give up on a firing after this many failed replays (poison-row guard).
_MAX_ATTEMPTS = 5
#: Rows one project drains per round-robin turn, the max rounds per tick,
#: and the max projects visited per round. The tick clears up to
#: ``_PER_PROJECT_BATCH * _MAX_ROUNDS_PER_TICK`` rows for a single tenant,
#: while round-robining across projects so a flooding tenant cannot starve
#: others at the head of the global FIFO queue.
_PER_PROJECT_BATCH = 100
_MAX_ROUNDS_PER_TICK = 50
_MAX_PROJECTS_PER_ROUND = 200
#: Backoff seconds applied to a FAILED row = attempts * this, so a poison /
#: transiently-failing row steps out of the FIFO head instead of blocking
#: fresh rows behind it (and is retried with escalating delay).
_FAILURE_BACKOFF_SECONDS = 30


class AutomationOutboxDrainWorker:
    def __init__(self, *, db: Any, dispatcher: Any, audit: Any, settings: Any) -> None:
        self._db = db
        self._dispatcher = dispatcher
        self._audit = audit
        self._settings = settings

    async def tick(self) -> None:
        from z4j_brain.persistence.repositories import (
            AutomationFiringOutboxRepository,
        )

        # Round-robin drain across projects. Each round takes one batch from
        # every project with DUE rows, so a flooding tenant with thousands of
        # queued firings cannot dominate the head of the global FIFO queue
        # and starve other tenants. Rows that FAIL a replay are backed off
        # (next_attempt_at) so they drop out of the "due" set for a while --
        # a poison/transient-failing row at the head no longer blocks fresh
        # rows behind it. Bounded per tick so the loop always yields.
        now = datetime.now(UTC)
        drained = 0
        attempted: set[Any] = set()
        for _ in range(_MAX_ROUNDS_PER_TICK):
            async with self._db.session() as read_session:
                project_ids = await AutomationFiringOutboxRepository(
                    read_session,
                ).list_due_project_ids(now=now, limit=_MAX_PROJECTS_PER_ROUND)
            if not project_ids:
                break
            progressed = False
            for project_id in project_ids:
                async with self._db.session() as read_session:
                    rows = await AutomationFiringOutboxRepository(
                        read_session,
                    ).list_pending(
                        now=now,
                        project_id=project_id,
                        limit=_PER_PROJECT_BATCH,
                    )
                pending = [
                    (r.id, r.project_id, r.trigger, dict(r.fields or {}))
                    for r in rows
                    if r.id not in attempted
                ]
                for row_id, pid, trigger, fields in pending:
                    attempted.add(row_id)
                    progressed = True
                    if await self._replay_one(row_id, pid, trigger, fields):
                        drained += 1
            if not progressed:
                # Every due project returned only already-attempted rows this
                # tick (they failed + were backed off); stop to avoid a spin.
                break
        if drained:
            logger.info(
                "z4j.brain.workers.automation_outbox: drained %d firing(s)",
                drained,
            )

    async def _replay_one(
        self,
        row_id: Any,
        project_id: Any,
        trigger: str,
        fields: dict[str, Any],
    ) -> bool:
        from z4j_brain.domain.automation import (
            AutomationActionRunner,
            AutomationExecutor,
        )
        from z4j_brain.persistence.repositories import (
            AuditLogRepository,
            AutomationFiringOutboxRepository,
            AutomationRuleRepository,
        )

        try:
            async with self._db.session(write=True) as session:
                executor = AutomationExecutor(
                    audit=self._audit,
                    runner=AutomationActionRunner(dispatcher=self._dispatcher),
                )
                # Force a notify-coalesce window of at least the drain
                # interval on the replay path. This bounds the crash-gap dup
                # (run_matching commits the firing, then a crash before the
                # outbox-row delete re-drains it next tick): the re-fired
                # notify lands inside the window and coalesces into the first,
                # so replay safety does NOT depend on the operator having
                # opted into automation_notify_coalesce_seconds (default 0).
                # Command actions are already replay-idempotent via their
                # idempotency_key. Coalescing flood-deferred notifies is
                # desirable anyway.
                coalesce = max(
                    self._settings.automation_notify_coalesce_seconds,
                    self._settings.automation_outbox_drain_interval_seconds + 5,
                )
                await executor.run_matching(
                    session=session,
                    rules_repo=AutomationRuleRepository(session),
                    audit_log=AuditLogRepository(session),
                    project_id=project_id,
                    trigger=trigger,
                    fields=fields,
                    now=datetime.now(UTC),
                    notify_coalesce_seconds=coalesce,
                )
                # run_matching commits each fired rule internally; the outbox
                # delete is a separate commit (see the coalesce note above for
                # the crash-gap dup bound).
                await AutomationFiringOutboxRepository(session).delete_by_id(row_id)
                await session.commit()
        except Exception:
            logger.exception(
                "z4j.brain.workers.automation_outbox: replay failed for row_id=%s",
                row_id,
            )
            await self._register_failure(row_id, project_id, trigger)
            return False
        return True

    async def _register_failure(self, row_id: Any, project_id: Any, trigger: str) -> None:
        from datetime import timedelta

        from z4j_brain.persistence.repositories import (
            AutomationFiringOutboxRepository,
        )

        try:
            async with self._db.session() as session:
                repo = AutomationFiringOutboxRepository(session)
                attempts = await repo.increment_attempts(row_id)
                if attempts >= _MAX_ATTEMPTS:
                    await repo.delete_by_id(row_id)
                    logger.error(
                        "z4j.brain.workers.automation_outbox: giving up on "
                        "firing after %d attempts (permanent drop)",
                        attempts,
                    )
                    self._metric_exhausted(project_id, trigger)
                else:
                    # Escalating backoff so a poison / transiently-failing row
                    # steps out of the FIFO head instead of blocking the fresh
                    # rows behind it, and is retried with growing delay.
                    until = datetime.now(UTC) + timedelta(
                        seconds=min(attempts, _MAX_ATTEMPTS) * _FAILURE_BACKOFF_SECONDS,
                    )
                    await repo.backoff(row_id, until=until)
                await session.commit()
        except Exception:
            logger.exception(
                "z4j.brain.workers.automation_outbox: failed to record replay failure",
            )

    @staticmethod
    def _metric_exhausted(project_id: Any, trigger: str) -> None:
        try:
            from z4j_brain.api.metrics import (
                z4j_automation_firings_dropped_total,
            )

            z4j_automation_firings_dropped_total.labels(
                project=str(project_id),
                reason="outbox_exhausted",
            ).inc()
        except Exception:
            from z4j_brain.api.metrics import record_swallowed

            record_swallowed("automation_outbox", "exhausted_metric")


__all__ = ["AutomationOutboxDrainWorker"]
