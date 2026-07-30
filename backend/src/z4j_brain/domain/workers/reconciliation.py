"""``ReconciliationWorker`` - closes the stuck-task gap.

Every ``reconciliation_sweep_seconds`` (default 300s = 5 min) this
worker scans for tasks stuck in ``started`` or ``pending`` longer
than ``reconciliation_stale_threshold_seconds`` (default 15 min)
and asks the project's online agent to probe the engine's result
backend for the authoritative state.

When the agent reports ``engine_state != brain_state``, the brain
updates its own snapshot to match + writes an audit row noting
"state changed by reconciliation" + (when the engine's answer is a
TERMINAL state, i.e. the task really did start-but-never-finish in
the brain's view) fires any ``task.orphaned`` automation rules. The
emit site lives where the probe result lands --
``CommandDispatcher._apply_reconciliation_result`` -- not in this
worker, because the probe is asynchronous. This closes the
"task-stuck-in-started-forever" gap that happens when:

- The agent restarted mid-task and lost its event buffer.
- A broker hiccup dropped the ``task.succeeded`` event.
- The buffer hit its size cap and evicted events.

Safety properties:

- Bounded per-tick (max 100 stuck tasks probed per sweep).
- Idempotent - running twice against the same stuck task produces
  the same final state.
- Fails open - if no online agent for the project, we skip this
  tick and retry next cycle.
- Writes are single-statement UPDATEs inside one transaction.
Leader-locked ((b)) - ``main.py`` wraps the tick in the
  per-worker advisory lock (same pattern as the partition creator),
  so with ``z4j serve``'s min(4, cpu) uvicorn workers only ONE
  process sweeps per interval instead of four issuing duplicate
  probe commands.
Deduplicated ((c)) - each probe command carries a
  deterministic per-task / per-sweep-window idempotency key, so any
  duplicate sweep that slips past the lock collapses onto the same
  ``commands`` row."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from z4j_brain.persistence.database import DatabaseManager


logger = structlog.get_logger("z4j.brain.workers.reconciliation")

# Cap on how many stuck tasks we probe per sweep. Reconciliation
# commands dispatch to agents over the same WebSocket slot that
# serves normal commands, so unbounded reconciliation would starve
# user-initiated retries/cancels.
_MAX_TASKS_PER_SWEEP = 100

# ``commands.idempotency_key`` is ``String(200)``; keys longer than
# this would fail the INSERT outright.
_IDEMPOTENCY_KEY_MAX_LEN = 200


def _probe_idempotency_key(engine: str, task_id: str, window: int) -> str:
    """Deterministic per-task / per-sweep-window probe dedupe key.

    (c): probe commands used to carry no idempotency key, so
    duplicate sweeps (multiple brain replicas, a retried tick) issued
    duplicate ``reconcile_task`` commands that nothing downstream
    deduplicated. The key is deterministic over ``(engine, task_id,
    window)`` where ``window`` is the sweep-interval bucket: a
    duplicate sweep inside the same window collapses onto the same
    ``commands`` row (unique on ``(project_id, idempotency_key)``),
    while a later window mints a new key so a still-stuck task can be
    re-probed.

    ``task_id`` can be up to 200 chars, which would overflow the
    200-char column with the prefix attached - in that case the
    ``engine:task_id`` pair is folded into a SHA-256 digest. Still
    deterministic, just not human-readable.
    """
    key = f"reconcile:{engine}:{task_id}:{window}"
    if len(key) <= _IDEMPOTENCY_KEY_MAX_LEN:
        return key
    digest = hashlib.sha256(f"{engine}:{task_id}".encode()).hexdigest()[:32]
    return f"reconcile:sha256:{digest}:{window}"


class ReconciliationWorker:
    """Periodic stuck-task reconciliation sweeper."""

    def __init__(
        self,
        db: DatabaseManager,
        *,
        stale_threshold_seconds: int = 900,
        sweep_interval_seconds: int = 300,
        dispatcher: object | None = None,
    ) -> None:
        """
        Args:
            db: Shared DatabaseManager.
            stale_threshold_seconds: Tasks whose age anchor
                (``started_at``, falling back to ``received_at`` then
                ``created_at``) is older than this and still
                non-terminal are probed.
            sweep_interval_seconds: The tick cadence, used as the
                idempotency-key window: duplicate sweeps within one
                window dedupe onto the same probe command, the next
                window can re-probe. Wire the same value the
                PeriodicWorker ticks with.
            dispatcher: Optional CommandDispatcher; in production the
                supervisor wires the live one. Tests pass a stub or
                ``None`` (worker will just count stuck tasks without
                firing commands, which is useful for integration tests).
        """
        self._db = db
        self._stale_threshold = timedelta(seconds=stale_threshold_seconds)
        self._sweep_interval = max(1, int(sweep_interval_seconds))
        self._dispatcher = dispatcher

    async def tick(self) -> None:
        """One reconciliation pass. Safe to call repeatedly."""
        from uuid import UUID

        from z4j_brain.persistence.repositories import (
            AgentRepository,
            CommandRepository,
            TaskRepository,
        )

        now = datetime.now(UTC)
        cutoff = now - self._stale_threshold
        # Idempotency window for this sweep ((c)) - see
        # ``_probe_idempotency_key``.
        window = int(now.timestamp() // self._sweep_interval)

        async with self._db.session(write=True) as session:
            task_repo = TaskRepository(session)
            agent_repo = AgentRepository(session)
            stuck = await task_repo.list_stuck_for_reconciliation(
                stuck_before=cutoff,
                limit=_MAX_TASKS_PER_SWEEP,
            )
            if not stuck:
                return

            by_project: dict[str, list[object]] = {}
            for t in stuck:
                by_project.setdefault(str(t.project_id), []).append(t)

            dispatched = 0
            skipped_no_agent = 0
            skipped_no_dispatcher = 0
            errored = 0

            for project_id_str, tasks in by_project.items():
                project_id = UUID(project_id_str)
                online_agents = await agent_repo.list_online_for_project(
                    project_id,
                )
                if not online_agents:
                    skipped_no_agent += len(tasks)
                    continue

                if self._dispatcher is None:
                    # Test or stub mode: no real WebSocket dispatch
                    # wired. Count the tasks we would have probed so
                    # tests can still assert behavior.
                    skipped_no_dispatcher += len(tasks)
                    continue

                # ENGINE-AWARE AGENT PICK: route each stuck task to an
                # agent that actually advertises its engine. Without
                # this, the reconciler could ask a Celery agent about
                # an RQ task - the adapter would either return
                # ``unknown`` (best case) or, on id collision across
                # engines, clobber the wrong task's state. Per the
                # security audit (H2).
                agents_by_engine: dict[str, object] = {}
                for a in online_agents:
                    for eng in a.engine_adapters or []:
                        agents_by_engine.setdefault(eng, a)

                for t in tasks:
                    agent = agents_by_engine.get(t.engine)
                    if agent is None:
                        skipped_no_agent += 1
                        continue
                    # Each stuck task → one ``reconcile_task`` command
                    # over the agent's WebSocket. The agent-side
                    # handler in ``z4j_bare.dispatcher`` calls the
                    # adapter's ``reconcile_task`` and returns a
                    # ``CommandResult`` whose ``result`` dict carries
                    # ``engine_state``. The brain's
                    # ``CommandDispatcher.handle_result`` path picks
                    # that up and applies it back to ``tasks.state``
                    # via ``TaskRepository.apply_reconciled_state``.
                    try:
                        commands = CommandRepository(session)
                        from z4j_brain.persistence.repositories import (
                            AuditLogRepository,
                        )

                        audit_log = AuditLogRepository(session)
                        await self._dispatcher.issue(
                            commands=commands,
                            audit_log=audit_log,
                            project_id=project_id,
                            agent_id=agent.id,
                            action="reconcile_task",
                            target_type="task",
                            target_id=t.task_id,
                            payload={
                                "task_id": t.task_id,
                                "engine": t.engine,
                            },
                            issued_by=None,
                            ip=None,
                            user_agent="z4j-reconciliation-worker",
                            # Dedupe duplicate sweeps within one
                            # window onto a single probe command
                            # ((c)).
                            idempotency_key=_probe_idempotency_key(
                                t.engine,
                                t.task_id,
                                window,
                            ),
                        )
                        dispatched += 1
                    except Exception:
                        # Per-task failures (agent went offline mid-sweep,
                        # registry hiccup) shouldn't kill the whole tick.
                        # Log and move on so the next tick gets another shot.
                        logger.exception(
                            "z4j reconciliation: dispatch failed",
                            task_id=t.task_id,
                            project_id=str(project_id),
                        )
                        errored += 1

        if dispatched or skipped_no_agent or skipped_no_dispatcher or errored:
            logger.info(
                "z4j reconciliation sweep",
                dispatched=dispatched,
                skipped_no_agent=skipped_no_agent,
                skipped_no_dispatcher=skipped_no_dispatcher,
                errored=errored,
                stuck_found=len(stuck),
            )


__all__ = ["ReconciliationWorker"]
