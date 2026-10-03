"""Audit-log retention sweeper (1.2.2+).

Periodically deletes ``audit_log`` rows older than
``settings.audit_retention_days``. Wired into brain's lifespan so
it starts on boot and stops cleanly on shutdown.

Why bother:

- The audit trail grows linearly forever. A homelab brain doing
  10 actions/sec (~860k rows/day) hits 30M rows in a month and
  starts choking the dashboard's ``ORDER BY occurred_at`` paged
  reads. 90 days is enough trail for forensics; older rows are
  noise.
- Operators have asked for a "set retention and forget" knob
  rather than an external cron + ``DELETE`` script.

How it works:

- Legacy/keyless Postgres: opens one outer transaction for the capped
  pass and takes ``pg_try_advisory_xact_lock`` once. Each bounded DELETE
  runs inside a SAVEPOINT and repeats ``SET LOCAL z4j.audit_sweep = 'on'``;
  both the GUC and advisory lock remain scoped to the outer transaction,
  which commits all successful batches together. The authenticated v2
  path instead opens a transaction and takes the advisory/chain locks for
  each batch.
- SQLite: no trigger; plain DELETE. Most homelabs run SQLite,
  so this is the common path. The legacy and authenticated paths commit
  each batch independently; SQLite's writer serialization replaces the
  Postgres advisory-lock coordination.

The sweep runs on a fixed cadence
(``audit_retention_sweep_interval_seconds``, default 3600s = 1h).
Each pass uses statements bounded by
``audit_retention_sweep_batch_size`` and caps the *whole* pass at
``audit_retention_sweep_max_per_pass`` so a multi-million-row
backlog cannot make the legacy Postgres outer transaction or any
other pass unbounded. Errors are logged but never crash the task;
the next tick retries.

The hash chain (``prev_row_hmac``) breaks at the boundary where
old rows are deleted. Verification of the surviving chain still
works from the new oldest row forward, which is the documented
behaviour of any time-based audit retention policy.

Retention by action class
-------------------------

``settings.audit_retention_by_class`` maps an action class (the first
dotted segment of an action name: ``auth`` for ``auth.login``,
``command`` for ``command.issue.requeue_dead_letter``) to its own window
in days; everything else uses ``audit_retention_days``. The chain only
ever loses a contiguous oldest-first prefix, because that is the one
shape the authenticated prune boundary can describe, so the rule is:

- a row is *expired* when it is older than its own class's cutoff;
- a pass removes the longest run of expired rows at the oldest end of the
  active generation and stops at the first row that is not expired,
  whatever lies beyond it.

A class with a longer window therefore holds every row written after
its oldest retained row, and a class with a shorter window only takes
effect on rows older than all their retained neighbours. Both are
allowed; the docs say what each buys. :class:`RetentionCutoffs` holds
the computed cutoffs and :func:`expired_prefix` applies the rule; the
sweep and ``z4j audit prune`` share them so there is exactly one answer
to "what would retention remove".

``z4j audit prune`` is the operator-driven form of the same authenticated
prefix prune (soft mode) plus an epoch cut (hard mode, a generation reset
once the generation is fully pruned). It reuses :meth:`AuditRetentionSweeper.
prune_authenticated` and :func:`preview_authenticated_prune` rather than a
second deletion path.

1.5.0 extension: the same task body also purges
``agent_status_history`` rows older than
``settings.event_retention_days`` (NOT ``audit_retention_days`` -
agent_status is high-frequency observability data, more like the
event stream than the audit trail, so it shares the events
retention knob). The agent_status sweep runs in the same pass as
the audit sweep so operators only have one cadence to tune. The
sweeper class name is unchanged for backward compatibility. The
agent-status helper has the same batch and per-pass caps, but runs
in its own per-batch sessions and does not take the audit sweep's
advisory lock.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Protocol, TypeVar

from sqlalchemy import and_, delete, func, not_, or_, select, text

from z4j_brain.domain.audit_chain import (
    AUDIT_ROW_HMAC_VERSION,
    AuditChainIntegrityError,
    authenticate_state,
    build_audit_keyring,
    canonical_audit_key_id,
    compute_state_mac,
    normalize_timestamp,
)
from z4j_brain.persistence.models import AuditChainState, AuditLog
from z4j_brain.persistence.models.audit_chain import AUDIT_CHAIN_SINGLETON_ID

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.sql import ColumnElement

    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings

logger = logging.getLogger("z4j.brain.audit_retention")


#: Postgres advisory-lock key for cross-worker sweep coordination.
#: Computed from ``hashtext('z4j.audit_sweep')``, any int32 will
#: do, but using ``hashtext`` keeps it readable in the migration's
#: comments.
_SWEEP_ADVISORY_LOCK_KEY: int = 0x7A346A41  # "z4jaA" stable seed

#: Action name of the row ``z4j audit prune`` writes about itself.
AUDIT_PRUNE_ACTION = "audit.prune"


class SweepLeaseBusyError(Exception):
    """Another process holds the retention sweep's advisory lock.

    The periodic sweeper treats this as "skip this pass"; ``z4j audit
    prune`` surfaces it as a refusal, because an operator who asked for a
    prune and got silence would reasonably conclude there was nothing to
    prune.
    """


def action_class(action: str) -> str:
    """Return the retention class of an action name: its first dotted segment.

    ``command.issue.requeue_dead_letter`` -> ``command``, ``dead_letters.list``
    -> ``dead_letters``, ``auth`` -> ``auth``.
    """
    return action.partition(".")[0]


class _ActionRow(Protocol):
    action: str
    occurred_at: datetime


class _ChainRow(_ActionRow, Protocol):
    id: uuid.UUID


RowT = TypeVar("RowT", bound=_ActionRow)


@dataclass(frozen=True, slots=True)
class RetentionCutoffs:
    """The moment before which a row of each class is expired.

    ``default`` applies to every class absent from ``by_class``. ``label`` is
    the human description the sweep logs and the CLI prints, so the two never
    describe the same policy in two ways.
    """

    default: datetime
    by_class: Mapping[str, datetime] = field(default_factory=dict)
    label: str = ""

    @classmethod
    def from_settings(cls, settings: Settings, now: datetime) -> RetentionCutoffs:
        """Compute the cutoffs the configured policy implies at ``now``."""
        by_class = {
            name: now - timedelta(days=days)
            for name, days in sorted(settings.audit_retention_by_class.items())
        }
        parts = [f"{settings.audit_retention_days} days"]
        parts.extend(
            f"{name} {days} days"
            for name, days in sorted(settings.audit_retention_by_class.items())
        )
        return cls(
            default=now - timedelta(days=settings.audit_retention_days),
            by_class=by_class,
            label="retention: " + ", ".join(parts),
        )

    @classmethod
    def before(cls, cutoff: datetime) -> RetentionCutoffs:
        """One explicit cutoff for every class (``z4j audit prune --before``)."""
        normalized = normalize_timestamp(cutoff)
        return cls(
            default=normalized,
            by_class={},
            label="--before " + normalized.isoformat(timespec="seconds").replace("+00:00", "Z"),
        )

    def cutoff_for(self, action: str) -> datetime:
        return self.by_class.get(action_class(action), self.default)

    @property
    def latest(self) -> datetime:
        """The newest cutoff: no row at or after it is expired in any class."""
        return max(self.default, *self.by_class.values()) if self.by_class else self.default

    def expired(self, action: str, occurred_at: datetime | str) -> bool:
        return normalize_timestamp(occurred_at) < self.cutoff_for(action)


def expired_prefix(
    rows: Iterable[RowT],
    cutoffs: RetentionCutoffs,
) -> list[RowT]:
    """Return the leading run of ``rows`` that retention may remove.

    ``rows`` must be in chain order, oldest first. The run stops at the first
    row that is not expired under its own class; nothing after it is
    returned even if it is expired, because the chain can only lose a
    contiguous prefix.
    """
    out: list[RowT] = []
    for row in rows:
        if not cutoffs.expired(row.action, row.occurred_at):
            break
        out.append(row)
    return out


def expired_predicate(cutoffs: RetentionCutoffs) -> ColumnElement[bool]:
    """The SQL form of :meth:`RetentionCutoffs.expired`.

    A row matches when it is older than the cutoff of its own class, so a
    count under this predicate says how many rows retention would remove if
    the chain could lose them individually. The prefix rule is what stops
    it, and the difference is what :func:`warn_when_prefix_blocked` reports.
    """
    if not cutoffs.by_class:
        return AuditLog.occurred_at < cutoffs.default
    in_any_class = []
    clauses = []
    for name, cutoff in cutoffs.by_class.items():
        # A class name may carry an underscore, which LIKE treats as a
        # wildcard; escape it so ``dead_letters`` matches only itself.
        escaped = name.replace("_", r"\_")
        in_class = or_(
            AuditLog.action == name,
            AuditLog.action.like(f"{escaped}.%", escape="\\"),
        )
        in_any_class.append(in_class)
        clauses.append(and_(in_class, AuditLog.occurred_at < cutoff))
    clauses.append(and_(not_(or_(*in_any_class)), AuditLog.occurred_at < cutoffs.default))
    return or_(*clauses)


async def warn_when_prefix_blocked(
    session: AsyncSession,
    *,
    candidates: Sequence[_ChainRow],
    kept: int,
    cutoffs: RetentionCutoffs,
    generation: uuid.UUID | None = None,
) -> int:
    """Log one WARNING when the prefix stopped early with expired rows behind it.

    ``candidates`` is the oldest-first page the batch considered and ``kept``
    how many of them :func:`expired_prefix` returned. When the run stopped
    inside the page, the row it stopped at is the blocker: its class window
    keeps it, and nothing after it can be removed however old, because the
    chain only loses a contiguous prefix. Silence here is what let a class
    window quietly hold several times the configured retention, so the pass
    says which row holds the line, how old it is, and how many expired rows
    wait behind it. Returns that count (0 when there is nothing to say).
    """
    if kept >= len(candidates):
        return 0
    blocker = candidates[kept]
    stmt = (
        select(func.count())
        .select_from(AuditLog)
        .where(
            expired_predicate(cutoffs),
            or_(
                AuditLog.occurred_at > blocker.occurred_at,
                and_(
                    AuditLog.occurred_at == blocker.occurred_at,
                    AuditLog.id > blocker.id,
                ),
            ),
        )
    )
    if generation is not None:
        stmt = stmt.where(
            AuditLog.legacy_frozen.is_(False),
            AuditLog.chain_generation == generation,
        )
    behind = int((await session.execute(stmt)).scalar_one())
    if not behind:
        return 0
    occurred_at = normalize_timestamp(blocker.occurred_at)
    age_days = (datetime.now(UTC) - occurred_at).days
    logger.warning(
        "z4j.brain.audit_retention: the prune stopped at a %s row (%s, %d days "
        "old; its class keeps rows until %s) with %d expired row(s) retained "
        "behind it. The chain only loses a contiguous prefix, so they stay "
        "until that row ages out (%s)",
        action_class(blocker.action),
        blocker.action,
        age_days,
        cutoffs.cutoff_for(blocker.action).isoformat(timespec="seconds"),
        behind,
        cutoffs.label,
    )
    return behind


@dataclass(frozen=True, slots=True)
class PrunePreview:
    """What one authenticated prefix prune would remove, computed read-only."""

    generation: uuid.UUID
    active_rows: int
    frozen_rows: int
    expired_rows: int
    expired_by_class: dict[str, int]
    #: The newest row the prune would remove, which becomes the new boundary.
    boundary_id: uuid.UUID | None
    boundary_row_hmac: str | None
    boundary_occurred_at: datetime | None
    #: The first row the prune stops at, when an expired row exists beyond it.
    blocker_action: str | None
    blocker_occurred_at: datetime | None
    blocker_cutoff: datetime | None
    #: The authenticated boundary before the prune, if retention ever ran.
    current_prune_id: uuid.UUID | None

    @property
    def remaining_rows(self) -> int:
        return self.active_rows - self.expired_rows


async def preview_authenticated_prune(
    session: AsyncSession,
    settings: Settings,
    *,
    cutoffs: RetentionCutoffs,
    page_size: int = 1000,
) -> PrunePreview:
    """Count the expired prefix of the active generation without touching it.

    Authenticates the chain state first and refuses (raises
    :class:`AuditChainIntegrityError`) when the state is missing, does not
    authenticate under the configured keys, or disagrees with the physical
    row count, so a dry run never reports a number from a chain the prune
    itself would refuse. The walk also checks every link of the prefix it
    counts; a broken link is the same refusal.
    """
    from z4j_brain.persistence.repositories import AuditLogRepository

    if not 1 <= page_size <= 5000:
        raise ValueError("page_size must be between 1 and 5000")
    secrets = settings.all_audit_chain_secrets_for_verification()
    if not secrets:
        raise AuditChainIntegrityError("dedicated audit-chain key is unavailable")
    keyring = {canonical_audit_key_id(secret): secret for secret in secrets}
    states = list(
        (
            await session.execute(
                select(AuditChainState).where(
                    AuditChainState.singleton_id == AUDIT_CHAIN_SINGLETON_ID,
                ),
            )
        ).scalars(),
    )
    if len(states) != 1:
        raise AuditChainIntegrityError(
            f"audit_chain_state holds {len(states)} rows where exactly one is required",
        )
    state = states[0]
    authenticate_state(state, keyring)
    repo = AuditLogRepository(session)
    active_count = await repo.count_active_generation(generation=state.generation)
    if active_count != state.active_row_count:
        raise AuditChainIntegrityError(
            f"active audit row count {active_count} does not match authenticated "
            f"state {state.active_row_count}",
        )
    frozen_count = await repo.count_frozen_rows()

    expired = 0
    by_class: dict[str, int] = {}
    boundary: AuditLog | None = None
    blocker: AuditLog | None = None
    previous = state.prune_row_hmac
    cursor_time: datetime | None = None
    cursor_id: uuid.UUID | None = None
    while blocker is None:
        stmt = (
            select(AuditLog)
            .where(
                AuditLog.legacy_frozen.is_(False),
                AuditLog.chain_generation == state.generation,
                AuditLog.occurred_at < cutoffs.latest,
            )
            .order_by(AuditLog.occurred_at.asc(), AuditLog.id.asc())
            .limit(page_size)
        )
        if cursor_time is not None and cursor_id is not None:
            stmt = stmt.where(
                or_(
                    AuditLog.occurred_at > cursor_time,
                    (AuditLog.occurred_at == cursor_time) & (AuditLog.id > cursor_id),
                ),
            )
        rows = list((await session.execute(stmt)).scalars().all())
        if not rows:
            break
        for row in rows:
            if not cutoffs.expired(row.action, row.occurred_at):
                blocker = row
                break
            if row.prev_row_hmac != previous:
                raise AuditChainIntegrityError(
                    f"expired audit prefix contains a broken link at row {row.id}",
                )
            previous = row.row_hmac
            expired += 1
            by_class[action_class(row.action)] = by_class.get(action_class(row.action), 0) + 1
            boundary = row
        cursor_time = rows[-1].occurred_at
        cursor_id = rows[-1].id
        if len(rows) < page_size:
            break
    return PrunePreview(
        generation=state.generation,
        active_rows=active_count,
        frozen_rows=frozen_count,
        expired_rows=expired,
        expired_by_class=dict(sorted(by_class.items())),
        boundary_id=boundary.id if boundary is not None else None,
        boundary_row_hmac=boundary.row_hmac if boundary is not None else None,
        boundary_occurred_at=(
            normalize_timestamp(boundary.occurred_at) if boundary is not None else None
        ),
        blocker_action=blocker.action if blocker is not None else None,
        blocker_occurred_at=(
            normalize_timestamp(blocker.occurred_at) if blocker is not None else None
        ),
        blocker_cutoff=cutoffs.cutoff_for(blocker.action) if blocker is not None else None,
        current_prune_id=state.prune_id,
    )


class AuditRetentionSweeper:
    """Background task that prunes ``audit_log`` on a schedule.

    Lifecycle::

        sweeper = AuditRetentionSweeper()
        sweeper.start(db=db, settings=settings)
        ...
        await sweeper.stop()

    All sweep activity is opt-in: when
    ``settings.audit_retention_days <= 0`` the task wakes,
    notices retention is disabled, and goes back to sleep. The
    operator can flip the setting at runtime (next tick picks it
    up) without restarting brain.
    """

    def __init__(self) -> None:
        self._db: DatabaseManager | None = None
        self._settings: Settings | None = None
        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()
        self._last_deleted: int = 0
        self._total_deleted: int = 0
        self._last_run_at: datetime | None = None
        self._last_error: str | None = None
        # 1.5.0: agent_status_history sweep counters. Tracked
        # separately from the audit-log counters so the /metrics
        # self-watch can graph the two retention streams without
        # conflating them.
        self._last_agent_status_deleted: int = 0
        self._total_agent_status_deleted: int = 0

    @property
    def last_deleted(self) -> int:
        """Rows deleted in the most recent sweep pass."""
        return self._last_deleted

    @property
    def total_deleted(self) -> int:
        """Cumulative rows deleted since :meth:`start`."""
        return self._total_deleted

    @property
    def last_run_at(self) -> datetime | None:
        """Wall-clock time of the most recent sweep pass."""
        return self._last_run_at

    @property
    def last_error(self) -> str | None:
        """Stringified exception from the most recent failed sweep."""
        return self._last_error

    @property
    def last_agent_status_deleted(self) -> int:
        """``agent_status_history`` rows deleted in the most recent pass."""
        return self._last_agent_status_deleted

    @property
    def total_agent_status_deleted(self) -> int:
        """Cumulative ``agent_status_history`` deletes since :meth:`start`."""
        return self._total_agent_status_deleted

    def bind(self, *, db: DatabaseManager, settings: Settings) -> None:
        """Attach a database and settings without spawning the periodic task.

        ``z4j audit prune`` drives :meth:`prune_authenticated` from a
        short-lived process and never wants the loop.
        """
        self._db = db
        self._settings = settings

    def start(
        self,
        *,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        """Spawn the sweep task. Idempotent."""
        if self._task is not None:
            return
        self.bind(db=db, settings=settings)
        self._stop_event.clear()
        self._task = asyncio.create_task(
            self._loop(),
            name="z4j.brain.audit_retention.sweep",
        )

    async def stop(self) -> None:
        """Signal the task to exit and wait briefly for it.

        ``CancelledError`` raised into ``stop()`` from the outer
        lifespan (e.g. uvicorn shutdown timeout) propagates up, it
        MUST NOT be swallowed, otherwise the cancellation never
        reaches the parent and shutdown stalls.
        We catch ``TimeoutError`` (the wait_for budget elapsed) and
        broad ``Exception`` (the task itself raised) but explicitly
        re-raise ``CancelledError``.
        """
        if self._task is None:
            return
        self._stop_event.set()
        try:
            await asyncio.wait_for(self._task, timeout=5.0)
        except asyncio.CancelledError:
            # Outer scope is cancelling us, try a clean cancel of
            # the inner task, then re-raise so the cancellation
            # propagates.
            self._task.cancel()
            raise
        except (TimeoutError, Exception):
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            except Exception:  # noqa: S110  best-effort inner task cleanup
                pass
        self._task = None

    async def sweep_once(self) -> int:
        """Run one sweep pass synchronously and return rows deleted.

        Exposed for tests + the ``z4j audit prune`` CLI
        subcommand. Honours the same settings as the periodic loop.

        Returns the audit_log delete count for backward compatibility
        with pre-1.5 callers; the agent_status delete count is
        exposed via :attr:`last_agent_status_deleted`. The two
        streams use different retention windows (audit_retention_days
        vs event_retention_days) and shouldn't be summed.
        """
        deleted = await self._do_sweep()
        # 1.5.0: also purge agent_status_history. Errors are caught
        # so a failure in this stream doesn't poison the audit-log
        # counters. The ``_do_sweep_agent_status`` helper runs in
        # its own session with its own transaction discipline.
        try:
            await self._do_sweep_agent_status()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception(
                "z4j.brain.audit_retention: agent_status sweep failed; "
                "audit_log sweep already ran successfully",
            )
            self._last_error = f"agent_status: {type(exc).__name__}: {exc}"
        return deleted

    async def _loop(self) -> None:
        assert self._settings is not None
        while not self._stop_event.is_set():
            interval = max(
                60,
                self._settings.audit_retention_sweep_interval_seconds,
            )
            try:
                await self._do_sweep()
            except asyncio.CancelledError:
                # Explicit re-raise so the loop
                # exits cleanly when stop() / outer cancel fires
                # mid-sweep.
                raise
            except Exception as exc:
                self._last_error = f"{type(exc).__name__}: {exc}"
                logger.exception(
                    "z4j.brain.audit_retention: sweep pass failed; next attempt in %ds",
                    interval,
                )
            # 1.5.0: agent_status_history sweep. Runs every tick
            # alongside the audit sweep so operators have one cadence
            # to tune. Failures in this stream don't poison the next
            # tick.
            try:
                await self._do_sweep_agent_status()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._last_error = f"agent_status: {type(exc).__name__}: {exc}"
                logger.exception(
                    "z4j.brain.audit_retention: agent_status sweep "
                    "pass failed; next attempt in %ds",
                    interval,
                )
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=interval,
                )
                return
            except asyncio.CancelledError:
                raise
            except TimeoutError:
                continue

    async def _do_sweep(self) -> int:
        """Execute one pass.

        Legacy Postgres holds one transaction-scoped advisory lock and
        one outer transaction across the capped pass; individual batches
        are SAVEPOINTs, not separately committed transactions. Legacy
        SQLite commits each batch independently. The authenticated v2
        implementation delegated to above also commits per batch on both
        dialects. Every branch caps the pass at
        ``audit_retention_sweep_max_per_pass`` rows.
        """
        assert self._db is not None
        assert self._settings is not None

        if self._settings.audit_chain_secret is not None:
            return await self._do_sweep_v2()

        # Clear last_error at the top of every pass so
        # retention-disabled / no-eligible-rows
        # paths reset the metric. Without this, an error from a
        # prior pass kept ``z4j_background_task_error_active`` at 1
        # indefinitely after the operator disabled retention.
        self._last_error = None

        retention_days = self._settings.audit_retention_days
        if retention_days <= 0:
            return 0
        if retention_days < 1:
            logger.warning(
                "z4j.brain.audit_retention: refusing to sweep with "
                "retention_days=%d (must be >= 1)",
                retention_days,
            )
            return 0

        cutoffs = RetentionCutoffs.from_settings(self._settings, datetime.now(UTC))
        batch_size = max(
            100,
            self._settings.audit_retention_sweep_batch_size,
        )
        max_per_pass = max(
            batch_size,
            self._settings.audit_retention_sweep_max_per_pass,
        )
        dialect_name = self._db.engine.dialect.name
        is_postgres = dialect_name == "postgresql"

        total = 0

        # Pre-flight: on Postgres only one worker should sweep at a
        # time. Use an xact-scoped advisory lock that auto-releases
        # at COMMIT/ROLLBACK, no explicit unlock needed.
        #
        # The previous design used ``pg_try_advisory_lock``
        # (session-scoped) with an
        # explicit ``pg_advisory_unlock`` in a ``finally`` block
        # INSIDE ``async with session.begin()``. If the unlock
        # itself failed, the begin's __aexit__ rolled back the
        # entire transaction, including the legitimate batched
        # DELETEs from earlier in the pass. By switching to
        # ``pg_try_advisory_xact_lock`` we eliminate the unlock
        # call entirely; the lock auto-releases on the same
        # COMMIT that persists the deletes.
        #
        # ``SET LOCAL`` per batch is transaction-scoped (Postgres
        # docs); we re-set it every batch as belt-and-suspenders
        # so a future refactor that drops the SAVEPOINT still
        # works. The ``begin_nested()`` SAVEPOINTs isolate
        # batch-level errors so a single bad row doesn't abort
        # the whole pass.
        if is_postgres:
            async with self._db.session() as session, session.begin():
                lock_row = await session.execute(
                    text("SELECT pg_try_advisory_xact_lock(:k)"),
                    {"k": _SWEEP_ADVISORY_LOCK_KEY},
                )
                got_lock = bool(lock_row.scalar())
                if not got_lock:
                    logger.debug(
                        "z4j.brain.audit_retention: another "
                        "worker holds the sweep lock; "
                        "skipping pass",
                    )
                    # Update last_run_at even on the lock-skip path
                    # so /metrics doesn't report a stale
                    # timestamp making operators think the
                    # sweeper has stalled.
                    self._last_run_at = datetime.now(UTC)
                    return 0
                while not self._stop_event.is_set() and total < max_per_pass:
                    rows = await self._sweep_one_batch_postgres(
                        session,
                        cutoffs=cutoffs,
                        batch_size=batch_size,
                    )
                    total += rows
                    if rows < batch_size:
                        break
                    # The xact-scoped lock auto-releases at the
                    # implicit COMMIT when ``begin()`` exits.
        else:
            # SQLite: per-batch session so each commit returns the
            # connection to the pool and the WAL doesn't grow
            # unbounded across the pass.
            while not self._stop_event.is_set() and total < max_per_pass:
                rows = await self._sweep_one_batch_sqlite(
                    cutoffs=cutoffs,
                    batch_size=batch_size,
                )
                total += rows
                if rows < batch_size:
                    break

        # Record the HMAC-chain prune boundary so `z4j audit verify`
        # does not permanently false-positive on the first surviving row
        # once retention has deleted the genesis row.
        if total:
            await self._record_prune_watermark()

        self._last_deleted = total
        self._total_deleted += total
        # Write last_run_at LAST so a /metrics scrape that
        # interleaves with the sweep doesn't see a stale timestamp
        # alongside an updated total. (See audit note on the
        # `_refresh_self_watch_gauges` race.)
        self._last_run_at = datetime.now(UTC)
        self._last_error = None
        if total:
            logger.info(
                "z4j.brain.audit_retention: pruned %d rows older than their class cutoff (%s)",
                total,
                cutoffs.label,
            )
        return total

    async def prune_authenticated(self, *, cutoffs: RetentionCutoffs) -> int:
        """Run authenticated prefix passes until nothing expired remains.

        The entry point ``z4j audit prune`` uses. Each pass is bounded by the
        same batch and per-pass caps as the periodic sweep and commits per
        batch, so an interrupted run leaves a consistent, signed state and
        the next run continues. Raises :class:`SweepLeaseBusyError` instead of
        skipping when the periodic sweeper holds the lease.
        """
        assert self._settings is not None
        batch_size = max(100, self._settings.audit_retention_sweep_batch_size)
        max_per_pass = max(batch_size, self._settings.audit_retention_sweep_max_per_pass)
        total = 0
        while True:
            pruned = await self._do_sweep_v2(cutoffs=cutoffs, raise_when_busy=True)
            total += pruned
            if pruned < max_per_pass:
                return total

    async def _do_sweep_v2(
        self,
        *,
        cutoffs: RetentionCutoffs | None = None,
        raise_when_busy: bool = False,
    ) -> int:
        """Delete authenticated v2 prefixes and advance state atomically.

        ``cutoffs`` defaults to the configured policy at the current time;
        ``z4j audit prune`` passes its own. ``raise_when_busy`` turns the
        periodic "another worker holds the sweep lock, skip" into
        :class:`SweepLeaseBusyError` for a caller that must not stay silent.
        """

        assert self._db is not None
        assert self._settings is not None

        self._last_error = None
        if cutoffs is None:
            retention_days = self._settings.audit_retention_days
            if retention_days <= 0:
                return 0
            cutoffs = RetentionCutoffs.from_settings(self._settings, datetime.now(UTC))
        batch_size = max(100, self._settings.audit_retention_sweep_batch_size)
        max_per_pass = max(
            batch_size,
            self._settings.audit_retention_sweep_max_per_pass,
        )
        secrets = self._settings.all_audit_chain_secrets_for_verification()
        if not secrets:
            raise AuditChainIntegrityError(
                "dedicated audit-chain key is unavailable",
            )
        current_key_id, keyring = build_audit_keyring(secrets[0], secrets[1:])

        total = 0
        while not self._stop_event.is_set() and total < max_per_pass:
            try:
                rows = await self._sweep_one_batch_v2_in_session(
                    cutoffs=cutoffs,
                    batch_size=min(batch_size, max_per_pass - total),
                    current_key_id=current_key_id,
                    keyring=keyring,
                )
            except SweepLeaseBusyError:
                if raise_when_busy:
                    raise
                logger.debug(
                    "z4j.brain.audit_retention: another worker holds the sweep lock; skipping pass",
                )
                break
            total += rows
            if rows < batch_size:
                break

        self._last_deleted = total
        self._total_deleted += total
        self._last_run_at = datetime.now(UTC)
        self._last_error = None
        if total:
            logger.info(
                "z4j.brain.audit_retention: authenticated-prefix prune "
                "removed %d rows older than their class cutoff (%s)",
                total,
                cutoffs.label,
            )
        return total

    async def _sweep_one_batch_v2_in_session(
        self,
        *,
        cutoffs: RetentionCutoffs,
        batch_size: int,
        current_key_id: str,
        keyring: dict[str, bytes],
    ) -> int:
        """Open one session with the dialect's write discipline for one batch."""

        assert self._db is not None
        async with self._db.session() as session:
            is_postgres = session.bind is not None and (session.bind.dialect.name == "postgresql")
            if is_postgres:
                async with session.begin():
                    return await self._sweep_one_batch_v2(
                        session,
                        cutoffs=cutoffs,
                        batch_size=batch_size,
                        current_key_id=current_key_id,
                        keyring=keyring,
                        is_postgres=True,
                    )
            # SQLite must obtain its writer reservation before its
            # first read; upgrading a deferred read transaction after
            # inspecting state is forbidden.
            await session.execute(text("BEGIN IMMEDIATE"))
            try:
                rows = await self._sweep_one_batch_v2(
                    session,
                    cutoffs=cutoffs,
                    batch_size=batch_size,
                    current_key_id=current_key_id,
                    keyring=keyring,
                    is_postgres=False,
                )
                await session.commit()
            except BaseException:
                await session.rollback()
                raise
            return rows

    async def _sweep_one_batch_v2(  # noqa: PLR0912, PLR0915
        self,
        session,
        *,
        cutoffs: RetentionCutoffs,
        batch_size: int,
        current_key_id: str,
        keyring: dict[str, bytes],
        is_postgres: bool,
    ) -> int:
        """Verify and delete exactly one oldest active-generation prefix.

        The candidate page is every active row older than the newest class
        cutoff, oldest first; :func:`expired_prefix` then keeps only the
        leading run that is expired under each row's own class, so the
        deleted set is always a contiguous prefix of the chain.
        """

        from z4j_brain.domain.audit_service import AuditService
        from z4j_brain.persistence.repositories import AuditLogRepository

        repo = AuditLogRepository(session)
        if is_postgres:
            lock_row = await session.execute(
                text("SELECT pg_try_advisory_xact_lock(:k)"),
                {"k": _SWEEP_ADVISORY_LOCK_KEY},
            )
            if not bool(lock_row.scalar()):
                raise SweepLeaseBusyError("another worker holds the audit retention sweep lock")
        await repo.acquire_chain_lock()
        state = await repo.get_chain_state_for_update()
        state_payload = authenticate_state(state, keyring)
        if state_payload["state_key_id"] != current_key_id:
            raise AuditChainIntegrityError(
                "configured current audit key differs from authenticated state",
            )

        head = await repo.get_active_head_for_update(
            generation=state.generation,
        )
        actual_count = await repo.count_active_generation(
            generation=state.generation,
        )
        if actual_count != state.active_row_count:
            raise AuditChainIntegrityError(
                "active audit row count does not match authenticated state",
            )
        verifier = AuditService(self._settings)
        if state.active_row_count == 0:
            if head is not None:
                raise AuditChainIntegrityError(
                    "authenticated state says empty but an active head exists",
                )
            return 0
        if head is None:
            raise AuditChainIntegrityError(
                "authenticated active audit head is missing",
            )
        if (
            head.row_hmac != state.head_row_hmac
            or head.hmac_key_id != state.head_hmac_key_id
            or normalize_timestamp(head.occurred_at) != normalize_timestamp(state.head_occurred_at)
            or head.id != state.head_id
            or head.chain_generation != state.generation
            or head.legacy_frozen is not False
            or head.hmac_version != AUDIT_ROW_HMAC_VERSION
            or not verifier.verify_row(head)
        ):
            raise AuditChainIntegrityError(
                "live audit head does not authenticate against state",
            )

        stmt = (
            select(AuditLog)
            .where(
                AuditLog.legacy_frozen.is_(False),
                AuditLog.chain_generation == state.generation,
                AuditLog.occurred_at < cutoffs.latest,
            )
            .order_by(AuditLog.occurred_at.asc(), AuditLog.id.asc())
            .limit(batch_size)
        )
        if is_postgres:
            stmt = stmt.with_for_update()
        candidates = list((await session.execute(stmt)).scalars().all())
        selected = expired_prefix(candidates, cutoffs)
        await warn_when_prefix_blocked(
            session,
            candidates=candidates,
            kept=len(selected),
            cutoffs=cutoffs,
            generation=state.generation,
        )
        if not selected:
            return 0

        successor_stmt = (
            select(AuditLog)
            .where(
                AuditLog.legacy_frozen.is_(False),
                AuditLog.chain_generation == state.generation,
                (
                    (AuditLog.occurred_at > selected[-1].occurred_at)
                    | (
                        (AuditLog.occurred_at == selected[-1].occurred_at)
                        & (AuditLog.id > selected[-1].id)
                    )
                ),
            )
            .order_by(AuditLog.occurred_at.asc(), AuditLog.id.asc())
            .limit(1)
        )
        if is_postgres:
            successor_stmt = successor_stmt.with_for_update()
        successor = (await session.execute(successor_stmt)).scalar_one_or_none()

        expected_prev = state.prune_row_hmac
        if expected_prev is None:
            if selected[0].prev_row_hmac is not None:
                raise AuditChainIntegrityError(
                    "oldest active row is not the generation genesis",
                )
        else:
            if selected[0].prev_row_hmac != expected_prev:
                raise AuditChainIntegrityError(
                    "oldest active row does not follow the authenticated prune boundary",
                )
            if (
                normalize_timestamp(selected[0].occurred_at),
                selected[0].id.int,
            ) <= (
                normalize_timestamp(state.prune_occurred_at),
                state.prune_id.int,
            ):
                raise AuditChainIntegrityError(
                    "selected prefix does not sort after the prune boundary",
                )

        prior_hmac = expected_prev
        for row in selected:
            if row.prev_row_hmac != prior_hmac:
                raise AuditChainIntegrityError(
                    "selected audit prefix contains a broken link",
                )
            if not verifier.verify_row(row):
                raise AuditChainIntegrityError(
                    "selected audit prefix contains an invalid row HMAC",
                )
            prior_hmac = row.row_hmac
        if successor is not None and (
            successor.prev_row_hmac != prior_hmac or not verifier.verify_row(successor)
        ):
            raise AuditChainIntegrityError(
                "audit prefix successor does not authenticate",
            )

        await repo.set_chain_transition("retention-v1")
        if is_postgres:
            # The preparation migration replaces the legacy branch with the
            # transition guard.  Setting both keeps this implementation able
            # to test against the pre-activation trigger without treating the
            # old permission as signing authority.
            await session.execute(text("SET LOCAL z4j.audit_sweep = 'on'"))
        deleted = await session.execute(
            delete(AuditLog).where(AuditLog.id.in_([row.id for row in selected])),
        )
        if int(deleted.rowcount or 0) != len(selected):
            raise AuditChainIntegrityError(
                "authenticated retention deleted an unexpected row count",
            )

        counts = dict(state.active_key_counts)
        for row in selected:
            key_id = row.hmac_key_id
            if key_id is None or counts.get(key_id, 0) <= 0:
                raise AuditChainIntegrityError(
                    "selected row key is absent from authenticated key counts",
                )
            counts[key_id] -= 1
            if counts[key_id] == 0:
                del counts[key_id]
        boundary = selected[-1]
        state.prune_row_hmac = boundary.row_hmac
        state.prune_hmac_key_id = boundary.hmac_key_id
        state.prune_occurred_at = boundary.occurred_at
        state.prune_id = boundary.id
        state.active_row_count -= len(selected)
        state.active_key_counts = counts
        state.state_mac = compute_state_mac(keyring[current_key_id], state)
        await session.flush()
        return len(selected)

    async def _sweep_one_batch_postgres(
        self,
        session,
        *,
        cutoffs: RetentionCutoffs,
        batch_size: int,
    ) -> int:
        """Delete one bounded batch on Postgres.

        Uses ``SET LOCAL z4j.audit_sweep = 'on'`` so the trigger
        function added in migration 0015 permits the DELETE.
        ``FOR UPDATE SKIP LOCKED`` cooperates with concurrent
        readers. The candidates are selected first and trimmed to the
        expired prefix under each row's class, then deleted by id.

        Scoping note: per Postgres docs, ``SET LOCAL`` is
        TRANSACTION-scoped, not SAVEPOINT-scoped. The GUC
        therefore persists across savepoint releases until the
        outer COMMIT/ROLLBACK. We deliberately re-set it every
        batch as belt-and-suspenders so a future refactor that
        drops the per-batch SAVEPOINT (or moves the lock-and-loop
        out of the explicit outer begin) still has the GUC set
        for every DELETE.

        The SAVEPOINT itself isolates errors: a row-level failure
        in one batch rolls back to the SAVEPOINT without aborting
        the entire pass + losing the advisory lock.
        """
        async with session.begin_nested():
            await session.execute(
                text("SET LOCAL z4j.audit_sweep = 'on'"),
            )
            candidates = (
                await session.execute(
                    select(AuditLog.id, AuditLog.action, AuditLog.occurred_at)
                    .where(AuditLog.occurred_at < cutoffs.latest)
                    .order_by(AuditLog.occurred_at.asc(), AuditLog.id.asc())
                    .limit(batch_size)
                    .with_for_update(skip_locked=True),
                )
            ).all()
            doomed = expired_prefix(candidates, cutoffs)
            await warn_when_prefix_blocked(
                session,
                candidates=candidates,
                kept=len(doomed),
                cutoffs=cutoffs,
            )
            if not doomed:
                return 0
            result = await session.execute(
                delete(AuditLog).where(AuditLog.id.in_([row.id for row in doomed])),
            )
            return int(result.rowcount or 0)

    async def _sweep_one_batch_sqlite(
        self,
        *,
        cutoffs: RetentionCutoffs,
        batch_size: int,
    ) -> int:
        """Delete one bounded batch on SQLite, in its own tx."""
        async with self._db.session() as session:  # type: ignore[union-attr]
            candidates = (
                await session.execute(
                    select(AuditLog.id, AuditLog.action, AuditLog.occurred_at)
                    .where(AuditLog.occurred_at < cutoffs.latest)
                    .order_by(AuditLog.occurred_at.asc(), AuditLog.id.asc())
                    .limit(batch_size),
                )
            ).all()
            doomed = expired_prefix(candidates, cutoffs)
            await warn_when_prefix_blocked(
                session,
                candidates=candidates,
                kept=len(doomed),
                cutoffs=cutoffs,
            )
            if not doomed:
                return 0
            result = await session.execute(
                delete(AuditLog).where(AuditLog.id.in_([row.id for row in doomed])),
            )
            await session.commit()
            return int(result.rowcount or 0)

    async def _record_prune_watermark(self) -> None:
        """Advance the audit HMAC-chain prune watermark after a sweep.

        Retention deletes the oldest rows, INCLUDING the genesis row
        (``prev_row_hmac IS NULL``). Without a watermark the chain
        verifier then flags the first surviving row -- which now carries
        a non-NULL ``prev_row_hmac`` -- as a truncation MISMATCH forever.
        We record the prune boundary, the ``row_hmac`` of the newest row
        just deleted, which equals the oldest surviving row's
        ``prev_row_hmac`` (the deleted set is a contiguous oldest-first
        prefix; see ``AuditLogRepository.get_oldest_prev_row_hmac``), into
        the ``z4j_meta`` watermark. The verifier accepts a first
        surviving row whose ``prev_row_hmac`` matches it, while a genuine
        tamper (a deleted MIDDLE row or an altered ``row_hmac``) still
        fails.

        Deriving the boundary from the surviving row keeps the DELETE SQL
        untouched and behaves identically on Postgres and SQLite. If the
        sweep emptied the table, the next audit row re-anchors as a NULL
        genesis, so no watermark is needed and any prior value is left
        untouched.
        """
        assert self._db is not None
        assert self._settings is not None
        from z4j_brain.persistence.repositories import AuditLogRepository

        secret = self._settings.secret.get_secret_value().encode("utf-8")
        async with self._db.session() as session:
            repo = AuditLogRepository(session)
            boundary = await repo.get_oldest_prev_row_hmac()
            if boundary is None:
                return
            # Store the watermark authenticated to the master secret, which
            # is not in the database, so re-anchoring the chain past a
            # prefix-truncation takes a value the brain actually signed
            # (see ``_watermark_mac``). That raises the cost of inventing a
            # new boundary, not of restoring an older real one: a role that
            # can write this row can put back a watermark from an earlier
            # sweep and delete the rows after it, and the MAC still checks
            # out because it was genuine when it was written.
            await repo.set_prune_watermark(boundary, secret=secret)
            await session.commit()

    # ------------------------------------------------------------------
    # agent_status_history sweep (1.5.0+)
    # ------------------------------------------------------------------

    async def _do_sweep_agent_status(self) -> int:
        """Purge ``agent_status_history`` rows older than the cutoff.

        Uses ``settings.event_retention_days`` for the cutoff (NOT
        ``audit_retention_days``) because agent_status is high-
        frequency observability data, not an audit trail. Reuses the
        same per-batch cap + max-per-pass discipline as the audit
        sweep so the worst-case transaction window stays bounded.

        Unlike the audit_log path there is no DB-level mutation
        guard to bypass: ``agent_status_history`` is plain
        append-only by application convention. This helper uses one
        committed session per batch on both dialects and does not
        acquire the audit sweep advisory lock. Concurrent replicas can
        therefore race over candidate rows; each bounded DELETE remains
        authoritative for its own returned row count.
        """
        assert self._db is not None
        assert self._settings is not None

        retention_days = self._settings.event_retention_days
        if retention_days <= 0:
            self._last_agent_status_deleted = 0
            return 0

        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        batch_size = max(
            100,
            self._settings.audit_retention_sweep_batch_size,
        )
        max_per_pass = max(
            batch_size,
            self._settings.audit_retention_sweep_max_per_pass,
        )

        from z4j_brain.persistence.repositories.agent_status_history import (
            AgentStatusHistoryRepository,
        )

        total = 0
        # Per-batch session so each commit returns the connection to
        # the pool quickly. Mirrors the SQLite path in the audit
        # sweep; on Postgres the plain DELETE doesn't need the
        # ``SET LOCAL`` GUC because there is no append-only trigger.
        while not self._stop_event.is_set() and total < max_per_pass:
            async with self._db.session() as session:
                repo = AgentStatusHistoryRepository(session)
                rows = await repo.delete_older_than(
                    cutoff=cutoff,
                    batch_size=batch_size,
                )
                await session.commit()
            total += rows
            if rows < batch_size:
                break

        self._last_agent_status_deleted = total
        self._total_agent_status_deleted += total
        if total:
            logger.info(
                "z4j.brain.audit_retention: pruned %d agent_status_history "
                "rows older than %s (event_retention_days=%d)",
                total,
                cutoff.isoformat(),
                retention_days,
            )
        return total


__all__ = [
    "AUDIT_PRUNE_ACTION",
    "AuditRetentionSweeper",
    "PrunePreview",
    "RetentionCutoffs",
    "SweepLeaseBusyError",
    "action_class",
    "expired_predicate",
    "expired_prefix",
    "preview_authenticated_prune",
    "warn_when_prefix_blocked",
]
