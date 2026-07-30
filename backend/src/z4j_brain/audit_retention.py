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

- Postgres: opens ONE transaction per batch, ``SET LOCAL
  z4j.audit_sweep = 'on'`` (the trigger function added in
  ``2026_05_01_0015_audit_sweep`` permits DELETE iff that GUC is
  on), then ``DELETE FROM audit_log WHERE occurred_at < cutoff``
  in batches. ``SET LOCAL`` dies at COMMIT/ROLLBACK so each
  batch's GUC scope is contained. A
  ``pg_try_advisory_lock(hashtext('z4j.audit_sweep'))`` at the
  top of the pass means only one brain replica holds the sweep
  at a time, the others see the lock fail and skip the pass
  cleanly. (Audit fix MED-15.)
- SQLite: no trigger; plain DELETE. Most homelabs run SQLite,
  so this is the common path. SQLite is single-writer so the
  advisory-lock dance is unnecessary.

The sweep runs on a fixed cadence
(``audit_retention_sweep_interval_seconds``, default 3600s = 1h).
Each pass deletes in batches of
``audit_retention_sweep_batch_size`` to avoid long-running
transactions, AND caps the *whole* pass at
``audit_retention_sweep_max_per_pass`` so a multi-million-row
backlog doesn't run as one runaway transaction window. Errors
are logged but never crash the task; the next tick retries.

The hash chain (``prev_row_hmac``) breaks at the boundary where
old rows are deleted. Verification of the surviving chain still
works from the new oldest row forward, which is the documented
behaviour of any time-based audit retention policy.

1.5.0 extension: the same task body also purges
``agent_status_history`` rows older than
``settings.event_retention_days`` (NOT ``audit_retention_days`` -
agent_status is high-frequency observability data, more like the
event stream than the audit trail, so it shares the events
retention knob). The agent_status sweep runs in the same pass as
the audit sweep so operators only have one cadence to tune. The
sweeper class name is unchanged for backward compatibility; the
agent_status pass is implemented as an adjacent helper that
shares the same advisory-lock + cap discipline.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import delete, select, text

from z4j_brain.domain.audit_chain import (
    AUDIT_ROW_HMAC_VERSION,
    AuditChainIntegrityError,
    authenticate_state,
    build_audit_keyring,
    compute_state_mac,
    normalize_timestamp,
)
from z4j_brain.persistence.models import AuditLog

if TYPE_CHECKING:
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings

logger = logging.getLogger("z4j.brain.audit_retention")


#: Postgres advisory-lock key for cross-worker sweep coordination.
#: Computed from ``hashtext('z4j.audit_sweep')``, any int32 will
#: do, but using ``hashtext`` keeps it readable in the migration's
#: comments. Audit fix MED-15.
_SWEEP_ADVISORY_LOCK_KEY: int = 0x7A346A41  # "z4jaA" stable seed


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

    def start(
        self,
        *,
        db: DatabaseManager,
        settings: Settings,
    ) -> None:
        """Spawn the sweep task. Idempotent."""
        if self._task is not None:
            return
        self._db = db
        self._settings = settings
        self._stop_event.clear()
        self._task = asyncio.create_task(
            self._loop(),
            name="z4j.brain.audit_retention.sweep",
        )

    async def stop(self) -> None:
        """Signal the task to exit and wait briefly for it.

        Audit fix CRIT-2: ``CancelledError`` raised into ``stop()``
        from the outer lifespan (e.g. uvicorn shutdown timeout)
        propagates up, it MUST NOT be swallowed, otherwise the
        cancellation never reaches the parent and shutdown stalls.
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

        Per-batch transactions keep the WAL footprint bounded.
        Postgres advisory-locks the sweep so multiple workers
        don't fight. Caps at
        ``audit_retention_sweep_max_per_pass`` rows per pass
        to avoid a runaway transaction window.
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

        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
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
                        cutoff=cutoff,
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
                    cutoff=cutoff,
                    batch_size=batch_size,
                )
                total += rows
                if rows < batch_size:
                    break

        # Record the HMAC-chain prune boundary so `z4j audit verify`
        # does not permanently false-positive on the first surviving row
        # once retention has deleted the genesis row. (1.7 audit.)
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
                "z4j.brain.audit_retention: pruned %d rows older than %s (retention_days=%d)",
                total,
                cutoff.isoformat(),
                retention_days,
            )
        return total

    async def _do_sweep_v2(self) -> int:
        """Delete authenticated v2 prefixes and advance state atomically."""

        assert self._db is not None
        assert self._settings is not None

        self._last_error = None
        retention_days = self._settings.audit_retention_days
        if retention_days <= 0:
            return 0
        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
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
            async with self._db.session() as session:
                is_postgres = session.bind is not None and (
                    session.bind.dialect.name == "postgresql"
                )
                if is_postgres:
                    async with session.begin():
                        rows = await self._sweep_one_batch_v2(
                            session,
                            cutoff=cutoff,
                            batch_size=min(batch_size, max_per_pass - total),
                            current_key_id=current_key_id,
                            keyring=keyring,
                            is_postgres=True,
                        )
                else:
                    # SQLite must obtain its writer reservation before its
                    # first read; upgrading a deferred read transaction after
                    # inspecting state is forbidden.
                    await session.execute(text("BEGIN IMMEDIATE"))
                    try:
                        rows = await self._sweep_one_batch_v2(
                            session,
                            cutoff=cutoff,
                            batch_size=min(batch_size, max_per_pass - total),
                            current_key_id=current_key_id,
                            keyring=keyring,
                            is_postgres=False,
                        )
                        await session.commit()
                    except BaseException:
                        await session.rollback()
                        raise
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
                "removed %d rows older than %s",
                total,
                cutoff.isoformat(),
            )
        return total

    async def _sweep_one_batch_v2(  # noqa: PLR0912, PLR0915
        self,
        session,
        *,
        cutoff: datetime,
        batch_size: int,
        current_key_id: str,
        keyring: dict[str, bytes],
        is_postgres: bool,
    ) -> int:
        """Verify and delete exactly one oldest active-generation prefix."""

        from z4j_brain.domain.audit_service import AuditService
        from z4j_brain.persistence.repositories import AuditLogRepository

        repo = AuditLogRepository(session)
        if is_postgres:
            lock_row = await session.execute(
                text("SELECT pg_try_advisory_xact_lock(:k)"),
                {"k": _SWEEP_ADVISORY_LOCK_KEY},
            )
            if not bool(lock_row.scalar()):
                return 0
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
                AuditLog.occurred_at < cutoff,
            )
            .order_by(AuditLog.occurred_at.asc(), AuditLog.id.asc())
            .limit(batch_size)
        )
        if is_postgres:
            stmt = stmt.with_for_update()
        selected = list((await session.execute(stmt)).scalars().all())
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
        cutoff: datetime,
        batch_size: int,
    ) -> int:
        """Delete one bounded batch on Postgres.

        Uses ``SET LOCAL z4j.audit_sweep = 'on'`` so the trigger
        function added in migration 0015 permits the DELETE.
        ``FOR UPDATE SKIP LOCKED`` cooperates with concurrent
        readers.

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
            result = await session.execute(
                text(
                    "DELETE FROM audit_log "
                    "WHERE id IN ("
                    "  SELECT id FROM audit_log "
                    "  WHERE occurred_at < :cutoff "
                    "  ORDER BY occurred_at "
                    "  LIMIT :limit "
                    "  FOR UPDATE SKIP LOCKED"
                    ") RETURNING 1",
                ),
                {"cutoff": cutoff, "limit": batch_size},
            )
            return len(result.fetchall())

    async def _sweep_one_batch_sqlite(
        self,
        *,
        cutoff: datetime,
        batch_size: int,
    ) -> int:
        """Delete one bounded batch on SQLite, in its own tx."""
        async with self._db.session() as session:  # type: ignore[union-attr]
            result = await session.execute(
                delete(AuditLog).where(
                    AuditLog.id.in_(
                        text(
                            "SELECT id FROM audit_log "
                            "WHERE occurred_at < :cutoff "
                            "ORDER BY occurred_at LIMIT :limit",
                        ).bindparams(
                            cutoff=cutoff,
                            limit=batch_size,
                        ),
                    ),
                ),
            )
            await session.commit()
            return result.rowcount or 0

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
            # Store the watermark authenticated to the master secret so a
            # DB-write adversary cannot re-anchor the chain past a
            # prefix-truncation (see ``_watermark_mac``).
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
        append-only by application convention. The Postgres path
        therefore skips the ``SET LOCAL`` GUC dance but still uses
        the advisory-lock pattern when other replicas might race
        on the same table.
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


__all__ = ["AuditRetentionSweeper"]
