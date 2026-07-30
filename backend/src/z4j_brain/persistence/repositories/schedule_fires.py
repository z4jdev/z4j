"""``schedule_fires`` repository.

Three operation surfaces:

- :meth:`record` - the FireSchedule handler creates a row when
  it dispatches (status=delivered/buffered/failed).
- :meth:`acknowledge` - the AcknowledgeFireResult handler updates
  the row with ack outcome + latency.
- :meth:`list_recent_for_schedule` / :meth:`recent_failures` -
  read paths for the dashboard + circuit breaker worker.

Inserts are idempotent on ``fire_id`` so a scheduler retry doesn't
duplicate the row. Updates are bounded WHERE-clauses so the
acknowledge path can't accidentally rewrite history.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import and_, delete, exists, or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.domain.schedule_fire_authority import (
    SCHEDULE_FIRE_PROTOCOL_MARKER,
)
from z4j_brain.persistence.models import (
    Command,
    ScheduleFire,
    ScheduleOccurrenceResolution,
)
from z4j_brain.persistence.schedule_guard import (
    arm_evidence_delete,
    assert_evidence_delete_consumed,
)

_MAX_PERSISTED_LATENCY_MS = 2_147_483_647


def _slot_key(dt: datetime) -> datetime:
    """A tz- and sub-second-normalised key for comparing two
    ``scheduled_for`` values across a DB round-trip. SQLite drops the tz (naive)
    and a fire_id identifies a whole-SECOND slot (derive_fire_id ignores
    microseconds), so compare naive-UTC whole seconds -- otherwise a legitimate
    idempotent retry (aware in memory vs naive from the DB) would falsely look
    divergent."""
    naive = dt.replace(tzinfo=None) if dt.tzinfo is not None else dt
    return naive.replace(microsecond=0)


class ScheduleFireRepository:
    """``schedule_fires`` table CRUD."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def record_current(
        self,
        *,
        fire_id: UUID,
        schedule_id: UUID,
        project_id: UUID,
        command_id: UUID | None,
        status: str,
        scheduled_for: datetime,
        observed_control_token: UUID | None,
        receipt_control_token: UUID,
        acceptance_revision: int,
        definition_digest: str,
        expected_schedule_revision: int,
        expected_last_run_at: datetime | None,
        expected_next_run_at: datetime,
        prepared_next_run_at: datetime | None,
        fired_at: datetime | None = None,
        triggered_by_user_id: UUID | None = None,
    ) -> tuple[ScheduleFire, bool]:
        """Insert/reuse exact generation-scoped current fire history."""

        resolved_legacy = exists().where(
            ScheduleOccurrenceResolution.schedule_id == ScheduleFire.schedule_id,
            ScheduleOccurrenceResolution.fire_id == ScheduleFire.fire_id,
            ScheduleOccurrenceResolution.scheduled_for == ScheduleFire.scheduled_for,
        )
        unresolved_legacy = await self.session.scalar(
            select(
                exists().where(
                    ScheduleFire.fire_id == fire_id,
                    ScheduleFire.receipt_control_token.is_(None),
                    ~resolved_legacy,
                ),
            ),
        )
        if unresolved_legacy:
            raise ValueError(
                "unresolved legacy fire identity blocks current acceptance",
            )
        row = ScheduleFire(
            fire_id=fire_id,
            schedule_id=schedule_id,
            project_id=project_id,
            command_id=command_id,
            status=status,
            scheduled_for=scheduled_for,
            fired_at=fired_at or datetime.now(UTC),
            triggered_by_user_id=triggered_by_user_id,
            protocol_marker=SCHEDULE_FIRE_PROTOCOL_MARKER,
            state_write_nonce=uuid4(),
            observed_control_token=observed_control_token,
            receipt_control_token=receipt_control_token,
            acceptance_revision=acceptance_revision,
            definition_digest=definition_digest,
            expected_schedule_revision=expected_schedule_revision,
            expected_last_run_at=expected_last_run_at,
            expected_next_run_at=expected_next_run_at,
            prepared_next_run_at=prepared_next_run_at,
        )
        try:
            async with self.session.begin_nested():
                self.session.add(row)
                await self.session.flush()
        except IntegrityError:
            existing = await self._get_by_identity(
                fire_id=fire_id,
                receipt_control_token=receipt_control_token,
                scheduled_for=scheduled_for,
            )
            if existing is None:
                raise
            exact = (
                existing.schedule_id == schedule_id
                and existing.project_id == project_id
                and existing.command_id == command_id
                and existing.status == status
                and _slot_key(existing.scheduled_for) == _slot_key(scheduled_for)
                and existing.protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER
                and existing.observed_control_token == observed_control_token
                and existing.receipt_control_token == receipt_control_token
                and existing.acceptance_revision == acceptance_revision
                and existing.definition_digest == definition_digest
                and existing.expected_schedule_revision == expected_schedule_revision
                and _same_datetime(
                    existing.expected_last_run_at,
                    expected_last_run_at,
                )
                and _same_datetime(
                    existing.expected_next_run_at,
                    expected_next_run_at,
                )
                and _same_datetime(
                    existing.prepared_next_run_at,
                    prepared_next_run_at,
                )
            )
            if not exact:
                raise ValueError(
                    "current fire receipt identity is divergent",
                ) from None
            return existing, False
        return row, True

    async def record(
        self,
        *,
        fire_id: UUID,
        schedule_id: UUID,
        project_id: UUID,
        command_id: UUID | None,
        status: str,
        scheduled_for: datetime,
        fired_at: datetime | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
        triggered_by_user_id: UUID | None = None,
    ) -> ScheduleFire:
        """Insert one fire row. Idempotent on ``fire_id``.

        A second insert of the same fire_id upgrades the row's
        ``status`` (e.g. ``buffered → delivered``) and returns the
        updated row. Lets the FireSchedule retry path + the
        pending-fires replay worker write the row blindly without
        TOCTOU concerns.

        A bare ``session.rollback()`` on IntegrityError would
        wipe the caller's ENTIRE outer transaction (releasing
        FOR UPDATE locks + discarding queued audit/dispatcher
        writes). We use a SAVEPOINT (``begin_nested``) so only
        the failed INSERT rolls back. The upgrade case
        (buffered → delivered) updates the row's status +
        command_id so the dashboard's "buffered" state correctly
        progresses to "delivered" once the agent comes online.
        """
        # Enforce single-identity per fire_id BEFORE inserting. On Postgres
        # the fire-history table is partitioned and its unique key is the COMPOSITE
        # (fire_id, scheduled_for), so a reused fire_id at a DIFFERENT second does
        # NOT raise IntegrityError -- it inserts a SECOND row and the later
        # bare-fire_id ack lookup then raises MultipleResultsFound. Probe UNPRUNED
        # (fire_id only) and refuse any existing row whose (schedule, project,
        # scheduled_for) differs, so one fire_id can never map to two rows / credit
        # two schedules. (The normal idempotent retry matches on all three and
        # proceeds to the upgrade path below.)
        prior = await self._get_by_fire_id(fire_id)
        if prior is not None and (
            prior.schedule_id != schedule_id
            or prior.project_id != project_id
            or _slot_key(prior.scheduled_for) != _slot_key(scheduled_for)
        ):
            raise ValueError(
                f"fire_id {fire_id} already recorded for a different "
                f"schedule/project/slot; refusing to record a divergent row",
            )
        row = ScheduleFire(
            fire_id=fire_id,
            schedule_id=schedule_id,
            project_id=project_id,
            command_id=command_id,
            status=status,
            scheduled_for=scheduled_for,
            fired_at=fired_at or datetime.now(UTC),
            error_code=error_code,
            error_message=(error_message[:2000] if error_message else None),
            triggered_by_user_id=triggered_by_user_id,
        )
        try:
            async with self.session.begin_nested():
                self.session.add(row)
                await self.session.flush()
        except IntegrityError:
            # Prune to the single partition on Postgres: scheduled_for is
            # stable per fire_id and we have it here, so the buffered ->
            # delivered upgrade lookup is a single-partition probe, not a
            # scan of every daily partition.
            existing = await self._get_by_fire_id(fire_id, scheduled_for=scheduled_for)
            if existing is None:
                raise
            # A fire_id must map to exactly ONE (schedule, project). If a
            # buggy or hostile trusted peer reuses a fire_id across schedules, the
            # blind upgrade below would dispatch/credit the WRONG schedule
            # (schedule B's fire mutating schedule A's history row). Refuse the
            # cross-identity collision instead of silently rewriting it.
            if existing.schedule_id != schedule_id or existing.project_id != project_id:
                raise ValueError(
                    f"fire_id {fire_id} already recorded for a different "
                    f"schedule/project; refusing to rewrite it",
                ) from None
            # Upgrade transitions: buffered → delivered/failed,
            # delivered → acked_*. Do NOT downgrade an acked row
            # back to delivered (a late retry of FireSchedule for
            # an already-acked fire would otherwise rewrite
            # history). _UPGRADE_TRANSITIONS encodes the
            # permitted state machine.
            if _is_status_upgrade(existing.status, status):
                existing.status = status
                if command_id is not None:
                    existing.command_id = command_id
                # Preserve an existing trigger attribution: the replay
                # worker upgrades buffered -> delivered with None here, so
                # only set it when explicitly supplied (never clobber a
                # real user id back to NULL).
                if triggered_by_user_id is not None:
                    existing.triggered_by_user_id = triggered_by_user_id
                if error_code is not None:
                    existing.error_code = error_code[:64]
                if error_message is not None:
                    existing.error_message = error_message[:2000]
                await self.session.flush()
            return existing
        return row

    @staticmethod
    def _latency_ms(fired_at: datetime | None, now: datetime) -> int | None:
        """Return a non-negative latency that fits the DB's 32-bit INTEGER."""
        if fired_at is None:
            return None
        now_naive = now.replace(tzinfo=None)
        fired_at_naive = fired_at.replace(tzinfo=None) if fired_at.tzinfo is not None else fired_at
        elapsed_ms = int(max(0, (now_naive - fired_at_naive).total_seconds() * 1000))
        return min(elapsed_ms, _MAX_PERSISTED_LATENCY_MS)

    async def acknowledge(
        self,
        *,
        fire_id: UUID,
        status: str,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> tuple[ScheduleFire | None, bool, bool]:
        """Atomically record the ack outcome. Returns ``(row, should_notify, became_success)``.

        RM2/RM3/RL1: the status transition is a SINGLE guarded Core UPDATE, so
        concurrent acks can neither both advance counters nor both fan out a
        notification; the status is TERMINAL-PREFERRING toward success (a late
        FAILED ack never downgrades an already-``acked_success`` row); and a
        success transition clears the stale failure detail.

        - ``row`` is the row (refreshed) or None if no row exists for ``fire_id``.
        - ``became_success`` is True iff THIS ack transitioned the row INTO
          ``acked_success`` (the guarded ``WHERE status != 'acked_success'``
          UPDATE matched exactly one row). The handler advances the schedule's
          lifetime counters on this, so a success ack following a failed ack of
          the same fire_id advances exactly once and a duplicate success ack does
          not double-count.
        - ``should_notify`` is True iff THIS ack is the one that should fan out a
          notification (dedup across HA retries / network duplicates): for a
          SUCCESS ack it equals ``became_success`` (announce the fire / the
          failed->success recovery once); for a FAILED ack it is True only on the
          FIRST ack of the fire (the ``WHERE acked_at IS NULL`` UPDATE matched),
          so a duplicate or after-success failed ack neither downgrades nor
          re-pages.
        """
        existing = await self._get_by_fire_id(fire_id)
        if existing is None:
            return None, False, False
        now = datetime.now(UTC)
        latency_ms = self._latency_ms(existing.fired_at, now)
        if status == "acked_success":
            # Atomic success transition. WHERE status != acked_success lets a
            # failed->success recovery through (RL1) but a duplicate success get
            # rowcount 0. Clears the stale failure detail on the transition.
            result = await self.session.execute(
                update(ScheduleFire)
                .where(
                    ScheduleFire.fire_id == fire_id,
                    ScheduleFire.status != "acked_success",
                )
                .values(
                    status="acked_success",
                    acked_at=now,
                    error_code=None,
                    error_message=None,
                    latency_ms=latency_ms,
                ),
            )
            became_success = (result.rowcount or 0) == 1
            should_notify = became_success
        else:
            # Failed / non-success ack: only the FIRST ack of the fire transitions
            # (WHERE acked_at IS NULL), so it never downgrades an already-acked
            # (success OR failed) row (RM3) and pages exactly once (RM2).
            result = await self.session.execute(
                update(ScheduleFire)
                .where(
                    ScheduleFire.fire_id == fire_id,
                    ScheduleFire.acked_at.is_(None),
                )
                .values(
                    status=status,
                    acked_at=now,
                    error_code=error_code[:64] if error_code is not None else None,
                    error_message=(error_message[:2000] if error_message is not None else None),
                    latency_ms=latency_ms,
                ),
            )
            should_notify = (result.rowcount or 0) == 1
            became_success = False
        await self.session.flush()
        # Reload so the returned row reflects the post-UPDATE state (the Core
        # UPDATE bypasses the ORM identity map). Callers read immutable fields
        # (scheduled_for, triggered_by_user_id) for RH5/RH6.
        await self.session.refresh(existing)
        return existing, should_notify, became_success

    async def acknowledge_current_command(
        self,
        *,
        command: Command,
        fire_id: UUID,
        status: str,
        new_task_id: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> tuple[ScheduleFire | None, bool]:
        """Record a scheduler receipt for one exact current command.

        ``AcknowledgeFireResult`` reports the already-returned FireSchedule
        round trip, not agent execution.  It therefore writes only the
        dedicated scheduler-ack history fields.  A retained history row must
        match the command's complete immutable cadence tuple; if retention
        already removed it, the acknowledgement is an idempotent history
        no-op.
        """

        if not _complete_current_command(command):
            raise ValueError("current cadence command evidence is incomplete")
        if command.schedule_fire_id != fire_id:
            raise ValueError("scheduler fire id does not match command evidence")
        assert command.schedule_receipt_control_token is not None
        fire = await self._get_by_identity(
            fire_id=fire_id,
            receipt_control_token=command.schedule_receipt_control_token,
            scheduled_for=command.schedule_scheduled_for,
        )
        if fire is None:
            return None, False
        if not _current_fire_matches_command(fire, command):
            raise ValueError("current fire history diverges from command evidence")
        return await self._acknowledge_current_row(
            fire=fire,
            status=status,
            new_task_id=new_task_id,
            error_code=error_code,
            error_message=error_message,
        )

    async def acknowledge_current_unbound(
        self,
        *,
        fire: ScheduleFire,
        status: str,
        new_task_id: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> tuple[ScheduleFire, bool]:
        """Record a command-less current scheduler receipt.

        This is limited to a single exact retained current fire whose
        ``command_id`` is still NULL (the buffered/pre-command shape).  It
        cannot be used to acknowledge a receipt-bound command without the
        command id returned by FireSchedule.
        """

        if not _complete_current_fire(fire) or fire.command_id is not None:
            raise ValueError(
                "command-less acknowledgement lacks exact current fire evidence",
            )
        return await self._acknowledge_current_row(
            fire=fire,
            status=status,
            new_task_id=new_task_id,
            error_code=error_code,
            error_message=error_message,
        )

    async def acknowledge_legacy_history(
        self,
        *,
        fire: ScheduleFire,
        command_id: UUID | None,
        status: str,
        new_task_id: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> tuple[ScheduleFire, bool]:
        """Record a migrated tokenless scheduler receipt as history only.

        Boundary-D activation marks pre-1.8 fire evidence but deliberately
        leaves its receipt authority NULL.  Such a receipt can never project
        schedule cadence or command state.  It may only update the dedicated
        scheduler-ack history fields on the exact retained fire row.
        """

        if (
            fire.protocol_marker != SCHEDULE_FIRE_PROTOCOL_MARKER
            or fire.receipt_control_token is not None
            or fire.state_write_nonce is None
        ):
            raise ValueError("legacy scheduler receipt is not tokenless evidence")
        if command_id is not None and fire.command_id != command_id:
            raise ValueError("legacy command id does not match fire evidence")
        if fire.status == "operator_skipped":
            return fire, False
        return await self._acknowledge_current_row(
            fire=fire,
            status=status,
            new_task_id=new_task_id,
            error_code=error_code,
            error_message=error_message,
        )

    async def _acknowledge_current_row(
        self,
        *,
        fire: ScheduleFire,
        status: str,
        new_task_id: str | None,
        error_code: str | None,
        error_message: str | None,
    ) -> tuple[ScheduleFire, bool]:
        """Apply one nonce-guarded history-only scheduler receipt."""

        assert fire.state_write_nonce is not None
        now = datetime.now(UTC)
        latency_ms = self._latency_ms(fire.fired_at, now)
        predicates = [
            ScheduleFire.id == fire.id,
            ScheduleFire.fire_id == fire.fire_id,
            ScheduleFire.receipt_control_token == fire.receipt_control_token,
            ScheduleFire.state_write_nonce == fire.state_write_nonce,
        ]
        values: dict[str, object] = {
            "scheduler_acknowledged_at": now,
            "scheduler_ack_task_id": (new_task_id[:200] if new_task_id else None),
            "latency_ms": latency_ms,
            "state_write_nonce": uuid4(),
        }
        if status == "success":
            predicates.append(
                or_(
                    ScheduleFire.scheduler_ack_status.is_(None),
                    ScheduleFire.scheduler_ack_status != "success",
                ),
            )
            values.update(
                scheduler_ack_status="success",
                scheduler_ack_error_code=None,
                scheduler_ack_error_message=None,
            )
        else:
            predicates.append(ScheduleFire.scheduler_ack_status.is_(None))
            values.update(
                scheduler_ack_status="failed",
                scheduler_ack_error_code=(error_code[:64] if error_code is not None else None),
                scheduler_ack_error_message=(
                    error_message[:2000] if error_message is not None else None
                ),
            )
        result = await self.session.execute(
            update(ScheduleFire)
            .where(*predicates)
            .values(**values)
            .execution_options(synchronize_session=False),
        )
        should_notify = (result.rowcount or 0) == 1
        await self.session.flush()
        await self.session.refresh(fire)
        return fire, should_notify

    async def list_recent_for_schedule(
        self,
        *,
        schedule_id: UUID,
        project_id: UUID,
        limit: int = 100,
    ) -> list[ScheduleFire]:
        """Newest-first fire history for one schedule.

        Project-scoped to defend against IDOR via guessed
        schedule_ids. Returns at most ``limit`` rows.
        """
        result = await self.session.execute(
            select(ScheduleFire)
            .where(
                ScheduleFire.schedule_id == schedule_id,
                ScheduleFire.project_id == project_id,
            )
            .order_by(ScheduleFire.fired_at.desc())
            .limit(limit),
        )
        return list(result.scalars().all())

    async def recent_failures(
        self,
        *,
        schedule_id: UUID,
        limit: int,
    ) -> list[ScheduleFire]:
        """Last N fires for circuit-breaker evaluation.

        Returns the LAST N rows regardless of status. The caller
        decides whether the streak is consecutive-failed (i.e.
        every row in the slice has ``status in ('failed',
        'acked_failed')``). Fetching all-status rows lets the
        worker distinguish "10 failures in a row" from "5 failures
        and 5 successes interleaved" - the second is healthy.
        """
        result = await self.session.execute(
            select(ScheduleFire)
            .where(ScheduleFire.schedule_id == schedule_id)
            .order_by(ScheduleFire.fired_at.desc())
            .limit(limit),
        )
        return list(result.scalars().all())

    async def recent_failures_for_many(
        self,
        *,
        schedule_ids: list[UUID],
        per_schedule_limit: int,
    ) -> dict[UUID, list[ScheduleFire]]:
        """Bulk variant of :meth:`recent_failures`.

        The per-schedule call pattern would issue one
        :meth:`recent_failures` SELECT per enabled schedule (10k
        SELECTs + 10k sessions for a 10k-fleet). This
        single-query variant returns the most-recent
        ``per_schedule_limit`` rows for every supplied id in one
        round-trip via ``ROW_NUMBER() OVER (PARTITION BY
        schedule_id ORDER BY fired_at DESC)``.

        On SQLite (no window function in older builds) we fall back
        to a single ``WHERE schedule_id IN (...)`` then sort + slice
        in Python. Acceptable for dev because SQLite installs are
        single-tenant.
        """
        from sqlalchemy import select as _select

        if not schedule_ids:
            return {}
        dialect = self.session.bind.dialect.name if self.session.bind is not None else ""
        out: dict[UUID, list[ScheduleFire]] = {sid: [] for sid in schedule_ids}
        if dialect == "postgresql":
            from sqlalchemy import func as _func

            row_num = (
                _func.row_number()
                .over(
                    partition_by=ScheduleFire.schedule_id,
                    order_by=ScheduleFire.fired_at.desc(),
                )
                .label("rn")
            )
            inner = (
                _select(ScheduleFire, row_num)
                .where(ScheduleFire.schedule_id.in_(schedule_ids))
                .subquery()
            )
            from sqlalchemy.orm import aliased

            sf = aliased(ScheduleFire, inner)
            stmt = (
                _select(sf)
                .where(inner.c.rn <= per_schedule_limit)
                .order_by(
                    sf.schedule_id,
                    sf.fired_at.desc(),
                )
            )
            result = await self.session.execute(stmt)
            for fire in result.scalars().all():
                out[fire.schedule_id].append(fire)
            return out
        # SQLite fallback: one IN-list query, sort + slice in Python.
        stmt = (
            _select(ScheduleFire)
            .where(ScheduleFire.schedule_id.in_(schedule_ids))
            .order_by(
                ScheduleFire.schedule_id,
                ScheduleFire.fired_at.desc(),
            )
        )
        result = await self.session.execute(stmt)
        for fire in result.scalars().all():
            bucket = out[fire.schedule_id]
            if len(bucket) < per_schedule_limit:
                bucket.append(fire)
        return out

    async def delete_older_than(
        self,
        *,
        cutoff: datetime,
        limit: int = 1000,
    ) -> int:
        """Delete one bounded, locked batch of removable old history.

        Called by the periodic retention worker. On Postgres the table is
        RANGE-partitioned by scheduled_for and the daily partitions are
        reclaimed by the partition worker's whole-partition DROP; this
        DELETE only needs to sweep rows that landed in the DEFAULT partition
        (data the migration copied there, or out-of-window fires). Scoping
        the DELETE to schedule_fires_default avoids seq-scanning every
        partition to delete nothing (fired_at is not the partition key and
        has no standalone index, so the parent-wide DELETE cannot prune).
        On SQLite it is the plain table.

        Activated marked rows are deleted one at a time under the exact
        transaction-local evidence descriptor consumed by the database
        trigger.  Receipt-NULL legacy history is retained until an explicit
        occurrence resolution makes its replacement evidence self-contained.
        """
        bind = await self.session.connection()
        resolved_legacy = exists().where(
            ScheduleOccurrenceResolution.schedule_id == ScheduleFire.schedule_id,
            ScheduleOccurrenceResolution.fire_id == ScheduleFire.fire_id,
            ScheduleOccurrenceResolution.scheduled_for == ScheduleFire.scheduled_for,
        )
        removable = or_(
            ScheduleFire.protocol_marker.is_(None),
            and_(
                ScheduleFire.protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER,
                ScheduleFire.state_write_nonce.is_not(None),
                or_(
                    ScheduleFire.receipt_control_token.is_not(None),
                    resolved_legacy,
                ),
            ),
        )
        statement = (
            select(
                ScheduleFire.id,
                ScheduleFire.scheduled_for,
                ScheduleFire.protocol_marker,
                ScheduleFire.state_write_nonce,
            )
            .where(
                ScheduleFire.fired_at < cutoff,
                removable,
            )
            .order_by(ScheduleFire.fired_at.asc(), ScheduleFire.id.asc())
            .limit(max(1, min(limit, 10_000)))
        )
        if bind.dialect.name == "postgresql":
            statement = statement.where(
                text(
                    "schedule_fires.tableoid = 'schedule_fires_default'::regclass",
                ),
            ).with_for_update(skip_locked=True)
        candidates = (await self.session.execute(statement)).all()
        removed = 0
        for row_id, scheduled_for, marker, old_nonce in candidates:
            guard_active = False
            if marker == SCHEDULE_FIRE_PROTOCOL_MARKER:
                if old_nonce is None:
                    continue
                guard_active = await arm_evidence_delete(
                    self.session,
                    table_name="schedule_fires",
                    row_id=row_id,
                    old_nonce=old_nonce,
                    reason="history_retention",
                )
            predicates = [
                ScheduleFire.id == row_id,
                ScheduleFire.scheduled_for == scheduled_for,
            ]
            if marker == SCHEDULE_FIRE_PROTOCOL_MARKER:
                predicates.extend(
                    (
                        ScheduleFire.protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER,
                        ScheduleFire.state_write_nonce == old_nonce,
                    ),
                )
            result = await self.session.execute(
                delete(ScheduleFire).where(*predicates),
            )
            await assert_evidence_delete_consumed(
                self.session,
                active=guard_active,
            )
            removed += result.rowcount or 0
        return removed

    async def _get_by_fire_id(
        self,
        fire_id: UUID,
        scheduled_for: datetime | None = None,
    ) -> ScheduleFire | None:
        """Look up a fire row by fire_id.

        When ``scheduled_for`` is supplied, it is added to the WHERE so
        Postgres can prune to the single partition (the table is
        RANGE-partitioned by scheduled_for, and scheduled_for is stable per
        fire_id, so this is exact). Callers that have it -- record()'s
        upgrade path -- should pass it. The AcknowledgeFireResult path does
        NOT carry scheduled_for in its request, so it falls back to the
        cross-partition lookup; giving the ack request a scheduled_for
        field is the follow-up needed to prune it too.
        """
        stmt = select(ScheduleFire).where(ScheduleFire.fire_id == fire_id)
        if scheduled_for is not None:
            stmt = stmt.where(ScheduleFire.scheduled_for == scheduled_for)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def _get_by_identity(
        self,
        *,
        fire_id: UUID,
        receipt_control_token: UUID,
        scheduled_for: datetime | None = None,
    ) -> ScheduleFire | None:
        stmt = select(ScheduleFire).where(
            ScheduleFire.fire_id == fire_id,
            ScheduleFire.receipt_control_token == receipt_control_token,
        )
        if scheduled_for is not None:
            stmt = stmt.where(ScheduleFire.scheduled_for == scheduled_for)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_current(
        self,
        *,
        fire_id: UUID,
        receipt_control_token: UUID,
        scheduled_for: datetime | None = None,
    ) -> ScheduleFire | None:
        return await self._get_by_identity(
            fire_id=fire_id,
            receipt_control_token=receipt_control_token,
            scheduled_for=scheduled_for,
        )


# Permitted ``status`` transitions for the upgrade-on-conflict path
# in :meth:`ScheduleFireRepository.record`. Encodes the contract:
# - ``buffered`` is the entry state when no agent is online
# - ``delivered`` / ``failed`` follow once dispatch attempts
# - ``acked_*`` is terminal (do NOT downgrade back to delivered)
#
# A late retry of FireSchedule for an already-acked fire would
# otherwise overwrite the ack outcome - this map blocks that.
_UPGRADE_TRANSITIONS: dict[str, frozenset[str]] = {
    "pending": frozenset(
        {
            "buffered",
            "delivered",
            "failed",
            "acked_success",
            "acked_failed",
        }
    ),
    "buffered": frozenset(
        {
            "delivered",
            "failed",
            "acked_success",
            "acked_failed",
        }
    ),
    "accepted": frozenset(
        {
            "buffered",
            "delivered",
            "failed",
            "acked_success",
            "acked_failed",
        },
    ),
    "delivered": frozenset({"acked_success", "acked_failed", "failed"}),
    "failed": frozenset({"acked_success", "acked_failed"}),
    # ``acked_*`` are terminal - no upgrade.
    "acked_success": frozenset(),
    "acked_failed": frozenset(),
}


def _is_status_upgrade(current: str, proposed: str) -> bool:
    """True if ``proposed`` is a permitted forward transition.

    Used by :meth:`ScheduleFireRepository.record` to decide
    whether a late retry of FireSchedule for an existing fire_id
    should overwrite the row's status, or leave it alone (the
    proposed status would be a downgrade or sideways move).
    """
    if current == proposed:
        return False  # no-op
    return proposed in _UPGRADE_TRANSITIONS.get(current, frozenset())


def _same_datetime(left: datetime | None, right: datetime | None) -> bool:
    if left is None or right is None:
        return left is right
    left_utc = left.replace(tzinfo=UTC) if left.tzinfo is None else left.astimezone(UTC)
    right_utc = right.replace(tzinfo=UTC) if right.tzinfo is None else right.astimezone(UTC)
    return left_utc == right_utc


def _complete_current_command(command: Command) -> bool:
    return (
        command.schedule_protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER
        and command.schedule_state_nonce is not None
        and command.schedule_id is not None
        and command.schedule_fire_id is not None
        and command.schedule_scheduled_for is not None
        and command.schedule_receipt_control_token is not None
        and command.schedule_execution_fire_id is not None
        and command.schedule_acceptance_revision is not None
        and command.schedule_definition_digest is not None
        and command.schedule_expected_revision is not None
        and command.schedule_expected_next_run_at is not None
        and command.cadence_initial_claim_deadline is not None
    )


def _complete_current_fire(fire: ScheduleFire) -> bool:
    return (
        fire.protocol_marker == SCHEDULE_FIRE_PROTOCOL_MARKER
        and fire.state_write_nonce is not None
        and fire.receipt_control_token is not None
        and fire.acceptance_revision is not None
        and fire.definition_digest is not None
        and fire.expected_schedule_revision is not None
        and fire.expected_next_run_at is not None
    )


def _current_fire_matches_command(
    fire: ScheduleFire,
    command: Command,
) -> bool:
    return (
        _complete_current_fire(fire)
        and fire.command_id == command.id
        and fire.schedule_id == command.schedule_id
        and fire.project_id == command.project_id
        and fire.fire_id == command.schedule_fire_id
        and _same_datetime(fire.scheduled_for, command.schedule_scheduled_for)
        and fire.observed_control_token == command.schedule_observed_control_token
        and fire.receipt_control_token == command.schedule_receipt_control_token
        and fire.acceptance_revision == command.schedule_acceptance_revision
        and fire.definition_digest == command.schedule_definition_digest
        and fire.expected_schedule_revision == command.schedule_expected_revision
        and _same_datetime(
            fire.expected_last_run_at,
            command.schedule_expected_last_run_at,
        )
        and _same_datetime(
            fire.expected_next_run_at,
            command.schedule_expected_next_run_at,
        )
        and _same_datetime(
            fire.prepared_next_run_at,
            command.schedule_next_run_at,
        )
    )


__all__ = ["ScheduleFireRepository"]
