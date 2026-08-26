"""Notification dispatch service - per-user subscription model.

Replaces the old project-wide rule-based dispatcher. The
:meth:`NotificationService.evaluate_and_dispatch` entry point keeps
the same signature so the WebSocket frame router does not have to
change. Internally the implementation is now subscription-aware:

1. Find every active ``user_subscription`` for ``(project, trigger)``.
2. For each subscription:
   - skip if muted (``muted_until > now``)
   - skip if cooldown not elapsed (``last_fired_at + cooldown_seconds > now``)
   - confirm the user is still a project member
   - apply per-subscription filters (priority, task_name pattern, queue)
   - in-app -> insert :class:`UserNotification` row
   - project channels -> dispatch + log to ``notification_deliveries``
   - user channels   -> dispatch + log to ``notification_deliveries``
   - bump ``last_fired_at``

The service owns delivery via :func:`CHANNEL_DISPATCHERS` which
unchanged from the previous design - one dispatcher per channel
type (webhook / email / slack / telegram).

The membership materialization helper
:meth:`NotificationService.materialize_defaults_for_member` is
called by the membership service when a user joins a project.
It copies every :class:`ProjectDefaultSubscription` for that
project into a fresh :class:`UserSubscription` for the new user.
Idempotent - re-running on an existing membership skips defaults
that already have a matching user subscription.
"""

from __future__ import annotations

import asyncio
import contextlib
import fnmatch
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

from z4j_brain.domain.notifications.channels import CHANNEL_DISPATCHERS

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.persistence.models.notification import (
        NotificationChannel,
        UserSubscription,
    )

logger = logging.getLogger("z4j.brain.notifications.service")


# ---------------------------------------------------------------------------
# External delivery staging (PERF-10).
# ---------------------------------------------------------------------------
#
# The dispatcher builds a list of :class:`_PendingDelivery` inside the
# first DB transaction (cheap Python-only work) and only issues the
# actual HTTP calls AFTER committing. That way the database
# connection is not held for the duration of a webhook timeout
# (up to 10 s per target). A bounded semaphore caps the fan-out
# concurrency so one burst cannot exhaust outbound file descriptors.


@dataclass(slots=True)
class _PendingDelivery:
    """One queued outbound HTTP delivery to run outside the DB txn."""

    subscription_id: UUID
    recipient_user_id: UUID  # immutable subscription owner at delivery time
    channel_id: UUID | None  # project channel id (or None for user channel)
    user_channel_id: UUID | None  # user channel id (or None for project channel)
    channel_type: str  # webhook / email / slack / telegram
    channel_name: str | None  # snapshot of channel.name at staging time
    config: dict[str, Any]
    # Common context used to build the audit row later:
    project_id: UUID
    trigger: str
    task_id: str | None
    task_name: str | None


@dataclass(slots=True)
class _DeliveryOutcome:
    """Result of running one :class:`_PendingDelivery`."""

    pending: _PendingDelivery
    success: bool
    status_code: int | None = None
    response_body: str | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class _LiveDeliveryReferences:
    """Nullable audit pointers proven live immediately before insertion."""

    subscription_id: UUID | None
    recipient_user_id: UUID | None
    channel_id: UUID | None
    user_channel_id: UUID | None

    def intersect(self, other: _LiveDeliveryReferences) -> _LiveDeliveryReferences:
        """Clear stale pointers without ever restoring one during a retry."""

        return _LiveDeliveryReferences(
            subscription_id=(
                self.subscription_id if self.subscription_id == other.subscription_id else None
            ),
            recipient_user_id=(
                self.recipient_user_id
                if self.recipient_user_id == other.recipient_user_id
                else None
            ),
            channel_id=self.channel_id if self.channel_id == other.channel_id else None,
            user_channel_id=(
                self.user_channel_id if self.user_channel_id == other.user_channel_id else None
            ),
        )


async def _resolve_live_delivery_references(
    *,
    session: AsyncSession,
    pending: _PendingDelivery,
) -> _LiveDeliveryReferences:
    """Resolve every nullable FK carried across the outbound network gap."""

    from sqlalchemy import select

    from z4j_brain.persistence.models import User
    from z4j_brain.persistence.models.notification import (
        NotificationChannel,
        UserChannel,
        UserSubscription,
    )

    recipient_user_id = await session.scalar(
        select(User.id).where(User.id == pending.recipient_user_id),
    )
    subscription_id = None
    if recipient_user_id is not None:
        subscription_id = await session.scalar(
            select(UserSubscription.id).where(
                UserSubscription.id == pending.subscription_id,
                UserSubscription.user_id == recipient_user_id,
            ),
        )

    channel_id = None
    if pending.channel_id is not None:
        channel_id = await session.scalar(
            select(NotificationChannel.id).where(
                NotificationChannel.id == pending.channel_id,
                NotificationChannel.project_id == pending.project_id,
            ),
        )

    user_channel_id = None
    if pending.user_channel_id is not None and recipient_user_id is not None:
        user_channel_id = await session.scalar(
            select(UserChannel.id).where(
                UserChannel.id == pending.user_channel_id,
                UserChannel.user_id == recipient_user_id,
            ),
        )

    return _LiveDeliveryReferences(
        subscription_id=subscription_id,
        recipient_user_id=recipient_user_id,
        channel_id=channel_id,
        user_channel_id=user_channel_id,
    )


async def _flush_delivery_audit(
    *,
    session: AsyncSession,
    pending: _PendingDelivery,
    outcome: _DeliveryOutcome,
    references: _LiveDeliveryReferences,
    sanitized_error: str | None,
    sanitized_body: str | None,
) -> None:
    """Flush one audit row inside a savepoint for FK-race recovery."""

    from z4j_brain.persistence.models.notification import NotificationDelivery

    async with session.begin_nested():
        session.add(
            NotificationDelivery(
                subscription_id=references.subscription_id,
                recipient_user_id=references.recipient_user_id,
                channel_id=references.channel_id,
                user_channel_id=references.user_channel_id,
                project_id=pending.project_id,
                trigger=pending.trigger,
                task_id=pending.task_id,
                task_name=pending.task_name,
                status="sent" if outcome.success else "failed",
                response_code=outcome.status_code,
                response_body=sanitized_body,
                error=sanitized_error,
                channel_name=pending.channel_name,
                channel_type=pending.channel_type,
            ),
        )
        await session.flush()


async def _persist_delivery_audit(
    *,
    session: AsyncSession,
    pending: _PendingDelivery,
    outcome: _DeliveryOutcome,
    sanitized_error: str | None,
    sanitized_body: str | None,
) -> None:
    """Persist one audit while tolerating deletes of nullable FK targets."""

    from sqlalchemy.exc import IntegrityError

    references = await _resolve_live_delivery_references(
        session=session,
        pending=pending,
    )
    # One initial insert plus at most one monotonic clearing step for each of
    # the four nullable foreign keys.  Continuous unrelated integrity failures
    # therefore cannot turn notification dispatch into an unbounded retry.
    for attempt in range(5):
        try:
            await _flush_delivery_audit(
                session=session,
                pending=pending,
                outcome=outcome,
                references=references,
                sanitized_error=sanitized_error,
                sanitized_body=sanitized_body,
            )
            return
        except IntegrityError:
            # PostgreSQL can commit a target delete after the probes but
            # before the INSERT's FK check.  The savepoint has isolated that
            # failure, so resolve again and retry after clearing only pointers
            # proven stale.  ``intersect`` makes progress monotonic: at most
            # the four nullable references can be cleared, and an unrelated
            # integrity failure is re-raised instead of looping.
            if attempt == 4:
                raise
            refreshed = references.intersect(
                await _resolve_live_delivery_references(
                    session=session,
                    pending=pending,
                ),
            )
            if refreshed == references:
                raise
            references = refreshed
    raise AssertionError("unreachable delivery-audit retry state")


async def _reserve_sqlite_delivery_audit_writer(session: AsyncSession) -> None:
    """Serialize SQLite subscription probes with their audit inserts.

    SQLite's default deferred transactions do not reserve the writer until the
    first write.  A subscription delete can therefore acquire the writer after
    pass 3 has read the subscription but before the delivery audit is flushed.
    The read transaction then cannot be upgraded and fails immediately with
    ``SQLITE_BUSY``, losing the audit for an outbound call that already ran.

    Reserve the single SQLite writer before the ownership probe.  A delete
    that committed first is visible to the probe; one that starts afterward
    waits for the audit commit and then applies the FK's ``ON DELETE SET NULL``
    action.  PostgreSQL already provides the required MVCC/FK behaviour and
    must not receive SQLite transaction syntax.
    """

    if session.get_bind().dialect.name == "sqlite":
        from sqlalchemy import text

        await session.execute(text("BEGIN IMMEDIATE"))


def _delivery_metric_status(outcome: _DeliveryOutcome) -> str:
    """Map an outbound result to the dashboard's metric vocabulary."""

    if outcome.success:
        return "success"
    error = (outcome.error or "").lower()
    if "block" in error or "unsafe" in error or "ssrf" in error:
        return "blocked"
    return "failed"


def _record_delivery_metric(outcome: _DeliveryOutcome) -> str:
    """Increment the delivery counter best-effort and return its status."""

    status = _delivery_metric_status(outcome)
    try:
        from z4j_brain.api.metrics import z4j_notifications_sent_total
    except Exception:
        return status

    pending = outcome.pending
    with contextlib.suppress(Exception):
        z4j_notifications_sent_total.labels(
            project=str(pending.project_id) if pending.project_id else "",
            channel_type=pending.channel_type or "unknown",
            status=status,
        ).inc()
    return status


#: Max concurrent outbound HTTP deliveries per dispatch batch.
_MAX_CONCURRENT_DELIVERIES = 16


# ---------------------------------------------------------------------------
# Title formatter for in-app notifications.
# ---------------------------------------------------------------------------


def _format_title(
    *,
    trigger: str,
    task_name: str | None,
) -> str:
    """Build a short bell-row line for the notification.

    Examples:
        ``Task failed: demo_app.tasks.ping``
        ``Task succeeded: cleanup``
        ``Agent went offline``
    """
    pretty = trigger.replace(".", " ").replace("_", " ")
    pretty = pretty[:1].upper() + pretty[1:]
    if task_name:
        return f"{pretty}: {task_name}"
    return pretty


def _format_body(
    *,
    trigger: str,
    exception: str | None,
    state: str | None,
) -> str | None:
    """Optional detail line for the bell expanded view."""
    if exception:
        # Trim long exceptions; the full traceback lives in the task detail.
        return exception[:500]
    if state and state != trigger.rsplit(".", maxsplit=1)[-1]:
        return f"State: {state}"
    return None


# ---------------------------------------------------------------------------
# Service.
# ---------------------------------------------------------------------------


class NotificationService:
    """Evaluate user subscriptions and dispatch notifications.

    Stateless - construct per request from the DB session.
    """

    async def evaluate_and_dispatch(  # noqa: PLR0912, PLR0915  subscription dispatch pipeline
        self,
        *,
        session: AsyncSession,
        project_id: UUID,
        trigger: str,
        task_id: str | None = None,
        task_name: str | None = None,
        engine: str | None = None,
        priority: str = "normal",
        state: str | None = None,
        queue: str | None = None,
        exception: str | None = None,
        traceback: str | None = None,
        project_slug: str = "",
        resource_type: str = "task",
    ) -> int:
        """Find matching user subscriptions and deliver notifications.

        Returns the total number of deliveries attempted (in-app +
        external). Failures are logged in the deliveries table and
        do NOT raise - notification side effects must never crash
        the calling request handler.
        """
        from z4j_brain.persistence.models.notification import (
            NotificationReason,
            UserNotification,
        )
        from z4j_brain.persistence.repositories import (
            MembershipRepository,
            NotificationChannelRepository,
            UserChannelRepository,
            UserSubscriptionRepository,
        )

        sub_repo = UserSubscriptionRepository(session)
        subs = await sub_repo.list_active_for_dispatch(
            project_id=project_id,
            trigger=trigger,
        )
        if not subs:
            return 0

        membership_repo = MembershipRepository(session)
        project_channel_repo = NotificationChannelRepository(session)
        user_channel_repo = UserChannelRepository(session)

        payload: dict[str, Any] = {
            "trigger": trigger,
            "task_id": task_id,
            "task_name": task_name,
            "engine": engine,
            "priority": priority,
            "state": state,
            "queue": queue,
            "exception": exception,
            "traceback": traceback,
            "project_id": str(project_id),
            "project_slug": project_slug,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        title = _format_title(trigger=trigger, task_name=task_name)
        body = _format_body(trigger=trigger, exception=exception, state=state)
        # JSON used by the frontend for deep links from the bell. We
        # stamp ``engine`` here so the dashboard's
        # ``/projects/<slug>/tasks/<engine>/<task_id>`` link works
        # for RQ + Dramatiq tasks - without it every non-Celery
        # notification 404s (see docs/MULTI_ENGINE_VERIFICATION_2026Q2.md
        # BUG-2).
        deeplink_data: dict[str, Any] = {
            "task_id": task_id,
            "task_name": task_name,
            "engine": engine,
            "queue": queue,
            "priority": priority,
            # Round-4 LOW: schedule/agent alerts reuse the task-shaped
            # contract (task_id carries the schedule/agent UUID), so
            # the bell navigated every such alert to a nonexistent
            # task page. resource_type tells the dashboard which
            # detail route the id resolves to; "task" (and absent, for
            # pre-existing rows) preserves the original behavior.
            "resource_type": resource_type,
        }

        now = datetime.now(UTC)

        # ------------------------------------------------------------------
        # PERF-01: preload memberships in one query.
        # ------------------------------------------------------------------
        valid_user_ids = await membership_repo.list_active_user_ids_for_project(
            project_id,
        )

        # ------------------------------------------------------------------
        # PERF-02: batch channel lookups across all subs.
        # ------------------------------------------------------------------
        all_proj_channel_ids: set[UUID] = set()
        user_channel_pairs: list[tuple[UUID, UUID]] = []
        for sub in subs:
            if sub.project_channel_ids:
                all_proj_channel_ids.update(sub.project_channel_ids)
            if sub.user_channel_ids:
                for cid in sub.user_channel_ids:
                    user_channel_pairs.append((sub.user_id, cid))

        project_channels_by_id: dict[UUID, NotificationChannel] = {}
        if all_proj_channel_ids:
            fetched = await project_channel_repo.get_many_for_project(
                project_id=project_id,
                ids=list(all_proj_channel_ids),
            )
            # Filter inactive upfront so the inner loop is pure.
            project_channels_by_id = {c.id: c for c in fetched if c.is_active}

        user_channels_by_id = await user_channel_repo.get_many_by_pairs(
            user_channel_pairs,
        )

        # ------------------------------------------------------------------
        # Pass 1: claim cooldowns, insert in-app rows, stage external
        #          deliveries. All DB writes here go through a
        #          per-subscription savepoint (DATA-01) so a single
        #          bad row cannot poison the batch.
        # ------------------------------------------------------------------
        dispatched = 0
        pending: list[_PendingDelivery] = []

        for sub in subs:
            # 1) Muted? (cheap in-memory check; no writes.)
            if sub.muted_until is not None and sub.muted_until > now:
                continue

            # 2) Member-of-project sanity check, batched (PERF-01).
            if sub.user_id not in valid_user_ids:
                continue

            # 3) Filters.
            if not self._matches_filters(
                sub.filters or {},
                priority=priority,
                task_name=task_name,
                queue=queue,
                sub_id=sub.id,
            ):
                continue

            try:
                async with session.begin_nested():
                    # 4) Atomically claim the cooldown slot (HIGH-04).
                    claimed = await sub_repo.update_last_fired(
                        sub.id,
                        now,
                        cooldown_seconds=sub.cooldown_seconds,
                    )
                    if not claimed:
                        # PERF-17: cooldown-race losers are logged +
                        # counted, NOT written to notification_deliveries.
                        # At scale the audit-row-per-skip pattern floods
                        # the table with no operational value.
                        logger.debug(
                            "z4j notification: cooldown-skipped sub_id=%s trigger=%s",
                            sub.id,
                            trigger,
                        )
                        try:
                            from z4j_brain.api.metrics import (
                                z4j_notifications_cooldown_skipped_total,
                            )

                            z4j_notifications_cooldown_skipped_total.labels(
                                project=str(project_id),
                                trigger=trigger,
                            ).inc()
                        except Exception:  # noqa: S110  best-effort metrics increment, import + call
                            # Metrics module not importable in some
                            # test setups; safe to drop silently.
                            pass
                        continue

                    # 5) In-app delivery (the user_notifications row
                    #    IS the audit; no notification_deliveries row).
                    if sub.in_app:
                        session.add(
                            UserNotification(
                                user_id=sub.user_id,
                                project_id=project_id,
                                subscription_id=sub.id,
                                trigger=trigger,
                                reason=NotificationReason.SUBSCRIBED,
                                title=title,
                                body=body,
                                data=deeplink_data,
                            ),
                        )
                        dispatched += 1

                    # 6) Stage project channel deliveries (from the
                    #    pre-fetched dict, no DB round-trip here).
                    for cid in sub.project_channel_ids or []:
                        channel = project_channels_by_id.get(cid)
                        if channel is None:
                            continue
                        pending.append(
                            _PendingDelivery(
                                subscription_id=sub.id,
                                recipient_user_id=sub.user_id,
                                channel_id=channel.id,
                                user_channel_id=None,
                                channel_type=channel.type,
                                channel_name=channel.name,
                                config=dict(channel.config or {}),
                                project_id=project_id,
                                trigger=trigger,
                                task_id=task_id,
                                task_name=task_name,
                            ),
                        )

                    # 7) Stage user channel deliveries (pre-fetched,
                    #    ownership already enforced by get_many_by_pairs).
                    for cid in sub.user_channel_ids or []:
                        user_channel = user_channels_by_id.get(cid)
                        if user_channel is None or not user_channel.is_active:
                            continue
                        pending.append(
                            _PendingDelivery(
                                subscription_id=sub.id,
                                recipient_user_id=sub.user_id,
                                channel_id=None,
                                user_channel_id=user_channel.id,
                                channel_type=user_channel.type,
                                channel_name=user_channel.name,
                                config=dict(user_channel.config or {}),
                                project_id=project_id,
                                trigger=trigger,
                                task_id=task_id,
                                task_name=task_name,
                            ),
                        )
            except Exception:
                # Savepoint rolled back this sub's writes only.
                logger.exception(
                    "z4j notification: per-subscription staging failed (sub_id=%s)",
                    sub.id,
                )
                continue

        # Commit pass 1 BEFORE doing any external HTTP. This releases
        # the DB connection while webhooks / slack / telegram calls
        # are in flight (PERF-10).
        try:
            await session.commit()
        except Exception:
            await session.rollback()
            logger.exception(
                "z4j notification: pass-1 commit failed; rolled back batch",
            )
            raise

        # ------------------------------------------------------------------
        # Pass 2: fire external deliveries OUTSIDE the DB transaction,
        #          bounded-concurrency fan-out.
        # ------------------------------------------------------------------
        outcomes: list[_DeliveryOutcome] = []
        if pending:
            outcomes = await self._run_pending_deliveries(pending, payload)
            dispatched += len(outcomes)

        # ------------------------------------------------------------------
        # Pass 3: persist delivery audit rows in a fresh transaction.
        #          These are the sent/failed rows for the external
        #          deliveries attempted in pass 2.
        # ------------------------------------------------------------------
        if outcomes:
            try:
                from z4j_brain.domain.notifications.sanitize import (
                    sanitize_audit_text,
                )

                # A file-backed SQLite connection otherwise begins this as a
                # deferred read transaction.  Reserve its writer before any
                # live-subscription probe so a concurrent delete cannot land
                # between the probe and audit insert and make the read
                # snapshot fail its write upgrade with SQLITE_BUSY.
                await _reserve_sqlite_delivery_audit_writer(session)

                for outcome in outcomes:
                    p = outcome.pending
                    _record_delivery_metric(outcome)
                    # Sanitize error + response_body before persistence
                    # (audit H-1 / H-2 / H-3): the dispatcher's raw
                    # error / body text can carry the channel's
                    # webhook URL (containing the secret token), the
                    # body of an attacker-controlled webhook, or
                    # SSRF-guard rejection messages that leak resolved
                    # internal IPs. p.channel_config is the original
                    # config dict the dispatcher received - lets the
                    # sanitizer mask URL-bearing substrings.
                    raw_body = outcome.response_body if not outcome.success else None
                    # Pass the dispatcher's config dict directly
                    # via ``p.config``. The previous spelling
                    # ``getattr(p, "channel_config", None)`` silently
                    # returned None because the dataclass field is
                    # ``config`` (not ``channel_config``), causing the
                    # sanitizer to skip URL/token masking on the
                    # real-delivery path. Test-dispatch was unaffected
                    # because it passes the dict directly.
                    sanitized_error = sanitize_audit_text(
                        outcome.error,
                        channel_config=p.config,
                        max_len=1024,
                    )
                    sanitized_body = sanitize_audit_text(
                        raw_body,
                        channel_config=p.config,
                        max_len=2048,
                    )
                    # The outbound call intentionally runs after pass 1 has
                    # committed.  Users can delete the subscription, account,
                    # or target channel during that network gap.  Preserve the
                    # immutable audit snapshots while retaining only nullable
                    # live FKs; a savepoint retry handles a PostgreSQL delete
                    # that commits after these probes.
                    await _persist_delivery_audit(
                        session=session,
                        pending=p,
                        outcome=outcome,
                        sanitized_error=sanitized_error,
                        sanitized_body=sanitized_body,
                    )
                    if outcome.success:
                        logger.info(
                            "z4j notification sent (trigger=%s channel_type=%s task=%s)",
                            p.trigger,
                            p.channel_type,
                            p.task_name,
                        )
                    else:
                        logger.warning(
                            "z4j notification failed (trigger=%s channel_type=%s error=%s)",
                            p.trigger,
                            p.channel_type,
                            sanitized_error,
                        )
                await session.commit()
            except Exception:
                await session.rollback()
                logger.exception(
                    "z4j notification: audit-row commit failed",
                )
                # Don't re-raise: the deliveries already happened,
                # failing the caller adds no value.
        return dispatched

    # ------------------------------------------------------------------
    # External delivery runner (PERF-10).
    # ------------------------------------------------------------------

    async def _run_pending_deliveries(
        self,
        pending: list[_PendingDelivery],
        payload: dict[str, Any],
    ) -> list[_DeliveryOutcome]:
        """Fire every queued :class:`_PendingDelivery` with bounded concurrency.

        Runs outside any DB transaction so a slow HTTP target cannot
        hold a database connection for up to the timeout window.
        """
        sem = asyncio.Semaphore(_MAX_CONCURRENT_DELIVERIES)

        async def _run(p: _PendingDelivery) -> _DeliveryOutcome:
            async with sem:
                dispatcher = CHANNEL_DISPATCHERS.get(p.channel_type)
                if dispatcher is None:
                    return _DeliveryOutcome(
                        pending=p,
                        success=False,
                        error=f"unknown channel type {p.channel_type}",
                    )
                try:
                    result = await dispatcher(p.config, payload)
                except Exception as exc:
                    return _DeliveryOutcome(
                        pending=p,
                        success=False,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                return _DeliveryOutcome(
                    pending=p,
                    success=result.success,
                    status_code=result.status_code,
                    response_body=result.response_body,
                    error=result.error,
                )

        # Use
        # ``return_exceptions=True`` so a CancelledError on one
        # leg doesn't sibling-cancel every other in-flight HTTP
        # request mid-pin-IP / SNI handshake (those leak
        # connections under abrupt cancel). ``_run`` already
        # catches every per-leg ``Exception`` and returns a
        # _DeliveryOutcome; the only remaining unhandled raise is
        # CancelledError, which we coerce to a synthetic outcome.
        results = await asyncio.gather(
            *(_run(p) for p in pending),
            return_exceptions=True,
        )
        coerced: list[_DeliveryOutcome] = []
        for idx, item in enumerate(results):
            if isinstance(item, _DeliveryOutcome):
                coerced.append(item)
            else:
                # Either CancelledError or an unexpected exception
                # leak. Surface it as a failed delivery.
                coerced.append(
                    _DeliveryOutcome(
                        pending=pending[idx],
                        success=False,
                        error=f"{type(item).__name__}: {item}",
                    ),
                )
        return coerced

    # ------------------------------------------------------------------
    # Membership materialization (called when a user joins a project).
    # ------------------------------------------------------------------

    async def materialize_defaults_for_member(
        self,
        *,
        session: AsyncSession,
        user_id: UUID,
        project_id: UUID,
    ) -> int:
        """Copy ``project_default_subscriptions`` into ``user_subscriptions``.

        Idempotent: skips defaults that already have a matching
        user subscription (same trigger). Returns the number of
        subscriptions inserted. Caller is responsible for the
        commit.
        """
        from z4j_brain.persistence.models.notification import UserSubscription
        from z4j_brain.persistence.repositories import (
            ProjectDefaultSubscriptionRepository,
            UserSubscriptionRepository,
        )

        defaults = await ProjectDefaultSubscriptionRepository(
            session,
        ).list_for_project(project_id)
        if not defaults:
            return 0

        sub_repo = UserSubscriptionRepository(session)
        existing = await sub_repo.list_for_user(user_id, project_id=project_id)
        existing_triggers = {s.trigger for s in existing}

        inserted = 0
        for default in defaults:
            if default.trigger in existing_triggers:
                continue
            session.add(
                UserSubscription(
                    user_id=user_id,
                    project_id=project_id,
                    trigger=default.trigger,
                    filters=dict(default.filters or {}),
                    in_app=default.in_app,
                    project_channel_ids=list(default.project_channel_ids or []),
                    user_channel_ids=[],
                    cooldown_seconds=default.cooldown_seconds,
                ),
            )
            inserted += 1

        if inserted:
            await session.flush()
        return inserted

    # ------------------------------------------------------------------
    # Filter matching.
    # ------------------------------------------------------------------

    @staticmethod
    def _matches_filters(  # noqa: PLR0912  filter matching
        filters: dict[str, Any],
        *,
        priority: str | None,
        task_name: str | None,
        queue: str | None,
        sub_id: UUID | None = None,
    ) -> bool:
        """Subscription filter evaluation.

        Supported filter keys (all optional, all AND'd together):

        - ``priority``: list of priority strings; event.priority must be in it
        - ``task_name_pattern``: glob (fnmatch); event.task_name must match
        - ``task_name``: exact substring; event.task_name must contain it
        - ``queue``: exact match

        Defensive note: API-created filters are Pydantic-validated so
        the shape is guaranteed correct. Historical rows or direct DB
        writes could still have a wrong shape; in that case we skip
        the malformed key silently (treat as "no filter") and log a
        one-line warning for ops to investigate, rather than crashing
        the dispatch loop.
        """
        priority_filter = filters.get("priority")
        if priority_filter:
            if isinstance(priority_filter, list):
                if priority not in priority_filter:
                    return False
            else:
                logger.warning(
                    "z4j notification: malformed priority filter on "
                    "subscription %s (expected list, got %s); skipping "
                    "this filter key",
                    sub_id,
                    type(priority_filter).__name__,
                )

        pattern = filters.get("task_name_pattern")
        if pattern:
            if isinstance(pattern, str):
                # Defense-in-depth against ReDoS from
                # patterns that pre-date the v1.0.14 validator. A
                # subscription created in 1.0.13 with
                # ``"a*a*a*a*a*a*a*a*a*a*a*a*a*b"`` is already in
                # the DB; fnmatch.fnmatch on a long task_name would
                # backtrack catastrophically. Bound complexity here
                # too so a stored subscription can't ReDoS the WS
                # frame ingest path.
                if (
                    pattern.count("*") + pattern.count("?") > 5
                    or pattern.count("[") > 3
                    or len(pattern) > 200
                ):
                    logger.warning(
                        "z4j notification: subscription %s has a "
                        "high-complexity task_name_pattern (>5 wildcards "
                        "or >3 char-classes); skipping match to avoid "
                        "ReDoS. Edit the subscription to simplify the "
                        "pattern.",
                        sub_id,
                    )
                    return False
                if not task_name or not fnmatch.fnmatch(task_name, pattern):
                    return False
            else:
                logger.warning(
                    "z4j notification: malformed task_name_pattern filter "
                    "on subscription %s (expected str, got %s); skipping",
                    sub_id,
                    type(pattern).__name__,
                )

        substring = filters.get("task_name")
        if substring:
            if isinstance(substring, str):
                if not task_name or substring not in task_name:
                    return False
            else:
                logger.warning(
                    "z4j notification: malformed task_name filter on "
                    "subscription %s (expected str, got %s); skipping",
                    sub_id,
                    type(substring).__name__,
                )

        queue_filter = filters.get("queue")
        if queue_filter:
            if isinstance(queue_filter, str):
                if queue != queue_filter:
                    return False
            else:
                logger.warning(
                    "z4j notification: malformed queue filter on "
                    "subscription %s (expected str, got %s); skipping",
                    sub_id,
                    type(queue_filter).__name__,
                )

        return True

    # ------------------------------------------------------------------
    # Cooldown helper (mirrors the repo helper but in-process so we
    # don't need an extra DB roundtrip per subscription).
    # ------------------------------------------------------------------

    @staticmethod
    def _is_on_cooldown(
        sub: UserSubscription,
        *,
        now: datetime,
    ) -> bool:
        """DEPRECATED: use the atomic ``update_last_fired(...,
        cooldown_seconds=...)`` DB claim in :meth:`evaluate_and_dispatch`
        instead.

        This in-memory check is racy: two concurrent events can both
        read ``last_fired_at``, both pass the check, and both fire.
        Kept for backwards compatibility with any external caller
        that may still import it; no internal code path uses it.
        """
        if sub.cooldown_seconds <= 0 or sub.last_fired_at is None:
            return False
        cutoff = now - timedelta(seconds=sub.cooldown_seconds)
        return sub.last_fired_at >= cutoff


__all__ = ["NotificationService"]
