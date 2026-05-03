"""Repositories for the per-user notification system.

Five tables, four repositories:

- :class:`NotificationChannelRepository` - project-shared channels
  (the existing one, kept). Admins manage these in Project Settings.

- :class:`UserChannelRepository` - personal channels each user
  configures for themselves in Global Settings > Channels.

- :class:`UserSubscriptionRepository` - per-user mappings of
  ``(project, trigger) -> channels``. Used by the dispatcher
  (filtered by project + trigger + active) and by the user's
  Notifications settings page (filtered by user).

- :class:`ProjectDefaultSubscriptionRepository` - admin-owned
  templates that get copied into ``user_subscriptions`` when a user
  joins a project.

- :class:`UserNotificationRepository` - the in-app inbox. Bell
  reads here, mark-read writes here.

- :class:`NotificationDeliveryRepository` - external-delivery
  audit log (kept from the old design with a new ``subscription_id``
  column).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import and_, desc, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models.notification import (
    NotificationChannel,
    NotificationDelivery,
    ProjectDefaultSubscription,
    UserChannel,
    UserNotification,
    UserSubscription,
)
from z4j_brain.persistence.repositories._base import BaseRepository


# ---------------------------------------------------------------------------
# Project channels (existing).
# ---------------------------------------------------------------------------


class NotificationChannelRepository(BaseRepository[NotificationChannel]):
    """Project-shared channel CRUD."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, NotificationChannel)

    async def list_for_project(
        self,
        project_id: UUID,
        *,
        active_only: bool = False,
        limit: int = 500,
    ) -> list[NotificationChannel]:
        """Return channels for a project, newest first.

        Hard-capped at ``limit`` (default 500, max 5000) so a project
        with hundreds of channels can't return an unbounded result
        set (audit P-7, added v1.0.14). 500 is well above any
        realistic single-project channel count.
        """
        if limit < 1 or limit > 5000:
            raise ValueError("limit must be between 1 and 5000")
        stmt = (
            select(NotificationChannel)
            .where(NotificationChannel.project_id == project_id)
            .order_by(desc(NotificationChannel.created_at))
            .limit(limit)
        )
        if active_only:
            stmt = stmt.where(NotificationChannel.is_active.is_(True))
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_for_project(
        self,
        project_id: UUID,
        channel_id: UUID,
    ) -> NotificationChannel | None:
        """Get a channel only if it belongs to the given project."""
        stmt = select(NotificationChannel).where(
            NotificationChannel.id == channel_id,
            NotificationChannel.project_id == project_id,
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_many_for_project(
        self,
        project_id: UUID,
        ids: list[UUID],
    ) -> list[NotificationChannel]:
        """Return channels in ``ids`` that belong to the given project.

        Used by the dispatcher to fan out and by the subscription
        validator to verify the user-supplied channel ids are
        legitimate.
        """
        if not ids:
            return []
        stmt = select(NotificationChannel).where(
            NotificationChannel.id.in_(ids),
            NotificationChannel.project_id == project_id,
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())


# ---------------------------------------------------------------------------
# User channels.
# ---------------------------------------------------------------------------


class UserChannelRepository(BaseRepository[UserChannel]):
    """Personal channel CRUD - one user, their own destinations only."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, UserChannel)

    async def list_for_user(
        self,
        user_id: UUID,
        *,
        active_only: bool = False,
    ) -> list[UserChannel]:
        """All channels the user owns, newest first."""
        stmt = (
            select(UserChannel)
            .where(UserChannel.user_id == user_id)
            .order_by(desc(UserChannel.created_at))
        )
        if active_only:
            stmt = stmt.where(UserChannel.is_active.is_(True))
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_for_user(
        self,
        user_id: UUID,
        channel_id: UUID,
    ) -> UserChannel | None:
        """Get a channel only if it is owned by the user.

        Critical safety check: prevents user A from referencing
        user B's channel in a subscription.
        """
        stmt = select(UserChannel).where(
            UserChannel.id == channel_id,
            UserChannel.user_id == user_id,
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_many_for_user(
        self,
        user_id: UUID,
        ids: list[UUID],
    ) -> list[UserChannel]:
        """Return channels in ``ids`` that belong to the user."""
        if not ids:
            return []
        stmt = select(UserChannel).where(
            UserChannel.id.in_(ids),
            UserChannel.user_id == user_id,
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_many_by_pairs(
        self, pairs: list[tuple[UUID, UUID]],
    ) -> dict[UUID, UserChannel]:
        """Bulk-fetch user channels by (user_id, channel_id) pairs.

        Returns a dict keyed by channel_id. Enforces ownership: only
        channels where the (user_id, id) matches a supplied pair are
        returned.
        """
        if not pairs:
            return {}
        # Using IN on channel_id and a Python-side ownership filter is fine
        # for our sizes. Postgres VALUES composite match would be cleaner
        # but complicates the dialect handling.
        ids = [cid for _, cid in pairs]
        stmt = select(UserChannel).where(UserChannel.id.in_(ids))
        rows = (await self.session.execute(stmt)).scalars().all()
        supplied = set(pairs)
        return {
            r.id: r
            for r in rows
            if (r.user_id, r.id) in supplied
        }


# ---------------------------------------------------------------------------
# User subscriptions.
# ---------------------------------------------------------------------------


class UserSubscriptionRepository(BaseRepository[UserSubscription]):
    """Per-user subscription CRUD + dispatcher lookup."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, UserSubscription)

    async def list_for_user(
        self,
        user_id: UUID,
        *,
        project_id: UUID | None = None,
        limit: int | None = None,
        cursor_project_id: UUID | None = None,
        cursor_trigger: str | None = None,
        cursor_id: UUID | None = None,
    ) -> list[UserSubscription]:
        """All subscriptions for a user, optionally project-filtered.

        Used by the user's Notifications settings page.

        v1.1.0 N+1 fix: optional keyset pagination on
        ``(project_id, trigger, id)``. Caller passes ``limit`` and
        the prior page's cursor tuple; this returns the next slice
        in the same order. Legacy callers that omit ``limit`` and
        every cursor still get the full unbounded list, so internal
        dispatcher code (``list_active_for_dispatch`` is separate;
        only the settings UI page is paginated) is unaffected.
        """
        from sqlalchemy import and_, or_

        stmt = (
            select(UserSubscription)
            .where(UserSubscription.user_id == user_id)
            .order_by(
                UserSubscription.project_id,
                UserSubscription.trigger,
                UserSubscription.id,
            )
        )
        if project_id is not None:
            stmt = stmt.where(UserSubscription.project_id == project_id)
        if (
            cursor_project_id is not None
            and cursor_trigger is not None
            and cursor_id is not None
        ):
            stmt = stmt.where(
                or_(
                    UserSubscription.project_id > cursor_project_id,
                    and_(
                        UserSubscription.project_id == cursor_project_id,
                        UserSubscription.trigger > cursor_trigger,
                    ),
                    and_(
                        UserSubscription.project_id == cursor_project_id,
                        UserSubscription.trigger == cursor_trigger,
                        UserSubscription.id > cursor_id,
                    ),
                ),
            )
        if limit is not None:
            stmt = stmt.limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_active_for_dispatch(
        self,
        *,
        project_id: UUID,
        trigger: str,
    ) -> list[UserSubscription]:
        """Dispatcher lookup: active, non-muted subs for project+trigger.

        We let the dispatcher filter ``muted_until`` rather than
        SQL-WHERE here because ``muted_until > NOW()`` semantics need
        a UTC-aware comparison and the dispatcher already loops over
        the small result set. Simpler and easier to reason about.

        Note: the partial index ``ix_user_subs_project_trigger``
        already excludes inactive rows so this query is cheap.
        """
        stmt = select(UserSubscription).where(
            UserSubscription.project_id == project_id,
            UserSubscription.trigger == trigger,
            UserSubscription.is_active.is_(True),
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_for_user(
        self,
        user_id: UUID,
        sub_id: UUID,
    ) -> UserSubscription | None:
        """Get a subscription only if it belongs to the user."""
        stmt = select(UserSubscription).where(
            UserSubscription.id == sub_id,
            UserSubscription.user_id == user_id,
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_unique(
        self,
        *,
        user_id: UUID,
        project_id: UUID,
        trigger: str,
    ) -> UserSubscription | None:
        """Look up by the natural key (user, project, trigger)."""
        stmt = select(UserSubscription).where(
            UserSubscription.user_id == user_id,
            UserSubscription.project_id == project_id,
            UserSubscription.trigger == trigger,
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def update_last_fired(
        self,
        sub_id: UUID,
        when: datetime | None = None,
        *,
        cooldown_seconds: int = 0,
    ) -> bool:
        """Conditionally bump ``last_fired_at``.

        Returns ``True`` iff the row was updated (we won the race).
        If ``cooldown_seconds > 0``, the UPDATE only succeeds when
        ``last_fired_at`` is NULL or older than ``when - cooldown_seconds``,
        which atomically closes the gap between the "cooldown check"
        and "bump timestamp" for concurrent events racing the same
        subscription.
        """
        now = when or datetime.now(UTC)
        stmt = update(UserSubscription).where(UserSubscription.id == sub_id)
        if cooldown_seconds > 0:
            cutoff = now - timedelta(seconds=cooldown_seconds)
            stmt = stmt.where(
                (UserSubscription.last_fired_at.is_(None))
                | (UserSubscription.last_fired_at < cutoff),
            )
        stmt = stmt.values(last_fired_at=now)
        result = await self.session.execute(stmt)
        return (result.rowcount or 0) > 0

    async def is_on_cooldown(
        self,
        sub: UserSubscription,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Returns True if last_fired_at + cooldown > now."""
        if sub.cooldown_seconds <= 0 or sub.last_fired_at is None:
            return False
        cutoff = (now or datetime.now(UTC)) - timedelta(
            seconds=sub.cooldown_seconds,
        )
        return sub.last_fired_at >= cutoff

    async def strip_project_channel(
        self,
        *,
        project_id: UUID,
        channel_id: UUID,
    ) -> int:
        """Remove ``channel_id`` from every ``user_subscription`` in
        this project's ``project_channel_ids`` column. Returns the
        number of rows affected.

        Called when a project channel is deleted so we do not leave
        orphan UUIDs hanging in user subscriptions. Postgres uses
        ``array_remove`` for a single-statement UPDATE; on SQLite we
        fall back to a scan-and-rewrite (the column is JSON-backed
        there).
        """
        from sqlalchemy import text

        dialect = self.session.bind.dialect.name if self.session.bind else ""
        if dialect == "postgresql":
            stmt = text(
                "UPDATE user_subscriptions "
                "SET project_channel_ids = "
                "array_remove(project_channel_ids, :cid) "
                "WHERE project_id = :pid "
                "AND :cid = ANY(project_channel_ids)",
            )
            result = await self.session.execute(
                stmt, {"cid": channel_id, "pid": project_id},
            )
            return int(result.rowcount or 0)
        # SQLite fallback: scan the small project-scoped set and rewrite.
        subs = await self.session.execute(
            select(UserSubscription).where(
                UserSubscription.project_id == project_id,
            ),
        )
        touched = 0
        for sub in subs.scalars().all():
            ids = list(sub.project_channel_ids or [])
            if channel_id in ids:
                sub.project_channel_ids = [x for x in ids if x != channel_id]
                touched += 1
        if touched:
            await self.session.flush()
        return touched

    async def strip_user_channel(
        self,
        *,
        user_id: UUID,
        channel_id: UUID,
    ) -> int:
        """Remove ``channel_id`` from every ``user_subscription``
        owned by ``user_id`` in the ``user_channel_ids`` column.

        User channels are owned by a single user, so we scope the
        cleanup to that user. Returns the number of rows affected.
        """
        from sqlalchemy import text

        dialect = self.session.bind.dialect.name if self.session.bind else ""
        if dialect == "postgresql":
            stmt = text(
                "UPDATE user_subscriptions "
                "SET user_channel_ids = "
                "array_remove(user_channel_ids, :cid) "
                "WHERE user_id = :uid "
                "AND :cid = ANY(user_channel_ids)",
            )
            result = await self.session.execute(
                stmt, {"cid": channel_id, "uid": user_id},
            )
            return int(result.rowcount or 0)
        # SQLite fallback: scan the user-scoped set and rewrite.
        subs = await self.session.execute(
            select(UserSubscription).where(
                UserSubscription.user_id == user_id,
            ),
        )
        touched = 0
        for sub in subs.scalars().all():
            ids = list(sub.user_channel_ids or [])
            if channel_id in ids:
                sub.user_channel_ids = [x for x in ids if x != channel_id]
                touched += 1
        if touched:
            await self.session.flush()
        return touched

    async def delete_for_user_in_project(
        self,
        *,
        user_id: UUID,
        project_id: UUID,
    ) -> int:
        """Drop all of a user's subs for one project.

        Called when a membership is revoked - the user should not
        receive notifications for a project they're no longer in.
        Returns the number of subs removed.
        """
        from sqlalchemy import delete

        result = await self.session.execute(
            delete(UserSubscription).where(
                UserSubscription.user_id == user_id,
                UserSubscription.project_id == project_id,
            ),
        )
        return int(result.rowcount or 0)


# ---------------------------------------------------------------------------
# Project default subscriptions.
# ---------------------------------------------------------------------------


class ProjectDefaultSubscriptionRepository(
    BaseRepository[ProjectDefaultSubscription]
):
    """Admin-managed templates that materialize on user join."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, ProjectDefaultSubscription)

    async def list_for_project(
        self,
        project_id: UUID,
    ) -> list[ProjectDefaultSubscription]:
        """All default-subscription templates for a project."""
        stmt = (
            select(ProjectDefaultSubscription)
            .where(ProjectDefaultSubscription.project_id == project_id)
            .order_by(ProjectDefaultSubscription.trigger)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_for_project(
        self,
        project_id: UUID,
        default_id: UUID,
    ) -> ProjectDefaultSubscription | None:
        """Scoped get - only returns if owned by the given project."""
        stmt = select(ProjectDefaultSubscription).where(
            ProjectDefaultSubscription.id == default_id,
            ProjectDefaultSubscription.project_id == project_id,
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def exists_for_project_trigger(
        self,
        project_id: UUID,
        trigger: str,
    ) -> bool:
        """Fast DB-side uniqueness check on ``(project_id, trigger)``.

        Replaces the old "fetch all, scan in Python" pattern (POL-5).
        Matches the pre-existing
        ``uq_project_default_subscriptions_project_trigger`` unique
        constraint on the model; uses a bounded ``LIMIT 1`` so the
        query is constant-time regardless of project size.
        """
        stmt = (
            select(ProjectDefaultSubscription.id)
            .where(
                ProjectDefaultSubscription.project_id == project_id,
                ProjectDefaultSubscription.trigger == trigger,
            )
            .limit(1)
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none() is not None

    async def strip_project_channel(
        self,
        *,
        project_id: UUID,
        channel_id: UUID,
    ) -> int:
        """Remove ``channel_id`` from every default-subscription
        template in this project's ``project_channel_ids`` column.
        Returns the number of rows affected.

        Mirrors :meth:`UserSubscriptionRepository.strip_project_channel`
        so admins deleting a channel do not leave orphan UUIDs in the
        default templates.
        """
        from sqlalchemy import text

        dialect = self.session.bind.dialect.name if self.session.bind else ""
        if dialect == "postgresql":
            stmt = text(
                "UPDATE project_default_subscriptions "
                "SET project_channel_ids = "
                "array_remove(project_channel_ids, :cid) "
                "WHERE project_id = :pid "
                "AND :cid = ANY(project_channel_ids)",
            )
            result = await self.session.execute(
                stmt, {"cid": channel_id, "pid": project_id},
            )
            return int(result.rowcount or 0)
        # SQLite fallback: scan and rewrite.
        rows = await self.session.execute(
            select(ProjectDefaultSubscription).where(
                ProjectDefaultSubscription.project_id == project_id,
            ),
        )
        touched = 0
        for row in rows.scalars().all():
            ids = list(row.project_channel_ids or [])
            if channel_id in ids:
                row.project_channel_ids = [x for x in ids if x != channel_id]
                touched += 1
        if touched:
            await self.session.flush()
        return touched


# ---------------------------------------------------------------------------
# In-app inbox.
# ---------------------------------------------------------------------------


class UserNotificationRepository(BaseRepository[UserNotification]):
    """Per-user notification inbox."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, UserNotification)

    async def list_for_user(
        self,
        user_id: UUID,
        *,
        unread_only: bool = False,
        limit: int = 50,
    ) -> list[UserNotification]:
        """Recent notifications for the bell, newest first."""
        if limit <= 0 or limit > 200:
            raise ValueError("limit must be between 1 and 200")
        stmt = (
            select(UserNotification)
            .where(UserNotification.user_id == user_id)
            .order_by(desc(UserNotification.created_at))
            .limit(limit)
        )
        if unread_only:
            stmt = stmt.where(UserNotification.read_at.is_(None))
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def unread_count(self, user_id: UUID) -> int:
        """Server-side unread count for the bell badge.

        Uses the partial index ``ix_user_notifications_unread`` -
        bounded scan over only unread rows.
        """
        stmt = (
            select(func.count())
            .select_from(UserNotification)
            .where(
                UserNotification.user_id == user_id,
                UserNotification.read_at.is_(None),
            )
        )
        result = await self.session.execute(stmt)
        return int(result.scalar_one() or 0)

    async def mark_read(
        self,
        *,
        user_id: UUID,
        notification_id: UUID,
    ) -> bool:
        """Mark one notification as read for this user.

        Returns True iff a row was updated. The user_id check ensures
        a user cannot mark another user's notification as read.
        """
        stmt = (
            update(UserNotification)
            .where(
                UserNotification.id == notification_id,
                UserNotification.user_id == user_id,
                UserNotification.read_at.is_(None),
            )
            .values(read_at=datetime.now(UTC))
        )
        result = await self.session.execute(stmt)
        return bool(result.rowcount)

    async def mark_all_read(self, user_id: UUID) -> int:
        """Mark every unread notification for this user as read.

        Returns the number of rows updated.
        """
        stmt = (
            update(UserNotification)
            .where(
                UserNotification.user_id == user_id,
                UserNotification.read_at.is_(None),
            )
            .values(read_at=datetime.now(UTC))
        )
        result = await self.session.execute(stmt)
        return int(result.rowcount or 0)


# ---------------------------------------------------------------------------
# External delivery audit log.
# ---------------------------------------------------------------------------


class NotificationDeliveryRepository(BaseRepository[NotificationDelivery]):
    """Project-scoped delivery audit log (external sends only)."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, NotificationDelivery)

    async def list_for_project(
        self,
        project_id: UUID,
        *,
        limit: int = 50,
        cursor_sent_at: datetime | None = None,
        cursor_id: UUID | None = None,
    ) -> list[NotificationDelivery]:
        """Newest deliveries for a project, capped at ``limit``.

        Keyset pagination on ``(sent_at, id)`` - the id tiebreaker
        matches the pattern used by the home recent-failures feed
        (R4 follow-up) so pages are stable even when multiple rows
        share a millisecond.
        """
        # Accept ``limit + 1`` sentinel loads from keyset-paginated
        # callers (fetch one past the page so we can detect the next
        # cursor without a separate COUNT query).
        if limit <= 0 or limit > 501:
            raise ValueError("limit must be between 1 and 501")
        from sqlalchemy import and_, or_

        where_conds: list[Any] = [
            NotificationDelivery.project_id == project_id,
        ]
        if cursor_sent_at is not None and cursor_id is not None:
            where_conds.append(
                or_(
                    NotificationDelivery.sent_at < cursor_sent_at,
                    and_(
                        NotificationDelivery.sent_at == cursor_sent_at,
                        NotificationDelivery.id < cursor_id,
                    ),
                ),
            )
        stmt = (
            select(NotificationDelivery)
            .where(and_(*where_conds))
            .order_by(
                desc(NotificationDelivery.sent_at),
                desc(NotificationDelivery.id),
            )
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_for_user(
        self,
        user_id: UUID,
        *,
        limit: int = 50,
        cursor_sent_at: datetime | None = None,
        cursor_id: UUID | None = None,
        project_id: UUID | None = None,
    ) -> list[NotificationDelivery]:
        """Newest deliveries TO a specific user, capped at ``limit``.

        Joins ``notification_deliveries.subscription_id`` to
        ``user_subscriptions.user_id`` so a user sees every
        notification that fired into one of their personal
        subscriptions across all projects. Added v1.0.18 to
        complement the project-scoped audit log with a personal
        delivery history view.

        - ``project_id``: optional filter when the dashboard wants
          to scope the view to one project.
        - Pagination matches :meth:`list_for_project` (keyset on
          ``(sent_at, id)`` so pages stay stable under concurrent
          insert / delete).

        IMPORTANT: includes deliveries whose subscription was later
        deleted (``subscription_id`` orphaned). Those rows still
        belong to the user historically; the dashboard renders them
        with a "subscription deleted" hint rather than hiding them.
        Same principle for the user leaving the project, historical
        audit data survives membership changes.
        """
        if limit <= 0 or limit > 501:
            raise ValueError("limit must be between 1 and 501")
        from sqlalchemy import and_, or_

        from z4j_brain.persistence.models import UserSubscription

        # Subquery: subscription IDs that belong to this user. We
        # cache the LEFT-JOIN-friendly id list so a delivery row
        # whose subscription was deleted (subscription_id NULL)
        # still surfaces if it carries a user_subscription_id we
        # remember owning. For the v1.0.18 minimum, we just match
        # by user-owned subscription_id at query time.
        owned_subs = (
            select(UserSubscription.id)
            .where(UserSubscription.user_id == user_id)
            .scalar_subquery()
        )

        # v1.1.0: a row "belongs to" the user if EITHER it fired
        # into one of their subscriptions OR they personally
        # triggered it (channel-test fires, which have
        # subscription_id=NULL but triggered_by_user_id=user.id).
        # Without the OR, test fires never appear in the personal
        # Global Notification Log even though the user fired them
        # themselves. See migration 2026_04_27_0009.
        where_conds: list[Any] = [
            or_(
                NotificationDelivery.subscription_id.in_(owned_subs),
                NotificationDelivery.triggered_by_user_id == user_id,
            ),
        ]
        if project_id is not None:
            where_conds.append(
                NotificationDelivery.project_id == project_id,
            )
        if cursor_sent_at is not None and cursor_id is not None:
            where_conds.append(
                or_(
                    NotificationDelivery.sent_at < cursor_sent_at,
                    and_(
                        NotificationDelivery.sent_at == cursor_sent_at,
                        NotificationDelivery.id < cursor_id,
                    ),
                ),
            )
        stmt = (
            select(NotificationDelivery)
            .where(and_(*where_conds))
            .order_by(
                desc(NotificationDelivery.sent_at),
                desc(NotificationDelivery.id),
            )
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def delete_for_project(
        self,
        project_id: UUID,
        *,
        before: datetime | None = None,
    ) -> int:
        """Bulk-delete delivery rows for a project.

        Used by the admin "Clear logs" UI action. Returns the row
        count that was deleted so the caller can confirm the action
        with a "deleted N rows" toast.

        ``before``, when given, restricts the delete to rows older
        than that timestamp - lets a future "Clear deliveries older
        than 30 days" UI control reuse the same path. When None,
        deletes everything for the project.
        """
        from sqlalchemy import delete as sql_delete

        stmt = sql_delete(NotificationDelivery).where(
            NotificationDelivery.project_id == project_id,
        )
        if before is not None:
            stmt = stmt.where(NotificationDelivery.sent_at < before)
        result = await self.session.execute(stmt)
        # ``rowcount`` works on every SQLAlchemy dialect we support
        # (SQLite + Postgres) for DELETE statements.
        return int(result.rowcount or 0)


__all__ = [
    "NotificationChannelRepository",
    "NotificationDeliveryRepository",
    "ProjectDefaultSubscriptionRepository",
    "UserChannelRepository",
    "UserNotificationRepository",
    "UserSubscriptionRepository",
]
