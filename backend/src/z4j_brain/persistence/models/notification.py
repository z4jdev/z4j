"""Notification system models - per-user subscription model.

Five tables:

- :class:`NotificationChannel` - a project-scoped delivery target
  configured by an admin. Shared resource: any project member can
  subscribe to deliver via these channels. Examples: a team Slack
  webhook, a shared #api-alerts room, a project-wide email list.

- :class:`UserChannel` - a user-scoped delivery target the user
  configured for themselves. Examples: the user's personal email,
  their Telegram chat, a personal webhook. Only the owning user
  can reference their own user_channels in subscriptions.

- :class:`UserSubscription` - one user's choice to receive a given
  trigger from a given project, delivered via a chosen mix of
  in-app + project channels + user channels. UNIQUE per
  ``(user_id, project_id, trigger)`` so each user has at most one
  subscription per project per trigger.

- :class:`ProjectDefaultSubscription` - admin-defined templates
  copied into ``user_subscriptions`` whenever a user joins the
  project. After copy, the user owns their materialized rows
  (edit / delete is local). UNIQUE per ``(project_id, trigger)``.

- :class:`UserNotification` - the in-app inbox. One row per
  notification delivered to a user via the in-app channel. Each
  user has their own read state (``read_at``).

- :class:`NotificationDelivery` - immutable audit log of EXTERNAL
  delivery attempts (webhook/email/slack/telegram). In-app deliveries
  go to ``user_notifications`` directly and do NOT create delivery
  rows. References the originating subscription so admins can trace
  "which subscription fired this Slack message".

"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    desc,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin
from z4j_brain.persistence.types import jsonb, uuid_array


# ---------------------------------------------------------------------------
# Type vocabularies (kept as plain string constants - matches the rest of
# the brain's "string columns over Python enums" convention used by
# ChannelType in the previous design and by AlertEvent.severity).
# ---------------------------------------------------------------------------


class ChannelType:
    """Allowed values for the ``type`` column on channel tables.

    The same vocabulary applies to both project-scoped
    :class:`NotificationChannel` and user-scoped :class:`UserChannel`.
    """

    WEBHOOK = "webhook"
    EMAIL = "email"
    SLACK = "slack"
    TELEGRAM = "telegram"
    #: PagerDuty Events API v2 - one POST per alert. Config:
    #: ``{"integration_key": "...", "severity_default": "warning",
    #: "severity_map": {"task.failed": "error", "agent.offline":
    #: "critical", ...}}``. Added v1.0.14.
    PAGERDUTY = "pagerduty"
    #: Discord incoming webhook - accepts a Slack-compatible payload
    #: when posted to ``<webhook_url>/slack``. Config:
    #: ``{"webhook_url": "https://discord.com/api/webhooks/..."}``.
    #: Added v1.0.14.
    DISCORD = "discord"


class TriggerType:
    """Event types that can fire a subscription."""

    TASK_FAILED = "task.failed"
    TASK_SUCCEEDED = "task.succeeded"
    TASK_RETRIED = "task.retried"
    TASK_SLOW = "task.slow"
    AGENT_OFFLINE = "agent.offline"
    AGENT_ONLINE = "agent.online"


class DeliveryStatus:
    """Allowed values for ``notification_deliveries.status``."""

    SENT = "sent"
    FAILED = "failed"
    SKIPPED = "skipped"


class NotificationReason:
    """Allowed values for ``user_notifications.reason``.

    Helps users answer "why did I get this?" - shown in the bell row.
    """

    SUBSCRIBED = "subscribed"   # explicit user_subscription matched
    DEFAULT = "default"         # came from a project default subscription
    MENTIONED = "mentioned"     # @mention - phase 2


# ---------------------------------------------------------------------------
# Project-scoped: shared channels admins manage.
# ---------------------------------------------------------------------------


class NotificationChannel(PKMixin, TimestampsMixin, Base):
    """A project-shared notification delivery target.

    Configured by a project admin. Any project member can reference
    these in their subscriptions. Examples: a team Slack webhook
    that everyone might want to send their alerts to, a project
    pager email, a webhook into a shared incident-management tool.

    Attributes:
        project_id: Owning project.
        name: Human-readable label (e.g. "Ops Slack #alerts").
        type: One of webhook/email/slack/telegram.
        config: JSON blob with channel-specific settings.
            See :mod:`z4j_brain.domain.notifications.channels` for shapes.
        is_active: Soft toggle. Disabled channels are skipped
            during dispatch but kept for audit references.
    """

    __tablename__ = "notification_channels"

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    type: Mapped[str] = mapped_column(String(20), nullable=False)
    config: Mapped[dict] = mapped_column(jsonb(), nullable=False, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


# ---------------------------------------------------------------------------
# User-scoped: personal channels.
# ---------------------------------------------------------------------------


class UserChannel(PKMixin, TimestampsMixin, Base):
    """A user-scoped notification delivery target.

    The user configures these in Global Settings > Channels.
    Examples: their personal email, their personal Telegram chat,
    a webhook into their own pager. Only the owning user can
    reference their own ``user_channels`` from a subscription.

    Attributes:
        user_id: Owner. Cascade-delete with the user.
        name: Human-readable label (e.g. "My Telegram", "Work Email").
        type: One of webhook/email/slack/telegram - same vocabulary
            as project channels.
        config: JSON blob with channel-specific settings.
        is_verified: Future use - set when the user proves they
            actually own the destination (e.g., they replied to
            a confirmation email). Phase 1 ignores this.
        is_active: Soft toggle.
    """

    __tablename__ = "user_channels"
    __table_args__ = (
        UniqueConstraint("user_id", "name", name="uq_user_channel_name"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    type: Mapped[str] = mapped_column(String(20), nullable=False)
    config: Mapped[dict] = mapped_column(jsonb(), nullable=False, default=dict)
    is_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


# ---------------------------------------------------------------------------
# Per-user subscriptions.
# ---------------------------------------------------------------------------


class UserSubscription(PKMixin, TimestampsMixin, Base):
    """A user's choice to receive a given trigger on a given project.

    Each user decides which events they care about and which channels
    they want them on. UNIQUE per ``(user_id, project_id, trigger)``
    to keep the model simple - "do you want task.failed notifications
    for project X? yes/no, on these channels".

    Channels are referenced as UUID arrays (Postgres UUID[]). On
    SQLite the same column is JSONB-as-list - good enough for unit
    tests. The arrays are NOT foreign-key constrained; integrity
    is enforced at write time by the service (and stale entries
    are filtered at dispatch time).

    Attributes:
        user_id, project_id: Scope.
        trigger: Event type (e.g. ``task.failed``).
        filters: Optional narrowing (priority, task_name_pattern, queue).
        in_app: Deliver to the user's in-app inbox.
        project_channel_ids: List of NotificationChannel.id to fire.
        user_channel_ids: List of UserChannel.id (must be owned by user_id).
        muted_until: Soft-mute until this timestamp; NULL = not muted.
        cooldown_seconds: Minimum interval between firings for the
            same task_name. Phase 1 strategy is "drop if cooldown
            not elapsed" (Option A).
        last_fired_at: Updated each time a delivery fires for this
            subscription. Used for cooldown calculations.
        is_active: Soft toggle - user can disable without deleting.
    """

    __tablename__ = "user_subscriptions"
    __table_args__ = (
        UniqueConstraint(
            "user_id", "project_id", "trigger",
            name="uq_user_subscription_trigger",
        ),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    trigger: Mapped[str] = mapped_column(String(40), nullable=False)
    filters: Mapped[dict] = mapped_column(jsonb(), nullable=False, default=dict)
    in_app: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    project_channel_ids: Mapped[list[uuid.UUID]] = mapped_column(
        # Postgres-side UUID[]; on SQLite SQLAlchemy falls back to
        # storing the list as JSON (kombu/JSON encoder handles UUIDs).
        uuid_array(),
        nullable=False,
        default=list,
    )
    user_channel_ids: Mapped[list[uuid.UUID]] = mapped_column(
        uuid_array(),
        nullable=False,
        default=list,
    )
    muted_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    cooldown_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
    )
    last_fired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


# ---------------------------------------------------------------------------
# Project default subscriptions (onboarding templates).
# ---------------------------------------------------------------------------


class ProjectDefaultSubscription(PKMixin, TimestampsMixin, Base):
    """An admin-defined subscription template for new project members.

    When a user joins a project, the membership service materializes
    one ``UserSubscription`` row per ``ProjectDefaultSubscription``
    for that user. After materialization, the user fully owns the
    copy - editing / deleting their copy does not touch the template.

    User channels are intentionally NOT included here: defaults
    are project-scoped and cannot reference per-user destinations.
    Each user can add their own user channels to their materialized
    copy after the fact.

    UNIQUE per ``(project_id, trigger)`` - one default per trigger
    per project. The out-of-the-box default we ship for every new
    project is ``task.failed`` with ``in_app=True`` and no channels.

    Attributes:
        project_id: Owning project.
        trigger: Event type.
        filters: Optional narrowing copied into materialized subs.
        in_app: Default in-app preference for new members.
        project_channel_ids: Channel UUIDs to copy in.
        cooldown_seconds: Default cooldown.
    """

    __tablename__ = "project_default_subscriptions"
    __table_args__ = (
        UniqueConstraint(
            "project_id", "trigger",
            name="uq_project_default_subscription_trigger",
        ),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    trigger: Mapped[str] = mapped_column(String(40), nullable=False)
    filters: Mapped[dict] = mapped_column(jsonb(), nullable=False, default=dict)
    in_app: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    project_channel_ids: Mapped[list[uuid.UUID]] = mapped_column(
        uuid_array(),
        nullable=False,
        default=list,
    )
    cooldown_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
    )


# ---------------------------------------------------------------------------
# In-app inbox.
# ---------------------------------------------------------------------------


class UserNotification(PKMixin, Base):
    """One in-app notification delivered to a user.

    Created by the dispatcher when a subscription matches and
    ``in_app=True``. Users see these in the notification bell.
    Each user has independent read state (``read_at``).

    No ``updated_at`` - notifications are immutable except for
    the ``read_at`` flip (which is more of a status than a record
    update; we don't need full audit on it).

    Attributes:
        user_id: Recipient.
        project_id: Source project (for filtering / grouping).
        subscription_id: The subscription that fired this notification.
            ``SET NULL`` so deleting the subscription doesn't blow
            away the inbox row - the notification text remains
            readable in the bell.
        trigger: Event type that fired (e.g. ``task.failed``).
        reason: Why the user got this (subscribed / default / mentioned).
            See :class:`NotificationReason`.
        title: Short bell-row line ("Task failed: demo_app.tasks.ping").
        body: Optional longer body for the bell expanded view.
        data: JSON blob for deep-linking (``task_id``, ``worker_id``,
            ``schedule_id``, ``url``, ...).
        read_at: NULL = unread. Set to NOW() when the user marks read.
        created_at: When the notification was created.
    """

    __tablename__ = "user_notifications"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    subscription_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("user_subscriptions.id", ondelete="SET NULL"),
        nullable=True,
    )
    trigger: Mapped[str] = mapped_column(String(40), nullable=False)
    reason: Mapped[str] = mapped_column(
        String(20), nullable=False, default=NotificationReason.SUBSCRIBED,
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    data: Mapped[dict] = mapped_column(jsonb(), nullable=False, default=dict)
    read_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


# ---------------------------------------------------------------------------
# External-delivery audit log.
# ---------------------------------------------------------------------------


class NotificationDelivery(PKMixin, Base):
    """Immutable record of one EXTERNAL delivery attempt.

    Created when the dispatcher sends to a webhook / email / slack /
    telegram channel. In-app deliveries do NOT create delivery rows;
    they go to ``user_notifications`` directly. Use this table for
    "did the Slack POST succeed?" debugging.

    Attributes:
        subscription_id: Which subscription fired this delivery.
            SET NULL on subscription delete (audit history outlives
            the subscription). Always NULL for test fires (they
            aren't owned by any subscription).
        channel_id: NotificationChannel target. NULL if the channel
            was a UserChannel (we only audit project-channel sends
            globally; user-channel sends are owned by the user).
        user_channel_id: UserChannel target. NULL if project channel.
            Exactly one of channel_id / user_channel_id is set.
        project_id: Owning project (denormalized for fast queries).
        trigger: The trigger type that fired.
        task_id, task_name: Trigger context (if task-related).
        status: sent / failed / skipped (cooldown / muted).
        response_code: HTTP status code from the channel (if applicable).
        response_body: Truncated response body (for debugging failures).
        error: Error message if delivery failed.
        sent_at: When the delivery attempt was made.
        triggered_by_user_id: User who manually triggered this row
            (test fires only). NULL for subscription-driven fires.
            Lets the personal Global Notification Log surface test
            rows the operator triggered themselves; the dashboard
            renders these with a "channel test" badge.
    """

    __tablename__ = "notification_deliveries"

    subscription_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("user_subscriptions.id", ondelete="SET NULL"),
        nullable=True,
    )
    channel_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("notification_channels.id", ondelete="SET NULL"),
        nullable=True,
    )
    user_channel_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("user_channels.id", ondelete="SET NULL"),
        nullable=True,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    trigger: Mapped[str] = mapped_column(String(40), nullable=False)
    task_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    task_name: Mapped[str | None] = mapped_column(String(500), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    response_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Snapshot at insert time (audit L-2, added v1.0.14). Pre-1.0.14
    # the dashboard resolved channel_name + channel_type via a live
    # join on read - which let an admin rename a channel after a
    # sensitive dispatch and retroactively rewrite the audit story.
    # Snapshotting at write time freezes the audit row's view of
    # what destination it actually went to. NULL for pre-1.0.14
    # rows (the migration doesn't backfill); the read path falls
    # back to a live join when both snapshot fields are NULL.
    channel_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    channel_type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    sent_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    # v1.1.0: pointer to the user who manually triggered this row
    # (test fires only). Subscription-driven fires leave it NULL.
    # Migration 2026_04_27_0009.
    triggered_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Hot-path index for the admin Delivery Log page -
    # ``list_for_project`` filters by ``project_id`` and orders by
    # ``sent_at DESC``. Without this index a project with 100k+
    # deliveries forces a sort over the partition; with it the
    # listing stays sub-ms even at scale. See
    # docs/PRODUCTION_READINESS_2026Q2.md POL-1.
    __table_args__ = (
        Index(
            "ix_notification_deliveries_project_sent",
            "project_id",
            desc("sent_at"),
        ),
        Index(
            "ix_notification_deliveries_triggered_by_user",
            "triggered_by_user_id",
        ),
    )


__all__ = [
    "ChannelType",
    "DeliveryStatus",
    "NotificationChannel",
    "NotificationDelivery",
    "NotificationReason",
    "ProjectDefaultSubscription",
    "TriggerType",
    "UserChannel",
    "UserNotification",
    "UserSubscription",
]
