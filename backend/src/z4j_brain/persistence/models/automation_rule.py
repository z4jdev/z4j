"""``automation_rules`` table -- the cross-engine rule engine.

An automation rule watches a TRIGGER (``task.failed``, ``worker.offline``,
``schedule.misfired``, ...), evaluates a set of CONDITIONS against the
triggering event, and -- when they match -- runs one or more ACTIONS
(notify / retry / cancel / revoke / purge / pause_schedule) subject to a
per-rule circuit breaker.

Design notes:

- Conditions use a FIXED, statically-analyzable grammar validated at
  write time (see ``z4j_brain.domain.automation.evaluator``), NOT an
  arbitrary expression sandbox, so there is no ReDoS or code-execution
  surface. This is the deliberate compliance-safe choice.
- The condition / action / circuit-breaker CONFIG lives in JSONB columns;
  exact rolling-window admissions live in ``automation_rule_admissions``
  while the current count, oldest retained timestamp, configuration epoch,
  and tripped projection live on this row. The executor maintains them
  atomically under this rule's row lock.
- ``trigger`` is a plain string (not a native enum) so adding a trigger
  needs no migration -- the same convention as ``schedule_fires.status``
  and the notification-vocabulary columns.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin
from z4j_brain.persistence.types import jsonb


class AutomationRule(PKMixin, TimestampsMixin, Base):
    """One automation rule, scoped to a project."""

    __tablename__ = "automation_rules"

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    #: A dry-run rule evaluates + audits what it WOULD do but executes
    #: no action. New rules should default to dry_run at the API layer.
    dry_run: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )

    #: Trigger vocabulary string. See ``evaluator.TRIGGER_TYPES``.
    trigger: Mapped[str] = mapped_column(String(64), nullable=False)

    #: Condition grammar dict (validated at write time by
    #: ``evaluator.validate_conditions``). Empty ``{}`` = match every
    #: event of this trigger.
    conditions: Mapped[dict[str, Any]] = mapped_column(
        jsonb(),
        nullable=False,
        default=dict,
        server_default="{}",
    )
    #: Ordered list of action specs, gated by the target adapter's
    #: capabilities at execution time.
    actions: Mapped[list[Any]] = mapped_column(
        jsonb(),
        nullable=False,
        default=list,
        server_default="[]",
    )

    # ------------------------------------------------------------------
    # Circuit breaker (copied from Kanchi, then beaten with dry-run +
    # RBAC gates): bound the blast radius of a misfiring rule.
    # ------------------------------------------------------------------
    max_executions_per_window: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=100,
        server_default="100",
    )
    window_seconds: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=3600,
        server_default="3600",
    )
    #: Circuit-breaker STATE, maintained atomically by the executor.
    #: On trip the rule downgrades to notify-only "failsafe mode".
    cb_tripped: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )
    cb_window_start: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    cb_execution_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    #: Notify-coalesce STATE: the last time this rule emitted a notify
    #: action. When ``automation_notify_coalesce_seconds`` > 0, notifies
    #: inside that window are suppressed (and counted on a metric) so a
    #: distinct-event flood cannot fan out one notification per event per
    #: member. Advanced under the same FOR UPDATE lock as the breaker, so
    #: the check is race-free across concurrent dispatch tasks.
    last_notify_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    #: Creator, for audit attribution of automated actions. ``ON DELETE
    #: SET NULL`` so deleting a user does not delete their rules.
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    #: Content hash for future declarative reconciliation.
    source_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: Monotonic execution-configuration epoch. Every supported mutation of
    #: an execution-relevant field advances this value in the same locked
    #: database write. Unlike a content hash it cannot return to an earlier
    #: value after an edit-away/edit-back ABA sequence, so a dispatch selected
    #: before either edit remains stale even when the final JSON is identical.
    #:
    #: This and ``cb_config_digest`` are appended by 0014. Their explicit sort
    #: order keeps a consolidated fresh install byte-for-byte aligned with an
    #: upgrade from the prior release.
    config_revision: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
        sort_order=1000,
    )
    #: SHA-256 of the execution-relevant configuration whose admissions are
    #: stored in ``automation_rule_admissions``. A config change starts a new
    #: breaker epoch atomically at the next claim; without this marker,
    #: widening a window after old timestamps were pruned could not be an
    #: exact rolling-window calculation.
    #:
    #: This declaration intentionally remains the last physical column: 0014
    #: appends it after ``config_revision`` on an existing installation, and
    #: the consolidated fresh path must produce the identical ordinal schema.
    cb_config_digest: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        # Mixin columns are collected after ordinary subclass columns.
        # Explicitly sort this appended 0014 column after id/timestamps too.
        sort_order=1001,
    )

    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "name",
            name="uq_automation_rules_project_name",
        ),
        Index(
            "ix_automation_rules_project_trigger",
            "project_id",
            "trigger",
            "is_enabled",
        ),
    )


__all__ = ["AutomationRule"]
