"""``projects`` table - logical grouping of agents and events.

A project corresponds roughly to "one app deployment" - a Django
project, a Flask service, etc. Tokens are project-scoped, retention
is per-project, and dashboard navigation is project-scoped.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import Boolean, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin
from z4j_brain.persistence.types import jsonb


class Project(PKMixin, TimestampsMixin, Base):
    """A z4j project.

    Attributes:
        slug: URL-safe identifier, also surfaced in agent token
            prefixes. Format enforced as a CHECK constraint at the
            database level - defence in depth against SQL-injection
            attempts via slug routing.
        name: Human-readable display name.
        description: Optional free-form description.
        environment: Free-form label like ``production`` / ``staging``.
        timezone: Default timezone for dashboard rendering.
        retention_days: Per-project event retention. The
            RetentionWorker drops event partitions older than this.
        is_active: Soft-disable flag.
    """

    __tablename__ = "projects"

    slug: Mapped[str] = mapped_column(
        String(63), nullable=False, unique=True,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    environment: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        default="production",
        server_default="production",
    )
    timezone: Mapped[str] = mapped_column(
        String(64), nullable=False, default="UTC", server_default="UTC",
    )
    retention_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=30, server_default="30",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true",
    )

    # ``default_scheduler_owner`` (1.2.2+): which scheduler owns
    # newly-created schedules in this project when the operator
    # didn't pick explicitly. Default ``z4j-scheduler`` (the new
    # product); celery-beat-first shops can flip to ``celery-beat``
    # so new schedules created via the dashboard land under
    # celery-beat ownership without surprising the legacy stack.
    # The column intentionally accepts free-form strings (not an
    # enum) so future schedulers (apscheduler, custom, etc.) can
    # be added without a migration.
    # Width: ``String(64)`` (set by migration 0014). The Pydantic
    # gate (``_SCHEDULER_OWNER_PATTERN``) caps incoming values at
    # 40 chars to match ``Schedule.scheduler``; the column being
    # wider is harmless headroom. (We considered narrowing to 40
    # in 1.2.2 round 8 via migration 0021, reverted in round 9
    # along with the broader cascade revert.)
    default_scheduler_owner: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="z4j-scheduler",
        server_default="z4j-scheduler",
    )

    # ``allowed_schedulers`` (1.2.2+, audit fix MED-13): optional
    # JSON array of scheduler names this project may assign on
    # schedule create/update/import. ``NULL`` = unrestricted
    # (backwards-compat default, existing operators see no
    # behaviour change). When set, the schedule mutation paths
    # reject any value not in the list. Always allows
    # ``default_scheduler_owner`` so toggling the project setting
    # never strands existing schedules.
    allowed_schedulers: Mapped[list[str] | None] = mapped_column(
        jsonb(), nullable=True,
    )

    # ------------------------------------------------------------------
    # Future columns (reserved, unused until Phase 2/3)
    # ------------------------------------------------------------------
    settings: Mapped[dict[str, Any] | None] = mapped_column(
        jsonb(), nullable=True,
    )  # Per-project config overrides (Phase 2)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), nullable=True,
    )  # Org hierarchy (Phase 3)

    __table_args__ = (
        # The CHECK constraint that enforces the slug regex is added
        # in the alembic migration as raw SQL - Postgres uses ``~``
        # which SQLite cannot parse, so it has no place in the
        # cross-dialect model declaration.
        Index("ix_projects_active", "is_active"),
    )


__all__ = ["Project"]
