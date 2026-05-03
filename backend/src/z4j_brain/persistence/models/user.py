"""``users`` table - brain dashboard accounts.

Brain users are the operators who log into the dashboard. They are
NOT the customer's end-users - those live in the customer's own
Django/Flask/FastAPI app and the brain knows about them only via
``RequestContext`` enrichment on events.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin
from z4j_brain.persistence.types import citext, inet


class User(PKMixin, TimestampsMixin, Base):
    """A dashboard user account.

    Attributes:
        email: Case-insensitive email address. ``CITEXT UNIQUE`` on
            Postgres so ``alice@x`` and ``Alice@X`` are the same row.
        password_hash: argon2id hash. Set by the auth layer in B3.
        display_name: Optional human-readable name.
        is_admin: Global brain admin (created by the first-boot flow).
            Distinct from project-level ``admin`` role in
            :class:`Membership`.
        is_active: Soft-disable flag. Inactive users cannot log in but
            their audit-log rows are preserved.
        last_login_at: Updated by the auth layer on each successful
            login. Used to surface stale accounts.
        force_password_change: When True, the next login redirects
            to the password-reset flow before any other action.
        timezone: User-preferred timezone for dashboard rendering.
    """

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(
        citext(),
        unique=True,
        nullable=False,
    )
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    display_name: Mapped[str | None] = mapped_column(String, nullable=True)
    # Structured name fields, nullable to accommodate single-name or
    # organisational accounts. ``display_name`` stays canonical - if
    # present it wins; otherwise the API derives it from
    # ``{first} {last}`` and falls back to the email local part.
    first_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    last_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    is_admin: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true",
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    force_password_change: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false",
    )
    timezone: Mapped[str] = mapped_column(
        String(64), nullable=False, default="UTC", server_default="UTC",
    )

    # ------------------------------------------------------------------
    # Lockout / brute-force protection (B3)
    # ------------------------------------------------------------------
    failed_login_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_failed_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_failed_login_ip: Mapped[str | None] = mapped_column(
        inet(),
        nullable=True,
    )
    #: Anchor for the "password rotated → revoke older sessions" rule.
    #: Sessions issued at or before this timestamp are treated as
    #: revoked.
    password_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ------------------------------------------------------------------
    # Future columns (reserved, unused until Phase 2/3)
    # ------------------------------------------------------------------
    avatar_url: Mapped[str | None] = mapped_column(String, nullable=True)
    mfa_secret: Mapped[str | None] = mapped_column(String, nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false",
    )
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sso_provider: Mapped[str | None] = mapped_column(String(50), nullable=True)

    __table_args__ = (
        # Partial index - only active users matter for dashboard listings.
        # The migration adds this with `WHERE is_active` on Postgres.
        Index("ix_users_active", "is_active"),
    )


__all__ = ["User"]
