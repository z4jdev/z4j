"""``invitations`` table - single-use team-invitation tokens.

An admin mints an invitation for a specific ``(email, project,
role)``. The brain stores the token as an HMAC-SHA256 hash (the
plaintext is shown once at mint, never persisted). The invitee
accepts by visiting ``/invite?token=<plaintext>``, which verifies
the hash, creates the user, grants membership, and stamps
``accepted_at`` + ``accepted_by_user_id`` in the same transaction.

Lifecycle (mutually exclusive states):

- **Pending**: ``accepted_at IS NULL AND revoked_at IS NULL AND
  expires_at > now()``. Accept endpoint succeeds.
- **Accepted**: ``accepted_at IS NOT NULL``. The created user's id
  is in ``accepted_by_user_id``; the row stays as an audit trail.
- **Revoked**: ``revoked_at IS NOT NULL``. Admin cancelled before
  acceptance. Cannot be un-revoked; admin re-invites instead.
- **Expired**: ``expires_at <= now()`` and neither accepted nor
  revoked. Accept endpoint rejects with a clear error.

Security invariants (mirror first_boot_tokens per audit H5):

- Plaintext token never persisted - HMAC-SHA256 hash only.
- TTL default 7 days (overridable per-invite).
- Accept endpoint re-checks "user with this email doesn't already
  exist" inside the same transaction as the user insert (TOCTOU).
- Token comparison uses ``hmac.compare_digest`` (constant-time).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin


class Invitation(PKMixin, TimestampsMixin, Base):
    """A pending invitation to join a project.

    Attributes:
        project_id: Project the invitee will gain membership on.
        email: Invitee's email. Acceptance creates a user with this
            email; the invitee cannot change it in the accept form.
        role: Role the invitee will be granted - one of
            ``viewer`` / ``operator`` / ``admin``.
        invited_by: Admin who minted the invitation. SET NULL on
            user delete (invite stays as an audit row).
        token_hash: HMAC-SHA256 hex digest of the plaintext token.
            Plaintext shown once at mint, never stored. Indexed
            for constant-time accept-path lookups.
        expires_at: TTL. Default 7 days; accept endpoint refuses
            after this point.
        accepted_at: ``NULL`` until accepted. Set in the same
            transaction as the user + membership insert.
        accepted_by_user_id: FK to the user created at accept time.
            ``NULL`` until accepted; SET NULL on user delete (same
            reasoning as ``invited_by``).
        revoked_at: ``NULL`` until an admin cancels.
    """

    __tablename__ = "invitations"

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(20), nullable=False, default="viewer",
    )
    invited_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    token_hash: Mapped[str] = mapped_column(String, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
    )
    accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    accepted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )

    __table_args__ = (
        # Constant-time accept-path lookup by token hash.
        Index("ix_invitations_token_hash", "token_hash", unique=True),
        # Hot path: admin lists pending invites per project
        # (WHERE project_id = ? AND accepted_at IS NULL AND
        # revoked_at IS NULL ORDER BY expires_at).
        Index(
            "ix_invitations_project_pending",
            "project_id",
            "expires_at",
        ),
    )


__all__ = ["Invitation"]
