"""``sessions`` table - server-side session storage.

Sessions are looked up by id on every authenticated request, which
means we can revoke them before their absolute expiry: logout,
password change, admin kill, account deactivation. Pure stateless
JWT-style cookies cannot offer any of that without a separate
denylist that grows forever.

The cookie value is a signed envelope (``itsdangerous`` HMAC over
``{sid, csrf}``) - the session id alone is not the bearer; the
signature must verify too. The DB row is the source of truth for
``revoked_at``, ``last_seen_at``, and the absolute ``expires_at``.

Cost: one indexed SELECT + one indexed UPDATE per authenticated
request. Both hit the primary key. The trade is well worth the
ability to revoke sessions on demand - see ``docs/SECURITY.md``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.types import inet


class Session(Base):
    """A live (or revoked) dashboard session.

    Attributes:
        id: Random UUID. The cookie value carries this id inside an
            ``itsdangerous`` signed envelope.
        user_id: Owning user. ``ON DELETE CASCADE`` so deleting a
            user kills every session in one shot.
        csrf_token: 32 url-safe bytes bound to this session.
            Echoed in the parallel ``__Host-z4j_csrf`` cookie and
            checked on every state-changing request via
            ``hmac.compare_digest``.
        issued_at: When the session was created (login or setup
            completion).
        expires_at: Hard cap. Sessions past this are rejected even
            if active. Set to ``issued_at +
            settings.session_absolute_lifetime_seconds``.
        last_seen_at: Sliding-idle anchor. Updated on every request
            that successfully resolves a session. A session whose
            ``last_seen_at`` is older than
            ``settings.session_idle_timeout_seconds`` is rejected.
        revoked_at: Set when the session is explicitly killed.
            ``NULL`` for live sessions.
        revocation_reason: ``logout`` | ``password_changed`` |
            ``admin_revoke`` | ``deactivated`` | ``role_changed``.
        ip_at_issue: Real client IP at the time the session was
            issued. Used for forensics and (optionally) for
            session pinning.
        user_agent_at_issue: Truncated to 256 chars. Used for
            forensics and (optionally) for the user-agent
            pinning policy.
    """

    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revocation_reason: Mapped[str | None] = mapped_column(
        String(40),
        nullable=True,
    )
    ip_at_issue: Mapped[str] = mapped_column(inet(), nullable=False)
    user_agent_at_issue: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
    )

    __table_args__ = (
        Index("ix_sessions_user_id", "user_id"),
        Index("ix_sessions_expires_at", "expires_at"),
        # The partial index ``ix_sessions_user_active`` (WHERE
        # revoked_at IS NULL) is added in the migration as raw SQL -
        # SQLite cannot represent partial indexes portably.
    )


__all__ = ["Session"]
