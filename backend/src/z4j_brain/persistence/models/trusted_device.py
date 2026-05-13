"""``trusted_devices`` table - "remember this device for N days" cookie store.

When a user verifies their TOTP code with the ``remember_device`` flag
set, the brain mints an opaque random ``cookie_id`` (32 bytes) and
stores the SHA-256 hash here alongside a human label and an expiry.
The plaintext id rides in the ``z4j_mfa_trust`` cookie (HttpOnly +
Secure + SameSite=Strict, server-bound to the brain's domain). On
subsequent logins the brain hashes the inbound cookie value and looks
it up; if a non-revoked non-expired row is found for the same user,
the MFA second step is skipped.

The server-side row is the authoritative truth; the cookie is just an
opaque pointer. This buys us revoke-from-anywhere: the user can list
their trusted devices and revoke any one of them from any session,
and the brain enforces the revocation immediately.

Lifecycle (see ``docs/MFA-DESIGN.md``):

- Insert: at verify time when ``remember_device=true`` is set.
- Update ``last_seen_at``: on every successful trust-skip.
- Revoke: ``POST /auth/mfa/trusted-devices/{id}/revoke`` sets
  ``revoked_at``.
- Hard-delete: on ``POST /auth/change-password``, on
  ``POST /auth/mfa/disable``, on user delete (cascade), on
  ``z4j reset-mfa <email>``.
- Hard upper bound on lifetime: ``Z4J_MFA_REMEMBER_DEVICE_DAYS`` (with
  a 90-day ceiling enforced by the settings validator).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin


class TrustedDevice(PKMixin, Base):
    """A "remember this device" row.

    Attributes:
        user_id: Owning user. ``ON DELETE CASCADE`` so user deletes
            sweep the trust state cleanly.
        cookie_id_hash: SHA-256 hex digest of the plaintext cookie id.
            UNIQUE so a brute-force prefix collision attack would have
            to win against a 256-bit hash space.
        label: Human-readable device tag (e.g. ``Firefox on macOS``).
            Synthesized from the User-Agent at insert time; the user
            can rename it via ``PATCH /auth/mfa/trusted-devices/{id}``.
        created_at: When the device was first trusted.
        last_seen_at: Updated on every successful trust-skip.
        expires_at: Absolute expiry. Past this, the cookie no longer
            verifies even if the row is not explicitly revoked.
        revoked_at: ``NULL`` for live rows; set when the user (or the
            password-change hook) revokes the device.
    """

    __tablename__ = "trusted_devices"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    cookie_id_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
    )
    label: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        Index("ix_trusted_devices_user_id", "user_id"),
        Index("ix_trusted_devices_expires_at", "expires_at"),
    )


__all__ = ["TrustedDevice"]
