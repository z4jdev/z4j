"""``password_reset_tokens`` table - single-use password-reset tokens.

Same shape as :class:`FirstBootToken` (one token per row, HMAC hash,
TTL-bounded) with one extra field: ``user_id`` so the confirm path
can flip the user's password without trusting the email in the
request body.

Privacy note: the request endpoint responds with a generic success
message regardless of whether the email matches a known user, so
``password_reset_tokens`` only ever gets a row for real accounts.
An attacker probing which emails exist still can't tell from the
HTTP response - but they CAN tell from SMTP bounces if they have
access to the mail gateway, which is a broader threat-model issue
that affects every password-reset flow.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin


class PasswordResetToken(PKMixin, Base):
    """A one-time password-reset token.

    Attributes:
        user_id: User the token authorizes. FK to users.id with
            ``ON DELETE CASCADE`` so deleting a user invalidates
            any outstanding tokens.
        token_hash: HMAC-SHA256 hex digest of the plaintext token.
        expires_at: TTL - defaults to 30 minutes after creation.
        consumed_at: Set when the confirm endpoint accepts the token.
            Tokens are rejected once consumed (single-use).
        created_at: When the token was minted.
    """

    __tablename__ = "password_reset_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(String, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
    )
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


__all__ = ["PasswordResetToken"]
