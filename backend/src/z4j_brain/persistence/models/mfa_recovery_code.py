"""``mfa_recovery_codes`` table - single-use TOTP recovery codes.

A user enrolling in TOTP MFA is issued a fixed number (default 10,
controlled by ``Z4J_MFA_RECOVERY_CODE_COUNT``) of recovery codes. They
are shown in plaintext once, downloadable as a text file, and never
re-displayed afterwards. Each code can be redeemed at most once via
``POST /api/v1/auth/mfa/verify`` and produces an audit row.

Storage: each plaintext code is hashed with argon2id (same parameters
as user passwords) before insert. The plaintext never lives in the
database. Verification iterates the user's not-yet-consumed codes and
compares each hash; on hit, ``consumed_at`` is set in the same
transaction.

Lifecycle (see ``docs/MFA-DESIGN.md`` for the full design):

- Inserted at enrollment time (``POST /auth/mfa/enroll-complete``).
- Inserted again on regenerate (``POST /auth/mfa/recovery-codes/regenerate``),
  which deletes every existing row for the user first.
- Cascade-deleted on user delete (FK ``ON DELETE CASCADE``).
- Cascade-deleted when MFA is disabled (``POST /auth/mfa/disable``).
- Cascade-deleted on the operator escape hatch (``z4j reset-mfa <email>``).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin


class MfaRecoveryCode(PKMixin, Base):
    """One hashed, single-use TOTP recovery code.

    Attributes:
        user_id: Owning user. ``ON DELETE CASCADE`` so a user delete
            sweeps every code in one shot.
        code_hash: argon2id hash of the plaintext code (Crockford-ish
            ``XXXX-XXXX-XXXX`` format, ~60 bits of entropy).
        created_at: When the code was minted.
        consumed_at: ``NULL`` until verification redeems the code,
            then set to ``NOW()``. Consumed codes never verify again.
    """

    __tablename__ = "mfa_recovery_codes"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    code_hash: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        Index("ix_mfa_recovery_codes_user_id", "user_id"),
    )


__all__ = ["MfaRecoveryCode"]
