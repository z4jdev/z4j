"""``first_boot_tokens`` table - single-use first-boot setup token.

At most one row exists at any time. The brain creates a row on
first startup (when ``users`` is empty), prints the token to stdout
in an ASCII banner, and deletes the row when the operator completes
the setup form. Token plaintext is never stored - only an HMAC
hash.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin


class FirstBootToken(PKMixin, Base):
    """A one-time setup token.

    Attributes:
        token_hash: HMAC-SHA256 hex digest of the plaintext token.
            Plaintext is never persisted.
        expires_at: TTL - defaults to 15 minutes after creation.
            The setup endpoint refuses tokens past this point.
        created_at: When the token was minted.
    """

    __tablename__ = "first_boot_tokens"

    token_hash: Mapped[str] = mapped_column(String, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


__all__ = ["FirstBootToken"]
