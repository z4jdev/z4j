"""``feature_flags`` table - runtime feature toggles.

Used across all phases for gradual rollout of new features,
A/B testing, and emergency kill switches. Table created in
initial schema so no migration needed.
"""

from __future__ import annotations

from sqlalchemy import Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin


class FeatureFlag(PKMixin, TimestampsMixin, Base):
    """A runtime feature flag (key-value with enabled toggle)."""

    __tablename__ = "feature_flags"

    key: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false",
    )
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")


__all__ = ["FeatureFlag"]
