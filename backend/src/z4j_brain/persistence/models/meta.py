"""``z4j_meta`` table - application-level metadata.

Stores key-value pairs for the brain's internal bookkeeping:
- ``schema_version``: the CalVer of the code that last migrated the DB
- ``installed_at``: when the brain was first installed
- ``last_upgraded_at``: when the last migration ran

This is separate from Alembic's ``alembic_version`` table. Alembic
tracks migration file revisions; this table tracks the application
version that owns the schema. If a user downgrades the brain binary
but the schema was already migrated forward, the startup check
reads ``schema_version`` and refuses to start with a clear error.
"""

from __future__ import annotations

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin


class Z4JMeta(PKMixin, TimestampsMixin, Base):
    """Application metadata key-value store."""

    __tablename__ = "z4j_meta"

    key: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")


__all__ = ["Z4JMeta"]
