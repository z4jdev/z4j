"""``saved_views`` table - user-saved filter/view presets.

Phase 2 feature. Table created in initial schema so no migration
needed when the feature ships.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin
from z4j_brain.persistence.types import jsonb


class SavedView(PKMixin, TimestampsMixin, Base):
    """A saved filter/view preset for a dashboard page."""

    __tablename__ = "saved_views"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    page: Mapped[str] = mapped_column(String(50), nullable=False)  # tasks, workers, etc.
    filters: Mapped[dict[str, Any]] = mapped_column(
        jsonb(), nullable=False, default=dict, server_default="{}",
    )
    is_default: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false",
    )


__all__ = ["SavedView"]
