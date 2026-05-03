"""``export_jobs`` table - async data export requests.

Phase 3 feature. Table created in initial schema so no migration
needed when the feature ships.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin, TimestampsMixin
from z4j_brain.persistence.types import jsonb


class ExportJob(PKMixin, TimestampsMixin, Base):
    """An async data export request (CSV, JSON, XLSX)."""

    __tablename__ = "export_jobs"

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
    export_type: Mapped[str] = mapped_column(String(20), nullable=False)  # tasks, events, audit
    format: Mapped[str] = mapped_column(String(10), nullable=False)  # csv, json, xlsx
    filters: Mapped[dict[str, Any]] = mapped_column(
        jsonb(), nullable=False, default=dict, server_default="{}",
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending", server_default="pending",
    )  # pending, processing, completed, failed
    row_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String, nullable=True)
    error: Mapped[str | None] = mapped_column(String, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )


__all__ = ["ExportJob"]
