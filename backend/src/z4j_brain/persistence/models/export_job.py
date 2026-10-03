"""``export_jobs`` table - background export requests.

The synchronous export on ``GET /projects/{slug}/audit?format=`` refuses
result sets above its in-memory caps. A row here is the same request made
durable: the API queues it, the export-jobs worker streams the rows page by
page into the configured sink (a local directory or an S3-compatible
bucket) and records progress, and the API reports status and the sink
location. The location is a path or an object URL, never a credential.

Status vocabulary: ``queued`` (created, not yet claimed), ``running``
(claimed by a worker; ``row_count`` advances as pages are written),
``done`` (``file_path`` names the object, ``size_bytes`` its length) and
``failed`` (``error`` says why, with nothing secret in it).

The table was created in the initial schema with the request columns;
``sink``, ``size_bytes`` and ``started_at`` arrived with the worker
(``v1_12_export_jobs_sink``).
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
from z4j_brain.persistence.types import big_integer, jsonb

#: ``status`` values, in lifecycle order.
EXPORT_JOB_QUEUED = "queued"
EXPORT_JOB_RUNNING = "running"
EXPORT_JOB_DONE = "done"
EXPORT_JOB_FAILED = "failed"

#: Formats a job may be created with. Mirrors the synchronous export.
EXPORT_JOB_FORMATS = ("csv", "json", "xlsx")


class ExportJob(PKMixin, TimestampsMixin, Base):
    """A background export request (CSV, JSON, XLSX) to a configured sink."""

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
        jsonb(),
        nullable=False,
        default=dict,
        server_default="{}",
    )
    #: See the module docstring for the vocabulary. The server default is
    #: the one the initial schema shipped; every writer sets the value
    #: explicitly, so it never reaches a row.
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=EXPORT_JOB_QUEUED,
        server_default="pending",
    )
    #: Rows written so far while running; the total once done.
    row_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: Where the sink put the object: for the local sink the sink-relative
    #: key (``audit/<slug>/<stamp>-<id>.<format>``), which the download route
    #: rebuilds below the configured base and refuses otherwise; for S3 the
    #: ``s3://bucket/key`` URL. Rows written before the key was stored hold
    #: the absolute path and are still served when it lies below the base.
    #: Never carries a credential.
    file_path: Mapped[str | None] = mapped_column(String, nullable=True)
    error: Mapped[str | None] = mapped_column(String, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    #: The sink kind the job was queued for (``local`` or ``s3``), so a
    #: listing stays meaningful after the operator changes the sink.
    sink: Mapped[str | None] = mapped_column(String(20), nullable=True)
    #: Length of the written object in bytes, set when the job is done.
    size_bytes: Mapped[int | None] = mapped_column(big_integer(), nullable=True)
    #: When a worker claimed the job.
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


__all__ = [
    "EXPORT_JOB_DONE",
    "EXPORT_JOB_FAILED",
    "EXPORT_JOB_FORMATS",
    "EXPORT_JOB_QUEUED",
    "EXPORT_JOB_RUNNING",
    "ExportJob",
]
