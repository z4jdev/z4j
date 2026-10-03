"""Repository for ``export_jobs``.

Every state change a job goes through is one method here, and each of the
transition methods is a conditional ``UPDATE`` keyed on the state it leaves
from: a claim that finds the row no longer queued, or a completion that
finds it no longer running, reports ``False`` instead of overwriting what
another writer recorded. The worker is leader-gated, so the race this
guards is a leader lock lost mid-tick (connection death), which the lock
helper reports loudly but cannot prevent.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models.export_job import (
    EXPORT_JOB_DONE,
    EXPORT_JOB_FAILED,
    EXPORT_JOB_QUEUED,
    EXPORT_JOB_RUNNING,
    ExportJob,
)
from z4j_brain.persistence.repositories._base import BaseRepository

#: Upper bound on ``error`` text. Long enough for an exception message, short
#: enough that a stack trace or a request body can never land in the row.
_ERROR_TEXT_LIMIT = 500


def _now() -> datetime:
    return datetime.now(UTC)


def _affected(result: Any) -> int:
    """Rows an UPDATE touched; the DBAPI reports it on the cursor result."""
    return int(getattr(result, "rowcount", 0) or 0)


class ExportJobRepository(BaseRepository[ExportJob]):
    """CRUD and state transitions for background export jobs."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, ExportJob)

    async def create(
        self,
        *,
        user_id: uuid.UUID,
        project_id: uuid.UUID,
        export_type: str,
        export_format: str,
        filters: dict[str, Any],
        sink: str,
    ) -> ExportJob:
        """Queue one job. Does not commit."""
        job = ExportJob(
            user_id=user_id,
            project_id=project_id,
            export_type=export_type,
            format=export_format,
            filters=dict(filters),
            status=EXPORT_JOB_QUEUED,
            sink=sink,
        )
        return await self.add(job)

    async def get_for_project(
        self,
        job_id: uuid.UUID,
        *,
        project_id: uuid.UUID,
    ) -> ExportJob | None:
        """Return the job only when it belongs to ``project_id``."""
        stmt = select(ExportJob).where(
            ExportJob.id == job_id,
            ExportJob.project_id == project_id,
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def list_for_project(
        self,
        project_id: uuid.UUID,
        *,
        limit: int,
    ) -> list[ExportJob]:
        """Newest jobs first for one project."""
        stmt = (
            select(ExportJob)
            .where(ExportJob.project_id == project_id)
            .order_by(ExportJob.created_at.desc(), ExportJob.id.desc())
            .limit(limit)
        )
        return list((await self._session.execute(stmt)).scalars().all())

    async def count_pending_for_project(self, project_id: uuid.UUID) -> int:
        """Jobs queued or running for one project."""
        from sqlalchemy import func

        stmt = (
            select(func.count())
            .select_from(ExportJob)
            .where(
                ExportJob.project_id == project_id,
                ExportJob.status.in_((EXPORT_JOB_QUEUED, EXPORT_JOB_RUNNING)),
            )
        )
        return int((await self._session.execute(stmt)).scalar_one())

    async def next_queued(self) -> ExportJob | None:
        """The oldest queued job across every project, or None."""
        stmt = (
            select(ExportJob)
            .where(ExportJob.status == EXPORT_JOB_QUEUED)
            .order_by(ExportJob.created_at.asc(), ExportJob.id.asc())
            .limit(1)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def claim(self, job_id: uuid.UUID) -> bool:
        """Move ``queued`` to ``running``. False when it was no longer queued."""
        stmt = (
            update(ExportJob)
            .where(ExportJob.id == job_id, ExportJob.status == EXPORT_JOB_QUEUED)
            .values(status=EXPORT_JOB_RUNNING, started_at=_now(), row_count=0, error=None)
        )
        return _affected(await self._session.execute(stmt)) == 1

    async def record_progress(self, job_id: uuid.UUID, *, rows_written: int) -> bool:
        """Advance ``row_count`` on a running job."""
        stmt = (
            update(ExportJob)
            .where(ExportJob.id == job_id, ExportJob.status == EXPORT_JOB_RUNNING)
            .values(row_count=rows_written, updated_at=_now())
        )
        return _affected(await self._session.execute(stmt)) == 1

    async def mark_done(
        self,
        job_id: uuid.UUID,
        *,
        rows_written: int,
        size_bytes: int,
        location: str,
    ) -> bool:
        """Move ``running`` to ``done`` with the sink's answer."""
        stmt = (
            update(ExportJob)
            .where(ExportJob.id == job_id, ExportJob.status == EXPORT_JOB_RUNNING)
            .values(
                status=EXPORT_JOB_DONE,
                row_count=rows_written,
                size_bytes=size_bytes,
                file_path=location,
                error=None,
                completed_at=_now(),
            )
        )
        return _affected(await self._session.execute(stmt)) == 1

    async def mark_failed(self, job_id: uuid.UUID, *, reason: str) -> bool:
        """Move ``queued`` or ``running`` to ``failed`` with a bounded reason."""
        stmt = (
            update(ExportJob)
            .where(
                ExportJob.id == job_id,
                ExportJob.status.in_((EXPORT_JOB_QUEUED, EXPORT_JOB_RUNNING)),
            )
            .values(
                status=EXPORT_JOB_FAILED,
                error=reason[:_ERROR_TEXT_LIMIT],
                completed_at=_now(),
            )
        )
        return _affected(await self._session.execute(stmt)) == 1

    async def stale_running(self, *, idle_before: datetime) -> list[ExportJob]:
        """Running jobs whose last progress write is older than ``idle_before``.

        Progress bumps ``updated_at`` on every page, so a running row that
        has not moved for a long time belongs to a worker that is gone.
        """
        stmt = select(ExportJob).where(
            ExportJob.status == EXPORT_JOB_RUNNING,
            ExportJob.updated_at < idle_before,
        )
        return list((await self._session.execute(stmt)).scalars().all())


__all__ = ["ExportJobRepository"]
