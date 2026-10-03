"""``/api/v1/projects/{slug}/audit/export-jobs`` REST router.

Background exports of the audit log. The synchronous download on
``GET /projects/{slug}/audit?format=`` refuses result sets above its
in-memory caps; a job here takes the same filters, is written to the
configured sink by the export-jobs worker page by page, and can be any
size. The router creates rows and reports on them. It never writes to a
sink itself, and the only bytes it serves are a finished local-sink file
to a member holding the audit tier (auditor or admin).

Authorization mirrors the synchronous export: every route is gated on
``Action.EXPORT_AUDIT``, which the auditor and the admin hold. For API
keys the tag maps to ``audit:read`` on every method,
because queueing an export reveals exactly what the synchronous GET
reveals and nothing more (``auth/scopes.py``).

Every response names the sink by location, never by credential: a path
for the local sink, an ``s3://`` URL for S3.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import datetime
from typing import TYPE_CHECKING, Any, BinaryIO, Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from z4j_brain.api.deps import (
    get_audit_log_repo,
    get_audit_service,
    get_client_ip,
    get_current_user,
    get_membership_repo,
    get_project_repo,
    get_session,
    require_csrf,
    resolve_api_key_id,
)
from z4j_brain.domain.policy_engine import Action
from z4j_brain.errors import ConflictError, NotFoundError, ValidationError
from z4j_brain.persistence.models.export_job import (
    EXPORT_JOB_DONE,
    EXPORT_JOB_FORMATS,
    ExportJob,
)
from z4j_brain.persistence.repositories.export_jobs import ExportJobRepository

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.domain.export_sinks import ExportSink
    from z4j_brain.persistence.models import Project, User
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        MembershipRepository,
        ProjectRepository,
    )


router = APIRouter(
    prefix="/projects/{slug}/audit/export-jobs",
    tags=["audit-exports"],
)

#: The only export type this router queues today.
EXPORT_TYPE_AUDIT = "audit"

#: Audit action recorded when a job is queued.
AUDIT_ACTION_EXPORT_CREATED = "audit.export_job.created"

#: Media types for the download route, by format.
_DOWNLOAD_MEDIA_TYPES = {
    "csv": "text/csv",
    "json": "application/json",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}

#: Bytes read per chunk when streaming a finished export back to a caller.
_DOWNLOAD_CHUNK = 256 * 1024


def get_export_sink(request: Request) -> ExportSink | None:
    """The configured sink, or None when ``Z4J_EXPORT_SINK`` is ``none``."""
    sink: ExportSink | None = getattr(request.app.state, "export_sink", None)
    return sink


class ExportJobCreate(BaseModel):
    """Queue one background export of the audit log.

    The filters are the synchronous export's. ``fields`` selects columns
    by name; an unknown name is a ``422`` here rather than silently
    dropped, because a job runs later and out of sight.
    """

    format: Literal["csv", "json", "xlsx"]
    action_prefix: str | None = Field(default=None, max_length=80)
    outcome: str | None = Field(default=None, max_length=20)
    user_id: uuid.UUID | None = None
    since: datetime | None = None
    fields: list[str] | None = Field(default=None, max_length=20)


class ExportJobPublic(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    user_id: uuid.UUID
    export_type: str
    format: str
    filters: dict[str, Any]
    #: ``queued``, ``running``, ``done`` or ``failed``.
    status: str
    #: Rows written so far while running; the total once done.
    row_count: int | None
    size_bytes: int | None
    #: Sink kind the job was queued for: ``local`` or ``s3``.
    sink: str | None
    #: Where the object is: a path (local) or an ``s3://`` URL. Never a credential.
    location: str | None
    error: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    #: True when ``GET .../download`` will serve this job's file.
    downloadable: bool


class ExportJobListResponse(BaseModel):
    items: list[ExportJobPublic]
    #: Sink kind in effect for new jobs, or null when none is configured.
    sink: str | None
    #: Operator-facing description of the sink: a directory or a bucket URL.
    sink_location: str | None


def _public(job: ExportJob, sink: ExportSink | None) -> ExportJobPublic:
    from z4j_brain.domain.export_sinks import LocalDirectorySink

    downloadable = (
        sink is not None
        and sink.downloadable
        and job.status == EXPORT_JOB_DONE
        and job.sink == sink.kind
        and job.file_path is not None
    )
    # A local job row stores the sink-relative key; the path an operator
    # sees is rebuilt from the base in effect (``export_sinks.py``).
    location = job.file_path
    if location is not None and isinstance(sink, LocalDirectorySink) and job.sink == sink.kind:
        location = sink.display_location(location)
    return ExportJobPublic(
        id=job.id,
        project_id=job.project_id,
        user_id=job.user_id,
        export_type=job.export_type,
        format=job.format,
        filters=dict(job.filters or {}),
        status=job.status,
        row_count=job.row_count,
        size_bytes=job.size_bytes,
        sink=job.sink,
        location=location,
        error=job.error,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        downloadable=downloadable,
    )


async def _authorize_export(
    *,
    slug: str,
    user: User,
    memberships: MembershipRepository,
    projects: ProjectRepository,
) -> Project:
    """The audit tier (auditor or admin).

    A background export reveals exactly what the synchronous ``?format=``
    export reveals, so it carries the same action. Operators and viewers are
    refused; non-members see the 404.
    """
    from z4j_brain.domain.policy_engine import PolicyEngine

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project=project,
        action=Action.EXPORT_AUDIT,
    )
    return project


def _location(slug: str, job_id: uuid.UUID) -> str:
    return f"/api/v1/projects/{slug}/audit/export-jobs/{job_id}"


def _filters_for_storage(body: ExportJobCreate) -> dict[str, Any]:
    """The filters as the worker reads them back: JSON-native, no nulls."""
    from z4j_brain.api.audit import AUDIT_EXPORT_FIELD_NAMES

    filters: dict[str, Any] = {}
    if body.action_prefix:
        filters["action_prefix"] = body.action_prefix
    if body.outcome:
        filters["outcome"] = body.outcome
    if body.user_id is not None:
        filters["user_id"] = str(body.user_id)
    if body.since is not None:
        filters["since"] = body.since.isoformat()
    if body.fields:
        unknown = [name for name in body.fields if name not in AUDIT_EXPORT_FIELD_NAMES]
        if unknown:
            raise ValidationError(
                "unknown export field names",
                details={"unknown": unknown, "known": list(AUDIT_EXPORT_FIELD_NAMES)},
            )
        filters["fields"] = list(dict.fromkeys(body.fields))
    return filters


@router.post(
    "",
    response_model=ExportJobPublic,
    status_code=202,
    dependencies=[Depends(require_csrf)],
)
async def create_export_job(
    slug: str,
    body: ExportJobCreate,
    request: Request,
    response: Response,
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    audit_log: AuditLogRepository = Depends(get_audit_log_repo),
    audit_service: AuditService = Depends(get_audit_service),
    db_session: AsyncSession = Depends(get_session),
    sink: ExportSink | None = Depends(get_export_sink),
    ip: str = Depends(get_client_ip),
) -> ExportJobPublic:
    """Queue a background export of this project's audit log.

    Requires ``Action.EXPORT_AUDIT`` on the project (auditor or admin), the
    same as the synchronous export.
    Answers ``409`` when no export sink is configured
    (``Z4J_EXPORT_SINK``), ``422`` for an unknown field name. The job
    starts ``queued``; poll ``GET .../export-jobs/{id}`` for progress.
    """
    project = await _authorize_export(
        slug=slug,
        user=user,
        memberships=memberships,
        projects=projects,
    )
    if sink is None:
        raise ConflictError(
            "no export sink is configured; set Z4J_EXPORT_SINK to local or s3",
            details={"setting": "Z4J_EXPORT_SINK"},
        )
    if body.format not in EXPORT_JOB_FORMATS:  # pragma: no cover - Literal-validated
        raise ValidationError("unsupported export format", details={"format": body.format})
    filters = _filters_for_storage(body)

    repo = ExportJobRepository(db_session)
    job = await repo.create(
        user_id=user.id,
        project_id=project.id,
        export_type=EXPORT_TYPE_AUDIT,
        export_format=body.format,
        filters=filters,
        sink=sink.kind,
    )
    await audit_service.record(
        audit_log,
        action=AUDIT_ACTION_EXPORT_CREATED,
        target_type="export_job",
        target_id=str(job.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project.id,
        api_key_id=resolve_api_key_id(request),
        source_ip=ip,
        user_agent=request.headers.get("user-agent"),
        metadata={
            "export_type": EXPORT_TYPE_AUDIT,
            "format": body.format,
            "sink": sink.kind,
            "filters": filters,
        },
    )
    await db_session.commit()
    response.headers["Location"] = _location(slug, job.id)
    return _public(job, sink)


@router.get("", response_model=ExportJobListResponse)
async def list_export_jobs(
    slug: str,
    limit: int = Query(default=50, ge=1, le=200),
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    db_session: AsyncSession = Depends(get_session),
    sink: ExportSink | None = Depends(get_export_sink),
) -> ExportJobListResponse:
    """Newest export jobs for this project, with the sink in effect."""
    project = await _authorize_export(
        slug=slug,
        user=user,
        memberships=memberships,
        projects=projects,
    )
    jobs = await ExportJobRepository(db_session).list_for_project(project.id, limit=limit)
    return ExportJobListResponse(
        items=[_public(job, sink) for job in jobs],
        sink=sink.kind if sink is not None else None,
        sink_location=sink.describe() if sink is not None else None,
    )


@router.get("/{job_id}", response_model=ExportJobPublic)
async def get_export_job(
    slug: str,
    job_id: uuid.UUID,
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    db_session: AsyncSession = Depends(get_session),
    sink: ExportSink | None = Depends(get_export_sink),
) -> ExportJobPublic:
    """One job: status, progress, sink location, or the failure reason."""
    project = await _authorize_export(
        slug=slug,
        user=user,
        memberships=memberships,
        projects=projects,
    )
    job = await ExportJobRepository(db_session).get_for_project(job_id, project_id=project.id)
    if job is None:
        raise NotFoundError("export job not found", details={"id": str(job_id)})
    return _public(job, sink)


@router.get("/{job_id}/download")
async def download_export_job(
    slug: str,
    job_id: uuid.UUID,
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    db_session: AsyncSession = Depends(get_session),
    sink: ExportSink | None = Depends(get_export_sink),
) -> Any:
    """Stream a finished local-sink export to an auditor or an admin.

    ``409`` when the job is not done or its sink is not the local
    directory sink; an S3 object is fetched from the bucket at the
    job's ``location`` with the operator's own credentials. ``404`` when
    the row's location does not name a regular file below the configured
    directory: the row is not trusted to name the file, the sink is
    (``LocalDirectorySink.open_download``), and what is served is the
    handle the sink opened.
    """
    from z4j_brain.domain.export_sinks import ExportSinkError, LocalDirectorySink

    project = await _authorize_export(
        slug=slug,
        user=user,
        memberships=memberships,
        projects=projects,
    )
    job = await ExportJobRepository(db_session).get_for_project(job_id, project_id=project.id)
    if job is None:
        raise NotFoundError("export job not found", details={"id": str(job_id)})
    if job.status != EXPORT_JOB_DONE or job.file_path is None:
        raise ConflictError(
            "export job has no file to download yet",
            details={"status": job.status},
        )
    if not isinstance(sink, LocalDirectorySink) or job.sink != sink.kind:
        raise ConflictError(
            "download is served for the local sink only; fetch the object at the job's location",
            details={"sink": job.sink, "location": job.file_path},
        )
    try:
        opened = await asyncio.to_thread(sink.open_download, job.file_path)
    except ExportSinkError as exc:
        raise NotFoundError(str(exc), details={"id": str(job_id)}) from exc
    filename = f"z4j-audit-{slug}-{job.id}.{job.format}"
    quoted = quote(filename)
    disposition = (
        f'attachment; filename="{filename}"'
        if quoted == filename
        else f"attachment; filename*=utf-8''{quoted}"
    )
    return StreamingResponse(
        _stream_then_close(opened.file),
        media_type=_DOWNLOAD_MEDIA_TYPES.get(job.format, "application/octet-stream"),
        headers={
            "content-disposition": disposition,
            "content-length": str(opened.size_bytes),
        },
    )


async def _stream_then_close(handle: BinaryIO) -> AsyncIterator[bytes]:
    """Yield the opened export in chunks and close it however the stream ends."""
    try:
        while True:
            chunk = await asyncio.to_thread(handle.read, _DOWNLOAD_CHUNK)
            if not chunk:
                return
            yield chunk
    finally:
        handle.close()


__all__ = [
    "AUDIT_ACTION_EXPORT_CREATED",
    "EXPORT_TYPE_AUDIT",
    "ExportJobCreate",
    "ExportJobListResponse",
    "ExportJobPublic",
    "get_export_sink",
    "router",
]
