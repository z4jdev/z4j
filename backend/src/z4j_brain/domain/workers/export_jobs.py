"""``ExportJobsWorker``: background exports and the scheduled chain-head export.

Two jobs share this worker because they share a sink.

Export jobs
-----------
``POST /projects/{slug}/audit/export-jobs`` queues a row in ``export_jobs``.
This worker claims the oldest queued row, pages the same filtered query the
synchronous download runs, encodes each page as it arrives and streams the
bytes into the configured sink (``domain/export_sinks.py``). The whole
result is never in memory, which is what lets a job finish where the
synchronous path refuses. Progress lands on the row after every page, so
the dashboard can show a job moving, and the terminal state carries the
sink location and the object size, or the reason it failed. One audit row
records each completion or failure, written in the same transaction as the
status so the two cannot disagree.

Head export
-----------
``docs/SECURITY.md`` section 10.2 says what the in-database chain cannot
prove on its own, and the documented mitigation is a head exported to a
sink outside the database and checked later with ``z4j audit verify
--known-head``. Until now that needed an operator cron running ``z4j audit
export-head``. With ``Z4J_AUDIT_HEAD_EXPORT_INTERVAL_SECONDS`` set, this
worker writes the identical envelope to the sink on that cadence: a stable
key (``audit-head/current.json``) that a verify job can always read, and a
dated copy beside it, so a bucket with object lock or versioning keeps
every head ever anchored. The envelope is built the way the CLI builds it,
authenticated against the configured keyring first, six keys and nothing
else, because the verifier's parser is a closed allow-list.

No audit row is written for a head export. Writing one would move the
head, and the next export would anchor that row, forever one step behind.

Posture
-------
Leader-gated: N replicas each claiming the same queue would be N uploads
of the same object. The lock is taken in :meth:`tick` rather than by a
wrapper so the two ways acquisition can fail keep their own retry policy,
the same reasoning as ``audit_verifier.py``. Never raises out of ``tick``:
a sink that is down is a fact to report on the job rows and in the log,
not a reason to take the brain down.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import tempfile
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

import structlog
from sqlalchemy import and_, or_, select

from z4j_brain.api._export import (
    JsonArrayEncoder,
    XlsxStreamWriter,
    encode_csv_header,
    encode_csv_rows,
)
from z4j_brain.persistence.models import AuditChainState, AuditLog, Project
from z4j_brain.persistence.models.export_job import ExportJob
from z4j_brain.persistence.repositories.audit_log import AuditLogRepository
from z4j_brain.persistence.repositories.export_jobs import ExportJobRepository

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.domain.export_sinks import ExportSink, SinkWriteResult
    from z4j_brain.domain.workers._leader_lock import SingletonLockLease
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings

logger = structlog.get_logger("z4j.brain.workers.export_jobs")

#: Jobs claimed in one tick before yielding. More queued work asks the
#: supervisor for a prompt wake-up rather than running the loop forever.
MAX_JOBS_PER_TICK = 10

#: A running job whose row has not moved for this long belongs to a
#: process that is gone: progress bumps ``updated_at`` on every page.
STALE_RUNNING_SECONDS = 900

#: Object key of the always-current head envelope in the sink, and the
#: directory the dated copies land in.
HEAD_EXPORT_CURRENT_KEY = "audit-head/current.json"
HEAD_EXPORT_DIRECTORY = "audit-head"

#: Audit actions recorded for job terminal states.
AUDIT_ACTION_EXPORT_DONE = "audit.export_job.completed"
AUDIT_ACTION_EXPORT_FAILED = "audit.export_job.failed"

#: Media types per format, as the synchronous download sends them.
_CONTENT_TYPES = {
    "csv": "text/csv; charset=utf-8",
    "json": "application/json",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}

#: First retry wait after a tick that could not find out whether it leads.
_RETRY_BASE_SECONDS = 15.0
_MAX_RETRY_EXPONENT = 8

#: Bytes read per chunk when streaming a spooled xlsx file into the sink.
_FILE_CHUNK = 1024 * 1024

ProgressCallback = Callable[[int], Awaitable[None]]


class ExportJobsWorker:
    """Drain ``export_jobs`` into the sink; anchor the chain head on a schedule."""

    LEADER_LOCK_NAME: ClassVar[str] = "export_jobs_worker"

    def __init__(
        self,
        *,
        db: DatabaseManager,
        settings: Settings,
        audit: AuditService,
        sink: ExportSink,
    ) -> None:
        self._db = db
        self._settings = settings
        self._audit = audit
        self._sink = sink
        self._consecutive_errors = 0
        self._last_head_export_monotonic: float | None = None
        self._head_export_warned = False

    @property
    def sink(self) -> ExportSink:
        return self._sink

    # ------------------------------------------------------------------
    # Tick
    # ------------------------------------------------------------------

    async def tick(self) -> float | None:
        """Claim leadership, drain the queue, export the head if due.

        Returns seconds until the next run when work is still waiting, or
        None to take the configured interval. Never raises.
        """
        from z4j_brain.domain.workers._leader_lock import try_acquire_singleton_lock

        try:
            lease = await try_acquire_singleton_lock(
                self._db,
                self.LEADER_LOCK_NAME,
                announce=False,
            )
        except Exception:
            logger.exception("z4j export jobs: could not determine whether this replica leads")
            self._consecutive_errors += 1
            return self._retry_delay()
        if lease is None:
            return None
        self._consecutive_errors = 0
        try:
            return await self._work()
        finally:
            await self._release(lease)

    async def _release(self, lease: SingletonLockLease) -> None:
        try:
            held_throughout = await lease.release()
        except Exception:
            logger.exception("z4j export jobs: releasing the leader lock failed")
            return
        if not held_throughout:
            logger.error(
                "z4j export jobs: the leader lock was gone before the tick "
                "finished, so another replica may have been draining the same queue",
            )

    async def _work(self) -> float | None:
        more_waiting = False
        try:
            await self._fail_stale_running()
            more_waiting = await self._drain_jobs()
        except Exception:
            logger.exception("z4j export jobs: draining the queue failed")
        try:
            await self._maybe_export_head()
        except Exception:
            logger.exception("z4j export jobs: the scheduled head export failed")
        return 0.5 if more_waiting else None

    def _retry_delay(self) -> float:
        exponent = min(max(self._consecutive_errors - 1, 0), _MAX_RETRY_EXPONENT)
        interval = float(self._settings.export_jobs_poll_interval_seconds)
        return max(min(_RETRY_BASE_SECONDS * (2.0**exponent), interval), 1.0)

    # ------------------------------------------------------------------
    # Queue
    # ------------------------------------------------------------------

    async def _fail_stale_running(self) -> None:
        idle_before = datetime.now(UTC) - timedelta(seconds=STALE_RUNNING_SECONDS)
        async with self._db.session(write=True) as session:
            repo = ExportJobRepository(session)
            stale = await repo.stale_running(idle_before=idle_before)
            for job in stale:
                logger.error(
                    "z4j export jobs: a running job made no progress; marking it failed",
                    job_id=str(job.id),
                    idle_seconds=STALE_RUNNING_SECONDS,
                )
                await repo.mark_failed(
                    job.id,
                    reason=(
                        f"no progress for {STALE_RUNNING_SECONDS} seconds; the "
                        "brain that was running this export is gone. Queue it again."
                    ),
                )
                await self._record_audit(
                    session,
                    job,
                    action=AUDIT_ACTION_EXPORT_FAILED,
                    result="failed",
                    metadata={"reason": "stale"},
                )
            await session.commit()

    async def _drain_jobs(self) -> bool:
        """Run queued jobs oldest first; True when more are still waiting."""
        for _ in range(MAX_JOBS_PER_TICK):
            async with self._db.session() as session:
                job = await ExportJobRepository(session).next_queued()
                if job is None:
                    return False
                session.expunge(job)
            await self._run_job(job)
        async with self._db.session() as session:
            return await ExportJobRepository(session).next_queued() is not None

    async def _run_job(self, job: ExportJob) -> None:
        async with self._db.session(write=True) as session:
            claimed = await ExportJobRepository(session).claim(job.id)
            await session.commit()
        if not claimed:
            return
        logger.info(
            "z4j export jobs: started",
            job_id=str(job.id),
            format=job.format,
            sink=self._sink.kind,
        )
        rows_written = 0

        async def progress(count: int) -> None:
            nonlocal rows_written
            rows_written = count
            async with self._db.session(write=True) as session:
                await ExportJobRepository(session).record_progress(job.id, rows_written=count)
                await session.commit()

        try:
            slug = await self._project_slug(job.project_id)
            key = self._object_key(job, slug)
            result = await self._sink.write(
                key,
                self._chunks(job, progress),
                content_type=_CONTENT_TYPES[job.format],
            )
        except Exception as exc:
            reason = _safe_reason(exc)
            logger.exception(
                "z4j export jobs: failed",
                job_id=str(job.id),
                rows_written=rows_written,
            )
            await self._finish(job, failed=reason, rows_written=rows_written)
            return
        logger.info(
            "z4j export jobs: done",
            job_id=str(job.id),
            rows=rows_written,
            size_bytes=result.size_bytes,
            location=result.location,
        )
        await self._finish(
            job,
            rows_written=rows_written,
            size_bytes=result.size_bytes,
            location=result.location,
            stored_location=self._stored_location(result),
            key=result.key,
        )

    def _stored_location(self, result: SinkWriteResult) -> str:
        """What the job row records: the key for the local sink, else the location.

        The download route rebuilds a local path from the configured base
        and refuses anything that is not a plain key below it, so the row
        never carries a path it could be made to point elsewhere.
        """
        from z4j_brain.domain.export_sinks import LocalDirectorySink

        if self._sink.kind == LocalDirectorySink.kind:
            return result.key
        return result.location

    async def _finish(
        self,
        job: ExportJob,
        *,
        rows_written: int,
        size_bytes: int | None = None,
        location: str | None = None,
        stored_location: str | None = None,
        key: str | None = None,
        failed: str | None = None,
    ) -> None:
        """Record the terminal state, and only if the job was still ours.

        Both transitions are compare-and-set on ``running``. Losing one means
        another leader's stale sweep already marked the job failed while this
        process was writing (the lock was lost mid-tick, which the lease
        reports loudly but cannot prevent). Then the terminal state it
        recorded stands: no completion row is appended on top of a failure,
        and the object just written is discarded rather than left as an
        orphan no row refers to.
        """
        async with self._db.session(write=True) as session:
            repo = ExportJobRepository(session)
            if failed is None:
                recorded = await repo.mark_done(
                    job.id,
                    rows_written=rows_written,
                    size_bytes=int(size_bytes or 0),
                    location=str(stored_location if stored_location is not None else location),
                )
                if recorded:
                    await self._record_audit(
                        session,
                        job,
                        action=AUDIT_ACTION_EXPORT_DONE,
                        result="success",
                        metadata={
                            "rows": rows_written,
                            "size_bytes": int(size_bytes or 0),
                            "location": str(location),
                        },
                    )
            else:
                recorded = await repo.mark_failed(job.id, reason=failed)
                if recorded:
                    await self._record_audit(
                        session,
                        job,
                        action=AUDIT_ACTION_EXPORT_FAILED,
                        result="failed",
                        metadata={"rows_written": rows_written, "error": failed[:500]},
                    )
            if recorded:
                await session.commit()
                return
            await session.rollback()
        if failed is None:
            logger.error(
                "z4j export jobs: the job was no longer running when its export "
                "ended, so another replica had already marked it failed; its "
                "terminal state stands, nothing is appended to the audit trail, "
                "and the object written here is discarded",
                job_id=str(job.id),
                outcome="done",
                location=location,
            )
        else:
            # The write raised, so the sink retained nothing (the local sink
            # writes through a temporary file, the S3 sink aborts its upload);
            # there is no object to discard.
            logger.error(
                "z4j export jobs: the job was no longer running when its export "
                "failed, so another replica had already marked it failed; its "
                "terminal state stands, nothing is appended to the audit trail, "
                "and nothing was retained here since the write raised before "
                "any object was stored",
                job_id=str(job.id),
                outcome="failed",
                location=location,
            )
        if failed is None and key is not None:
            try:
                await self._sink.discard(key)
            except Exception:
                logger.exception(
                    "z4j export jobs: could not discard the orphaned export",
                    job_id=str(job.id),
                    key=key,
                )

    async def _record_audit(
        self,
        session: AsyncSession,
        job: ExportJob,
        *,
        action: str,
        result: str,
        metadata: dict[str, Any],
    ) -> None:
        await self._audit.record(
            AuditLogRepository(session),
            action=action,
            target_type="export_job",
            target_id=str(job.id),
            result=result,
            user_id=job.user_id,
            project_id=job.project_id,
            metadata={
                "export_type": job.export_type,
                "format": job.format,
                "sink": self._sink.kind,
                **metadata,
            },
        )

    async def _project_slug(self, project_id: uuid.UUID) -> str:
        async with self._db.session() as session:
            slug = (
                await session.execute(select(Project.slug).where(Project.id == project_id))
            ).scalar_one_or_none()
        if slug is None:
            raise RuntimeError("the job's project no longer exists")
        return str(slug)

    @staticmethod
    def _object_key(job: ExportJob, slug: str) -> str:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        return f"{job.export_type}/{slug}/{stamp}-{job.id}.{job.format}"

    # ------------------------------------------------------------------
    # Streaming
    # ------------------------------------------------------------------

    async def _row_pages(self, job: ExportJob) -> AsyncIterator[list[AuditLog]]:
        """Keyset-page the job's filter newest first, one page at a time."""
        from z4j_brain.api.audit import build_audit_export_statement

        filters = dict(job.filters or {})
        user_id = filters.get("user_id")
        since = filters.get("since")
        base = build_audit_export_statement(
            job.project_id,
            action_prefix=filters.get("action_prefix") or None,
            outcome=filters.get("outcome") or None,
            user_id=uuid.UUID(str(user_id)) if user_id else None,
            since=datetime.fromisoformat(str(since)) if since else None,
        )
        page_size = int(self._settings.export_jobs_page_size)
        cursor: tuple[datetime, uuid.UUID] | None = None
        async with self._db.session() as session:
            while True:
                stmt = base
                if cursor is not None:
                    sort_value, tiebreaker = cursor
                    stmt = stmt.where(
                        or_(
                            AuditLog.occurred_at < sort_value,
                            and_(
                                AuditLog.occurred_at == sort_value,
                                AuditLog.id < tiebreaker,
                            ),
                        ),
                    )
                stmt = stmt.order_by(
                    AuditLog.occurred_at.desc(),
                    AuditLog.id.desc(),
                ).limit(page_size)
                rows = list((await session.execute(stmt)).scalars().all())
                if not rows:
                    return
                yield rows
                last = rows[-1]
                cursor = (last.occurred_at, last.id)
                # Detach the page and end the read transaction: keyset
                # paging needs no snapshot across pages, and an open read
                # transaction on SQLite would hold the shared lock the
                # progress write between pages has to get past.
                session.expunge_all()
                await session.rollback()
                if len(rows) < page_size:
                    return

    async def _chunks(self, job: ExportJob, progress: ProgressCallback) -> AsyncIterator[bytes]:
        from z4j_brain.api.audit import resolve_audit_export_fields

        selected = job.filters.get("fields") if job.filters else None
        field_defs = resolve_audit_export_fields(list(selected) if selected else None)
        written = 0
        if job.format == "csv":
            yield encode_csv_header(field_defs)
            async for page in self._row_pages(job):
                yield encode_csv_rows(page, field_defs)
                written += len(page)
                await progress(written)
            return
        if job.format == "json":
            encoder = JsonArrayEncoder(field_defs)
            yield encoder.start()
            async for page in self._row_pages(job):
                yield encoder.rows(page)
                written += len(page)
                await progress(written)
            yield encoder.finish()
            return
        if job.format != "xlsx":
            raise RuntimeError(f"unknown export format {job.format!r}")
        async for chunk in self._xlsx_chunks(job, field_defs, progress):
            yield chunk

    async def _xlsx_chunks(
        self,
        job: ExportJob,
        field_defs: list[Any],
        progress: ProgressCallback,
    ) -> AsyncIterator[bytes]:
        """Spool the workbook to a private temporary file, then stream it."""
        handle, raw_path = tempfile.mkstemp(prefix="z4j-export-", suffix=".xlsx")
        os.close(handle)
        spool = Path(raw_path)
        try:
            writer = XlsxStreamWriter(str(spool), field_defs, "Audit")
            try:
                written = 0
                async for page in self._row_pages(job):
                    written = await asyncio.to_thread(writer.write_rows, page)
                    await progress(written)
            finally:
                await asyncio.to_thread(writer.close)
            stream = await asyncio.to_thread(spool.open, "rb")
            try:
                while True:
                    chunk = await asyncio.to_thread(stream.read, _FILE_CHUNK)
                    if not chunk:
                        break
                    yield chunk
            finally:
                await asyncio.to_thread(stream.close)
        finally:
            with contextlib.suppress(OSError):
                await asyncio.to_thread(spool.unlink)

    # ------------------------------------------------------------------
    # Head export
    # ------------------------------------------------------------------

    def head_export_due(self) -> bool:
        interval = int(self._settings.audit_head_export_interval_seconds)
        if interval <= 0:
            return False
        if self._last_head_export_monotonic is None:
            return True
        return (time.monotonic() - self._last_head_export_monotonic) >= interval

    async def _maybe_export_head(self) -> None:
        if not self.head_export_due():
            return
        await self.export_head_now()

    async def export_head_now(self) -> str | None:
        """Write the current authenticated head to the sink; return its location.

        Returns None when there is no head to export or it does not
        authenticate; both are logged. The cadence clock advances either
        way, so a chain with a problem is reported once per interval, not
        once per poll.
        """
        self._last_head_export_monotonic = time.monotonic()
        if self._settings.audit_chain_secret is None:
            if not self._head_export_warned:
                logger.warning(
                    "z4j export jobs: Z4J_AUDIT_HEAD_EXPORT_INTERVAL_SECONDS is set "
                    "but no audit-chain key is configured, so there is no "
                    "authenticated head to export",
                )
                self._head_export_warned = True
            return None
        async with self._db.session() as session:
            envelope = await build_audit_head_envelope(session, self._settings)
        if envelope is None:
            return None
        payload = encode_audit_head_envelope(envelope)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        current = await self._sink.write(
            HEAD_EXPORT_CURRENT_KEY,
            _one_chunk(payload),
            content_type="application/json",
        )
        dated = await self._sink.write(
            f"{HEAD_EXPORT_DIRECTORY}/{stamp}.json",
            _one_chunk(payload),
            content_type="application/json",
        )
        logger.info(
            "z4j export jobs: audit chain head exported",
            current=current.location,
            dated=dated.location,
            head_id=envelope["id"],
        )
        return current.location


# ---------------------------------------------------------------------------
# Head envelope, byte for byte what ``z4j audit export-head`` prints
# ---------------------------------------------------------------------------


async def build_audit_head_envelope(
    session: AsyncSession,
    settings: Settings,
) -> dict[str, Any] | None:
    """The six-key known-head envelope for the current authenticated head.

    Mirrors ``cli.py``'s ``_run_audit_export_head``: a plain read of the
    singleton state row (never ``FOR UPDATE``), authentication against the
    whole keyring, and refusal (None, logged) rather than an unproven head.
    """
    from z4j_brain.domain.audit_chain import (
        AUDIT_ROW_HMAC_VERSION,
        AuditChainIntegrityError,
        authenticate_state,
        canonical_audit_key_id,
        normalize_timestamp,
    )
    from z4j_brain.persistence.models.audit_chain import AUDIT_CHAIN_SINGLETON_ID

    rows = list(
        (
            await session.execute(
                select(AuditChainState).where(
                    AuditChainState.singleton_id == AUDIT_CHAIN_SINGLETON_ID,
                ),
            )
        ).scalars(),
    )
    if len(rows) != 1:
        logger.error(
            "z4j export jobs: audit_chain_state holds an unexpected number of rows",
            rows=len(rows),
        )
        return None
    state = rows[0]
    keyring = {
        canonical_audit_key_id(secret): secret
        for secret in settings.all_audit_chain_secrets_for_verification()
    }
    authenticated = True
    try:
        authenticate_state(state, keyring)
    except AuditChainIntegrityError:
        authenticated = False
    if not authenticated:
        logger.error(
            "z4j export jobs: the audit chain state does not authenticate "
            "against the configured keys, so its head was not exported",
        )
        return None
    if state.head_row_hmac is None or state.head_id is None:
        logger.info("z4j export jobs: the audit chain has no head yet; nothing to anchor")
        return None
    envelope: dict[str, Any] = {
        "row_hmac": state.head_row_hmac,
        "hmac_version": AUDIT_ROW_HMAC_VERSION,
        "generation": str(state.generation).lower(),
        "id": str(state.head_id).lower(),
    }
    if state.head_hmac_key_id is not None:
        envelope["hmac_key_id"] = state.head_hmac_key_id
    if state.head_occurred_at is not None:
        envelope["occurred_at"] = (
            normalize_timestamp(state.head_occurred_at)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
    return envelope


def encode_audit_head_envelope(envelope: dict[str, Any]) -> bytes:
    """Canonical JSON plus a newline: the bytes ``export-head --output`` writes."""
    from z4j_brain.domain.audit_chain import canonical_json

    return canonical_json(envelope) + b"\n"


async def _one_chunk(payload: bytes) -> AsyncIterator[bytes]:
    yield payload


#: Exception modules whose messages carry the endpoint URL (userinfo
#: included), the access key id, request parameters or the response
#: body. Their classes map to a fixed phrase and their text never lands
#: on the row.
_LIBRARY_MODULES: tuple[str, ...] = ("botocore.", "aiobotocore.", "boto3.", "aiohttp.")
_LIBRARY_PHRASES: dict[str, str] = {
    # botocore
    "EndpointConnectionError": "endpoint unreachable",
    "ConnectTimeoutError": "endpoint unreachable",
    "ReadTimeoutError": "endpoint unreachable",
    "ConnectionClosedError": "endpoint unreachable",
    "ProxyConnectionError": "endpoint unreachable",
    "SSLError": "endpoint unreachable",
    "InvalidEndpointConfigurationError": "endpoint unreachable",
    "NoCredentialsError": "access denied",
    "PartialCredentialsError": "access denied",
    "CredentialRetrievalError": "access denied",
    "NoSuchBucket": "bucket missing",
    # aiohttp
    "ClientConnectorError": "endpoint unreachable",
    "ClientConnectorDNSError": "endpoint unreachable",
    "ClientConnectorCertificateError": "endpoint unreachable",
    "ClientConnectorSSLError": "endpoint unreachable",
    "ClientProxyConnectionError": "endpoint unreachable",
    "ClientOSError": "endpoint unreachable",
    "ServerDisconnectedError": "endpoint unreachable",
    "ServerTimeoutError": "endpoint unreachable",
    "ClientSSLError": "endpoint unreachable",
    "InvalidURL": "endpoint unreachable",
    "ClientPayloadError": "upload aborted",
}
_ACCESS_DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "AllAccessDisabled",
        "InvalidAccessKeyId",
        "SignatureDoesNotMatch",
        "InvalidToken",
        "ExpiredToken",
        "403",
    }
)
_BUCKET_MISSING_CODES = frozenset({"NoSuchBucket", "404"})
_UPLOAD_ABORTED_CODES = frozenset(
    {"NoSuchUpload", "InvalidPart", "InvalidPartOrder", "EntityTooSmall", "IncompleteBody"}
)
#: ``user:password@`` right after a URL scheme, anywhere in a message.
_URL_USERINFO = re.compile(r"(?<=://)[^/?#@\s]*@")


def _safe_reason(exc: BaseException) -> str:
    """The reason a job records: a fixed phrase for a library failure.

    The reason lands on the job row, in the ``audit.export_job.failed``
    metadata and from there in every audit export, the forwarder payload
    and the backups. The class name alone is kept for our own exceptions
    and the stdlib; their text passes with any URL userinfo stripped.
    """
    name = type(exc).__name__
    if _connection_refused(exc):
        return "connection refused"
    module = type(exc).__module__ or ""
    if module.startswith(_LIBRARY_MODULES):
        return _library_phrase(exc, name)
    text = _URL_USERINFO.sub("", str(exc).strip())
    return f"{name}: {text}" if text else name


def _connection_refused(exc: BaseException) -> bool:
    """True when a ``ConnectionRefusedError`` sits at or under ``exc``."""
    seen: set[int] = set()
    queue: list[BaseException | None] = [exc]
    while queue:
        current = queue.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, ConnectionRefusedError):
            return True
        queue.append(current.__cause__)
        queue.append(current.__context__)
        nested = getattr(current, "os_error", None)
        if isinstance(nested, BaseException):
            queue.append(nested)
        kwargs = getattr(current, "kwargs", None)
        if isinstance(kwargs, dict) and isinstance(kwargs.get("error"), BaseException):
            queue.append(kwargs["error"])
    return False


def _library_phrase(exc: BaseException, name: str) -> str:
    phrase = _LIBRARY_PHRASES.get(name)
    if phrase is not None:
        return phrase
    code = _error_code(exc)
    if code in _ACCESS_DENIED_CODES:
        return "access denied"
    if code in _BUCKET_MISSING_CODES:
        return "bucket missing"
    if code in _UPLOAD_ABORTED_CODES:
        return "upload aborted"
    return f"unknown error ({name})"


def _error_code(exc: BaseException) -> str:
    """The service error code of a botocore ``ClientError``, else empty."""
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return ""
    error = response.get("Error")
    if not isinstance(error, dict):
        return ""
    code = error.get("Code")
    return code if isinstance(code, str) else ""


__all__ = [
    "AUDIT_ACTION_EXPORT_DONE",
    "AUDIT_ACTION_EXPORT_FAILED",
    "HEAD_EXPORT_CURRENT_KEY",
    "HEAD_EXPORT_DIRECTORY",
    "MAX_JOBS_PER_TICK",
    "STALE_RUNNING_SECONDS",
    "ExportJobsWorker",
    "build_audit_head_envelope",
    "encode_audit_head_envelope",
]
