"""Where background exports go.

A sink takes a key and a stream of byte chunks and puts the object
somewhere an operator can fetch it from. Two are shipped:

* :class:`LocalDirectorySink` (``Z4J_EXPORT_SINK=local``) writes under one
  directory. Every object is written through a temporary file in the same
  directory and renamed into place, so a reader never sees a partial file
  and a failed job leaves nothing behind. Files are created ``0640`` and
  the sink refuses to write through a symlink, at the directory or at the
  target, because an export directory is the kind of path an unprivileged
  account on the same host could otherwise point somewhere it should not.

* :class:`S3Sink` (``Z4J_EXPORT_SINK=s3``) streams to any S3-compatible
  store (AWS, MinIO, Ceph RGW, Backblaze B2) through ``aiobotocore``,
  which is optional: ``pip install "z4j[s3]"``. Objects larger than one
  part go up as a multipart upload, so the whole export is never held in
  memory. Credentials come from the standard AWS environment and config
  chain, or from the explicit ``Z4J_EXPORT_SINK_S3_*`` settings.

What a sink reports back is a location (a path, an ``s3://`` URL), the
key the object was written under, and a size. Nothing a sink returns or
logs carries a credential, and :meth:`ExportSink.describe` is the string
the API shows an operator.

A local job row stores the key, not the path. The download route rebuilds
the path from the configured base and :meth:`LocalDirectorySink.
open_download` admits nothing else: a row that names ``..``, an absolute
path outside the base, or a file reached through a symlink is refused, so
whoever can write ``export_jobs.file_path`` (a database role, an injection)
cannot turn the download into a read of an arbitrary file as the brain
user. Rows written before the key was stored hold the absolute path the
sink reported; they are accepted when the path is lexically below the base
and pass the same checks.

The audit chain head export (see ``domain/workers/export_jobs.py``) uses
the same sinks. That is the point: an operator who has configured a sink
for large exports has, without further work, somewhere outside the
database for the chain head to be anchored.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import stat
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, Protocol
from urllib.parse import urlsplit, urlunsplit

import structlog

if TYPE_CHECKING:
    from z4j_brain.settings import Settings

logger = structlog.get_logger("z4j.brain.export_sinks")

#: Mode for every file the local sink creates: owner read/write, group
#: read, nothing for others. Exports hold the audit trail.
LOCAL_FILE_MODE = 0o640

#: Mode for directories the local sink creates below its base.
LOCAL_DIR_MODE = 0o750

#: Smallest part S3 accepts in a multipart upload is 5 MiB; 8 MiB keeps
#: the part count low for the exports this is for without holding much.
S3_PART_SIZE = 8 * 1024 * 1024

#: Keys are built by the worker, never from a request, but the sink is the
#: last line and checks anyway: relative, forward slashes, plain characters.
_KEY_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ExportSinkError(RuntimeError):
    """A sink could not take the object. The message is safe to store."""


@dataclass(frozen=True, slots=True)
class SinkWriteResult:
    """What the sink reports once the object is durably in place."""

    #: Operator-facing: an absolute path for the local sink, an ``s3://``
    #: URL for S3. Logged and recorded on the audit row.
    location: str
    size_bytes: int
    #: The sink-relative key the object was written under. A local job row
    #: stores this rather than ``location``, so the path served later is
    #: always rebuilt from the configured base.
    key: str


@dataclass(frozen=True, slots=True)
class OpenedExport:
    """A finished local export opened for serving: the handle and its length."""

    file: BinaryIO
    size_bytes: int


class ExportSink(Protocol):
    """One place exports are written to."""

    #: ``local`` or ``s3``; stored on the job row.
    kind: str

    #: Whether the API can stream a finished object back to a caller.
    downloadable: bool

    def describe(self) -> str:
        """Operator-facing description with no credential in it."""

    async def write(
        self,
        key: str,
        chunks: AsyncIterator[bytes],
        *,
        content_type: str,
    ) -> SinkWriteResult:
        """Stream ``chunks`` to ``key`` and report where they landed."""

    async def discard(self, key: str) -> None:
        """Remove the object at ``key`` when its job cannot be completed.

        Called when the worker finished writing but the job row had already
        been moved to a terminal state by someone else (another leader's
        stale sweep), so the object would otherwise be an orphan nothing
        refers to. Best effort: a failure is logged, never raised.
        """


def validate_key(key: str) -> str:
    """Return ``key`` when it is a safe relative object key, else raise."""
    if not key or key.startswith("/") or "\\" in key:
        raise ExportSinkError(f"refusing export key {key!r}")
    segments = key.split("/")
    if any(_KEY_SEGMENT.fullmatch(segment) is None for segment in segments):
        raise ExportSinkError(f"refusing export key {key!r}")
    return key


# ---------------------------------------------------------------------------
# Local directory
# ---------------------------------------------------------------------------


class LocalDirectorySink:
    """Write exports under one directory, atomically, through no symlink."""

    kind = "local"
    downloadable = True

    def __init__(self, base: Path) -> None:
        self._base = Path(base)
        if self._base.is_symlink():
            raise ExportSinkError(f"export directory {self._base} is a symlink")
        if not self._base.is_dir():
            raise ExportSinkError(f"export directory {self._base} does not exist")

    @property
    def base(self) -> Path:
        return self._base

    def describe(self) -> str:
        return str(self._base)

    def _target_for(self, key: str) -> Path:
        """Resolve ``key`` below the base, refusing every symlinked step."""
        validate_key(key)
        current = self._base
        parts = key.split("/")
        for directory in parts[:-1]:
            current = current / directory
            if current.is_symlink():
                raise ExportSinkError(f"refusing to write through symlink {current}")
            if not current.exists():
                current.mkdir(mode=LOCAL_DIR_MODE)
            elif not current.is_dir():
                raise ExportSinkError(f"{current} is not a directory")
        target = current / parts[-1]
        if target.is_symlink():
            raise ExportSinkError(f"refusing to replace symlink {target}")
        return target

    async def write(
        self,
        key: str,
        chunks: AsyncIterator[bytes],
        *,
        content_type: str,
    ) -> SinkWriteResult:
        del content_type  # the filesystem keeps no media type
        target = self._target_for(key)
        staged = target.with_name(f".{target.name}.{os.getpid()}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(staged, flags, LOCAL_FILE_MODE)
        size = 0
        try:
            if hasattr(os, "fchmod"):
                # The umask may have taken bits off at creation; the mode
                # the docs promise is exact, not "at most".
                os.fchmod(fd, LOCAL_FILE_MODE)
            async for chunk in chunks:
                if not chunk:
                    continue
                await asyncio.to_thread(_write_all, fd, chunk)
                size += len(chunk)
            await asyncio.to_thread(os.fsync, fd)
        except BaseException:
            os.close(fd)
            with contextlib.suppress(OSError):
                staged.unlink()
            raise
        os.close(fd)
        if target.is_symlink():
            with contextlib.suppress(OSError):
                staged.unlink()
            raise ExportSinkError(f"refusing to replace symlink {target}")
        staged.replace(target)
        info = os.lstat(target)
        if not stat.S_ISREG(info.st_mode):
            raise ExportSinkError(f"{target} is not a regular file after write")
        return SinkWriteResult(location=str(target), size_bytes=size, key=key)

    async def discard(self, key: str) -> None:
        try:
            path = self.resolve_download(key)
            await asyncio.to_thread(path.unlink)
        except ExportSinkError:
            return
        except OSError:
            logger.warning("z4j export sink: could not remove an orphaned export", key=key)

    def key_for(self, location: str) -> str:
        """The sink-relative key a stored location names, or raise.

        A job row stores the key itself. A row written before the key was
        stored holds the absolute path the sink reported, accepted only when
        it is lexically below the configured base. Either way every part
        must be a plain segment: nothing empty, no ``.``, no ``..`` (which
        ``Path.relative_to`` accepts verbatim), nothing :func:`validate_key`
        refuses.
        """
        path = Path(location)
        try:
            parts = path.relative_to(self._base).parts
        except ValueError as exc:
            if path.is_absolute():
                raise ExportSinkError("export is not under the configured directory") from exc
            parts = tuple(location.split("/"))
        if not parts or any(part in ("", ".", "..") for part in parts):
            raise ExportSinkError("export location is not a plain key below the directory")
        return validate_key("/".join(parts))

    def display_location(self, stored: str) -> str:
        """The operator-facing path for what a job row stores."""
        return stored if Path(stored).is_absolute() else str(self._base / stored)

    def resolve_download(self, location: str) -> Path:
        """Return the file for ``location`` once it is proven to be ours.

        The location came from the job row. The row is not trusted: the
        base directory may have been moved since, the file may have been
        swapped for a link, and a writer of the row may have pointed it
        anywhere. The file returned is below the configured base both
        lexically (:meth:`key_for`) and physically (``resolve(strict=True)``
        of base and target), a regular file, reached through no symlink.
        """
        key = self.key_for(location)
        try:
            base = self._base.resolve(strict=True)
        except OSError as exc:
            raise ExportSinkError("export directory is missing") from exc
        current = self._base
        for part in key.split("/"):
            current = current / part
            if current.is_symlink():
                raise ExportSinkError("export path crosses a symlink")
        try:
            target = current.resolve(strict=True)
            info = os.lstat(current)
        except OSError as exc:
            raise ExportSinkError("export file is missing") from exc
        if not target.is_relative_to(base):
            raise ExportSinkError("export is not under the configured directory")
        if not stat.S_ISREG(info.st_mode):
            raise ExportSinkError("export file is missing")
        return current

    def open_download(self, location: str) -> OpenedExport:
        """Open the file for ``location`` for serving, following no symlink.

        :meth:`resolve_download` proves the path; the open itself carries
        ``O_NOFOLLOW`` where the platform has it, so a link swapped in
        between the check and the open is refused rather than followed,
        and what is served is the opened handle, not a path reopened later.
        """
        path = self.resolve_download(location)
        flags = os.O_RDONLY
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise ExportSinkError("export file is missing") from exc
        try:
            info = os.fstat(fd)
        except OSError as exc:
            os.close(fd)
            raise ExportSinkError("export file is missing") from exc
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            raise ExportSinkError("export file is missing")
        return OpenedExport(file=os.fdopen(fd, "rb"), size_bytes=int(info.st_size))


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


# ---------------------------------------------------------------------------
# S3-compatible object store
# ---------------------------------------------------------------------------

#: Builds an async context manager yielding an S3 client with the
#: aiobotocore method surface this sink uses. Tests inject a fake.
S3ClientFactory = Callable[[], Any]


class S3Sink:
    """Stream exports to an S3-compatible bucket through aiobotocore."""

    kind = "s3"
    downloadable = False

    def __init__(
        self,
        *,
        bucket: str,
        prefix: str = "",
        endpoint_url: str | None = None,
        region: str | None = None,
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        client_factory: S3ClientFactory | None = None,
        part_size: int = S3_PART_SIZE,
    ) -> None:
        if not bucket:
            raise ExportSinkError("the s3 export sink needs a bucket name")
        self._bucket = bucket
        self._prefix = prefix.strip("/")
        self._endpoint_url = endpoint_url
        self._region = region
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key
        self._client_factory = client_factory
        self._part_size = max(int(part_size), 5 * 1024 * 1024)

    def describe(self) -> str:
        base = f"s3://{self._bucket}"
        if self._prefix:
            base = f"{base}/{self._prefix}"
        host = _endpoint_host(self._endpoint_url)
        return f"{base} ({host})" if host else base

    def _full_key(self, key: str) -> str:
        validate_key(key)
        return f"{self._prefix}/{key}" if self._prefix else key

    def _client(self) -> Any:
        if self._client_factory is not None:
            return self._client_factory()
        try:
            import importlib

            session_module = importlib.import_module("aiobotocore.session")
        except ImportError as exc:
            raise ExportSinkError(
                "the s3 export sink needs the aiobotocore package; install "
                'the optional extra with: pip install "z4j[s3]"',
            ) from exc
        kwargs: dict[str, Any] = {}
        if self._endpoint_url:
            kwargs["endpoint_url"] = self._endpoint_url
        if self._region:
            kwargs["region_name"] = self._region
        if self._access_key_id and self._secret_access_key:
            kwargs["aws_access_key_id"] = self._access_key_id
            kwargs["aws_secret_access_key"] = self._secret_access_key
        return session_module.get_session().create_client("s3", **kwargs)

    async def write(
        self,
        key: str,
        chunks: AsyncIterator[bytes],
        *,
        content_type: str,
    ) -> SinkWriteResult:
        full_key = self._full_key(key)
        location = f"s3://{self._bucket}/{full_key}"
        async with self._client() as client:
            uploader = _MultipartUploader(
                client,
                bucket=self._bucket,
                key=full_key,
                content_type=content_type,
                part_size=self._part_size,
            )
            try:
                async for chunk in chunks:
                    await uploader.feed(chunk)
                size = await uploader.finish()
            except BaseException:
                await uploader.abort()
                raise
        return SinkWriteResult(location=location, size_bytes=size, key=key)

    async def discard(self, key: str) -> None:
        try:
            full_key = self._full_key(key)
            async with self._client() as client:
                await client.delete_object(Bucket=self._bucket, Key=full_key)
        except Exception:
            logger.warning(
                "z4j export sink: could not remove an orphaned object; the "
                "bucket's lifecycle rule or an operator will have to",
                key=key,
            )


class _MultipartUploader:
    """Buffer chunks into parts; one ``put_object`` when it all fits in one."""

    def __init__(
        self,
        client: Any,
        *,
        bucket: str,
        key: str,
        content_type: str,
        part_size: int,
    ) -> None:
        self._client = client
        self._bucket = bucket
        self._key = key
        self._content_type = content_type
        self._part_size = part_size
        self._buffer = bytearray()
        self._upload_id: str | None = None
        self._parts: list[dict[str, Any]] = []
        self._size = 0

    async def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        self._buffer.extend(chunk)
        self._size += len(chunk)
        while len(self._buffer) >= self._part_size:
            part = bytes(self._buffer[: self._part_size])
            del self._buffer[: self._part_size]
            await self._upload_part(part)

    async def _upload_part(self, body: bytes) -> None:
        if self._upload_id is None:
            created = await self._client.create_multipart_upload(
                Bucket=self._bucket,
                Key=self._key,
                ContentType=self._content_type,
            )
            self._upload_id = str(created["UploadId"])
        number = len(self._parts) + 1
        uploaded = await self._client.upload_part(
            Bucket=self._bucket,
            Key=self._key,
            UploadId=self._upload_id,
            PartNumber=number,
            Body=body,
        )
        self._parts.append({"PartNumber": number, "ETag": uploaded["ETag"]})

    async def finish(self) -> int:
        if self._upload_id is None:
            await self._client.put_object(
                Bucket=self._bucket,
                Key=self._key,
                Body=bytes(self._buffer),
                ContentType=self._content_type,
            )
            return self._size
        if self._buffer:
            await self._upload_part(bytes(self._buffer))
            self._buffer.clear()
        await self._client.complete_multipart_upload(
            Bucket=self._bucket,
            Key=self._key,
            UploadId=self._upload_id,
            MultipartUpload={"Parts": self._parts},
        )
        return self._size

    async def abort(self) -> None:
        if self._upload_id is None:
            return
        try:
            await self._client.abort_multipart_upload(
                Bucket=self._bucket,
                Key=self._key,
                UploadId=self._upload_id,
            )
        except Exception:
            logger.warning(
                "z4j export sink: could not abort a multipart upload; the "
                "bucket's lifecycle rule for incomplete uploads will reclaim it",
                key=self._key,
            )


def _endpoint_host(endpoint_url: str | None) -> str | None:
    """The host of an endpoint URL, with any userinfo stripped."""
    if not endpoint_url:
        return None
    parts = urlsplit(endpoint_url)
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, "", "", "")) if parts.scheme else host


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_export_sink(settings: Settings) -> ExportSink | None:
    """The sink this configuration names, or None when exports are off.

    Settings validation already requires the fields each kind needs, so a
    failure here is about the environment (a directory that is not there,
    a symlink) rather than the configuration's shape.
    """
    kind = settings.export_sink
    if kind == "none":
        return None
    if kind == "local":
        if settings.export_sink_path is None:  # pragma: no cover - validated
            raise ExportSinkError("Z4J_EXPORT_SINK_PATH is required for the local sink")
        return LocalDirectorySink(Path(settings.export_sink_path))
    if kind == "s3":
        if settings.export_sink_s3_bucket is None:  # pragma: no cover - validated
            raise ExportSinkError("Z4J_EXPORT_SINK_S3_BUCKET is required for the s3 sink")
        access = settings.export_sink_s3_access_key_id
        secret = settings.export_sink_s3_secret_access_key
        return S3Sink(
            bucket=settings.export_sink_s3_bucket,
            prefix=settings.export_sink_s3_prefix,
            endpoint_url=settings.export_sink_s3_endpoint_url,
            region=settings.export_sink_s3_region,
            access_key_id=access.get_secret_value() if access is not None else None,
            secret_access_key=secret.get_secret_value() if secret is not None else None,
        )
    raise ExportSinkError(f"unknown export sink {kind!r}")  # pragma: no cover


__all__ = [
    "LOCAL_DIR_MODE",
    "LOCAL_FILE_MODE",
    "S3_PART_SIZE",
    "ExportSink",
    "ExportSinkError",
    "LocalDirectorySink",
    "OpenedExport",
    "S3ClientFactory",
    "S3Sink",
    "SinkWriteResult",
    "build_export_sink",
    "validate_key",
]
