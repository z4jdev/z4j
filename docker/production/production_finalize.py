"""Architecture-neutral producer finalization for detached OCI authorities.

This module owns deterministic OCI bytes and the create/recovery state
machines shared by the production system and dashboard materials.  It owns no
network transport, credentials, GitHub/runner/registry identity selection, or
workflow.  Those authorities are injected after the material-specific
``require_ready`` barrier has succeeded.

The legacy common-helper Cosign subprocess boundary is deliberately not used.
``BoundExecutable`` and ``run_bound_process`` provide the fd-bound, closed,
bounded process primitive required by an injected live signer/verifier.
"""

from __future__ import annotations

import contextlib
import ctypes
import fcntl
import hashlib
import io
import os
import selectors
import signal
import stat
import struct
import subprocess
import tarfile
import time
import zlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, Protocol

MAX_COMPRESSED_LAYER_BYTES = 2 * 1024 * 1024 * 1024
MAX_UNCOMPRESSED_LAYER_BYTES = 8 * 1024 * 1024 * 1024
MAX_COSIGN_BYTES = 256 * 1024 * 1024
MAX_PROCESS_STREAM_BYTES = 4 * 1024 * 1024
MAX_PROCESS_AGGREGATE_BYTES = 6 * 1024 * 1024
SOURCE_CONTEXT_FORMAT = "z4j-production-source-context-binding-v1"
GIT_BINDING_FORMAT = "z4j-production-git-source-binding-v1"
SOURCE_FILE_PROJECTION_FORMAT = "z4j-production-source-file-projection-v1"
SIGNER_BOUNDARY_FORMAT = "z4j-production-fd-bound-cosign-v1"
LINUX_F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
LINUX_F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
LINUX_F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 0x0001)
LINUX_F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
LINUX_F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 0x0004)
LINUX_F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 0x0008)
LINUX_PR_SET_CHILD_SUBREAPER = 36
LINUX_PR_GET_CHILD_SUBREAPER = 37
LINUX_RENAME_NOREPLACE = 1


class FinalizationError(RuntimeError):
    """The producer finalization graph or transition failed closed."""


class CandidateInvalidError(FinalizationError):
    """One discovered authority candidate failed byte-derived validation."""


def _die(message: str) -> NoReturn:
    raise FinalizationError(message)


def _candidate_invalid(message: str) -> NoReturn:
    raise CandidateInvalidError(message)


@dataclass(frozen=True)
class BoundExecutable:
    """One authenticated executable retained in a sealed anonymous inode."""

    descriptor: int
    logical_path: Path
    raw_sha256: str
    raw_size: int

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            object.__setattr__(self, "descriptor", -1)

    def __enter__(self) -> BoundExecutable:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


@dataclass(frozen=True)
class ProcessResult:
    """Strict UTF-8 result from one bounded exact process execution."""

    argv: tuple[str, ...]
    returncode: int
    stderr: str
    stdout: str


@dataclass(frozen=True)
class CosignVerificationAuthority:
    """Reviewed private Cosign executable/cwd/trusted-root seals supplied live."""

    cwd: Path
    executable: BoundExecutable
    platform: str
    trusted_root_sha256: str
    trusted_root_size: int


@dataclass(frozen=True)
class OCIObject:
    """One literal OCI object and its exact descriptor."""

    descriptor: Mapping[str, Any]
    raw: bytes


@dataclass(frozen=True)
class OCIBuild:
    """Layer, config, and leaf bytes independently derived for one build."""

    config: OCIObject
    layer: OCIObject
    layer_diff_id: str
    leaf: OCIObject


@dataclass(frozen=True)
class OCIPlatform:
    """Both A/B OCI derivations and the fixed selected build for one platform."""

    builds: Mapping[str, OCIBuild]
    platform: str
    selected_build: str

    @property
    def selected(self) -> OCIBuild:
        try:
            return self.builds[self.selected_build]
        except KeyError as exc:  # pragma: no cover - constructor checks close this
            raise FinalizationError("selected OCI build is absent") from exc


@dataclass(frozen=True)
class MaterialBinding:
    """Material-owned claims after aggregation/OCI/source cross-binding."""

    manifest: Mapping[str, Any]
    material: Mapping[str, Any]
    readback_extra: Mapping[str, Any]
    source: Mapping[str, Any]
    source_context: Mapping[str, Any]
    verification: Mapping[str, Any]


@dataclass(frozen=True)
class GitHubEvidence:
    """Authenticated GitHub values selected entirely by the injected client."""

    ceremony: Mapping[str, Any]
    expected_identities: Mapping[str, Mapping[str, Any]]
    generator: Mapping[str, Any]
    protection: Mapping[str, Any]
    readback: Mapping[str, Any]


@dataclass(frozen=True)
class RecoveryAuthorization:
    """Authenticated authorization for an already exact immutable subject."""

    authority_publication_started: bool
    prior_run: Mapping[str, Any]


@dataclass(frozen=True)
class OCIReceiptEvidence:
    """Authenticated registry/settings evidence embedded in a new receipt."""

    dockerhub_readback: Mapping[str, Any]
    oci_readback: Mapping[str, Any]
    protection: Mapping[str, Any]
    readback_extra: Mapping[str, Any]


@dataclass(frozen=True)
class SubjectCreationAuthorization:
    """Authenticated immutable-rule/CAS authority obtained before first PUT."""

    conditional_create: bool
    protection: Mapping[str, Any]
    repository: str
    subject_digest: str
    subject_tag: str


@dataclass(frozen=True)
class ManifestPutResult:
    """Minimum immutable response authority returned by an OCI client."""

    created: bool
    digest: str
    subject_digest: str | None


@dataclass(frozen=True)
class AuthorityCandidate:
    """One literal K-tag candidate returned by complete recovery discovery."""

    bundle: bytes
    manifest: bytes
    receipt: bytes
    tag: str


@dataclass(frozen=True)
class AuthorityDiscovery:
    """One complete native-referrer and immutable-tag discovery snapshot."""

    candidates: tuple[AuthorityCandidate, ...]
    native_status: int
    referrer_pages: tuple[bytes, ...]
    referrers_complete: bool
    tag_pages: tuple[bytes, ...]
    tags_complete: bool


@dataclass(frozen=True)
class FinalizationResult:
    """Complete deterministic output selected or created by finalization."""

    authority_digest: str
    authority_manifest: bytes
    authority_tag: str
    bundle: bytes
    material: Mapping[str, Any]
    platform_oci: Mapping[str, OCIPlatform]
    receipt: bytes
    recovered_authority: bool
    source_context: Mapping[str, Any]
    subject_digest: str
    subject_index: bytes
    subject_tag: str
    tracked_authority: Mapping[str, Any]
    transition_kind: str
    verification: Mapping[str, Any]


class GitHubClient(Protocol):
    """Authenticated GitHub reads; implementations own transport/auth."""

    def current_evidence(self, *, profile: Any) -> GitHubEvidence: ...

    def authorize_subject_recovery(
        self,
        *,
        aggregation: Mapping[str, Any],
        profile: Any,
        subject_digest: str,
    ) -> RecoveryAuthorization: ...


class OCIClient(Protocol):
    """Raw OCI/settings operations; implementations own transport/auth."""

    def discover_authorities(
        self,
        *,
        authority_tag_prefix: str,
        repository: str,
        subject_digest: str,
    ) -> AuthorityDiscovery: ...

    def get_blob(self, *, digest: str, repository: str) -> bytes | None: ...

    def get_manifest(
        self,
        *,
        media_type: str,
        reference: str,
        repository: str,
    ) -> bytes | None: ...

    def put_blob(self, *, raw: bytes, repository: str) -> None: ...

    def put_manifest(
        self,
        *,
        media_type: str,
        raw: bytes,
        reference: str,
        repository: str,
        subject_digest: str | None,
        create_only: bool,
    ) -> ManifestPutResult: ...

    def authorize_subject_creation(
        self,
        *,
        profile: Any,
        subject_digest: str,
        subject_tag: str,
    ) -> SubjectCreationAuthorization: ...

    def receipt_evidence(
        self,
        *,
        profile: Any,
        subject_digest: str,
        subject_index: bytes,
        subject_tag: str,
        subject_tag_put_by_current_run: bool,
    ) -> OCIReceiptEvidence: ...

    def confirm_final_state(
        self,
        *,
        authority_digest: str,
        authority_manifest: bytes,
        authority_tag: str,
        profile: Any,
        subject_digest: str,
        subject_index: bytes,
        subject_tag: str,
    ) -> None: ...


class Signer(Protocol):
    """Injected signer plus captured authority for core-owned verification."""

    boundary_format: str

    def sign(self, *, profile: Any, receipt: bytes) -> bytes: ...

    def verification_authority(self, *, profile: Any) -> CosignVerificationAuthority: ...


@dataclass(frozen=True)
class ProducerRuntime:
    """Only live capabilities supplied to a producer-finalize CLI invocation."""

    github: GitHubClient
    now: Any
    oci: OCIClient
    signer: Signer


@dataclass(frozen=True)
class FinalizationAdapter:
    """Material-specific schema hooks; the finalization state machine is common."""

    architectures: Mapping[str, str]
    authority_schema: str
    bind_oci_platform_results: Callable[..., MaterialBinding]
    common: Any
    material_build: Any
    material_key: str
    platforms: tuple[str, str]
    policy_carrier_path: str
    policy_release_path: str
    profile: Any
    require_ready: Callable[..., None]
    validate_authority_manifest: Callable[..., Any]
    validate_bundle: Callable[[bytes, bytes, Mapping[str, Any]], Mapping[str, Any]]
    validate_manifest_authority: Callable[[Mapping[str, Any], bytes], Any]
    validate_platform_aggregation: Callable[..., Mapping[str, Any]]
    validate_receipt: Callable[..., Any]
    validate_subject_index: Callable[[bytes, Mapping[str, Any]], Any]
    validation_errors: tuple[type[BaseException], ...]

    def __post_init__(self) -> None:
        expected = ("linux/amd64", "linux/arm64")
        if self.platforms != expected or set(self.architectures) != set(expected):
            _die("finalization adapter platform set/order differs")
        if tuple(self.architectures[item] for item in expected) != ("amd64", "arm64"):
            _die("finalization adapter architecture mapping differs")
        if self.material_key not in {"system_packages", "dashboard"}:
            _die("finalization adapter material key differs")
        if not self.validation_errors or not all(
            isinstance(item, type) and issubclass(item, BaseException)
            for item in self.validation_errors
        ):
            _die("finalization adapter validation exception closure differs")


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _die(f"{context} must be one object")
    return value


def _canonical_copy(common: Any, value: Mapping[str, Any], context: str) -> dict[str, Any]:
    try:
        raw = common.canonical_json(value, terminal_lf=False)
        result = common.parse_json(raw, context=context)
    except Exception as exc:
        if isinstance(exc, common.CommonAuthorityError):
            raise FinalizationError(str(exc)) from exc
        raise
    if not isinstance(result, dict):
        _die(f"{context} must remain one object")
    return result


def capture_bound_executable(  # noqa: PLR0912, PLR0915 - stable fd capture transaction
    path: Path,
    *,
    expected_sha256: str,
    expected_size: int,
) -> BoundExecutable:
    """Authenticate and retain an executable without later reopening its path."""

    if (
        not path.is_absolute()
        or not hasattr(os, "memfd_create")
        or not Path("/proc/self/fd").is_dir()
    ):
        _die("fd-bound executable capture is unavailable")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        source = os.open(path, flags)
    except OSError as exc:
        raise FinalizationError("authenticated executable cannot be opened directly") from exc
    try:
        before = os.fstat(source)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not before.st_mode & stat.S_IXUSR
            or isinstance(expected_size, bool)
            or expected_size <= 0
            or before.st_size != expected_size
            or expected_size > MAX_COSIGN_BYTES
        ):
            _die("authenticated executable inode/size/mode differs")
        chunks: list[bytes] = []
        remaining = expected_size
        while remaining:
            chunk = os.read(source, min(1024 * 1024, remaining))
            if not chunk:
                _die("authenticated executable is truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(source, 1):
            _die("authenticated executable grew during capture")
        after = os.fstat(source)
        raw = b"".join(chunks)
        if (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
        ) or hashlib.sha256(raw).hexdigest() != expected_sha256:
            _die("authenticated executable changed or failed its reviewed SHA-256")
    finally:
        os.close(source)
    descriptor = os.memfd_create(
        "z4j-production-cosign",
        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                _die("private executable copy made no progress")
            offset += written
        os.fchmod(descriptor, 0o500)
        fcntl.fcntl(
            descriptor,
            LINUX_F_ADD_SEALS,
            LINUX_F_SEAL_WRITE | LINUX_F_SEAL_GROW | LINUX_F_SEAL_SHRINK | LINUX_F_SEAL_SEAL,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        copied = bytearray()
        while len(copied) < len(raw):
            chunk = os.read(descriptor, min(1024 * 1024, len(raw) - len(copied)))
            if not chunk:
                _die("private executable copy is truncated")
            copied.extend(chunk)
        if bytes(copied) != raw:
            _die("private executable copy differs")
    except BaseException:
        os.close(descriptor)
        raise
    return BoundExecutable(
        descriptor=descriptor,
        logical_path=path,
        raw_sha256=expected_sha256,
        raw_size=expected_size,
    )


def _validate_bound_executable(executable: BoundExecutable) -> None:
    """Re-prove the sealed private executable H/N immediately before exec."""

    if (
        not isinstance(executable, BoundExecutable)
        or executable.descriptor < 0
        or not executable.logical_path.is_absolute()
        or isinstance(executable.raw_size, bool)
        or executable.raw_size <= 0
        or executable.raw_size > MAX_COSIGN_BYTES
    ):
        _die("bound executable authority differs")
    observed = os.fstat(executable.descriptor)
    required_seals = (
        LINUX_F_SEAL_WRITE | LINUX_F_SEAL_GROW | LINUX_F_SEAL_SHRINK | LINUX_F_SEAL_SEAL
    )
    try:
        seals = fcntl.fcntl(executable.descriptor, LINUX_F_GET_SEALS)
    except OSError as exc:
        raise FinalizationError("bound executable is not one sealed private inode") from exc
    digest = hashlib.sha256()
    offset = 0
    while offset < executable.raw_size:
        chunk = os.pread(
            executable.descriptor,
            min(1024 * 1024, executable.raw_size - offset),
            offset,
        )
        if not chunk:
            _die("bound executable private inode is truncated")
        digest.update(chunk)
        offset += len(chunk)
    if (
        not stat.S_ISREG(observed.st_mode)
        or stat.S_IMODE(observed.st_mode) != 0o500
        or observed.st_size != executable.raw_size
        or seals & required_seals != required_seals
        or digest.hexdigest() != executable.raw_sha256
        or os.pread(executable.descriptor, 1, executable.raw_size)
    ):
        _die("bound executable private inode/seals/H/N differs")


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as exc:
        raise FinalizationError("bound process group could not be killed") from exc
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait(timeout=10)
        raise FinalizationError("bound process group did not terminate") from exc


def _direct_child_pids() -> tuple[int, ...]:
    """Read this task's exact Linux child set without invoking another process."""

    try:
        raw = Path(f"/proc/self/task/{os.getpid()}/children").read_bytes()
    except OSError as exc:
        raise FinalizationError("private descendant accounting is unavailable") from exc
    try:
        values = tuple(int(item) for item in raw.split())
    except ValueError as exc:
        raise FinalizationError("private descendant accounting is malformed") from exc
    if any(value <= 0 for value in values) or len(values) != len(set(values)):
        _die("private descendant accounting differs")
    return values


def _enable_private_subreaper() -> tuple[Any, int]:
    """Own orphaned hostile descendants for one single-task process boundary."""

    try:
        tasks = {item.name for item in Path("/proc/self/task").iterdir()}
    except OSError as exc:
        raise FinalizationError("private subreaper task accounting is unavailable") from exc
    if tasks != {str(os.getpid())} or _direct_child_pids():
        _die("bound process requires one task with no pre-existing child process")
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    if (
        libc.prctl(
            LINUX_PR_GET_CHILD_SUBREAPER,
            ctypes.byref(previous),
            0,
            0,
            0,
        )
        != 0
    ):
        _die("private subreaper state cannot be read")
    if previous.value not in {0, 1}:
        _die("private subreaper state differs")
    if libc.prctl(LINUX_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        _die("private subreaper state cannot be enabled")
    return libc, previous.value


def _restore_private_subreaper(libc: Any, previous: int) -> None:
    if libc.prctl(LINUX_PR_SET_CHILD_SUBREAPER, previous, 0, 0, 0) != 0:
        _die("private subreaper state cannot be restored")


def _drain_adopted_descendants() -> bool:
    """SIGKILL/reap every child adopted through the private subreaper."""

    observed = False
    deadline = time.monotonic() + 10
    while True:
        children = _direct_child_pids()
        if not children:
            return observed
        observed = True
        if time.monotonic() >= deadline:
            _die("hostile descendants could not be drained")
        for pid in children:
            try:
                descriptor = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            except (AttributeError, OSError) as exc:
                raise FinalizationError("hostile descendant cannot be retained") from exc
            try:
                with contextlib.suppress(ProcessLookupError):
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            finally:
                os.close(descriptor)
        for pid in children:
            with contextlib.suppress(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)
        time.sleep(0.01)


def run_bound_process(  # noqa: PLR0912, PLR0915 - explicit bounded process state machine
    executable: BoundExecutable,
    arguments: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    pass_fds: Sequence[int] = (),
    timeout_seconds: int = 180,
) -> ProcessResult:
    """Run an authenticated private copy with closed fds/env/cwd and bounded logs."""

    if (
        not arguments
        or any(not isinstance(item, str) or not item or "\0" in item for item in arguments)
        or isinstance(timeout_seconds, bool)
        or timeout_seconds < 1
        or timeout_seconds > 900
        or not all(
            isinstance(key, str)
            and key
            and "=" not in key
            and "\0" not in key
            and isinstance(value, str)
            and "\0" not in value
            for key, value in environment.items()
        )
    ):
        _die("bound process invocation differs")
    _validate_bound_executable(executable)
    inherited = [executable.descriptor, *pass_fds]
    if len(inherited) != len(set(inherited)):
        _die("bound process inherited descriptor set is duplicated")
    for descriptor in inherited:
        if isinstance(descriptor, bool) or not isinstance(descriptor, int) or descriptor < 0:
            _die("bound process inherited descriptor differs")
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            _die("bound process inherited descriptor is not regular")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directory = os.open(cwd, flags)
    except OSError as exc:
        raise FinalizationError("bound process cwd cannot be opened directly") from exc
    before = os.fstat(directory)
    if (
        not stat.S_ISDIR(before.st_mode)
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) != 0o700
        or before.st_nlink != 2
        or os.listdir(directory)  # noqa: PTH208
    ):
        os.close(directory)
        _die("bound process cwd is not one empty owner-private 0700 directory")
    try:
        subreaper, previous_subreaper = _enable_private_subreaper()
    except BaseException:
        os.close(directory)
        raise
    argv = (str(executable.logical_path), *arguments)
    process: subprocess.Popen[bytes] | None = None
    stdout = bytearray()
    stderr = bytearray()
    escaped_descendants = False
    try:
        try:
            process = subprocess.Popen(  # noqa: S603 - sealed fd and exact argv
                argv,
                executable=f"/proc/self/fd/{executable.descriptor}",
                cwd=f"/proc/self/fd/{directory}",
                env=dict(environment),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                pass_fds=(directory, *inherited),
                start_new_session=True,
            )
        except OSError as exc:
            raise FinalizationError("bound process could not start") from exc
        assert process.stdout is not None and process.stderr is not None
        streams = {process.stdout: stdout, process.stderr: stderr}
        selector = selectors.DefaultSelector()
        deadline = time.monotonic() + timeout_seconds
        try:
            for stream in streams:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _kill_process_group(process)
                    _die("bound process exceeded its monotonic deadline")
                events = selector.select(min(remaining, 0.25))
                for key, _mask in events:
                    stream = key.fileobj
                    try:
                        chunk = os.read(stream.fileno(), 64 * 1024)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        continue
                    streams[stream].extend(chunk)
                    if (
                        len(streams[stream]) > MAX_PROCESS_STREAM_BYTES
                        or len(stdout) + len(stderr) > MAX_PROCESS_AGGREGATE_BYTES
                    ):
                        _kill_process_group(process)
                        _die("bound process transcript exceeded its reviewed bound")
        finally:
            selector.close()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _kill_process_group(process)
            _die("bound process exceeded its monotonic deadline")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            _kill_process_group(process)
            _die("bound process exceeded its monotonic deadline")
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            pass
        else:
            _kill_process_group(process)
            _die("bound process left a surviving descendant")
        after = os.fstat(directory)
        if (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_nlink) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
        ) or os.listdir(directory):  # noqa: PTH208
            _die("bound process cwd changed during execution")
        try:
            stdout_text = bytes(stdout).decode("utf-8", errors="strict")
            stderr_text = bytes(stderr).decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise FinalizationError("bound process transcript is not strict UTF-8") from exc
    finally:
        try:
            if process is not None and process.poll() is None:
                _kill_process_group(process)
        finally:
            try:
                if process is not None:
                    if process.stdout is not None:
                        process.stdout.close()
                    if process.stderr is not None:
                        process.stderr.close()
            finally:
                try:
                    escaped_descendants = _drain_adopted_descendants()
                finally:
                    try:
                        if process is not None and process.returncode is None:
                            process.poll()
                    finally:
                        try:
                            _restore_private_subreaper(subreaper, previous_subreaper)
                        finally:
                            os.close(directory)
    if escaped_descendants:
        _die("bound process left a hostile session-escaped descendant")
    return ProcessResult(argv=argv, returncode=returncode, stderr=stderr_text, stdout=stdout_text)


def _sealed_memfd(name: str, raw: bytes, *, maximum: int) -> int:
    if not raw or len(raw) > maximum or not hasattr(os, "memfd_create"):
        _die(f"{name} cannot be retained in one bounded private inode")
    descriptor = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                _die(f"{name} private copy made no progress")
            offset += written
        fcntl.fcntl(
            descriptor,
            LINUX_F_ADD_SEALS,
            LINUX_F_SEAL_WRITE | LINUX_F_SEAL_GROW | LINUX_F_SEAL_SHRINK | LINUX_F_SEAL_SEAL,
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def verify_bound_cosign_blob(
    executable: BoundExecutable,
    *,
    bundle: bytes,
    cwd: Path,
    identity: Any,
    receipt: bytes,
    trusted_root: bytes,
    trusted_root_sha256: str,
    trusted_root_size: int,
) -> None:
    """Run exact offline ``cosign verify-blob`` only over sealed fd inputs."""

    if (
        hashlib.sha256(trusted_root).hexdigest() != trusted_root_sha256
        or len(trusted_root) != trusted_root_size
    ):
        _die("bound Cosign trusted-root bytes differ from their reviewed seal")
    fields = {
        name: getattr(identity, name, None)
        for name in (
            "issuer",
            "ref",
            "repository",
            "sha",
            "workflow_identity",
            "workflow_name",
        )
    }
    if not all(isinstance(value, str) and value and "\0" not in value for value in fields.values()):
        _die("bound Cosign identity is incomplete")
    receipt_fd = _sealed_memfd("z4j-cosign-receipt", receipt, maximum=16 * 1024 * 1024)
    bundle_fd = _sealed_memfd("z4j-cosign-bundle", bundle, maximum=16 * 1024 * 1024)
    trusted_fd = _sealed_memfd(
        "z4j-cosign-trusted-root",
        trusted_root,
        maximum=16 * 1024 * 1024,
    )
    try:
        result = run_bound_process(
            executable,
            (
                "verify-blob",
                "--bundle",
                f"/proc/self/fd/{bundle_fd}",
                "--trusted-root",
                f"/proc/self/fd/{trusted_fd}",
                "--certificate-identity",
                fields["workflow_identity"],
                "--certificate-oidc-issuer",
                fields["issuer"],
                "--certificate-github-workflow-name",
                fields["workflow_name"],
                "--certificate-github-workflow-repository",
                fields["repository"],
                "--certificate-github-workflow-ref",
                fields["ref"],
                "--certificate-github-workflow-sha",
                fields["sha"],
                "--certificate-github-workflow-trigger",
                "workflow_dispatch",
                f"/proc/self/fd/{receipt_fd}",
            ),
            cwd=cwd,
            environment={
                "HOME": "/nonexistent",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/nonexistent",
                "TZ": "UTC",
            },
            pass_fds=(receipt_fd, bundle_fd, trusted_fd),
            timeout_seconds=180,
        )
    finally:
        for descriptor in (receipt_fd, bundle_fd, trusted_fd):
            os.close(descriptor)
    if result.returncode != 0:
        raise CandidateInvalidError("bound Cosign cryptographic verification failed")


def _verify_signed_receipt(
    adapter: FinalizationAdapter,
    signer: Signer,
    *,
    bundle_raw: bytes,
    policy: Mapping[str, Any],
    receipt: Mapping[str, Any],
    receipt_raw: bytes,
    trusted_root_raw: bytes,
) -> None:
    """Close structure, Fulcio OIDs, and cryptography inside this module."""

    try:
        bundle = adapter.validate_bundle(receipt_raw, bundle_raw, policy)
        if not isinstance(bundle, Mapping):
            _candidate_invalid("material bundle validator did not return the validated bundle")
        identity = adapter.common.identity_from_receipt(adapter.profile, receipt)
        adapter.common.verify_fulcio(bundle, identity)
    except Exception as exc:
        if isinstance(exc, CandidateInvalidError):
            raise
        if isinstance(exc, adapter.validation_errors):
            raise CandidateInvalidError("candidate bundle/Fulcio validation failed") from exc
        raise
    authority = signer.verification_authority(profile=adapter.profile)
    if not isinstance(authority, CosignVerificationAuthority):
        _die("producer signer did not return one bound Cosign authority")
    if (
        not isinstance(authority.executable, BoundExecutable)
        or authority.executable.descriptor < 0
        or not authority.cwd.is_absolute()
        or authority.platform not in adapter.platforms
    ):
        _die("producer signer bound Cosign executable/cwd/platform differs")
    try:
        cosign_policy = policy["signature"]["cosign"]["platforms"][authority.platform]
        trusted_policy_value = policy["signature"]["trusted_root"]
    except (KeyError, TypeError) as exc:
        raise FinalizationError("producer signature tool/root policy is absent") from exc
    expected_cosign = adapter.common.exact_object(
        cosign_policy,
        {"sha256", "size", "url"},
        "producer Cosign platform policy",
    )
    trusted_policy = _mapping(trusted_policy_value, "producer trusted-root policy")
    if (
        authority.executable.raw_sha256 != expected_cosign["sha256"]
        or authority.executable.raw_size != expected_cosign["size"]
        or authority.trusted_root_sha256 != trusted_policy.get("sha256")
        or authority.trusted_root_size != trusted_policy.get("size")
    ):
        _die("bound Cosign/trusted-root H/N differs from the ready policy")
    verify_bound_cosign_blob(
        authority.executable,
        bundle=bundle_raw,
        cwd=authority.cwd,
        identity=identity,
        receipt=receipt_raw,
        trusted_root=trusted_root_raw,
        trusted_root_sha256=authority.trusted_root_sha256,
        trusted_root_size=authority.trusted_root_size,
    )


def _gzip(raw: bytes) -> bytes:
    """Return one literal deterministic RFC 1952 stream with fixed parameters."""

    compressor = zlib.compressobj(
        level=9,
        method=zlib.DEFLATED,
        wbits=-zlib.MAX_WBITS,
        memLevel=9,
        strategy=zlib.Z_DEFAULT_STRATEGY,
    )
    body = compressor.compress(raw) + compressor.flush(zlib.Z_FINISH)
    # MTIME=0, XFL=2 (maximum compression), OS=255 (unknown/platform neutral).
    return (
        b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
        + body
        + struct.pack("<II", zlib.crc32(raw) & 0xFFFFFFFF, len(raw) & 0xFFFFFFFF)
    )


def _gzip_diff_id(raw: bytes) -> str:
    if not raw or len(raw) > MAX_COMPRESSED_LAYER_BYTES:
        _die("selected OCI layer is empty or overlarge")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    digest = hashlib.sha256()
    size = 0
    offset = 0
    try:
        while offset < len(raw):
            chunk = raw[offset : offset + 1024 * 1024]
            offset += len(chunk)
            decoded = decoder.decompress(chunk)
            size += len(decoded)
            if size > MAX_UNCOMPRESSED_LAYER_BYTES:
                _die("selected OCI layer expands beyond its exact bound")
            digest.update(decoded)
        tail = decoder.flush()
    except zlib.error as exc:
        raise FinalizationError("selected OCI layer is not one valid gzip stream") from exc
    size += len(tail)
    digest.update(tail)
    if size > MAX_UNCOMPRESSED_LAYER_BYTES:
        _die("selected OCI layer expands beyond its exact bound")
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        _die("selected OCI layer has a truncated, concatenated, or trailing gzip stream")
    return "sha256:" + digest.hexdigest()


def _payload_records(
    adapter: FinalizationAdapter, root: Path, platform: str
) -> list[dict[str, Any]]:
    records = adapter.material_build.file_records(root, exclude=frozenset())
    if not records:
        _die(f"{platform} extracted payload is empty")
    return records


def _canonical_ustar(entries: Sequence[tuple[str, int, bytes]]) -> bytes:
    """Build the one reviewed USTAR representation used by every OCI layer."""

    output = io.BytesIO()
    try:
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, mode, raw in entries:
                info = tarfile.TarInfo(name)
                info.type = tarfile.REGTYPE
                info.mode = mode
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
    except (OSError, tarfile.TarError, ValueError) as exc:
        raise FinalizationError("payload cannot form canonical USTAR") from exc
    result = output.getvalue()
    if not result or len(result) > MAX_UNCOMPRESSED_LAYER_BYTES or len(result) % 512:
        _die("canonical payload USTAR size differs")
    return result


def _ustar_inventory(raw: bytes) -> tuple[tuple[str, int, int, int, int, bytes], ...]:
    """Independently inventory simple regular USTAR members without tarfile."""

    offset = 0
    inventory: list[tuple[str, int, int, int, int, bytes]] = []

    def octal(field: bytes, context: str) -> int:
        value = field.rstrip(b"\0 ").lstrip(b" ") or b"0"
        if any(item < ord("0") or item > ord("7") for item in value):
            _die(f"runtime USTAR {context} is not octal")
        return int(value, 8)

    while offset + 512 <= len(raw):
        header = raw[offset : offset + 512]
        if header == bytes(512):
            if raw[offset:] != bytes(len(raw) - offset) or len(raw) - offset < 1024:
                _die("runtime USTAR trailer differs")
            return tuple(inventory)
        if header[257:263] != b"ustar\0" or header[156:157] not in {b"\0", b"0"}:
            _die("runtime USTAR header/type differs")
        expected_checksum = octal(header[148:156], "checksum")
        observed_checksum = sum(header[:148]) + (8 * ord(" ")) + sum(header[156:])
        if expected_checksum != observed_checksum:
            _die("runtime USTAR checksum differs")
        try:
            name = header[:100].split(b"\0", 1)[0].decode("utf-8", errors="strict")
            prefix = header[345:500].split(b"\0", 1)[0].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise FinalizationError("runtime USTAR path is not strict UTF-8") from exc
        if prefix:
            name = f"{prefix}/{name}"
        mode = octal(header[100:108], "mode")
        uid = octal(header[108:116], "uid")
        gid = octal(header[116:124], "gid")
        size = octal(header[124:136], "size")
        mtime = octal(header[136:148], "mtime")
        data_start = offset + 512
        data_end = data_start + size
        padded_end = data_start + ((size + 511) // 512) * 512
        if padded_end > len(raw) or raw[data_end:padded_end] != bytes(padded_end - data_end):
            _die("runtime USTAR member data/padding differs")
        inventory.append((name, mode, uid, gid, mtime, raw[data_start:data_end]))
        offset = padded_end
    _die("runtime USTAR is truncated")


def _assert_oci_runtime_contract(adapter: FinalizationAdapter) -> None:
    """Prove the ambient tar/zlib/JSON runtime reproduces reviewed OCI bytes."""

    entries = (
        ("opt/z4j-production-runtime-vector/alpha.txt", 0o644, b"alpha\n"),
        (
            "opt/z4j-production-runtime-vector/nested/run.sh",
            0o755,
            b"#!/bin/sh\nprintf golden\\n\n",
        ),
    )
    tar_raw = _canonical_ustar(entries)
    if (
        len(tar_raw) != 10240
        or hashlib.sha256(tar_raw).hexdigest()
        != "75de7b3777898f1f20109711911c8a6da3ab5e65a6c5fd13de94e4646ee58a3d"
        or _ustar_inventory(tar_raw)
        != tuple((name, mode, 0, 0, 0, raw) for name, mode, raw in entries)
    ):
        _die("ambient USTAR runtime differs from the reviewed golden vector")
    layer_raw = _gzip(tar_raw)
    try:
        independently_decoded = zlib.decompress(layer_raw, 16 + zlib.MAX_WBITS)
    except zlib.error as exc:
        raise FinalizationError("ambient gzip runtime failed independent decoding") from exc
    diff_id = "sha256:" + hashlib.sha256(tar_raw).hexdigest()
    if (
        len(layer_raw) != 193
        or hashlib.sha256(layer_raw).hexdigest()
        != "5686f90b067abf315bdfbf82f683bab7cbdf4d7d7fe0a139d8af0a634bc55877"
        or independently_decoded != tar_raw
        or _gzip_diff_id(layer_raw) != diff_id
    ):
        _die("ambient gzip runtime differs from the reviewed golden vector")
    common = adapter.common
    layer_descriptor = {
        "digest": common.digest(layer_raw),
        "mediaType": common.OCI_LAYER_GZIP,
        "size": len(layer_raw),
    }
    expected = {
        "linux/amd64": {
            "config": (163, "367ba9b441a3704e5ce331981055384426d033a6cefc24517464ff5627b4e2be"),
            "leaf": (401, "f5d9d8bba2f4cbc6bfdd57e6c5395199c15533979d108508bb4a17fbdd85b7c0"),
        },
        "linux/arm64": {
            "config": (163, "9beff76fcfa6a9cd3deb6ae297b603aedac2b9e5d22d4e4387e174856b4bce7c"),
            "leaf": (401, "ffde2bbfe9b94625ddbb995a0a98c0cc1181725726fe5d0b249ecf9908b6dd6f"),
        },
    }
    leaves: dict[str, Mapping[str, Any]] = {}
    for platform in adapter.platforms:
        architecture = adapter.architectures[platform]
        config_raw = common.canonical_json(
            {
                "architecture": architecture,
                "config": {},
                "os": "linux",
                "rootfs": {"diff_ids": [diff_id], "type": "layers"},
            },
            terminal_lf=False,
        )
        if (len(config_raw), hashlib.sha256(config_raw).hexdigest()) != expected[platform][
            "config"
        ]:
            _die("ambient OCI config bytes differ from the reviewed golden vector")
        config_descriptor = {
            "digest": common.digest(config_raw),
            "mediaType": common.OCI_CONFIG,
            "size": len(config_raw),
        }
        common.validate_config(config_raw, architecture=architecture, layer_diff_id=diff_id)
        leaf_raw = common.canonical_json(
            {
                "config": config_descriptor,
                "layers": [layer_descriptor],
                "mediaType": common.OCI_MANIFEST,
                "schemaVersion": 2,
            },
            terminal_lf=False,
        )
        if (len(leaf_raw), hashlib.sha256(leaf_raw).hexdigest()) != expected[platform]["leaf"]:
            _die("ambient OCI leaf bytes differ from the reviewed golden vector")
        common.validate_leaf(
            leaf_raw,
            expected_config=config_descriptor,
            expected_layer=layer_descriptor,
        )
        leaves[platform] = {
            "digest": common.digest(leaf_raw),
            "mediaType": common.OCI_MANIFEST,
            "size": len(leaf_raw),
        }
    index_raw = common.canonical_json(
        {
            "manifests": [
                {
                    **dict(leaves[platform]),
                    "platform": {
                        "architecture": adapter.architectures[platform],
                        "os": "linux",
                    },
                }
                for platform in adapter.platforms
            ],
            "mediaType": common.OCI_INDEX,
            "schemaVersion": 2,
        },
        terminal_lf=False,
    )
    if (
        len(index_raw) != 491
        or hashlib.sha256(index_raw).hexdigest()
        != "6d6b0d05f28a3a0d994838c44cbdb45931e900df31c9f87d626452d73cf9c3ed"
    ):
        _die("ambient OCI index bytes differ from the reviewed golden vector")
    common.validate_index(
        index_raw,
        expected_platforms=tuple(
            (platform, adapter.architectures[platform]) for platform in adapter.platforms
        ),
        expected_descriptors=leaves,
    )


def _payload_tar(
    adapter: FinalizationAdapter,
    root: Path,
    records: Sequence[Mapping[str, Any]],
    platform: str,
) -> bytes:
    prefix = adapter.profile.payload_root.lstrip("/")
    if not prefix or PurePosixPath(prefix).as_posix() != prefix:
        _die("producer payload-root prefix differs")
    entries: list[tuple[str, int, bytes]] = []
    try:
        for record in records:
            raw = adapter.material_build.read_regular(
                root / record["path"],
                maximum=record["size"],
                context=f"{platform} OCI payload {record['path']}",
            )
            if (
                len(raw) != record["size"]
                or adapter.common.sha256(raw) != record["sha256"]
                or record["mode"] not in {"0644", "0755"}
            ):
                _die(f"{platform} OCI payload record changed")
            entries.append((f"{prefix}/{record['path']}", int(record["mode"], 8), raw))
    except (OSError, ValueError) as exc:
        raise FinalizationError(f"{platform} payload cannot form canonical USTAR") from exc
    result = _canonical_ustar(entries)
    if _payload_records(adapter, root, platform) != list(records):
        _die(f"{platform} payload changed during OCI layer construction")
    return result


def _validate_payload_seal(
    adapter: FinalizationAdapter,
    aggregation: Mapping[str, Any],
    *,
    build_id: str,
    platform: str,
    records: Sequence[Mapping[str, Any]],
) -> None:
    try:
        expected = aggregation["carrier_aggregation"]["platforms"][platform]["payloads"][build_id]
    except (KeyError, TypeError) as exc:
        raise FinalizationError("validated aggregation lacks extracted payload seals") from exc
    framing = {
        "files": list(records),
        "format": f"z4j-production-{adapter.profile.material}-extracted-payload-tree-v1",
        "platform": platform,
    }
    observed = {
        "bytes": sum(item["size"] for item in records),
        "entries": len(records),
        "sha256": adapter.common.sha256(adapter.common.canonical_json(framing, terminal_lf=False)),
    }
    if expected != observed:
        _die(f"{platform} build {build_id} extracted payload seal differs")


def _derive_oci_build(
    adapter: FinalizationAdapter,
    aggregation: Mapping[str, Any],
    root: Path,
    *,
    build_id: str,
    platform: str,
) -> OCIBuild:
    records = _payload_records(adapter, root, platform)
    _validate_payload_seal(
        adapter,
        aggregation,
        build_id=build_id,
        platform=platform,
        records=records,
    )
    tar_raw = _payload_tar(adapter, root, records, platform)
    layer_raw = _gzip(tar_raw)
    layer_diff_id = _gzip_diff_id(layer_raw)
    expected_diff_id = "sha256:" + hashlib.sha256(tar_raw).hexdigest()
    if layer_diff_id != expected_diff_id:
        _die(f"{platform} build {build_id} layer diff-ID differs")
    common = adapter.common
    layer_descriptor = {
        "digest": common.digest(layer_raw),
        "mediaType": common.OCI_LAYER_GZIP,
        "size": len(layer_raw),
    }
    architecture = adapter.architectures[platform]
    config_raw = common.canonical_json(
        {
            "architecture": architecture,
            "config": {},
            "os": "linux",
            "rootfs": {"diff_ids": [layer_diff_id], "type": "layers"},
        },
        terminal_lf=False,
    )
    common.validate_config(config_raw, architecture=architecture, layer_diff_id=layer_diff_id)
    config_descriptor = {
        "digest": common.digest(config_raw),
        "mediaType": common.OCI_CONFIG,
        "size": len(config_raw),
    }
    leaf_raw = common.canonical_json(
        {
            "config": config_descriptor,
            "layers": [layer_descriptor],
            "mediaType": common.OCI_MANIFEST,
            "schemaVersion": 2,
        },
        terminal_lf=False,
    )
    common.validate_leaf(
        leaf_raw,
        expected_config=config_descriptor,
        expected_layer=layer_descriptor,
    )
    leaf_descriptor = {
        "digest": common.digest(leaf_raw),
        "mediaType": common.OCI_MANIFEST,
        "size": len(leaf_raw),
    }
    return OCIBuild(
        config=OCIObject(config_descriptor, config_raw),
        layer=OCIObject(layer_descriptor, layer_raw),
        layer_diff_id=layer_diff_id,
        leaf=OCIObject(leaf_descriptor, leaf_raw),
    )


def _derive_oci_platforms(
    adapter: FinalizationAdapter,
    aggregation: Mapping[str, Any],
    extraction_root: Path,
) -> dict[str, OCIPlatform]:
    if not extraction_root.is_absolute():
        _die("platform aggregation extraction root is not absolute")
    selected_build = aggregation.get("selected_build")
    if selected_build != "A":
        _die("validated platform aggregation selected build differs")
    result: dict[str, OCIPlatform] = {}
    for platform in adapter.platforms:
        architecture = adapter.architectures[platform]
        builds = {
            build_id: _derive_oci_build(
                adapter,
                aggregation,
                extraction_root / architecture / build_id / "payload",
                build_id=build_id,
                platform=platform,
            )
            for build_id in ("A", "B")
        }
        if builds["A"] != builds["B"]:
            _die(f"{platform} independently derived A/B OCI bytes differ")
        result[platform] = OCIPlatform(
            builds=builds,
            platform=platform,
            selected_build=selected_build,
        )
    return result


def _derive_subject_index(
    adapter: FinalizationAdapter,
    platform_oci: Mapping[str, OCIPlatform],
) -> bytes:
    common = adapter.common
    raw = common.canonical_json(
        {
            "manifests": [
                {
                    **dict(platform_oci[platform].selected.leaf.descriptor),
                    "platform": {
                        "architecture": adapter.architectures[platform],
                        "os": "linux",
                    },
                }
                for platform in adapter.platforms
            ],
            "mediaType": common.OCI_INDEX,
            "schemaVersion": 2,
        },
        terminal_lf=False,
    )
    common.validate_index(
        raw,
        expected_platforms=tuple(
            (platform, adapter.architectures[platform]) for platform in adapter.platforms
        ),
        expected_descriptors={
            platform: platform_oci[platform].selected.leaf.descriptor
            for platform in adapter.platforms
        },
    )
    return raw


def _validate_aggregation_shape(
    adapter: FinalizationAdapter,
    value: Mapping[str, Any],
    *,
    policy_sha256: str,
) -> dict[str, Any]:
    aggregation = _canonical_copy(adapter.common, value, "validated platform aggregation")
    if (
        aggregation.get("material") != adapter.profile.material
        or aggregation.get("policy_sha256") != policy_sha256
        or aggregation.get("selected_build") != "A"
    ):
        _die("validated platform aggregation material/policy/selection differs")
    platforms = adapter.common.exact_object(
        aggregation.get("platforms"),
        set(adapter.platforms),
        "validated derived aggregation platforms",
    )
    for platform in adapter.platforms:
        item = _mapping(platforms[platform], f"validated aggregation {platform}")
        builds = item.get("builds")
        if (
            not isinstance(builds, list)
            or len(builds) != 2
            or [build.get("id") if isinstance(build, Mapping) else None for build in builds]
            != ["A", "B"]
        ):
            _die(f"validated aggregation {platform} does not retain exact builds A/B")
        if {key: item for key, item in builds[0].items() if key != "id"} != {
            key: item for key, item in builds[1].items() if key != "id"
        }:
            _die(f"validated aggregation {platform} A/B derived claims differ")
    return aggregation


def _validate_source_context(
    adapter: FinalizationAdapter,
    binding: MaterialBinding,
    aggregation: Mapping[str, Any],
    github: GitHubEvidence,
) -> dict[str, Any]:
    common = adapter.common
    context = _canonical_copy(
        common,
        _mapping(binding.source_context, "material source context"),
        "material source context",
    )
    if context != aggregation.get("source_context"):
        _die("material source context is not deep-equal to the validated aggregation")
    exact = common.exact_object(
        context,
        {"files", "format", "git"},
        "material source context",
    )
    if exact["format"] != SOURCE_CONTEXT_FORMAT:
        _die("material source-context binding format differs")
    git = common.exact_object(
        exact["git"],
        {"commit", "format", "reference", "source_prefix", "tree"},
        "material Git source binding",
    )
    if git["format"] != GIT_BINDING_FORMAT or git["source_prefix"] != "packages/z4j":
        _die("material Git source binding format/prefix differs")
    common.git_sha(git["commit"], "material Git source commit")
    common.git_sha(git["tree"], "material Git source tree")
    files = common.exact_object(
        exact["files"],
        {"entries", "sha256", "size"},
        "material source-file projection seal",
    )
    common.hex64(files["sha256"], "material source-file projection SHA-256")
    common.positive_int(files["size"], "material source-file projection size")
    common.positive_int(files["entries"], "material source-file projection entries")
    source = _mapping(binding.source, "material signed source")
    generator = common.exact_object(
        source.get("generator"),
        {"commit", "ref", "repository", "tree"},
        "material signed generator",
    )
    authenticated = _canonical_copy(common, github.generator, "authenticated GitHub generator")
    if generator != authenticated:
        _die("material signed generator differs from authenticated GitHub generator")
    if (
        git["commit"] != generator["commit"]
        or git["tree"] != generator["tree"]
        or git["reference"] != generator["ref"]
    ):
        _die("material source context and authenticated generator commit/tree/ref differ")
    return exact


def _crossbind_material(  # noqa: PLR0912 - explicit material/OCI/source closure
    adapter: FinalizationAdapter,
    binding: MaterialBinding,
    aggregation: Mapping[str, Any],
    github: GitHubEvidence,
    platform_oci: Mapping[str, OCIPlatform],
    subject_index: bytes,
    original_manifest: Mapping[str, Any],
) -> MaterialBinding:
    common = adapter.common
    if not isinstance(binding, MaterialBinding):
        _die("material binder did not return one MaterialBinding")
    material = _canonical_copy(common, _mapping(binding.material, "material binding"), "material")
    manifest = _canonical_copy(common, _mapping(binding.manifest, "bound manifest"), "manifest")
    source = _canonical_copy(common, _mapping(binding.source, "bound source"), "source")
    verification = _canonical_copy(
        common,
        _mapping(binding.verification, "bound verification"),
        "verification",
    )
    readback_extra = _canonical_copy(
        common,
        _mapping(binding.readback_extra, "bound extra readback"),
        "readback extra",
    )
    if set(readback_extra) & {"dockerhub", "github", "oci"}:
        _die("material extra readback collides with common authority keys")
    if set(manifest) != set(original_manifest):
        _die("material binder changed the tracked manifest root schema")
    for key in original_manifest:
        if key != adapter.material_key and manifest[key] != original_manifest[key]:
            _die(f"material binder changed unrelated manifest field {key}")
    if manifest.get(adapter.material_key) != material:
        _die("material binder manifest and receipt material differ")
    index = common.exact_object(material.get("index"), {"digest", "size"}, "material index")
    subject_digest = common.digest(subject_index)
    if index != {"digest": subject_digest, "size": len(subject_index)}:
        _die("material index does not select the derived literal OCI index")
    subject_tag = common.derived_tag(adapter.profile, subject_digest, authority=False)
    expected_image = f"{adapter.profile.repository}:{subject_tag}@{subject_digest}"
    if material.get("image") != expected_image:
        _die("material image does not select the fixed repository/tag/digest")
    material_platforms = common.exact_object(
        material.get("platforms"),
        set(adapter.platforms),
        "material platforms",
    )
    verification_platforms = common.exact_object(
        verification.get("platforms"),
        set(adapter.platforms),
        "material verification platforms",
    )
    for platform in adapter.platforms:
        item = _mapping(material_platforms[platform], f"material {platform}")
        expected = platform_oci[platform].selected
        if (
            item.get("config_digest") != expected.config.descriptor["digest"]
            or item.get("config_size") != expected.config.descriptor["size"]
            or item.get("manifest_digest") != expected.leaf.descriptor["digest"]
            or item.get("manifest_size") != expected.leaf.descriptor["size"]
        ):
            _die(f"material {platform} OCI descriptors differ from literal selected bytes")
        verification_platform = _mapping(
            verification_platforms[platform],
            f"material verification {platform}",
        )
        verification_builds = verification_platform.get("builds")
        if not isinstance(verification_builds, list) or len(verification_builds) != 2:
            _die(f"material verification {platform} does not retain builds A/B")
        for position, build_id in enumerate(("A", "B")):
            verification_build = _mapping(
                verification_builds[position],
                f"material verification {platform} build {build_id}",
            )
            literal = platform_oci[platform].builds[build_id]
            expected_oci = {
                "config_digest": literal.config.descriptor["digest"],
                "config_size": literal.config.descriptor["size"],
                "id": build_id,
                "layer_digest": literal.layer.descriptor["digest"],
                "layer_diff_id": literal.layer_diff_id,
                "layer_size": literal.layer.descriptor["size"],
                "manifest_digest": literal.leaf.descriptor["digest"],
                "manifest_size": literal.leaf.descriptor["size"],
            }
            if {key: verification_build.get(key) for key in expected_oci} != expected_oci:
                _die(
                    f"material verification {platform} build {build_id} "
                    "OCI fields differ from literal bytes"
                )
    adapter.validate_subject_index(subject_index, material)
    source_context = _validate_source_context(adapter, binding, aggregation, github)
    return MaterialBinding(
        manifest=manifest,
        material=material,
        readback_extra=readback_extra,
        source=source,
        source_context=source_context,
        verification=verification,
    )


def _validate_subject_graph(
    adapter: FinalizationAdapter,
    oci: OCIClient,
    platform_oci: Mapping[str, OCIPlatform],
    subject_digest: str,
    subject_index: bytes,
    subject_tag: str,
) -> None:
    common = adapter.common
    for reference in (subject_tag, subject_digest):
        raw = oci.get_manifest(
            reference=reference,
            repository=adapter.profile.repository,
            media_type=common.OCI_INDEX,
        )
        if raw != subject_index:
            _die("subject index tag/digest readback differs from literal bytes")
    for platform in adapter.platforms:
        item = platform_oci[platform].selected
        leaf = oci.get_manifest(
            reference=item.leaf.descriptor["digest"],
            repository=adapter.profile.repository,
            media_type=common.OCI_MANIFEST,
        )
        config = oci.get_blob(
            digest=item.config.descriptor["digest"],
            repository=adapter.profile.repository,
        )
        layer = oci.get_blob(
            digest=item.layer.descriptor["digest"],
            repository=adapter.profile.repository,
        )
        if leaf != item.leaf.raw or config != item.config.raw or layer != item.layer.raw:
            _die(f"{platform} subject leaf/config/layer readback differs")


def _validate_subject_creation_authorization(
    adapter: FinalizationAdapter,
    value: SubjectCreationAuthorization,
    *,
    subject_digest: str,
    subject_tag: str,
) -> dict[str, Any]:
    """Validate authenticated immutability/CAS authority before first mutation."""

    if not isinstance(value, SubjectCreationAuthorization):
        _die("subject creation authorization has the wrong type")
    if (
        value.conditional_create is not True
        or value.repository != adapter.profile.repository
        or value.subject_digest != subject_digest
        or value.subject_tag != subject_tag
    ):
        _die("subject creation authorization repository/tag/digest/CAS differs")
    common = adapter.common
    protection = _canonical_copy(
        common,
        _mapping(value.protection, "subject creation protection"),
        "subject creation protection",
    )
    exact = common.exact_object(
        protection,
        {"cleanup", "immutability", "publisher", "repository"},
        "subject creation protection",
    )
    publisher = common.exact_object(
        exact["publisher"],
        {"can_admin", "can_delete", "can_pull", "can_push", "id"},
        "subject creation publisher",
    )
    if (
        exact["repository"] != adapter.profile.repository
        or exact["cleanup"] != {"excludes": list(adapter.profile.cleanup_excludes)}
        or exact["immutability"] != dict(adapter.profile.immutability_patterns)
        or publisher.get("can_admin") is not False
        or publisher.get("can_delete") is not False
        or publisher.get("can_pull") is not True
        or publisher.get("can_push") is not True
    ):
        _die("subject creation immutable protection/publisher authority differs")
    common.ascii_text(publisher["id"], "subject creation publisher ID")
    return exact


def _upload_subject_graph(
    adapter: FinalizationAdapter,
    oci: OCIClient,
    platform_oci: Mapping[str, OCIPlatform],
    subject_digest: str,
    subject_index: bytes,
    subject_tag: str,
) -> None:
    common = adapter.common
    for platform in adapter.platforms:
        item = platform_oci[platform].selected
        oci.put_blob(raw=item.layer.raw, repository=adapter.profile.repository)
        oci.put_blob(raw=item.config.raw, repository=adapter.profile.repository)
        result = oci.put_manifest(
            media_type=common.OCI_MANIFEST,
            raw=item.leaf.raw,
            reference=item.leaf.descriptor["digest"],
            repository=adapter.profile.repository,
            subject_digest=None,
            create_only=False,
        )
        if (
            not isinstance(result, ManifestPutResult)
            or not isinstance(result.created, bool)
            or result.digest != item.leaf.descriptor["digest"]
            or result.subject_digest is not None
        ):
            _die(f"{platform} leaf manifest PUT response differs")
    result = oci.put_manifest(
        media_type=common.OCI_INDEX,
        raw=subject_index,
        reference=subject_tag,
        repository=adapter.profile.repository,
        subject_digest=None,
        create_only=True,
    )
    if result != ManifestPutResult(created=True, digest=subject_digest, subject_digest=None):
        _die("subject index PUT response differs")


def _transition(
    adapter: FinalizationAdapter,
    authorization: RecoveryAuthorization | None,
) -> dict[str, Any]:
    if authorization is None:
        return {
            "kind": adapter.profile.created_transition,
            "prior_run": None,
            "subject_tag_put_by_current_run": True,
        }
    if not isinstance(authorization, RecoveryAuthorization):
        _die("GitHub recovery authorization has the wrong type")
    if not isinstance(authorization.authority_publication_started, bool):
        _die("GitHub recovery publication state is not one boolean")
    return {
        "kind": adapter.profile.recovered_transition,
        "prior_run": _canonical_copy(
            adapter.common,
            _mapping(authorization.prior_run, "recovery prior run"),
            "recovery prior run",
        ),
        "subject_tag_put_by_current_run": False,
    }


def _crossbind_receipt(
    adapter: FinalizationAdapter,
    receipt: Mapping[str, Any],
    binding: MaterialBinding,
    policy_raw: bytes,
) -> None:
    common = adapter.common
    if (
        receipt.get(adapter.material_key) != binding.material
        or receipt.get("verification") != binding.verification
        or receipt.get("source") != binding.source
    ):
        _die("signed receipt is not deep-equal to derived material/source/verification")
    contract = _mapping(receipt.get("contract"), "receipt contract")
    if contract.get("sha256") != common.sha256(policy_raw) or contract.get("size") != len(
        policy_raw
    ):
        _die("signed receipt policy H/N cross-binding differs")


def _validate_receipt(
    adapter: FinalizationAdapter,
    receipt: Mapping[str, Any],
    *,
    aggregation: Mapping[str, Any],
    binding: MaterialBinding,
    expected_identities: Mapping[str, Mapping[str, Any]],
    policy_raw: bytes,
) -> None:
    adapter.validate_receipt(
        receipt,
        manifest=binding.manifest,
        policy_raw=policy_raw,
        platform_aggregation=aggregation,
        expected_identities=expected_identities,
    )
    _crossbind_receipt(adapter, receipt, binding, policy_raw)


def _assemble_receipt(
    adapter: FinalizationAdapter,
    *,
    aggregation: Mapping[str, Any],
    binding: MaterialBinding,
    expected_identities: Mapping[str, Mapping[str, Any]],
    github: GitHubEvidence,
    oci: OCIReceiptEvidence,
    policy_raw: bytes,
    transition: Mapping[str, Any],
) -> tuple[dict[str, Any], bytes]:
    common = adapter.common
    if not isinstance(github, GitHubEvidence) or not isinstance(oci, OCIReceiptEvidence):
        _die("producer receipt evidence has the wrong injected type")
    injected_extra = _canonical_copy(
        common,
        _mapping(oci.readback_extra, "injected extra OCI readback"),
        "injected extra OCI readback",
    )
    if set(binding.readback_extra) & set(injected_extra):
        _die("material and injected extra readback keys overlap")
    readback_extra = {**dict(binding.readback_extra), **injected_extra}
    if set(readback_extra) & {"dockerhub", "github", "oci"}:
        _die("extra readback collides with common authority keys")
    receipt: dict[str, Any] = {
        "ceremony": _canonical_copy(common, github.ceremony, "GitHub ceremony"),
        "contract": {
            "carrier_path": adapter.policy_carrier_path,
            "release_path": adapter.policy_release_path,
            "schema": adapter.authority_schema,
            "sha256": common.sha256(policy_raw),
            "size": len(policy_raw),
        },
        "format": adapter.profile.receipt_format,
        "protection": {
            "dockerhub": _canonical_copy(common, oci.protection, "Docker Hub protection"),
            "github": _canonical_copy(common, github.protection, "GitHub protection"),
        },
        "readback": {
            "dockerhub": _canonical_copy(
                common,
                oci.dockerhub_readback,
                "Docker Hub readback",
            ),
            "github": _canonical_copy(common, github.readback, "GitHub readback"),
            "oci": _canonical_copy(common, oci.oci_readback, "OCI readback"),
            **readback_extra,
        },
        "release": common.RELEASE,
        "repository": adapter.profile.repository,
        "result": "pass",
        "source": dict(binding.source),
        adapter.material_key: dict(binding.material),
        "transition": dict(transition),
        "verification": dict(binding.verification),
    }
    raw = common.canonical_json(receipt, terminal_lf=True)
    parsed = common.parse_json(raw, context=f"{adapter.profile.material} producer receipt")
    if parsed != receipt:
        _die("producer receipt canonical round trip differs")
    _validate_receipt(
        adapter,
        parsed,
        aggregation=aggregation,
        binding=binding,
        expected_identities=expected_identities,
        policy_raw=policy_raw,
    )
    return parsed, raw


def _validate_discovery(  # noqa: PLR0912, PLR0915 - closed tag/referrer reconciliation
    adapter: FinalizationAdapter,
    discovery: AuthorityDiscovery,
    *,
    subject_digest: str,
) -> tuple[AuthorityCandidate, ...]:
    if not isinstance(discovery, AuthorityDiscovery):
        _die("OCI authority discovery has the wrong type")
    if (
        isinstance(discovery.native_status, bool)
        or not isinstance(discovery.native_status, int)
        or discovery.native_status != 200
        or discovery.referrers_complete is not True
        or discovery.tags_complete is not True
        or not discovery.referrer_pages
        or not discovery.tag_pages
    ):
        _die("OCI authority discovery is non-native, incomplete, or unpaginated")
    candidate_tags: set[str] = set()
    candidate_digests: set[str] = set()
    candidate_subjects: dict[str, str] = {}
    for candidate in discovery.candidates:
        if not isinstance(candidate, AuthorityCandidate):
            _die("OCI authority candidate has the wrong type")
        digest = adapter.common.digest(candidate.manifest)
        adapter.common.validate_derived_tag(
            adapter.profile,
            candidate.tag,
            digest,
            authority=True,
        )
        if candidate.tag in candidate_tags or digest in candidate_digests:
            _die("OCI authority discovery contains duplicate tag/digest candidates")
        manifest = adapter.common.parse_json(
            candidate.manifest,
            context=f"immutable tag {candidate.tag} authority manifest",
        )
        if not isinstance(manifest, Mapping):
            _die("immutable authority tag manifest must be one object")
        subject = adapter.common.exact_object(
            manifest.get("subject"),
            {"digest", "mediaType", "size"},
            f"immutable tag {candidate.tag} subject",
        )
        adapter.common.oci_digest(subject["digest"], f"immutable tag {candidate.tag} subject")
        adapter.common.positive_int(subject["size"], f"immutable tag {candidate.tag} subject size")
        if subject["mediaType"] != adapter.common.OCI_INDEX:
            _die("immutable authority tag subject media type differs")
        candidate_tags.add(candidate.tag)
        candidate_digests.add(digest)
        candidate_subjects[candidate.tag] = subject["digest"]
    listed_tags: set[str] = set()
    repository_name = adapter.profile.repository.removeprefix("docker.io/")
    for position, raw in enumerate(discovery.tag_pages):
        page = adapter.common.parse_json(raw, context=f"immutable tag page {position}")
        page = adapter.common.exact_object(
            page,
            {"name", "tags"},
            f"immutable tag page {position}",
        )
        if page["name"] != repository_name or (
            page["tags"] is not None and not isinstance(page["tags"], list)
        ):
            _die("immutable tag page repository/schema differs")
        for tag in page["tags"] or []:
            adapter.common.ascii_text(tag, f"immutable tag page {position} tag")
            if not tag.startswith(adapter.profile.authority_tag_prefix):
                continue
            suffix = tag.removeprefix(adapter.profile.authority_tag_prefix)
            digest = "sha256:" + suffix
            adapter.common.validate_derived_tag(
                adapter.profile,
                tag,
                digest,
                authority=True,
            )
            if tag in listed_tags:
                _die("complete immutable tag pages contain a duplicate authority tag")
            listed_tags.add(tag)
    if listed_tags != candidate_tags:
        _die("complete immutable tag pages and authority candidates differ")
    current_candidates = tuple(
        candidate
        for candidate in discovery.candidates
        if candidate_subjects[candidate.tag] == subject_digest
    )
    current_candidate_descriptors = {
        adapter.common.digest(candidate.manifest): len(candidate.manifest)
        for candidate in current_candidates
    }
    all_referrer_digests: set[str] = set()
    referrer_descriptors: dict[str, int] = {}
    for position, raw in enumerate(discovery.referrer_pages):
        page = adapter.common.parse_json(raw, context=f"native referrers page {position}")
        page = adapter.common.exact_object(
            page,
            {"manifests", "mediaType", "schemaVersion"},
            f"native referrers page {position}",
        )
        if (
            page["mediaType"] != adapter.common.OCI_INDEX
            or page["schemaVersion"] != 2
            or not isinstance(page["manifests"], list)
        ):
            _die("native referrers capability page schema/media differs")
        for descriptor_number, value in enumerate(page["manifests"]):
            context = f"native referrers page {position} descriptor {descriptor_number}"
            if not isinstance(value, dict):
                _die(f"{context} must be one object")
            allowed = {"annotations", "artifactType", "digest", "mediaType", "size"}
            required = {"digest", "mediaType", "size"}
            if set(value) - allowed or not required <= set(value):
                _die(f"{context} has a non-OCI or incomplete descriptor shape")
            descriptor = value
            adapter.common.oci_digest(descriptor["digest"], f"{context}.digest")
            adapter.common.positive_int(descriptor["size"], f"{context}.size")
            if descriptor["mediaType"] != adapter.common.OCI_MANIFEST:
                _die("native referrer descriptor media type differs")
            if "annotations" in descriptor and not isinstance(descriptor["annotations"], dict):
                _die(f"{context}.annotations must be one object")
            if descriptor["digest"] in all_referrer_digests:
                _die("complete native referrer pages contain a duplicate descriptor digest")
            all_referrer_digests.add(descriptor["digest"])
            if descriptor.get("artifactType") != adapter.profile.artifact_type:
                continue
            referrer_descriptors[descriptor["digest"]] = descriptor["size"]
    if referrer_descriptors != current_candidate_descriptors:
        _die("complete native referrer pages and authority candidates differ")
    return current_candidates


def _tracked_authority(
    adapter: FinalizationAdapter,
    *,
    authority_digest: str,
    authority_tag: str,
    bundle: bytes,
    manifest: bytes,
    receipt: bytes,
) -> dict[str, Any]:
    return {
        "artifact": {
            "digest": authority_digest,
            "size": len(manifest),
            "tag": authority_tag,
        },
        "bundle": {"sha256": adapter.common.sha256(bundle), "size": len(bundle)},
        "receipt": {"sha256": adapter.common.sha256(receipt), "size": len(receipt)},
        "repository": adapter.profile.repository,
    }


def _candidate_result(
    adapter: FinalizationAdapter,
    signer: Signer,
    candidate: AuthorityCandidate,
    discovery: AuthorityDiscovery,
    *,
    aggregation: Mapping[str, Any],
    binding: MaterialBinding,
    expected_identities: Mapping[str, Mapping[str, Any]],
    platform_oci: Mapping[str, OCIPlatform],
    policy: Mapping[str, Any],
    policy_raw: bytes,
    subject_digest: str,
    subject_index: bytes,
    subject_tag: str,
    trusted_root_raw: bytes,
) -> FinalizationResult:
    common = adapter.common
    try:
        authority_digest = common.digest(candidate.manifest)
        authority_tag = common.validate_derived_tag(
            adapter.profile,
            candidate.tag,
            authority_digest,
            authority=True,
        )
        adapter.validate_authority_manifest(
            candidate.manifest,
            receipt_raw=candidate.receipt,
            bundle_raw=candidate.bundle,
            subject_digest=subject_digest,
            subject_size=len(subject_index),
            selected_tag=authority_tag,
        )
        receipt = common.parse_json(candidate.receipt, context="recovered authority receipt")
        if common.canonical_json(receipt, terminal_lf=True) != candidate.receipt:
            _candidate_invalid("recovered authority receipt is not canonical plus one LF")
        _validate_receipt(
            adapter,
            receipt,
            aggregation=aggregation,
            binding=binding,
            expected_identities=expected_identities,
            policy_raw=policy_raw,
        )
        bundle = common.parse_json(candidate.bundle, context="recovered authority bundle")
        if common.canonical_json(bundle, terminal_lf=True) != candidate.bundle:
            _candidate_invalid("recovered authority bundle is not canonical plus one LF")
    except Exception as exc:
        if isinstance(exc, CandidateInvalidError):
            raise
        if isinstance(exc, (FinalizationError, *adapter.validation_errors)):
            raise CandidateInvalidError("candidate authority bytes failed validation") from exc
        raise
    _verify_signed_receipt(
        adapter,
        signer,
        bundle_raw=candidate.bundle,
        policy=policy,
        receipt=receipt,
        receipt_raw=candidate.receipt,
        trusted_root_raw=trusted_root_raw,
    )
    common.validate_native_referrers(
        discovery.referrer_pages,
        authority_digest=authority_digest,
        authority_size=len(candidate.manifest),
        artifact_type=adapter.profile.artifact_type,
    )
    return FinalizationResult(
        authority_digest=authority_digest,
        authority_manifest=candidate.manifest,
        authority_tag=authority_tag,
        bundle=candidate.bundle,
        material=binding.material,
        platform_oci=platform_oci,
        receipt=candidate.receipt,
        recovered_authority=True,
        source_context=binding.source_context,
        subject_digest=subject_digest,
        subject_index=subject_index,
        subject_tag=subject_tag,
        tracked_authority=_tracked_authority(
            adapter,
            authority_digest=authority_digest,
            authority_tag=authority_tag,
            bundle=candidate.bundle,
            manifest=candidate.manifest,
            receipt=candidate.receipt,
        ),
        transition_kind=str(receipt["transition"]["kind"]),
        verification=binding.verification,
    )


def _valid_candidates(
    adapter: FinalizationAdapter,
    signer: Signer,
    discovery: AuthorityDiscovery,
    **kwargs: Any,
) -> list[FinalizationResult]:
    current_candidates = _validate_discovery(
        adapter,
        discovery,
        subject_digest=kwargs["subject_digest"],
    )
    valid: list[FinalizationResult] = []
    for candidate in current_candidates:
        try:
            result = _candidate_result(adapter, signer, candidate, discovery, **kwargs)
        except CandidateInvalidError:
            continue
        valid.append(result)
    if len(valid) > 1:
        _die("multiple valid authority candidates require reviewed manual selection")
    return valid


def _discover_valid_candidates(
    adapter: FinalizationAdapter,
    oci: OCIClient,
    signer: Signer,
    **kwargs: Any,
) -> list[FinalizationResult]:
    discovery = oci.discover_authorities(
        authority_tag_prefix=adapter.profile.authority_tag_prefix,
        repository=adapter.profile.repository,
        subject_digest=kwargs["subject_digest"],
    )
    return _valid_candidates(adapter, signer, discovery, **kwargs)


def _confirm_final_state(
    adapter: FinalizationAdapter,
    oci: OCIClient,
    result: FinalizationResult,
) -> FinalizationResult:
    oci.confirm_final_state(
        authority_digest=result.authority_digest,
        authority_manifest=result.authority_manifest,
        authority_tag=result.authority_tag,
        profile=adapter.profile,
        subject_digest=result.subject_digest,
        subject_index=result.subject_index,
        subject_tag=result.subject_tag,
    )
    return result


def _publish_authority(
    adapter: FinalizationAdapter,
    oci: OCIClient,
    signer: Signer,
    *,
    aggregation: Mapping[str, Any],
    binding: MaterialBinding,
    bundle: bytes,
    expected_identities: Mapping[str, Mapping[str, Any]],
    platform_oci: Mapping[str, OCIPlatform],
    policy: Mapping[str, Any],
    policy_raw: bytes,
    receipt: bytes,
    recovery_polls: int,
    subject_digest: str,
    subject_index: bytes,
    subject_tag: str,
    trusted_root_raw: bytes,
    transition_kind: str,
) -> FinalizationResult:
    common = adapter.common
    manifest = common.build_artifact_manifest(
        adapter.profile,
        receipt_raw=receipt,
        bundle_raw=bundle,
        subject_digest=subject_digest,
        subject_size=len(subject_index),
    )
    authority_digest = common.digest(manifest)
    authority_tag = common.derived_tag(adapter.profile, authority_digest, authority=True)
    adapter.validate_authority_manifest(
        manifest,
        receipt_raw=receipt,
        bundle_raw=bundle,
        subject_digest=subject_digest,
        subject_size=len(subject_index),
        selected_tag=authority_tag,
    )
    existing = oci.get_manifest(
        reference=authority_tag,
        repository=adapter.profile.repository,
        media_type=common.OCI_MANIFEST,
    )
    if existing is not None and existing != manifest:
        _die("content-derived authority tag contains conflicting bytes")
    if existing is None:
        for raw in (common.EMPTY_CONFIG, receipt, bundle):
            oci.put_blob(raw=raw, repository=adapter.profile.repository)
        result = oci.put_manifest(
            media_type=common.OCI_MANIFEST,
            raw=manifest,
            reference=authority_tag,
            repository=adapter.profile.repository,
            subject_digest=subject_digest,
            create_only=True,
        )
        if result != ManifestPutResult(
            created=True,
            digest=authority_digest,
            subject_digest=subject_digest,
        ):
            _die("authority manifest PUT digest/OCI-Subject differs")
    for reference in (authority_tag, authority_digest):
        raw = oci.get_manifest(
            reference=reference,
            repository=adapter.profile.repository,
            media_type=common.OCI_MANIFEST,
        )
        if raw != manifest:
            _die("authority tag/digest readback differs from literal manifest")
    selected: FinalizationResult | None = None
    candidate_arguments = {
        "aggregation": aggregation,
        "binding": binding,
        "expected_identities": expected_identities,
        "platform_oci": platform_oci,
        "policy": policy,
        "policy_raw": policy_raw,
        "subject_digest": subject_digest,
        "subject_index": subject_index,
        "subject_tag": subject_tag,
        "trusted_root_raw": trusted_root_raw,
    }
    for _attempt in range(recovery_polls + 1):
        valid = _discover_valid_candidates(
            adapter,
            oci,
            signer,
            **candidate_arguments,
        )
        exact = [
            item
            for item in valid
            if item.authority_manifest == manifest
            and item.receipt == receipt
            and item.bundle == bundle
        ]
        if len(exact) == 1:
            selected = exact[0]
            break
        if valid:
            _die("registry selected different valid authority bytes after manifest PUT")
    if selected is None:
        _die("published authority never appeared in complete native referrer/tag discovery")
    created = FinalizationResult(
        authority_digest=authority_digest,
        authority_manifest=manifest,
        authority_tag=authority_tag,
        bundle=bundle,
        material=binding.material,
        platform_oci=platform_oci,
        receipt=receipt,
        recovered_authority=False,
        source_context=binding.source_context,
        subject_digest=subject_digest,
        subject_index=subject_index,
        subject_tag=subject_tag,
        tracked_authority=_tracked_authority(
            adapter,
            authority_digest=authority_digest,
            authority_tag=authority_tag,
            bundle=bundle,
            manifest=manifest,
            receipt=receipt,
        ),
        transition_kind=transition_kind,
        verification=binding.verification,
    )
    return _confirm_final_state(adapter, oci, created)


def producer_finalize(  # noqa: PLR0912, PLR0915 - explicit fail-closed ceremony
    adapter: FinalizationAdapter,
    *,
    aggregation: Mapping[str, Any],
    extraction_root: Path,
    github: GitHubClient | None,
    manifest: Mapping[str, Any],
    now: Any,
    oci: OCIClient | None,
    policy: Mapping[str, Any],
    policy_raw: bytes,
    recovery_polls: int,
    signer: Signer | None,
    trusted_root_raw: bytes | None,
) -> FinalizationResult:
    """Finalize one material after an unconditional readiness barrier.

    No aggregation/extraction path, client, token, process, registry, or output
    is inspected before ``require_ready``.  CLI adapters must likewise load
    only policy/trusted-root bytes before invoking their first readiness check.
    """

    adapter.require_ready(policy, trusted_root_raw=trusted_root_raw, now=now)
    _assert_oci_runtime_contract(adapter)

    if github is None or oci is None or signer is None:
        _die("live authenticated producer clients were not injected")
    if getattr(signer, "boundary_format", None) != SIGNER_BOUNDARY_FORMAT:
        _die("producer signer does not expose the reviewed fd-bound Cosign boundary")
    if not isinstance(trusted_root_raw, bytes) or not trusted_root_raw:
        _die("producer trusted-root literal bytes are absent")
    if isinstance(recovery_polls, bool) or not isinstance(recovery_polls, int):
        _die("authority recovery poll bound must be one integer")
    if recovery_polls < 0 or recovery_polls > 16:
        _die("authority recovery poll bound is outside 0..16")
    common = adapter.common
    parsed_policy = common.parse_json(policy_raw, context="producer authority policy")
    if (
        parsed_policy != policy
        or common.canonical_json(parsed_policy, terminal_lf=True) != policy_raw
    ):
        _die("producer policy mapping and canonical literal bytes differ")
    policy_sha256 = common.sha256(policy_raw)
    original_manifest = _canonical_copy(
        common,
        _mapping(manifest, "producer tracked manifest"),
        "producer tracked manifest",
    )
    adapter.validate_manifest_authority(original_manifest, policy_raw)
    github_evidence = github.current_evidence(profile=adapter.profile)
    if not isinstance(github_evidence, GitHubEvidence):
        _die("GitHub current evidence has the wrong type")
    expected_identities = common.exact_object(
        github_evidence.expected_identities,
        set(adapter.platforms),
        "authenticated expected platform identities",
    )
    validated = adapter.validate_platform_aggregation(
        aggregation,
        policy_raw=policy_raw,
        expected_identities=expected_identities,
    )
    validated = _validate_aggregation_shape(
        adapter,
        validated,
        policy_sha256=policy_sha256,
    )
    before_extraction = adapter.material_build.file_records(
        extraction_root,
        exclude=frozenset(),
    )
    platform_oci = _derive_oci_platforms(adapter, validated, extraction_root)
    subject_index = _derive_subject_index(adapter, platform_oci)
    subject_digest = common.digest(subject_index)
    subject_tag = common.derived_tag(adapter.profile, subject_digest, authority=False)
    binding = adapter.bind_oci_platform_results(
        validated,
        platform_oci,
        original_manifest,
        policy,
        github_evidence.generator,
        extraction_root=extraction_root,
        subject_index=subject_index,
    )
    binding = _crossbind_material(
        adapter,
        binding,
        validated,
        github_evidence,
        platform_oci,
        subject_index,
        original_manifest,
    )
    after_extraction = adapter.material_build.file_records(
        extraction_root,
        exclude=frozenset(),
    )
    if before_extraction != after_extraction:
        _die("platform aggregation extraction changed during finalization derivation")

    existing_subject = oci.get_manifest(
        reference=subject_tag,
        repository=adapter.profile.repository,
        media_type=common.OCI_INDEX,
    )
    authorization: RecoveryAuthorization | None = None
    creation_protection: dict[str, Any] | None = None
    if existing_subject is None:
        creation_protection = _validate_subject_creation_authorization(
            adapter,
            oci.authorize_subject_creation(
                profile=adapter.profile,
                subject_digest=subject_digest,
                subject_tag=subject_tag,
            ),
            subject_digest=subject_digest,
            subject_tag=subject_tag,
        )
        _upload_subject_graph(
            adapter,
            oci,
            platform_oci,
            subject_digest,
            subject_index,
            subject_tag,
        )
    elif existing_subject == subject_index:
        authorization = github.authorize_subject_recovery(
            aggregation=validated,
            profile=adapter.profile,
            subject_digest=subject_digest,
        )
        if not isinstance(authorization, RecoveryAuthorization):
            _die("existing exact subject lacks authenticated recovery authority")
        if not isinstance(authorization.authority_publication_started, bool):
            _die("existing exact subject recovery publication state is not boolean")
    else:
        _die("immutable subject tag contains conflicting bytes")
    _validate_subject_graph(
        adapter,
        oci,
        platform_oci,
        subject_digest,
        subject_index,
        subject_tag,
    )
    transition = _transition(adapter, authorization)
    candidate_arguments = {
        "aggregation": validated,
        "binding": binding,
        "expected_identities": expected_identities,
        "platform_oci": platform_oci,
        "policy": policy,
        "policy_raw": policy_raw,
        "subject_digest": subject_digest,
        "subject_index": subject_index,
        "subject_tag": subject_tag,
        "trusted_root_raw": trusted_root_raw,
    }
    valid = _discover_valid_candidates(adapter, oci, signer, **candidate_arguments)
    if valid:
        return _confirm_final_state(adapter, oci, valid[0])
    if authorization is not None and authorization.authority_publication_started:
        for _attempt in range(recovery_polls):
            valid = _discover_valid_candidates(adapter, oci, signer, **candidate_arguments)
            if valid:
                return _confirm_final_state(adapter, oci, valid[0])
        _die("settled authority recovery found no valid candidate after bounded polling")

    oci_evidence = oci.receipt_evidence(
        profile=adapter.profile,
        subject_digest=subject_digest,
        subject_index=subject_index,
        subject_tag=subject_tag,
        subject_tag_put_by_current_run=authorization is None,
    )
    if creation_protection is not None and (
        not isinstance(oci_evidence, OCIReceiptEvidence)
        or _canonical_copy(
            common,
            _mapping(oci_evidence.protection, "post-create Docker Hub protection"),
            "post-create Docker Hub protection",
        )
        != creation_protection
    ):
        _die("post-create protection differs from authenticated immutable-rule preflight")
    _receipt, receipt_raw = _assemble_receipt(
        adapter,
        aggregation=validated,
        binding=binding,
        expected_identities=expected_identities,
        github=github_evidence,
        oci=oci_evidence,
        policy_raw=policy_raw,
        transition=transition,
    )
    bundle_raw = signer.sign(profile=adapter.profile, receipt=receipt_raw)
    bundle = common.parse_json(bundle_raw, context="producer Sigstore bundle")
    if common.canonical_json(bundle, terminal_lf=True) != bundle_raw:
        _die("producer signer returned a noncanonical bundle")
    _verify_signed_receipt(
        adapter,
        signer,
        bundle_raw=bundle_raw,
        policy=policy,
        receipt=_receipt,
        receipt_raw=receipt_raw,
        trusted_root_raw=trusted_root_raw,
    )
    return _publish_authority(
        adapter,
        oci,
        signer,
        aggregation=validated,
        binding=binding,
        bundle=bundle_raw,
        expected_identities=expected_identities,
        platform_oci=platform_oci,
        policy=policy,
        policy_raw=policy_raw,
        receipt=receipt_raw,
        recovery_polls=recovery_polls,
        subject_digest=subject_digest,
        subject_index=subject_index,
        subject_tag=subject_tag,
        trusted_root_raw=trusted_root_raw,
        transition_kind=str(transition["kind"]),
    )


def _open_direct_directory(path: Path) -> int:
    absolute = path.absolute()
    if (
        not path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts[1:])
        or not absolute.parts
        or absolute.parts[0] != "/"
        or any(part in {"", ".", ".."} for part in absolute.parts[1:])
    ):
        _die("producer output path is not one absolute direct path")
    descriptor = os.open(
        "/",
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        for part in absolute.parts[1:]:
            child = os.open(
                part,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _directory_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid)


def _rename_exchange(parent: int, source: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "renameat2", None)
    if function is None:
        _die("atomic producer output directory exchange is unavailable")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    if (
        function(
            parent,
            os.fsencode(source),
            parent,
            os.fsencode(destination),
            2,  # Linux RENAME_EXCHANGE
        )
        != 0
    ):
        error = ctypes.get_errno()
        raise FinalizationError(
            f"atomic producer output directory exchange failed: {os.strerror(error)}"
        )


def _write_output_file(directory: int, name: str, raw: bytes) -> None:
    descriptor = os.open(
        name,
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=directory,
    )
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                _die("producer output write made no progress")
            offset += written
        os.fsync(descriptor)
        observed = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        readback = bytearray()
        while len(readback) < len(raw):
            chunk = os.read(descriptor, min(1024 * 1024, len(raw) - len(readback)))
            if not chunk:
                _die("producer output readback is truncated")
            readback.extend(chunk)
        if (
            bytes(readback) != raw
            or os.read(descriptor, 1)
            or not stat.S_ISREG(observed.st_mode)
            or stat.S_IMODE(observed.st_mode) != 0o600
            or observed.st_nlink != 1
            or observed.st_uid != os.getuid()
            or observed.st_size != len(raw)
        ):
            _die("producer output inode/bytes differ after write")
    finally:
        os.close(descriptor)


def _verify_output_files(directory: int, files: Sequence[tuple[str, bytes]]) -> None:
    if set(os.listdir(directory)) != {name for name, _raw in files}:
        _die("producer output directory does not contain exactly R/B/M")
    for name, raw in files:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory,
        )
        try:
            observed = os.fstat(descriptor)
            chunks: list[bytes] = []
            remaining = len(raw)
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    _die("published producer output readback is truncated")
                chunks.append(chunk)
                remaining -= len(chunk)
            if (
                b"".join(chunks) != raw
                or os.read(descriptor, 1)
                or not stat.S_ISREG(observed.st_mode)
                or stat.S_IMODE(observed.st_mode) != 0o600
                or observed.st_nlink != 1
                or observed.st_uid != os.getuid()
                or observed.st_size != len(raw)
            ):
                _die("published producer output inode/bytes differ")
        finally:
            os.close(descriptor)


def _rollback_output_exchange(
    parent: int,
    *,
    output_name: str,
    output_descriptor: int,
    output_state: os.stat_result,
    parent_state: os.stat_result,
    staging_name: str,
    staging_descriptor: int,
    staging_state: os.stat_result,
) -> None:
    """Restore the retained empty output inode after an uncommitted exchange."""

    if (
        _directory_identity(os.fstat(parent)) != _directory_identity(parent_state)
        or _directory_identity(os.fstat(output_descriptor)) != _directory_identity(output_state)
        or _directory_identity(os.fstat(staging_descriptor)) != _directory_identity(staging_state)
        or _directory_identity(os.stat(output_name, dir_fd=parent, follow_symlinks=False))
        != _directory_identity(staging_state)
        or _directory_identity(os.stat(staging_name, dir_fd=parent, follow_symlinks=False))
        != _directory_identity(output_state)
        or os.listdir(output_descriptor)
    ):
        _die("uncommitted producer output exchange cannot be safely rolled back")
    _rename_exchange(parent, staging_name, output_name)
    os.fsync(parent)
    if (
        _directory_identity(os.stat(output_name, dir_fd=parent, follow_symlinks=False))
        != _directory_identity(output_state)
        or _directory_identity(os.stat(staging_name, dir_fd=parent, follow_symlinks=False))
        != _directory_identity(staging_state)
        or os.listdir(output_descriptor)
    ):
        _die("producer output rollback readback differs")


def write_finalization_output(  # noqa: PLR0912, PLR0915 - atomic R/B/M transaction
    output: Path,
    result: FinalizationResult,
    *,
    profile: Any,
) -> None:
    """Atomically exchange a staged exact R/B/M set into a pre-created output."""

    if output.name in {"", ".", ".."} or "/" in output.name or not output.is_absolute():
        _die("producer output path is unsafe")
    files = (
        (profile.receipt_filename, result.receipt),
        (profile.bundle_filename, result.bundle),
        (profile.artifact_filename, result.authority_manifest),
    )
    if len({name for name, _raw in files}) != 3 or any(
        Path(name).name != name or name in {"", ".", ".."} or not isinstance(raw, bytes)
        for name, raw in files
    ):
        _die("producer output filename/bytes differ")
    parent = _open_direct_directory(output.parent)
    output_descriptor = -1
    staging_descriptor = -1
    staging_name = ""
    exchanged = False
    committed = False
    written: list[str] = []
    try:
        parent_state = os.fstat(parent)
        if parent_state.st_uid != os.getuid() or stat.S_IMODE(parent_state.st_mode) & 0o077:
            _die("producer output parent is not owner-private")
        output_descriptor = os.open(
            output.name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent,
        )
        output_state = os.fstat(output_descriptor)
        if (
            not stat.S_ISDIR(output_state.st_mode)
            or stat.S_IMODE(output_state.st_mode) != 0o700
            or output_state.st_uid != os.getuid()
            or os.listdir(output_descriptor)  # noqa: PTH208
        ):
            _die("producer output must be one empty owner-private 0700 directory")
        for _attempt in range(8):
            candidate = f".z4j-finalize-stage-{os.getrandom(16).hex()}"
            try:
                os.mkdir(candidate, 0o700, dir_fd=parent)
            except FileExistsError:
                continue
            staging_name = candidate
            break
        if not staging_name:
            _die("producer output staging name could not be allocated")
        staging_descriptor = os.open(
            staging_name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent,
        )
        os.fchmod(staging_descriptor, 0o700)
        staging_state = os.fstat(staging_descriptor)
        for name, raw in files:
            written.append(name)
            _write_output_file(staging_descriptor, name, raw)
        os.fsync(staging_descriptor)
        _verify_output_files(staging_descriptor, files)
        if (
            _directory_identity(os.stat(output.name, dir_fd=parent, follow_symlinks=False))
            != _directory_identity(output_state)
            or _directory_identity(os.stat(staging_name, dir_fd=parent, follow_symlinks=False))
            != _directory_identity(staging_state)
            or os.listdir(output_descriptor)  # noqa: PTH208
            or _directory_identity(os.fstat(parent)) != _directory_identity(parent_state)
        ):
            _die("producer output/staging/parent binding changed before exchange")
        _rename_exchange(parent, staging_name, output.name)
        exchanged = True
        published = os.open(
            output.name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent,
        )
        try:
            if _directory_identity(os.fstat(published)) != _directory_identity(staging_state):
                _die("atomically published producer output inode differs")
            _verify_output_files(published, files)
        finally:
            os.close(published)
        if (
            _directory_identity(os.stat(staging_name, dir_fd=parent, follow_symlinks=False))
            != _directory_identity(output_state)
            or os.listdir(output_descriptor)  # noqa: PTH208
        ):
            _die("swapped-out empty producer output inode differs")
        os.fsync(parent)
        committed = True
        os.close(output_descriptor)
        output_descriptor = -1
        stale_name = staging_name
        staging_name = ""
        try:
            os.rmdir(stale_name, dir_fd=parent)
        except OSError:
            # R/B/M is already verified and parent-fsynced.  Stale-old cleanup
            # is maintenance, not a reason to report the committed transaction
            # as absent or to exchange it back.
            pass
        else:
            with contextlib.suppress(OSError):
                os.fsync(parent)
    except BaseException:
        if exchanged and not committed:
            try:
                _rollback_output_exchange(
                    parent,
                    output_name=output.name,
                    output_descriptor=output_descriptor,
                    output_state=output_state,
                    parent_state=parent_state,
                    staging_name=staging_name,
                    staging_descriptor=staging_descriptor,
                    staging_state=staging_state,
                )
                exchanged = False
            except BaseException as rollback_failure:
                raise FinalizationError(
                    "producer output failed before commit and rollback could not be proven"
                ) from rollback_failure
        raise
    finally:
        if staging_name and not exchanged and staging_descriptor >= 0:
            for name in written:
                with contextlib.suppress(OSError):
                    os.unlink(name, dir_fd=staging_descriptor)
        if staging_descriptor >= 0:
            os.close(staging_descriptor)
        if output_descriptor >= 0:
            os.close(output_descriptor)
        if staging_name and not exchanged:
            with contextlib.suppress(OSError):
                os.rmdir(staging_name, dir_fd=parent)
        os.close(parent)
