#!/usr/bin/env python3
"""Publish and verify subject-bound OCI 1.1 rollback evidence.

The tool deliberately uses the OCI Distribution HTTP API directly. Evidence
manifests are addressed only by their digest: it never creates or changes a
tag. Every successful operation rereads the referrers response, artifact
manifest, config, all role blobs, and every receipt-authenticated payload
layer as raw bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
RECORD_FORMAT = "z4j-rollback-compat-durable-evidence-record-v1"
CONFIG_FORMAT = "z4j-rollback-compat-durable-evidence-config-v1"
INDEX_FORMAT = "z4j-rollback-compat-release-evidence-index-v1"
COMPLETION_FORMAT = "z4j-rollback-compat-release-index-completion-v1"
GRAPH_FORMAT = "z4j-rollback-compat-portable-evidence-graph-verification-v1"
MATERIALIZATION_FORMAT = "z4j-rollback-compat-original-evidence-materialization-v1"
QUALIFICATION_REPLAY_FORMAT = "z4j-rollback-compat-qualification-replay-authority-v1"
NORMAL_IDENTITY = (
    "https://github.com/z4jdev/z4j/.github/workflows/release-rollback-compat.yml@refs/heads/main"
)
RECOVERY_IDENTITY = (
    "https://github.com/z4jdev/z4j/.github/workflows/"
    "recover-rollback-compat-promotion.yml@refs/heads/main"
)
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
HEX = re.compile(r"[0-9a-f]{64}")
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_PAYLOAD_BYTES = 100 * 1024 * 1024
MAX_PORTABLE_GRAPH_BYTES = 1024 * 1024 * 1024
MAX_PORTABLE_GRAPH_FILES = 4096
MAX_REFERRER_PAGES = 128
MAX_REFERRER_DESCRIPTORS = 4096
MAX_REFERRER_BYTES = 64 * 1024 * 1024
SYSTEM_CA_BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")
REGISTRY_AUTHORITY_ERROR = (
    "common signed E0 runtime-registry settings authority and PAT-HMAC validator "
    "are unavailable; live rollback OCI access is blocked"
)
COSIGN_AUTHORITY_ERROR = "finalized manifest-bound Cosign byte and version authority is unavailable"
EXPECTED_PREDECESSORS: dict[str, tuple[str, ...]] = {
    "qualification": (),
    "finalization": ("qualification",),
    "promotion": ("finalization",),
    "recovery": ("finalization",),
    "release-index": ("promotion", "recovery"),
}


class EvidenceError(RuntimeError):
    """The evidence graph or its registry representation is invalid."""


class EvidenceAbsentError(EvidenceError):
    """The requested, otherwise valid, filtered referrer set is empty."""


def fail(message: str) -> None:
    raise EvidenceError(message)


def require_runtime_registry_authority() -> None:
    legacy = sorted(
        name for name in ("DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN") if os.environ.get(name)
    )
    if legacy:
        fail("legacy Docker Hub credential aliases are forbidden")
    fail(REGISTRY_AUTHORITY_ERROR)


def require_cosign_binary_authority() -> None:
    # The finalized compatibility manifest will eventually carry the exact
    # per-platform bytes and version transcript. Until that reviewed producer
    # lands, no PATH-selected or caller-selected executable is authority.
    fail(COSIGN_AUTHORITY_ERROR)


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw)


def file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def directory_locator_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
    )


def _directory_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        fail("this platform cannot perform held no-follow directory operations")
    return os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY


def _open_directory_chain(path: Path, *, create: bool) -> list[int]:
    path = Path(path)
    flags = _directory_flags()
    if path.is_absolute():
        descriptors = [os.open("/", flags)]
        parts = path.parts[1:]
    else:
        descriptors = [os.open(".", flags)]
        parts = path.parts
    try:
        current = descriptors[-1]
        for part in parts:
            if part in ("", ".", "..") or "/" in part or "\\" in part:
                fail(f"directory path is not canonical: {path}")
            try:
                child = os.open(part, flags, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise EvidenceError(f"required directory is absent: {path}") from None
                os.mkdir(part, mode=0o700, dir_fd=current)
                os.fsync(current)
                child = os.open(part, flags, dir_fd=current)
            except OSError as exc:
                raise EvidenceError(f"directory cannot be opened safely: {path}") from exc
            descriptors.append(child)
            current = child
        return descriptors
    except Exception:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def _close_descriptors(descriptors: Sequence[int]) -> None:
    for descriptor in reversed(descriptors):
        os.close(descriptor)


def _assert_chain_still_names_same_directories(path: Path, descriptors: Sequence[int]) -> None:
    original = tuple(directory_locator_identity(os.fstat(item)) for item in descriptors)
    reopened = _open_directory_chain(path, create=False)
    try:
        observed = tuple(directory_locator_identity(os.fstat(item)) for item in reopened)
    finally:
        _close_descriptors(reopened)
    if observed != original:
        fail(f"directory path changed while authority bytes were accessed: {path}")


def _require_private_directory(info: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(info.st_mode):
        fail(f"{label} is not a real directory")
    if info.st_uid != os.geteuid():
        fail(f"{label} is not owned by the effective user")
    if stat.S_IMODE(info.st_mode) != 0o700:
        fail(f"{label} is not owner-private mode 0700")
    if info.st_nlink < 1:
        fail(f"{label} has an invalid link count")


def _read_regular_descriptor(
    descriptor: int,
    *,
    label: str,
    maximum: int,
    require_private: bool,
) -> bytes:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        fail(f"{label} is not a real regular file")
    if before.st_nlink != 1:
        fail(f"{label} has multiple hard links")
    if require_private and (before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600):
        fail(f"{label} is not an owner-private mode-0600 file")
    if before.st_size <= 0 or before.st_size > maximum:
        fail(f"{label} has an invalid size")
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    after = os.fstat(descriptor)
    raw = b"".join(chunks)
    if (
        file_identity(before) != file_identity(after)
        or len(raw) != before.st_size
        or len(raw) > maximum
    ):
        fail(f"{label} changed while being read")
    return raw


class PrivateDirectory:
    """A held owner-private directory whose pathname is rechecked on close."""

    def __init__(self, path: Path, *, create: bool) -> None:
        self.path = Path(path)
        self._descriptors = _open_directory_chain(self.path, create=create)
        self.descriptor = self._descriptors[-1]
        _require_private_directory(os.fstat(self.descriptor), "private authority root")
        self._closed = False

    def __enter__(self) -> PrivateDirectory:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        try:
            _require_private_directory(os.fstat(self.descriptor), "private authority root")
            _assert_chain_still_names_same_directories(self.path, self._descriptors)
        finally:
            self._closed = True
            _close_descriptors(self._descriptors)

    def _open_parent(self, relative: str, *, create: bool) -> tuple[list[int], str]:
        relative = safe_relative_path(relative)
        parts = PurePosixPath(relative).parts
        descriptors = [os.dup(self.descriptor)]
        try:
            current = descriptors[-1]
            for part in parts[:-1]:
                try:
                    child = os.open(part, _directory_flags(), dir_fd=current)
                except FileNotFoundError:
                    if not create:
                        raise EvidenceError(
                            f"private authority directory is absent: {relative}"
                        ) from None
                    os.mkdir(part, mode=0o700, dir_fd=current)
                    os.fsync(current)
                    child = os.open(part, _directory_flags(), dir_fd=current)
                except OSError as exc:
                    raise EvidenceError(
                        f"private authority directory cannot be opened safely: {relative}"
                    ) from exc
                _require_private_directory(os.fstat(child), f"private authority directory {part}")
                descriptors.append(child)
                current = child
            return descriptors, parts[-1]
        except Exception:
            _close_descriptors(descriptors)
            raise

    def mkdir(self, relative: str) -> None:
        marker = safe_relative_path(relative) + "/.directory-marker"
        descriptors, _marker = self._open_parent(marker, create=True)
        try:
            os.fsync(descriptors[-1])
        finally:
            _close_descriptors(descriptors)

    def write(self, relative: str, raw: bytes, *, skip_existing_exact: bool) -> None:
        descriptors, name = self._open_parent(relative, create=True)
        current = descriptors[-1]
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            try:
                output = os.open(name, flags, 0o600, dir_fd=current)
            except FileExistsError:
                if not skip_existing_exact:
                    fail(f"refusing to overwrite materialized evidence: {relative}")
                try:
                    existing = os.open(
                        name,
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=current,
                    )
                except OSError as exc:
                    raise EvidenceError(
                        f"existing materialized evidence cannot be opened safely: {relative}"
                    ) from exc
                try:
                    existing_raw = _read_regular_descriptor(
                        existing,
                        label=f"existing materialized evidence {relative}",
                        maximum=max(len(raw), 1),
                        require_private=True,
                    )
                finally:
                    os.close(existing)
                if existing_raw != raw:
                    fail(f"existing materialized evidence differs: {relative}")
                return
            try:
                with os.fdopen(output, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                check = os.open(
                    name,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=current,
                )
                try:
                    observed = _read_regular_descriptor(
                        check,
                        label=f"new materialized evidence {relative}",
                        maximum=max(len(raw), 1),
                        require_private=True,
                    )
                finally:
                    os.close(check)
                if observed != raw:
                    fail(f"new materialized evidence differs after write: {relative}")
                os.fsync(current)
            except Exception:
                with suppress(OSError):
                    os.unlink(name, dir_fd=current)
                raise
        finally:
            _close_descriptors(descriptors)


def strict_json(raw: bytes, label: str) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                fail(f"{label} contains duplicate JSON keys")
            value[key] = item
        return value

    def reject_number(value: str) -> Any:
        fail(f"{label} contains a floating or non-finite JSON number: {value}")

    try:
        return json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_constant=reject_number,
            parse_float=reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"{label} is invalid JSON") from exc


def regular_bytes(path: Path, *, maximum: int = MAX_JSON_BYTES) -> bytes:
    path = Path(path)
    parent_descriptors = _open_directory_chain(path.parent, create=False)
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_descriptors[-1],
            )
        except FileNotFoundError as exc:
            raise EvidenceError(f"required file is absent: {path}") from exc
        except OSError as exc:
            raise EvidenceError(f"required file cannot be opened safely: {path}") from exc
        try:
            raw = _read_regular_descriptor(
                descriptor,
                label=f"required file {path}",
                maximum=maximum,
                require_private=False,
            )
            opened_identity = file_identity(os.fstat(descriptor))
        finally:
            os.close(descriptor)
        _assert_chain_still_names_same_directories(path.parent, parent_descriptors)
        reopened = os.open(
            path.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_descriptors[-1],
        )
        try:
            if file_identity(os.fstat(reopened)) != opened_identity:
                fail(f"required file pathname changed while being read: {path}")
        finally:
            os.close(reopened)
    finally:
        _close_descriptors(parent_descriptors)
    return raw


def json_value(path: Path, *, require_canonical: bool) -> tuple[dict[str, Any], bytes]:
    raw = regular_bytes(path)
    value = strict_json(raw, f"JSON document {path}")
    if not isinstance(value, dict):
        fail(f"JSON document must be an object: {path}")
    if require_canonical and raw != canonical(value):
        fail(f"JSON document is not canonical newline JSON: {path}")
    return value, raw


def write_private(path: Path, raw: bytes) -> None:
    write_private_relative(path.parent, path.name, raw, skip_existing_exact=False)


def write_private_relative(
    root: Path,
    relative: str,
    raw: bytes,
    *,
    skip_existing_exact: bool,
) -> None:
    """Write below a held private root without following any path component."""
    with PrivateDirectory(Path(root), create=True) as private:
        private.write(relative, raw, skip_existing_exact=skip_existing_exact)


@contextmanager
def private_tree_snapshot(source: Path) -> Iterator[Path]:  # noqa: PLR0915
    """Capture one coherent private tree through held descriptors."""
    source = Path(source)
    with PrivateDirectory(source, create=False) as held_source:
        source_before = file_identity(os.fstat(held_source.descriptor))
        with tempfile.TemporaryDirectory(prefix="z4j-durable-held-tree-") as temporary:
            snapshot = Path(temporary) / "root"
            snapshot.mkdir(mode=0o700)
            file_count = 0
            total_size = 0
            with PrivateDirectory(snapshot, create=False) as held_snapshot:

                def capture(  # noqa: PLR0912
                    directory: int, relative: PurePosixPath
                ) -> None:
                    nonlocal file_count, total_size
                    before = os.fstat(directory)
                    _require_private_directory(before, f"portable directory {relative}")
                    names = sorted(os.listdir(directory))
                    for name in names:
                        if name in ("", ".", "..") or "/" in name or "\\" in name:
                            fail("portable evidence contains a non-canonical member name")
                        member = relative / name
                        try:
                            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                        except OSError as exc:
                            raise EvidenceError(
                                f"portable evidence member cannot be inspected: {member}"
                            ) from exc
                        if stat.S_ISDIR(info.st_mode):
                            try:
                                child = os.open(name, _directory_flags(), dir_fd=directory)
                            except OSError as exc:
                                raise EvidenceError(
                                    f"portable evidence directory cannot be held: {member}"
                                ) from exc
                            try:
                                _require_private_directory(
                                    os.fstat(child), f"portable directory {member}"
                                )
                                held_snapshot.mkdir(member.as_posix())
                                capture(child, member)
                                if directory_locator_identity(os.fstat(child)) != (
                                    directory_locator_identity(info)
                                ):
                                    fail(f"portable evidence directory changed: {member}")
                            finally:
                                os.close(child)
                        elif stat.S_ISREG(info.st_mode):
                            file_count += 1
                            if file_count > MAX_PORTABLE_GRAPH_FILES:
                                fail("portable evidence graph has too many files")
                            try:
                                item = os.open(
                                    name,
                                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                    dir_fd=directory,
                                )
                            except OSError as exc:
                                raise EvidenceError(
                                    f"portable evidence file cannot be held: {member}"
                                ) from exc
                            try:
                                raw = _read_regular_descriptor(
                                    item,
                                    label=f"portable evidence file {member}",
                                    maximum=MAX_PAYLOAD_BYTES,
                                    require_private=True,
                                )
                            finally:
                                os.close(item)
                            total_size += len(raw)
                            if total_size > MAX_PORTABLE_GRAPH_BYTES:
                                fail("portable evidence graph exceeds the aggregate size bound")
                            held_snapshot.write(member.as_posix(), raw, skip_existing_exact=False)
                        else:
                            fail(f"portable evidence contains a special member: {member}")
                    if sorted(os.listdir(directory)) != names or file_identity(
                        os.fstat(directory)
                    ) != file_identity(before):
                        fail(f"portable evidence directory changed during capture: {relative}")

                capture(held_source.descriptor, PurePosixPath())
            if file_identity(os.fstat(held_source.descriptor)) != source_before:
                fail("portable evidence root changed during capture")
            yield snapshot


def descriptor(raw: bytes, media_type: str, *, name: str | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {
        "mediaType": media_type,
        "digest": digest(raw),
        "size": len(raw),
    }
    if name is not None:
        value["annotations"] = {"org.opencontainers.image.title": name}
    return value


def component_projection(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": value["annotations"]["org.opencontainers.image.title"],
        "mediaType": value["mediaType"],
        "digest": value["digest"],
        "size": value["size"],
    }


def artifact_projection(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "stage": record["stage"],
        "artifact_type": record["artifact_type"],
        "artifact": record["artifact"],
        "config": record["config"],
        "receipt": record["receipt"],
        "bundle": record["bundle"],
        "authentication": record["authentication"],
        "payload": record["payload"],
        "predecessor": record["predecessor"],
    }


def load_lock(path: Path) -> dict[str, Any]:
    lock, _ = json_value(path, require_canonical=False)
    try:
        policy = lock["publication_gate"]["durable_evidence"]
    except (KeyError, TypeError) as exc:
        raise EvidenceError("manifest lacks the durable-evidence policy") from exc
    if policy.get("record_format") != RECORD_FORMAT:
        fail("durable-evidence record format differs")
    if policy.get("config_format") != CONFIG_FORMAT:
        fail("durable-evidence config format differs")
    if policy.get("release_index_format") != INDEX_FORMAT:
        fail("durable-evidence release-index format differs")
    if policy.get("completion_format") != COMPLETION_FORMAT:
        fail("durable-evidence completion format differs")
    if policy.get("portable_graph_format") != GRAPH_FORMAT:
        fail("durable-evidence portable graph format differs")
    if policy.get("original_materialization_format") != MATERIALIZATION_FORMAT:
        fail("durable-evidence materialization format differs")
    if policy.get("manifest_media_type") != OCI_MANIFEST:
        fail("durable-evidence manifest media type differs")
    if policy.get("subject_media_type") != OCI_INDEX:
        fail("durable-evidence subject media type differs")
    if set(policy.get("stages", {})) != set(EXPECTED_PREDECESSORS):
        fail("durable-evidence stage policy differs")
    return lock


def policy_for(lock: Mapping[str, Any], stage: str) -> dict[str, Any]:
    if stage not in EXPECTED_PREDECESSORS:
        fail(f"unsupported durable-evidence stage: {stage}")
    policy = lock["publication_gate"]["durable_evidence"]
    stage_policy = policy["stages"][stage]
    expected = {
        "artifact_type",
        "receipt_media_type",
        "authentication_format",
        "identities",
        "predecessors",
    }
    if set(stage_policy) != expected:
        fail(f"{stage} durable-evidence policy keys differ")
    if tuple(stage_policy["predecessors"]) != EXPECTED_PREDECESSORS[stage]:
        fail(f"{stage} predecessor policy differs")
    identities = stage_policy["identities"]
    if (
        not isinstance(identities, list)
        or not identities
        or any(value not in (NORMAL_IDENTITY, RECOVERY_IDENTITY) for value in identities)
    ):
        fail(f"{stage} durable-evidence identities differ")
    return stage_policy


def validate_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        fail(f"{label} is not an OCI SHA-256 digest")
    return value


def validate_size(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        fail(f"{label} is not a positive integer")
    return value


def validate_authentication(
    authentication: Mapping[str, Any],
    *,
    expected_format: str,
    expected_identities: Sequence[str],
    receipt_raw: bytes,
    bundle_raw: bytes,
) -> None:
    required = {
        "format",
        "result",
        "method",
        "cosign_version",
        "identity",
        "issuer",
        "subject",
        "bundle",
        "verification",
    }
    if not required.issubset(authentication) or set(authentication) - (
        required | {"immutable_tag_authority"}
    ):
        fail("receipt authentication keys differ")
    if authentication["format"] != expected_format:
        fail("receipt authentication format differs")
    if authentication["result"] != "pass":
        fail("receipt authentication did not pass")
    if authentication["method"] != "sigstore-keyless-cosign-sign-blob":
        fail("receipt authentication method differs")
    if authentication["cosign_version"] != "3.1.3":
        fail("receipt authentication Cosign version differs")
    if authentication["issuer"] != "https://token.actions.githubusercontent.com":
        fail("receipt authentication issuer differs")
    if authentication["identity"] not in expected_identities:
        fail("receipt authentication workflow identity differs")

    def matches(value: object, raw: bytes) -> bool:
        if not isinstance(value, dict) or set(value) != {"path", "sha256", "size"}:
            return False
        safe_relative_path(value["path"])
        return value["sha256"] == sha256(raw) and value["size"] == len(raw)

    if not matches(authentication["subject"], receipt_raw):
        fail("receipt authentication subject seal differs")
    if not matches(authentication["bundle"], bundle_raw):
        fail("receipt authentication bundle seal differs")
    verification = authentication["verification"]
    if (
        not isinstance(verification, dict)
        or set(verification) != {"path", "sha256", "size", "verified"}
        or verification.get("verified") is not True
    ):
        fail("receipt authentication verification is absent")
    safe_relative_path(verification.get("path"))
    if (
        not isinstance(verification.get("sha256"), str)
        or HEX.fullmatch(verification["sha256"]) is None
    ):
        fail("receipt authentication verification SHA-256 is invalid")
    validate_size(verification.get("size"), "receipt verification size")


def load_record(path: Path) -> dict[str, Any]:
    value, _ = json_value(path, require_canonical=True)
    if value.get("format") != RECORD_FORMAT or value.get("result") != "pass":
        fail(f"invalid durable-evidence record: {path}")
    stage = value.get("stage")
    if stage not in EXPECTED_PREDECESSORS:
        fail(f"durable-evidence record has an invalid stage: {path}")
    validate_digest(value.get("subject", {}).get("digest"), "record subject digest")
    validate_size(value.get("subject", {}).get("size"), "record subject size")
    validate_digest(value.get("artifact", {}).get("digest"), "record artifact digest")
    validate_size(value.get("artifact", {}).get("size"), "record artifact size")
    return value


def predecessor_value(stage: str, predecessor: Mapping[str, Any] | None) -> object:
    allowed = EXPECTED_PREDECESSORS[stage]
    if not allowed:
        if predecessor is not None:
            fail(f"{stage} forbids a predecessor")
        return None
    if predecessor is None:
        fail(f"{stage} requires a predecessor")
    if predecessor.get("stage") not in allowed:
        fail(f"{stage} predecessor stage differs")
    return {
        "stage": predecessor["stage"],
        "artifact": predecessor["artifact"],
        "receipt": predecessor["receipt"],
    }


def safe_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        fail("evidence payload path is invalid")
    if "\\" in value or not value.isascii():
        fail("evidence payload path is not portable ASCII POSIX")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        fail("evidence payload path escapes its private root")
    normalized = path.as_posix()
    if normalized != value:
        fail("evidence payload path is not normalized")
    return normalized


def validate_layer_inventory(
    *,
    durable: Mapping[str, Any],
    stage_policy: Mapping[str, Any],
    role_layers: Sequence[Mapping[str, Any]],
    payload_layers: Sequence[Mapping[str, Any]],
) -> None:
    expected_role_media = (
        stage_policy["receipt_media_type"],
        durable["bundle_layer_media_type"],
        durable["authentication_layer_media_type"],
    )
    if len(role_layers) != len(expected_role_media):
        fail("durable evidence role layer count differs")
    titles: list[str] = []
    for item, media_type in zip(role_layers, expected_role_media, strict=True):
        if not isinstance(item, dict) or set(item) != {
            "mediaType",
            "digest",
            "size",
            "annotations",
        }:
            fail("durable evidence role layer descriptor keys differ")
        if item["mediaType"] != media_type:
            fail("durable evidence role layer media type differs")
        annotations = item["annotations"]
        if not isinstance(annotations, dict) or set(annotations) != {
            "org.opencontainers.image.title"
        }:
            fail("durable evidence role layer annotations differ")
        titles.append(safe_relative_path(annotations["org.opencontainers.image.title"]))
        validate_digest(item["digest"], "durable evidence role layer digest")
        validate_size(item["size"], "durable evidence role layer size")
    payload_titles: list[str] = []
    for item in payload_layers:
        if not isinstance(item, dict) or set(item) != {
            "mediaType",
            "digest",
            "size",
            "annotations",
        }:
            fail("durable evidence payload layer descriptor keys differ")
        if item["mediaType"] != durable["payload_layer_media_type"]:
            fail("durable evidence payload layer media type differs")
        annotations = item["annotations"]
        if not isinstance(annotations, dict) or set(annotations) != {
            "org.opencontainers.image.title"
        }:
            fail("durable evidence payload layer annotations differ")
        payload_titles.append(safe_relative_path(annotations["org.opencontainers.image.title"]))
        validate_digest(item["digest"], "durable evidence payload layer digest")
        validate_size(item["size"], "durable evidence payload layer size")
    if payload_titles != sorted(payload_titles):
        fail("durable evidence payload layer titles are not sorted")
    titles.extend(payload_titles)
    if len(titles) != len(set(titles)):
        fail("durable evidence layer titles are not unique")


def payload_entry(
    *, root: Path, relative: str, expected_sha256: object, expected_size: object | None
) -> tuple[dict[str, Any], bytes]:
    relative = safe_relative_path(relative)
    if not isinstance(expected_sha256, str) or HEX.fullmatch(expected_sha256) is None:
        fail(f"payload SHA-256 is invalid: {relative}")
    path = root.joinpath(*PurePosixPath(relative).parts)
    raw = regular_bytes(path, maximum=MAX_PAYLOAD_BYTES)
    if sha256(raw) != expected_sha256:
        fail(f"payload SHA-256 differs from signed receipt: {relative}")
    if expected_size is not None and len(raw) != validate_size(
        expected_size, f"payload size for {relative}"
    ):
        fail(f"payload size differs from signed receipt: {relative}")
    return (
        descriptor(
            raw,
            "application/vnd.z4j.rollback-compat.evidence-payload.v1",
            name=relative,
        ),
        raw,
    )


def receipt_payloads(  # noqa: PLR0912
    *, stage: str, receipt: Mapping[str, Any], root: Path | None
) -> tuple[tuple[dict[str, Any], bytes], ...]:
    evidence = receipt.get("evidence")
    if isinstance(evidence, dict) and isinstance(evidence.get("files"), list):
        if root is None:
            fail(f"{stage} receipt requires a payload root")
        rows = evidence["files"]
        if not rows:
            fail(f"{stage} signed evidence inventory is empty")
        result = []
        names = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"path", "sha256", "size"}:
                fail(f"{stage} signed evidence inventory entry differs")
            names.append(safe_relative_path(row["path"]))
            result.append(
                payload_entry(
                    root=root,
                    relative=row["path"],
                    expected_sha256=row["sha256"],
                    expected_size=row["size"],
                )
            )
        if names != sorted(names) or len(set(names)) != len(names):
            fail(f"{stage} signed evidence inventory is not sorted and unique")
        return tuple(result)

    if stage == "release-index":
        return ()
    if root is None:
        fail(f"{stage} receipt requires a payload root")

    requested: list[tuple[str, object, object | None]] = []
    if stage == "finalization":
        reread = receipt.get("registry_reread")
        proofs = receipt.get("proofs")
        authority = receipt.get("immutable_tag_authority")
        if (
            not isinstance(reread, dict)
            or not isinstance(proofs, dict)
            or not isinstance(authority, dict)
        ):
            fail("finalization receipt lacks referenced payload authority")
        requested.append(
            (
                "registry-reread/candidate.index.oci.json",
                reread["index"]["sha256"],
                reread["index"]["size"],
            )
        )
        for arch in ("amd64", "arm64"):
            for kind, filename in (
                ("manifest", "manifest.oci.json"),
                ("config", "config.oci.json"),
            ):
                sealed = reread["platforms"][arch][kind]
                requested.append(
                    (f"registry-reread/native/{arch}/{filename}", sealed["sha256"], sealed["size"])
                )
        proof_names = {
            "signature": "signature-verification.json",
            "sbom_attestation": "sbom-attestation-verification.json",
            "provenance": "provenance-verification.json",
        }
        for label, filename in proof_names.items():
            requested.append((f"proofs/{filename}", proofs[label]["sha256"], None))
        capture = authority["capture"]
        authority_auth = authority["authentication"]
        authority_auth_raw = canonical(authority_auth)
        requested.extend(
            [
                (capture["path"], capture["sha256"], capture["size"]),
                (
                    "docker-hub-immutable-tag-authority-authentication.json",
                    sha256(authority_auth_raw),
                    len(authority_auth_raw),
                ),
                (
                    authority_auth["bundle"]["path"],
                    authority_auth["bundle"]["sha256"],
                    authority_auth["bundle"]["size"],
                ),
                (
                    authority_auth["verification"]["path"],
                    authority_auth["verification"]["sha256"],
                    authority_auth["verification"]["size"],
                ),
            ]
        )
    elif stage in ("promotion", "recovery"):
        authority = receipt.get("immutable_tag_authority")
        if not isinstance(authority, dict):
            fail(f"{stage} receipt lacks referenced immutable authority payloads")
        for key in ("prewrite_reread", "bundle_reverification"):
            value = authority.get(key)
            if isinstance(value, dict) and {"path", "sha256", "size"}.issubset(value):
                requested.append((value["path"], value["sha256"], value["size"]))
        if not requested:
            fail(f"{stage} receipt has no signed payload descriptors")
    else:
        fail(f"{stage} receipt lacks an exact signed evidence.files inventory")

    requested.sort(key=lambda item: item[0])
    names = [safe_relative_path(item[0]) for item in requested]
    if len(set(names)) != len(names):
        fail(f"{stage} signed payload inventory contains duplicates")
    return tuple(
        payload_entry(
            root=root,
            relative=relative,
            expected_sha256=expected_sha,
            expected_size=expected_size,
        )
        for relative, expected_sha, expected_size in requested
    )


def combined_payloads(
    *,
    stage: str,
    receipt: Mapping[str, Any],
    authentication: Mapping[str, Any],
    root: Path | None,
) -> tuple[tuple[dict[str, Any], bytes], ...]:
    if root is None:
        fail(f"{stage} durable evidence requires an original payload root")
    payload = list(receipt_payloads(stage=stage, receipt=receipt, root=root))
    verification = authentication.get("verification")
    if not isinstance(verification, dict) or set(verification) != {
        "path",
        "sha256",
        "size",
        "verified",
    }:
        fail(f"{stage} receipt authentication verification descriptor differs")
    if verification["verified"] is not True:
        fail(f"{stage} receipt authentication verification did not pass")
    payload.append(
        payload_entry(
            root=root,
            relative=verification["path"],
            expected_sha256=verification["sha256"],
            expected_size=verification["size"],
        )
    )
    payload.sort(key=lambda item: item[0]["annotations"]["org.opencontainers.image.title"])
    names = [item[0]["annotations"]["org.opencontainers.image.title"] for item in payload]
    if len(names) != len(set(names)):
        fail(f"{stage} receipt and authentication payload inventories overlap")
    return tuple(payload)


def candidate_durable_projection(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "artifact": record["artifact"],
        "config": record["config"],
        "receipt": record["receipt"],
        "bundle": record["bundle"],
        "authentication": record["authentication"],
        "payload": record["payload"],
    }


def validate_qualification_replay_authority(  # noqa: PLR0912
    value: object,
    *,
    subject: Mapping[str, Any],
    lock: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "format",
        "qualification",
        "recipe",
        "candidate_image",
    }:
        fail("qualification replay authority keys differ")
    if value.get("format") != QUALIFICATION_REPLAY_FORMAT:
        fail("qualification replay authority format differs")
    qualification = value.get("qualification")
    if not isinstance(qualification, dict) or set(qualification) != {
        "run_id",
        "repository",
        "workflow_ref",
    }:
        fail("qualification replay run authority keys differ")
    run_id = qualification.get("run_id")
    if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
        fail("qualification replay run id differs")
    if (
        qualification.get("repository") != "z4jdev/z4j"
        or qualification.get("workflow_ref")
        != ".github/workflows/release-rollback-compat.yml@refs/heads/main"
    ):
        fail("qualification replay workflow authority differs")
    recipe = value.get("recipe")
    if not isinstance(recipe, dict) or set(recipe) != {
        "dockerfile_sha256",
        "verifier_sha256",
        "workflow_sha256",
    }:
        fail("qualification replay recipe authority keys differ")
    if any(not isinstance(item, str) or HEX.fullmatch(item) is None for item in recipe.values()):
        fail("qualification replay recipe SHA-256 differs")
    candidate = value.get("candidate_image")
    if not isinstance(candidate, dict) or set(candidate) != {
        "repository",
        "index",
        "platforms",
    }:
        fail("qualification replay candidate authority keys differ")
    if candidate.get("repository") != lock["candidate_image"]["repository"]:
        fail("qualification replay candidate repository differs")
    if candidate.get("index") != {
        "digest": subject["digest"],
        "size": subject["size"],
    }:
        fail("qualification replay candidate subject differs")
    platforms = candidate.get("platforms")
    if not isinstance(platforms, dict) or set(platforms) != {"amd64", "arm64"}:
        fail("qualification replay candidate platforms differ")
    for arch, platform in platforms.items():
        if not isinstance(platform, dict) or set(platform) != {"manifest", "config"}:
            fail(f"qualification replay {arch} platform keys differ")
        for kind, component in platform.items():
            if not isinstance(component, dict) or set(component) != {"digest", "size"}:
                fail(f"qualification replay {arch} {kind} descriptor keys differ")
            validate_digest(component["digest"], f"qualification replay {arch} {kind} digest")
            validate_size(component["size"], f"qualification replay {arch} {kind} size")
    return dict(value)


def qualification_replay_projection(receipt: object) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        fail("qualification replay receipt is not an object")
    if (
        receipt.get("format") != "z4j-rollback-compat-qualification-receipt-v1"
        or receipt.get("result") != "pass"
    ):
        fail("qualification replay receipt format or result differs")
    return {
        "format": QUALIFICATION_REPLAY_FORMAT,
        "qualification": receipt.get("qualification"),
        "recipe": receipt.get("recipe"),
        "candidate_image": receipt.get("candidate_image"),
    }


def validate_completion(  # noqa: PLR0912
    value: object, *, terminal_stage: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail("release-index completion authority is absent")
    common = {"format", "mode", "workflow_identity", "transition"}
    if value.get("format") != COMPLETION_FORMAT:
        fail("release-index completion format differs")
    mode = value.get("mode")
    if mode == "normal-promotion":
        if set(value) != common:
            fail("normal release-index completion keys differ")
        if terminal_stage != "promotion":
            fail("normal release-index completion requires promotion evidence")
        if value.get("workflow_identity") != NORMAL_IDENTITY:
            fail("normal release-index completion identity differs")
        if value.get("transition") != "authenticated-promotion-terminal-to-release-index":
            fail("normal release-index completion transition differs")
        return dict(value)

    expected_modes = {
        "recovery-completion-after-promotion": (
            "promotion",
            "authenticated-promotion-terminal-to-release-index-only",
        ),
        "recovery-after-tag-write": (
            "recovery",
            "authenticated-finalization-to-recovery-terminal-and-release-index",
        ),
    }
    if mode not in expected_modes:
        fail("release-index completion mode differs")
    if set(value) != common | {"recovery_run_id", "original_run_id", "source"}:
        fail("recovery release-index completion keys differ")
    required_terminal, required_transition = expected_modes[mode]
    if terminal_stage != required_terminal:
        fail("recovery release-index completion terminal differs")
    if value.get("workflow_identity") != RECOVERY_IDENTITY:
        fail("recovery release-index completion identity differs")
    if value.get("transition") != required_transition:
        fail("recovery release-index completion transition differs")
    for name in ("recovery_run_id", "original_run_id"):
        run_id = value.get(name)
        if not isinstance(run_id, str) or re.fullmatch(r"[1-9][0-9]*", run_id) is None:
            fail(f"release-index {name} is not a positive decimal string")
    source = value.get("source")
    if not isinstance(source, dict) or set(source) != {
        "repository",
        "ref",
        "workflow_path",
        "sha",
        "tree",
        "qualification_run_id",
    }:
        fail("recovery release-index source keys differ")
    if (
        source.get("repository") != "z4jdev/z4j"
        or source.get("ref") != "refs/heads/main"
        or source.get("workflow_path") != ".github/workflows/release-rollback-compat.yml"
    ):
        fail("recovery release-index source authority differs")
    for name in ("sha", "tree"):
        if (
            not isinstance(source.get(name), str)
            or re.fullmatch(r"[0-9a-f]{40}", source[name]) is None
        ):
            fail(f"recovery release-index source {name} differs")
    if (
        not isinstance(source.get("qualification_run_id"), str)
        or re.fullmatch(r"[1-9][0-9]*", source["qualification_run_id"]) is None
    ):
        fail("recovery release-index qualification run differs")
    return dict(value)


def validate_completion_against_terminal(  # noqa: PLR0912
    completion: Mapping[str, Any],
    *,
    terminal_stage: str,
    terminal_receipt: Mapping[str, Any],
) -> None:
    if terminal_stage == "recovery":
        recovery_of = terminal_receipt.get("recovery_of")
        qualification = terminal_receipt.get("qualification")
        source_authority = terminal_receipt.get("source")
        recovery_authority = terminal_receipt.get("recovery_authority")
        if not all(
            isinstance(value, dict)
            for value in (
                recovery_of,
                qualification,
                source_authority,
                recovery_authority,
            )
        ):
            fail("recovery receipt source authority is absent")
        expected_source = {
            "repository": recovery_of.get("repository"),
            "ref": "refs/heads/main",
            "workflow_path": recovery_of.get("workflow_path"),
            "sha": source_authority.get("finalization_git_sha"),
            "tree": source_authority.get("finalization_git_tree"),
            "qualification_run_id": str(qualification.get("run_id")),
        }
        if completion["original_run_id"] != str(recovery_of.get("run_id")):
            fail("recovery completion original run differs from recovery receipt")
        if completion["recovery_run_id"] != str(recovery_authority.get("run_id")):
            fail("recovery completion run differs from recovery receipt")
        if completion["source"] != expected_source:
            fail("recovery completion source differs from recovery receipt")
        return
    if terminal_stage != "promotion":
        fail("release-index terminal receipt stage differs")
    authority = terminal_receipt.get("promotion_authority")
    required = {
        "run_id",
        "repository",
        "workflow_path",
        "ref",
        "head_sha",
        "head_tree",
        "qualification_run_id",
    }
    if not isinstance(authority, dict) or set(authority) != required:
        fail("promotion receipt authority keys differ")
    for name in ("run_id", "qualification_run_id"):
        value = authority.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            fail(f"promotion receipt {name} differs")
    if (
        authority.get("repository") != "z4jdev/z4j"
        or authority.get("workflow_path") != ".github/workflows/release-rollback-compat.yml"
        or authority.get("ref") != "refs/heads/main"
    ):
        fail("promotion receipt source authority differs")
    for name in ("head_sha", "head_tree"):
        if (
            not isinstance(authority.get(name), str)
            or re.fullmatch(r"[0-9a-f]{40}", authority[name]) is None
        ):
            fail(f"promotion receipt {name} differs")
    if terminal_receipt.get("qualification_run_id") != authority["qualification_run_id"]:
        fail("promotion receipt qualification run bindings differ")
    if terminal_receipt.get("transition") != "created-under-immutable-rule":
        fail("promotion receipt transition differs")
    if completion["mode"] != "recovery-completion-after-promotion":
        return
    source = completion["source"]
    expected_source = {
        "repository": authority["repository"],
        "ref": authority["ref"],
        "workflow_path": authority["workflow_path"],
        "sha": authority["head_sha"],
        "tree": authority["head_tree"],
        "qualification_run_id": str(authority["qualification_run_id"]),
    }
    if completion["original_run_id"] != str(authority["run_id"]):
        fail("recovery completion original run differs from promotion authority")
    if source != expected_source:
        fail("recovery completion source differs from promotion authority")


def normal_completion() -> dict[str, Any]:
    return {
        "format": COMPLETION_FORMAT,
        "mode": "normal-promotion",
        "workflow_identity": NORMAL_IDENTITY,
        "transition": "authenticated-promotion-terminal-to-release-index",
    }


def release_index_value(
    *,
    lock: Mapping[str, Any],
    manifest_raw: bytes,
    records: Sequence[Mapping[str, Any]],
    completion: object,
) -> dict[str, Any]:
    if len(records) != 3:
        fail("release evidence index requires exactly three stage records")
    stages = [record["stage"] for record in records]
    if stages not in (
        ["qualification", "finalization", "promotion"],
        ["qualification", "finalization", "recovery"],
    ):
        fail("release evidence index stage order differs")
    subject = records[0]["subject"]
    if any(record["subject"] != subject for record in records):
        fail("release evidence index records have different subjects")
    if records[1]["predecessor"] != predecessor_value("finalization", records[0]):
        fail("release evidence finalization cross-link differs")
    if records[2]["predecessor"] != predecessor_value(records[2]["stage"], records[1]):
        fail("release evidence terminal cross-link differs")
    candidate = lock["candidate_image"]
    if candidate.get("finalized") is not True:
        fail("release evidence index requires a finalized candidate")
    if candidate["index"] != {"digest": subject["digest"], "size": subject["size"]}:
        fail("release evidence index subject differs from finalized candidate")
    if candidate.get("qualification_durable_evidence") != candidate_durable_projection(records[0]):
        fail("release evidence qualification authority differs from finalized candidate")
    completion_value = validate_completion(completion, terminal_stage=records[-1]["stage"])
    return {
        "format": INDEX_FORMAT,
        "result": "pass",
        "subject": subject,
        "manifest": {"sha256": sha256(manifest_raw), "size": len(manifest_raw)},
        "candidate_components": {
            "index": candidate["index"],
            "platforms": candidate["platforms"],
            "qualification_receipt_sha256": candidate["release_receipt_sha256"],
            "qualification_durable_evidence": candidate["qualification_durable_evidence"],
        },
        "evidence": [artifact_projection(record) for record in records],
        "terminal_stage": records[-1]["stage"],
        "completion": completion_value,
        "github_release_asset": {
            "published": False,
            "semantics": "retain-these-exact-bytes-for-eventual-immutable-release-asset",
        },
    }


@dataclass(frozen=True)
class BuiltArtifact:
    config: bytes
    manifest: bytes
    receipt: bytes
    bundle: bytes
    authentication: bytes
    config_descriptor: dict[str, Any]
    layer_descriptors: tuple[dict[str, Any], ...]
    payload_descriptors: tuple[dict[str, Any], ...]
    payload_raw: tuple[bytes, ...]
    manifest_descriptor: dict[str, Any]
    subject: dict[str, Any]
    predecessor: object


def build_artifact(
    *,
    lock: Mapping[str, Any],
    stage: str,
    subject_digest: str,
    subject_size: int,
    receipt_path: Path,
    bundle_path: Path,
    authentication_path: Path,
    payload_root: Path | None,
    predecessor: Mapping[str, Any] | None,
) -> BuiltArtifact:
    durable = lock["publication_gate"]["durable_evidence"]
    stage_policy = policy_for(lock, stage)
    subject = {
        "mediaType": durable["subject_media_type"],
        "digest": validate_digest(subject_digest, "subject digest"),
        "size": validate_size(subject_size, "subject size"),
    }
    receipt_value, receipt_raw = json_value(receipt_path, require_canonical=True)
    _, bundle_raw = json_value(bundle_path, require_canonical=False)
    authentication, authentication_raw = json_value(authentication_path, require_canonical=True)
    validate_authentication(
        authentication,
        expected_format=stage_policy["authentication_format"],
        expected_identities=stage_policy["identities"],
        receipt_raw=receipt_raw,
        bundle_raw=bundle_raw,
    )
    receipt_descriptor = descriptor(
        receipt_raw,
        stage_policy["receipt_media_type"],
        name=receipt_path.name,
    )
    bundle_descriptor = descriptor(
        bundle_raw,
        durable["bundle_layer_media_type"],
        name=bundle_path.name,
    )
    authentication_descriptor = descriptor(
        authentication_raw,
        durable["authentication_layer_media_type"],
        name=authentication_path.name,
    )
    payload = combined_payloads(
        stage=stage,
        receipt=receipt_value,
        authentication=authentication,
        root=payload_root,
    )
    payload_descriptors = tuple(item[0] for item in payload)
    validate_layer_inventory(
        durable=durable,
        stage_policy=stage_policy,
        role_layers=(receipt_descriptor, bundle_descriptor, authentication_descriptor),
        payload_layers=payload_descriptors,
    )
    if (
        authentication["subject"]["path"]
        != receipt_descriptor["annotations"]["org.opencontainers.image.title"]
    ):
        fail("receipt authentication subject path differs from receipt layer title")
    if (
        authentication["bundle"]["path"]
        != bundle_descriptor["annotations"]["org.opencontainers.image.title"]
    ):
        fail("receipt authentication bundle path differs from bundle layer title")
    if any(
        item["mediaType"] != durable["payload_layer_media_type"] for item in payload_descriptors
    ):
        fail("payload layer media type differs from manifest policy")
    predecessor_projection = predecessor_value(stage, predecessor)
    if stage == "release-index":
        completion = validate_completion(
            receipt_value.get("completion"), terminal_stage=predecessor["stage"]
        )
        if authentication["identity"] != completion["workflow_identity"]:
            fail("release-index identity differs from signed completion authority")
    config_value = {
        "format": durable["config_format"],
        "stage": stage,
        "artifact_type": stage_policy["artifact_type"],
        "subject": subject,
        "receipt": component_projection(receipt_descriptor),
        "bundle": component_projection(bundle_descriptor),
        "authentication": component_projection(authentication_descriptor),
        "payload": [component_projection(item) for item in payload_descriptors],
        "predecessor": predecessor_projection,
    }
    config_raw = canonical(config_value)
    config_descriptor = descriptor(config_raw, durable["config_media_type"])
    layers = (
        receipt_descriptor,
        bundle_descriptor,
        authentication_descriptor,
        *payload_descriptors,
    )
    manifest_value = {
        "schemaVersion": 2,
        "mediaType": durable["manifest_media_type"],
        "artifactType": stage_policy["artifact_type"],
        "config": config_descriptor,
        "layers": list(layers),
        "subject": subject,
    }
    manifest_raw = canonical(manifest_value)
    manifest_descriptor = {
        **descriptor(manifest_raw, durable["manifest_media_type"]),
        "artifactType": stage_policy["artifact_type"],
    }
    return BuiltArtifact(
        config=config_raw,
        manifest=manifest_raw,
        receipt=receipt_raw,
        bundle=bundle_raw,
        authentication=authentication_raw,
        config_descriptor=config_descriptor,
        layer_descriptors=layers,
        payload_descriptors=payload_descriptors,
        payload_raw=tuple(item[1] for item in payload),
        manifest_descriptor=manifest_descriptor,
        subject=subject,
        predecessor=predecessor_projection,
    )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        del args, kwargs


def _registry_opener() -> urllib.request.OpenerDirector:
    try:
        metadata = SYSTEM_CA_BUNDLE.stat(follow_symlinks=False)
    except OSError as exc:
        raise EvidenceError("fixed system CA bundle is absent or unsafe") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        fail("fixed system CA bundle is not root-owned and non-writable")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(SYSTEM_CA_BUNDLE))
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        _NoRedirectHandler(),
    )


def _response_header_values(headers: Any, name: str) -> list[str]:
    if hasattr(headers, "get_all"):
        values = headers.get_all(name, [])
    else:
        values = [
            value
            for key, value in headers.items()
            if isinstance(key, str) and key.lower() == name.lower()
        ]
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        fail(f"registry response {name} headers are invalid")
    for value in values:
        if "\r" in value or "\n" in value or value != value.strip():
            fail(f"registry response {name} header has folding or whitespace")
    return values


def _single_response_header(headers: Any, name: str) -> str:
    values = _response_header_values(headers, name)
    if len(values) != 1:
        fail(f"registry response must contain exactly one {name} header")
    return values[0]


def _optional_response_header(headers: Any, name: str) -> str | None:
    values = _response_header_values(headers, name)
    if len(values) > 1:
        fail(f"registry response contains duplicate {name} headers")
    return values[0] if values else None


def _content_type(headers: Any, expected: set[str]) -> str:
    observed = _single_response_header(headers, "Content-Type").split(";", 1)[0].lower()
    if observed not in expected:
        fail("registry response content type differs")
    return observed


def _next_referrer_url(
    headers: Any,
    *,
    current_url: str,
    base: str,
    repository: str,
    subject_digest: str,
    artifact_type: str,
) -> str | None:
    link = _optional_response_header(headers, "Link")
    if link is None:
        return None
    match = re.fullmatch(r'<([^<>]+)>; rel="next"', link)
    if match is None:
        fail("registry referrers Link header differs")
    value = urllib.parse.urljoin(current_url, match.group(1))
    parsed = urllib.parse.urlsplit(value)
    base_parts = urllib.parse.urlsplit(base)
    if (
        parsed.scheme != "https"
        or (parsed.scheme, parsed.netloc) != (base_parts.scheme, base_parts.netloc)
        or parsed.path != f"/v2/{repository}/referrers/{subject_digest}"
        or parsed.fragment
    ):
        fail("registry referrers pagination URL differs or crosses origin")
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if len(pairs) != len({key for key, _value in pairs}):
        fail("registry referrers pagination query contains duplicate keys")
    query = dict(pairs)
    if (
        set(query) - {"artifactType", "last", "n"}
        or query.get("artifactType") != artifact_type
        or not query.get("last")
        or query.get("n") != "100"
    ):
        fail("registry referrers pagination query differs")
    return value


def _referrer_page(raw: bytes) -> list[dict[str, Any]]:
    value = strict_json(raw, "registry referrers response")
    if not isinstance(value, dict) or set(value) != {"schemaVersion", "mediaType", "manifests"}:
        fail("registry referrers response keys differ")
    if value.get("schemaVersion") != 2 or value.get("mediaType") != OCI_INDEX:
        fail("registry referrers response is not an OCI index")
    manifests = value.get("manifests")
    if not isinstance(manifests, list) or any(not isinstance(item, dict) for item in manifests):
        fail("registry referrers response lacks descriptor objects")
    return manifests


class Registry:
    def __init__(self, *, base: str, repository: str, push: bool) -> None:
        parsed = urllib.parse.urlsplit(base)
        require_runtime_registry_authority()
        if parsed.scheme != "https" or not parsed.netloc or parsed.path not in ("", "/"):
            fail("registry must be an HTTPS origin without a path")
        if not re.fullmatch(
            r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+", repository
        ):
            fail("registry repository is invalid")
        del push
        # The reviewed E0 consumer will populate base/repository/token/opener only
        # after authenticating the exact PAT UUID, HMAC, permissions and repository.
        # The guard above is unconditional until that consumer lands.
        raise AssertionError("runtime registry authority guard unexpectedly returned")

    def _url(self, suffix: str) -> str:
        return f"{self.base}/v2/{self.repository}/{suffix}"

    def request(
        self,
        method: str,
        suffix_or_url: str,
        *,
        data: bytes | None = None,
        content_type: str | None = None,
        accept: str | None = None,
        expected: tuple[int, ...] = (200,),
        maximum: int = MAX_JSON_BYTES,
    ) -> tuple[bytes, Any, int]:
        url = suffix_or_url if suffix_or_url.startswith("https://") else self._url(suffix_or_url)
        parsed = urllib.parse.urlsplit(url)
        base = urllib.parse.urlsplit(self.base)
        if (parsed.scheme, parsed.netloc) != (base.scheme, base.netloc) or parsed.fragment:
            fail("registry attempted a cross-origin authenticated request")
        headers = {"Authorization": f"Bearer {self.token}"}
        if content_type:
            headers["Content-Type"] = content_type
        if accept:
            headers["Accept"] = accept
        request = urllib.request.Request(  # noqa: S310 - URL is HTTPS and same-origin checked
            url, method=method, data=data, headers=headers
        )
        try:
            with self.opener.open(request, timeout=60) as response:
                raw = response.read(maximum + 1)
                code = response.status
                response_headers = response.headers
                final_url = response.geturl()
        except urllib.error.HTTPError as exc:
            with exc:
                raw = exc.read(maximum + 1)
                code = exc.code
                response_headers = exc.headers
                final_url = exc.geturl()
        if len(raw) > maximum:
            fail("registry response exceeds the evidence size limit")
        if final_url != url:
            fail("registry response URL differs or redirected")
        if code not in expected:
            fail(f"registry {method} failed with HTTP {code}")
        return raw, response_headers, code

    def _referrer_snapshot(
        self, subject_digest: str, artifact_type: str
    ) -> tuple[bytes, tuple[tuple[str, bytes, str, str, str | None], ...]]:
        query = urllib.parse.urlencode({"artifactType": artifact_type, "n": "100"})
        current = self._url(f"referrers/{subject_digest}?{query}")
        manifests: list[dict[str, Any]] = []
        transcript: list[tuple[str, bytes, str, str, str | None]] = []
        total = 0
        seen_urls: set[str] = set()
        seen_descriptors: set[bytes] = set()
        for _page in range(MAX_REFERRER_PAGES):
            if current in seen_urls:
                fail("registry referrers pagination loop detected")
            seen_urls.add(current)
            raw, headers, _ = self.request("GET", current, accept=OCI_INDEX)
            total += len(raw)
            if total > MAX_REFERRER_BYTES:
                fail("registry referrers aggregate response is too large")
            content_type = _content_type(headers, {OCI_INDEX})
            filters = _single_response_header(headers, "OCI-Filters-Applied")
            if filters != "artifactType":
                fail("registry did not apply exact artifactType filtering")
            response_digest = _optional_response_header(headers, "Docker-Content-Digest")
            if response_digest is not None and response_digest != digest(raw):
                fail("registry referrers response digest differs")
            link = _optional_response_header(headers, "Link")
            transcript.append((current, raw, content_type, filters, link))
            for descriptor_value in _referrer_page(raw):
                encoded = canonical(descriptor_value)
                if encoded in seen_descriptors:
                    fail("registry referrers pages contain a duplicate descriptor")
                seen_descriptors.add(encoded)
                manifests.append(descriptor_value)
                if len(manifests) > MAX_REFERRER_DESCRIPTORS:
                    fail("registry referrers descriptor count exceeds limit")
            following = _next_referrer_url(
                headers,
                current_url=current,
                base=self.base,
                repository=self.repository,
                subject_digest=subject_digest,
                artifact_type=artifact_type,
            )
            if following is None:
                merged = canonical(
                    {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": manifests}
                )
                return merged, tuple(transcript)
            current = following
        fail("registry referrers pagination exceeds page limit")
        raise AssertionError("unreachable after referrers page-limit refusal")

    def referrers(self, subject_digest: str, artifact_type: str) -> bytes:
        first, first_transcript = self._referrer_snapshot(subject_digest, artifact_type)
        second, second_transcript = self._referrer_snapshot(subject_digest, artifact_type)
        if first != second or first_transcript != second_transcript:
            fail("registry referrers changed during complete paginated reread")
        return first

    def put_blob(self, raw: bytes) -> None:
        _, headers, _ = self.request("POST", "blobs/uploads/", expected=(202,))
        location = _single_response_header(headers, "Location")
        absolute = urllib.parse.urljoin(self.base, location)
        separator = "&" if "?" in absolute else "?"
        _, completed_headers, _ = self.request(
            "PUT",
            absolute + separator + urllib.parse.urlencode({"digest": digest(raw)}),
            data=raw,
            content_type="application/octet-stream",
            expected=(201,),
        )
        if _single_response_header(completed_headers, "Docker-Content-Digest") != digest(raw):
            fail("registry blob upload response digest differs")

    def put_manifest(self, raw: bytes) -> None:
        expected_digest = digest(raw)
        _, headers, _ = self.request(
            "PUT",
            f"manifests/{expected_digest}",
            data=raw,
            content_type=OCI_MANIFEST,
            expected=(201,),
        )
        observed = _single_response_header(headers, "Docker-Content-Digest")
        if observed != expected_digest:
            fail("registry manifest response digest differs")

    def get_manifest(self, value: str) -> bytes:
        raw, headers, _ = self.request("GET", f"manifests/{value}", accept=OCI_MANIFEST)
        _content_type(headers, {OCI_MANIFEST})
        observed = _single_response_header(headers, "Docker-Content-Digest")
        if observed != value or digest(raw) != value:
            fail("registry artifact manifest digest differs")
        return raw

    def get_blob(self, value: str) -> bytes:
        raw, headers, _ = self.request("GET", f"blobs/{value}", maximum=MAX_PAYLOAD_BYTES)
        _content_type(headers, {"application/octet-stream"})
        if _single_response_header(headers, "Docker-Content-Digest") != value:
            fail("registry evidence blob response digest differs")
        if digest(raw) != value:
            fail("registry evidence blob digest differs")
        return raw


def parse_referrers(raw: bytes, artifact: Mapping[str, Any]) -> None:
    try:
        value = strict_json(raw, "registry referrers response")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("registry referrers response is invalid JSON") from exc
    if not isinstance(value, dict) or value.get("schemaVersion") != 2:
        fail("registry referrers response is not an OCI index")
    manifests = value.get("manifests")
    if not isinstance(manifests, list):
        fail("registry referrers response lacks manifests")
    matches = [item for item in manifests if item == artifact]
    same_type = [
        item
        for item in manifests
        if isinstance(item, dict) and item.get("artifactType") == artifact.get("artifactType")
    ]
    if matches != [artifact] or same_type != [artifact]:
        fail("registry referrers response is missing or substitutes the exact artifact")


def verify_cosign(
    *, receipt_raw: bytes, bundle_raw: bytes, authentication: Mapping[str, Any], cosign: str
) -> None:
    require_cosign_binary_authority()
    executable = shutil.which(cosign) if "/" not in cosign else cosign
    if not executable or not Path(executable).is_file():
        fail("Cosign executable is absent")
    version = subprocess.run(  # noqa: S603
        [executable, "version"], capture_output=True, text=True, check=False, timeout=20
    )
    version_output = version.stdout + version.stderr
    if (
        version.returncode != 0
        or re.search(r"(?m)^GitVersion:\s+v3\.1\.3(?:\s|$)", version_output) is None
    ):
        fail("Cosign executable is not exact version 3.1.3")
    with tempfile.TemporaryDirectory(prefix="z4j-durable-cosign-") as temporary:
        root = Path(temporary)
        receipt = root / "receipt.json"
        bundle = root / "bundle.json"
        receipt.write_bytes(receipt_raw)
        bundle.write_bytes(bundle_raw)
        completed = subprocess.run(  # noqa: S603
            [
                executable,
                "verify-blob",
                "--bundle",
                str(bundle),
                "--certificate-identity",
                authentication["identity"],
                "--certificate-oidc-issuer",
                authentication["issuer"],
                str(receipt),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    if completed.returncode != 0:
        fail("Cosign rejected the durable receipt and bundle")


def verify_remote(  # noqa: PLR0912, PLR0915
    *,
    registry: Registry,
    lock: Mapping[str, Any],
    record: Mapping[str, Any],
    output_dir: Path,
    cosign: str,
) -> dict[str, Any]:
    stage = record["stage"]
    stage_policy = policy_for(lock, stage)
    if record["artifact_type"] != stage_policy["artifact_type"]:
        fail("durable record artifact type differs from policy")
    artifact = record["artifact"]
    referrers_raw = registry.referrers(record["subject"]["digest"], record["artifact_type"])
    parse_referrers(referrers_raw, artifact)
    manifest_raw = registry.get_manifest(artifact["digest"])
    if len(manifest_raw) != artifact["size"]:
        fail("registry artifact manifest size differs")
    try:
        manifest = strict_json(manifest_raw, "registry artifact manifest")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("registry artifact manifest is invalid JSON") from exc
    if manifest_raw != canonical(manifest):
        fail("registry artifact manifest is not the exact canonical bytes")
    if set(manifest) != {
        "schemaVersion",
        "mediaType",
        "artifactType",
        "config",
        "layers",
        "subject",
    }:
        fail("registry artifact manifest keys differ")
    if manifest["schemaVersion"] != 2 or manifest["mediaType"] != OCI_MANIFEST:
        fail("registry artifact manifest schema differs")
    if manifest["artifactType"] != record["artifact_type"]:
        fail("registry artifact manifest type differs")
    if manifest["subject"] != record["subject"]:
        fail("registry artifact subject differs")
    if manifest["config"] != record["config"]:
        fail("registry artifact config descriptor differs")
    payload_names = []
    payload_media_type = lock["publication_gate"]["durable_evidence"]["payload_layer_media_type"]
    for item in record["payload"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"mediaType", "digest", "size", "annotations"}
            or item["mediaType"] != payload_media_type
        ):
            fail("registry payload descriptor differs")
        validate_digest(item["digest"], "registry payload digest")
        validate_size(item["size"], "registry payload size")
        payload_names.append(
            safe_relative_path(item["annotations"].get("org.opencontainers.image.title"))
        )
    if payload_names != sorted(payload_names) or len(payload_names) != len(set(payload_names)):
        fail("registry payload inventory is not sorted and unique")
    validate_layer_inventory(
        durable=lock["publication_gate"]["durable_evidence"],
        stage_policy=stage_policy,
        role_layers=[record[name] for name in ("receipt", "bundle", "authentication")],
        payload_layers=record["payload"],
    )
    expected_layers = [record[name] for name in ("receipt", "bundle", "authentication")] + record[
        "payload"
    ]
    if manifest["layers"] != expected_layers:
        fail("registry artifact layer descriptors differ")

    config_raw = registry.get_blob(manifest["config"]["digest"])
    layer_raw = [registry.get_blob(item["digest"]) for item in manifest["layers"]]
    if len(config_raw) != manifest["config"]["size"]:
        fail("registry artifact config size differs")
    for item, raw in zip(manifest["layers"], layer_raw, strict=True):
        if len(raw) != item["size"]:
            fail("registry artifact layer size differs")
    try:
        config = strict_json(config_raw, "registry artifact config")
        receipt_value = strict_json(layer_raw[0], "registry artifact receipt")
        authentication = strict_json(layer_raw[2], "registry artifact authentication")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(
            "registry artifact config, receipt, or authentication is invalid"
        ) from exc
    if (
        config_raw != canonical(config)
        or layer_raw[0] != canonical(receipt_value)
        or layer_raw[2] != canonical(authentication)
    ):
        fail("registry config, receipt, or authentication is not canonical")
    expected_config = {
        "format": CONFIG_FORMAT,
        "stage": stage,
        "artifact_type": record["artifact_type"],
        "subject": record["subject"],
        "receipt": component_projection(record["receipt"]),
        "bundle": component_projection(record["bundle"]),
        "authentication": component_projection(record["authentication"]),
        "payload": [component_projection(item) for item in record["payload"]],
        "predecessor": record["predecessor"],
    }
    if config != expected_config:
        fail("registry durable config or predecessor cross-link differs")
    validate_authentication(
        authentication,
        expected_format=stage_policy["authentication_format"],
        expected_identities=stage_policy["identities"],
        receipt_raw=layer_raw[0],
        bundle_raw=layer_raw[1],
    )
    if (
        authentication["subject"]["path"]
        != record["receipt"]["annotations"]["org.opencontainers.image.title"]
    ):
        fail("receipt authentication subject path differs from receipt layer title")
    if (
        authentication["bundle"]["path"]
        != record["bundle"]["annotations"]["org.opencontainers.image.title"]
    ):
        fail("receipt authentication bundle path differs from bundle layer title")
    if stage == "release-index":
        completion = validate_completion(
            receipt_value.get("completion"), terminal_stage=record["predecessor"]["stage"]
        )
        if authentication["identity"] != completion["workflow_identity"]:
            fail("release-index identity differs from signed completion authority")
    verify_cosign(
        receipt_raw=layer_raw[0],
        bundle_raw=layer_raw[1],
        authentication=authentication,
        cosign=cosign,
    )
    with PrivateDirectory(output_dir, create=True):
        pass
    files = {
        "referrers.oci.json": referrers_raw,
        "artifact-manifest.oci.json": manifest_raw,
        "config.json": config_raw,
        "receipt.json": layer_raw[0],
        "bundle.sigstore.json": layer_raw[1],
        "authentication.json": layer_raw[2],
    }
    for name, raw in files.items():
        write_private(output_dir / name, raw)
    payload_root = output_dir / "payload"
    for item, raw in zip(record["payload"], layer_raw[3:], strict=True):
        relative = safe_relative_path(item["annotations"]["org.opencontainers.image.title"])
        write_private(payload_root.joinpath(*PurePosixPath(relative).parts), raw)
    observed_payload = combined_payloads(
        stage=stage,
        receipt=receipt_value,
        authentication=authentication,
        root=payload_root,
    )
    if [item[0] for item in observed_payload] != record["payload"]:
        fail("materialized payload inventory differs from signed receipt")
    return {
        "referrers": {
            "sha256": sha256(referrers_raw),
            "size": len(referrers_raw),
            "matched_descriptor": artifact,
        },
        "manifest": {"sha256": sha256(manifest_raw), "size": len(manifest_raw)},
        "config": {"sha256": sha256(config_raw), "size": len(config_raw)},
        "layers": [{"sha256": sha256(raw), "size": len(raw)} for raw in layer_raw],
        "exact_raw_bytes": True,
    }


def record_template(*, lock: Mapping[str, Any], stage: str, built: BuiltArtifact) -> dict[str, Any]:
    durable = lock["publication_gate"]["durable_evidence"]
    return {
        "format": durable["record_format"],
        "result": "pass",
        "stage": stage,
        "registry": durable["registry"],
        "repository": durable["repository"],
        "artifact_type": policy_for(lock, stage)["artifact_type"],
        "subject": built.subject,
        "artifact": built.manifest_descriptor,
        "config": built.config_descriptor,
        "receipt": built.layer_descriptors[0],
        "bundle": built.layer_descriptors[1],
        "authentication": built.layer_descriptors[2],
        "payload": list(built.payload_descriptors),
        "predecessor": built.predecessor,
    }


def command_authentication(arguments: argparse.Namespace) -> None:
    lock = load_lock(arguments.manifest)
    stage_policy = policy_for(lock, arguments.stage)
    if arguments.format != stage_policy["authentication_format"]:
        fail("authentication format differs from stage policy")
    subject_raw = regular_bytes(arguments.subject)
    _, bundle_raw = json_value(arguments.bundle, require_canonical=False)
    verification_raw = regular_bytes(arguments.verification)
    if arguments.cosign_version != "3.1.3":
        fail("authentication requires exact Cosign 3.1.3")
    if arguments.issuer != "https://token.actions.githubusercontent.com":
        fail("authentication issuer differs")
    if arguments.identity not in stage_policy["identities"]:
        fail("authentication workflow identity differs")

    def local(value: bytes, path: Path) -> dict[str, Any]:
        return {"path": path.name, "sha256": sha256(value), "size": len(value)}

    value = {
        "format": arguments.format,
        "result": "pass",
        "method": "sigstore-keyless-cosign-sign-blob",
        "cosign_version": arguments.cosign_version,
        "identity": arguments.identity,
        "issuer": arguments.issuer,
        "subject": local(subject_raw, arguments.subject),
        "bundle": local(bundle_raw, arguments.bundle),
        "verification": {
            **local(verification_raw, arguments.verification),
            "verified": True,
        },
    }
    write_private(arguments.output, canonical(value))


def command_publish(arguments: argparse.Namespace) -> None:
    lock = load_lock(arguments.manifest)
    predecessor = (
        load_record(arguments.predecessor_record) if arguments.predecessor_record else None
    )
    built = build_artifact(
        lock=lock,
        stage=arguments.stage,
        subject_digest=arguments.subject_digest,
        subject_size=arguments.subject_size,
        receipt_path=arguments.receipt,
        bundle_path=arguments.bundle,
        authentication_path=arguments.authentication,
        payload_root=arguments.payload_root,
        predecessor=predecessor,
    )
    record = record_template(lock=lock, stage=arguments.stage, built=built)
    registry = Registry(base=record["registry"], repository=record["repository"], push=True)
    before_raw = registry.referrers(record["subject"]["digest"], record["artifact_type"])
    try:
        before = strict_json(before_raw, "pre-publish referrers response")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("pre-publish referrers response is invalid") from exc
    if not isinstance(before, dict) or before.get("schemaVersion") != 2:
        fail("pre-publish referrers response is not an OCI index")
    manifests = before.get("manifests")
    if not isinstance(manifests, list):
        fail("pre-publish referrers response lacks manifests")
    existing = [
        item
        for item in manifests
        if isinstance(item, dict) and item.get("artifactType") == record["artifact_type"]
    ]
    if len(existing) > 1:
        fail("durable evidence has duplicate same-stage referrers")
    if existing and existing[0] != record["artifact"]:
        fail("durable evidence replay substitutes different signed bytes")
    if not existing:
        for raw in (
            built.config,
            built.receipt,
            built.bundle,
            built.authentication,
            *built.payload_raw,
        ):
            registry.put_blob(raw)
        registry.put_manifest(built.manifest)
    root = arguments.output_dir
    record["readback"] = verify_remote(
        registry=registry,
        lock=lock,
        record=record,
        output_dir=root / "readback",
        cosign=arguments.cosign,
    )
    write_private(root / "record.json", canonical(record))
    sys.stdout.write(canonical(record).decode("ascii"))


def unique_referrer(raw: bytes, artifact_type: str) -> dict[str, Any]:
    try:
        value = strict_json(raw, "registry referrers response")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("registry referrers response is invalid JSON") from exc
    if not isinstance(value, dict) or value.get("schemaVersion") != 2:
        fail("registry referrers response is not an OCI index")
    manifests = value.get("manifests")
    if not isinstance(manifests, list):
        fail("registry referrers response lacks manifests")
    matches = [
        item
        for item in manifests
        if isinstance(item, dict) and item.get("artifactType") == artifact_type
    ]
    if not matches:
        raise EvidenceAbsentError("requested durable evidence is absent")
    if len(matches) > 1:
        fail("registry must expose exactly one referrer for the requested artifact type")
    artifact = matches[0]
    if set(artifact) != {"mediaType", "digest", "size", "artifactType"}:
        fail("registry referrer descriptor keys differ")
    if artifact["mediaType"] != OCI_MANIFEST or artifact["artifactType"] != artifact_type:
        fail("registry referrer descriptor media or artifact type differs")
    validate_digest(artifact["digest"], "discovered artifact digest")
    validate_size(artifact["size"], "discovered artifact size")
    return artifact


def discover_record(  # noqa: PLR0912, PLR0915
    *,
    registry: Registry,
    lock: Mapping[str, Any],
    stage: str,
    subject_digest: str,
    subject_size: int,
    predecessor: Mapping[str, Any] | None,
) -> dict[str, Any]:
    durable = lock["publication_gate"]["durable_evidence"]
    stage_policy = policy_for(lock, stage)
    subject = {
        "mediaType": durable["subject_media_type"],
        "digest": validate_digest(subject_digest, "discovery subject digest"),
        "size": validate_size(subject_size, "discovery subject size"),
    }
    referrers_raw = registry.referrers(subject_digest, stage_policy["artifact_type"])
    artifact = unique_referrer(referrers_raw, stage_policy["artifact_type"])
    manifest_raw = registry.get_manifest(artifact["digest"])
    if len(manifest_raw) != artifact["size"]:
        fail("discovered artifact manifest size differs")
    try:
        manifest = strict_json(manifest_raw, "discovered artifact manifest")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("discovered artifact manifest is invalid JSON") from exc
    if manifest_raw != canonical(manifest):
        fail("discovered artifact manifest is not canonical newline JSON")
    if set(manifest) != {
        "schemaVersion",
        "mediaType",
        "artifactType",
        "config",
        "layers",
        "subject",
    }:
        fail("discovered artifact manifest keys differ")
    if manifest["schemaVersion"] != 2 or manifest["mediaType"] != OCI_MANIFEST:
        fail("discovered artifact manifest schema differs")
    if manifest["artifactType"] != stage_policy["artifact_type"] or manifest["subject"] != subject:
        fail("discovered artifact type or subject differs")
    layers = manifest["layers"]
    if not isinstance(layers, list) or len(layers) < 3:
        fail("discovered artifact lacks required receipt, bundle, and authentication layers")
    expected_role_media = (
        stage_policy["receipt_media_type"],
        durable["bundle_layer_media_type"],
        durable["authentication_layer_media_type"],
    )
    for item, media_type in zip(layers[:3], expected_role_media, strict=True):
        if not isinstance(item, dict) or set(item) != {
            "mediaType",
            "digest",
            "size",
            "annotations",
        }:
            fail("discovered role layer descriptor keys differ")
        if item["mediaType"] != media_type:
            fail("discovered role layer media type differs")
        safe_relative_path(item["annotations"].get("org.opencontainers.image.title"))
        validate_digest(item["digest"], "discovered role layer digest")
        validate_size(item["size"], "discovered role layer size")
    payload = layers[3:]
    payload_names = []
    for item in payload:
        if not isinstance(item, dict) or set(item) != {
            "mediaType",
            "digest",
            "size",
            "annotations",
        }:
            fail("discovered payload layer descriptor keys differ")
        if item["mediaType"] != durable["payload_layer_media_type"]:
            fail("discovered payload layer media type differs")
        payload_names.append(
            safe_relative_path(item["annotations"].get("org.opencontainers.image.title"))
        )
        validate_digest(item["digest"], "discovered payload digest")
        validate_size(item["size"], "discovered payload size")
    if payload_names != sorted(payload_names) or len(payload_names) != len(set(payload_names)):
        fail("discovered payload inventory is not sorted and unique")
    validate_layer_inventory(
        durable=durable,
        stage_policy=stage_policy,
        role_layers=layers[:3],
        payload_layers=payload,
    )
    config_descriptor = manifest["config"]
    if not isinstance(config_descriptor, dict) or set(config_descriptor) != {
        "mediaType",
        "digest",
        "size",
    }:
        fail("discovered config descriptor keys differ")
    if config_descriptor["mediaType"] != durable["config_media_type"]:
        fail("discovered config media type differs")
    config_raw = registry.get_blob(config_descriptor["digest"])
    if len(config_raw) != config_descriptor["size"]:
        fail("discovered config size differs")
    try:
        config = strict_json(config_raw, "discovered config")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("discovered config is invalid JSON") from exc
    expected_predecessor = predecessor_value(stage, predecessor)
    expected_config = {
        "format": CONFIG_FORMAT,
        "stage": stage,
        "artifact_type": stage_policy["artifact_type"],
        "subject": subject,
        "receipt": component_projection(layers[0]),
        "bundle": component_projection(layers[1]),
        "authentication": component_projection(layers[2]),
        "payload": [component_projection(item) for item in payload],
        "predecessor": expected_predecessor,
    }
    if config_raw != canonical(config) or config != expected_config:
        fail("discovered config or predecessor cross-link differs")
    return {
        "format": RECORD_FORMAT,
        "result": "pass",
        "stage": stage,
        "registry": durable["registry"],
        "repository": durable["repository"],
        "artifact_type": stage_policy["artifact_type"],
        "subject": subject,
        "artifact": artifact,
        "config": config_descriptor,
        "receipt": layers[0],
        "bundle": layers[1],
        "authentication": layers[2],
        "payload": payload,
        "predecessor": expected_predecessor,
    }


def command_discover(arguments: argparse.Namespace) -> None:  # noqa: PLR0912
    lock = load_lock(arguments.manifest)
    predecessor = (
        load_record(arguments.predecessor_record) if arguments.predecessor_record else None
    )
    durable = lock["publication_gate"]["durable_evidence"]
    qualification_authority = None
    if arguments.expected_qualification_authority:
        if arguments.stage != "qualification":
            fail("qualification replay authority is valid only for qualification discovery")
        if arguments.expected_receipt:
            fail("qualification discovery authorities are mutually exclusive")
        authority_value, _ = json_value(
            arguments.expected_qualification_authority,
            require_canonical=True,
        )
        expected_subject = {
            "mediaType": durable["subject_media_type"],
            "digest": validate_digest(arguments.subject_digest, "discovery subject digest"),
            "size": validate_size(arguments.subject_size, "discovery subject size"),
        }
        qualification_authority = validate_qualification_replay_authority(
            authority_value,
            subject=expected_subject,
            lock=lock,
        )
    registry = Registry(base=durable["registry"], repository=durable["repository"], push=False)
    record = discover_record(
        registry=registry,
        lock=lock,
        stage=arguments.stage,
        subject_digest=arguments.subject_digest,
        subject_size=arguments.subject_size,
        predecessor=predecessor,
    )
    if (
        arguments.expected_artifact_digest
        and record["artifact"]["digest"] != arguments.expected_artifact_digest
    ):
        fail("discovered artifact digest differs from expected authority")
    if (
        arguments.expected_artifact_size
        and record["artifact"]["size"] != arguments.expected_artifact_size
    ):
        fail("discovered artifact size differs from expected authority")
    if arguments.expected_receipt:
        expected_receipt_raw = regular_bytes(arguments.expected_receipt)
        expected_receipt = descriptor(
            expected_receipt_raw,
            policy_for(lock, arguments.stage)["receipt_media_type"],
            name=arguments.expected_receipt.name,
        )
        if record["receipt"] != expected_receipt:
            fail("discovered receipt differs from the expected exact bytes")
    if arguments.stage == "qualification":
        sealed = lock["candidate_image"].get("qualification_durable_evidence")
        if sealed is None:
            if lock["candidate_image"].get("finalized") is not False or (
                not arguments.expected_receipt and qualification_authority is None
            ):
                fail("unsealed qualification discovery requires current exact authority")
        elif candidate_durable_projection(record) != sealed:
            fail("discovered qualification evidence differs from finalized candidate authority")
    root = arguments.output_dir
    with PrivateDirectory(root, create=True):
        pass
    record["readback"] = verify_remote(
        registry=registry,
        lock=lock,
        record=record,
        output_dir=root / "readback",
        cosign=arguments.cosign,
    )
    if qualification_authority is not None:
        qualification_receipt, _ = json_value(
            root / "readback" / "receipt.json",
            require_canonical=True,
        )
        if qualification_replay_projection(qualification_receipt) != qualification_authority:
            fail("discovered qualification receipt differs from current replay authority")
    write_private(root / "record.json", canonical(record))
    sys.stdout.write(canonical(record).decode("ascii"))


def command_assert_absent(arguments: argparse.Namespace) -> None:
    lock = load_lock(arguments.manifest)
    durable = lock["publication_gate"]["durable_evidence"]
    stage_policy = policy_for(lock, arguments.stage)
    subject_digest = validate_digest(arguments.subject_digest, "absence subject digest")
    registry = Registry(base=durable["registry"], repository=durable["repository"], push=False)
    raw = registry.referrers(subject_digest, stage_policy["artifact_type"])
    try:
        value = strict_json(raw, "absence referrers response")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("absence referrers response is invalid JSON") from exc
    if not isinstance(value, dict) or value.get("schemaVersion") != 2:
        fail("absence referrers response is not an OCI index")
    manifests = value.get("manifests")
    if not isinstance(manifests, list):
        fail("absence referrers response lacks manifests")
    matches = [
        item
        for item in manifests
        if isinstance(item, dict) and item.get("artifactType") == stage_policy["artifact_type"]
    ]
    if matches:
        fail(f"{arguments.stage} durable evidence already exists")
    write_private(arguments.output, raw)
    sys.stdout.write(canonical({"result": "absent", "stage": arguments.stage}).decode("ascii"))


class LocalRegistry:
    def __init__(self, *, directory: Path, record: Mapping[str, Any]) -> None:
        self.directory = directory
        self.record = record
        readback = directory / "readback"
        self.referrers_raw = regular_bytes(readback / "referrers.oci.json")
        self.manifest_raw = regular_bytes(readback / "artifact-manifest.oci.json")
        self.blobs: dict[str, bytes] = {}
        paths = [
            (record["config"], readback / "config.json"),
            (record["receipt"], readback / "receipt.json"),
            (record["bundle"], readback / "bundle.sigstore.json"),
            (record["authentication"], readback / "authentication.json"),
        ]
        for item in record["payload"]:
            relative = safe_relative_path(item["annotations"]["org.opencontainers.image.title"])
            paths.append((item, readback / "payload" / relative))
        for item, path in paths:
            raw = regular_bytes(path, maximum=MAX_PAYLOAD_BYTES)
            if digest(raw) != item["digest"] or len(raw) != item["size"]:
                fail(f"portable local evidence blob differs: {path}")
            if item["digest"] in self.blobs and self.blobs[item["digest"]] != raw:
                fail("portable local evidence aliases a digest with different bytes")
            self.blobs[item["digest"]] = raw

    def referrers(self, subject_digest: str, artifact_type: str) -> bytes:
        if (
            subject_digest != self.record["subject"]["digest"]
            or artifact_type != self.record["artifact_type"]
        ):
            fail("portable local referrers request differs from record")
        return self.referrers_raw

    def get_manifest(self, value: str) -> bytes:
        if value != self.record["artifact"]["digest"] or digest(self.manifest_raw) != value:
            fail("portable local artifact manifest differs")
        return self.manifest_raw

    def get_blob(self, value: str) -> bytes:
        try:
            return self.blobs[value]
        except KeyError as exc:
            raise EvidenceError("portable local evidence blob is absent") from exc


def validate_portable_directory(directory: Path, record: Mapping[str, Any]) -> None:
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or directory.is_symlink():
        fail("portable evidence stage root is not a real directory")
    expected_files = {
        "record.json",
        "readback/referrers.oci.json",
        "readback/artifact-manifest.oci.json",
        "readback/config.json",
        "readback/receipt.json",
        "readback/bundle.sigstore.json",
        "readback/authentication.json",
    }
    for item in record["payload"]:
        title = safe_relative_path(item["annotations"]["org.opencontainers.image.title"])
        expected_files.add("readback/payload/" + title)
    expected_directories = {"readback"}
    for name in expected_files:
        parent = PurePosixPath(name).parent
        while parent.as_posix() not in (".", ""):
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    actual_files = set()
    actual_directories = set()
    for path in directory.rglob("*"):
        relative = path.relative_to(directory).as_posix()
        item_info = path.lstat()
        if stat.S_ISLNK(item_info.st_mode):
            fail(f"portable evidence contains a symlink: {relative}")
        if stat.S_ISREG(item_info.st_mode):
            actual_files.add(relative)
        elif stat.S_ISDIR(item_info.st_mode):
            actual_directories.add(relative)
        else:
            fail(f"portable evidence contains a special file: {relative}")
    if actual_files != expected_files or actual_directories != expected_directories:
        fail("portable evidence stage file inventory differs")


def verify_local_record(
    *,
    lock: Mapping[str, Any],
    directory: Path,
    record: Mapping[str, Any],
    predecessor: Mapping[str, Any] | None,
    cosign: str,
) -> dict[str, Any]:
    if record["predecessor"] != predecessor_value(record["stage"], predecessor):
        fail("portable local predecessor cross-link differs")
    durable = lock["publication_gate"]["durable_evidence"]
    if record["registry"] != durable["registry"] or record["repository"] != durable["repository"]:
        fail("portable local registry authority differs")
    validate_portable_directory(directory, record)
    registry = LocalRegistry(directory=directory, record=record)
    with tempfile.TemporaryDirectory(prefix="z4j-durable-local-") as temporary:
        readback = verify_remote(
            registry=registry,
            lock=lock,
            record=record,
            output_dir=Path(temporary) / "materialized",
            cosign=cosign,
        )
    if record.get("readback") != readback:
        fail("portable local record readback seals differ")
    return artifact_projection(record)


def materialize_original(
    *,
    lock: Mapping[str, Any],
    directory: Path,
    output_dir: Path,
    predecessor: Mapping[str, Any] | None,
    cosign: str,
    skip_existing_exact: bool,
) -> dict[str, Any]:
    """Verify a portable stage and reconstruct its original regular files."""
    with private_tree_snapshot(directory) as captured:
        return _materialize_original_captured(
            lock=lock,
            directory=captured,
            output_dir=output_dir,
            predecessor=predecessor,
            cosign=cosign,
            skip_existing_exact=skip_existing_exact,
        )


def _materialize_original_captured(
    *,
    lock: Mapping[str, Any],
    directory: Path,
    output_dir: Path,
    predecessor: Mapping[str, Any] | None,
    cosign: str,
    skip_existing_exact: bool,
) -> dict[str, Any]:
    record = load_record(directory / "record.json")
    verify_local_record(
        lock=lock,
        directory=directory,
        record=record,
        predecessor=predecessor,
        cosign=cosign,
    )
    readback = directory / "readback"
    sources = [
        (record["receipt"], readback / "receipt.json"),
        (record["bundle"], readback / "bundle.sigstore.json"),
        (record["authentication"], readback / "authentication.json"),
    ]
    for item in record["payload"]:
        title = safe_relative_path(item["annotations"]["org.opencontainers.image.title"])
        sources.append((item, readback / "payload" / title))
    inventory = []
    layer_titles = []
    with PrivateDirectory(output_dir, create=True) as output:
        for item, source in sources:
            title = safe_relative_path(item["annotations"]["org.opencontainers.image.title"])
            layer_titles.append(title)
            raw = regular_bytes(source, maximum=MAX_PAYLOAD_BYTES)
            if digest(raw) != item["digest"] or len(raw) != item["size"]:
                fail(f"portable layer changed before reconstruction: {title}")
            output.write(title, raw, skip_existing_exact=skip_existing_exact)
            inventory.append(
                {
                    "path": title,
                    "sha256": sha256(raw),
                    "size": len(raw),
                    "source": "oci-layer",
                }
            )
        receipt_title = layer_titles[0]
        receipt_path = PurePosixPath(receipt_title)
        if receipt_path.suffix != ".json":
            fail("receipt layer title does not support a deterministic SHA sidecar")
        sidecar = receipt_path.with_suffix(".sha256").as_posix()
        if sidecar in layer_titles:
            fail("derived receipt SHA sidecar collides with an OCI layer")
        receipt_raw = regular_bytes(readback / "receipt.json")
        sidecar_raw = f"{sha256(receipt_raw)}  {receipt_path.name}\n".encode("ascii")
        output.write(sidecar, sidecar_raw, skip_existing_exact=skip_existing_exact)
    inventory.append(
        {
            "path": sidecar,
            "sha256": sha256(sidecar_raw),
            "size": len(sidecar_raw),
            "source": "deterministic-receipt-sha256-sidecar",
        }
    )
    inventory.sort(key=lambda item: item["path"])
    return {
        "format": MATERIALIZATION_FORMAT,
        "result": "pass",
        "stage": record["stage"],
        "record": artifact_projection(record),
        "files": inventory,
    }


def verify_local_graph(
    manifest_path: Path | str,
    evidence_root: Path | str,
    *,
    cosign: str = "cosign",
) -> dict[str, Any]:
    """Offline-verify the exact portable Q/F/(P|R)/index evidence graph."""
    manifest_path = Path(manifest_path)
    evidence_root = Path(evidence_root)
    with private_tree_snapshot(evidence_root) as captured:
        return _verify_local_graph_captured(manifest_path, captured, cosign=cosign)


def _verify_local_graph_captured(  # noqa: PLR0912
    manifest_path: Path,
    evidence_root: Path,
    *,
    cosign: str,
) -> dict[str, Any]:
    lock = load_lock(manifest_path)
    root_info = evidence_root.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or evidence_root.is_symlink():
        fail("portable evidence graph root is not a real directory")
    children = {}
    for path in evidence_root.iterdir():
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or path.is_symlink():
            fail("portable evidence graph contains a non-directory entry")
        children[path.name] = path
    terminal_names = set(children) & {"promotion", "recovery"}
    if len(terminal_names) != 1:
        fail("portable evidence graph requires exactly one terminal stage")
    terminal_stage = next(iter(terminal_names))
    expected_names = {
        "qualification",
        "finalization",
        terminal_stage,
        "release-index",
    }
    if set(children) != expected_names:
        fail("portable evidence graph stage directory inventory differs")
    ordered_stages = ["qualification", "finalization", terminal_stage, "release-index"]
    records = {stage: load_record(children[stage] / "record.json") for stage in ordered_stages}
    if any(records[stage]["stage"] != stage for stage in ordered_stages):
        fail("portable evidence graph record stage differs from its directory")
    subject = records["qualification"]["subject"]
    if any(records[stage]["subject"] != subject for stage in ordered_stages):
        fail("portable evidence graph subjects differ")
    candidate = lock["candidate_image"]
    if candidate.get("finalized") is not True:
        fail("portable evidence graph requires a finalized candidate")
    if candidate.get("index") != {
        "digest": subject["digest"],
        "size": subject["size"],
    }:
        fail("portable evidence graph subject differs from candidate")
    if candidate.get("qualification_durable_evidence") != candidate_durable_projection(
        records["qualification"]
    ):
        fail("portable qualification evidence differs from candidate authority")
    projections: dict[str, Any] = {}
    predecessor = None
    for stage in ordered_stages:
        projections[stage] = verify_local_record(
            lock=lock,
            directory=children[stage],
            record=records[stage],
            predecessor=predecessor,
            cosign=cosign,
        )
        predecessor = records[stage]
    manifest_raw = regular_bytes(manifest_path)
    index_receipt, index_raw = json_value(
        children["release-index"] / "readback" / "receipt.json",
        require_canonical=True,
    )
    expected_index = release_index_value(
        lock=lock,
        manifest_raw=manifest_raw,
        records=[
            records["qualification"],
            records["finalization"],
            records[terminal_stage],
        ],
        completion=index_receipt.get("completion"),
    )
    if index_receipt != expected_index:
        fail("portable release evidence index content differs")
    terminal_receipt, terminal_receipt_raw = json_value(
        children[terminal_stage] / "readback" / "receipt.json",
        require_canonical=True,
    )
    if digest(terminal_receipt_raw) != records[terminal_stage]["receipt"]["digest"]:
        fail("portable terminal receipt differs from its descriptor")
    validate_completion_against_terminal(
        index_receipt["completion"],
        terminal_stage=terminal_stage,
        terminal_receipt=terminal_receipt,
    )
    qualification_receipt_raw = regular_bytes(
        children["qualification"] / "readback" / "receipt.json"
    )
    if sha256(qualification_receipt_raw) != candidate["release_receipt_sha256"]:
        fail("portable qualification receipt differs from candidate authority")
    return {
        "format": GRAPH_FORMAT,
        "result": "pass",
        "subject": subject,
        "terminal_stage": terminal_stage,
        "records": projections,
        "release_index": {
            "sha256": sha256(index_raw),
            "size": len(index_raw),
            "completion": index_receipt["completion"],
        },
        "manifest": {"sha256": sha256(manifest_raw), "size": len(manifest_raw)},
        "candidate_components": expected_index["candidate_components"],
    }


def command_materialize_original(arguments: argparse.Namespace) -> None:
    lock = load_lock(arguments.manifest)
    predecessor = (
        load_record(arguments.predecessor_record) if arguments.predecessor_record else None
    )
    result = materialize_original(
        lock=lock,
        directory=arguments.directory,
        output_dir=arguments.output_dir,
        predecessor=predecessor,
        cosign=arguments.cosign,
        skip_existing_exact=arguments.skip_existing_exact,
    )
    sys.stdout.write(canonical(result).decode("ascii"))


def command_verify_local_graph(arguments: argparse.Namespace) -> None:
    result = verify_local_graph(
        arguments.manifest, arguments.evidence_root, cosign=arguments.cosign
    )
    sys.stdout.write(canonical(result).decode("ascii"))


def command_require_runtime_registry_authority(_arguments: argparse.Namespace) -> None:

    require_runtime_registry_authority()


def command_verify_local(arguments: argparse.Namespace) -> None:
    lock = load_lock(arguments.manifest)
    record = load_record(arguments.record)
    predecessor = (
        load_record(arguments.predecessor_record) if arguments.predecessor_record else None
    )
    projection = verify_local_record(
        lock=lock,
        directory=arguments.directory,
        record=record,
        predecessor=predecessor,
        cosign=arguments.cosign,
    )
    sys.stdout.write(canonical({"result": "pass", "record": projection}).decode("ascii"))


def command_verify(arguments: argparse.Namespace) -> None:
    lock = load_lock(arguments.manifest)
    record = load_record(arguments.record)
    if arguments.stage and record["stage"] != arguments.stage:
        fail("durable-evidence record stage differs")
    if arguments.subject_digest and record["subject"]["digest"] != arguments.subject_digest:
        fail("durable-evidence record subject digest differs")
    if arguments.subject_size and record["subject"]["size"] != arguments.subject_size:
        fail("durable-evidence record subject size differs")
    expected_predecessor = (
        load_record(arguments.predecessor_record) if arguments.predecessor_record else None
    )
    if record["predecessor"] != predecessor_value(record["stage"], expected_predecessor):
        fail("durable-evidence predecessor record differs")
    durable = lock["publication_gate"]["durable_evidence"]
    if record["registry"] != durable["registry"] or record["repository"] != durable["repository"]:
        fail("durable-evidence registry authority differs")
    registry = Registry(base=record["registry"], repository=record["repository"], push=False)
    readback = verify_remote(
        registry=registry,
        lock=lock,
        record=record,
        output_dir=arguments.output_dir,
        cosign=arguments.cosign,
    )
    sys.stdout.write(canonical({"result": "pass", "readback": readback}).decode("ascii"))


def command_make_index(arguments: argparse.Namespace) -> None:
    lock = load_lock(arguments.manifest)
    records = [load_record(path) for path in arguments.record]
    manifest_raw = regular_bytes(arguments.manifest)
    completion = normal_completion()
    if arguments.completion_authority:
        completion, _ = json_value(arguments.completion_authority, require_canonical=True)
    value = release_index_value(
        lock=lock,
        manifest_raw=manifest_raw,
        records=records,
        completion=completion,
    )
    terminal_receipt, terminal_raw = json_value(
        arguments.record[-1].parent / "readback" / "receipt.json",
        require_canonical=True,
    )
    if (
        digest(terminal_raw) != records[-1]["receipt"]["digest"]
        or len(terminal_raw) != records[-1]["receipt"]["size"]
    ):
        fail("terminal receipt differs from its durable descriptor")
    validate_completion_against_terminal(
        value["completion"],
        terminal_stage=records[-1]["stage"],
        terminal_receipt=terminal_receipt,
    )
    write_private(arguments.output, canonical(value))


def build_parser() -> argparse.ArgumentParser:  # noqa: PLR0915
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    authentication = commands.add_parser("authentication")
    authentication.add_argument("--manifest", type=Path, required=True)
    authentication.add_argument("--stage", choices=tuple(EXPECTED_PREDECESSORS), required=True)
    authentication.add_argument("--format", required=True)
    authentication.add_argument("--subject", type=Path, required=True)
    authentication.add_argument("--bundle", type=Path, required=True)
    authentication.add_argument("--verification", type=Path, required=True)
    authentication.add_argument("--identity", required=True)
    authentication.add_argument("--issuer", required=True)
    authentication.add_argument("--cosign-version", default="3.1.3")
    authentication.add_argument("--output", type=Path, required=True)
    authentication.set_defaults(handler=command_authentication)

    publish = commands.add_parser("publish")
    publish.add_argument("--manifest", type=Path, required=True)
    publish.add_argument("--stage", choices=tuple(EXPECTED_PREDECESSORS), required=True)
    publish.add_argument("--subject-digest", required=True)
    publish.add_argument("--subject-size", type=int, required=True)
    publish.add_argument("--receipt", type=Path, required=True)
    publish.add_argument("--bundle", type=Path, required=True)
    publish.add_argument("--authentication", type=Path, required=True)
    publish.add_argument("--payload-root", type=Path)
    publish.add_argument("--predecessor-record", type=Path)
    publish.add_argument("--output-dir", type=Path, required=True)
    publish.add_argument("--cosign", default="cosign")
    publish.set_defaults(handler=command_publish)

    discover = commands.add_parser("discover")
    discover.add_argument("--manifest", type=Path, required=True)
    discover.add_argument("--stage", choices=tuple(EXPECTED_PREDECESSORS), required=True)
    discover.add_argument("--subject-digest", required=True)
    discover.add_argument("--subject-size", type=int, required=True)
    discover.add_argument("--expected-artifact-digest")
    discover.add_argument("--expected-artifact-size", type=int)
    discover.add_argument("--expected-receipt", type=Path)
    discover.add_argument("--expected-qualification-authority", type=Path)
    discover.add_argument("--predecessor-record", type=Path)
    discover.add_argument("--output-dir", type=Path, required=True)
    discover.add_argument("--cosign", default="cosign")
    discover.set_defaults(handler=command_discover)

    assert_absent = commands.add_parser("assert-absent")
    assert_absent.add_argument("--manifest", type=Path, required=True)
    assert_absent.add_argument("--stage", choices=("recovery", "release-index"), required=True)
    assert_absent.add_argument("--subject-digest", required=True)
    assert_absent.add_argument("--output", type=Path, required=True)
    assert_absent.set_defaults(handler=command_assert_absent)

    verify = commands.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--record", type=Path, required=True)
    verify.add_argument("--stage", choices=tuple(EXPECTED_PREDECESSORS))
    verify.add_argument("--subject-digest")
    verify.add_argument("--subject-size", type=int)
    verify.add_argument("--predecessor-record", type=Path)
    verify.add_argument("--output-dir", type=Path, required=True)
    verify.add_argument("--cosign", default="cosign")
    verify.set_defaults(handler=command_verify)

    verify_local = commands.add_parser("verify-local")
    verify_local.add_argument("--manifest", type=Path, required=True)
    verify_local.add_argument("--record", type=Path, required=True)
    verify_local.add_argument("--directory", type=Path, required=True)
    verify_local.add_argument("--predecessor-record", type=Path)
    verify_local.add_argument("--cosign", default="cosign")
    verify_local.set_defaults(handler=command_verify_local)

    materialize = commands.add_parser("materialize-original")
    materialize.add_argument("--manifest", type=Path, required=True)
    materialize.add_argument("--directory", type=Path, required=True)
    materialize.add_argument("--predecessor-record", type=Path)
    materialize.add_argument("--output-dir", type=Path, required=True)
    materialize.add_argument("--skip-existing-exact", action="store_true")
    materialize.add_argument("--cosign", default="cosign")
    materialize.set_defaults(handler=command_materialize_original)

    registry_authority = commands.add_parser("require-runtime-registry-authority")
    registry_authority.set_defaults(handler=command_require_runtime_registry_authority)

    verify_graph = commands.add_parser("verify-local-graph")
    verify_graph.add_argument("--manifest", type=Path, required=True)
    verify_graph.add_argument("--evidence-root", type=Path, required=True)
    verify_graph.add_argument("--cosign", default="cosign")
    verify_graph.set_defaults(handler=command_verify_local_graph)

    make_index = commands.add_parser("make-index")
    make_index.add_argument("--manifest", type=Path, required=True)
    make_index.add_argument("--record", type=Path, action="append", required=True)
    make_index.add_argument("--completion-authority", type=Path)
    make_index.add_argument("--output", type=Path, required=True)
    make_index.set_defaults(handler=command_make_index)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        arguments.handler(arguments)
    except EvidenceAbsentError as exc:
        sys.stderr.write(f"rollback durable evidence absent: {exc}\n")
        return 3
    except (
        EvidenceError,
        KeyError,
        TypeError,
        ValueError,
        OSError,
        subprocess.TimeoutExpired,
    ) as exc:
        sys.stderr.write(f"rollback durable evidence failed: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
