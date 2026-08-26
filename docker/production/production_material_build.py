#!/usr/bin/env python3
"""Shared local mechanics for production material builders.

This module contains no material policy and no remote authority.  The system
and dashboard helpers own every URL, package, command, image, and evidence
schema.  This file only supplies a closed subprocess boundary, safe output
directories, canonical file inventories, and deterministic local records.

No function in this module can issue an HTTP request.  A caller must complete
its material-specific ``require-ready`` gate before constructing a runner or
calling :func:`run_buildx`.  The checked-in generator Dockerfiles separate
networked acquisition RUN instructions from ``--network=none`` qualification,
build, scanner, and maintainer-script instructions.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, Protocol

HEX64 = re.compile(r"[0-9a-f]{64}")
GIT_SHA1 = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
PLATFORMS = {"linux/amd64": "amd64", "linux/arm64": "arm64"}
HOST_ARCHITECTURES = {"linux/amd64": "x86_64", "linux/arm64": "aarch64"}
DOCKER_HOST = "unix:///var/run/docker.sock"
DOCKER_CONTEXT = "default"
DOCKER_DRIVER = "docker-container"
BUILDKIT_WORKER_NETWORK = "bridge"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MAX_COMMAND_OUTPUT = 32 * 1024 * 1024
MAX_FILES = 500_000
MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024
MAX_CONTEXT_BYTES = 512 * 1024 * 1024
MAX_TREE_BYTES = 8 * 1024 * 1024 * 1024
MAX_IMAGE_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
GIT_SOURCE_BINDING_FORMAT = "z4j-production-git-source-binding-v1"
SOURCE_CONTEXT_BINDING_FORMAT = "z4j-production-source-context-binding-v1"
SOURCE_FILE_PROJECTION_FORMAT = "z4j-production-source-file-projection-v1"
DirectoryIdentity = tuple[int, int, int, int]


class MaterialBuildError(RuntimeError):
    """A local material build crossed or failed its reviewed boundary."""


def _die(message: str) -> NoReturn:
    raise MaterialBuildError(message)


def pnpm_lock_components(raw: bytes) -> list[dict[str, Any]]:  # noqa: PLR0912,PLR0915
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MaterialBuildError("dashboard pnpm lock is not UTF-8") from exc
    if (
        "\r" in text
        or "\t" in text
        or text.count("\nimporters:\n") != 1
        or text.count("\npackages:\n") != 1
        or text.count("\nsnapshots:\n") != 1
        or text.index("\nimporters:\n") > text.index("\npackages:\n")
        or text.index("\npackages:\n") > text.index("\nsnapshots:\n")
    ):
        _die("dashboard pnpm lock framing is unsupported or ambiguous")
    if not text.startswith("lockfileVersion: '9.0'\n"):
        _die("dashboard pnpm lock must use exact lockfileVersion 9.0")

    def scalar(value: str, context: str) -> str:
        if value.startswith("'") or value.endswith("'"):
            if not (value.startswith("'") and value.endswith("'") and len(value) >= 2):
                _die(f"{context} quoting differs")
            value = value[1:-1].replace("''", "'")
        if (
            not value
            or value.strip() != value
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            _die(f"{context} scalar differs")
        return value

    def blocks(section: str, context: str) -> list[tuple[str, list[str]]]:
        lines = section.split("\n")
        starts = [
            index for index, line in enumerate(lines) if re.fullmatch(r"  \S.*:(?: \{\})?", line)
        ]
        if not starts:
            _die(f"{context} is empty")
        covered: set[int] = set()
        result: list[tuple[str, list[str]]] = []
        for offset, start in enumerate(starts):
            stop = starts[offset + 1] if offset + 1 < len(starts) else len(lines)
            covered.update(range(start, stop))
            header = lines[start][2:]
            inline_empty = header.endswith(": {}")
            header = header[: -4 if inline_empty else -1]
            body = lines[start + 1 : stop]
            if inline_empty and any(line for line in body):
                _die(f"{context} inline-empty body differs")
            result.append((scalar(header, f"{context} key"), body))
        if any(line and index not in covered for index, line in enumerate(lines)):
            _die(f"{context} top-level framing differs")
        return result

    importer_section = text.split("\nimporters:\n", 1)[1].split("\npackages:\n", 1)[0]
    importers = blocks(importer_section, "dashboard pnpm importer set")
    if len(importers) != 1 or importers[0][0] != ".":
        _die("dashboard pnpm importer set is not the exact root importer")
    root_targets: dict[str, list[str]] = {}
    importer_fields: dict[tuple[str, str], set[str]] = {}
    importer_group: str | None = None
    importer_dependency: str | None = None
    for line in importers[0][1]:
        if not line:
            continue
        group_match = re.fullmatch(
            r"    (dependencies|devDependencies|optionalDependencies):", line
        )
        if group_match:
            importer_group = group_match.group(1)
            importer_dependency = None
            continue
        dependency_match = re.fullmatch(r"      (\S.*):", line)
        if dependency_match and importer_group is not None:
            importer_dependency = scalar(
                dependency_match.group(1), "dashboard pnpm importer dependency"
            )
            identity = (importer_group, importer_dependency)
            if identity in importer_fields:
                _die("dashboard pnpm importer dependency is duplicate")
            importer_fields[identity] = set()
            continue
        field_match = re.fullmatch(r"        (specifier|version): (\S.*)", line)
        if field_match and importer_group is not None and importer_dependency is not None:
            fields = importer_fields.get((importer_group, importer_dependency))
            if fields is None or field_match.group(1) in fields:
                _die("dashboard pnpm importer field is duplicate")
            fields.add(field_match.group(1))
            if field_match.group(1) == "version":
                version = scalar(
                    field_match.group(2),
                    f"dashboard pnpm importer {importer_dependency} version",
                )
                target = f"{importer_dependency}@{version}"
                roots = root_targets.setdefault(target, [])
                if importer_group in roots:
                    _die("dashboard pnpm importer target is duplicate")
                roots.append(importer_group)
            continue
        _die("dashboard pnpm root importer framing differs")
    if any(fields != {"specifier", "version"} for fields in importer_fields.values()):
        _die("dashboard pnpm importer dependency fields differ")
    if not root_targets:
        _die("dashboard pnpm root importer is empty")

    package_section = text.split("\npackages:\n", 1)[1].split("\nsnapshots:\n", 1)[0]
    packages: dict[str, dict[str, Any]] = {}
    for key, body in blocks(package_section, "dashboard pnpm package universe"):
        if key.count("@") < 1 or "(" in key:
            _die(f"dashboard pnpm package key has no exact version: {key!r}")
        name, version = key.rsplit("@", 1)
        if not name or not version or key in packages:
            _die(f"dashboard pnpm package identity is malformed: {key!r}")
        integrity_matches: list[str] = []
        for line in body:
            match = re.search(
                r"(?:^|[,{])integrity: (sha512-[A-Za-z0-9+/=]+)(?:[,}]|$)",
                line.strip(),
            )
            if match:
                integrity_matches.append(match.group(1))
        if len(integrity_matches) != 1:
            _die(f"dashboard pnpm package has absent/ambiguous SHA-512 integrity: {key}")
        integrity = integrity_matches[0]
        try:
            decoded = base64.b64decode(integrity.removeprefix("sha512-"), validate=True)
        except (ValueError, binascii.Error) as exc:
            raise MaterialBuildError(f"dashboard pnpm integrity is invalid: {key}") from exc
        if len(decoded) != 64:
            _die(f"dashboard pnpm integrity is wrong-sized or duplicate: {key}")
        constraints: dict[str, list[str] | None] = {}
        for constraint_field in ("cpu", "libc", "os"):
            matches = [
                match.group(1)
                for line in body
                if (match := re.fullmatch(rf"{constraint_field}: \[([^\]]*)\]", line.strip()))
            ]
            if len(matches) > 1:
                _die(f"dashboard pnpm {constraint_field} constraint is ambiguous: {key}")
            if not matches:
                constraints[constraint_field] = None
                continue
            values = [item.strip() for item in matches[0].split(",")]
            if len(values) != len(set(values)) or any(
                re.fullmatch(r"!?[a-z0-9_-]+", item) is None for item in values
            ):
                _die(f"dashboard pnpm {constraint_field} constraint differs: {key}")
            constraints[constraint_field] = values
        packages[key] = {
            "cpu": constraints["cpu"],
            "integrity_sha512": integrity,
            "libc": constraints["libc"],
            "name": name,
            "os": constraints["os"],
            "version": version,
        }

    def dependency_target(name_raw: str, version_raw: str, context: str) -> str:
        name = scalar(name_raw, f"{context} name")
        version = scalar(version_raw, f"{context} version")
        if version.startswith(("file:", "link:", "workspace:")):
            _die(f"{context} uses a non-registry target")
        return f"{name}@{version}"

    snapshot_section = text.split("\nsnapshots:\n", 1)[1]
    snapshots: dict[str, dict[str, Any]] = {}
    for key, body in blocks(snapshot_section, "dashboard pnpm snapshot graph"):
        if key in snapshots:
            _die(f"dashboard pnpm snapshot is duplicate: {key}")
        package_key = key.split("(", 1)[0]
        metadata = packages.get(package_key)
        if metadata is None:
            _die(f"dashboard pnpm snapshot has no package metadata: {key}")
        dependencies: list[str] = []
        optional_dependencies: list[str] = []
        transitive_peers: list[str] = []
        field: str | None = None
        optional = False
        for line in body:
            if not line:
                continue
            field_match = re.fullmatch(
                r"    (dependencies|optionalDependencies|transitivePeerDependencies):",
                line,
            )
            if field_match:
                field = field_match.group(1)
                continue
            if line == "    optional: true":
                if optional:
                    _die(f"dashboard pnpm snapshot optional marker is duplicate: {key}")
                optional = True
                field = None
                continue
            edge_match = re.fullmatch(r"      (\S.*): (\S.*)", line)
            if edge_match and field in {"dependencies", "optionalDependencies"}:
                target = dependency_target(
                    edge_match.group(1), edge_match.group(2), f"dashboard pnpm snapshot {key}"
                )
                (dependencies if field == "dependencies" else optional_dependencies).append(target)
                continue
            peer_match = re.fullmatch(r"      - (\S.*)", line)
            if peer_match and field == "transitivePeerDependencies":
                transitive_peers.append(
                    scalar(
                        peer_match.group(1),
                        f"dashboard pnpm snapshot {key} transitive peer",
                    )
                )
                continue
            _die(f"dashboard pnpm snapshot framing differs: {key}")
        for values in (dependencies, optional_dependencies, transitive_peers):
            if len(values) != len(set(values)):
                _die(f"dashboard pnpm snapshot edge is duplicate: {key}")
            values.sort(key=str.encode)
        snapshots[key] = {
            **metadata,
            "dependencies": dependencies,
            "key": key,
            "optional": optional,
            "optional_dependencies": optional_dependencies,
            "package_key": package_key,
            "root_groups": sorted(root_targets.get(key, [])),
            "transitive_peer_dependencies": transitive_peers,
        }
    represented_packages = {item["package_key"] for item in snapshots.values()}
    if any(key not in represented_packages for key in packages):
        _die("dashboard pnpm package universe has no exact snapshot instance")
    for target in root_targets:
        if target not in snapshots:
            _die(f"dashboard pnpm importer target is dangling: {target}")
    for item in snapshots.values():
        for target in (*item["dependencies"], *item["optional_dependencies"]):
            if target not in snapshots:
                _die(f"dashboard pnpm snapshot edge is dangling: {target}")
    return sorted(snapshots.values(), key=lambda item: item["key"].encode())


def pnpm_platform_components(
    components: list[dict[str, Any]], platform: str
) -> list[dict[str, Any]]:
    cpu = {"linux/amd64": "x64", "linux/arm64": "arm64"}[platform]

    def permits(values: list[str] | None, target: str) -> bool:
        if values is None:
            return True
        positives = [value for value in values if not value.startswith("!")]
        return f"!{target}" not in values and (not positives or target in positives)

    by_key = {item["key"]: item for item in components}
    if len(by_key) != len(components):
        _die("dashboard pnpm snapshot graph contains duplicate instances")
    queue = [
        {
            "optional": all(group == "optionalDependencies" for group in item["root_groups"]),
            "target": item["key"],
        }
        for item in components
        if item["root_groups"]
    ]
    if not queue:
        _die("dashboard pnpm native realization has no root importer targets")
    selected_keys: set[str] = set()
    while queue:
        edge = queue.pop(0)
        component = by_key.get(edge["target"])
        if component is None:
            _die(f"dashboard pnpm native realization edge is dangling: {edge['target']}")
        compatible = (
            permits(component["os"], "linux")
            and permits(component["cpu"], cpu)
            and permits(component["libc"], "glibc")
        )
        if not compatible:
            if edge["optional"] or component["optional"]:
                continue
            _die(
                f"dashboard pnpm required snapshot is incompatible with {platform}: "
                f"{component['key']}"
            )
        if component["key"] in selected_keys:
            continue
        selected_keys.add(component["key"])
        queue.extend({"optional": False, "target": target} for target in component["dependencies"])
        queue.extend(
            {"optional": True, "target": target} for target in component["optional_dependencies"]
        )
    selected = [item for item in components if item["key"] in selected_keys]
    if not selected:
        _die("dashboard pnpm native realization is empty")
    return selected


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _git_sha1_object_id(kind: str, raw: bytes) -> str:
    """Recompute one SHA-1 Git object identity from its exact loose framing."""

    if kind not in {"blob", "commit", "tree"}:
        _die("Git object kind differs")
    header = f"{kind} {len(raw)}\0".encode("ascii")
    return hashlib.sha1(header + raw, usedforsecurity=False).hexdigest()


def canonical_json(value: Any, *, terminal_lf: bool) -> bytes:
    """Encode closed ASCII JSON and reject non-integral or duplicate aliases."""

    def walk(item: Any, context: str) -> None:
        if item is None or isinstance(item, (bool, str)):
            return
        if isinstance(item, int):
            return
        if isinstance(item, float):
            _die(f"{context} contains a floating-point number")
        if isinstance(item, list):
            for position, child in enumerate(item):
                walk(child, f"{context}[{position}]")
            return
        if isinstance(item, dict):
            if not all(isinstance(key, str) for key in item):
                _die(f"{context} contains a non-string key")
            for key, child in item.items():
                walk(child, f"{context}.{key}")
            return
        _die(f"{context} contains unsupported JSON type {type(item).__name__}")

    walk(value, "canonical JSON")
    try:
        raw = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise MaterialBuildError("value is not canonical ASCII JSON") from exc
    return raw + (b"\n" if terminal_lf else b"")


def _open_directory(path: Path) -> int:
    """Open every path component without following a symlink."""

    absolute = path.absolute()
    parts = absolute.parts
    if not parts or parts[0] != "/" or any(part in {"", ".", ".."} for part in parts[1:]):
        _die("directory path is not one absolute direct path")
    descriptor = os.open(
        "/",
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        for part in parts[1:]:
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
        observed = os.fstat(descriptor)
        if not stat.S_ISDIR(observed.st_mode):
            _die("captured path is not a directory")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_descriptor(descriptor: int, *, maximum: int, context: str) -> bytes:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 0
        or before.st_size > maximum
    ):
        _die(f"{context} is not one bounded regular inode")
    chunks: list[bytes] = []
    remaining = before.st_size
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            _die(f"{context} changed while reading")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        _die(f"{context} grew while reading")
    after = os.fstat(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_after != identity_before:
        _die(f"{context} changed while reading")
    raw = b"".join(chunks)
    if len(raw) != before.st_size:
        _die(f"{context} size changed while reading")
    return raw


def read_regular(path: Path, *, maximum: int, context: str) -> bytes:
    """Read one bounded, direct, single-link regular file."""

    if path.name in {"", ".", ".."}:
        _die(f"{context} path is unsafe")
    parent = _open_directory(path.parent)
    try:
        descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent,
        )
    except OSError as exc:
        raise MaterialBuildError(f"{context} is unavailable") from exc
    finally:
        os.close(parent)
    try:
        return _read_descriptor(descriptor, maximum=maximum, context=context)
    finally:
        os.close(descriptor)


def require_empty_private_directory(path: Path, *, context: str) -> Path:
    """Require a caller-created, owner-private, empty output directory."""

    try:
        descriptor = _open_directory(path)
    except OSError as exc:
        raise MaterialBuildError(f"{context} does not exist") from exc
    try:
        observed = os.fstat(descriptor)
        if observed.st_uid != os.geteuid() or stat.S_IMODE(observed.st_mode) & 0o077:
            _die(f"{context} is not owner-private")
        if os.listdir(descriptor):  # noqa: PTH208 - fd-bound enumeration is intentional
            _die(f"{context} is not empty")
    finally:
        os.close(descriptor)
    return path.absolute()


def create_empty_private_directory(path: Path, *, context: str) -> Path:
    """Create one absent owner-private output directory under a direct parent."""

    if path.name in {"", ".", ".."} or "/" in path.name or not path.is_absolute():
        _die(f"{context} path is unsafe")
    parent = _open_directory(path.parent)
    try:
        try:
            os.mkdir(path.name, mode=0o700, dir_fd=parent)
        except FileExistsError as exc:
            raise MaterialBuildError(f"{context} already exists") from exc
        descriptor = os.open(
            path.name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent,
        )
        try:
            observed = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(observed.st_mode)
                or observed.st_uid != os.geteuid()
                or stat.S_IMODE(observed.st_mode) != 0o700
                or os.listdir(descriptor)  # noqa: PTH208 - fd-bound enumeration
            ):
                _die(f"{context} creation differs")
        finally:
            os.close(descriptor)
        os.fsync(parent)
    finally:
        os.close(parent)
    return path


def directory_identity(path: Path, *, context: str) -> DirectoryIdentity:
    """Capture one direct directory's stable device/inode/owner/mode."""

    descriptor = _open_directory(path)
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.geteuid():
            _die(f"{context} owner/type differs")
        return (
            observed.st_dev,
            observed.st_ino,
            observed.st_uid,
            stat.S_IMODE(observed.st_mode),
        )
    finally:
        os.close(descriptor)


def require_directory_identity(
    path: Path,
    expected: DirectoryIdentity,
    *,
    context: str,
) -> None:
    """Reject rename/recreate or owner/mode drift at a retained path."""

    if directory_identity(path, context=context) != expected:
        _die(f"{context} changed or was replaced")


def require_direct_directory(path: Path, *, context: str) -> Path:
    """Capture every component and require one direct directory path."""

    try:
        descriptor = _open_directory(path)
    except OSError as exc:
        raise MaterialBuildError(f"{context} does not exist directly") from exc
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISDIR(observed.st_mode):
            _die(f"{context} is not a directory")
    finally:
        os.close(descriptor)
    return path.absolute()


def atomic_write_new(path: Path, raw: bytes, *, mode: int = 0o600) -> None:
    """Create one new file without replacement and fsync its directory."""

    if path.name in {"", ".", ".."} or "/" in path.name or mode & ~0o777:
        _die("output path is unsafe")
    parent = _open_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(
            path.name,
            flags | getattr(os, "O_NOFOLLOW", 0),
            mode,
            dir_fd=parent,
        )
        try:
            os.fchmod(descriptor, mode)
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    _die("short output write")
                view = view[written:]
            os.fsync(descriptor)
            observed = os.fstat(descriptor)
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_nlink != 1
                or observed.st_size != len(raw)
                or stat.S_IMODE(observed.st_mode) != mode
            ):
                _die("new output file identity differs")
        finally:
            os.close(descriptor)
        os.fsync(parent)
    finally:
        os.close(parent)


def require_absent_direct(path: Path, *, context: str) -> None:
    """Require that a direct child name is absent under an fd-bound parent."""

    if path.name in {"", ".", ".."} or "/" in path.name:
        _die(f"{context} path is unsafe")
    parent = _open_directory(path.parent)
    try:
        try:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        _die(f"{context} already exists")
    finally:
        os.close(parent)


@dataclass(frozen=True)
class CommandResult:
    """Literal bounded output from one exact argv execution."""

    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes

    def record(self) -> dict[str, Any]:
        """Return the closed carrier record, including both literal streams."""

        return {
            "argv": list(self.argv),
            "exit_code": self.returncode,
            "stderr": _raw_bytes_record(self.stderr),
            "stdout": _raw_bytes_record(self.stdout),
        }


class CommandRunner(Protocol):
    """Injectable no-shell command interface used by fake-transport tests."""

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        executable_fd: int | None = None,
        stdin: bytes | None = None,
        pass_fds: Sequence[int] = (),
        timeout_seconds: int,
    ) -> CommandResult: ...


class SubprocessRunner:
    """Execute exact argv with a closed environment, no shell, and bounded logs."""

    @staticmethod
    def _kill_group(process: subprocess.Popen[bytes]) -> None:
        """Kill and reap the entire child session, including pipe-holding heirs."""

        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            raise MaterialBuildError(
                "exact material command process group could not be stopped"
            ) from exc
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired as exc:
            raise MaterialBuildError("exact material command process group did not stop") from exc

    def run(  # noqa: PLR0912, PLR0915 - bounded streaming process state machine
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        executable_fd: int | None = None,
        stdin: bytes | None = None,
        pass_fds: Sequence[int] = (),
        timeout_seconds: int,
    ) -> CommandResult:
        if (
            not argv
            or not all(isinstance(item, str) and item and "\0" not in item for item in argv)
            or not Path(argv[0]).is_absolute()
            or timeout_seconds < 1
            or timeout_seconds > 21_600
        ):
            _die("command boundary is malformed")
        closed_env = dict(env)
        if not all(
            isinstance(key, str)
            and isinstance(value, str)
            and key
            and "=" not in key
            and "\0" not in key + value
            for key, value in closed_env.items()
        ):
            _die("command environment is malformed")
        if stdin is not None and len(stdin) > 64 * 1024:
            _die("command stdin exceeds its reviewed bound")
        inherited: list[int] = []
        if executable_fd is not None:
            pass_fds = (*pass_fds, executable_fd)
        for descriptor in pass_fds:
            if isinstance(descriptor, bool) or not isinstance(descriptor, int) or descriptor < 0:
                _die("command inherited descriptor differs")
            observed_descriptor = os.fstat(descriptor)
            if not stat.S_ISREG(observed_descriptor.st_mode) or observed_descriptor.st_nlink != 1:
                _die("command inherited executable descriptor differs")
            inherited.append(descriptor)
        if len(inherited) != len(set(inherited)):
            _die("command inherited descriptor is duplicated")
        execution_argv = list(argv)
        if executable_fd is not None:
            execution_argv[0] = f"/proc/self/fd/{executable_fd}"
        directory = _open_directory(cwd)
        before = os.fstat(directory)
        process: subprocess.Popen[bytes] | None = None
        try:
            try:
                process = subprocess.Popen(  # noqa: S603 - fd-bound exact argv, no shell
                    execution_argv,
                    cwd=f"/proc/self/fd/{directory}",
                    env=closed_env,
                    stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    pass_fds=(directory, *inherited),
                    start_new_session=True,
                )
            except OSError as exc:
                raise MaterialBuildError("exact material command did not complete") from exc
            if stdin is not None:
                assert process.stdin is not None
                process.stdin.write(stdin)
                process.stdin.close()
            assert process.stdout is not None and process.stderr is not None
            streams = {process.stdout: bytearray(), process.stderr: bytearray()}
            selector = selectors.DefaultSelector()
            try:
                for stream in streams:
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ)
                deadline = time.monotonic() + timeout_seconds
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._kill_group(process)
                        _die("exact material command timed out")
                    events = selector.select(min(remaining, 1.0))
                    for key, _mask in events:
                        stream = next(
                            candidate for candidate in streams if candidate.fileno() == key.fd
                        )
                        try:
                            chunk = os.read(stream.fileno(), 64 * 1024)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(stream)
                            continue
                        streams[stream].extend(chunk)
                        if len(streams[stream]) > MAX_COMMAND_OUTPUT:
                            self._kill_group(process)
                            _die("material command output exceeds its reviewed bound")
            finally:
                selector.close()
            returncode = process.wait()
            after = os.fstat(directory)
            if (before.st_dev, before.st_ino, before.st_mode) != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
            ):
                _die("command working directory changed during execution")
        finally:
            if process is not None and process.poll() is None:
                self._kill_group(process)
            if process is not None:
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()
            os.close(directory)
        return CommandResult(
            tuple(argv),
            returncode,
            bytes(streams[process.stdout]),
            bytes(streams[process.stderr]),
        )


def require_success(result: CommandResult, *, context: str) -> CommandResult:
    if result.returncode != 0:
        _die(f"{context} failed with exit code {result.returncode}")
    return result


def file_records(  # noqa: PLR0915 - fd-bound recursive inventory is intentionally one transaction
    root: Path,
    *,
    exclude: frozenset[str] = frozenset({"inventory.json"}),
    exclude_patterns: Sequence[str] = (),
    maximum_bytes: int = MAX_TREE_BYTES,
    maximum_files: int = MAX_FILES,
) -> list[dict[str, Any]]:
    """Seal a complete regular payload tree in strict UTF-8 path order."""

    if maximum_bytes < 1 or maximum_bytes > MAX_TREE_BYTES:
        _die("payload byte bound differs")
    if maximum_files < 1 or maximum_files > MAX_FILES:
        _die("payload file bound differs")
    patterns = _validate_exclusion_patterns(exclude_patterns)
    records: list[dict[str, Any]] = []
    total_bytes = 0
    root_descriptor = _open_directory(root)

    def visit(directory: int, prefix: PurePosixPath) -> None:  # noqa: PLR0912
        nonlocal total_bytes
        try:
            names = sorted(os.listdir(directory), key=lambda item: item.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise MaterialBuildError("payload contains a non-UTF-8 path") from exc
        for name in names:
            if name in {"", ".", ".."} or "/" in name or "\\" in name:
                _die("payload contains an unsafe path component")
            logical_path = prefix / name
            logical = logical_path.as_posix()
            observed = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISLNK(observed.st_mode):
                _die(f"payload contains symlink {logical}")
            if stat.S_ISDIR(observed.st_mode):
                if _matches_exclusion(logical_path, patterns):
                    continue
                child = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory,
                )
                try:
                    captured_directory = os.fstat(child)
                    if (captured_directory.st_dev, captured_directory.st_ino) != (
                        observed.st_dev,
                        observed.st_ino,
                    ):
                        _die(f"payload directory changed during capture: {logical}")
                    visit(child, logical_path)
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(observed.st_mode):
                _die(f"payload entry is not regular: {logical}")
            if logical in exclude or _matches_exclusion(logical_path, patterns):
                continue
            if (
                len(records) >= maximum_files
                or observed.st_size > MAX_FILE_BYTES
                or observed.st_size > maximum_bytes - total_bytes
            ):
                _die("payload exceeds its reviewed file/size bound")
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory,
            )
            try:
                raw = _read_descriptor(
                    descriptor, maximum=MAX_FILE_BYTES, context=f"payload {logical}"
                )
                captured = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            if (captured.st_dev, captured.st_ino) != (observed.st_dev, observed.st_ino):
                _die(f"payload entry changed during capture: {logical}")
            records.append(
                {
                    "mode": f"{stat.S_IMODE(captured.st_mode):04o}",
                    "path": logical,
                    "sha256": sha256(raw),
                    "size": len(raw),
                }
            )
            total_bytes += len(raw)

    try:
        visit(root_descriptor, PurePosixPath())
    finally:
        os.close(root_descriptor)
    if not records:
        _die("payload tree is empty")
    return records


def _validate_exclusion_patterns(patterns: Sequence[str]) -> tuple[str, ...]:
    """Validate the closed basename/suffix exclusion grammar without ambient globbing."""

    normalized = tuple(patterns)
    if len(normalized) != len(set(normalized)) or any(
        not isinstance(pattern, str)
        or not pattern
        or "/" in pattern
        or "\\" in pattern
        or ("*" in pattern and (not pattern.startswith("*.") or pattern.count("*") != 1))
        or any(character in pattern for character in "?[]")
        for pattern in normalized
    ):
        _die("selected context exclusion policy differs")
    return normalized


def _matches_exclusion(path: PurePosixPath, patterns: Sequence[str]) -> bool:
    """Apply exclusions to path components exactly like the production verifier."""

    for component in path.parts:
        for pattern in patterns:
            if pattern.startswith("*."):
                if component.endswith(pattern[1:]):
                    return True
            elif component == pattern:
                return True
    return False


def install_inventory(
    root: Path,
    *,
    platform: str,
    inventory_format: str,
    tree_format: str,
) -> dict[str, Any]:
    """Install canonical inventory.json and return its manifest seals."""

    if platform not in PLATFORMS:
        _die("material platform differs")
    records = file_records(root)
    inventory = {"files": records, "format": inventory_format, "platform": platform}
    inventory_raw = canonical_json(inventory, terminal_lf=True)
    atomic_write_new(root / "inventory.json", inventory_raw, mode=0o644)
    tree = {"files": records, "format": tree_format, "platform": platform}
    return {
        "inventory_entries": len(records),
        "inventory_sha256": sha256(inventory_raw),
        "inventory_size": len(inventory_raw),
        "tree_bytes": sum(record["size"] for record in records),
        "tree_sha256": sha256(canonical_json(tree, terminal_lf=False)),
    }


def compare_payload_roots(left: Path, right: Path) -> dict[str, Any]:
    """Require two isolated output trees to be byte/mode/path identical."""

    left_records = file_records(left, exclude=frozenset())
    right_records = file_records(right, exclude=frozenset())
    if left_records != right_records:
        left_by_path = {record["path"]: record for record in left_records}
        right_by_path = {record["path"]: record for record in right_records}
        differing = sorted(
            path
            for path in left_by_path.keys() | right_by_path.keys()
            if left_by_path.get(path) != right_by_path.get(path)
        )
        _die("isolated material builds differ: " + ", ".join(differing[:20]))
    framing = {"files": left_records, "format": "z4j-production-build-comparison-v1"}
    return {
        "bytes": sum(record["size"] for record in left_records),
        "entries": len(left_records),
        "sha256": sha256(canonical_json(framing, terminal_lf=False)),
    }


def capture_selected_paths(  # noqa: PLR0912,PLR0915 - closed no-follow tree copier
    source_root: Path,
    destination_root: Path,
    *,
    selections: Sequence[str],
    executables: Sequence[str] = (),
    exclusions: Sequence[str] = (),
) -> list[dict[str, Any]]:
    """Copy an exact context with canonical modes through fd-bound reads."""

    require_direct_directory(source_root, context="selected context source")
    require_empty_private_directory(destination_root, context="selected context destination")
    normalized: list[PurePosixPath] = []
    for selection in selections:
        logical = PurePosixPath(selection)
        if (
            not selection
            or logical.is_absolute()
            or ".." in logical.parts
            or "\\" in selection
            or logical.as_posix() != selection
        ):
            _die("selected context path differs")
        normalized.append(logical)
    if normalized != sorted(set(normalized), key=lambda item: item.as_posix().encode("utf-8")):
        _die("selected context paths are duplicate or unsorted")
    executable_set = frozenset(executables)
    exclusion_patterns = _validate_exclusion_patterns(exclusions)
    if (
        len(executable_set) != len(executables)
        or tuple(executables) != tuple(sorted(executable_set, key=str.encode))
        or any(
            not item
            or PurePosixPath(item).is_absolute()
            or PurePosixPath(item).as_posix() != item
            or ".." in PurePosixPath(item).parts
            for item in executable_set
        )
    ):
        _die("selected context executable allowlist differs")
    for position, left in enumerate(normalized):
        for right in normalized[position + 1 :]:
            if left in right.parents:
                _die("selected context paths overlap")

    source_records: list[dict[str, Any]] = []
    for logical_selection in normalized:
        if _matches_exclusion(logical_selection, exclusion_patterns):
            _die("selected context exact input is excluded by its policy")
        source = source_root / logical_selection.as_posix()
        observed = source.stat(follow_symlinks=False)
        if stat.S_ISLNK(observed.st_mode):
            _die("selected context contains a symlink")
        if stat.S_ISDIR(observed.st_mode):
            remaining_files = MAX_FILES - len(source_records)
            remaining_bytes = MAX_CONTEXT_BYTES - sum(item["size"] for item in source_records)
            if remaining_files < 1 or remaining_bytes < 1:
                _die("selected context exceeds its aggregate bound")
            records = file_records(
                source,
                exclude=frozenset(),
                exclude_patterns=exclusion_patterns,
                maximum_bytes=remaining_bytes,
                maximum_files=remaining_files,
            )
            for record in records:
                logical_path = (logical_selection / record["path"]).as_posix()
                mode = int(record["mode"], 8)
                expected_executable = logical_path in executable_set
                if (
                    not mode & 0o400
                    or mode & 0o7022
                    or (expected_executable and not mode & 0o100)
                    or (not expected_executable and mode & 0o111)
                ):
                    _die(f"selected context file mode differs: {logical_path}")
                source_records.append(
                    {
                        **record,
                        "mode": "0755" if expected_executable else "0644",
                        "path": logical_path,
                    }
                )
        elif stat.S_ISREG(observed.st_mode):
            remaining_bytes = MAX_CONTEXT_BYTES - sum(item["size"] for item in source_records)
            raw = read_regular(
                source,
                maximum=min(MAX_FILE_BYTES, remaining_bytes),
                context=f"context {logical_selection}",
            )
            mode = stat.S_IMODE(observed.st_mode)
            expected_executable = logical_selection.as_posix() in executable_set
            if (
                not mode & 0o400
                or mode & 0o7022
                or (expected_executable and not mode & 0o100)
                or (not expected_executable and mode & 0o111)
            ):
                _die(f"selected context file mode differs: {logical_selection}")
            source_records.append(
                {
                    "mode": "0755" if expected_executable else "0644",
                    "path": logical_selection.as_posix(),
                    "sha256": sha256(raw),
                    "size": len(raw),
                }
            )
        else:
            _die("selected context entry is not regular or a directory")
    source_records.sort(key=lambda item: item["path"].encode("utf-8"))
    if not source_records or len({item["path"] for item in source_records}) != len(source_records):
        _die("selected context is empty or ambiguous")
    if executable_set != {item["path"] for item in source_records if item["mode"] == "0755"}:
        _die("selected context executable allowlist is not fully selected")

    for record in source_records:
        relative = PurePosixPath(record["path"])
        parent = destination_root
        for component in relative.parts[:-1]:
            parent = parent / component
            try:
                parent.mkdir(mode=0o700)
            except FileExistsError:
                require_direct_directory(parent, context="selected context destination parent")
        source = source_root / record["path"]
        raw = read_regular(source, maximum=MAX_FILE_BYTES, context=f"context {record['path']}")
        if sha256(raw) != record["sha256"] or len(raw) != record["size"]:
            _die(f"selected context changed during capture: {record['path']}")
        atomic_write_new(destination_root / record["path"], raw, mode=int(record["mode"], 8))
    captured = file_records(destination_root, exclude=frozenset())
    if captured != source_records:
        _die("selected context snapshot differs from its source capture")
    return captured


def _validate_git_reference(value: str) -> str:
    """Accept one unambiguous full ref (or detached-checkout ``HEAD``)."""

    if not isinstance(value, str) or not value or "\0" in value:
        _die("claimed Git reference differs")
    if value == "HEAD":
        return value
    components = value.split("/")
    if (
        len(components) < 3
        or components[0] != "refs"
        or any(
            not component
            or component.startswith(".")
            or component.endswith(".")
            or component.endswith(".lock")
            for component in components
        )
        or value.endswith("/")
        or ".." in value
        or "//" in value
        or "@{" in value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        or any(character in value for character in " ~^:?*[\\")
    ):
        _die("claimed Git reference differs")
    return value


def _validate_source_prefix(value: str) -> PurePosixPath:
    if not isinstance(value, str):
        _die("claimed Git source prefix differs")
    logical = PurePosixPath(value)
    if (
        not value
        or logical.is_absolute()
        or logical.as_posix() != value
        or "." in logical.parts
        or ".." in logical.parts
        or "\\" in value
        or "\0" in value
        or "\n" in value
        or "\r" in value
    ):
        _die("claimed Git source prefix differs")
    return logical


def _validate_git_tool_authority(value: Mapping[str, Any]) -> tuple[Path, str, int, str]:
    if not isinstance(value, Mapping) or set(value) != {
        "path",
        "sha256",
        "size",
        "version_output_sha256",
    }:
        _die("Git tool authority differs")
    path = value["path"]
    digest = value["sha256"]
    size = value["size"]
    version_digest = value["version_output_sha256"]
    if (
        not isinstance(path, str)
        or not Path(path).is_absolute()
        or Path(path).as_posix() != path
        or "." in Path(path).parts
        or ".." in Path(path).parts
        or "\\" in path
        or "\0" in path
        or "\n" in path
        or "\r" in path
        or Path(path).name in {"", ".", ".."}
        or not isinstance(digest, str)
        or HEX64.fullmatch(digest) is None
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size < 1
        or size > MAX_FILE_BYTES
        or not isinstance(version_digest, str)
        or HEX64.fullmatch(version_digest) is None
    ):
        _die("Git tool authority is incomplete or malformed")
    return Path(path), digest, size, version_digest


def _git_environment() -> dict[str, str]:
    """Return the closed, local-only Git environment used for source proof."""

    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_ASKPASS": "/bin/false",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "SSH_ASKPASS": "/bin/false",
        "XDG_CONFIG_HOME": "/nonexistent",
    }


def _git_argv(executable: Path, arguments: Sequence[str]) -> list[str]:
    return [
        str(executable),
        "--no-pager",
        "--no-replace-objects",
        "--literal-pathspecs",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.excludesFile=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        *arguments,
    ]


def _git_output(
    runner: CommandRunner,
    executable: Path,
    executable_fd: int,
    repo_root: Path,
    *arguments: str,
    context: str,
) -> bytes:
    result = require_success(
        runner.run(
            _git_argv(executable, arguments),
            cwd=repo_root,
            env=_git_environment(),
            executable_fd=executable_fd,
            timeout_seconds=120,
        ),
        context=context,
    )
    if result.stderr:
        _die(f"{context} wrote an unexpected diagnostic")
    return result.stdout


def _one_ascii_line(raw: bytes, *, context: str) -> str:
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1 or b"\r" in raw:
        _die(f"{context} output framing differs")
    try:
        value = raw[:-1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise MaterialBuildError(f"{context} output is not ASCII") from exc
    if not value:
        _die(f"{context} output is empty")
    return value


def _normalize_git_selections(
    selections: Sequence[str],
    *,
    source_prefix: PurePosixPath,
) -> tuple[tuple[PurePosixPath, ...], tuple[str, ...]]:
    normalized: list[PurePosixPath] = []
    for selection in selections:
        if not isinstance(selection, str):
            _die("selected Git context path differs")
        logical = PurePosixPath(selection)
        if (
            not selection
            or logical.is_absolute()
            or logical.as_posix() != selection
            or "." in logical.parts
            or ".." in logical.parts
            or "\\" in selection
            or "\0" in selection
            or "\n" in selection
            or "\r" in selection
        ):
            _die("selected Git context path differs")
        normalized.append(logical)
    ordered = tuple(sorted(set(normalized), key=lambda item: item.as_posix().encode("utf-8")))
    if tuple(normalized) != ordered:
        _die("selected Git context paths are duplicate or unsorted")
    for position, left in enumerate(ordered):
        for right in ordered[position + 1 :]:
            if left in right.parents:
                _die("selected Git context paths overlap")
    return ordered, tuple((source_prefix / item).as_posix() for item in ordered)


def _relative_git_path(
    raw_path: bytes,
    *,
    source_prefix: PurePosixPath,
    selections: Sequence[PurePosixPath],
    context: str,
) -> PurePosixPath:
    try:
        path = raw_path.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MaterialBuildError(f"{context} contains a non-UTF-8 path") from exc
    logical = PurePosixPath(path)
    prefix_parts = source_prefix.parts
    if (
        not path
        or logical.is_absolute()
        or logical.as_posix() != path
        or "." in logical.parts
        or ".." in logical.parts
        or "\\" in path
        or "\n" in path
        or "\r" in path
        or logical.parts[: len(prefix_parts)] != prefix_parts
        or len(logical.parts) <= len(prefix_parts)
    ):
        _die(f"{context} contains a path outside the claimed source prefix")
    relative = PurePosixPath(*logical.parts[len(prefix_parts) :])
    if not any(relative == selection or selection in relative.parents for selection in selections):
        _die(f"{context} contains a path outside the exact selection")
    return relative


def _git_tree_projection(
    raw: bytes,
    *,
    source_prefix: PurePosixPath,
    selections: Sequence[PurePosixPath],
    executables: frozenset[str],
    exclusions: Sequence[str],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    total = 0
    encoded_records = raw.split(b"\0")
    if not raw or encoded_records[-1] or any(not item for item in encoded_records[:-1]):
        _die("claimed Git tree listing framing differs")
    for encoded in encoded_records[:-1]:
        try:
            metadata, raw_path = encoded.split(b"\t", 1)
            mode, object_type, object_id, raw_size = metadata.decode("ascii").split()
        except (UnicodeDecodeError, ValueError) as exc:
            raise MaterialBuildError("claimed Git tree listing is malformed") from exc
        relative = _relative_git_path(
            raw_path,
            source_prefix=source_prefix,
            selections=selections,
            context="claimed Git tree",
        )
        logical = relative.as_posix()
        if mode not in {"100644", "100755"} or object_type != "blob":
            _die(f"claimed Git tree contains an unsupported entry: {logical}")
        if GIT_SHA1.fullmatch(object_id) is None or not raw_size.isdecimal():
            _die(f"claimed Git tree blob identity differs: {logical}")
        size = int(raw_size)
        if size > MAX_COMMAND_OUTPUT or size > MAX_FILE_BYTES:
            _die(f"claimed Git tree blob exceeds the bounded Git read: {logical}")
        if _matches_exclusion(relative, exclusions):
            continue
        expected_mode = "100755" if logical in executables else "100644"
        if mode != expected_mode:
            _die(f"claimed Git tree executable projection differs: {logical}")
        if len(records) >= MAX_FILES or size > MAX_CONTEXT_BYTES - total:
            _die("claimed Git tree selection exceeds its aggregate bound")
        records.append(
            {
                "blob": object_id,
                "mode": "0755" if mode == "100755" else "0644",
                "path": logical,
                "size": size,
            }
        )
        total += size
    records.sort(key=lambda item: item["path"].encode("utf-8"))
    paths = [item["path"] for item in records]
    if not records or len(paths) != len(set(paths)):
        _die("claimed Git tree selection is empty or ambiguous")
    if executables != {item["path"] for item in records if item["mode"] == "0755"}:
        _die("claimed Git executable allowlist is not fully selected")
    return records


def _git_tree_object_ids(raw: bytes, *, root: str) -> tuple[str, ...]:
    """Extract every tree traversed by one selected recursive listing."""

    identities = {root}
    paths: set[bytes] = set()
    encoded_records = raw.split(b"\0")
    if not raw or encoded_records[-1] or any(not item for item in encoded_records[:-1]):
        _die("claimed Git object graph listing framing differs")
    for encoded in encoded_records[:-1]:
        try:
            metadata, path = encoded.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split()
        except (UnicodeDecodeError, ValueError) as exc:
            raise MaterialBuildError("claimed Git object graph listing is malformed") from exc
        if (
            not path
            or path in paths
            or b"\0" in path
            or GIT_SHA1.fullmatch(object_id) is None
            or (object_type == "tree" and mode != "040000")
            or (object_type == "blob" and mode not in {"100644", "100755", "120000"})
            or object_type not in {"blob", "tree"}
        ):
            _die("claimed Git object graph listing differs")
        paths.add(path)
        if object_type == "tree":
            identities.add(object_id)
        if len(paths) > MAX_FILES:
            _die("claimed Git object graph exceeds its reviewed bound")
    if len(identities) == 1:
        _die("claimed Git object graph does not traverse the source prefix")
    return tuple(sorted(identities))


def _git_commit_tree(raw: bytes, *, context: str) -> str:
    """Read the exact root-tree header from a raw, independently hashed commit."""

    first, separator, _remainder = raw.partition(b"\n")
    if not separator or not first.startswith(b"tree ") or len(first) != 45:
        _die(f"{context} root tree header differs")
    try:
        tree = first.removeprefix(b"tree ").decode("ascii")
    except UnicodeDecodeError as exc:
        raise MaterialBuildError(f"{context} root tree header is not ASCII") from exc
    if GIT_SHA1.fullmatch(tree) is None:
        _die(f"{context} root tree identity differs")
    return tree


def _git_index_projection(
    raw: bytes,
    *,
    source_prefix: PurePosixPath,
    selections: Sequence[PurePosixPath],
    executables: frozenset[str],
    exclusions: Sequence[str],
) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    encoded_records = raw.split(b"\0")
    if not raw or encoded_records[-1] or any(not item for item in encoded_records[:-1]):
        _die("selected Git index listing framing differs")
    for encoded in encoded_records[:-1]:
        try:
            metadata, raw_path = encoded.split(b"\t", 1)
            mode, object_id, stage = metadata.decode("ascii").split()
        except (UnicodeDecodeError, ValueError) as exc:
            raise MaterialBuildError("selected Git index listing is malformed") from exc
        relative = _relative_git_path(
            raw_path,
            source_prefix=source_prefix,
            selections=selections,
            context="selected Git index",
        )
        logical = relative.as_posix()
        if (
            mode not in {"100644", "100755"}
            or GIT_SHA1.fullmatch(object_id) is None
            or stage != "0"
        ):
            _die(f"selected Git index contains an unsupported entry: {logical}")
        if _matches_exclusion(relative, exclusions):
            continue
        expected_mode = "100755" if logical in executables else "100644"
        if mode != expected_mode:
            _die(f"selected Git index executable projection differs: {logical}")
        records.append(
            {
                "blob": object_id,
                "mode": "0755" if mode == "100755" else "0644",
                "path": logical,
            }
        )
    records.sort(key=lambda item: item["path"].encode("utf-8"))
    if len(records) != len({item["path"] for item in records}):
        _die("selected Git index projection is ambiguous")
    return records


def _source_file_projection_raw(files: Sequence[Mapping[str, Any]]) -> bytes:
    return canonical_json(
        {"files": list(files), "format": SOURCE_FILE_PROJECTION_FORMAT},
        terminal_lf=False,
    )


def source_file_projection_seal(files: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Return the compact seal later carried by cross-platform aggregation."""

    validated = _validate_tree_records(list(files), context="source file projection")
    raw = _source_file_projection_raw(validated)
    return {"entries": len(validated), "sha256": sha256(raw), "size": len(raw)}


def capture_git_selected_paths(  # noqa: PLR0912,PLR0915
    repo_root: Path,
    source_root: Path,
    destination_root: Path,
    *,
    reference: str,
    claimed_commit: str,
    claimed_tree: str,
    source_prefix: str,
    selections: Sequence[str],
    git_authority: Mapping[str, Any],
    runner: CommandRunner,
    executables: Sequence[str] = (),
    exclusions: Sequence[str] = (),
) -> dict[str, Any]:
    """Materialize selected raw blobs and prove checkout/index equality.

    The authenticated commit/tree is publication authority.  The mutable
    checkout and index are read only as negative controls: any selected dirty,
    staged, untracked, symlink, or unsupported entry fails, but their bytes are
    never copied into the Buildx context.
    """

    if GIT_SHA1.fullmatch(claimed_commit) is None or GIT_SHA1.fullmatch(claimed_tree) is None:
        _die("claimed Git commit/tree identity differs")
    claimed_reference = _validate_git_reference(reference)
    prefix = _validate_source_prefix(source_prefix)
    normalized, prefixed = _normalize_git_selections(selections, source_prefix=prefix)
    executable_set = frozenset(executables)
    exclusion_patterns = _validate_exclusion_patterns(exclusions)
    if (
        len(executable_set) != len(executables)
        or tuple(executables) != tuple(sorted(executable_set, key=str.encode))
        or any(
            not isinstance(item, str)
            or not item
            or PurePosixPath(item).is_absolute()
            or PurePosixPath(item).as_posix() != item
            or "." in PurePosixPath(item).parts
            or ".." in PurePosixPath(item).parts
            or "\\" in item
            or "\0" in item
            or "\n" in item
            or "\r" in item
            for item in executable_set
        )
    ):
        _die("selected Git executable allowlist differs")

    repository = require_direct_directory(repo_root, context="Git source repository root")
    source = require_direct_directory(source_root, context="Git selected source root")
    expected_source = (repository / prefix.as_posix()).absolute()
    if source != expected_source:
        _die("Git selected source root differs from its claimed prefix")
    administration = require_direct_directory(
        repository / ".git", context="Git source administrative directory"
    )
    object_store = require_direct_directory(
        administration / "objects", context="Git source object directory"
    )
    object_info = require_direct_directory(
        object_store / "info", context="Git source object information directory"
    )
    require_absent_direct(object_info / "alternates", context="Git source object alternates")
    require_absent_direct(
        object_info / "http-alternates", context="Git source HTTP object alternates"
    )
    require_absent_direct(
        administration / "commondir", context="Git source common-directory indirection"
    )
    repository_identity = directory_identity(repository, context="Git source repository root")
    source_identity = directory_identity(source, context="Git selected source root")
    administration_identity = directory_identity(
        administration, context="Git source administrative directory"
    )
    object_store_identity = directory_identity(object_store, context="Git source object directory")
    object_info_identity = directory_identity(
        object_info, context="Git source object information directory"
    )
    require_empty_private_directory(destination_root, context="Git source materialization")
    git_path, git_sha256, git_size, version_sha256 = _validate_git_tool_authority(git_authority)

    with private_temporary_directory(prefix="z4j-git-source-context.") as private_root:
        captured_git = private_root / "git"
        capture_sealed_executable(
            git_path,
            captured_git,
            expected_sha256=git_sha256,
            expected_size=git_size,
            context="policy-selected Git executable",
        )
        checkout_audit = private_root / "checkout"
        checkout_audit.mkdir(mode=0o700)
        with held_verified_executable(
            captured_git,
            expected_sha256=git_sha256,
            expected_size=git_size,
            context="held policy-selected Git executable",
        ) as git_fd:
            version = require_success(
                runner.run(
                    [str(captured_git), "--version"],
                    cwd=repository,
                    env=_git_environment(),
                    executable_fd=git_fd,
                    timeout_seconds=60,
                ),
                context="policy-selected Git version probe",
            )
            _one_ascii_line(version.stdout, context="policy-selected Git version probe")
            if version.stderr or sha256(version.stdout) != version_sha256:
                _die("policy-selected Git version transcript differs")

            def git(*arguments: str, context: str) -> bytes:
                return _git_output(
                    runner,
                    captured_git,
                    git_fd,
                    repository,
                    *arguments,
                    context=context,
                )

            top_level = _one_ascii_line(
                git("rev-parse", "--show-toplevel", context="Git repository root resolution"),
                context="Git repository root resolution",
            )
            if Path(top_level).absolute() != repository:
                _die("Git repository root resolution differs")
            object_format = _one_ascii_line(
                git("rev-parse", "--show-object-format", context="Git object format resolution"),
                context="Git object format resolution",
            )
            if object_format != "sha1":
                _die("Git repository object format is not the reviewed SHA-1 format")

            def resolve_identity() -> tuple[str, str]:
                commit = _one_ascii_line(
                    git(
                        "rev-parse",
                        "--verify",
                        "--end-of-options",
                        f"{claimed_reference}^{{commit}}",
                        context="claimed Git reference resolution",
                    ),
                    context="claimed Git reference resolution",
                )
                tree = _one_ascii_line(
                    git(
                        "rev-parse",
                        "--verify",
                        "--end-of-options",
                        f"{claimed_commit}^{{tree}}",
                        context="claimed Git commit tree resolution",
                    ),
                    context="claimed Git commit tree resolution",
                )
                if commit != claimed_commit or tree != claimed_tree:
                    _die("claimed Git reference/commit/tree does not identify the checkout")
                return commit, tree

            resolve_identity()
            commit_raw = git(
                "cat-file",
                "commit",
                claimed_commit,
                context="claimed Git commit object",
            )
            if (
                _git_sha1_object_id("commit", commit_raw) != claimed_commit
                or _git_commit_tree(commit_raw, context="claimed Git commit object") != claimed_tree
            ):
                _die("claimed Git commit object identity/tree differs")
            object_graph_raw = git(
                "ls-tree",
                "-r",
                "-t",
                "-z",
                "--full-tree",
                claimed_tree,
                "--",
                *prefixed,
                context="claimed Git object graph projection",
            )
            tree_object_ids = _git_tree_object_ids(object_graph_raw, root=claimed_tree)
            for object_id in tree_object_ids:
                raw_tree = git(
                    "cat-file",
                    "tree",
                    object_id,
                    context=f"claimed Git tree object {object_id}",
                )
                if _git_sha1_object_id("tree", raw_tree) != object_id:
                    _die(f"claimed Git tree object identity differs: {object_id}")
            tree_raw = git(
                "ls-tree",
                "-r",
                "-l",
                "-z",
                "--full-tree",
                claimed_tree,
                "--",
                *prefixed,
                context="claimed Git tree projection",
            )
            tree_projection = _git_tree_projection(
                tree_raw,
                source_prefix=prefix,
                selections=normalized,
                executables=executable_set,
                exclusions=exclusion_patterns,
            )
            index_raw = git(
                "ls-files",
                "--stage",
                "-z",
                "--",
                *prefixed,
                context="selected Git index projection",
            )
            index_projection = _git_index_projection(
                index_raw,
                source_prefix=prefix,
                selections=normalized,
                executables=executable_set,
                exclusions=exclusion_patterns,
            )
            comparable_tree = [
                {key: item[key] for key in ("blob", "mode", "path")} for item in tree_projection
            ]
            if index_projection != comparable_tree:
                _die("selected Git index differs from the claimed commit tree")

            expected_records: list[dict[str, Any]] = []
            blob_cache: dict[str, bytes] = {}
            for item in tree_projection:
                object_id = item["blob"]
                raw = blob_cache.get(object_id)
                if raw is None:
                    raw = git(
                        "cat-file",
                        "blob",
                        object_id,
                        context=f"claimed Git blob {object_id}",
                    )
                    blob_cache[object_id] = raw
                if len(raw) != item["size"] or _git_sha1_object_id("blob", raw) != object_id:
                    _die(f"claimed Git blob identity/size differs: {item['path']}")
                relative = PurePosixPath(item["path"])
                parent = destination_root
                for component in relative.parts[:-1]:
                    parent = parent / component
                    try:
                        parent.mkdir(mode=0o700)
                    except FileExistsError:
                        require_direct_directory(
                            parent, context="Git source materialization parent"
                        )
                output = destination_root.joinpath(*relative.parts)
                atomic_write_new(output, raw, mode=int(item["mode"], 8))
                expected_records.append(
                    {
                        "mode": item["mode"],
                        "path": item["path"],
                        "sha256": sha256(raw),
                        "size": len(raw),
                    }
                )
            captured = file_records(destination_root, exclude=frozenset())
            if captured != expected_records:
                _die("materialized Git source differs from its claimed blob projection")

            checkout = capture_selected_paths(
                source,
                checkout_audit,
                selections=selections,
                executables=executables,
                exclusions=exclusions,
            )
            if checkout != captured:
                _die("selected worktree contains dirty or untracked build input")

            post_tree_raw = git(
                "ls-tree",
                "-r",
                "-l",
                "-z",
                "--full-tree",
                claimed_tree,
                "--",
                *prefixed,
                context="claimed Git tree projection readback",
            )
            post_commit_raw = git(
                "cat-file",
                "commit",
                claimed_commit,
                context="claimed Git commit object readback",
            )
            post_object_graph_raw = git(
                "ls-tree",
                "-r",
                "-t",
                "-z",
                "--full-tree",
                claimed_tree,
                "--",
                *prefixed,
                context="claimed Git object graph projection readback",
            )
            post_tree_object_ids = _git_tree_object_ids(post_object_graph_raw, root=claimed_tree)
            for object_id in post_tree_object_ids:
                raw_tree = git(
                    "cat-file",
                    "tree",
                    object_id,
                    context=f"claimed Git tree object {object_id} readback",
                )
                if _git_sha1_object_id("tree", raw_tree) != object_id:
                    _die(f"claimed Git tree object identity changed: {object_id}")
            post_index_raw = git(
                "ls-files",
                "--stage",
                "-z",
                "--",
                *prefixed,
                context="selected Git index projection readback",
            )
            if (
                post_commit_raw != commit_raw
                or post_object_graph_raw != object_graph_raw
                or post_tree_object_ids != tree_object_ids
                or post_tree_raw != tree_raw
                or post_index_raw != index_raw
            ):
                _die("selected Git object graph, tree, or index changed during materialization")
            resolve_identity()

    require_directory_identity(
        repository, repository_identity, context="Git source repository root"
    )
    require_directory_identity(source, source_identity, context="Git selected source root")
    require_directory_identity(
        administration,
        administration_identity,
        context="Git source administrative directory",
    )
    require_directory_identity(
        object_store, object_store_identity, context="Git source object directory"
    )
    require_directory_identity(
        object_info, object_info_identity, context="Git source object information directory"
    )
    require_absent_direct(
        object_info / "alternates", context="Git source object alternates readback"
    )
    require_absent_direct(
        object_info / "http-alternates", context="Git source HTTP object alternates readback"
    )
    require_absent_direct(
        administration / "commondir", context="Git source common-directory indirection readback"
    )
    if file_records(destination_root, exclude=frozenset()) != captured:
        _die("materialized Git source changed after source proof")
    return {
        "files": captured,
        "git": {
            "commit": claimed_commit,
            "format": GIT_SOURCE_BINDING_FORMAT,
            "reference": claimed_reference,
            "source_prefix": prefix.as_posix(),
            "tree": claimed_tree,
        },
    }


def _canonical_tar_bytes(
    members: Sequence[tuple[Mapping[str, Any], bytes]],
    *,
    context: str,
) -> bytes:
    """Encode one canonical USTAR stream with no ambient metadata."""

    output = io.BytesIO()
    try:
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for record, raw in members:
                path = record["path"]
                mode = record["mode"]
                if (
                    not isinstance(path, str)
                    or not isinstance(mode, str)
                    or mode not in {"0644", "0755"}
                    or len(raw) != record["size"]
                    or sha256(raw) != record["sha256"]
                ):
                    _die(f"{context} canonical member differs")
                info = tarfile.TarInfo(path)
                info.type = tarfile.REGTYPE
                info.mode = int(mode, 8)
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
    except (OSError, tarfile.TarError, ValueError) as exc:
        raise MaterialBuildError(f"{context} cannot be represented as canonical USTAR") from exc
    raw_output = output.getvalue()
    if len(raw_output) > MAX_TREE_BYTES or len(raw_output) % tarfile.BLOCKSIZE:
        _die(f"{context} canonical USTAR size differs")
    return raw_output


def _validate_tree_records(
    values: Any,
    *,
    context: str,
) -> list[dict[str, Any]]:
    """Validate one closed, sorted, traversal-free regular-file inventory."""

    if not isinstance(values, list) or not values or len(values) > MAX_FILES:
        _die(f"{context} inventory differs")
    records: list[dict[str, Any]] = []
    paths: list[str] = []
    total = 0
    for position, value in enumerate(values):
        if not isinstance(value, dict) or set(value) != {"mode", "path", "sha256", "size"}:
            _die(f"{context} record {position} keys differ")
        path = value["path"]
        mode = value["mode"]
        size = value["size"]
        digest = value["sha256"]
        if (
            not isinstance(path, str)
            or not path
            or path.startswith("/")
            or path.startswith("./")
            or path.endswith("/")
            or "//" in path
            or "\\" in path
            or "\0" in path
            or "\n" in path
            or "\r" in path
            or PurePosixPath(path).as_posix() != path
            or any(component in {"", ".", ".."} for component in PurePosixPath(path).parts)
            or mode not in {"0644", "0755"}
            or not isinstance(digest, str)
            or HEX64.fullmatch(digest) is None
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or size > MAX_FILE_BYTES
        ):
            _die(f"{context} record {position} differs")
        try:
            path.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise MaterialBuildError(f"{context} record {position} path is not UTF-8") from exc
        total += size
        if total > MAX_TREE_BYTES:
            _die(f"{context} inventory exceeds its byte bound")
        paths.append(path)
        records.append(dict(value))
    if paths != sorted(paths, key=lambda item: item.encode("utf-8")) or len(set(paths)) != len(
        paths
    ):
        _die(f"{context} inventory is not unique UTF-8 path order")
    return records


def _validate_native_result_layout(
    records: Sequence[Mapping[str, Any]], *, context: str, material: str
) -> None:
    if material not in {"system", "dashboard"}:
        _die(f"{context} material differs")
    paths = [str(record["path"]) for record in records]
    if any(path.split("/", 1)[0] not in {"A", "B"} for path in paths):
        _die(f"{context} contains a file outside builds A and B")
    for build_id in ("A", "B"):
        payload = [path for path in paths if path.startswith(build_id + "/payload/")]
        run_evidence = [path for path in paths if path.startswith(build_id + "/run-evidence/")]
        if not payload or not run_evidence:
            _die(f"{context} lacks {build_id} payload or run evidence")
    required_executables = {f"{build_id}/payload/evidence/trivy" for build_id in ("A", "B")}
    observed_executables = {str(record["path"]) for record in records if record["mode"] == "0755"}
    if observed_executables != required_executables:
        _die(f"{context} executable-mode authority differs")


def build_canonical_tree_tar(root: Path, *, context: str) -> tuple[bytes, list[dict[str, Any]]]:
    """Capture a complete tree in a mode-preserving canonical USTAR carrier."""

    records = file_records(root, exclude=frozenset())
    members: list[tuple[Mapping[str, Any], bytes]] = []
    for record in records:
        raw = read_regular(
            root / record["path"],
            maximum=record["size"],
            context=f"{context} member {record['path']}",
        )
        if len(raw) != record["size"] or sha256(raw) != record["sha256"]:
            _die(f"{context} changed during canonical capture")
        members.append((record, raw))
    return _canonical_tar_bytes(members, context=context), records


def validate_canonical_tree_tar(
    raw: bytes,
    *,
    expected_records: Sequence[Mapping[str, Any]],
    context: str,
) -> list[tuple[dict[str, Any], bytes]]:
    """Reject mode loss, aliases, duplicate/link members, and noncanonical tar bytes."""

    if not raw or len(raw) > MAX_TREE_BYTES or len(raw) % tarfile.BLOCKSIZE:
        _die(f"{context} raw USTAR size differs")
    expected = _validate_tree_records(list(expected_records), context=f"{context} expected")
    members: list[tuple[dict[str, Any], bytes]] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            if archive.pax_headers:
                _die(f"{context} is not plain USTAR")
            observed_members = archive.getmembers()
            if len(observed_members) != len(expected):
                _die(f"{context} member count differs")
            for member, record in zip(observed_members, expected, strict=True):
                if (
                    not member.isfile()
                    or member.issym()
                    or member.islnk()
                    or member.name != record["path"]
                    or member.name.startswith("./")
                    or "//" in member.name
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname
                    or member.gname
                    or member.mtime != 0
                    or member.pax_headers
                    or stat.S_IMODE(member.mode) != int(record["mode"], 8)
                    or member.size != record["size"]
                ):
                    _die(f"{context} member metadata differs")
                stream = archive.extractfile(member)
                if stream is None:
                    _die(f"{context} member content is absent")
                content = stream.read(record["size"] + 1)
                if len(content) != record["size"] or sha256(content) != record["sha256"]:
                    _die(f"{context} member content differs")
                members.append((record, content))
    except (KeyError, OSError, tarfile.TarError, UnicodeError, ValueError) as exc:
        raise MaterialBuildError(f"{context} is not a canonical USTAR carrier") from exc
    if _canonical_tar_bytes(members, context=context) != raw:
        _die(f"{context} raw USTAR encoding differs")
    return members


def _write_new_at(
    directory: int,
    name: str,
    raw: bytes,
    *,
    mode: int,
    context: str,
) -> None:
    descriptor = os.open(
        name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        mode,
        dir_fd=directory,
    )
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                _die(f"{context} short write")
            view = view[written:]
        os.fsync(descriptor)
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_nlink != 1
            or observed.st_size != len(raw)
            or stat.S_IMODE(observed.st_mode) != mode
        ):
            _die(f"{context} extracted inode differs")
    finally:
        os.close(descriptor)


def extract_canonical_tree_tar(
    raw: bytes,
    destination: Path,
    *,
    expected_records: Sequence[Mapping[str, Any]],
    context: str,
) -> list[dict[str, Any]]:
    """Extract validated USTAR bytes without links, pathname reopen, or overwrite."""

    members = validate_canonical_tree_tar(
        raw,
        expected_records=expected_records,
        context=context,
    )
    require_empty_private_directory(destination, context=f"{context} destination")
    root = _open_directory(destination)
    try:
        for record, content in members:
            parts = PurePosixPath(record["path"]).parts
            current = os.dup(root)
            try:
                for component in parts[:-1]:
                    with suppress(FileExistsError):
                        os.mkdir(component, mode=0o700, dir_fd=current)
                    child = os.open(
                        component,
                        os.O_RDONLY
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=current,
                    )
                    observed = os.fstat(child)
                    if (
                        not stat.S_ISDIR(observed.st_mode)
                        or observed.st_uid != os.geteuid()
                        or stat.S_IMODE(observed.st_mode) != 0o700
                    ):
                        os.close(child)
                        _die(f"{context} extracted directory differs")
                    os.close(current)
                    current = child
                _write_new_at(
                    current,
                    parts[-1],
                    content,
                    mode=int(record["mode"], 8),
                    context=context,
                )
            finally:
                os.close(current)
        os.fsync(root)
    finally:
        os.close(root)
    observed_records = file_records(destination, exclude=frozenset())
    if observed_records != [dict(item) for item in expected_records]:
        _die(f"{context} extracted inventory differs")
    return observed_records


def create_platform_result_carrier(
    source_root: Path,
    destination: Path,
    *,
    filename: str,
    material: str,
    platform: str,
) -> dict[str, Any]:
    """Create and self-verify the sole mode-preserving native-result carrier."""

    if (
        material not in {"system", "dashboard"}
        or platform not in PLATFORMS
        or filename != f"production-{material}-{PLATFORMS[platform]}-native-result.tar"
    ):
        _die("native-result carrier identity differs")
    raw, records = build_canonical_tree_tar(
        source_root,
        context=f"{material} {platform} native result",
    )
    _validate_native_result_layout(
        records, context=f"{material} {platform} native result", material=material
    )
    validate_canonical_tree_tar(
        raw,
        expected_records=records,
        context=f"{material} {platform} native result",
    )
    framing = {
        "files": records,
        "format": "z4j-production-mode-preserving-tree-v1",
    }
    atomic_write_new(destination, raw, mode=0o644)
    return {
        "filename": filename,
        "format": "z4j-production-native-result-carrier-v1",
        "media_type": "application/vnd.z4j.production-native-result.v1.tar",
        "members_bytes": sum(item["size"] for item in records),
        "members_entries": len(records),
        "members_sha256": sha256(canonical_json(framing, terminal_lf=False)),
        "records": records,
        "sha256": sha256(raw),
        "size": len(raw),
    }


def validate_platform_result_carrier(
    archive: Path,
    value: Any,
    *,
    material: str,
    platform: str,
) -> list[dict[str, Any]]:
    """Validate a downloaded carrier before any platform aggregation."""

    if not isinstance(value, dict) or set(value) != {
        "filename",
        "format",
        "media_type",
        "members_bytes",
        "members_entries",
        "members_sha256",
        "records",
        "sha256",
        "size",
    }:
        _die("native-result carrier keys differ")
    filename = f"production-{material}-{PLATFORMS.get(platform, '')}-native-result.tar"
    if (
        value["filename"] != filename
        or archive.name != filename
        or value["format"] != "z4j-production-native-result-carrier-v1"
        or value["media_type"] != "application/vnd.z4j.production-native-result.v1.tar"
        or not isinstance(value["size"], int)
        or isinstance(value["size"], bool)
        or value["size"] <= 0
        or not isinstance(value["members_entries"], int)
        or isinstance(value["members_entries"], bool)
        or value["members_entries"] <= 0
        or not isinstance(value["members_bytes"], int)
        or isinstance(value["members_bytes"], bool)
        or value["members_bytes"] <= 0
        or not isinstance(value["sha256"], str)
        or HEX64.fullmatch(value["sha256"]) is None
        or not isinstance(value["members_sha256"], str)
        or HEX64.fullmatch(value["members_sha256"]) is None
        or not isinstance(value["records"], list)
    ):
        _die("native-result carrier values differ")
    raw = read_regular(
        archive,
        maximum=MAX_TREE_BYTES,
        context=f"{material} {platform} downloaded native result",
    )
    if len(raw) != value["size"] or sha256(raw) != value["sha256"]:
        _die("native-result carrier raw seal differs")
    records = _validate_tree_records(value["records"], context=f"{material} {platform} carrier")
    framing = {
        "files": records,
        "format": "z4j-production-mode-preserving-tree-v1",
    }
    if (
        len(records) != value["members_entries"]
        or sum(item["size"] for item in records) != value["members_bytes"]
        or sha256(canonical_json(framing, terminal_lf=False)) != value["members_sha256"]
    ):
        _die("native-result carrier member seals differ")
    validate_canonical_tree_tar(
        raw,
        expected_records=records,
        context=f"{material} {platform} downloaded native result",
    )
    _validate_native_result_layout(
        records, context=f"{material} {platform} carrier", material=material
    )
    return records


def _validate_raw_bytes_record(
    value: Any,
    *,
    maximum: int,
    context: str,
    allow_empty: bool = True,
) -> bytes:
    """Decode one exact bounded byte record and recompute both of its seals."""

    record = _object(value, {"base64", "sha256", "size"}, context=context)
    encoded = record["base64"]
    size = record["size"]
    if (
        not isinstance(encoded, str)
        or not isinstance(record["sha256"], str)
        or HEX64.fullmatch(record["sha256"]) is None
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size < 0
        or size > maximum
        or (not allow_empty and size == 0)
        or len(encoded) != 4 * ((size + 2) // 3)
    ):
        _die(f"{context} literal-byte record differs")
    try:
        encoded_ascii = encoded.encode("ascii", errors="strict")
        raw = base64.b64decode(encoded_ascii, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise MaterialBuildError(f"{context} Base64 bytes differ") from exc
    if (
        len(raw) != size
        or sha256(raw) != record["sha256"]
        or base64.b64encode(raw) != encoded_ascii
    ):
        _die(f"{context} literal-byte seals differ")
    return raw


def _validate_command_record(
    value: Any,
    *,
    context: str,
    expected_argv: Sequence[str] | None = None,
) -> tuple[dict[str, Any], bytes, bytes]:
    """Validate one successful command and return its literal stdout/stderr."""

    command = _object(value, {"argv", "exit_code", "stderr", "stdout"}, context=context)
    argv = command["argv"]
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(item, str) and item and "\0" not in item for item in argv)
        or (expected_argv is not None and argv != list(expected_argv))
        or command["exit_code"] != 0
    ):
        _die(f"{context} command identity/result differs")
    stderr = _validate_raw_bytes_record(
        command["stderr"], maximum=MAX_COMMAND_OUTPUT, context=f"{context} stderr"
    )
    stdout = _validate_raw_bytes_record(
        command["stdout"], maximum=MAX_COMMAND_OUTPUT, context=f"{context} stdout"
    )
    return command, stdout, stderr


def validate_git_source_binding(value: Any, *, context: str) -> dict[str, str]:
    """Validate the small authority-neutral Git identity carried downstream."""

    binding = _object(
        value,
        {"commit", "format", "reference", "source_prefix", "tree"},
        context=context,
    )
    if (
        binding["format"] != GIT_SOURCE_BINDING_FORMAT
        or not isinstance(binding["commit"], str)
        or GIT_SHA1.fullmatch(binding["commit"]) is None
        or not isinstance(binding["tree"], str)
        or GIT_SHA1.fullmatch(binding["tree"]) is None
    ):
        _die(f"{context} commit/tree identity differs")
    _validate_git_reference(binding["reference"])
    _validate_source_prefix(binding["source_prefix"])
    return binding


def validate_compact_source_context(value: Any, *, context: str) -> dict[str, Any]:
    """Validate the aggregation's Git binding plus exact file-projection seal."""

    source = _object(value, {"files", "format", "git"}, context=context)
    if source["format"] != SOURCE_CONTEXT_BINDING_FORMAT:
        _die(f"{context} format differs")
    validate_git_source_binding(source["git"], context=f"{context} Git")
    files = _object(source["files"], {"entries", "sha256", "size"}, context=f"{context} files")
    _positive_int(files["entries"], context=f"{context} file entries")
    _positive_int(files["size"], context=f"{context} file seal size")
    if not isinstance(files["sha256"], str) or HEX64.fullmatch(files["sha256"]) is None:
        _die(f"{context} file projection SHA-256 differs")
    return source


def compact_source_context(value: Any, *, material: str) -> dict[str, Any]:
    """Reduce full carrier evidence to the aggregation's crossbinding record."""

    source = _object(value, {"files", "format", "git"}, context=f"{material} full source context")
    if source["format"] != f"z4j-production-{material}-build-context-capture-v2":
        _die(f"{material} full source-context format differs")
    files = _validate_tree_records(source["files"], context=f"{material} full source context files")
    git = validate_git_source_binding(source["git"], context=f"{material} full source context Git")
    result = {
        "files": source_file_projection_seal(files),
        "format": SOURCE_CONTEXT_BINDING_FORMAT,
        "git": git,
    }
    return validate_compact_source_context(result, context=f"{material} compact source context")


def _validate_raw_command_response(
    value: Any,
    *,
    context: str,
    expected_argv: Sequence[str] | None = None,
    allow_empty: bool = False,
) -> tuple[dict[str, Any], bytes]:
    """Validate a command seal that also binds its complete stdout bytes."""

    response, stdout, _stderr = _validate_command_record(
        value, context=context, expected_argv=expected_argv
    )
    if not allow_empty and not stdout:
        _die(f"{context} raw stdout seal differs")
    return response, stdout


def _validate_platform_identity(value: Any, *, platform: str) -> dict[str, Any]:
    """Validate an externally selected run/job/artifact identity without selecting it."""

    identity = _object(value, {"artifact", "job", "run"}, context=f"{platform} identity")
    run = _object(identity["run"], {"attempt", "id"}, context=f"{platform} run identity")
    _positive_int(run["id"], context=f"{platform} run id")
    _positive_int(run["attempt"], context=f"{platform} run attempt")
    job = _object(
        identity["job"],
        {"id", "name", "runner_arch", "runner_name", "runner_os"},
        context=f"{platform} job identity",
    )
    _positive_int(job["id"], context=f"{platform} job id")
    for key in ("name", "runner_arch", "runner_name", "runner_os"):
        _string(job[key], context=f"{platform} job {key}")
    expected_arch = "X64" if platform == "linux/amd64" else "ARM64"
    if job["runner_arch"] != expected_arch or job["runner_os"] != "Linux":
        _die(f"{platform} job native platform identity differs")
    artifact = _object(
        identity["artifact"],
        {"id", "name", "sha256", "size"},
        context=f"{platform} artifact identity",
    )
    _positive_int(artifact["id"], context=f"{platform} artifact id")
    _string(artifact["name"], context=f"{platform} artifact name")
    if not isinstance(artifact["sha256"], str) or HEX64.fullmatch(artifact["sha256"]) is None:
        _die(f"{platform} artifact SHA-256 differs")
    _positive_int(artifact["size"], context=f"{platform} artifact size")
    return identity


def _validate_toolchain_record(
    value: Any,
    *,
    expected: Mapping[str, Any],
    probe_arguments: Sequence[str],
    context: str,
) -> tuple[dict[str, Any], str]:
    record = _object(value, {"sha256", "size", "version_probe"}, context=context)
    if (
        record["sha256"] != expected.get("sha256")
        or record["size"] != expected.get("size")
        or not isinstance(record["sha256"], str)
        or HEX64.fullmatch(record["sha256"]) is None
    ):
        _die(f"{context} binary authority differs")
    _positive_int(record["size"], context=f"{context} size")
    probe, stdout, stderr = _validate_command_record(
        record["version_probe"], context=f"{context} version probe"
    )
    if (
        probe["argv"][1:] != list(probe_arguments)
        or len(probe["argv"]) != len(probe_arguments) + 1
        or not Path(probe["argv"][0]).is_absolute()
        or not stdout + stderr
    ):
        _die(f"{context} version command differs")
    expected_transcript = expected.get("version_output_sha256")
    if (
        not isinstance(expected_transcript, str)
        or HEX64.fullmatch(expected_transcript) is None
        or sha256(stdout + stderr) != expected_transcript
    ):
        _die(f"{context} version transcript differs")
    return record, probe["argv"][0]


def _validate_inventory_response(
    value: Any,
    *,
    context: str,
    docker_executable: str,
    prefix: str,
) -> dict[str, Any]:
    inventory = _object(value, {"builders", "containers"}, context=context)
    expected = {
        "builders": [docker_executable, "buildx", "ls", "--format", "{{.Name}}"],
        "containers": [
            docker_executable,
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--filter",
            "name=buildx_buildkit_" + prefix,
            "--format",
            "{{.Names}}",
        ],
    }
    for key in ("builders", "containers"):
        _response, stdout = _validate_raw_command_response(
            inventory[key],
            context=f"{context} {key} response",
            expected_argv=expected[key],
            allow_empty=True,
        )
        selected_prefix = prefix if key == "builders" else "buildx_buildkit_" + prefix
        if _builder_names(stdout, prefix=selected_prefix):
            _die(f"{context} {key} response retains a helper-owned name")
    return inventory


def _validate_execution_plane_record(
    value: Any,
    *,
    platform: str,
    expected_daemon: Mapping[str, Any],
    docker_executable: str,
    context: str,
) -> dict[str, Any]:
    plane = _object(value, {"context", "daemon"}, context=context)
    context_record = _object(
        plane["context"], {"projection", "response"}, context=f"{context} context"
    )
    if context_record["projection"] != {
        "docker_host": DOCKER_HOST,
        "name": DOCKER_CONTEXT,
        "skip_tls_verify": False,
    }:
        _die(f"{context} Docker context projection differs")
    _context_response, context_raw = _validate_raw_command_response(
        context_record["response"],
        context=f"{context} Docker context response",
        expected_argv=[docker_executable, "context", "inspect", DOCKER_CONTEXT],
    )
    if _context_projection(context_raw) != context_record["projection"]:
        _die(f"{context} Docker context response/projection differs")
    daemon = _object(plane["daemon"], {"projection", "response"}, context=f"{context} daemon")
    if daemon["projection"] != dict(expected_daemon):
        _die(f"{context} daemon projection differs from policy")
    _validate_daemon_projection(daemon["projection"], platform=platform)
    _daemon_response, daemon_raw = _validate_raw_command_response(
        daemon["response"],
        context=f"{context} Docker daemon response",
        expected_argv=[docker_executable, "info", "--format", "{{json .}}"],
    )
    if _daemon_projection(daemon_raw, platform=platform) != daemon["projection"]:
        _die(f"{context} Docker daemon response/projection differs")
    return plane


def _validate_buildkit_record(
    value: Any,
    *,
    platform: str,
    expected: Mapping[str, Any],
    docker_executable: str,
) -> dict[str, Any]:
    record = _object(
        value, {"index", "manifest", "selected_platform"}, context="native BuildKit readback"
    )
    selected = _object(
        record["selected_platform"],
        {"architecture", "config_digest", "config_size", "manifest_digest", "manifest_size", "os"},
        context="native BuildKit selected platform",
    )
    expected_native = expected["platforms"][platform]
    if selected != {
        "architecture": PLATFORMS[platform],
        "config_digest": expected_native["config_digest"],
        "config_size": expected_native["config_size"],
        "manifest_digest": expected_native["manifest_digest"],
        "manifest_size": expected_native["manifest_size"],
        "os": "linux",
    }:
        _die("native BuildKit selected platform differs from policy")
    repository = expected["image"].split(":v", 1)[0]
    manifest_ref = repository + "@" + expected_native["manifest_digest"]
    _index_response, index_raw = _validate_raw_command_response(
        record["index"],
        context="native BuildKit index",
        expected_argv=[
            docker_executable,
            "buildx",
            "imagetools",
            "inspect",
            "--raw",
            expected["image"],
        ],
    )
    descriptor = _validate_buildkit_index(index_raw, policy=expected, platform=platform)
    _manifest_response, manifest_raw = _validate_raw_command_response(
        record["manifest"],
        context="native BuildKit manifest",
        expected_argv=[
            docker_executable,
            "buildx",
            "imagetools",
            "inspect",
            "--raw",
            manifest_ref,
        ],
    )
    _validate_buildkit_manifest(manifest_raw, policy=expected, platform=platform)
    if (
        descriptor["digest"] != selected["manifest_digest"]
        or descriptor["size"] != selected["manifest_size"]
    ):
        _die("native BuildKit raw index/selected platform differs")
    return record


def _validate_builder_authority_record(
    value: Any,
    *,
    builder: str,
    platform: str,
    expected_buildkit: Mapping[str, Any],
    docker_executable: str,
    ownership_nonce: str,
    archive_path: Path,
    context: str,
) -> dict[str, Any]:
    authority = _object(value, {"builder", "container", "image"}, context=context)
    builder_record = _object(
        authority["builder"], {"projection", "response"}, context=f"{context} builder"
    )
    expected_builder_projection = {
        "driver": DOCKER_DRIVER,
        "name": builder,
        "nodes": [
            {
                "buildkit": expected_buildkit["version"],
                "endpoint": DOCKER_HOST,
                "name": builder + "0",
                "platforms": [platform],
                "status": "running",
            }
        ],
    }
    if builder_record["projection"] != expected_builder_projection:
        _die(f"{context} builder projection differs")
    _builder_response, builder_raw = _validate_raw_command_response(
        builder_record["response"],
        context=f"{context} builder response",
        expected_argv=[
            docker_executable,
            "buildx",
            "inspect",
            builder,
            "--bootstrap",
            "--format",
            "{{json .}}",
        ],
    )
    if (
        _builder_projection(
            builder_raw,
            builder=builder,
            platform=platform,
            version=expected_buildkit["version"],
        )
        != builder_record["projection"]
    ):
        _die(f"{context} builder response/projection differs")

    native = expected_buildkit["platforms"][platform]
    container = _object(
        authority["container"], {"projection", "response"}, context=f"{context} container"
    )
    container_projection = _object(
        container["projection"],
        {
            "config_image",
            "id",
            "image",
            "label",
            "mounts",
            "name",
            "network_mode",
            "ownership_nonce",
            "privileged",
        },
        context=f"{context} container projection",
    )
    if HEX64.fullmatch(str(container_projection["id"])) is None or container_projection != {
        "config_image": expected_buildkit["image"],
        "id": container_projection["id"],
        "image": native["config_digest"],
        "label": builder,
        "mounts": [{"destination": "/var/lib/buildkit", "type": "volume"}],
        "name": "/buildx_buildkit_" + builder + "0",
        "network_mode": BUILDKIT_WORKER_NETWORK,
        "ownership_nonce": ownership_nonce,
        "privileged": True,
    }:
        _die(f"{context} BuildKit container projection differs")
    _container_response, container_raw = _validate_raw_command_response(
        container["response"],
        context=f"{context} container response",
        expected_argv=[
            docker_executable,
            "inspect",
            "--type",
            "container",
            "--format",
            "{{json .}}",
            "buildx_buildkit_" + builder + "0",
        ],
    )
    if (
        _container_projection(
            container_raw,
            builder=builder,
            image=expected_buildkit["image"],
            config_digest=native["config_digest"],
            ownership_nonce=ownership_nonce,
        )
        != container_projection
    ):
        _die(f"{context} container response/projection differs")

    image = _object(
        authority["image"], {"config", "projection", "response", "save"}, context=f"{context} image"
    )
    if image["projection"] != {
        "architecture": PLATFORMS[platform],
        "id": native["config_digest"],
        "os": "linux",
    }:
        _die(f"{context} BuildKit image/config projection differs")
    config_raw = _validate_raw_bytes_record(
        image["config"], maximum=MAX_FILE_BYTES, context=f"{context} raw image config"
    )
    if (
        len(config_raw) != native["config_size"]
        or "sha256:" + sha256(config_raw) != native["config_digest"]
    ):
        _die(f"{context} raw BuildKit image config differs")
    config_value = parse_json(config_raw, context=f"{context} raw BuildKit image config")
    if (
        not isinstance(config_value, dict)
        or config_value.get("architecture") != PLATFORMS[platform]
        or config_value.get("os") != "linux"
    ):
        _die(f"{context} raw BuildKit image config platform differs")
    _image_response, image_raw = _validate_raw_command_response(
        image["response"],
        context=f"{context} image response",
        expected_argv=[
            docker_executable,
            "image",
            "inspect",
            "--format",
            "{{json .}}",
            native["config_digest"],
        ],
    )
    if (
        _image_projection(image_raw, platform=platform, config_digest=native["config_digest"])
        != image["projection"]
    ):
        _die(f"{context} image response/projection differs")
    save = _object(image["save"], {"archive", "command"}, context=f"{context} image save")
    archive = _object(save["archive"], {"sha256", "size"}, context=f"{context} image archive")
    _validate_command_record(
        save["command"],
        context=f"{context} image save command",
        expected_argv=[
            docker_executable,
            "image",
            "save",
            "--output",
            str(archive_path),
            native["config_digest"],
        ],
    )
    if HEX64.fullmatch(str(archive["sha256"])) is None:
        _die(f"{context} image archive SHA-256 differs")
    _positive_int(archive["size"], context=f"{context} image archive size")
    if archive["size"] > MAX_IMAGE_ARCHIVE_BYTES:
        _die(f"{context} image archive exceeds the reviewed bound")
    return authority


def _recorded_absolute_path(value: Any, *, context: str) -> Path:
    """Validate a durable Linux path lexically without touching the producer host."""

    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or value == "/"
        or "//" in value
        or "\\" in value
        or "\0" in value
        or "\n" in value
        or "\r" in value
    ):
        _die(f"{context} differs")
    logical = PurePosixPath(value)
    if logical.as_posix() != value or any(part in {"", ".", ".."} for part in logical.parts[1:]):
        _die(f"{context} differs")
    return Path(value)


def _validate_native_build_operand_contract(
    contract: Any, *, material: str
) -> tuple[PurePosixPath, dict[str, str]]:
    expected = _object(
        contract,
        {"context_name", "dockerfile", "output_directories"},
        context=f"{material} native build operand contract",
    )
    if expected["context_name"] != "context":
        _die(f"{material} native context name differs")
    dockerfile_record = _object(
        expected["dockerfile"],
        {"path", "sha256", "size"},
        context=f"{material} native Dockerfile contract",
    )
    dockerfile_relative = dockerfile_record["path"]
    logical_dockerfile = PurePosixPath(str(dockerfile_relative))
    if (
        dockerfile_relative != f"docker/production/generators/{material}.Dockerfile"
        or logical_dockerfile.is_absolute()
        or logical_dockerfile.as_posix() != dockerfile_relative
        or any(part in {"", ".", ".."} for part in logical_dockerfile.parts)
        or not isinstance(dockerfile_record["sha256"], str)
        or HEX64.fullmatch(dockerfile_record["sha256"]) is None
    ):
        _die(f"{material} native Dockerfile contract differs")
    _positive_int(dockerfile_record["size"], context=f"{material} native Dockerfile size")
    output_directories = _object(
        expected["output_directories"],
        {"A", "B"},
        context=f"{material} native output directory contract",
    )
    if output_directories != {"A": "A", "B": "B"}:
        _die(f"{material} native output directory contract differs")
    return logical_dockerfile, output_directories


def _validate_native_build_operands(
    value: Any,
    *,
    contract: Any,
    material: str,
) -> tuple[Path, Path, Path, Path, dict[str, str]]:
    """Bind ephemeral absolute paths to the reviewed logical build contract."""

    expected = _object(
        contract,
        {"context_name", "dockerfile", "output_directories"},
        context=f"{material} native build operand contract",
    )
    logical_dockerfile, output_directories = _validate_native_build_operand_contract(
        expected, material=material
    )

    operands = _object(
        value,
        {"context_root", "dockerfile", "output_root", "toolchain_root"},
        context=f"{material} native build operands",
    )
    context_root = _recorded_absolute_path(
        operands["context_root"], context=f"{material} native context root"
    )
    dockerfile = _recorded_absolute_path(
        operands["dockerfile"], context=f"{material} native Dockerfile"
    )
    output_root = _recorded_absolute_path(
        operands["output_root"], context=f"{material} native output root"
    )
    toolchain_root = _recorded_absolute_path(
        operands["toolchain_root"], context=f"{material} native toolchain root"
    )
    if (
        context_root.name != expected["context_name"]
        or dockerfile != context_root.joinpath(*logical_dockerfile.parts)
        or not toolchain_root.name.startswith("z4j-production-docker.")
    ):
        _die(f"{material} native build operand relationship differs")
    roots = (context_root, output_root, toolchain_root)
    for position, left in enumerate(roots):
        for right in roots[position + 1 :]:
            if left == right or left.is_relative_to(right) or right.is_relative_to(left):
                _die(f"{material} native build roots overlap")
    return context_root, dockerfile, output_root, toolchain_root, output_directories


def _validate_native_build_command(
    value: Any,
    *,
    docker_executable: str,
    builder: str,
    platform: str,
    dockerfile: Path,
    context_root: Path,
    destination: Path,
    build_args: Mapping[str, str],
    context: str,
) -> dict[str, Any]:
    """Rebuild one exact Buildx argv from independently retained operands."""

    expected_argv = buildx_argv(
        docker=Path(docker_executable),
        builder=builder,
        platform=platform,
        dockerfile=dockerfile,
        context=context_root,
        destination=destination,
        build_args=build_args,
    )
    command, stdout, stderr = _validate_command_record(
        value, context=context, expected_argv=expected_argv
    )
    if not stdout + stderr:
        _die(f"{context} retained no Buildx transcript")
    return command


def _validate_native_execution(  # noqa: PLR0912, PLR0915
    value: Any,
    *,
    material: str,
    platform: str,
    expected_identity: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> dict[str, Any]:
    execution = _object(
        value,
        {
            "builder_inventory",
            "builders",
            "buildkit",
            "builds",
            "execution_plane",
            "format",
            "operands",
            "run",
            "toolchain",
        },
        context="platform native execution",
    )
    if execution["format"] != "z4j-production-native-build-execution-v2":
        _die("platform native execution format differs")
    contract_value = _object(
        contract,
        {
            "build_args",
            "build_operands",
            "builder_prefix",
            "docker_authority",
            "execution_plane",
        },
        context=f"{material} {platform} execution contract",
    )
    if contract_value["builder_prefix"] != f"z4j-production-{material}":
        _die("platform native execution builder prefix differs")
    expected_plane = contract_value["execution_plane"]
    if validate_execution_plane_policy(expected_plane, platforms=tuple(PLATFORMS)):
        _die("platform native execution contract is unfinalized")
    expected_docker = _object(
        contract_value["docker_authority"],
        {"path", "sha256", "size", "version_output_sha256"},
        context=f"{material} {platform} Docker authority",
    )
    run = _object(execution["run"], {"attempt", "id"}, context="platform native execution run")
    if run != expected_identity["run"]:
        _die("platform native execution run differs from selected run identity")
    base_name = _builder_base_name(
        builder_prefix=contract_value["builder_prefix"],
        platform=platform,
        run_id=run["id"],
        run_attempt=run["attempt"],
    )
    context_root, dockerfile, output_root, toolchain_root, output_directories = (
        _validate_native_build_operands(
            execution["operands"], contract=contract_value["build_operands"], material=material
        )
    )
    toolchain = _object(execution["toolchain"], {"buildx", "docker"}, context="native toolchain")
    _docker_record, docker_executable = _validate_toolchain_record(
        toolchain["docker"],
        expected=expected_docker,
        probe_arguments=("--version",),
        context="captured Docker",
    )
    _buildx_record, buildx_docker_executable = _validate_toolchain_record(
        toolchain["buildx"],
        expected=expected_plane["buildx"]["platforms"][platform],
        probe_arguments=("buildx", "version"),
        context="captured Buildx",
    )
    if buildx_docker_executable != docker_executable:
        _die("captured Docker/Buildx probes used different Docker executables")
    if Path(docker_executable) != toolchain_root / "bin/docker":
        _die("captured Docker executable differs from the retained toolchain root")
    _validate_buildkit_record(
        execution["buildkit"],
        platform=platform,
        expected=expected_plane["buildkit"],
        docker_executable=docker_executable,
    )
    initial_inventory = _object(
        execution["builder_inventory"], {"after", "before"}, context="builder inventory"
    )
    _validate_inventory_response(
        initial_inventory["before"],
        context="initial builder inventory",
        docker_executable=docker_executable,
        prefix=contract_value["builder_prefix"] + "-",
    )
    _validate_inventory_response(
        initial_inventory["after"],
        context="final builder inventory",
        docker_executable=docker_executable,
        prefix=contract_value["builder_prefix"] + "-",
    )
    plane = _object(execution["execution_plane"], {"after", "before"}, context="execution plane")
    before_plane = _validate_execution_plane_record(
        plane["before"],
        platform=platform,
        expected_daemon=expected_plane["daemon"][platform],
        docker_executable=docker_executable,
        context="initial execution plane",
    )
    after_plane = _validate_execution_plane_record(
        plane["after"],
        platform=platform,
        expected_daemon=expected_plane["daemon"][platform],
        docker_executable=docker_executable,
        context="final execution plane",
    )
    if (
        before_plane["context"]["projection"] != after_plane["context"]["projection"]
        or before_plane["daemon"]["projection"] != after_plane["daemon"]["projection"]
    ):
        _die("platform native execution plane changed")

    builds = execution["builds"]
    builders = execution["builders"]
    if not isinstance(builds, list) or len(builds) != 2:
        _die("platform native execution build command set differs")
    if not isinstance(builders, list) or len(builders) != 2:
        _die("platform native execution builder set differs")
    expected_build_args = _object(
        contract_value["build_args"], set(contract_value["build_args"]), context="native build args"
    )
    if not expected_build_args or any(
        re.fullmatch(r"[A-Z][A-Z0-9_]*", key) is None
        or not isinstance(item, str)
        or not item
        or "\0" in item
        for key, item in expected_build_args.items()
    ):
        _die("native build argument contract differs")
    for position, build_id in enumerate(("A", "B")):
        builder_name = base_name + "-" + build_id.casefold()
        builder = _object(
            builders[position],
            {"after", "before", "build", "build_id", "create", "inventory_after", "name", "remove"},
            context=f"platform native builder {build_id}",
        )
        if builder["build_id"] != build_id or builder["name"] != builder_name:
            _die(f"platform native builder {build_id} identity differs")
        create, create_stdout, _create_stderr = _validate_command_record(
            builder["create"], context=f"platform native builder {build_id} create"
        )
        create_argv = create["argv"]
        if len(create_argv) != 15:
            _die(f"platform native builder {build_id} create command differs")
        nonce_value = create_argv[10].removeprefix("env.Z4J_AUTHORITY_NONCE=")
        expected_create = [
            docker_executable,
            "buildx",
            "create",
            "--name",
            builder_name,
            "--driver",
            DOCKER_DRIVER,
            "--driver-opt",
            "image=" + expected_plane["buildkit"]["image"],
            "--driver-opt",
            "env.Z4J_AUTHORITY_NONCE=" + nonce_value,
            "--buildkitd-flags=--oci-worker-net=" + BUILDKIT_WORKER_NETWORK,
            "--platform",
            platform,
            DOCKER_HOST,
        ]
        if (
            HEX64.fullmatch(nonce_value) is None
            or create_argv != expected_create
            or create_stdout != (builder_name + "\n").encode("ascii")
        ):
            _die(f"platform native builder {build_id} create command differs")
        before = _validate_builder_authority_record(
            builder["before"],
            builder=builder_name,
            platform=platform,
            expected_buildkit=expected_plane["buildkit"],
            docker_executable=docker_executable,
            ownership_nonce=nonce_value,
            archive_path=toolchain_root / f"buildkit-{build_id.casefold()}.tar",
            context=f"platform native builder {build_id} before",
        )
        after = _validate_builder_authority_record(
            builder["after"],
            builder=builder_name,
            platform=platform,
            expected_buildkit=expected_plane["buildkit"],
            docker_executable=docker_executable,
            ownership_nonce=nonce_value,
            archive_path=toolchain_root / f"buildkit-{build_id.casefold()}-after.tar",
            context=f"platform native builder {build_id} after",
        )
        for component, key in (
            ("builder", "projection"),
            ("container", "projection"),
            ("image", "config"),
        ):
            if before[component][key] != after[component][key]:
                _die(f"platform native builder {build_id} authority changed")
        destination = output_root / output_directories[build_id]
        build = _validate_native_build_command(
            builds[position],
            docker_executable=docker_executable,
            builder=builder_name,
            platform=platform,
            dockerfile=dockerfile,
            context_root=context_root,
            destination=destination,
            build_args={**expected_build_args, "Z4J_BUILD_ID": build_id},
            context=f"platform native build {build_id}",
        )
        if builder["build"] != build:
            _die(f"platform native builder {build_id} command alias differs")
        _remove, _remove_stdout, _remove_stderr = _validate_command_record(
            builder["remove"],
            context=f"platform native builder {build_id} remove",
            expected_argv=[docker_executable, "buildx", "rm", "--force", builder_name],
        )
        _validate_inventory_response(
            builder["inventory_after"],
            context=f"platform native builder {build_id} post-removal inventory",
            docker_executable=docker_executable,
            prefix=contract_value["builder_prefix"] + "-",
        )
    return execution


def validate_platform_result_document(
    raw: bytes,
    archive: Path,
    *,
    material: str,
    platform: str,
    expected_policy_sha256: str,
    expected_identity: Mapping[str, Any],
    execution_contract: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Validate one canonical sidecar and its exact USTAR carrier."""

    if (
        material not in {"system", "dashboard"}
        or platform not in PLATFORMS
        or HEX64.fullmatch(expected_policy_sha256) is None
    ):
        _die("platform-result validation identity differs")
    value = parse_json(raw, context=f"{material} {platform} platform result")
    if canonical_json(value, terminal_lf=True) != raw:
        _die("platform-result sidecar is not canonical ASCII JSON plus one LF")
    result = _object(
        value,
        {
            "carrier",
            "comparison",
            "execution",
            "format",
            "platform",
            "policy_sha256",
            "selected_build",
            "source_context",
        },
        context=f"{material} {platform} platform result",
    )
    if (
        result["format"] != f"z4j-production-{material}-platform-build-v1"
        or result["platform"] != platform
        or result["policy_sha256"] != expected_policy_sha256
        or result["selected_build"] != "A"
    ):
        _die("platform-result constants differ")
    comparison = _object(
        result["comparison"], {"bytes", "entries", "sha256"}, context="payload comparison"
    )
    for key in ("bytes", "entries"):
        _positive_int(comparison[key], context=f"payload comparison {key}")
    if not isinstance(comparison["sha256"], str) or HEX64.fullmatch(comparison["sha256"]) is None:
        _die("payload comparison SHA-256 differs")
    source_context = _object(
        result["source_context"],
        {"files", "format", "git"},
        context="platform source context",
    )
    if source_context["format"] != f"z4j-production-{material}-build-context-capture-v2":
        _die("platform source-context format differs")
    _validate_tree_records(source_context["files"], context="platform source context")
    binding = validate_git_source_binding(
        source_context["git"], context="platform source context Git"
    )
    if binding["source_prefix"] != "packages/z4j":
        _die("platform source-context prefix differs")
    identity = _validate_platform_identity(expected_identity, platform=platform)
    _validate_native_execution(
        result["execution"],
        material=material,
        platform=platform,
        expected_identity=identity,
        contract=execution_contract,
    )
    records = validate_platform_result_carrier(
        archive,
        result["carrier"],
        material=material,
        platform=platform,
    )
    return result, records


def aggregate_platform_result_carriers(
    inputs: Mapping[str, Mapping[str, Path]],
    destination: Path,
    *,
    material: str,
    expected_policy_sha256: str,
    expected_identities: Mapping[str, Mapping[str, Any]],
    execution_contracts: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Validate, safely extract, and summarize exactly two native result carriers."""

    if (
        set(inputs) != set(PLATFORMS)
        or set(expected_identities) != set(PLATFORMS)
        or set(execution_contracts) != set(PLATFORMS)
    ):
        _die("native-result aggregation platform set differs")
    require_empty_private_directory(destination, context=f"{material} aggregation output")
    prepared: dict[str, tuple[dict[str, Any], list[dict[str, Any]], bytes, bytes]] = {}
    for platform in PLATFORMS:
        item = inputs[platform]
        if not isinstance(item, Mapping) or set(item) != {"archive", "result"}:
            _die(f"{material} {platform} aggregation input differs")
        result_path = item["result"]
        archive = item["archive"]
        if (
            not isinstance(result_path, Path)
            or not isinstance(archive, Path)
            or result_path.name != "platform-result.json"
        ):
            _die(f"{material} {platform} aggregation paths differ")
        result_raw = read_regular(
            result_path,
            maximum=MAX_CONTEXT_BYTES,
            context=f"{material} {platform} platform-result sidecar",
        )
        result, records = validate_platform_result_document(
            result_raw,
            archive,
            material=material,
            platform=platform,
            expected_policy_sha256=expected_policy_sha256,
            expected_identity=expected_identities[platform],
            execution_contract=execution_contracts[platform],
        )
        archive_raw = read_regular(
            archive,
            maximum=MAX_TREE_BYTES,
            context=f"{material} {platform} native-result archive",
        )
        if (
            len(archive_raw) != result["carrier"]["size"]
            or sha256(archive_raw) != result["carrier"]["sha256"]
        ):
            _die(f"{material} {platform} native-result archive changed after validation")
        prepared[platform] = (result, records, result_raw, archive_raw)

    source_contexts = [prepared[platform][0]["source_context"] for platform in PLATFORMS]
    if source_contexts[0] != source_contexts[1]:
        _die(f"{material} native platforms used different source contexts")
    compact_source = compact_source_context(source_contexts[0], material=material)
    identities = {
        platform: _validate_platform_identity(expected_identities[platform], platform=platform)
        for platform in PLATFORMS
    }
    runs = [identity["run"] for identity in identities.values()]
    if runs[0] != runs[1]:
        _die("native-result aggregation platforms came from different run identities")
    for key in ("job", "artifact"):
        ids = [identity[key]["id"] for identity in identities.values()]
        names = [identity[key]["name"] for identity in identities.values()]
        if len(set(ids)) != len(ids) or len(set(names)) != len(names):
            _die(f"native-result aggregation reuses one {key} identity across platforms")

    summaries: dict[str, Any] = {}
    for platform, architecture in PLATFORMS.items():
        result, records, result_raw, archive_raw = prepared[platform]
        platform_root = _create_private_subdirectory(destination, architecture)
        extract_canonical_tree_tar(
            archive_raw,
            platform_root,
            expected_records=records,
            context=f"{material} {platform} native-result archive",
        )
        comparison = compare_payload_roots(platform_root / "A/payload", platform_root / "B/payload")
        if comparison != result["comparison"]:
            _die(f"{material} {platform} extracted payload comparison differs")
        payloads: dict[str, Any] = {}
        run_evidence: dict[str, Any] = {}
        for build_id in ("A", "B"):
            payload_records = file_records(
                platform_root / f"{build_id}/payload", exclude=frozenset()
            )
            payload_framing = {
                "files": payload_records,
                "format": f"z4j-production-{material}-extracted-payload-tree-v1",
                "platform": platform,
            }
            payloads[build_id] = {
                "bytes": sum(item["size"] for item in payload_records),
                "entries": len(payload_records),
                "sha256": sha256(canonical_json(payload_framing, terminal_lf=False)),
            }
            run_records = file_records(
                platform_root / f"{build_id}/run-evidence", exclude=frozenset()
            )
            framing = {
                "files": run_records,
                "format": f"z4j-production-{material}-run-evidence-tree-v1",
                "platform": platform,
                "build_id": build_id,
            }
            run_evidence[build_id] = {
                "bytes": sum(item["size"] for item in run_records),
                "entries": len(run_records),
                "sha256": sha256(canonical_json(framing, terminal_lf=False)),
            }
        summaries[platform] = {
            "carrier": {
                "filename": result["carrier"]["filename"],
                "sha256": result["carrier"]["sha256"],
                "size": result["carrier"]["size"],
            },
            "comparison": comparison,
            "execution": result["execution"],
            "identity": identities[platform],
            "payloads": payloads,
            "platform_result": {"sha256": sha256(result_raw), "size": len(result_raw)},
            "run_evidence": run_evidence,
            "source_context": {
                "files": compact_source["files"],
                "git": compact_source["git"],
                "sha256": sha256(canonical_json(result["source_context"], terminal_lf=False)),
                "size": len(canonical_json(result["source_context"], terminal_lf=False)),
            },
        }
    aggregation = {
        "format": f"z4j-production-{material}-native-result-aggregation-v2",
        "material": material,
        "platforms": summaries,
        "policy_sha256": expected_policy_sha256,
        "run": runs[0],
        "selected_build": "A",
        "source_context": compact_source,
    }
    # A final fd-bound inventory proves extraction did not escape or replace the root.
    file_records(destination, exclude=frozenset())
    return validate_platform_result_aggregation(
        aggregation,
        material=material,
        expected_policy_sha256=expected_policy_sha256,
        expected_identities=expected_identities,
        execution_contracts=execution_contracts,
    )


def validate_platform_result_aggregation(  # noqa: PLR0912, PLR0915
    value: Any,
    *,
    material: str,
    expected_policy_sha256: str,
    expected_identities: Mapping[str, Mapping[str, Any]],
    execution_contracts: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Validate the exact authority-neutral object later embedded by a signed AR."""

    aggregation = _object(
        value,
        {
            "format",
            "material",
            "platforms",
            "policy_sha256",
            "run",
            "selected_build",
            "source_context",
        },
        context="native-result aggregation",
    )
    if (
        material not in {"system", "dashboard"}
        or HEX64.fullmatch(expected_policy_sha256) is None
        or set(expected_identities) != set(PLATFORMS)
        or set(execution_contracts) != set(PLATFORMS)
        or aggregation["format"] != f"z4j-production-{material}-native-result-aggregation-v2"
        or aggregation["material"] != material
        or aggregation["policy_sha256"] != expected_policy_sha256
        or aggregation["selected_build"] != "A"
    ):
        _die("native-result aggregation constants differ")
    run = _object(aggregation["run"], {"attempt", "id"}, context="native-result run")
    _positive_int(run["id"], context="native-result run id")
    _positive_int(run["attempt"], context="native-result run attempt")
    platforms = _object(
        aggregation["platforms"], set(PLATFORMS), context="native-result aggregation platforms"
    )
    compact_source = validate_compact_source_context(
        aggregation["source_context"], context="native-result aggregation source context"
    )
    if compact_source["git"]["source_prefix"] != "packages/z4j":
        _die("native-result aggregation source prefix differs")
    platform_source_seals: list[dict[str, Any]] = []
    identity_ids: dict[str, list[int]] = {"artifact": [], "job": []}
    identity_names: dict[str, list[str]] = {"artifact": [], "job": []}
    for platform, architecture in PLATFORMS.items():
        item = _object(
            platforms[platform],
            {
                "carrier",
                "comparison",
                "execution",
                "identity",
                "payloads",
                "platform_result",
                "run_evidence",
                "source_context",
            },
            context=f"native-result aggregation {platform}",
        )
        carrier = _object(
            item["carrier"], {"filename", "sha256", "size"}, context=f"{platform} carrier"
        )
        if carrier["filename"] != (f"production-{material}-{architecture}-native-result.tar"):
            _die(f"native-result aggregation {platform} carrier filename differs")
        for context, raw_seal in (
            ("carrier", carrier),
            ("platform result", item["platform_result"]),
        ):
            validated_seal = raw_seal
            if context != "carrier":
                validated_seal = _object(
                    raw_seal, {"sha256", "size"}, context=f"{platform} {context} seal"
                )
            if (
                not isinstance(validated_seal["sha256"], str)
                or HEX64.fullmatch(validated_seal["sha256"]) is None
                or isinstance(validated_seal["size"], bool)
                or not isinstance(validated_seal["size"], int)
                or validated_seal["size"] <= 0
            ):
                _die(f"native-result aggregation {platform} {context} seal differs")
        identity = _validate_platform_identity(item["identity"], platform=platform)
        if identity != expected_identities[platform] or identity["run"] != run:
            _die(f"native-result aggregation {platform} identity differs")
        for component in ("artifact", "job"):
            identity_ids[component].append(identity[component]["id"])
            identity_names[component].append(identity[component]["name"])
        _validate_native_execution(
            item["execution"],
            material=material,
            platform=platform,
            expected_identity=identity,
            contract=execution_contracts[platform],
        )
        comparison = _object(
            item["comparison"], {"bytes", "entries", "sha256"}, context=f"{platform} comparison"
        )
        for key in ("bytes", "entries"):
            _positive_int(comparison[key], context=f"{platform} comparison {key}")
        if (
            not isinstance(comparison["sha256"], str)
            or HEX64.fullmatch(comparison["sha256"]) is None
        ):
            _die(f"native-result aggregation {platform} comparison differs")
        payloads = _object(item["payloads"], {"A", "B"}, context=f"{platform} payloads")
        for build_id in ("A", "B"):
            seal = _object(
                payloads[build_id],
                {"bytes", "entries", "sha256"},
                context=f"{platform} payload {build_id}",
            )
            for key in ("bytes", "entries"):
                _positive_int(seal[key], context=f"{platform} payload {build_id} {key}")
            if not isinstance(seal["sha256"], str) or HEX64.fullmatch(seal["sha256"]) is None:
                _die(f"native-result aggregation {platform} payload differs")
        if payloads["A"] != payloads["B"]:
            _die(f"native-result aggregation {platform} A/B payload seals differ")
        run_evidence = _object(item["run_evidence"], {"A", "B"}, context=f"{platform} run evidence")
        for build_id in ("A", "B"):
            seal = _object(
                run_evidence[build_id],
                {"bytes", "entries", "sha256"},
                context=f"{platform} run evidence {build_id}",
            )
            for key in ("bytes", "entries"):
                _positive_int(seal[key], context=f"{platform} run evidence {build_id} {key}")
            if not isinstance(seal["sha256"], str) or HEX64.fullmatch(seal["sha256"]) is None:
                _die(f"native-result aggregation {platform} run evidence differs")
        platform_source = _object(
            item["source_context"],
            {"files", "git", "sha256", "size"},
            context=f"{platform} source context seal",
        )
        if (
            platform_source["files"] != compact_source["files"]
            or platform_source["git"] != compact_source["git"]
            or not isinstance(platform_source["sha256"], str)
            or HEX64.fullmatch(platform_source["sha256"]) is None
            or isinstance(platform_source["size"], bool)
            or not isinstance(platform_source["size"], int)
            or platform_source["size"] <= 0
        ):
            _die(f"native-result aggregation {platform} source context seal differs")
        platform_source_seals.append(
            {"sha256": platform_source["sha256"], "size": platform_source["size"]}
        )
    if platform_source_seals[0] != platform_source_seals[1]:
        _die("native-result aggregation platform source contexts differ")
    for component in ("artifact", "job"):
        if len(set(identity_ids[component])) != len(identity_ids[component]) or len(
            set(identity_names[component])
        ) != len(identity_names[component]):
            _die(f"native-result aggregation reuses one {component} identity across platforms")
    return aggregation


def validate_derived_platform_aggregation(
    value: Any,
    *,
    material: str,
    expected_policy_sha256: str,
    expected_identities: Mapping[str, Mapping[str, Any]],
    execution_contracts: Mapping[str, Mapping[str, Any]],
    derived_checks: frozenset[str],
    selection_keys: frozenset[str],
) -> dict[str, Any]:
    """Validate the closed material wrapper around one dual-platform carrier aggregation."""

    wrapper = _object(
        value,
        {
            "carrier_aggregation",
            "format",
            "material",
            "platforms",
            "policy_sha256",
            "run",
            "selected_build",
            "source_context",
        },
        context=f"derived {material} platform aggregation",
    )
    carrier = validate_platform_result_aggregation(
        wrapper["carrier_aggregation"],
        material=material,
        expected_policy_sha256=expected_policy_sha256,
        expected_identities=expected_identities,
        execution_contracts=execution_contracts,
    )
    if (
        wrapper["format"] != f"z4j-production-{material}-derived-platform-aggregation-v1"
        or wrapper["material"] != material
        or wrapper["policy_sha256"] != expected_policy_sha256
        or wrapper["run"] != carrier["run"]
        or wrapper["selected_build"] != "A"
        or wrapper["source_context"] != carrier["source_context"]
        or not derived_checks
        or not selection_keys
    ):
        _die(f"derived {material} platform aggregation constants differ")
    platforms = _object(
        wrapper["platforms"], set(PLATFORMS), context=f"derived {material} platforms"
    )
    payload_keys = {
        "inventory_entries",
        "inventory_sha256",
        "inventory_size",
        "tree_bytes",
        "tree_sha256",
    }
    for platform in PLATFORMS:
        item = _object(
            platforms[platform],
            {"builds", "checks", "payload", "selection"},
            context=f"derived {material} {platform}",
        )
        checks = _object(
            item["checks"], set(derived_checks), context=f"derived {material} {platform} checks"
        )
        if checks != dict.fromkeys(derived_checks, True):
            _die(f"derived {material} {platform} checks differ")
        payload = _object(
            item["payload"], payload_keys, context=f"derived {material} {platform} payload"
        )
        for key in ("inventory_entries", "inventory_size", "tree_bytes"):
            _positive_int(payload[key], context=f"derived {material} {platform} {key}")
        for key in ("inventory_sha256", "tree_sha256"):
            if not isinstance(payload[key], str) or HEX64.fullmatch(payload[key]) is None:
                _die(f"derived {material} {platform} {key} differs")
        selection = _object(
            item["selection"],
            set(selection_keys),
            context=f"derived {material} {platform} selection",
        )
        if any(selection[key] != payload[key] for key in payload_keys):
            _die(f"derived {material} {platform} payload/selection binding differs")
        builds = item["builds"]
        if not isinstance(builds, list) or len(builds) != 2:
            _die(f"derived {material} {platform} A/B set differs")
        normalized: list[dict[str, Any]] = []
        for position, build_id in enumerate(("A", "B")):
            build = _object(
                builds[position],
                {"checks", "id", "payload", "selection"},
                context=f"derived {material} {platform} build {build_id}",
            )
            if build["id"] != build_id:
                _die(f"derived {material} {platform} build order differs")
            normalized.append({key: build[key] for key in ("checks", "payload", "selection")})
        expected = {"checks": checks, "payload": payload, "selection": selection}
        if normalized[0] != normalized[1] or normalized[0] != expected:
            _die(f"derived {material} {platform} A/B material differs")
    return wrapper


def load_canonical_evidence(
    root: Path,
    logical_path: str,
    *,
    context: str,
    maximum: int = MAX_FILE_BYTES,
) -> tuple[dict[str, Any], bytes]:
    """Read one direct canonical JSON+LF evidence file below an extracted root."""

    logical = PurePosixPath(logical_path)
    if (
        not logical_path
        or logical.is_absolute()
        or logical.as_posix() != logical_path
        or any(component in {"", ".", ".."} for component in logical.parts)
    ):
        _die(f"{context} logical path differs")
    raw = read_regular(root / logical_path, maximum=maximum, context=context)
    value = parse_json(raw, context=context)
    if not isinstance(value, dict) or canonical_json(value, terminal_lf=True) != raw:
        _die(f"{context} is not one canonical object plus LF")
    return value, raw


def evidence_file_seal(root: Path, logical_path: str, *, context: str) -> dict[str, Any]:
    """Seal one direct regular evidence file selected by a reviewed relative path."""

    logical = PurePosixPath(logical_path)
    if (
        not logical_path
        or logical.is_absolute()
        or logical.as_posix() != logical_path
        or any(component in {"", ".", ".."} for component in logical.parts)
    ):
        _die(f"{context} logical path differs")
    raw = read_regular(root / logical_path, maximum=MAX_FILE_BYTES, context=context)
    return {"sha256": sha256(raw), "size": len(raw)}


def derive_payload_inventory(
    payload_root: Path,
    *,
    platform: str,
    inventory_format: str,
    tree_format: str,
) -> dict[str, Any]:
    """Derive inventory/tree values from extracted payload bytes, never sidecar booleans."""

    inventory, inventory_raw = load_canonical_evidence(
        payload_root, "inventory.json", context=f"{platform} payload inventory"
    )
    inventory = _object(
        inventory, {"files", "format", "platform"}, context=f"{platform} payload inventory"
    )
    if inventory["format"] != inventory_format or inventory["platform"] != platform:
        _die(f"{platform} payload inventory identity differs")
    records = _validate_tree_records(inventory["files"], context=f"{platform} payload inventory")
    observed = file_records(payload_root)
    if records != observed:
        _die(f"{platform} payload inventory differs from extracted files")
    tree = {"files": records, "format": tree_format, "platform": platform}
    return {
        "inventory_entries": len(records),
        "inventory_sha256": sha256(inventory_raw),
        "inventory_size": len(inventory_raw),
        "tree_bytes": sum(item["size"] for item in records),
        "tree_sha256": sha256(canonical_json(tree, terminal_lf=False)),
    }


def validate_evidence_command(
    value: Any,
    evidence_root: Path,
    *,
    context: str,
    expected_argv: Sequence[str] | None = None,
    expected_cwd: str | None = None,
    expected_environment: Mapping[str, str] | None = None,
    extra_file_keys: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Cross-check a retained command object against its extracted transcript files."""

    command = _object(
        value,
        {"argv", "cwd", "environment", "exit_code", "stderr", "stdout"} | set(extra_file_keys),
        context=context,
    )
    argv = command["argv"]
    environment = command["environment"]
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(item, str) and item and "\0" not in item for item in argv)
        or (expected_argv is not None and argv != list(expected_argv))
        or not isinstance(command["cwd"], str)
        or not command["cwd"].startswith("/")
        or "\0" in command["cwd"]
        or (expected_cwd is not None and command["cwd"] != expected_cwd)
        or not isinstance(environment, dict)
        or not environment
        or not all(
            isinstance(key, str)
            and key
            and isinstance(item, str)
            and "\0" not in key
            and "\0" not in item
            for key, item in environment.items()
        )
        or (expected_environment is not None and environment != dict(expected_environment))
        or command["exit_code"] != 0
    ):
        _die(f"{context} command identity/result differs")
    for key in ("stderr", "stdout", *sorted(extra_file_keys)):
        seal = _object(command[key], {"path", "sha256", "size"}, context=f"{context} {key}")
        if (
            not isinstance(seal["path"], str)
            or not isinstance(seal["sha256"], str)
            or HEX64.fullmatch(seal["sha256"]) is None
            or isinstance(seal["size"], bool)
            or not isinstance(seal["size"], int)
            or seal["size"] < 0
            or evidence_file_seal(evidence_root, seal["path"], context=f"{context} retained {key}")
            != {"sha256": seal["sha256"], "size": seal["size"]}
        ):
            _die(f"{context} {key} transcript differs")
    return command


def tar_member_records(raw: bytes, *, context: str) -> list[dict[str, Any]]:  # noqa: PLR0912
    """Parse, bound, and seal a tar stream without extracting any member."""

    records: list[dict[str, Any]] = []
    total = 0
    paths: dict[str, str] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
            if archive.pax_headers:
                _die(f"{context} contains global PAX metadata")
            for member in archive:
                if len(records) >= MAX_FILES:
                    _die(f"{context} has too many members")
                raw_name = member.name
                name = raw_name.removesuffix("/")
                logical = PurePosixPath(name)
                if (
                    not name
                    or raw_name.startswith("./")
                    or "//" in raw_name
                    or logical.is_absolute()
                    or ".." in logical.parts
                    or "\\" in name
                    or "\0" in name
                    or "\n" in name
                    or member.pax_headers
                    or getattr(member, "sparse", None)
                    or member.size < 0
                    or member.size > MAX_FILE_BYTES
                    or stat.S_IMODE(member.mode) & 0o7000
                ):
                    _die(f"{context} contains an unsafe member")
                if member.isdir():
                    kind = "directory"
                    size = 0
                elif member.isfile() and not member.issym() and not member.islnk():
                    kind = "file"
                    size = member.size
                else:
                    _die(f"{context} contains a link or special member")
                if name in paths:
                    _die(f"{context} contains a duplicate member")
                for parent in logical.parents:
                    parent_name = parent.as_posix()
                    if parent_name == ".":
                        continue
                    if paths.get(parent_name) == "file":
                        _die(f"{context} contains a file/directory collision")
                if kind == "file" and any(existing.startswith(name + "/") for existing in paths):
                    _die(f"{context} contains a file/directory collision")
                paths[name] = kind
                mode = stat.S_IMODE(member.mode)
                if mode & 0o022 or (kind == "file" and mode not in {0o644, 0o755}):
                    _die(f"{context} contains an unsafe member mode")
                total += size
                if total > MAX_FILE_BYTES:
                    _die(f"{context} expanded bytes exceed the reviewed bound")
                records.append(
                    {
                        "mode": f"{mode:04o}",
                        "path": name,
                        "size": size,
                        "type": kind,
                    }
                )
    except (tarfile.TarError, UnicodeError) as exc:
        raise MaterialBuildError(f"{context} is not a safe tar stream") from exc
    if not records:
        _die(f"{context} has no members")
    return records


def extract_reviewed_tar(  # noqa: PLR0912,PLR0915 - full safe archive transaction
    raw: bytes,
    destination: Path,
    *,
    expected_sha256: str,
    expected_entries: int,
    expected_bytes: int,
    context: str,
) -> list[dict[str, Any]]:
    """Safely extract an authenticated gzip/plain tar without invoking `/bin/tar`."""

    records = validate_tar_member_authority(
        raw,
        expected_sha256=expected_sha256,
        expected_entries=expected_entries,
        expected_bytes=expected_bytes,
        context=context,
    )
    require_empty_private_directory(destination, context=f"{context} destination")
    root = _open_directory(destination)
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
            observed = archive.getmembers()
            if len(observed) != len(records):
                _die(f"{context} member count changed during extraction")
            for member, record in zip(observed, records, strict=True):
                name = record["path"]
                if member.name.removesuffix("/") != name:
                    _die(f"{context} member order changed during extraction")
                parts = PurePosixPath(name).parts
                current = os.dup(root)
                try:
                    for component in parts[:-1]:
                        with suppress(FileExistsError):
                            os.mkdir(component, mode=0o700, dir_fd=current)
                        child = os.open(
                            component,
                            os.O_RDONLY
                            | getattr(os, "O_DIRECTORY", 0)
                            | getattr(os, "O_CLOEXEC", 0)
                            | getattr(os, "O_NOFOLLOW", 0),
                            dir_fd=current,
                        )
                        info = os.fstat(child)
                        if (
                            not stat.S_ISDIR(info.st_mode)
                            or info.st_uid != os.geteuid()
                            or stat.S_IMODE(info.st_mode) != 0o700
                        ):
                            os.close(child)
                            _die(f"{context} extraction parent differs")
                        os.close(current)
                        current = child
                    if record["type"] == "directory":
                        try:
                            os.mkdir(parts[-1], mode=0o700, dir_fd=current)
                        except FileExistsError:
                            child = os.open(
                                parts[-1],
                                os.O_RDONLY
                                | getattr(os, "O_DIRECTORY", 0)
                                | getattr(os, "O_CLOEXEC", 0)
                                | getattr(os, "O_NOFOLLOW", 0),
                                dir_fd=current,
                            )
                            try:
                                info = os.fstat(child)
                                if not stat.S_ISDIR(info.st_mode):
                                    _die(f"{context} directory member collides")
                            finally:
                                os.close(child)
                    else:
                        stream = archive.extractfile(member)
                        if stream is None:
                            _die(f"{context} file member is absent")
                        content = stream.read(record["size"] + 1)
                        if len(content) != record["size"]:
                            _die(f"{context} file member size differs")
                        _write_new_at(
                            current,
                            parts[-1],
                            content,
                            mode=int(record["mode"], 8),
                            context=context,
                        )
                finally:
                    os.close(current)
            os.fsync(root)
    except (OSError, tarfile.TarError) as exc:
        raise MaterialBuildError(f"{context} safe extraction failed") from exc
    files = file_records(destination, exclude=frozenset())
    expected_files = [
        {
            "mode": item["mode"],
            "path": item["path"],
            "size": item["size"],
        }
        for item in records
        if item["type"] == "file"
    ]
    if [
        {"mode": item["mode"], "path": item["path"], "size": item["size"]} for item in files
    ] != expected_files:
        _die(f"{context} extracted projection differs")
    return files


def validate_tar_member_authority(
    raw: bytes,
    *,
    expected_sha256: str,
    expected_entries: int,
    expected_bytes: int,
    context: str,
) -> list[dict[str, Any]]:
    """Require the exact reviewed semantic header inventory before extraction."""

    records = tar_member_records(raw, context=context)
    framing = {"files": records, "format": "z4j-production-tar-members-v1"}
    if (
        HEX64.fullmatch(expected_sha256) is None
        or sha256(canonical_json(framing, terminal_lf=False)) != expected_sha256
        or len(records) != expected_entries
        or sum(item["size"] for item in records) != expected_bytes
    ):
        _die(f"{context} semantic member authority differs")
    return records


def validate_generator_dockerfile(
    raw: bytes,
    *,
    acquisition_marker: bytes,
    offline_markers: Sequence[bytes],
) -> None:
    """Require explicit network separation in a checked-in generator Dockerfile."""

    if not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        _die("generator Dockerfile framing differs")
    if raw.count(acquisition_marker) != 1:
        _die("generator Dockerfile acquisition boundary differs")
    for marker in offline_markers:
        if raw.count(marker) != 1:
            _die("generator Dockerfile offline boundary differs")
    if b"--network=host" in raw or b"curl |" in raw or b"wget |" in raw:
        _die("generator Dockerfile contains an unreviewed network escape")


def _duplicate_key(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _die(f"JSON contains duplicate key {key!r}")
        value[key] = item
    return value


def parse_json(raw: bytes, *, context: str) -> Any:
    """Parse JSON without accepting duplicate keys, floats, or non-UTF-8 bytes."""

    def reject_float(value: str) -> NoReturn:
        _die(f"{context} contains floating-point number {value}")

    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicate_key,
            parse_float=reject_float,
            parse_constant=reject_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MaterialBuildError(f"{context} is not strict JSON") from exc


def _object(value: Any, keys: set[str], *, context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _die(f"{context} keys differ")
    return value


def _string(value: Any, *, context: str) -> str:
    if not isinstance(value, str) or not value or "\0" in value:
        _die(f"{context} is not a nonempty string")
    return value


def _positive_int(value: Any, *, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        _die(f"{context} is not a positive integer")
    return value


def _digest(value: Any, *, context: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        _die(f"{context} is not a sha256 digest")
    return value


def _file_authority(value: Any, *, path: str, context: str) -> list[str]:
    authority = _object(value, {"path", "sha256", "size", "version_output_sha256"}, context=context)
    if authority["path"] != path:
        _die(f"{context} path differs")
    poison: list[str] = []
    if authority["sha256"] is None or authority["size"] is None:
        poison.append(f"{context} binary seal is null")
    else:
        if not isinstance(authority["sha256"], str) or HEX64.fullmatch(authority["sha256"]) is None:
            _die(f"{context} SHA-256 differs")
        _positive_int(authority["size"], context=f"{context} size")
    if authority["version_output_sha256"] is None:
        poison.append(f"{context} version transcript seal is null")
    elif (
        not isinstance(authority["version_output_sha256"], str)
        or HEX64.fullmatch(authority["version_output_sha256"]) is None
    ):
        _die(f"{context} version transcript SHA-256 differs")
    return poison


def validate_platform_file_authority(
    value: Any,
    *,
    platforms: Sequence[str],
    path: str,
    context: str,
) -> list[str]:
    """Validate one exact native executable authority per reviewed platform."""

    wrapper = _object(value, {"platforms"}, context=context)
    matrix = _object(wrapper["platforms"], set(platforms), context=context + " platforms")
    poison: list[str] = []
    for platform in platforms:
        poison.extend(
            _file_authority(
                matrix[platform],
                path=path,
                context=f"{context} {platform}",
            )
        )
    return poison


def validate_platform_git_authority(
    value: Any,
    *,
    platforms: Sequence[str],
    context: str,
) -> list[str]:
    """Validate policy-selected Git tools without choosing an ambient path.

    The path, byte seal, and version-transcript seal are all identity poison
    until an external policy authority selects them.  Runtime capture applies
    the stricter non-null validator before opening the selected executable.
    """

    wrapper = _object(value, {"platforms"}, context=context)
    matrix = _object(wrapper["platforms"], set(platforms), context=context + " platforms")
    poison: list[str] = []
    for platform in platforms:
        platform_context = f"{context} {platform}"
        authority = _object(
            matrix[platform],
            {"path", "sha256", "size", "version_output_sha256"},
            context=platform_context,
        )
        path = authority["path"]
        if path is None:
            poison.append(f"{platform_context} path is null")
        elif (
            not isinstance(path, str)
            or not Path(path).is_absolute()
            or Path(path).as_posix() != path
            or "." in Path(path).parts
            or ".." in Path(path).parts
            or "\\" in path
            or Path(path).name in {"", ".", ".."}
            or "\0" in path
            or "\n" in path
            or "\r" in path
        ):
            _die(f"{platform_context} path differs")
        if authority["sha256"] is None or authority["size"] is None:
            poison.append(f"{platform_context} binary seal is null")
        if authority["sha256"] is not None and (
            not isinstance(authority["sha256"], str) or HEX64.fullmatch(authority["sha256"]) is None
        ):
            _die(f"{platform_context} SHA-256 differs")
        if authority["size"] is not None:
            _positive_int(authority["size"], context=f"{platform_context} size")
            if authority["size"] > MAX_FILE_BYTES:
                _die(f"{platform_context} size exceeds its reviewed bound")
        version_digest = authority["version_output_sha256"]
        if version_digest is None:
            poison.append(f"{platform_context} version transcript seal is null")
        elif not isinstance(version_digest, str) or HEX64.fullmatch(version_digest) is None:
            _die(f"{platform_context} version transcript SHA-256 differs")
    return poison


DAEMON_PROJECTION_KEYS = {
    "architecture",
    "cgroup_driver",
    "cgroup_version",
    "docker_root_dir",
    "driver",
    "kernel_version",
    "operating_system",
    "os_type",
    "security_options",
    "server_version",
}


def _validate_daemon_projection(value: Any, *, platform: str) -> dict[str, Any]:
    projection = _object(value, DAEMON_PROJECTION_KEYS, context=f"daemon {platform}")
    if projection["architecture"] != HOST_ARCHITECTURES[platform]:
        _die(f"daemon {platform} architecture differs")
    for key in DAEMON_PROJECTION_KEYS - {"security_options"}:
        _string(projection[key], context=f"daemon {platform} {key}")
    if projection["os_type"] != "linux":
        _die(f"daemon {platform} OS differs")
    options = projection["security_options"]
    if (
        not isinstance(options, list)
        or not all(isinstance(item, str) and item for item in options)
        or options != sorted(set(options), key=lambda item: item.encode("utf-8"))
    ):
        _die(f"daemon {platform} security options differ")
    return projection


def validate_execution_plane_policy(  # noqa: PLR0912
    value: Any,
    *,
    platforms: Sequence[str],
    buildx_path: str = "/usr/libexec/docker/cli-plugins/docker-buildx",
) -> list[str]:
    """Validate the closed, material-neutral native Buildx authority policy."""

    plane = _object(
        value,
        {"buildkit", "buildx", "context", "daemon", "driver", "worker_network"},
        context="generator execution plane",
    )
    if plane["driver"] != DOCKER_DRIVER:
        _die("generator execution-plane driver differs")
    if plane["worker_network"] != BUILDKIT_WORKER_NETWORK:
        _die("generator BuildKit worker network differs")
    context = _object(plane["context"], {"docker_host", "name"}, context="generator Docker context")
    if context != {"docker_host": DOCKER_HOST, "name": DOCKER_CONTEXT}:
        _die("generator Docker context differs")
    expected_platforms = list(platforms)
    if expected_platforms != list(PLATFORMS):
        _die("generator execution-plane platform order differs")
    poison = validate_platform_file_authority(
        plane["buildx"],
        platforms=expected_platforms,
        path=buildx_path,
        context="generator Buildx plugin",
    )
    daemon = _object(
        plane["daemon"], set(expected_platforms), context="generator daemon projections"
    )
    for platform in expected_platforms:
        if daemon[platform] is None:
            poison.append(f"generator daemon {platform} projection is null")
        else:
            _validate_daemon_projection(daemon[platform], platform=platform)

    buildkit = _object(
        plane["buildkit"],
        {"image", "index", "platforms", "version"},
        context="generator BuildKit image",
    )
    index = _object(buildkit["index"], {"digest", "size"}, context="BuildKit index")
    platform_records = _object(
        buildkit["platforms"], set(expected_platforms), context="BuildKit platform records"
    )
    if buildkit["image"] is None or buildkit["version"] is None:
        poison.append("generator BuildKit image/version is null")
    else:
        image = _string(buildkit["image"], context="BuildKit image")
        version = _string(buildkit["version"], context="BuildKit version")
        match = re.fullmatch(
            r"docker\.io/moby/buildkit:(v[0-9]+\.[0-9]+\.[0-9]+)@(sha256:[0-9a-f]{64})",
            image,
        )
        if match is None or match.group(1) != version:
            _die("BuildKit image/version identity differs")
        if index["digest"] is not None and match.group(2) != index["digest"]:
            _die("BuildKit image/index digest differs")
    if index["digest"] is None or index["size"] is None:
        poison.append("generator BuildKit index seal is null")
    else:
        _digest(index["digest"], context="BuildKit index digest")
        _positive_int(index["size"], context="BuildKit index size")
    descriptor_keys = {"config_digest", "config_size", "manifest_digest", "manifest_size"}
    for platform in expected_platforms:
        record = _object(
            platform_records[platform], descriptor_keys, context=f"BuildKit {platform} record"
        )
        if any(record[key] is None for key in descriptor_keys):
            poison.append(f"generator BuildKit {platform} seals are null")
            continue
        _digest(record["manifest_digest"], context=f"BuildKit {platform} manifest")
        _positive_int(record["manifest_size"], context=f"BuildKit {platform} manifest size")
        _digest(record["config_digest"], context=f"BuildKit {platform} config")
        _positive_int(record["config_size"], context=f"BuildKit {platform} config size")
    return poison


def _raw_seal(raw: bytes) -> dict[str, Any]:
    return {"sha256": sha256(raw), "size": len(raw)}


def _raw_bytes_record(raw: bytes) -> dict[str, Any]:
    """Encode literal bytes in the canonical JSON-safe carrier representation."""

    return {
        "base64": base64.b64encode(raw).decode("ascii"),
        "sha256": sha256(raw),
        "size": len(raw),
    }


def _remove_private_tree(path: Path, *, expected_identity: tuple[int, int]) -> None:
    """Remove only the exact private temporary tree created by this process."""

    parent = _open_directory(path.parent)

    def clear(directory: int) -> None:
        for name in os.listdir(directory):
            observed = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISDIR(observed.st_mode):
                child = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory,
                )
                try:
                    captured = os.fstat(child)
                    if (captured.st_dev, captured.st_ino) != (observed.st_dev, observed.st_ino):
                        _die("private execution directory changed during cleanup")
                    clear(child)
                finally:
                    os.close(child)
                os.rmdir(name, dir_fd=directory)
            else:
                os.unlink(name, dir_fd=directory)

    try:
        observed = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(observed.st_mode)
            or (observed.st_dev, observed.st_ino) != expected_identity
        ):
            _die("private execution root identity changed")
        root = os.open(
            path.name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent,
        )
        try:
            clear(root)
        finally:
            os.close(root)
        final = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (final.st_dev, final.st_ino) != expected_identity:
            _die("private execution root changed before removal")
        os.rmdir(path.name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


@contextmanager
def private_temporary_directory(*, prefix: str) -> Iterator[Path]:
    """Yield one owner-private empty tree and remove only that captured inode."""

    if re.fullmatch(r"z4j-[a-z0-9-]{1,60}\.", prefix) is None:
        _die("private temporary-directory prefix differs")
    root = Path(tempfile.mkdtemp(prefix=prefix))
    root.chmod(0o700)
    observed = root.stat(follow_symlinks=False)
    identity = (observed.st_dev, observed.st_ino)
    if (
        not stat.S_ISDIR(observed.st_mode)
        or observed.st_uid != os.geteuid()
        or stat.S_IMODE(observed.st_mode) != 0o700
    ):
        _die("private temporary directory differs")
    try:
        yield root
    finally:
        _remove_private_tree(root, expected_identity=identity)


@dataclass(frozen=True)
class CapturedDockerToolchain:
    """Owner-private, byte-captured Docker CLI and Buildx plugin."""

    docker: Path
    docker_descriptor: int
    environment: dict[str, str]
    records: dict[str, Any]
    root: Path


def _copy_sealed_executable(
    source: Path,
    destination: Path,
    *,
    expected_sha256: str,
    expected_size: int,
    context: str,
) -> dict[str, Any]:
    raw = read_regular(source, maximum=MAX_FILE_BYTES, context=context)
    if (
        HEX64.fullmatch(expected_sha256) is None
        or sha256(raw) != expected_sha256
        or len(raw) != expected_size
    ):
        _die(f"{context} seal differs")
    atomic_write_new(destination, raw, mode=0o500)
    captured = read_regular(destination, maximum=MAX_FILE_BYTES, context=f"captured {context}")
    if captured != raw:
        _die(f"captured {context} differs")
    return {"sha256": expected_sha256, "size": expected_size}


def capture_sealed_executable(
    source: Path,
    destination: Path,
    *,
    expected_sha256: str,
    expected_size: int,
    context: str,
) -> dict[str, Any]:
    """Public fd-safe capture primitive for a material-specific generator."""

    return _copy_sealed_executable(
        source,
        destination,
        expected_sha256=expected_sha256,
        expected_size=expected_size,
        context=context,
    )


def verify_captured_executable(
    path: Path,
    *,
    expected_sha256: str,
    expected_size: int,
    context: str,
) -> None:
    """Re-read one private captured tool before later execution."""

    raw = read_regular(path, maximum=MAX_FILE_BYTES, context=context)
    if sha256(raw) != expected_sha256 or len(raw) != expected_size:
        _die(f"{context} seal differs")


@contextmanager
def held_verified_executable(
    path: Path,
    *,
    expected_sha256: str,
    expected_size: int,
    context: str,
) -> Iterator[int]:
    """Hold and verify the exact inode that a subprocess will execute."""

    parent = _open_directory(path.parent)
    try:
        descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent,
        )
    finally:
        os.close(parent)
    try:
        raw = _read_descriptor(descriptor, maximum=MAX_FILE_BYTES, context=context)
        observed = os.fstat(descriptor)
        if (
            sha256(raw) != expected_sha256
            or len(raw) != expected_size
            or not stat.S_IMODE(observed.st_mode) & 0o100
        ):
            _die(f"{context} held executable differs")
        yield descriptor
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            observed.st_dev,
            observed.st_ino,
            observed.st_size,
            observed.st_mtime_ns,
            observed.st_ctime_ns,
        ):
            _die(f"{context} held executable changed during use")
    finally:
        os.close(descriptor)


@contextmanager
def captured_docker_toolchain(
    runner: CommandRunner,
    *,
    docker_authority: Mapping[str, Any],
    buildx_authority: Mapping[str, Any],
    cwd: Path,
) -> Iterator[CapturedDockerToolchain]:
    """Capture and probe the exact Docker/Buildx bytes in a sterile config."""

    root = Path(tempfile.mkdtemp(prefix="z4j-production-docker."))
    root.chmod(0o700)
    root_stat = root.stat(follow_symlinks=False)
    identity = (root_stat.st_dev, root_stat.st_ino)
    docker_descriptor: int | None = None
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_IMODE(root_stat.st_mode) != 0o700:
        _die("private Docker capture root differs")
    try:
        bin_directory = root / "bin"
        config_directory = root / "config"
        plugin_directory = config_directory / "cli-plugins"
        bin_directory.mkdir(mode=0o700)
        config_directory.mkdir(mode=0o700)
        plugin_directory.mkdir(mode=0o700)
        docker = bin_directory / "docker"
        buildx = plugin_directory / "docker-buildx"
        docker_record = _copy_sealed_executable(
            Path(docker_authority["path"]),
            docker,
            expected_sha256=docker_authority["sha256"],
            expected_size=docker_authority["size"],
            context="Docker CLI",
        )
        buildx_record = _copy_sealed_executable(
            Path(buildx_authority["path"]),
            buildx,
            expected_sha256=buildx_authority["sha256"],
            expected_size=buildx_authority["size"],
            context="Buildx plugin",
        )
        docker_descriptor = os.open(
            docker,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        atomic_write_new(config_directory / "config.json", b"{}\n", mode=0o600)
        environment = {
            "BUILDX_NO_DEFAULT_ATTESTATIONS": "1",
            "DOCKER_BUILDKIT": "1",
            "DOCKER_CONFIG": str(config_directory),
            "DOCKER_CONTEXT": DOCKER_CONTEXT,
            "DOCKER_HOST": DOCKER_HOST,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "TZ": "UTC",
        }
        docker_probe = require_success(
            runner.run(
                [str(docker), "--version"],
                cwd=cwd,
                env=environment,
                executable_fd=docker_descriptor,
                timeout_seconds=60,
            ),
            context="captured Docker version probe",
        )
        buildx_probe = require_success(
            runner.run(
                [str(docker), "buildx", "version"],
                cwd=cwd,
                env=environment,
                executable_fd=docker_descriptor,
                timeout_seconds=60,
            ),
            context="captured Buildx version probe",
        )
        if (
            sha256(docker_probe.stdout + docker_probe.stderr)
            != docker_authority["version_output_sha256"]
        ):
            _die("captured Docker version transcript differs")
        if (
            sha256(buildx_probe.stdout + buildx_probe.stderr)
            != buildx_authority["version_output_sha256"]
        ):
            _die("captured Buildx version transcript differs")
        if (
            _raw_seal(read_regular(docker, maximum=MAX_FILE_BYTES, context="captured Docker CLI"))
            != docker_record
        ):
            _die("captured Docker CLI changed after probe")
        if (
            _raw_seal(
                read_regular(buildx, maximum=MAX_FILE_BYTES, context="captured Buildx plugin")
            )
            != buildx_record
        ):
            _die("captured Buildx plugin changed after probe")
        yield CapturedDockerToolchain(
            docker=docker,
            docker_descriptor=docker_descriptor,
            environment=environment,
            records={
                "buildx": {**buildx_record, "version_probe": buildx_probe.record()},
                "docker": {**docker_record, "version_probe": docker_probe.record()},
            },
            root=root,
        )
        if (
            _raw_seal(read_regular(docker, maximum=MAX_FILE_BYTES, context="captured Docker CLI"))
            != docker_record
        ):
            _die("captured Docker CLI changed during execution")
        if (
            _raw_seal(
                read_regular(buildx, maximum=MAX_FILE_BYTES, context="captured Buildx plugin")
            )
            != buildx_record
        ):
            _die("captured Buildx plugin changed during execution")
    finally:
        if docker_descriptor is not None:
            os.close(docker_descriptor)
        _remove_private_tree(root, expected_identity=identity)


def _docker_command(
    runner: CommandRunner,
    toolchain: CapturedDockerToolchain,
    arguments: Sequence[str],
    *,
    cwd: Path,
    context: str,
    accept_failure: bool = False,
    timeout_seconds: int = 300,
) -> CommandResult:
    result = runner.run(
        [str(toolchain.docker), *arguments],
        cwd=cwd,
        env=toolchain.environment,
        executable_fd=toolchain.docker_descriptor,
        timeout_seconds=timeout_seconds,
    )
    if not accept_failure:
        require_success(result, context=context)
    return result


def _context_projection(raw: bytes) -> dict[str, Any]:
    value = parse_json(raw, context="Docker context inspect")
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        _die("Docker context inspect response differs")
    item = value[0]
    if item.get("Name") != DOCKER_CONTEXT or not isinstance(item.get("Endpoints"), dict):
        _die("Docker context identity differs")
    endpoints = item["Endpoints"]
    if set(endpoints) != {"docker"} or not isinstance(endpoints["docker"], dict):
        _die("Docker context endpoints differ")
    endpoint = endpoints["docker"]
    if endpoint.get("Host") != DOCKER_HOST or endpoint.get("SkipTLSVerify") is not False:
        _die("Docker context endpoint differs")
    return {
        "docker_host": endpoint["Host"],
        "name": item["Name"],
        "skip_tls_verify": endpoint["SkipTLSVerify"],
    }


def _daemon_projection(raw: bytes, *, platform: str) -> dict[str, Any]:
    value = parse_json(raw, context="Docker daemon info")
    if not isinstance(value, dict):
        _die("Docker daemon info response differs")
    source_keys = {
        "Architecture": "architecture",
        "CgroupDriver": "cgroup_driver",
        "CgroupVersion": "cgroup_version",
        "DockerRootDir": "docker_root_dir",
        "Driver": "driver",
        "KernelVersion": "kernel_version",
        "OperatingSystem": "operating_system",
        "OSType": "os_type",
        "ServerVersion": "server_version",
    }
    projection: dict[str, Any] = {}
    for source, target in source_keys.items():
        item = value.get(source)
        if source == "CgroupVersion" and isinstance(item, int) and not isinstance(item, bool):
            item = str(item)
        projection[target] = _string(item, context=f"Docker info {source}")
    security = value.get("SecurityOptions")
    if not isinstance(security, list) or not all(
        isinstance(item, str) and item for item in security
    ):
        _die("Docker daemon security options differ")
    projection["security_options"] = sorted(set(security), key=lambda item: item.encode("utf-8"))
    return _validate_daemon_projection(projection, platform=platform)


def _inspect_context_and_daemon(
    runner: CommandRunner,
    toolchain: CapturedDockerToolchain,
    *,
    cwd: Path,
    platform: str,
    expected_daemon: Mapping[str, Any],
) -> dict[str, Any]:
    context_result = _docker_command(
        runner,
        toolchain,
        ("context", "inspect", DOCKER_CONTEXT),
        cwd=cwd,
        context="Docker context inspection",
    )
    context_projection = _context_projection(context_result.stdout)
    daemon_result = _docker_command(
        runner,
        toolchain,
        ("info", "--format", "{{json .}}"),
        cwd=cwd,
        context="Docker daemon inspection",
    )
    daemon_projection = _daemon_projection(daemon_result.stdout, platform=platform)
    if daemon_projection != expected_daemon:
        _die("Docker daemon projection differs from policy")
    return {
        "context": {
            "projection": context_projection,
            "response": context_result.record(),
        },
        "daemon": {
            "projection": daemon_projection,
            "response": daemon_result.record(),
        },
    }


def _builder_names(raw: bytes, *, prefix: str) -> list[str]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise MaterialBuildError("Buildx builder inventory is not UTF-8") from exc
    if "\r" in text or "\0" in text:
        _die("Buildx builder inventory framing differs")
    names = [line for line in text.splitlines() if line]
    if any(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name) is None for name in names):
        _die("Buildx builder inventory contains an invalid name")
    if len(names) != len(set(names)):
        _die("Buildx builder inventory contains a duplicate name")
    return sorted(name for name in names if name.startswith(prefix))


def _builder_inventory(
    runner: CommandRunner,
    toolchain: CapturedDockerToolchain,
    *,
    cwd: Path,
    prefix: str,
) -> tuple[list[str], dict[str, Any]]:
    builders = _docker_command(
        runner,
        toolchain,
        ("buildx", "ls", "--format", "{{.Name}}"),
        cwd=cwd,
        context="Buildx builder inventory",
    )
    container_prefix = "buildx_buildkit_" + prefix
    containers = _docker_command(
        runner,
        toolchain,
        (
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--filter",
            "name=" + container_prefix,
            "--format",
            "{{.Names}}",
        ),
        cwd=cwd,
        context="BuildKit helper-owned container inventory",
    )
    builder_names = _builder_names(builders.stdout, prefix=prefix)
    container_names = _builder_names(containers.stdout, prefix=container_prefix)
    stale = [
        *("builder:" + name for name in builder_names),
        *("container:" + name for name in container_names),
    ]
    return stale, {
        "builders": builders.record(),
        "containers": containers.record(),
    }


def _validate_buildkit_index(
    raw: bytes,
    *,
    policy: Mapping[str, Any],
    platform: str,
) -> dict[str, Any]:
    index = policy["index"]
    if len(raw) != index["size"] or "sha256:" + sha256(raw) != index["digest"]:
        _die("raw BuildKit index seal differs")
    value = parse_json(raw, context="raw BuildKit index")
    if (
        not isinstance(value, dict)
        or value.get("schemaVersion") != 2
        or value.get("mediaType") != OCI_INDEX
    ):
        _die("raw BuildKit index schema/media differs")
    manifests = value.get("manifests")
    if not isinstance(manifests, list) or not manifests:
        _die("raw BuildKit index descriptors differ")
    selected_policy = policy["platforms"][platform]
    matches: list[dict[str, Any]] = []
    for descriptor in manifests:
        if not isinstance(descriptor, dict):
            _die("raw BuildKit descriptor differs")
        selected = (
            descriptor.get("mediaType") == OCI_MANIFEST
            and descriptor.get("digest") == selected_policy["manifest_digest"]
            and descriptor.get("size") == selected_policy["manifest_size"]
            and descriptor.get("platform") == {"architecture": PLATFORMS[platform], "os": "linux"}
        )
        if selected:
            matches.append(descriptor)
    if len(matches) != 1:
        _die("raw BuildKit native platform descriptor is not unique")
    return matches[0]


def _validate_buildkit_manifest(
    raw: bytes,
    *,
    policy: Mapping[str, Any],
    platform: str,
) -> dict[str, Any]:
    record = policy["platforms"][platform]
    if len(raw) != record["manifest_size"] or "sha256:" + sha256(raw) != record["manifest_digest"]:
        _die("raw BuildKit platform manifest seal differs")
    value = parse_json(raw, context="raw BuildKit platform manifest")
    if (
        not isinstance(value, dict)
        or value.get("schemaVersion") != 2
        or value.get("mediaType") != OCI_MANIFEST
    ):
        _die("raw BuildKit platform manifest schema/media differs")
    config = value.get("config")
    if not isinstance(config, dict):
        _die("raw BuildKit config descriptor differs")
    expected = {
        "digest": record["config_digest"],
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "size": record["config_size"],
    }
    if config != expected:
        _die("raw BuildKit config descriptor differs")
    layers = value.get("layers")
    if not isinstance(layers, list) or not layers:
        _die("raw BuildKit layers differ")
    for layer in layers:
        if (
            not isinstance(layer, dict)
            or set(layer) - {"annotations", "digest", "mediaType", "size", "urls"}
            or DIGEST.fullmatch(str(layer.get("digest"))) is None
            or not isinstance(layer.get("size"), int)
            or isinstance(layer.get("size"), bool)
            or layer["size"] <= 0
            or layer.get("mediaType")
            not in {
                "application/vnd.oci.image.layer.v1.tar+gzip",
                "application/vnd.oci.image.layer.v1.tar+zstd",
            }
        ):
            _die("raw BuildKit layer descriptor differs")
    return value


def _fetch_buildkit_authority(
    runner: CommandRunner,
    toolchain: CapturedDockerToolchain,
    *,
    cwd: Path,
    policy: Mapping[str, Any],
    platform: str,
) -> dict[str, Any]:
    index_result = _docker_command(
        runner,
        toolchain,
        ("buildx", "imagetools", "inspect", "--raw", policy["image"]),
        cwd=cwd,
        context="raw BuildKit index inspection",
    )
    selected = _validate_buildkit_index(index_result.stdout, policy=policy, platform=platform)
    repository = policy["image"].split(":v", 1)[0]
    manifest_ref = repository + "@" + selected["digest"]
    manifest_result = _docker_command(
        runner,
        toolchain,
        ("buildx", "imagetools", "inspect", "--raw", manifest_ref),
        cwd=cwd,
        context="raw BuildKit platform manifest inspection",
    )
    _validate_buildkit_manifest(manifest_result.stdout, policy=policy, platform=platform)
    return {
        "index": index_result.record(),
        "manifest": manifest_result.record(),
        "selected_platform": {
            "architecture": PLATFORMS[platform],
            "config_digest": policy["platforms"][platform]["config_digest"],
            "config_size": policy["platforms"][platform]["config_size"],
            "manifest_digest": selected["digest"],
            "manifest_size": selected["size"],
            "os": "linux",
        },
    }


def _builder_projection(raw: bytes, *, builder: str, platform: str, version: str) -> dict[str, Any]:
    value = parse_json(raw, context="Buildx builder inspect")
    if not isinstance(value, dict):
        _die("Buildx builder inspect response differs")
    nodes = value.get("Nodes")
    if value.get("Name") != builder or value.get("Driver") != DOCKER_DRIVER:
        _die("Buildx builder identity/driver differs")
    if not isinstance(nodes, list) or len(nodes) != 1 or not isinstance(nodes[0], dict):
        _die("Buildx builder node count differs")
    node = nodes[0]
    platforms = node.get("Platforms")
    if platforms != [platform]:
        _die("Buildx builder native platform set differs")
    if (
        node.get("Name") != builder + "0"
        or node.get("Endpoint") != DOCKER_HOST
        or node.get("Status") != "running"
        or node.get("Buildkit") != version
    ):
        _die("Buildx builder node authority differs")
    return {
        "driver": value["Driver"],
        "name": value["Name"],
        "nodes": [
            {
                "buildkit": node["Buildkit"],
                "endpoint": node["Endpoint"],
                "name": node["Name"],
                "platforms": platforms,
                "status": node["Status"],
            }
        ],
    }


def _container_projection(
    raw: bytes,
    *,
    builder: str,
    image: str,
    config_digest: str,
    ownership_nonce: str,
) -> dict[str, Any]:
    value = parse_json(raw, context="BuildKit builder container inspect")
    if not isinstance(value, dict):
        _die("BuildKit builder container response differs")
    config = value.get("Config")
    host = value.get("HostConfig")
    mounts = value.get("Mounts")
    if not isinstance(config, dict) or not isinstance(host, dict) or not isinstance(mounts, list):
        _die("BuildKit builder container schema differs")
    labels = config.get("Labels")
    environment = config.get("Env")
    if not isinstance(labels, dict) or labels.get("com.docker.buildx.builder") != builder:
        _die("BuildKit builder container ownership label differs")
    if (
        HEX64.fullmatch(ownership_nonce) is None
        or not isinstance(environment, list)
        or not all(isinstance(item, str) for item in environment)
    ):
        _die("BuildKit builder ownership environment differs")
    ownership_values = [
        item.removeprefix("Z4J_AUTHORITY_NONCE=")
        for item in environment
        if item.startswith("Z4J_AUTHORITY_NONCE=")
    ]
    if ownership_values != [ownership_nonce]:
        _die("BuildKit builder ownership nonce differs")
    container_id = value.get("Id")
    if not isinstance(container_id, str) or HEX64.fullmatch(container_id) is None:
        _die("BuildKit builder container id differs")
    normalized_mounts: list[dict[str, str]] = []
    for mount in mounts:
        if not isinstance(mount, dict):
            _die("BuildKit builder mount differs")
        mount_type = mount.get("Type")
        destination = mount.get("Destination")
        if mount_type != "volume" or destination != "/var/lib/buildkit":
            _die("BuildKit builder has an unreviewed mount")
        normalized_mounts.append({"destination": destination, "type": mount_type})
    if normalized_mounts != [{"destination": "/var/lib/buildkit", "type": "volume"}]:
        _die("BuildKit builder volume set differs")
    projection = {
        "config_image": config.get("Image"),
        "id": container_id,
        "image": value.get("Image"),
        "label": labels["com.docker.buildx.builder"],
        "mounts": normalized_mounts,
        "name": value.get("Name"),
        "network_mode": host.get("NetworkMode"),
        "ownership_nonce": ownership_nonce,
        "privileged": host.get("Privileged"),
    }
    expected = {
        "config_image": image,
        "id": container_id,
        "image": config_digest,
        "label": builder,
        "mounts": [{"destination": "/var/lib/buildkit", "type": "volume"}],
        "name": "/buildx_buildkit_" + builder + "0",
        "network_mode": "bridge",
        "ownership_nonce": ownership_nonce,
        "privileged": True,
    }
    if projection != expected:
        _die("BuildKit builder container authority differs")
    return projection


def _image_projection(raw: bytes, *, platform: str, config_digest: str) -> dict[str, Any]:
    value = parse_json(raw, context="BuildKit local image inspect")
    if not isinstance(value, dict):
        _die("BuildKit local image response differs")
    projection = {
        "architecture": value.get("Architecture"),
        "id": value.get("Id"),
        "os": value.get("Os"),
    }
    expected = {
        "architecture": PLATFORMS[platform],
        "id": config_digest,
        "os": "linux",
    }
    if projection != expected:
        _die("BuildKit local image authority differs")
    return projection


def _config_from_image_archive(raw: bytes, *, config_digest: str, expected_size: int) -> bytes:
    target_hex = config_digest.removeprefix("sha256:")
    accepted_names = {target_hex + ".json", "blobs/sha256/" + target_hex}
    matches: list[bytes] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
            members = archive.getmembers()
            if len(members) > MAX_FILES:
                _die("BuildKit image archive has too many members")
            seen: set[str] = set()
            for member in members:
                logical = PurePosixPath(member.name)
                if (
                    member.name in seen
                    or logical.is_absolute()
                    or ".." in logical.parts
                    or "\\" in member.name
                    or member.size < 0
                    or member.size > MAX_FILE_BYTES
                ):
                    _die("BuildKit image archive member differs")
                seen.add(member.name)
                if member.name not in accepted_names:
                    continue
                if not member.isfile() or member.issym() or member.islnk():
                    _die("BuildKit raw config archive member is not regular")
                descriptor = archive.extractfile(member)
                if descriptor is None:
                    _die("BuildKit raw config archive member is unavailable")
                config_raw = descriptor.read(expected_size + 1)
                if len(config_raw) != expected_size:
                    _die("BuildKit raw config archive size differs")
                matches.append(config_raw)
    except tarfile.TarError as exc:
        raise MaterialBuildError("BuildKit image archive is malformed") from exc
    if len(matches) != 1:
        _die("BuildKit raw config archive selection is not unique")
    config_raw = matches[0]
    if "sha256:" + sha256(config_raw) != config_digest:
        _die("BuildKit raw config digest differs")
    return config_raw


def _inspect_builder_authority(
    runner: CommandRunner,
    toolchain: CapturedDockerToolchain,
    *,
    cwd: Path,
    builder: str,
    platform: str,
    buildkit: Mapping[str, Any],
    ownership_nonce: str,
    archive_path: Path,
) -> dict[str, Any]:
    inspect_result = _docker_command(
        runner,
        toolchain,
        ("buildx", "inspect", builder, "--bootstrap", "--format", "{{json .}}"),
        cwd=cwd,
        context="Buildx builder bootstrap/inspection",
        timeout_seconds=900,
    )
    projection = _builder_projection(
        inspect_result.stdout,
        builder=builder,
        platform=platform,
        version=buildkit["version"],
    )
    container_name = "buildx_buildkit_" + builder + "0"
    container_result = _docker_command(
        runner,
        toolchain,
        ("inspect", "--type", "container", "--format", "{{json .}}", container_name),
        cwd=cwd,
        context="BuildKit builder container inspection",
    )
    config_digest = buildkit["platforms"][platform]["config_digest"]
    container_projection = _container_projection(
        container_result.stdout,
        builder=builder,
        image=buildkit["image"],
        config_digest=config_digest,
        ownership_nonce=ownership_nonce,
    )
    image_result = _docker_command(
        runner,
        toolchain,
        ("image", "inspect", "--format", "{{json .}}", config_digest),
        cwd=cwd,
        context="BuildKit local image inspection",
    )
    image_projection = _image_projection(
        image_result.stdout, platform=platform, config_digest=config_digest
    )
    require_absent_direct(archive_path, context="BuildKit raw-config archive")
    save_result = _docker_command(
        runner,
        toolchain,
        ("image", "save", "--output", str(archive_path), config_digest),
        cwd=cwd,
        context="BuildKit raw image export",
        timeout_seconds=900,
    )
    archive_raw = read_regular(
        archive_path,
        maximum=MAX_IMAGE_ARCHIVE_BYTES,
        context="BuildKit raw image archive",
    )
    config_raw = _config_from_image_archive(
        archive_raw,
        config_digest=config_digest,
        expected_size=buildkit["platforms"][platform]["config_size"],
    )
    config_value = parse_json(config_raw, context="raw BuildKit image config")
    if (
        not isinstance(config_value, dict)
        or config_value.get("architecture") != PLATFORMS[platform]
        or config_value.get("os") != "linux"
    ):
        _die("raw BuildKit config platform differs")
    parent = _open_directory(archive_path.parent)
    try:
        observed = os.stat(archive_path.name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
            _die("BuildKit raw image archive identity differs")
        os.unlink(archive_path.name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)
    return {
        "builder": {
            "projection": projection,
            "response": inspect_result.record(),
        },
        "container": {
            "projection": container_projection,
            "response": container_result.record(),
        },
        "image": {
            "config": _raw_bytes_record(config_raw),
            "projection": image_projection,
            "response": image_result.record(),
            "save": {"archive": _raw_seal(archive_raw), "command": save_result.record()},
        },
    }


def buildx_argv(
    *,
    docker: Path,
    builder: str,
    platform: str,
    dockerfile: Path,
    context: Path,
    destination: Path,
    build_args: Mapping[str, str],
) -> tuple[str, ...]:
    """Construct the only accepted source-to-local-payload Buildx command."""

    if platform not in PLATFORMS or re.fullmatch(r"z4j-[a-z0-9-]{1,100}", builder) is None:
        _die("Buildx platform/builder identity differs")
    if not docker.is_absolute() or not dockerfile.is_absolute():
        _die("Docker/Buildx authority paths differ")
    if not context.is_absolute() or not destination.is_absolute():
        _die("Buildx context/output path differs")
    argv = [
        str(docker),
        "buildx",
        "build",
        "--builder",
        builder,
        "--no-cache",
        "--progress=plain",
        "--pull",
        "--platform",
        platform,
        "--file",
        str(dockerfile),
        "--target",
        "export",
        "--output",
        "type=local,dest=" + str(destination),
    ]
    for key in sorted(build_args):
        value = build_args[key]
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", key) is None or not value or "\0" in value:
            _die("Buildx argument is malformed")
        argv.extend(("--build-arg", f"{key}={value}"))
    argv.append(str(context))
    return tuple(argv)


def _run_buildx_captured(
    runner: CommandRunner,
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    executable_fd: int,
    timeout_seconds: int = 21_600,
) -> CommandResult:
    return require_success(
        runner.run(
            argv,
            cwd=cwd,
            env=environment,
            executable_fd=executable_fd,
            timeout_seconds=timeout_seconds,
        ),
        context="native Buildx material generator",
    )


def _builder_base_name(*, builder_prefix: str, platform: str, run_id: int, run_attempt: int) -> str:
    _positive_int(run_id, context="GitHub run id")
    _positive_int(run_attempt, context="GitHub run attempt")
    if re.fullmatch(r"z4j-production-(?:system|dashboard)", builder_prefix) is None:
        _die("material builder prefix differs")
    architecture = PLATFORMS.get(platform)
    if architecture is None:
        _die("material builder platform differs")
    name = f"{builder_prefix}-{architecture}-r{run_id}-a{run_attempt}"
    if len(name) > 110:
        _die("authority-bound builder name is too long")
    return name


def _builder_ownership_nonce(*, builder: str) -> str:
    """Return one unpredictable, domain-separated marker for an owned builder."""

    if re.fullmatch(r"z4j-production-(?:system|dashboard)-[a-z0-9-]{1,100}", builder) is None:
        _die("builder ownership nonce target differs")
    entropy = os.urandom(32)
    if len(entropy) != 32:  # pragma: no cover - the OS contract is exact
        _die("builder ownership entropy differs")
    return sha256(
        b"z4j-production-builder-ownership-v1\0" + builder.encode("ascii") + b"\0" + entropy
    )


def _create_private_subdirectory(parent: Path, name: str) -> Path:
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", name) is None:
        _die("private subdirectory name differs")
    directory = _open_directory(parent)
    try:
        os.mkdir(name, mode=0o700, dir_fd=directory)
        observed = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (
            not stat.S_ISDIR(observed.st_mode)
            or observed.st_uid != os.geteuid()
            or stat.S_IMODE(observed.st_mode) != 0o700
        ):
            _die("private subdirectory identity differs")
        os.fsync(directory)
    finally:
        os.close(directory)
    return parent / name


def _remove_builder(
    runner: CommandRunner,
    toolchain: CapturedDockerToolchain,
    *,
    cwd: Path,
    builder: str,
) -> CommandResult:
    return _docker_command(
        runner,
        toolchain,
        ("buildx", "rm", "--force", builder),
        cwd=cwd,
        context="ephemeral Buildx builder removal",
        timeout_seconds=900,
    )


def _require_automatic_builder_removal(
    *,
    builder: str,
    inspect_raw: bytes,
    owned_current: bool,
    active_error: BaseException | None,
) -> None:
    """Never remove an exact-name replacement after a failed/ambiguous operation."""

    if active_error is not None:
        raise MaterialBuildError(
            "failed native build left an exact-name builder for manual ownership review "
            f"({builder}, inspect {sha256(inspect_raw)})"
        ) from active_error
    if not owned_current:
        _die(
            "ambiguous exact-name builder requires manual cleanup "
            f"({builder}, inspect {sha256(inspect_raw)})"
        )


def _require_same_builder_authority_for_removal(
    *,
    builder: str,
    expected: Mapping[str, Any],
    observed: Mapping[str, Any],
) -> None:
    """Reject a same-name replacement before the destructive removal call."""

    for component, key in (
        ("builder", "projection"),
        ("container", "projection"),
        ("image", "projection"),
        ("image", "config"),
    ):
        expected_component = expected.get(component)
        observed_component = observed.get(component)
        if (
            not isinstance(expected_component, Mapping)
            or not isinstance(observed_component, Mapping)
            or expected_component.get(key) != observed_component.get(key)
        ):
            _die(
                "successful native build left an ambiguous exact-name builder for manual cleanup "
                f"({builder}, {component}.{key})"
            )


def run_native_build_pair(  # noqa: PLR0912, PLR0915
    runner: CommandRunner,
    *,
    docker_authority: Mapping[str, Any],
    execution_plane: Mapping[str, Any],
    build_operand_contract: Mapping[str, Any],
    builder_prefix: str,
    platform: str,
    run_id: int,
    run_attempt: int,
    dockerfile: Path,
    context: Path,
    output_root: Path,
    build_args: Mapping[str, str],
    cwd: Path,
) -> dict[str, Any]:
    """Run A/B in separate helper-owned builders and close every crash window."""

    if validate_execution_plane_policy(execution_plane, platforms=tuple(PLATFORMS)):
        _die("native Buildx execution plane is UNFINALIZED")
    material = builder_prefix.removeprefix("z4j-production-")
    logical_dockerfile, output_directories = _validate_native_build_operand_contract(
        build_operand_contract, material=material
    )
    recorded_context = _recorded_absolute_path(str(context), context="native build context root")
    recorded_dockerfile = _recorded_absolute_path(str(dockerfile), context="native Dockerfile")
    recorded_output = _recorded_absolute_path(str(output_root), context="native build output root")
    if (
        recorded_context.name != build_operand_contract["context_name"]
        or recorded_dockerfile != recorded_context.joinpath(*logical_dockerfile.parts)
        or recorded_context == recorded_output
        or recorded_context.is_relative_to(recorded_output)
        or recorded_output.is_relative_to(recorded_context)
    ):
        _die("native build operand relationship differs")
    dockerfile_raw = read_regular(
        recorded_dockerfile, maximum=MAX_CONTEXT_BYTES, context="native build Dockerfile"
    )
    expected_dockerfile = build_operand_contract["dockerfile"]
    if (
        sha256(dockerfile_raw) != expected_dockerfile["sha256"]
        or len(dockerfile_raw) != expected_dockerfile["size"]
    ):
        _die("native build Dockerfile differs from the operand contract")
    base_name = _builder_base_name(
        builder_prefix=builder_prefix,
        platform=platform,
        run_id=run_id,
        run_attempt=run_attempt,
    )
    prefix = builder_prefix + "-"
    builds: list[dict[str, Any]] = []
    builder_records: list[dict[str, Any]] = []
    with captured_docker_toolchain(
        runner,
        docker_authority=docker_authority,
        buildx_authority=execution_plane["buildx"]["platforms"][platform],
        cwd=cwd,
    ) as toolchain:
        operands = {
            "context_root": str(recorded_context),
            "dockerfile": str(recorded_dockerfile),
            "output_root": str(recorded_output),
            "toolchain_root": str(toolchain.root),
        }
        _validate_native_build_operands(
            operands, contract=build_operand_contract, material=material
        )
        initial_plane = _inspect_context_and_daemon(
            runner,
            toolchain,
            cwd=cwd,
            platform=platform,
            expected_daemon=execution_plane["daemon"][platform],
        )
        stale, initial_inventory = _builder_inventory(runner, toolchain, cwd=cwd, prefix=prefix)
        if stale:
            seal = sha256(canonical_json(initial_inventory, terminal_lf=False))
            _die(f"stale helper-owned builders require manual cleanup ({seal}): {', '.join(stale)}")
        buildkit_record = _fetch_buildkit_authority(
            runner,
            toolchain,
            cwd=cwd,
            policy=execution_plane["buildkit"],
            platform=platform,
        )
        for build_id in ("A", "B"):
            builder = base_name + "-" + build_id.casefold()
            ownership_nonce = _builder_ownership_nonce(builder=builder)
            destination = _create_private_subdirectory(output_root, output_directories[build_id])
            create_attempted = False
            owned_current = False
            validated_current = False
            removal_record: dict[str, Any] | None = None
            record: dict[str, Any] = {"build_id": build_id, "name": builder}
            active_error: BaseException | None = None
            expected_cleanup_authority: dict[str, Any] | None = None
            try:
                create_attempted = True
                create = _docker_command(
                    runner,
                    toolchain,
                    (
                        "buildx",
                        "create",
                        "--name",
                        builder,
                        "--driver",
                        DOCKER_DRIVER,
                        "--driver-opt",
                        "image=" + execution_plane["buildkit"]["image"],
                        "--driver-opt",
                        "env.Z4J_AUTHORITY_NONCE=" + ownership_nonce,
                        "--buildkitd-flags=--oci-worker-net=" + BUILDKIT_WORKER_NETWORK,
                        "--platform",
                        platform,
                        DOCKER_HOST,
                    ),
                    cwd=cwd,
                    context="ephemeral native Buildx builder creation",
                    timeout_seconds=900,
                )
                owned_current = True
                record["create"] = create.record()
                before = _inspect_builder_authority(
                    runner,
                    toolchain,
                    cwd=cwd,
                    builder=builder,
                    platform=platform,
                    buildkit=execution_plane["buildkit"],
                    ownership_nonce=ownership_nonce,
                    archive_path=toolchain.root / f"buildkit-{build_id.casefold()}.tar",
                )
                validated_current = True
                argv = buildx_argv(
                    docker=toolchain.docker,
                    builder=builder,
                    platform=platform,
                    dockerfile=dockerfile,
                    context=context,
                    destination=destination,
                    build_args={**build_args, "Z4J_BUILD_ID": build_id},
                )
                build = _run_buildx_captured(
                    runner,
                    argv,
                    cwd=cwd,
                    environment=toolchain.environment,
                    executable_fd=toolchain.docker_descriptor,
                )
                after = _inspect_builder_authority(
                    runner,
                    toolchain,
                    cwd=cwd,
                    builder=builder,
                    platform=platform,
                    buildkit=execution_plane["buildkit"],
                    ownership_nonce=ownership_nonce,
                    archive_path=toolchain.root / f"buildkit-{build_id.casefold()}-after.tar",
                )
                if before["builder"]["projection"] != after["builder"]["projection"]:
                    _die("Buildx builder projection changed during build")
                if before["container"]["projection"] != after["container"]["projection"]:
                    _die("BuildKit container projection changed during build")
                if before["image"]["config"] != after["image"]["config"]:
                    _die("BuildKit raw config changed during build")
                expected_cleanup_authority = after
                record.update({"after": after, "before": before, "build": build.record()})
                builds.append(build.record())
            except BaseException as exc:
                active_error = exc
                raise
            finally:
                if create_attempted:
                    if active_error is not None:
                        current = _docker_command(
                            runner,
                            toolchain,
                            ("buildx", "inspect", builder, "--format", "{{json .}}"),
                            cwd=cwd,
                            context="failed ephemeral builder cleanup inspection",
                            accept_failure=True,
                        )
                        if current.returncode == 0:
                            _require_automatic_builder_removal(
                                builder=builder,
                                inspect_raw=current.stdout,
                                owned_current=owned_current,
                                active_error=active_error,
                            )
                    else:
                        if (
                            not owned_current
                            or not validated_current
                            or expected_cleanup_authority is None
                        ):
                            _die("successful native build lost its builder ownership proof")
                        cleanup_authority = _inspect_builder_authority(
                            runner,
                            toolchain,
                            cwd=cwd,
                            builder=builder,
                            platform=platform,
                            buildkit=execution_plane["buildkit"],
                            ownership_nonce=ownership_nonce,
                            archive_path=toolchain.root
                            / f"buildkit-{build_id.casefold()}-cleanup.tar",
                        )
                        _require_same_builder_authority_for_removal(
                            builder=builder,
                            expected=expected_cleanup_authority,
                            observed=cleanup_authority,
                        )
                        removed = _remove_builder(runner, toolchain, cwd=cwd, builder=builder)
                        removal_record = removed.record()
                record["remove"] = removal_record
            builder_records.append(record)
            remaining, inventory = _builder_inventory(runner, toolchain, cwd=cwd, prefix=prefix)
            record["inventory_after"] = inventory
            if remaining:
                _die("helper-owned builder remains after removal: " + ", ".join(remaining))
        final_plane = _inspect_context_and_daemon(
            runner,
            toolchain,
            cwd=cwd,
            platform=platform,
            expected_daemon=execution_plane["daemon"][platform],
        )
        if initial_plane["context"]["projection"] != final_plane["context"]["projection"]:
            _die("Docker context changed during A/B builds")
        if initial_plane["daemon"]["projection"] != final_plane["daemon"]["projection"]:
            _die("Docker daemon changed during A/B builds")
        final_stale, final_inventory = _builder_inventory(runner, toolchain, cwd=cwd, prefix=prefix)
        if final_stale:
            _die("helper-owned builders remain at final readback")
        return {
            "builder_inventory": {"after": final_inventory, "before": initial_inventory},
            "builders": builder_records,
            "buildkit": buildkit_record,
            "builds": builds,
            "execution_plane": {"after": final_plane, "before": initial_plane},
            "format": "z4j-production-native-build-execution-v2",
            "operands": operands,
            "run": {"attempt": run_attempt, "id": run_id},
            "toolchain": toolchain.records,
        }


def exact_tool_probe(
    runner: CommandRunner,
    *,
    executable: Path,
    arguments: Sequence[str],
    expected_sha256: str,
    expected_size: int,
    expected_output_sha256: str,
    cwd: Path,
) -> CommandResult:
    """Verify and execute a private captured copy of one policy-sealed tool."""

    root = Path(tempfile.mkdtemp(prefix="z4j-production-tool."))
    root.chmod(0o700)
    observed = root.stat(follow_symlinks=False)
    identity = (observed.st_dev, observed.st_ino)
    captured = root / "tool"
    descriptor: int | None = None
    try:
        _copy_sealed_executable(
            executable,
            captured,
            expected_sha256=expected_sha256,
            expected_size=expected_size,
            context="builder executable",
        )
        descriptor = os.open(
            captured,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        result = require_success(
            runner.run(
                [str(captured), *arguments],
                cwd=cwd,
                env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"},
                executable_fd=descriptor,
                timeout_seconds=60,
            ),
            context="captured builder executable version probe",
        )
        if sha256(result.stdout + result.stderr) != expected_output_sha256:
            _die("builder executable version transcript differs")
        raw = read_regular(captured, maximum=MAX_FILE_BYTES, context="captured builder executable")
        if sha256(raw) != expected_sha256 or len(raw) != expected_size:
            _die("captured builder executable changed during probe")
        return result
    finally:
        if descriptor is not None:
            os.close(descriptor)
        _remove_private_tree(root, expected_identity=identity)
