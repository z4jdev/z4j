#!/usr/bin/env python3
"""Architecture-neutral production wheelhouse mechanics.

This module deliberately contains no repository, workflow, credential, signer,
publisher, E0/T_E, readiness, or live-network authority.  It operates only on
caller-supplied bytes and paths.  The tracked production manifest remains
UNFINALIZED, and no function here can realize or infer a production identity.
"""

from __future__ import annotations

import base64
import contextlib
import csv
import datetime as dt
import email.parser
import hashlib
import io
import json
import os
import re
import stat
import struct
import tarfile
import tomllib
import urllib.parse
import zipfile
import zlib
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

RELEASE = "1.9.0"
CUTOFF = "2026-08-23T04:14:39.107Z"
PLATFORMS = ("linux/amd64", "linux/arm64")
ARCHITECTURES = {"linux/amd64": "amd64", "linux/arm64": "arm64"}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
ASCII_TEXT = re.compile(r"[\x21-\x7e]+\Z")
OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip"
AM_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
MAX_MANIFEST_BYTES = 1024 * 1024

MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_INDEX_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_LOCK_BYTES = 64 * 1024 * 1024
MAX_EXPORT_BYTES = 8 * 1024 * 1024
MAX_EXPORT_RECORDS = 20_000
MAX_SUPPORTED_TAGS = 8_192
MAX_PLATFORM_CARRIER_BYTES = 2 * 1024 * 1024 * 1024
PLATFORM_CARRIER_MODES = frozenset(
    {
        0o400,
        0o440,
        0o444,
        0o500,
        0o540,
        0o544,
        0o550,
        0o555,
        0o600,
        0o640,
        0o644,
        0o700,
        0o740,
        0o744,
        0o750,
        0o755,
    }
)

UV_EXPORT_COMMON_ARGUMENTS = (
    "--format",
    "requirements.txt",
    "--locked",
    "--offline",
    "--no-python-downloads",
    "--no-default-groups",
    "--no-emit-workspace",
    "--no-config",
    "--no-cache",
    "--no-header",
    "--no-annotate",
)
UV_EXPORT_ROLES: dict[str, tuple[str, ...]] = {
    "z4j-core": ("--package", "z4j-core"),
    "z4j": ("--package", "z4j", "--extra", "postgres", "--extra", "scheduler-grpc"),
    "z4j-scheduler": ("--package", "z4j-scheduler"),
    "production-wheel-build": ("--only-group", "production-wheel-build"),
}
UV_EXPORT_ROLE_EXTRAS: dict[str, tuple[str, ...]] = {
    "z4j-core": (),
    "z4j": ("postgres", "scheduler-grpc"),
    "z4j-scheduler": (),
    "production-wheel-build": (),
}
UV_EXPORT_ROLE_FILENAMES: dict[str, str] = {
    role: f"{role}.requirements.txt" for role in UV_EXPORT_ROLES
}
BUILD_CLOSURE_VERSIONS = {
    "hatchling": "1.32.0",
    "packaging": "26.3",
    "pathspec": "1.1.1",
    "pluggy": "1.6.0",
    "tomlkit": "0.15.1",
    "trove-classifiers": "2026.6.1.19",
}
LOCAL_WHEEL_DISTRIBUTIONS = ("z4j", "z4j-core", "z4j-scheduler")
MARKER_ENVIRONMENT_KEYS = {
    "implementation_name",
    "implementation_version",
    "os_name",
    "platform_machine",
    "platform_python_implementation",
    "platform_system",
    "python_full_version",
    "python_version",
    "sys_platform",
}
STERILE_ENVIRONMENT_KEYS = {
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONHASHSEED",
    "PYTHONNOUSERSITE",
    "SOURCE_DATE_EPOCH",
    "TMPDIR",
    "TZ",
}


class WheelhouseMechanicsError(RuntimeError):
    """Neutral wheelhouse input or output violates the closed byte contract."""


# Backward-neutral alias used only by the reviewed mechanics below.
AuthorityError = WheelhouseMechanicsError


def _die(message: str) -> NoReturn:
    raise WheelhouseMechanicsError(message)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _die(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def _reject_number(value: str) -> NoReturn:
    _die(f"non-integer JSON number {value!r} is forbidden")


def _read_regular(path: Path, *, maximum: int, context: str) -> bytes:
    if maximum < 0:
        _die(f"{context} has an invalid size bound")
    try:
        named = path.lstat()
    except OSError as exc:
        raise WheelhouseMechanicsError(f"{context} is unavailable: {exc}") from exc
    if path.is_symlink() or not stat.S_ISREG(named.st_mode) or named.st_size > maximum:
        _die(f"{context} is not one bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        before = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        if (
            (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_size > maximum
        ):
            _die(f"{context} changed while opening")
        chunks: list[bytes] = []
        offset = 0
        while offset < opened.st_size:
            chunk = os.pread(descriptor, min(1024 * 1024, opened.st_size - offset), offset)
            if not chunk:
                _die(f"{context} ended during bounded read")
            chunks.append(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != before:
            _die(f"{context} changed during bounded read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _parse_json(raw: bytes, *, context: str) -> Any:
    if raw.startswith(b"\xef\xbb\xbf"):
        _die(f"{context} has a forbidden UTF-8 BOM")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise WheelhouseMechanicsError(f"{context} is not strict UTF-8: {exc}") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except json.JSONDecodeError as exc:
        raise WheelhouseMechanicsError(f"{context} is not one JSON value: {exc}") from exc


def canonical_json(value: Any, *, terminal_lf: bool) -> bytes:
    try:
        raw = json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise WheelhouseMechanicsError(f"value cannot be canonicalized: {exc}") from exc
    return raw + (b"\n" if terminal_lf else b"")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(raw: bytes) -> str:
    return "sha256:" + _sha256(raw)


def _exact_keys(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _die(f"{context} must be one JSON object")
    actual = set(value)
    if actual != expected:
        _die(
            f"{context} keys differ; missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    return value


def _list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        _die(f"{context} must be one JSON array")
    return value


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or ASCII_TEXT.fullmatch(value) is None:
        _die(f"{context} must be a nonempty printable ASCII string")
    return value


def _positive_int(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        _die(f"{context} must be a positive JSON integer")
    return value


def _nonnegative_int(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _die(f"{context} must be a nonnegative JSON integer")
    return value


def _hex(value: Any, context: str) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        _die(f"{context} must be 64 lowercase SHA-256 hex digits")
    return value


def _pypi_timestamp(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z",
            value,
        )
        is None
    ):
        _die(f"{context} must be an exact RFC3339 UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise WheelhouseMechanicsError(f"{context} is not a real UTC timestamp") from exc
    if parsed.utcoffset() != dt.timedelta(0):
        _die(f"{context} is not UTC")
    return value


def _descriptor(value: Any, context: str, *, media_type: str) -> dict[str, Any]:
    descriptor = _exact_keys(value, {"digest", "mediaType", "size"}, context)
    digest_value = descriptor["digest"]
    if not isinstance(digest_value, str) or OCI_DIGEST.fullmatch(digest_value) is None:
        _die(f"{context}.digest is not a lowercase sha256 OCI digest")
    if descriptor["mediaType"] != media_type:
        _die(f"{context}.mediaType differs")
    _positive_int(descriptor["size"], f"{context}.size")
    return descriptor


def validate_leaf_bytes(raw: bytes, *, platform: str) -> dict[str, Any]:
    if platform not in PLATFORMS or len(raw) > MAX_MANIFEST_BYTES:
        _die("wheelhouse leaf platform or size differs")
    value = _parse_json(raw, context=f"{platform} leaf manifest")
    if canonical_json(value, terminal_lf=False) != raw:
        _die(f"{platform} leaf manifest is not literal canonical no-LF JSON")
    leaf = _exact_keys(
        value,
        {"config", "layers", "mediaType", "schemaVersion"},
        f"{platform} leaf",
    )
    if leaf["mediaType"] != AM_MEDIA_TYPE or leaf["schemaVersion"] != 2:
        _die(f"{platform} leaf media/schema differs")
    _descriptor(leaf["config"], f"{platform} leaf config", media_type=OCI_CONFIG_MEDIA_TYPE)
    layers = _list(leaf["layers"], f"{platform} leaf layers")
    if len(layers) != 1:
        _die(f"{platform} leaf must contain exactly one distributable gzip layer")
    _descriptor(layers[0], f"{platform} leaf layer", media_type=OCI_LAYER_MEDIA_TYPE)
    return leaf


def _atomic_write_new(path: Path, raw: bytes, *, mode: int = 0o600) -> None:
    if path.exists() or path.is_symlink():
        _die(f"refusing to overwrite existing output {path}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)
        raise


def _normalized_distribution(value: Any, context: str) -> str:
    name = _string(value, context)
    normalized = re.sub(r"[-_.]+", "-", name).lower()
    if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", normalized) is None:
        _die(f"{context} is not one normalized Python distribution name")
    return normalized


def uv_export_argv(
    *,
    uv: Path,
    python: Path,
    output: Path,
    role: str,
) -> list[str]:
    """Return one of the four exact locked/offline universal export commands."""

    if role not in UV_EXPORT_ROLES:
        _die("uv export role differs from the exact four-role contract")
    for path, context in ((uv, "uv"), (python, "CPython"), (output, "role output")):
        if not path.is_absolute() or any(
            character in str(path) for character in ("\n", "\r", "\0")
        ):
            _die(f"{context} path must be absolute and single-line")
    return [
        str(uv),
        "export",
        *UV_EXPORT_ROLES[role],
        *UV_EXPORT_COMMON_ARGUMENTS,
        "--python",
        str(python),
        "--output-file",
        str(output),
    ]


def sterile_uv_environment(
    *,
    path: str,
    home: Path,
    temporary: Path,
    source_date_epoch: int,
) -> dict[str, str]:
    """Construct, rather than filter, the complete env-i export/build environment."""

    for value, context in ((home, "HOME"), (temporary, "TMPDIR")):
        if not value.is_absolute() or any(
            character in str(value) for character in ("\n", "\r", "\0")
        ):
            _die(f"sterile {context} must be one absolute single-line path")
    if (
        not path.startswith("/")
        or any(not item.startswith("/") for item in path.split(":"))
        or any(character in path for character in ("\n", "\r", "\0"))
    ):
        _die("sterile PATH must contain absolute single-line entries only")
    if not 1_600_000_000 <= source_date_epoch <= 2_000_000_000:
        _die("sterile SOURCE_DATE_EPOCH is outside the reviewed range")
    environment = {
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": path,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "SOURCE_DATE_EPOCH": str(source_date_epoch),
        "TMPDIR": str(temporary),
        "TZ": "UTC",
    }
    if set(environment) != STERILE_ENVIRONMENT_KEYS:
        _die("sterile export environment implementation drifted")
    return environment


def parse_uv_export(  # noqa: PLR0912,PLR0915 - closed requirements grammar
    raw: bytes, *, role: str
) -> list[dict[str, Any]]:
    """Parse one hash-bearing uv requirements export without accepting source directives."""

    if role not in UV_EXPORT_ROLES:
        _die("uv export role differs")
    if not raw or len(raw) > MAX_EXPORT_BYTES or not raw.endswith(b"\n") or b"\r" in raw:
        _die(f"{role} export must be bounded UTF-8 with exactly one terminal LF convention")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuthorityError(f"{role} export is not UTF-8") from exc
    logical: list[str] = []
    current = ""
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            _die(f"{role} export retains a forbidden header/annotation on line {line_number}")
        continuation = stripped.endswith("\\")
        piece = stripped[:-1].strip() if continuation else stripped
        current = (current + " " + piece).strip()
        if not continuation:
            logical.append(current)
            current = ""
        if len(logical) > MAX_EXPORT_RECORDS:
            _die(f"{role} export exceeds its record bound")
    if current:
        _die(f"{role} export ends with an incomplete continuation")
    if not logical:
        _die(f"{role} export is empty")

    forbidden = (
        " --index-url",
        " --extra-index-url",
        " --find-links",
        " --trusted-host",
        " @ ",
        "://",
        "-e ",
        "--editable",
        "--no-hashes",
    )
    records: list[dict[str, Any]] = []
    for line_number, requirement in enumerate(logical, 1):
        if any(token in requirement for token in forbidden):
            _die(f"{role} export line {line_number} contains a mutable or local source")
        pieces = re.split(r"\s+--hash=sha256:", requirement)
        if len(pieces) < 2 or any(HEX64.fullmatch(piece) is None for piece in pieces[1:]):
            _die(f"{role} export line {line_number} lacks only exact SHA-256 hashes")
        head = pieces[0].strip()
        match = re.fullmatch(
            r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9_.+!-]*)"
            r"(?:\s*;\s*(.+))?",
            head,
        )
        if match is None:
            _die(f"{role} export line {line_number} is not one exact pinned requirement")
        name = _normalized_distribution(match.group(1), f"{role} export distribution")
        if name in LOCAL_WHEEL_DISTRIBUTIONS:
            _die(f"{role} export illegally emitted local workspace package {name}")
        marker = match.group(3)
        if marker is not None:
            marker = marker.strip()
            if not marker or len(marker.encode("utf-8")) > 4096:
                _die(f"{role} export marker is empty or oversized")
        hashes = sorted(set(pieces[1:]))
        if hashes != pieces[1:]:
            _die(f"{role} export hashes are duplicate or not byte-sorted")
        records.append(
            {
                "hashes": hashes,
                "marker": marker,
                "name": name,
                "version": match.group(2),
            }
        )
    order = [
        (record["name"].encode("utf-8"), (record["marker"] or "").encode("utf-8"))
        for record in records
    ]
    if order != sorted(set(order)):
        _die(f"{role} export requirements are duplicate or not strictly byte-sorted")
    return records


_MARKER_TOKEN = re.compile(
    r"\s*(?:"
    r"(?P<lparen>\()|(?P<rparen>\))|"
    r"(?P<operator>===|==|!=|~=|<=|>=|<|>|not\s+in\b|in\b)|"
    r"(?P<and>and\b)|(?P<or>or\b)|"
    r"(?P<string>'[^'\\\r\n]*'|\"[^\"\\\r\n]*\")|"
    r"(?P<identifier>[A-Za-z_][A-Za-z0-9_]*)"
    r")"
)


class _MarkerParser:
    def __init__(self, expression: str, environment: Mapping[str, str]) -> None:
        self._environment = environment
        self._tokens: list[tuple[str, str]] = []
        offset = 0
        while offset < len(expression):
            match = _MARKER_TOKEN.match(expression, offset)
            if match is None:
                _die("export marker contains unsupported or ambiguous syntax")
            kind = str(match.lastgroup)
            self._tokens.append((kind, match.group(kind)))
            offset = match.end()
        if not self._tokens:
            _die("export marker is empty")
        self._offset = 0

    def parse(self) -> bool:
        result = self._or_expression()
        if self._offset != len(self._tokens):
            _die("export marker has trailing tokens")
        return result

    def _peek(self, kind: str) -> bool:
        return self._offset < len(self._tokens) and self._tokens[self._offset][0] == kind

    def _take(self, kind: str) -> str:
        if not self._peek(kind):
            _die(f"export marker expected {kind}")
        value = self._tokens[self._offset][1]
        self._offset += 1
        return value

    def _or_expression(self) -> bool:
        value = self._and_expression()
        while self._peek("or"):
            self._take("or")
            right = self._and_expression()
            value = value or right
        return value

    def _and_expression(self) -> bool:
        value = self._atom()
        while self._peek("and"):
            self._take("and")
            right = self._atom()
            value = value and right
        return value

    def _atom(self) -> bool:
        if self._peek("lparen"):
            self._take("lparen")
            value = self._or_expression()
            self._take("rparen")
            return value
        left, left_variable = self._operand()
        operator = " ".join(self._take("operator").split())
        right, right_variable = self._operand()
        if left_variable is None and right_variable is None:
            _die("export marker comparison has no sealed environment variable")
        version_comparison = any(
            item in {"implementation_version", "python_full_version", "python_version"}
            for item in (left_variable, right_variable)
        )
        return _compare_marker_values(left, operator, right, version=version_comparison)

    def _operand(self) -> tuple[str, str | None]:
        if self._peek("string"):
            value = self._take("string")
            return value[1:-1], None
        name = self._take("identifier")
        if name not in self._environment:
            _die(f"export marker uses unsealed environment variable {name!r}")
        return self._environment[name], name


def _version_key(value: str) -> tuple[int, ...]:
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value) is None:
        _die(f"marker version {value!r} is outside the reviewed numeric form")
    return tuple(int(item) for item in value.split("."))


def _compare_marker_values(left: str, operator: str, right: str, *, version: bool) -> bool:
    if operator in {"in", "not in"}:
        result = left in right
        return not result if operator == "not in" else result
    if operator == "==" and right.endswith(".*") and version:
        return left == right[:-2] or left.startswith(right[:-1])
    if operator == "!=" and right.endswith(".*") and version:
        return not _compare_marker_values(left, "==", right, version=True)
    if operator == "~=":
        if not version:
            _die("compatible-release marker operator requires a sealed version variable")
        left_key = _version_key(left)
        right_key = _version_key(right)
        prefix = right_key[:-1] if len(right_key) > 1 else right_key
        return left_key >= right_key and left_key[: len(prefix)] == prefix
    if version:
        left_key = _version_key(left)
        right_key = _version_key(right)
        width = max(len(left_key), len(right_key))
        left_value: Any = left_key + (0,) * (width - len(left_key))
        right_value: Any = right_key + (0,) * (width - len(right_key))
    else:
        left_value = left
        right_value = right
    comparisons = {
        "<": left_value < right_value,
        "<=": left_value <= right_value,
        "==": left_value == right_value,
        "===": left == right,
        "!=": left_value != right_value,
        ">=": left_value >= right_value,
        ">": left_value > right_value,
    }
    if operator not in comparisons:
        _die(f"export marker operator {operator!r} is unsupported")
    return bool(comparisons[operator])


def evaluate_marker(
    expression: str | None,
    *,
    environment: Mapping[str, str],
    extras: Sequence[str] = (),
) -> bool:
    """Evaluate the reviewed PEP 508 subset only from the sealed native environment."""

    if set(environment) != MARKER_ENVIRONMENT_KEYS:
        _die("native marker environment key set differs")
    values = tuple(extras) or ("",)
    if tuple(sorted(set(values), key=lambda item: item.encode("utf-8"))) != values:
        _die("selected extras are duplicate or not strictly byte-sorted")
    if expression is None:
        return True
    for extra in values:
        if _MarkerParser(expression, {**environment, "extra": extra}).parse():
            return True
    return False


def validate_native_python_carrier(  # noqa: PLR0912,PLR0915 - closed native runtime profile
    value: Any, *, platform: str
) -> dict[str, Any]:
    """Validate the mode-neutral facts captured by packaging 26.3 in one native image."""

    if platform not in PLATFORMS:
        _die("native Python carrier platform differs")
    carrier = _exact_keys(
        value,
        {
            "architecture",
            "cache_tag",
            "ext_suffix",
            "format",
            "gil_disabled",
            "glibc",
            "marker_environment",
            "packaging",
            "platform",
            "python",
            "soabi",
            "supported_tags",
        },
        "native Python carrier",
    )
    expected_machine = {"linux/amd64": "x86_64", "linux/arm64": "aarch64"}[platform]
    expected_architecture = ARCHITECTURES[platform]
    expected_soabi = f"cpython-314-{expected_machine}-linux-gnu"
    if (
        carrier["format"] != "z4j-production-wheelhouse-native-python-v1"
        or carrier["platform"] != platform
        or carrier["architecture"] != expected_architecture
        or carrier["cache_tag"] != "cpython-314"
        or carrier["gil_disabled"] is not False
        or carrier["soabi"] != expected_soabi
        or carrier["ext_suffix"] != f".{expected_soabi}.so"
    ):
        _die("native Python ABI/GIL/platform identity differs")
    python = _exact_keys(carrier["python"], {"implementation", "version"}, "native Python identity")
    if python != {"implementation": "CPython", "version": "3.14.7"}:
        _die("native Python identity differs")
    glibc = _exact_keys(carrier["glibc"], {"name", "version"}, "native glibc")
    glibc_match = re.fullmatch(r"([0-9]+)\.([0-9]+)", str(glibc["version"]))
    if glibc["name"] != "glibc" or glibc_match is None:
        _die("native glibc identity differs")
    glibc_version = (int(glibc_match.group(1)), int(glibc_match.group(2)))
    packaging = _exact_keys(carrier["packaging"], {"sha256", "size", "version"}, "native packaging")
    if packaging["version"] != "26.3":
        _die("native tag evaluator is not packaging 26.3")
    _hex(packaging["sha256"], "native packaging sha256")
    _positive_int(packaging["size"], "native packaging size")
    marker = _exact_keys(
        carrier["marker_environment"], MARKER_ENVIRONMENT_KEYS, "native marker environment"
    )
    expected_marker = {
        "implementation_name": "cpython",
        "implementation_version": "3.14.7",
        "os_name": "posix",
        "platform_machine": expected_machine,
        "platform_python_implementation": "CPython",
        "platform_system": "Linux",
        "python_full_version": "3.14.7",
        "python_version": "3.14",
        "sys_platform": "linux",
    }
    if marker != expected_marker:
        _die("native marker environment differs from exact CPython 3.14.7/Linux")
    tags = _list(carrier["supported_tags"], "native supported tags")
    if not tags or len(tags) > MAX_SUPPORTED_TAGS:
        _die("native supported tag list is empty or oversized")
    normalized_tags: list[str] = []
    for index, tag in enumerate(tags):
        text = _string(tag, f"native supported tag {index}")
        if re.fullmatch(r"[a-z0-9]+-[a-z0-9]+-[a-z0-9_.]+", text) is None:
            _die("native supported tag has an unsupported form")
        normalized_tags.append(text)
    if len(set(normalized_tags)) != len(normalized_tags):
        _die("native supported tag list contains duplicates")
    expected_platform_suffix = "_x86_64" if platform == "linux/amd64" else "_aarch64"
    for tag in normalized_tags:
        platform_tag = tag.rsplit("-", 1)[-1]
        if platform_tag == "any":
            continue
        if not platform_tag.endswith(expected_platform_suffix):
            _die("native supported tag list crosses the sealed architecture")
        base = platform_tag.removesuffix(expected_platform_suffix)
        floor: tuple[int, int] | None
        if base == "linux":
            floor = None
        elif base == "manylinux1":
            floor = (2, 5)
        elif base == "manylinux2010":
            floor = (2, 12)
        elif base == "manylinux2014":
            floor = (2, 17)
        else:
            manylinux = re.fullmatch(r"manylinux_([0-9]+)_([0-9]+)", base)
            if manylinux is None:
                _die("native supported tag uses an unreviewed Linux platform family")
            floor = (int(manylinux.group(1)), int(manylinux.group(2)))
        if floor is not None and floor > glibc_version:
            _die("native supported tag claims a glibc floor newer than the sealed runtime")
    if not any(tag.startswith("cp314-cp314-") for tag in normalized_tags):
        _die("native supported tags omit the exact CPython 3.14 ABI")
    if any(tag.startswith("cp314t-") or "-cp314t-" in tag for tag in normalized_tags):
        _die("GIL-enabled native carrier unexpectedly contains free-threaded tags")
    return carrier


def _lock_packages(  # noqa: PLR0912 - closed uv.lock source/artifact grammar
    raw: bytes,
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    if not raw or len(raw) > MAX_LOCK_BYTES or b"\0" in raw:
        _die("uv.lock is empty or exceeds its byte bound")
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise AuthorityError("uv.lock is not one valid UTF-8 TOML document") from exc
    if not isinstance(value, dict) or value.get("version") != 1 or value.get("revision") != 3:
        _die("uv.lock format/revision differs")
    packages = value.get("package")
    if not isinstance(packages, list) or not packages or len(packages) > MAX_EXPORT_RECORDS:
        _die("uv.lock package inventory is absent or oversized")
    by_name: dict[str, list[dict[str, Any]]] = {}
    for index, raw_package in enumerate(packages):
        if not isinstance(raw_package, dict):
            _die(f"uv.lock package {index} is not an object")
        name = _normalized_distribution(raw_package.get("name"), f"uv.lock package {index} name")
        version = raw_package.get("version")
        if not isinstance(version, str) or not version:
            _die(f"uv.lock package {name} version is absent")
        source = raw_package.get("source")
        if not isinstance(source, dict) or len(source) != 1:
            _die(f"uv.lock package {name} source shape differs")
        if source == {"registry": "https://pypi.org/simple"}:
            wheels = raw_package.get("wheels")
            if wheels is not None and not isinstance(wheels, list):
                _die(f"uv.lock package {name} wheel inventory is malformed")
        elif source == {"editable": f"packages/{name}"}:
            # A monorepo lock necessarily carries every workspace member.  The
            # role walk below is what forbids reaching any member outside the
            # exact three local-wheel roots.
            pass
        elif source == {"virtual": "."} and name == "z4j-workspace":
            pass
        else:
            _die(f"uv.lock package {name} uses an unreviewed non-PyPI/local source")
        package = dict(raw_package)
        package["name"] = name
        by_name.setdefault(name, []).append(package)
    return value, by_name


def _lock_marker_active(
    value: Any,
    *,
    environment: Mapping[str, str],
    extras: Sequence[str] = (),
) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return evaluate_marker(value, environment=environment, extras=extras)
    if isinstance(value, list) and value and all(isinstance(item, str) for item in value):
        return any(evaluate_marker(item, environment=environment, extras=extras) for item in value)
    _die("uv.lock resolution marker shape differs")


def _select_lock_package(
    by_name: Mapping[str, list[dict[str, Any]]],
    dependency: Mapping[str, Any],
    *,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    name = _normalized_distribution(dependency.get("name"), "uv.lock dependency name")
    candidates = list(by_name.get(name, []))
    version = dependency.get("version")
    if version is not None:
        if not isinstance(version, str) or not version:
            _die(f"uv.lock dependency {name} version selector is malformed")
        candidates = [candidate for candidate in candidates if candidate["version"] == version]
    candidates = [
        candidate
        for candidate in candidates
        if _lock_marker_active(
            candidate.get("resolution-markers"),
            environment=environment,
        )
    ]
    if len(candidates) != 1:
        _die(f"uv.lock dependency {name} does not select exactly one native package record")
    return candidates[0]


def _dependency_records(value: Any, context: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        _die(f"{context} dependency inventory is malformed")
    return [dict(item) for item in value]


def _reachable_role_packages(  # noqa: PLR0912,PLR0915 - bounded dependency graph
    by_name: Mapping[str, list[dict[str, Any]]],
    *,
    role: str,
    environment: Mapping[str, str],
) -> set[str]:
    if role == "production-wheel-build":
        roots = by_name.get("z4j-workspace", [])
        if len(roots) != 1:
            _die("uv.lock virtual workspace root is absent or ambiguous")
        groups = roots[0].get("dev-dependencies")
        if not isinstance(groups, dict) or set(groups) - {
            "dev",
            "production-wheel-build",
        }:
            _die("uv.lock dependency-group inventory differs")
        initial = _dependency_records(
            groups.get("production-wheel-build"), "production-wheel-build"
        )
        if not initial:
            _die("uv.lock lacks the explicit production-wheel-build group")
        queue: list[tuple[dict[str, Any], tuple[str, ...]]] = [
            (dependency, ()) for dependency in initial
        ]
    else:
        roots = by_name.get(role, [])
        if len(roots) != 1:
            _die(f"uv.lock role root {role} is absent or ambiguous")
        root = roots[0]
        extras = UV_EXPORT_ROLE_EXTRAS[role]
        initial = _dependency_records(root.get("dependencies"), f"uv.lock {role}")
        optional = root.get("optional-dependencies", {})
        if not isinstance(optional, dict):
            _die(f"uv.lock {role} optional-dependencies shape differs")
        for extra in extras:
            initial.extend(_dependency_records(optional.get(extra), f"uv.lock {role}[{extra}]"))
        queue = [(dependency, ()) for dependency in initial]

    external: set[str] = set()
    visited: set[tuple[str, str, tuple[str, ...]]] = set()
    while queue:
        dependency, parent_extras = queue.pop(0)
        marker = dependency.get("marker")
        if marker is not None and (
            not isinstance(marker, str)
            or not evaluate_marker(marker, environment=environment, extras=parent_extras)
        ):
            continue
        package = _select_lock_package(by_name, dependency, environment=environment)
        requested = dependency.get("extra", dependency.get("extras", []))
        if requested is None:
            requested = []
        if not isinstance(requested, list) or any(not isinstance(item, str) for item in requested):
            _die(f"uv.lock dependency {package['name']} extras shape differs")
        selected_extras = tuple(sorted(set(requested), key=lambda item: item.encode("utf-8")))
        identity = (str(package["name"]), str(package["version"]), selected_extras)
        if identity in visited:
            continue
        visited.add(identity)
        source = package["source"]
        if source == {"registry": "https://pypi.org/simple"}:
            external.add(str(package["name"]))
        elif package["name"] not in LOCAL_WHEEL_DISTRIBUTIONS:
            _die(f"role {role} reaches unrelated workspace package {package['name']}")
        children = _dependency_records(
            package.get("dependencies"), f"uv.lock package {package['name']}"
        )
        optional = package.get("optional-dependencies", {})
        if not isinstance(optional, dict):
            _die(f"uv.lock package {package['name']} optional dependencies differ")
        for extra in selected_extras:
            children.extend(
                _dependency_records(
                    optional.get(extra), f"uv.lock package {package['name']}[{extra}]"
                )
            )
        queue.extend((child, selected_extras) for child in children)
        if len(visited) > MAX_EXPORT_RECORDS or len(queue) > MAX_EXPORT_RECORDS:
            _die("uv.lock role dependency graph exceeds its bound")
    return external


def _lock_artifact_hashes(package: Mapping[str, Any]) -> set[str]:
    hashes: set[str] = set()
    for raw_artifact in [*list(package.get("wheels") or []), package.get("sdist")]:
        if raw_artifact is None:
            continue
        if not isinstance(raw_artifact, dict):
            _die(f"uv.lock package {package['name']} artifact shape differs")
        digest_value = raw_artifact.get("hash")
        if not isinstance(digest_value, str) or not digest_value.startswith("sha256:"):
            _die(f"uv.lock package {package['name']} artifact lacks SHA-256")
        digest_hex = digest_value.removeprefix("sha256:")
        _hex(digest_hex, f"uv.lock package {package['name']} artifact")
        hashes.add(digest_hex)
    return hashes


def resolve_native_exports(  # noqa: PLR0912 - four-role cross-equality gate
    *,
    lock_raw: bytes,
    exports: Mapping[str, bytes],
    native_carrier: Any,
    platform: str,
) -> dict[str, Any]:
    """Filter four universal exports and prove each exact role against final uv.lock."""

    native = validate_native_python_carrier(native_carrier, platform=platform)
    environment = native["marker_environment"]
    if set(exports) != set(UV_EXPORT_ROLES):
        _die("universal export set differs from the exact four roles")
    _lock, by_name = _lock_packages(lock_raw)
    role_results: dict[str, list[dict[str, Any]]] = {}
    for role in UV_EXPORT_ROLES:
        parsed = parse_uv_export(exports[role], role=role)
        merged: dict[str, dict[str, Any]] = {}
        for record in parsed:
            if not evaluate_marker(
                record["marker"],
                environment=environment,
                extras=UV_EXPORT_ROLE_EXTRAS[role],
            ):
                continue
            previous = merged.get(record["name"])
            if previous is not None and previous["version"] != record["version"]:
                _die(f"{role} activates conflicting versions for {record['name']}")
            if previous is None:
                previous = {
                    "hashes": [],
                    "name": record["name"],
                    "version": record["version"],
                }
                merged[record["name"]] = previous
            previous["hashes"] = sorted(set(previous["hashes"]) | set(record["hashes"]))
        reachable = _reachable_role_packages(
            by_name,
            role=role,
            environment=environment,
        )
        if set(merged) != reachable:
            _die(
                f"{role} active export differs from uv.lock reachability; "
                f"missing={sorted(reachable - set(merged))}, "
                f"extra={sorted(set(merged) - reachable)}"
            )
        role_records: list[dict[str, Any]] = []
        for name in sorted(merged, key=lambda item: item.encode("utf-8")):
            record = merged[name]
            package = _select_lock_package(
                by_name,
                {"name": name, "version": record["version"]},
                environment=environment,
            )
            if package["source"] != {"registry": "https://pypi.org/simple"}:
                _die(f"{role} active external package {name} is not from exact PyPI")
            if not set(record["hashes"]) <= _lock_artifact_hashes(package):
                _die(f"{role} export hashes for {name} are absent from final uv.lock")
            role_records.append(record)
        role_results[role] = role_records

    build_versions = {
        record["name"]: record["version"] for record in role_results["production-wheel-build"]
    }
    if build_versions != BUILD_CLOSURE_VERSIONS:
        _die("production-wheel-build role differs from the reviewed six-wheel closure")
    runtime: dict[str, dict[str, Any]] = {}
    for role in ("z4j-core", "z4j", "z4j-scheduler"):
        for record in role_results[role]:
            previous = runtime.get(record["name"])
            if previous is not None and previous["version"] != record["version"]:
                _die(f"runtime roles disagree on {record['name']} version")
            if previous is None:
                runtime[record["name"]] = dict(record)
            else:
                previous["hashes"] = sorted(set(previous["hashes"]) | set(record["hashes"]))
    return {
        "build": role_results["production-wheel-build"],
        "format": "z4j-production-wheelhouse-native-exports-v1",
        "lock": {"sha256": _sha256(lock_raw), "size": len(lock_raw)},
        "platform": platform,
        "roles": role_results,
        "runtime": [
            runtime[name] for name in sorted(runtime, key=lambda item: item.encode("utf-8"))
        ],
    }


def wheel_filename_tags(filename: str) -> tuple[str, str, set[str]]:
    if PurePosixPath(filename).name != filename or not filename.endswith(".whl"):
        _die("selected artifact filename is not one safe wheel basename")
    parts = filename[:-4].split("-")
    if len(parts) not in {5, 6}:
        _die("selected wheel filename has an unsupported PEP 427 field count")
    name = _normalized_distribution(parts[0], "selected wheel filename distribution")
    version = parts[1]
    if not version:
        _die("selected wheel filename version is absent")
    python_tags, abi_tags, platform_tags = parts[-3:]
    tags = {
        f"{python_tag}-{abi_tag}-{platform_tag}"
        for python_tag in python_tags.split(".")
        for abi_tag in abi_tags.split(".")
        for platform_tag in platform_tags.split(".")
    }
    if not tags or any(
        re.fullmatch(r"[a-z0-9]+-[a-z0-9]+-[a-z0-9_]+", tag) is None for tag in tags
    ):
        _die("selected wheel filename tags are malformed")
    return name, version, tags


def select_locked_wheel(
    *,
    package: Mapping[str, Any],
    exported_hashes: Sequence[str],
    native_carrier: Any,
    platform: str,
) -> dict[str, Any]:
    """Select exactly one final-lock wheel compatible with native packaging.sys_tags()."""

    native = validate_native_python_carrier(native_carrier, platform=platform)
    name = _normalized_distribution(package.get("name"), "locked wheel package name")
    version = _string(package.get("version"), "locked wheel package version")
    if package.get("source") != {"registry": "https://pypi.org/simple"}:
        _die(f"locked wheel package {name} is not from exact PyPI")
    exported = set(exported_hashes)
    if not exported or any(HEX64.fullmatch(item) is None for item in exported):
        _die(f"exported hash set for {name} is empty or malformed")
    supported = set(native["supported_tags"])
    selected: list[dict[str, Any]] = []
    wheels = package.get("wheels")
    if not isinstance(wheels, list):
        _die(f"locked package {name} has no wheel inventory; sdist fallback is forbidden")
    for raw_wheel in wheels:
        if not isinstance(raw_wheel, dict) or set(raw_wheel) != {
            "hash",
            "size",
            "upload-time",
            "url",
        }:
            _die(f"locked wheel record for {name} differs")
        parsed = urllib.parse.urlsplit(str(raw_wheel["url"]))
        filename = PurePosixPath(parsed.path).name
        wheel_name, wheel_version, tags = wheel_filename_tags(filename)
        digest_text = str(raw_wheel["hash"])
        digest_hex = digest_text.removeprefix("sha256:")
        if (
            parsed.scheme != "https"
            or parsed.netloc != "files.pythonhosted.org"
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or wheel_name != name
            or wheel_version.replace("_", "-") != version.replace("_", "-")
            or not digest_text.startswith("sha256:")
            or HEX64.fullmatch(digest_hex) is None
            or isinstance(raw_wheel["size"], bool)
            or not isinstance(raw_wheel["size"], int)
            or raw_wheel["size"] <= 0
        ):
            _die(f"locked wheel identity for {name} differs")
        if digest_hex in exported and tags & supported:
            selected.append(
                {
                    "filename": filename,
                    "name": name,
                    "sha256": digest_hex,
                    "size": raw_wheel["size"],
                    "supported_tags": sorted(tags & supported),
                    "upload_time_utc": raw_wheel["upload-time"],
                    "url": raw_wheel["url"],
                    "version": version,
                }
            )
    if len(selected) != 1:
        _die(f"locked package {name} does not select exactly one compatible wheel")
    return selected[0]


def _specifier_contains_python_3147(value: str) -> bool:
    if not value or len(value) > 1024:
        return False
    for raw_clause in value.split(","):
        clause = raw_clause.strip()
        match = re.fullmatch(r"(===|==|!=|~=|<=|>=|<|>)([0-9]+(?:\.[0-9]+)*(?:\.\*)?)", clause)
        if match is None or not _compare_marker_values(
            "3.14.7", match.group(1), match.group(2), version=True
        ):
            return False
    return True


def select_simple_wheel(  # noqa: PLR0912,PLR0915 - closed Simple 1.0..1.4 profile
    *,
    simple: Mapping[str, Any],
    locked: Mapping[str, Any],
) -> dict[str, Any]:
    """Cross-equal one Simple 1.0..1.4 file with the final-lock native selection."""

    name = _normalized_distribution(locked.get("name"), "locked Simple distribution")
    meta = simple.get("meta")
    if not isinstance(meta, dict) or set(meta) != {"api-version"}:
        _die(f"Simple response for {name} metadata differs")
    match = re.fullmatch(r"1\.(0|1|2|3|4)", str(meta["api-version"]))
    if match is None:
        _die(f"Simple response for {name} is outside reviewed API 1.0..1.4")
    minor = int(match.group(1))
    expected_top = {"files", "meta", "name"}
    if minor >= 1:
        expected_top.add("versions")
    if minor >= 2:
        expected_top.add("alternate-locations")
    if minor >= 4:
        expected_top.add("project-status")
    if set(simple) != expected_top:
        _die(f"Simple response for {name} has unknown or version-inconsistent fields")
    if _normalized_distribution(simple.get("name"), f"Simple response {name} name") != name:
        _die(f"Simple response project name differs for {name}")
    if minor >= 2 and simple["alternate-locations"] != []:
        _die(f"Simple response alternate locations are forbidden for {name}")
    if minor >= 4 and simple["project-status"] != {"reason": None, "status": "active"}:
        _die(f"Simple project {name} is not active")
    if minor >= 1:
        versions = simple["versions"]
        if (
            not isinstance(versions, list)
            or any(not isinstance(version, str) or not version for version in versions)
            or len(versions) != len(set(versions))
            or locked.get("version") not in versions
        ):
            _die(f"Simple project version inventory differs for {name}")
    files = simple.get("files")
    if not isinstance(files, list):
        _die(f"Simple files for {name} are malformed")
    selected = [
        item
        for item in files
        if isinstance(item, dict) and item.get("filename") == locked.get("filename")
    ]
    if len(selected) != 1:
        _die(f"Simple response does not select exactly one filename for {name}")
    item = selected[0]
    required = {
        "filename",
        "hashes",
        "requires-python",
        "size",
        "upload-time",
        "url",
        "yanked",
    }
    allowed = required | {"core-metadata", "provenance"}
    if set(item) - allowed or not required <= set(item):
        _die(f"Simple selected file shape differs for {name}")
    hashes = item.get("hashes")
    if hashes != {"sha256": locked.get("sha256")}:
        _die(f"Simple selected file hash differs for {name}")
    parsed = urllib.parse.urlsplit(str(item.get("url")))
    if (
        item.get("url") != locked.get("url")
        or item.get("size") != locked.get("size")
        or item.get("upload-time") != locked.get("upload_time_utc")
        or item.get("yanked") is not False
        or parsed.scheme != "https"
        or parsed.netloc != "files.pythonhosted.org"
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or PurePosixPath(parsed.path).name != locked.get("filename")
    ):
        _die(f"Simple selected file origin/size/time/yanked state differs for {name}")
    upload_time = _pypi_timestamp(str(item["upload-time"]), f"Simple {name} upload time")
    if dt.datetime.fromisoformat(upload_time.replace("Z", "+00:00")) > dt.datetime.fromisoformat(
        CUTOFF.replace("Z", "+00:00")
    ):
        _die(f"Simple selected wheel for {name} was uploaded after the cutoff")
    requires_python = item.get("requires-python")
    if not isinstance(requires_python, str) or not _specifier_contains_python_3147(requires_python):
        _die(f"Simple selected wheel for {name} does not explicitly allow CPython 3.14.7")
    core_metadata = item.get("core-metadata")
    if core_metadata is True:
        _die(f"Simple core metadata for {name} is unhashed")
    if core_metadata is not None and core_metadata is not False:
        if not isinstance(core_metadata, dict) or set(core_metadata) != {"sha256"}:
            _die(f"Simple core metadata for {name} has an unsupported seal")
        _hex(core_metadata["sha256"], f"Simple core metadata {name}")
    provenance = item.get("provenance")
    if provenance is not None:
        parsed_provenance = urllib.parse.urlsplit(str(provenance))
        expected_provenance_path = "/integrity/{}/{}/{}/provenance".format(
            urllib.parse.quote(name, safe=""),
            urllib.parse.quote(str(locked["version"]), safe=""),
            urllib.parse.quote(str(locked["filename"]), safe=""),
        )
        if (
            parsed_provenance.scheme != "https"
            or parsed_provenance.netloc != "pypi.org"
            or parsed_provenance.username
            or parsed_provenance.password
            or parsed_provenance.path != expected_provenance_path
            or parsed_provenance.query
            or parsed_provenance.fragment
        ):
            _die(f"Simple provenance URL for {name} differs")
    return {
        **{key: locked[key] for key in ("filename", "name", "sha256", "size", "url", "version")},
        "core_metadata": core_metadata,
        "provenance": provenance,
        "requires_python": requires_python,
        "upload_time_utc": upload_time,
        "yanked": False,
    }


def audit_wheel_bytes(  # noqa: PLR0912,PLR0915 - bounded ZIP/wheel profile
    raw: bytes,
    *,
    filename: str,
    native_carrier: Any,
    platform: str,
) -> dict[str, Any]:
    """Audit ZIP/RECORD/METADATA/WHEEL identity and native supported-tag compatibility."""

    if not raw or len(raw) > 512 * 1024 * 1024:
        _die("wheel bytes are empty or oversized")
    native = validate_native_python_carrier(native_carrier, platform=platform)
    filename_name, filename_version, filename_tags = wheel_filename_tags(filename)
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise AuthorityError(f"wheel {filename} is not a valid ZIP") from exc
    members: dict[str, bytes] = {}
    expanded = 0
    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_EXPORT_RECORDS:
            _die(f"wheel {filename} member count is absent or oversized")
        for info in infos:
            pure = _safe_carrier_path(info.filename, f"wheel {filename} member")
            unix_mode = info.external_attr >> 16
            if (
                info.filename in members
                or info.is_dir()
                or stat.S_IFMT(unix_mode) not in {0, stat.S_IFREG}
                or info.file_size > 256 * 1024 * 1024
            ):
                _die(f"wheel {filename} contains an unsafe member {info.filename!r}")
            expanded += info.file_size
            if expanded > 1024 * 1024 * 1024:
                _die(f"wheel {filename} expanded bytes exceed the bound")
            try:
                members[pure.as_posix()] = archive.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                raise AuthorityError(f"wheel {filename} member bytes are invalid") from exc
    metadata_names = [name for name in members if name.endswith(".dist-info/METADATA")]
    wheel_names = [name for name in members if name.endswith(".dist-info/WHEEL")]
    record_names = [name for name in members if name.endswith(".dist-info/RECORD")]
    if len(metadata_names) != 1 or len(wheel_names) != 1 or len(record_names) != 1:
        _die(f"wheel {filename} lacks one exact METADATA/WHEEL/RECORD set")
    metadata = email.parser.BytesParser().parsebytes(members[metadata_names[0]])
    names = metadata.get_all("Name") or []
    versions = metadata.get_all("Version") or []
    if metadata.defects or len(names) != 1 or len(versions) != 1:
        _die(f"wheel {filename} METADATA identity is ambiguous")
    name = _normalized_distribution(names[0], f"wheel {filename} metadata name")
    version = str(versions[0])
    if name != filename_name or version.replace("-", "_") != filename_version.replace("-", "_"):
        _die(f"wheel {filename} filename and METADATA identity differ")
    dist_info = PurePosixPath(metadata_names[0]).parts[0]
    filename_parts = filename[:-4].split("-")
    expected_dist_info = f"{filename_parts[0]}-{filename_parts[1]}.dist-info"
    if dist_info != expected_dist_info:
        _die(f"wheel {filename} dist-info directory differs from its filename identity")
    if not all(PurePosixPath(item).parts[0] == dist_info for item in (*wheel_names, *record_names)):
        _die(f"wheel {filename} metadata files do not share one dist-info directory")
    try:
        rows = list(csv.reader(io.StringIO(members[record_names[0]].decode("utf-8"), newline="")))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise AuthorityError(f"wheel {filename} RECORD is invalid") from exc
    recorded: set[str] = set()
    for row in rows:
        if len(row) != 3 or row[0] in recorded or row[0] not in members:
            _die(f"wheel {filename} RECORD row is malformed, duplicate, or absent")
        member_name, digest_value, size_value = row
        recorded.add(member_name)
        if member_name == record_names[0]:
            if digest_value or size_value:
                _die(f"wheel {filename} RECORD self-row must omit its seal")
            continue
        payload = members[member_name]
        expected = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
        if digest_value != "sha256=" + expected or size_value != str(len(payload)):
            _die(f"wheel {filename} RECORD seal differs for {member_name}")
    if recorded != set(members):
        _die(f"wheel {filename} RECORD inventory differs from ZIP members")
    wheel_metadata = email.parser.BytesParser().parsebytes(members[wheel_names[0]])
    raw_tags = wheel_metadata.get_all("Tag") or []
    if wheel_metadata.defects or not raw_tags or len(raw_tags) != len(set(raw_tags)):
        _die(f"wheel {filename} WHEEL tags are absent or ambiguous")
    wheel_tags = set(raw_tags)
    if wheel_tags != filename_tags:
        _die(f"wheel {filename} filename and WHEEL tag sets differ")
    supported = filename_tags & set(native["supported_tags"])
    if not supported:
        _die(f"wheel {filename} has no exact native supported tag")
    requires_python = metadata.get_all("Requires-Python") or []
    if len(requires_python) > 1 or (
        requires_python and not _specifier_contains_python_3147(requires_python[0])
    ):
        _die(f"wheel {filename} METADATA does not allow CPython 3.14.7")
    requires_dist = metadata.get_all("Requires-Dist") or []
    if any(not isinstance(item, str) or len(item) > 4096 for item in requires_dist):
        _die(f"wheel {filename} Requires-Dist inventory differs")
    return {
        "filename": filename,
        "metadata_sha256": _sha256(members[metadata_names[0]]),
        "metadata_size": len(members[metadata_names[0]]),
        "name": name,
        "requires_dist": sorted(requires_dist, key=lambda item: item.encode("utf-8")),
        "requires_python": requires_python[0] if requires_python else None,
        "sha256": _sha256(raw),
        "size": len(raw),
        "supported_tags": sorted(supported),
        "version": version,
    }


def reconcile_native_acquisition(  # noqa: PLR0912 - closed multi-source cross-check
    *,
    lock_raw: bytes,
    exports: Mapping[str, bytes],
    native_carrier: Any,
    platform: str,
    simple_documents: Mapping[str, Mapping[str, Any]],
    core_metadata_bytes: Mapping[str, bytes],
    wheel_bytes: Mapping[str, bytes],
) -> dict[str, Any]:
    """Reconcile lock, roles, Simple metadata, downloaded bytes, and wheel internals."""

    resolution = resolve_native_exports(
        lock_raw=lock_raw,
        exports=exports,
        native_carrier=native_carrier,
        platform=platform,
    )
    native = validate_native_python_carrier(native_carrier, platform=platform)
    _lock, by_name = _lock_packages(lock_raw)
    closure: dict[str, dict[str, Any]] = {}
    for role in UV_EXPORT_ROLES:
        for record in resolution["roles"][role]:
            current = closure.get(record["name"])
            if current is None:
                current = {
                    "hashes": set(),
                    "name": record["name"],
                    "roles": [],
                    "version": record["version"],
                }
                closure[record["name"]] = current
            elif current["version"] != record["version"]:
                _die(f"native acquisition roles disagree on {record['name']} version")
            current["hashes"].update(record["hashes"])
            current["roles"].append(role)
    if set(simple_documents) != set(closure):
        _die("Simple document set differs from the complete native external closure")

    results: list[dict[str, Any]] = []
    selected_metadata_filenames: set[str] = set()
    selected_filenames: set[str] = set()
    for name in sorted(closure, key=lambda item: item.encode("utf-8")):
        authority = closure[name]
        package = _select_lock_package(
            by_name,
            {"name": name, "version": authority["version"]},
            environment=native["marker_environment"],
        )
        locked = select_locked_wheel(
            package=package,
            exported_hashes=sorted(authority["hashes"]),
            native_carrier=native_carrier,
            platform=platform,
        )
        simple = select_simple_wheel(simple=simple_documents[name], locked=locked)
        filename = simple["filename"]
        if filename in selected_filenames:
            _die("native acquisition selected one filename for multiple distributions")
        selected_filenames.add(filename)
        raw = wheel_bytes.get(filename)
        if (
            not isinstance(raw, bytes)
            or len(raw) != simple["size"]
            or _sha256(raw) != simple["sha256"]
        ):
            _die(f"downloaded wheel bytes differ from the lock/Simple seal for {name}")
        audited = audit_wheel_bytes(
            raw,
            filename=filename,
            native_carrier=native_carrier,
            platform=platform,
        )
        if (
            any(
                audited[key] != simple[key]
                for key in ("filename", "name", "sha256", "size", "version")
            )
            or audited["requires_python"] != simple["requires_python"]
        ):
            _die(f"wheel internals differ from lock/Simple identity for {name}")
        core_metadata = simple["core_metadata"]
        core_metadata_receipt: dict[str, Any] | None = None
        if isinstance(core_metadata, dict):
            selected_metadata_filenames.add(filename)
            metadata_raw = core_metadata_bytes.get(filename)
            if (
                not isinstance(metadata_raw, bytes)
                or not metadata_raw
                or len(metadata_raw) > MAX_JSON_BYTES
                or _sha256(metadata_raw) != core_metadata["sha256"]
                or _sha256(metadata_raw) != audited["metadata_sha256"]
                or len(metadata_raw) != audited["metadata_size"]
            ):
                _die(f"fetched core metadata differs from Simple and wheel METADATA for {name}")
            core_metadata_receipt = {
                "sha256": core_metadata["sha256"],
                "size": len(metadata_raw),
                "url": simple["url"] + ".metadata",
            }
        results.append(
            {
                **audited,
                "core_metadata": core_metadata_receipt,
                "provenance": simple["provenance"],
                "roles": sorted(authority["roles"], key=lambda item: item.encode("utf-8")),
                "upload_time_utc": simple["upload_time_utc"],
                "url": simple["url"],
                "yanked": False,
            }
        )
    if set(wheel_bytes) != selected_filenames:
        _die("downloaded wheel byte set contains a missing or unselected filename")
    if set(core_metadata_bytes) != selected_metadata_filenames:
        _die("fetched core metadata set contains a missing or unselected filename")
    return {
        "format": "z4j-production-wheelhouse-native-acquisition-v1",
        "lock": resolution["lock"],
        "platform": platform,
        "wheels": results,
    }


def audit_local_wheel_build_pair(
    *,
    build_a: Mapping[str, bytes],
    build_b: Mapping[str, bytes],
    native_carrier: Any,
    platform: str,
) -> list[dict[str, Any]]:
    """Require two clean local builds to yield the exact same three universal wheels."""

    if not build_a or set(build_a) != set(build_b):
        _die("local wheel build A/B filename sets differ or are empty")
    records: dict[str, dict[str, Any]] = {}
    for filename in sorted(build_a, key=lambda item: item.encode("utf-8")):
        raw_a = build_a[filename]
        raw_b = build_b[filename]
        if not isinstance(raw_a, bytes) or not isinstance(raw_b, bytes) or raw_a != raw_b:
            _die(f"local wheel build A/B bytes differ for {filename}")
        audited = audit_wheel_bytes(
            raw_a,
            filename=filename,
            native_carrier=native_carrier,
            platform=platform,
        )
        name = audited["name"]
        if (
            name not in LOCAL_WHEEL_DISTRIBUTIONS
            or name in records
            or audited["version"] != RELEASE
            or audited["supported_tags"] != ["py3-none-any"]
        ):
            _die("local build output is not one exact universal z4j 1.9.0 wheel per distribution")
        records[name] = audited
    if tuple(sorted(records, key=lambda item: item.encode("utf-8"))) != LOCAL_WHEEL_DISTRIBUTIONS:
        _die("local build output differs from the exact three-wheel closure")
    return [records[name] for name in LOCAL_WHEEL_DISTRIBUTIONS]


def component_projection(components: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Build the sole acyclic component subject used by SBOM and advisory evidence."""

    records: list[dict[str, Any]] = []
    for index, raw in enumerate(components):
        if set(raw) != {"name", "version", "wheel_sha256"}:
            _die(f"component {index} shape differs")
        record = {
            "name": _normalized_distribution(raw["name"], f"component {index} name"),
            "version": _string(raw["version"], f"component {index} version"),
            "wheel_sha256": _hex(raw["wheel_sha256"], f"component {index} wheel digest"),
        }
        records.append(record)
    order = [(item["name"].encode("utf-8"), item["version"].encode("utf-8")) for item in records]
    if not records or order != sorted(set(order)):
        _die("component projection is empty, duplicate, or not strictly byte-sorted")
    return {"components": records, "format": "z4j-production-wheel-components-v1"}


def reconcile_component_evidence(  # noqa: PLR0912,PLR0915 - closed evidence cross-check
    *,
    external_wheels: Sequence[Mapping[str, Any]],
    local_wheels_a: Sequence[Mapping[str, Any]],
    local_wheels_b: Sequence[Mapping[str, Any]],
    sbom: Mapping[str, Any],
    advisory: Mapping[str, Any],
    advisory_report: bytes,
    platform: str,
) -> dict[str, Any]:
    """Cross-equal A/B builds, wheel closure, SBOM subject, and advisory scan inventory."""

    if platform not in PLATFORMS:
        _die("component reconciliation platform differs")

    def wheel_records(values: Sequence[Mapping[str, Any]], context: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for index, value in enumerate(values):
            if not {"name", "version", "sha256", "size"} <= set(value):
                _die(f"{context} wheel {index} shape differs")
            records.append(
                {
                    "name": _normalized_distribution(value["name"], f"{context} wheel name"),
                    "sha256": _hex(value["sha256"], f"{context} wheel sha256"),
                    "size": _positive_int(value["size"], f"{context} wheel size"),
                    "version": _string(value["version"], f"{context} wheel version"),
                }
            )
        order = [(item["name"], item["version"]) for item in records]
        if order != sorted(set(order)):
            _die(f"{context} wheel inventory is duplicate or unsorted")
        return records

    external = wheel_records(external_wheels, "external")
    local_a = wheel_records(local_wheels_a, "local build A")
    local_b = wheel_records(local_wheels_b, "local build B")
    if local_a != local_b:
        _die("clean local wheel builds A/B are not byte-identical")
    if [item["name"] for item in local_a] != list(LOCAL_WHEEL_DISTRIBUTIONS):
        _die("local wheel build closure differs from the exact three distributions")
    combined = sorted([*external, *local_a], key=lambda item: item["name"].encode("utf-8"))
    if len({item["name"] for item in combined}) != len(combined):
        _die("external and local wheel closures overlap")
    projection = component_projection(
        [
            {"name": item["name"], "version": item["version"], "wheel_sha256": item["sha256"]}
            for item in combined
        ]
    )
    components_sha256 = _sha256(canonical_json(projection, terminal_lf=False))

    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX":
        _die("wheelhouse SBOM is not CycloneDX")
    metadata = sbom.get("metadata")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("component"), dict):
        _die("wheelhouse SBOM subject is absent")
    subject = metadata["component"]
    subject_hashes = subject.get("hashes")
    if (
        subject.get("type") != "application"
        or subject.get("name") != "z4j-production-wheelhouse"
        or subject.get("version") != RELEASE
        or subject_hashes != [{"alg": "SHA-256", "content": components_sha256}]
    ):
        _die("wheelhouse SBOM subject does not bind components_sha256")
    sbom_components = sbom.get("components")
    if not isinstance(sbom_components, list):
        _die("wheelhouse SBOM components are absent")
    observed: list[dict[str, Any]] = []
    for item in sbom_components:
        if not isinstance(item, dict):
            _die("wheelhouse SBOM component is malformed")
        hashes = item.get("hashes")
        if (
            not isinstance(hashes, list)
            or len(hashes) != 1
            or not isinstance(hashes[0], dict)
            or set(hashes[0]) != {"alg", "content"}
            or hashes[0].get("alg") != "SHA-256"
        ):
            _die("wheelhouse SBOM component does not carry one wheel SHA-256")
        observed.append(
            {
                "name": _normalized_distribution(item.get("name"), "SBOM component name"),
                "version": _string(item.get("version"), "SBOM component version"),
                "wheel_sha256": _hex(hashes[0]["content"], "SBOM component wheel digest"),
            }
        )
    if component_projection(observed) != projection:
        _die("wheelhouse SBOM component closure differs")

    if not isinstance(advisory, dict) or set(advisory) != {
        "components_sha256",
        "database",
        "findings",
        "format",
        "platform",
        "policy",
        "report",
        "scan_completed_at_utc",
        "scanner",
        "verdict",
    }:
        _die("wheelhouse advisory receipt shape differs or contains a cyclic tree subject")
    if (
        advisory["format"] != "z4j-production-advisory-receipt-v1"
        or advisory["platform"] != platform
        or advisory["components_sha256"] != components_sha256
        or advisory["findings"] != []
        or advisory["verdict"] != "pass"
    ):
        _die("wheelhouse advisory does not bind the exact passing component closure")
    report = _exact_keys(
        advisory["report"], {"path", "sha256", "size"}, "wheelhouse advisory raw report"
    )
    if (
        report["path"] != "evidence/advisory-report.json"
        or _hex(report["sha256"], "wheelhouse advisory raw report sha256")
        != _sha256(advisory_report)
        or _positive_int(report["size"], "wheelhouse advisory raw report size")
        != len(advisory_report)
    ):
        _die("wheelhouse advisory raw report bytes differ from their receipt seal")
    report_value = _parse_json(advisory_report, context="wheelhouse advisory raw report")
    if not isinstance(report_value, dict) or report_value.get("SchemaVersion") != 2:
        _die("wheelhouse advisory raw report is not Trivy schema version 2")
    results = report_value.get("Results")
    if (
        not isinstance(results, list)
        or not results
        or any(
            not isinstance(result, dict) or result.get("Vulnerabilities") not in (None, [])
            for result in results
        )
    ):
        _die("wheelhouse advisory raw report contains findings or malformed results")
    python_results = [
        result
        for result in results
        if isinstance(result, dict) and result.get("Type") == "python-pkg"
    ]
    if not python_results:
        _die("wheelhouse advisory raw report has no python-pkg target")
    scanned: list[tuple[str, str]] = []
    for result in python_results:
        packages = result.get("Packages")
        if not isinstance(packages, list) or not packages:
            _die("wheelhouse advisory python-pkg target has no package inventory")
        for item in packages:
            if not isinstance(item, dict):
                _die("wheelhouse advisory raw package is malformed")
            scanned.append(
                (
                    _normalized_distribution(item.get("Name"), "scanned package name"),
                    _string(item.get("Version"), "scanned package version"),
                )
            )
    scanned.sort()
    expected_scanned = [(item["name"], item["version"]) for item in combined]
    if scanned != expected_scanned or len(scanned) != len(set(scanned)):
        _die("advisory scanner package inventory differs from runtime/build/local closure")
    return {
        "components": projection["components"],
        "components_sha256": components_sha256,
        "format": projection["format"],
    }


def _safe_carrier_path(value: str, context: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or not value.isascii()
        or len(value) > 4096
        or path.is_absolute()
        or path.as_posix() != value
        or len(path.parts) > 64
        or ".." in path.parts
        or "\\" in value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        or any(not part or part in {".", ".."} for part in path.parts)
    ):
        _die(f"{context} path is unsafe")
    return path


def build_platform_carrier(  # noqa: PLR0912,PLR0915 - canonical USTAR construction
    *,
    files: Mapping[str, tuple[int, bytes]],
    platform: str,
    source_date_epoch: int,
) -> bytes:
    """Build a canonical bounded USTAR carrier while preserving every regular-file mode."""

    if platform not in PLATFORMS:
        _die("platform carrier platform differs")
    if not 1_600_000_000 <= source_date_epoch <= 2_000_000_000:
        _die("platform carrier SOURCE_DATE_EPOCH differs")
    if not files or len(files) > MAX_EXPORT_RECORDS:
        _die("platform carrier file inventory is empty or oversized")
    if any(not isinstance(name, str) for name in files):
        _die("platform carrier payload name is not text")
    file_names = set(files)
    records: list[dict[str, Any]] = []
    payload: dict[str, bytes] = {}
    for name in sorted(files, key=lambda item: item.encode("utf-8")):
        path = _safe_carrier_path(name, "platform carrier payload")
        if any(
            parent != PurePosixPath(".") and parent.as_posix() in file_names
            for parent in path.parents
        ):
            _die("platform carrier payload contains a file/directory prefix collision")
        mode, raw = files[name]
        if (
            mode not in PLATFORM_CARRIER_MODES
            or not isinstance(raw, bytes)
            or len(raw) > 512 * 1024 * 1024
        ):
            _die(f"platform carrier payload {name} mode/bytes differ")
        payload[name] = raw
        records.append(
            {"mode": f"{mode:04o}", "path": name, "sha256": _sha256(raw), "size": len(raw)}
        )
    if sum(record["size"] for record in records) > MAX_PLATFORM_CARRIER_BYTES // 2:
        _die("platform carrier payload bytes exceed the pre-archive bound")
    tree = {
        "files": records,
        "format": "z4j-production-wheelhouse-platform-tree-v1",
        "platform": platform,
    }
    metadata = {
        "files": records,
        "format": "z4j-production-wheelhouse-platform-carrier-v1",
        "platform": platform,
        "source_date_epoch": source_date_epoch,
        "tree_bytes": sum(record["size"] for record in records),
        "tree_sha256": _sha256(canonical_json(tree, terminal_lf=False)),
    }
    carrier_raw = canonical_json(metadata, terminal_lf=True)
    archive_files = {"carrier.json": (0o400, carrier_raw)}
    archive_files.update(
        {
            f"payload/{name}": (int(records[index]["mode"], 8), payload[name])
            for index, name in enumerate(payload)
        }
    )
    directories: set[str] = set()
    for name in archive_files:
        parent = PurePosixPath(name).parent
        while parent != PurePosixPath("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    entries: list[tuple[str, int, bytes | None]] = [
        (name + "/", 0o755, None) for name in directories
    ] + [(name, mode, raw) for name, (mode, raw) in archive_files.items()]
    entries.sort(key=lambda item: item[0].encode("utf-8"))
    if len(entries) > MAX_EXPORT_RECORDS * 2:
        _die("platform carrier member inventory exceeds its bound")
    output = io.BytesIO()
    try:
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, mode, entry_raw in entries:
                info = tarfile.TarInfo(name)
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = source_date_epoch
                info.mode = mode
                if entry_raw is None:
                    info.type = tarfile.DIRTYPE
                    info.size = 0
                    archive.addfile(info)
                else:
                    info.type = tarfile.REGTYPE
                    info.size = len(entry_raw)
                    archive.addfile(info, io.BytesIO(entry_raw))
    except (OSError, tarfile.TarError, ValueError) as exc:
        raise AuthorityError("platform carrier cannot be encoded as canonical USTAR") from exc
    result = output.getvalue()
    if len(result) > MAX_PLATFORM_CARRIER_BYTES:
        _die("platform carrier exceeds its aggregate byte bound")
    return result


def validate_platform_carrier(  # noqa: PLR0912,PLR0915 - closed USTAR verifier
    raw: bytes, *, platform: str
) -> tuple[dict[str, Any], dict[str, tuple[int, bytes]]]:
    """Validate without extraction and prove the archive equals its canonical reconstruction."""

    if not raw or len(raw) > MAX_PLATFORM_CARRIER_BYTES:
        _die("platform carrier is empty or oversized")
    observed: dict[str, tuple[int, bytes]] = {}
    names: list[str] = []
    expanded = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            if not members or len(members) > MAX_EXPORT_RECORDS * 2:
                _die("platform carrier member count is absent or oversized")
            for member in members:
                name = member.name
                names.append(name)
                canonical_name = name[:-1] if member.isdir() and name.endswith("/") else name
                _safe_carrier_path(canonical_name, "platform carrier member")
                if (
                    member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.pax_headers
                    or member.issym()
                    or member.islnk()
                    or not (member.isdir() or member.isreg())
                ):
                    _die(f"platform carrier member {name} metadata/type differs")
                if member.isreg():
                    if member.mode not in PLATFORM_CARRIER_MODES:
                        _die(f"platform carrier member {name} mode differs")
                    expanded += member.size
                    if expanded > MAX_PLATFORM_CARRIER_BYTES // 2:
                        _die("platform carrier expanded bytes exceed the bound")
                    stream = archive.extractfile(member)
                    if stream is None:
                        _die(f"platform carrier member {name} is unreadable")
                    payload = stream.read(512 * 1024 * 1024 + 1)
                    if (
                        len(payload) > 512 * 1024 * 1024
                        or len(payload) != member.size
                        or name in observed
                    ):
                        _die(f"platform carrier member {name} is oversized or duplicate")
                    observed[name] = (member.mode, payload)
    except (OSError, tarfile.TarError) as exc:
        raise AuthorityError("platform carrier is not one valid USTAR archive") from exc
    if names != sorted(set(names), key=lambda item: item.encode("utf-8")):
        _die("platform carrier members are duplicate or not strictly byte-sorted")
    carrier_entry = observed.get("carrier.json")
    if carrier_entry is None or carrier_entry[0] != 0o400:
        _die("platform carrier metadata member is absent or has the wrong mode")
    metadata = _parse_json(carrier_entry[1], context="platform carrier metadata")
    metadata = _exact_keys(
        metadata,
        {
            "files",
            "format",
            "platform",
            "source_date_epoch",
            "tree_bytes",
            "tree_sha256",
        },
        "platform carrier metadata",
    )
    if canonical_json(metadata, terminal_lf=True) != carrier_entry[1]:
        _die("platform carrier metadata is not canonical JSON plus LF")
    if (
        metadata["format"] != "z4j-production-wheelhouse-platform-carrier-v1"
        or metadata["platform"] != platform
    ):
        _die("platform carrier format/platform differs")
    source_date_epoch = _positive_int(metadata["source_date_epoch"], "platform carrier epoch")
    records = _list(metadata["files"], "platform carrier files")
    files: dict[str, tuple[int, bytes]] = {}
    previous: bytes | None = None
    for index, value in enumerate(records):
        record = _exact_keys(
            value, {"mode", "path", "sha256", "size"}, f"platform carrier file {index}"
        )
        name = _safe_carrier_path(record["path"], f"platform carrier file {index}").as_posix()
        encoded = name.encode("utf-8")
        if previous is not None and encoded <= previous:
            _die("platform carrier file records are not strictly byte-sorted")
        previous = encoded
        if (
            not isinstance(record["mode"], str)
            or re.fullmatch(r"0[4567][0-7]{2}", record["mode"]) is None
        ):
            _die("platform carrier file mode differs")
        payload_entry = observed.get("payload/" + name)
        if payload_entry is None:
            _die(f"platform carrier payload {name} is absent")
        mode, payload = payload_entry
        _hex(record["sha256"], f"platform carrier file {name} sha256")
        _nonnegative_int(record["size"], f"platform carrier file {name} size")
        if (
            mode != int(record["mode"], 8)
            or len(payload) != record["size"]
            or _sha256(payload) != record["sha256"]
        ):
            _die(f"platform carrier payload {name} mode/size/hash differs")
        files[name] = (mode, payload)
    if set(observed) != {"carrier.json", *("payload/" + name for name in files)}:
        _die("platform carrier has unlisted regular members")
    tree = {
        "files": records,
        "format": "z4j-production-wheelhouse-platform-tree-v1",
        "platform": platform,
    }
    if metadata["tree_bytes"] != sum(len(payload) for _mode, payload in files.values()) or metadata[
        "tree_sha256"
    ] != _sha256(canonical_json(tree, terminal_lf=False)):
        _die("platform carrier tree seal differs")
    if (
        build_platform_carrier(
            files=files,
            platform=platform,
            source_date_epoch=source_date_epoch,
        )
        != raw
    ):
        _die("platform carrier bytes are not the canonical USTAR encoding")
    return metadata, files


def aggregate_platform_carriers(*, amd64: bytes, arm64: bytes) -> dict[str, Any]:
    """Validate the complete native pair and require universal local wheels byte-equal."""

    decoded: dict[str, tuple[dict[str, Any], dict[str, tuple[int, bytes]], bytes]] = {}
    for platform, raw in zip(PLATFORMS, (amd64, arm64), strict=True):
        metadata, files = validate_platform_carrier(raw, platform=platform)
        decoded[platform] = (metadata, files, raw)

    local_by_platform: dict[str, dict[str, tuple[str, int, bytes]]] = {}
    for platform, (_metadata, files, _raw) in decoded.items():
        selected: dict[str, tuple[str, int, bytes]] = {}
        for name, (mode, payload) in files.items():
            if not name.startswith("wheels/") or not name.endswith(".whl"):
                continue
            if mode != 0o444:
                _die(f"{platform} platform carrier wheel mode differs")
            wheel_basename = PurePosixPath(name).name
            wheel_name, version, tags = wheel_filename_tags(wheel_basename)
            if wheel_name in LOCAL_WHEEL_DISTRIBUTIONS:
                if (
                    name != "wheels/" + wheel_basename
                    or version != RELEASE
                    or tags != {"py3-none-any"}
                ):
                    _die(f"{platform} platform carrier local wheel identity differs")
                if wheel_name in selected:
                    _die(f"{platform} platform carrier duplicates local wheel {wheel_name}")
                selected[wheel_name] = (name, mode, payload)
        if (
            tuple(sorted(selected, key=lambda item: item.encode("utf-8")))
            != LOCAL_WHEEL_DISTRIBUTIONS
        ):
            _die(f"{platform} platform carrier local wheel closure differs")
        local_by_platform[platform] = selected
    first = local_by_platform["linux/amd64"]
    second = local_by_platform["linux/arm64"]
    if first != second:
        _die("universal local wheel filenames/modes/bytes differ between native carriers")
    return {
        "format": "z4j-production-wheelhouse-platform-carrier-set-v1",
        "local_wheels": [
            {
                "filename": first[name][0].removeprefix("wheels/"),
                "name": name,
                "sha256": _sha256(first[name][2]),
                "size": len(first[name][2]),
            }
            for name in LOCAL_WHEEL_DISTRIBUTIONS
        ],
        "platforms": {
            platform: {
                "carrier_sha256": _sha256(raw),
                "carrier_size": len(raw),
                "tree_bytes": metadata["tree_bytes"],
                "tree_sha256": metadata["tree_sha256"],
            }
            for platform, (metadata, _files, raw) in decoded.items()
        },
    }


def _payload_records(root: Path) -> list[dict[str, Any]]:
    if not root.is_dir() or root.is_symlink():
        _die("wheelhouse payload root is absent or unsafe")
    records: list[dict[str, Any]] = []
    for path in sorted(
        root.rglob("*"), key=lambda item: item.relative_to(root).as_posix().encode()
    ):
        relative = path.relative_to(root).as_posix()
        if relative == "inventory.json" or path.is_dir():
            continue
        before = path.stat(follow_symlinks=False)
        if path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            _die(f"wheelhouse payload contains unsafe entry {relative}")
        mode = stat.S_IMODE(before.st_mode)
        if mode not in {0o400, 0o444, 0o500, 0o544, 0o555, 0o600, 0o644, 0o700, 0o744, 0o755}:
            _die(f"wheelhouse payload mode is outside the reviewed regular-file set: {relative}")
        raw = _read_regular(path, maximum=512 * 1024 * 1024, context=f"payload {relative}")
        records.append(
            {"mode": f"{mode:04o}", "path": relative, "sha256": _sha256(raw), "size": len(raw)}
        )
    if not records:
        _die("wheelhouse payload is empty")
    return records


def _deterministic_tar(root: Path, *, source_date_epoch: int) -> bytes:
    if not 1_600_000_000 <= source_date_epoch <= 2_000_000_000:
        _die("SOURCE_DATE_EPOCH is absent or outside the reviewed range")
    entries: list[tuple[str, Path | None, bool]] = [
        ("opt", None, True),
        ("opt/z4j-production", None, True),
    ]
    children = sorted(
        root.rglob("*"),
        key=lambda item: item.relative_to(root).as_posix().encode(),
    )
    entries.extend(
        (
            "opt/z4j-production/" + path.relative_to(root).as_posix(),
            path,
            path.is_dir(),
        )
        for path in children
    )
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        previous: bytes | None = None
        for name, path, directory in entries:
            encoded = name.encode("utf-8")
            if previous is not None and encoded <= previous:
                _die("deterministic tar path order is not strictly UTF-8 sorted")
            previous = encoded
            info = tarfile.TarInfo(name + ("/" if directory else ""))
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = source_date_epoch
            if directory:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.size = 0
                archive.addfile(info)
                continue
            if path is None:
                _die("deterministic tar regular file path is absent")
            before = path.stat(follow_symlinks=False)
            if path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                _die(f"deterministic tar input is unsafe: {name}")
            raw = _read_regular(path, maximum=512 * 1024 * 1024, context=name)
            info.type = tarfile.REGTYPE
            info.mode = stat.S_IMODE(before.st_mode)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return output.getvalue()


def _deterministic_gzip(raw: bytes) -> bytes:
    compressor = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15, memLevel=9)
    compressed = compressor.compress(raw) + compressor.flush()
    return (
        b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
        + compressed
        + struct.pack("<II", zlib.crc32(raw) & 0xFFFFFFFF, len(raw) & 0xFFFFFFFF)
    )


def pack_platform(
    *,
    payload_root: Path,
    output: Path,
    platform: str,
    source_date_epoch: int,
) -> dict[str, Any]:
    """Seal one native payload as exact inventory, tar/gzip, config, and leaf bytes."""

    if platform not in PLATFORMS:
        _die("wheelhouse pack platform differs")
    if output.exists() or output.is_symlink():
        _die("wheelhouse platform output already exists")
    inventory_path = payload_root / "inventory.json"
    if inventory_path.exists() or inventory_path.is_symlink():
        _die("wheelhouse payload inventory must be generated into an absent path")
    records = _payload_records(payload_root)
    inventory = {
        "files": records,
        "format": "z4j-production-wheelhouse-inventory-v1",
        "platform": platform,
    }
    inventory_raw = canonical_json(inventory, terminal_lf=True)
    _atomic_write_new(inventory_path, inventory_raw, mode=0o600)
    tar_raw = _deterministic_tar(payload_root, source_date_epoch=source_date_epoch)
    layer_raw = _deterministic_gzip(tar_raw)
    architecture = ARCHITECTURES[platform]
    config = {
        "architecture": architecture,
        "config": {},
        "os": "linux",
        "rootfs": {"diff_ids": [_digest(tar_raw)], "type": "layers"},
    }
    config_raw = canonical_json(config, terminal_lf=False)
    leaf = {
        "config": {
            "digest": _digest(config_raw),
            "mediaType": OCI_CONFIG_MEDIA_TYPE,
            "size": len(config_raw),
        },
        "layers": [
            {
                "digest": _digest(layer_raw),
                "mediaType": OCI_LAYER_MEDIA_TYPE,
                "size": len(layer_raw),
            }
        ],
        "mediaType": AM_MEDIA_TYPE,
        "schemaVersion": 2,
    }
    leaf_raw = canonical_json(leaf, terminal_lf=False)
    tree = {
        "files": records,
        "format": "z4j-production-wheelhouse-tree-v1",
        "platform": platform,
    }
    record = {
        "config_digest": _digest(config_raw),
        "config_size": len(config_raw),
        "inventory_sha256": _sha256(inventory_raw),
        "inventory_size": len(inventory_raw),
        "layer_diff_id": _digest(tar_raw),
        "layer_digest": _digest(layer_raw),
        "layer_size": len(layer_raw),
        "manifest_digest": _digest(leaf_raw),
        "manifest_size": len(leaf_raw),
        "tree_bytes": sum(int(item["size"]) for item in records),
        "tree_sha256": _sha256(canonical_json(tree, terminal_lf=False)),
    }
    output.mkdir(mode=0o700, parents=True)
    for name, raw in (
        ("config.json", config_raw),
        ("layer.tar.gz", layer_raw),
        ("manifest.json", leaf_raw),
        ("build-record.json", canonical_json(record, terminal_lf=True)),
    ):
        _atomic_write_new(output / name, raw)
    return record


def assemble_index(*, amd64_leaf: bytes, arm64_leaf: bytes) -> bytes:
    """Construct the exact two-descriptor amd64/arm64 OCI index."""

    descriptors = []
    for platform, raw in zip(PLATFORMS, (amd64_leaf, arm64_leaf), strict=True):
        validate_leaf_bytes(raw, platform=platform)
        descriptors.append(
            {
                "digest": _digest(raw),
                "mediaType": AM_MEDIA_TYPE,
                "platform": {"architecture": ARCHITECTURES[platform], "os": "linux"},
                "size": len(raw),
            }
        )
    return canonical_json(
        {"manifests": descriptors, "mediaType": OCI_INDEX_MEDIA_TYPE, "schemaVersion": 2},
        terminal_lf=False,
    )
