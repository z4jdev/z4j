"""Version freshness checks for the dashboard's *Update available*
badge on the Agents page.

Privacy posture (1.3.4 design):

- The brain SHIPS with a bundled snapshot of the latest known
  versions of every z4j package, generated from
  ``sites/_shared/packages.ts`` at brain release time. This file
  is loaded at startup and used for every comparison by default.
  No network call. Air-gapped friendly.
- An operator can click *Settings -> System -> Check for updates* to fetch
  a fresher snapshot from GitHub
  (``https://raw.githubusercontent.com/z4jdev/z4j/main/versions.json``).
  This is the only version-check network request and is always
  operator-initiated. (Other configured features, such as notification
  delivery, can make their own outbound requests.) The result is cached in
  process memory so subsequent comparisons use the fresh data until the next
  restart.
- Operators who want zero outbound HTTP can set
  ``Z4J_VERSION_CHECK_URL`` empty; the dashboard disables the
  *Check for updates* button and keeps using the bundled snapshot.
- Air-gapped operators with an internal mirror set
  ``Z4J_VERSION_CHECK_URL=https://internal-mirror/versions.json``.

There is no automatic background polling. There is no telemetry.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import structlog

logger = structlog.get_logger("z4j.brain.version_check")


_BUNDLED_PATH = Path(__file__).resolve().parent.parent / "data" / "versions.json"
"""Resolves to ``z4j_brain/data/versions.json`` once installed."""

#: SemVer 2.0.0 identifiers. Numeric core and pre-release identifiers reject
#: leading zeroes; build identifiers may contain them. A pre-release always
#: starts with ``-`` and build metadata with ``+``.
_SEMVER_NUMERIC_IDENTIFIER = r"(?:0|[1-9]\d*)"
_SEMVER_NONNUMERIC_IDENTIFIER = r"(?:[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
_SEMVER_PRERELEASE_IDENTIFIER = rf"(?:{_SEMVER_NUMERIC_IDENTIFIER}|{_SEMVER_NONNUMERIC_IDENTIFIER})"
_SEMVER_BUILD_IDENTIFIER = r"[0-9A-Za-z-]+"
_SEMVER_RE = re.compile(
    rf"^(?P<major>{_SEMVER_NUMERIC_IDENTIFIER})\."
    rf"(?P<minor>{_SEMVER_NUMERIC_IDENTIFIER})\."
    rf"(?P<patch>{_SEMVER_NUMERIC_IDENTIFIER})"
    rf"(?:-(?P<pre>{_SEMVER_PRERELEASE_IDENTIFIER}"
    rf"(?:\.{_SEMVER_PRERELEASE_IDENTIFIER})*))?"
    rf"(?:\+(?P<build>{_SEMVER_BUILD_IDENTIFIER}"
    rf"(?:\.{_SEMVER_BUILD_IDENTIFIER})*))?$",
)


VersionStatus = Literal[
    "current",  # agent at exactly snapshot's latest
    "outdated",  # agent < snapshot's latest, same major
    "newer_than_known",  # agent > snapshot (brain itself may be stale)
    "incompatible",  # major bump separates agent and snapshot
    "unknown",  # snapshot doesn't list this package, or version unparseable
]


@dataclass(frozen=True)
class ParsedVersion:
    """SemVer parts extracted from a version string."""

    major: int
    minor: int
    patch: int
    pre: str = ""
    build: str = ""

    @classmethod
    def parse(cls, raw: str) -> ParsedVersion | None:
        """Return parsed parts, or ``None`` if ``raw`` is unparseable."""
        if not raw or not isinstance(raw, str):
            return None
        m = _SEMVER_RE.fullmatch(raw)
        if m is None:
            return None
        return cls(
            major=int(m.group("major")),
            minor=int(m.group("minor")),
            patch=int(m.group("patch")),
            pre=m.group("pre") or "",
            build=m.group("build") or "",
        )

    def __str__(self) -> str:
        rendered = f"{self.major}.{self.minor}.{self.patch}"
        if self.pre:
            rendered += f"-{self.pre}"
        if self.build:
            rendered += f"+{self.build}"
        return rendered

    def core_tuple(self) -> tuple[int, int, int]:
        """The numeric core, useful to compatibility callers.

        This is not a complete SemVer ordering key because pre-release
        identifiers require component-wise numeric/string comparison. Use
        :meth:`compare_precedence` when release precedence matters.
        """
        return (self.major, self.minor, self.patch)

    def compare_precedence(self, other: ParsedVersion) -> int:  # noqa: PLR0911
        """Return ``-1``, ``0``, or ``1`` by SemVer 2.0.0 precedence.

        Build metadata is intentionally ignored, as required by SemVer.
        Numeric pre-release identifiers compare numerically and sort before
        non-numeric identifiers; a release without a pre-release component
        sorts after every pre-release of the same numeric core.
        """
        if self.core_tuple() != other.core_tuple():
            return -1 if self.core_tuple() < other.core_tuple() else 1
        if self.pre == other.pre:
            return 0
        if not self.pre:
            return 1
        if not other.pre:
            return -1

        mine = self.pre.split(".")
        theirs = other.pre.split(".")
        for left, right in zip(mine, theirs, strict=False):
            if left == right:
                continue
            left_numeric = left.isdigit()
            right_numeric = right.isdigit()
            if left_numeric and right_numeric:
                return -1 if int(left) < int(right) else 1
            if left_numeric != right_numeric:
                return -1 if left_numeric else 1
            return -1 if left < right else 1
        if len(mine) == len(theirs):
            return 0
        return -1 if len(mine) < len(theirs) else 1


@dataclass
class VersionsSnapshot:
    """A point-in-time snapshot of the latest known z4j versions."""

    schema_version: int
    generated_at: str
    generated_by: str
    canonical_url: str
    packages: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Any) -> VersionsSnapshot:
        """Validate + parse a JSON dict into a snapshot.

        Tolerant of unknown extra fields (we may add them in a
        future schema_version 2 without breaking older brains) but
        strict about the required ones.
        """
        if not isinstance(raw, dict):
            raise ValueError(  # noqa: TRY004  ValueError is this module's validation-error contract
                f"versions.json: root must be a JSON object (got {type(raw).__name__})",
            )
        schema_version = raw.get("schema_version")
        if (
            not isinstance(schema_version, int)
            or isinstance(schema_version, bool)
            or schema_version < 1
        ):
            raise ValueError(
                f"versions.json: missing or invalid schema_version (got {schema_version!r})",
            )
        if schema_version > 1:
            # Forward-compat: log + continue with the fields we know.
            logger.warning(
                "versions.json: unknown schema_version, treating as v1",
                received_schema_version=schema_version,
            )
        packages_raw = raw.get("packages")
        if not isinstance(packages_raw, dict):
            raise ValueError(  # noqa: TRY004  ValueError is this module's validation-error contract, caught by load_bundled
                "versions.json: 'packages' must be a dict of "
                f"{{name: version}} (got {type(packages_raw).__name__})",
            )
        packages: dict[str, str] = {}
        for k, v in packages_raw.items():
            if not isinstance(k, str) or not isinstance(v, str):
                logger.warning(
                    "versions.json: skipping non-string entry",
                    key=str(k),
                    value=str(v),
                )
                continue
            packages[k] = v
        return cls(
            schema_version=schema_version,
            generated_at=str(raw.get("generated_at", "")),
            generated_by=str(raw.get("generated_by", "")),
            canonical_url=str(raw.get("canonical_url", "")),
            packages=packages,
        )

    def latest(self, package: str) -> ParsedVersion | None:
        """Return the parsed latest version for ``package``, or None."""
        raw = self.packages.get(package)
        if raw is None:
            return None
        return ParsedVersion.parse(raw)

    def to_payload(self) -> dict[str, Any]:
        """Round-trip back to a JSON-serializable dict for the API."""
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "generated_by": self.generated_by,
            "canonical_url": self.canonical_url,
            "packages": dict(self.packages),
        }


def load_bundled() -> VersionsSnapshot:
    """Load the snapshot bundled into the brain wheel.

    Always succeeds - if the file is missing or unparseable (which
    would be a packaging defect, not a runtime expectation), returns
    a minimal empty snapshot rather than crashing the brain. The
    dashboard then renders ``unknown`` for every agent's version
    badge instead of breaking the page entirely.
    """
    if not _BUNDLED_PATH.is_file():
        logger.error(
            "z4j: bundled versions.json missing - dashboard "
            "version comparisons will all be 'unknown'. This is a "
            "packaging defect; rebuild the brain wheel.",
            expected_path=str(_BUNDLED_PATH),
        )
        return _empty_snapshot()
    try:
        raw = json.loads(_BUNDLED_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        logger.exception(
            "z4j: bundled versions.json unreadable",
            error=str(exc),
        )
        return _empty_snapshot()
    try:
        return VersionsSnapshot.from_dict(raw)
    except ValueError as exc:
        logger.exception(
            "z4j: bundled versions.json failed validation",
            error=str(exc),
        )
        return _empty_snapshot()


def _empty_snapshot() -> VersionsSnapshot:
    return VersionsSnapshot(
        schema_version=1,
        generated_at="",
        generated_by="",
        canonical_url="",
        packages={},
    )


def compare(  # noqa: PLR0911  version-status dispatch
    agent_version: str | None,
    package: str,
    snapshot: VersionsSnapshot,
) -> VersionStatus:
    """Compare ``agent_version`` against the snapshot's latest known
    for ``package`` and return a status string the dashboard can
    render directly.

    Rules:

    - ``unknown`` - either the agent didn't report a version, the
      version is unparseable, or the snapshot doesn't list this
      package.
    - ``incompatible`` - major version differs (e.g. ``1.x`` agent,
      ``2.x`` snapshot).
    - ``newer_than_known`` - agent's version > snapshot's latest.
      Suggests the operator's brain itself is stale.
    - ``outdated`` - agent < snapshot, same major.
    - ``current`` - equal SemVer precedence. Build metadata does not affect
      precedence, while a pre-release ranks below the corresponding release.
    """
    if not agent_version:
        return "unknown"
    parsed_agent = ParsedVersion.parse(agent_version)
    if parsed_agent is None:
        return "unknown"
    parsed_snap = snapshot.latest(package)
    if parsed_snap is None:
        return "unknown"
    if parsed_agent.major != parsed_snap.major:
        return "incompatible"
    ordering = parsed_agent.compare_precedence(parsed_snap)
    if ordering == 0:
        return "current"
    if ordering > 0:
        return "newer_than_known"
    return "outdated"


# ---------------------------------------------------------------------------
# Operator-initiated remote refresh
# ---------------------------------------------------------------------------


# Strict allow-list of URL schemes for the version-check endpoint.
# We hardcode ``https://`` to make typoed http:// configs noisy at
# startup rather than letting them silently land on a snooped
# connection. Operators who genuinely want unencrypted internal
# mirrors can lift this in a custom build; no path for it in the
# default ship.
_ALLOWED_SCHEME = "https://"

_FETCH_TIMEOUT_SECONDS = 10.0
"""Wall-clock cap on the complete remote fetch.

Tuned for the GitHub raw fetch (typically <500ms), with enough
headroom that a slow internal mirror doesn't cause the operator's
``Check for updates`` click to feel hung. Past 10s the operator
gets a clear error; they can retry.
"""

_MAX_RESPONSE_BYTES = 256 * 1024
"""Hard cap on the bytes we accept from the remote.

The expected payload is small. 256KB gives ample headroom for future schema
growth without exposing the brain
to a hostile mirror that ships a 10MB JSON to OOM the validator.
"""

_STREAM_CHUNK_BYTES = 64 * 1024
"""Maximum decoded chunk requested from the HTTP client."""


@dataclass(frozen=True)
class RefreshResult:
    """Return shape from :func:`fetch_remote`."""

    snapshot: VersionsSnapshot
    fetched_from: str
    fetched_at: datetime


async def _read_remote_body(url: str, *, http_client: Any) -> bytes:
    """Stream one response into a byte buffer that never exceeds the cap."""
    async with http_client.stream(
        "GET",
        url,
        timeout=_FETCH_TIMEOUT_SECONDS,
        # No auth headers: the canonical URL is public. Sending an
        # Authorization header would leak whatever was configured
        # to GitHub or the mirror.
        headers={"Accept": "application/json"},
        follow_redirects=False,
    ) as response:
        if response.status_code != 200:
            raise RuntimeError(
                f"version-check fetch returned HTTP {response.status_code} from {url!r}",
            )
        content_length = response.headers.get("content-length")
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError:
                declared_size = None
            if declared_size is not None and declared_size > _MAX_RESPONSE_BYTES:
                raise RuntimeError(
                    "version-check response too large: declared "
                    f"{declared_size} bytes > cap {_MAX_RESPONSE_BYTES}",
                )

        body = bytearray()
        async for chunk in response.aiter_bytes(chunk_size=_STREAM_CHUNK_BYTES):
            if len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
                raise RuntimeError(
                    "version-check response too large: streamed bytes "
                    f"exceed cap {_MAX_RESPONSE_BYTES}",
                )
            body.extend(chunk)
    return bytes(body)


async def fetch_remote(
    url: str,
    *,
    http_client: Any,  # ``httpx.AsyncClient``-shaped; loose for tests
) -> RefreshResult:
    """Fetch ``url`` and return a parsed snapshot. Raises on any
    failure mode that should keep the previous snapshot in place.

    Failure modes:

    - URL doesn't start with ``https://``: ``ValueError``.
    - HTTP status != 200: ``RuntimeError`` with status code.
    - Response > ``_MAX_RESPONSE_BYTES``: ``RuntimeError``.
    - Response not valid UTF-8 JSON: ``RuntimeError``.
    - JSON fails snapshot validation: ``RuntimeError``.
    - Timeout or transport failure: ``RuntimeError``.

    The caller (the API endpoint) maps these to a user-facing
    error toast; the brain's cached snapshot is unchanged when
    fetch_remote raises.
    """
    if not url:
        raise ValueError("Z4J_VERSION_CHECK_URL is empty; remote check is disabled")
    if not url.startswith(_ALLOWED_SCHEME):
        raise ValueError(
            f"Z4J_VERSION_CHECK_URL must use https:// (got {url!r})",
        )

    try:
        async with asyncio.timeout(_FETCH_TIMEOUT_SECONDS):
            body = await _read_remote_body(url, http_client=http_client)
    except TimeoutError as exc:
        raise RuntimeError(
            f"version-check fetch timed out after {_FETCH_TIMEOUT_SECONDS:g} seconds",
        ) from exc
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(
            f"version-check fetch failed: {type(exc).__name__}: {exc}",
        ) from exc

    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(
            f"version-check response is not valid UTF-8: {exc}",
        ) from exc
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"version-check response is not JSON: {exc}",
        ) from exc
    try:
        snapshot = VersionsSnapshot.from_dict(raw)
    except ValueError as exc:
        raise RuntimeError(
            f"version-check response failed validation: {exc}",
        ) from exc

    return RefreshResult(
        snapshot=snapshot,
        fetched_from=url,
        fetched_at=datetime.now(UTC),
    )


__all__ = [
    "ParsedVersion",
    "RefreshResult",
    "VersionStatus",
    "VersionsSnapshot",
    "compare",
    "fetch_remote",
    "load_bundled",
]
