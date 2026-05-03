"""Version freshness checks for the dashboard's *Update available*
badge on the Agents page.

Privacy posture (1.3.4 design):

- The brain SHIPS with a bundled snapshot of the latest known
  versions of every z4j package, generated from
  ``sites/_shared/packages.ts`` at brain release time. This file
  is loaded at startup and used for every comparison by default.
  No network call. Air-gapped friendly.
- An operator can click *Settings -> Check for updates* to fetch
  a fresher snapshot from GitHub
  (``https://raw.githubusercontent.com/z4jdev/z4j/main/versions.json``).
  This is the ONLY case where the brain reaches out, and it's
  always operator-initiated. Result is cached in process memory
  so subsequent comparisons use the fresh data until the next
  restart.
- Operators who want zero outbound HTTP can set
  ``Z4J_VERSION_CHECK_URL`` empty; the dashboard hides the
  *Check for updates* button entirely and the bundled snapshot
  is the source of truth.
- Air-gapped operators with an internal mirror set
  ``Z4J_VERSION_CHECK_URL=https://internal-mirror/versions.json``.

There is no automatic background polling. There is no telemetry.
"""

from __future__ import annotations

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

#: Strict SemVer + optional pre-release tail. Matches the format
#: every z4j package emits: ``MAJOR.MINOR.PATCH`` plus an optional
#: ``-pre.N`` / ``rc1`` style suffix. We only care about the three
#: numeric components for ordering; the suffix is informational.
#: Pre-release tail must start with a letter or ``-``. Forbidding a
#: leading ``.`` rejects malformed 4-part inputs like ``1.3.0.0``
#: instead of silently parsing them as ``1.3.0`` with pre=".0" (which
#: would then rank EQUAL to the 3-part version under ``core_tuple``,
#: causing a 4-part agent to be wrongly badged ``current``).
_SEMVER_RE = re.compile(
    r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    r"(?P<pre>(?:[a-z-][a-z0-9.+-]*)?)$",
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

    @classmethod
    def parse(cls, raw: str) -> ParsedVersion | None:
        """Return parsed parts, or ``None`` if ``raw`` is unparseable."""
        if not raw or not isinstance(raw, str):
            return None
        m = _SEMVER_RE.match(raw.strip())
        if m is None:
            return None
        return cls(
            major=int(m.group("major")),
            minor=int(m.group("minor")),
            patch=int(m.group("patch")),
            pre=m.group("pre") or "",
        )

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}{self.pre}"

    def core_tuple(self) -> tuple[int, int, int]:
        """Comparison key on the numeric trio only.

        We deliberately ignore pre-release suffixes when ranking:
        an operator running ``1.3.0`` against a snapshot of
        ``1.3.0rc1`` is *current* in the operationally relevant sense.
        Pre-release semantics aren't worth a TODO list of edge cases
        when the simpler rule works for every release we ship.
        """
        return (self.major, self.minor, self.patch)


@dataclass
class VersionsSnapshot:
    """A point-in-time snapshot of the latest known z4j versions."""

    schema_version: int
    generated_at: str
    generated_by: str
    canonical_url: str
    packages: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> VersionsSnapshot:
        """Validate + parse a JSON dict into a snapshot.

        Tolerant of unknown extra fields (we may add them in a
        future schema_version 2 without breaking older brains) but
        strict about the required ones.
        """
        schema_version = raw.get("schema_version")
        if not isinstance(schema_version, int) or schema_version < 1:
            raise ValueError(
                "versions.json: missing or invalid schema_version "
                f"(got {schema_version!r})",
            )
        if schema_version > 1:
            # Forward-compat: log + continue with the fields we know.
            logger.warning(
                "versions.json: unknown schema_version, treating as v1",
                received_schema_version=schema_version,
            )
        packages_raw = raw.get("packages")
        if not isinstance(packages_raw, dict):
            raise ValueError(
                "versions.json: 'packages' must be a dict of "
                f"{{name: version}} (got {type(packages_raw).__name__})",
            )
        packages: dict[str, str] = {}
        for k, v in packages_raw.items():
            if not isinstance(k, str) or not isinstance(v, str):
                logger.warning(
                    "versions.json: skipping non-string entry",
                    key=str(k), value=str(v),
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
    except (OSError, json.JSONDecodeError) as exc:
        logger.error(
            "z4j: bundled versions.json unreadable",
            error=str(exc),
        )
        return _empty_snapshot()
    try:
        return VersionsSnapshot.from_dict(raw)
    except ValueError as exc:
        logger.error(
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


def compare(
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
      ``2.x`` snapshot). This is the only RED badge.
    - ``newer_than_known`` - agent's version > snapshot's latest.
      Suggests the operator's brain itself is stale.
    - ``outdated`` - agent < snapshot, same major. Yellow badge.
    - ``current`` - agent == snapshot. Green / no badge.
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
    a = parsed_agent.core_tuple()
    s = parsed_snap.core_tuple()
    if a == s:
        return "current"
    if a > s:
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
"""Hard cap on how long the brain waits for the remote fetch.

Tuned for the GitHub raw fetch (typically <500ms), with enough
headroom that a slow internal mirror doesn't cause the operator's
``Check for updates`` click to feel hung. Past 10s the operator
gets a clear error; they can retry.
"""

_MAX_RESPONSE_BYTES = 256 * 1024
"""Hard cap on the bytes we accept from the remote.

The expected payload is ~2KB (20 packages, JSON). 256KB gives a
1000x headroom for future schema growth without exposing the brain
to a hostile mirror that ships a 10MB JSON to OOM the validator.
"""


@dataclass(frozen=True)
class RefreshResult:
    """Return shape from :func:`fetch_remote`."""

    snapshot: VersionsSnapshot
    fetched_from: str
    fetched_at: datetime


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
    - Response not valid JSON: ``RuntimeError``.
    - JSON fails snapshot validation: ``RuntimeError``.

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

    response = await http_client.get(
        url,
        timeout=_FETCH_TIMEOUT_SECONDS,
        # No auth headers: the canonical URL is public. Sending an
        # Authorization header would leak whatever was configured
        # to GitHub or the mirror.
        headers={"Accept": "application/json"},
        follow_redirects=False,
    )
    if response.status_code != 200:
        raise RuntimeError(
            f"version-check fetch returned HTTP {response.status_code} "
            f"from {url!r}",
        )
    body = response.content
    if len(body) > _MAX_RESPONSE_BYTES:
        raise RuntimeError(
            f"version-check response too large: "
            f"{len(body)} bytes > cap {_MAX_RESPONSE_BYTES}",
        )
    try:
        raw = json.loads(body)
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
