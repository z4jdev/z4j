"""Tests for the 1.3.4 version-check pipeline.

Covers:

- ``ParsedVersion.parse``, SemVer extraction, tolerant of suffixes
- ``VersionsSnapshot.from_dict``, schema validation + forward-compat
- ``compare``, every status branch including the corner cases
- ``load_bundled``, the file-shipped-with-the-wheel path
- ``fetch_remote``, happy path + every documented failure mode
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from z4j_brain.domain.version_check import (
    ParsedVersion,
    VersionsSnapshot,
    compare,
    fetch_remote,
    load_bundled,
)


class TestParsedVersion:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("1.3.0", (1, 3, 0, "")),
            ("0.0.1", (0, 0, 1, "")),
            ("10.20.30", (10, 20, 30, "")),
            ("1.3.0a1", (1, 3, 0, "a1")),
            ("1.3.0rc2", (1, 3, 0, "rc2")),
            ("1.3.0-pre.4", (1, 3, 0, "-pre.4")),
            ("  1.3.0  ", (1, 3, 0, "")),  # surrounding whitespace OK
        ],
    )
    def test_parses_well_formed(
        self, raw: str, expected: tuple[int, int, int, str],
    ) -> None:
        result = ParsedVersion.parse(raw)
        assert result is not None
        assert (
            result.major, result.minor, result.patch, result.pre,
        ) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "1.3",         # missing patch
            "v1.3.0",      # leading v
            "1.3.0.0",     # 4-part
            "abc",
            None,
        ],
    )
    def test_rejects_malformed(self, raw: Any) -> None:
        assert ParsedVersion.parse(raw) is None

    def test_core_tuple_ignores_pre_release(self) -> None:
        """``1.3.0`` and ``1.3.0rc1`` rank equal for our purposes -
        the dashboard would otherwise flag every operator running
        a stable release as ``newer_than_known`` after we ship an rc."""
        a = ParsedVersion.parse("1.3.0")
        b = ParsedVersion.parse("1.3.0rc1")
        assert a is not None and b is not None
        assert a.core_tuple() == b.core_tuple()


class TestVersionsSnapshotFromDict:
    def _payload(self, **overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "schema_version": 1,
            "generated_at": "2026-04-30T15:00:00Z",
            "generated_by": "z4j-brain@1.3.4",
            "canonical_url": (
                "https://raw.githubusercontent.com/z4jdev/z4j/main/"
                "versions.json"
            ),
            "packages": {"z4j-core": "1.3.1", "z4j-brain": "1.3.4"},
        }
        base.update(overrides)
        return base

    def test_well_formed_payload_round_trips(self) -> None:
        snap = VersionsSnapshot.from_dict(self._payload())
        assert snap.schema_version == 1
        assert snap.packages == {
            "z4j-core": "1.3.1", "z4j-brain": "1.3.4",
        }
        # Round-trip through to_payload preserves shape.
        again = VersionsSnapshot.from_dict(snap.to_payload())
        assert again.packages == snap.packages

    def test_missing_schema_version_raises(self) -> None:
        bad = self._payload()
        del bad["schema_version"]
        with pytest.raises(ValueError, match="schema_version"):
            VersionsSnapshot.from_dict(bad)

    def test_packages_must_be_dict(self) -> None:
        bad = self._payload(packages=["not", "a", "dict"])
        with pytest.raises(ValueError, match="must be a dict"):
            VersionsSnapshot.from_dict(bad)

    def test_skips_non_string_package_entries(self) -> None:
        """Forward-compat: a future schema might add structured
        package entries. We tolerate them by skipping rather than
        crashing."""
        bad = self._payload(packages={
            "z4j-core": "1.3.1",
            "z4j-brain": {"version": "1.3.4"},  # unsupported shape
            42: "not_a_string_key",
        })
        snap = VersionsSnapshot.from_dict(bad)
        assert snap.packages == {"z4j-core": "1.3.1"}

    def test_unknown_schema_version_warns_but_loads(self) -> None:
        """schema_version 99 → still parses everything we recognize."""
        snap = VersionsSnapshot.from_dict(self._payload(schema_version=99))
        assert snap.schema_version == 99
        assert "z4j-core" in snap.packages

    def test_latest_returns_parsed_version(self) -> None:
        snap = VersionsSnapshot.from_dict(self._payload())
        assert snap.latest("z4j-core") == ParsedVersion(1, 3, 1, "")
        assert snap.latest("does-not-exist") is None


class TestCompare:
    """The badge logic the dashboard renders against."""

    def _snap(self) -> VersionsSnapshot:
        return VersionsSnapshot.from_dict({
            "schema_version": 1,
            "generated_at": "2026-04-30T00:00:00Z",
            "generated_by": "z4j-brain@1.3.4",
            "canonical_url": "https://example.test/versions.json",
            "packages": {"z4j-core": "1.3.1"},
        })

    def test_current_when_versions_match(self) -> None:
        assert compare("1.3.1", "z4j-core", self._snap()) == "current"

    def test_outdated_when_agent_older_same_major(self) -> None:
        assert compare("1.3.0", "z4j-core", self._snap()) == "outdated"
        assert compare("1.2.5", "z4j-core", self._snap()) == "outdated"
        assert compare("1.0.0", "z4j-core", self._snap()) == "outdated"

    def test_newer_than_known_when_agent_ahead(self) -> None:
        # Operator's brain has a stale snapshot; agent runs newer.
        assert compare(
            "1.3.5", "z4j-core", self._snap(),
        ) == "newer_than_known"
        assert compare(
            "1.4.0", "z4j-core", self._snap(),
        ) == "newer_than_known"

    def test_incompatible_on_major_mismatch(self) -> None:
        assert compare("2.0.0", "z4j-core", self._snap()) == "incompatible"
        assert compare("0.9.0", "z4j-core", self._snap()) == "incompatible"

    def test_unknown_when_agent_version_missing(self) -> None:
        assert compare(None, "z4j-core", self._snap()) == "unknown"
        assert compare("", "z4j-core", self._snap()) == "unknown"

    def test_unknown_when_agent_version_unparseable(self) -> None:
        assert compare("garbage", "z4j-core", self._snap()) == "unknown"
        assert compare("v1.3.0", "z4j-core", self._snap()) == "unknown"

    def test_unknown_when_package_not_in_snapshot(self) -> None:
        assert compare(
            "1.3.0", "z4j-mystery", self._snap(),
        ) == "unknown"

    def test_pre_release_does_not_create_outdated_noise(self) -> None:
        """Operator runs ``1.3.1`` against a snapshot of ``1.3.1``.
        Pre-release agent at ``1.3.1rc1`` should rank ``current`` -
        not ``outdated``. (Edge case after a future rc cycle.)"""
        assert compare(
            "1.3.1rc1", "z4j-core", self._snap(),
        ) == "current"


class TestLoadBundled:
    """The path that reads ``z4j_brain/data/versions.json`` from the
    installed package. We can't easily monkey-patch the path constant
    so we just sanity-check that the file shipped with the brain in
    this repo loads correctly."""

    def test_bundled_file_loads_and_lists_z4j_brain(self) -> None:
        snap = load_bundled()
        # Even if the file is missing or malformed the function
        # returns an empty snapshot rather than crashing, but the
        # repo's checked-in copy SHOULD be valid.
        assert snap.schema_version == 1
        assert "z4j-brain" in snap.packages, (
            f"z4j-brain missing from bundled snapshot, regenerate "
            f"with ``python scripts/gen-versions-json.py``. "
            f"Loaded packages: {sorted(snap.packages.keys())}"
        )


@pytest.mark.asyncio
class TestFetchRemote:
    """The operator-initiated *Check for updates* fetch."""

    def _good_payload(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "generated_at": "2026-05-01T00:00:00Z",
            "generated_by": "z4j-brain@1.3.5",
            "canonical_url": (
                "https://raw.githubusercontent.com/z4jdev/z4j/main/"
                "versions.json"
            ),
            "packages": {"z4j-core": "1.3.2", "z4j-brain": "1.3.5"},
        }

    async def test_happy_path_returns_parsed_snapshot(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = httpx.Response(
            200, content=json.dumps(self._good_payload()).encode(),
        )
        result = await fetch_remote(
            "https://example.test/versions.json", http_client=client,
        )
        assert result.snapshot.packages["z4j-core"] == "1.3.2"
        assert result.fetched_from == "https://example.test/versions.json"

    async def test_empty_url_raises_value_error(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        with pytest.raises(ValueError, match="empty"):
            await fetch_remote("", http_client=client)

    async def test_non_https_url_raises_value_error(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        with pytest.raises(ValueError, match="https"):
            await fetch_remote(
                "http://example.test/v.json", http_client=client,
            )

    async def test_non_200_raises_runtime_error(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = httpx.Response(404, content=b"")
        with pytest.raises(RuntimeError, match="HTTP 404"):
            await fetch_remote(
                "https://example.test/v.json", http_client=client,
            )

    async def test_invalid_json_raises_runtime_error(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = httpx.Response(
            200, content=b"not json at all",
        )
        with pytest.raises(RuntimeError, match="not JSON"):
            await fetch_remote(
                "https://example.test/v.json", http_client=client,
            )

    async def test_oversized_response_raises_runtime_error(self) -> None:
        big = b"x" * (300 * 1024)  # 300KB > 256KB cap
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = httpx.Response(200, content=big)
        with pytest.raises(RuntimeError, match="too large"):
            await fetch_remote(
                "https://example.test/v.json", http_client=client,
            )

    async def test_invalid_schema_raises_runtime_error(self) -> None:
        bad = json.dumps({"packages": {"z4j-core": "1.3.0"}}).encode()  # missing schema_version
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = httpx.Response(200, content=bad)
        with pytest.raises(RuntimeError, match="failed validation"):
            await fetch_remote(
                "https://example.test/v.json", http_client=client,
            )
