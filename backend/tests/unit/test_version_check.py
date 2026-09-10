"""Tests for the 1.3.4 version-check pipeline.

Covers:

- ``ParsedVersion.parse``, strict SemVer 2.0 parsing and precedence
- ``VersionsSnapshot.from_dict``, schema validation + forward-compat
- ``compare``, every status branch including the corner cases
- ``load_bundled``, the file-shipped-with-the-wheel path
- ``fetch_remote``, happy path + every documented failure mode
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from itertools import pairwise
from types import TracebackType
from typing import Any

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
            ("1.3.0", (1, 3, 0, "", "")),
            ("0.0.1", (0, 0, 1, "", "")),
            ("10.20.30", (10, 20, 30, "", "")),
            ("1.3.0-alpha", (1, 3, 0, "alpha", "")),
            ("1.3.0-rc.2", (1, 3, 0, "rc.2", "")),
            ("1.3.0-pre.4+build.07", (1, 3, 0, "pre.4", "build.07")),
            ("1.11.0a1", (1, 11, 0, "alpha.1", "")),
            ("1.11.0b2", (1, 11, 0, "beta.2", "")),
            ("1.11.0rc1", (1, 11, 0, "rc.1", "")),
        ],
    )
    def test_parses_well_formed(
        self,
        raw: str,
        expected: tuple[int, int, int, str, str],
    ) -> None:
        result = ParsedVersion.parse(raw)
        assert result is not None
        assert (
            result.major,
            result.minor,
            result.patch,
            result.pre,
            result.build,
        ) == expected
        assert str(result) == raw

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "1.3",  # missing patch
            "v1.3.0",  # leading v
            "1.3.0.0",  # 4-part
            "01.3.0",  # leading zero in core
            "1.03.0",
            "1.3.00",
            "1.3.0rc",  # canonical PyPA prereleases need a numeric suffix
            "1.3.0rc01",  # canonical spellings have no leading zeroes
            "1.3.0-01",  # numeric prerelease identifiers reject leading zero
            "1.3.0-",
            "1.3.0+",
            " 1.3.0",  # strict: no surrounding whitespace
            "1.3.0 ",
            "abc",
            None,
        ],
    )
    def test_rejects_malformed(self, raw: Any) -> None:
        assert ParsedVersion.parse(raw) is None

    def test_semver_precedence_including_prereleases(self) -> None:
        ordered = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ]
        parsed = [ParsedVersion.parse(raw) for raw in ordered]
        assert all(version is not None for version in parsed)
        for left, right in pairwise(parsed):
            assert left is not None and right is not None
            assert left.compare_precedence(right) == -1
            assert right.compare_precedence(left) == 1

    def test_build_metadata_does_not_change_precedence(self) -> None:
        left = ParsedVersion.parse("1.3.0+build.1")
        right = ParsedVersion.parse("1.3.0+build.2")
        assert left is not None and right is not None
        assert left.compare_precedence(right) == 0

    def test_pypa_candidates_sort_numerically_before_stable(self) -> None:
        ordered = ["1.11.0a1", "1.11.0b1", "1.11.0rc2", "1.11.0rc10", "1.11.0"]
        for left_raw, right_raw in pairwise(ordered):
            left = ParsedVersion.parse(left_raw)
            right = ParsedVersion.parse(right_raw)
            assert left is not None and right is not None
            assert left.compare_precedence(right) == -1
            assert right.compare_precedence(left) == 1
        candidate = ParsedVersion.parse("1.11.0rc2")
        semver = ParsedVersion.parse("1.11.0-rc.2")
        assert candidate is not None and semver is not None
        assert candidate.compare_precedence(semver) == 0


class TestVersionsSnapshotFromDict:
    def _payload(self, **overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "schema_version": 1,
            "generated_at": "2026-04-30T15:00:00Z",
            "generated_by": "z4j-brain@1.3.4",
            "canonical_url": ("https://raw.githubusercontent.com/z4jdev/z4j/main/versions.json"),
            "packages": {"z4j-core": "1.3.1", "z4j-brain": "1.3.4"},
        }
        base.update(overrides)
        return base

    def test_well_formed_payload_round_trips(self) -> None:
        snap = VersionsSnapshot.from_dict(self._payload())
        assert snap.schema_version == 1
        assert snap.packages == {
            "z4j-core": "1.3.1",
            "z4j-brain": "1.3.4",
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

    @pytest.mark.parametrize("raw", [[], "not-an-object", None])
    def test_root_must_be_an_object(self, raw: Any) -> None:
        with pytest.raises(ValueError, match="root must be a JSON object"):
            VersionsSnapshot.from_dict(raw)

    def test_boolean_schema_version_is_not_an_integer_version(self) -> None:
        with pytest.raises(ValueError, match="schema_version"):
            VersionsSnapshot.from_dict(self._payload(schema_version=True))

    def test_skips_non_string_package_entries(self) -> None:
        """Forward-compat: a future schema might add structured
        package entries. We tolerate them by skipping rather than
        crashing."""
        bad = self._payload(
            packages={
                "z4j-core": "1.3.1",
                "z4j-brain": {"version": "1.3.4"},  # unsupported shape
                42: "not_a_string_key",
            }
        )
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

    def _snap(self, version: str = "1.3.1") -> VersionsSnapshot:
        return VersionsSnapshot.from_dict(
            {
                "schema_version": 1,
                "generated_at": "2026-04-30T00:00:00Z",
                "generated_by": "z4j-brain@1.3.4",
                "canonical_url": "https://example.test/versions.json",
                "packages": {"z4j-core": version},
            }
        )

    def test_current_when_versions_match(self) -> None:
        assert compare("1.3.1", "z4j-core", self._snap()) == "current"

    def test_outdated_when_agent_older_same_major(self) -> None:
        assert compare("1.3.0", "z4j-core", self._snap()) == "outdated"
        assert compare("1.2.5", "z4j-core", self._snap()) == "outdated"
        assert compare("1.0.0", "z4j-core", self._snap()) == "outdated"

    def test_newer_than_known_when_agent_ahead(self) -> None:
        # Operator's brain has a stale snapshot; agent runs newer.
        assert (
            compare(
                "1.3.5",
                "z4j-core",
                self._snap(),
            )
            == "newer_than_known"
        )
        assert (
            compare(
                "1.4.0",
                "z4j-core",
                self._snap(),
            )
            == "newer_than_known"
        )

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
        assert (
            compare(
                "1.3.0",
                "z4j-mystery",
                self._snap(),
            )
            == "unknown"
        )

    def test_pre_release_ranks_below_the_corresponding_release(self) -> None:
        assert compare("1.3.1-rc.1", "z4j-core", self._snap()) == "outdated"
        assert compare("1.3.1", "z4j-core", self._snap("1.3.1-rc.1")) == "newer_than_known"

    def test_build_metadata_does_not_create_a_false_difference(self) -> None:
        assert compare("1.3.1+agent.4", "z4j-core", self._snap("1.3.1+snapshot.9")) == "current"


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


class _StreamingResponse:
    """Minimal response whose body is available only as a stream."""

    def __init__(
        self,
        status_code: int,
        chunks: list[bytes],
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self._chunks = chunks
        self.chunks_yielded = 0

    @property
    def content(self) -> bytes:
        raise AssertionError("fetch_remote must not buffer response.content")

    async def aiter_bytes(self, *, chunk_size: int) -> AsyncIterator[bytes]:
        assert chunk_size > 0
        for chunk in self._chunks:
            self.chunks_yielded += 1
            yield chunk


class _StreamContext:
    def __init__(self, response: _StreamingResponse) -> None:
        self._response = response

    async def __aenter__(self) -> _StreamingResponse:
        return self._response

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None


class _StreamingClient:
    def __init__(self, response: _StreamingResponse) -> None:
        self.response = response
        self.requests: list[tuple[str, str, dict[str, Any]]] = []

    def stream(self, method: str, url: str, **kwargs: Any) -> _StreamContext:
        self.requests.append((method, url, kwargs))
        return _StreamContext(self.response)


@pytest.mark.asyncio
class TestFetchRemote:
    """The operator-initiated *Check for updates* fetch."""

    def _good_payload(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "generated_at": "2026-05-01T00:00:00Z",
            "generated_by": "z4j-brain@1.3.5",
            "canonical_url": ("https://raw.githubusercontent.com/z4jdev/z4j/main/versions.json"),
            "packages": {"z4j-core": "1.3.2", "z4j-brain": "1.3.5"},
        }

    async def test_happy_path_returns_parsed_snapshot(self) -> None:
        payload = json.dumps(self._good_payload()).encode()
        response = _StreamingResponse(
            200,
            [payload[:11], payload[11:]],
        )
        client = _StreamingClient(response)
        result = await fetch_remote(
            "https://example.test/versions.json",
            http_client=client,
        )
        assert result.snapshot.packages["z4j-core"] == "1.3.2"
        assert result.fetched_from == "https://example.test/versions.json"
        assert response.chunks_yielded == 2
        assert client.requests[0][0] == "GET"

    async def test_empty_url_raises_value_error(self) -> None:
        client = _StreamingClient(_StreamingResponse(200, []))
        with pytest.raises(ValueError, match="empty"):
            await fetch_remote("", http_client=client)

    async def test_non_https_url_raises_value_error(self) -> None:
        client = _StreamingClient(_StreamingResponse(200, []))
        with pytest.raises(ValueError, match="https"):
            await fetch_remote(
                "http://example.test/v.json",
                http_client=client,
            )

    async def test_non_200_raises_runtime_error(self) -> None:
        client = _StreamingClient(_StreamingResponse(404, []))
        with pytest.raises(RuntimeError, match="HTTP 404"):
            await fetch_remote(
                "https://example.test/v.json",
                http_client=client,
            )

    async def test_invalid_json_raises_runtime_error(self) -> None:
        client = _StreamingClient(_StreamingResponse(200, [b"not json at all"]))
        with pytest.raises(RuntimeError, match="not JSON"):
            await fetch_remote(
                "https://example.test/v.json",
                http_client=client,
            )

    async def test_oversized_response_raises_runtime_error(self) -> None:
        response = _StreamingResponse(
            200,
            [b"x" * (200 * 1024), b"y" * (100 * 1024), b"not-read"],
        )
        client = _StreamingClient(response)
        with pytest.raises(RuntimeError, match="too large"):
            await fetch_remote(
                "https://example.test/v.json",
                http_client=client,
            )
        assert response.chunks_yielded == 2

    async def test_oversized_declared_length_is_rejected_before_reading(self) -> None:
        response = _StreamingResponse(
            200,
            [b"not-read"],
            headers={"content-length": str(300 * 1024)},
        )
        with pytest.raises(RuntimeError, match="declared"):
            await fetch_remote(
                "https://example.test/v.json",
                http_client=_StreamingClient(response),
            )
        assert response.chunks_yielded == 0

    async def test_invalid_utf8_raises_runtime_error(self) -> None:
        client = _StreamingClient(_StreamingResponse(200, [b'{"x":"\xff"}']))
        with pytest.raises(RuntimeError, match="not valid UTF-8"):
            await fetch_remote(
                "https://example.test/v.json",
                http_client=client,
            )

    async def test_json_root_must_be_an_object(self) -> None:
        client = _StreamingClient(_StreamingResponse(200, [b"[]"]))
        with pytest.raises(RuntimeError, match="root must be a JSON object"):
            await fetch_remote(
                "https://example.test/v.json",
                http_client=client,
            )

    async def test_invalid_schema_raises_runtime_error(self) -> None:
        bad = json.dumps({"packages": {"z4j-core": "1.3.0"}}).encode()  # missing schema_version
        client = _StreamingClient(_StreamingResponse(200, [bad]))
        with pytest.raises(RuntimeError, match="failed validation"):
            await fetch_remote(
                "https://example.test/v.json",
                http_client=client,
            )
