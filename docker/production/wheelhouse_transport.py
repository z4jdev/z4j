#!/usr/bin/env python3
"""Credential-free transport boundary for neutral wheel acquisition.

No concrete HTTP client, credential source, repository identity, workflow
identity, or operation gate is defined here.  Production reachability remains
fail-closed until an independently reviewed public-acquisition adapter is
provided.  Tests use in-memory transports only.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, NoReturn, Protocol

MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_WHEEL_BYTES = 512 * 1024 * 1024


class WheelhouseTransportError(RuntimeError):
    """A public response escaped the closed credential-free transport contract."""


def _die(message: str) -> NoReturn:
    raise WheelhouseTransportError(message)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _die(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def _reject_number(value: str) -> NoReturn:
    _die(f"non-integer JSON number {value!r} is forbidden")


def _parse_object(raw: bytes, context: str) -> dict[str, Any]:
    if not raw or raw.startswith(b"\xef\xbb\xbf"):
        _die(f"{context} is empty or has a forbidden UTF-8 BOM")
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WheelhouseTransportError(f"{context} is not strict object JSON: {exc}") from exc
    if not isinstance(value, dict):
        _die(f"{context} is not one JSON object")
    return value


def _content_type(headers: Mapping[str, str]) -> str:
    raw = headers.get("content-type", "")
    return raw.split(";", 1)[0].strip().lower()


@dataclass(frozen=True)
class HttpResponse:
    """Secret-free response projection returned by a public-only adapter."""

    status: int
    url: str
    headers: Mapping[str, str]
    body: bytes

    def normalized(self) -> HttpResponse:
        if isinstance(self.status, bool) or not isinstance(self.status, int):
            _die("public HTTP response status is not an integer")
        if not isinstance(self.url, str) or not self.url:
            _die("public HTTP response URL is absent")
        if not isinstance(self.body, bytes):
            _die("public HTTP response body is not bytes")
        normalized: dict[str, str] = {}
        for raw_name, raw_value in self.headers.items():
            if not isinstance(raw_name, str) or not isinstance(raw_value, str):
                _die("public HTTP response headers are not text")
            name = raw_name.strip().lower()
            value = raw_value.strip()
            if (
                not name
                or name in normalized
                or re.fullmatch(r"[a-z0-9!#$%&'*+.^_`|~-]+", name) is None
                or any(character in raw_value for character in "\r\n\0")
            ):
                _die("public HTTP response headers are ambiguous")
            normalized[name] = value
        content_length = normalized.get("content-length")
        if content_length is not None and (
            not content_length.isascii()
            or not content_length.isdecimal()
            or int(content_length) != len(self.body)
        ):
            _die("public HTTP response Content-Length differs")
        return HttpResponse(self.status, self.url, normalized, self.body)


class PublicTransport(Protocol):
    """Unrealized adapter seam: callers may issue only credential-free GETs."""

    def request_public(self, url: str, *, accept: str, maximum: int) -> HttpResponse: ...


class PublicPyPI:
    """No-redirect PyPI Simple 1.0..1.4, wheel, and PEP 658 client."""

    SIMPLE_MEDIA_TYPE = "application/vnd.pypi.simple.v1+json"
    OCTET_STREAM = "application/octet-stream"

    def __init__(self, *, transport: PublicTransport) -> None:
        self._transport = transport

    @staticmethod
    def _validated_url(url: str, *, origins: set[str]) -> urllib.parse.SplitResult:
        parsed = urllib.parse.urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.netloc not in origins
        ):
            _die("PyPI acquisition URL is outside the fixed credential-free origins")
        return parsed

    def _request(self, url: str, *, accept: str, maximum: int) -> HttpResponse:
        self._validated_url(url, origins={"pypi.org", "files.pythonhosted.org"})
        if maximum <= 0:
            _die("PyPI acquisition size bound differs")
        response = self._transport.request_public(
            url,
            accept=accept,
            maximum=maximum,
        ).normalized()
        if (
            response.status != 200
            or response.url != url
            or len(response.body) > maximum
            or "location" in response.headers
        ):
            _die("PyPI acquisition status, size, or no-redirect boundary differs")
        return response

    def simple(  # noqa: PLR0912 - closed versioned Simple schema
        self, normalized_name: str
    ) -> tuple[HttpResponse, dict[str, Any]]:
        expected_name = re.sub(r"[-_.]+", "-", normalized_name).lower()
        if (
            normalized_name != expected_name
            or re.fullmatch(r"[a-z0-9][a-z0-9-]*", expected_name) is None
        ):
            _die("PEP 503 normalized project name differs")
        url = f"https://pypi.org/simple/{expected_name}/"
        response = self._request(
            url,
            accept=self.SIMPLE_MEDIA_TYPE,
            maximum=MAX_JSON_BYTES,
        )
        if _content_type(response.headers) != self.SIMPLE_MEDIA_TYPE:
            _die("PyPI Simple response media type differs")
        value = _parse_object(response.body, f"PyPI Simple {expected_name} response")
        meta = value.get("meta")
        if not isinstance(meta, dict) or set(meta) != {"api-version"}:
            _die("PyPI Simple response omits exact meta")
        match = re.fullmatch(r"1\.(0|1|2|3|4)", str(meta.get("api-version")))
        if match is None:
            _die("PyPI Simple API version is outside the reviewed exact 1.0..1.4 range")
        minor = int(match.group(1))
        allowed_keys = {"files", "meta", "name"}
        if minor >= 1:
            allowed_keys.add("versions")
        if minor >= 2:
            allowed_keys.add("alternate-locations")
        if minor >= 4:
            allowed_keys.add("project-status")
        if set(value) != allowed_keys:
            _die("PyPI Simple response has unknown or version-inconsistent fields")
        if re.sub(r"[-_.]+", "-", str(value.get("name"))).lower() != expected_name:
            _die("PyPI Simple response project identity differs")
        if not isinstance(value.get("files"), list):
            _die("PyPI Simple response files inventory differs")
        if minor >= 1 and not isinstance(value["versions"], list):
            _die("PyPI Simple versions inventory differs")
        if minor >= 2 and value["alternate-locations"] != []:
            _die("PyPI Simple alternate locations are forbidden")
        if minor >= 4 and value["project-status"] != {"reason": None, "status": "active"}:
            _die("PyPI Simple 1.4 project status is not active")
        return response, value

    @classmethod
    def _wheel_url(cls, url: str) -> urllib.parse.SplitResult:
        parsed = cls._validated_url(url, origins={"files.pythonhosted.org"})
        if not parsed.path.endswith(".whl") or parsed.path.endswith("/.whl"):
            _die("selected PyPI wheel URL differs from files.pythonhosted.org")
        return parsed

    def wheel(self, url: str, *, maximum: int = MAX_WHEEL_BYTES) -> HttpResponse:
        self._wheel_url(url)
        return self._request(url, accept=self.OCTET_STREAM, maximum=maximum)

    def metadata(self, wheel_url: str, *, maximum: int = MAX_METADATA_BYTES) -> HttpResponse:
        """Fetch the exact PEP 658 sidecar derived from a selected wheel URL."""

        self._wheel_url(wheel_url)
        response = self._request(
            wheel_url + ".metadata",
            accept=self.OCTET_STREAM,
            maximum=maximum,
        )
        if not response.body or _content_type(response.headers) != self.OCTET_STREAM:
            _die("PEP 658 core metadata response media type or body differs")
        return response
