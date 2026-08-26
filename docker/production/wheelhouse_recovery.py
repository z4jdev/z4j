#!/usr/bin/env python3
"""Architecture-neutral authority discovery and crash recovery mechanics.

The module has no concrete registry transport, repository, credentials,
publisher, signer, workflow identity, operation gate, or CLI.  A selected
authority architecture must provide and independently audit the Registry
adapter before these algorithms can become live.  In-memory fakes are the only
current consumers.
"""

from __future__ import annotations

import base64
import json
import re
import time
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, NoReturn, Protocol

MAX_JSON_BYTES = 16 * 1024 * 1024
OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCTET_STREAM = "application/octet-stream"


class WheelhouseRecoveryError(RuntimeError):
    """Registry evidence is incomplete, ambiguous, substituted, or unsafe."""


# Compatibility name retained inside the reviewed recovery algorithm only.
TransportError = WheelhouseRecoveryError


def _die(message: str) -> NoReturn:
    raise WheelhouseRecoveryError(message)


def sha256(raw: bytes) -> str:
    import hashlib

    return hashlib.sha256(raw).hexdigest()


def digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw)


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
    if not raw or len(raw) > MAX_JSON_BYTES or raw.startswith(b"\xef\xbb\xbf"):
        _die(f"{context} is empty, oversized, or has a forbidden BOM")
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WheelhouseRecoveryError(f"{context} is not strict object JSON: {exc}") from exc
    if not isinstance(value, dict):
        _die(f"{context} is not one JSON object")
    return value


def _oci_digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or OCI_DIGEST.fullmatch(value) is None:
        _die(f"{context} is not one lowercase SHA-256 OCI digest")
    return value


def _same_origin_url(url: str, *, origin: str, prefix: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    expected = urllib.parse.urlsplit(origin)
    if (
        parsed.scheme != expected.scheme
        or parsed.netloc != expected.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith(prefix)
    ):
        _die("registry response URL escaped its fixed credential-free origin")
    return url


class HttpResponse(Protocol):
    status: int
    url: str
    headers: Mapping[str, str]
    body: bytes

    def normalized(self) -> HttpResponse: ...


class Registry(Protocol):
    """Unrealized registry seam; no live implementation exists in this source."""

    def tags(self, *, pattern: str) -> list[str]: ...

    def referrer_pages(
        self, subject_digest: str, *, artifact_type: str
    ) -> Sequence[HttpResponse]: ...

    def manifest(self, reference: str, *, media_type: str, operation: str) -> HttpResponse: ...

    def optional_manifest(
        self, reference: str, *, media_type: str, operation: str
    ) -> HttpResponse | None: ...

    def blob(self, digest_value: str, *, operation: str) -> HttpResponse: ...

    def upload_blob(self, raw: bytes, *, operation: str) -> Any: ...

    def put_manifest(
        self,
        reference: str,
        raw: bytes,
        *,
        media_type: str,
        subject_digest: str,
        operation: str,
    ) -> HttpResponse: ...


def _referrer_descriptors(raw: bytes, *, artifact_type: str) -> list[dict[str, Any]]:
    value = _parse_object(raw, "native referrers response")
    if set(value) != {"manifests", "mediaType", "schemaVersion"}:
        _die("native referrers response keys differ")
    if value["mediaType"] != OCI_INDEX or value["schemaVersion"] != 2:
        _die("native referrers response media/schema differs")
    manifests = value["manifests"]
    if not isinstance(manifests, list):
        _die("native referrers manifests is not an array")
    descriptors: list[dict[str, Any]] = []
    for index, item in enumerate(manifests):
        if not isinstance(item, dict):
            _die(f"native referrer descriptor {index} is not an object")
        allowed = {"annotations", "artifactType", "digest", "mediaType", "size"}
        if set(item) - allowed or not {"artifactType", "digest", "mediaType", "size"} <= set(item):
            _die(f"native referrer descriptor {index} shape differs")
        if (
            item["artifactType"] != artifact_type
            or item["mediaType"] != OCI_MANIFEST
            or isinstance(item["size"], bool)
            or not isinstance(item["size"], int)
            or item["size"] <= 0
        ):
            _die(f"native referrer descriptor {index} identity differs")
        _oci_digest(item["digest"], f"native referrer descriptor {index} digest")
        if "annotations" in item and not isinstance(item["annotations"], dict):
            _die(f"native referrer descriptor {index} annotations differ")
        descriptors.append(item)
    return descriptors


def manifest_response_record(response: HttpResponse, *, request_accept: str) -> dict[str, Any]:
    """Create the secret-free exact OCI manifest response carrier."""

    response = response.normalized()
    observed = response.headers.get("docker-content-digest")
    if response.status != 200 or observed != digest(response.body):
        _die("raw OCI manifest response digest/status differs")
    return {
        "body_base64": base64.b64encode(response.body).decode("ascii"),
        "body_sha256": sha256(response.body),
        "body_size": len(response.body),
        "docker_content_digest": observed,
        "method": "GET",
        "request_accept": request_accept,
        "response_content_type": response.headers.get("content-type", ""),
        "status": response.status,
        "url": response.url,
    }


def blob_response_record(response: HttpResponse) -> dict[str, Any]:
    response = response.normalized()
    observed = digest(response.body)
    if response.status != 200:
        _die("raw OCI blob response status differs")
    return {
        "docker_content_digest": observed,
        "method": "GET",
        "request_accept": OCTET_STREAM,
        "sha256": sha256(response.body),
        "size": len(response.body),
        "status": 200,
        "url": response.url,
    }


def put_response_record(
    response: HttpResponse,
    *,
    expected_digest: str,
    expected_subject: str | None,
) -> dict[str, Any]:
    response = response.normalized()
    location = response.headers.get("location")
    if not location:
        _die("OCI manifest PUT response omits Location")
    request_url = urllib.parse.urlsplit(response.url)
    if (
        request_url.scheme != "https"
        or not request_url.netloc
        or request_url.username
        or request_url.password
        or request_url.query
        or request_url.fragment
    ):
        _die("OCI manifest PUT request URL is not one credential-free HTTPS origin")
    registry_origin = urllib.parse.urlunsplit(("https", request_url.netloc, "", "", ""))
    absolute_location = urllib.parse.urljoin(registry_origin, location)
    _same_origin_url(absolute_location, origin=registry_origin, prefix="/v2/")
    retained_location = urllib.parse.urlsplit(absolute_location)
    if "/manifests/" not in request_url.path:
        _die("OCI manifest PUT request URL shape differs")
    repository_prefix = request_url.path.rsplit("/manifests/", 1)[0]
    if (
        retained_location.path != repository_prefix + "/manifests/" + expected_digest
        or retained_location.query
        or retained_location.fragment
        or retained_location.username
        or retained_location.password
    ):
        _die("OCI manifest PUT Location is not the exact credential-free digest path")
    if (
        response.status != 201
        or response.headers.get("docker-content-digest") != expected_digest
        or response.headers.get("oci-subject") != expected_subject
    ):
        _die("OCI manifest PUT response digest/subject/status differs")
    return {
        "docker_content_digest": expected_digest,
        "location": absolute_location,
        "oci_subject": expected_subject,
        "status": 201,
        "url": response.url,
    }


@dataclass(frozen=True)
class AuthorityCandidate:
    tag: str
    manifest: bytes
    receipt: bytes
    bundle: bytes
    referrer_indexed: bool
    tag_present: bool = True


@dataclass(frozen=True)
class AuthorityDiscovery:
    """One complete tag-first plus native-referrer enumeration snapshot."""

    candidates: tuple[AuthorityCandidate, ...]
    referrers: tuple[tuple[str, int], ...]
    tags: tuple[str, ...]


def discover_authority_candidates(  # noqa: PLR0915 - closed candidate byte schema
    registry: Registry,
    *,
    subject_digest: str,
    authority_tag_pattern: str,
    authority_tag_prefix: str,
    artifact_type: str,
    receipt_media_type: str,
    bundle_media_type: str,
) -> AuthorityDiscovery:
    """Fetch the complete union of version tags and native referrers for S."""

    if re.fullmatch(r"[a-z0-9][a-z0-9_.-]*-", authority_tag_prefix) is None:
        _die("authority recovery tag prefix/pattern contract differs")
    canonical_pattern = "^" + re.escape(authority_tag_prefix).replace(r"\-", "-") + "[0-9a-f]{64}$"
    if authority_tag_pattern != canonical_pattern:
        _die("authority recovery tag prefix/pattern contract differs")

    tags = tuple(registry.tags(pattern=authority_tag_pattern))
    pages = registry.referrer_pages(subject_digest, artifact_type=artifact_type)
    referrers: dict[str, int] = {}
    for page in pages:
        for item in _referrer_descriptors(page.body, artifact_type=artifact_type):
            previous = referrers.get(item["digest"])
            if previous is not None and previous != item["size"]:
                _die("native referrers duplicate one digest with conflicting sizes")
            referrers[item["digest"]] = item["size"]
    candidates_by_digest: dict[str, AuthorityCandidate] = {}

    def materialize(reference: str, *, tag: str | None) -> AuthorityCandidate:
        response = registry.manifest(
            reference,
            media_type=OCI_MANIFEST,
            operation="candidate-manifest-tag"
            if tag is not None
            else "candidate-manifest-referrer",
        )
        candidate_digest = digest(response.body)
        expected_tag = authority_tag_prefix + candidate_digest.removeprefix("sha256:")
        if tag is not None and tag != expected_tag:
            _die("authority candidate tag suffix differs from literal manifest")
        if tag is None and reference != candidate_digest:
            _die("authority referrer candidate digest differs from literal manifest")
        manifest = _parse_object(response.body, "authority candidate manifest")
        if set(manifest) != {
            "artifactType",
            "config",
            "layers",
            "mediaType",
            "schemaVersion",
            "subject",
        }:
            _die("authority candidate manifest shape differs")
        subject = manifest.get("subject")
        if (
            manifest.get("artifactType") != artifact_type
            or manifest.get("mediaType") != OCI_MANIFEST
            or manifest.get("schemaVersion") != 2
            or not isinstance(subject, dict)
            or subject.get("digest") != subject_digest
            or subject.get("mediaType") != OCI_INDEX
            or isinstance(subject.get("size"), bool)
            or not isinstance(subject.get("size"), int)
            or subject["size"] <= 0
        ):
            _die("authority candidate manifest subject/media identity differs")
        if manifest.get("config") != {
            "data": "e30=",
            "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            "mediaType": "application/vnd.oci.empty.v1+json",
            "size": 2,
        }:
            _die("authority candidate empty config differs")
        layers = manifest.get("layers")
        if not isinstance(layers, list) or len(layers) != 2:
            _die("authority candidate does not have exact receipt/bundle layers")
        expected_media = (receipt_media_type, bundle_media_type)
        layer_bytes: list[bytes] = []
        for index, media_type in enumerate(expected_media):
            layer = layers[index]
            if not isinstance(layer, dict) or layer.get("mediaType") != media_type:
                _die("authority candidate layer media type differs")
            layer_digest = layer.get("digest")
            layer_size = layer.get("size")
            if (
                not isinstance(layer_digest, str)
                or OCI_DIGEST.fullmatch(layer_digest) is None
                or isinstance(layer_size, bool)
                or not isinstance(layer_size, int)
                or layer_size <= 0
            ):
                _die("authority candidate layer descriptor differs")
            raw = registry.blob(layer_digest, operation=f"candidate-layer-{index}").body
            if len(raw) != layer_size or digest(raw) != layer_digest:
                _die("authority candidate layer bytes differ from descriptor")
            layer_bytes.append(raw)
        return AuthorityCandidate(
            tag=expected_tag,
            manifest=response.body,
            receipt=layer_bytes[0],
            bundle=layer_bytes[1],
            referrer_indexed=referrers.get(candidate_digest) == len(response.body),
            tag_present=tag is not None,
        )

    for tag in tags:
        candidate = materialize(tag, tag=tag)
        candidate_digest = digest(candidate.manifest)
        if candidate_digest in candidates_by_digest:
            _die("multiple authority tags select the same candidate digest")
        candidates_by_digest[candidate_digest] = candidate
    for candidate_digest in sorted(referrers):
        if candidate_digest in candidates_by_digest:
            continue
        candidate = materialize(candidate_digest, tag=None)
        if not candidate.referrer_indexed:
            _die("native referrer candidate descriptor differs from literal manifest")
        candidates_by_digest[candidate_digest] = candidate
    return AuthorityDiscovery(
        candidates=tuple(
            candidates_by_digest[digest_value] for digest_value in sorted(candidates_by_digest)
        ),
        referrers=tuple(sorted(referrers.items())),
        tags=tags,
    )


def poll_authority_candidates(
    fetch: Callable[[], AuthorityDiscovery],
    *,
    attempts: int,
    interval_seconds: int,
    sleep: Callable[[float], None] = time.sleep,
) -> list[AuthorityCandidate]:
    """Wait for a stable complete tag/referrer view; never race into re-signing."""

    if attempts < 3 or attempts > 20 or interval_seconds < 0 or interval_seconds > 60:
        _die("authority recovery polling bound is outside the reviewed range")
    previous: tuple[Any, ...] | None = None
    stable_rounds = 0
    authority_evidence_seen = False
    final_discovery: AuthorityDiscovery | None = None
    for attempt in range(attempts):
        discovery = fetch()
        if not isinstance(discovery, AuthorityDiscovery):
            _die("authority discovery callback returned an unreviewed shape")
        final_discovery = discovery
        authority_evidence_seen = authority_evidence_seen or bool(
            discovery.tags or discovery.referrers or discovery.candidates
        )
        materialized_tags = tuple(
            candidate.tag for candidate in discovery.candidates if candidate.tag_present
        )
        if (
            tuple(sorted(materialized_tags, key=lambda item: item.encode("utf-8")))
            != discovery.tags
        ):
            _die("authority discovery did not materialize every patterned tag")
        snapshot = (
            discovery.tags,
            discovery.referrers,
            tuple(
                (
                    candidate.tag,
                    digest(candidate.manifest),
                    candidate.referrer_indexed,
                    candidate.tag_present,
                )
                for candidate in discovery.candidates
            ),
        )
        if snapshot == previous:
            stable_rounds += 1
        else:
            previous = snapshot
            stable_rounds = 1
        if attempt + 1 < attempts:
            sleep(interval_seconds)
    if final_discovery is None or stable_rounds < 2:
        _die("authority tag/referrer view did not settle completely; re-signing is forbidden")
    if final_discovery.candidates:
        if not all(candidate.referrer_indexed for candidate in final_discovery.candidates):
            _die("authority tag/referrer view did not settle completely; re-signing is forbidden")
        return list(final_discovery.candidates)
    if authority_evidence_seen or final_discovery.tags or final_discovery.referrers:
        _die("authority evidence disappeared during recovery; re-signing is forbidden")
    return []


def select_authority_recovery_candidate(
    candidates: Sequence[AuthorityCandidate],
    *,
    validator: Callable[[AuthorityCandidate], Any],
) -> tuple[AuthorityCandidate, Any] | None:
    """Return zero or one fully valid candidate; any invalid/multiple view is manual."""

    if not candidates:
        return None
    validated: list[tuple[AuthorityCandidate, Any]] = []
    for candidate in candidates:
        try:
            result = validator(candidate)
        except Exception as exc:
            raise TransportError(
                "authority candidate failed full validation; reviewed manual recovery is required"
            ) from exc
        validated.append((candidate, result))
    if len(validated) != 1:
        _die("multiple valid authority candidates require reviewed manual selection")
    return validated[0]


@dataclass(frozen=True)
class AuthorityPublication:
    put: dict[str, Any] | None
    by_tag: dict[str, Any]
    by_digest: dict[str, Any]
    referrer_pages: tuple[bytes, ...]


def publish_authority(
    registry: Registry,
    *,
    empty_config: bytes,
    receipt: bytes,
    bundle: bytes,
    manifest: bytes,
    tag: str,
    subject_digest: str,
    artifact_type: str,
) -> AuthorityPublication:
    """Publish AR/AB/AM once, then require exact K and native referrer readback."""

    expected_digest = digest(manifest)
    existing = registry.optional_manifest(
        tag,
        media_type=OCI_MANIFEST,
        operation="authority-tag-precondition",
    )
    if existing is not None:
        _die("authority tag already exists; recovery must reuse it without re-signing")
    for label, raw in (
        ("authority-empty-config", empty_config),
        ("authority-receipt", receipt),
        ("authority-bundle", bundle),
    ):
        registry.upload_blob(raw, operation=label)
    response = registry.put_manifest(
        tag,
        manifest,
        media_type=OCI_MANIFEST,
        subject_digest=subject_digest,
        operation="authority-tag-put",
    )
    put = put_response_record(
        response,
        expected_digest=expected_digest,
        expected_subject=subject_digest,
    )
    by_tag_response = registry.manifest(tag, media_type=OCI_MANIFEST, operation="authority-tag")
    by_digest_response = registry.manifest(
        expected_digest,
        media_type=OCI_MANIFEST,
        operation="authority-digest",
    )
    if by_tag_response.body != manifest or by_digest_response.body != manifest:
        _die("authority tag/digest literal readback differs")
    pages = registry.referrer_pages(subject_digest, artifact_type=artifact_type)
    matches = [
        item
        for page in pages
        for item in _referrer_descriptors(page.body, artifact_type=artifact_type)
        if item.get("digest") == expected_digest
        and item.get("size") == len(manifest)
        and item.get("mediaType") == OCI_MANIFEST
    ]
    if not matches:
        _die("native referrers do not include the newly retained authority")
    return AuthorityPublication(
        put=put,
        by_tag=manifest_response_record(by_tag_response, request_accept=OCI_MANIFEST),
        by_digest=manifest_response_record(by_digest_response, request_accept=OCI_MANIFEST),
        referrer_pages=tuple(page.body for page in pages),
    )


def retain_recovered_authority(
    registry: Registry,
    *,
    candidate: AuthorityCandidate,
    subject_digest: str,
    artifact_type: str,
    authority_tag_prefix: str,
) -> AuthorityPublication:
    """Recover literal AM without creating AR/AB; add only a missing derived K tag."""

    expected_digest = digest(candidate.manifest)
    if (
        not authority_tag_prefix
        or re.fullmatch(r"[a-z0-9][a-z0-9_.-]*-", authority_tag_prefix) is None
    ):
        _die("recovered authority tag prefix differs")
    expected_tag = authority_tag_prefix + expected_digest[7:]
    if (
        candidate.tag != expected_tag
        or not candidate.referrer_indexed
        or candidate.receipt == b""
        or candidate.bundle == b""
    ):
        _die("recovered authority candidate identity/completeness differs")
    existing = registry.optional_manifest(
        expected_tag,
        media_type=OCI_MANIFEST,
        operation="recovered-authority-tag-precondition",
    )
    put: dict[str, Any] | None = None
    if existing is None:
        if candidate.tag_present:
            _die("candidate claimed a present authority tag but precondition is absent")
        response = registry.put_manifest(
            expected_tag,
            candidate.manifest,
            media_type=OCI_MANIFEST,
            subject_digest=subject_digest,
            operation="recovered-authority-tag-put",
        )
        put = put_response_record(
            response,
            expected_digest=expected_digest,
            expected_subject=subject_digest,
        )
    elif existing.body != candidate.manifest or digest(existing.body) != expected_digest:
        _die("recovered authority derived tag contains conflicting bytes")
    by_tag_response = registry.manifest(
        expected_tag,
        media_type=OCI_MANIFEST,
        operation="recovered-authority-tag",
    )
    by_digest_response = registry.manifest(
        expected_digest,
        media_type=OCI_MANIFEST,
        operation="recovered-authority-digest",
    )
    if by_tag_response.body != candidate.manifest or by_digest_response.body != candidate.manifest:
        _die("recovered authority literal tag/digest readback differs")
    pages = registry.referrer_pages(subject_digest, artifact_type=artifact_type)
    matches = [
        item
        for page in pages
        for item in _referrer_descriptors(page.body, artifact_type=artifact_type)
        if item.get("digest") == expected_digest
        and item.get("size") == len(candidate.manifest)
        and item.get("mediaType") == OCI_MANIFEST
    ]
    if len(matches) != 1:
        _die("recovered authority native referrer readback is absent or ambiguous")
    return AuthorityPublication(
        put=put,
        by_tag=manifest_response_record(by_tag_response, request_accept=OCI_MANIFEST),
        by_digest=manifest_response_record(by_digest_response, request_accept=OCI_MANIFEST),
        referrer_pages=tuple(page.body for page in pages),
    )
