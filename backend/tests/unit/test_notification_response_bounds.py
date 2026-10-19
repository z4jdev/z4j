"""Exercise notification HTTP response limits through real httpx streams."""

from __future__ import annotations

import asyncio
import gzip
import tracemalloc
import zlib
from collections.abc import AsyncIterator

import httpx
import pytest
from z4j_brain.domain.notifications import channels


class _Body(httpx.AsyncByteStream):
    def __init__(self, *chunks: bytes) -> None:
        self.chunks = chunks
        self.consumed = 0
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            self.consumed += 1
            yield chunk

    async def aclose(self) -> None:
        await asyncio.sleep(0)
        self.closed = True


async def _request(
    monkeypatch: pytest.MonkeyPatch,
    body: _Body,
    *,
    encoding: str | None = None,
) -> httpx.Response:
    def handler(request: httpx.Request) -> httpx.Response:
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(sum(map(len, body.chunks))),
            "Retry-After": "12",
        }
        if encoding is not None:
            headers["Content-Encoding"] = encoding
        return httpx.Response(202, headers=headers, stream=body, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        monkeypatch.setattr(channels, "_shared_client", client)
        return await channels._post("https://example.test/hook")


@pytest.mark.parametrize("encoding", [None, "identity", "gzip", "deflate"])
async def test_small_response_remains_readable_with_matching_headers(
    monkeypatch: pytest.MonkeyPatch, encoding: str | None
) -> None:
    payload = b'{"ok":true}'
    encoded = (
        gzip.compress(payload)
        if encoding == "gzip"
        else zlib.compress(payload)
        if encoding == "deflate"
        else payload
    )
    body = _Body(*(encoded[i : i + 2] for i in range(0, len(encoded), 2)))
    response = await _request(monkeypatch, body, encoding=encoding)
    assert response.status_code == 202
    assert response.json() == {"ok": True}
    assert response.text == payload.decode()
    assert response.headers["content-type"] == "application/json"
    assert response.headers["retry-after"] == "12"
    assert "content-encoding" not in response.headers
    assert int(response.headers["content-length"]) == len(payload)
    assert body.closed


@pytest.mark.parametrize("encoding", ["gzip", "deflate"])
async def test_compressed_expansion_is_bounded_before_it_is_allocated(
    monkeypatch: pytest.MonkeyPatch, encoding: str
) -> None:
    payload = b"x" * (2 * 1024 * 1024)
    encoded = gzip.compress(payload) if encoding == "gzip" else zlib.compress(payload)
    assert len(encoded) < channels._MAX_RESPONSE_BYTES
    body = _Body(encoded)
    tracemalloc.start()
    try:
        response = await _request(monkeypatch, body, encoding=encoding)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 512 * 1024, f"compressed response allocated {peak} bytes"
    assert response.content == payload[: channels._MAX_RESPONSE_BYTES]
    assert int(response.headers["content-length"]) == channels._MAX_RESPONSE_BYTES
    assert body.closed


async def test_large_raw_transport_chunk_is_not_copied_into_response_buffer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = _Body(b"x" * (4 * 1024 * 1024), b"must not be consumed")
    tracemalloc.start()
    try:
        response = await _request(monkeypatch, body)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 512 * 1024, f"raw response allocated {peak} bytes"
    assert response.content == b"x" * channels._MAX_RESPONSE_BYTES
    assert body.consumed == 1
    assert body.closed


@pytest.mark.parametrize("encoding", ["gzip", "deflate"])
@pytest.mark.parametrize("damage", ["invalid", "missing-trailer", "incomplete-data"])
async def test_invalid_or_naturally_truncated_compressed_body_is_refused(
    monkeypatch: pytest.MonkeyPatch, encoding: str, damage: str
) -> None:
    data = gzip.compress(b'{"ok":true}') if encoding == "gzip" else zlib.compress(b'{"ok":true}')
    data = (
        b"not compressed"
        if damage == "invalid"
        else data[:-4]
        if damage == "missing-trailer"
        else data[: len(data) // 2]
    )
    body = _Body(data)
    with pytest.raises(httpx.DecodingError):
        await _request(monkeypatch, body, encoding=encoding)
    assert body.closed


@pytest.mark.parametrize("encoding", ["br", "zstd", "gzip, deflate", "unknown"])
async def test_unsupported_response_encoding_is_refused_and_closed(
    monkeypatch: pytest.MonkeyPatch, encoding: str
) -> None:
    body = _Body(b"unrecognized payload")
    with pytest.raises(httpx.DecodingError):
        await _request(monkeypatch, body, encoding=encoding)
    assert body.closed


async def test_concatenated_gzip_members_are_bounded_and_decoded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = _Body(gzip.compress(b'{"ok":') + gzip.compress(b"true}"))
    response = await _request(monkeypatch, body, encoding="gzip")
    assert response.json() == {"ok": True}
    assert body.closed


async def test_request_uses_identity_encoding_without_losing_pin_or_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[httpx.Request] = []
    body = _Body(b"ok")

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, stream=body, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        monkeypatch.setattr(channels, "_shared_client", client)
        await channels._post(
            "https://original.example/hook",
            headers={"accept-encoding": "gzip", "host": "wrong.example"},
            pin_ip="93.184.216.34",
            timeout=2.0,
        )
        assert not client.is_closed
    request = seen[0]
    assert str(request.url) == "https://93.184.216.34/hook"
    assert request.headers["accept-encoding"] == "identity"
    assert request.headers["host"] == "original.example"
    assert request.extensions["sni_hostname"] == "original.example"
    assert request.extensions["timeout"]["read"] == 2.0
    assert body.closed


async def test_cancellation_closes_stream_and_keeps_shared_client_usable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    waiting = asyncio.Event()

    class BlockingBody(_Body):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"prefix"
            waiting.set()
            await asyncio.Future()

    body = BlockingBody()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=body))
    ) as client:
        monkeypatch.setattr(channels, "_shared_client", client)
        task = asyncio.create_task(channels._post("https://example.test/hook"))
        await asyncio.wait_for(waiting.wait(), timeout=2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert body.closed
        assert not client.is_closed


async def test_encoded_limit_stops_reading_and_returns_only_decoded_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A deterministic, poorly compressible body reaches the encoded
    # limit before the decoded limit and cannot include the trailer.
    import random

    payload = random.Random(481).randbytes(32 * 1024)
    encoded = gzip.compress(payload)
    body = _Body(encoded[: channels._MAX_RESPONSE_BYTES], encoded[channels._MAX_RESPONSE_BYTES :])
    response = await _request(monkeypatch, body, encoding="gzip")
    assert 0 < len(response.content) < channels._MAX_RESPONSE_BYTES
    assert payload.startswith(response.content)
    assert body.consumed == 1
    assert body.closed


@pytest.mark.parametrize("encoding", ["gzip", "deflate"])
async def test_corrupt_compression_checksum_is_refused_and_stream_closed(
    monkeypatch: pytest.MonkeyPatch, encoding: str
) -> None:
    encoded = bytearray(
        gzip.compress(b"complete") if encoding == "gzip" else zlib.compress(b"complete")
    )
    encoded[-1] ^= 0xFF
    body = _Body(bytes(encoded))
    with pytest.raises(httpx.DecodingError):
        await _request(monkeypatch, body, encoding=encoding)
    assert body.closed


@pytest.mark.parametrize(
    "payload", [b"short body", b"x" * channels._MAX_RESPONSE_BYTES], ids=["complete", "truncated"]
)
async def test_cancellation_during_close_does_not_cancel_stream_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    closing = asyncio.Event()
    release = asyncio.Event()
    closed = asyncio.Event()

    class SlowCloseBody(_Body):
        async def aclose(self) -> None:
            closing.set()
            await release.wait()
            self.closed = True
            closed.set()

    body = SlowCloseBody(payload)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=body))
    ) as client:
        monkeypatch.setattr(channels, "_shared_client", client)
        task = asyncio.create_task(channels._post("https://example.test/hook"))
        await asyncio.wait_for(closing.wait(), timeout=2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        release.set()
        await asyncio.wait_for(closed.wait(), timeout=2)
        assert body.closed
        assert not client.is_closed
