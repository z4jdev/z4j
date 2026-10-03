"""The brain's outbound HTTP client never logs a delivery URL.

httpx logs ``HTTP Request: POST <url> "HTTP/1.1 200 OK"`` at INFO on the
``httpx`` logger for every response it receives. That URL is the whole
secret for a Slack, Teams or Discord webhook, carries the Telegram bot
token in its path and is the audit forwarder's SIEM intake URL.
``configure_logging`` silences the logger, and rewrites the line to its
scheme and host when an operator raises the logger again.

Each delivery here runs against a stub transport with a marker secret in
the URL path; the transport records what it was asked for, so a clean
log is only accepted next to proof that the request really went out.
"""

from __future__ import annotations

import io
import logging
import sys
from collections.abc import Iterator

import httpx
import pytest
from z4j_brain.domain import audit_forwarder as fwd
from z4j_brain.domain.notifications import channels as ch
from z4j_brain.logging_config import _url_origin, configure_logging

SLACK_SECRET = "R2ESLACKSECRETPATH"
BOT_TOKEN = "123456789:R2ETELEGRAMBOTTOKEN_abcdef"
SIEM_SECRET = "R2EAUDITWEBHOOKPATHSECRET"
PINNED_IP = "203.0.113.50"
PAYLOAD = {
    "title": "test",
    "message": "hello",
    "severity": "info",
    "event_type": "test.dispatch",
    "project": "default",
    "project_slug": "default",
    "agent_name": "agent",
    "timestamp": "2026-01-01T00:00:00+00:00",
}


class _Transport:
    """Records every request URL and answers 200 to all of them."""

    def __init__(self) -> None:
        self.urls: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.urls.append(str(request.url))
        # ``stream=`` rather than ``content=``: the dispatcher reads the
        # body through ``aiter_raw`` and a pre-read response refuses that.
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=httpx.ByteStream(b'{"ok": true, "result": {}}'),
            request=request,
        )


@pytest.fixture
def restored_logging() -> Iterator[None]:
    """Root and HTTP-client logger state put back after the test."""
    root = logging.getLogger()
    previous = (root.handlers[:], root.level)
    client_loggers = {
        name: (logging.getLogger(name).level, logging.getLogger(name).filters[:])
        for name in ("httpx", "httpcore")
    }
    try:
        yield
    finally:
        root.handlers, level = previous
        root.setLevel(level)
        for name, (level, filters) in client_loggers.items():
            logging.getLogger(name).setLevel(level)
            logging.getLogger(name).filters = filters


def _capture_stdout(monkeypatch: pytest.MonkeyPatch) -> io.StringIO:
    """Replace stdout from inside the test body.

    pytest's capture manager re-points ``sys.stdout`` between fixture
    setup and the call phase, so a swap made in a fixture is undone
    before ``configure_logging`` builds its handler.
    """
    stream = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stream)
    return stream


def _flushed(stream: io.StringIO) -> str:
    for handler in logging.getLogger().handlers:
        handler.flush()
    return stream.getvalue()


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Transport]:
    transport = _Transport()

    async def _pin(url: str) -> tuple[None, str]:
        return None, PINNED_IP

    async def _valid(url: str) -> None:
        return None

    monkeypatch.setattr(ch, "resolve_and_pin", _pin)
    monkeypatch.setattr(ch, "validate_webhook_url", _valid)
    monkeypatch.setattr(fwd, "resolve_and_pin", _pin)
    ch.set_shared_client(httpx.AsyncClient(transport=httpx.MockTransport(transport)))
    try:
        yield transport
    finally:
        ch.set_shared_client(None)


@pytest.mark.usefixtures("restored_logging")
def test_configure_logging_quiets_the_http_client_loggers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _capture_stdout(monkeypatch)
    configure_logging(level="INFO", json_output=True)
    configure_logging(level="INFO", json_output=True)
    for name in ("httpx", "httpcore"):
        quiet = logging.getLogger(name)
        assert quiet.level == logging.WARNING
        # The second call must not stack a second copy of the filter.
        assert len(quiet.filters) == 1


@pytest.mark.usefixtures("restored_logging")
@pytest.mark.parametrize("json_output", [True, False])
@pytest.mark.parametrize("raised_to_debug", [False, True])
async def test_deliveries_never_log_the_url_path(
    monkeypatch: pytest.MonkeyPatch,
    stub: _Transport,
    json_output: bool,
    raised_to_debug: bool,
) -> None:
    captured = _capture_stdout(monkeypatch)
    configure_logging(level="INFO", json_output=json_output)
    if raised_to_debug:
        # An operator chasing a delivery problem raises the client logger.
        logging.getLogger("httpx").setLevel(logging.DEBUG)

    slack = await ch.deliver_slack(
        {"webhook_url": f"https://hooks.slack.com/services/T0/B0/{SLACK_SECRET}"},
        dict(PAYLOAD),
    )
    telegram = await ch.deliver_telegram(
        {"bot_token": BOT_TOKEN, "chat_id": "12345"},
        dict(PAYLOAD),
    )
    forwarder = fwd.AuditForwarder(
        db=object(),  # type: ignore[arg-type]  _send_one never touches it
        webhook_url=f"https://siem.example.net/hook/{SIEM_SECRET}",
        hmac_secret=b"k" * 32,
    )
    forwarded = await forwarder._send_one({"id": "1", "action": "test"})

    # Positive control: every delivery happened, and the request that
    # left really carried the secret in its path.
    assert slack.success is True, slack.error
    assert telegram.success is True, telegram.error
    assert forwarded is True
    assert len(stub.urls) == 3
    assert any(SLACK_SECRET in url for url in stub.urls)
    assert any(BOT_TOKEN in url for url in stub.urls)
    assert any(SIEM_SECRET in url for url in stub.urls)

    out = _flushed(captured)
    assert SLACK_SECRET not in out
    assert BOT_TOKEN not in out
    assert SIEM_SECRET not in out
    lines = [line for line in out.splitlines() if "HTTP Request:" in line]
    if raised_to_debug:
        # The line still comes out, with scheme and host only.
        assert len(lines) == 3
        assert all(f"HTTP Request: POST https://{PINNED_IP} " in line for line in lines)
    else:
        assert lines == []


@pytest.mark.usefixtures("restored_logging")
def test_a_request_line_from_any_logger_keeps_the_origin_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The structlog processor covers a copy of the line on another logger."""
    captured = _capture_stdout(monkeypatch)
    configure_logging(level="INFO", json_output=True)
    logging.getLogger("some.relay").info(
        'HTTP Request: POST https://hooks.example.net/hook/%s "HTTP/1.1 200 OK"',
        SIEM_SECRET,
    )
    out = _flushed(captured)
    assert SIEM_SECRET not in out
    assert 'HTTP Request: POST https://hooks.example.net \\"HTTP/1.1 200 OK\\"' in out


@pytest.mark.parametrize(
    ("url", "origin"),
    [
        ("https://user:pw@host:8443/path?x=1#f", "https://host:8443"),
        ("https://203.0.113.50/services/T0/B0/secret", "https://203.0.113.50"),
        ("http://[::1]:9/p", "http://[::1]:9"),
        ("https://api.telegram.org/bot123:ABC/sendMessage", "https://api.telegram.org"),
        ("not a url", "[redacted-url]"),
        ("https://host:notaport/p", "[redacted-url]"),
    ],
)
def test_url_origin(url: str, origin: str) -> None:
    assert _url_origin(url) == origin
