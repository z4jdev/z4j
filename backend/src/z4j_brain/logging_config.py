"""Structured logging setup using :mod:`structlog`.

The brain logs as JSON in production and as colorized console output
in development. ``request_id`` and ``user_id`` are automatically
attached to every log record inside a request via the
``RequestIdMiddleware``.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any
from urllib.parse import urlsplit

import structlog
from structlog.types import EventDict, Processor


def configure_logging(*, level: str, json_output: bool) -> None:
    """Wire stdlib logging through structlog.

    Idempotent: calling this twice in the same process is safe - the
    second call replaces the configuration cleanly.

    Args:
        level: stdlib level name (``DEBUG``, ``INFO``, ...).
        json_output: When True, every record is rendered as a single
            JSON object on stdout. When False, records are rendered
            with structlog's ``ConsoleRenderer`` (color, key=value).
    """
    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)

    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        timestamper,
        _drop_secrets,
        _redact_http_request_urls,
    ]

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(level),
        ),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    renderer: Processor
    if json_output:
        renderer = structlog.processors.JSONRenderer()
    else:
        stdout_is_tty = bool(
            getattr(sys.stdout, "isatty", lambda: False)(),
        )
        renderer = structlog.dev.ConsoleRenderer(
            colors=stdout_is_tty,
            force_colors=stdout_is_tty,
            exception_formatter=(
                structlog.dev.rich_traceback if stdout_is_tty else structlog.dev.plain_traceback
            ),
        )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)

    # Quiet down libraries that scream by default.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    # httpx logs ``HTTP Request: POST <full url> "HTTP/1.1 200 OK"`` at
    # INFO for every response. The brain's outbound URLs carry the
    # secret: Slack, Teams and Discord webhook paths, the Telegram bot
    # token, the audit forwarder's SIEM intake URL. Quiet both loggers,
    # and keep a filter on them so an operator who raises ``httpx`` to
    # DEBUG still sees scheme and host only.
    for name in ("httpx", "httpcore"):
        quiet = logging.getLogger(name)
        quiet.setLevel(logging.WARNING)
        quiet.addFilter(_HTTP_REQUEST_URL_FILTER)


_HTTP_REQUEST_PREFIX = "HTTP Request:"
_HTTP_REQUEST_LINE = re.compile(r"^(HTTP Request: \S+ )(\S+)(.*)$", re.DOTALL)


def _url_origin(url: object) -> str:
    """``scheme://host[:port]`` of a URL; the path, query and userinfo are gone."""
    try:
        parts = urlsplit(str(url))
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return "[redacted-url]"
    if not parts.scheme or not host:
        return "[redacted-url]"
    if ":" in host:
        host = f"[{host}]"
    if port is not None:
        host = f"{host}:{port}"
    return f"{parts.scheme}://{host}"


class _HttpRequestUrlFilter(logging.Filter):
    """Rewrite httpx's request line to scheme and host before any handler sees it.

    Attached to the ``httpx`` and ``httpcore`` loggers, so it runs even
    when an operator installs their own handler there.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.msg
        args = record.args
        if (
            isinstance(msg, str)
            and msg.startswith(_HTTP_REQUEST_PREFIX)
            and isinstance(args, tuple)
            and len(args) >= 2
        ):
            record.args = (args[0], _url_origin(args[1]), *args[2:])
        return True


_HTTP_REQUEST_URL_FILTER = _HttpRequestUrlFilter()


def _redact_http_request_urls(
    logger: Any,
    method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """Second line of defence for the httpx request line, at the structlog layer.

    The stdlib filter above rewrites the record's arguments; this
    processor rewrites the rendered event, so a copy of the line that
    reaches the formatter through any other logger still carries the
    scheme and host only.
    """
    event = event_dict.get("event")
    if isinstance(event, str) and event.startswith(_HTTP_REQUEST_PREFIX):
        match = _HTTP_REQUEST_LINE.match(event)
        if match is not None:
            event_dict["event"] = f"{match.group(1)}{_url_origin(match.group(2))}{match.group(3)}"
    return event_dict


def _drop_secrets(
    logger: Any,
    method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """Strip well-known secret-bearing keys from every log record.

    Defense-in-depth: callers shouldn't put secrets in log context in
    the first place, but if they do, we replace the value with a
    ``[REDACTED]`` marker rather than leaking it.
    """
    for key in (
        "password",
        "token",
        "secret",
        "session_secret",
        "authorization",
        "cookie",
    ):
        if key in event_dict:
            event_dict[key] = "[REDACTED]"
    return event_dict


__all__ = ["configure_logging"]
