"""Structured logging setup using :mod:`structlog`.

The brain logs as JSON in production and as colorized console output
in development. ``request_id`` and ``user_id`` are automatically
attached to every log record inside a request via the
``RequestIdMiddleware``.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

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
        renderer = structlog.dev.ConsoleRenderer(colors=True)

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


def _drop_secrets(
    logger: Any,  # noqa: ARG001
    method_name: str,  # noqa: ARG001
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
