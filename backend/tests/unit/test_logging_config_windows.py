"""Native-Windows regression coverage for repeated logging setup."""

from __future__ import annotations

import io
import logging
import os
import sys

import pytest
from z4j_brain.logging_config import configure_logging


def _raise_foreign_logger_failure() -> None:
    raise RuntimeError("foreign logger failure")


@pytest.mark.skipif(os.name != "nt", reason="native Windows colorama behavior")
def test_repeated_non_tty_console_configuration_does_not_stack_colorama(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stream)
    root = logging.getLogger()
    previous_handlers = root.handlers[:]
    previous_level = root.level
    try:
        for _ in range(1100):
            configure_logging(level="INFO", json_output=False)

        logging.getLogger("z4j.colorama-regression").warning("logging remains writable")
        assert "logging remains writable" in stream.getvalue()
    finally:
        root.handlers = previous_handlers
        root.setLevel(previous_level)


def test_non_utf8_pipe_formats_foreign_traceback_without_unicode_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
    diagnostics = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setattr(sys, "stderr", diagnostics)
    root = logging.getLogger()
    previous_handlers = root.handlers[:]
    previous_level = root.level
    previous_raise_exceptions = logging.raiseExceptions
    logging.raiseExceptions = True
    try:
        configure_logging(level="INFO", json_output=False)
        try:
            _raise_foreign_logger_failure()
        except RuntimeError:
            logging.getLogger("z4j.non-utf8-regression").exception(
                "foreign traceback remains writable",
            )
        for handler in root.handlers:
            handler.flush()
        stream.flush()
        rendered = raw.getvalue().decode("cp1252")
        assert "foreign traceback remains writable" in rendered
        assert "RuntimeError: foreign logger failure" in rendered
        assert "Logging error" not in diagnostics.getvalue()
    finally:
        root.handlers = previous_handlers
        root.setLevel(previous_level)
        logging.raiseExceptions = previous_raise_exceptions
        stream.close()
