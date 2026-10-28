"""A notification email keeps the end of a long traceback.

A Python traceback ends with the innermost frame and the exception line.
The email body cut a long one to its first 2000 characters, which kept the
outermost framework frames and dropped the cause.
"""

from __future__ import annotations

from z4j_brain.domain.notifications.channels import _build_email_body


def test_a_long_traceback_keeps_its_end() -> None:
    traceback = (
        "Traceback (most recent call last):\n"
        + '  File "/app/outer.py", line 1, in outer\n' * 200
        + "ValueError: the real cause"
    )
    body = _build_email_body({"trigger": "task.failed", "traceback": traceback})

    assert "ValueError: the real cause" in body
    assert "[... traceback truncated ...]\n" in body
    assert "Traceback (most recent call last)" not in body


def test_a_short_traceback_is_untouched() -> None:
    traceback = "Traceback (most recent call last):\nValueError: x"
    body = _build_email_body({"trigger": "task.failed", "traceback": traceback})

    assert f"Traceback:\n{traceback}\n" in body
    assert "truncated" not in body
