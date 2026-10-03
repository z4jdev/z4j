"""``changepassword --password-stdin`` reads the password the way the docs say.

The password-reset guide documents ``--password-stdin`` as a prompt that is
never echoed. The reader behind it was a bare ``sys.stdin.read().strip()``:
on a terminal that echoes every keystroke, and on a pipe it trimmed any
leading or trailing space a secret manager had put there. Now a terminal gets
``getpass`` (no echo) and a pipe is read once with only its trailing line
ending removed. Both branches are driven here with stdin and getpass stubbed.
"""

from __future__ import annotations

import getpass
import io
import sys
from types import SimpleNamespace

import pytest
from z4j_brain import cli


class _Terminal(io.StringIO):
    """stdin that claims to be a TTY and must never be read directly."""

    def isatty(self) -> bool:
        return True

    def read(self, *_args) -> str:
        pytest.fail("a terminal stdin must be read through getpass, never echoed")


def test_terminal_stdin_prompts_without_echo(monkeypatch: pytest.MonkeyPatch) -> None:
    prompts: list[str] = []

    def fake_getpass(prompt: str = "") -> str:
        prompts.append(prompt)
        return "typed at the prompt\n"

    monkeypatch.setattr(sys, "stdin", _Terminal())
    monkeypatch.setattr(getpass, "getpass", fake_getpass)

    password = cli._read_password_from_args(SimpleNamespace(password_stdin=True, password=None))

    assert password == "typed at the prompt"
    assert prompts == ["z4j changepassword: new password: "]


def test_piped_stdin_is_read_once_and_keeps_inner_and_edge_spaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("  s3cret with spaces  \r\n"))
    monkeypatch.setattr(
        getpass,
        "getpass",
        lambda *_a, **_k: pytest.fail("a pipe must not open a prompt"),
    )

    password = cli._read_password_from_args(SimpleNamespace(password_stdin=True, password=None))

    assert password == "  s3cret with spaces  "


def test_piped_stdin_without_trailing_newline_is_taken_whole(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("printf-style"))

    password = cli._read_password_from_args(SimpleNamespace(password_stdin=True, password=None))

    assert password == "printf-style"


@pytest.mark.parametrize("piped", ("", "\n", "\r\n"))
def test_empty_piped_password_is_refused(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    piped: str,
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(piped))

    password = cli._read_password_from_args(SimpleNamespace(password_stdin=True, password=None))

    assert password is None
    assert "empty password from stdin" in capsys.readouterr().err
