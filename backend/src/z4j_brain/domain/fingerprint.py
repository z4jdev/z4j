"""Failure fingerprinting: collapse the same logical failure to one hash.

A fingerprint is a stable, pure hash of the failure fields the agent reports:
the ``exception`` string plus the deepest few traceback frames
(``file:line:func``). Adapters do not agree that ``exception`` is a class name:
some send only the class and others include a summary. Noise normalization is
therefore applied to that reported string and to the fallback used when the
traceback has no parseable Python frames. It does not inspect or separately
normalize a failure-message field.

Computed once when a ``task.failed`` event is ingested and stored on the
task row, then consumed by both the Issues aggregation and the rule
engine's ``task.failed`` trigger (as a ``fingerprint`` condition field).

Design choices:

Keep ``file:line`` (per the spec): a code change that shifts a line
  legitimately produces a NEW fingerprint (a new deploy's bug is new).
- Use the DEEPEST frames (a Python traceback is oldest-first, most-recent
  call last), capped at ``_MAX_FRAMES``, since the frames nearest the raise
  are the most distinctive and the top of a deep stack is mostly framework
  boilerplate.
- Pure + deterministic: no clock, no randomness, no I/O. Same inputs always
  hash to the same value across processes and restarts."""

from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath
from typing import Any

#: Deepest N traceback frames to include. Enough to distinguish call sites
#: without letting a slightly different top-of-stack split one bug in two.
_MAX_FRAMES = 5

#: ``File "<path>", line <n>, in <func>`` -- the standard CPython traceback
#: frame header. Windows paths use ``\`` inside the quotes; both are handled
#: because we only split on the quote + comma structure.
_FRAME_RE = re.compile(r'File "(?P<file>[^"]+)", line (?P<line>\d+), in (?P<func>\S+)')

#: Volatile tokens to strip from any residual text so noise in a message
#: (or an un-redacted frame) cannot split one logical failure into many.
_NOISE_SUBS: tuple[tuple[re.Pattern[str], str], ...] = (
    # hex addresses: 0x7f8b..., "at 0x..."
    (re.compile(r"0x[0-9a-fA-F]+"), "0xADDR"),
    # uuids
    (
        re.compile(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        ),
        "UUID",
    ),
    # object reprs: <Foo object at 0xADDR> -> <Foo object>
    (re.compile(r"<([\w.]+) object at [^>]+>"), r"<\1 object>"),
    # bare long numeric ids (>= 4 digits) not part of a word
    (re.compile(r"(?<![\w.])\d{4,}(?![\w.])"), "N"),
)


def _strip_noise(text: str) -> str:
    for pattern, repl in _NOISE_SUBS:
        text = pattern.sub(repl, text)
    return text


def _frame_signatures(traceback: str) -> list[str]:
    """The deepest ``_MAX_FRAMES`` frames as ``basename:line:func``."""
    frames = [
        f"{PurePosixPath(m.group('file').replace(chr(92), '/')).name}:"
        f"{m.group('line')}:{m.group('func')}"
        for m in _FRAME_RE.finditer(traceback)
    ]
    return frames[-_MAX_FRAMES:]


def compute_fingerprint(
    exception: str | None,
    traceback: str | None,
) -> str | None:
    """Return a stable 32-hex-char fingerprint for a failure, or ``None`` if
    there is nothing to fingerprint (no exception and no traceback).

    ``exception`` is the adapter-reported exception string (class-only for
    some adapters, a summary for others). ``traceback`` is the redacted
    traceback text.
    """
    exc = (exception or "").strip()
    tb = traceback or ""
    if not exc and not tb.strip():
        return None

    parts: list[str] = []
    if exc:
        parts.append(_strip_noise(exc))
    frames = _frame_signatures(tb)
    if frames:
        parts.extend(frames)
    elif tb.strip():
        # No parseable frames (a non-Python or already-flattened trace):
        # fall back to the noise-stripped body so distinct bodies still
        # separate, capped so a huge trace does not dominate the hash.
        parts.append(_strip_noise(tb.strip())[:2000])

    signature = "\n".join(parts)
    return hashlib.sha256(signature.encode("utf-8", "replace")).hexdigest()[:32]


def fingerprint_from_data(data: dict[str, Any]) -> str | None:
    """Fingerprint a task-failure event's ``data`` dict -- the single
    entry point shared by the ingestor (task-row column), the WS frame
    router (automation ``fingerprint`` condition), and any other
    consumer, so all three key on ONE identical value.

    Coerces ``exception`` + ``traceback`` to their FULL string form (not
    the 8192-char storage truncation): a CPython traceback is
    most-recent-call-last, so head-truncating before frame extraction
    would drop the deepest, most distinctive frames.
    """
    exc = data.get("exception")
    tb = data.get("traceback")
    return compute_fingerprint(
        str(exc) if exc is not None else None,
        str(tb) if tb is not None else None,
    )


__all__ = ["compute_fingerprint", "fingerprint_from_data"]
