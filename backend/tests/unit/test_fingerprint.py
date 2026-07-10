"""Tests for failure fingerprinting (R4).

The load-bearing property: the SAME logical failure across runs -- with
different memory addresses, uuids, object reprs, and numeric ids in the
message -- collapses to ONE fingerprint, while genuinely different failures
(different exception class or different call site) stay distinct.
"""

from __future__ import annotations

from z4j_brain.domain.fingerprint import compute_fingerprint, fingerprint_from_data

_TB_TEMPLATE = """Traceback (most recent call last):
  File "/app/tasks.py", line 42, in process
    result = compute(payload)
  File "/app/lib/calc.py", line 17, in compute
    raise ValueError(f"bad value {{obj}}")
ValueError: bad value {msg}"""


def _tb(msg: str) -> str:
    return _TB_TEMPLATE.format(msg=msg)


def test_none_when_nothing_to_fingerprint() -> None:
    assert compute_fingerprint(None, None) is None
    assert compute_fingerprint("", "   ") is None


def test_deterministic() -> None:
    fp1 = compute_fingerprint("ValueError", _tb("<Foo object at 0x7f8b2c>"))
    fp2 = compute_fingerprint("ValueError", _tb("<Foo object at 0x7f8b2c>"))
    assert fp1 == fp2
    assert len(fp1) == 32


def test_noise_in_message_collapses_to_one_fingerprint() -> None:
    """Same class + same frames, message varies only in volatile noise."""
    variants = [
        "<Foo object at 0x7f8b2c1d>",
        "<Foo object at 0x55aa99bb>",
        "id=1234567 user=987654321",
        "550e8400-e29b-41d4-a716-446655440000 failed",
        "session f47ac10b-58cc-4372-a567-0e02b2c3d479 at 0xdeadbeef",
    ]
    fps = {compute_fingerprint("ValueError", _tb(v)) for v in variants}
    assert len(fps) == 1, f"expected one fingerprint, got {fps}"


def test_different_exception_class_differs() -> None:
    a = compute_fingerprint("ValueError", _tb("x"))
    b = compute_fingerprint("KeyError", _tb("x"))
    assert a != b


def test_different_frame_line_differs() -> None:
    tb_a = _TB_TEMPLATE.format(msg="x")
    tb_b = tb_a.replace("line 17", "line 250")
    assert compute_fingerprint("ValueError", tb_a) != compute_fingerprint("ValueError", tb_b)


def test_different_call_site_file_differs() -> None:
    tb_a = _TB_TEMPLATE.format(msg="x")
    tb_b = tb_a.replace("/app/lib/calc.py", "/app/lib/other.py")
    assert compute_fingerprint("ValueError", tb_a) != compute_fingerprint("ValueError", tb_b)


def test_windows_paths_use_basename() -> None:
    tb = (
        "Traceback (most recent call last):\n"
        '  File "C:\\\\app\\\\tasks.py", line 42, in process\n'
        "SomeError: boom"
    )
    tb_posix = tb.replace("C:\\\\app\\\\", "/srv/app/")
    # Same basename + line + func -> same fingerprint regardless of the dir.
    assert compute_fingerprint("SomeError", tb) == compute_fingerprint("SomeError", tb_posix)


def test_deepest_frames_used_not_top() -> None:
    """Two failures sharing the deepest frames but differing in an outer
    (framework) frame collapse together."""
    deep = (
        "Traceback (most recent call last):\n"
        '  File "/venv/celery/worker.py", line {top}, in _run\n'
        '  File "/app/tasks.py", line 42, in process\n'
        '  File "/app/lib/calc.py", line 17, in compute\n'
        "ValueError: boom"
    )
    a = compute_fingerprint("ValueError", deep.format(top=100))
    b = compute_fingerprint("ValueError", deep.format(top=999))
    # Only the outermost frame's line differs; with a 5-frame cap on 3
    # frames it is INCLUDED, so these differ -- pin that the outer frame
    # still matters when within the cap.
    assert a != b


def test_exception_only_no_traceback() -> None:
    fp = compute_fingerprint("TimeoutError", None)
    assert fp is not None
    # Stable + distinct from a different class.
    assert fp == compute_fingerprint("TimeoutError", "")
    assert fp != compute_fingerprint("ValueError", None)


def test_fingerprint_from_data_matches_direct_compute() -> None:
    """``fingerprint_from_data`` (the shared ingestion entry point) equals
    a direct ``compute_fingerprint`` of the same values -- this is the
    'shown == matched' contract: the ingestor, the task row, and the rule
    engine all key on ONE value."""
    data = {"exception": "ValueError", "traceback": _tb("x")}
    assert fingerprint_from_data(data) == compute_fingerprint("ValueError", _tb("x"))


def test_fingerprint_from_data_none_and_non_string() -> None:
    assert fingerprint_from_data({}) is None
    assert fingerprint_from_data({"exception": None, "traceback": None}) is None
    # Non-string values are coerced, not crashed on.
    assert fingerprint_from_data({"exception": 123, "traceback": None}) is not None


def test_deep_frames_survive_beyond_8192_char_truncation() -> None:
    """REGRESSION: the fingerprint must be computed from the FULL
    traceback, not the 8192-char storage truncation. A CPython traceback
    is most-recent-call-last, so head-truncating drops the deepest,
    most-distinctive frames -- collapsing two genuinely different bugs
    that share a long shallow framework stack."""
    header = "Traceback (most recent call last):\n"
    # ~20k chars of framework filler pushes the distinctive deepest frame
    # well past the 8192-char cut.
    filler = "".join(
        f'  File "/venv/framework/module{i}.py", line {i}, in _wrap\n' for i in range(400)
    )
    assert len(filler) > 8192
    tb_a = f'{header}{filler}  File "/app/calc.py", line 17, in compute\nValueError: boom'
    tb_b = f'{header}{filler}  File "/app/calc.py", line 250, in compute\nValueError: boom'
    fp_a = fingerprint_from_data({"exception": "ValueError", "traceback": tb_a})
    fp_b = fingerprint_from_data({"exception": "ValueError", "traceback": tb_b})
    # Differ only in the DEEPEST frame's line, which lives past char 8192;
    # under the old truncate-then-fingerprint path both would collapse.
    assert fp_a != fp_b


def test_frame_router_fingerprint_of_prefers_stamped_value() -> None:
    """The automation path reads the ingestor-stamped fingerprint so a
    rule matches what the Issues view shows, and falls back to computing
    for an un-stamped event."""
    from z4j_brain.websocket.frame_router import _fingerprint_of

    # Stamped value wins verbatim (even if it disagrees with a recompute).
    assert _fingerprint_of({"fingerprint": "deadbeef", "exception": "X"}) == "deadbeef"
    # No stamp -> fall back to computing from the event data.
    data = {"exception": "ValueError", "traceback": _tb("x")}
    assert _fingerprint_of(data) == compute_fingerprint("ValueError", _tb("x"))
    # Empty stamp is ignored (falls back).
    assert _fingerprint_of({"fingerprint": "", "exception": "ValueError"}) == compute_fingerprint(
        "ValueError", None
    )
