"""The gateway must warn only when an agent is OUTSIDE the supported skew.

``docs/UPGRADE.md`` states the contract: brain minor >= agent minor, and the
agent may trail by at most ONE minor within the same major.

The previous implementation compared ``major.minor`` for plain inequality, and
its comment still reasoned about CalVer ("agent 2026.4 vs brain 2026.5") long
after the move to SemVer. Equality is the wrong test: it fired on a 1.7 agent
against a 1.8 brain, which the contract explicitly supports. A warning that
fires on the supported path cannot tell an operator anything, so it gets
ignored, and then the genuinely unsupported 1.6-against-1.8 case is invisible
too.

These tests pin both halves: silence where the contract allows it, and a warning
carrying an actionable remedy where it does not.

Deliberately NOT tested here: rejection. The brain still only warns, because a
deployed 1.6/1.7 agent classifies every close code except 4401/4403 as a
transient ``ConnectionError`` and reconnects on the normal backoff. Closing on
skew would make exactly the outdated agents being rejected reconnect-storm the
brain. ``CLOSE_VERSION_SKEW`` is reserved for when 1.8 agents are the floor.
"""

from __future__ import annotations

import uuid
from unittest.mock import Mock, patch

import pytest
import z4j_brain.websocket.gateway as gateway
from z4j_brain.websocket.gateway import (
    _MAX_AGENT_MINOR_LAG,
    CLOSE_VERSION_SKEW,
    _warn_on_version_skew,
)


def _skew(agent: str, brain: str = "1.8.0") -> list[dict]:
    """Return the log events emitted for one agent/brain pairing."""
    recording_logger = Mock()
    # ``structlog.testing.capture_logs`` mutates global structlog processors.
    # Once another full-suite test has cached this module's bound logger, that
    # helper sees no events even though the real logging pipeline receives the
    # warning. Replace the exact module dependency instead, so this test stays
    # sensitive regardless of suite order and logging configuration.
    with patch.object(gateway, "logger", recording_logger):
        _warn_on_version_skew(
            agent_id=uuid.uuid4(),
            agent_version=agent,
            brain_version=brain,
        )
    return [
        {
            "event": call.args[0],
            "log_level": "warning",
            **call.kwargs,
        }
        for call in recording_logger.warning.call_args_list
    ]


@pytest.mark.parametrize(
    "agent",
    [
        "1.8.0",  # exact match
        "1.8.3",  # patch behind, irrelevant to the contract
        "1.8.9",  # patch ahead, still the same minor
        "1.7.0",  # one minor behind: the supported rolling-upgrade state
        "1.7.3",
    ],
)
def test_supported_skew_is_silent(agent: str) -> None:
    """A supported pairing must not log. This is the regression that matters.

    1.7-against-1.8 previously warned, which is the case the docs call
    supported, so the log could not be used to find real problems.
    """
    assert _skew(agent) == [], f"{agent} is within the contract and must not warn"


@pytest.mark.parametrize(
    ("agent", "expected_in_reason"),
    [
        ("1.6.9", "trails the brain by 2 minors"),  # the 1.6 -> 1.8 jump
        ("1.5.0", "trails the brain by 3 minors"),
        ("1.0.0", "trails the brain by 8 minors"),
    ],
)
def test_agent_too_far_behind_warns(agent: str, expected_in_reason: str) -> None:
    logs = _skew(agent)

    assert len(logs) == 1, logs
    assert logs[0]["log_level"] == "warning"
    assert expected_in_reason in logs[0]["reason"]
    # The operator needs to know what to DO, not merely that something is off.
    assert "docs/UPGRADE.md" in logs[0]["remedy"]


def test_agent_newer_than_brain_warns() -> None:
    """``brain >= agent`` is the contract's hard direction."""
    logs = _skew("1.9.0")

    assert len(logs) == 1
    assert "newer than the brain" in logs[0]["reason"]


def test_different_major_warns() -> None:
    logs = _skew("2.0.0")

    assert len(logs) == 1
    assert "different majors" in logs[0]["reason"]


@pytest.mark.parametrize("agent", ["", "0.0.0"])
def test_unknown_agent_version_is_silent(agent: str) -> None:
    """Skew is unknowable, not wrong.

    Agents that cannot determine their own version send an empty string or the
    ``0.0.0`` sentinel. Warning on those would fire on every such connection
    while telling the operator nothing they can act on.
    """
    assert _skew(agent) == []


def test_unparseable_version_warns_that_it_could_not_check() -> None:
    """Say the check was skipped rather than implying the pairing is fine."""
    logs = _skew("not-a-version")

    assert len(logs) == 1
    assert "unparseable" in logs[0]["event"]


def test_close_code_is_reserved_for_future_enforcement() -> None:
    """Pin the protocol allocation without claiming universal control flow."""
    assert CLOSE_VERSION_SKEW == 4427
    assert _MAX_AGENT_MINOR_LAG == 1


def test_release_candidates_keep_the_existing_minor_skew_contract() -> None:
    assert _skew("1.11.0rc1", "1.11.0rc1") == []
    assert _skew("1.10.0", "1.11.0rc1") == []
    logs = _skew("1.9.0", "1.11.0rc1")
    assert len(logs) == 1
    assert "trails the brain by 2 minors" in logs[0]["reason"]
