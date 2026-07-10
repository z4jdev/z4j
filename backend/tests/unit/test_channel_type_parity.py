"""Channel-type <-> dispatcher parity (pins the Teams regression).

The dashboard offered Microsoft Teams, and a ``deliver_teams``
dispatcher shipped, but both notification routers' channel-type regex
EXCLUDED ``teams`` -- so channel creation 422'd at Pydantic validation
before the dispatcher was ever reached. The existing unit tests
constructed channels bypassing Pydantic, so CI never caught it. These
tests pin the pattern at the Pydantic-gate level and assert the pattern
and the dispatcher table never drift apart again.
"""

from __future__ import annotations

import re

from z4j_brain.api.notifications import _CHANNEL_TYPE_PATTERN as PROJECT_PATTERN
from z4j_brain.api.user_notifications import (
    _CHANNEL_TYPE_PATTERN as USER_PATTERN,
)
from z4j_brain.domain.notifications.channels import CHANNEL_DISPATCHERS

_EXPECTED_TYPES = {
    "webhook",
    "email",
    "slack",
    "telegram",
    "pagerduty",
    "discord",
    "teams",
}


def _pattern_types(pattern: str) -> set[str]:
    return set(re.search(r"\(([^)]*)\)", pattern).group(1).split("|"))


def test_teams_matches_both_router_patterns() -> None:
    assert re.match(PROJECT_PATTERN, "teams")
    assert re.match(USER_PATTERN, "teams")


def test_both_routers_share_one_channel_type_vocabulary() -> None:
    assert PROJECT_PATTERN == USER_PATTERN
    assert _pattern_types(PROJECT_PATTERN) == _EXPECTED_TYPES


def test_every_router_accepted_type_has_a_dispatcher() -> None:
    # The exact drift class that broke Teams: a type the router accepts
    # with no dispatcher to serve it (or a dispatcher the router blocks).
    for channel_type in _pattern_types(PROJECT_PATTERN):
        assert channel_type in CHANNEL_DISPATCHERS, (
            f"router accepts {channel_type!r} but no dispatcher serves it"
        )


def test_a_bogus_type_is_still_rejected() -> None:
    assert re.match(PROJECT_PATTERN, "carrierpigeon") is None
