"""The schedule timezone validator must agree with the cadence engine.

``_validate_iana_timezone`` exists to stop a bad timezone from being
accepted at create time, watch-streamed to the scheduler, and only then
failing on first tick -- which the operator sees as a schedule that was
created successfully and never fires, with no API-side error.

It validated with bare ``ZoneInfo``, which searches the host's
``/usr/share/zoneinfo`` before the release-pinned ``tzdata`` wheel, while
``canonical_next_run_at`` computes through ``packaged_zoneinfo`` and reads
the wheel only. Validating against a different tzdb than the engine ticks
with reopens exactly the failure the validator closes.

``localtime`` is the reachable case: ``/etc/localtime`` exists on any
Linux host, so bare ``ZoneInfo("localtime")`` succeeded and the API
accepted the schedule, while the packaged wheel has no such entry and the
first tick raised. Reproduced in python:3.14-slim-trixie.
"""

from __future__ import annotations

from zoneinfo import ZoneInfoNotFoundError

import pytest
from z4j_brain.api.schedules import _validate_iana_timezone
from z4j_brain.domain.schedule_runtime import packaged_zoneinfo


class TestTimezoneValidatorMatchesTheEngine:
    def test_accepts_real_zones(self) -> None:
        for zone in ("UTC", "America/New_York", "Europe/London", "Australia/Sydney"):
            assert _validate_iana_timezone(zone) == zone

    def test_empty_and_none_keep_their_documented_behaviour(self) -> None:
        assert _validate_iana_timezone("") == "UTC"
        assert _validate_iana_timezone("   ") == "UTC"
        assert _validate_iana_timezone(None) is None

    def test_trims_before_validating(self) -> None:
        assert _validate_iana_timezone("  Europe/Berlin  ") == "Europe/Berlin"

    @pytest.mark.parametrize(
        "bad",
        [
            "localtime",  # exists on the host tzdb, absent from the pinned wheel
            "America/New York",  # the space typo named in the validator docstring
            "Foo/Bar",
            "../../etc/passwd",
            "/UTC",
        ],
    )
    def test_rejects_what_the_engine_cannot_tick(self, bad: str) -> None:
        # The property under test is agreement, asserted in both
        # directions: whatever the validator accepts, the engine must be
        # able to load. "localtime" is the case that used to pass here
        # and then fail at tick.
        #
        # The engine assertion names ZoneInfoNotFoundError rather than
        # Exception on purpose. A bare ``pytest.raises(Exception)`` would
        # pass for any failure at all, including one that has nothing to
        # do with the zone being absent, so it would certify the claim
        # without testing it. All five inputs below raise this exact type,
        # two of them through packaged_zoneinfo's traversal guard rather
        # than through a failed open.
        with pytest.raises(ValueError):
            _validate_iana_timezone(bad)
        with pytest.raises(ZoneInfoNotFoundError):
            packaged_zoneinfo(bad)

    def test_runtime_membership_does_not_normalize_the_key(self) -> None:
        # API callers may trim before validation, but the runtime's contract is
        # exact membership in the pinned manifest rather than implicit cleanup.
        with pytest.raises(ZoneInfoNotFoundError):
            packaged_zoneinfo(" UTC ")

    def test_every_accepted_zone_loads_in_the_engine(self) -> None:
        # Guards the general property rather than the one known instance:
        # a zone the API accepts must be loadable by the cadence engine.
        for zone in ("UTC", "America/Vancouver", "Africa/Casablanca", "Asia/Kolkata"):
            accepted = _validate_iana_timezone(zone)
            assert packaged_zoneinfo(accepted) is not None
