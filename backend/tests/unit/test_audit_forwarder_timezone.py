"""SQLite UTC timestamps must not be interpreted using the forwarder host zone."""

import json
import os
import subprocess
import sys

import pytest


@pytest.mark.parametrize("zone", ["America/New_York", "Asia/Tokyo", "UTC"])
def test_sqlite_and_aware_timestamps_have_identical_wire_time(zone):
    child = r"""
import json, time
from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace
from z4j_brain.domain.audit_forwarder import row_to_payload
if hasattr(time, 'tzset'):
    time.tzset()
values = [datetime(2026, 1, 1, 12), datetime(2026, 1, 1, 12, tzinfo=UTC),
          datetime(2026, 1, 1, 7, tzinfo=timezone(timedelta(hours=-5)))]
out = []
for value in values:
    row = SimpleNamespace(id=None, action='test', target_type='test', target_id=None,
                          result='success', outcome='allow', occurred_at=value,
                          prev_row_hmac=None, row_hmac='a' * 64)
    out.append(row_to_payload(row)['occurred_at'])
print(json.dumps(out))
"""
    result = subprocess.run(
        [sys.executable, "-c", child],
        env={**os.environ, "TZ": zone},
        text=True,
        capture_output=True,
        check=True,
    )
    assert json.loads(result.stdout) == ["2026-01-01T12:00:00.000000+00:00"] * 3
