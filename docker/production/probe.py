#!/usr/bin/env python3
"""Emit the canonical cadence identity from an installed production image."""

from __future__ import annotations

import json
import platform
import sys
from importlib import metadata

from z4j_brain.domain.schedule_cadence import (
    CADENCE_SEMANTICS_VERSION as BRAIN_SEMANTICS,
)
from z4j_brain.domain.schedule_cadence import (
    cadence_behavior_vector_digest as brain_behavior,
)
from z4j_brain.domain.schedule_cadence import (
    cadence_runtime_fingerprint as brain_fingerprint,
)
from z4j_brain.domain.schedule_runtime import packaged_tzdata_digest as brain_tzdata
from z4j_scheduler.tick._runtime import packaged_tzdata_digest as scheduler_tzdata
from z4j_scheduler.tick.cadence import (
    CADENCE_SEMANTICS_VERSION as SCHEDULER_SEMANTICS,
)
from z4j_scheduler.tick.cadence import (
    cadence_behavior_vector_digest as scheduler_behavior,
)
from z4j_scheduler.tick.cadence import (
    cadence_runtime_fingerprint as scheduler_fingerprint,
)

DEPENDENCIES = ("astral", "croniter", "python-dateutil", "six", "tzdata")


def _identity(
    semantics: int,
    behavior: str,
    timezone_tree: str,
    fingerprint: str,
) -> dict[str, object]:
    return {
        "semantics_version": semantics,
        "behavior_vector_sha256": behavior,
        "tzdata_tree_sha256": timezone_tree,
        "fingerprint": fingerprint,
    }


def main() -> int:
    payload = {
        "format": "z4j-production-cadence-probe-v1",
        "platform": {
            "machine": platform.machine(),
            "system": platform.system(),
        },
        "python": {
            "implementation": platform.python_implementation(),
            "version": list(sys.version_info[:3]),
        },
        "dependencies": {name: metadata.version(name) for name in DEPENDENCIES},
        "brain": _identity(
            BRAIN_SEMANTICS,
            brain_behavior(),
            brain_tzdata(),
            brain_fingerprint(),
        ),
        "scheduler": _identity(
            SCHEDULER_SEMANTICS,
            scheduler_behavior(),
            scheduler_tzdata(),
            scheduler_fingerprint(),
        ),
    }
    sys.stdout.write(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
