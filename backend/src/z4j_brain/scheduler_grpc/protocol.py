"""Exact Boundary-D scheduler protocol tuple supported by the Brain."""

from __future__ import annotations

from z4j_brain.domain.schedule_cadence import (
    CADENCE_SEMANTICS_VERSION,
    cadence_runtime_fingerprint,
)
from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb

CURRENT_PROTOCOL_EPOCH = 1
CURRENT_FIRE_RESPONSE_VERSION = 1
CURRENT_CURSOR_TRANSITION_VERSION = 1
CURRENT_STABLE_SNAPSHOT_VERSION = 1
CURRENT_REVISION_WATCH_VERSION = 1
CURRENT_PER_ID_STATE_VERSION = 1
CURRENT_QUARANTINE_VERSION = 1


def current_capabilities() -> pb.SchedulerProtocolCapabilities:
    return pb.SchedulerProtocolCapabilities(
        protocol_epoch=CURRENT_PROTOCOL_EPOCH,
        fire_response_version=CURRENT_FIRE_RESPONSE_VERSION,
        cursor_transition_version=CURRENT_CURSOR_TRANSITION_VERSION,
        stable_snapshot_version=CURRENT_STABLE_SNAPSHOT_VERSION,
        revision_watch_version=CURRENT_REVISION_WATCH_VERSION,
        per_id_state_version=CURRENT_PER_ID_STATE_VERSION,
        quarantine_version=CURRENT_QUARANTINE_VERSION,
        cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
        cadence_runtime_fingerprint=cadence_runtime_fingerprint(),
    )


def capabilities_are_exact(
    offered: pb.SchedulerProtocolCapabilities,
) -> bool:
    expected = current_capabilities()
    return offered.SerializeToString(deterministic=True) == expected.SerializeToString(
        deterministic=True,
    )


__all__ = [
    "CURRENT_PROTOCOL_EPOCH",
    "CURRENT_REVISION_WATCH_VERSION",
    "CURRENT_STABLE_SNAPSHOT_VERSION",
    "capabilities_are_exact",
    "current_capabilities",
]
