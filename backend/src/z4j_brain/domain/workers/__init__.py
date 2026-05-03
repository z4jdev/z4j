"""Background worker pool.

Two periodic loops in B4:

- :class:`CommandTimeoutWorker` - sweeps stale commands every
  ``command_timeout_sweep_seconds``.
- :class:`AgentHealthWorker` - marks agents offline when their
  heartbeat is older than ``agent_offline_timeout_seconds``.

Both run under :class:`WorkerSupervisor`, which catches
exceptions, logs, and restarts the loop with backoff. A crashed
worker never kills the brain.
"""

from __future__ import annotations

from z4j_brain.domain.workers.agent_health import AgentHealthWorker
from z4j_brain.domain.workers.command_timeout import CommandTimeoutWorker
from z4j_brain.domain.workers.supervisor import (
    PeriodicWorker,
    WorkerSupervisor,
)

__all__ = [
    "AgentHealthWorker",
    "CommandTimeoutWorker",
    "PeriodicWorker",
    "WorkerSupervisor",
]
