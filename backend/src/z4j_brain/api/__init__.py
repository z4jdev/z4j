"""REST API routers.

In B1 only ``health`` exists. The other routers (``setup``,
``projects``, ``agents``, ``tasks``, ``events``, ``commands``,
``audit``, ``users``, ``schedules``, ``queues``, ``workers``) are
added in later phases as the corresponding domain services land.
"""

from __future__ import annotations

from z4j_brain.api import (
    agents,
    audit,
    auth,
    commands,
    events,
    health,
    memberships,
    metrics,
    projects,
    queues,
    schedules,
    setup,
    stats,
    tasks,
    users,
    workers,
)

__all__ = [
    "agents",
    "audit",
    "auth",
    "commands",
    "events",
    "health",
    "memberships",
    "metrics",
    "projects",
    "queues",
    "schedules",
    "setup",
    "stats",
    "tasks",
    "users",
    "workers",
]
