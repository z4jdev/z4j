"""REST API routers for health, authentication, projects and operations."""

from __future__ import annotations

from z4j_brain.api import (
    admin_settings,
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
    "admin_settings",
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
