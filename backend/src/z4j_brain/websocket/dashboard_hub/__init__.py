"""Dashboard fan-out hub.

Two backends mirror the agent registry split:

- :class:`LocalDashboardHub` for tests, single-worker dev, and SQLite mode
- :class:`PostgresNotifyDashboardHub` for multi-worker production (Postgres)

The Postgres hub imports asyncpg which is optional (not installed in
SQLite-only deployments). Import it lazily to avoid ModuleNotFoundError.
"""

from z4j_brain.websocket.dashboard_hub._protocol import (
    DASHBOARD_TOPICS,
    DashboardHub,
    DashboardSubscription,
    DashboardTopic,
    SendCallable,
)
from z4j_brain.websocket.dashboard_hub.local import LocalDashboardHub


def __getattr__(name: str) -> object:
    """Lazy import for PostgresNotifyDashboardHub (requires asyncpg)."""
    if name == "PostgresNotifyDashboardHub":
        from z4j_brain.websocket.dashboard_hub.postgres_notify import (
            PostgresNotifyDashboardHub,
        )

        return PostgresNotifyDashboardHub
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "DASHBOARD_TOPICS",
    "DashboardHub",
    "DashboardSubscription",
    "DashboardTopic",
    "LocalDashboardHub",
    "PostgresNotifyDashboardHub",
    "SendCallable",
]
