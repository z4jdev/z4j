"""Brain-side WebSocket registry - Protocol + implementations.

Two backends:

- :class:`LocalRegistry` - single-process dict for dev/test/SQLite mode
- :class:`PostgresNotifyRegistry` - production Postgres LISTEN/NOTIFY

The Postgres registry imports asyncpg which is optional. Import it
lazily to avoid ModuleNotFoundError in SQLite-only deployments.
"""

from __future__ import annotations

from z4j_brain.websocket.registry._protocol import BrainRegistry, DeliveryResult
from z4j_brain.websocket.registry.local import LocalRegistry


def __getattr__(name: str) -> object:
    """Lazy import for PostgresNotifyRegistry (requires asyncpg)."""
    if name == "PostgresNotifyRegistry":
        from z4j_brain.websocket.registry.postgres_notify import (
            PostgresNotifyRegistry,
        )

        return PostgresNotifyRegistry
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "BrainRegistry",
    "DeliveryResult",
    "LocalRegistry",
    "PostgresNotifyRegistry",
]
