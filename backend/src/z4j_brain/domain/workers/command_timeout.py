"""``CommandTimeoutWorker`` - sweeps stale commands.

Every ``command_timeout_sweep_seconds`` (default 5s) flips every
command whose ``timeout_at`` has elapsed and whose status is
still ``pending`` or ``dispatched`` to ``timeout``. Single bulk
UPDATE per tick.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from z4j_brain.persistence.database import DatabaseManager


logger = structlog.get_logger("z4j.brain.workers.command_timeout")


class CommandTimeoutWorker:
    """Periodic command-timeout sweeper."""

    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    async def tick(self) -> None:
        from z4j_brain.persistence.repositories import CommandRepository

        async with self._db.session() as session:
            count = await CommandRepository(session).sweep_timeouts(
                now=datetime.now(UTC),
            )
            await session.commit()
        if count:
            logger.info("z4j command timeout sweep", marked_timeout=count)


__all__ = ["CommandTimeoutWorker"]
