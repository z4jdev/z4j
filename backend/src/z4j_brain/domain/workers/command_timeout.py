"""``CommandTimeoutWorker`` - terminalizes elapsed commands.

Every ``command_timeout_sweep_seconds`` (default 5s) flips every
ordinary command whose ``timeout_at`` has elapsed to ``timeout``.
Marked cadence commands are handled first, one transaction each,
through the schedule-first terminal service so they can never pass
through the generic bulk UPDATE.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.websocket.registry import BrainRegistry


logger = structlog.get_logger("z4j.brain.workers.command_timeout")


class CommandTimeoutWorker:
    """Periodic command-timeout sweeper."""

    def __init__(
        self,
        db: DatabaseManager,
        *,
        audit: AuditService,
        registry: BrainRegistry | None = None,
        cadence_recovery_interval_seconds: float = 10.0,
    ) -> None:
        self._db = db
        self._audit = audit
        self._registry = registry
        self._cadence_recovery_interval_seconds = max(
            cadence_recovery_interval_seconds,
            0.1,
        )

    async def tick(self, *, now: datetime | None = None) -> None:
        from z4j_brain.persistence.repositories import (
            AuditLogRepository,
            CommandRepository,
        )
        from z4j_brain.persistence.repositories.schedule_control import (
            ScheduleControlRepository,
        )
        from z4j_brain.persistence.repositories.schedule_external import (
            ScheduleExternalRepository,
        )

        occurred_at = now or datetime.now(UTC)
        recovered = 0
        if self._registry is not None:
            async with self._db.session() as session:
                recoverable = await CommandRepository(
                    session,
                ).list_recoverable_current_websocket_deliveries(
                    now=occurred_at,
                    minimum_interval_seconds=(self._cadence_recovery_interval_seconds),
                )
            for command_id, agent_id, owner_id, generation in recoverable:
                if await self._registry.deliver_frozen(
                    command_id=command_id,
                    agent_id=agent_id,
                    registry_owner_id=owner_id,
                    session_generation=generation,
                ):
                    recovered += 1

        async with self._db.session() as session:
            cadence_candidates = await CommandRepository(
                session,
            ).list_expired_current_schedule_deliveries(
                now=occurred_at,
            )

        cadence_timeouts = 0
        cadence_holds = 0
        for command_id in cadence_candidates:
            # SQLite must acquire its writer lock before the unlocked candidate
            # read; PostgreSQL then adds row locks in the repository's global
            # schedule -> fire -> command -> hold order.
            async with self._db.session(write=True) as session:
                transition = await ScheduleControlRepository(
                    session,
                ).expire_current_schedule_delivery(
                    command_id=command_id,
                    occurred_at=occurred_at,
                )
                command = transition.command
                if transition.command_transitioned and command is not None:
                    schedule = transition.schedule
                    await self._audit.record(
                        AuditLogRepository(session),
                        action="schedule.fire.delivery_timeout",
                        target_type="schedule",
                        target_id=str(command.schedule_id),
                        result="timeout",
                        outcome="failure",
                        project_id=command.project_id,
                        metadata={
                            "command_id": str(command.id),
                            "fire_id": str(command.schedule_fire_id),
                            "never_claimed": (command.first_delivery_claimed_at is None),
                            "agent_acknowledged": (command.agent_acknowledged_at is not None),
                            "cadence_hold_created": transition.hold_created,
                            "acceptance_revision": (command.schedule_acceptance_revision),
                            "live_schedule_revision": (
                                int(schedule.schedule_revision or 0)
                                if schedule is not None
                                else None
                            ),
                        },
                    )
                    cadence_timeouts += 1
                    cadence_holds += int(transition.hold_created)
                await session.commit()

        async with self._db.session() as session:
            external_control_candidates = await ScheduleExternalRepository(
                session,
            ).list_expired_claimed_controls(
                now=occurred_at,
            )

        external_control_timeouts = 0
        for command_id in external_control_candidates:
            async with self._db.session(write=True) as session:
                transition = await ScheduleExternalRepository(
                    session,
                ).expire_claimed_control(
                    command_id=command_id,
                    occurred_at=occurred_at,
                )
                operation = transition.operation
                if transition.disposition == "ambiguous" and operation is not None:
                    await self._audit.record(
                        AuditLogRepository(session),
                        action="schedule.external_control.timeout",
                        target_type="schedule",
                        target_id=str(operation.schedule_id),
                        result="ambiguous",
                        outcome="failure",
                        project_id=(
                            transition.stream.project_id if transition.stream is not None else None
                        ),
                        metadata={
                            "command_id": str(command_id),
                            "operation_id": str(operation.id),
                            "stream_id": str(operation.stream_id),
                            "reserved_sequence": operation.reserved_sequence,
                        },
                    )
                    external_control_timeouts += 1
                await session.commit()

        async with self._db.session() as session:
            count = await CommandRepository(session).sweep_timeouts(
                now=occurred_at,
            )
            await session.commit()
        if count:
            logger.info("z4j command timeout sweep", marked_timeout=count)
        if cadence_timeouts:
            logger.info(
                "z4j cadence delivery timeout sweep",
                marked_timeout=cadence_timeouts,
                holds_created=cadence_holds,
            )
        if external_control_timeouts:
            logger.info(
                "z4j external control timeout sweep",
                marked_ambiguous=external_control_timeouts,
            )
        if recovered:
            logger.info(
                "z4j cadence delivery recovery sweep",
                recovered=recovered,
            )


__all__ = ["CommandTimeoutWorker"]
