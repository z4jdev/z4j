"""Startup/periodic coordinator for Boundary-B durable child outboxes."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog

from z4j_brain.domain.retry_contract import (
    required_retry_engine,
    session_supports_retry_engine,
)

if TYPE_CHECKING:
    from uuid import UUID

    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.models import Command
    from z4j_brain.settings import Settings
    from z4j_brain.websocket.registry import BrainRegistry


logger = structlog.get_logger("z4j.brain.workers.bulk_retry")


class BulkRetryCoordinator:
    """Fair, bounded progress actor for sealed parents."""

    def __init__(
        self,
        *,
        db: DatabaseManager,
        settings: Settings,
        registry: BrainRegistry,
    ) -> None:
        self._db = db
        self._settings = settings
        self._registry = registry

    async def tick(self) -> None:
        """Project outcomes, enforce budgets, then send a bounded fair batch."""

        from z4j_brain.persistence.repositories import BulkRetryRequestRepository

        now = datetime.now(UTC)
        async with self._db.session() as session:
            repository = BulkRetryRequestRepository(session)
            reconciled = await repository.reconcile_command_outcomes(
                limit=int(self._settings.bulk_retry_scan_batch),
            )
            expired = await repository.expire_claims(now=now)
            blocked = await repository.block_expired_parents(now=now)
            await session.commit()
        if reconciled or expired or blocked:
            logger.info(
                "z4j bulk retry coordinator reconciled",
                outcomes=reconciled,
                expired_claims=expired,
                blocked_parents=blocked,
            )

        sent = 0
        batch = int(self._settings.bulk_retry_scan_batch)
        # One child per parent per round. Requerying applies last_progress_at and
        # keeps parents that arrived during this tick from starving.
        while sent < batch:
            async with self._db.session() as session:
                parent_ids = await BulkRetryRequestRepository(session).fair_parent_ids(
                    limit=batch,
                )
            if not parent_ids:
                break
            progressed = False
            for parent_id in parent_ids:
                if sent >= batch:
                    break
                if await self._send_one(parent_id):
                    sent += 1
                    progressed = True
            if not progressed:
                break

    async def _send_one(self, parent_id: UUID) -> bool:
        from z4j_brain.persistence.repositories import BulkRetryRequestRepository
        from z4j_brain.websocket.gateway import deliver_command_frame_with_authority

        async with self._db.session() as session:
            repository = BulkRetryRequestRepository(session)
            engines = await repository.pending_engines(parent_id=parent_id)
        for engine in engines:
            async with self._db.session() as session:
                children = await BulkRetryRequestRepository(session).pending_children(
                    parent_id=parent_id,
                    eligible_engines=(engine,),
                    limit=1,
                )
            if not children:
                continue
            child = children[0]
            required_engine = required_retry_engine("bulk_retry", child.payload)
            if required_engine != child.engine:
                logger.error(
                    "z4j bulk retry child has an unsatisfiable engine requirement",
                    parent_id=str(parent_id),
                    child_id=str(child.id),
                    sealed_engine=child.engine,
                )
                continue
            if child.target_agent_id is not None:
                handle = await self._registry.select_session(
                    agent_id=child.target_agent_id,
                    required_retry_engine=required_engine,
                )
            else:
                handle = await self._registry.select_project_session(
                    project_id=child.project_id,
                    required_retry_engine=required_engine,
                )
            if handle is None:
                continue
            # Retain this exact immutable handle across claim and send.
            async with self._db.session() as claim_session:
                command = await BulkRetryRequestRepository(claim_session).claim_child(
                    child_id=child.id,
                    agent_id=handle.agent_id,
                    generation=handle.generation,
                    command_timeout_seconds=int(self._settings.command_timeout_seconds),
                )
                await claim_session.commit()
            if command is None:
                continue
            try:
                delivered = await deliver_command_frame_with_authority(
                    db=self._db,
                    websocket=handle.websocket,
                    settings=self._settings,
                    command=command,
                )
                if not delivered:
                    # The authority lock proves no bytes were sent, but the
                    # bulk claim is intentionally irreversible. Keep it bound
                    # to this episode and let normal expiry/reconciliation
                    # classify the unobserved result; never retarget or revert.
                    logger.error(
                        "z4j bulk retry send refused after irreversible claim "
                        "because its agent was revoked",
                        parent_id=str(parent_id),
                        child_id=str(child.id),
                        command_id=str(command.id),
                        generation=str(handle.generation),
                    )
            except Exception:
                # Unlike a False authority result, a socket exception is
                # ambiguous: bytes may have crossed the boundary. The claim is
                # still irreversible, so never retarget or return PENDING.
                logger.exception(
                    "z4j bulk retry send failed after irreversible claim",
                    parent_id=str(parent_id),
                    child_id=str(child.id),
                    command_id=str(command.id),
                    generation=str(handle.generation),
                )
            return True
        # An unavailable engine must not pin the oldest scan window forever.
        # ``updated_at`` is the durable scheduling cursor; claims and control
        # changes already advance it, and this advances it for a no-op visit.
        async with self._db.session() as session:
            await BulkRetryRequestRepository(session).touch_scan_position(parent_id=parent_id)
            await session.commit()
        return False

    async def claim_for_longpoll(
        self,
        *,
        project_id: UUID,
        agent_id: UUID,
        retry_contracts: dict[str, int],
        generation: uuid.UUID,
        maximum: int,
    ) -> list[Command]:
        """Claim children at the exact authenticated polling request edge."""

        from z4j_brain.persistence.repositories import BulkRetryRequestRepository

        claimed: list[Command] = []
        while len(claimed) < maximum:
            async with self._db.session() as session:
                parent_ids = await BulkRetryRequestRepository(session).fair_parent_ids(
                    limit=maximum,
                    project_id=project_id,
                    eligible_agent_id=agent_id,
                    eligible_engines=tuple(sorted(retry_contracts)),
                )
            if not parent_ids:
                break
            progressed = False
            for parent_id in parent_ids:
                if len(claimed) >= maximum:
                    break
                async with self._db.session() as session:
                    children = await BulkRetryRequestRepository(session).pending_children(
                        parent_id=parent_id,
                        eligible_agent_id=agent_id,
                        eligible_engines=tuple(sorted(retry_contracts)),
                    )
                child = next(
                    (
                        candidate
                        for candidate in children
                        if candidate.target_agent_id in (None, agent_id)
                        and required_retry_engine("bulk_retry", candidate.payload)
                        == candidate.engine
                        and session_supports_retry_engine(
                            retry_contracts,
                            candidate.engine,
                        )
                    ),
                    None,
                )
                if child is None:
                    continue
                async with self._db.session() as claim_session:
                    command = await BulkRetryRequestRepository(claim_session).claim_child(
                        child_id=child.id,
                        agent_id=agent_id,
                        generation=generation,
                        command_timeout_seconds=int(self._settings.command_timeout_seconds),
                    )
                    await claim_session.commit()
                if command is not None:
                    claimed.append(command)
                    progressed = True
            if not progressed:
                break
        return claimed


__all__ = ["BulkRetryCoordinator"]
