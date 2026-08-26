"""Persistence boundary for durable bulk-retry parents and children."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import case, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.domain.bulk_retry import (
    RETRY_CONTRACT_VERSION,
    CanonicalRequest,
    PlannedChild,
)
from z4j_brain.persistence.enums import CommandStatus
from z4j_brain.persistence.models import (
    Agent,
    BulkRetryControlState,
    BulkRetryDeliveryState,
    BulkRetryOutcome,
    BulkRetryRequest,
    BulkRetryRequestChild,
    Command,
)
from z4j_brain.persistence.repositories._base import BaseRepository


@dataclass(frozen=True, slots=True)
class BulkRetryCounts:
    total: int
    pending: int
    claimed: int
    unobserved: int
    succeeded: int
    failed: int
    unknown: int


@dataclass(frozen=True, slots=True)
class BulkRetrySnapshot:
    parent: BulkRetryRequest
    counts: BulkRetryCounts
    status: str


def _as_utc(value: datetime) -> datetime:
    """SQLite returns timezone columns naive; normalize at Python boundaries."""

    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def derive_bulk_retry_status(
    parent: BulkRetryRequest,
    counts: BulkRetryCounts,
) -> str:
    """Derive public state; counters are never stored independently."""

    if counts.total == 0:
        return "no_match"
    unfinished = counts.pending > 0 or counts.unobserved > 0
    if unfinished and parent.control_state == BulkRetryControlState.PAUSED.value:
        status = "paused"
    elif unfinished and parent.control_state == BulkRetryControlState.BLOCKED.value:
        status = "blocked"
    elif unfinished:
        status = "in_progress"
    elif counts.unknown:
        status = "partial" if counts.succeeded or counts.failed else "indeterminate"
    elif counts.succeeded == counts.total:
        status = "succeeded"
    elif counts.failed == counts.total:
        status = "failed"
    else:
        status = "partial"
    return status


class BulkRetryRequestRepository(BaseRepository[BulkRetryRequest]):
    """CRUD, conditional claims, and outcome projection."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, BulkRetryRequest)

    @property
    def _is_sqlite(self) -> bool:
        return bool(self.session.bind and self.session.bind.dialect.name == "sqlite")

    async def begin_immediate_if_sqlite(self) -> None:
        """Start a fresh SQLite writer before any read-to-write upgrade."""

        if self._is_sqlite:
            if self.session.in_transaction():
                await self.session.rollback()
            await self.session.execute(text("BEGIN IMMEDIATE"))
            # Re-arm the audited write unit as well. The rollback above ends
            # the previous one, which clears this marker, and Boundary F
            # refuses to write an audit row inside a unit that did not begin
            # with BEGIN IMMEDIATE. Without this the seal path raises on its
            # own audit row after the seal has already succeeded, so the
            # request 500s while the work is done.
            self.session.sync_session.info["z4j_sqlite_immediate"] = True

    async def get_by_key(
        self,
        *,
        project_id: UUID,
        idempotency_key: str,
    ) -> BulkRetryRequest | None:
        result = await self.session.execute(
            select(BulkRetryRequest).where(
                BulkRetryRequest.project_id == project_id,
                BulkRetryRequest.idempotency_key == idempotency_key,
            )
        )
        return result.scalar_one_or_none()

    async def get_for_project(
        self,
        *,
        project_id: UUID,
        request_id: UUID,
        lock: bool = False,
    ) -> BulkRetryRequest | None:
        statement = select(BulkRetryRequest).where(
            BulkRetryRequest.id == request_id,
            BulkRetryRequest.project_id == project_id,
        )
        if lock:
            statement = statement.with_for_update()
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def insert_sealed(
        self,
        *,
        project_id: UUID,
        issued_by: UUID | None,
        idempotency_key: str,
        canonical: CanonicalRequest,
        target_agent_id: UUID | None,
        planned_children: list[PlannedChild],
        plan_digest: str,
        max_in_flight: int,
        deadline_at: datetime,
        source_ip: str | None,
    ) -> BulkRetryRequest:
        """Stage the parent, raw-key reservation, and every child."""

        now = datetime.now(UTC)
        parent = BulkRetryRequest(
            id=uuid.uuid4(),
            project_id=project_id,
            issued_by=issued_by,
            idempotency_key=idempotency_key,
            canonicalizer_version=canonical.version,
            canonical_request=canonical.exact_bytes,
            canonical_digest=canonical.digest,
            effective_request=canonical.effective,
            plan_digest=plan_digest,
            control_state=BulkRetryControlState.RUNNING.value,
            target_agent_id=target_agent_id,
            child_count=len(planned_children),
            max_in_flight=max_in_flight,
            deadline_at=deadline_at,
            sealed_at=now,
            created_at=now,
            updated_at=now,
        )
        self.session.add(parent)
        # Reservation is visible to a released brain because it occupies the
        # exact raw commands idempotency namespace.  It is terminal at insert,
        # so no old reconnect/reconcile loop can dispatch it.
        self.session.add(
            Command(
                id=uuid.uuid4(),
                project_id=project_id,
                issued_by=issued_by,
                agent_id=None,
                action="bulk_retry_request.reservation",
                target_type="bulk_retry_request",
                target_id=str(parent.id),
                payload={
                    "canonical_digest": canonical.digest,
                    "canonicalizer_version": canonical.version,
                },
                idempotency_key=idempotency_key,
                status=CommandStatus.COMPLETED,
                result={"reserved": True, "bulk_retry_request_id": str(parent.id)},
                issued_at=now,
                completed_at=now,
                timeout_at=deadline_at,
                source_ip=source_ip,
            )
        )
        for child in planned_children:
            self.session.add(
                BulkRetryRequestChild(
                    id=uuid.uuid4(),
                    parent_id=parent.id,
                    project_id=project_id,
                    ordinal=child.ordinal,
                    engine=child.engine,
                    target_agent_id=target_agent_id,
                    payload=child.payload,
                    payload_digest=child.payload_digest,
                    payload_size=child.payload_size,
                    required_contract_version=RETRY_CONTRACT_VERSION,
                    delivery_state=BulkRetryDeliveryState.PENDING.value,
                    outcome=BulkRetryOutcome.UNOBSERVED.value,
                    created_at=now,
                )
            )
        await self.session.flush()
        return parent

    async def counts(self, parent_id: UUID) -> BulkRetryCounts:
        result = await self.session.execute(
            select(
                func.count(BulkRetryRequestChild.id),
                func.sum(
                    case(
                        (
                            BulkRetryRequestChild.delivery_state
                            == BulkRetryDeliveryState.PENDING.value,
                            1,
                        ),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (
                            BulkRetryRequestChild.delivery_state
                            == BulkRetryDeliveryState.DELIVERY_CLAIMED.value,
                            1,
                        ),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (
                            BulkRetryRequestChild.outcome == BulkRetryOutcome.UNOBSERVED.value,
                            1,
                        ),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (
                            BulkRetryRequestChild.outcome == BulkRetryOutcome.SUCCEEDED.value,
                            1,
                        ),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (
                            BulkRetryRequestChild.outcome == BulkRetryOutcome.FAILED.value,
                            1,
                        ),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (
                            BulkRetryRequestChild.outcome == BulkRetryOutcome.UNKNOWN.value,
                            1,
                        ),
                        else_=0,
                    )
                ),
            ).where(BulkRetryRequestChild.parent_id == parent_id)
        )
        row = result.one()
        values = [int(value or 0) for value in row]
        return BulkRetryCounts(*values)

    async def snapshot(self, parent: BulkRetryRequest) -> BulkRetrySnapshot:
        counts = await self.counts(parent.id)
        return BulkRetrySnapshot(
            parent=parent,
            counts=counts,
            status=derive_bulk_retry_status(parent, counts),
        )

    async def fair_parent_ids(
        self,
        *,
        limit: int,
        project_id: UUID | None = None,
        eligible_agent_id: UUID | None = None,
        eligible_engines: tuple[str, ...] | None = None,
    ) -> list[UUID]:
        if eligible_engines is not None and not eligible_engines:
            return []
        pending_predicates = [
            BulkRetryRequestChild.parent_id == BulkRetryRequest.id,
            BulkRetryRequestChild.delivery_state == BulkRetryDeliveryState.PENDING.value,
        ]
        if eligible_agent_id is not None:
            pending_predicates.append(
                (BulkRetryRequestChild.target_agent_id.is_(None))
                | (BulkRetryRequestChild.target_agent_id == eligible_agent_id)
            )
        if eligible_engines is not None:
            pending_predicates.append(BulkRetryRequestChild.engine.in_(eligible_engines))
        pending_exists = select(BulkRetryRequestChild.id).where(*pending_predicates).exists()
        in_flight_count = (
            select(func.count(BulkRetryRequestChild.id))
            .where(
                BulkRetryRequestChild.parent_id == BulkRetryRequest.id,
                BulkRetryRequestChild.delivery_state
                == BulkRetryDeliveryState.DELIVERY_CLAIMED.value,
                BulkRetryRequestChild.outcome == BulkRetryOutcome.UNOBSERVED.value,
            )
            .scalar_subquery()
        )
        statement = select(BulkRetryRequest.id).where(
            BulkRetryRequest.control_state == BulkRetryControlState.RUNNING.value,
            BulkRetryRequest.deadline_at > datetime.now(UTC),
            in_flight_count < BulkRetryRequest.max_in_flight,
            pending_exists,
        )
        if project_id is not None:
            statement = statement.where(BulkRetryRequest.project_id == project_id)
        result = await self.session.execute(
            statement.order_by(
                BulkRetryRequest.updated_at.asc(),
                BulkRetryRequest.created_at.asc(),
                BulkRetryRequest.id.asc(),
            ).limit(limit)
        )
        return list(result.scalars().all())

    async def pending_children(
        self,
        *,
        parent_id: UUID,
        limit: int = 32,
        eligible_agent_id: UUID | None = None,
        eligible_engines: tuple[str, ...] | None = None,
    ) -> list[BulkRetryRequestChild]:
        if eligible_engines is not None and not eligible_engines:
            return []
        predicates = [
            BulkRetryRequestChild.parent_id == parent_id,
            BulkRetryRequestChild.delivery_state == BulkRetryDeliveryState.PENDING.value,
        ]
        if eligible_agent_id is not None:
            predicates.append(
                (BulkRetryRequestChild.target_agent_id.is_(None))
                | (BulkRetryRequestChild.target_agent_id == eligible_agent_id)
            )
        if eligible_engines is not None:
            predicates.append(BulkRetryRequestChild.engine.in_(eligible_engines))
        result = await self.session.execute(
            select(BulkRetryRequestChild)
            .where(*predicates)
            .order_by(BulkRetryRequestChild.ordinal.asc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def pending_engines(self, *, parent_id: UUID) -> list[str]:
        """Return the bounded engine set without an ordinal-prefix bias."""

        result = await self.session.execute(
            select(BulkRetryRequestChild.engine)
            .where(
                BulkRetryRequestChild.parent_id == parent_id,
                BulkRetryRequestChild.delivery_state == BulkRetryDeliveryState.PENDING.value,
            )
            .distinct()
            .order_by(BulkRetryRequestChild.engine.asc())
        )
        return list(result.scalars().all())

    async def touch_scan_position(self, *, parent_id: UUID) -> None:
        """Durably rotate an examined parent that made no progress."""

        await self.session.execute(
            update(BulkRetryRequest)
            .where(
                BulkRetryRequest.id == parent_id,
                BulkRetryRequest.control_state == BulkRetryControlState.RUNNING.value,
            )
            .values(updated_at=datetime.now(UTC))
        )

    async def claim_child(
        self,
        *,
        child_id: UUID,
        agent_id: UUID,
        generation: UUID,
        command_timeout_seconds: int,
    ) -> Command | None:
        """Atomically claim one child and create one non-redrivable command."""

        await self.begin_immediate_if_sqlite()
        child_result = await self.session.execute(
            select(BulkRetryRequestChild).where(BulkRetryRequestChild.id == child_id)
        )
        child = child_result.scalar_one_or_none()
        if child is None:
            return None
        live_agent = (
            await self.session.execute(
                select(Agent)
                .where(
                    Agent.id == agent_id,
                    Agent.project_id == child.project_id,
                    Agent.revoked_at.is_(None),
                )
                .with_for_update(),
            )
        ).scalar_one_or_none()
        # This is the irreversible claim edge, so re-derive the retry
        # requirement from the sealed payload here rather than trusting the
        # denormalized child.engine or any upstream issuer.
        from z4j_brain.domain.retry_contract import required_retry_engine

        if live_agent is None or required_retry_engine("bulk_retry", child.payload) != child.engine:
            return None
        parent = await self.get_for_project(
            project_id=child.project_id,
            request_id=child.parent_id,
            lock=True,
        )
        now = datetime.now(UTC)
        if (
            parent is None
            or parent.control_state != BulkRetryControlState.RUNNING.value
            or _as_utc(parent.deadline_at) <= now
            or (child.target_agent_id is not None and child.target_agent_id != agent_id)
        ):
            return None

        in_flight_result = await self.session.execute(
            select(func.count(BulkRetryRequestChild.id)).where(
                BulkRetryRequestChild.parent_id == parent.id,
                BulkRetryRequestChild.delivery_state
                == BulkRetryDeliveryState.DELIVERY_CLAIMED.value,
                BulkRetryRequestChild.outcome == BulkRetryOutcome.UNOBSERVED.value,
            )
        )
        if int(in_flight_result.scalar_one()) >= parent.max_in_flight:
            return None

        deadline = min(
            _as_utc(parent.deadline_at),
            now + timedelta(seconds=command_timeout_seconds),
        )
        claimed = await self.session.execute(
            update(BulkRetryRequestChild)
            .where(
                BulkRetryRequestChild.id == child_id,
                BulkRetryRequestChild.delivery_state == BulkRetryDeliveryState.PENDING.value,
            )
            .values(
                delivery_state=BulkRetryDeliveryState.DELIVERY_CLAIMED.value,
                claimed_agent_id=agent_id,
                claimed_generation=generation,
                claimed_at=now,
                claim_deadline_at=deadline,
            )
            .returning(BulkRetryRequestChild.id)
        )
        if claimed.scalar_one_or_none() is None:
            return None

        command = Command(
            id=uuid.uuid4(),
            project_id=parent.project_id,
            agent_id=agent_id,
            issued_by=parent.issued_by,
            action="bulk_retry",
            target_type="bulk",
            target_id=None,
            payload=dict(child.payload),
            idempotency_key=None,
            status=CommandStatus.DISPATCHED,
            issued_at=now,
            dispatched_at=now,
            timeout_at=deadline,
            source_ip=None,
            bulk_retry_child_id=child.id,
        )
        self.session.add(command)
        await self.session.execute(
            update(BulkRetryRequest)
            .where(BulkRetryRequest.id == parent.id)
            .values(last_progress_at=now, updated_at=now)
        )
        await self.session.flush()
        return command

    async def reconcile_command_outcomes(
        self,
        *,
        limit: int = 1000,
        command_id: UUID | None = None,
    ) -> int:
        """Project terminal commands, including authenticated late results."""

        statement = (
            select(BulkRetryRequestChild, Command)
            .join(Command, Command.bulk_retry_child_id == BulkRetryRequestChild.id)
            .where(
                BulkRetryRequestChild.delivery_state
                == BulkRetryDeliveryState.DELIVERY_CLAIMED.value,
                Command.status.in_(
                    [
                        CommandStatus.COMPLETED,
                        CommandStatus.FAILED,
                        CommandStatus.TIMEOUT,
                    ]
                ),
                (BulkRetryRequestChild.outcome == BulkRetryOutcome.UNOBSERVED.value)
                | (
                    (BulkRetryRequestChild.outcome == BulkRetryOutcome.UNKNOWN.value)
                    & Command.status.in_([CommandStatus.COMPLETED, CommandStatus.FAILED])
                ),
            )
        )
        if command_id is not None:
            statement = statement.where(Command.id == command_id)
        result = await self.session.execute(
            statement.order_by(BulkRetryRequestChild.claimed_at.asc()).limit(limit)
        )
        changed = 0
        now = datetime.now(UTC)
        parent_ids: set[UUID] = set()
        for child, command in result.all():
            if command.status == CommandStatus.COMPLETED:
                outcome = BulkRetryOutcome.SUCCEEDED.value
                error = None
                eligible_outcomes = (
                    BulkRetryOutcome.UNOBSERVED.value,
                    BulkRetryOutcome.UNKNOWN.value,
                )
            elif command.status == CommandStatus.FAILED:
                outcome = BulkRetryOutcome.FAILED.value
                error = command.error
                eligible_outcomes = (
                    BulkRetryOutcome.UNOBSERVED.value,
                    BulkRetryOutcome.UNKNOWN.value,
                )
            else:
                outcome = BulkRetryOutcome.UNKNOWN.value
                error = (
                    "delivery outcome unknown: the command may have executed "
                    "and the original attempt may still execute"
                )
                eligible_outcomes = (BulkRetryOutcome.UNOBSERVED.value,)
            command_still_has_observed_status = (
                select(Command.id)
                .where(
                    Command.id == command.id,
                    Command.bulk_retry_child_id == child.id,
                    Command.status == command.status,
                )
                .exists()
            )
            projected = await self.session.execute(
                update(BulkRetryRequestChild)
                .where(
                    BulkRetryRequestChild.id == child.id,
                    BulkRetryRequestChild.outcome.in_(eligible_outcomes),
                    command_still_has_observed_status,
                )
                .values(outcome=outcome, completed_at=now, error=error)
                .execution_options(synchronize_session=False)
            )
            if projected.rowcount:
                parent_ids.add(child.parent_id)
                changed += 1
        if parent_ids:
            await self.session.execute(
                update(BulkRetryRequest)
                .where(BulkRetryRequest.id.in_(parent_ids))
                .values(last_progress_at=now, updated_at=now)
            )
        return changed

    async def expire_claims(self, *, now: datetime) -> int:
        result = await self.session.execute(
            update(BulkRetryRequestChild)
            .execution_options(synchronize_session=False)
            .where(
                BulkRetryRequestChild.delivery_state
                == BulkRetryDeliveryState.DELIVERY_CLAIMED.value,
                BulkRetryRequestChild.outcome == BulkRetryOutcome.UNOBSERVED.value,
                BulkRetryRequestChild.claim_deadline_at < now,
            )
            .values(
                outcome=BulkRetryOutcome.UNKNOWN.value,
                completed_at=now,
                error=(
                    "delivery outcome unknown: the command may have executed "
                    "and the original attempt may still execute"
                ),
            )
        )
        return int(result.rowcount or 0)

    async def block_expired_parents(self, *, now: datetime) -> int:
        pending_exists = (
            select(BulkRetryRequestChild.id)
            .where(
                BulkRetryRequestChild.parent_id == BulkRetryRequest.id,
                BulkRetryRequestChild.delivery_state == BulkRetryDeliveryState.PENDING.value,
            )
            .exists()
        )
        result = await self.session.execute(
            update(BulkRetryRequest)
            .where(
                BulkRetryRequest.control_state == BulkRetryControlState.RUNNING.value,
                BulkRetryRequest.deadline_at <= now,
                pending_exists,
            )
            .values(
                control_state=BulkRetryControlState.BLOCKED.value,
                updated_at=now,
            )
        )
        return int(result.rowcount or 0)

    async def set_control_state(
        self,
        *,
        project_id: UUID,
        request_id: UUID,
        control_state: BulkRetryControlState,
        resume_window_seconds: int | None = None,
    ) -> BulkRetryRequest | None:
        parent = await self.get_for_project(
            project_id=project_id,
            request_id=request_id,
            lock=True,
        )
        if parent is None:
            return None
        values: dict[str, Any] = {
            "control_state": control_state.value,
            "updated_at": datetime.now(UTC),
        }
        if control_state == BulkRetryControlState.RUNNING and resume_window_seconds is not None:
            values["deadline_at"] = datetime.now(UTC) + timedelta(seconds=resume_window_seconds)
        await self.session.execute(
            update(BulkRetryRequest).where(BulkRetryRequest.id == parent.id).values(**values)
        )
        await self.session.flush()
        await self.session.refresh(parent)
        return parent


__all__ = [
    "BulkRetryCounts",
    "BulkRetryRequestRepository",
    "BulkRetrySnapshot",
    "derive_bulk_retry_status",
]
