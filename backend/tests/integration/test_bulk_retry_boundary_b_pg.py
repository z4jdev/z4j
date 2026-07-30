"""Boundary-B creator and scanner races on real PostgreSQL."""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from z4j_brain.api.bulk_retry_requests import (
    BulkRetryRequestCreate,
    create_bulk_retry_request,
)
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.bulk_retry import PlannedChild, canonicalize_request
from z4j_brain.persistence.enums import CommandStatus
from z4j_brain.persistence.models import (
    Agent,
    AuditLog,
    BulkRetryDeliveryState,
    BulkRetryOutcome,
    BulkRetryRequest,
    BulkRetryRequestChild,
    Command,
    Project,
    User,
)
from z4j_brain.persistence.repositories import (
    AuditLogRepository,
    BulkRetryRequestRepository,
    CommandRepository,
)
from z4j_brain.settings import Settings

pytestmark = pytest.mark.asyncio


class _AllowProjectPolicy:
    async def get_project_or_404(self, projects: Any, _slug: str) -> Any:
        return projects

    async def require_member(
        self,
        _memberships: Any,
        **_kwargs: Any,
    ) -> None:
        return None


def _child(ordinal: int) -> PlannedChild:
    task_id = f"pg-task-{ordinal}"
    payload = {
        "filter": {
            "engine": "celery",
            "task_ids": [task_id],
            "task_names": {task_id: "tasks.work"},
        },
        "max": 1,
    }
    exact = (
        f'{{"filter":{{"engine":"celery","task_ids":["{task_id}"],'
        f'"task_names":{{"{task_id}":"tasks.work"}}}},"max":1}}'
    ).encode()
    return PlannedChild(
        ordinal=ordinal,
        engine="celery",
        payload=payload,
        canonical_payload=exact,
        payload_digest=hashlib.sha256(exact).hexdigest(),
        payload_size=len(exact),
    )


async def _seed_project(
    sessions: async_sessionmaker[AsyncSession],
) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    project_id = uuid.uuid4()
    user_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    async with sessions() as session:
        session.add(Project(id=project_id, slug="boundary-b-pg", name="Boundary B"))
        session.add(
            User(
                id=user_id,
                email=f"boundary-b-{uuid.uuid4()}@example.com",
                password_hash="not-used",
            )
        )
        await session.commit()
        session.add(
            Agent(
                id=agent_id,
                project_id=project_id,
                name="boundary-b-agent",
                token_hash=f"token-{agent_id}",
                protocol_version="2",
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
            )
        )
        await session.commit()
    return project_id, user_id, agent_id


async def _seal(
    session: AsyncSession,
    *,
    project_id: uuid.UUID,
    user_id: uuid.UUID,
    key: str,
    children: list[PlannedChild],
    max_in_flight: int,
) -> BulkRetryRequest:
    canonical = canonicalize_request({"filter": {"state": "failure"}})
    return await BulkRetryRequestRepository(session).insert_sealed(
        project_id=project_id,
        issued_by=user_id,
        idempotency_key=key,
        canonical=canonical,
        target_agent_id=None,
        planned_children=children,
        plan_digest=hashlib.sha256(key.encode()).hexdigest(),
        max_in_flight=max_in_flight,
        deadline_at=datetime.now(UTC) + timedelta(minutes=15),
        source_ip="127.0.0.1",
    )


async def test_concurrent_creators_return_one_exact_parent(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions = async_sessionmaker(migrated_engine, expire_on_commit=False)
    project_id, user_id, _agent_id = await _seed_project(sessions)
    monkeypatch.setattr(
        "z4j_brain.domain.policy_engine.PolicyEngine",
        _AllowProjectPolicy,
    )
    body = BulkRetryRequestCreate(
        idempotency_key="same-raw-key",
        filter={"state": "failure"},
        max=100,
    )

    async def _create() -> tuple[uuid.UUID, int]:
        async with sessions() as session:
            project = await session.get(Project, project_id)
            user = await session.get(User, user_id)
            assert project is not None and user is not None
            response = Response()
            result = await create_bulk_retry_request(
                slug=project.slug,
                body=body,
                response=response,
                user=user,
                memberships=object(),
                projects=project,
                audit_log=AuditLogRepository(session),
                audit_service=AuditService(integration_settings),
                db_session=session,
                settings=integration_settings,
                ip="127.0.0.1",
            )
            return result.id, response.status_code

    results = await asyncio.gather(_create(), _create())
    assert results[0][0] == results[1][0]
    assert {status for _, status in results} <= {200, 202}

    async with sessions() as session:
        assert (
            await session.scalar(
                select(func.count(BulkRetryRequest.id)).where(
                    BulkRetryRequest.project_id == project_id,
                    BulkRetryRequest.idempotency_key == "same-raw-key",
                )
            )
            == 1
        )
        reservation = await session.scalar(
            select(Command).where(
                Command.project_id == project_id,
                Command.idempotency_key == "same-raw-key",
            )
        )
        assert reservation is not None
        assert reservation.action == "bulk_retry_request.reservation"
        assert reservation.status == CommandStatus.COMPLETED
        assert (
            await session.scalar(
                select(func.count(AuditLog.id)).where(
                    AuditLog.project_id == project_id,
                    AuditLog.action == "bulk_retry_request.sealed",
                )
            )
            == 1
        )


async def test_parent_lock_enforces_cross_scanner_inflight_bound(
    migrated_engine: AsyncEngine,
) -> None:
    sessions = async_sessionmaker(migrated_engine, expire_on_commit=False)
    project_id, user_id, agent_id = await _seed_project(sessions)
    async with sessions() as session:
        parent = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="pg-parent-bound",
            children=[_child(0), _child(1)],
            max_in_flight=1,
        )
        await session.commit()
        child_ids = list(
            (
                await session.execute(
                    select(BulkRetryRequestChild.id)
                    .where(BulkRetryRequestChild.parent_id == parent.id)
                    .order_by(BulkRetryRequestChild.ordinal)
                )
            ).scalars()
        )

    async def _claim(child_id: uuid.UUID) -> Command | None:
        async with sessions() as session:
            command = await BulkRetryRequestRepository(session).claim_child(
                child_id=child_id,
                agent_id=agent_id,
                generation=uuid.uuid4(),
                command_timeout_seconds=60,
            )
            await session.commit()
            return command

    claims = await asyncio.gather(*(_claim(child_id) for child_id in child_ids))
    assert sum(command is not None for command in claims) == 1
    async with sessions() as session:
        assert (
            await session.scalar(
                select(func.count(BulkRetryRequestChild.id)).where(
                    BulkRetryRequestChild.parent_id == parent.id,
                    BulkRetryRequestChild.delivery_state
                    == BulkRetryDeliveryState.DELIVERY_CLAIMED.value,
                )
            )
            == 1
        )
        assert (
            await session.scalar(
                select(func.count(Command.id)).where(Command.bulk_retry_child_id.is_not(None))
            )
            == 1
        )


async def test_conditional_claim_has_one_winner_on_same_child(
    migrated_engine: AsyncEngine,
) -> None:
    sessions = async_sessionmaker(migrated_engine, expire_on_commit=False)
    project_id, user_id, agent_id = await _seed_project(sessions)
    async with sessions() as session:
        parent = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="pg-child-winner",
            children=[_child(0)],
            max_in_flight=8,
        )
        await session.commit()
        child_id = await session.scalar(
            select(BulkRetryRequestChild.id).where(BulkRetryRequestChild.parent_id == parent.id)
        )
    assert child_id is not None

    async def _claim() -> Command | None:
        async with sessions() as session:
            command = await BulkRetryRequestRepository(session).claim_child(
                child_id=child_id,
                agent_id=agent_id,
                generation=uuid.uuid4(),
                command_timeout_seconds=60,
            )
            await session.commit()
            return command

    claims = await asyncio.gather(_claim(), _claim())
    assert sum(command is not None for command in claims) == 1
    async with sessions() as session:
        assert (
            await session.scalar(
                select(func.count(Command.id)).where(Command.bulk_retry_child_id == child_id)
            )
            == 1
        )


async def test_stale_timeout_projection_cannot_overwrite_authenticated_success(
    migrated_engine: AsyncEngine,
) -> None:
    """A projection must validate its observation again when it writes."""

    sessions = async_sessionmaker(migrated_engine, expire_on_commit=False)
    project_id, user_id, agent_id = await _seed_project(sessions)
    async with sessions() as session:
        parent = await _seal(
            session,
            project_id=project_id,
            user_id=user_id,
            key="pg-late-result-race",
            children=[_child(0)],
            max_in_flight=1,
        )
        await session.commit()
        child_id = await session.scalar(
            select(BulkRetryRequestChild.id).where(BulkRetryRequestChild.parent_id == parent.id)
        )
    assert child_id is not None

    async with sessions() as session:
        command = await BulkRetryRequestRepository(session).claim_child(
            child_id=child_id,
            agent_id=agent_id,
            generation=uuid.uuid4(),
            command_timeout_seconds=60,
        )
        assert command is not None
        command.status = CommandStatus.TIMEOUT
        command.completed_at = datetime.now(UTC)
        command.error = "timed out"
        command_id = command.id
        await session.commit()

    stale_selected = asyncio.Event()
    release_stale = asyncio.Event()

    class _PausingSession(AsyncSession):
        async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
            result = await super().execute(statement, *args, **kwargs)
            rendered = str(statement)
            if (
                getattr(statement, "is_select", False)
                and "bulk_retry_request_children" in rendered
                and "JOIN commands" in rendered
                and not stale_selected.is_set()
            ):
                stale_selected.set()
                await release_stale.wait()
            return result

    pausing_sessions = async_sessionmaker(
        migrated_engine,
        class_=_PausingSession,
        expire_on_commit=False,
    )

    stale_changes: list[int] = []

    async def _project_stale_timeout() -> None:
        async with pausing_sessions() as session:
            changed = await BulkRetryRequestRepository(session).reconcile_command_outcomes(
                command_id=command_id
            )
            stale_changes.append(changed)
            await session.commit()

    stale_task = asyncio.create_task(_project_stale_timeout())
    await asyncio.wait_for(stale_selected.wait(), timeout=10)

    async with sessions() as session:
        commands = CommandRepository(session)
        assert await commands.mark_completed(
            command_id,
            result_payload={"retried": 1},
            project_id=project_id,
            agent_id=agent_id,
        )
        assert (
            await BulkRetryRequestRepository(session).reconcile_command_outcomes(
                command_id=command_id
            )
            == 1
        )
        await session.commit()

    release_stale.set()
    await stale_task
    assert stale_changes == [0]

    async with sessions() as session:
        final_command = await session.get(Command, command_id)
        final_child = await session.get(BulkRetryRequestChild, child_id)
        assert final_command is not None
        assert final_child is not None
        assert final_command.status == CommandStatus.COMPLETED
        assert final_child.outcome == BulkRetryOutcome.SUCCEEDED.value
