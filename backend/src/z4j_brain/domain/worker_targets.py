"""Conservative command targets from retained, authenticated worker reports."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import select

from z4j_brain.errors import ValidationError
from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models import Event, Worker

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.persistence.models import Agent


async def worker_reporting_agent(
    session: AsyncSession,
    *,
    project_id: UUID,
    engine: str,
    worker_name: str,
) -> UUID | None:
    """Return the sole reporter of this engine/name, or no provable target.

    Worker rows have no owning-agent column. Only retained worker lifecycle
    events bind their exact engine/name to an authenticated reporting agent;
    task events can be deduplicated across observers and are not evidence.
    Multiple reporters are ambiguous even if only one is currently online.
    Event retention may remove all evidence, in which case controls stay off.
    An agent identity does not prove an individual process under a shared token.
    """
    reporters = list(
        await session.scalars(
            select(Event.agent_id)
            .where(
                Event.project_id == project_id,
                Event.engine == engine,
                Event.kind.startswith("worker."),
                Event.payload["worker"].as_string() == worker_name,
            )
            .distinct()
            .limit(2),
        )
    )
    return reporters[0] if len(reporters) == 1 else None


async def require_native_worker_target(
    session: AsyncSession,
    *,
    project_id: UUID,
    agent: Agent,
    worker_name: str,
    engine: str | None,
    action: str,
) -> str:
    """Resolve a stored worker and require its sole reporter's native action.

    Older callers can omit engine only when the project has exactly one
    matching worker name. Always put the resolved engine on the command.
    Unreported inventory and self-exit restart polyfills cannot establish a
    safe named-worker target, so neither is admitted here.
    """
    query = select(Worker).where(Worker.project_id == project_id, Worker.name == worker_name)
    if engine is not None:
        query = query.where(Worker.engine == engine)
    workers = list(await session.scalars(query.limit(2)))
    if len(workers) != 1:
        raise ValidationError("worker target is missing or ambiguous; specify its engine")
    worker = workers[0]
    reporter = await worker_reporting_agent(
        session,
        project_id=project_id,
        engine=worker.engine,
        worker_name=worker.name,
    )
    if reporter is None or reporter != agent.id:
        raise ValidationError("worker has no unambiguous reporting relationship to this agent")
    capabilities = (agent.capabilities or {}).get(worker.engine)
    if (
        agent.state != AgentState.ONLINE
        or worker.engine not in (agent.engine_adapters or [])
        or not isinstance(capabilities, list)
        or action not in capabilities
    ):
        raise ValidationError(
            "worker control requires an online reporter advertising the native action"
        )
    return worker.engine
