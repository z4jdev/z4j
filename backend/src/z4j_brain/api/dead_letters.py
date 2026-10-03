"""``/api/v1/projects/{slug}/dead-letters`` REST router.

The read side of the dead-letter store, so a dashboard can show *what* is
parked before an operator decides to requeue it. The brain holds no copy of
an engine's dead letters; each request issues one ``dlq.list`` command to an
online agent whose session advertises the engine with ``list_dead_letters``
(the capability rule in :mod:`z4j_brain.domain.retry_contract`), waits for
the agent's ``command_result``, re-validates the page it returned and hands
it back. The command row and its result stay in the ``commands`` table like
any other command, so the listing is auditable and the raw page can be
inspected afterwards.

The wait is bounded: a page that does not arrive within
:data:`DEAD_LETTER_WAIT_SECONDS` (or the configured command timeout, when
shorter) is a ``504`` naming the command; the agent's late result still lands
on the row. The wait polls the durable row rather than an in-process future
because the result may be received by another brain replica.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from z4j_core.models.dead_letter import (
    DLQ_LIST_ACTION,
    DLQ_LIST_DEFAULT_LIMIT,
    DLQ_LIST_MAX_LIMIT,
    LIST_DEAD_LETTERS_CAPABILITY,
    DeadLetterPage,
)

from z4j_brain.api.deps import (
    get_audit_service,
    get_brain_registry,
    get_client_ip,
    get_command_dispatcher,
    get_current_user,
    get_db,
    get_membership_repo,
    get_project_repo,
    get_session,
    get_settings,
    resolve_api_key_id,
)
from z4j_brain.domain.ip_rate_limit import require_bulk_action_throttle
from z4j_brain.domain.retry_contract import (
    advertised_actions,
    agent_reports_inventory,
    dispatch_refusal,
    engine_name_error,
)
from z4j_brain.persistence.enums import CommandStatus, ProjectRole
from z4j_brain.persistence.models import Command

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.domain.command_dispatcher import CommandDispatcher
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.persistence.models import Agent, User
    from z4j_brain.persistence.repositories import (
        MembershipRepository,
        ProjectRepository,
    )
    from z4j_brain.settings import Settings


router = APIRouter(prefix="/projects/{slug}/dead-letters", tags=["dead-letters"])

#: Upper bound on how long one listing request waits for the agent's page.
#: The effective wait is the smaller of this and ``command_timeout_seconds``.
DEAD_LETTER_WAIT_SECONDS: float = 15.0

#: Longest cursor the brain forwards. Matches ``DeadLetterPage.next_cursor``,
#: which is where every cursor a client can legitimately hold came from.
CURSOR_MAX_LENGTH = 200

#: The text every adapter produces when it refuses a cursor it cannot page
#: from: :func:`z4j_core.models.dead_letter.decode_offset_cursor` raises it
#: and the adapters wrap it unchanged in their ``ValidationError``. A failed
#: command carries only its error string (no structured refusal), so this
#: exact text, not the word "cursor", is what tells the client's error (422)
#: from the upstream's (502): a broker failure that happens to mention a
#: cursor (a Redis ``SCAN`` cursor, say) stays a 502.
CURSOR_REFUSAL_TEXT = "invalid dead-letter cursor"

#: Command states that end the wait.
_TERMINAL = frozenset(
    {
        CommandStatus.COMPLETED,
        CommandStatus.FAILED,
        CommandStatus.TIMEOUT,
        CommandStatus.CANCELLED,
    }
)


def cursor_error(cursor: str | None) -> str | None:
    """Why ``cursor`` cannot be a token a previous page handed out, or ``None``.

    The brain never interprets a cursor; its shape belongs to the adapter.
    This bounds it to what ``next_cursor`` can carry (printable ASCII without
    whitespace, at most :data:`CURSOR_MAX_LENGTH` characters) so a malformed
    value is refused here instead of being delivered to an agent.
    """
    if cursor is None or cursor == "":
        return None
    if len(cursor) > CURSOR_MAX_LENGTH:
        return f"cursor is longer than {CURSOR_MAX_LENGTH} characters"
    if any(not (33 <= ord(ch) <= 126) for ch in cursor):
        return "cursor must be the next_cursor of a previous page (printable ASCII, no whitespace)"
    return None


def wait_seconds(settings: Settings) -> float:
    """How long one request may wait for the agent's page."""
    return max(0.0, min(DEAD_LETTER_WAIT_SECONDS, float(settings.command_timeout_seconds)))


def _agent_summary(agent: Agent, engine: str) -> dict[str, Any]:
    engines = [name for name in (agent.engine_adapters or []) if isinstance(name, str)]
    return {
        "id": str(agent.id),
        "name": agent.name,
        "engines": sorted(engines),
        "advertises": sorted(advertised_actions(agent.capabilities, engine)),
        "inventory_reported": agent_reports_inventory(agent),
    }


def _choose_agent(agents: list[Agent], *, registry: Any) -> Agent | None:
    """The online agent this listing goes to, or ``None``.

    Every candidate passed the capability rule. An agent whose hello
    advertised the engine with the token is preferred over one whose
    inventory is unreported (a long-poll row, admitted on its next poll), and
    among those, one with a session on this registry delivers fastest.
    """
    reported = [agent for agent in agents if agent_reports_inventory(agent)]
    for pool in (reported, agents):
        for agent in pool:
            try:
                local = bool(registry.is_online(agent.id))
            except Exception:
                local = False
            if local:
                return agent
        if pool:
            return pool[0]
    return None


async def _read_terminal(
    db: DatabaseManager, command_id: uuid.UUID
) -> tuple[CommandStatus, Any, str | None] | None:
    """The command's (status, result, error) once terminal, else ``None``."""
    async with db.session() as session:
        row = (
            await session.execute(
                select(Command.status, Command.result, Command.error).where(
                    Command.id == command_id
                )
            )
        ).one_or_none()
    if row is None:
        return None
    status, result, error = row
    if status not in _TERMINAL:
        return None
    return status, result, error


async def _wait_for_page(
    db: DatabaseManager, *, command_id: uuid.UUID, wait: float
) -> tuple[CommandStatus, Any, str | None] | None:
    """Poll the durable command row until it is terminal or ``wait`` seconds pass."""
    deadline = time.monotonic() + wait
    interval = 0.05
    while True:
        outcome = await _read_terminal(db, command_id)
        if outcome is not None:
            return outcome
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        await asyncio.sleep(min(interval, remaining))
        interval = min(interval * 1.5, 0.25)


@router.get(
    "",
    response_model=DeadLetterPage,
    # Each listing fans a command out to an agent and holds the request for
    # up to ``DEAD_LETTER_WAIT_SECONDS``, so it draws on the same per-IP
    # bucket as the other agent fan-outs (bulk retry, purge, trigger-now)
    # rather than being the one unbounded way to keep a worker busy.
    dependencies=[Depends(require_bulk_action_throttle)],
)
async def list_dead_letters(
    slug: str,
    request: Request,
    engine: str = Query(min_length=1, max_length=40),
    queue: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=DLQ_LIST_DEFAULT_LIMIT, ge=1, le=DLQ_LIST_MAX_LIMIT),
    cursor: str | None = Query(default=None, max_length=CURSOR_MAX_LENGTH),
    user: User = Depends(get_current_user),
    memberships: MembershipRepository = Depends(get_membership_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    db_session: AsyncSession = Depends(get_session),
    db: DatabaseManager = Depends(get_db),
    dispatcher: CommandDispatcher = Depends(get_command_dispatcher),
    audit_service: AuditService = Depends(get_audit_service),
    registry: Any = Depends(get_brain_registry),
    settings: Settings = Depends(get_settings),
    ip: str = Depends(get_client_ip),
) -> DeadLetterPage:
    """One page of the engine's dead letters, newest first.

    ``engine`` is required and checked for shape only; whether anything can
    serve it is decided by the online agents' advertised capabilities. ``queue``
    narrows the page to one queue; absent, every queue the adapter knows. The
    ``cursor`` is the ``next_cursor`` of the previous page, passed back
    verbatim.

    Errors: ``409`` when no online agent advertises ``list_dead_letters`` for
    the engine (the response lists the online agents and what each advertises
    for it), ``504`` when the agent does not answer within the wait bound,
    ``422`` for a malformed engine, limit or cursor, ``429`` when the
    caller's address has used up the bulk-action bucket, and ``502`` when
    the agent refused the listing or returned something that is not a page.
    """
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import (
        AgentRepository,
        AuditLogRepository,
        CommandRepository,
    )

    shape_error = engine_name_error(engine)
    if shape_error is not None:
        raise HTTPException(status_code=422, detail={"error": shape_error, "engine": engine})
    bad_cursor = cursor_error(cursor)
    if bad_cursor is not None:
        # A stable code with the sentence as the message, so a client that
        # keys on the code does not read the sentence as one.
        raise HTTPException(
            status_code=422, detail={"error": "invalid_cursor", "message": bad_cursor}
        )
    queue = queue or None
    cursor = cursor or None

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project=project,
        min_role=ProjectRole.VIEWER,
    )

    online = await AgentRepository(db_session).list_online_for_project(project.id)
    capable = [
        agent
        for agent in online
        if dispatch_refusal(agent, engine=engine, action=DLQ_LIST_ACTION) is None
    ]
    target = _choose_agent(capable, registry=registry)
    if target is None:
        raise HTTPException(
            status_code=409,
            detail={
                "error": (
                    f"no online agent advertises {LIST_DEAD_LETTERS_CAPABILITY!r} for "
                    f"engine {engine!r}"
                ),
                "engine": engine,
                "capability": LIST_DEAD_LETTERS_CAPABILITY,
                "agents": [_agent_summary(agent, engine) for agent in online],
            },
        )

    # The command insert is a write, and a GET's request session is a read
    # unit, so the command and the listing's audit row go through their own
    # write session (the SQLite write unit begins immediately there). Both
    # rows commit together in ``dispatcher.issue``.
    async with db.session(write=True) as write_session:
        audit_log = AuditLogRepository(write_session)
        await audit_service.record(
            audit_log,
            action="dead_letters.list",
            target_type="queue",
            target_id=f"{engine}:{queue or '*'}",
            result="success",
            outcome="allow",
            user_id=user.id,
            project_id=project.id,
            api_key_id=resolve_api_key_id(request),
            source_ip=ip,
            metadata={
                "engine": engine,
                "queue": queue,
                "limit": limit,
                "cursor_supplied": cursor is not None,
                "agent_id": str(target.id),
                "agent_name": target.name,
            },
        )
        command = await dispatcher.issue(
            commands=CommandRepository(write_session),
            audit_log=audit_log,
            project_id=project.id,
            agent_id=target.id,
            action=DLQ_LIST_ACTION,
            target_type="queue",
            target_id=queue,
            payload={
                "engine": engine,
                "queue": queue,
                "limit": limit,
                "cursor": cursor,
            },
            issued_by=user.id,
            ip=ip,
            user_agent=None,
        )
        command_id = command.id

    outcome = await _wait_for_page(db, command_id=command_id, wait=wait_seconds(settings))
    if outcome is None:
        raise HTTPException(
            status_code=504,
            detail={
                "error": (
                    f"agent {target.name!r} did not answer the dead-letter listing "
                    f"within {wait_seconds(settings):g}s"
                ),
                "command_id": str(command_id),
                "agent_id": str(target.id),
                "engine": engine,
            },
        )
    status, result, error = outcome
    if status is not CommandStatus.COMPLETED:
        message = error or f"command ended in state {status.value!r}"
        if status is CommandStatus.TIMEOUT:
            raise HTTPException(
                status_code=504,
                detail={"error": message, "command_id": str(command_id), "engine": engine},
            )
        # The adapter validates the one opaque client input it owns, the
        # cursor, and refuses a value it cannot page from with the core's
        # exact text; that is the client's error. Anything else (broker
        # unreachable, a capability the agent withdrew between hello and
        # now, a broker error that merely mentions a cursor) is the
        # upstream's.
        upstream_status = 422 if CURSOR_REFUSAL_TEXT in message else 502
        raise HTTPException(
            status_code=upstream_status,
            detail={"error": message, "command_id": str(command_id), "engine": engine},
        )
    try:
        return DeadLetterPage.model_validate(result, strict=False)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail={
                "error": f"agent {target.name!r} returned something that is not a dead-letter page",
                "command_id": str(command_id),
                "engine": engine,
                "reason": str(exc)[:500],
            },
        ) from exc


__all__ = [
    "CURSOR_MAX_LENGTH",
    "CURSOR_REFUSAL_TEXT",
    "DEAD_LETTER_WAIT_SECONDS",
    "cursor_error",
    "router",
    "wait_seconds",
]
