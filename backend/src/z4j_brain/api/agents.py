"""``/api/v1/projects/{slug}/agents`` REST router."""

from __future__ import annotations

import base64
import secrets
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError

from z4j_brain.errors import ConflictError
from z4j_core.transport import CURRENT_PROTOCOL
from z4j_core.transport.hmac import derive_project_secret

from z4j_brain.api.deps import (
    get_audit_log_repo,
    get_audit_service,
    get_client_ip,
    get_current_user,
    get_membership_repo,
    get_project_repo,
    get_session,
    get_settings,
    require_csrf,
)
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.websocket.auth import hash_agent_token

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.models import Agent, User
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        MembershipRepository,
        ProjectRepository,
    )
    from z4j_brain.settings import Settings


router = APIRouter(prefix="/projects/{slug}/agents", tags=["agents"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class AgentPublic(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    name: str
    state: str
    protocol_version: str
    framework_adapter: str
    engine_adapters: list[str]
    scheduler_adapters: list[str]
    capabilities: dict[str, Any]
    last_seen_at: datetime | None
    last_connect_at: datetime | None
    created_at: datetime
    is_outdated: bool = Field(
        description=(
            "True when the agent has connected at least once and its "
            "last advertised ``protocol_version`` is older than the "
            "brain's ``CURRENT_PROTOCOL``. Never-connected agents "
            "(``last_connect_at`` is null) report ``false`` because "
            "they have not advertised a real version yet."
        ),
    )
    host_name: str | None = Field(
        default=None,
        description=(
            "Operator-supplied host label sent by the agent in the "
            "hello frame's ``host.name`` field. Distinct from ``name`` "
            "(which is set at mint time on the brain side) - useful "
            "when one agent token is shared across multiple worker "
            "instances and you want per-instance labels in the "
            "dashboard. Null if the agent never set Z4J_AGENT_NAME."
        ),
    )
    agent_version: str | None = Field(
        default=None,
        description=(
            "z4j-core SemVer string the agent advertised in its hello "
            "frame (1.3.4+). Null when the agent has never connected "
            "or runs a pre-1.0.3 build that didn't populate the field."
        ),
    )
    version_status: str | None = Field(
        default=None,
        description=(
            "Comparison of ``agent_version`` against the brain's "
            "bundled (or operator-refreshed) versions snapshot. One "
            "of: ``current`` (agent matches the snapshot), "
            "``outdated`` (agent older, same major - update "
            "available), ``newer_than_known`` (agent newer than the "
            "snapshot - the brain's snapshot is stale, refresh from "
            "Settings -> Check for updates), ``incompatible`` (major "
            "version mismatch), ``unknown`` (no agent_version "
            "reported, or the package is missing from the snapshot). "
            "Null if ``agent_version`` is null."
        ),
    )


class CreateAgentRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class CreateAgentResponse(BaseModel):
    agent: AgentPublic
    token: str = Field(
        description="Plaintext bearer token. Returned ONCE; not retrievable later.",
    )
    hmac_secret: str = Field(
        description=(
            "Per-project signing secret (urlsafe-base64, 32 raw bytes). "
            "Returned ONCE alongside the bearer token. Deterministically "
            "derived from the brain master via HMAC, so the brain re-derives "
            "the same value on every frame and never needs to store it. "
            "Operators paste both ``token`` and ``hmac_secret`` into their "
            "agent configuration; the agent refuses to start without "
            "``hmac_secret``."
        ),
    )


def _agent_payload(
    agent: "Agent",
    *,
    versions_snapshot: Any | None = None,
) -> AgentPublic:
    # Only flag as outdated when the agent has actually connected -
    # never-connected rows carry a placeholder ``protocol_version``
    # (see AgentRepository.insert) and would otherwise show as
    # outdated before they get a chance to advertise their real
    # version.
    is_outdated = (
        agent.last_connect_at is not None
        and agent.protocol_version != CURRENT_PROTOCOL
    )
    # Pull the operator-supplied host.name out of agent_metadata.host
    # if the agent ever sent one in its hello frame. The metadata blob
    # is bounded by the gateway (only the host dict + agent_version
    # are persisted there) so there's no risk of exposing internal
    # fields.
    meta = agent.agent_metadata or {}
    host_blob = meta.get("host") if isinstance(meta, dict) else None
    host_name: str | None = None
    if isinstance(host_blob, dict):
        candidate = host_blob.get("name")
        if isinstance(candidate, str) and candidate:
            host_name = candidate

    # 1.3.4: ``agent_version`` and the computed ``version_status``.
    # Both null for agents that never reported a version (older
    # builds, never-connected rows). The status is computed against
    # whatever versions_snapshot the brain has cached (bundled at
    # build time, optionally refreshed via Settings -> Check for
    # updates).
    agent_version_raw: str | None = None
    if isinstance(meta, dict):
        v = meta.get("version")
        if isinstance(v, str) and v:
            agent_version_raw = v
    version_status: str | None = None
    if agent_version_raw is not None:
        if versions_snapshot is None:
            version_status = "unknown"
        else:
            from z4j_brain.domain.version_check import compare

            # Compare against the agent's z4j-core line (the
            # ``agent_version`` field carries z4j-core's version).
            version_status = compare(
                agent_version_raw, "z4j-core", versions_snapshot,
            )

    return AgentPublic(
        id=agent.id,
        project_id=agent.project_id,
        name=agent.name,
        state=agent.state.value,
        protocol_version=agent.protocol_version,
        framework_adapter=agent.framework_adapter,
        engine_adapters=list(agent.engine_adapters or []),
        scheduler_adapters=list(agent.scheduler_adapters or []),
        capabilities=dict(agent.capabilities or {}),
        last_seen_at=agent.last_seen_at,
        last_connect_at=agent.last_connect_at,
        created_at=agent.created_at,
        is_outdated=is_outdated,
        host_name=host_name,
        agent_version=agent_version_raw,
        version_status=version_status,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("", response_model=list[AgentPublic])
async def list_agents(
    slug: str,
    request: "Request",
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> list[AgentPublic]:
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import AgentRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.VIEWER,
    )
    agents = AgentRepository(db_session)
    rows = await agents.list_for_project(project.id)
    snapshot = getattr(request.app.state, "versions_snapshot", None)
    return [_agent_payload(a, versions_snapshot=snapshot) for a in rows]


@router.post(
    "",
    response_model=CreateAgentResponse,
    status_code=201,
    dependencies=[Depends(require_csrf)],
)
async def create_agent(
    slug: str,
    body: CreateAgentRequest,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    settings: "Settings" = Depends(get_settings),
    audit: "AuditService" = Depends(get_audit_service),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> CreateAgentResponse:
    """Mint a new agent token.

    The plaintext token is returned ONCE - only the HMAC hash is
    stored. Operators must paste the plaintext into their agent
    configuration; if they lose it they have to mint another.
    """
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.persistence.repositories import AgentRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.ADMIN,
    )

    plaintext = secrets.token_urlsafe(32)
    secret = settings.secret.get_secret_value().encode("utf-8")
    token_hash = hash_agent_token(plaintext=plaintext, secret=secret)

    agents = AgentRepository(db_session)
    try:
        agent = await agents.insert(
            project_id=project.id,
            name=body.name.strip(),
            token_hash=token_hash,
        )
    except IntegrityError as exc:  # noqa: F841 -- str() used below
        # Audit A5: unique constraint on (project_id, name) -
        # concurrent mints with the same name land here. Previous
        # behavior silently created duplicates.
        await db_session.rollback()
        raise ConflictError(
            "an agent with that name already exists in this project",
            details={"name": body.name.strip()},
        ) from None
    await audit.record(
        audit_log,
        action="agent.token.minted",
        target_type="agent",
        target_id=str(agent.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project.id,
        source_ip=ip,
        metadata={"name": body.name.strip()},
    )
    await db_session.commit()

    project_signing_secret = derive_project_secret(secret, project.id)
    return CreateAgentResponse(
        agent=_agent_payload(agent),
        token=plaintext,
        hmac_secret=base64.urlsafe_b64encode(project_signing_secret).decode("ascii"),
    )


@router.delete(
    "/{agent_id}",
    status_code=204,
    dependencies=[Depends(require_csrf)],
)
async def revoke_agent(
    slug: str,
    agent_id: uuid.UUID,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit: "AuditService" = Depends(get_audit_service),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> None:
    from z4j_brain.domain.policy_engine import PolicyEngine
    from z4j_brain.errors import NotFoundError
    from z4j_brain.persistence.repositories import AgentRepository

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships,
        user=user,
        project_id=project.id,
        min_role=ProjectRole.ADMIN,
    )

    agents = AgentRepository(db_session)
    agent = await agents.get(agent_id)
    if agent is None or agent.project_id != project.id:
        raise NotFoundError(
            "agent not found",
            details={"agent_id": str(agent_id)},
        )

    await agents.delete(agent)
    await audit.record(
        audit_log,
        action="agent.token.revoked",
        target_type="agent",
        target_id=str(agent_id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project.id,
        source_ip=ip,
    )
    await db_session.commit()


__all__ = ["AgentPublic", "router"]
