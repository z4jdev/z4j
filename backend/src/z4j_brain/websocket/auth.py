"""WebSocket bearer-token authentication.

The agent presents its plaintext token in the
``Authorization: Bearer <token>`` header on the WebSocket upgrade.
We HMAC-hash it (same algorithm as the brain stores) and look up
the agent row by a unique indexed equality query on that fixed-size
digest. The plaintext token never reaches the database query.

The plaintext token NEVER appears in logs, never in audit metadata,
never in any persisted form.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import TYPE_CHECKING

from sqlalchemy import select
from z4j_core.errors import AuthorizationError

from z4j_brain.auth.ip import TrustedProxyResolver

if TYPE_CHECKING:
    from uuid import UUID

    from fastapi import WebSocket
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.persistence.models import Agent
    from z4j_brain.persistence.repositories import AgentRepository
    from z4j_brain.settings import Settings


class ProjectInactiveError(AuthorizationError):
    """The bearer is valid but the agent's project has been archived.

    Raised by the long-poll routes so the agent gets a ``403`` whose
    ``error`` field is the stable string ``project_inactive`` rather
    than the ``401`` a bad or revoked token gets. The WebSocket
    gateway does not raise it; it closes with the revoked-agent close
    codes instead, because the shipped agent runtime treats any
    unknown close code as a transient network failure and would
    reconnect on its fastest schedule.
    """

    code = "project_inactive"


#: Salt baked into the agent-token HMAC. Distinct from the salt used
#: for setup tokens so the same secret cannot collide between the
#: two surfaces.
_AGENT_TOKEN_SALT: bytes = b"z4j-agent-token-v1"


def hash_agent_token(*, plaintext: str, secret: bytes) -> str:
    """HMAC-SHA256 hex digest of an agent token.

    Same call site for token mint AND token verification - minting
    stores the result, verification recomputes and compares.
    """
    h = hmac.new(secret + _AGENT_TOKEN_SALT, plaintext.encode("utf-8"), hashlib.sha256)
    return h.hexdigest()


async def resolve_agent_by_bearer(
    *,
    bearer: str | None,
    settings: Settings,
    agents: AgentRepository,
) -> Agent | None:
    """Resolve an inbound bearer header to an :class:`Agent` row.

    Returns ``None`` for missing/malformed/unknown tokens. Never
    raises. Caller (the gateway) maps ``None`` to a 4401 close.

    If the operator is mid-rotation (``Z4J_PREVIOUS_SECRETS``
    set), try every accepted secret. The token row in the DB was
    hashed with whatever was the master secret at mint time, so
    without this loop a rotation would reject every live agent
    token at the handshake.

    Do NOT read that as "rotation is survivable for agents". It is
    not, and an earlier version of this docstring said re-minting
    "requires a working bearer", which is false and propagated into
    the operator documentation. Minting is a human operation behind
    a browser session, CSRF and project-admin authority; no
    agent-authenticated path returns credentials. And the frame
    signing key is derived from the CURRENT master alone (see
    ``gateway.py``), with no fallback here or anywhere else. So all
    this loop changes is the failure mode: instead of a clean 4401
    at the handshake, the agent connects, registers online, and is
    closed on its first data frame. Every agent still has to be
    re-credentialed by an operator.
    """
    if not bearer:
        return None
    parts = bearer.strip().split(maxsplit=1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    plaintext = parts[1].strip()
    if not plaintext:
        return None
    for secret in settings.all_secrets_for_verification():
        expected_hash = hash_agent_token(plaintext=plaintext, secret=secret)
        agent = await agents.get_by_token_hash(expected_hash)
        if agent is not None:
            return agent
    return None


async def agent_project_is_active(
    *,
    project_id: UUID,
    session: AsyncSession,
) -> bool:
    """Return whether the project an agent belongs to is still active.

    A valid bearer is not enough to admit an agent: archiving a project
    (``DELETE /api/v1/projects/{slug}``) flips ``projects.is_active`` to
    false and leaves the agent rows and their token hashes intact, so
    without this check the agents of an archived project keep
    connecting, streaming events and pulling commands. Both agent
    transports call this right after the bearer lookup, and the
    gateway calls it again after registry registration to close the
    window where the archive commits mid-handshake.

    A project row that does not exist counts as inactive; the agent's
    foreign key makes that impossible in practice, but the safe answer
    for a dangling reference is to refuse.
    """
    from z4j_brain.persistence.models import Project

    result = await session.execute(
        select(Project.is_active).where(Project.id == project_id),
    )
    return bool(result.scalar_one_or_none())


def resolve_websocket_client_ip(websocket: WebSocket, *, settings: Settings) -> str:
    """The trusted-proxy-resolved address of a WebSocket peer.

    ``RealClientIPMiddleware`` only sees HTTP scopes, so both gateways run
    the same :class:`TrustedProxyResolver` themselves: ``X-Forwarded-For``
    counts only when the socket peer is inside ``trusted_proxies``, and a
    header from anywhere else is ignored in favour of the peer. Returns the
    empty string when the peer is unknown, which a non-empty allowlist
    refuses and an empty one admits, exactly as on HTTP.
    """
    resolver: TrustedProxyResolver | None = getattr(
        websocket.app.state,
        "proxy_resolver",
        None,
    )
    if resolver is None:
        resolver = TrustedProxyResolver(settings.trusted_proxies)
    return resolver.resolve(
        peer_ip=websocket.client.host if websocket.client else None,
        xff_header=websocket.headers.get("x-forwarded-for"),
    )


__all__ = [
    "ProjectInactiveError",
    "agent_project_is_active",
    "hash_agent_token",
    "resolve_agent_by_bearer",
    "resolve_websocket_client_ip",
]
