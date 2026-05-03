"""WebSocket bearer-token authentication.

The agent presents its plaintext token in the
``Authorization: Bearer <token>`` header on the WebSocket upgrade.
We HMAC-hash it (same algorithm as the brain stores) and look up
the agent row by hash. Constant-time compare via the unique index
+ ``hmac.compare_digest`` on the hash itself.

The plaintext token NEVER appears in logs, never in audit metadata,
never in any persisted form.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from z4j_brain.persistence.models import Agent
    from z4j_brain.persistence.repositories import AgentRepository
    from z4j_brain.settings import Settings


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

    Round-6 audit fix SR-HIGH (Apr 2026): if the operator is mid-
    rotation (``Z4J_PREVIOUS_SECRETS`` set), try every accepted
    secret. The token row in the DB was hashed with whatever was the
    master secret at mint time; without this loop a rotation would
    immediately invalidate every live agent token until each agent
    re-mints one, which itself requires a working bearer.
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


__all__ = ["hash_agent_token", "resolve_agent_by_bearer"]
