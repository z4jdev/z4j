"""Serialization primitives for durable agent authority.

Agent revocation has two boundaries with different deployment shapes:

* PostgreSQL can run multiple brain replicas.  Inbound writes and revoke use
  the same transaction-scoped advisory mutex, while physical command sends
  retain the agent-row lock needed to order across replicas.
* SQLite is a supported single-worker deployment.  A process-local per-agent
  mutex orders physical sends against revoke without holding SQLite's global
  ``BEGIN IMMEDIATE`` writer reservation across socket I/O.

The PostgreSQL mutex deliberately is not an ``agents FOR UPDATE`` lock.  Some
inbound projections subsequently lock schedules or external streams, whereas
command claims take those rows before the agent row.  Making the authority
gate advisory-only avoids introducing the inverse Agent -> Schedule/Stream
row-lock order while still giving revoke and stale inbound frames one durable
linearization point.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID
from weakref import WeakValueDictionary

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

_LOCAL_AGENT_AUTHORITY_LOCKS: WeakValueDictionary[UUID, asyncio.Lock] = WeakValueDictionary()


def _postgres_agent_authority_key(agent_id: UUID) -> int:
    """Return a stable, namespace-separated signed PostgreSQL bigint key."""

    digest = hashlib.blake2b(
        agent_id.bytes,
        digest_size=8,
        person=b"z4j-agent-auth",
    ).digest()
    return int.from_bytes(digest, byteorder="big", signed=True)


async def acquire_agent_authority_xact_lock(
    session: AsyncSession,
    agent_id: UUID,
) -> None:
    """Acquire this agent's transaction-scoped authority mutex on PostgreSQL.

    SQLite callers already begin their mutation unit with ``BEGIN IMMEDIATE``;
    the database-global writer reservation supplies the corresponding durable
    ordering there.
    """

    if session.bind is None:
        raise RuntimeError("agent-authority session is not bound to an engine")
    if session.bind.dialect.name != "postgresql":
        return
    await session.execute(
        text("SELECT pg_advisory_xact_lock(:lock_id)"),
        {"lock_id": _postgres_agent_authority_key(agent_id)},
    )


@asynccontextmanager
async def local_agent_authority(agent_id: UUID) -> AsyncIterator[None]:
    """Hold the process-local authority mutex for one SQLite agent.

    Lock lookup and creation contain no ``await`` and therefore cannot
    interleave on the single event loop used by a supported SQLite brain.
    Keeping ``lock`` as a strong local reference also prevents the weak map
    from discarding it while a caller is waiting or holding it.
    """

    lock = _LOCAL_AGENT_AUTHORITY_LOCKS.get(agent_id)
    if lock is None:
        lock = asyncio.Lock()
        _LOCAL_AGENT_AUTHORITY_LOCKS[agent_id] = lock
    async with lock:
        yield


__all__ = [
    "acquire_agent_authority_xact_lock",
    "local_agent_authority",
]
