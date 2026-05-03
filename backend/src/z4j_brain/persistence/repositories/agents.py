"""``agents`` repository."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models import Agent
from z4j_brain.persistence.repositories._base import BaseRepository


class AgentRepository(BaseRepository[Agent]):
    """Agent CRUD + heartbeat / state bookkeeping."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Agent)

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    async def get_by_token_hash(self, token_hash: str) -> Agent | None:
        """Resolve an agent by its bearer-token HMAC hash.

        Used by :mod:`z4j_brain.websocket.auth` to authenticate
        inbound WebSocket handshakes. Single PK-equivalent index
        lookup (``token_hash`` is UNIQUE).
        """
        result = await self.session.execute(
            select(Agent).where(Agent.token_hash == token_hash),
        )
        return result.scalar_one_or_none()

    async def list_for_project(
        self,
        project_id: UUID,
        *,
        limit: int = 500,
    ) -> list[Agent]:
        """Return agents for a project, newest first.

        Hard-capped at ``limit`` rows (default 500, max 5000) so a
        runaway agent fleet can't return tens of thousands of rows
        and OOM the response (audit P-7, added v1.0.14). The cap is
        well above any realistic single-project agent count
        (operators with > 500 agents are doing something unusual and
        should paginate at the API layer).
        """
        if limit < 1 or limit > 5000:
            raise ValueError("limit must be between 1 and 5000")
        result = await self.session.execute(
            select(Agent)
            .where(Agent.project_id == project_id)
            .order_by(Agent.created_at.desc())
            .limit(limit),
        )
        return list(result.scalars().all())

    async def list_online_for_project(
        self, project_id: UUID,
    ) -> list[Agent]:
        """Return only the currently-online agents for a project.

        Used by the ReconciliationWorker to pick an agent to dispatch
        a reconcile probe to. Ordered by most-recently-seen first so
        the freshest WS slot gets picked.
        """
        from z4j_brain.persistence.enums import AgentState

        result = await self.session.execute(
            select(Agent)
            .where(
                Agent.project_id == project_id,
                Agent.state == AgentState.ONLINE,
            )
            .order_by(Agent.last_seen_at.desc()),
        )
        return list(result.scalars().all())

    # ------------------------------------------------------------------
    # State updates - used by the gateway + AgentHealthWorker
    # ------------------------------------------------------------------

    async def mark_online(
        self,
        agent_id: UUID,
        *,
        protocol_version: str,
        framework_adapter: str,
        engine_adapters: list[str],
        scheduler_adapters: list[str],
        capabilities: dict[str, Any],
        host: dict[str, Any] | None = None,
        agent_version: str | None = None,
    ) -> None:
        """Set state=online + bump connect/seen + refresh handshake metadata.

        ``host`` carries the agent's optional ``host`` dict from the hello
        frame's payload (currently the operator-provided ``host.name`` label).
        Stored under ``agent_metadata['host']`` so it survives across the
        existing schema without a migration. Dashboards surface
        ``host.name`` next to the mint-time agent name.

        ``agent_version`` (1.3.4+) is the agent's z4j-core version
        string from the hello frame's ``agent_version`` field. Stored
        under ``agent_metadata['version']`` for the dashboard's
        per-agent VERSION column + *update available* badge.
        Optional - older agents that don't populate the field skip
        the write and the dashboard renders ``unknown``.
        """
        now = datetime.now(UTC)
        # Build the set of metadata-keys we want to merge on this
        # connect. ``host`` and ``agent_version`` are both optional;
        # if neither is present we skip the metadata write entirely
        # (the simpler ELSE branch below).
        metadata_updates: dict[str, Any] = {}
        if host:
            metadata_updates["host"] = dict(host)
        if agent_version:
            # 1.3.4: persist the hello-frame agent_version so the
            # Agents page can render the per-agent VERSION column +
            # *update available* badge against the bundled
            # ``versions.json`` snapshot.
            metadata_updates["version"] = str(agent_version)

        # Round-7 audit fix R7-LOW (race) (Apr 2026): use Postgres
        # ``jsonb_set`` so the metadata write is a single atomic UPDATE
        # instead of SELECT-then-UPDATE. The previous RMW could lose
        # concurrent updates from a NAT-bounce double-reconnect (both
        # sessions read the same baseline, the loser's write overwrites
        # the winner's). On SQLite (no jsonb_set) we fall back to the
        # legacy RMW path, the dev DB is single-writer so no race.
        if metadata_updates:
            dialect = (
                self.session.bind.dialect.name
                if self.session.bind is not None else ""
            )
            if dialect == "postgresql":
                from sqlalchemy import text as _text  # noqa: PLC0415

                # Chain ``jsonb_set`` calls so each metadata key is
                # set independently in a single SQL statement. Order
                # is deterministic; later keys see the merged result
                # of earlier ones. Each call uses
                # ``COALESCE(metadata, '{}'::jsonb)`` defensively in
                # case some prior path nulled the column.
                #
                # Raw SQL refers to the underlying DB column name,
                # ``metadata`` (the Python attribute is prefixed
                # only because plain ``metadata`` clashes with
                # SQLAlchemy's ``Base.metadata``). Pre-1.3.1 this
                # referenced ``agent_metadata`` which does not
                # exist as a real column.
                # Audit fix S006-D (1.4.0): use ``CAST(:name AS jsonb)``
                # instead of ``:name::jsonb``. SQLAlchemy 2.x's text()
                # bindparam regex parses ``:meta_0_value::jsonb`` as
                # the parameter name ``meta_0_value::jsonb`` (greedy on
                # the trailing ``::jsonb``), then fails to bind it
                # because the caller passes ``meta_0_value`` without
                # the type suffix. ``CAST(... AS jsonb)`` is the
                # SQL-standard equivalent and parses cleanly.
                expr = "COALESCE(metadata, CAST('{}' AS jsonb))"
                bind_params: dict[str, Any] = {}
                for i, (key, value) in enumerate(metadata_updates.items()):
                    pname = f"meta_{i}_value"
                    expr = (
                        f"jsonb_set({expr}, "
                        f"'{{{key}}}', "
                        f"CAST(:{pname} AS jsonb), true)"
                    )
                    bind_params[pname] = (
                        __import__("json").dumps(value)
                    )
                await self.session.execute(
                    update(Agent)
                    .where(Agent.id == agent_id)
                    .values(
                        state=AgentState.ONLINE,
                        last_connect_at=now,
                        last_seen_at=now,
                        protocol_version=protocol_version,
                        framework_adapter=framework_adapter,
                        engine_adapters=engine_adapters,
                        scheduler_adapters=scheduler_adapters,
                        capabilities=capabilities,
                        agent_metadata=_text(expr).bindparams(**bind_params),
                    ),
                )
            else:
                row = await self.session.execute(
                    select(Agent.agent_metadata).where(Agent.id == agent_id),
                )
                current_meta = row.scalar_one_or_none() or {}
                new_meta = dict(current_meta)
                new_meta.update(metadata_updates)
                await self.session.execute(
                    update(Agent)
                    .where(Agent.id == agent_id)
                    .values(
                        state=AgentState.ONLINE,
                        last_connect_at=now,
                        last_seen_at=now,
                        protocol_version=protocol_version,
                        framework_adapter=framework_adapter,
                        engine_adapters=engine_adapters,
                        scheduler_adapters=scheduler_adapters,
                        capabilities=capabilities,
                        agent_metadata=new_meta,
                    ),
                )
        else:
            await self.session.execute(
                update(Agent)
                .where(Agent.id == agent_id)
                .values(
                    state=AgentState.ONLINE,
                    last_connect_at=now,
                    last_seen_at=now,
                    protocol_version=protocol_version,
                    framework_adapter=framework_adapter,
                    engine_adapters=engine_adapters,
                    scheduler_adapters=scheduler_adapters,
                    capabilities=capabilities,
                ),
            )

    async def mark_offline(self, agent_id: UUID) -> None:
        """Set state=offline. Idempotent."""
        await self.session.execute(
            update(Agent)
            .where(Agent.id == agent_id)
            .values(state=AgentState.OFFLINE),
        )

    async def touch_heartbeat(self, agent_id: UUID) -> None:
        """Bump ``last_seen_at`` to now. Single indexed UPDATE."""
        await self.touch_heartbeat_at(agent_id, when=None)

    async def touch_heartbeat_at(
        self, agent_id: UUID, *, when: datetime | None = None,
    ) -> None:
        """Bump ``last_seen_at`` to ``when`` (defaults to now).

        Added in v1.0.15 (P-1) so :class:`EventIngestor.ingest_batch`
        can carry the ``max(occurred_at)`` from the batch instead of
        racing with wall-clock ``now()`` on every batch. Single
        indexed UPDATE either way.
        """
        await self.session.execute(
            update(Agent)
            .where(Agent.id == agent_id)
            .values(last_seen_at=when or datetime.now(UTC)),
        )

    async def sweep_offline(self, *, cutoff: datetime) -> int:
        """Mark every agent whose ``last_seen_at`` is older than ``cutoff``.

        Used by :class:`AgentHealthWorker`. Returns the number of
        rows transitioned. Single bulk UPDATE - no row scan.
        """
        result = await self.session.execute(
            update(Agent)
            .where(
                Agent.state == AgentState.ONLINE,
                Agent.last_seen_at < cutoff,
            )
            .values(state=AgentState.OFFLINE),
        )
        return int(result.rowcount or 0)

    async def prune_stale(self, *, cutoff: datetime) -> int:
        """Delete agents that have been offline past ``cutoff``.

        "Stale" means: ``state != online`` AND (``last_seen_at`` is
        older than cutoff OR the row has never connected at all
        AND ``created_at`` is older than cutoff). Invoked by the
        daily :class:`AgentHygieneWorker`; protects the Agents
        page from accumulating ghost rows after a container is
        removed without revoking the token first.

        Cascades via FK (``events.agent_id``, ``commands.agent_id``)
        as configured on the model - events lose their agent link
        but survive with ``agent_id=NULL``.
        """
        from sqlalchemy import delete, or_

        result = await self.session.execute(
            delete(Agent).where(
                Agent.state != AgentState.ONLINE,
                or_(
                    Agent.last_seen_at < cutoff,
                    # Never-connected agents (minted token then
                    # someone deleted the container before it
                    # booted) have last_seen_at=NULL; fall back to
                    # created_at so we can still prune them.
                    (Agent.last_seen_at.is_(None)) & (Agent.created_at < cutoff),
                ),
            ),
        )
        return int(result.rowcount or 0)

    async def insert(
        self,
        *,
        project_id: UUID,
        name: str,
        token_hash: str,
    ) -> Agent:
        """Create a new agent row with placeholder handshake fields.

        Used by the "mint agent token" admin endpoint. The handshake
        metadata (``protocol_version``, ``framework_adapter``,
        ``capabilities``) is overwritten when the agent first
        connects via :meth:`mark_online`.
        """
        agent = Agent(
            project_id=project_id,
            name=name,
            token_hash=token_hash,
            protocol_version="0",
            framework_adapter="unknown",
            engine_adapters=[],
            scheduler_adapters=[],
            capabilities={},
            state=AgentState.UNKNOWN,
        )
        self.session.add(agent)
        await self.session.flush()
        return agent


__all__ = ["AgentRepository"]
