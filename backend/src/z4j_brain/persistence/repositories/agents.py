"""``agents`` repository."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.agent_authority import acquire_agent_authority_xact_lock
from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models import Agent
from z4j_brain.persistence.repositories._base import BaseRepository

# Reserved for hidden tombstones. The create API rejects this prefix, which
# makes renaming a revoked row collision-free for all post-upgrade agents. The
# repository still probes for collisions so legacy rows that used the prefix
# cannot make a security-sensitive revoke fail.
REVOKED_AGENT_NAME_PREFIX = "__z4j_revoked__:"

# Keep one hygiene mutation far below asyncpg's 32,767-argument ceiling and
# PostgreSQL's shared advisory-lock capacity. The worker drains as many batches
# as needed, so this bounds one transaction without imposing a fleet-size cap.
AGENT_STALE_PRUNE_BATCH_SIZE = 256


class AgentNameConflictError(Exception):
    """Raised when a live agent already owns a project/name pair."""


@dataclass(frozen=True, slots=True)
class AgentNameReservation:
    """Name owner observed while holding its row-level mutation authority."""

    project_id: UUID
    name: str
    owner: Agent | None


class AgentRepository(BaseRepository[Agent]):
    """Agent CRUD + heartbeat / state bookkeeping."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Agent)

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    async def get_live(self, agent_id: UUID, *, lock: bool = False) -> Agent | None:
        """Return an unrevoked agent by primary key.

        Generic :meth:`BaseRepository.get` deliberately remains a raw row
        lookup: the revoke endpoint needs to find the durable tombstone. Any
        path selecting an agent as a command or retry target must use this
        method instead, so a hidden tombstone cannot receive new work.
        """
        statement = select(Agent).where(
            Agent.id == agent_id,
            Agent.revoked_at.is_(None),
        )
        if lock:
            statement = statement.with_for_update()
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def get_locked(self, agent_id: UUID) -> Agent | None:
        """Return the raw row under ``FOR UPDATE``, including tombstones.

        Explicit revoke needs both properties: idempotent access to an already
        revoked row and the same row-lock authority used by outbound physical
        sends. Acquiring this lock before the live/tombstone decision prevents
        a new send from overtaking a revoke between its check and token-killing
        UPDATE.
        """
        result = await self.session.execute(
            select(Agent).where(Agent.id == agent_id).with_for_update(),
        )
        return result.scalar_one_or_none()

    async def get_by_token_hash(self, token_hash: str) -> Agent | None:
        """Resolve a LIVE agent by its bearer-token HMAC hash.

        Used by :mod:`z4j_brain.websocket.auth` and the long-poll transport
        to authenticate inbound agents. Single PK-equivalent index lookup
        (``token_hash`` is UNIQUE).

        Revoked agents are excluded here rather than only at the call sites,
        so a transport that forgets the check cannot authenticate one. That
        is belt and braces: :meth:`revoke` also rewrites ``token_hash`` to a
        sentinel no HMAC can produce, so a revoked row is unreachable by this
        lookup even if this predicate were dropped.
        """
        result = await self.session.execute(
            select(Agent).where(
                Agent.token_hash == token_hash,
                Agent.revoked_at.is_(None),
            ),
        )
        return result.scalar_one_or_none()

    async def revoke(self, agent: Agent, *, at: datetime) -> None:
        """Retire an agent without erasing it, and kill its token.

        Revocation used to be ``DELETE``, which the schema never supported:
        ``events.agent_id`` is non-null with ``ON DELETE RESTRICT`` so that
        history outlives the agent. PostgreSQL therefore refused to revoke
        any agent that had emitted an event, and SQLite (no
        ``PRAGMA foreign_keys``) accepted it and orphaned the events.

        The token is invalidated by overwriting the hash, not just by the
        timestamp. ``hash_agent_token`` returns a hex digest, so a value
        carrying a colon can never collide with a real one, and the column's
        UNIQUE constraint still holds because the operation id is embedded.
        The consequence worth knowing: revocation is irreversible by design,
        because the hash of the old token is gone rather than merely flagged.
        """
        metadata = dict(agent.agent_metadata or {})
        if agent.revoked_at is None:
            # This key is internal provenance, not agent-supplied metadata.
            # Overwrite a spoofed value on the first revoke, but preserve the
            # real value on an idempotent revoke after name release renamed
            # the tombstone into the reserved namespace.
            metadata["_z4j_revoked_original_name"] = agent.name
        agent.agent_metadata = metadata
        # Keep the original name here. Revocation is the security boundary and
        # must not depend on an unrelated uniqueness-preserving rename. A later
        # mint of the same name releases it under the row lock in insert().
        agent.revoked_at = at
        agent.token_hash = f"revoked:{agent.id}:{at.isoformat()}"
        agent.state = AgentState.OFFLINE
        await self.session.flush()

    async def _release_revoked_name(self, agent: Agent) -> None:
        """Move a tombstone into the reserved namespace before replacement."""
        base_name = f"{REVOKED_AGENT_NAME_PREFIX}{agent.id}"
        tombstone_name = base_name
        collision_suffix = 0
        while (
            await self.session.scalar(
                select(Agent.id)
                .where(
                    Agent.project_id == agent.project_id,
                    Agent.name == tombstone_name,
                    Agent.id != agent.id,
                )
                .limit(1),
            )
            is not None
        ):
            collision_suffix += 1
            tombstone_name = f"{base_name}:{collision_suffix}"
        agent.name = tombstone_name
        await self.session.flush()

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
        # Revoked agents are retired, not listed. Their rows survive so the
        # events they emitted keep a valid owner, but an operator who revoked
        # a leaked token should not keep seeing it in the fleet.
        result = await self.session.execute(
            select(Agent)
            .where(Agent.project_id == project_id, Agent.revoked_at.is_(None))
            .order_by(Agent.created_at.desc())
            .limit(limit),
        )
        return list(result.scalars().all())

    async def list_online_for_project(
        self,
        project_id: UUID,
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
                Agent.revoked_at.is_(None),
            )
            .order_by(Agent.last_seen_at.desc()),
        )
        return list(result.scalars().all())

    # ------------------------------------------------------------------
    # State updates - used by the gateway + AgentHealthWorker
    # ------------------------------------------------------------------

    async def record_runtime_features(self, *, agent_id: UUID, runtime_features: list[str]) -> None:
        """Persist the runtime feature flags an agent advertised.

        The WebSocket handshake records these through:meth:`mark_online`.
        Long-poll has no handshake frame, so it advertises the same list in a
        header on its connect probe and lands here. Recording both transports
        keeps operator inspection consistent; these flags are advisory and do
        not gate retry delivery, whose safety contract is enforced separately.

        Same dialect split as :meth:`mark_online`: ``jsonb_set`` on Postgres so a
        concurrent reconnect cannot clobber a sibling key, read-modify-write on
        SQLite, which has no ``jsonb_set`` and is single-writer anyway.
        """
        value = list(runtime_features)
        dialect = self.session.bind.dialect.name if self.session.bind is not None else ""
        if dialect == "postgresql":
            import json

            from sqlalchemy import text as _text

            expr = (
                "jsonb_set(COALESCE(metadata, CAST('{}' AS jsonb)), "
                "'{runtime_features}', CAST(:rf AS jsonb), true)"
            )
            await self.session.execute(
                update(Agent)
                .where(Agent.id == agent_id, Agent.revoked_at.is_(None))
                .values(
                    agent_metadata=_text(expr).bindparams(rf=json.dumps(value)),
                ),
            )
            return
        row = await self.session.execute(
            select(Agent.agent_metadata).where(
                Agent.id == agent_id,
                Agent.revoked_at.is_(None),
            ),
        )
        current = row.scalar_one_or_none()
        if current is None:
            # No such agent, or the column is NULL and the row may not exist.
            # A missing agent is not this method's problem to report; the caller
            # resolved it moments ago.
            current = {}
        new_meta = dict(current)
        new_meta["runtime_features"] = value
        await self.session.execute(
            update(Agent)
            .where(Agent.id == agent_id, Agent.revoked_at.is_(None))
            .values(agent_metadata=new_meta),
        )

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
        runtime_features: list[str] | None = None,
    ) -> datetime | None:
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
        if runtime_features is not None:
            # RH1: persist the runtime feature flags the agent advertised, for
            # operator INSPECTION only (e.g. surfacing which agents run the
            # 1.7.1+ runtime). This is ADVISORY, NOT a safety gate: retry safety
            # is enforced by the override-presence rule in
            # ``z4j_brain.domain.retry_contract`` (see HelloPayload.runtime_
            # features). Recorded only on the WS handshake -- the long-poll
            # transport carries no hello -- but because nothing gates on it, that
            # gap is cosmetic. Stored under agent_metadata['runtime_features'].
            metadata_updates["runtime_features"] = list(runtime_features)

        # Use Postgres
        # ``jsonb_set`` so the metadata write is a single atomic UPDATE
        # instead of SELECT-then-UPDATE. The previous RMW could lose
        # concurrent updates from a NAT-bounce double-reconnect (both
        # sessions read the same baseline, the loser's write overwrites
        # the winner's). On SQLite (no jsonb_set) we fall back to the
        # legacy RMW path, the dev DB is single-writer so no race.
        if metadata_updates:
            dialect = self.session.bind.dialect.name if self.session.bind is not None else ""
            if dialect == "postgresql":
                from sqlalchemy import text as _text

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
                # Use ``CAST(:name AS jsonb)``
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
                    expr = f"jsonb_set({expr}, '{{{key}}}', CAST(:{pname} AS jsonb), true)"
                    bind_params[pname] = __import__("json").dumps(value)
                result = await self.session.execute(
                    update(Agent)
                    .where(Agent.id == agent_id, Agent.revoked_at.is_(None))
                    .values(
                        state=AgentState.ONLINE,
                        last_connect_at=now,
                        last_seen_at=now,
                        protocol_version=protocol_version,
                        framework_adapter=framework_adapter,
                        engine_adapters=engine_adapters,
                        scheduler_adapters=scheduler_adapters,
                        capabilities=capabilities,
                        agent_metadata=_text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                            expr,
                        ).bindparams(**bind_params),
                    ),
                )
            else:
                row = await self.session.execute(
                    select(Agent.agent_metadata).where(
                        Agent.id == agent_id,
                        Agent.revoked_at.is_(None),
                    ),
                )
                current_meta = row.scalar_one_or_none() or {}
                new_meta = dict(current_meta)
                new_meta.update(metadata_updates)
                result = await self.session.execute(
                    update(Agent)
                    .where(Agent.id == agent_id, Agent.revoked_at.is_(None))
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
            result = await self.session.execute(
                update(Agent)
                .where(Agent.id == agent_id, Agent.revoked_at.is_(None))
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
        # Return the timestamp written to
        # ``last_connect_at`` so the caller can plumb it into a
        # later ``mark_offline(captured_at=...)`` call. The race the
        # captured_at gates against requires exact-pair semantics
        # between this connection's mark_online and its eventual
        # mark_offline; the wall clock at close time isn't precise
        # enough.
        return now if result.rowcount else None

    async def mark_offline(
        self,
        agent_id: UUID,
        *,
        captured_at: datetime | None = None,
    ) -> None:
        """Set state=offline conditional on no fresher connect having landed.

        An unconditional UPDATE racing the new connection's
        ``mark_online`` would leave agents pinned at
        ``state=offline`` while their WS was alive and heartbeats
        were flowing. The race window: a closing-connection task
        commits ``mark_offline`` AFTER a reconnecting-connection
        task has committed ``mark_online``, and the late writer
        wins.

        When the caller knows when the offlining gateway task
        was processing the close (``captured_at``), we only flip
        state if no connect newer than that timestamp has
        landed. Combined with the heartbeat handler's
        opportunistic re-promotion of state to online, agents
        cannot stay stuck offline while their WS is alive.

        ``captured_at`` is optional for backwards compat with
        callers that don't track the close timestamp; in that
        case the unconditional behavior runs and the caller is
        responsible for ensuring no race exists. New callers
        should pass it.
        """
        stmt = update(Agent).where(Agent.id == agent_id)
        if captured_at is not None:
            # Only flip state if no fresher connect has happened.
            # ``last_connect_at`` is bumped on every successful
            # mark_online; if it's > captured_at, a newer
            # connection won the race and we MUST NOT clobber.
            from sqlalchemy import or_

            stmt = stmt.where(
                or_(
                    Agent.last_connect_at.is_(None),
                    Agent.last_connect_at <= captured_at,
                ),
            )
        stmt = stmt.values(state=AgentState.OFFLINE)
        await self.session.execute(stmt)

    async def promote_online_if_offline(self, agent_id: UUID) -> bool:
        """Re-assert state=online from any non-online state. Heartbeat path.

        Heartbeats arriving from a live connection flip the state
        column to ``online`` if it wrongly drifted to ``offline``
        (a late mark_offline that lost the race against a new
        connection's mark_online) OR is still ``unknown``.

        The ``unknown`` case matters for LONG-POLL agents: long-poll
        has no ``hello`` handshake, so nothing calls ``mark_online``
        (that is WS-gateway-only). Verified long-poll heartbeats and
        event batches reach this method, so widening the guard from
        ``== OFFLINE`` to ``!= ONLINE`` is what lets a long-poll-only
        agent ever show online at all (pre-fix it was pinned at
        ``unknown`` forever). Idempotent: a no-op when already online.

        The operation is a single indexed UPDATE with a WHERE
        guard so the row is touched only when needed; cheap to call
        from every heartbeat.
        """
        result = await self.session.execute(
            update(Agent)
            .where(Agent.id == agent_id)
            .where(Agent.revoked_at.is_(None))
            .where(Agent.state != AgentState.ONLINE)
            .values(state=AgentState.ONLINE),
        )
        return bool(result.rowcount)

    async def touch_heartbeat(self, agent_id: UUID) -> bool:
        """Bump ``last_seen_at`` to now. Single indexed UPDATE."""
        return await self.touch_heartbeat_at(agent_id, when=None)

    async def touch_heartbeat_at(
        self,
        agent_id: UUID,
        *,
        when: datetime | None = None,
    ) -> bool:
        """Bump ``last_seen_at`` to ``when`` (defaults to now), MONOTONICALLY.

        Added in v1.0.15 (P-1) so :class:`EventIngestor.ingest_batch`
        can carry the ``max(occurred_at)`` from the batch instead of
        racing with wall-clock ``now()`` on every batch. Single
        indexed UPDATE either way.

        The update never moves ``last_seen_at`` BACKWARDS (round-9 external
        MED): ``ingest_batch`` passes the batch ``max(occurred_at)``, so a
        reconnect that re-flushes an OLD buffered batch (all duplicates) would
        otherwise rewind a live agent's ``last_seen_at`` to that stale
        timestamp and trip a false offline sweep / alert. The WHERE guard
        makes the write a no-op unless it advances the clock; for a plain
        ``when=None`` heartbeat (``now()``), the guard is satisfied normally.
        """
        resolved = when or datetime.now(UTC)
        result = await self.session.execute(
            update(Agent)
            .where(Agent.id == agent_id)
            .where(Agent.revoked_at.is_(None))
            .where(or_(Agent.last_seen_at.is_(None), Agent.last_seen_at < resolved))
            .values(last_seen_at=resolved),
        )
        return bool(result.rowcount)

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

    async def list_offline_unseen_since(
        self,
        *,
        cutoff: datetime,
        limit: int = 500,
    ) -> list[Agent]:
        """Offline agents whose last heartbeat predates ``cutoff``.

        Used by :class:`AgentHealthWorker` to find confirmed-down
        offline EPISODES to alert on. Includes agents flipped offline by
        the gateway's close handler as well as by the sweep, because
        both paths land on ``state=offline`` -- the alert must not
        depend on WHICH path noticed the death. Agents that never
        connected (``last_seen_at IS NULL``) are excluded: with no
        heartbeat anchor there is no episode to alert on (and nothing
        was ever "lost"). Oldest-unseen first so a burst that overflows
        the caller's per-sweep cap alerts the longest-dead agents first.
        """
        result = await self.session.execute(
            select(Agent)
            .where(
                Agent.state == AgentState.OFFLINE,
                Agent.revoked_at.is_(None),
                Agent.last_seen_at.is_not(None),
                Agent.last_seen_at < cutoff,
            )
            .order_by(Agent.last_seen_at.asc())
            .limit(limit),
        )
        return list(result.scalars().all())

    async def list_stale_ids(
        self,
        *,
        cutoff: datetime,
        limit: int = AGENT_STALE_PRUNE_BATCH_SIZE,
    ) -> list[UUID]:
        """Discover live agents eligible for the hygiene soft revoke.

        Discovery is deliberately separate from mutation. The hygiene worker
        can close this read transaction, acquire the SQLite process-local
        authority mutex, then open ``BEGIN IMMEDIATE`` without retaining a
        global writer reservation while it waits. :meth:`prune_stale`
        revalidates every candidate under mutation authority.
        """
        if limit < 1 or limit > AGENT_STALE_PRUNE_BATCH_SIZE:
            raise ValueError(
                f"stale-agent discovery limit must be between 1 and {AGENT_STALE_PRUNE_BATCH_SIZE}",
            )
        result = await self.session.execute(
            select(Agent.id)
            .where(
                Agent.revoked_at.is_(None),
                Agent.state != AgentState.ONLINE,
                or_(
                    Agent.last_seen_at < cutoff,
                    (Agent.last_seen_at.is_(None)) & (Agent.created_at < cutoff),
                ),
            )
            .order_by(Agent.id.asc())
            .limit(limit),
        )
        return list(result.scalars())

    async def prune_stale(
        self,
        *,
        cutoff: datetime,
        candidate_ids: list[UUID] | None = None,
    ) -> int:
        """Soft-revoke live agents that have been stale past ``cutoff``.

        "Stale" means: ``state != online`` AND (``last_seen_at`` is
        older than cutoff OR the row has never connected at all
        AND ``created_at`` is older than cutoff). Invoked by the
        daily :class:`AgentHygieneWorker`. Revocation hides an eligible ghost
        from the live Agents page and invalidates its bearer token. Event-
        bearing rows remain candidates just as they were for the former hard
        delete, but the soft revoke keeps those events attached instead of
        failing on PostgreSQL or orphaning them on SQLite.

        No stale row is hard-deleted. Agents are referenced by events,
        commands, worker/status history and alert state, with different FK
        actions across backends. In particular SQLite intentionally runs with
        FK enforcement disabled, so a reference-probe followed by DELETE can
        silently create dangling historical IDs. A durable tombstone is the
        single cross-backend lifecycle rule and also lets a later mint safely
        reclaim the human-readable name.
        """
        if candidate_ids is None:
            candidate_ids = await self.list_stale_ids(
                cutoff=cutoff,
                limit=AGENT_STALE_PRUNE_BATCH_SIZE,
            )
        candidate_ids = sorted(set(candidate_ids), key=str)
        if not candidate_ids:
            return 0
        if len(candidate_ids) > AGENT_STALE_PRUNE_BATCH_SIZE:
            raise ValueError(
                f"stale-agent mutation batch exceeds {AGENT_STALE_PRUNE_BATCH_SIZE} candidates",
            )

        # PostgreSQL callers share this transaction-scoped authority mutex
        # with inbound frames and explicit revocation. Lock in stable order so
        # a batch cannot deadlock another batch. SQLite's matching local mutex
        # must be acquired by the worker before it opens this write session.
        for agent_id in candidate_ids:
            await acquire_agent_authority_xact_lock(self.session, agent_id)

        stale = list(
            (
                await self.session.execute(
                    select(Agent)
                    .where(
                        Agent.id.in_(candidate_ids),
                        Agent.revoked_at.is_(None),
                        Agent.state != AgentState.ONLINE,
                        or_(
                            Agent.last_seen_at < cutoff,
                            # Never-connected agents (minted token then
                            # someone deleted the container before it
                            # booted) have last_seen_at=NULL; fall back to
                            # created_at so we can still prune them.
                            (Agent.last_seen_at.is_(None)) & (Agent.created_at < cutoff),
                        ),
                    )
                    .with_for_update(),
                )
            ).scalars(),
        )
        revoked_at = datetime.now(UTC)
        for agent in stale:
            await self.revoke(agent, at=revoked_at)
        return len(stale)

    async def reserve_name(
        self,
        *,
        project_id: UUID,
        name: str,
    ) -> AgentNameReservation:
        """Observe the current name owner under mutation authority.

        PostgreSQL holds ``FOR UPDATE`` through the caller's transaction. A
        remint can therefore perform any authorization refresh that may have
        been invalidated while waiting for this row before it releases the
        tombstone's human-readable name. SQLite callers already own the
        ``BEGIN IMMEDIATE`` writer reservation before reaching this query.

        An absent owner cannot be row-locked. The unique constraint remains
        the final arbiter for concurrent first mints of the same name.
        """
        owner = (
            await self.session.execute(
                select(Agent)
                .where(
                    Agent.project_id == project_id,
                    Agent.name == name,
                )
                .with_for_update(),
            )
        ).scalar_one_or_none()
        return AgentNameReservation(
            project_id=project_id,
            name=name,
            owner=owner,
        )

    async def insert_reserved(
        self,
        *,
        reservation: AgentNameReservation,
        token_hash: str,
    ) -> Agent:
        """Create an agent after :meth:`reserve_name` has established order.

        Used by the "mint agent token" admin endpoint. The handshake
        metadata (``protocol_version``, ``framework_adapter``,
        ``capabilities``) is overwritten when the agent first
        connects via :meth:`mark_online`.
        """
        existing = reservation.owner
        if existing is not None:
            # The API expires its identity map after authority acquisition so
            # its policy recheck cannot reuse stale User/Project/Membership
            # objects. Refresh the row whose lock we still own before deciding
            # whether its name can be released.
            await self.session.refresh(existing)
            if existing.revoked_at is None:
                raise AgentNameConflictError(reservation.name)
            await self._release_revoked_name(existing)

        agent = Agent(
            project_id=reservation.project_id,
            name=reservation.name,
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

    async def insert(
        self,
        *,
        project_id: UUID,
        name: str,
        token_hash: str,
    ) -> Agent:
        """Reserve a name and insert without an intervening policy refresh.

        Non-request callers can use this convenience method. The mint endpoint
        uses the explicit two-step API so it can revalidate authorization after
        a potentially blocking name reservation.
        """
        reservation = await self.reserve_name(project_id=project_id, name=name)
        return await self.insert_reserved(
            reservation=reservation,
            token_hash=token_hash,
        )


__all__ = [
    "AGENT_STALE_PRUNE_BATCH_SIZE",
    "REVOKED_AGENT_NAME_PREFIX",
    "AgentNameConflictError",
    "AgentNameReservation",
    "AgentRepository",
]
