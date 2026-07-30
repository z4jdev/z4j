"""``audit_log`` repository.

Insert-only by application convention; the database trigger on
Postgres also enforces it. Concrete callers go through
:class:`AuditService`, NOT this repository directly - the service
owns the row HMAC and the canonicalisation.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import AuditChainState, AuditLog, Z4JMeta
from z4j_brain.persistence.models.audit_chain import AUDIT_CHAIN_SINGLETON_ID
from z4j_brain.persistence.repositories._base import BaseRepository

#: ``z4j_meta`` key under which the audit-log retention sweeper stores the
#: HMAC-chain prune watermark: the ``row_hmac`` of the newest row it has
#: deleted. The chain verifier accepts a first surviving row whose
#: ``prev_row_hmac`` equals this value instead of demanding the
#: NULL-genesis anchor (which retention legitimately deletes), so an
#: enabled retention policy no longer produces a permanent false-positive
#: chain-truncation MISMATCH.
AUDIT_PRUNE_WATERMARK_KEY = "audit_prune_watermark"

# One exported lock id is shared by append, retention, and the offline
# Boundary-F ceremonies.  A signer must never silently continue after this
# lock fails.
AUDIT_CHAIN_ADVISORY_LOCK_KEY = 0x7A_34_6A_DA

#: Domain-separation label for the watermark MAC (see below).
_WATERMARK_MAC_LABEL = b"audit_prune_watermark|"


def _watermark_mac(secret: bytes, row_hmac: str) -> str:
    """MAC that authenticates a stored prune watermark to the master secret.

    The prune watermark re-anchors the HMAC chain after retention deletes
    the genesis row: ``verify_chain`` accepts a first surviving row whose
    ``prev_row_hmac`` equals the watermark instead of flagging a
    truncation. If the watermark were an unauthenticated ``z4j_meta``
    value, a DB-write adversary (no master secret) could delete the
    earliest rows -- e.g. intrusion evidence -- and set the watermark to
    the new-oldest row's own ``prev_row_hmac`` (already in the DB), and
    both verifiers would report a clean, fully-anchored chain. That is the
    exact prefix-truncation attack the NULL-genesis anchor was added to
    stop (1.6.0 High-3), re-opened by the 1.7 prune exception. Binding the
    watermark to ``HMAC(master_secret, label || row_hmac)`` means only the
    holder of the master secret can mint a watermark the verifier honors.
    """
    return hmac.new(
        secret, _WATERMARK_MAC_LABEL + row_hmac.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def format_prune_watermark(secret: bytes, row_hmac: str) -> str:
    """Serialize a watermark as ``<row_hmac>:<mac>`` for storage."""
    return f"{row_hmac}:{_watermark_mac(secret, row_hmac)}"


def authenticate_prune_watermark(
    secrets: Sequence[bytes],
    stored: str | None,
) -> str | None:
    """Return the bare ``row_hmac`` iff the watermark verifies under ANY
    secret in the rotation window.

    1.7.1 (M1): mirrors :meth:`AuditService.verify_row`, which tries every
    secret in ``settings.all_secrets_for_verification()`` so that rows (and
    now the watermark) minted BEFORE a ``Z4J_SECRET`` rotation still
    authenticate. The pre-1.7.1 single-secret check made ``z4j audit
    verify`` false-alarm "chain truncation" after a rotation even though
    every row verified -- the watermark had been signed with the previous
    key and no longer matched the current one.

    A missing / malformed / legacy-untagged / forged watermark (one that
    verifies under NO accepted secret) returns ``None`` -- the verifier then
    requires the NULL-genesis anchor exactly as if no prune had occurred. A
    pre-1.7.1 bare ``row_hmac`` value (no MAC) is indistinguishable from an
    attacker-set one and is correctly rejected; the operator heals it
    EXPLICITLY with ``z4j audit reseal-watermark`` after independently
    verifying the chain (H1 -- we never auto-retag, which would bless a
    possibly-forged truncation anchor).
    """
    if not stored or ":" not in stored:
        return None
    row_hmac, _, mac = stored.rpartition(":")
    if not row_hmac or not mac:
        return None
    return next(
        (
            row_hmac
            for secret in secrets
            if hmac.compare_digest(mac, _watermark_mac(secret, row_hmac))
        ),
        None,
    )


class AuditLogRepository(BaseRepository[AuditLog]):
    """Append-only access to the audit log."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, AuditLog)

    async def insert(
        self,
        *,
        id: UUID | None = None,  # noqa: A002  public insert() kwarg mirrors the audit_log.id column
        action: str,
        target_type: str,
        target_id: str | None,
        result: str,
        outcome: str | None,
        event_id: UUID | None,
        user_id: UUID | None,
        project_id: UUID | None,
        source_ip: str | None,
        user_agent: str | None,
        metadata: dict[str, Any],
        row_hmac: str,
        occurred_at: datetime,
        prev_row_hmac: str | None = None,
        api_key_id: UUID | None = None,
        legacy_frozen: bool | None = None,
        hmac_version: int | None = None,
        hmac_key_id: str | None = None,
        legacy_integrity_class: str | None = None,
        legacy_origin: str | None = None,
        chain_generation: UUID | None = None,
    ) -> AuditLog:
        """Insert one row with the AuditService-supplied row HMAC.

        ``prev_row_hmac`` links this row into the HMAC chain
        (audit v3 - finding A8). AuditService fetches the prior
        row's hmac via ``get_latest_row_hmac`` before building
        this row's input so deleting any chained row breaks the
        next chained row's anchor - detectable by
        ``AuditService.verify_chain``.
        """
        kwargs: dict[str, Any] = {
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "result": result,
            "outcome": outcome,
            "event_id": event_id,
            "user_id": user_id,
            "project_id": project_id,
            "api_key_id": api_key_id,
            "source_ip": source_ip,
            "user_agent": user_agent,
            "audit_metadata": metadata,
            "row_hmac": row_hmac,
            "prev_row_hmac": prev_row_hmac,
            "occurred_at": occurred_at,
            "legacy_frozen": legacy_frozen,
            "hmac_version": hmac_version,
            "hmac_key_id": hmac_key_id,
            "legacy_integrity_class": legacy_integrity_class,
            "legacy_origin": legacy_origin,
            "chain_generation": chain_generation,
        }
        if id is not None:
            kwargs["id"] = id
        row = AuditLog(**kwargs)
        self.session.add(row)
        await self.session.flush()
        return row

    async def list_misfires_for_schedule(
        self,
        *,
        project_id: UUID,
        schedule_id: UUID,
        limit: int = 50,
    ) -> list[AuditLog]:
        """Return a schedule's ``scheduler.misfire_detected`` rows, newest
        first.

        Backs the VIEWER-facing per-schedule misfire history (A4). The
        misfire detector writes these rows with ``target_id`` set to the
        schedule id; the ``(project_id, target_id, action)`` filter keeps
        it project-scoped + IDOR-safe. Bounded by ``limit``.
        """
        result = await self.session.execute(
            select(AuditLog)
            .where(
                AuditLog.project_id == project_id,
                AuditLog.target_id == str(schedule_id),
                AuditLog.action == "scheduler.misfire_detected",
            )
            .order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc())
            .limit(limit),
        )
        return list(result.scalars().all())

    async def list_misfires_for_project(
        self,
        *,
        project_id: UUID,
        limit: int = 50,
    ) -> list[AuditLog]:
        """Return a project's ``scheduler.misfire_detected`` rows across
        ALL its schedules, newest first.

        Backs the project-wide misfire view + the ``z4j misfires`` CLI.
        Mirrors :meth:`list_misfires_for_schedule` but drops the
        per-schedule ``target_id`` filter, so the result spans every
        schedule in the project; each returned row's ``target_id`` IS its
        own schedule id. The ``(project_id, action)`` filter keeps it
        project-scoped + IDOR-safe. Bounded by ``limit`` (hard-capped at
        1000 so a caller -- including the CLI, which hits this repo
        directly, not via the API's own cap -- can never runaway-scan the
        hot audit table).
        """
        capped = max(1, min(1000, limit))
        result = await self.session.execute(
            select(AuditLog)
            .where(
                AuditLog.project_id == project_id,
                AuditLog.action == "scheduler.misfire_detected",
            )
            .order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc())
            .limit(capped),
        )
        return list(result.scalars().all())

    async def get_latest_row_hmac(self) -> str | None:
        """Return the row_hmac of the most recently inserted row.

        Used by ``AuditService.record`` to build the HMAC chain
        anchor. Returns None for the very first row ever written
        (genesis).

        The chain anchor lock is NOT taken here, because the
        caller may then do seconds of I/O (signing, audit
        metadata serialisation, etc.) before the actual INSERT,
        turning the audit chain into a global serialisation
        point. The lock is taken by :meth:`acquire_chain_lock`
        immediately before the INSERT in
        ``AuditService.record``, holding it for microseconds
        instead.

        This also depends on the
        ``ux_audit_log_prev_row_hmac`` partial UNIQUE index so
        that a concurrent insert that wins the race instead of
        blocking on the lock collides at the DB level rather
        than silently forking the chain.

        Orders by ``id DESC`` as a deterministic tiebreaker.
        Two rows with identical ``occurred_at`` (sub-microsecond
        resolution on some platforms / bulk audit writes in a
        single tx) would otherwise fall through to Postgres
        heap order, flipping the chain anchor
        non-deterministically between calls.
        """
        from sqlalchemy import desc as _desc

        stmt = (
            select(AuditLog.row_hmac)
            .order_by(_desc(AuditLog.occurred_at), _desc(AuditLog.id))
            .limit(1)
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def acquire_chain_lock(self) -> None:
        """Tight chain lock taken JUST before the INSERT.

        Takes a Postgres transaction-scoped advisory lock
        immediately before the INSERT in ``AuditService.record``.
        The lock is released on commit (xact-scope), so it's
        held for microseconds. Combined with the UNIQUE partial
        index on ``prev_row_hmac``, a concurrent racer that
        bypasses the lock fails at the DB level instead of
        forking the chain silently.

        SQLite no-ops the lock - the dialect doesn't ship
        ``pg_advisory_xact_lock`` and the dev path is
        single-writer.
        """
        if self.session.bind is None:
            raise RuntimeError("audit-chain session is not bound to an engine")
        if self.session.bind.dialect.name != "postgresql":
            return
        from sqlalchemy import text as _text

        await self.session.execute(
            _text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": AUDIT_CHAIN_ADVISORY_LOCK_KEY},
        )

    async def require_sqlite_immediate_write_unit(self) -> None:
        """Start, or prove, the pre-read SQLite writer transaction."""

        if self.session.bind is None:
            raise RuntimeError("audit-chain session is not bound to an engine")
        if self.session.bind.dialect.name != "sqlite":
            return
        if self.session.sync_session.info.get("z4j_sqlite_immediate") is True:
            return
        if self.session.in_transaction():
            raise RuntimeError(
                "audited SQLite write unit did not begin with BEGIN IMMEDIATE "
                "before its first database read",
            )
        from sqlalchemy import text as _text

        await self.session.execute(_text("BEGIN IMMEDIATE"))
        self.session.sync_session.info["z4j_sqlite_immediate"] = True

    async def get_chain_state_for_update(self) -> AuditChainState:
        """Lock and return the one mandatory authenticated state row."""

        stmt = (
            select(AuditChainState)
            .where(
                AuditChainState.singleton_id == AUDIT_CHAIN_SINGLETON_ID,
            )
            .with_for_update()
        )
        rows = list((await self.session.execute(stmt)).scalars().all())
        if len(rows) != 1:
            raise RuntimeError(
                "audit chain state is missing or duplicated; refusing to sign",
            )
        return rows[0]

    async def set_chain_transition(self, transition: str) -> None:
        """Enable one transaction-local guarded Boundary-F state transition."""

        if self.session.bind is None:
            raise RuntimeError("audit-chain session is not bound to an engine")
        if self.session.bind.dialect.name == "sqlite":
            from sqlalchemy import text as _text

            from z4j_brain.persistence.audit_guard import (
                register_sqlite_audit_guard,
            )

            async_connection = await self.session.connection()
            await async_connection.run_sync(
                lambda sync_connection: register_sqlite_audit_guard(
                    sync_connection.connection.dbapi_connection,
                ),
            )
            await self.session.execute(
                _text("SELECT z4j_audit_guard('arm', :value)"),
                {"value": transition},
            )
            return
        if self.session.bind.dialect.name != "postgresql":
            return
        from sqlalchemy import text as _text

        await self.session.execute(
            _text("SELECT set_config('z4j.audit_transition', :value, true)"),
            {"value": transition},
        )

    async def get_active_head_for_update(
        self,
        *,
        generation: UUID,
    ) -> AuditLog | None:
        """Lock the actual newest active row in one generation."""

        stmt = (
            select(AuditLog)
            .where(
                AuditLog.legacy_frozen.is_(False),
                AuditLog.chain_generation == generation,
            )
            .order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc())
            .limit(1)
            .with_for_update()
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def count_active_generation(self, *, generation: UUID) -> int:
        result = await self.session.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.legacy_frozen.is_(False),
                AuditLog.chain_generation == generation,
            ),
        )
        return int(result.scalar_one())

    async def count_frozen_rows(self) -> int:
        result = await self.session.execute(
            select(func.count()).select_from(AuditLog).where(AuditLog.legacy_frozen.is_(True)),
        )
        return int(result.scalar_one())

    async def count_recent_by_action_and_ip(
        self,
        *,
        action_prefix: str,
        source_ip: str,
        since: datetime,
    ) -> int:
        """Return the number of audit rows matching prefix + ip + window.

        Used by the SetupService to enforce a per-IP rate limit on
        ``setup.attempt`` rows that survives across worker restarts
        and across multiple uvicorn workers - a per-process deque
        cannot do that. The query is bounded by the
        ``ix_audit_log_action_pattern`` index added in migration
        0002 (``(project_id, action text_pattern_ops, occurred_at DESC)``)
        for fast prefix lookups.
        """
        result = await self.session.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.action.like(f"{action_prefix}%"),
                AuditLog.source_ip == source_ip,
                AuditLog.occurred_at >= since,
            ),
        )
        return int(result.scalar_one() or 0)

    async def count_recent_by_action(
        self,
        *,
        action_prefix: str,
        since: datetime,
        exclude_actions: tuple[str, ...] = (),
    ) -> int:
        """Global counter complementing the per-IP variant.

        Mirrors :meth:`count_recent_by_action_and_ip` but does
        NOT filter by IP. SetupService uses this to enforce a
        global cap that complements the per-IP cap, closing the
        bypass where an attacker on a NAT or distributed botnet
        rotates source IPs to brute-force the 256-bit setup
        token without ever hitting the per-IP threshold.

        ``exclude_actions`` lets the SetupService subtract the
        single ``setup.completed`` row that a successful
        first-boot leaves behind. Without this, the global cap
        would count that success-row toward the 8x-per-IP
        ceiling, consuming one of the legitimate retry budget
        on a brand-new install before the first failed attempt.
        """
        where_clauses = [
            AuditLog.action.like(f"{action_prefix}%"),
            AuditLog.occurred_at >= since,
        ]
        for excluded in exclude_actions:
            where_clauses.append(AuditLog.action != excluded)
        result = await self.session.execute(
            select(func.count()).select_from(AuditLog).where(*where_clauses),
        )
        return int(result.scalar_one() or 0)

    async def stream_for_verify(
        self,
        *,
        chunk: int = 500,
        after_occurred_at: datetime | None = None,
        after_id: UUID | None = None,
    ) -> list[AuditLog]:
        """Return up to ``chunk`` rows in chain order for HMAC verify.

        Keyset-paginated on the chain-order key ``(occurred_at, id)``:
        pass the previous page's last ``(occurred_at, id)`` as
        ``after_occurred_at`` / ``after_id`` to fetch the next page. The
        ``z4j audit verify`` CLI loops until a short page, so the ENTIRE
        chain is verified rather than only the first ``chunk`` rows (the
        earlier single-slice behaviour silently skipped every row past
        the cap -- exactly the case a compliance audit cares about).
        Hot-table-aware: we never load the whole table into memory.
        """
        if chunk <= 0 or chunk > 5000:
            raise ValueError("chunk must be between 1 and 5000")
        stmt = select(AuditLog).order_by(
            AuditLog.occurred_at.asc(),
            AuditLog.id.asc(),
        )
        if after_occurred_at is not None and after_id is not None:
            # Row-value keyset "strictly after (occurred_at, id)",
            # written as an OR rather than a tuple comparison so it is
            # portable across Postgres and SQLite.
            stmt = stmt.where(
                or_(
                    AuditLog.occurred_at > after_occurred_at,
                    and_(
                        AuditLog.occurred_at == after_occurred_at,
                        AuditLog.id > after_id,
                    ),
                ),
            )
        result = await self.session.execute(stmt.limit(chunk))
        return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Retention prune watermark (1.7 security hardening)
    # ------------------------------------------------------------------

    async def get_oldest_prev_row_hmac(self) -> str | None:
        """Return the ``prev_row_hmac`` of the oldest surviving audit row.

        Chain order is ``(occurred_at, id)`` ascending. After an
        oldest-first retention prune this value is, by construction, the
        ``row_hmac`` of the newest row the sweep deleted: the deleted set
        is a contiguous prefix (rows are deleted strictly oldest-first by
        ``occurred_at``, which is monotonic with insert order), so the
        oldest survivor's chain-predecessor is exactly the last-deleted
        row. The retention sweeper reads this back and stores it as the
        prune watermark. Returns None when the table is empty or the
        oldest surviving row is a NULL-genesis row (no prune has crossed
        it, so no watermark is needed).
        """
        stmt = (
            select(AuditLog.prev_row_hmac)
            .order_by(AuditLog.occurred_at.asc(), AuditLog.id.asc())
            .limit(1)
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def get_prune_watermark(self, *, secrets: Sequence[bytes]) -> str | None:
        """Return the AUTHENTICATED bare ``row_hmac`` watermark, or None.

        Read by the chain verifiers (``AuditService.verify_chain`` and
        the ``z4j audit verify`` CLI). The stored value is
        ``<row_hmac>:<mac>`` (see :func:`format_prune_watermark`); this
        verifies the MAC against ANY secret in the rotation window
        ``secrets`` (M1) before returning the bare ``row_hmac``, so a
        tampered / forged / legacy-untagged watermark resolves to None and
        the verifier falls back to requiring the NULL-genesis anchor.
        Stored in the existing ``z4j_meta`` key-value table under
        :data:`AUDIT_PRUNE_WATERMARK_KEY`; no dedicated table.
        """
        stored = await self.get_raw_prune_watermark()
        return authenticate_prune_watermark(secrets, stored)

    async def get_raw_prune_watermark(self) -> str | None:
        """Return the RAW stored watermark value (no authentication).

        Only the reseal ceremony (``z4j audit reseal-watermark``, H1) reads
        this: it must inspect a legacy bare value that does not authenticate
        so an operator can, after independently verifying the chain,
        re-sign it under the current secret. Never used by the verifiers.
        """
        stmt = select(Z4JMeta.value).where(Z4JMeta.key == AUDIT_PRUNE_WATERMARK_KEY)
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def set_prune_watermark(self, row_hmac: str, *, secret: bytes) -> None:
        """Upsert the AUTHENTICATED audit-prune watermark into ``z4j_meta``.

        Stores ``<row_hmac>:<mac>`` where the MAC binds ``row_hmac`` to the
        master ``secret`` (see :func:`format_prune_watermark`), so only the
        secret holder can mint a watermark the verifier honors.

        Idempotent single-row upsert: update the value in place when the
        key exists, insert it otherwise. Only one retention sweep runs at
        a time (Postgres advisory lock; SQLite single-writer), so the
        update-then-insert needs no further concurrency guard.
        ``z4j_meta.updated_at`` doubles as the ``pruned_at`` timestamp.
        """
        tagged = format_prune_watermark(secret, row_hmac)
        result = await self.session.execute(
            update(Z4JMeta).where(Z4JMeta.key == AUDIT_PRUNE_WATERMARK_KEY).values(value=tagged),
        )
        if int(result.rowcount or 0) == 0:
            self.session.add(Z4JMeta(key=AUDIT_PRUNE_WATERMARK_KEY, value=tagged))
            await self.session.flush()


__all__ = [
    "AUDIT_CHAIN_ADVISORY_LOCK_KEY",
    "AUDIT_PRUNE_WATERMARK_KEY",
    "AuditLogRepository",
    "authenticate_prune_watermark",
    "format_prune_watermark",
]
