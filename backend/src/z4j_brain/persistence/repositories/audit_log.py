"""``audit_log`` repository.

Insert-only by application convention; the database trigger on
Postgres also enforces it. Concrete callers go through
:class:`AuditService`, NOT this repository directly - the service
owns the row HMAC and the canonicalisation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import AuditLog
from z4j_brain.persistence.repositories._base import BaseRepository


class AuditLogRepository(BaseRepository[AuditLog]):
    """Append-only access to the audit log."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, AuditLog)

    async def insert(
        self,
        *,
        id: UUID | None = None,
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
    ) -> AuditLog:
        """Insert one row with the AuditService-supplied row HMAC.

        ``prev_row_hmac`` links this row into the HMAC chain
        (audit v3 - finding A8). AuditService fetches the prior
        row's hmac via ``get_latest_row_hmac`` before building
        this row's input so deleting any chained row breaks the
        next chained row's anchor - detectable by
        ``AuditService.verify_chain``.
        """
        kwargs: dict[str, Any] = dict(
            action=action,
            target_type=target_type,
            target_id=target_id,
            result=result,
            outcome=outcome,
            event_id=event_id,
            user_id=user_id,
            project_id=project_id,
            api_key_id=api_key_id,
            source_ip=source_ip,
            user_agent=user_agent,
            audit_metadata=metadata,
            row_hmac=row_hmac,
            prev_row_hmac=prev_row_hmac,
            occurred_at=occurred_at,
        )
        if id is not None:
            kwargs["id"] = id
        row = AuditLog(**kwargs)
        self.session.add(row)
        await self.session.flush()
        return row

    async def get_latest_row_hmac(self) -> str | None:
        """Return the row_hmac of the most recently inserted row.

        Used by ``AuditService.record`` to build the HMAC chain
        anchor (audit v3 - finding A8). Returns None for the very
        first row ever written (genesis).

        Round-9 audit fix R9-Stor-H4 (Apr 2026): the chain anchor
        lock used to be taken HERE, but the caller may then do
        seconds of I/O (signing, audit metadata serialisation,
        etc.) before the actual INSERT, turning the audit chain
        into a global serialisation point. The lock is now taken
        by :meth:`acquire_chain_lock` immediately before the
        INSERT in ``AuditService.record``, holding it for
        microseconds instead.

        Round-9 audit fix R9-Stor-H5 (Apr 2026): also depends on
        the new ``ux_audit_log_prev_row_hmac`` partial UNIQUE index
        (migration ``2026_04_28_0012-audit_chain_unique.py``) so
        that a concurrent insert that wins the race instead of
        blocking on the lock collides at the DB level rather than
        silently forking the chain.

        Round-9 audit fix R9-Stor-MED-7 (Apr 2026): also order by
        ``id DESC`` as a deterministic tiebreaker. Two rows with
        identical ``occurred_at`` (sub-microsecond resolution on
        some platforms / bulk audit writes in a single tx) used to
        fall through to Postgres heap order, so the chain anchor
        flipped non-deterministically between calls.
        """
        from sqlalchemy import desc as _desc  # noqa: PLC0415

        stmt = (
            select(AuditLog.row_hmac)
            .order_by(_desc(AuditLog.occurred_at), _desc(AuditLog.id))
            .limit(1)
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def acquire_chain_lock(self) -> None:
        """Round-9 audit fix R9-Stor-H4 (Apr 2026): tight chain lock.

        Take a Postgres transaction-scoped advisory lock JUST before
        the INSERT in ``AuditService.record``. The lock is released
        on commit (xact-scope), so it's held for microseconds rather
        than the seconds the prior R7 placement allowed. Combined
        with the UNIQUE partial index on ``prev_row_hmac``, a
        concurrent racer that bypasses the lock fails at the DB
        level instead of forking the chain silently.

        SQLite no-ops the lock, the dialect doesn't ship
        ``pg_advisory_xact_lock`` and the dev path is single-writer.
        """
        # Stable magic so the same lock is reused across processes.
        # 0x7A_34_6A_DA = "z4j" + "ada"(udit) ASCII pun, fits in int32.
        _AUDIT_CHAIN_LOCK_ID = 0x7A_34_6A_DA
        if self.session.bind is None:
            return
        if self.session.bind.dialect.name != "postgresql":
            return
        try:
            from sqlalchemy import text as _text  # noqa: PLC0415

            await self.session.execute(
                _text("SELECT pg_advisory_xact_lock(:lock_id)"),
                {"lock_id": _AUDIT_CHAIN_LOCK_ID},
            )
        except Exception:  # noqa: BLE001
            # Lock is best-effort. The UNIQUE partial index on
            # ``prev_row_hmac`` (R9-Stor-H5) is the durable
            # safeguard.
            pass

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
        """Round-8 audit fix R8-HIGH-6 (Apr 2026): global counter.

        Mirrors :meth:`count_recent_by_action_and_ip` but does NOT
        filter by IP. SetupService uses this to enforce a global
        cap that complements the per-IP cap, closing the bypass
        where an attacker on a NAT or distributed botnet rotates
        source IPs to brute-force the 256-bit setup token without
        ever hitting the per-IP threshold.

        Round-9 audit fix R9-Reaud-H1 (Apr 2026): added
        ``exclude_actions`` so the SetupService can subtract the
        single ``setup.completed`` row that a successful first-boot
        leaves behind. Pre-fix the global cap counted that
        success-row toward the 8x-per-IP ceiling, effectively
        consuming one of the legitimate retry budget on a brand-new
        install before the first failed attempt.
        """
        where_clauses = [
            AuditLog.action.like(f"{action_prefix}%"),
            AuditLog.occurred_at >= since,
        ]
        for excluded in exclude_actions:
            where_clauses.append(AuditLog.action != excluded)
        result = await self.session.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(*where_clauses),
        )
        return int(result.scalar_one() or 0)

    async def stream_for_verify(
        self,
        *,
        chunk: int = 500,
    ) -> list[AuditLog]:
        """Return rows for offline HMAC verification.

        v1 returns up to ``chunk`` rows starting from the oldest;
        the verifier CLI re-invokes with ``offset`` for paging.
        Hot-table-aware: we never load the whole table into memory.
        """
        if chunk <= 0 or chunk > 5000:
            raise ValueError("chunk must be between 1 and 5000")
        result = await self.session.execute(
            select(AuditLog)
            .order_by(AuditLog.occurred_at.asc(), AuditLog.id.asc())
            .limit(chunk),
        )
        return list(result.scalars().all())


__all__ = ["AuditLogRepository"]
