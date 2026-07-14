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

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain.persistence.models import AuditLog, Z4JMeta
from z4j_brain.persistence.repositories._base import BaseRepository

#: ``z4j_meta`` key under which the audit-log retention sweeper stores the
#: HMAC-chain prune watermark: the ``row_hmac`` of the newest row it has
#: deleted. The chain verifier accepts a first surviving row whose
#: ``prev_row_hmac`` equals this value instead of demanding the
#: NULL-genesis anchor (which retention legitimately deletes), so an
#: enabled retention policy no longer produces a permanent false-positive
#: chain-truncation MISMATCH.
AUDIT_PRUNE_WATERMARK_KEY = "audit_prune_watermark"


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
        # Stable magic so the same lock is reused across processes.
        # 0x7A_34_6A_DA = "z4j" + "ada"(udit) ASCII pun, fits in int32.
        audit_chain_lock_id = 0x7A_34_6A_DA
        if self.session.bind is None:
            return
        if self.session.bind.dialect.name != "postgresql":
            return
        try:
            from sqlalchemy import text as _text

            await self.session.execute(
                _text("SELECT pg_advisory_xact_lock(:lock_id)"),
                {"lock_id": audit_chain_lock_id},
            )
        except Exception:  # noqa: S110  best-effort advisory lock, unique index is the durable safeguard
            # Lock is best-effort. The UNIQUE partial index on
            # ``prev_row_hmac`` is the durable safeguard.
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

    async def get_prune_watermark(self) -> str | None:
        """Return the stored audit-prune watermark, or None if unset.

        Read by the chain verifiers (``AuditService.verify_chain`` and
        the ``z4j audit verify`` CLI). Stored in the existing ``z4j_meta``
        key-value table under :data:`AUDIT_PRUNE_WATERMARK_KEY`; no
        dedicated table.
        """
        stmt = select(Z4JMeta.value).where(Z4JMeta.key == AUDIT_PRUNE_WATERMARK_KEY)
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def set_prune_watermark(self, row_hmac: str) -> None:
        """Upsert the audit-prune watermark into ``z4j_meta``.

        Idempotent single-row upsert: update the value in place when the
        key exists, insert it otherwise. Only one retention sweep runs at
        a time (Postgres advisory lock; SQLite single-writer), so the
        update-then-insert needs no further concurrency guard.
        ``z4j_meta.updated_at`` doubles as the ``pruned_at`` timestamp.
        """
        result = await self.session.execute(
            update(Z4JMeta).where(Z4JMeta.key == AUDIT_PRUNE_WATERMARK_KEY).values(value=row_hmac),
        )
        if int(result.rowcount or 0) == 0:
            self.session.add(Z4JMeta(key=AUDIT_PRUNE_WATERMARK_KEY, value=row_hmac))
            await self.session.flush()


__all__ = ["AUDIT_PRUNE_WATERMARK_KEY", "AuditLogRepository"]
