"""``audit_log`` table - append-only audit trail.

Every command execution and every privileged action writes a row
here. The migration installs database-level triggers that REVOKE
``UPDATE`` and ``DELETE`` from the public role and raise an
exception on attempted mutation - application-level guards alone
are not sufficient for an audit trail.

Each row also carries a per-row HMAC-SHA256 over its canonical
content, computed by :class:`AuditService` using
``settings.secret`` as the key. The verifier is exposed via the
``z4j audit verify`` CLI subcommand. Combined with the
append-only trigger, this gives us tamper-evidence for any
modification short of a privileged DBA who also holds the master
secret.

Retention is handled out-of-band by a privileged role that bypasses
the trigger. Intentional, audited exception.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin
from z4j_brain.persistence.types import inet, jsonb


class AuditLog(PKMixin, Base):
    """A single audit-log entry.

    Attributes:
        project_id: Owning project. ``ON DELETE SET NULL`` so the
            audit trail outlives project deletion.
        user_id: Acting user, if any. ``ON DELETE SET NULL``.
        action: What happened (``command.issued``,
            ``token.minted``, ``project.created``, ...).
        target_type: Generic target identifier (``task``, ``project``,
            ``user``, ``agent``, ...).
        target_id: Engine- or brain-native identifier of the target.
        result: ``success`` / ``failed`` / ``denied``.
        metadata: Free-form context.
        source_ip: Caller IP, if known.
        user_agent: Caller user-agent, if known.
        occurred_at: Server-side timestamp.
    """

    __tablename__ = "audit_log"

    project_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="SET NULL"),
        nullable=True,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    #: Acting API key, if the action was triggered via a bearer
    #: token (declarative reconciler, deploy script, CI). NULL for
    #: actions performed via session cookie (dashboard) or for
    #: legacy rows written before 1.2.2.
    #:
    #: NOTE (1.2.2 third-pass audit fix): this column intentionally
    #: has NO FOREIGN KEY constraint. The HMAC at v4 includes
    #: ``api_key_id``; an ``ON DELETE SET NULL`` cascade would
    #: silently rewrite the column on key revoke and break the
    #: HMAC, marking thousands of audit rows as "tampered" after
    #: a routine key rotation. ``ON DELETE RESTRICT`` would block
    #: revoke entirely. Neither is acceptable. Without the FK the
    #: column is informational only; the audit trail keeps the
    #: original UUID forever, and ``z4j audit verify``
    #: continues to validate the row even after the referenced
    #: api_keys row is gone.
    api_key_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    target_type: Mapped[str] = mapped_column(String(40), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    result: Mapped[str] = mapped_column(String(20), nullable=False)
    audit_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        jsonb(),
        nullable=False,
        default=dict,
        server_default="{}",
    )
    source_ip: Mapped[str | None] = mapped_column(inet(), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # ------------------------------------------------------------------
    # B3 hardening: structured outcome + correlation + tamper evidence.
    # ------------------------------------------------------------------
    #: ``allow`` | ``deny`` | ``error``. Lets dashboards filter on
    #: outcome without parsing the free-form ``result`` text.
    outcome: Mapped[str | None] = mapped_column(String(20), nullable=True)
    #: Correlation id for multi-row events. Set by ``AuditService``
    #: when a single user-visible action produces several audit rows
    #: (e.g. login → membership lookup → policy check).
    event_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    #: Per-row HMAC-SHA256 over canonical row content using
    #: ``settings.secret`` as the key. Computed by
    #: :class:`AuditService` on insert. Verified offline by
    #: ``z4j audit verify``. Tamper-evidence for any party
    #: without the master secret.
    row_hmac: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: HMAC of the PRIOR row at the moment THIS row was written -
    #: folds into the HMAC input (v3) so consecutive rows form a
    #: chain. Deleting an entire row breaks the chain at the next
    #: row's `prev_row_hmac` check, which the `verify` walk
    #: detects. Null for v2 rows (pre-chain upgrade) and for the
    #: very first row ever written (genesis).
    prev_row_hmac: Mapped[str | None] = mapped_column(
        String(64), nullable=True,
    )

    __table_args__ = (
        Index(
            "ix_audit_log_project_occurred",
            "project_id", "occurred_at",
        ),
        Index(
            "ix_audit_log_user_occurred",
            "user_id", "occurred_at",
        ),
        Index(
            "ix_audit_log_action_occurred",
            "action", "occurred_at",
        ),
        # Standalone index on occurred_at so the retention
        # sweeper's ``WHERE occurred_at < ? ORDER BY occurred_at``
        # range scan doesn't degrade to seq-scan + sort.
        Index(
            "ix_audit_log_occurred_at",
            "occurred_at",
        ),
        # Partial UNIQUE index on prev_row_hmac, enforces "one row
        # per chain link" so a missed advisory lock or a future
        # bypass of ``AuditService.record`` can't silently fork the
        # chain. Genesis row carries ``prev_row_hmac=NULL`` and
        # NULL!=NULL in UNIQUE, so the partial predicate excludes
        # the genesis row from uniqueness, exactly what we want.
        Index(
            "ux_audit_log_prev_row_hmac",
            "prev_row_hmac",
            unique=True,
            postgresql_where=text("prev_row_hmac IS NOT NULL"),
            sqlite_where=text("prev_row_hmac IS NOT NULL"),
        ),
        # Partial index on api_key_id, supports the dashboard's
        # "filter audit log by API key" view without a sequential
        # scan once the table grows. Most rows have api_key_id IS
        # NULL (cookie-session actions), so the partial predicate
        # keeps the index small.
        Index(
            "ix_audit_log_api_key_id",
            "api_key_id",
            postgresql_where=text("api_key_id IS NOT NULL"),
            sqlite_where=text("api_key_id IS NOT NULL"),
        ),
    )


__all__ = ["AuditLog"]
