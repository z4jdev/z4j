"""``audit_log`` table - append-only audit trail.

Mutating workflows write rows transactionally where their contract requires
it. Some denials and security breadcrumbs are best-effort, and an
infrastructure failure can prevent such a record. The migration installs
database-level triggers that raise on mutation, because application-level
guards alone cannot constrain a code path that forgets to call them.

Each row also carries a per-row HMAC-SHA256 over its canonical
content chained to its predecessor, computed by
:class:`AuditService` under the dedicated audit-chain key. The
verifier is exposed via the ``z4j audit verify`` CLI subcommand.

The scope of that evidence is narrower than it looks, and the
narrowness is deliberate rather than an oversight. The head and row
counts the verifier compares against live in ``audit_chain_state``,
in this same database, so a role that can write both tables can
delete recent rows and restore an earlier copy of that state row;
the copy still authenticates, because it was signed when it was
current, and verification then reports the shortened history as
clean. What these guards do defend is every path that goes through
the application: a bug that writes outside the audit service, a
downgraded adapter, an operator running a ``DELETE`` by hand.
Evidence that must survive a hostile database role has to be
anchored outside the database (see ``docs/SECURITY.md`` section 10.2).

The DELETE trigger admits a statement whose ``z4j.audit_transition``
session setting names a recognised transition, which is how retention
and generation reset remove rows. That setting is not an identity
check; it separates code paths, not people.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    DateTime,
    Index,
    String,
    Text,
    desc,
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
        nullable=True,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    #: Acting API key, if the action was triggered via a bearer
    #: token (declarative reconciler, deploy script, CI). NULL for
    #: actions performed via session cookie (dashboard) or for
    #: legacy rows written before 1.2.2.
    #:
    #: NOTE: this column intentionally
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
        String(64),
        nullable=True,
    )
    #: Boundary-F marker columns.  They remain nullable only at the
    #: preparation revision while pre-1.8 rows are classified offline.
    #: Activation removes server defaults and installs the conditional
    #: constraints that distinguish frozen legacy evidence from active v2
    #: generation members.
    legacy_frozen: Mapped[bool | None] = mapped_column(nullable=True)
    hmac_version: Mapped[int | None] = mapped_column(nullable=True)
    hmac_key_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    legacy_integrity_class: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    legacy_origin: Mapped[str | None] = mapped_column(String(120), nullable=True)
    chain_generation: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )

    __table_args__ = (
        Index(
            "ix_audit_log_project_occurred",
            "project_id",
            "occurred_at",
        ),
        Index(
            "ix_audit_log_user_occurred",
            "user_id",
            "occurred_at",
        ),
        Index(
            "ix_audit_log_action_occurred",
            "action",
            "occurred_at",
        ),
        # Setup's unauthenticated brute-force budget performs bounded
        # ``action LIKE 'setup.%'`` scans.  A normal varchar B-tree cannot
        # service that prefix predicate under a non-C PostgreSQL collation;
        # bind the matching operator class explicitly and cover both the
        # global and per-IP time-window counters.  SQLite uses the same
        # physical column order and receives an additional binary prefix
        # range in the repository query.
        Index(
            "ix_audit_log_action_pattern",
            "action",
            desc("occurred_at"),
            "source_ip",
            postgresql_ops={"action": "varchar_pattern_ops"},
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
            postgresql_where=text("prev_row_hmac IS NOT NULL AND legacy_frozen = false"),
            sqlite_where=text("prev_row_hmac IS NOT NULL AND legacy_frozen = 0"),
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
