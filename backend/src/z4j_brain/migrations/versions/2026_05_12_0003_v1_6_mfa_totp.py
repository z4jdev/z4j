"""z4j 1.6.0 TOTP MFA: users mfa columns, mfa_recovery_codes,
trusted_devices, sessions.mfa_verified_at.

Revision ID: v1_6_mfa_totp
Revises: v1_5_agent_status_history
Create Date: 2026-05-12

Phase 1 of the 1.6.0 MFA work. Lands the schema only; the rest of the
brain still ignores these columns until phase 3 wires them up. See
``docs/MFA-DESIGN.md`` for the full design.

Idempotent design
-----------------

The codebase's ``v1_3_0_initial`` migration creates every table by
calling ``Base.metadata.create_all()`` against the live ORM model.
Because the ORM model is updated in the same commit that ships this
migration, a fresh 1.6+ install ends up with the new MFA columns +
tables already populated by ``v1_3_0_initial`` -- the alembic chain
then runs ``v1_5_agent_status_history`` and finally this migration,
which would otherwise fail with "column already exists" on the fresh
path.

To make a single migration body work for **both** fresh-install and
upgrade-from-earlier-build paths, we inspect each target column /
table and only emit DDL when the artifact is actually absent. The
downgrade is symmetrical: drop only what currently exists.

A future "schema spring-clean" migration can collapse the column
pattern (and remove the 1.3.x unused stubs ``users.mfa_secret`` /
``users.mfa_enabled`` that linger on real upgrade paths) once the
operator population on 1.4.x is small enough that the churn is
worth it. For now we tolerate the cosmetic leftovers.

What this migration adds
------------------------

1. Three new ``users`` columns:
   - ``mfa_secret_encrypted`` BYTEA -- AES-GCM ciphertext of the TOTP
     shared secret, with a 12-byte nonce prefix. Key derived from
     ``Z4J_SECRET`` via HKDF-SHA256 with ``info=z4j-mfa-totp-secret``.
   - ``mfa_enrolled_at`` TIMESTAMPTZ -- canonical "MFA is on"
     predicate; non-null iff the user is enrolled.
   - ``mfa_enforcement_started_at`` TIMESTAMPTZ -- anchor for the
     grace-window deadline.
2. New table ``mfa_recovery_codes``: single-use codes, argon2id-hashed.
3. New table ``trusted_devices``: server-side ``z4j_mfa_trust`` cookie
   store, UNIQUE on ``cookie_id_hash``.
4. New column ``sessions.mfa_verified_at`` TIMESTAMPTZ -- consumed by
   the sensitive-action gate.

Per the v1.4 compat floor, the round-trip
``upgrade head -> downgrade base -> upgrade head`` is exercised by
``TestMigrationRoundTrip`` in ``tests/integration/test_migration_pg.py``.

Cross-dialect notes
-------------------

``BYTEA`` on Postgres maps to ``BLOB`` on SQLite via SQLAlchemy's
``LargeBinary``; ``TIMESTAMPTZ`` maps to ``TEXT (ISO8601)`` on
SQLite. The migration relies on SQLAlchemy emitting the right DDL
per dialect.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models.mfa_recovery_code import MfaRecoveryCode
from z4j_brain.persistence.models.trusted_device import TrustedDevice


# ---------------------------------------------------------------------------
# Alembic revision identifiers
# ---------------------------------------------------------------------------

revision: str = "v1_6_mfa_totp"
down_revision: str | Sequence[str] | None = "v1_5_agent_status_history"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


compat = {
    "min_z4j_version": "1.6.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_5_agent_status_history",
    "downgrade_to": "v1_5_agent_status_history",
}


# ---------------------------------------------------------------------------
# Idempotency helpers
# ---------------------------------------------------------------------------


def _column_exists(bind, table_name: str, column_name: str) -> bool:
    """Return True iff the column is already present in the live DB."""
    inspector = sa.inspect(bind)
    return any(
        c["name"] == column_name
        for c in inspector.get_columns(table_name)
    )


def _table_exists(bind, table_name: str) -> bool:
    """Return True iff the table is already present in the live DB."""
    return sa.inspect(bind).has_table(table_name)


def _add_column_if_missing(
    bind, table_name: str, column: sa.Column,
) -> None:
    if not _column_exists(bind, table_name, column.name):
        op.add_column(table_name, column)


def _drop_column_if_present(
    bind, table_name: str, column_name: str,
) -> None:
    if _column_exists(bind, table_name, column_name):
        op.drop_column(table_name, column_name)


# ---------------------------------------------------------------------------
# upgrade / downgrade
# ---------------------------------------------------------------------------


def upgrade() -> None:
    """Apply the 1.6.0 MFA schema, idempotently."""
    bind = op.get_bind()

    # 1. ``users`` MFA columns.
    _add_column_if_missing(
        bind, "users",
        sa.Column("mfa_secret_encrypted", sa.LargeBinary, nullable=True),
    )
    _add_column_if_missing(
        bind, "users",
        sa.Column(
            "mfa_enrolled_at", sa.DateTime(timezone=True), nullable=True,
        ),
    )
    _add_column_if_missing(
        bind, "users",
        sa.Column(
            "mfa_enforcement_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    # 2-3. New tables. ``Base.metadata.create_all(..., checkfirst=True)``
    # already skips tables that exist, so no extra guard needed; the
    # default is checkfirst=True but make it explicit for the reader.
    Base.metadata.create_all(
        bind=bind,
        tables=[MfaRecoveryCode.__table__, TrustedDevice.__table__],
        checkfirst=True,
    )

    # 4. ``sessions`` sensitive-action gate anchor.
    _add_column_if_missing(
        bind, "sessions",
        sa.Column(
            "mfa_verified_at", sa.DateTime(timezone=True), nullable=True,
        ),
    )


def downgrade() -> None:
    """Reverse every added column and table, idempotently."""
    bind = op.get_bind()

    # 4 (reverse).
    _drop_column_if_present(bind, "sessions", "mfa_verified_at")

    # 2-3 (reverse). Tables drop via the model object's ``drop`` with
    # ``checkfirst=True`` so the call is safe if the table is absent.
    TrustedDevice.__table__.drop(bind=bind, checkfirst=True)
    MfaRecoveryCode.__table__.drop(bind=bind, checkfirst=True)

    # 1 (reverse).
    _drop_column_if_present(bind, "users", "mfa_enforcement_started_at")
    _drop_column_if_present(bind, "users", "mfa_enrolled_at")
    _drop_column_if_present(bind, "users", "mfa_secret_encrypted")
