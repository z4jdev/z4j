"""z4j 1.7 security-hardening schema delta (per-account MFA lockout +
TOTP anti-replay).

Revision ID: v1_7_security_hardening
Revises: v1_7_schema
Create Date: 2026-07-11

Adds three columns to ``users`` for the 1.7 security-hardening wave:

1. ``failed_mfa_count`` (INTEGER NOT NULL DEFAULT 0) -- the per-account
   failed-MFA-code counter backing the NIST 800-63B 5.2.2 lockout that
   complements the bypassable per-IP verify throttle.
2. ``mfa_locked_until`` (TIMESTAMPTZ, nullable) -- when set and in the
   future, MFA code entry is refused for the account.
3. ``last_totp_counter`` (BIGINT, nullable) -- the TOTP single-use
   high-water mark (RFC 6238 5.2) that closes the ~90s replay window on
   the +/-1 step acceptance skew.

The audit-log HMAC-chain prune watermark (1.7 audit) needs NO new
schema: it is stored in the existing ``z4j_meta`` key-value table under
the ``audit_prune_watermark`` key, so this migration carries only the
three ``users`` columns.

Idempotency and fresh installs. A fresh install builds the whole schema
from the model metadata in the 0001 initial migration, so on a fresh DB
these columns already exist and every ``add_column`` here is guarded to
be a no-op (the inspector check finds the column present). On a real
1.6.x / 1.7-consolidated upgrade the columns do not yet exist and each is
added. Every added column is nullable or server-defaulted, so a running
N-1 brain is unaffected and the additive step is safe on a populated DB.

Cross-dialect + round-trip. ``upgrade()`` adds the three columns;
``downgrade()`` drops them, using ``batch_alter_table`` on SQLite (which
cannot ``ALTER TABLE ... DROP COLUMN`` in place on older engines) and a
plain ``drop_column`` on Postgres, mirroring the drop discipline in
``v1_7_schema``. The revision round-trips on Postgres and SQLite per the
1.4 compatibility floor."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# ---------------------------------------------------------------------------
# Alembic revision identifiers
# ---------------------------------------------------------------------------

revision: str = "v1_7_security_hardening"
down_revision: str | Sequence[str] | None = "v1_7_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

compat = {
    "min_z4j_version": "1.7.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_7_schema",
    "downgrade_to": "v1_7_schema",
}

_USERS_TABLE = "users"
_FAILED_MFA_COUNT_COLUMN = "failed_mfa_count"
_MFA_LOCKED_UNTIL_COLUMN = "mfa_locked_until"
_LAST_TOTP_COUNTER_COLUMN = "last_totp_counter"


def _column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    return any(c["name"] == column for c in sa.inspect(bind).get_columns(table))


def upgrade() -> None:
    """Add the three security-hardening columns to ``users`` (guarded)."""
    bind = op.get_bind()

    if not _column_exists(bind, _USERS_TABLE, _FAILED_MFA_COUNT_COLUMN):
        op.add_column(
            _USERS_TABLE,
            sa.Column(
                _FAILED_MFA_COUNT_COLUMN,
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
        )
    if not _column_exists(bind, _USERS_TABLE, _MFA_LOCKED_UNTIL_COLUMN):
        op.add_column(
            _USERS_TABLE,
            sa.Column(
                _MFA_LOCKED_UNTIL_COLUMN,
                sa.DateTime(timezone=True),
                nullable=True,
            ),
        )
    if not _column_exists(bind, _USERS_TABLE, _LAST_TOTP_COUNTER_COLUMN):
        op.add_column(
            _USERS_TABLE,
            sa.Column(
                _LAST_TOTP_COUNTER_COLUMN,
                sa.BigInteger(),
                nullable=True,
            ),
        )


def downgrade() -> None:
    """Drop the three security-hardening columns (guarded, dialect-safe)."""
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    # Drop in reverse add order. On SQLite, batch each drop so the
    # table-rebuild engine can remove the column; on Postgres a plain
    # drop_column suffices.
    for column in (
        _LAST_TOTP_COUNTER_COLUMN,
        _MFA_LOCKED_UNTIL_COLUMN,
        _FAILED_MFA_COUNT_COLUMN,
    ):
        if not _column_exists(bind, _USERS_TABLE, column):
            continue
        if is_postgres:
            op.drop_column(_USERS_TABLE, column)
        else:
            with op.batch_alter_table(_USERS_TABLE) as batch:
                batch.drop_column(column)
