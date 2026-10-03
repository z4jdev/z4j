"""Add the ``auditor`` project role.

``memberships.role`` is the native PostgreSQL enum ``project_role``.
Adding a label to a native enum is additive and keeps every existing row
as it is. On SQLite the same column is a plain ``VARCHAR`` with no
``CHECK`` constraint listing the roles, so nothing changes there.

The downgrade is the inverse and is refused while a membership still
holds the role: the previous brain cannot represent such a row, so it
would fail on the first read of it rather than lose it quietly. Move
those members to another role first (``viewer`` is the nearest; it
holds strictly less authority), then run the downgrade. The refusal is
declared as ``DOWNGRADE_PREFLIGHT`` so ``env.py`` evaluates it over the
whole resolved downgrade plan before its first step, and ``downgrade()``
asks once more before it rebuilds the type. Pending
invitations that name the role are left alone: the previous brain
refuses them at accept time by validating the stored role against its
own enum.

Revision ID: v1_12_auditor_role
Revises: v1_12_export_jobs_sink
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from alembic.util import CommandError

revision: str = "v1_12_auditor_role"
down_revision: str | Sequence[str] | None = "v1_12_export_jobs_sink"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TYPE = "project_role"
_TABLE = "memberships"
_COLUMN = "role"
_ROLE = "auditor"
#: The labels the previous release's enum carries, in its declaration order.
_PREVIOUS_LABELS = ("viewer", "operator", "admin")


def _auditor_membership_count(bind: sa.engine.Connection) -> int:
    return int(
        bind.execute(
            # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
            sa.text("SELECT count(*) FROM memberships WHERE role = :role"),
            {"role": _ROLE},
        ).scalar_one(),
    )


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # SQLite stores the role as VARCHAR(8) with no CHECK constraint;
        # "auditor" fits and needs no schema change.
        return
    # ``ADD VALUE`` is idempotent with IF NOT EXISTS, so a half-applied
    # upgrade can be re-run. The new label is not used in this transaction
    # (PostgreSQL forbids that), which is exactly the case here.
    # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    op.execute(sa.text(f"ALTER TYPE {_TYPE} ADD VALUE IF NOT EXISTS '{_ROLE}'"))


def _assert_no_auditor_memberships(bind: sa.engine.Connection) -> None:
    """Refuse the complete downgrade plan while a membership holds the role.

    One count over ``memberships``; ``env.py`` evaluates it over the whole
    resolved plan before its first step runs, so a row the previous release
    cannot represent stops the downgrade before a revision stacked above
    this one drops anything. ``downgrade()`` asks again before it rebuilds
    the type.
    """
    held = _auditor_membership_count(bind)
    if held:
        raise CommandError(
            f"{held} membership row(s) hold the '{_ROLE}' role, which the "
            "previous release cannot represent; move those members to another "
            "role (viewer holds strictly less authority) and run the downgrade again",
        )


# Read by migrations/env.py from every revision in the resolved downgrade
# plan, ahead of its first migration body.
DOWNGRADE_PREFLIGHT = _assert_no_auditor_memberships


def downgrade() -> None:
    bind = op.get_bind()
    _assert_no_auditor_memberships(bind)
    if bind.dialect.name != "postgresql":
        return
    # PostgreSQL cannot drop a label from an enum in place: rebuild the type
    # without it and move the one column that uses it. The column default is
    # dropped and re-set because it is typed on the enum being replaced.
    # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    bind.execute(sa.text("SELECT pg_advisory_xact_lock(:key)"), {"key": 0x7A_34_6A_DE})
    # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    bind.execute(sa.text(f"LOCK TABLE {_TABLE} IN ACCESS EXCLUSIVE MODE"))
    labels = ", ".join(f"'{label}'" for label in _PREVIOUS_LABELS)
    # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    op.execute(sa.text(f"ALTER TYPE {_TYPE} RENAME TO {_TYPE}_with_auditor"))
    # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    op.execute(sa.text(f"CREATE TYPE {_TYPE} AS ENUM ({labels})"))
    # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    op.execute(sa.text(f"ALTER TABLE {_TABLE} ALTER COLUMN {_COLUMN} DROP DEFAULT"))
    op.execute(
        # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
        sa.text(
            f"ALTER TABLE {_TABLE} ALTER COLUMN {_COLUMN} "
            f"TYPE {_TYPE} USING {_COLUMN}::text::{_TYPE}",
        ),
    )
    # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    op.execute(sa.text(f"ALTER TABLE {_TABLE} ALTER COLUMN {_COLUMN} SET DEFAULT 'viewer'"))
    # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    op.execute(sa.text(f"DROP TYPE {_TYPE}_with_auditor"))
