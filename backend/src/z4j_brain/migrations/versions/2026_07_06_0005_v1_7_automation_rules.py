"""z4j 1.7 add ``automation_rules`` table (the rule engine).

Revision ID: v1_7_automation_rules
Revises: v1_6_6_scrub_worker_conf
Create Date: 2026-07-06

Cluster R of the 1.7 release adds a cross-engine automation rule engine.
A rule watches a trigger, evaluates a fixed-grammar condition set against
the triggering event, and runs governed actions (notify / retry / cancel
/ revoke / purge / pause_schedule) subject to a per-rule circuit breaker.

Schema mirrors the ORM model in
``z4j_brain.persistence.models.automation_rule``: project-scoped, JSONB
condition/action config, circuit-breaker config + state columns,
created_by attribution, a per-project unique name, and a
``(project_id, trigger, is_enabled)`` lookup index.

DOWNGRADE COMPATIBILITY: ``downgrade()`` drops the table (and its
indexes). Rules configured during 1.7+ are lost on downgrade; there is
no way to preserve them on an older brain that has no rule engine, so
the loss is intentional and bounded by time spent on the older release.
Works on both Postgres and SQLite via a single-table
``Base.metadata.create_all`` subset.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models.automation_rule import AutomationRule

# ---------------------------------------------------------------------------
# Alembic revision identifiers
# ---------------------------------------------------------------------------

revision: str = "v1_7_automation_rules"
down_revision: str | Sequence[str] | None = "v1_6_6_scrub_worker_conf"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

compat = {
    "min_z4j_version": "1.7.0",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_6_6_scrub_worker_conf",
    "downgrade_to": "v1_6_6_scrub_worker_conf",
}


def upgrade() -> None:
    """Create the ``automation_rules`` table + its indexes.

    Idempotent: ``create_all`` with ``checkfirst`` (the default) skips
    the table if it already exists, so a re-run is a no-op.
    """
    bind = op.get_bind()
    Base.metadata.create_all(
        bind=bind,
        tables=[AutomationRule.__table__],
        checkfirst=True,
    )


def downgrade() -> None:
    """Drop the ``automation_rules`` table (indexes drop with it)."""
    bind = op.get_bind()
    AutomationRule.__table__.drop(bind=bind, checkfirst=True)
