"""z4j 1.6.6 R7-H1: scrub credentialed Celery conf from workers.metadata.

Revision ID: v1_6_6_scrub_worker_conf
Revises: v1_6_mfa_totp
Create Date: 2026-06-07

Round-7 audit finding R7-H1 (HIGH, information disclosure)
----------------------------------------------------------

Before 1.6.6, ``z4j-celery``'s ``CeleryEngineAdapter.get_worker_details``
called Celery's ``inspector.conf()`` and shipped the WHOLE worker conf
dict to the brain on every heartbeat. The brain persisted the dict
verbatim into ``workers.metadata.conf`` (JSONB on Postgres, JSON on
SQLite). The ``GET /api/v1/projects/{slug}/workers/{worker_id}``
endpoint exposes ``worker_metadata`` to ``ProjectRole.VIEWER`` (the
lowest project role), so every viewer-role member could read
credentialed Celery configuration: ``broker_url``
(``redis://:password@...`` / ``amqp://user:pw@...`` / SQS access keys),
``result_backend`` (``db+postgresql://user:pw@...``),
``broker_transport_options`` (TLS keys, IAM creds), and
``beat_schedule`` (PII / tokens embedded in schedule kwargs).

The three-layer fix landed in 1.6.6 source code:

1. ``z4j-celery`` adapter allowlist-filters at the source before
   shipping to the brain (``_redact_worker_conf`` /
   ``_CONF_ALLOWLIST``).
2. The brain re-applies the SAME allowlist defense-in-depth in
   ``z4j_brain.websocket.frame_router`` before writing the JSONB
   column (``_filter_worker_conf`` / ``_WORKER_CONF_ALLOWLIST``).
3. This migration: scrub the JSONB column for ANY worker row that
   was written by a pre-1.6.6 brain so the credentialed keys do not
   linger in the operator DB until the row is next overwritten by
   a heartbeat.

Why scrub the whole ``conf`` sub-object rather than per-key filter?

* Per-key SQL filtering across both dialects is fragile and slow;
  the next heartbeat from a 1.6.6 agent will repopulate the
  allowlisted keys within ~10 seconds anyway.
* Operators who downgrade to a pre-1.6.6 brain after running 1.6.6
  see allowlisted-only data, not credentials. That is the
  conservative direction.

Downgrade is a no-op: we cannot restore the original conf bytes
(they are gone from the DB and live only in the running Celery
processes), and operators do not want credentialed data restored
even if we could.

Cross-dialect
-------------

Postgres uses ``jsonb_set`` against the ``jsonb`` column; SQLite
uses ``json_set`` against the ``json`` column. Dispatch is on
``op.get_bind().dialect.name``. Other dialects fall through to the
generic ORM-level scrub, which is portable but slower; in practice
1.4+ only supports Postgres / SQLite.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
from sqlalchemy import text


# ---------------------------------------------------------------------------
# Alembic revision identifiers
# ---------------------------------------------------------------------------

revision: str = "v1_6_6_scrub_worker_conf"
down_revision: str | Sequence[str] | None = "v1_6_mfa_totp"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


compat = {
    "min_z4j_version": "1.6.6",
    "max_z4j_version": "1.99.99",
    "upgrade_from": "v1_6_mfa_totp",
    "downgrade_to": "v1_6_mfa_totp",
}


def upgrade() -> None:
    """Scrub credentialed Celery conf from existing worker rows.

    Idempotent: re-running the migration finds no rows with a
    non-empty ``conf`` sub-object and is a no-op.
    """
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        # ``metadata ? 'conf'`` matches rows where the JSONB document
        # has a top-level ``conf`` key. ``jsonb_set(..., '{conf}',
        # '{}'::jsonb)`` replaces just that sub-object, leaving every
        # other top-level key (stats / active / active_queues /
        # registered) untouched.
        op.execute(
            text(
                "UPDATE workers "
                "SET metadata = jsonb_set(metadata, '{conf}', '{}'::jsonb) "
                "WHERE metadata ? 'conf'",
            ),
        )
    elif dialect == "sqlite":
        # SQLite's JSON1 functions use ``$.conf`` JSONPath syntax.
        # ``json_extract`` returns NULL if the key is absent, so the
        # WHERE clause skips already-clean rows.
        op.execute(
            text(
                "UPDATE workers "
                "SET metadata = json_set(metadata, '$.conf', json('{}')) "
                "WHERE json_extract(metadata, '$.conf') IS NOT NULL",
            ),
        )
    else:  # pragma: no cover - 1.4 floor only supports pg + sqlite
        # Generic fallback: pull every row, scrub in Python, write
        # back. Slow but portable. Other dialects are out of scope
        # for the v1.4 compat floor but the fallback keeps the
        # migration safe to run anywhere.
        import json as _json
        rows = bind.execute(
            text("SELECT id, metadata FROM workers"),
        ).fetchall()
        for row in rows:
            md = row.metadata
            if isinstance(md, str):
                try:
                    md = _json.loads(md)
                except (ValueError, TypeError):
                    continue
            if not isinstance(md, dict) or "conf" not in md:
                continue
            md["conf"] = {}
            bind.execute(
                text("UPDATE workers SET metadata = :md WHERE id = :id"),
                {"md": _json.dumps(md), "id": row.id},
            )


def downgrade() -> None:
    """No-op: we cannot resurrect scrubbed credentials, and operators
    would not want them resurrected even if we could."""
    return None
