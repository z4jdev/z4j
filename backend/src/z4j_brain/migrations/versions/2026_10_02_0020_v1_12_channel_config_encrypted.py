"""Encrypt notification channel configs at rest.

``notification_channels.config`` and ``user_channels.config`` carried
Slack webhook URLs, SMTP passwords, webhook HMAC secrets and PagerDuty
integration keys as plaintext JSONB. They now hold one ``z4jenc1:<base64>``
token per row (AES-256-GCM under a key derived from ``Z4J_SECRET``, see
``z4j_brain.domain.secret_fields``) in a ``TEXT`` column, the same
protection ``users.mfa_secret_encrypted`` already has.

Upgrade: on Postgres, ``ALTER COLUMN ... TYPE TEXT USING config::text`` when
the column is still ``jsonb``; on SQLite, a batch alter from ``JSON`` to
``TEXT`` when the declared type is not already ``TEXT`` (a database that
reached this revision through a fresh install already has ``TEXT``, because
the initial migration builds these two tables from the live models). Then
every row whose value does not start with ``z4jenc1:`` is encrypted in
place, in batches. Rows already carrying the prefix are left alone, so an
interrupted run resumes and a repeated run is a no-op.

Downgrade: the mirror image. Every row carrying the prefix is decrypted
back to plaintext JSON text; then the column returns to ``jsonb`` on
Postgres (``USING config::jsonb``) and ``JSON`` on SQLite. A row that no
listed secret can decrypt stops the downgrade before any column change, so
no data is turned into an unparseable ``jsonb`` cast. The same check is
declared as ``DOWNGRADE_PREFLIGHT``, which ``env.py`` evaluates over the
whole resolved downgrade plan before its first step, so a plan that crosses
this revision from above is refused before anything stacked above it is
dropped and committed.

Both directions need the master the application reads: ``Z4J_SECRET``,
with ``Z4J_PREVIOUS_SECRETS`` honoured on decrypt, taken from the Settings
snapshot Alembic bound for this invocation. Without that snapshot the
migration refuses with a readable message rather than guessing a key.

Revision ID: v1_12_channel_config_encrypted
Revises: v1_12_audit_forward_state
"""

from __future__ import annotations

import json
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from alembic.util import CommandError
from z4j_brain.domain.secret_fields import (
    ENCRYPTED_JSON_COLUMNS,
    ENCRYPTED_PREFIX,
    DecryptionFailed,
    SecretKeyring,
    bind_keyring,
    canonical_json,
    decrypt_json,
    encrypt_json,
    is_encrypted,
)
from z4j_brain.migrations import settings_from_context

revision: str = "v1_12_channel_config_encrypted"
down_revision: str | Sequence[str] | None = "v1_12_audit_forward_state"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMN = "config"
_BATCH = 500


def _keyring() -> SecretKeyring:
    try:
        settings = settings_from_context()
    except CommandError as exc:
        raise CommandError(
            "encrypting notification channel configs needs the master secret: "
            "run this migration through `z4j migrate` with Z4J_SECRET set the "
            "way the server reads it (environment or $Z4J_HOME/secret.env)",
        ) from exc
    keyring = SecretKeyring.from_settings(settings)
    # The models' EncryptedJSON type is not used below (raw SQL keeps this
    # file independent of how the models evolve), but a later migration in
    # the same invocation may load a channel row through the ORM.
    bind_keyring(keyring)
    return keyring


def _column_type(bind: sa.engine.Connection, table: str) -> str:
    """Lower-cased declared type of ``<table>.config`` on either dialect."""
    declared: object | None
    if bind.dialect.name == "postgresql":
        declared = bind.execute(
            # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
            sa.text(
                "SELECT data_type FROM information_schema.columns "
                "WHERE table_schema = current_schema() "
                "AND table_name = :table AND column_name = :column",
            ),
            {"table": table, "column": _COLUMN},
        ).scalar()
    else:
        declared = next(
            (
                r[2]
                for r in bind.exec_driver_sql(f"PRAGMA table_info('{table}')").all()
                if str(r[1]) == _COLUMN
            ),
            None,
        )
    if declared is None:
        raise CommandError(
            f"{table}.{_COLUMN} is missing; the schema is not at the expected revision",
        )
    return str(declared).lower()


def _alter_to_text(bind: sa.engine.Connection, table: str) -> None:
    current = _column_type(bind, table)
    if current == "text":
        return
    if bind.dialect.name == "postgresql":
        op.execute(
            # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
            sa.text(f"ALTER TABLE {table} ALTER COLUMN {_COLUMN} TYPE TEXT USING {_COLUMN}::text"),
        )
        return
    with op.batch_alter_table(table) as batch:
        batch.alter_column(
            _COLUMN,
            existing_type=sa.JSON(),
            type_=sa.Text(),
            existing_nullable=False,
        )


def _alter_to_json(bind: sa.engine.Connection, table: str) -> None:
    current = _column_type(bind, table)
    if current in {"jsonb", "json"}:
        return
    if bind.dialect.name == "postgresql":
        op.execute(
            # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
            sa.text(
                f"ALTER TABLE {table} ALTER COLUMN {_COLUMN} TYPE JSONB USING {_COLUMN}::jsonb"
            ),
        )
        return
    with op.batch_alter_table(table) as batch:
        batch.alter_column(
            _COLUMN,
            existing_type=sa.Text(),
            type_=sa.JSON(),
            existing_nullable=False,
        )


def _encrypt_rows(
    bind: sa.engine.Connection, table: str, purpose: str, keyring: SecretKeyring
) -> int:
    """Encrypt every plaintext row of ``table`` in place; return the count."""
    # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    select = sa.text(
        f"SELECT id, {_COLUMN} FROM {table} "  # noqa: S608  identifiers are module constants
        f"WHERE {_COLUMN} NOT LIKE :prefix ORDER BY id LIMIT :limit",
    )
    update = sa.text(f"UPDATE {table} SET {_COLUMN} = :value WHERE id = :id")  # noqa: S608 # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    done = 0
    while True:
        rows = bind.execute(select, {"prefix": ENCRYPTED_PREFIX + "%", "limit": _BATCH}).all()
        if not rows:
            return done
        params = []
        for row_id, stored in rows:
            value = stored
            if isinstance(stored, str | bytes):
                try:
                    value = json.loads(stored)
                except ValueError as exc:
                    raise CommandError(
                        f"{table}.{_COLUMN} for id {row_id} is neither encrypted nor "
                        "valid JSON; repair the row before upgrading",
                    ) from exc
            params.append(
                {"id": row_id, "value": encrypt_json(value, keyring=keyring, purpose=purpose)}
            )
        bind.execute(update, params)
        done += len(params)


def _decrypt_or_refuse(
    table: str, row_id: object, stored: str, purpose: str, keyring: SecretKeyring
) -> object:
    """Decrypt one stored row, or refuse the downgrade naming that row."""
    try:
        value, _ = decrypt_json(stored, keyring=keyring, purpose=purpose)
    except DecryptionFailed as exc:
        raise CommandError(
            f"{table}.{_COLUMN} for id {row_id} does not decrypt under Z4J_SECRET "
            "or any Z4J_PREVIOUS_SECRETS entry; put the secret it was written "
            "under back before downgrading",
        ) from exc
    return value


def _decrypt_rows(
    bind: sa.engine.Connection, table: str, purpose: str, keyring: SecretKeyring
) -> int:
    """Decrypt every encrypted row of ``table`` back to JSON text."""
    # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    select = sa.text(
        f"SELECT id, {_COLUMN} FROM {table} "  # noqa: S608  identifiers are module constants
        f"WHERE {_COLUMN} LIKE :prefix ORDER BY id LIMIT :limit",
    )
    update = sa.text(f"UPDATE {table} SET {_COLUMN} = :value WHERE id = :id")  # noqa: S608 # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    done = 0
    while True:
        rows = bind.execute(select, {"prefix": ENCRYPTED_PREFIX + "%", "limit": _BATCH}).all()
        if not rows:
            return done
        params = []
        for row_id, stored in rows:
            if not is_encrypted(stored):  # pragma: no cover - LIKE already filtered
                continue
            value = _decrypt_or_refuse(table, row_id, stored, purpose, keyring)
            params.append({"id": row_id, "value": canonical_json(value).decode("utf-8")})
        if params:
            bind.execute(update, params)
        done += len(params)


def _assert_rows_decrypt(
    bind: sa.engine.Connection, table: str, purpose: str, keyring: SecretKeyring
) -> int:
    """Read every encrypted row of ``table`` under the keyring; return the count.

    The same rows, the same keyring and the same refusal as
    :func:`_decrypt_rows`, without the UPDATE. Nothing here moves a row out
    of the ``LIKE`` predicate between pages, so the pages are keyed on ``id``
    (the primary key, one index range per page on either engine) rather than
    re-read from the top.
    """
    # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    first_page = sa.text(
        f"SELECT id, {_COLUMN} FROM {table} "  # noqa: S608  identifiers are module constants
        f"WHERE {_COLUMN} LIKE :prefix ORDER BY id LIMIT :limit",
    )
    # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    next_page = sa.text(
        f"SELECT id, {_COLUMN} FROM {table} "  # noqa: S608  identifiers are module constants
        f"WHERE {_COLUMN} LIKE :prefix AND id > :after ORDER BY id LIMIT :limit",
    )
    checked = 0
    after: object | None = None
    while True:
        params: dict[str, object] = {"prefix": ENCRYPTED_PREFIX + "%", "limit": _BATCH}
        if after is None:
            rows = bind.execute(first_page, params).all()
        else:
            rows = bind.execute(next_page, {**params, "after": after}).all()
        if not rows:
            return checked
        for row_id, stored in rows:
            if not is_encrypted(stored):  # pragma: no cover - LIKE already filtered
                continue
            _decrypt_or_refuse(table, row_id, stored, purpose, keyring)
            checked += 1
        after = rows[-1][0]


def _assert_downgrade_rows_decrypt(bind: sa.engine.Connection) -> None:
    """Refuse the complete downgrade plan while any channel config cannot be read.

    ``env.py`` evaluates this over the whole resolved plan before its first
    step runs, so a row written under a secret that is no longer listed stops
    the downgrade before a revision stacked above this one drops anything.
    ``downgrade()`` then decrypts under the same keyring and refuses the same
    way, row by row, before any column changes type.
    """
    keyring = _keyring()
    for table, purpose in ENCRYPTED_JSON_COLUMNS:
        _assert_rows_decrypt(bind, table, purpose, keyring)


# Read by migrations/env.py from every revision in the resolved downgrade
# plan, ahead of its first migration body.
DOWNGRADE_PREFLIGHT = _assert_downgrade_rows_decrypt


def upgrade() -> None:
    bind = op.get_bind()
    keyring = _keyring()
    for table, purpose in ENCRYPTED_JSON_COLUMNS:
        _alter_to_text(bind, table)
        _encrypt_rows(bind, table, purpose, keyring)


def downgrade() -> None:
    bind = op.get_bind()
    keyring = _keyring()
    for table, purpose in ENCRYPTED_JSON_COLUMNS:
        # Every row must decrypt before any column changes type, so a
        # failure leaves the schema exactly as it was.
        _decrypt_rows(bind, table, purpose, keyring)
    for table, _purpose in ENCRYPTED_JSON_COLUMNS:
        _alter_to_json(bind, table)
