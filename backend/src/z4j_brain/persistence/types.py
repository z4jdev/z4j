"""Portable column-type adapters.

Production runs against Postgres 18+ with all the rich types
(``JSONB``, ``CITEXT``, ``ARRAY``, ``INET``, ``TSVECTOR``, ...). The
unit-test suite runs against an in-memory ``sqlite+aiosqlite`` engine
so contributors can run tests without a Postgres install.

Each adapter below is a SQLAlchemy ``TypeEngine`` instance that
SQLAlchemy will render as the rich type on Postgres and as a sane
fallback on SQLite. Models import these names instead of the raw
dialect-specific types - that's the only place SQLite/Postgres
differences live.

Tests against the SQLite fallback do NOT exercise full-text search,
JSON containment indexes, or true ``CITEXT`` case folding. Those
features are validated by the integration test suite (B7) against a
real Postgres 18 container.
"""

from __future__ import annotations

import json
import uuid as _uuid
from typing import Any

import structlog
from sqlalchemy import JSON, BigInteger, Text
from sqlalchemy.dialects.postgresql import ARRAY, CITEXT, INET, JSONB, TSVECTOR
from sqlalchemy.exc import DontWrapMixin
from sqlalchemy.types import TypeDecorator, TypeEngine, Uuid

logger = structlog.get_logger("z4j.brain.persistence")


class _SQLiteUuidArrayJSON(TypeDecorator):
    """JSON storage for ``list[UUID]`` columns on SQLite.

    SQLAlchemy's plain ``JSON`` type calls ``json.dumps`` on the bind
    value, which raises ``TypeError: Object of type UUID is not JSON
    serializable`` if the list contains :class:`uuid.UUID` instances
    (the natural shape after Pydantic-validated request bodies hit
    the persistence layer). This decorator converts UUIDs to their
    canonical string form at write time and back to UUID objects at
    read time, so callers can keep working with native UUIDs on both
    Postgres (real ``UUID[]``) and SQLite (JSON-of-strings).

    Postgres takes the unmodified ``ARRAY(Uuid)`` path; this
    decorator is only registered as the SQLite variant.
    """

    impl = JSON
    cache_ok = True

    def process_bind_param(
        self,
        value: Any,
        dialect: Any,
    ) -> list[str] | None:
        if value is None:
            return None
        out: list[str] = []
        for item in value:
            if isinstance(item, _uuid.UUID):
                out.append(str(item))
            else:
                # Defensive: tolerate already-string ids (some older
                # call sites pass strings) so a mixed list still
                # round-trips. Validate the shape so a typo'd field
                # name doesn't silently store garbage.
                out.append(str(item))
        return out

    def process_result_value(
        self,
        value: Any,
        dialect: Any,
    ) -> list[_uuid.UUID] | None:
        if value is None:
            return None
        out: list[_uuid.UUID] = []
        for item in value:
            if isinstance(item, _uuid.UUID):
                out.append(item)
            else:
                # Read back as UUID so callers see the same Python
                # type they would on the Postgres path.
                try:
                    out.append(_uuid.UUID(str(item)))
                except (ValueError, TypeError):
                    # A row written by a buggy older release that
                    # stored a non-UUID string. Skip it rather than
                    # crash the whole read - the dispatcher / API
                    # validators will silently drop unknown ids.
                    continue
        return out


#: Purpose strings for the two encrypted notification config columns. They
#: live here, not in ``domain.secret_fields``, because the models import this
#: module and the domain package imports the repositories, which import the
#: models; ``secret_fields`` re-exports them for the migration and the CLI.
NOTIFICATION_CHANNEL_CONFIG_PURPOSE = "notification_channels.config"
USER_CHANNEL_CONFIG_PURPOSE = "user_channels.config"


class EncryptedJSONWriteError(RuntimeError, DontWrapMixin):
    """A value could not be encrypted for an :class:`EncryptedJSON` column.

    Any other exception a bind processor raises is wrapped by SQLAlchemy in
    a ``StatementError`` whose text carries the bound parameters, which for
    this column are the plaintext config. ``DontWrapMixin`` makes SQLAlchemy
    raise this one as it is, and the message names the column's purpose and
    the failure, never the value.
    """


#: Purposes a plaintext read has already been logged for in this process.
#: One WARNING per purpose per process: the warning is a signal to run
#: ``z4j secrets rewrap``, and a table full of plaintext rows read on every
#: request must not turn it into a log flood.
_plaintext_read_warned: set[str] = set()


def reset_plaintext_read_warnings() -> None:
    """Forget which purposes have been warned about (tests)."""
    _plaintext_read_warned.clear()


def _warn_plaintext_read(purpose: str) -> None:
    if purpose in _plaintext_read_warned:
        return
    _plaintext_read_warned.add(purpose)
    logger.warning(
        "encrypted_column_plaintext_read",
        purpose=purpose,
        hint=(
            "a stored secret is not encrypted at rest (written by a downgraded "
            "brain or by hand); it was read as plaintext JSON. Run "
            "`z4j secrets rewrap` to encrypt every such row under the current "
            "Z4J_SECRET. Logged once per process per column."
        ),
    )


class EncryptedJSON(TypeDecorator[Any]):
    """A JSON value stored encrypted at rest, as text.

    The column holds one ``z4jenc1:<base64>`` token (see
    :mod:`z4j_brain.domain.secret_fields` for the format, the key
    derivation and the rotation story). Python code reads and writes the
    column as a plain dict or list exactly as it did when the column was
    JSONB; the API and the dashboard do not know the storage changed.

    What changes for the database: the column is ``TEXT`` on both
    dialects, so JSON path queries and containment indexes against it are
    not possible. Nothing in the brain queried channel configs that way
    (they are loaded by row and inspected in Python), which is why this
    column could move without touching a repository.

    ``purpose`` is the per-column domain-separation string. The same
    constant is used by the migration and the re-wrap command; a value
    encrypted for one purpose will not decrypt under another.

    Reads of a value without the prefix (a row written by a downgraded
    brain, or plaintext JSON text inserted by hand) are parsed as JSON
    rather than refused, and logged as a WARNING naming the purpose (once
    per process per purpose, never the value). That is the migration path:
    the next write of the row encrypts it, and ``z4j secrets rewrap``
    encrypts every such row in one run. Writes always encrypt.

    Where the keyring is needed: every write, and every read of a prefixed
    value; both fail closed with :class:`SecretKeyringUnbound` when none is
    bound. A read of a non-prefixed value does not touch the keyring, so it
    returns the plaintext with no keyring bound. A write that fails for any
    reason raises an exception whose text never carries the value:
    :class:`SecretKeyringUnbound` with the purpose prepended, or
    :class:`EncryptedJSONWriteError` when the value is not JSON.

    A value that decrypted only under a previous secret is returned as
    normal; the type cannot schedule a write, so the re-wrap is either the
    row's next ordinary write or ``z4j secrets rewrap``.
    """

    impl = Text
    cache_ok = True

    def __init__(self, purpose: str) -> None:
        if not purpose:
            raise ValueError("EncryptedJSON needs a non-empty purpose string")
        super().__init__()
        self.purpose = purpose

    def process_bind_param(self, value: Any, dialect: Any) -> str | None:
        if value is None:
            return None
        from z4j_brain.domain import secret_fields

        try:
            keyring = secret_fields.active_keyring()
        except secret_fields.SecretKeyringUnbound as exc:
            # Same class (it carries DontWrapMixin, so SQLAlchemy raises it
            # as is rather than inside a StatementError that would print the
            # bound parameters, i.e. the plaintext), with the column named.
            raise secret_fields.SecretKeyringUnbound(f"{self.purpose}: {exc}") from None
        try:
            return secret_fields.encrypt_json(value, keyring=keyring, purpose=self.purpose)
        except (TypeError, ValueError) as exc:
            # json.dumps names the offending type, never the value, so the
            # chained cause is safe to keep.
            raise EncryptedJSONWriteError(
                f"{self.purpose}: the value could not be serialised as JSON "
                f"({type(exc).__name__}); the value itself is not part of this message",
            ) from exc

    def compare_values(self, x: Any, y: Any) -> bool:
        # Never "unchanged": an assignment to the attribute always reaches
        # the database, even when the new dict equals the loaded one, so
        # ``channel.config = channel.config`` re-encrypts under the current
        # master (fresh nonce, current key). Rows that are merely loaded and
        # never assigned have no attribute history and are not written.
        return False

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        from z4j_brain.domain import secret_fields

        if secret_fields.is_encrypted(value):
            decrypted, _needs_rewrap = secret_fields.decrypt_json(
                value,
                keyring=secret_fields.active_keyring(),
                purpose=self.purpose,
            )
            return decrypted
        _warn_plaintext_read(self.purpose)
        if isinstance(value, str):
            return json.loads(value)
        # A dialect that already decoded JSON (a JSONB column read through
        # this type before the migration altered it to TEXT).
        return value


def jsonb() -> TypeEngine:
    """``JSONB`` on Postgres, ``JSON`` on SQLite.

    Use for any column that holds redacted task payloads, metadata,
    capabilities, etc. SQLite's ``JSON`` is a thin wrapper around
    ``TEXT`` that still supports the SQLAlchemy JSON accessor API.
    """
    return JSONB().with_variant(JSON(), "sqlite")


def citext() -> TypeEngine:
    """``CITEXT`` on Postgres, ``TEXT`` on SQLite.

    Used for ``users.email`` so case variants of the same address
    cannot create duplicate accounts. The SQLite fallback is plain
    ``TEXT`` and unit tests must lowercase emails before insert if
    they care about uniqueness.
    """
    return CITEXT().with_variant(Text(), "sqlite")


def text_array() -> TypeEngine:
    """``TEXT[]`` on Postgres, ``JSON`` on SQLite.

    SQLite has no array type. ``JSON`` lets us round-trip a Python
    list of strings via SQLAlchemy's JSON serialiser without losing
    structure for tests.
    """
    return ARRAY(Text()).with_variant(JSON(), "sqlite")


def uuid_array() -> TypeEngine:
    """``UUID[]`` on Postgres, ``JSON``-of-strings on SQLite.

    Used by user_subscriptions / project_default_subscriptions to
    reference channel ids without a separate join table. The arrays
    are NOT FK-constrained at the DB level (Postgres has no
    array-element FK); the dispatcher and the API validators
    enforce referential integrity instead.

    The SQLite variant uses :class:`_SQLiteUuidArrayJSON`, a
    TypeDecorator that converts UUIDs to strings on write and
    back to UUIDs on read. Without this conversion, SQLAlchemy's
    plain ``JSON`` type would raise
    ``TypeError: Object of type UUID is not JSON serializable``
    when the column is written with a ``list[UUID]`` value (the
    natural shape after Pydantic-validated request bodies reach
    the persistence layer). Bug present in v1.0.0..v1.0.16; fixed
    in v1.0.17. SQLite-only - the Postgres path is unaffected.
    """
    return ARRAY(Uuid(as_uuid=True)).with_variant(
        _SQLiteUuidArrayJSON(),
        "sqlite",
    )


def inet() -> TypeEngine:
    """``INET`` on Postgres, ``TEXT`` on SQLite.

    Used for ``audit_log.source_ip`` and ``commands.source_ip``.
    SQLite stores it as a plain string; Postgres validates the format.
    """
    return INET().with_variant(Text(), "sqlite")


def tsvector() -> TypeEngine:
    """``TSVECTOR`` on Postgres, ``TEXT`` on SQLite.

    The full-text search index is Postgres-only. The column exists on
    SQLite so the model + create_all() round-trip works in tests, but
    nothing populates it there.
    """
    return TSVECTOR().with_variant(Text(), "sqlite")


def big_integer() -> TypeEngine:
    """64-bit integer column type.

    Used for ``runtime_ms`` and ``schedules.total_runs``. SQLite
    handles 64-bit integers natively, so this is just a clear name.
    """
    return BigInteger()


__all__ = [
    "NOTIFICATION_CHANNEL_CONFIG_PURPOSE",
    "USER_CHANNEL_CONFIG_PURPOSE",
    "EncryptedJSON",
    "EncryptedJSONWriteError",
    "big_integer",
    "citext",
    "inet",
    "jsonb",
    "reset_plaintext_read_warnings",
    "text_array",
    "tsvector",
    "uuid_array",
]
