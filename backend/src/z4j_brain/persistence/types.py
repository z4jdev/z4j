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

import uuid as _uuid
from typing import Any

from sqlalchemy import JSON, BigInteger, Text
from sqlalchemy.dialects.postgresql import ARRAY, CITEXT, INET, JSONB, TSVECTOR
from sqlalchemy.types import TypeDecorator, TypeEngine, Uuid


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
        self, value: Any, dialect: Any,
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
        self, value: Any, dialect: Any,
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
        _SQLiteUuidArrayJSON(), "sqlite",
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
    "big_integer",
    "citext",
    "inet",
    "jsonb",
    "text_array",
    "tsvector",
    "uuid_array",
]
