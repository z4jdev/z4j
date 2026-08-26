"""In-memory SQLite must get a StaticPool, or every connection is a new database.

The predicate matched text on the URL and so missed the bare form,
``sqlite+aiosqlite://`` with no path, which SQLAlchemy also treats as
in-memory. That deployment got a sized pool over an in-memory database: each
connection opened its own empty one, so tables created during migration were
invisible to the next request. Easy to configure by accident and baffling to
diagnose.

Parametrized over every shape rather than the one that was broken, because the
first fix broke the shared-cache form while fixing the bare one. ``mode=memory``
is a query parameter and SQLAlchemy splits it off the path, so looking for it in
``database`` alone finds nothing.
"""

from __future__ import annotations

import pytest
from sqlalchemy.engine.url import make_url
from z4j_brain.persistence.database import _uses_static_pool


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("sqlite+aiosqlite:///:memory:", True),
        ("sqlite:///:memory:", True),
        # No path at all. SQLAlchemy opens an anonymous in-memory database.
        ("sqlite+aiosqlite://", True),
        ("sqlite://", True),
        # Shared-cache memory: one database, reached through a URI parameter.
        ("sqlite+aiosqlite:///file:z4j?mode=memory&cache=shared", True),
        # Real files, on both path styles.
        ("sqlite+aiosqlite:///./z4j.db", False),
        ("sqlite+aiosqlite:////var/lib/z4j/z4j.db", False),
        ("sqlite+aiosqlite:///C:/data/z4j.db", False),
        ("postgresql+asyncpg://user:pw@host/db", False),
    ],
)
def test_every_url_shape_is_classified_correctly(url: str, expected: bool) -> None:
    assert _uses_static_pool(url) is expected


def test_the_bare_form_really_is_in_memory() -> None:
    """The premise, from SQLAlchemy rather than from this file's belief.

    If a future SQLAlchemy stopped treating a pathless URL as in-memory, the
    predicate above would be wrong in the other direction and this says so.
    """
    assert make_url("sqlite+aiosqlite://").database is None
    assert make_url("sqlite+aiosqlite:///./z4j.db").database == "./z4j.db"


def test_an_unparseable_url_does_not_raise() -> None:
    """This runs during engine construction; raising here hides the real error."""
    assert _uses_static_pool("sqlite+aiosqlite://:::bad") in (True, False)
