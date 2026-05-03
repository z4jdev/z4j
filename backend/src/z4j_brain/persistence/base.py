"""SQLAlchemy declarative base for the brain.

A single :class:`DeclarativeBase` shared by every ORM model so the
same metadata can be passed to alembic for autogenerate. The naming
convention is fixed so migrations are deterministic across machines
- without this, every developer ends up with differently-named
indexes and unique constraints in their generated migrations.
"""

from __future__ import annotations

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

#: Stable naming convention for indexes, FKs, uniques, and PKs.
#: alembic uses this to render predictable migration names. Changing
#: it after the first migration ships is a hard break - it would
#: silently rename every constraint in the database.
naming_convention: dict[str, str] = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Common base class for every brain ORM model.

    Models are added in B2; in B1 we only need ``Base.metadata`` to
    exist so alembic env.py can target it.
    """

    metadata = MetaData(naming_convention=naming_convention)


__all__ = ["Base", "naming_convention"]
