"""Reusable model mixins.

Two patterns:

- :class:`PKMixin` adds a ``id UUID PRIMARY KEY DEFAULT gen_random_uuid()``
  column. Every model except :class:`Event` (which uses a composite
  PK keyed on the partition column) inherits from it.
- :class:`TimestampsMixin` adds ``created_at`` and ``updated_at``
  ``TIMESTAMPTZ NOT NULL DEFAULT NOW()`` columns. ``updated_at`` is
  bumped automatically by SQLAlchemy on every flush.

The mixins live separately so they can be applied independently -
e.g. :class:`Membership` has timestamps but uses a composite key,
and :class:`AuditLog` has its own ``occurred_at`` instead of the
generic timestamps.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid


class PKMixin:
    """``id UUID PRIMARY KEY`` with a Python-side default of ``uuid4``.

    The Python default is what tests use against SQLite; on Postgres
    we still get the same UUIDs because SQLAlchemy generates them
    before the INSERT. The migration also installs a server-side
    ``gen_random_uuid()`` default for callers that bypass SQLAlchemy.
    """

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )


class TimestampsMixin:
    """``created_at`` / ``updated_at`` ``TIMESTAMPTZ`` columns.

    Both default to ``NOW()`` server-side. ``updated_at`` is also
    bumped on every UPDATE via SQLAlchemy's ``onupdate`` so callers
    do not have to remember to set it. Tests run against SQLite,
    where ``func.now()`` returns local time - that's fine for
    round-trip checks.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


__all__ = ["PKMixin", "TimestampsMixin"]
