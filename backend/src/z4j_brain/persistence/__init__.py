"""Persistence layer.

The brain talks to PostgreSQL via SQLAlchemy 2.0 async + asyncpg.
This package contains the engine + session factory and a shared
``DeclarativeBase``. ORM models live in submodules added in B2.

Repositories (``repositories/``) are the only callers of the ORM
from inside the application - domain services depend on repository
interfaces, never on SQLAlchemy directly.
"""

from __future__ import annotations

from z4j_brain.persistence.base import Base, naming_convention
from z4j_brain.persistence.database import (
    DatabaseManager,
    create_engine_from_settings,
    get_session,
)

__all__ = [
    "Base",
    "DatabaseManager",
    "create_engine_from_settings",
    "get_session",
    "naming_convention",
]
