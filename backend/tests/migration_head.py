"""The current Alembic head, derived rather than hardcoded.

Tests that assert "after upgrading, the database is at head" mean the head
this code declares, not one particular revision id. Writing the id as a
literal makes every one of them fail the next time somebody adds a
migration, which is noise that trains people to update assertions without
reading them.
"""

from __future__ import annotations

from functools import cache


@cache
def code_head() -> str:
    """Resolve the head revision from the shipped Alembic scripts."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    from z4j_brain.cli import _find_alembic_config_path

    config_path = _find_alembic_config_path()
    if config_path is None:  # pragma: no cover - packaging failure
        raise RuntimeError("alembic.ini not found; cannot resolve the head revision")
    head = ScriptDirectory.from_config(Config(str(config_path))).get_current_head()
    if head is None:  # pragma: no cover - empty version directory
        raise RuntimeError("alembic reports no head revision")
    return head


__all__ = ["code_head"]
