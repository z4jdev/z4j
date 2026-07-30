"""Alembic migration scripts.

Files in ``versions/`` are managed by ``z4j migrate``. Do not
edit them by hand after they ship - generate a new migration instead.
"""

from z4j_brain.settings import Settings

MIGRATION_SETTINGS_ATTRIBUTE = "z4j_migration_settings"


def settings_from_context() -> Settings:
    """Return the settings snapshot bound by this Alembic invocation."""

    from alembic import op
    from alembic.util import CommandError

    settings = op.get_context().config.attributes.get(
        MIGRATION_SETTINGS_ATTRIBUTE,
    )
    if not isinstance(settings, Settings):
        raise CommandError(
            "Alembic migration settings are not bound to a configuration snapshot",
        )
    return settings


__all__ = [
    "MIGRATION_SETTINGS_ATTRIBUTE",
    "settings_from_context",
]
