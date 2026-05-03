"""Schema version tracking and startup compatibility check.

After Alembic migrations run and before the app starts serving,
this module:

1. Reads the ``schema_version`` from the ``z4j_meta`` table
2. Compares it to the current code version
3. If the DB schema is NEWER than the code -> log a warning and
   continue (v1.0.19 changed this from a hard error - see
   docs/MIGRATIONS.md for the bidirectional-compat contract).
4. If the DB schema is OLDER or equal -> update the record and proceed

v1.0.0..v1.0.18 raised :class:`SchemaVersionError` here, which
caused systemd flap loops on any operator who downgraded across
a migration boundary. From v1.0.19 onward, every additive
migration is designed so older code can ignore it - newer
features simply aren't available, but the brain stays up. The
contract is documented in docs/MIGRATIONS.md and enforced by
tests/integration/test_compat_matrix.py.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from z4j_brain import __version__
from z4j_brain.persistence.models.meta import Z4JMeta

logger = logging.getLogger("z4j.brain.startup_version")


class SchemaVersionError(RuntimeError):
    """Kept for backwards-compatible imports (v1.0.0..v1.0.18 raised
    this from :func:`check_and_update_schema_version`).

    From v1.0.19 onward, the schema-version check logs a warning
    instead of raising, see the module docstring for the
    bidirectional-compat contract. This class is retained so any
    downstream code that catches the exception name doesn't break,
    but the brain itself never raises it anymore.
    """


def _parse_calver(version: str) -> tuple[int, int, int]:
    """Parse CalVer 'YYYY.M.PATCH' or 'YYYY.M.PATCHaN' into a comparable tuple."""
    # Strip pre-release suffix (a1, b1, rc1)
    clean = version.split("a")[0].split("b")[0].split("rc")[0]
    parts = clean.split(".")
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]) if len(parts) > 2 else 0)
    except (ValueError, IndexError):
        return (0, 0, 0)


async def check_and_update_schema_version(session: AsyncSession) -> None:
    """Check schema compatibility and update the version record.

    Called during app startup, after migrations have been applied.

    From v1.0.19 onward this method NEVER raises. If the DB schema
    is newer than the code, it logs a warning and continues - the
    brain serves whatever subset of functionality the running
    code understands, and any newer features (added by future
    migrations) are simply unavailable until the operator
    upgrades. See docs/MIGRATIONS.md for the full contract.
    """
    code_version = __version__
    code_tuple = _parse_calver(code_version)

    # Read the stored schema version.
    result = await session.execute(
        select(Z4JMeta).where(Z4JMeta.key == "schema_version"),
    )
    meta = result.scalar_one_or_none()

    if meta is None:
        # First run - no schema version stored yet. Create it.
        session.add(Z4JMeta(key="schema_version", value=code_version))
        session.add(Z4JMeta(key="installed_at", value=datetime.now(UTC).isoformat()))
        session.add(Z4JMeta(key="last_upgraded_at", value=datetime.now(UTC).isoformat()))
        await session.commit()
        logger.info(
            "z4j schema version initialized (version=%s)",
            code_version,
        )
        return

    db_version = meta.value
    db_tuple = _parse_calver(db_version)

    if db_tuple > code_tuple:
        # v1.0.19 change: don't refuse to start. Migrations from
        # v1.0.19 onward are guaranteed additive (new columns are
        # nullable or have server_defaults; new tables are
        # tolerated by old code's queries via the ``_has_table``
        # pattern in workers/repos). Old code can serve whatever
        # subset it understands; newer features simply aren't
        # available. Pre-1.0.19 versions raised SchemaVersionError
        # here, which caused systemd flap loops on any operator
        # who downgraded across a migration boundary - see
        # docs/MIGRATIONS.md for the full migration discipline.
        logger.warning(
            "z4j schema version skew: DB was last migrated by "
            "z4j %s but running code is %s. The brain will "
            "serve the subset of features this code version "
            "understands; newer features are unavailable until you "
            "upgrade. To use everything in the DB, install "
            "z4j-brain>=%s.",
            db_version, code_version, db_version,
        )
        # Don't update last_upgraded_at on a downgrade-skew boot;
        # leave the higher-version mark intact so future upgrade
        # paths can read accurate timestamps.
        return

    if db_tuple < code_tuple:
        # Upgrading - update the stored version.
        meta.value = code_version
        # Update last_upgraded_at.
        result = await session.execute(
            select(Z4JMeta).where(Z4JMeta.key == "last_upgraded_at"),
        )
        upgraded_meta = result.scalar_one_or_none()
        if upgraded_meta:
            upgraded_meta.value = datetime.now(UTC).isoformat()
        else:
            session.add(Z4JMeta(key="last_upgraded_at", value=datetime.now(UTC).isoformat()))
        await session.commit()
        logger.info(
            "z4j schema version upgraded (from=%s to=%s)",
            db_version,
            code_version,
        )
    else:
        # Same version - nothing to do.
        logger.debug(
            "z4j schema version matches code (version=%s)",
            db_version,
        )


__all__ = ["SchemaVersionError", "check_and_update_schema_version"]
