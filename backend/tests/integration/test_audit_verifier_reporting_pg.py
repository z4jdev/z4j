"""Boundary-F verification reporting against real PostgreSQL semantics.

The SQLite cases live in ``tests/unit/test_audit_verifier_reporting.py``. This
one exists because the marker CHECK constraint is what admits the malformed
row, and a constraint is only as good as the engine enforcing it: PostgreSQL
guards ``audit_log`` against UPDATE and DELETE but leaves INSERT to the CHECK
alone, so here the row arrives through the front door.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from z4j_brain.domain.audit_verifier import (
    AuditVerificationReport,
    verify_active_audit_generation,
)
from z4j_brain.persistence.models import AuditChainState, AuditLog
from z4j_brain.settings import Settings

pytestmark = pytest.mark.asyncio

#: Sixty-four valid hexadecimal characters that are not the canonical form,
#: which is lowercase. The marker CHECK requires this column to be NOT NULL for
#: a verified frozen row and says nothing else about it.
_NONCANONICAL_KEY_ID = "A" * 64


async def _insert_frozen_row(
    engine: AsyncEngine,
    *,
    hmac_key_id: str,
    legacy_integrity_class: str = "legacy-linked-verified",
) -> uuid.UUID:
    """Insert one frozen row past nothing but the marker CHECK.

    ``audit_log`` carries UPDATE and DELETE triggers on PostgreSQL and no
    INSERT trigger, so this is the constraint deciding on its own whether the
    row is admissible, which is the question the verifier inherits.
    """

    row_id = uuid.uuid4()
    async with engine.begin() as connection:
        await connection.execute(
            AuditLog.__table__.insert().values(
                id=row_id,
                action="legacy.frozen",
                target_type="test",
                target_id=str(row_id),
                result="success",
                outcome="allow",
                metadata={"legacy": True},
                occurred_at=datetime(2026, 7, 1, 12, 0, tzinfo=UTC),
                event_id=None,
                project_id=None,
                user_id=None,
                api_key_id=None,
                source_ip=None,
                user_agent=None,
                legacy_frozen=True,
                hmac_version=1,
                hmac_key_id=hmac_key_id,
                row_hmac="b" * 64,
                prev_row_hmac=None,
                chain_generation=None,
                legacy_integrity_class=legacy_integrity_class,
                legacy_origin="audit-log:preparation-v1",
            ),
        )
    return row_id


async def _verify(
    engine: AsyncEngine,
    settings: Settings,
) -> AuditVerificationReport:
    async with AsyncSession(engine, expire_on_commit=False) as session:
        return await verify_active_audit_generation(session, settings, page_size=100)


async def test_a_noncanonical_frozen_row_is_reported_not_raised(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    """The malformed row is admissible to the table and must be a finding.

    Raising here discarded the report the walk had already built, so the
    scheduled verifier filed a corrupted chain as a run to retry. Startup still
    refused to serve either way, which is exactly what made this hard to see:
    the only surface that showed the difference was the one an operator watches
    between restarts.
    """

    assert (await _verify(migrated_engine, integration_settings)).clean

    # Negative control: the CHECK is live and rejects a class outside the
    # closed set, so the insert that follows is one it deliberately admitted.
    with pytest.raises(IntegrityError):
        await _insert_frozen_row(
            migrated_engine,
            hmac_key_id=_NONCANONICAL_KEY_ID,
            legacy_integrity_class="legacy-fabricated",
        )

    row_id = await _insert_frozen_row(migrated_engine, hmac_key_id=_NONCANONICAL_KEY_ID)

    report = await _verify(migrated_engine, integration_settings)

    assert not report.clean
    assert any(str(row_id) in line and "not canonical" in line for line in report.mismatches), (
        report.mismatches
    )
    assert any("unprovable" in line for line in report.mismatches), report.mismatches
    # Counted by the row census, credited to nothing: it was compared against
    # no authenticated digest at all.
    assert report.verified_frozen_rows == 0
    assert report.mismatch_count == len(report.mismatches)


async def test_the_authenticated_state_is_untouched_by_the_finding(
    migrated_engine: AsyncEngine,
    integration_settings: Settings,
) -> None:
    """Reporting damage must not become a second way of writing to the chain."""

    async with AsyncSession(migrated_engine, expire_on_commit=False) as session:
        before = (await session.execute(select(AuditChainState))).scalar_one()
        before_mac = before.state_mac
        before_frozen = before.frozen_row_count

    await _insert_frozen_row(migrated_engine, hmac_key_id=_NONCANONICAL_KEY_ID)
    assert not (await _verify(migrated_engine, integration_settings)).clean

    async with AsyncSession(migrated_engine, expire_on_commit=False) as session:
        after = (await session.execute(select(AuditChainState))).scalar_one()
        assert after.state_mac == before_mac
        assert after.frozen_row_count == before_frozen
        assert (
            await session.execute(
                text("SELECT COUNT(*) FROM audit_log WHERE legacy_frozen = true"),
            )
        ).scalar_one() == 1
