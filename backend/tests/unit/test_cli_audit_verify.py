"""``z4j audit verify`` CLI: exit codes, break reporting, paging.

Drives the real console-script entrypoint (``main(["audit",
"verify", ...])`` -> ``_run_audit_verify``) against a file-backed
SQLite database seeded through the real ``AuditService``, so the
HMAC chain under test is genuine:

- clean chain -> exit 0
- tampered row -> exit 1 + the row id in the MISMATCHES report
- deleted middle row -> exit 1 + chain break reported on the NEXT row
- truncated prefix -> exit 1 + genesis-anchor violation reported
- empty log -> exit 0, ``verified: 0``
- ``--limit`` outside 1..5000 -> exit 2

The paging tests exercise the keyset-cursor loop with a page size
smaller than the row count so the walk spans multiple pages. The
page size is the CLI's own ``--limit`` parameter (default 1000, max
5000; it only controls rows-per-query, never rows-verified), so
shrinking it drives the EXACT loop the default runs without seeding
1000+ rows. The regression pinned here: a tamper BEYOND the first
page must be detected (the pre-fix verifier loaded a single slice
and silently skipped every row past the cap).
"""

from __future__ import annotations

import asyncio
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.persistence import models  # noqa: F401  registers metadata
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import AuditLog
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.settings import Settings


@pytest.fixture
def cli_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Settings:
    """Wire a file-backed SQLite DB + secrets into the process env.

    ``_run_audit_verify`` constructs its own ``Settings()`` from the
    environment, so the CLI under test and the seeding helper must
    agree on both the database file and the HMAC signing secret
    (in-memory SQLite would give the CLI's fresh engine an empty,
    unrelated database).
    """
    db_url = f"sqlite+aiosqlite:///{(tmp_path / 'audit.db').as_posix()}"
    secret = secrets.token_urlsafe(48)
    session_secret = secrets.token_urlsafe(48)
    monkeypatch.setenv("Z4J_DATABASE_URL", db_url)
    monkeypatch.setenv("Z4J_SECRET", secret)
    monkeypatch.setenv("Z4J_SESSION_SECRET", session_secret)
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    # A developer's rotation-window var would add extra verify
    # secrets; drop it so the test is hermetic.
    monkeypatch.delenv("Z4J_SECRETS_PREVIOUS", raising=False)
    # _bootstrap_env_for_management_commands would setdefault this
    # OUTSIDE monkeypatch's restore list; set it here so the value
    # is restored after the test.
    monkeypatch.setenv("Z4J_ALLOWED_HOSTS", '["localhost","127.0.0.1"]')
    return Settings(
        database_url=db_url,
        secret=secret,  # type: ignore[arg-type]
        session_secret=session_secret,  # type: ignore[arg-type]
        environment="dev",
    )


async def _seed_chain(settings: Settings, n: int) -> list[uuid.UUID]:
    """Create the schema and write ``n`` chained audit rows.

    Mirrors ``AuditService.record`` step for step (mint id -> chain
    lock -> read chain head -> HMAC -> insert -> commit) with ONE
    deviation: ``occurred_at`` is stamped as a NAIVE UTC datetime,
    which is exactly what SQLite hands back on every later read (the
    dialect's storage format drops the UTC offset). Seeding through
    ``record()`` itself signs an AWARE timestamp whose canonical form
    no longer matches after that naive round-trip on hosts whose
    local timezone is not UTC -- a production-side verify_row issue
    reported separately. These tests pin the CLI's exit codes, break
    reporting, and paging, so the fixture writes rows whose canonical
    form is stable on any host timezone.

    ``occurred_at`` advances 1ms per row so the chain-order walk
    ``(occurred_at, id)`` matches insert order deterministically.
    Returns the row ids in chain order.
    """
    from z4j_brain.domain.audit_service import AuditEntry

    engine = create_async_engine(settings.database_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory = sessionmaker(  # type: ignore[call-overload]
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        audit = AuditService(settings)
        base = datetime.now(UTC).replace(tzinfo=None)
        ids: list[uuid.UUID] = []
        async with factory() as session:
            repo = AuditLogRepository(session)
            for i in range(n):
                row_id = uuid.uuid4()
                await repo.acquire_chain_lock()  # no-op on SQLite
                prev_row_hmac = await repo.get_latest_row_hmac()
                entry = AuditEntry(
                    id=row_id,
                    action="test.event",
                    target_type="thing",
                    target_id=str(i),
                    result="success",
                    outcome="allow",
                    event_id=None,
                    user_id=None,
                    project_id=None,
                    source_ip=None,
                    user_agent=None,
                    metadata={},
                    occurred_at=base + timedelta(milliseconds=i),
                    prev_row_hmac=prev_row_hmac,
                )
                # The service's own canonicaliser + signer, so the
                # chain is genuine (same code path verify_row runs).
                row_hmac = audit._compute_hmac(entry)
                await repo.insert(
                    id=row_id,
                    action=entry.action,
                    target_type=entry.target_type,
                    target_id=entry.target_id,
                    result=entry.result,
                    outcome=entry.outcome,
                    event_id=entry.event_id,
                    user_id=entry.user_id,
                    project_id=entry.project_id,
                    source_ip=entry.source_ip,
                    user_agent=entry.user_agent,
                    metadata=entry.metadata,
                    row_hmac=row_hmac,
                    prev_row_hmac=prev_row_hmac,
                    occurred_at=entry.occurred_at,
                )
                # Commit per row so each iteration reads a settled
                # chain head (deterministic linkage, no fork).
                await session.commit()
                ids.append(row_id)
        return ids
    finally:
        await engine.dispose()


async def _tamper_row(settings: Settings, row_id: uuid.UUID) -> None:
    """Flip a signed field WITHOUT re-signing: verify_row must fail."""
    engine = create_async_engine(settings.database_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                update(AuditLog).where(AuditLog.id == row_id).values(action="tampered.event"),
            )
    finally:
        await engine.dispose()


async def _delete_row(settings: Settings, row_id: uuid.UUID) -> None:
    """Drop a row so the successor's prev_row_hmac anchor dangles."""
    engine = create_async_engine(settings.database_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.execute(delete(AuditLog).where(AuditLog.id == row_id))
    finally:
        await engine.dispose()


def _run_verify(*extra: str) -> int:
    """Invoke the real console-script path: ``z4j audit verify``."""
    from z4j_brain.cli import main

    return main(["audit", "verify", *extra])


class TestAuditVerifyCLI:
    def test_clean_chain_exits_zero(
        self,
        cli_settings: Settings,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        asyncio.run(_seed_chain(cli_settings, 8))
        rc = _run_verify()
        out = capsys.readouterr().out
        assert rc == 0
        assert "verified: 8" in out
        assert "MISMATCHES" not in out

    def test_empty_log_exits_zero(
        self,
        cli_settings: Settings,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Empty log is a clean verification: nothing to mismatch."""
        asyncio.run(_seed_chain(cli_settings, 0))
        rc = _run_verify()
        out = capsys.readouterr().out
        assert rc == 0
        assert "verified: 0" in out
        assert "MISMATCHES" not in out

    def test_tampered_row_exits_one_and_names_the_row(
        self,
        cli_settings: Settings,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A field edit without re-signing is reported by row id.

        The tampered row's stored row_hmac is unchanged, so the
        successor's prev_row_hmac anchor still matches: exactly one
        mismatch, no spurious chain-break cascade.
        """
        ids = asyncio.run(_seed_chain(cli_settings, 6))
        asyncio.run(_tamper_row(cli_settings, ids[2]))
        rc = _run_verify()
        out = capsys.readouterr().out
        assert rc == 1
        assert "MISMATCHES (1)" in out
        assert str(ids[2]) in out
        assert "verified: 5" in out

    def test_deleted_middle_row_reports_chain_break(
        self,
        cli_settings: Settings,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Deleting a row breaks the NEXT row's prev_row_hmac anchor."""
        ids = asyncio.run(_seed_chain(cli_settings, 6))
        asyncio.run(_delete_row(cli_settings, ids[2]))
        rc = _run_verify()
        out = capsys.readouterr().out
        assert rc == 1
        assert "chain break" in out
        # The break is reported at the successor of the deleted row.
        assert str(ids[3]) in out

    def test_truncated_prefix_reports_missing_genesis_anchor(
        self,
        cli_settings: Settings,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Deleting the genesis row must NOT let the chain re-anchor.

        The first streamed row now has a non-null prev_row_hmac, which
        the verifier flags as chain truncation. (1.6.0 round-3 High-1.)
        """
        ids = asyncio.run(_seed_chain(cli_settings, 4))
        asyncio.run(_delete_row(cli_settings, ids[0]))
        rc = _run_verify()
        out = capsys.readouterr().out
        assert rc == 1
        assert "chain truncation" in out
        assert str(ids[1]) in out

    @pytest.mark.parametrize("bad_limit", ["0", "5001", "-3"])
    def test_limit_out_of_range_exits_two(
        self,
        cli_settings: Settings,
        capsys: pytest.CaptureFixture[str],
        bad_limit: str,
    ) -> None:
        asyncio.run(_seed_chain(cli_settings, 1))
        rc = _run_verify("--limit", bad_limit)
        err = capsys.readouterr().err
        assert rc == 2
        assert "--limit must be between 1 and 5000" in err


class TestAuditVerifyCLIPaging:
    """The keyset-cursor paging loop, driven via ``--limit``.

    ``--limit`` IS the page-size constant (default 1000, max 5000),
    so a small value drives the identical loop over multiple pages
    without seeding 1000+ rows.
    """

    def test_full_chain_verified_across_multiple_pages(
        self,
        cli_settings: Settings,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """12 rows at page size 5 = three pages, all verified."""
        total = 12
        page_size = 5
        asyncio.run(_seed_chain(cli_settings, total))
        rc = _run_verify("--limit", str(page_size))
        out = capsys.readouterr().out
        assert rc == 0
        # verified == total proves the cursor advanced past page one
        # (the pre-fix single-slice verifier would report 5).
        assert f"verified: {total}" in out
        assert "MISMATCHES" not in out

    def test_tamper_beyond_first_page_is_detected(
        self,
        cli_settings: Settings,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """THE regression this suite exists for: a tampered row past
        the first page must still fail verification."""
        total = 12
        page_size = 5
        victim_index = 8
        assert victim_index >= page_size  # victim lives on page two+
        ids = asyncio.run(_seed_chain(cli_settings, total))
        asyncio.run(_tamper_row(cli_settings, ids[victim_index]))
        rc = _run_verify("--limit", str(page_size))
        out = capsys.readouterr().out
        assert rc == 1
        assert "MISMATCHES (1)" in out
        assert str(ids[victim_index]) in out
        assert f"verified: {total - 1}" in out

    def test_chain_break_across_a_page_boundary_is_detected(
        self,
        cli_settings: Settings,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The prev_hmac cursor must carry across pages.

        Delete ids[5] from a 10-row chain at page size 5: the nine
        surviving rows page as ids[0..4] then ids[6..9], so ids[6]
        leads page two with a prev_row_hmac referencing the deleted
        row. Detecting that requires the verifier to compare against
        the prev_hmac carried over from the END of page one.
        """
        total = 10
        page_size = 5
        ids = asyncio.run(_seed_chain(cli_settings, total))
        asyncio.run(_delete_row(cli_settings, ids[page_size]))
        rc = _run_verify("--limit", str(page_size))
        out = capsys.readouterr().out
        assert rc == 1
        assert "chain break" in out
        assert str(ids[page_size + 1]) in out


class TestCanonicalizeNaiveUTC:
    """The naive-datetime regression behind SQLite false tampering.

    The service signs an aware-UTC ``occurred_at``, but SQLite's
    ``DateTime(timezone=True)`` drops the offset in storage, so a
    verify re-read sees a NAIVE datetime. ``astimezone(UTC)`` on a
    naive value assumes LOCAL time, so on any non-UTC host the
    canonical string shifted and the whole log false-positived as
    tampered. The fix treats naive as UTC; these tests pin it in a
    host-timezone-independent way.
    """

    @staticmethod
    def _entry(occurred_at: datetime):
        from z4j_brain.domain.audit_service import AuditEntry

        return AuditEntry(
            id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
            action="test.naive_utc",
            target_type="test",
            target_id=None,
            result="ok",
            outcome="allow",
            event_id=None,
            user_id=None,
            project_id=None,
            source_ip=None,
            user_agent=None,
            metadata={},
            occurred_at=occurred_at,
            prev_row_hmac=None,
        )

    def test_naive_and_aware_utc_canonicalize_identically(self) -> None:
        aware = datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)
        naive = aware.replace(tzinfo=None)
        assert AuditService._canonicalize(self._entry(aware)) == AuditService._canonicalize(
            self._entry(naive)
        )

    def test_canonical_occurred_at_is_the_utc_instant(self) -> None:
        naive = datetime(2026, 1, 2, 3, 4, 5, 123456)
        canonical = AuditService._canonicalize(self._entry(naive))
        assert '"occurred_at":"2026-01-02T03:04:05.123456+00:00"' in canonical
