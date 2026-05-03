"""Tests for ``z4j_brain.domain.audit_service.AuditService``."""

from __future__ import annotations

import secrets
import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from z4j_brain.domain.audit_service import AuditService
from z4j_brain.persistence.base import Base
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.settings import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
    )


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


@pytest.fixture
def audit(settings: Settings) -> AuditService:
    return AuditService(settings)


@pytest.mark.asyncio
class TestRecord:
    async def test_basic_insert(
        self, audit: AuditService, session: AsyncSession,
    ) -> None:
        repo = AuditLogRepository(session)
        row = await audit.record(
            repo,
            action="auth.login",
            target_type="user",
            target_id="abc",
            result="success",
            metadata={"email": "alice@example.com"},
        )
        await session.commit()
        assert row.id is not None
        assert row.row_hmac is not None
        assert len(row.row_hmac) == 64  # sha256 hex

    async def test_default_outcome_for_success(
        self, audit: AuditService, session: AsyncSession,
    ) -> None:
        repo = AuditLogRepository(session)
        row = await audit.record(
            repo,
            action="x",
            target_type="y",
            result="success",
        )
        assert row.outcome == "allow"

    async def test_default_outcome_for_failed(
        self, audit: AuditService, session: AsyncSession,
    ) -> None:
        """v1.1.0: ``result="failed"`` now defaults to ``outcome="failure"``,
        not ``outcome="deny"``. Pre-1.1 the two were conflated, so a
        routine task crash showed up alongside real authorization
        denials when an operator filtered the audit log by
        ``outcome=deny``. The split lets security dashboards keep
        ``outcome=deny`` as a pure access-rejected signal.
        """
        repo = AuditLogRepository(session)
        row = await audit.record(
            repo,
            action="x",
            target_type="y",
            result="failed",
        )
        assert row.outcome == "failure"

    async def test_explicit_outcome_wins(
        self, audit: AuditService, session: AsyncSession,
    ) -> None:
        repo = AuditLogRepository(session)
        row = await audit.record(
            repo,
            action="x",
            target_type="y",
            result="success",
            outcome="error",
        )
        assert row.outcome == "error"


@pytest.mark.asyncio
class TestVerify:
    async def test_freshly_inserted_row_verifies(
        self, audit: AuditService, session: AsyncSession,
    ) -> None:
        repo = AuditLogRepository(session)
        row = await audit.record(
            repo,
            action="auth.login",
            target_type="user",
            target_id="abc",
            result="success",
            metadata={"email": "alice@example.com"},
        )
        assert audit.verify_row(row) is True

    async def test_tampered_action_fails_verify(
        self, audit: AuditService, session: AsyncSession,
    ) -> None:
        repo = AuditLogRepository(session)
        row = await audit.record(
            repo, action="auth.login", target_type="user", result="success",
        )
        # Modify the row in-memory to simulate post-insert tampering.
        row.action = "auth.logout"
        assert audit.verify_row(row) is False

    async def test_tampered_metadata_fails_verify(
        self, audit: AuditService, session: AsyncSession,
    ) -> None:
        repo = AuditLogRepository(session)
        row = await audit.record(
            repo,
            action="x",
            target_type="y",
            result="success",
            metadata={"email": "alice@example.com"},
        )
        row.audit_metadata = {"email": "mallory@example.com"}
        assert audit.verify_row(row) is False

    async def test_different_secret_fails_verify(
        self, session: AsyncSession,
    ) -> None:
        s1 = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            secret="x" * 48,  # type: ignore[arg-type]
            session_secret="y" * 48,  # type: ignore[arg-type]
            environment="dev",
        )
        s2 = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            secret="z" * 48,  # type: ignore[arg-type]
            session_secret="y" * 48,  # type: ignore[arg-type]
            environment="dev",
        )
        a1 = AuditService(s1)
        a2 = AuditService(s2)
        repo = AuditLogRepository(session)
        row = await a1.record(
            repo, action="x", target_type="y", result="success",
        )
        # a1 verifies its own row.
        assert a1.verify_row(row) is True
        # a2 cannot - wrong key.
        assert a2.verify_row(row) is False

    async def test_uuid_fields_canonicalized(
        self, audit: AuditService, session: AsyncSession,
    ) -> None:
        repo = AuditLogRepository(session)
        uid = uuid.uuid4()
        row = await audit.record(
            repo,
            action="x",
            target_type="y",
            result="success",
            user_id=uid,
            project_id=uuid.uuid4(),
            event_id=uuid.uuid4(),
        )
        assert audit.verify_row(row) is True


@pytest.mark.asyncio
class TestApiKeyAttribution:
    """v4 HMAC + ``audit_log.api_key_id`` (1.2.2 audit fix HIGH-11)."""

    async def test_api_key_id_persisted(
        self, audit: AuditService, session: AsyncSession,
    ) -> None:
        repo = AuditLogRepository(session)
        key_id = uuid.uuid4()
        row = await audit.record(
            repo,
            action="schedules.import",
            target_type="project",
            result="success",
            user_id=uuid.uuid4(),
            api_key_id=key_id,
        )
        assert row.api_key_id == key_id
        assert audit.verify_row(row) is True

    async def test_tampering_with_api_key_id_breaks_hmac(
        self, audit: AuditService, session: AsyncSession,
    ) -> None:
        """A DBA who swaps api_key_id without re-signing must fail verify."""
        repo = AuditLogRepository(session)
        original_key = uuid.uuid4()
        row = await audit.record(
            repo,
            action="schedules.import",
            target_type="project",
            result="success",
            api_key_id=original_key,
        )
        await session.commit()
        # Simulate raw-DB tamper: rebind api_key_id without re-signing.
        row.api_key_id = uuid.uuid4()
        assert audit.verify_row(row) is False

    async def test_pre_1_2_2_row_with_null_api_key_id_verifies(
        self, audit: AuditService, session: AsyncSession,
    ) -> None:
        """A row written without api_key_id (the common cookie-session
        path AND the pre-1.2.2 historical case) verifies cleanly via
        the v4 HMAC where ``api_key_id IS NULL``.
        """
        repo = AuditLogRepository(session)
        row = await audit.record(
            repo,
            action="schedules.create",
            target_type="schedule",
            result="success",
            # api_key_id intentionally omitted - cookie-session call
        )
        assert row.api_key_id is None
        assert audit.verify_row(row) is True

    async def test_tampered_api_key_id_fails_verify(
        self, audit: AuditService, session: AsyncSession,
    ) -> None:
        """v1.3.0 baseline: api_key_id is part of the v1 canonical
        form, so swapping it without re-signing must break verify.
        """
        repo = AuditLogRepository(session)
        row = await audit.record(
            repo,
            action="audit.test",
            target_type="schedule",
            result="success",
            api_key_id=uuid.uuid4(),
        )
        await session.commit()
        assert audit.verify_row(row) is True

        # Tamper api_key_id in place, verify must fail.
        row.api_key_id = uuid.uuid4()
        assert audit.verify_row(row) is False
