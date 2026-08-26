"""Tests for ``z4j_brain.domain.audit_service.AuditService``.

These run against a MIGRATED database rather than a create_all() one. The
Boundary-F guards (the append-only triggers, the marker CHECK constraint,
the authenticated ``audit_chain_state`` singleton) all live in migrations,
so a create_all() schema let ``record()`` take the keyless legacy branch and
never exercised the signed path a real operator's database forces.
"""

from __future__ import annotations

import asyncio
import secrets
import uuid
from collections.abc import AsyncIterator
from types import SimpleNamespace

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from z4j_brain.domain import audit_service as audit_service_module
from z4j_brain.domain.audit_chain import AuditChainIntegrityError
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.settings import Settings


@pytest.fixture
def settings(migrated_db_url: str, migrated_audit_chain_secret: str) -> Settings:
    return Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        # A migrated database has Boundary F activated, so it refuses an
        # audit row that carries no chain authentication. Production always
        # has this configured; a test that omits it is not testing production.
        audit_chain_secret=migrated_audit_chain_secret,  # type: ignore[arg-type]
        environment="dev",
    )


@pytest.fixture
async def session(settings: Settings):
    engine = create_async_engine(settings.database_url)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


@pytest.fixture
def audit(settings: Settings) -> AuditService:
    return AuditService(settings)


@pytest.mark.asyncio
class TestRecord:
    async def test_basic_insert(
        self,
        audit: AuditService,
        session: AsyncSession,
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
        self,
        audit: AuditService,
        session: AsyncSession,
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
        self,
        audit: AuditService,
        session: AsyncSession,
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
        self,
        audit: AuditService,
        session: AsyncSession,
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

    async def test_an_append_links_to_the_prior_head_and_moves_it(
        self,
        audit: AuditService,
        session: AsyncSession,
    ) -> None:
        """Each append anchors on the last one and then becomes the anchor.

        Neither half is enforced by the database. The INSERT trigger checks
        that a row is signed, not that it is signed onto anything, and the
        partial unique index on ``prev_row_hmac`` ignores NULL entirely, so
        an append that anchored on nothing would insert cleanly and quietly
        re-open the prefix-truncation hole the chain exists to close. The
        state half is the other side of it: ``audit_chain_state`` MACs the
        head pointer and the active row count, and the next append refuses
        to sign unless the live head still matches, so a row written
        without moving the state wedges the log on the following write.

        Both appends happen before either read on purpose. On SQLite an
        audited write unit must take its writer reservation with BEGIN
        IMMEDIATE before its first read, so reading the state first would
        fail the write rather than the assertion.
        """
        from sqlalchemy import func, select
        from z4j_brain.persistence.models import AuditLog

        repo = AuditLogRepository(session)
        first = await audit.record(
            repo,
            action="auth.login",
            target_type="user",
            result="success",
        )
        first_hmac = first.row_hmac
        await session.commit()
        second = await audit.record(
            repo,
            action="auth.logout",
            target_type="user",
            result="success",
        )
        await session.commit()

        assert second.prev_row_hmac == first_hmac

        state = await repo.get_chain_state_for_update()
        live = await session.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.legacy_frozen.is_(False),
                AuditLog.chain_generation == state.generation,
            ),
        )
        assert state.head_row_hmac == second.row_hmac
        assert state.head_id == second.id
        assert state.active_row_count == live.scalar_one()


@pytest.mark.asyncio
class TestVerify:
    async def test_freshly_inserted_row_verifies(
        self,
        audit: AuditService,
        session: AsyncSession,
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
        self,
        audit: AuditService,
        session: AsyncSession,
    ) -> None:
        repo = AuditLogRepository(session)
        row = await audit.record(
            repo,
            action="auth.login",
            target_type="user",
            result="success",
        )
        # Modify the row in-memory to simulate post-insert tampering.
        row.action = "auth.logout"
        assert audit.verify_row(row) is False

    async def test_tampered_metadata_fails_verify(
        self,
        audit: AuditService,
        session: AsyncSession,
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
        self,
        settings: Settings,
        session: AsyncSession,
    ) -> None:
        """The signing identity is the audit-chain key, not the master secret.

        Pre-Boundary-F this test varied ``secret``, because that was what
        signed a row. An activated database signs with the dedicated
        ``audit_chain_secret`` and looks the key up by its derived key id,
        so an unrelated key is not merely a failed comparison: the keyring
        has no entry for that id at all. Varying ``secret`` here would now
        assert nothing, since both services would verify the same row.
        """
        s2 = settings.model_copy(
            update={
                "secret": settings.secret,
                "audit_chain_secret": type(settings.secret)("z" * 48),
            },
        )
        a1 = AuditService(settings)
        a2 = AuditService(s2)
        repo = AuditLogRepository(session)
        row = await a1.record(
            repo,
            action="x",
            target_type="y",
            result="success",
        )
        # a1 verifies its own row.
        assert a1.verify_row(row) is True
        # a2 cannot - wrong key.
        assert a2.verify_row(row) is False

    async def test_uuid_fields_canonicalized(
        self,
        audit: AuditService,
        session: AsyncSession,
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
        self,
        audit: AuditService,
        session: AsyncSession,
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
        self,
        audit: AuditService,
        session: AsyncSession,
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
        self,
        audit: AuditService,
        session: AsyncSession,
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
        self,
        audit: AuditService,
        session: AsyncSession,
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


def _capture_forwards(
    audit: AuditService,
    monkeypatch: pytest.MonkeyPatch,
) -> list[dict[str, object]]:
    received: list[dict[str, object]] = []

    def _payload(inserted: object) -> dict[str, object]:
        return {"label": inserted}

    monkeypatch.setattr(audit_service_module, "_build_forward_payload", _payload)
    audit.register_post_write_hook(received.append)
    return received


def _stage_forward(audit: AuditService, session: AsyncSession, label: str) -> None:
    audit._stage_forward(
        label,  # type: ignore[arg-type]
        SimpleNamespace(session=session),  # type: ignore[arg-type]
    )


def _labels(received: list[dict[str, object]]) -> list[object]:
    return [payload["label"] for payload in received]


@pytest.mark.asyncio
class TestPostCommitForwardTransactions:
    """A SAVEPOINT is not an externally durable audit commit."""

    @pytest.fixture
    def audit(self) -> AuditService:
        return AuditService(
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                secret="s" * 48,
                session_secret="t" * 48,
                audit_chain_secret="a" * 48,
                environment="dev",
            ),
        )

    @pytest.fixture
    async def session(self) -> AsyncIterator[AsyncSession]:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        factory = async_sessionmaker(engine, class_=AsyncSession)
        async with factory() as session:
            yield session
        await engine.dispose()

    async def test_nested_commit_waits_for_outer_commit_and_keeps_order(
        self,
        audit: AuditService,
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        received = _capture_forwards(audit, monkeypatch)
        outer = await session.begin()
        _stage_forward(audit, session, "outer-before")
        nested = await session.begin_nested()
        _stage_forward(audit, session, "nested")

        await nested.commit()
        assert received == []

        _stage_forward(audit, session, "outer-after")
        await outer.commit()
        assert _labels(received) == ["outer-before", "nested", "outer-after"]
        assert audit_service_module._PENDING_KEY not in session.sync_session.info

    async def test_outer_rollback_drops_a_committed_nested_payload(
        self,
        audit: AuditService,
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        received = _capture_forwards(audit, monkeypatch)
        outer = await session.begin()
        _stage_forward(audit, session, "outer")
        nested = await session.begin_nested()
        _stage_forward(audit, session, "nested")
        await nested.commit()

        await outer.rollback()

        assert received == []
        assert audit_service_module._PENDING_KEY not in session.sync_session.info

        next_outer = await session.begin()
        _stage_forward(audit, session, "next-root")
        await next_outer.commit()
        assert _labels(received) == ["next-root"]

    async def test_nested_rollback_preserves_outer_payloads(
        self,
        audit: AuditService,
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        received = _capture_forwards(audit, monkeypatch)
        outer = await session.begin()
        _stage_forward(audit, session, "outer-before")
        nested = await session.begin_nested()
        _stage_forward(audit, session, "nested")
        await nested.rollback()
        _stage_forward(audit, session, "outer-after")

        await outer.commit()

        assert _labels(received) == ["outer-before", "outer-after"]

    async def test_inner_commit_then_parent_savepoint_rollback_drops_both(
        self,
        audit: AuditService,
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        received = _capture_forwards(audit, monkeypatch)
        outer = await session.begin()
        _stage_forward(audit, session, "outer")
        first_savepoint = await session.begin_nested()
        _stage_forward(audit, session, "first-savepoint")
        second_savepoint = await session.begin_nested()
        _stage_forward(audit, session, "second-savepoint")

        await second_savepoint.commit()
        assert received == []
        await first_savepoint.rollback()
        await outer.commit()

        assert _labels(received) == ["outer"]

    async def test_nested_rollback_does_not_clear_integrity_rollback_only(
        self,
        audit: AuditService,
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        received = _capture_forwards(audit, monkeypatch)
        outer = await session.begin()
        _stage_forward(audit, session, "outer")
        nested = await session.begin_nested()
        session.sync_session.info[audit_service_module._ROLLBACK_ONLY_KEY] = True
        _stage_forward(audit, session, "nested")
        await nested.rollback()

        assert session.sync_session.info[audit_service_module._ROLLBACK_ONLY_KEY] is True
        with pytest.raises(AuditChainIntegrityError, match="rollback is required"):
            await outer.commit()
        await session.rollback()

        assert received == []
        assert audit_service_module._PENDING_KEY not in session.sync_session.info
        assert audit_service_module._ROLLBACK_ONLY_KEY not in session.sync_session.info

    async def test_nested_exception_drops_only_nested_payload(
        self,
        audit: AuditService,
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        received = _capture_forwards(audit, monkeypatch)
        outer = await session.begin()
        _stage_forward(audit, session, "outer-before")
        with pytest.raises(RuntimeError, match="savepoint failed"):
            async with session.begin_nested():
                _stage_forward(audit, session, "nested")
                raise RuntimeError("savepoint failed")
        _stage_forward(audit, session, "outer-after")

        await outer.commit()

        assert _labels(received) == ["outer-before", "outer-after"]

    async def test_nested_task_cancellation_drops_only_nested_payload(
        self,
        audit: AuditService,
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        received = _capture_forwards(audit, monkeypatch)
        outer = await session.begin()
        _stage_forward(audit, session, "outer-before")
        staged = asyncio.Event()

        async def _cancelled_savepoint() -> None:
            async with session.begin_nested():
                _stage_forward(audit, session, "nested")
                staged.set()
                await asyncio.Future()

        task = asyncio.create_task(_cancelled_savepoint())
        await staged.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        _stage_forward(audit, session, "outer-after")

        await outer.commit()

        assert _labels(received) == ["outer-before", "outer-after"]

    async def test_outer_task_cancellation_drops_committed_nested_payloads(
        self,
        audit: AuditService,
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        received = _capture_forwards(audit, monkeypatch)
        staged = asyncio.Event()

        async def _cancelled_unit() -> None:
            async with session.begin():
                _stage_forward(audit, session, "outer")
                async with session.begin_nested():
                    _stage_forward(audit, session, "nested")
                staged.set()
                await asyncio.Future()

        task = asyncio.create_task(_cancelled_unit())
        await staged.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert received == []
        assert audit_service_module._PENDING_KEY not in session.sync_session.info

    async def test_session_close_drops_state_before_session_reuse(
        self,
        audit: AuditService,
        session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        received = _capture_forwards(audit, monkeypatch)
        await session.begin()
        _stage_forward(audit, session, "abandoned")

        await session.close()

        assert received == []
        assert audit_service_module._PENDING_KEY not in session.sync_session.info
        next_outer = await session.begin()
        _stage_forward(audit, session, "fresh")
        await next_outer.commit()
        assert _labels(received) == ["fresh"]
