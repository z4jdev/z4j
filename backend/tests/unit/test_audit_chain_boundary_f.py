"""Boundary-F core authority tests.

These tests intentionally use the real SQLite models, repository, and
AuditService.  They prove that an active v2 signer cannot recreate authority
after rows/state are deleted and that the dedicated audit key is independent
from the application master secret.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.audit_retention import AuditRetentionSweeper
from z4j_brain.domain.audit_chain import (
    AuditChainIntegrityError,
    canonical_audit_key_id,
    canonical_row_payload,
    canonical_state_payload,
    make_empty_chain_state,
)
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.audit_verifier import verify_active_audit_generation
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import AuditChainState, AuditLog, Z4JMeta
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.settings import Settings
from z4j_brain.startup import verify_production_authority_at_startup

MASTER = "master-secret-that-is-not-the-audit-key-000000"
SESSION = "session-secret-that-is-not-the-audit-key-0000"
AUDIT = "audit-only-secret-that-is-independent-000000000"
AUDIT_NEXT = "next-audit-only-secret-that-is-independent-000000"


def _settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=MASTER,  # type: ignore[arg-type]
        session_secret=SESSION,  # type: ignore[arg-type]
        audit_chain_secret=AUDIT,  # type: ignore[arg-type]
        environment="dev",
        audit_retention_days=1,
        audit_retention_sweep_batch_size=100,
    )


@pytest.fixture
async def engine():
    value = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with value.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield value
    await value.dispose()


async def _activate(engine, service: AuditService) -> tuple[uuid.UUID, str]:
    from sqlalchemy.ext.asyncio import AsyncSession

    async with AsyncSession(engine, expire_on_commit=False) as session:
        await session.execute(text("BEGIN IMMEDIATE"))
        session.sync_session.info["z4j_sqlite_immediate"] = True
        state = make_empty_chain_state(secret=AUDIT.encode())
        session.add(state)
        await session.flush()
        row = await service.record(
            AuditLogRepository(session),
            action="audit.chain_generation_started",
            target_type="audit_chain",
            target_id=str(state.generation),
            metadata={"fresh": True},
        )
        await session.flush()
        generation = state.generation
        row_hmac = row.row_hmac
        assert row_hmac is not None
        await session.commit()
    return generation, row_hmac


async def _mark_release_migration_head(engine) -> None:
    async with engine.begin() as connection:
        await connection.execute(
            text("CREATE TABLE alembic_version (version_num VARCHAR(80) NOT NULL)"),
        )
        await connection.execute(
            text(
                "INSERT INTO alembic_version (version_num) VALUES ('v1_8_schedule_cursor_repair')"
            ),
        )


def test_retired_recovery_binding_is_a_closed_authenticated_schema() -> None:
    state = make_empty_chain_state(secret=AUDIT.encode())
    state.retired_recovery_binding = {
        "status": "ARBITRARY",
        "caller_path": "/",
    }
    with pytest.raises(
        AuditChainIntegrityError,
        match="retired_recovery_binding",
    ):
        canonical_state_payload(state)

    binding = {
        "version": 1,
        "operation_id": str(uuid.uuid4()),
        "old_bundle_manifest_digest": "1" * 64,
        "retained_parent_identity_digest": "2" * 64,
        "replacement_installation_id": str(state.installation_id),
        "status": "RECOVERABLE",
        "destruction_journal_digest": None,
    }
    state.retired_recovery_binding = binding
    assert canonical_state_payload(state)["retired_recovery_binding"] == binding

    state.retired_recovery_binding = {
        **binding,
        "status": "DESTROYING",
    }
    with pytest.raises(
        AuditChainIntegrityError,
        match="destruction_journal_digest",
    ):
        canonical_state_payload(state)

    state.retired_recovery_binding = {
        **binding,
        "unexpected": True,
    }
    with pytest.raises(
        AuditChainIntegrityError,
        match="retired_recovery_binding",
    ):
        canonical_state_payload(state)


@pytest.mark.asyncio
async def test_startup_authenticates_complete_active_authority(engine) -> None:
    settings = _settings()
    await _activate(engine, AuditService(settings))
    await _mark_release_migration_head(engine)

    report = await verify_production_authority_at_startup(
        db=DatabaseManager(engine),
        settings=settings,
    )

    assert report.clean
    assert report.verified_active_rows == 1


@pytest.mark.asyncio
async def test_startup_refuses_tampered_authenticated_state(engine) -> None:
    settings = _settings()
    await _activate(engine, AuditService(settings))
    await _mark_release_migration_head(engine)
    from sqlalchemy.ext.asyncio import AsyncSession

    async with AsyncSession(engine) as attacker:
        await attacker.execute(update(AuditChainState).values(state_mac="0" * 64))
        await attacker.commit()

    with pytest.raises(AuditChainIntegrityError, match="state MAC mismatch"):
        await verify_production_authority_at_startup(
            db=DatabaseManager(engine),
            settings=settings,
        )


@pytest.mark.asyncio
async def test_api_login_starts_authenticated_sqlite_write_unit_before_read(
    engine,
) -> None:
    """The request dependency must reserve SQLite before auth reads the user.

    Ordinary auth tests do not activate Boundary F, so a deferred request
    transaction can look green until the released container's first login.
    Exercise the real ASGI dependency graph with authenticated chain state.
    """
    from httpx import ASGITransport, AsyncClient
    from z4j_brain.auth.passwords import PasswordHasher
    from z4j_brain.main import create_app
    from z4j_brain.persistence.models import User

    settings = _settings()
    await _activate(engine, AuditService(settings))
    app = create_app(settings, engine=engine)
    async with app.state.db.session(write=True) as session:
        session.add(
            User(
                email="release-admin@example.com",
                password_hash=PasswordHasher(settings).hash(
                    "release-login-password-1!Aa",
                ),
                display_name="Release Admin",
                is_admin=True,
                is_active=True,
            ),
        )
        await session.commit()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "release-admin@example.com",
                "password": "release-login-password-1!Aa",
            },
        )

    assert response.status_code == 200, response.text
    async with app.state.db.session() as session:
        actions = (
            (
                await session.execute(
                    select(AuditLog.action).where(
                        AuditLog.action == "auth.login",
                    ),
                )
            )
            .scalars()
            .all()
        )
    assert actions == ["auth.login"]


@pytest.mark.asyncio
async def test_explicit_audit_key_rotation_is_atomic_and_idempotent(engine) -> None:
    old_settings = _settings()
    await _activate(engine, AuditService(old_settings))
    rotated_settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=MASTER,  # type: ignore[arg-type]
        session_secret=SESSION,  # type: ignore[arg-type]
        audit_chain_secret=AUDIT_NEXT,  # type: ignore[arg-type]
        audit_chain_previous_secrets=AUDIT,  # type: ignore[arg-type]
        environment="dev",
    )
    rotated_service = AuditService(rotated_settings)
    from sqlalchemy.ext.asyncio import AsyncSession

    async with AsyncSession(engine, expire_on_commit=False) as session:
        marker = await rotated_service.rotate_chain_key(
            AuditLogRepository(session),
        )
        await session.commit()
        assert marker is not None
        assert marker.action == "audit.chain_key_rotated"
        assert marker.hmac_key_id == canonical_audit_key_id(AUDIT_NEXT.encode())

    async with AsyncSession(engine, expire_on_commit=False) as session:
        state = (await session.execute(select(AuditChainState))).scalar_one()
        assert state.state_key_id == canonical_audit_key_id(AUDIT_NEXT.encode())
        assert state.active_key_counts == {
            canonical_audit_key_id(AUDIT.encode()): 1,
            canonical_audit_key_id(AUDIT_NEXT.encode()): 1,
        }

    async with AsyncSession(engine, expire_on_commit=False) as session:
        assert await rotated_service.rotate_chain_key(AuditLogRepository(session)) is None
        await session.commit()
        markers = (
            (
                await session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "audit.chain_key_rotated",
                    ),
                )
            )
            .scalars()
            .all()
        )
        assert len(markers) == 1


@pytest.mark.asyncio
async def test_old_audit_key_cannot_be_removed_while_live_rows_need_it(engine) -> None:
    await _activate(engine, AuditService(_settings()))
    rotated_settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=MASTER,  # type: ignore[arg-type]
        session_secret=SESSION,  # type: ignore[arg-type]
        audit_chain_secret=AUDIT_NEXT,  # type: ignore[arg-type]
        audit_chain_previous_secrets=AUDIT,  # type: ignore[arg-type]
        environment="dev",
    )
    from sqlalchemy.ext.asyncio import AsyncSession

    async with AsyncSession(engine) as session:
        await AuditService(rotated_settings).rotate_chain_key(
            AuditLogRepository(session),
        )
        await session.commit()

    without_old = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=MASTER,  # type: ignore[arg-type]
        session_secret=SESSION,  # type: ignore[arg-type]
        audit_chain_secret=AUDIT_NEXT,  # type: ignore[arg-type]
        environment="dev",
    )
    async with AsyncSession(engine) as session:
        with pytest.raises(AuditChainIntegrityError, match="every live active row"):
            await AuditService(without_old).record(
                AuditLogRepository(session),
                action="must.not.sign",
                target_type="test",
            )


def test_explicit_rotation_cli_commits_marker_and_state(
    tmp_path,
    monkeypatch,
) -> None:
    import asyncio

    from z4j_brain.cli import main

    database_url = f"sqlite+aiosqlite:///{(tmp_path / 'rotation.db').as_posix()}"
    old_settings = Settings(
        database_url=database_url,
        secret=MASTER,  # type: ignore[arg-type]
        session_secret=SESSION,  # type: ignore[arg-type]
        audit_chain_secret=AUDIT,  # type: ignore[arg-type]
        environment="dev",
    )

    async def _prepare() -> None:
        local_engine = create_async_engine(database_url)
        async with local_engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        await _activate(local_engine, AuditService(old_settings))
        await local_engine.dispose()

    asyncio.run(_prepare())
    tmp_path.chmod(0o700)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z4J_HOME", str(tmp_path))
    monkeypatch.setenv("Z4J_DATABASE_URL", database_url)
    monkeypatch.setenv("Z4J_SECRET", MASTER)
    monkeypatch.setenv("Z4J_SESSION_SECRET", SESSION)
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", AUDIT_NEXT)
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_PREVIOUS_SECRETS", AUDIT)
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.setenv(
        "Z4J_ALLOWED_HOSTS",
        '["localhost","127.0.0.1"]',
    )

    assert main(["audit", "rotate-chain-key"]) == 0

    async def _assert_rotated() -> None:
        local_engine = create_async_engine(database_url)
        from sqlalchemy.ext.asyncio import AsyncSession

        async with AsyncSession(local_engine) as session:
            state = (await session.execute(select(AuditChainState))).scalar_one()
            assert state.state_key_id == canonical_audit_key_id(
                AUDIT_NEXT.encode(),
            )
            markers = (
                (
                    await session.execute(
                        select(AuditLog).where(
                            AuditLog.action == "audit.chain_key_rotated",
                        ),
                    )
                )
                .scalars()
                .all()
            )
            assert len(markers) == 1
        await local_engine.dispose()

    asyncio.run(_assert_rotated())


def test_managed_rotation_cli_persists_file_first_and_resumes(
    tmp_path,
) -> None:
    import asyncio
    import os
    import subprocess
    import sys

    from z4j_brain.secret_store import read_secret_store, update_secret_store

    tmp_path.chmod(0o700)
    database_url = f"sqlite+aiosqlite:///{(tmp_path / 'managed-rotation.db').as_posix()}"
    update_secret_store(
        tmp_path / "secret.env",
        {
            "Z4J_SECRET": MASTER,
            "Z4J_SESSION_SECRET": SESSION,
            "Z4J_AUDIT_CHAIN_SECRET": AUDIT,
        },
    )
    old_settings = Settings(
        database_url=database_url,
        secret=MASTER,  # type: ignore[arg-type]
        session_secret=SESSION,  # type: ignore[arg-type]
        audit_chain_secret=AUDIT,  # type: ignore[arg-type]
        environment="dev",
    )

    async def _prepare() -> None:
        local_engine = create_async_engine(database_url)
        async with local_engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        await _activate(local_engine, AuditService(old_settings))
        await local_engine.dispose()

    asyncio.run(_prepare())
    environment = dict(os.environ)
    for key in (
        "Z4J_SECRET",
        "Z4J_SESSION_SECRET",
        "Z4J_AUDIT_CHAIN_SECRET",
        "Z4J_AUDIT_CHAIN_PREVIOUS_SECRETS",
    ):
        environment.pop(key, None)
    environment.update(
        {
            "Z4J_HOME": str(tmp_path),
            "Z4J_DATABASE_URL": database_url,
            "Z4J_ENVIRONMENT": "dev",
            "Z4J_ALLOWED_HOSTS": '["localhost","127.0.0.1"]',
        },
    )
    command = [
        sys.executable,
        "-c",
        (
            "from z4j_brain.cli import main; "
            "raise SystemExit(main(['audit','rotate-chain-key','--begin-managed']))"
        ),
    ]
    first = subprocess.run(
        command,
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert first.returncode == 0, first.stderr
    winner = read_secret_store(tmp_path / "secret.env")
    new_secret = winner.values["Z4J_AUDIT_CHAIN_SECRET"]
    assert new_secret != AUDIT
    assert AUDIT in winner.values["Z4J_AUDIT_CHAIN_PREVIOUS_SECRETS"].split(",")

    async def _assert_rotated() -> None:
        local_engine = create_async_engine(database_url)
        from sqlalchemy.ext.asyncio import AsyncSession

        async with AsyncSession(local_engine) as session:
            state = (await session.execute(select(AuditChainState))).scalar_one()
            assert state.state_key_id == canonical_audit_key_id(
                new_secret.encode(),
            )
        await local_engine.dispose()

    asyncio.run(_assert_rotated())

    resume = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from z4j_brain.cli import main; "
                "raise SystemExit(main(['audit','rotate-chain-key']))"
            ),
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert resume.returncode == 0, resume.stderr
    assert read_secret_store(tmp_path / "secret.env").values["Z4J_AUDIT_CHAIN_SECRET"] == new_secret


def test_managed_rotation_resumes_crash_after_file_replace(tmp_path) -> None:
    import asyncio
    import os
    import subprocess
    import sys

    from z4j_brain.secret_store import update_secret_store

    tmp_path.chmod(0o700)
    database_url = f"sqlite+aiosqlite:///{(tmp_path / 'pending-rotation.db').as_posix()}"
    update_secret_store(
        tmp_path / "secret.env",
        {
            "Z4J_SECRET": MASTER,
            "Z4J_SESSION_SECRET": SESSION,
            "Z4J_AUDIT_CHAIN_SECRET": AUDIT,
        },
    )
    old_settings = Settings(
        database_url=database_url,
        secret=MASTER,  # type: ignore[arg-type]
        session_secret=SESSION,  # type: ignore[arg-type]
        audit_chain_secret=AUDIT,  # type: ignore[arg-type]
        environment="dev",
    )

    async def _prepare() -> None:
        local_engine = create_async_engine(database_url)
        async with local_engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        await _activate(local_engine, AuditService(old_settings))
        await local_engine.dispose()

    asyncio.run(_prepare())
    # Durable file-first phase committed, then the process crashed before the
    # database marker/state transaction.
    update_secret_store(
        tmp_path / "secret.env",
        {
            "Z4J_AUDIT_CHAIN_SECRET": AUDIT_NEXT,
            "Z4J_AUDIT_CHAIN_PREVIOUS_SECRETS": AUDIT,
        },
    )
    environment = dict(os.environ)
    for key in (
        "Z4J_SECRET",
        "Z4J_SESSION_SECRET",
        "Z4J_AUDIT_CHAIN_SECRET",
        "Z4J_AUDIT_CHAIN_PREVIOUS_SECRETS",
    ):
        environment.pop(key, None)
    environment.update(
        {
            "Z4J_HOME": str(tmp_path),
            "Z4J_DATABASE_URL": database_url,
            "Z4J_ENVIRONMENT": "dev",
            "Z4J_ALLOWED_HOSTS": '["localhost","127.0.0.1"]',
        },
    )
    resumed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from z4j_brain.cli import main; "
                "raise SystemExit(main(['audit','rotate-chain-key']))"
            ),
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert resumed.returncode == 0, resumed.stderr

    async def _assert_rotated() -> None:
        local_engine = create_async_engine(database_url)
        from sqlalchemy.ext.asyncio import AsyncSession

        async with AsyncSession(local_engine) as session:
            state = (await session.execute(select(AuditChainState))).scalar_one()
            assert state.state_key_id == canonical_audit_key_id(
                AUDIT_NEXT.encode(),
            )
        await local_engine.dispose()

    asyncio.run(_assert_rotated())


def test_managed_retirement_requires_zero_live_count(
    tmp_path,
    monkeypatch,
) -> None:
    import asyncio
    import os
    import subprocess
    import sys

    from z4j_brain.secret_store import read_secret_store, update_secret_store

    tmp_path.chmod(0o700)
    database_url = f"sqlite+aiosqlite:///{(tmp_path / 'retirement.db').as_posix()}"
    old_settings = Settings(
        database_url=database_url,
        secret=MASTER,  # type: ignore[arg-type]
        session_secret=SESSION,  # type: ignore[arg-type]
        audit_chain_secret=AUDIT,  # type: ignore[arg-type]
        environment="dev",
        audit_retention_days=1,
        audit_retention_sweep_batch_size=100,
    )
    rotated_settings = Settings(
        database_url=database_url,
        secret=MASTER,  # type: ignore[arg-type]
        session_secret=SESSION,  # type: ignore[arg-type]
        audit_chain_secret=AUDIT_NEXT,  # type: ignore[arg-type]
        audit_chain_previous_secrets=AUDIT,  # type: ignore[arg-type]
        environment="dev",
        audit_retention_days=1,
        audit_retention_sweep_batch_size=100,
    )
    old_now = datetime.now(UTC) - timedelta(days=30)

    class OldClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return old_now if tz is not None else old_now.replace(tzinfo=None)

    async def _prepare() -> None:
        local_engine = create_async_engine(database_url)
        async with local_engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        monkeypatch.setattr("z4j_brain.domain.audit_service.datetime", OldClock)
        await _activate(local_engine, AuditService(old_settings))
        monkeypatch.setattr("z4j_brain.domain.audit_service.datetime", datetime)
        from sqlalchemy.ext.asyncio import AsyncSession

        async with AsyncSession(local_engine) as session:
            await AuditService(rotated_settings).rotate_chain_key(
                AuditLogRepository(session),
            )
            await session.commit()
        sweeper = AuditRetentionSweeper()
        sweeper._db = DatabaseManager(local_engine)
        sweeper._settings = rotated_settings
        assert await sweeper.sweep_once() == 1
        async with AsyncSession(local_engine) as session:
            state = (await session.execute(select(AuditChainState))).scalar_one()
            assert canonical_audit_key_id(AUDIT.encode()) not in (state.active_key_counts)
        await local_engine.dispose()

    asyncio.run(_prepare())
    update_secret_store(
        tmp_path / "secret.env",
        {
            "Z4J_SECRET": MASTER,
            "Z4J_SESSION_SECRET": SESSION,
            "Z4J_AUDIT_CHAIN_SECRET": AUDIT_NEXT,
            "Z4J_AUDIT_CHAIN_PREVIOUS_SECRETS": AUDIT,
        },
    )
    environment = dict(os.environ)
    for key in (
        "Z4J_SECRET",
        "Z4J_SESSION_SECRET",
        "Z4J_AUDIT_CHAIN_SECRET",
        "Z4J_AUDIT_CHAIN_PREVIOUS_SECRETS",
    ):
        environment.pop(key, None)
    environment.update(
        {
            "Z4J_HOME": str(tmp_path),
            "Z4J_DATABASE_URL": database_url,
            "Z4J_ENVIRONMENT": "dev",
            "Z4J_ALLOWED_HOSTS": '["localhost","127.0.0.1"]',
        },
    )
    retired = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from z4j_brain.cli import main; "
                "raise SystemExit(main(['audit','retire-chain-key','--key-id',"
                f"'{canonical_audit_key_id(AUDIT.encode())}']))"
            ),
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert retired.returncode == 0, retired.stderr
    assert (
        "Z4J_AUDIT_CHAIN_PREVIOUS_SECRETS"
        not in read_secret_store(
            tmp_path / "secret.env",
        ).values
    )


@pytest.mark.asyncio
async def test_active_v2_append_advances_authenticated_state(engine) -> None:
    settings = _settings()
    service = AuditService(settings)
    generation, genesis_hmac = await _activate(engine, service)

    from sqlalchemy.ext.asyncio import AsyncSession

    async with AsyncSession(engine, expire_on_commit=False) as session:
        row = await service.record(
            AuditLogRepository(session),
            action="project.updated",
            target_type="project",
            target_id=str(uuid.uuid4()),
            source_ip="2001:0db8:0:0:0:0:0:1",
            metadata={"nested": {"finite": 1.25}},
        )
        await session.commit()

        state = (await session.execute(select(AuditChainState))).scalar_one()
        assert row.hmac_version == 2
        assert row.legacy_frozen is False
        assert row.chain_generation == generation
        assert row.prev_row_hmac == genesis_hmac
        assert row.source_ip == "2001:db8::1"
        assert state.active_row_count == 2
        assert state.head_row_hmac == row.row_hmac
        assert state.active_key_counts == {
            canonical_audit_key_id(AUDIT.encode()): 2,
        }
        assert service.verify_row(row)


@pytest.mark.asyncio
async def test_deleted_active_rows_do_not_create_a_new_genesis(engine) -> None:
    service = AuditService(_settings())
    await _activate(engine, service)

    from sqlalchemy.ext.asyncio import AsyncSession

    async with AsyncSession(engine, expire_on_commit=False) as attacker:
        await attacker.execute(delete(AuditLog))
        await attacker.commit()

    async with AsyncSession(engine, expire_on_commit=False) as session:
        with pytest.raises(AuditChainIntegrityError, match=r"count|head is missing"):
            await service.record(
                AuditLogRepository(session),
                action="must.not.sign",
                target_type="test",
            )
        # Even if a legacy caller catches the integrity exception, the session
        # cannot commit some unrelated business mutation.
        state = (await session.execute(select(AuditChainState))).scalar_one()
        state.frozen_row_count = 1
        with pytest.raises(AuditChainIntegrityError, match="rollback is required"):
            await session.commit()
        await session.rollback()


@pytest.mark.asyncio
async def test_deleted_state_is_not_recreated(engine) -> None:
    service = AuditService(_settings())
    await _activate(engine, service)

    from sqlalchemy.ext.asyncio import AsyncSession

    async with AsyncSession(engine) as attacker:
        attacker.add(Z4JMeta(key="business-state", value="before"))
        await attacker.execute(delete(AuditChainState))
        await attacker.commit()

    async with AsyncSession(engine, expire_on_commit=False) as session:
        await session.execute(text("BEGIN IMMEDIATE"))
        session.sync_session.info["z4j_sqlite_immediate"] = True
        business_state = (
            await session.execute(
                select(Z4JMeta).where(Z4JMeta.key == "business-state"),
            )
        ).scalar_one()
        business_state.value = "unaudited-change"
        with pytest.raises(RuntimeError, match="state is missing"):
            await service.record(
                AuditLogRepository(session),
                action="must.not.recreate",
                target_type="test",
            )
        assert (await session.execute(select(AuditChainState))).scalar_one_or_none() is None
        with pytest.raises(AuditChainIntegrityError, match="rollback is required"):
            await session.commit()
        await session.rollback()

    async with AsyncSession(engine) as session:
        persisted = (
            await session.execute(
                select(Z4JMeta.value).where(Z4JMeta.key == "business-state"),
            )
        ).scalar_one()
        assert persisted == "before"


@pytest.mark.asyncio
async def test_state_mac_tamper_fails_before_append(engine) -> None:
    service = AuditService(_settings())
    await _activate(engine, service)

    from sqlalchemy.ext.asyncio import AsyncSession

    async with AsyncSession(engine) as attacker:
        await attacker.execute(
            update(AuditChainState).values(state_mac="0" * 64),
        )
        await attacker.commit()

    async with AsyncSession(engine) as session:
        with pytest.raises(AuditChainIntegrityError, match="state MAC mismatch"):
            await service.record(
                AuditLogRepository(session),
                action="must.not.sign",
                target_type="test",
            )


def test_v2_metadata_rejects_serializer_fallbacks() -> None:
    with pytest.raises(AuditChainIntegrityError, match="unsupported JSON value"):
        canonical_row_payload(
            row_id=uuid.uuid4(),
            action="x",
            target_type="x",
            target_id=None,
            result="success",
            outcome="allow",
            event_id=None,
            user_id=None,
            api_key_id=None,
            project_id=None,
            source_ip=None,
            user_agent=None,
            metadata={"would-have-used-default-str": object()},
            occurred_at=__import__("datetime").datetime.now(
                __import__("datetime").UTC,
            ),
            prev_row_hmac=None,
            hmac_key_id=canonical_audit_key_id(AUDIT.encode()),
            chain_generation=uuid.uuid4(),
        )


def test_master_secret_cannot_verify_or_select_audit_key() -> None:
    settings = _settings()
    assert settings.all_audit_chain_secrets_for_verification() == [AUDIT.encode()]
    assert MASTER.encode() not in settings.all_audit_chain_secrets_for_verification()


@pytest.mark.asyncio
async def test_full_prune_retains_head_and_next_append_links_to_it(
    engine,
    monkeypatch,
) -> None:
    settings = _settings()
    service = AuditService(settings)
    old_now = datetime.now(UTC) - timedelta(days=30)

    class OldClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return old_now if tz is not None else old_now.replace(tzinfo=None)

    monkeypatch.setattr("z4j_brain.domain.audit_service.datetime", OldClock)
    _generation, _genesis = await _activate(engine, service)
    from sqlalchemy.ext.asyncio import AsyncSession

    async with AsyncSession(engine, expire_on_commit=False) as session:
        old_tail = await service.record(
            AuditLogRepository(session),
            action="old.tail",
            target_type="test",
        )
        await session.commit()
        old_head_hmac = old_tail.row_hmac
        old_head_id = old_tail.id

    monkeypatch.setattr("z4j_brain.domain.audit_service.datetime", datetime)
    db = DatabaseManager(engine)
    sweeper = AuditRetentionSweeper()
    sweeper._db = db
    sweeper._settings = settings
    assert await sweeper.sweep_once() == 2

    async with AsyncSession(engine, expire_on_commit=False) as session:
        from sqlalchemy import text

        await session.execute(text("BEGIN IMMEDIATE"))
        session.sync_session.info["z4j_sqlite_immediate"] = True
        state = (await session.execute(select(AuditChainState))).scalar_one()
        assert state.active_row_count == 0
        assert state.active_key_counts == {}
        assert state.head_row_hmac == old_head_hmac
        assert state.prune_row_hmac == old_head_hmac
        assert state.head_id == old_head_id
        assert state.prune_id == old_head_id

        new_row = await service.record(
            AuditLogRepository(session),
            action="after.full.prune",
            target_type="test",
        )
        await session.commit()
        assert new_row.prev_row_hmac == old_head_hmac
        assert new_row.occurred_at > old_tail.occurred_at


@pytest.mark.asyncio
async def test_full_prune_allows_one_authenticated_generation_reset(
    engine,
    monkeypatch,
) -> None:
    settings = _settings()
    service = AuditService(settings)
    old_now = datetime.now(UTC) - timedelta(days=30)

    class OldClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return old_now if tz is not None else old_now.replace(tzinfo=None)

    monkeypatch.setattr("z4j_brain.domain.audit_service.datetime", OldClock)
    generation, _genesis_hmac = await _activate(engine, service)
    from sqlalchemy.ext.asyncio import AsyncSession

    async with AsyncSession(engine, expire_on_commit=False) as session:
        old_tail = await service.record(
            AuditLogRepository(session),
            action="old.before.reset",
            target_type="test",
        )
        await session.commit()

    monkeypatch.setattr("z4j_brain.domain.audit_service.datetime", datetime)
    sweeper = AuditRetentionSweeper()
    sweeper._db = DatabaseManager(engine)
    sweeper._settings = settings
    assert await sweeper.sweep_once() == 2

    async with AsyncSession(engine, expire_on_commit=False) as session:
        await session.execute(text("BEGIN IMMEDIATE"))
        session.sync_session.info["z4j_sqlite_immediate"] = True
        state = (await session.execute(select(AuditChainState))).scalar_one()
        assert state.active_row_count == 0
        assert state.head_row_hmac == state.prune_row_hmac == old_tail.row_hmac
        assert state.head_id == state.prune_id == old_tail.id
        marker = await service.reset_generation(
            AuditLogRepository(session),
            metadata={"reason": "full-prune-regression"},
        )
        await session.commit()
        assert marker.action == "audit.chain_generation_reset"
        assert marker.target_id == str(generation)

    async with AsyncSession(engine) as session:
        rows = list((await session.execute(select(AuditLog))).scalars())
        state = (await session.execute(select(AuditChainState))).scalar_one()
        assert [row.action for row in rows] == ["audit.chain_generation_reset"]
        assert state.active_row_count == 1
        assert state.head_row_hmac == rows[0].row_hmac
        assert state.prune_row_hmac is None


@pytest.mark.asyncio
async def test_attacker_prefix_delete_is_not_blessed_by_retention(
    engine,
    monkeypatch,
) -> None:
    settings = _settings()
    service = AuditService(settings)
    old_now = datetime.now(UTC) - timedelta(days=30)

    class OldClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return old_now if tz is not None else old_now.replace(tzinfo=None)

    monkeypatch.setattr("z4j_brain.domain.audit_service.datetime", OldClock)
    await _activate(engine, service)
    from sqlalchemy.ext.asyncio import AsyncSession

    async with AsyncSession(engine) as session:
        await service.record(
            AuditLogRepository(session),
            action="old.second",
            target_type="test",
        )
        await session.commit()
    monkeypatch.setattr("z4j_brain.domain.audit_service.datetime", datetime)

    async with AsyncSession(engine) as attacker:
        oldest = (
            await attacker.execute(
                select(AuditLog).order_by(AuditLog.occurred_at, AuditLog.id).limit(1),
            )
        ).scalar_one()
        await attacker.execute(delete(AuditLog).where(AuditLog.id == oldest.id))
        await attacker.commit()

    db = DatabaseManager(engine)
    sweeper = AuditRetentionSweeper()
    sweeper._db = db
    sweeper._settings = settings
    with pytest.raises(AuditChainIntegrityError, match="count"):
        await sweeper.sweep_once()

    async with AsyncSession(engine) as session:
        state = (await session.execute(select(AuditChainState))).scalar_one()
        assert state.prune_row_hmac is None
        assert state.active_row_count == 2


@pytest.mark.asyncio
async def test_stable_v2_verifier_authenticates_state_counts_head_and_anchor(
    engine,
) -> None:
    settings = _settings()
    service = AuditService(settings)
    await _activate(engine, service)
    from sqlalchemy.ext.asyncio import AsyncSession

    async with AsyncSession(engine, expire_on_commit=False) as session:
        await service.record(
            AuditLogRepository(session),
            action="verified.tail",
            target_type="test",
        )
        await session.commit()

    async with AsyncSession(engine, expire_on_commit=False) as session:
        state = (await session.execute(select(AuditChainState))).scalar_one()
        envelope = {
            "row_hmac": state.head_row_hmac,
            "hmac_version": 2,
            "hmac_key_id": state.head_hmac_key_id,
            "generation": str(state.generation),
            "occurred_at": state.head_occurred_at.isoformat(),
            "id": str(state.head_id),
        }

    async with AsyncSession(engine, expire_on_commit=False) as session:
        report = await verify_active_audit_generation(
            session,
            settings,
            page_size=1,
            known_head=envelope,
        )
        assert report.clean
        assert report.verified_active_rows == 2
        assert report.known_head_result == "CURRENT_MATCH"


@pytest.mark.asyncio
async def test_v2_verifier_reports_deleted_prefix_and_unprovable_anchor(
    engine,
) -> None:
    settings = _settings()
    service = AuditService(settings)
    await _activate(engine, service)
    from sqlalchemy.ext.asyncio import AsyncSession

    async with AsyncSession(engine) as attacker:
        oldest = (
            await attacker.execute(
                select(AuditLog).order_by(AuditLog.occurred_at, AuditLog.id).limit(1),
            )
        ).scalar_one()
        await attacker.delete(oldest)
        await attacker.commit()

    async with AsyncSession(engine, expire_on_commit=False) as session:
        report = await verify_active_audit_generation(
            session,
            settings,
            page_size=5,
            known_head={"row_hmac": "0" * 64},
        )
        assert not report.clean
        assert report.known_head_result == "UNPROVABLE"
        assert any("count" in mismatch for mismatch in report.mismatches)


@pytest.mark.asyncio
async def test_sqlite_audited_write_refuses_deferred_read_transaction(
    engine,
) -> None:
    settings = _settings()
    service = AuditService(settings)
    await _activate(engine, service)
    from sqlalchemy.ext.asyncio import AsyncSession

    async with AsyncSession(engine, expire_on_commit=False) as session:
        await session.execute(select(AuditChainState))
        with pytest.raises(RuntimeError, match="BEGIN IMMEDIATE"):
            await service.record(
                AuditLogRepository(session),
                action="must.not.upgrade.deferred",
                target_type="test",
            )
        await session.rollback()


@pytest.mark.asyncio
async def test_sqlite_mid_session_commit_requires_a_fresh_immediate_write_unit(
    engine,
) -> None:
    settings = _settings()
    service = AuditService(settings)
    await _activate(engine, service)

    db = DatabaseManager(engine)
    async with db.session(write=True) as session:
        await service.record(
            AuditLogRepository(session),
            action="outbound.intent",
            target_type="test",
        )
        await session.commit()
        assert "z4j_sqlite_immediate" not in session.sync_session.info

        # The result transaction may safely begin a new immediate writer when
        # it has done no intervening read.
        await service.record(
            AuditLogRepository(session),
            action="outbound.result",
            target_type="test",
        )
        await session.commit()
        assert "z4j_sqlite_immediate" not in session.sync_session.info

        # A later write may never borrow the first transaction's marker after
        # an ordinary read opened a deferred transaction.
        await session.execute(select(AuditChainState))
        with pytest.raises(RuntimeError, match="BEGIN IMMEDIATE"):
            await service.record(
                AuditLogRepository(session),
                action="outbound.late-result",
                target_type="test",
            )
        await session.rollback()
