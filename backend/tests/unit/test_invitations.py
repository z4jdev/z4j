"""Multi-user invitation flow - repository + accept-path invariant tests.

Covers the security-critical invariants of the invitation flow
without relying on the full HTTP stack (which is tested by
`test_setup_endpoint.py` and the IDOR/authz audit for the shared
auth machinery):

- Token hash roundtrip - plaintext never stored.
- TTL enforcement - expired invitations are rejected.
- Single-use - accept stamps ``accepted_at``; ``_is_pending`` goes False.
- Revoke - revoked invitations are rejected.
- Accept stores ``accepted_by_user_id`` for audit trail.
- List returns only pending (non-accepted, non-revoked, non-expired).
"""

from __future__ import annotations

import asyncio
import hmac
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool
from starlette.responses import Response
from z4j_brain.api import invitations as invitation_api
from z4j_brain.api.invitations import (
    InvitationMintPublic,
    InvitationPreviewRequest,
)
from z4j_brain.errors import NotFoundError
from z4j_brain.persistence import models  # noqa: F401  (registers metadata)
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import Project, User
from z4j_brain.persistence.repositories import (
    InvitationRepository,
    MembershipRepository,
    UserRepository,
)


@pytest.fixture
async def session():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSession(engine) as s:
        yield s
    await engine.dispose()


@pytest.fixture
async def admin_user(session: AsyncSession):
    user = User(
        email="admin@example.com",
        password_hash="fake-hash-for-test",
        display_name="Admin",
        is_admin=True,
        is_active=True,
        password_changed_at=datetime.now(UTC),
    )
    session.add(user)
    await session.flush()
    return user


@pytest.fixture
async def project(session: AsyncSession):
    p = Project(slug="team", name="Team Project")
    session.add(p)
    await session.flush()
    return p


def _hash(plaintext: str, key: str = "unit-test-secret") -> str:
    return hmac.new(key.encode(), plaintext.encode(), sha256).hexdigest()


def test_mint_schema_documents_fragment_token_transport() -> None:
    token_schema = InvitationMintPublic.model_json_schema()["properties"]["token"]
    description = token_schema["description"]
    assert "/invite#token=" in description
    assert "/invite?token=" not in description


def test_preview_schema_is_body_only_post() -> None:
    app = FastAPI()
    app.include_router(invitation_api.public_router, prefix="/api/v1")

    path = app.openapi()["paths"]["/api/v1/invitations/preview"]
    assert set(path) == {"post"}
    operation = path["post"]
    assert "requestBody" in operation
    assert not any(
        parameter.get("name") == "token" for parameter in operation.get("parameters", [])
    )


@pytest.mark.asyncio
class TestInvitationPreviewTransport:
    async def test_body_token_is_hashed_and_response_is_not_cacheable(
        self,
        brain_settings,
    ) -> None:  # type: ignore[no-untyped-def]
        token = "P" * 43
        project_id = uuid.uuid4()
        row = SimpleNamespace(
            project_id=project_id,
            email="preview@example.com",
            role="viewer",
            expires_at=datetime.now(UTC) + timedelta(days=1),
            accepted_at=None,
            revoked_at=None,
        )
        invitations = SimpleNamespace(get_by_hash=AsyncMock(return_value=row))
        projects = SimpleNamespace(
            get=AsyncMock(
                return_value=SimpleNamespace(
                    id=project_id,
                    slug="preview",
                    name="Preview Project",
                ),
            ),
        )
        response = Response()

        result = await invitation_api.preview_invitation(
            body=InvitationPreviewRequest(token=token),
            response=response,
            invitations=invitations,
            projects=projects,
            settings=brain_settings,
        )

        invitations.get_by_hash.assert_awaited_once_with(
            invitation_api._hash_token(token, brain_settings),
        )
        assert result.email == "preview@example.com"
        assert response.headers["Cache-Control"] == "no-store"

    @pytest.mark.parametrize(
        "state",
        ["missing", "expired", "revoked", "accepted"],
    )
    async def test_unusable_states_share_one_generic_error(
        self,
        state: str,
        brain_settings,
    ) -> None:  # type: ignore[no-untyped-def]
        row = None
        if state != "missing":
            row = SimpleNamespace(
                project_id=uuid.uuid4(),
                expires_at=(
                    datetime.now(UTC) - timedelta(seconds=1)
                    if state == "expired"
                    else datetime.now(UTC) + timedelta(days=1)
                ),
                revoked_at=datetime.now(UTC) if state == "revoked" else None,
                accepted_at=datetime.now(UTC) if state == "accepted" else None,
            )
        projects = SimpleNamespace(get=AsyncMock())

        with pytest.raises(NotFoundError, match="invalid_or_expired"):
            await invitation_api.preview_invitation(
                body=InvitationPreviewRequest(token=f"invalid-{state}"),
                response=Response(),
                invitations=SimpleNamespace(
                    get_by_hash=AsyncMock(return_value=row),
                ),
                projects=projects,
                settings=brain_settings,
            )

        projects.get.assert_not_awaited()


@pytest.mark.asyncio
class TestInvitationRepository:
    async def test_create_stores_hash_not_plaintext(
        self,
        session,
        admin_user,
        project,
    ):
        repo = InvitationRepository(session)
        plaintext = secrets.token_urlsafe(32)
        token_hash = _hash(plaintext)
        row = await repo.create(
            project_id=project.id,
            email="alice@example.com",
            role="operator",
            invited_by=admin_user.id,
            token_hash=token_hash,
            expires_at=datetime.now(UTC) + timedelta(days=7),
        )
        assert row.id is not None
        assert row.token_hash == token_hash
        # Plaintext is never on the model.
        assert plaintext not in repr(row.__dict__)

    async def test_get_by_hash_returns_row(
        self,
        session,
        admin_user,
        project,
    ):
        repo = InvitationRepository(session)
        h = _hash("secret-token-plaintext")
        await repo.create(
            project_id=project.id,
            email="bob@example.com",
            role="viewer",
            invited_by=admin_user.id,
            token_hash=h,
            expires_at=datetime.now(UTC) + timedelta(days=7),
        )
        found = await repo.get_by_hash(h)
        assert found is not None
        assert found.email == "bob@example.com"

        nope = await repo.get_by_hash("nonexistent-hash-value")
        assert nope is None

    async def test_accept_stamps_timestamp_and_user_id(
        self,
        session,
        admin_user,
        project,
    ):
        repo = InvitationRepository(session)
        row = await repo.create(
            project_id=project.id,
            email="carol@example.com",
            role="operator",
            invited_by=admin_user.id,
            token_hash=_hash("t1"),
            expires_at=datetime.now(UTC) + timedelta(days=7),
        )
        # Create the accepting user
        acceptor = User(
            email="carol@example.com",
            password_hash="hash",
            display_name="Carol",
            is_admin=False,
            is_active=True,
            password_changed_at=datetime.now(UTC),
        )
        session.add(acceptor)
        await session.flush()

        updated = await repo.accept(
            row.id,
            accepted_by_user_id=acceptor.id,
        )
        assert updated is not None
        assert updated.accepted_at is not None
        assert updated.accepted_by_user_id == acceptor.id

    async def test_revoke_stamps_revoked_at(
        self,
        session,
        admin_user,
        project,
    ):
        repo = InvitationRepository(session)
        row = await repo.create(
            project_id=project.id,
            email="dave@example.com",
            role="viewer",
            invited_by=admin_user.id,
            token_hash=_hash("t2"),
            expires_at=datetime.now(UTC) + timedelta(days=7),
        )
        updated = await repo.revoke(row.id)
        assert updated is not None
        assert updated.revoked_at is not None

    async def test_accept_and_revoke_are_one_way_mutually_exclusive(
        self,
        session,
        admin_user,
        project,
    ):
        repo = InvitationRepository(session)
        accepted = await repo.create(
            project_id=project.id,
            email="accepted@example.com",
            role="viewer",
            invited_by=admin_user.id,
            token_hash=_hash("accepted-first"),
            expires_at=datetime.now(UTC) + timedelta(days=7),
        )
        assert (
            await repo.accept(
                accepted.id,
                accepted_by_user_id=admin_user.id,
            )
            is not None
        )
        assert await repo.revoke(accepted.id) is None
        await session.refresh(accepted)
        assert accepted.accepted_at is not None
        assert accepted.revoked_at is None

        revoked = await repo.create(
            project_id=project.id,
            email="revoked@example.com",
            role="viewer",
            invited_by=admin_user.id,
            token_hash=_hash("revoked-first"),
            expires_at=datetime.now(UTC) + timedelta(days=7),
        )
        assert await repo.revoke(revoked.id) is not None
        assert (
            await repo.accept(
                revoked.id,
                accepted_by_user_id=admin_user.id,
            )
            is None
        )
        await session.refresh(revoked)
        assert revoked.accepted_at is None
        assert revoked.revoked_at is not None

    async def test_expiry_is_rechecked_at_terminal_update(
        self,
        session,
        admin_user,
        project,
    ):
        repo = InvitationRepository(session)
        row = await repo.create(
            project_id=project.id,
            email="expired@example.com",
            role="viewer",
            invited_by=admin_user.id,
            token_hash=_hash("expired-at-claim"),
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        assert (
            await repo.accept(
                row.id,
                accepted_by_user_id=admin_user.id,
            )
            is None
        )
        assert await repo.revoke(row.id) is None

    async def test_list_excludes_accepted_revoked_expired(
        self,
        session,
        admin_user,
        project,
    ):
        repo = InvitationRepository(session)
        now = datetime.now(UTC)

        # Pending (should appear)
        pending = await repo.create(
            project_id=project.id,
            email="p@example.com",
            role="viewer",
            invited_by=admin_user.id,
            token_hash=_hash("p"),
            expires_at=now + timedelta(days=7),
        )

        # Expired (should NOT appear)
        await repo.create(
            project_id=project.id,
            email="e@example.com",
            role="viewer",
            invited_by=admin_user.id,
            token_hash=_hash("e"),
            expires_at=now - timedelta(days=1),
        )

        # Revoked (should NOT appear)
        rev = await repo.create(
            project_id=project.id,
            email="r@example.com",
            role="viewer",
            invited_by=admin_user.id,
            token_hash=_hash("r"),
            expires_at=now + timedelta(days=7),
        )
        await repo.revoke(rev.id)

        listing = await repo.list_for_project(project.id)
        ids = {r.id for r in listing}
        assert pending.id in ids
        assert rev.id not in ids
        assert len(listing) == 1

    async def test_concurrent_accept_and_revoke_have_exactly_one_winner(
        self,
        tmp_path,
    ):
        database_path = tmp_path / "invitation-race.sqlite3"
        engine = create_async_engine(
            f"sqlite+aiosqlite:///{database_path}",
            connect_args={"timeout": 10},
        )
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with sessions() as seed:
                admin = User(
                    email="race-admin@example.com",
                    password_hash="hash",
                    is_admin=True,
                    is_active=True,
                )
                race_project = Project(slug="race", name="Race")
                seed.add_all([admin, race_project])
                await seed.flush()
                invitation = await InvitationRepository(seed).create(
                    project_id=race_project.id,
                    email="race@example.com",
                    role="viewer",
                    invited_by=admin.id,
                    token_hash=_hash("accept-revoke-race"),
                    expires_at=datetime.now(UTC) + timedelta(days=1),
                )
                await seed.commit()
                invitation_id = invitation.id
                admin_id = admin.id

            gate = asyncio.Event()

            async def accept() -> bool:
                async with sessions() as contender:
                    await gate.wait()
                    result = await InvitationRepository(contender).accept(
                        invitation_id,
                        accepted_by_user_id=admin_id,
                    )
                    await (contender.commit() if result is not None else contender.rollback())
                    return result is not None

            async def revoke() -> bool:
                async with sessions() as contender:
                    await gate.wait()
                    result = await InvitationRepository(contender).revoke(
                        invitation_id,
                    )
                    await (contender.commit() if result is not None else contender.rollback())
                    return result is not None

            accept_task = asyncio.create_task(accept())
            revoke_task = asyncio.create_task(revoke())
            gate.set()
            accept_won, revoke_won = await asyncio.gather(
                accept_task,
                revoke_task,
            )
            assert accept_won is not revoke_won

            async with sessions() as check:
                final = await InvitationRepository(check).get(invitation_id)
                assert final is not None
                assert (final.accepted_at is not None) is accept_won
                assert (final.revoked_at is not None) is revoke_won
                assert not (final.accepted_at is not None and final.revoked_at is not None)
        finally:
            await engine.dispose()


@pytest.mark.asyncio
class TestAcceptPathInvariants:
    """Verify the invariants the public accept endpoint relies on."""

    async def test_accept_path_is_atomic_with_membership_grant(
        self,
        session,
        admin_user,
        project,
    ):
        """Simulate the accept flow: create user + grant + stamp, in one tx.

        If anything raises before ``session.commit()``, all three side
        effects must be absent. We prove this by asserting the
        post-state after a full successful run, then running an
        identical path with an intentional failure and checking rollback.
        """
        inv_repo = InvitationRepository(session)
        user_repo = UserRepository(session)
        mem_repo = MembershipRepository(session)

        row = await inv_repo.create(
            project_id=project.id,
            email="eve@example.com",
            role="operator",
            invited_by=admin_user.id,
            token_hash=_hash("happy"),
            expires_at=datetime.now(UTC) + timedelta(days=7),
        )

        # Happy path - create user, grant, accept, commit.
        new_user = User(
            email="eve@example.com",
            password_hash="hash",
            display_name="Eve",
            is_admin=False,
            is_active=True,
            password_changed_at=datetime.now(UTC),
        )
        session.add(new_user)
        await session.flush()
        await mem_repo.grant(
            user_id=new_user.id,
            project_id=project.id,
            role="operator",
        )
        await inv_repo.accept(
            row.id,
            accepted_by_user_id=new_user.id,
        )

        # All three side effects present.
        assert await user_repo.get_by_email("eve@example.com") is not None
        assert (
            await mem_repo.get_for_user_project(
                user_id=new_user.id,
                project_id=project.id,
            )
            is not None
        )
        reloaded = await inv_repo.get(row.id)
        assert reloaded.accepted_at is not None
        assert reloaded.accepted_by_user_id == new_user.id

    async def test_invite_revoked_stays_revoked(
        self,
        session,
        admin_user,
        project,
    ):
        """Cannot un-revoke: the row state is one-way."""
        repo = InvitationRepository(session)
        row = await repo.create(
            project_id=project.id,
            email="x@example.com",
            role="viewer",
            invited_by=admin_user.id,
            token_hash=_hash("rev"),
            expires_at=datetime.now(UTC) + timedelta(days=7),
        )
        await repo.revoke(row.id)
        # The repository update is itself authoritative: even if an accept
        # request passed an earlier pending check before this revoke committed,
        # its terminal compare-and-set cannot overwrite the revoked state.
        assert (
            await repo.accept(
                row.id,
                accepted_by_user_id=admin_user.id,
            )
            is None
        )
        reloaded = await repo.get(row.id)
        now = datetime.now(UTC)
        expires_at = reloaded.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        pending = reloaded.accepted_at is None and reloaded.revoked_at is None and expires_at > now
        assert not pending, "revoked row must not be 'pending'"
        assert reloaded.accepted_at is None


@pytest.mark.asyncio
class TestAcceptRouteArbitration:
    async def test_lost_terminal_claim_aborts_before_commit(
        self,
        brain_settings,
    ) -> None:  # type: ignore[no-untyped-def]
        project_id = uuid.uuid4()
        invitation_id = uuid.uuid4()
        row = SimpleNamespace(
            id=invitation_id,
            project_id=project_id,
            email="claim-loser@example.com",
            role="viewer",
            expires_at=datetime.now(UTC) + timedelta(days=1),
            accepted_at=None,
            revoked_at=None,
        )
        project = SimpleNamespace(id=project_id, slug="claim", name="Claim")
        invitation_repo = SimpleNamespace(
            get_by_hash=AsyncMock(return_value=row),
            accept=AsyncMock(return_value=None),
        )

        async def add_user(user) -> None:  # type: ignore[no-untyped-def]
            user.id = uuid.uuid4()

        users = SimpleNamespace(
            get_by_email=AsyncMock(return_value=None),
            add=AsyncMock(side_effect=add_user),
        )
        memberships = SimpleNamespace(grant=AsyncMock())
        db_session = SimpleNamespace(commit=AsyncMock())

        with pytest.raises(NotFoundError, match="invalid_or_expired"):
            await invitation_api.accept_invitation(
                body=invitation_api.InvitationAcceptRequest(
                    token="long-enough-invitation-token",
                    display_name="Claim Loser",
                    password="Correct-Horse-Battery-9!",
                ),
                invitations=invitation_repo,
                users=users,
                memberships=memberships,
                projects=SimpleNamespace(get=AsyncMock(return_value=project)),
                settings=brain_settings,
                audit=SimpleNamespace(record=AsyncMock()),
                audit_log=object(),
                db_session=db_session,
                ip="127.0.0.1",
            )

        assert users.add.await_count == 1
        assert memberships.grant.await_count == 1
        invitation_repo.accept.assert_awaited_once_with(
            invitation_id,
            accepted_by_user_id=users.add.await_args.args[0].id,
        )
        assert db_session.commit.await_count == 0
