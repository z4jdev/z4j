"""``api_keys.last_used_at`` still gets written, and nothing waits on it.

The stamp is the only record that a key is in use, so it is what an operator
reads before revoking one. It is written on a session of its own, which means
a connection of its own, and the request that triggers it is holding one for
its whole life. Taken during the request that second checkout waits behind
the first, and ``pool_size=1, max_overflow=0`` is a size this brain permits,
so the wait was for a connection that was never coming.

Timing alone is a weak assertion here: deleting the write would also make the
request fast. So these pin both halves -- the stamp lands, and it lands
without the request waiting for it.
"""

from __future__ import annotations

import asyncio
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from z4j_brain.api import deps as deps_module
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401  register mappers
from z4j_brain.persistence.database import create_engine_from_settings
from z4j_brain.persistence.models import ApiKey, Project, User
from z4j_brain.settings import Settings

_URL = "/api/v1/health/deep"
_PW = "correct-horse-battery-staple-9"

#: Comfortably longer than this request needs and far below SQLAlchemy's 30s
#: default pool-checkout timeout, so a request waiting for a connection it
#: will never get fails here instead of passing slowly.
_ONE_CONNECTION_BUDGET_S: float = 5.0


def _settings(database_url: str, audit_chain_secret: str) -> Settings:
    return Settings(
        database_url=database_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        audit_chain_secret=audit_chain_secret,  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        disable_spa_fallback=True,
        # The configuration the stall needs: one connection, no overflow.
        database_pool_size=1,
        database_max_overflow=0,
    )


async def _seed_key(app, settings: Settings) -> tuple[uuid.UUID, str]:
    """One active user plus one bearer key that has never been used."""

    from z4j_brain.api.api_keys import _hash_api_key
    from z4j_brain.auth.passwords import PasswordHasher

    plaintext = f"z4k_{secrets.token_urlsafe(32)}"
    key_id = uuid.uuid4()
    db = app.state.db
    async with db.session() as session:
        project = (
            await session.execute(select(Project).where(Project.slug == "default"))
        ).scalar_one_or_none()
        if project is None:
            session.add(Project(id=uuid.uuid4(), slug="default", name="default"))
        user = User(
            id=uuid.uuid4(),
            email=f"{uuid.uuid4().hex[:10]}@example.test",
            password_hash=PasswordHasher(settings).hash(_PW),
            is_active=True,
        )
        session.add(user)
        await session.flush()
        session.add(
            ApiKey(
                id=key_id,
                user_id=user.id,
                name="probe",
                token_hash=_hash_api_key(
                    plaintext=plaintext,
                    secret=settings.secret.get_secret_value().encode("utf-8"),
                ),
                prefix=plaintext[:8],
                scopes=["home:read"],
            ),
        )
        await session.commit()
    return key_id, plaintext


async def _read_key(app, key_id: uuid.UUID) -> ApiKey:
    async with app.state.db.session() as session:
        return (await session.execute(select(ApiKey).where(ApiKey.id == key_id))).scalar_one()


@pytest.fixture(autouse=True)
def _fresh_touch_throttle():
    """The sampling window is process-global; do not inherit another test's."""

    deps_module._touch_last_committed.clear()
    yield
    deps_module._touch_last_committed.clear()


@pytest.mark.asyncio
async def test_bearer_use_is_stamped_on_a_one_connection_pool(
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> None:
    """The stamp lands, and the request that produced it did not wait for it.

    Driven through a real request on an engine the product's own factory
    built from the operator's own setting. The migrated fixture is
    file-backed, which this needs: in-memory SQLite gets a StaticPool, which
    has no size and therefore cannot exhibit the contention at all.
    """
    settings = _settings(migrated_db_url, migrated_audit_chain_secret)
    engine = create_engine_from_settings(settings)
    try:
        assert engine.pool.size() == 1, "the pool under test is not the pool configured"
        app = create_app(settings, engine=engine)
        app.state.lifespan_ready = True
        key_id, plaintext = await _seed_key(app, settings)

        before = await _read_key(app, key_id)
        assert before.last_used_at is None, "the fixture key starts unused"

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            try:
                response = await asyncio.wait_for(
                    client.get(
                        _URL,
                        headers={"Authorization": f"Bearer {plaintext}"},
                    ),
                    timeout=_ONE_CONNECTION_BUDGET_S,
                )
            except TimeoutError:
                pytest.fail(
                    f"a bearer request did not answer within "
                    f"{_ONE_CONNECTION_BUDGET_S}s on pool_size=1, max_overflow=0: "
                    "the last-used bookkeeping is waiting for a second "
                    "connection that this pool will never hand out",
                )

        assert response.status_code == 200, response.text

        after = await _read_key(app, key_id)
        assert after.last_used_at is not None, (
            "the key authenticated a request and the table still says it has "
            "never been used, which is what an operator reads before revoking"
        )
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_second_use_inside_the_window_is_not_written_again(
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> None:
    """The sampling window survived moving the write off the request path.

    Deciding the sample later must not turn one write per key per minute back
    into one write per request, which is the cost the sampling exists to
    avoid.
    """
    settings = _settings(migrated_db_url, migrated_audit_chain_secret)
    engine = create_engine_from_settings(settings)
    try:
        app = create_app(settings, engine=engine)
        app.state.lifespan_ready = True
        key_id, plaintext = await _seed_key(app, settings)
        headers = {"Authorization": f"Bearer {plaintext}"}

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            assert (await client.get(_URL, headers=headers)).status_code == 200
            first = (await _read_key(app, key_id)).last_used_at
            assert first is not None

            # Rewind the stored stamp. A second write inside the window would
            # move it back to "now"; a sampled request leaves it where it is.
            async with app.state.db.session() as session:
                key = (
                    await session.execute(select(ApiKey).where(ApiKey.id == key_id))
                ).scalar_one()
                key.last_used_at = datetime.now(UTC) - timedelta(days=1)
                await session.commit()
            rewound = (await _read_key(app, key_id)).last_used_at

            assert (await client.get(_URL, headers=headers)).status_code == 200

        assert (await _read_key(app, key_id)).last_used_at == rewound
    finally:
        await engine.dispose()


def _utc(value: datetime) -> datetime:
    """SQLite gives a ``DateTime(timezone=True)`` column back naive."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


async def _drain_a_parked_touch(app, key_id: uuid.UUID, *, ip: str, when: datetime) -> None:
    """Run the bookkeeping the way a finishing request runs it.

    ``_drain_api_key_touch`` is where a request's parked stamp is written,
    and the stamp it writes is the one taken when the key AUTHENTICATED, not
    when this runs. Requests therefore reach here in the order they finish,
    which is not the order they started.
    """
    from starlette.requests import Request

    request = Request({"type": "http", "app": app, "state": {}})
    setattr(request.state, deps_module._TOUCH_STATE_ATTR, (key_id, ip, when))
    await deps_module._drain_api_key_touch(request)


@pytest.mark.asyncio
async def test_a_slow_request_cannot_rewind_the_stamp_a_later_one_left(
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> None:
    """Two requests, finishing in the opposite order from the one they began.

    The pair is read as evidence: an operator deciding whether a leaked key
    has been used since checks when it was last used and from where. A stamp
    that walks backwards, dragging an older address with it, answers that
    question wrongly rather than merely untidily.
    """
    settings = _settings(migrated_db_url, migrated_audit_chain_secret)
    engine = create_engine_from_settings(settings)
    try:
        app = create_app(settings, engine=engine)
        app.state.lifespan_ready = True
        key_id, plaintext = await _seed_key(app, settings)

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            response = await client.get(
                _URL,
                headers={"Authorization": f"Bearer {plaintext}"},
            )
        assert response.status_code == 200, response.text
        authenticated_at = _utc((await _read_key(app, key_id)).last_used_at)

        # Clearing the sampling window between drains is load-bearing: inside
        # it the drain returns before it opens a session, and both writes
        # below would be skipped without ever reaching the repository.
        deps_module._touch_last_committed.clear()
        later = authenticated_at + timedelta(minutes=2)
        await _drain_a_parked_touch(app, key_id, ip="198.51.100.2", when=later)

        moved = await _read_key(app, key_id)
        assert _utc(moved.last_used_at) == later, "a later use must advance the stamp"
        assert moved.last_used_ip == "198.51.100.2"

        # The straggler: it authenticated a minute after the row's stamp was
        # taken but a minute BEFORE the use now recorded there, and it is
        # only finishing now.
        deps_module._touch_last_committed.clear()
        earlier = authenticated_at + timedelta(minutes=1)
        await _drain_a_parked_touch(app, key_id, ip="203.0.113.7", when=earlier)

        final = await _read_key(app, key_id)
        assert _utc(final.last_used_at) == later, (
            "the newest use is what the table has to report, whatever order "
            "the requests that made them happened to finish in"
        )
        assert final.last_used_ip == "198.51.100.2", (
            "the address travels with the stamp; rewinding one rewinds both"
        )
    finally:
        await engine.dispose()
