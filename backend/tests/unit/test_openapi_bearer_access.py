"""Private API docs authenticate bearer keys before serving or auditing them."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.api.api_keys import _hash_api_key
from z4j_brain.main import create_app
from z4j_brain.persistence.models import ApiKey, AuditLog, Project, User
from z4j_brain.settings import Settings


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/v1/openapi.json", "/api/v1/docs"])
@pytest.mark.parametrize(
    ("credential", "expected_status"),
    [
        ("active", 200),
        ("anonymous", 401),
        ("unknown", 401),
        ("revoked", 401),
        ("expired", 401),
        ("inactive_owner", 401),
        ("project_bound", 403),
    ],
)
async def test_private_docs_bearer_authentication(
    path: str,
    credential: str,
    expected_status: int,
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> None:
    settings = Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),
        session_secret=secrets.token_urlsafe(48),
        audit_chain_secret=migrated_audit_chain_secret,
        environment="dev",
        log_json=False,
        registry_backend="local",
        disable_spa_fallback=True,
        openapi_visibility="private",
    )
    engine = create_async_engine(
        settings.database_url,
        pool_size=1,
        max_overflow=0,
        pool_timeout=0.5,
    )
    app = create_app(settings, engine=engine)
    user_id, key_id, project_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    token = f"z4k_{secrets.token_urlsafe(32)}"
    try:
        async with app.state.db.session() as session:
            session.add_all(
                [
                    User(
                        id=user_id,
                        email="docs-reader@example.com",
                        password_hash="unused-password-hash",
                        is_active=credential != "inactive_owner",
                        is_admin=False,
                    ),
                    Project(id=project_id, slug="docs-team", name="Docs Team"),
                ],
            )
            await session.flush()
            session.add(
                ApiKey(
                    id=key_id,
                    user_id=user_id,
                    project_id=project_id if credential == "project_bound" else None,
                    name="Docs reader",
                    prefix=token[:8],
                    token_hash=_hash_api_key(
                        plaintext=token,
                        secret=settings.secret.get_secret_value().encode(),
                    ),
                    scopes=["home:read"],
                    revoked_at=datetime.now(UTC) if credential == "revoked" else None,
                    expires_at=(
                        datetime.now(UTC) - timedelta(seconds=1)
                        if credential == "expired"
                        else None
                    ),
                ),
            )
            await session.commit()

        headers = {}
        if credential != "anonymous":
            presented = f"z4k_{secrets.token_urlsafe(32)}" if credential == "unknown" else token
            headers["Authorization"] = f"Bearer {presented}"
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            response = await client.get(path, headers=headers)
        assert response.status_code == expected_status, response.text[:300]

        async with app.state.db.session() as session:
            rows = list(
                await session.scalars(
                    select(AuditLog).where(AuditLog.action == "openapi.schema_accessed"),
                ),
            )
            key = await session.get(ApiKey, key_id)
            if credential == "active":
                assert len(rows) == 1
                assert rows[0].user_id == user_id
                assert rows[0].target_id == path
                assert rows[0].audit_metadata["auth_kind"] == "api_key"
                assert rows[0].outcome == "allow"
                assert key.last_used_at is not None
                assert response.headers["cache-control"].startswith("private,")
                if path.endswith(".json"):
                    assert "openapi" in response.json()
                else:
                    assert "text/html" in response.headers["content-type"]
            else:
                assert rows == []
                assert key.last_used_at is None
        assert engine.pool.checkedout() == 0
    finally:
        await engine.dispose()
