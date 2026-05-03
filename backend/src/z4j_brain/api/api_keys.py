"""``/api/v1/api-keys`` REST router - personal API key management.

Dashboard users create API keys for programmatic access (CI/CD,
scripts, Grafana). The plaintext token is returned exactly once
on creation; only the HMAC-SHA256 hash is stored.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, field_validator

from z4j_brain.api.deps import (
    get_audit_log_repo,
    get_audit_service,
    get_client_ip,
    get_current_user,
    get_session,
    get_settings,
    require_csrf,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.models import User
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
    )
    from z4j_brain.settings import Settings


router = APIRouter(prefix="/api-keys", tags=["api-keys"])

#: Token prefix that helps users identify z4j API keys in configs.
_TOKEN_PREFIX = "z4k_"

#: Salt for API key HMAC - distinct from agent token salt so the
#: same secret cannot collide between the two surfaces.
_API_KEY_SALT: bytes = b"z4j-api-key-v1"


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ApiKeyPublic(BaseModel):
    """Public representation of an API key (no plaintext)."""

    id: uuid.UUID
    name: str
    prefix: str
    scopes: list[str]
    project_id: uuid.UUID | None
    project_slug: str | None
    last_used_at: datetime | None
    last_used_ip: str | None
    expires_at: datetime | None
    revoked_at: datetime | None
    revoked_reason: str | None
    created_at: datetime


class ApiKeyCreated(ApiKeyPublic):
    """Response from key creation - includes the plaintext token.

    The token is shown exactly once. It cannot be retrieved later.
    """

    token: str


class CreateApiKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    # Round-8 audit fix R8-Pyd-H6 (Apr 2026): cap list cardinality
    # AND per-element length. Pre-fix the list was unbounded and
    # each scope string was unbounded, so a 1M-element list of
    # 100KB strings reached ``validate_requested_scopes`` before
    # rejection. ``ALL_SCOPES`` has tens of values; 64 leaves
    # plenty of headroom.
    scopes: list[str] = Field(
        default_factory=list,
        max_length=64,
        description=(
            "Catalogue of allowed actions. See "
            "z4j_brain.auth.scopes.ALL_SCOPES for valid values. "
            "An empty list mints a powerless token."
        ),
    )

    @field_validator("scopes")
    @classmethod
    def _cap_scope_strings(cls, v: list[str]) -> list[str]:
        for entry in v:
            if not isinstance(entry, str):
                raise ValueError("scope entries must be strings")
            if len(entry) > 64:
                raise ValueError(
                    "scope entries are bounded to 64 characters",
                )
        return v
    project_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Bind this token to a single project. When set, any "
            "request that targets a different project is rejected "
            "with 403, regardless of ``scopes``."
        ),
    )
    expires_in_days: int | None = Field(
        default=None,
        ge=1,
        le=3650,
        description="Key lifetime in days. Null means never expires.",
    )


class ScopeCatalogue(BaseModel):
    """Served by ``GET /api-keys/scopes`` so the UI stays in sync."""

    scopes: list[str]
    admin_only: list[str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash_api_key(*, plaintext: str, secret: bytes) -> str:
    """HMAC-SHA256 hex digest of a personal API key.

    Uses a distinct salt from agent tokens so the same master
    secret cannot produce collisions across the two surfaces.
    """
    import hashlib
    import hmac

    h = hmac.new(
        secret + _API_KEY_SALT,
        plaintext.encode("utf-8"),
        hashlib.sha256,
    )
    return h.hexdigest()


def _key_payload(
    key,  # type: ignore[no-untyped-def]
    *,
    project_slug: str | None = None,
) -> ApiKeyPublic:
    """Build the public response from an ApiKey row.

    ``project_slug`` is resolved by the caller so this function
    stays DB-free; the caller already has to load the project row
    when it wants to render the slug.
    """
    return ApiKeyPublic(
        id=key.id,
        name=key.name,
        prefix=key.prefix,
        scopes=list(key.scopes or []),
        project_id=key.project_id,
        project_slug=project_slug,
        last_used_at=key.last_used_at,
        last_used_ip=key.last_used_ip,
        expires_at=key.expires_at,
        revoked_at=key.revoked_at,
        revoked_reason=key.revoked_reason,
        created_at=key.created_at,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/scopes", response_model=ScopeCatalogue)
async def list_scopes() -> ScopeCatalogue:
    """Catalogue of scopes the UI can offer at mint time.

    Unauthenticated by design - the shape is static and helps
    docs/tooling without leaking anything sensitive. Deployments
    that want to hide this can strip the endpoint at a reverse
    proxy; the brain does not.
    """
    from z4j_brain.auth.scopes import ADMIN_ONLY_SCOPES, ALL_SCOPES

    return ScopeCatalogue(
        scopes=list(ALL_SCOPES),
        admin_only=sorted(ADMIN_ONLY_SCOPES),
    )


@router.get("", response_model=list[ApiKeyPublic])
async def list_api_keys(
    user: "User" = Depends(get_current_user),
    db_session: "AsyncSession" = Depends(get_session),
) -> list[ApiKeyPublic]:
    """List all active (non-revoked) API keys for the current user.

    Never returns the plaintext token - only the prefix for
    identification.
    """
    from sqlalchemy import select

    from z4j_brain.persistence.models import Project
    from z4j_brain.persistence.repositories.api_keys import ApiKeyRepository

    repo = ApiKeyRepository(db_session)
    keys = await repo.list_for_user(user.id)
    # Single IN-query to resolve project slugs in one hop, instead
    # of one round trip per distinct project across the user's keys.
    project_ids = {k.project_id for k in keys if k.project_id is not None}
    slug_by_id: dict[uuid.UUID, str] = {}
    if project_ids:
        rows = (
            await db_session.execute(
                select(Project.id, Project.slug).where(
                    Project.id.in_(project_ids),
                ),
            )
        ).all()
        slug_by_id = {r.id: r.slug for r in rows}
    return [
        _key_payload(k, project_slug=slug_by_id.get(k.project_id))
        for k in keys
    ]


@router.post(
    "",
    response_model=ApiKeyCreated,
    status_code=201,
    dependencies=[Depends(require_csrf)],
)
async def create_api_key(
    body: CreateApiKeyRequest,
    user: "User" = Depends(get_current_user),
    settings: "Settings" = Depends(get_settings),
    audit: "AuditService" = Depends(get_audit_service),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> ApiKeyCreated:
    """Create a new personal API key.

    The plaintext token is returned ONCE in the response. Only the
    HMAC-SHA256 hash is stored. If the user loses the plaintext they
    must revoke the key and create a new one.

    Token format: ``z4k_`` prefix + 32 bytes urlsafe base64.
    """
    from z4j_brain.auth.scopes import validate_requested_scopes
    from z4j_brain.errors import ConflictError, NotFoundError
    from z4j_brain.persistence.repositories import (
        MembershipRepository,
        ProjectRepository,
    )
    from z4j_brain.persistence.repositories.api_keys import ApiKeyRepository

    # ------------------------------------------------------------
    # Scope validation. Typos or admin-only requests from a
    # non-admin caller get rejected up front with a helpful message
    # instead of silently dropping the scope.
    # ------------------------------------------------------------
    accepted, rejected = validate_requested_scopes(
        requested=body.scopes, user_is_admin=bool(user.is_admin),
    )
    if rejected:
        raise ConflictError(
            "one or more requested scopes are not granted",
            details={"rejected_scopes": rejected},
        )

    # ------------------------------------------------------------
    # Project-scope validation. The caller must actually be a
    # member of the project (or a global admin). Otherwise any
    # user could mint a cross-project token.
    # ------------------------------------------------------------
    project_slug: str | None = None
    if body.project_id is not None:
        projects_repo = ProjectRepository(db_session)
        project = await projects_repo.get(body.project_id)
        if project is None or not project.is_active:
            raise NotFoundError(
                "project not found",
                details={"project_id": str(body.project_id)},
            )
        if not user.is_admin:
            memberships = MembershipRepository(db_session)
            member = await memberships.get_for_user_project(
                user_id=user.id, project_id=project.id,
            )
            if member is None:
                raise ConflictError(
                    "cannot bind an API key to a project you do not belong to",
                    details={"project_id": str(body.project_id)},
                )
        project_slug = project.slug

    # Mint the plaintext token.
    raw_bytes = secrets.token_urlsafe(32)
    plaintext = f"{_TOKEN_PREFIX}{raw_bytes}"
    prefix = plaintext[:8]

    # Hash with the API-key-specific salt.
    secret = settings.secret.get_secret_value().encode("utf-8")
    token_hash = _hash_api_key(plaintext=plaintext, secret=secret)

    # Compute expiration if requested.
    expires_at: datetime | None = None
    if body.expires_in_days is not None:
        expires_at = datetime.now(UTC) + timedelta(days=body.expires_in_days)

    repo = ApiKeyRepository(db_session)
    api_key = await repo.create(
        user_id=user.id,
        name=body.name.strip(),
        token_hash=token_hash,
        prefix=prefix,
        scopes=accepted,
        project_id=body.project_id,
        expires_at=expires_at,
    )

    await audit.record(
        audit_log,
        action="api_key.created",
        target_type="api_key",
        target_id=str(api_key.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=body.project_id,
        source_ip=ip,
        metadata={
            "name": body.name.strip(),
            "scopes": accepted,
            "project_scoped": body.project_id is not None,
        },
    )
    await db_session.commit()

    return ApiKeyCreated(
        id=api_key.id,
        name=api_key.name,
        prefix=api_key.prefix,
        scopes=accepted,
        project_id=api_key.project_id,
        project_slug=project_slug,
        last_used_at=api_key.last_used_at,
        last_used_ip=api_key.last_used_ip,
        expires_at=api_key.expires_at,
        revoked_at=api_key.revoked_at,
        revoked_reason=api_key.revoked_reason,
        created_at=api_key.created_at,
        token=plaintext,
    )


@router.delete(
    "/{key_id}",
    status_code=204,
    dependencies=[Depends(require_csrf)],
)
async def revoke_api_key(
    key_id: uuid.UUID,
    user: "User" = Depends(get_current_user),
    audit: "AuditService" = Depends(get_audit_service),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> None:
    """Revoke (soft-delete) a personal API key.

    Sets ``revoked_at`` on the key. The key can no longer be used
    for authentication but remains in the database for audit
    purposes.
    """
    from z4j_brain.errors import NotFoundError
    from z4j_brain.persistence.repositories.api_keys import ApiKeyRepository

    repo = ApiKeyRepository(db_session)
    revoked = await repo.revoke(key_id, user.id)
    if not revoked:
        raise NotFoundError(
            "api key not found",
            details={"key_id": str(key_id)},
        )

    await audit.record(
        audit_log,
        action="api_key.revoked",
        target_type="api_key",
        target_id=str(key_id),
        result="success",
        outcome="allow",
        user_id=user.id,
        source_ip=ip,
    )
    await db_session.commit()


__all__ = ["router"]
