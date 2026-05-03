"""User-scoped notification endpoints.

All routes are under ``/api/v1/user/`` and operate on the
authenticated user's own data only.

Three resources:

- ``/user/channels``       - personal delivery destinations
- ``/user/subscriptions``  - per-(project, trigger) delivery rules
- ``/user/notifications``  - in-app inbox (the bell)

The user can ONLY ever see / write their own resources. Project
admin permissions don't grant access to other users' personal
data even within projects they administer.
"""

from __future__ import annotations

import copy
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import IntegrityError

from z4j_brain.api.deps import (
    get_audit_log_repo,
    get_audit_service,
    get_current_user,
    get_membership_repo,
    get_project_repo,
    get_session,
    require_csrf,
)
from z4j_brain.api.notifications import ChannelTestRequest, ChannelTestResult
from z4j_brain.domain.ip_rate_limit import (
    require_channel_import_throttle,
    require_channel_test_throttle,
)
from z4j_brain.domain.notifications.channels import (
    validate_smtp_config,
    validate_telegram_config,
    validate_webhook_headers,
    validate_webhook_url,
)
from z4j_brain.errors import ConflictError
from z4j_brain.persistence.enums import ProjectRole

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.models import User
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        MembershipRepository,
        ProjectRepository,
    )


router = APIRouter(prefix="/user", tags=["user-notifications"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


_TRIGGER_PATTERN = (
    r"^(task\.failed|task\.succeeded|task\.retried|"
    r"task\.slow|agent\.offline|agent\.online)$"
)
_CHANNEL_TYPE_PATTERN = r"^(webhook|email|slack|telegram|pagerduty|discord)$"

_SENSITIVE_KEYS = (
    "smtp_pass",
    "hmac_secret",
    "bot_token",
    "password",
    "integration_key",
)
_MASK = "••••••••"


def _mask(config: dict[str, Any]) -> dict[str, Any]:
    safe = dict(config)
    for k in _SENSITIVE_KEYS:
        if k in safe and safe[k]:
            safe[k] = _MASK
    return safe


def _safe_merge_config(
    existing: dict[str, Any],
    incoming: dict[str, Any],
    *,
    mask: str,
) -> tuple[dict[str, Any], bool]:
    """Merge a PATCH config payload onto an existing channel config.

    HIGH-01 fix. Two related credential bugs are solved here:

    1. Clients that render a channel and POST it back unchanged send
       the MASK placeholder ("••••••••") in place of the real secret.
       Naive ``dict.update`` would overwrite the real password with
       bullets. We DROP any incoming value equal to the mask so the
       existing secret is preserved.

    2. If the caller changes the URL (e.g. from a legitimate webhook
       to ``http://attacker.com``) without also re-supplying the
       credentials, the attacker would inherit the signed payloads
       or SMTP password ("URL-pivot credential harvest"). When the
       url/webhook_url changes we forcibly clear every sensitive
       key from the merged config so the user must re-enter them.

    Returns ``(merged, url_changed)``.
    """
    merged = dict(existing or {})
    scrubbed: dict[str, Any] = {}
    for k, v in (incoming or {}).items():
        if k in _SENSITIVE_KEYS and v == mask:
            # Preserve existing secret - client just echoed the mask.
            continue
        scrubbed[k] = v

    url_changed = False
    for url_key in ("url", "webhook_url"):
        if url_key in scrubbed and scrubbed[url_key] != merged.get(url_key):
            url_changed = True
            break

    merged.update(scrubbed)

    if url_changed:
        for sk in _SENSITIVE_KEYS:
            merged.pop(sk, None)

    return merged, url_changed


async def _validate_channel_config(
    channel_type: str,
    config: dict[str, Any] | None,
) -> None:
    """Validate a user channel config. Raises ``ConflictError`` on
    unsafe input. Only keys present in ``config`` are checked, so
    PATCH payloads work too.

    Previously this validator only covered webhook + slack - the
    telegram + email paths slipped through unchecked, giving any
    authenticated user an SSRF and a blind SMTP egress primitive
    on their own channel (external audit High #2 + #3). Every
    channel type is now validated via the shared domain-level
    helpers so the project-admin and user paths stay in sync.
    """
    if not config:
        return
    if channel_type == "webhook":
        if "url" in config:
            err = await validate_webhook_url(config.get("url", ""))
            if err:
                raise ConflictError(f"unsafe URL: {err}")
        if "headers" in config:
            header_err, _ = validate_webhook_headers(config.get("headers"))
            if header_err:
                raise ConflictError(f"unsafe headers: {header_err}")
    elif channel_type == "slack":
        if "webhook_url" in config:
            err = await validate_webhook_url(config.get("webhook_url", ""))
            if err:
                raise ConflictError(f"unsafe URL: {err}")
    elif channel_type == "telegram":
        err = validate_telegram_config(config)
        if err:
            raise ConflictError(f"unsafe telegram config: {err}")
    elif channel_type == "email":
        err = await validate_smtp_config(config)
        if err:
            raise ConflictError(f"unsafe email config: {err}")
    elif channel_type == "pagerduty":
        from z4j_brain.domain.notifications.channels import (
            validate_pagerduty_config,
        )
        err = validate_pagerduty_config(config)
        if err:
            raise ConflictError(f"invalid pagerduty config: {err}")
    elif channel_type == "discord":
        from z4j_brain.domain.notifications.channels import (
            validate_discord_config,
        )
        err = validate_discord_config(config)
        if err:
            raise ConflictError(f"invalid discord config: {err}")
        url = config.get("webhook_url", "")
        if url:
            err = await validate_webhook_url(url)
            if err:
                raise ConflictError(f"unsafe discord webhook URL: {err}")


class SubscriptionFilters(BaseModel):
    """Strict shape for subscription filter JSON.

    HIGH-06: the service's ``_matches_filters`` expects typed fields
    (e.g. ``priority`` is a list of strings). Without this model the
    API accepted arbitrary shapes and silently dropped mistyped
    filters, so users would see unfiltered floods of notifications.
    ``task_name_pattern`` is capped to prevent pathological fnmatch
    patterns from reaching the dispatcher.

    v1.0.19: ``extra=ignore`` (was ``forbid``) so a newer dashboard
    bundle that adds an unknown filter key can still PATCH against
    an older brain without 422'ing. The unknown key is silently
    dropped (the old brain's dispatcher wouldn't apply it
    anyway). Trade typo-detection for rolling-upgrade safety -
    documented in docs/MIGRATIONS.md.
    """

    priority: list[Literal["critical", "high", "normal", "low"]] | None = None
    task_name: str | None = Field(default=None, max_length=500)
    task_name_pattern: str | None = Field(default=None, max_length=200)
    queue: str | None = Field(default=None, max_length=200)
    model_config = {"extra": "ignore"}


# -- User channels ----------------------------------------------------------


class UserChannelCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    type: str = Field(pattern=_CHANNEL_TYPE_PATTERN)
    config: dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True

    @field_validator("config")
    @classmethod
    def _check_config_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        # Audit P-8: cap config size at the request boundary (16 KiB
        # JSON-serialized) so a hostile or runaway client can't bloat
        # the channel row.
        from z4j_brain.api.notifications import _validate_config_size

        return _validate_config_size(v) or {}


class UserChannelUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    config: dict[str, Any] | None = None
    is_active: bool | None = None

    @field_validator("config")
    @classmethod
    def _check_config_size(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        from z4j_brain.api.notifications import _validate_config_size

        return _validate_config_size(v)


class UserChannelPublic(BaseModel):
    id: uuid.UUID
    name: str
    type: str
    config: dict[str, Any]
    is_verified: bool
    is_active: bool
    created_at: datetime
    updated_at: datetime


class UserChannelImportFromProjectRequest(BaseModel):
    """Body for ``POST /user/channels/import_from_project`` (v1.0.14).

    Caller wants a personal copy of a channel that already exists
    in one of their projects (e.g. the project Slack webhook, but
    routed to their inbox via a personal subscription). Backend
    copies the row server-side so the unmasked secret never crosses
    the wire.

    Caller MUST be a project admin because the operation copies
    secret-bearing delivery config into a personal scope. The
    channel must belong to that project.
    """
    project_slug: str = Field(min_length=1, max_length=63)
    channel_id: uuid.UUID
    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        description=(
            "Override the imported channel's name. Defaults to "
            "'Copy of {original}' if omitted."
        ),
    )
    model_config = {"extra": "forbid"}


# -- User subscriptions -----------------------------------------------------


class UserSubscriptionCreate(BaseModel):
    # ``extra=forbid`` rejects unknown body keys so a future
    # refactor that accidentally re-adds a ``user_id`` /
    # privilege-controlling field can't silently bypass the
    # membership check (R3 M11 defence in depth - the caller's
    # identity is already established from the session cookie).
    model_config = {"extra": "forbid"}

    project_id: uuid.UUID
    trigger: str = Field(pattern=_TRIGGER_PATTERN)
    filters: SubscriptionFilters = Field(default_factory=SubscriptionFilters)
    in_app: bool = True
    # Round-8 audit fix R8-Pyd-H5 (Apr 2026): cap channel_ids lists.
    project_channel_ids: list[uuid.UUID] = Field(
        default_factory=list, max_length=64,
    )
    user_channel_ids: list[uuid.UUID] = Field(
        default_factory=list, max_length=64,
    )
    cooldown_seconds: int = Field(default=0, ge=0, le=86400)


class UserSubscriptionUpdate(BaseModel):
    """Body for ``PATCH /user/subscriptions/{sub_id}``.

    Every field is optional; only keys actually present mutate the
    row. v1.0.18 added ``trigger`` for parity with the project
    default-subscription update endpoint - lets users rename a
    subscription without delete-and-recreate.
    """

    trigger: str | None = Field(default=None, pattern=_TRIGGER_PATTERN)
    filters: SubscriptionFilters | None = None
    in_app: bool | None = None
    # Round-8 audit fix R8-Pyd-H5 (Apr 2026).
    project_channel_ids: list[uuid.UUID] | None = Field(
        default=None, max_length=64,
    )
    user_channel_ids: list[uuid.UUID] | None = Field(
        default=None, max_length=64,
    )
    cooldown_seconds: int | None = Field(default=None, ge=0, le=86400)
    muted_until: datetime | None = None
    is_active: bool | None = None


class UserSubscriptionPublic(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    project_id: uuid.UUID
    trigger: str
    filters: dict[str, Any]
    in_app: bool
    project_channel_ids: list[uuid.UUID]
    user_channel_ids: list[uuid.UUID]
    muted_until: datetime | None
    cooldown_seconds: int
    last_fired_at: datetime | None
    is_active: bool
    created_at: datetime
    updated_at: datetime


class UserSubscriptionsListPublic(BaseModel):
    """Paged list of user subscriptions (v1.1.0 N+1 fix).

    Pre-1.1 ``GET /user/subscriptions`` returned a bare
    ``list[UserSubscriptionPublic]`` and would have linearly grown
    with the user's per-project subscription count. We switch to a
    cursor-paged envelope keyed on ``(project_id, trigger, id)``
    to keep response time bounded as a power user accumulates
    subscriptions across many projects.

    Breaking change vs 1.0.x: clients that iterated the response
    directly must now read ``response.items``.
    """

    items: list[UserSubscriptionPublic]
    next_cursor: str | None


def _encode_user_subscriptions_cursor(
    project_id: uuid.UUID, trigger: str, sub_id: uuid.UUID,
) -> str:
    return f"{project_id.hex}|{trigger}|{sub_id.hex}"


def _decode_user_subscriptions_cursor(
    raw: str | None,
) -> tuple[uuid.UUID | None, str | None, uuid.UUID | None]:
    if not raw:
        return None, None, None
    parts = raw.split("|", 2)
    if len(parts) != 3:
        return None, None, None
    try:
        project_id = uuid.UUID(parts[0])
        sub_id = uuid.UUID(parts[2])
    except ValueError:
        return None, None, None
    return project_id, parts[1], sub_id


# -- In-app notifications ---------------------------------------------------


class UserNotificationPublic(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    subscription_id: uuid.UUID | None
    trigger: str
    reason: str
    title: str
    body: str | None
    data: dict[str, Any]
    read_at: datetime | None
    created_at: datetime


class UnreadCountPublic(BaseModel):
    unread: int


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------


def _channel_payload(c: Any) -> UserChannelPublic:
    return UserChannelPublic(
        id=c.id,
        name=c.name,
        type=c.type,
        config=_mask(c.config or {}),
        is_verified=c.is_verified,
        is_active=c.is_active,
        created_at=c.created_at,
        updated_at=c.updated_at,
    )


def _subscription_payload(s: Any) -> UserSubscriptionPublic:
    return UserSubscriptionPublic(
        id=s.id,
        user_id=s.user_id,
        project_id=s.project_id,
        trigger=s.trigger,
        filters=s.filters or {},
        in_app=s.in_app,
        project_channel_ids=list(s.project_channel_ids or []),
        user_channel_ids=list(s.user_channel_ids or []),
        muted_until=s.muted_until,
        cooldown_seconds=s.cooldown_seconds,
        last_fired_at=s.last_fired_at,
        is_active=s.is_active,
        created_at=s.created_at,
        updated_at=s.updated_at,
    )


def _notification_payload(n: Any) -> UserNotificationPublic:
    return UserNotificationPublic(
        id=n.id,
        project_id=n.project_id,
        subscription_id=n.subscription_id,
        trigger=n.trigger,
        reason=n.reason,
        title=n.title,
        body=n.body,
        data=n.data or {},
        read_at=n.read_at,
        created_at=n.created_at,
    )


# ---------------------------------------------------------------------------
# /user/channels
# ---------------------------------------------------------------------------


@router.get("/channels", response_model=list[UserChannelPublic])
async def list_user_channels(
    user: "User" = Depends(get_current_user),
    db_session: "AsyncSession" = Depends(get_session),
) -> list[UserChannelPublic]:
    from z4j_brain.persistence.repositories import UserChannelRepository

    rows = await UserChannelRepository(db_session).list_for_user(user.id)
    return [_channel_payload(r) for r in rows]


@router.post(
    "/channels",
    response_model=UserChannelPublic,
    status_code=201,
    dependencies=[Depends(require_csrf)],
)
async def create_user_channel(
    body: UserChannelCreate,
    user: "User" = Depends(get_current_user),
    db_session: "AsyncSession" = Depends(get_session),
) -> UserChannelPublic:
    from z4j_brain.persistence.models.notification import UserChannel

    # SSRF / header validation BEFORE persisting. Blocks private-IP
    # webhooks and auth-header smuggling at the entry point.
    await _validate_channel_config(body.type, body.config)
    channel = UserChannel(
        user_id=user.id,
        name=body.name,
        type=body.type,
        config=body.config,
        is_active=body.is_active,
    )
    db_session.add(channel)
    await db_session.flush()
    try:
        await db_session.commit()
    except IntegrityError:
        await db_session.rollback()
        raise ConflictError("channel already exists") from None
    await db_session.refresh(channel)
    return _channel_payload(channel)


@router.post(
    "/channels/import_from_project",
    response_model=UserChannelPublic,
    status_code=201,
    dependencies=[
        Depends(require_csrf),
        Depends(require_channel_import_throttle),
    ],
)
async def import_user_channel_from_project(
    body: UserChannelImportFromProjectRequest,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> UserChannelPublic:
    """Copy a project's channel into the caller's personal channels.

    Use case: the project has a verified Slack webhook / Telegram
    bot / PagerDuty key. A member wants the same destination as
    their personal channel (so they can attach it to subscriptions
    that aren't part of the project's defaults, or use it across
    multiple projects without re-pasting the secret).

    Server-side copy: the source NotificationChannel's config (incl.
    real secrets) is read directly from the DB and written to a new
    UserChannel owned by the caller. The unmasked secret never
    crosses the wire.

    Permission model:
      - Caller must be a project admin. A read-only member can use a
        project channel in subscriptions, but cannot copy its secret
        config into a personal channel and then export/reuse it
        across projects.
      - Source channel must belong to that project.
      - Re-validates through the same SSRF / format guards used at
        create time.
    """
    from z4j_brain.errors import NotFoundError
    from z4j_brain.persistence.models.notification import UserChannel
    from z4j_brain.persistence.repositories import (
        NotificationChannelRepository,
    )

    # Resolve slug -> project_id via the policy engine, then verify
    # the caller has membership. Mirrors the pattern in
    # api/notifications.py::_resolve_member_project but keeps the
    # logic local so we don't cross-module-import a private helper.
    from z4j_brain.domain.policy_engine import PolicyEngine

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, body.project_slug)
    project_id = project.id

    # This copies the real, unmasked channel secret server-side.
    # Project viewers/operators may reference project channels in
    # subscriptions, but they cannot clone those credentials into a
    # personal scope where they could be re-exported to another project.
    await policy.require_member(
        memberships,
        user=user,
        project_id=project_id,
        min_role=ProjectRole.ADMIN,
    )

    source = await NotificationChannelRepository(db_session).get_for_project(
        project_id, body.channel_id,
    )
    if source is None:
        raise NotFoundError(
            "channel not found in project",
            details={
                "project_slug": body.project_slug,
                "channel_id": str(body.channel_id),
            },
        )

    # Defense in depth: re-validate the config (see project-side
    # import endpoint for the same rationale).
    await _validate_channel_config(source.type, source.config)

    new_name = body.name or f"Copy of {source.name}"
    channel = UserChannel(
        user_id=user.id,
        name=new_name,
        type=source.type,
        # Audit L-4: deep-copy so nested dicts (headers, severity_map)
        # don't share references with the source row's SQLAlchemy
        # JSON-column dict. See api/notifications.py for the same fix.
        config=copy.deepcopy(source.config or {}),
        is_active=source.is_active,
    )
    db_session.add(channel)
    await db_session.flush()
    try:
        await db_session.commit()
    except IntegrityError:
        await db_session.rollback()
        raise ConflictError(
            f"a channel named {new_name!r} already exists in your "
            f"personal channels",
        ) from None
    await db_session.refresh(channel)
    return _channel_payload(channel)


@router.patch(
    "/channels/{channel_id}",
    response_model=UserChannelPublic,
    dependencies=[Depends(require_csrf)],
)
async def update_user_channel(
    channel_id: uuid.UUID,
    body: UserChannelUpdate,
    user: "User" = Depends(get_current_user),
    db_session: "AsyncSession" = Depends(get_session),
) -> UserChannelPublic:
    from z4j_brain.errors import NotFoundError
    from z4j_brain.persistence.repositories import UserChannelRepository

    channel = await UserChannelRepository(db_session).get_for_user(
        user.id, channel_id,
    )
    if channel is None:
        raise NotFoundError(
            "channel not found",
            details={"channel_id": str(channel_id)},
        )
    if body.name is not None:
        channel.name = body.name
    if body.config is not None:
        # Validate any incoming URL/headers BEFORE the merge so
        # unsafe patches never touch the DB.
        await _validate_channel_config(channel.type, body.config)
        # See _safe_merge_config for HIGH-01 details (mask-echo
        # preservation + URL-pivot scrub).
        merged, _url_changed = _safe_merge_config(
            channel.config or {}, body.config, mask=_MASK,
        )
        channel.config = merged
    if body.is_active is not None:
        channel.is_active = body.is_active
    await db_session.flush()
    await db_session.commit()
    await db_session.refresh(channel)
    return _channel_payload(channel)


@router.delete(
    "/channels/{channel_id}",
    status_code=204,
    dependencies=[Depends(require_csrf)],
)
async def delete_user_channel(
    channel_id: uuid.UUID,
    user: "User" = Depends(get_current_user),
    db_session: "AsyncSession" = Depends(get_session),
) -> None:
    from sqlalchemy import delete

    from z4j_brain.persistence.models.notification import UserChannel
    from z4j_brain.persistence.repositories import UserSubscriptionRepository

    # DATA-05: scrub this channel id from the user's own
    # subscriptions before the channel row is gone, so no
    # subscription holds an orphan UUID in user_channel_ids. User
    # channels are owned by a single user, so the cleanup is scoped
    # to that user only.
    await UserSubscriptionRepository(db_session).strip_user_channel(
        user_id=user.id, channel_id=channel_id,
    )

    await db_session.execute(
        delete(UserChannel).where(
            UserChannel.id == channel_id,
            UserChannel.user_id == user.id,
        ),
    )
    await db_session.commit()


# ---------------------------------------------------------------------------
# User channel test (dispatch a one-off verification payload)
# ---------------------------------------------------------------------------
#
# Mirrors the project-channel test endpoints in ``api.notifications``
# so the global /settings/channels page has feature parity with the
# per-project Providers page. Private-channel secrets (smtp_pass,
# bot_token, hmac_secret) are masked in list/get responses - the
# saved-channel test uses the stored unmasked config; the unsaved
# variant validates the config the caller sends BEFORE persistence
# so admins can verify creds in the create dialog.


async def _dispatch_user_test(
    channel_type: str, config: dict[str, Any],
) -> ChannelTestResult:
    """Run the real dispatcher with a canned test payload.

    Validates the config through the user-scoped
    ``_validate_channel_config`` (same guards as create/update) and
    returns the dispatcher's structured result. Imports ``_test_payload``
    from ``api.notifications`` so the test message matches the
    project-channel endpoints exactly (single canned body, single
    dashboard toast renderer).
    """
    from z4j_brain.api.notifications import _test_payload
    from z4j_brain.domain.notifications.channels import (
        CHANNEL_DISPATCHERS,
    )

    try:
        await _validate_channel_config(channel_type, config)
    except ConflictError as exc:
        return ChannelTestResult(success=False, error=str(exc))

    dispatcher = CHANNEL_DISPATCHERS.get(channel_type)
    if dispatcher is None:
        return ChannelTestResult(
            success=False, error=f"unknown channel type {channel_type!r}",
        )

    result = await dispatcher(config, _test_payload())
    return ChannelTestResult(
        success=result.success,
        status_code=result.status_code,
        error=result.error,
        response_body=(
            (result.response_body or "")[:500] if result.response_body else None
        ),
    )


@router.post(
    "/channels/test",
    response_model=ChannelTestResult,
    dependencies=[
        Depends(require_csrf),
        Depends(require_channel_test_throttle),
    ],
)
async def test_user_channel_config(
    body: ChannelTestRequest,
    request: Request,
    user: "User" = Depends(get_current_user),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    audit: "AuditService" = Depends(get_audit_service),
    db_session: "AsyncSession" = Depends(get_session),
) -> ChannelTestResult:
    """Dispatch a test notification against an UNSAVED user-channel config.

    Used by the "Test" button in the global settings/channels create
    dialog so the user can verify SMTP / webhook / Slack / Telegram
    credentials BEFORE persisting. Delivery is NOT logged to
    ``notification_deliveries`` - preflight semantics only. Runs the
    same SSRF / format guards as ``create_user_channel``.

    Round-6 audit fix Notif-HIGH (Apr 2026): the project-channel test
    endpoints already record a ``notifications.channel.test`` audit
    row (data-exfil pivot via attacker-controlled webhook URL); the
    user-scoped variant was missing it. Same threat model, a
    compromised user account can dial out arbitrary HTTP / SMTP
    payloads to attacker infrastructure carrying brain test content.
    """
    from z4j_brain.api.notifications import _destination_summary

    result = await _dispatch_user_test(body.type, body.config)
    await audit.record(
        audit_log,
        action="user_notifications.channel.test",
        target_type="user_notification_channel",
        target_id=None,
        result="success" if result.success else "failed",
        outcome="allow",
        user_id=user.id,
        project_id=None,
        source_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        metadata={
            "type": body.type,
            "destination_summary": _destination_summary(body.type, body.config),
            "ok": result.success,
        },
    )
    await db_session.commit()
    return result


@router.post(
    "/channels/{channel_id}/test",
    response_model=ChannelTestResult,
    dependencies=[
        Depends(require_csrf),
        Depends(require_channel_test_throttle),
    ],
)
async def test_saved_user_channel(
    channel_id: uuid.UUID,
    request: Request,
    user: "User" = Depends(get_current_user),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    audit: "AuditService" = Depends(get_audit_service),
    db_session: "AsyncSession" = Depends(get_session),
) -> ChannelTestResult:
    """Dispatch a test notification against a SAVED user channel.

    Uses the channel's stored (unmasked) config. Only the owning
    user can test their own channel - ``get_for_user`` scopes the
    lookup by ``user.id`` so a leaked UUID cannot cross-test another
    user's channel.

    Round-6 audit fix Notif-HIGH (Apr 2026): also writes the
    ``user_notifications.channel.test`` audit row that the project-
    channel variant has had since 1.0.14.
    """
    from z4j_brain.api.notifications import _destination_summary
    from z4j_brain.errors import NotFoundError
    from z4j_brain.persistence.repositories import UserChannelRepository

    channel = await UserChannelRepository(db_session).get_for_user(
        user.id, channel_id,
    )
    if channel is None:
        raise NotFoundError(
            "channel not found",
            details={"channel_id": str(channel_id)},
        )
    result = await _dispatch_user_test(channel.type, channel.config or {})
    await audit.record(
        audit_log,
        action="user_notifications.channel.test",
        target_type="user_notification_channel",
        target_id=str(channel.id),
        result="success" if result.success else "failed",
        outcome="allow",
        user_id=user.id,
        project_id=None,
        source_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        metadata={
            "type": channel.type,
            "destination_summary": _destination_summary(
                channel.type, channel.config or {},
            ),
            "ok": result.success,
        },
    )
    await db_session.commit()
    return result


# ---------------------------------------------------------------------------
# /user/subscriptions
# ---------------------------------------------------------------------------


@router.get(
    "/subscriptions",
    response_model=UserSubscriptionsListPublic,
)
async def list_user_subscriptions(
    project_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    cursor: str | None = Query(default=None),
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> UserSubscriptionsListPublic:
    """List the caller's subscriptions, optionally filtered to one project.

    When ``project_id`` is supplied the caller must currently be a
    member of that project (R3 finding M10). Today the underlying
    query already scopes by ``user.id`` so a non-member sees only an
    empty list, but the explicit check documents intent and prevents
    a regression if ``list_for_user`` is ever widened to span users.

    v1.1.0: keyset paginated on ``(project_id, trigger, id)``.
    Cursor encoded as ``"<project_uuid_hex>|<trigger>|<sub_uuid_hex>"``.
    Default page size 50, max 500. Response shape is the
    ``UserSubscriptionsListPublic`` envelope; pre-1.1 clients that
    iterated the bare list must read ``response.items``.
    """
    from z4j_brain.persistence.repositories import UserSubscriptionRepository

    if project_id is not None and not user.is_admin:
        membership = await memberships.get_for_user_project(
            user_id=user.id, project_id=project_id,
        )
        if membership is None:
            from z4j_brain.errors import AuthorizationError

            raise AuthorizationError(
                "no membership on this project",
                details={"project_id": str(project_id)},
            )

    cursor_project_id, cursor_trigger, cursor_id = (
        _decode_user_subscriptions_cursor(cursor)
    )
    # Fetch limit+1 so we can detect a next page without a second
    # COUNT() round-trip. Mirrors the schedules / deliveries pattern.
    rows = await UserSubscriptionRepository(db_session).list_for_user(
        user.id,
        project_id=project_id,
        limit=limit + 1,
        cursor_project_id=cursor_project_id,
        cursor_trigger=cursor_trigger,
        cursor_id=cursor_id,
    )
    next_cursor: str | None = None
    if len(rows) > limit:
        rows = rows[:limit]
        last = rows[-1]
        next_cursor = _encode_user_subscriptions_cursor(
            last.project_id, last.trigger, last.id,
        )
    return UserSubscriptionsListPublic(
        items=[_subscription_payload(r) for r in rows],
        next_cursor=next_cursor,
    )


@router.post(
    "/subscriptions",
    response_model=UserSubscriptionPublic,
    status_code=201,
    dependencies=[Depends(require_csrf)],
)
async def create_user_subscription(
    body: UserSubscriptionCreate,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> UserSubscriptionPublic:
    from z4j_brain.persistence.models.notification import UserSubscription
    from z4j_brain.persistence.repositories import (
        NotificationChannelRepository,
        UserChannelRepository,
        UserSubscriptionRepository,
    )

    # User must be a member of the project they're subscribing to.
    # Bug fixed in 1.3.2: global brain admins (``user.is_admin``) MUST
    # bypass this membership check. /auth/me synthesises an admin
    # membership for them on every project (so the project switcher
    # renders), but the Membership table itself has no row for a
    # global admin who hasn't been explicitly added, and pre-1.3.2
    # this endpoint queried the table directly and 403'd. The
    # ``list_user_subscriptions`` GET handler at the top of this file
    # already used the ``not user.is_admin`` short-circuit; this POST
    # had drifted out of sync with it. Switching to the canonical
    # ``policy.require_member`` helper closes the drift permanently -
    # it returns a synthesised admin-grade Membership for global
    # admins without touching the DB.
    from z4j_brain.domain.policy_engine import PolicyEngine

    await PolicyEngine().require_member(
        memberships,
        user=user,
        project_id=body.project_id,
        min_role=ProjectRole.VIEWER,
    )

    # Validate channel ids: project channels must belong to the
    # project, user channels must be owned by this user.
    if body.project_channel_ids:
        valid = await NotificationChannelRepository(
            db_session,
        ).get_many_for_project(body.project_id, body.project_channel_ids)
        if len(valid) != len(set(body.project_channel_ids)):
            raise ConflictError(
                "one or more project_channel_ids do not belong to this project",
            )
    if body.user_channel_ids:
        valid = await UserChannelRepository(db_session).get_many_for_user(
            user.id, body.user_channel_ids,
        )
        if len(valid) != len(set(body.user_channel_ids)):
            raise ConflictError(
                "one or more user_channel_ids do not belong to you",
            )

    sub_repo = UserSubscriptionRepository(db_session)
    existing = await sub_repo.get_by_unique(
        user_id=user.id, project_id=body.project_id, trigger=body.trigger,
    )
    if existing is not None:
        raise ConflictError(
            "you already have a subscription for this trigger on this project",
            details={"trigger": body.trigger},
        )

    sub = UserSubscription(
        user_id=user.id,
        project_id=body.project_id,
        trigger=body.trigger,
        filters=body.filters.model_dump(exclude_none=True),
        in_app=body.in_app,
        project_channel_ids=body.project_channel_ids,
        user_channel_ids=body.user_channel_ids,
        cooldown_seconds=body.cooldown_seconds,
    )
    db_session.add(sub)
    await db_session.flush()
    try:
        await db_session.commit()
    except IntegrityError:
        # HIGH-02: concurrent insert lost the check-then-insert race.
        await db_session.rollback()
        raise ConflictError(
            "subscription for this trigger already exists",
            details={"trigger": body.trigger},
        ) from None
    await db_session.refresh(sub)
    return _subscription_payload(sub)


@router.patch(
    "/subscriptions/{sub_id}",
    response_model=UserSubscriptionPublic,
    dependencies=[Depends(require_csrf)],
)
async def update_user_subscription(
    sub_id: uuid.UUID,
    body: UserSubscriptionUpdate,
    user: "User" = Depends(get_current_user),
    db_session: "AsyncSession" = Depends(get_session),
) -> UserSubscriptionPublic:
    from z4j_brain.errors import NotFoundError
    from z4j_brain.persistence.repositories import (
        NotificationChannelRepository,
        UserChannelRepository,
        UserSubscriptionRepository,
    )

    user_sub_repo = UserSubscriptionRepository(db_session)
    sub = await user_sub_repo.get_for_user(user.id, sub_id)
    if sub is None:
        raise NotFoundError(
            "subscription not found",
            details={"subscription_id": str(sub_id)},
        )

    # v1.0.18: trigger rename. Defends the (user, project, trigger)
    # uniqueness invariant so the user gets a clean 409 instead of
    # an opaque IntegrityError on commit.
    if body.trigger is not None and body.trigger != sub.trigger:
        existing = await user_sub_repo.get_by_unique(
            user_id=user.id,
            project_id=sub.project_id,
            trigger=body.trigger,
        )
        if existing is not None:
            raise ConflictError(
                "you already have a subscription for this trigger "
                "on this project",
                details={"trigger": body.trigger},
            )
        sub.trigger = body.trigger

    if body.filters is not None:
        sub.filters = body.filters.model_dump(exclude_none=True)
    if body.in_app is not None:
        sub.in_app = body.in_app
    if body.project_channel_ids is not None:
        if body.project_channel_ids:
            valid = await NotificationChannelRepository(
                db_session,
            ).get_many_for_project(sub.project_id, body.project_channel_ids)
            if len(valid) != len(set(body.project_channel_ids)):
                raise ConflictError(
                    "one or more project_channel_ids do not belong to this project",
                )
        sub.project_channel_ids = body.project_channel_ids
    if body.user_channel_ids is not None:
        if body.user_channel_ids:
            valid = await UserChannelRepository(db_session).get_many_for_user(
                user.id, body.user_channel_ids,
            )
            if len(valid) != len(set(body.user_channel_ids)):
                raise ConflictError(
                    "one or more user_channel_ids do not belong to you",
                )
        sub.user_channel_ids = body.user_channel_ids
    if body.cooldown_seconds is not None:
        sub.cooldown_seconds = body.cooldown_seconds
    if body.muted_until is not None:
        sub.muted_until = body.muted_until
    if body.is_active is not None:
        sub.is_active = body.is_active
    await db_session.flush()
    try:
        await db_session.commit()
    except IntegrityError:
        # Concurrent insert/rename lost the check-then-write race.
        await db_session.rollback()
        raise ConflictError(
            "you already have a subscription for this trigger on this project",
            details={"trigger": body.trigger or sub.trigger},
        ) from None
    await db_session.refresh(sub)
    return _subscription_payload(sub)


@router.delete(
    "/subscriptions/{sub_id}",
    status_code=204,
    dependencies=[Depends(require_csrf)],
)
async def delete_user_subscription(
    sub_id: uuid.UUID,
    user: "User" = Depends(get_current_user),
    db_session: "AsyncSession" = Depends(get_session),
) -> None:
    from sqlalchemy import delete

    from z4j_brain.persistence.models.notification import UserSubscription

    await db_session.execute(
        delete(UserSubscription).where(
            UserSubscription.id == sub_id,
            UserSubscription.user_id == user.id,
        ),
    )
    await db_session.commit()


# ---------------------------------------------------------------------------
# /user/deliveries  (personal delivery history, v1.0.18)
# ---------------------------------------------------------------------------


@router.get(
    "/deliveries",
)
async def list_user_deliveries(
    limit: int = Query(default=50, ge=1, le=500),
    cursor: str | None = Query(default=None),
    project_slug: str | None = Query(default=None),
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
):
    """Personal delivery history across all of the user's projects.

    Mirror of the project-scoped ``/projects/{slug}/notifications/
    deliveries`` endpoint, scoped to the calling user. Returns
    every notification that fired into one of the caller's
    personal subscriptions, regardless of which project it came
    from. Optional ``project_slug`` filter narrows the view.

    Includes deliveries from projects the user is no longer a
    member of - the dashboard renders those rows with a "you
    left this project" hint rather than hiding them, since
    historical audit data should survive membership changes.

    Pagination: keyset on ``(sent_at, id)``. Returns
    ``{"items": [...], "next_cursor": ...}``. Each item carries
    ``project_id`` + ``project_slug`` (nullable - NULL when the
    project was deleted) so the dashboard can group by project
    and badge ex-membership rows.
    """
    from z4j_brain.api.home import (
        _decode_recent_failures_cursor as _decode_cursor,
        _encode_recent_failures_cursor as _encode_cursor,
    )
    from z4j_brain.api.notifications import (
        DeliveryListPublic,
        _delivery_payload,
    )
    from z4j_brain.persistence.repositories import (
        NotificationDeliveryRepository,
    )

    project_id_filter: uuid.UUID | None = None
    if project_slug is not None:
        project = await projects.get_by_slug(project_slug)
        if project is None:
            # Mirror the "no rows" behaviour for an unknown slug
            # rather than 404 - keeps the endpoint forgiving for
            # the dashboard's optional filter dropdown.
            return {"items": [], "next_cursor": None}
        project_id_filter = project.id

    cursor_dt, cursor_id = _decode_cursor(cursor)
    rows = await NotificationDeliveryRepository(db_session).list_for_user(
        user.id,
        limit=limit + 1,
        cursor_sent_at=cursor_dt,
        cursor_id=cursor_id,
        project_id=project_id_filter,
    )
    next_cursor: str | None = None
    if len(rows) > limit:
        # Truncate to the requested page size, then encode the LAST
        # visible row as the cursor. The WHERE predicate is strict
        # ``sent_at < cursor`` so encoding the last visible row makes
        # page 2 correctly start with the row that was the overflow.
        # Encoding the overflow itself (older code) would have skipped
        # one row per page boundary.
        rows = rows[:limit]
        last = rows[-1]
        next_cursor = _encode_cursor(last.sent_at, last.id)

    # v1.1.0: batch-resolve triggered_by_user_id -> email so the
    # personal Global Notification Log can render "channel test by
    # alice@example.com" on test rows without a per-row fetch.
    # Mirrors the project-side list_deliveries pattern.
    from sqlalchemy import select

    from z4j_brain.persistence.models import User

    triggered_by_user_ids = list(
        {r.triggered_by_user_id for r in rows if r.triggered_by_user_id is not None},
    )
    triggered_by_lookup: dict[uuid.UUID, str] = {}
    if triggered_by_user_ids:
        result = await db_session.execute(
            select(User.id, User.email).where(User.id.in_(triggered_by_user_ids)),
        )
        triggered_by_lookup = {row.id: row.email for row in result.all()}

    return DeliveryListPublic(
        items=[
            _delivery_payload(r, triggered_by_lookup=triggered_by_lookup)
            for r in rows
        ],
        next_cursor=next_cursor,
    )


# ---------------------------------------------------------------------------
# /user/notifications  (the in-app inbox)
# ---------------------------------------------------------------------------


@router.get(
    "/notifications",
    response_model=list[UserNotificationPublic],
)
async def list_user_notifications(
    unread_only: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=200),
    user: "User" = Depends(get_current_user),
    db_session: "AsyncSession" = Depends(get_session),
) -> list[UserNotificationPublic]:
    from z4j_brain.persistence.repositories import UserNotificationRepository

    rows = await UserNotificationRepository(db_session).list_for_user(
        user.id, unread_only=unread_only, limit=limit,
    )
    return [_notification_payload(r) for r in rows]


@router.get(
    "/notifications/unread-count",
    response_model=UnreadCountPublic,
)
async def user_unread_count(
    user: "User" = Depends(get_current_user),
    db_session: "AsyncSession" = Depends(get_session),
) -> UnreadCountPublic:
    from z4j_brain.persistence.repositories import UserNotificationRepository

    count = await UserNotificationRepository(db_session).unread_count(user.id)
    return UnreadCountPublic(unread=count)


@router.post(
    "/notifications/{notification_id}/read",
    status_code=204,
    dependencies=[Depends(require_csrf)],
)
async def mark_user_notification_read(
    notification_id: uuid.UUID,
    user: "User" = Depends(get_current_user),
    db_session: "AsyncSession" = Depends(get_session),
) -> None:
    from z4j_brain.persistence.repositories import UserNotificationRepository

    await UserNotificationRepository(db_session).mark_read(
        user_id=user.id, notification_id=notification_id,
    )
    await db_session.commit()


@router.post(
    "/notifications/read-all",
    status_code=204,
    dependencies=[Depends(require_csrf)],
)
async def mark_all_user_notifications_read(
    user: "User" = Depends(get_current_user),
    db_session: "AsyncSession" = Depends(get_session),
) -> None:
    from z4j_brain.persistence.repositories import UserNotificationRepository

    await UserNotificationRepository(db_session).mark_all_read(user.id)
    await db_session.commit()


__all__ = ["router"]
