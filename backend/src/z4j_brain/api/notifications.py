"""Project-scoped notification endpoints.

Three sub-resources, all under ``/api/v1/projects/{slug}/notifications``:

- ``/channels``  - shared channels project admins manage. Any
  member can reference these in their personal subscriptions.
  Admin-only for write, member-readable for select-list use.

- ``/defaults``  - project default subscriptions. Admin-managed
  templates that materialize into ``user_subscriptions`` whenever
  a user joins the project.

- ``/deliveries`` - audit log of external delivery attempts.
  Admin-only.

Per-user resources live in :mod:`z4j_brain.api.user_notifications`
under the ``/api/v1/user/`` prefix.
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
from z4j_brain.domain.ip_rate_limit import (
    require_channel_import_throttle,
    require_channel_test_throttle,
)
from z4j_brain.domain.notifications.channels import (
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


router = APIRouter(
    prefix="/projects/{slug}/notifications",
    tags=["notifications"],
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


_TRIGGER_PATTERN = (
    r"^(task\.failed|task\.succeeded|task\.retried|"
    r"task\.slow|agent\.offline|agent\.online|"
    r"schedule\.fire\.failed|schedule\.fire\.succeeded|"
    r"schedule\.task_failed|"
    r"schedule\.circuit_breaker\.tripped)$"
)
_CHANNEL_TYPE_PATTERN = r"^(webhook|email|slack|telegram|pagerduty|discord)$"


#: Hard cap on the JSON-serialized size of a channel config dict.
#: 16 KiB is comfortably more than the largest legitimate config
#: (an SMTP block with full server cert chain runs ~4 KiB) but
#: rejects abusive 1 MiB payloads before they hit the DB / are
#: re-serialized into HMAC bodies / copied into PD custom_details.
#: Audit P-8 (added v1.0.14).
_CHANNEL_CONFIG_MAX_BYTES = 16 * 1024


def _validate_config_size(config: dict[str, Any] | None) -> dict[str, Any] | None:
    """Reject channel configs whose JSON form exceeds the hard cap.

    Used as a pydantic ``field_validator`` on every ``config`` field
    in this module + ``user_notifications`` so the size cap is
    enforced at the request boundary, before anything writes to the
    DB or constructs a delivery payload.
    """
    if config is None:
        return None
    import json as _json

    try:
        size = len(_json.dumps(config, ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"config must be JSON-serialisable: {exc}") from exc
    if size > _CHANNEL_CONFIG_MAX_BYTES:
        raise ValueError(
            f"config too large ({size} bytes; max {_CHANNEL_CONFIG_MAX_BYTES})",
        )
    return config


class ChannelCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    type: str = Field(pattern=_CHANNEL_TYPE_PATTERN)
    config: dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True

    @field_validator("config")
    @classmethod
    def _check_config_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_config_size(v) or {}


class ChannelUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    config: dict[str, Any] | None = None
    is_active: bool | None = None

    @field_validator("config")
    @classmethod
    def _check_config_size(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_config_size(v)


class ChannelImportFromUserRequest(BaseModel):
    """Body for ``POST /channels/import_from_user`` (added v1.0.14).

    Operator already has a personal channel with verified credentials
    (Telegram bot token, Slack webhook, PagerDuty integration key,
    etc.) and wants to share that destination with the project
    without re-pasting the secret. Backend copies the row server-side
    so the unmasked secret never crosses the wire.

    The source must be owned by the caller (anti-takeover: an admin
    can't import another user's personal channel into their project).
    """
    user_channel_id: uuid.UUID
    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        description=(
            "Override the imported channel's name. Defaults to "
            "'Copy of {original}' if omitted."
        ),
    )


class ChannelPublic(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    name: str
    type: str
    config: dict[str, Any]
    is_active: bool
    created_at: datetime
    updated_at: datetime


class ChannelTestRequest(BaseModel):
    """Body for the unsaved-config test endpoint.

    Admin is composing a channel in the dialog and wants to verify
    credentials BEFORE persisting. We accept a full ``{type, config}``
    shape, validate it through the same SSRF / format guards that
    create_channel / update_channel use, and dispatch a single test
    payload. Nothing is written to the DB.
    """

    type: str = Field(pattern=_CHANNEL_TYPE_PATTERN)
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("config")
    @classmethod
    def _check_config_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_config_size(v) or {}


class ChannelTestResult(BaseModel):
    """Structured outcome of a test dispatch.

    Mirrors :class:`z4j_brain.domain.notifications.channels.DeliveryResult`
    without leaking the raw ``response_body`` by default - we cap it
    server-side to protect against huge bodies from hostile webhooks
    and truncate further here so the dashboard card stays small.
    """

    success: bool
    status_code: int | None = None
    error: str | None = None
    response_body: str | None = None


class SubscriptionFilters(BaseModel):
    """Strict shape for subscription filter JSON.

    HIGH-06: the service's ``_matches_filters`` expects typed fields
    (e.g. ``priority`` is a list of strings). Without this model the
    API accepted arbitrary shapes and silently dropped mistyped
    filters, so users would see unfiltered floods of notifications.
    ``task_name_pattern`` is capped to prevent pathological fnmatch
    patterns from reaching the dispatcher.

    v1.0.19: ``extra=ignore`` (was ``forbid``) so a newer dashboard
    bundle that adds an unknown filter key can still POST against
    an older brain without 422'ing. Old brain just drops the
    unknown key (it would never apply the filter anyway). Trade
    typo-detection for rolling-upgrade safety - documented in
    docs/MIGRATIONS.md.
    """

    # Round-8 audit fix R8-Pyd-MED (Apr 2026): cap the priority
    # list. Pre-fix the list was unbounded; a 1M-element list of
    # the same Literal value bloated the dispatcher's per-event
    # match loop with no functional benefit (only 4 distinct
    # priorities exist, so 8 covers the matrix).
    priority: list[Literal["critical", "high", "normal", "low"]] | None = (
        Field(default=None, max_length=8)
    )
    task_name: str | None = Field(default=None, max_length=500)
    task_name_pattern: str | None = Field(default=None, max_length=200)
    queue: str | None = Field(default=None, max_length=200)
    model_config = {"extra": "ignore"}

    @field_validator("task_name_pattern")
    @classmethod
    def _check_pattern_complexity(cls, v: str | None) -> str | None:
        """Reject pathologically catastrophic-backtracking fnmatch patterns.

        ``fnmatch`` translates to a regex via ``fnmatch.translate``. A
        pattern like ``"a*a*a*a*a*a*a*a*a*a*a*a*a*b"`` compiles to a
        regex that is exponentially backtracking on long inputs (a
        20+ char task name takes seconds). Since this filter runs
        synchronously per event in the WS frame ingest path
        (``NotificationService._matches_filters``), a hostile
        subscription is a ReDoS DoS vector against event ingestion.

        We bound complexity by counting wildcards (``*`` and ``?``)
        and character classes (``[...]``). Realistic operator
        patterns use 1-3 wildcards (``"my_app.*.send_email"``);
        20+ wildcards is always pathological.

        Audit P-2 (added v1.0.14).
        """
        if v is None:
            return None
        wildcard_count = v.count("*") + v.count("?")
        # Each "[...]" character class is one bracket open.
        bracket_count = v.count("[")
        if wildcard_count > 5:
            raise ValueError(
                f"task_name_pattern has too many wildcards "
                f"({wildcard_count}; max 5). Use the more specific "
                f"task_name field for exact matches.",
            )
        if bracket_count > 3:
            raise ValueError(
                f"task_name_pattern has too many [...] character classes "
                f"({bracket_count}; max 3).",
            )
        return v


class DefaultSubscriptionCreate(BaseModel):
    trigger: str = Field(pattern=_TRIGGER_PATTERN)
    filters: SubscriptionFilters = Field(default_factory=SubscriptionFilters)
    in_app: bool = True
    # Round-8 audit fix R8-Pyd-H5 (Apr 2026): cap channel_ids list.
    # Pre-fix a 10M-UUID list forced ``get_many_for_project`` to
    # build an enormous IN-clause. Real subscriptions hit at most
    # a handful of channels.
    project_channel_ids: list[uuid.UUID] = Field(
        default_factory=list, max_length=64,
    )
    cooldown_seconds: int = Field(default=0, ge=0, le=86400)


class DefaultSubscriptionPublic(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    trigger: str
    filters: dict[str, Any]
    in_app: bool
    project_channel_ids: list[uuid.UUID]
    cooldown_seconds: int
    created_at: datetime


class DeliveryPublic(BaseModel):
    id: uuid.UUID
    # v1.0.18: ``project_id`` is now exposed so the personal
    # delivery-history tab can group / filter by project without
    # an N+1 fetch. The project-scoped delivery log already knows
    # the project from the URL slug, so it doesn't need this -
    # but it's harmless to include for symmetry.
    project_id: uuid.UUID | None = None
    subscription_id: uuid.UUID | None
    channel_id: uuid.UUID | None
    user_channel_id: uuid.UUID | None
    trigger: str
    task_id: str | None
    task_name: str | None
    status: str
    response_code: int | None
    error: str | None
    sent_at: datetime
    # Denormalized at read time (1.0.14+) so the dashboard doesn't
    # have to issue a separate per-channel fetch to label the row.
    # NULL when the underlying channel was deleted, or when the row
    # was an unsaved-config test (no channel exists). The list
    # endpoint resolves these via a single batch query per page.
    channel_name: str | None = None
    channel_type: str | None = None
    # v1.1.0: who manually triggered this row. NULL for
    # subscription-driven fires. Populated only on channel-test
    # rows (``trigger == "test.dispatch"``) so the dashboard can
    # render a "channel test" badge. See migration 2026_04_27_0009.
    triggered_by_user_id: uuid.UUID | None = None
    # v1.1.0: email of the user identified by triggered_by_user_id,
    # resolved at read time via a single batch query per page (same
    # pattern as channel_lookup). NULL when the user was deleted or
    # the row had no triggered_by. Lets the dashboard render
    # "channel test by alice@example.com" without a per-row fetch.
    triggered_by_email: str | None = None


class DeliveryListPublic(BaseModel):
    """Paged listing of delivery rows.

    Matches the envelope shape used by the other list endpoints
    (``RecentFailuresPublic``, etc.) - ``items`` + keyset
    ``next_cursor``. Cursor encoding mirrors ``home._encode_recent_failures_cursor``:
    ``"<iso8601>|<uuid_hex>"``.
    """

    items: list[DeliveryPublic]
    next_cursor: str | None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_SENSITIVE_CONFIG_KEYS = (
    "smtp_pass",
    "hmac_secret",
    "bot_token",
    "password",
    # PagerDuty Events API v2 routing key. Anyone with this key can
    # open incidents on the linked PD service, so treat it like a
    # password: masked on read, preserved on PATCH-with-blank.
    "integration_key",
)

# Audit-log sanitization helper lives in domain so service.py and
# api.notifications.py share one implementation (audit H-1/H-2/H-3).
from z4j_brain.domain.notifications.sanitize import sanitize_audit_text as _sanitize_audit_text  # noqa: E501

# Telegram bot-token and chat-id regexes now live in the domain
# module (``z4j_brain.domain.notifications.channels``) so the
# project-channel and user-channel validators share one source of
# truth - see external-audit High #2.
_MASK = "••••••••"


def _mask_config(config: dict[str, Any]) -> dict[str, Any]:
    """Mask credential-like fields when returning channel configs."""
    safe = dict(config)
    for key in _SENSITIVE_CONFIG_KEYS:
        if key in safe and safe[key]:
            safe[key] = _MASK
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
        if k in _SENSITIVE_CONFIG_KEYS and v == mask:
            # Preserve existing secret - client just echoed the mask.
            continue
        scrubbed[k] = v

    # Detect URL change BEFORE applying the merge so we know whether
    # to wipe sensitive keys below.
    url_changed = False
    for url_key in ("url", "webhook_url"):
        if url_key in scrubbed and scrubbed[url_key] != merged.get(url_key):
            url_changed = True
            break

    merged.update(scrubbed)

    if url_changed:
        for sk in _SENSITIVE_CONFIG_KEYS:
            merged.pop(sk, None)

    return merged, url_changed


async def _validate_channel_config(
    channel_type: str,
    config: dict[str, Any] | None,
) -> None:
    """Validate the URL + headers in a (partial) channel config.

    Raises :class:`ConflictError` if anything is unsafe. Safe to call
    with a PATCH payload - only keys that are present are checked.
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
        # Shared helper (domain/notifications/channels.py) so the
        # project-channel + user-channel validators stay in sync.
        # The earlier in-file regex has moved there - see R3 H7
        # + external-audit High #2 for rationale.
        from z4j_brain.domain.notifications.channels import (
            validate_telegram_config,
        )
        err = validate_telegram_config(config)
        if err:
            raise ConflictError(f"unsafe telegram config: {err}")
    elif channel_type == "email":
        # External-audit High #3 - block SMTP egress to private
        # IPs and non-allowlisted ports from both validators.
        from z4j_brain.domain.notifications.channels import (
            validate_smtp_config,
        )
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
        # First the static checks (URL present, etc.).
        err = validate_discord_config(config)
        if err:
            raise ConflictError(f"invalid discord config: {err}")
        # Then the SSRF + scheme checks shared with the webhook path.
        url = config.get("webhook_url", "")
        if url:
            err = await validate_webhook_url(url)
            if err:
                raise ConflictError(f"unsafe discord webhook URL: {err}")


async def _resolve_member_project(
    slug: str,
    user: "User",
    memberships: "MembershipRepository",
    projects: "ProjectRepository",
    *,
    min_role: ProjectRole = ProjectRole.VIEWER,
) -> uuid.UUID:
    """Verify membership and return the project id."""
    from z4j_brain.domain.policy_engine import PolicyEngine

    policy = PolicyEngine()
    project = await policy.get_project_or_404(projects, slug)
    await policy.require_member(
        memberships, user=user, project_id=project.id, min_role=min_role,
    )
    return project.id


def _channel_payload(c: Any) -> ChannelPublic:
    return ChannelPublic(
        id=c.id,
        project_id=c.project_id,
        name=c.name,
        type=c.type,
        config=_mask_config(c.config or {}),
        is_active=c.is_active,
        created_at=c.created_at,
        updated_at=c.updated_at,
    )


def _default_payload(d: Any) -> DefaultSubscriptionPublic:
    return DefaultSubscriptionPublic(
        id=d.id,
        project_id=d.project_id,
        trigger=d.trigger,
        filters=d.filters or {},
        in_app=d.in_app,
        project_channel_ids=list(d.project_channel_ids or []),
        cooldown_seconds=d.cooldown_seconds,
        created_at=d.created_at,
    )


def _delivery_payload(
    d: Any,
    *,
    channel_lookup: dict[uuid.UUID, tuple[str, str]] | None = None,
    user_channel_lookup: dict[uuid.UUID, tuple[str, str]] | None = None,
    triggered_by_lookup: dict[uuid.UUID, str] | None = None,
) -> DeliveryPublic:
    """Convert a NotificationDelivery row to its public payload.

    Resolution order for ``channel_name`` / ``channel_type``:

    1. **Snapshot columns** on the delivery row itself (audit L-2,
       added v1.0.14). This is the authoritative source for the
       audit log: snapshotted at write time, so a later channel
       rename / delete cannot rewrite history.
    2. **Live join via ``channel_lookup``** as a fallback for
       pre-1.0.14 rows that don't have the snapshot.
    3. None when neither is available (channel was deleted before
       1.0.14, or this row was an unsaved-config test).

    The two lookup dicts are built once per request by
    ``list_deliveries`` so the fallback path is still O(1) per row.
    """
    # Snapshot fields (set at write time as of v1.0.14).
    name: str | None = getattr(d, "channel_name", None)
    type_: str | None = getattr(d, "channel_type", None)
    # Live join fallback for older rows without the snapshot.
    if name is None and type_ is None:
        if d.channel_id and channel_lookup and d.channel_id in channel_lookup:
            name, type_ = channel_lookup[d.channel_id]
        elif (
            d.user_channel_id
            and user_channel_lookup
            and d.user_channel_id in user_channel_lookup
        ):
            name, type_ = user_channel_lookup[d.user_channel_id]
    triggered_by_user_id = getattr(d, "triggered_by_user_id", None)
    triggered_by_email: str | None = None
    if triggered_by_user_id is not None and triggered_by_lookup:
        triggered_by_email = triggered_by_lookup.get(triggered_by_user_id)
    return DeliveryPublic(
        id=d.id,
        project_id=d.project_id,
        subscription_id=d.subscription_id,
        channel_id=d.channel_id,
        user_channel_id=d.user_channel_id,
        trigger=d.trigger,
        task_id=d.task_id,
        task_name=d.task_name,
        status=d.status,
        response_code=d.response_code,
        error=d.error,
        sent_at=d.sent_at,
        channel_name=name,
        channel_type=type_,
        triggered_by_user_id=triggered_by_user_id,
        triggered_by_email=triggered_by_email,
    )


# ---------------------------------------------------------------------------
# Channels (project-scoped, shared)
# ---------------------------------------------------------------------------


@router.get("/channels", response_model=list[ChannelPublic])
async def list_channels(
    slug: str,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> list[ChannelPublic]:
    """List the project's shared channels.

    All members can read - they may need to pick from this list
    when subscribing to events. Only admins can write.
    """
    from z4j_brain.persistence.repositories import (
        NotificationChannelRepository,
    )

    project_id = await _resolve_member_project(slug, user, memberships, projects)
    rows = await NotificationChannelRepository(db_session).list_for_project(project_id)
    return [_channel_payload(r) for r in rows]


@router.post(
    "/channels",
    response_model=ChannelPublic,
    status_code=201,
    dependencies=[Depends(require_csrf)],
)
async def create_channel(
    slug: str,
    body: ChannelCreate,
    request: Request,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    audit: "AuditService" = Depends(get_audit_service),
    db_session: "AsyncSession" = Depends(get_session),
) -> ChannelPublic:
    from z4j_brain.persistence.models.notification import NotificationChannel

    project_id = await _resolve_member_project(
        slug, user, memberships, projects, min_role=ProjectRole.ADMIN,
    )
    # SSRF / header validation BEFORE persisting. Blocks private-IP
    # webhooks and auth-header smuggling at the entry point.
    await _validate_channel_config(body.type, body.config)
    channel = NotificationChannel(
        project_id=project_id,
        name=body.name,
        type=body.type,
        config=body.config,
        is_active=body.is_active,
    )
    db_session.add(channel)
    await db_session.flush()
    # Audit BEFORE commit so create + audit-row are atomic.
    # Channels carry secrets (webhook URLs, bot tokens, SMTP creds)
    # so creation is a privileged event that must leave a trail.
    # Audit-Phase4-1 caught the missing audit.
    await audit.record(
        audit_log,
        action="notifications.channel.create",
        target_type="notification_channel",
        target_id=str(channel.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project_id,
        source_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        metadata={"name": channel.name, "type": channel.type},
    )
    try:
        await db_session.commit()
    except IntegrityError:
        await db_session.rollback()
        raise ConflictError("channel already exists") from None
    await db_session.refresh(channel)
    return _channel_payload(channel)


@router.post(
    "/channels/import_from_user",
    response_model=ChannelPublic,
    status_code=201,
    dependencies=[
        Depends(require_csrf),
        Depends(require_channel_import_throttle),
    ],
)
async def import_channel_from_user(
    slug: str,
    body: ChannelImportFromUserRequest,
    request: Request,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    audit: "AuditService" = Depends(get_audit_service),
    db_session: "AsyncSession" = Depends(get_session),
) -> ChannelPublic:
    """Copy one of the caller's personal channels into the project.

    Use case: operator has a Telegram bot token / Slack webhook /
    PagerDuty key set up and verified in their personal channels,
    and wants to make the same destination available project-wide
    without re-pasting the secret.

    Server-side copy: the source UserChannel's config (incl. real
    secrets) is read directly from the DB and written to a new
    NotificationChannel. The unmasked secret never crosses the wire.

    Permission model:
      - Caller must be project ADMIN (creating shared resources).
      - Source channel MUST be owned by the caller (no taking over
        another user's secret without their knowledge).
      - Re-validates the channel config through the same SSRF /
        format guards used at create time, so a stale unsafe config
        in a UserChannel can't backdoor into the project.
    """
    from z4j_brain.errors import NotFoundError
    from z4j_brain.persistence.models.notification import NotificationChannel
    from z4j_brain.persistence.repositories import UserChannelRepository

    project_id = await _resolve_member_project(
        slug, user, memberships, projects, min_role=ProjectRole.ADMIN,
    )

    source = await UserChannelRepository(db_session).get_for_user(
        user.id, body.user_channel_id,
    )
    if source is None:
        # NotFound (not Forbidden) so we don't leak whether a channel
        # exists owned by another user. Same shape as get_for_user
        # missing.
        raise NotFoundError(
            "user channel not found",
            details={"user_channel_id": str(body.user_channel_id)},
        )

    # Defense in depth: the source was created via the same validator
    # we'd run here, but a config that was valid at creation time
    # might not be valid now (e.g. URL allow-list tightened in a
    # later release). Re-validate before persisting into the project.
    await _validate_channel_config(source.type, source.config)

    new_name = body.name or f"Copy of {source.name}"
    channel = NotificationChannel(
        project_id=project_id,
        name=new_name,
        type=source.type,
        # Deep-copy the dict so any later mutation in either copy
        # doesn't accidentally mutate the other through a shared
        # reference (SQLAlchemy hands back the same dict instance
        # on subsequent reads of the JSON column).
        # Audit L-4: deep-copy so nested dicts (headers, severity_map)
        # don't share references with the source row's SQLAlchemy
        # JSON-column dict. A future PATCH on the source mutating a
        # nested dict in place would otherwise leak into the imported
        # copy via the shared reference.
        config=copy.deepcopy(source.config or {}),
        is_active=source.is_active,
    )
    db_session.add(channel)
    await db_session.flush()
    # Audit the cross-boundary copy: a personal user channel
    # (with secrets) became visible to all project admins. Names
    # both the source user_channel_id and the new project channel.
    # Audit-Phase4-1 caught the missing audit.
    await audit.record(
        audit_log,
        action="notifications.channel.import_from_user",
        target_type="notification_channel",
        target_id=str(channel.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project_id,
        source_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        metadata={
            "name": new_name,
            "type": source.type,
            "source_user_channel_id": str(source.id),
        },
    )
    try:
        await db_session.commit()
    except IntegrityError:
        await db_session.rollback()
        raise ConflictError(
            f"a channel named {new_name!r} already exists in this project",
        ) from None
    await db_session.refresh(channel)
    return _channel_payload(channel)


@router.patch(
    "/channels/{channel_id}",
    response_model=ChannelPublic,
    dependencies=[Depends(require_csrf)],
)
async def update_channel(
    slug: str,
    channel_id: uuid.UUID,
    body: ChannelUpdate,
    request: Request,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    audit: "AuditService" = Depends(get_audit_service),
    db_session: "AsyncSession" = Depends(get_session),
) -> ChannelPublic:
    from z4j_brain.errors import NotFoundError
    from z4j_brain.persistence.repositories import (
        NotificationChannelRepository,
    )

    project_id = await _resolve_member_project(
        slug, user, memberships, projects, min_role=ProjectRole.ADMIN,
    )
    channel = await NotificationChannelRepository(db_session).get_for_project(
        project_id, channel_id,
    )
    if channel is None:
        raise NotFoundError(
            "channel not found",
            details={"channel_id": str(channel_id)},
        )
    fields_changed: list[str] = []
    if body.name is not None:
        channel.name = body.name
        fields_changed.append("name")
    url_changed = False
    if body.config is not None:
        # Validate any incoming URL/headers BEFORE the merge so
        # unsafe patches never touch the DB.
        await _validate_channel_config(channel.type, body.config)
        # Merge instead of replace so admins don't have to re-enter
        # masked credentials. See _safe_merge_config for HIGH-01
        # details (mask-echo preservation + URL-pivot scrub).
        merged, url_changed = _safe_merge_config(
            channel.config or {}, body.config, mask=_MASK,
        )
        channel.config = merged
        fields_changed.append("config")
    if body.is_active is not None:
        channel.is_active = body.is_active
        fields_changed.append("is_active")
    await db_session.flush()
    # Audit the patch. Don't include the raw config (would leak
    # rotated secrets via the audit_log table); instead record
    # which fields changed + a flag for URL pivots so security
    # ops can spot a credential rotation followed by URL change
    # (classic phishing-the-channel attack pattern).
    # Audit-Phase4-1 caught the missing audit.
    await audit.record(
        audit_log,
        action="notifications.channel.update",
        target_type="notification_channel",
        target_id=str(channel.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project_id,
        source_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        metadata={
            "fields_changed": fields_changed,
            "url_changed": url_changed,
            "type": channel.type,
        },
    )
    await db_session.commit()
    await db_session.refresh(channel)
    return _channel_payload(channel)


@router.delete(
    "/channels/{channel_id}",
    status_code=204,
    dependencies=[Depends(require_csrf)],
)
async def delete_channel(
    slug: str,
    channel_id: uuid.UUID,
    request: Request,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    audit: "AuditService" = Depends(get_audit_service),
    db_session: "AsyncSession" = Depends(get_session),
) -> None:
    from sqlalchemy import delete

    from z4j_brain.persistence.models.notification import NotificationChannel
    from z4j_brain.persistence.repositories import (
        NotificationChannelRepository,
    )

    project_id = await _resolve_member_project(
        slug, user, memberships, projects, min_role=ProjectRole.ADMIN,
    )

    # Look up the row first so the audit metadata can name what was
    # deleted (operator looking at the audit page should see
    # ``deleted webhook channel "Slack: ops-alerts"``, not just
    # an opaque UUID). Returns None on cross-project IDOR attempts.
    channel = await NotificationChannelRepository(db_session).get_for_project(
        project_id, channel_id,
    )

    # DATA-05: strip this channel id from every subscription that
    # referenced it BEFORE the channel row is gone. Otherwise the
    # dispatcher would see orphan UUIDs in user_subscriptions /
    # project_default_subscriptions and silently skip (or worse,
    # log scary "unknown channel" warnings per event).
    from z4j_brain.persistence.repositories import (
        ProjectDefaultSubscriptionRepository,
        UserSubscriptionRepository,
    )

    await UserSubscriptionRepository(db_session).strip_project_channel(
        project_id=project_id, channel_id=channel_id,
    )
    await ProjectDefaultSubscriptionRepository(db_session).strip_project_channel(
        project_id=project_id, channel_id=channel_id,
    )

    await db_session.execute(
        delete(NotificationChannel).where(
            NotificationChannel.id == channel_id,
            NotificationChannel.project_id == project_id,
        ),
    )
    # Audit-Phase4-1 caught the missing audit. Privileged delete -
    # rogue admin shouldn't be able to silently nuke a channel
    # carrying alert credentials.
    await audit.record(
        audit_log,
        action="notifications.channel.delete",
        target_type="notification_channel",
        target_id=str(channel_id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project_id,
        source_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        metadata={
            "name": channel.name if channel else None,
            "type": channel.type if channel else None,
        },
    )
    await db_session.commit()


# ---------------------------------------------------------------------------
# Channel test (dispatch a one-off verification payload)
# ---------------------------------------------------------------------------


def _destination_summary(channel_type: str, config: dict[str, Any]) -> str:
    """Compact, audit-safe rendering of a channel's destination.

    Returns the host (for webhook / slack / discord URLs), email
    address (for email type), or chat id (for telegram). NEVER
    returns secrets - bot tokens, webhook signing secrets, SMTP
    passwords are all dropped. The audit log persists these
    summaries indefinitely so leaking a credential here would
    create a long-lived breach.

    Used by the channel-test audit to record where the test fired
    so a security review can spot exfiltration via test endpoints
    pointed at attacker-controlled URLs.
    """
    from urllib.parse import urlparse

    if channel_type in {"webhook", "slack", "discord", "pagerduty"}:
        url = config.get("webhook_url") or config.get("url") or ""
        try:
            host = urlparse(str(url)).hostname or ""
        except (ValueError, TypeError):
            host = ""
        return f"{channel_type}://{host}" if host else channel_type
    if channel_type == "email":
        to = config.get("to") or ""
        return f"email:{to}"
    if channel_type == "telegram":
        chat_id = config.get("chat_id") or ""
        return f"telegram:chat_id={chat_id}"
    return channel_type


def _test_payload() -> dict[str, Any]:
    """Canned payload every test dispatch uses.

    Marked clearly as a z4j test so operators reading the Slack
    channel / inbox don't mistake it for a real alert. The shape
    matches the real notification envelope (``trigger``,
    ``task_name``, ``priority``, ``state``) so the test exercises
    the same rendering path production traffic hits.
    """
    from datetime import UTC, datetime as _dt

    now = _dt.now(UTC).isoformat()
    return {
        "trigger": "z4j.test",
        "task_name": "z4j-self-test",
        "task_id": "test-" + now,
        "priority": "normal",
        "state": "test",
        "subject": "z4j test notification",
        "body": (
            "This is a z4j channel test. If you can read this, the "
            "credentials in this notification channel work.\n\n"
            f"Dispatched at {now}."
        ),
    }


async def _dispatch_test(
    channel_type: str,
    config: dict[str, Any],
    *,
    project_id: uuid.UUID | None = None,
    channel_id: uuid.UUID | None = None,
    user_channel_id: uuid.UUID | None = None,
    triggered_by_user_id: uuid.UUID | None = None,
    db_session: "AsyncSession | None" = None,
) -> ChannelTestResult:
    """Run the real dispatcher with a canned test payload.

    Shared between the saved-channel and unsaved-config endpoints so
    there is a single test path. Validates the config through the
    same SSRF / format guards create / update use, then returns the
    dispatcher's structured result.

    As of v1.0.14, when ``project_id`` and ``db_session`` are passed,
    the test dispatch is logged to ``notification_deliveries`` with
    ``trigger="test.dispatch"`` so the operator sees test history on
    the dashboard's Delivery Log page. Pre-1.0.14 tests were silently
    not logged - operators couldn't tell if a test had actually
    fired or not without checking the destination directly. The
    audit row is marked with the ``test.dispatch`` trigger so the UI
    can render a "test" badge to distinguish from real notifications.
    Callers without a project_id (e.g. user-channel test that's not
    project-scoped) skip the log step.
    """
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

    # Audit-log the test dispatch (1.0.14+). Best-effort: a logging
    # failure must not turn a successful test into a failed one
    # the operator sees as red - we swallow + log to structlog only.
    if project_id is not None and db_session is not None:
        try:
            from z4j_brain.persistence.models.notification import (
                NotificationDelivery,
            )

            # Sanitize error + response_body before persistence
            # (audit H-1, H-2, H-3): the dispatcher's raw error /
            # response_body can carry the channel's webhook URL
            # (which contains the secret token), the body of a
            # hostile attacker-controlled webhook, or SSRF-guard
            # rejection messages that leak resolved internal IPs.
            # _sanitize_audit_text scrubs all three before write.
            sanitized_error = _sanitize_audit_text(
                result.error,
                channel_config=config,
                max_len=1024,
            )
            sanitized_body = _sanitize_audit_text(
                result.response_body,
                channel_config=config,
                max_len=2048,
            )
            # Snapshot channel name + type (audit L-2) so historical
            # rows survive a future channel rename / delete with their
            # original destination intact. For unsaved-config preflight
            # tests there's no channel name; store None so the read
            # path renders "(unsaved test)".
            snapshot_name: str | None = None
            if channel_id is not None and db_session is not None:
                from z4j_brain.persistence.repositories import (
                    NotificationChannelRepository,
                )
                src = await NotificationChannelRepository(db_session).get_for_project(
                    project_id, channel_id,
                )
                if src is not None:
                    snapshot_name = src.name
            row = NotificationDelivery(
                project_id=project_id,
                channel_id=channel_id,
                user_channel_id=user_channel_id,
                subscription_id=None,
                trigger="test.dispatch",
                task_id=None,
                task_name=None,
                status="sent" if result.success else "failed",
                response_code=result.status_code,
                response_body=sanitized_body,
                error=sanitized_error,
                channel_name=snapshot_name,
                channel_type=channel_type,
                # v1.1.0: stamp the row with the user who triggered
                # the test so it surfaces in their personal Global
                # Notification Log alongside subscription-driven fires.
                triggered_by_user_id=triggered_by_user_id,
            )
            db_session.add(row)
            await db_session.commit()
        except Exception:  # noqa: BLE001
            import logging as _logging

            try:
                await db_session.rollback()
            except Exception:  # noqa: BLE001
                pass
            _logging.getLogger("z4j.brain.notifications").exception(
                "test_dispatch_audit_failed",
            )

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
async def test_channel_config(
    slug: str,
    body: ChannelTestRequest,
    request: Request,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    audit: "AuditService" = Depends(get_audit_service),
    db_session: "AsyncSession" = Depends(get_session),
) -> ChannelTestResult:
    """Dispatch a single test notification against an UNSAVED config.

    Used by the dashboard's "Test" button in the create dialog so
    admins can verify SMTP / webhook / Slack / Telegram credentials
    BEFORE persisting the channel.

    The dispatch IS logged to ``notification_deliveries`` (1.0.14+)
    with ``trigger="test.dispatch"`` so operators see test history on
    the Delivery Log page. ``channel_id`` is NULL for unsaved-config
    tests (the channel doesn't exist yet) - the row's audit value is
    "did this test fire and what did the destination say?", which is
    independent of any specific channel row.

    Admin-only; same role gate as create_channel.
    """
    project_id = await _resolve_member_project(
        slug, user, memberships, projects, min_role=ProjectRole.ADMIN,
    )
    result = await _dispatch_test(
        body.type,
        body.config,
        project_id=project_id,
        channel_id=None,
        triggered_by_user_id=user.id,
        db_session=db_session,
    )
    # Audit-Phase4-1: the test endpoint is a data-exfil vector
    # (operator can configure an attacker-controlled webhook URL +
    # fire one test that puts arbitrary brain data on the wire).
    # Record every test attempt with the destination's URL/host
    # in metadata so a security review can spot the pivot.
    await audit.record(
        audit_log,
        action="notifications.channel.test",
        target_type="notification_channel",
        target_id=None,  # unsaved-config test
        result="success" if result.success else "failed",
        outcome="allow",
        user_id=user.id,
        project_id=project_id,
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
async def test_saved_channel(
    slug: str,
    channel_id: uuid.UUID,
    request: Request,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    audit: "AuditService" = Depends(get_audit_service),
    db_session: "AsyncSession" = Depends(get_session),
) -> ChannelTestResult:
    """Dispatch a single test notification against a SAVED channel.

    Uses the channel's stored config (including secrets the admin
    entered at create / update time), not anything the caller sends
    in the body. The delivery is NOT logged to
    ``notification_deliveries`` - same preflight semantics as the
    unsaved variant.

    Admin-only.
    """
    from z4j_brain.errors import NotFoundError
    from z4j_brain.persistence.repositories import (
        NotificationChannelRepository,
    )

    project_id = await _resolve_member_project(
        slug, user, memberships, projects, min_role=ProjectRole.ADMIN,
    )
    channel = await NotificationChannelRepository(db_session).get_for_project(
        project_id, channel_id,
    )
    if channel is None:
        raise NotFoundError(
            "channel not found",
            details={"channel_id": str(channel_id)},
        )
    result = await _dispatch_test(
        channel.type,
        channel.config or {},
        project_id=project_id,
        channel_id=channel.id,
        triggered_by_user_id=user.id,
        db_session=db_session,
    )
    # Audit-Phase4-1: same exfil concern as test_channel_config
    # but against a stored channel - the audit row names which
    # channel was poked.
    await audit.record(
        audit_log,
        action="notifications.channel.test",
        target_type="notification_channel",
        target_id=str(channel.id),
        result="success" if result.success else "failed",
        outcome="allow",
        user_id=user.id,
        project_id=project_id,
        source_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        metadata={
            "type": channel.type,
            "name": channel.name,
            "ok": result.success,
        },
    )
    await db_session.commit()
    return result


# ---------------------------------------------------------------------------
# Project default subscriptions (admin onboarding templates)
# ---------------------------------------------------------------------------


@router.get(
    "/defaults",
    response_model=list[DefaultSubscriptionPublic],
)
async def list_defaults(
    slug: str,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> list[DefaultSubscriptionPublic]:
    from z4j_brain.persistence.repositories import (
        ProjectDefaultSubscriptionRepository,
    )

    project_id = await _resolve_member_project(
        slug, user, memberships, projects, min_role=ProjectRole.ADMIN,
    )
    rows = await ProjectDefaultSubscriptionRepository(
        db_session,
    ).list_for_project(project_id)
    return [_default_payload(r) for r in rows]


@router.post(
    "/defaults",
    response_model=DefaultSubscriptionPublic,
    status_code=201,
    dependencies=[Depends(require_csrf)],
)
async def create_default(
    slug: str,
    body: DefaultSubscriptionCreate,
    request: Request,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    audit: "AuditService" = Depends(get_audit_service),
    db_session: "AsyncSession" = Depends(get_session),
) -> DefaultSubscriptionPublic:
    from z4j_brain.persistence.models.notification import (
        ProjectDefaultSubscription,
    )
    from z4j_brain.persistence.repositories import (
        NotificationChannelRepository,
        ProjectDefaultSubscriptionRepository,
    )

    project_id = await _resolve_member_project(
        slug, user, memberships, projects, min_role=ProjectRole.ADMIN,
    )

    # Validate channel ids belong to this project (defaults can only
    # reference project channels, never user channels).
    if body.project_channel_ids:
        valid = await NotificationChannelRepository(
            db_session,
        ).get_many_for_project(project_id, body.project_channel_ids)
        if len(valid) != len(set(body.project_channel_ids)):
            raise ConflictError(
                "one or more channel_ids do not belong to this project",
            )

    # Enforce uniqueness on (project_id, trigger) at the API layer
    # so we can return a clean 409. Single-query LIMIT 1 check
    # against the backing unique index (POL-5).
    if await ProjectDefaultSubscriptionRepository(
        db_session,
    ).exists_for_project_trigger(project_id, body.trigger):
        raise ConflictError(
            "default subscription for this trigger already exists",
            details={"trigger": body.trigger},
        )

    default = ProjectDefaultSubscription(
        project_id=project_id,
        trigger=body.trigger,
        filters=body.filters.model_dump(exclude_none=True),
        in_app=body.in_app,
        project_channel_ids=body.project_channel_ids,
        cooldown_seconds=body.cooldown_seconds,
    )
    db_session.add(default)
    await db_session.flush()
    # Audit-Phase4-1: defaults auto-materialise into UserSubscriptions
    # for every new project member. Defining one is a privileged
    # operation that propagates across the whole org → must audit.
    await audit.record(
        audit_log,
        action="notifications.default.create",
        target_type="project_default_subscription",
        target_id=str(default.id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project_id,
        source_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        metadata={
            "trigger": default.trigger,
            "in_app": default.in_app,
            "channel_count": len(default.project_channel_ids or []),
            "cooldown_seconds": default.cooldown_seconds,
        },
    )
    try:
        await db_session.commit()
    except IntegrityError:
        # HIGH-02: concurrent insert lost the check-then-insert race.
        await db_session.rollback()
        raise ConflictError(
            "default subscription for this trigger already exists",
            details={"trigger": body.trigger},
        ) from None
    await db_session.refresh(default)
    return _default_payload(default)


class DefaultSubscriptionUpdate(BaseModel):
    """Body for ``PATCH /defaults/{default_id}`` (added v1.0.18).

    Every field is optional - only the keys actually present in
    the request mutate the row. Lets admins flip a single channel
    on/off, change the cooldown, or rename the trigger without
    re-typing the whole subscription. Mirrors :class:`ChannelUpdate`'s
    partial-update shape.
    """

    trigger: str | None = Field(default=None, pattern=_TRIGGER_PATTERN)
    filters: SubscriptionFilters | None = None
    in_app: bool | None = None
    # Round-8 audit fix R8-Pyd-H5 (Apr 2026).
    project_channel_ids: list[uuid.UUID] | None = Field(
        default=None, max_length=64,
    )
    cooldown_seconds: int | None = Field(default=None, ge=0, le=86400)


@router.patch(
    "/defaults/{default_id}",
    response_model=DefaultSubscriptionPublic,
    dependencies=[Depends(require_csrf)],
)
async def update_default(
    slug: str,
    default_id: uuid.UUID,
    body: DefaultSubscriptionUpdate,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> DefaultSubscriptionPublic:
    """Partial-update an existing default subscription (admin only).

    Added v1.0.18 so admins can adjust a default's channels /
    in-app / cooldown / trigger without the
    ``delete + recreate`` workaround. Mutated fields:

    - ``trigger``: rename. Validated against the same allow-list
      as create. Rejects with 409 if another default already
      exists for the new trigger in this project (race-safe).
    - ``filters``: replace the JSON filter blob.
    - ``in_app``: toggle in-app delivery.
    - ``project_channel_ids``: replace the channel-id list. Each
      id MUST belong to this project (409 ConflictError otherwise).
    - ``cooldown_seconds``: integer 0..86400.

    All five are independent: a request containing only
    ``project_channel_ids`` updates ONLY that field. Omitted keys
    leave the existing value untouched (PATCH semantics, not PUT).
    """
    from z4j_brain.errors import NotFoundError
    from z4j_brain.persistence.repositories import (
        NotificationChannelRepository,
        ProjectDefaultSubscriptionRepository,
    )

    project_id = await _resolve_member_project(
        slug, user, memberships, projects, min_role=ProjectRole.ADMIN,
    )

    # Load the row scoped to this project so a leaked default_id
    # cannot mutate a default in a different project.
    repo = ProjectDefaultSubscriptionRepository(db_session)
    default = await repo.get_for_project(project_id, default_id)
    if default is None:
        raise NotFoundError(
            "default subscription not found",
            details={"default_id": str(default_id)},
        )

    # Validate channel ids belong to this project BEFORE any
    # write, so a partial-state row is never persisted on bad
    # input.
    if body.project_channel_ids is not None and body.project_channel_ids:
        valid = await NotificationChannelRepository(
            db_session,
        ).get_many_for_project(project_id, body.project_channel_ids)
        if len(valid) != len(set(body.project_channel_ids)):
            raise ConflictError(
                "one or more channel_ids do not belong to this project",
            )

    # If the trigger is changing, defend the (project_id, trigger)
    # uniqueness invariant so the user gets a clean 409 instead
    # of an opaque IntegrityError on commit.
    if body.trigger is not None and body.trigger != default.trigger:
        if await repo.exists_for_project_trigger(project_id, body.trigger):
            raise ConflictError(
                "default subscription for this trigger already exists",
                details={"trigger": body.trigger},
            )
        default.trigger = body.trigger

    if body.filters is not None:
        default.filters = body.filters.model_dump(exclude_none=True)
    if body.in_app is not None:
        default.in_app = body.in_app
    if body.project_channel_ids is not None:
        default.project_channel_ids = body.project_channel_ids
    if body.cooldown_seconds is not None:
        default.cooldown_seconds = body.cooldown_seconds

    await db_session.flush()
    try:
        await db_session.commit()
    except IntegrityError:
        # Concurrent insert / update lost the check-then-write
        # race for a trigger rename. Re-raise as a clean 409.
        await db_session.rollback()
        raise ConflictError(
            "default subscription for this trigger already exists",
            details={"trigger": body.trigger or default.trigger},
        ) from None
    await db_session.refresh(default)
    return _default_payload(default)

@router.delete(
    "/defaults/{default_id}",
    status_code=204,
    dependencies=[Depends(require_csrf)],
)
async def delete_default(
    slug: str,
    default_id: uuid.UUID,
    request: Request,
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    audit: "AuditService" = Depends(get_audit_service),
    db_session: "AsyncSession" = Depends(get_session),
) -> None:
    from sqlalchemy import delete

    from z4j_brain.persistence.models.notification import (
        ProjectDefaultSubscription,
    )
    from z4j_brain.persistence.repositories import (
        ProjectDefaultSubscriptionRepository,
    )

    project_id = await _resolve_member_project(
        slug, user, memberships, projects, min_role=ProjectRole.ADMIN,
    )
    # Capture the trigger before the row goes so the audit metadata
    # has something more useful than an opaque UUID.
    existing = await ProjectDefaultSubscriptionRepository(
        db_session,
    ).get_for_project(project_id, default_id)
    await db_session.execute(
        delete(ProjectDefaultSubscription).where(
            ProjectDefaultSubscription.id == default_id,
            ProjectDefaultSubscription.project_id == project_id,
        ),
    )
    # Audit-Phase4-1: removing a default touches every future
    # member's notification preferences. Privileged + must audit.
    await audit.record(
        audit_log,
        action="notifications.default.delete",
        target_type="project_default_subscription",
        target_id=str(default_id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project_id,
        source_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        metadata={
            "trigger": existing.trigger if existing else None,
        },
    )
    await db_session.commit()


# ---------------------------------------------------------------------------
# Delivery audit log (admin-only, read-only)
# ---------------------------------------------------------------------------


class ClearDeliveriesResult(BaseModel):
    """Response shape for the admin clear-log endpoint (added v1.0.14)."""
    deleted: int


@router.delete(
    "/deliveries",
    response_model=ClearDeliveriesResult,
    dependencies=[Depends(require_csrf)],
)
async def clear_deliveries(
    request: Request,
    slug: str,
    before: datetime | None = Query(
        default=None,
        description=(
            "When set, only delete delivery rows older than this "
            "ISO-8601 timestamp. Useful for retention policy "
            "(e.g. delete rows older than 30 days) without wiping "
            "recent debugging history. When unset, deletes everything."
        ),
    ),
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> ClearDeliveriesResult:
    """Bulk-delete every delivery row for the project.

    Admin-only - the audit log is the same data the dashboard
    surfaces, so the same role gate applies. Returns the number of
    rows deleted so the UI can render a "Cleared N entries" toast.

    NOTE: this is destructive. Once deleted, the rows are gone -
    they don't move to a soft-delete table. The notification
    deliveries are already an *audit* of external sends, not a
    source of truth (the message reached its destination either
    way), so wiping them is a UX choice (clean view) rather than a
    data-loss risk. Operators who need long-term retention should
    forward via webhooks to an external log store.

    Audit: as of v1.0.14 (audit L-1) every clear writes one row to
    the brain audit_log so a rogue admin cannot silently delete
    delivery history to cover the trail of a sensitive test
    dispatch. The audit row carries the actor, the row count, and
    the optional ``before`` timestamp.
    """
    from z4j_brain.api.deps import get_settings
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        NotificationDeliveryRepository,
    )

    project_id = await _resolve_member_project(
        slug, user, memberships, projects, min_role=ProjectRole.ADMIN,
    )
    deleted = await NotificationDeliveryRepository(db_session).delete_for_project(
        project_id,
        before=before,
    )

    # Audit the wipe BEFORE commit so deletion + audit happen
    # atomically; if the audit insert fails the delete rolls back.
    settings = get_settings(request)
    await AuditService(settings).record(
        AuditLogRepository(db_session),
        action="notifications.deliveries.clear",
        target_type="project",
        target_id=str(project_id),
        result="success",
        outcome="allow",
        user_id=user.id,
        project_id=project_id,
        source_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        metadata={
            "deleted_count": deleted,
            "before": before.isoformat() if before else None,
        },
    )
    await db_session.commit()
    return ClearDeliveriesResult(deleted=deleted)


@router.get("/deliveries", response_model=DeliveryListPublic)
async def list_deliveries(
    slug: str,
    limit: int = Query(default=50, ge=1, le=500),
    cursor: str | None = Query(default=None),
    user: "User" = Depends(get_current_user),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    db_session: "AsyncSession" = Depends(get_session),
) -> DeliveryListPublic:
    """Paged admin-visible delivery log with keyset pagination.

    Matches the shape of every other list endpoint - ``items`` +
    optional ``next_cursor``. The cursor encodes the ``(sent_at, id)``
    tuple to keep pages stable under concurrent insert / delete.
    See docs/PRODUCTION_READINESS_2026Q2.md POL-2.
    """
    from z4j_brain.api.home import (  # reuse the same encoder shape
        _decode_recent_failures_cursor as _decode_cursor,
        _encode_recent_failures_cursor as _encode_cursor,
    )
    from z4j_brain.persistence.repositories import (
        NotificationDeliveryRepository,
    )

    project_id = await _resolve_member_project(
        slug, user, memberships, projects, min_role=ProjectRole.ADMIN,
    )

    cursor_dt, cursor_id = _decode_cursor(cursor)
    # Fetch limit + 1 so we can detect whether there's a next page.
    rows = await NotificationDeliveryRepository(db_session).list_for_project(
        project_id,
        limit=limit + 1,
        cursor_sent_at=cursor_dt,
        cursor_id=cursor_id,
    )
    next_cursor: str | None = None
    if len(rows) > limit:
        # v1.0.18: encode the last visible row, not the overflow
        # row. The keyset predicate is strict ``sent_at < cursor``,
        # so encoding the overflow would skip one row per page
        # boundary. Now page 2 starts with what was previously the
        # overflow row, exactly as paging is intended to work.
        rows = rows[:limit]
        last = rows[-1]
        next_cursor = _encode_cursor(last.sent_at, last.id)

    # Batch-resolve channel name + type for each row in this page so
    # the dashboard can label "which Slack channel did this fire to?"
    # without an N+1 fetch (added v1.0.14). Two queries: one for
    # project channels, one for user channels. Both use the
    # already-imported repos. Empty input lists short-circuit so the
    # common-case "all rows are project channels" path still fires
    # only one query.
    from sqlalchemy import select

    from z4j_brain.persistence.models.notification import (
        NotificationChannel,
        UserChannel,
    )

    project_channel_ids = list(
        {r.channel_id for r in rows if r.channel_id is not None},
    )
    user_channel_ids = list(
        {r.user_channel_id for r in rows if r.user_channel_id is not None},
    )

    channel_lookup: dict[uuid.UUID, tuple[str, str]] = {}
    if project_channel_ids:
        result = await db_session.execute(
            select(
                NotificationChannel.id,
                NotificationChannel.name,
                NotificationChannel.type,
            ).where(NotificationChannel.id.in_(project_channel_ids)),
        )
        channel_lookup = {row.id: (row.name, row.type) for row in result.all()}

    user_channel_lookup: dict[uuid.UUID, tuple[str, str]] = {}
    if user_channel_ids:
        result = await db_session.execute(
            select(
                UserChannel.id,
                UserChannel.name,
                UserChannel.type,
            ).where(UserChannel.id.in_(user_channel_ids)),
        )
        user_channel_lookup = {row.id: (row.name, row.type) for row in result.all()}

    # v1.1.0: batch-resolve triggered_by_user_id -> email for the page
    # so the dashboard can render "channel test by alice@example.com"
    # without an N+1 fetch. Only test fires populate this field; on a
    # page with zero test rows the lookup is skipped entirely.
    triggered_by_user_ids = list(
        {r.triggered_by_user_id for r in rows if r.triggered_by_user_id is not None},
    )
    triggered_by_lookup: dict[uuid.UUID, str] = {}
    if triggered_by_user_ids:
        from z4j_brain.persistence.models import User

        result = await db_session.execute(
            select(User.id, User.email).where(User.id.in_(triggered_by_user_ids)),
        )
        triggered_by_lookup = {row.id: row.email for row in result.all()}

    return DeliveryListPublic(
        items=[
            _delivery_payload(
                r,
                channel_lookup=channel_lookup,
                user_channel_lookup=user_channel_lookup,
                triggered_by_lookup=triggered_by_lookup,
            )
            for r in rows
        ],
        next_cursor=next_cursor,
    )


__all__ = ["router"]
