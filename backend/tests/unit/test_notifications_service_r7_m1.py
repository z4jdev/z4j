"""Regression test for the round-7 audit M-1 sanitizer wiring bug.

The :class:`_PendingDelivery` dataclass field is called ``config``
but the persistence step in
:meth:`NotificationService.evaluate_and_dispatch` was passing
``getattr(p, "channel_config", None)`` into ``sanitize_audit_text``.
Because the field name does not match, the getattr fell back to
``None`` for EVERY real delivery, which made the sanitiser skip the
config-value masking pass at
``z4j_brain.domain.notifications.sanitize.sanitize_audit_text``
line 108. The result is that an error string containing the
channel's full webhook URL (with bearer token / hmac secret /
slack T.../B.../SECRET token) landed in
``notification_deliveries.error`` UNMASKED for any failed delivery
since 1.6.0.

The test-dispatch path (``test_channel_config`` /
``test_saved_channel``) passes the config dict directly into
``sanitize_audit_text`` so it was unaffected -- which is why the
bug shipped without a failing existing test. This regression test
exercises the real ``evaluate_and_dispatch`` path with a stubbed
channel dispatcher that returns an error string containing the
secret URL, and asserts the URL is masked in the persisted
``notification_deliveries.error`` row.

Structural identifier: R7-M1.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.domain.notifications import channels as channels_module
from z4j_brain.domain.notifications.channels import DeliveryResult
from z4j_brain.domain.notifications.service import NotificationService
from z4j_brain.persistence import models  # noqa: F401 - register tables
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import (
    Membership,
    NotificationChannel,
    NotificationDelivery,
    Project,
    User,
    UserSubscription,
)
from z4j_brain.settings import Settings


SECRET_WEBHOOK_URL = (
    "https://hooks.slack.com/services/T1234ABCD/B5678EFGH/SECRETTOKENXYZ"
)


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        login_min_duration_ms=10,
        registry_backend="local",
        metrics_public=True,
        disable_spa_fallback=True,
    )


@pytest.fixture
async def engine(settings: Settings):
    engine = create_async_engine(
        settings.database_url,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.mark.asyncio
async def test_real_delivery_error_masks_webhook_url_r7_m1(
    settings: Settings, engine, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real-delivery persistence path must mask config URLs.

    Pre-fix: ``getattr(p, "channel_config", None)`` returned None
    (real attribute is ``config``), the sanitiser skipped the
    config-value mask pass, and the secret webhook URL was
    persisted unmasked.

    Post-fix: ``p.config`` is passed through, the sanitiser
    replaces the URL substring with ``[REDACTED]``.
    """
    hasher = PasswordHasher(settings)

    user_id = uuid.uuid4()
    project_id = uuid.uuid4()
    channel_id = uuid.uuid4()
    sub_id = uuid.uuid4()

    from sqlalchemy.ext.asyncio import async_sessionmaker

    # Seed: user + project + membership + a webhook channel pointing
    # at the secret URL + a user_subscription bound to that channel.
    Session = async_sessionmaker(engine, expire_on_commit=False)
    async with Session() as s:
        s.add_all([
            Project(id=project_id, slug="r7m1", name="R7M1"),
            User(
                id=user_id,
                email=f"u-{uuid.uuid4().hex[:8]}@example.com",
                password_hash=hasher.hash(
                    "correct horse battery staple 9",
                ),
                is_admin=False,
                is_active=True,
            ),
            Membership(
                user_id=user_id, project_id=project_id,
                role=ProjectRole.VIEWER,
            ),
            NotificationChannel(
                id=channel_id,
                project_id=project_id,
                name="slack-ops",
                type="webhook",
                # The sanitiser masks config values for the
                # URL-bearing key set (``url``, ``webhook_url``,
                # ``bot_token``, ``integration_key``) whose value
                # is >= 8 chars long. ``url`` is the only relevant
                # key in this webhook config; the secret URL is
                # the substring we need to see redacted.
                config={
                    "url": SECRET_WEBHOOK_URL,
                    "hmac_secret": "supersecrethmackeyAAAAAAAAAAAAAA",
                },
                is_active=True,
            ),
            UserSubscription(
                id=sub_id,
                user_id=user_id,
                project_id=project_id,
                trigger="task.failed",
                filters={},
                # in_app False so we don't accidentally satisfy the
                # dispatch path via the in-app insert alone.
                in_app=False,
                project_channel_ids=[channel_id],
                user_channel_ids=[],
                cooldown_seconds=0,
                # last_fired_at NULL so the cooldown claim succeeds
                # without contention.
                last_fired_at=None,
                muted_until=None,
                is_active=True,
            ),
        ])
        await s.commit()

    # Stub the webhook dispatcher with one that returns a failed
    # outcome whose error + body text contains the full secret URL
    # (this is the realistic shape of an httpx / SSRF / 4xx error
    # message: the URL appears in the message). The dispatcher
    # signature is ``(config, payload) -> DeliveryResult``.
    async def _stub_webhook(
        config, payload,  # noqa: ANN001 - test stub matches signature
    ) -> DeliveryResult:
        # Real httpx errors often look like:
        # ``ConnectError: [...] sending request to
        # https://hooks.slack.com/...`` -- the URL appears verbatim
        # in the error string. That URL is what must be masked.
        msg = f"ConnectError: failed POST to {SECRET_WEBHOOK_URL}"
        body = f"<html>received at {SECRET_WEBHOOK_URL}</html>"
        return DeliveryResult(
            success=False,
            status_code=502,
            response_body=body,
            error=msg,
        )

    # CHANNEL_DISPATCHERS is a module-level dict the service reads
    # by key inside ``_run_pending_deliveries``. Monkeypatch the
    # webhook entry only.
    monkeypatch.setitem(
        channels_module.CHANNEL_DISPATCHERS, "webhook", _stub_webhook,
    )

    # Drive the real evaluate_and_dispatch path (the one that
    # constructs _PendingDelivery and persists notification_deliveries).
    async with Session() as s:
        service = NotificationService()
        dispatched = await service.evaluate_and_dispatch(
            session=s,
            project_id=project_id,
            trigger="task.failed",
            task_id="t-r7m1",
            task_name="r7m1.smoke",
            engine="celery",
            priority="normal",
            state="failed",
            queue=None,
            exception=None,
            traceback=None,
            project_slug="r7m1",
        )
        assert dispatched >= 1

    # Verify the persisted error + response_body are MASKED.
    # Pre-fix this assertion fails: the secret URL is present
    # verbatim in deliveries.error / deliveries.response_body.
    async with Session() as s:
        rows = (
            await s.execute(
                select(NotificationDelivery).where(
                    NotificationDelivery.project_id == project_id,
                ),
            )
        ).scalars().all()

    assert len(rows) == 1, (
        f"expected exactly one delivery row, got {len(rows)}"
    )
    row = rows[0]
    assert row.status == "failed"
    # The URL substring MUST be redacted in the error.
    assert SECRET_WEBHOOK_URL not in (row.error or ""), (
        "R7-M1 regression: webhook URL leaked unmasked into "
        f"notification_deliveries.error: {row.error!r}"
    )
    # The URL substring MUST be redacted in the response_body too.
    assert SECRET_WEBHOOK_URL not in (row.response_body or ""), (
        "R7-M1 regression: webhook URL leaked unmasked into "
        f"notification_deliveries.response_body: {row.response_body!r}"
    )
    # R7-M1 TWIN (pre-ship audit follow-up): channel_name was a
    # getattr against a slots dataclass field that never existed,
    # so it silently wrote NULL on every row. After the 1.6.6
    # fix, _PendingDelivery has a channel_name field populated
    # from channel.name at staging time and the persistence step
    # reads p.channel_name directly. Assert the row carries the
    # actual channel name (forensic UX gap that was hiding the
    # destination on every delivery audit row pre-fix).
    assert row.channel_name == "slack-ops", (
        "R7-M1 twin regression: channel_name was NULL on the "
        "persisted delivery row, breaking the Audit L-2 "
        "channel-rename snapshot. Expected 'slack-ops', got "
        f"{row.channel_name!r}."
    )
    assert row.channel_type == "webhook", (
        f"channel_type should be 'webhook', got {row.channel_type!r}"
    )
