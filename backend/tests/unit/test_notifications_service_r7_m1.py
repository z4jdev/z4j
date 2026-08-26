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

Structural identifier:."""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import uuid
from pathlib import Path

import pytest
from sqlalchemy import delete, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.domain.notifications import channels as channels_module
from z4j_brain.domain.notifications import service as notification_service_module
from z4j_brain.domain.notifications.channels import DeliveryResult
from z4j_brain.domain.notifications.service import NotificationService
from z4j_brain.persistence import models  # noqa: F401 - register tables
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import (
    Membership,
    NotificationChannel,
    NotificationDelivery,
    Project,
    User,
    UserChannel,
    UserSubscription,
)
from z4j_brain.settings import Settings

SECRET_WEBHOOK_URL = "https://hooks.slack.com/services/T1234ABCD/B5678EFGH/SECRETTOKENXYZ"


async def _seed_delivery_target(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    *,
    personal_channel: bool = False,
) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID]:
    """Seed one subscription-backed external delivery target."""

    user_id = uuid.uuid4()
    project_id = uuid.uuid4()
    channel_id = uuid.uuid4()
    sub_id = uuid.uuid4()
    hasher = PasswordHasher(settings)

    async with session_factory() as session:
        session.add_all(
            [
                Project(id=project_id, slug=f"r7m1-{project_id.hex[:8]}", name="R7M1"),
                User(
                    id=user_id,
                    email=f"u-{uuid.uuid4().hex[:8]}@example.com",
                    password_hash=hasher.hash("correct horse battery staple 9"),
                    is_admin=False,
                    is_active=True,
                ),
            ],
        )
        await session.flush()
        channel = (
            UserChannel(
                id=channel_id,
                user_id=user_id,
                name="slack-ops",
                type="webhook",
                config={
                    "url": SECRET_WEBHOOK_URL,
                    "hmac_secret": "supersecrethmackeyAAAAAAAAAAAAAA",
                },
                is_active=True,
            )
            if personal_channel
            else NotificationChannel(
                id=channel_id,
                project_id=project_id,
                name="slack-ops",
                type="webhook",
                config={
                    "url": SECRET_WEBHOOK_URL,
                    "hmac_secret": "supersecrethmackeyAAAAAAAAAAAAAA",
                },
                is_active=True,
            )
        )
        session.add_all(
            [
                Membership(
                    user_id=user_id,
                    project_id=project_id,
                    role=ProjectRole.VIEWER,
                ),
                channel,
                UserSubscription(
                    id=sub_id,
                    user_id=user_id,
                    project_id=project_id,
                    trigger="task.failed",
                    filters={},
                    in_app=False,
                    project_channel_ids=[] if personal_channel else [channel_id],
                    user_channel_ids=[channel_id] if personal_channel else [],
                    cooldown_seconds=0,
                    last_fired_at=None,
                    muted_until=None,
                    is_active=True,
                ),
            ],
        )
        await session.commit()

    return user_id, project_id, channel_id, sub_id


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
    # Production wraps even caller-supplied engines in DatabaseManager.  This
    # installs the SQLite FK checkout guard after StaticPool has already made
    # its one connection, covering the injected-engine path as well.
    DatabaseManager(engine)
    yield engine
    await engine.dispose()


@pytest.mark.asyncio
async def test_real_delivery_error_masks_webhook_url_r7_m1(
    settings: Settings,
    engine,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The real-delivery persistence path must mask config URLs.

    Pre-fix: ``getattr(p, "channel_config", None)`` returned None
    (real attribute is ``config``), the sanitiser skipped the
    config-value mask pass, and the secret webhook URL was
    persisted unmasked.

    Post-fix: ``p.config`` is passed through, the sanitiser
    replaces the URL substring with ``[REDACTED]``.
    """
    # Seed: user + project + membership + a webhook channel pointing
    # at the secret URL + a user_subscription bound to that channel.
    Session = async_sessionmaker(engine, expire_on_commit=False)  # noqa: N806  SQLAlchemy sessionmaker naming convention
    user_id, project_id, _channel_id, sub_id = await _seed_delivery_target(
        Session,
        settings,
    )

    # Stub the webhook dispatcher with one that returns a failed
    # outcome whose error + body text contains the full secret URL
    # (this is the realistic shape of an httpx / SSRF / 4xx error
    # message: the URL appears in the message). The dispatcher
    # signature is ``(config, payload) -> DeliveryResult``.
    async def _stub_webhook(
        config,
        payload,
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
        channels_module.CHANNEL_DISPATCHERS,
        "webhook",
        _stub_webhook,
    )
    from unittest.mock import Mock

    record_metric = Mock(wraps=notification_service_module._record_delivery_metric)
    monkeypatch.setattr(
        notification_service_module,
        "_record_delivery_metric",
        record_metric,
    )

    service = NotificationService()
    run_pending = service._run_pending_deliveries

    async def _run_then_delete_subscription(pending, payload):
        outcomes = await run_pending(pending, payload)
        # Reproduce the real network-gap race: pass 1 has committed and the
        # send completed, but the owner deletes the subscription before the
        # audit insert.  The durable recipient snapshot must survive while the
        # now-stale live FK is written as NULL.
        async with Session() as delete_session:
            await delete_session.execute(
                delete(UserSubscription).where(UserSubscription.id == sub_id),
            )
            await delete_session.commit()
        return outcomes

    monkeypatch.setattr(
        service,
        "_run_pending_deliveries",
        _run_then_delete_subscription,
    )
    caplog.set_level("WARNING", logger="z4j.brain.notifications.service")

    # Drive the real evaluate_and_dispatch path (the one that
    # constructs _PendingDelivery and persists notification_deliveries).
    async with Session() as s:
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
    record_metric.assert_called_once()
    assert record_metric.call_args.args[0].success is False

    # Verify the persisted error + response_body are MASKED.
    # Pre-fix this assertion fails: the secret URL is present
    # verbatim in deliveries.error / deliveries.response_body.
    async with Session() as s:
        rows = (
            (
                await s.execute(
                    select(NotificationDelivery).where(
                        NotificationDelivery.project_id == project_id,
                    ),
                )
            )
            .scalars()
            .all()
        )

    assert len(rows) == 1, f"expected exactly one delivery row, got {len(rows)}"
    row = rows[0]
    assert row.status == "failed"
    # The URL substring MUST be redacted in the error.
    assert SECRET_WEBHOOK_URL not in (row.error or ""), (
        " regression: webhook URL leaked unmasked into "
        f"notification_deliveries.error: {row.error!r}"
    )
    # The URL substring MUST be redacted in the response_body too.
    assert SECRET_WEBHOOK_URL not in (row.response_body or ""), (
        " regression: webhook URL leaked unmasked into "
        f"notification_deliveries.response_body: {row.response_body!r}"
    )
    # TWIN (pre-ship audit follow-up): channel_name was a
    # getattr against a slots dataclass field that never existed,
    # so it silently wrote NULL on every row. After the 1.6.6
    # fix, _PendingDelivery has a channel_name field populated
    # from channel.name at staging time and the persistence step
    # reads p.channel_name directly. Assert the row carries the
    # actual channel name (forensic UX gap that was hiding the
    # destination on every delivery audit row pre-fix).
    assert row.channel_name == "slack-ops", (
        " twin regression: channel_name was NULL on the "
        "persisted delivery row, breaking the Audit L-2 "
        "channel-rename snapshot. Expected 'slack-ops', got "
        f"{row.channel_name!r}."
    )
    assert row.channel_type == "webhook", (
        f"channel_type should be 'webhook', got {row.channel_type!r}"
    )
    assert row.recipient_user_id == user_id, (
        "subscription-driven delivery did not snapshot its recipient; "
        "personal history would disappear after subscription deletion"
    )
    assert row.subscription_id is None
    assert SECRET_WEBHOOK_URL not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("delete_target", "personal_channel"),
    [
        ("subscription", False),
        ("project_channel", False),
        ("user_channel", True),
        ("recipient", False),
    ],
)
async def test_network_gap_deletes_clear_only_stale_audit_references(
    settings: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    delete_target: str,
    personal_channel: bool,
) -> None:
    """Every nullable FK may disappear during a file-SQLite network gap."""

    sqlite_engine = create_async_engine(
        f"sqlite+aiosqlite:///{tmp_path / f'network-gap-{delete_target}.sqlite3'}",
    )
    database = DatabaseManager(sqlite_engine)
    try:
        async with sqlite_engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        Session = async_sessionmaker(sqlite_engine, expire_on_commit=False)  # noqa: N806  SQLAlchemy sessionmaker naming convention
        user_id, project_id, channel_id, sub_id = await _seed_delivery_target(
            Session,
            settings,
            personal_channel=personal_channel,
        )

        async def _stub_webhook(config, payload) -> DeliveryResult:
            del config, payload
            return DeliveryResult(success=True, status_code=204)

        monkeypatch.setitem(
            channels_module.CHANNEL_DISPATCHERS,
            "webhook",
            _stub_webhook,
        )
        service = NotificationService()
        run_pending = service._run_pending_deliveries

        async def _run_then_delete_target(pending, payload):
            outcomes = await run_pending(pending, payload)
            async with database.session(write=True) as delete_session:
                if delete_target == "subscription":
                    statement = delete(UserSubscription).where(
                        UserSubscription.id == sub_id,
                    )
                elif delete_target == "project_channel":
                    statement = delete(NotificationChannel).where(
                        NotificationChannel.id == channel_id,
                    )
                elif delete_target == "user_channel":
                    statement = delete(UserChannel).where(UserChannel.id == channel_id)
                else:
                    statement = delete(User).where(User.id == user_id)
                await delete_session.execute(statement)
                await delete_session.commit()
            return outcomes

        monkeypatch.setattr(
            service,
            "_run_pending_deliveries",
            _run_then_delete_target,
        )

        async with Session() as session:
            dispatched = await service.evaluate_and_dispatch(
                session=session,
                project_id=project_id,
                trigger="task.failed",
                task_id=f"network-gap-{delete_target}",
                task_name="network.gap",
                project_slug="network-gap",
            )
        assert dispatched == 1

        async with Session() as session:
            row = (
                await session.scalars(
                    select(NotificationDelivery).where(
                        NotificationDelivery.project_id == project_id,
                    ),
                )
            ).one()

        assert row.status == "sent"
        assert row.channel_name == "slack-ops"
        assert row.channel_type == "webhook"
        assert row.subscription_id == (
            None if delete_target in {"subscription", "recipient"} else sub_id
        )
        assert row.recipient_user_id == (None if delete_target == "recipient" else user_id)
        assert row.channel_id == (
            channel_id if not personal_channel and delete_target != "project_channel" else None
        )
        assert row.user_channel_id == (
            channel_id
            if personal_channel and delete_target not in {"user_channel", "recipient"}
            else None
        )
    finally:
        await sqlite_engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("delete_target", "personal_channel"),
    [
        ("subscription", False),
        ("project_channel", False),
        ("user_channel", True),
        ("recipient", False),
    ],
)
async def test_stale_optional_fk_probe_retries_with_only_live_references(
    settings: Settings,
    engine,
    monkeypatch: pytest.MonkeyPatch,
    delete_target: str,
    personal_channel: bool,
) -> None:
    """An FK race after the probe retries without discarding ownership."""

    Session = async_sessionmaker(engine, expire_on_commit=False)  # noqa: N806  SQLAlchemy sessionmaker naming convention
    user_id, project_id, channel_id, sub_id = await _seed_delivery_target(
        Session,
        settings,
        personal_channel=personal_channel,
    )

    async def _stub_webhook(config, payload) -> DeliveryResult:
        del config, payload
        return DeliveryResult(success=True, status_code=204)

    monkeypatch.setitem(
        channels_module.CHANNEL_DISPATCHERS,
        "webhook",
        _stub_webhook,
    )
    service = NotificationService()
    run_pending = service._run_pending_deliveries

    async def _run_then_delete_target(pending, payload):
        outcomes = await run_pending(pending, payload)
        async with Session() as delete_session:
            if delete_target == "subscription":
                statement = delete(UserSubscription).where(
                    UserSubscription.id == sub_id,
                )
            elif delete_target == "project_channel":
                statement = delete(NotificationChannel).where(
                    NotificationChannel.id == channel_id,
                )
            elif delete_target == "user_channel":
                statement = delete(UserChannel).where(UserChannel.id == channel_id)
            elif delete_target == "recipient":
                statement = delete(User).where(User.id == user_id)
            await delete_session.execute(statement)
            await delete_session.commit()
        return outcomes

    monkeypatch.setattr(
        service,
        "_run_pending_deliveries",
        _run_then_delete_target,
    )

    # Return the pre-delete references once, reproducing a target deletion
    # that commits after PostgreSQL's live probes but before its INSERT FK
    # check.  The first real insert fails inside the savepoint; the next probe
    # sees the committed delete and the retry must preserve all other links.
    original_resolve = notification_service_module._resolve_live_delivery_references
    resolve_calls = 0

    async def _stale_once(*, session, pending):
        nonlocal resolve_calls
        resolve_calls += 1
        if resolve_calls == 1:
            return notification_service_module._LiveDeliveryReferences(
                subscription_id=sub_id,
                recipient_user_id=user_id,
                channel_id=None if personal_channel else channel_id,
                user_channel_id=channel_id if personal_channel else None,
            )
        return await original_resolve(session=session, pending=pending)

    monkeypatch.setattr(
        notification_service_module,
        "_resolve_live_delivery_references",
        _stale_once,
    )

    async with Session() as session:
        dispatched = await service.evaluate_and_dispatch(
            session=session,
            project_id=project_id,
            trigger="task.failed",
            task_id=f"stale-probe-{delete_target}",
            task_name="stale.probe",
            project_slug="stale-probe",
        )
    assert dispatched == 1
    assert resolve_calls == 2

    async with Session() as session:
        row = (
            await session.scalars(
                select(NotificationDelivery).where(
                    NotificationDelivery.project_id == project_id,
                ),
            )
        ).one()

    assert row.status == "sent"
    assert row.channel_name == "slack-ops"
    assert row.channel_type == "webhook"
    assert row.subscription_id == (
        None if delete_target in {"subscription", "recipient"} else sub_id
    )
    assert row.recipient_user_id == (None if delete_target == "recipient" else user_id)
    assert row.channel_id == (
        channel_id if not personal_channel and delete_target != "project_channel" else None
    )
    assert row.user_channel_id == (
        channel_id
        if personal_channel and delete_target not in {"user_channel", "recipient"}
        else None
    )


@pytest.mark.asyncio
async def test_nullable_fk_retry_is_bounded_to_four_monotonic_clears(
    engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Continuous FK conflicts stop after one attempt per nullable pointer."""

    ids = [uuid.uuid4() for _ in range(5)]
    pending = notification_service_module._PendingDelivery(
        subscription_id=ids[0],
        recipient_user_id=ids[1],
        channel_id=ids[2],
        user_channel_id=ids[3],
        channel_type="webhook",
        channel_name="bounded",
        config={},
        project_id=ids[4],
        trigger="task.failed",
        task_id=None,
        task_name=None,
    )
    outcome = notification_service_module._DeliveryOutcome(
        pending=pending,
        success=True,
    )
    reference_states = iter(
        [
            notification_service_module._LiveDeliveryReferences(
                subscription_id=ids[0],
                recipient_user_id=ids[1],
                channel_id=ids[2],
                user_channel_id=ids[3],
            ),
            notification_service_module._LiveDeliveryReferences(
                subscription_id=None,
                recipient_user_id=ids[1],
                channel_id=ids[2],
                user_channel_id=ids[3],
            ),
            notification_service_module._LiveDeliveryReferences(
                subscription_id=None,
                recipient_user_id=None,
                channel_id=ids[2],
                user_channel_id=ids[3],
            ),
            notification_service_module._LiveDeliveryReferences(
                subscription_id=None,
                recipient_user_id=None,
                channel_id=None,
                user_channel_id=ids[3],
            ),
            notification_service_module._LiveDeliveryReferences(
                subscription_id=None,
                recipient_user_id=None,
                channel_id=None,
                user_channel_id=None,
            ),
        ],
    )
    resolve_calls = 0
    flush_calls = 0

    async def _resolve_sequence(*, session, pending):
        del session, pending
        nonlocal resolve_calls
        resolve_calls += 1
        return next(reference_states)

    async def _always_conflict(**kwargs):
        del kwargs
        nonlocal flush_calls
        flush_calls += 1
        raise IntegrityError("INSERT", {}, RuntimeError("forced FK conflict"))

    monkeypatch.setattr(
        notification_service_module,
        "_resolve_live_delivery_references",
        _resolve_sequence,
    )
    monkeypatch.setattr(
        notification_service_module,
        "_flush_delivery_audit",
        _always_conflict,
    )

    Session = async_sessionmaker(engine, expire_on_commit=False)  # noqa: N806  SQLAlchemy sessionmaker naming convention
    async with Session() as session:
        with pytest.raises(IntegrityError, match="forced FK conflict"):
            await notification_service_module._persist_delivery_audit(
                session=session,
                pending=pending,
                outcome=outcome,
                sanitized_error=None,
                sanitized_body=None,
            )

    assert flush_calls == 5
    assert resolve_calls == 5


@pytest.mark.asyncio
async def test_file_sqlite_delete_after_probe_waits_for_delivery_audit(
    settings: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A SQLite delete after the live probe must not lose the sent audit.

    This uses two real connections to a file database.  The delete statement
    is issued only after pass 3 has completed its subscription SELECT and
    entered the audit-flush call.  Pass 3 must already own SQLite's writer
    reservation, so the delete waits for the audit commit and subsequently
    nulls the optional subscription pointer through the production FK.
    """

    database_path = tmp_path / "notification-audit-race.sqlite3"
    sqlite_engine = create_async_engine(
        f"sqlite+aiosqlite:///{database_path}",
        connect_args={"timeout": 2},
    )
    database = DatabaseManager(sqlite_engine)
    delete_task: asyncio.Task[None] | None = None
    delete_begin_issued = asyncio.Event()
    delete_lock_acquired = asyncio.Event()

    try:
        async with sqlite_engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        Session = async_sessionmaker(sqlite_engine, expire_on_commit=False)  # noqa: N806  SQLAlchemy sessionmaker naming convention
        user_id, project_id, _channel_id, sub_id = await _seed_delivery_target(
            Session,
            settings,
        )

        async def _stub_webhook(config, payload) -> DeliveryResult:
            del config, payload
            return DeliveryResult(success=True, status_code=204)

        monkeypatch.setitem(
            channels_module.CHANNEL_DISPATCHERS,
            "webhook",
            _stub_webhook,
        )

        async def _delete_subscription() -> None:
            async with database.session(write=True) as delete_session:
                delete_lock_acquired.set()
                await delete_session.execute(
                    delete(UserSubscription).where(UserSubscription.id == sub_id),
                )
                await delete_session.commit()

        original_flush = notification_service_module._flush_delivery_audit

        async def _flush_after_delete_attempt(
            *,
            session: AsyncSession,
            pending: notification_service_module._PendingDelivery,
            outcome: notification_service_module._DeliveryOutcome,
            references: notification_service_module._LiveDeliveryReferences,
            sanitized_error: str | None,
            sanitized_body: str | None,
        ) -> None:
            nonlocal delete_task

            # Install the observer only after pass 3's own BEGIN IMMEDIATE and
            # ownership SELECT have completed.  The next BEGIN IMMEDIATE is
            # therefore the second connection's delete reservation.
            def _observe_delete_begin(
                connection: object,
                cursor: object,
                statement: str,
                parameters: object,
                context: object,
                executemany: bool,
            ) -> None:
                del connection, cursor, parameters, context, executemany
                if statement.strip().upper() == "BEGIN IMMEDIATE":
                    delete_begin_issued.set()

            event.listen(
                sqlite_engine.sync_engine,
                "before_cursor_execute",
                _observe_delete_begin,
                once=True,
            )
            delete_task = asyncio.create_task(_delete_subscription())
            await asyncio.wait_for(delete_begin_issued.wait(), timeout=1)
            # The delete's BEGIN IMMEDIATE reached SQLite after the ownership
            # probe, but pass 3 reserved the writer first, so the second
            # connection cannot acquire it before the audit transaction
            # commits.
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(delete_lock_acquired.wait(), timeout=0.1)
            await original_flush(
                session=session,
                pending=pending,
                outcome=outcome,
                references=references,
                sanitized_error=sanitized_error,
                sanitized_body=sanitized_body,
            )

        monkeypatch.setattr(
            notification_service_module,
            "_flush_delivery_audit",
            _flush_after_delete_attempt,
        )

        async with Session() as session:
            dispatched = await NotificationService().evaluate_and_dispatch(
                session=session,
                project_id=project_id,
                trigger="task.failed",
                task_id="sqlite-probe-delete-race",
                task_name="sqlite.race",
                project_slug="sqlite-race",
            )
        assert dispatched == 1
        assert delete_task is not None
        await asyncio.wait_for(delete_task, timeout=2)

        async with Session() as session:
            rows = (
                (
                    await session.execute(
                        select(NotificationDelivery).where(
                            NotificationDelivery.project_id == project_id,
                        ),
                    )
                )
                .scalars()
                .all()
            )
            assert await session.get(UserSubscription, sub_id) is None

        assert len(rows) == 1
        assert rows[0].status == "sent"
        assert rows[0].recipient_user_id == user_id
        assert rows[0].subscription_id is None
    finally:
        if delete_task is not None and not delete_task.done():
            delete_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await delete_task
        await sqlite_engine.dispose()
