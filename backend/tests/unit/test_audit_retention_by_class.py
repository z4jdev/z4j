"""Retention by action class (``Z4J_AUDIT_RETENTION_BY_CLASS``).

Covers the setting's validation, the pure cutoff and prefix rule, and both
sweep paths of ``AuditRetentionSweeper`` honouring it: the keyless legacy
path on a ``create_all()`` schema (rows inserted directly, dated into the
past) and the authenticated v2 path on an activated chain written through
the real ``AuditService``. Also the removed ten-year ceiling on
``audit_retention_days`` and the startup WARNING that replaced it.
"""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from z4j_brain.audit_retention import (
    AuditRetentionSweeper,
    RetentionCutoffs,
    action_class,
    expired_predicate,
    expired_prefix,
)
from z4j_brain.domain.audit_chain import make_empty_chain_state
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.audit_verifier import verify_active_audit_generation
from z4j_brain.persistence import models  # noqa: F401  registers metadata
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import AuditChainState, AuditLog
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.settings import AUDIT_RETENTION_WARN_DAYS, Settings

MASTER = "master-secret-that-is-not-the-audit-key-000000"
SESSION = "session-secret-that-is-not-the-audit-key-0000"
AUDIT = "audit-only-secret-that-is-independent-000000000"


def _keyless_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "database_url": "sqlite+aiosqlite:///:memory:",
        "secret": secrets.token_urlsafe(48),
        "session_secret": secrets.token_urlsafe(48),
        "environment": "dev",
        "audit_retention_days": 30,
        "audit_retention_sweep_batch_size": 100,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _keyed_settings(**overrides: object) -> Settings:
    return _keyless_settings(
        secret=MASTER,
        session_secret=SESSION,
        audit_chain_secret=AUDIT,
        **overrides,
    )


# ---------------------------------------------------------------------------
# Settings validation
# ---------------------------------------------------------------------------


def test_by_class_defaults_to_empty_and_accepts_json_or_dict() -> None:
    assert _keyless_settings().audit_retention_by_class == {}
    as_json = _keyless_settings(audit_retention_by_class='{"auth": 365, "command": 30}')
    assert as_json.audit_retention_by_class == {"auth": 365, "command": 30}
    as_dict = _keyless_settings(audit_retention_by_class={"dead_letters": 7})
    assert as_dict.audit_retention_by_class == {"dead_letters": 7}
    assert _keyless_settings(audit_retention_by_class="").audit_retention_by_class == {}


@pytest.mark.parametrize(
    "raw",
    [
        "[365]",
        "not json",
        '{"auth.login": 365}',
        '{"Auth": 365}',
        '{"": 365}',
        '{"auth": true}',
        '{"auth": 30.5}',
        '{"auth": "30"}',
        '{"auth": 0}',
        '{"auth": -1}',
    ],
    ids=[
        "not-an-object",
        "invalid-json",
        "whole-action-not-class",
        "uppercase-key",
        "empty-key",
        "bool-value",
        "float-value",
        "string-value",
        "zero-days",
        "negative-days",
    ],
)
def test_by_class_rejects_bad_shapes_at_construction(raw: str) -> None:
    with pytest.raises(ValidationError, match="audit_retention_by_class"):
        _keyless_settings(audit_retention_by_class=raw)


def test_retention_days_has_no_ceiling_and_long_windows_are_named() -> None:
    assert _keyless_settings().retention_windows_over_ten_years() == []
    long = _keyless_settings(
        audit_retention_days=AUDIT_RETENTION_WARN_DAYS + 1,
        audit_retention_by_class={"auth": 7300, "command": 30},
    )
    assert long.audit_retention_days == AUDIT_RETENTION_WARN_DAYS + 1
    assert long.retention_windows_over_ten_years() == [
        f"Z4J_AUDIT_RETENTION_DAYS={AUDIT_RETENTION_WARN_DAYS + 1}",
        "Z4J_AUDIT_RETENTION_BY_CLASS[auth]=7300",
    ]
    with pytest.raises(ValidationError):
        _keyless_settings(audit_retention_days=0)


def test_startup_logs_one_warning_for_a_window_over_ten_years(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The brain's logger is structlog writing JSON lines to stdout."""
    from z4j_brain.main import create_app

    create_app(_keyless_settings(audit_retention_days=4000, metrics_public=True))
    lines = [line for line in capsys.readouterr().out.splitlines() if "exceeds ten years" in line]
    assert len(lines) == 1
    assert "Z4J_AUDIT_RETENTION_DAYS=4000" in lines[0]
    assert '"level": "warning"' in lines[0]

    create_app(_keyless_settings(metrics_public=True))
    assert "exceeds ten years" not in capsys.readouterr().out


# ---------------------------------------------------------------------------
# The pure rule
# ---------------------------------------------------------------------------


def test_action_class_is_the_first_dotted_segment() -> None:
    assert action_class("command.issue.requeue_dead_letter") == "command"
    assert action_class("dead_letters.list") == "dead_letters"
    assert action_class("auth") == "auth"


def test_cutoffs_follow_the_class_and_latest_is_the_newest() -> None:
    now = datetime(2026, 6, 1, tzinfo=UTC)
    cutoffs = RetentionCutoffs.from_settings(
        _keyless_settings(
            audit_retention_days=90,
            audit_retention_by_class={"auth": 365, "command": 10},
        ),
        now,
    )
    assert cutoffs.default == now - timedelta(days=90)
    assert cutoffs.cutoff_for("auth.login") == now - timedelta(days=365)
    assert cutoffs.cutoff_for("command.issue") == now - timedelta(days=10)
    assert cutoffs.cutoff_for("schedule.create") == now - timedelta(days=90)
    assert cutoffs.latest == now - timedelta(days=10)
    assert cutoffs.label == "retention: 90 days, auth 365 days, command 10 days"
    assert cutoffs.expired("auth.login", now - timedelta(days=366))
    assert not cutoffs.expired("auth.login", now - timedelta(days=364))
    # Naive timestamps from SQLite are read as UTC, like everywhere else.
    assert cutoffs.expired("command.issue", (now - timedelta(days=11)).replace(tzinfo=None))

    explicit = RetentionCutoffs.before(datetime(2026, 1, 31, 12, 0, tzinfo=UTC))
    assert explicit.cutoff_for("auth.login") == explicit.default
    assert explicit.latest == explicit.default
    assert explicit.label == "--before 2026-01-31T12:00:00Z"


def test_expired_prefix_stops_at_the_first_row_its_class_keeps() -> None:
    now = datetime(2026, 6, 1, tzinfo=UTC)
    cutoffs = RetentionCutoffs.from_settings(
        _keyless_settings(audit_retention_days=90, audit_retention_by_class={"auth": 365}),
        now,
    )
    rows = [
        SimpleNamespace(action="command.issue", occurred_at=now - timedelta(days=400)),
        SimpleNamespace(action="auth.login", occurred_at=now - timedelta(days=400)),
        SimpleNamespace(action="command.issue", occurred_at=now - timedelta(days=200)),
        SimpleNamespace(action="auth.login", occurred_at=now - timedelta(days=200)),
        SimpleNamespace(action="command.issue", occurred_at=now - timedelta(days=100)),
        SimpleNamespace(action="command.issue", occurred_at=now - timedelta(days=1)),
    ]
    # The auth row at 200 days is inside its 365-day window, so the prefix
    # ends before it even though the command row after it is expired.
    assert expired_prefix(rows, cutoffs) == rows[:3]
    assert expired_prefix([], cutoffs) == []
    assert expired_prefix(rows[3:], cutoffs) == []


# ---------------------------------------------------------------------------
# Legacy (keyless) sweep
# ---------------------------------------------------------------------------


async def _legacy_db() -> DatabaseManager:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return DatabaseManager(engine)


async def _insert_legacy(db: DatabaseManager, action: str, *, days_ago: int) -> None:
    async with db.session() as session:
        session.add(
            AuditLog(
                action=action,
                target_type="test",
                target_id="x",
                result="success",
                occurred_at=datetime.now(UTC) - timedelta(days=days_ago),
            ),
        )
        await session.commit()


async def _legacy_actions(db: DatabaseManager) -> list[str]:
    async with db.session() as session:
        return list(
            (
                await session.execute(
                    select(AuditLog.action).order_by(AuditLog.occurred_at, AuditLog.id),
                )
            ).scalars(),
        )


async def test_legacy_sweep_holds_the_prefix_at_a_longer_class_window() -> None:
    db = await _legacy_db()
    try:
        await _insert_legacy(db, "command.issue", days_ago=45)
        await _insert_legacy(db, "auth.login", days_ago=44)
        await _insert_legacy(db, "command.issue", days_ago=43)
        await _insert_legacy(db, "command.issue", days_ago=1)
        sweeper = AuditRetentionSweeper()
        sweeper.bind(
            db=db,
            settings=_keyless_settings(audit_retention_by_class={"auth": 365}),
        )
        assert await sweeper.sweep_once() == 1
        assert await _legacy_actions(db) == ["auth.login", "command.issue", "command.issue"]

        # Without the class window the same policy removes the whole old prefix.
        sweeper.bind(db=db, settings=_keyless_settings())
        assert await sweeper.sweep_once() == 2
        assert await _legacy_actions(db) == ["command.issue"]
    finally:
        await db.engine.dispose()


@pytest.fixture(autouse=True)
def _capture_retention_logger(caplog: pytest.LogCaptureFixture):
    """Attach the capture handler to the module logger itself, enabled.

    In the whole brain suite an earlier test runs a migration in-process, and
    alembic's ``fileConfig`` used to disable every logger that already existed
    (``disable_existing_loggers`` defaults to true), this module's included,
    so its records were dropped before any handler saw them. The migration
    environment now keeps existing loggers enabled; this fixture re-enables
    the logger and captures at it anyway so the assertion stays
    order-independent whatever another test does to the logging tree.
    """
    logger = logging.getLogger("z4j.brain.audit_retention")
    was_disabled = logger.disabled
    was_propagate = logger.propagate
    logger.disabled = False
    # Capture only through the handler attached here: with propagation on,
    # the root capture handler would record the same event a second time.
    logger.propagate = False
    logger.addHandler(caplog.handler)
    try:
        yield
    finally:
        logger.removeHandler(caplog.handler)
        logger.disabled = was_disabled
        logger.propagate = was_propagate


def _blocker_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.WARNING and "prune stopped at" in record.getMessage()
    ]


async def test_legacy_sweep_warns_once_when_a_retained_row_holds_expired_rows_behind_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A class window that holds the line is reported, with what it holds.

    Nothing behind the retained row is pruned, however old; silence here is
    how a longer class window came to retain several times the configured
    window without anyone being told. One WARNING per pass names the row's
    class and age, the cutoff its class keeps it until, and the expired rows
    waiting behind it.
    """
    db = await _legacy_db()
    try:
        await _insert_legacy(db, "command.issue", days_ago=45)
        await _insert_legacy(db, "auth.login", days_ago=44)
        await _insert_legacy(db, "command.issue", days_ago=43)
        await _insert_legacy(db, "command.issue", days_ago=42)
        await _insert_legacy(db, "command.issue", days_ago=1)
        sweeper = AuditRetentionSweeper()
        sweeper.bind(
            db=db,
            settings=_keyless_settings(audit_retention_by_class={"auth": 365}),
        )
        with caplog.at_level(logging.WARNING, logger="z4j.brain.audit_retention"):
            assert await sweeper.sweep_once() == 1
        warnings = _blocker_warnings(caplog)
        assert len(warnings) == 1
        assert "stopped at a auth row (auth.login, 44 days old" in warnings[0]
        assert "2 expired row(s) retained behind it" in warnings[0]
        assert "auth 365 days" in warnings[0]

        # Negative control: the same blocker with only retained rows behind it
        # has nothing to warn about.
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="z4j.brain.audit_retention"):
            sweeper.bind(
                db=db,
                settings=_keyless_settings(
                    audit_retention_days=44,
                    audit_retention_by_class={"auth": 365},
                ),
            )
            assert await sweeper.sweep_once() == 0
        assert _blocker_warnings(caplog) == []
    finally:
        await db.engine.dispose()


async def test_expired_predicate_agrees_with_the_python_rule() -> None:
    """The SQL count behind the blocker is the Python rule, class escaping included."""
    db = await _legacy_db()
    try:
        for action, days_ago in (
            ("command.issue", 50),
            ("dead_letters.list", 50),
            ("dead_letters", 50),
            ("deadXletters.list", 50),
            ("auth.login", 50),
            ("auth.login", 10),
            ("command.issue", 10),
        ):
            await _insert_legacy(db, action, days_ago=days_ago)
        cutoffs = RetentionCutoffs.from_settings(
            _keyless_settings(
                audit_retention_days=30,
                audit_retention_by_class={"dead_letters": 365, "auth": 5},
            ),
            datetime.now(UTC),
        )
        async with db.session() as session:
            rows = list((await session.execute(select(AuditLog))).scalars())
            counted = int(
                (
                    await session.execute(
                        select(func.count()).select_from(AuditLog).where(expired_predicate(cutoffs))
                    )
                ).scalar_one()
            )
            expired = sorted(
                row.action for row in rows if cutoffs.expired(row.action, row.occurred_at)
            )
        # ``dead_letters`` rows are kept for a year; the LIKE underscore is
        # escaped, so ``deadXletters`` is not mistaken for that class and
        # expires under the global window like any other.
        assert expired == ["auth.login", "auth.login", "command.issue", "deadXletters.list"]
        assert counted == len(expired)
    finally:
        await db.engine.dispose()


async def test_legacy_sweep_shorter_class_window_only_reaches_past_retained_neighbours() -> None:
    db = await _legacy_db()
    try:
        await _insert_legacy(db, "command.issue", days_ago=20)
        await _insert_legacy(db, "auth.login", days_ago=19)
        await _insert_legacy(db, "command.issue", days_ago=18)
        sweeper = AuditRetentionSweeper()
        sweeper.bind(
            db=db,
            settings=_keyless_settings(
                audit_retention_days=90,
                audit_retention_by_class={"command": 10},
            ),
        )
        # The first command row is past its ten days; the auth row behind it
        # is well inside the global window and stops the prefix there.
        assert await sweeper.sweep_once() == 1
        assert await _legacy_actions(db) == ["auth.login", "command.issue"]
        assert await sweeper.sweep_once() == 0
    finally:
        await db.engine.dispose()


# ---------------------------------------------------------------------------
# Authenticated (v2) sweep
# ---------------------------------------------------------------------------


async def _activated_engine(service: AuditService, monkeypatch: pytest.MonkeyPatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    old_now = datetime.now(UTC) - timedelta(days=40)

    class OldClock(datetime):
        @classmethod
        def now(cls, tz=None):  # type: ignore[override]
            return old_now if tz is not None else old_now.replace(tzinfo=None)

    monkeypatch.setattr("z4j_brain.domain.audit_service.datetime", OldClock)
    async with AsyncSession(engine, expire_on_commit=False) as session:
        await session.execute(text("BEGIN IMMEDIATE"))
        session.sync_session.info["z4j_sqlite_immediate"] = True
        state = make_empty_chain_state(secret=AUDIT.encode())
        session.add(state)
        await session.flush()
        await service.record(
            AuditLogRepository(session),
            action="audit.chain_generation_started",
            target_type="audit_chain",
            target_id=str(state.generation),
        )
        await session.commit()
    for action in ("command.issue", "auth.login", "command.issue"):
        async with AsyncSession(engine, expire_on_commit=False) as session:
            await service.record(AuditLogRepository(session), action=action, target_type="test")
            await session.commit()
    monkeypatch.setattr("z4j_brain.domain.audit_service.datetime", datetime)
    async with AsyncSession(engine, expire_on_commit=False) as session:
        await service.record(AuditLogRepository(session), action="command.issue", target_type="t")
        await session.commit()
    return engine


async def _v2_rows(engine) -> list[AuditLog]:
    async with AsyncSession(engine, expire_on_commit=False) as session:
        return list(
            (
                await session.execute(
                    select(AuditLog).order_by(AuditLog.occurred_at, AuditLog.id),
                )
            ).scalars(),
        )


async def test_v2_sweep_honours_the_class_window_and_verify_stays_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _keyed_settings(audit_retention_by_class={"auth": 365})
    service = AuditService(settings)
    engine = await _activated_engine(service, monkeypatch)
    try:
        before = await _v2_rows(engine)
        assert [row.action for row in before] == [
            "audit.chain_generation_started",
            "command.issue",
            "auth.login",
            "command.issue",
            "command.issue",
        ]
        sweeper = AuditRetentionSweeper()
        sweeper.bind(db=DatabaseManager(engine), settings=settings)
        assert await sweeper.sweep_once() == 2

        after = await _v2_rows(engine)
        assert [row.id for row in after] == [row.id for row in before[2:]]
        async with AsyncSession(engine, expire_on_commit=False) as session:
            state = (await session.execute(select(AuditChainState))).scalar_one()
            assert state.prune_id == before[1].id
            assert state.active_row_count == 3
        # The verifier opens its own immediate write unit, so it gets a session
        # that has not read anything yet.
        async with AsyncSession(engine, expire_on_commit=False) as session:
            report = await verify_active_audit_generation(session, settings, page_size=2)
            await session.rollback()
        assert report.clean, report.mismatches

        # Dropping the class window lets the next pass take the rest of the
        # old prefix, still ending exactly at the retention cutoff.
        plain = _keyed_settings()
        sweeper.bind(db=DatabaseManager(engine), settings=plain)
        assert await sweeper.sweep_once() == 2
        assert [row.id for row in await _v2_rows(engine)] == [before[4].id]
        async with AsyncSession(engine, expire_on_commit=False) as session:
            report = await verify_active_audit_generation(session, plain, page_size=2)
            await session.rollback()
        assert report.clean, report.mismatches
    finally:
        await engine.dispose()


async def test_v2_sweep_warns_about_the_row_holding_the_prefix(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The authenticated path reports the blocker too, scoped to the generation."""
    settings = _keyed_settings(audit_retention_by_class={"auth": 365})
    service = AuditService(settings)
    engine = await _activated_engine(service, monkeypatch)
    try:
        sweeper = AuditRetentionSweeper()
        sweeper.bind(db=DatabaseManager(engine), settings=settings)
        with caplog.at_level(logging.WARNING, logger="z4j.brain.audit_retention"):
            assert await sweeper.sweep_once() == 2
        warnings = _blocker_warnings(caplog)
        assert len(warnings) == 1
        # The forty-day-old auth row holds the line; the forty-day-old command
        # row behind it is expired and stays.
        assert "stopped at a auth row (auth.login, 40 days old" in warnings[0]
        assert "1 expired row(s) retained behind it" in warnings[0]

        # A second pass with nothing left to remove in front of the blocker
        # still says so once, and only once.
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="z4j.brain.audit_retention"):
            assert await sweeper.sweep_once() == 0
        assert len(_blocker_warnings(caplog)) == 1
    finally:
        await engine.dispose()
