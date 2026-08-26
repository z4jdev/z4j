"""Adversarial contracts for the persistent and in-process rate limiters."""

from __future__ import annotations

import asyncio
import math
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi import HTTPException, Request, status
from sqlalchemy import Table
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.engine import Dialect
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.domain.ip_rate_limit import (
    _IPBucket,
    _login_bucket,
    _mfa_verify_bucket,
    _setup_bucket,
    require_login_throttle,
    require_mfa_verify_throttle,
    require_setup_throttle,
)
from z4j_brain.domain.scheduler_rate_limiter import (
    SchedulerRateLimiter,
    _seed_bucket_statement,
)
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import SchedulerRateBucket


def _settings(*, capacity: float = 1.0, refill_rate: float = 0.000001) -> Any:
    return SimpleNamespace(
        scheduler_grpc_fire_rate_limit_enabled=True,
        scheduler_grpc_fire_rate_capacity=capacity,
        scheduler_grpc_fire_rate_per_second=refill_rate,
    )


@pytest.mark.parametrize(
    ("dialect_name", "dialect"),
    [
        ("sqlite", sqlite.dialect()),
        ("postgresql", postgresql.dialect()),  # type: ignore[no-untyped-call]
    ],
)
def test_bucket_seed_is_atomic_for_supported_dialects(
    dialect_name: str,
    dialect: Dialect,
) -> None:
    statement = _seed_bucket_statement(
        dialect_name=dialect_name,
        cert_cn="scheduler-a",
        capacity=3.0,
        refill_rate=1.0,
        now=datetime.now(UTC),
    )

    compiled = " ".join(str(statement.compile(dialect=dialect)).split()).upper()
    assert "INSERT INTO SCHEDULER_RATE_BUCKETS" in compiled
    assert "ON CONFLICT (CERT_CN) DO NOTHING" in compiled


def test_bucket_seed_rejects_an_unsupported_dialect() -> None:
    with pytest.raises(RuntimeError, match="PostgreSQL and SQLite"):
        _seed_bucket_statement(
            dialect_name="mysql",
            cert_cn="scheduler-a",
            capacity=3.0,
            refill_rate=1.0,
            now=datetime.now(UTC),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tokens",
    [0.0, -1.0, math.nan, math.inf, -math.inf, True],
)
async def test_scheduler_limiter_rejects_non_positive_or_non_finite_tokens(
    tokens: float,
) -> None:
    limiter = SchedulerRateLimiter(
        db=cast("DatabaseManager", None),
        settings=_settings(),
    )

    with pytest.raises(ValueError, match="finite positive"):
        await limiter.consume(cert_cn="scheduler-a", tokens=tokens)
    with pytest.raises(ValueError, match="finite positive"):
        await limiter.refund(cert_cn="scheduler-a", tokens=tokens)


@pytest.mark.asyncio
async def test_sqlite_concurrent_first_consume_is_serialized(tmp_path: Path) -> None:
    database_path = tmp_path / "scheduler-rate.sqlite3"
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{database_path}",
        connect_args={"timeout": 30},
    )
    async with engine.begin() as connection:
        await connection.run_sync(
            cast("Table", SchedulerRateBucket.__table__).create,
        )

    try:
        db = DatabaseManager(engine)
        limiter = SchedulerRateLimiter(
            db=db,
            settings=_settings(),
        )
        start = asyncio.Event()

        async def consume_once() -> bool:
            await start.wait()
            return await limiter.consume(cert_cn="new-cert")

        tasks = [asyncio.create_task(consume_once()) for _ in range(32)]
        await asyncio.sleep(0)
        start.set()
        results = await asyncio.gather(*tasks)

        assert sum(results) == 1
        async with db.session() as session:
            persisted = await session.get(SchedulerRateBucket, "new-cert")
        assert persisted is not None
        assert math.isfinite(persisted.tokens)
        assert 0 <= persisted.tokens < 1
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_stored_future_refill_time_fails_closed_without_regression(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "scheduler-clock-skew.sqlite3"
    engine = create_async_engine(f"sqlite+aiosqlite:///{database_path}")
    async with engine.begin() as connection:
        await connection.run_sync(
            cast("Table", SchedulerRateBucket.__table__).create,
        )

    process_now = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
    stored_future = process_now + timedelta(minutes=5)

    async def behind_database_clock(**_kwargs: object) -> datetime:
        return process_now

    monkeypatch.setattr(
        "z4j_brain.domain.scheduler_rate_limiter._database_now",
        behind_database_clock,
    )

    try:
        db = DatabaseManager(engine)
        async with db.session() as session:
            session.add(
                SchedulerRateBucket(
                    cert_cn="ahead-cert",
                    tokens=0.0,
                    last_refill=stored_future,
                    capacity=1.0,
                    refill_per_second=1.0,
                ),
            )
            await session.commit()

        limiter = SchedulerRateLimiter(
            db=db,
            settings=_settings(capacity=1.0, refill_rate=1.0),
        )
        assert await limiter.consume(cert_cn="ahead-cert") is False

        async with db.session() as session:
            persisted = await session.get(SchedulerRateBucket, "ahead-cert")
        assert persisted is not None
        persisted_refill = persisted.last_refill
        if persisted_refill.tzinfo is None:
            persisted_refill = persisted_refill.replace(tzinfo=UTC)
        assert persisted_refill == stored_future
        assert persisted.tokens == 0.0
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_unique_ip_flood_stays_at_hard_cardinality_cap() -> None:
    bucket = _IPBucket(window_seconds=60, max_hits=1, max_keys=17)

    results = await asyncio.gather(*(bucket.hit(f"198.51.100.{i}") for i in range(500)))

    assert sum(results) == 17
    assert len(bucket._hits) == 17
    # Active histories remain in place. A known exhausted key and an unseen
    # key both fail; the unseen key is never allocated.
    retained_key = next(iter(bucket._hits))
    assert await bucket.hit(retained_key) is False
    assert await bucket.hit("203.0.113.250") is False
    assert "203.0.113.250" not in bucket._hits
    assert len(bucket._hits) == 17


@pytest.mark.asyncio
async def test_cardinality_cap_reclaims_only_stale_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [100.0]
    monkeypatch.setattr(
        "z4j_brain.domain.ip_rate_limit.time.monotonic",
        lambda: clock[0],
    )
    bucket = _IPBucket(window_seconds=10, max_hits=2, max_keys=2)

    assert await bucket.hit("198.51.100.1") is True
    assert await bucket.hit("198.51.100.2") is True
    assert await bucket.hit("198.51.100.3") is False
    assert set(bucket._hits) == {"198.51.100.1", "198.51.100.2"}

    clock[0] = 111.0
    assert await bucket.hit("198.51.100.3") is True
    assert set(bucket._hits) == {"198.51.100.3"}


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"window_seconds": 0, "max_hits": 1}, "window_seconds"),
        ({"window_seconds": 1, "max_hits": 0}, "max_hits"),
        ({"window_seconds": 1, "max_hits": 1, "max_keys": 0}, "max_keys"),
    ],
)
def test_ip_bucket_rejects_non_positive_dimensions(
    kwargs: dict[str, int],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _IPBucket(**kwargs)


@pytest.mark.asyncio
async def test_ip_bucket_rejects_invalid_per_call_cap() -> None:
    bucket = _IPBucket(window_seconds=60, max_hits=1, max_keys=1)

    with pytest.raises(ValueError, match="max_hits"):
        await bucket.hit("198.51.100.1", max_hits=0)


@pytest.mark.asyncio
async def test_ip_bucket_retry_delay_tracks_window_and_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [100.0]
    monkeypatch.setattr(
        "z4j_brain.domain.ip_rate_limit.time.monotonic",
        lambda: clock[0],
    )
    bucket = _IPBucket(window_seconds=60, max_hits=1)

    assert await bucket.hit_with_retry_after("198.51.100.10") == (True, None)
    assert await bucket.hit_with_retry_after("198.51.100.10") == (False, 60)

    clock[0] = 159.25
    assert await bucket.hit_with_retry_after("198.51.100.10") == (False, 1)

    clock[0] = 160.0
    assert await bucket.hit_with_retry_after("198.51.100.10") == (True, None)


@pytest.mark.asyncio
async def test_ip_bucket_retry_delay_handles_a_runtime_cap_reduction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [100.0]
    monkeypatch.setattr(
        "z4j_brain.domain.ip_rate_limit.time.monotonic",
        lambda: clock[0],
    )
    bucket = _IPBucket(window_seconds=60, max_hits=3)

    assert await bucket.hit("198.51.100.20") is True
    clock[0] = 110.0
    assert await bucket.hit("198.51.100.20") is True
    clock[0] = 120.0
    assert await bucket.hit("198.51.100.20") is True

    # With three retained hits and a runtime cap of two, two hits must expire
    # before another request fits. The second retained hit expires at t=170.
    assert await bucket.hit_with_retry_after("198.51.100.20", max_hits=2) == (
        False,
        50,
    )


@pytest.mark.asyncio
async def test_ip_bucket_cardinality_retry_delay_uses_earliest_stale_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [100.0]
    monkeypatch.setattr(
        "z4j_brain.domain.ip_rate_limit.time.monotonic",
        lambda: clock[0],
    )
    bucket = _IPBucket(window_seconds=60, max_hits=2, max_keys=2)

    assert await bucket.hit("198.51.100.21") is True
    clock[0] = 110.0
    assert await bucket.hit("198.51.100.22") is True
    clock[0] = 125.0

    assert await bucket.hit_with_retry_after("198.51.100.23") == (False, 35)
    assert "198.51.100.23" not in bucket._hits


def _isolate_process_bucket(
    monkeypatch: pytest.MonkeyPatch,
    bucket: _IPBucket,
) -> None:
    """Give a module-level limiter private mutable state for one test."""
    monkeypatch.setattr(bucket, "_hits", OrderedDict())
    monkeypatch.setattr(bucket, "_hits_since_prune", 0)
    monkeypatch.setattr(bucket, "_lock", asyncio.Lock())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("bucket", "dependency", "max_hits", "retry_seconds", "name"),
    [
        (_login_bucket, require_login_throttle, 20, 60, "login"),
        (_setup_bucket, require_setup_throttle, 5, 900, "setup-complete"),
    ],
)
async def test_fixed_throttle_response_reports_its_actual_retry_window(
    monkeypatch: pytest.MonkeyPatch,
    bucket: _IPBucket,
    dependency: Any,
    max_hits: int,
    retry_seconds: int,
    name: str,
) -> None:
    monkeypatch.setattr(
        "z4j_brain.domain.ip_rate_limit.time.monotonic",
        lambda: 100.0,
    )
    _isolate_process_bucket(monkeypatch, bucket)
    request = Request({"type": "http"})

    for _ in range(max_hits):
        await dependency(request=request, ip="198.51.100.11")

    with pytest.raises(HTTPException) as exc_info:
        await dependency(request=request, ip="198.51.100.11")

    error = exc_info.value
    assert error.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert error.detail == f"too many requests; retry in {retry_seconds} seconds ({name})"
    assert error.headers is None


@pytest.mark.asyncio
async def test_settings_driven_mfa_throttle_uses_same_retry_response_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "z4j_brain.domain.ip_rate_limit.time.monotonic",
        lambda: 100.0,
    )
    _isolate_process_bucket(monkeypatch, _mfa_verify_bucket)
    request = cast(
        "Request",
        SimpleNamespace(
            app=SimpleNamespace(
                state=SimpleNamespace(
                    settings=SimpleNamespace(mfa_verification_rate_per_min=1),
                ),
            ),
        ),
    )

    await require_mfa_verify_throttle(request=request, ip="198.51.100.12")
    with pytest.raises(HTTPException) as exc_info:
        await require_mfa_verify_throttle(request=request, ip="198.51.100.12")

    error = exc_info.value
    assert error.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert error.detail == "too many requests; retry in 60 seconds (mfa-verify)"
    assert error.headers is None
