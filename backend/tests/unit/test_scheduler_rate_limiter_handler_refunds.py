"""SQLite contracts for every FireSchedule rate-limit refund branch."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock

import grpc  # type: ignore[import-untyped]
import pytest
from google.protobuf.timestamp_pb2 import Timestamp  # type: ignore[import-untyped]
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.domain.schedule_cadence import (
    CADENCE_SEMANTICS_VERSION,
    cadence_runtime_fingerprint,
)
from z4j_brain.domain.schedule_fire_authority import derive_scheduler_fire_id
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import ScheduleKind
from z4j_brain.persistence.models import (
    Project,
    Schedule,
    SchedulerRateBucket,
)
from z4j_brain.persistence.models.schedule_control import (
    SCHEDULE_REVISION_SINGLETON_ID,
    ScheduleRevisionState,
)
from z4j_brain.scheduler_grpc.handlers import SchedulerServiceImpl
from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb
from z4j_brain.scheduler_grpc.protocol import CURRENT_PROTOCOL_EPOCH
from z4j_brain.settings import Settings

_CERT_CN = "scheduler-refund"


class Context:
    def __init__(self) -> None:
        self.aborted: tuple[grpc.StatusCode, str] | None = None

    def cancelled(self) -> bool:
        return False

    async def abort(self, code: grpc.StatusCode, details: str) -> None:
        self.aborted = (code, details)
        raise AssertionError(f"unexpected abort {code}: {details}")

    def auth_context(self) -> dict[str, list[bytes]]:
        return {"x509_common_name": [_CERT_CN.encode()]}


def _timestamp(value: datetime) -> Timestamp:
    stamp = Timestamp()
    stamp.FromDatetime(value)
    return stamp


def _current_request(*, schedule_id: uuid.UUID, slot: datetime) -> pb.FireScheduleRequest:
    return pb.FireScheduleRequest(
        schedule_id=str(schedule_id),
        fire_id=str(derive_scheduler_fire_id(schedule_id, slot)),
        scheduled_for=_timestamp(slot),
        fired_at=_timestamp(slot + timedelta(seconds=1)),
        scheduler_protocol_epoch=CURRENT_PROTOCOL_EPOCH,
        observed_control_token=str(uuid.uuid4()),
        definition_digest="d" * 64,
        expected_schedule_revision=1,
        expected_next_run_at=_timestamp(slot),
        cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
        cadence_runtime_fingerprint=cadence_runtime_fingerprint(),
    )


def _legacy_request(
    *,
    schedule_id: uuid.UUID,
    slot: datetime,
    control_active: bool,
) -> pb.FireScheduleRequest:
    if not control_active:
        return pb.FireScheduleRequest(
            schedule_id=str(schedule_id),
            fire_id=str(uuid.uuid4()),
        )
    return pb.FireScheduleRequest(
        schedule_id=str(schedule_id),
        fire_id=str(derive_scheduler_fire_id(schedule_id, slot)),
        scheduled_for=_timestamp(slot),
        fired_at=_timestamp(slot + timedelta(seconds=1)),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("protocol", "control_active", "row_state", "expected_code"),
    [
        pytest.param(
            "legacy",
            False,
            "missing",
            "schedule_not_found",
            id="pre-control-missing",
        ),
        pytest.param(
            "legacy",
            False,
            "disabled",
            "schedule_disabled",
            id="pre-control-disabled",
        ),
        pytest.param(
            "legacy",
            False,
            "paused",
            "schedule_paused",
            id="pre-control-paused",
        ),
        pytest.param(
            "legacy",
            True,
            "missing",
            "schedule_not_found",
            id="current-control-legacy-missing",
        ),
        pytest.param(
            "legacy",
            True,
            "paused",
            "schedule_paused",
            id="current-control-legacy-paused",
        ),
        pytest.param(
            "legacy",
            True,
            "disabled",
            "schedule_disabled",
            id="current-control-legacy-disabled",
        ),
        pytest.param(
            "current",
            True,
            "missing",
            "schedule_not_found",
            id="current-protocol-missing",
        ),
    ],
)
async def test_refusal_refunds_in_the_existing_sqlite_write_transaction(
    tmp_path: Path,
    protocol: str,
    control_active: bool,
    row_state: str,
    expected_code: str,
) -> None:
    database_path = tmp_path / "handler-refund.sqlite3"
    database_url = f"sqlite+aiosqlite:///{database_path}"
    settings = Settings(
        database_url=database_url,
        secret=secrets.token_urlsafe(48),
        session_secret=secrets.token_urlsafe(48),
        environment="dev",
        log_json=False,
        scheduler_grpc_fire_rate_capacity=1.0,
        scheduler_grpc_fire_rate_per_second=0.01,
    )
    engine = create_async_engine(
        database_url,
        connect_args={"timeout": 0.05},
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    database = DatabaseManager(engine)
    schedule_id = uuid.uuid4()
    project_id = uuid.uuid4()
    slot = (datetime.now(UTC) - timedelta(minutes=2)).replace(microsecond=0)
    control_token = uuid.uuid4()

    try:
        async with database.session(write=True) as session:
            session.add(Project(id=project_id, slug="refunds", name="Refunds"))
            if control_active:
                session.add(
                    ScheduleRevisionState(
                        singleton_id=SCHEDULE_REVISION_SINGLETON_ID,
                        current_revision=1,
                        change_log_pruned_through=0,
                    ),
                )
            if row_state != "missing":
                session.add(
                    Schedule(
                        id=schedule_id,
                        project_id=project_id,
                        engine="celery",
                        scheduler="z4j-scheduler",
                        name=f"refund-{row_state}",
                        task_name="jobs.cleanup",
                        kind=ScheduleKind.CRON,
                        expression="* * * * *",
                        timezone="UTC",
                        args=[],
                        kwargs={},
                        is_enabled=row_state != "disabled",
                        paused_at=(slot if row_state == "paused" else None),
                        next_run_at=slot,
                        control_token=(control_token if control_active else None),
                        legacy_fire_control_token=(control_token if control_active else None),
                        schedule_revision=(1 if control_active else None),
                        definition_digest=("d" * 64 if control_active else None),
                        cadence_semantics_version=(
                            CADENCE_SEMANTICS_VERSION if control_active else None
                        ),
                        cadence_runtime_fingerprint=(
                            cadence_runtime_fingerprint() if control_active else None
                        ),
                    ),
                )
            await session.commit()

        service = SchedulerServiceImpl(
            settings=settings,
            db=database,
            command_dispatcher=AsyncMock(),
            audit_service=AsyncMock(),
        )
        request = (
            _current_request(schedule_id=schedule_id, slot=slot)
            if protocol == "current"
            else _legacy_request(
                schedule_id=schedule_id,
                slot=slot,
                control_active=control_active,
            )
        )

        response = await service.FireSchedule(request, Context())

        assert response.error_code == expected_code
        async with database.session() as session:
            bucket = await session.get(SchedulerRateBucket, _CERT_CN)
        assert bucket is not None
        assert bucket.tokens == 1.0
        assert await service._rate_limiter.consume(cert_cn=_CERT_CN) is True
    finally:
        await engine.dispose()


class AbortContext(Context):
    async def abort(self, code: grpc.StatusCode, details: str) -> None:
        self.aborted = (code, details)


@pytest.mark.asyncio
async def test_legacy_ack_fails_closed_on_ambiguous_fire_history(
    tmp_path: Path,
) -> None:
    """A pre-fence duplicate never leaks MultipleResultsFound or picks a row."""

    database_path = tmp_path / "ambiguous-legacy-ack.sqlite3"
    database_url = f"sqlite+aiosqlite:///{database_path}"
    settings = Settings(
        database_url=database_url,
        secret=secrets.token_urlsafe(48),
        session_secret=secrets.token_urlsafe(48),
        environment="dev",
        log_json=False,
    )
    engine = create_async_engine(database_url)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        # SQLite normally enforces the legacy bare-fire-id fence.  Removing it
        # constructs the historical corrupt state PostgreSQL partitioning once
        # allowed, without weakening production schema code.
        await connection.exec_driver_sql("DROP INDEX uq_schedule_fires_legacy_fire")

    database = DatabaseManager(engine)
    project_id = uuid.uuid4()
    first_schedule = uuid.uuid4()
    second_schedule = uuid.uuid4()
    fire_id = uuid.uuid5(uuid.NAMESPACE_OID, "ambiguous-legacy-fire")
    first_slot = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=2)
    second_slot = first_slot + timedelta(minutes=1)

    try:
        async with database.session(write=True) as session:
            session.add(Project(id=project_id, slug="ambiguous", name="Ambiguous"))
            for schedule_id, name in (
                (first_schedule, "first"),
                (second_schedule, "second"),
            ):
                session.add(
                    Schedule(
                        id=schedule_id,
                        project_id=project_id,
                        engine="celery",
                        scheduler="z4j-scheduler",
                        name=name,
                        task_name="jobs.cleanup",
                        kind=ScheduleKind.CRON,
                        expression="* * * * *",
                        timezone="UTC",
                        args=[],
                        kwargs={},
                        total_runs=0,
                    ),
                )
            from z4j_brain.persistence.models import ScheduleFire

            session.add_all(
                [
                    ScheduleFire(
                        fire_id=fire_id,
                        schedule_id=first_schedule,
                        project_id=project_id,
                        status="delivered",
                        scheduled_for=first_slot,
                        fired_at=first_slot,
                    ),
                    ScheduleFire(
                        fire_id=fire_id,
                        schedule_id=second_schedule,
                        project_id=project_id,
                        status="delivered",
                        scheduled_for=second_slot,
                        fired_at=second_slot,
                    ),
                ],
            )
            await session.commit()

        service = SchedulerServiceImpl(
            settings=settings,
            db=database,
            command_dispatcher=AsyncMock(),
            audit_service=AsyncMock(),
        )
        context = AbortContext()

        await service.AcknowledgeFireResult(
            pb.AcknowledgeFireResultRequest(
                fire_id=str(fire_id),
                status="success",
            ),
            context,
        )

        assert context.aborted == (
            grpc.StatusCode.FAILED_PRECONDITION,
            "legacy fire identity is ambiguous",
        )
        async with database.session() as session:
            first = await session.get(Schedule, first_schedule)
            second = await session.get(Schedule, second_schedule)
        assert first is not None and first.total_runs == 0
        assert second is not None and second.total_runs == 0
    finally:
        await engine.dispose()
