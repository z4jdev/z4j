"""What a hold has to survive: the envelope, the projection, an ownership move.

Every case here runs on a MIGRATED database. The change-log envelope, the
revision allocator and the transition guards all arrive with a migration
rather than with the ORM metadata, so a ``create_all`` schema accepts writes
an operator's database refuses, and a hold that only ever travels through
``create_all`` has never been tested where it lives.
"""

from __future__ import annotations

import secrets
import sqlite3
import uuid
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import grpc
import pytest
from google.protobuf.timestamp_pb2 import Timestamp
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.domain.schedule_cadence import (
    CADENCE_SEMANTICS_VERSION,
    cadence_runtime_fingerprint,
)
from z4j_brain.domain.schedule_fire_authority import derive_scheduler_fire_id
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import (
    Project,
    Schedule,
    ScheduleChangeLog,
)
from z4j_brain.persistence.repositories import schedule_control as control_module
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
)
from z4j_brain.persistence.repositories.schedule_external import (
    ScheduleExternalRepository,
)
from z4j_brain.scheduler_grpc.handlers import SchedulerServiceImpl
from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb
from z4j_brain.scheduler_grpc.wire import ScheduleWireError, schedule_to_pb
from z4j_brain.settings import Settings

_PLANNED_AT = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


class RpcAbortError(RuntimeError):
    def __init__(self, code: grpc.StatusCode, details: str) -> None:
        super().__init__(details)
        self.code = code


class Context:
    def cancelled(self) -> bool:
        return False

    async def abort(self, code: grpc.StatusCode, details: str) -> None:
        raise RpcAbortError(code, details)

    def auth_context(self) -> dict[str, list[bytes]]:
        return {}


def _settings(migrated_db_url: str, audit_chain_secret: str) -> Settings:
    return Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        # A migrated database has Boundary F activated and refuses an audit
        # row that carries no chain authentication.
        audit_chain_secret=audit_chain_secret,  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )


@pytest.fixture
async def held_schedule(
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> AsyncIterator[tuple[SchedulerServiceImpl, DatabaseManager, Project, str]]:
    """One reserved-owner schedule on a migrated database, plus the service."""

    settings = _settings(migrated_db_url, migrated_audit_chain_secret)
    engine = create_async_engine(settings.database_url)
    database = DatabaseManager(engine)
    project = Project(id=uuid.uuid4(), slug="hold", name="Hold")
    try:
        async with database.session() as session:
            session.add(project)
            await session.flush()
            await _create(session, project_id=project.id, name="nightly")
            await session.commit()
        service = SchedulerServiceImpl(
            settings=settings,
            db=database,
            command_dispatcher=AsyncMock(),
            audit_service=AsyncMock(),
        )
        yield service, database, project, migrated_db_url
    finally:
        await engine.dispose()


async def _create(session: Any, *, project_id: uuid.UUID, name: str) -> Schedule:
    return await ScheduleControlRepository(session).create_current(
        project_id=project_id,
        data={
            "name": name,
            "task_name": f"jobs.{name}",
            "engine": "celery",
            "scheduler": "z4j-scheduler",
            "kind": "interval",
            "expression": "5m",
            "timezone": "UTC",
            "queue": "maintenance",
            "priority": "normal",
            "args": [],
            "kwargs": {},
            "is_enabled": True,
            "catch_up": "skip",
            "source": "dashboard",
        },
        planning_at=_PLANNED_AT,
    )


async def _pause(
    database: DatabaseManager,
    *,
    project_id: uuid.UUID,
    schedule_id: uuid.UUID,
    paused: bool = True,
) -> None:
    async with database.session(write=True) as session:
        transition = await ScheduleControlRepository(session).set_paused(
            project_id=project_id,
            schedule_id=schedule_id,
            paused=paused,
            occurred_at=_PLANNED_AT + timedelta(minutes=1),
        )
        assert transition.outcome == "applied"
        await session.commit()


async def _row(database: DatabaseManager) -> Schedule:
    async with database.session() as session:
        return (await session.execute(select(Schedule))).scalar_one()


async def _latest_envelope(database: DatabaseManager) -> dict[str, Any]:
    async with database.session() as session:
        change = (
            await session.execute(
                select(ScheduleChangeLog).order_by(ScheduleChangeLog.revision.desc()).limit(1),
            )
        ).scalar_one()
        assert change.snapshot is not None
        return dict(change.snapshot["schedule"])


def _table_columns(database_url: str) -> set[str]:
    path = database_url.split("///", 1)[1]
    with sqlite3.connect(path) as probe:
        return {row[1] for row in probe.execute("PRAGMA table_info(schedules)")}


class _RecordingSnapshot(dict):
    """A snapshot that remembers which fields the projection asked it for."""

    def __init__(self, source: Mapping[str, Any]) -> None:
        super().__init__(source)
        self.consulted: list[str] = []

    def __contains__(self, key: object) -> bool:
        self.consulted.append(str(key))
        return super().__contains__(key)


def _timestamp(value: datetime) -> Timestamp:
    result = Timestamp()
    result.FromDatetime(value)
    return result


async def test_the_stored_envelope_describes_every_column_the_table_has(
    held_schedule: tuple[SchedulerServiceImpl, DatabaseManager, Project, str],
) -> None:
    """The envelope is the row, or it is a partial description of one.

    A watching scheduler never sees the row, only this. Checking the exact
    field that went missing last time would prove nothing about the next one,
    so compare against the schema an operator's database actually has.
    """

    _service, database, _project, database_url = held_schedule
    envelope = await _latest_envelope(database)

    assert set(envelope) == _table_columns(database_url)


async def test_the_envelope_records_what_the_row_will_hold(
    held_schedule: tuple[SchedulerServiceImpl, DatabaseManager, Project, str],
) -> None:
    """A create writes its envelope before the flush that applies defaults.

    A column left to its model default is still ``None`` on the row at that
    moment, so an envelope that copies the row verbatim claims NULL for a
    value the database is about to store as something else.
    """

    _service, database, _project, _url = held_schedule
    envelope = await _latest_envelope(database)
    row = await _row(database)

    for field, recorded in envelope.items():
        assert recorded == control_module._json_value(getattr(row, field)), field


async def test_the_projection_refuses_a_snapshot_that_cannot_answer_it(
    held_schedule: tuple[SchedulerServiceImpl, DatabaseManager, Project, str],
) -> None:
    """Every field the projection reads is one the envelope has to carry.

    Both halves matter and neither names a field. The first is the cross-file
    invariant that broke: the writer must store everything the reader asks
    for. The second is what makes a future gap loud instead of plausible, so a
    field nobody stored can never be answered with a default that happens to
    mean "running".
    """

    _service, database, project, _url = held_schedule
    row = await _row(database)
    await _pause(database, project_id=project.id, schedule_id=row.id)
    envelope = await _latest_envelope(database)

    recording = _RecordingSnapshot(envelope)
    assert schedule_to_pb(recording).is_enabled is False
    consulted = sorted(set(recording.consulted))
    assert consulted

    assert set(consulted) <= set(envelope)
    for field in consulted:
        truncated = {key: value for key, value in envelope.items() if key != field}
        with pytest.raises(ScheduleWireError):
            schedule_to_pb(truncated)


async def test_watch_projects_a_held_schedule_as_not_enabled(
    held_schedule: tuple[SchedulerServiceImpl, DatabaseManager, Project, str],
) -> None:
    """The stream a scheduler learns state from, carrying the hold.

    Every scheduler skips an entry that is not enabled, so this frame is what
    actually stops the tick. The brain refusing the fire is the backstop.
    """

    service, database, project, _url = held_schedule
    row = await _row(database)
    await _pause(database, project_id=project.id, schedule_id=row.id)

    stream = service.WatchSchedulesV2(
        pb.WatchSchedulesV2Request(
            project_id=str(project.id),
            after_revision=1,
            watch_format_version=1,
        ),
        Context(),
    )
    frame = await anext(stream)
    await stream.aclose()

    assert frame.WhichOneof("frame") == "change"
    assert frame.change.kind == pb.ScheduleChange.Kind.UPSERT
    assert frame.change.schedule.is_enabled is False


async def test_watch_stops_rather_than_replay_an_envelope_it_cannot_project(
    held_schedule: tuple[SchedulerServiceImpl, DatabaseManager, Project, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A brain build that forgot a column leaves envelopes nothing can fix.

    The change log is immutable, so the only way to hold one of those is to
    write it, which is what narrowing the field list does here. Replaying it
    would hand the scheduler a schedule that decodes cleanly and is wrong
    about whether it may run, so the stream has to end instead.
    """

    service, database, project, _url = held_schedule
    monkeypatch.setattr(
        control_module,
        "_SNAPSHOT_FIELDS",
        tuple(field for field in control_module._SNAPSHOT_FIELDS if field != "paused_at"),
    )
    row = await _row(database)
    await _pause(database, project_id=project.id, schedule_id=row.id)

    stream = service.WatchSchedulesV2(
        pb.WatchSchedulesV2Request(
            project_id=str(project.id),
            after_revision=1,
            watch_format_version=1,
        ),
        Context(),
    )
    with pytest.raises(RpcAbortError) as caught:
        await anext(stream)

    assert caught.value.code is grpc.StatusCode.DATA_LOSS


async def test_a_fire_that_raced_a_hold_is_answered_with_a_revision_that_moved(
    held_schedule: tuple[SchedulerServiceImpl, DatabaseManager, Project, str],
) -> None:
    """A hold does not rotate control, so the refusal has to move something.

    A fire prepared before the hold lands after it and is refused. The control
    token is deliberately unchanged, because a hold does not change the
    definition, so a caller that remembers this refusal against the token
    alone has remembered it against something that will never move again. The
    revision is what moves, on the hold and on the release, and it is on the
    wire in the refusal itself.
    """

    service, database, _project, _url = held_schedule
    row = await _row(database)
    assert row.control_token is not None
    slot = _PLANNED_AT + timedelta(minutes=5)
    request = pb.FireScheduleRequest(
        schedule_id=str(row.id),
        fire_id=str(derive_scheduler_fire_id(row.id, slot)),
        scheduled_for=_timestamp(slot),
        fired_at=_timestamp(slot + timedelta(seconds=1)),
        scheduler_protocol_epoch=1,
        observed_control_token=str(row.control_token),
        definition_digest=row.definition_digest,
        expected_schedule_revision=row.schedule_revision,
        expected_next_run_at=_timestamp(slot),
        prepared_next_run_at=_timestamp(slot + timedelta(minutes=5)),
        cadence_semantics_version=CADENCE_SEMANTICS_VERSION,
        cadence_runtime_fingerprint=cadence_runtime_fingerprint(),
    )
    await _pause(database, project_id=row.project_id, schedule_id=row.id)

    response = await service.FireSchedule(request, Context())

    assert response.disposition == pb.FireDisposition.FIRE_STALE_CONTROL_REFRESH
    assert response.live_control_token == str(row.control_token)
    assert response.live_revision > row.schedule_revision

    held_at = response.live_revision
    await _pause(
        database,
        project_id=row.project_id,
        schedule_id=row.id,
        paused=False,
    )
    resumed = await _row(database)
    assert resumed.control_token == row.control_token
    assert resumed.schedule_revision > held_at


async def _cutover(
    database: DatabaseManager,
    *,
    project_id: uuid.UUID,
    schedule_id: uuid.UUID,
) -> str:
    """Run the full attested reserved-to-external hand-off, once."""

    target_scope = '{"kind":"scheduler-owner","owner":"apscheduler","version":1}'
    selection_scope = '{"kind":"schedule-ids","version":1}'
    executor = {
        "target_adapter_instance_id": str(uuid.uuid4()),
        "target_executor_agent_id": uuid.uuid4(),
        "target_executor_registry_owner_id": uuid.uuid4(),
        "target_executor_session_generation": str(uuid.uuid4()),
        "target_executor_worker_id": "worker-a",
    }
    async with database.session(write=True) as session:
        repository = ScheduleExternalRepository(session)
        preview = await repository.preview_to_external_cutover(
            project_id=project_id,
            from_owner="z4j-scheduler",
            source_scope=selection_scope,
            to_owner="apscheduler",
            target_source_scope=target_scope,
            schedule_ids=(schedule_id,),
            **executor,
        )
        transition = await repository.finalize_to_external_cutover(
            operation_id=uuid.uuid4(),
            project_id=project_id,
            from_owner="z4j-scheduler",
            source_scope=selection_scope,
            to_owner="apscheduler",
            target_source_scope=target_scope,
            schedule_ids=(schedule_id,),
            preview_manifest_digest=preview.manifest_digest,
            cursor_policy="PRESERVE",
            quiescence_attestation={
                "all_old_and_new_scheduler_replicas_quiesced": True,
                "preview_manifest_digest": preview.manifest_digest,
                "source_stream_id": None,
            },
            occurred_at=_PLANNED_AT + timedelta(minutes=2),
            **executor,
        )
        if transition.disposition == "completed":
            await session.commit()
        return transition.disposition


async def test_a_running_schedule_can_be_handed_to_a_foreign_owner(
    held_schedule: tuple[SchedulerServiceImpl, DatabaseManager, Project, str],
) -> None:
    """The control: nothing about this hand-off is otherwise refused."""

    _service, database, project, _url = held_schedule
    row = await _row(database)

    disposition = await _cutover(
        database,
        project_id=project.id,
        schedule_id=row.id,
    )

    assert disposition == "completed"
    assert (await _row(database)).scheduler == "apscheduler"


async def test_a_held_schedule_is_not_handed_to_a_foreign_owner(
    held_schedule: tuple[SchedulerServiceImpl, DatabaseManager, Project, str],
) -> None:
    """A hold this brain cannot enforce, on a row it can no longer resume.

    The target adapter runs its own clock and has no channel to be told to
    stop, and pausing is refused outright for a schedule it owns, so a hold
    that crosses the boundary is either released without anyone saying so or
    stranded on a row nothing can clear.
    """

    _service, database, project, _url = held_schedule
    row = await _row(database)
    await _pause(database, project_id=project.id, schedule_id=row.id)

    disposition = await _cutover(
        database,
        project_id=project.id,
        schedule_id=row.id,
    )

    assert disposition == "unresolved_schedule_state"
    stranded = await _row(database)
    assert stranded.scheduler == "z4j-scheduler"
    assert stranded.paused_at is not None
