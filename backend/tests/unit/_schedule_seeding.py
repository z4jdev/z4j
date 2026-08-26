"""Seeding helpers that go the way the product goes.

An activated (migrated) database refuses a hand-built ``schedules`` row, so
a test that needs one has to plan it through the same repository the brain
uses. Reserved-owner rows are one call (``create_current``); an externally
owned row is not, which is why that sequence lives here rather than being
retyped in every file that needs a foreign-owner schedule.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.repositories.schedule_external import (
    ScheduleExternalRepository,
)
from z4j_core.schedule_external import (
    external_projection_body,
    external_projection_digest,
)


async def project_external_schedule(
    db: DatabaseManager,
    *,
    project_id: uuid.UUID,
    name: str,
    owner: str = "celery-beat",
    task_name: str = "t.t",
    kind: str = "cron",
    expression: str = "0 * * * *",
    occurred_at: datetime | None = None,
) -> uuid.UUID:
    """Land one externally owned schedule and return its stream id.

    An externally owned row is never written directly. The adapter opens an
    activation epoch for its stream, then the brain applies a digest-bound
    snapshot projection; the Boundary-D external guards refuse anything that
    is not the exact next frame for a live epoch.
    """
    when = occurred_at or datetime.now(UTC)
    source_scope = f'{{"kind":"scheduler-owner","owner":"{owner}","version":1}}'

    async with db.session(write=True) as session:
        stream = await ScheduleExternalRepository(session).ensure_activation_epoch(
            project_id=project_id,
            owner=owner,
            source_scope=source_scope,
            occurred_at=when,
            adapter_instance_id="adapter-one",
            executor_agent_id=uuid.uuid4(),
            executor_registry_owner_id=uuid.uuid4(),
            executor_session_generation=uuid.uuid4().hex,
        )
        stream_id = stream.id
        epoch_uuid = stream.current_epoch_uuid
        epoch_number = stream.current_epoch_number
        await session.commit()

    projected: dict[str, Any] = {
        "source_key": "external",
        "engine": "celery",
        "scheduler": owner,
        "name": name,
        "task_name": task_name,
        "kind": kind,
        "expression": expression,
        "timezone": "UTC",
        "queue": None,
        "priority": "normal",
        "args": [],
        "kwargs": {},
        "is_enabled": True,
        "last_run_at": None,
        "next_run_at": None,
        "total_runs": 0,
        "external_id": None,
        "catch_up": "skip",
        "source": "agent",
        "source_hash": None,
    }
    frame: dict[str, Any] = {
        "stream_id": str(stream_id),
        "epoch_uuid": str(epoch_uuid),
        "epoch_number": epoch_number,
        "sequence": 1,
        "kind": "snapshot",
        "owner": owner,
        "source_scope": source_scope,
        "adapter_instance_id": "adapter-one",
        "schedules": [projected],
        "deleted_source_keys": [],
        "complete": True,
        "stable_source": True,
    }
    digest = external_projection_digest(external_projection_body(**frame))

    async with db.session(write=True) as session:
        applied = await ScheduleExternalRepository(session).apply_projection(
            project_id=project_id,
            stream_id=stream_id,
            epoch_uuid=epoch_uuid,
            epoch_number=epoch_number,
            sequence=1,
            kind="snapshot",
            owner=owner,
            source_scope=source_scope,
            adapter_instance_id="adapter-one",
            schedules=[projected],
            deleted_source_keys=[],
            complete=True,
            stable_source=True,
            payload_digest=digest,
            operation_id=None,
            occurred_at=when,
        )
        assert applied.disposition == "applied", applied.disposition
        assert applied.inserted == 1
        await session.commit()
    return stream_id
