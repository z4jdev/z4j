"""The ``workers.metadata`` merge cases every backend and every write path
has to agree on.

One table, imported by the SQLite suite and by the real-PostgreSQL suite, so
the two cannot be given different expectations. The merge used to be written
once per dialect -- ``jsonb ||`` on PostgreSQL, ``json_patch`` on SQLite -- and
those two disagree about nested objects and about nulls, which is exactly what
no test compared. A shared table is the only version of this file that can
catch that: a case list copied into each suite drifts the same way the two SQL
expressions did.

The drivers are here for the same reason. The bulk statement and the per-row
fallback it drops to on a deadlock are two different write paths, and a case
that only ever runs through one of them says nothing about the other.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from z4j_brain.persistence.enums import WorkerState
from z4j_brain.persistence.models import Worker
from z4j_brain.persistence.repositories import WorkerRepository

#: A default-bearing configuration report, the shape a current agent sends: the
#: whole effective Celery config, not only the settings an application set.
_FULL_CONF = {
    "task_acks_late": True,
    "worker_prefetch_multiplier": 4,
    "task_time_limit": 300,
    "timezone": "UTC",
}

#: What an older agent reports for the same worker: only the explicitly
#: overridden settings. Partial with respect to the newer vocabulary, and about
#: the same live worker, so neither report contradicts the other.
_PARTIAL_CONF = {"task_acks_late": False}


MERGE_CASES = [
    pytest.param(
        [{"conf": dict(_FULL_CONF)}, {"conf": dict(_PARTIAL_CONF)}],
        {
            "conf": {
                "task_acks_late": False,
                "worker_prefetch_multiplier": 4,
                "task_time_limit": 300,
                "timezone": "UTC",
            },
        },
        id="rolling-upgrade-partial-conf-does-not-drop-the-rest",
    ),
    pytest.param(
        [{"conf": dict(_PARTIAL_CONF)}, {"conf": dict(_FULL_CONF)}],
        {"conf": dict(_FULL_CONF)},
        id="rolling-upgrade-order-does-not-change-the-outcome",
    ),
    pytest.param(
        [
            {"stats": {"pool": {"max-concurrency": 8}}, "conf": dict(_FULL_CONF)},
            {"stats": {"pool": {"max-concurrency": 8}}},
        ],
        {
            "stats": {"pool": {"max-concurrency": 8}},
            "conf": dict(_FULL_CONF),
        },
        id="a-report-the-heartbeat-omits-is-left-alone",
    ),
    pytest.param(
        [
            {"stats": {"pool": {"max-concurrency": 8}, "clock": 100}},
            {"stats": {"clock": 200}},
        ],
        {"stats": {"pool": {"max-concurrency": 8}, "clock": 200}},
        id="nested-object-merges-rather-than-replacing",
    ),
    pytest.param(
        [
            {"stats": {"rusage": {"utime": 1.0, "stime": 2.0}}},
            {"stats": {"rusage": {"utime": 9.0}}},
        ],
        {"stats": {"rusage": {"utime": 9.0, "stime": 2.0}}},
        id="the-merge-does-not-stop-at-the-second-level",
    ),
    pytest.param(
        [
            {"active": [{"id": "a"}, {"id": "b"}], "registered": ["t.one"]},
            {"active": []},
        ],
        {"active": [], "registered": ["t.one"]},
        id="an-empty-list-is-a-fact-and-replaces",
    ),
    pytest.param(
        # A null in an inbound document is a value, not an instruction to
        # delete. SQLite's json_patch reads it as a delete, which would let one
        # agent erase what another reported.
        [{"conf": {"timezone": "UTC"}}, {"conf": {"timezone": None}}],
        {"conf": {"timezone": None}},
        id="a-null-is-stored-not-treated-as-a-deletion",
    ),
    pytest.param(
        [{"conf": {"timezone": "UTC"}}, {"conf": "unavailable"}],
        {"conf": "unavailable"},
        id="a-scalar-replaces-the-object-it-lands-on",
    ),
    pytest.param(
        [{"stats": {"clock": 1}}, {}],
        {"stats": {"clock": 1}},
        id="an-empty-document-touches-nothing",
    ),
]


async def _stored(session: AsyncSession, project_id: uuid.UUID, name: str) -> Any:
    row = (
        await session.execute(
            select(Worker).where(
                Worker.project_id == project_id,
                Worker.engine == "celery",
                Worker.name == name,
            ),
        )
    ).scalar_one()
    return row.worker_metadata


async def apply_via_bulk(
    session: AsyncSession,
    project_id: uuid.UUID,
    name: str,
    documents: list[dict[str, Any]],
) -> Any:
    """Land each document through the bulk statement, one heartbeat at a time."""
    repo = WorkerRepository(session)
    for document in documents:
        await repo.upsert_from_events_bulk(
            [
                {
                    "project_id": project_id,
                    "engine": "celery",
                    "name": name,
                    "state": WorkerState.ONLINE,
                    "last_heartbeat": datetime.now(UTC),
                    "worker_metadata": document,
                },
            ],
        )
        await session.commit()
    return await _stored(session, project_id, name)


async def apply_via_per_row(
    session: AsyncSession,
    project_id: uuid.UUID,
    name: str,
    documents: list[dict[str, Any]],
) -> Any:
    """Land each document through the path the bulk statement falls back to."""
    repo = WorkerRepository(session)
    for document in documents:
        await repo.upsert_from_event(
            project_id=project_id,
            engine="celery",
            name=name,
            updates={
                "state": WorkerState.ONLINE,
                "last_heartbeat": datetime.now(UTC),
                "worker_metadata": document,
            },
        )
        await session.commit()
    return await _stored(session, project_id, name)


#: Both write paths, so a case runs through the bulk statement AND through the
#: per-row path the router drops to when the bulk one deadlocks.
WRITE_PATHS = [
    pytest.param(apply_via_bulk, id="bulk"),
    pytest.param(apply_via_per_row, id="per-row-fallback"),
]


__all__ = ["MERGE_CASES", "WRITE_PATHS", "apply_via_bulk", "apply_via_per_row"]
