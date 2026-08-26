"""End-to-end test for ``FrameRouter._handle_heartbeat``.

Exercises the **full** heartbeat handling path that runs in production
on every WebSocket heartbeat from a real agent: a HEARTBEAT frame
arrives carrying ``adapter_health["celery.worker_details"]`` (a JSON
string of ``{hostname: {stats, active, active_queues, registered, conf}}``)
and ``adapter_health["celery.queue_depths"]`` (a JSON string of
``{queue_name: depth}``); the router should land worker rows + queue
rows in the DB.

This test was added in 1.3.1 after a regression escaped 1.3.0:
``Worker.worker_metadata`` is the Python attribute, but the DB column
is ``metadata``. The bulk-upsert path used the attribute name in
``stmt.excluded.<>`` lookups, which key off DB column names, every
heartbeat raised ``AttributeError: worker_metadata`` and the workers
list silently stayed empty on every dashboard. The unit-level
:mod:`test_workers_repo_bulk_upsert` tests didn't catch it because
``_row()`` never set ``worker_metadata``. This file closes that gap
by exercising the ``_handle_heartbeat`` code path the production WS
gateway actually invokes, with a payload shaped exactly like what
``z4j-celery``'s ``CeleryEngine.health()`` emits.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import Agent, Project, Queue, Worker
from z4j_brain.websocket.frame_router import FrameOutcome, FrameRouter
from z4j_core.transport.frames import HeartbeatFrame, HeartbeatPayload


@pytest.fixture
async def db_manager():
    """A real DatabaseManager backed by in-memory SQLite."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    db = DatabaseManager(engine)
    yield db
    await engine.dispose()


@pytest.fixture
async def project_and_agent(db_manager: DatabaseManager):
    """Pre-seed the DB with one project + one agent so the router has
    valid foreign-key targets."""
    factory = sessionmaker(
        db_manager._engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    project_id: uuid.UUID
    agent_id: uuid.UUID
    async with factory() as s:
        p = Project(slug="picker", name="Picker")
        s.add(p)
        await s.flush()
        project_id = p.id

        a = Agent(
            project_id=project_id,
            name="picker_django",
            token_hash="x" * 64,
            protocol_version=1,
            framework_adapter="django",
        )
        s.add(a)
        await s.flush()
        agent_id = a.id
        await s.commit()
    return project_id, agent_id


def _build_celery_worker_details_payload() -> str:
    """Mirror the shape z4j-celery's ``CeleryEngine.get_worker_details``
    emits: dict keyed by hostname, each value carrying stats / active /
    active_queues / registered / conf. Encoded as a JSON string because
    ``HeartbeatFrame.adapter_health`` is typed ``dict[str, str]`` -
    agents serialise structured values to JSON before stuffing them
    in.
    """
    return json.dumps(
        {
            "celery@picker_django": {
                "stats": {
                    "pool": {
                        "max-concurrency": 4,
                        "processes": [101, 102, 103, 104],
                    },
                    "rusage": {"utime": 12.3, "stime": 4.5},
                    "loadavg": [0.5, 0.7, 0.8],
                    "pid": 100,
                },
                "active": [
                    {"id": "task-1", "name": "myapp.tasks.add"},
                ],
                "active_queues": [
                    {"name": "celery"},
                    {"name": "high_priority"},
                ],
                "registered": ["myapp.tasks.add", "myapp.tasks.send_email"],
                "conf": {"BROKER_URL": "redis://localhost:6379/0"},
            },
        }
    )


@pytest.fixture
def heartbeat_frame() -> HeartbeatFrame:
    """A heartbeat frame in the exact shape a real Celery agent sends."""
    return HeartbeatFrame(
        id=str(uuid.uuid4()),
        ts=datetime.now(UTC),
        payload=HeartbeatPayload(
            buffer_size=0,
            last_flush_at=datetime.now(UTC),
            dropped_events=0,
            adapter_health={
                "celery.broker": "redis",
                "celery.broker_alive": "True",
                "celery.worker_details": _build_celery_worker_details_payload(),
                "celery.queue_depths": json.dumps(
                    {
                        "celery": 3,
                        "high_priority": 1,
                    }
                ),
            },
        ),
    )


@pytest.mark.asyncio
class TestFrameRouterHeartbeatE2E:
    """The whole heartbeat handler with a real DB and a real frame."""

    async def test_worker_details_lands_worker_row_with_metadata(
        self,
        db_manager: DatabaseManager,
        project_and_agent: tuple[uuid.UUID, uuid.UUID],
        heartbeat_frame: HeartbeatFrame,
    ) -> None:
        project_id, agent_id = project_and_agent

        router = FrameRouter(
            db=db_manager,
            ingestor=None,  # not used by _handle_heartbeat
            dispatcher=None,  # not used by _handle_heartbeat
            project_id=project_id,
            agent_id=agent_id,
            dashboard_hub=None,
            worker_id=None,
        )

        # ---- THE CALL UNDER TEST ----
        # Pre-1.3.1 this raised AttributeError: worker_metadata
        # internally and the worker row never landed.
        await router._handle_heartbeat(heartbeat_frame)

        # The worker row MUST exist with metadata populated.
        factory = sessionmaker(
            db_manager._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        async with factory() as s:
            result = await s.execute(
                select(Worker).where(Worker.project_id == project_id),
            )
            workers = list(result.scalars().all())
            assert len(workers) == 1, (
                "expected exactly one worker row from the heartbeat; "
                "if zero, the bulk-upsert path silently swallowed the "
                "row (1.3.0 regression). if multiple, dedup is broken."
            )
            w = workers[0]
            assert w.engine == "celery"
            assert w.name == "celery@picker_django"
            assert w.hostname == "celery@picker_django"
            assert w.concurrency == 4
            # active task count came from data["active"] length (=1).
            assert w.active_tasks == 1
            # The two queues from active_queues land on the row.
            assert sorted(w.queues or []) == ["celery", "high_priority"]
            # And the metadata bundle round-trips through JSON ↔
            # the "metadata" DB column ↔ the Python attribute.
            assert isinstance(w.worker_metadata, dict)
            assert "stats" in w.worker_metadata
            assert "active" in w.worker_metadata
            assert "active_queues" in w.worker_metadata

    async def test_worker_details_idempotent_across_two_heartbeats(
        self,
        db_manager: DatabaseManager,
        project_and_agent: tuple[uuid.UUID, uuid.UUID],
        heartbeat_frame: HeartbeatFrame,
    ) -> None:
        """Two consecutive heartbeats from the same agent should
        update the existing worker row, not duplicate it."""
        project_id, _ = project_and_agent

        router = FrameRouter(
            db=db_manager,
            ingestor=None,
            dispatcher=None,
            project_id=project_id,
            agent_id=project_and_agent[1],
            dashboard_hub=None,
            worker_id=None,
        )

        await router._handle_heartbeat(heartbeat_frame)
        await router._handle_heartbeat(heartbeat_frame)

        factory = sessionmaker(
            db_manager._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        async with factory() as s:
            result = await s.execute(
                select(Worker).where(Worker.project_id == project_id),
            )
            workers = list(result.scalars().all())
            assert len(workers) == 1, (
                "two heartbeats produced "
                f"{len(workers)} worker rows; "
                "ON CONFLICT DO UPDATE on (project_id, engine, name) "
                "must collapse them to one"
            )

    async def test_queue_observations_use_frame_source_time_and_never_rewind(
        self,
        db_manager: DatabaseManager,
        project_and_agent: tuple[uuid.UUID, uuid.UUID],
    ) -> None:
        """Depth and worker-announced queue touches share signed frame time."""
        project_id, agent_id = project_and_agent
        fresh_observed = datetime.now(UTC)
        stale_observed = fresh_observed - timedelta(seconds=1)
        worker_details = json.dumps(
            {
                "celery@queue-clock": {
                    "stats": {"pool": {"max-concurrency": 1}},
                    "active_queues": [{"name": "worker-only"}],
                },
            },
        )
        fresh_frame = HeartbeatFrame(
            id=str(uuid.uuid4()),
            ts=fresh_observed,
            payload=HeartbeatPayload(
                last_flush_at=fresh_observed,
                adapter_health={
                    "celery.queue_depths": json.dumps({"critical": 29}),
                    "celery.worker_details": worker_details,
                },
            ),
        )
        stale_frame = HeartbeatFrame(
            id=str(uuid.uuid4()),
            ts=stale_observed,
            payload=HeartbeatPayload(
                last_flush_at=stale_observed,
                adapter_health={
                    "celery.queue_depths": json.dumps({"critical": 11}),
                },
            ),
        )
        router = FrameRouter(
            db=db_manager,
            ingestor=None,
            dispatcher=None,
            project_id=project_id,
            agent_id=agent_id,
            dashboard_hub=None,
            worker_id=None,
        )

        await router._handle_heartbeat(fresh_frame)
        await router._handle_heartbeat(stale_frame)

        factory = sessionmaker(
            db_manager._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        async with factory() as session:
            queues = {
                row.name: row for row in (await session.execute(select(Queue))).scalars().all()
            }
        critical = queues["critical"]
        worker_only = queues["worker-only"]
        assert critical.pending_count == 29
        assert critical.last_seen_at is not None
        assert critical.last_seen_at.replace(tzinfo=UTC) == fresh_observed
        assert worker_only.last_seen_at is not None
        assert worker_only.last_seen_at.replace(tzinfo=UTC) == fresh_observed

    async def test_revoked_agent_heartbeat_is_rejected_without_derived_rows(
        self,
        db_manager: DatabaseManager,
        project_and_agent: tuple[uuid.UUID, uuid.UUID],
        heartbeat_frame: HeartbeatFrame,
    ) -> None:
        """A committed revoke is authoritative even if its WS kick failed."""
        project_id, agent_id = project_and_agent

        async with db_manager.session(write=True) as session:
            agent = await session.get(Agent, agent_id)
            assert agent is not None
            agent.revoked_at = datetime.now(UTC)
            await session.commit()

        router = FrameRouter(
            db=db_manager,
            ingestor=None,
            dispatcher=None,
            project_id=project_id,
            agent_id=agent_id,
            dashboard_hub=None,
            worker_id=None,
        )

        outcome = await router.dispatch(heartbeat_frame)

        assert outcome is FrameOutcome.REVOKED
        async with db_manager.session() as session:
            workers = (await session.execute(select(Worker))).scalars().all()
            queues = (await session.execute(select(Queue))).scalars().all()
            agent = await session.get(Agent, agent_id)

        assert workers == []
        assert queues == []
        assert agent is not None
        assert agent.last_seen_at is None


# ---------------------------------------------------------------------------
# Defense-in-depth allowlist at brain side
# ---------------------------------------------------------------------------


def _malicious_celery_worker_details_payload() -> str:
    """Simulate an adapter that DID NOT filter conf before shipping.

    Could be: a pre-1.6.6 z4j-celery in the wild, a third-party
    queue-engine adapter that reuses the ``celery.worker_details``
    key shape, or a compromised agent. The brain must scrub the
    forbidden keys before they land in workers.metadata.
    """
    return json.dumps(
        {
            "celery@malicious_agent": {
                "stats": {
                    "pool": {"max-concurrency": 2, "processes": [101, 102]},
                    "rusage": {"utime": 1.0, "stime": 0.1},
                    "pid": 100,
                },
                "active": [],
                "active_queues": [{"name": "celery"}],
                "registered": ["myapp.tasks.do_thing"],
                "conf": {
                    # ALL of these MUST be stripped at the brain even
                    # though the (hypothetical) bad adapter shipped them.
                    "broker_url": "redis://:LEAKED_BROKER_PASSWORD@redis.internal:6379/0",
                    "result_backend": "db+postgresql://celery:LEAKED_PG_PW@db.internal/celery",
                    "broker_transport_options": {
                        "aws_secret_access_key": "LEAKED_AWS_SECRET",
                    },
                    "beat_schedule": {
                        "weekly": {
                            "task": "myapp.report",
                            "kwargs": {"recipient": "PII@example.com"},
                        },
                    },
                    # Benign keys must survive the filter.
                    "task_serializer": "json",
                    "worker_concurrency": 2,
                    "timezone": "UTC",
                },
            },
        }
    )


@pytest.fixture
def malicious_heartbeat_frame() -> HeartbeatFrame:
    return HeartbeatFrame(
        id=str(uuid.uuid4()),
        ts=datetime.now(UTC),
        payload=HeartbeatPayload(
            buffer_size=0,
            last_flush_at=datetime.now(UTC),
            dropped_events=0,
            adapter_health={
                "celery.broker": "redis",
                "celery.broker_alive": "True",
                "celery.worker_details": _malicious_celery_worker_details_payload(),
                "celery.queue_depths": json.dumps({"celery": 0}),
            },
        ),
    )


@pytest.mark.asyncio
class TestFrameRouterConfScrub:
    """Defense in depth: brain MUST allowlist-filter the conf
    sub-object even when a (broken or malicious) adapter ships
    credentialed keys.

    The source-side filter lives at
    ``z4j_celery.engine._redact_worker_conf``; this test verifies the
    brain re-applies the same allowlist before the JSONB column write,
    so a compromised / downgraded / third-party adapter cannot pivot
    credentials into the worker_metadata blob and from there to
    ProjectRole.VIEWER over the worker-detail endpoint.
    """

    async def test_brain_strips_credentialed_conf_from_malicious_adapter_r7_h1(
        self,
        db_manager: DatabaseManager,
        project_and_agent: tuple[uuid.UUID, uuid.UUID],
        malicious_heartbeat_frame: HeartbeatFrame,
    ) -> None:
        project_id, agent_id = project_and_agent

        router = FrameRouter(
            db=db_manager,
            ingestor=None,
            dispatcher=None,
            project_id=project_id,
            agent_id=agent_id,
            dashboard_hub=None,
            worker_id=None,
        )

        await router._handle_heartbeat(malicious_heartbeat_frame)

        factory = sessionmaker(
            db_manager._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        async with factory() as s:
            result = await s.execute(
                select(Worker).where(Worker.project_id == project_id),
            )
            workers = list(result.scalars().all())
            assert len(workers) == 1
            w = workers[0]
            persisted_conf = (
                w.worker_metadata.get("conf", {})
                if isinstance(
                    w.worker_metadata,
                    dict,
                )
                else {}
            )

            # Forbidden keys MUST NOT have landed in JSONB.
            for forbidden in (
                "broker_url",
                "result_backend",
                "broker_transport_options",
                "beat_schedule",
            ):
                assert forbidden not in persisted_conf, (
                    f"brain persisted {forbidden!r} into "
                    "workers.metadata.conf; ProjectRole.VIEWER would "
                    "read it via GET /api/v1/projects/{slug}/workers/{worker_id}"
                )

            # And the dumped JSON string must NOT contain the secret
            # values anywhere (catches the case where a future
            # refactor moves the dangerous keys into a nested
            # collision-free position but still ships the bytes).
            persisted_blob = json.dumps(w.worker_metadata, default=str)
            for needle in (
                "LEAKED_BROKER_PASSWORD",
                "LEAKED_PG_PW",
                "LEAKED_AWS_SECRET",
            ):
                assert needle not in persisted_blob, (
                    f"{needle!r} leaked into the persisted worker_metadata "
                    "JSON blob despite the structural strip"
                )

            # Benign keys SHOULD have survived the filter so the
            # dashboard's worker-detail page stays useful.
            assert persisted_conf.get("task_serializer") == "json"
            assert persisted_conf.get("worker_concurrency") == 2
            assert persisted_conf.get("timezone") == "UTC"


def _partial_worker_details_payload() -> str:
    """The same worker, from a round where most inspect broadcasts timed out.

    ``get_worker_details`` builds its result one broadcast at a time and only
    records a key for the ones that answered, so this is what a real agent
    emits when the stats reply arrives and the queue, task-list and config
    replies do not.
    """
    return json.dumps(
        {
            "celery@picker_django": {
                "stats": {"pid": 100},
            },
        }
    )


@pytest.mark.asyncio
async def test_a_heartbeat_that_collected_less_does_not_erase_what_was_collected(
    db_manager: DatabaseManager,
    project_and_agent: tuple[uuid.UUID, uuid.UUID],
    heartbeat_frame: HeartbeatFrame,
) -> None:
    """A broadcast that went unanswered is not a worker with nothing.

    Each field in a worker's report comes from its own Celery inspect
    broadcast with its own timeout, so a heartbeat routinely carries some of
    them and not the rest. Writing the missing ones out as empty results made
    every such heartbeat blank a live worker's queue list, running-task count
    and configuration, and the dashboard flapped at whatever rate the
    broadcasts happened to time out.
    """
    project_id, agent_id = project_and_agent
    router = FrameRouter(
        db=db_manager,
        ingestor=None,
        dispatcher=None,
        project_id=project_id,
        agent_id=agent_id,
        dashboard_hub=None,
        worker_id=None,
    )

    await router._handle_heartbeat(heartbeat_frame)

    partial = heartbeat_frame.model_copy(deep=True)
    partial.payload.adapter_health["celery.worker_details"] = _partial_worker_details_payload()
    await router._handle_heartbeat(partial)

    factory = sessionmaker(
        db_manager._engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with factory() as s:
        worker = (
            await s.execute(select(Worker).where(Worker.project_id == project_id))
        ).scalar_one()

    assert sorted(worker.queues or []) == ["celery", "high_priority"], (
        "the queue list a previous heartbeat established was cleared by a "
        "heartbeat whose active_queues broadcast did not answer"
    )
    assert worker.active_tasks == 1
    assert worker.concurrency == 4
    assert worker.load_average == [0.5, 0.7, 0.8]
    assert worker.worker_metadata["active_queues"] == [
        {"name": "celery"},
        {"name": "high_priority"},
    ]
    assert worker.worker_metadata["registered"] == [
        "myapp.tasks.add",
        "myapp.tasks.send_email",
    ]
    assert worker.worker_metadata["active"] == [
        {"id": "task-1", "name": "myapp.tasks.add"},
    ]
    # The report that DID answer is still applied, merged onto the rest.
    assert worker.worker_metadata["stats"]["pid"] == 100
    assert worker.worker_metadata["stats"]["rusage"] == {"utime": 12.3, "stime": 4.5}


# ---------------------------------------------------------------------------
# A heartbeat describes several workers at once, and they do not answer alike
# ---------------------------------------------------------------------------


def _mixed_worker_details_payload(rich: str, quiet: str) -> str:
    """Two workers in one round: one answered every broadcast, one answered none.

    Not a contrived pairing. Every field is its own Celery inspect broadcast
    with its own timeout, and the broadcasts are per worker, so a fleet where
    one worker is busy or slow produces exactly this on a routine round.
    """
    return json.dumps(
        {
            rich: {
                "stats": {
                    "pool": {"max-concurrency": 4, "processes": [101, 102, 103, 104]},
                    "loadavg": [0.5, 0.7, 0.8],
                    "pid": 100,
                },
                "active": [{"id": "task-1", "name": "myapp.tasks.add"}],
                "active_queues": [{"name": "celery"}],
                "registered": ["myapp.tasks.add"],
                "conf": {"task_serializer": "json"},
            },
            quiet: {},
        }
    )


@pytest.mark.parametrize(
    ("rich", "quiet"),
    [
        # The batch is sorted by conflict key before it is written, so which
        # of the two decides the statement's shape is decided by the worker
        # NAMES, which no caller here chooses. Both ways round.
        pytest.param("celery@aaa-full", "celery@zzz-silent", id="reporting-worker-first"),
        pytest.param("celery@zzz-full", "celery@aaa-silent", id="silent-worker-first"),
    ],
)
@pytest.mark.asyncio
async def test_one_worker_answering_nothing_does_not_cost_the_other_its_report(
    db_manager: DatabaseManager,
    project_and_agent: tuple[uuid.UUID, uuid.UUID],
    heartbeat_frame: HeartbeatFrame,
    rich: str,
    quiet: str,
) -> None:
    """Both rows land, and the one that reported keeps what it reported.

    The two failures this covers are opposite and both total: with the
    reporting worker first the statement cannot be compiled and neither row
    lands at all, and with the silent worker first the columns only the
    reporting worker carries leave the statement, so both rows land stripped.
    """
    project_id, agent_id = project_and_agent
    router = FrameRouter(
        db=db_manager,
        ingestor=None,
        dispatcher=None,
        project_id=project_id,
        agent_id=agent_id,
        dashboard_hub=None,
        worker_id=None,
    )

    mixed = heartbeat_frame.model_copy(deep=True)
    mixed.payload.adapter_health["celery.worker_details"] = _mixed_worker_details_payload(
        rich,
        quiet,
    )
    await router._handle_heartbeat(mixed)

    factory = sessionmaker(db_manager._engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        landed = {
            w.name: w
            for w in (await s.execute(select(Worker).where(Worker.project_id == project_id)))
            .scalars()
            .all()
        }

    assert set(landed) == {rich, quiet}, (
        f"expected both workers from one heartbeat, got {sorted(landed)}; a "
        "batch whose rows carry different columns must not cost the round"
    )
    reporting = landed[rich]
    assert reporting.concurrency == 4, (
        "the reporting worker's pool size did not land; the column was "
        "dropped from the statement because a sibling row did not carry it"
    )
    assert reporting.pid == 100
    assert reporting.active_tasks == 1
    assert sorted(reporting.queues or []) == ["celery"]
    assert reporting.load_average == [0.5, 0.7, 0.8]
    assert reporting.worker_metadata["registered"] == ["myapp.tasks.add"]
    # The silent worker is recorded as seen and nothing more.
    assert landed[quiet].concurrency is None
    assert landed[quiet].worker_metadata == {}


@pytest.mark.asyncio
async def test_a_bulk_write_that_fails_any_way_at_all_falls_back_per_row(
    db_manager: DatabaseManager,
    project_and_agent: tuple[uuid.UUID, uuid.UUID],
    heartbeat_frame: HeartbeatFrame,
    monkeypatch,
) -> None:
    """The fallback is for the batch, not for one exception class.

    The bulk statement has more than one way to fail: it deadlocks, it can be
    asked to express rows one statement cannot express, and an agent-supplied
    worker name can violate a column bound. Only the first of those is an
    ``OperationalError``. A fallback that names it catches the fault it was
    written for and lets every other one take the whole batch, on a path that
    runs every ten seconds per agent.

    The fault is injected at the bulk repository call because that is the
    collaborator that fails in production; everything below it here is the
    real per-row write, which is what has to be shown still landing the row.
    """
    from sqlalchemy.exc import CompileError
    from z4j_brain.persistence.repositories import WorkerRepository

    async def _refuse(self, rows):
        raise CompileError("this batch is not expressible as one statement")

    monkeypatch.setattr(WorkerRepository, "upsert_from_events_bulk", _refuse)

    project_id, agent_id = project_and_agent
    router = FrameRouter(
        db=db_manager,
        ingestor=None,
        dispatcher=None,
        project_id=project_id,
        agent_id=agent_id,
        dashboard_hub=None,
        worker_id=None,
    )

    await router._handle_heartbeat(heartbeat_frame)

    factory = sessionmaker(db_manager._engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        workers = list(
            (await s.execute(select(Worker).where(Worker.project_id == project_id))).scalars().all()
        )

    assert len(workers) == 1, (
        "the heartbeat's worker rows were lost when the bulk statement failed "
        "with something other than a deadlock; the per-row fallback did not run"
    )
    assert workers[0].name == "celery@picker_django"
    assert workers[0].concurrency == 4
    assert workers[0].worker_metadata["registered"] == [
        "myapp.tasks.add",
        "myapp.tasks.send_email",
    ]


@pytest.mark.asyncio
async def test_a_worker_that_answered_last_round_keeps_what_it_reported(
    db_manager: DatabaseManager,
    project_and_agent: tuple[uuid.UUID, uuid.UUID],
    heartbeat_frame: HeartbeatFrame,
) -> None:
    """The sequence a real fleet produces, and the flapping it caused.

    Which worker answers is not stable across rounds. A round where worker A
    answers and B does not is followed by one where B answers and A does not,
    and if the columns only one of them carried are written out for both, the
    dashboard shows each worker's pool size, queue list and configuration
    appearing and disappearing at whatever rate the broadcasts time out.
    """
    first, second = "celery@aaa-one", "celery@zzz-two"
    project_id, agent_id = project_and_agent
    router = FrameRouter(
        db=db_manager,
        ingestor=None,
        dispatcher=None,
        project_id=project_id,
        agent_id=agent_id,
        dashboard_hub=None,
        worker_id=None,
    )

    # Round one: the first worker answers, the second does not.
    round_one = heartbeat_frame.model_copy(deep=True)
    round_one.payload.adapter_health["celery.worker_details"] = _mixed_worker_details_payload(
        first,
        second,
    )
    await router._handle_heartbeat(round_one)

    # Round two: the other way round.
    round_two = heartbeat_frame.model_copy(deep=True)
    round_two.payload.adapter_health["celery.worker_details"] = _mixed_worker_details_payload(
        second,
        first,
    )
    await router._handle_heartbeat(round_two)

    factory = sessionmaker(db_manager._engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        landed = {
            w.name: w
            for w in (await s.execute(select(Worker).where(Worker.project_id == project_id)))
            .scalars()
            .all()
        }

    for name in (first, second):
        worker = landed[name]
        assert worker.concurrency == 4, (
            f"{name} lost the pool size it reported; a round it did not answer "
            "wrote a sibling row's absent value over it"
        )
        assert worker.pid == 100
        assert sorted(worker.queues or []) == ["celery"]
        assert worker.worker_metadata["registered"] == ["myapp.tasks.add"]
        assert worker.load_average == [0.5, 0.7, 0.8]
