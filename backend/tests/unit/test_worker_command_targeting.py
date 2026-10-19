"""Real worker detail/command routes must not redirect controls to another agent."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select
from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models import Agent, Command, Event, Worker

from tests.unit import test_b4_endpoints as b4

brain_app = b4.brain_app
client = b4.client
seeded = b4.seeded
settings = b4.settings

ACTIONS = ["restart_worker", "pool_grow", "pool_shrink", "add_consumer", "cancel_consumer"]
ROUTES = [
    ("restart-worker", {}),
    ("pool-resize", {"delta": 1}),
    ("add-consumer", {"queue": "jobs"}),
    ("cancel-consumer", {"queue": "jobs"}),
]


@pytest.fixture
async def workers(brain_app, seeded):
    now = datetime.now(UTC)
    async with brain_app.state.db.session() as session:
        agents = [
            Agent(
                project_id=seeded["project_id"],
                name=name,
                token_hash=name * 8,
                protocol_version="2",
                framework_adapter="bare",
                state=AgentState.ONLINE,
                engine_adapters=["celery"],
                capabilities={"celery": ACTIONS},
                last_connect_at=now,
            )
            for name in ("unrelated", "reporter")
        ]
        session.add_all(agents)
        worker = Worker(project_id=seeded["project_id"], engine="celery", name="same-worker-name")
        session.add(worker)
        await session.flush()
        session.add(
            Event(
                project_id=seeded["project_id"],
                agent_id=agents[1].id,
                engine="celery",
                task_id="",
                kind="worker.online",
                occurred_at=now,
                payload={"worker": worker.name},
            )
        )
        await session.commit()
        return {
            "owner": agents[1].id,
            "other": agents[0].id,
            "worker": worker.id,
            "name": worker.name,
            "project": seeded["project_id"],
        }


@pytest.mark.asyncio
@pytest.mark.parametrize("route, extra", ROUTES)
async def test_wrong_agent_is_refused_without_command(
    client, seeded, brain_app, workers, route, extra
):
    response = await client.post(
        f"/api/v1/projects/default/commands/{route}",
        headers={"X-CSRF-Token": seeded["csrf"]},
        json={
            "agent_id": str(workers["other"]),
            "engine": "celery",
            "worker_name": workers["name"],
            **extra,
        },
    )
    assert response.status_code == 422, response.text
    async with brain_app.state.db.session() as session:
        assert await session.scalar(select(func.count()).select_from(Command)) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("route, extra", ROUTES)
async def test_native_command_keeps_observed_reporter_and_engine(
    client, seeded, brain_app, workers, route, extra
):
    detail = await client.get(f"/api/v1/projects/default/workers/{workers['worker']}")
    assert detail.status_code == 200
    assert detail.json()["agent_id"] == str(workers["owner"])
    response = await client.post(
        f"/api/v1/projects/default/commands/{route}",
        headers={"X-CSRF-Token": seeded["csrf"]},
        json={
            "agent_id": str(workers["owner"]),
            "engine": "celery",
            "worker_name": workers["name"],
            **extra,
        },
    )
    assert response.status_code == 202, response.text
    async with brain_app.state.db.session() as session:
        command = (await session.scalars(select(Command))).one()
        assert command.agent_id == workers["owner"]
        assert command.payload["engine"] == "celery"
        assert command.payload["worker_name"] == workers["name"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    ["missing", "task_only", "ambiguous", "unknown_inventory", "unsupported", "wrong_engine"],
)
async def test_restart_fails_closed_without_target_proof(client, seeded, brain_app, workers, fault):
    from sqlalchemy import delete

    async with brain_app.state.db.session() as session:
        owner = await session.get(Agent, workers["owner"])
        if fault in ("missing", "task_only"):
            await session.execute(delete(Event))
            if fault == "task_only":
                session.add(
                    Event(
                        project_id=workers["project"],
                        agent_id=workers["owner"],
                        engine="celery",
                        task_id="task",
                        kind="task.success",
                        occurred_at=datetime.now(UTC),
                        payload={"worker": workers["name"]},
                    )
                )
        elif fault == "ambiguous":
            session.add(
                Event(
                    project_id=workers["project"],
                    agent_id=workers["other"],
                    engine="celery",
                    task_id="",
                    kind="worker.heartbeat",
                    occurred_at=datetime.now(UTC),
                    payload={"worker": workers["name"]},
                )
            )
        elif fault == "unknown_inventory":
            owner.engine_adapters = []
            owner.capabilities = {}
            owner.last_connect_at = None
        elif fault == "unsupported":
            owner.capabilities = {"celery": []}
        await session.commit()
    if fault in ("missing", "task_only", "ambiguous"):
        detail = await client.get(f"/api/v1/projects/default/workers/{workers['worker']}")
        assert detail.json()["agent_id"] is None
    response = await client.post(
        "/api/v1/projects/default/commands/restart-worker",
        headers={"X-CSRF-Token": seeded["csrf"]},
        json={
            "agent_id": str(workers["owner"]),
            "engine": "rq" if fault == "wrong_engine" else "celery",
            "worker_name": workers["name"],
        },
    )
    assert response.status_code == 422, response.text
    async with brain_app.state.db.session() as session:
        assert await session.scalar(select(func.count()).select_from(Command)) == 0


@pytest.mark.asyncio
async def test_engine_omission_refuses_ambiguous_worker_name(client, seeded, brain_app, workers):
    async with brain_app.state.db.session() as session:
        session.add(Worker(project_id=workers["project"], engine="rq", name=workers["name"]))
        await session.commit()
    body = {"agent_id": str(workers["owner"]), "worker_name": workers["name"]}
    response = await client.post(
        "/api/v1/projects/default/commands/restart-worker",
        headers={"X-CSRF-Token": seeded["csrf"]},
        json=body,
    )
    assert response.status_code == 422, response.text
    async with brain_app.state.db.session() as session:
        assert await session.scalar(select(func.count()).select_from(Command)) == 0
    response = await client.post(
        "/api/v1/projects/default/commands/restart-worker",
        headers={"X-CSRF-Token": seeded["csrf"]},
        json={**body, "engine": "celery"},
    )
    assert response.status_code == 202, response.text
