"""Boundary A: retry authority is bound to the executing session.

The cases that touch a database run against a MIGRATED one rather than a
create_all() one. Every Boundary-D and Boundary-F guard lives inside a
migration, so a create_all() schema refuses nothing: a delivery path could
pass here and be refused on first use by an operator's database.
"""

from __future__ import annotations

import asyncio
import importlib.util
import secrets
import tomllib
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.domain.command_dispatcher import CommandDispatcher
from z4j_brain.domain.retry_contract import (
    engine_is_native_retry,
    required_retry_engine,
    retry_contracts_from_capabilities,
    session_supports_retry_engine,
)
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import AgentState, CommandStatus
from z4j_brain.persistence.models import Agent, Project
from z4j_brain.persistence.repositories import (
    AuditLogRepository,
    CommandRepository,
)
from z4j_brain.settings import Settings
from z4j_brain.websocket.auth import hash_agent_token
from z4j_brain.websocket.gateway import _drain_pending_for_agent
from z4j_brain.websocket.registry._protocol import DeliveryResult, SessionHandle
from z4j_brain.websocket.registry.local import LocalRegistry
from z4j_brain.websocket.registry.postgres_notify import PostgresNotifyRegistry
from z4j_core.transport import CURRENT_PROTOCOL
from z4j_core.transport.framing import FrameSigner


class FakeWebSocket:
    def __init__(self, name: str) -> None:
        self.name = name
        self.closed = False
        self.sent: list[bytes] = []

    async def close(self, code: int = 1000) -> None:
        self.closed = True

    async def send_bytes(self, payload: bytes) -> None:
        self.sent.append(payload)


@pytest.mark.parametrize(
    ("action", "payload", "expected"),
    [
        ("cancel_task", {"engine": "celery"}, None),
        ("retry_task", {"engine": "celery"}, "celery"),
        ("retry_task", {"engine": "unknown"}, ""),
        ("retry_task", {}, ""),
        ("bulk_retry", {"filter": {"engine": "rq"}}, "rq"),
        ("bulk_retry", {"filter": {"engine": "unknown"}}, ""),
        ("bulk_retry", {"filter": {}}, ""),
        ("bulk_retry", None, ""),
    ],
)
def test_retry_requirement_is_derived_from_canonical_command_shape(
    action: str,
    payload: Any,
    expected: str | None,
) -> None:
    assert required_retry_engine(action, payload) == expected


def test_retry_contract_is_extracted_only_from_versioned_adapter_marker() -> None:
    assert retry_contracts_from_capabilities(
        {
            "celery": ["retry_task", "retry_by_reference_v1"],
            "rq": ["retry_task"],
            "not-a-map": "retry_by_reference_v1",
        },
    ) == {"celery": 1}


def test_native_argument_safety_does_not_authorize_an_unadvertised_session() -> None:
    assert engine_is_native_retry("celery") is True
    assert session_supports_retry_engine({}, "celery") is False
    assert session_supports_retry_engine({"celery": 1}, "celery") is True


def _repo_root() -> Path:
    repo_root = Path(__file__).resolve().parents[5]
    assert (repo_root / "VERSION").is_file(), "test did not resolve the repository root"
    return repo_root


def _release_floor_guard(repo_root: Path) -> Any:
    """Load the release guard by path: it is tooling, not an installed module."""
    location = repo_root / "scripts" / "check-release-floors.py"
    assert location.is_file(), f"the release floor guard is missing at {location}"
    spec = importlib.util.spec_from_file_location("z4j_release_floor_guard", location)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _internal_requirements(repo_root: Path) -> tuple[list[str], int]:
    """Count releasable packages and sibling requirements, independently.

    Deliberately a second implementation. If this test only asked the guard
    how much it examined, a guard that examined nothing would agree with
    itself and pass. Reading the tree here is what makes "no violations"
    mean "nothing was wrong" rather than "nothing was looked at".
    """
    guard = _release_floor_guard(repo_root)
    frozen = guard.frozen_packages()
    distributions = {}
    for pyproject in sorted((repo_root / "packages").glob("*/pyproject.toml")):
        project = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]
        distributions[canonicalize_name(project["name"])] = project

    releasable = sorted(distributions.keys() - frozen)
    internal = 0
    for name in releasable:
        project = distributions[name]
        raw_requirements = list(project.get("dependencies", ()))
        for optional_requirements in project.get("optional-dependencies", {}).values():
            raw_requirements.extend(optional_requirements)
        for raw_requirement in raw_requirements:
            required = canonicalize_name(Requirement(raw_requirement).name)
            if required != name and required in distributions:
                internal += 1
    return releasable, internal


def test_release_packages_require_the_siblings_this_release_ships() -> None:
    """No package may resolve beside a sibling from an older release.

    Version-free on purpose. The rule is relational: a requirement on a
    sibling must not admit a release older than the one this tree ships.
    A guard written against a literal version stops selecting anything the
    moment the fleet is stamped past it, and then reports success over an
    empty set while the floors it named go stale underneath it.
    """
    repo_root = _repo_root()
    guard = _release_floor_guard(repo_root)
    expected_packages, expected_requirements = _internal_requirements(repo_root)

    violations, packages, requirements = guard.run(None)

    assert packages == len(expected_packages), (
        f"the guard examined {packages} packages, but the tree has "
        f"{len(expected_packages)} releasable ones: {expected_packages}"
    )
    assert requirements == expected_requirements, (
        f"the guard examined {requirements} sibling requirements, "
        f"but the tree declares {expected_requirements}"
    )
    assert requirements > 0, "no sibling requirement exists to check"
    assert violations == [], "uncoordinated internal dependency floors:\n" + "\n".join(violations)


def test_release_floor_guard_rejects_a_floor_below_the_shipped_sibling() -> None:
    """The guard must actually refuse the pairing it exists to prevent.

    Without this, the assertion above would still pass if ``audit`` were
    reduced to returning an empty list. The failing case here is the live
    one: an agent that imports a symbol its declared floor does not
    guarantee, so the install resolves and the import raises.
    """
    guard = _release_floor_guard(_repo_root())
    providers = {"z4j-core": {"name": "z4j-core", "version": "9.1.0"}}

    stale = {
        "z4j-bare": {
            "name": "z4j-bare",
            "version": "9.1.0",
            "dependencies": ["z4j-core>=9.0.0,<10"],
            "_source": "synthetic",
        },
    }
    violations, examined = guard.audit(stale, providers, frozen=())
    assert examined == 1
    assert len(violations) == 1
    assert "z4j-core 9.0.0" in violations[0]

    coordinated = {
        "z4j-bare": {
            "name": "z4j-bare",
            "version": "9.1.0",
            "dependencies": ["z4j-core>=9.1.0,<10"],
            "_source": "synthetic",
        },
    }
    violations, examined = guard.audit(coordinated, providers, frozen=())
    assert examined == 1
    assert violations == []


def _fake_wheel(directory: Path, name: str, version: str, requires: tuple[str, ...]) -> None:
    metadata = [
        "Metadata-Version: 2.3",
        f"Name: {name}",
        f"Version: {version}",
        *(f"Requires-Dist: {r}" for r in requires),
        "",
    ]
    wheel = directory / f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            f"{name.replace('-', '_')}-{version}.dist-info/METADATA",
            "\n".join(metadata),
        )


def test_release_floor_guard_refuses_to_pass_on_a_partial_wave_build(tmp_path: Path) -> None:
    """A dist directory missing wheels cannot be reported as verified.

    With a sibling absent, the version it is held to would be read from the
    working tree instead of the artifact, and a floor pointing at the
    previous release then reads as correct. Verifying one wheel out of the
    wave has to be a refusal, not a pass.
    """
    repo_root = _repo_root()
    guard = _release_floor_guard(repo_root)
    releasable, _ = _internal_requirements(repo_root)

    _fake_wheel(tmp_path, "z4j-bare", "9.1.0", ("z4j-core<10,>=9.0.0",))
    with pytest.raises(guard.FloorError, match="partial build"):
        guard.run(tmp_path)

    # Completing the wave must change the answer from "cannot run" to the
    # verdict on the floor, not to silence.
    for name in releasable:
        if name != "z4j-bare":
            _fake_wheel(tmp_path, name, "9.1.0", ())
    violations, packages, requirements = guard.run(tmp_path)
    assert packages == len(releasable)
    assert requirements == 1
    assert len(violations) == 1
    assert "z4j-core 9.0.0" in violations[0]

    # And a coordinated floor over the same complete wave must pass, or the
    # refusals above would be indistinguishable from a guard that refuses
    # everything and therefore verifies nothing.
    _fake_wheel(tmp_path, "z4j-bare", "9.1.0", ("z4j-core<10,>=9.1.0",))
    violations, packages, requirements = guard.run(tmp_path)
    assert violations == []
    assert packages == len(releasable)
    assert requirements == 1


@pytest.mark.asyncio
async def test_mixed_workers_deliver_retry_only_to_attested_adapter_session() -> None:
    """A current agent row must not authorize a colocated old worker."""
    delivered_to: list[str] = []

    async def deliver(_command_id: uuid.UUID, ws: Any) -> bool:
        delivered_to.append(ws.name)
        return True

    registry = LocalRegistry(deliver_local=deliver)
    agent_id = uuid.uuid4()
    project_id = uuid.uuid4()
    await registry.register(
        project_id=project_id,
        agent_id=agent_id,
        ws=FakeWebSocket("old-first"),
        worker_id="old",
        retry_contracts={},
    )
    await registry.register(
        project_id=project_id,
        agent_id=agent_id,
        ws=FakeWebSocket("current-second"),
        worker_id="current",
        retry_contracts={"celery": 1},
    )

    result = await registry.deliver(
        command_id=uuid.uuid4(),
        agent_id=agent_id,
        required_retry_engine="celery",
    )

    assert result.delivered_locally is True
    assert delivered_to == ["current-second"]


@pytest.mark.asyncio
async def test_selected_generation_is_not_retargeted_to_replacement() -> None:
    """Reconnect under one worker id cannot inherit a claimed retry."""
    delivered_to: list[str] = []
    registry: LocalRegistry
    agent_id = uuid.uuid4()
    project_id = uuid.uuid4()

    async def deliver(_command_id: uuid.UUID, ws: Any) -> bool:
        delivered_to.append(ws.name)
        if ws.name == "selected":
            await registry.register(
                project_id=project_id,
                agent_id=agent_id,
                ws=FakeWebSocket("replacement"),
                worker_id="same-slot",
                retry_contracts={"celery": 1},
            )
            return False
        raise AssertionError("delivery retargeted after the selected generation vanished")

    registry = LocalRegistry(deliver_local=deliver)
    await registry.register(
        project_id=project_id,
        agent_id=agent_id,
        ws=FakeWebSocket("selected"),
        worker_id="same-slot",
        retry_contracts={"celery": 1},
    )

    result = await asyncio.wait_for(
        registry.deliver(
            command_id=uuid.uuid4(),
            agent_id=agent_id,
            required_retry_engine="celery",
        ),
        timeout=1,
    )

    assert result.delivered_locally is False
    assert delivered_to == ["selected"]


@pytest.mark.asyncio
async def test_postgres_selected_generation_send_does_not_block_replacement() -> None:
    """The production registry must not hold its map lock across send I/O."""
    # No schema: registry selection is entirely in-memory and the engine only
    # exists to satisfy the constructor, so there is nothing here for a
    # migrated database to guard.
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )
    engine = create_async_engine(settings.database_url)
    registry: PostgresNotifyRegistry
    agent_id = uuid.uuid4()
    project_id = uuid.uuid4()
    delivered_to: list[str] = []

    async def deliver(_command_id: uuid.UUID, ws: Any) -> bool:
        delivered_to.append(ws.name)
        if ws.name == "selected":
            await registry.register(
                project_id=project_id,
                agent_id=agent_id,
                ws=FakeWebSocket("replacement"),
                worker_id="same-slot",
                retry_contracts={"celery": 1},
            )
            return False
        raise AssertionError("delivery retargeted after the selected generation vanished")

    registry = PostgresNotifyRegistry(
        settings=settings,
        db=DatabaseManager(engine),
        dsn_provider=lambda: "postgresql://unused",
        deliver_local=deliver,
    )
    try:
        await registry.register(
            project_id=project_id,
            agent_id=agent_id,
            ws=FakeWebSocket("selected"),
            worker_id="same-slot",
            retry_contracts={"celery": 1},
        )
        result = await asyncio.wait_for(
            registry.deliver(
                command_id=uuid.uuid4(),
                agent_id=agent_id,
                required_retry_engine="celery",
            ),
            timeout=1,
        )
    finally:
        await engine.dispose()

    assert result.delivered_locally is False
    assert result.notified_cluster is False
    assert delivered_to == ["selected"]


@pytest.mark.asyncio
async def test_postgres_exact_delivery_allows_reconnect_and_rejects_displaced_send() -> None:
    """Reconnect cannot deadlock, retarget, or send through a displaced socket."""
    # No schema, for the same reason as the test above.
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )
    engine = create_async_engine(settings.database_url)
    entered = asyncio.Event()
    release = asyncio.Event()
    delivered_to: list[str] = []

    async def deliver(_command_id: uuid.UUID, ws: Any) -> bool:
        entered.set()
        await release.wait()
        validate = ws._z4j_validate_registry_generation
        if not await validate():
            return False
        delivered_to.append(ws.name)
        return True

    registry = PostgresNotifyRegistry(
        settings=settings,
        db=DatabaseManager(engine),
        dsn_provider=lambda: "postgresql://unused",
        deliver_local=deliver,
    )
    agent_id = uuid.uuid4()
    project_id = uuid.uuid4()
    try:
        original = await registry.register(
            project_id=project_id,
            agent_id=agent_id,
            ws=FakeWebSocket("original"),
            worker_id="same-slot",
            retry_contracts={"celery": 1},
        )
        delivery = asyncio.create_task(
            registry.deliver_exact(
                command_id=uuid.uuid4(),
                session=original,
            ),
        )
        await entered.wait()
        try:
            replacement_handle = await asyncio.wait_for(
                registry.register(
                    project_id=project_id,
                    agent_id=agent_id,
                    ws=FakeWebSocket("replacement"),
                    worker_id="same-slot",
                    retry_contracts={"celery": 1},
                ),
                timeout=1,
            )
        finally:
            release.set()
            delivered = await asyncio.wait_for(delivery, timeout=1)
        assert replacement_handle.generation != original.generation
        assert delivered is False
        assert delivered_to == []
    finally:
        release.set()
        await engine.dispose()


@pytest.mark.asyncio
async def test_websocket_reconnect_drain_cannot_claim_for_old_session(
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> None:
    """The reconnect bypass must enforce the same exact-session contract."""
    settings = Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        audit_chain_secret=migrated_audit_chain_secret,  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )
    engine = create_async_engine(settings.database_url)
    db = DatabaseManager(engine)
    try:
        async with db.session() as session:
            project = Project(slug="ws-drain-retry", name="WS drain retry")
            session.add(project)
            await session.flush()
            agent = Agent(
                project_id=project.id,
                name="ws-drain-agent",
                token_hash=secrets.token_hex(32),
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.ONLINE,
            )
            session.add(agent)
            await session.flush()
            command, _ = await CommandRepository(session).insert(
                project_id=project.id,
                agent_id=agent.id,
                issued_by=None,
                action="retry_task",
                target_type="task",
                target_id="celery:drain",
                payload={"engine": "celery", "task_id": "drain"},
                idempotency_key=None,
                timeout_at=datetime.now(UTC) + timedelta(minutes=5),
                source_ip=None,
            )
            await session.commit()
            project_id = project.id
            agent_id = agent.id
            command_id = command.id

        old_ws = FakeWebSocket("old")
        # Registry.register stamps this immutable delivery coordinate in
        # production. This test calls the drain helper directly, so its socket
        # double must carry the same binding or the outbound authority guard
        # correctly refuses the physical send before consulting the signer.
        old_ws._z4j_agent_id = agent_id  # type: ignore[attr-defined]
        old_ws._z4j_signer = FrameSigner(  # type: ignore[attr-defined]
            secret=b"x" * 32,
            agent_id=agent_id,
            project_id=project_id,
            session_id="old",
        )
        old_handle = SessionHandle.create(
            agent_id=agent_id,
            worker_id="old",
            websocket=old_ws,  # type: ignore[arg-type]
            retry_contracts={},
        )
        await _drain_pending_for_agent(
            db=db,
            settings=settings,
            agent_id=agent_id,
            session_handle=old_handle,
        )
        async with db.session() as session:
            still_pending = await CommandRepository(session).get(command_id)
            assert still_pending is not None
            assert still_pending.status == CommandStatus.PENDING
        assert old_ws.sent == []

        current_ws = FakeWebSocket("current")
        current_ws._z4j_agent_id = agent_id  # type: ignore[attr-defined]
        current_ws._z4j_signer = FrameSigner(  # type: ignore[attr-defined]
            secret=b"y" * 32,
            agent_id=agent_id,
            project_id=project_id,
            session_id="current",
        )
        current_handle = SessionHandle.create(
            agent_id=agent_id,
            worker_id="current",
            websocket=current_ws,  # type: ignore[arg-type]
            retry_contracts={"celery": 1},
        )
        await _drain_pending_for_agent(
            db=db,
            settings=settings,
            agent_id=agent_id,
            session_handle=current_handle,
        )
        async with db.session() as session:
            dispatched = await CommandRepository(session).get(command_id)
            assert dispatched is not None
            assert dispatched.status == CommandStatus.DISPATCHED
        assert len(current_ws.sent) == 1
    finally:
        await engine.dispose()


class RequirementRecordingRegistry:
    def __init__(self) -> None:
        self.required_retry_engines: list[str | None] = []

    async def deliver(
        self,
        *,
        command_id: uuid.UUID,
        agent_id: uuid.UUID,
        required_retry_engine: str | None = None,
    ) -> DeliveryResult:
        self.required_retry_engines.append(required_retry_engine)
        return DeliveryResult(
            delivered_locally=False,
            notified_cluster=True,
            agent_was_known=True,
        )


@pytest.mark.asyncio
async def test_dispatcher_enforces_retry_requirement_below_automation_path(
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> None:
    """Every direct dispatcher caller inherits the retry-session gate."""
    settings = Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        audit_chain_secret=migrated_audit_chain_secret,  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )
    engine = create_async_engine(settings.database_url)

    registry = RequirementRecordingRegistry()
    try:
        # ``write=True``, because that is the session every production caller of
        # ``issue`` holds. On SQLite it is the BEGIN IMMEDIATE the audit chain
        # demands before its first read.
        async with DatabaseManager(engine).session(write=True) as session:
            project = Project(slug="retry-boundary", name="Retry boundary")
            session.add(project)
            await session.flush()
            agent = Agent(
                project_id=project.id,
                name="agent",
                token_hash=secrets.token_hex(32),
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.ONLINE,
            )
            session.add(agent)
            await session.flush()

            dispatcher = CommandDispatcher(
                settings=settings,
                registry=registry,  # type: ignore[arg-type]
                audit=AuditService(settings),
            )
            await dispatcher.issue(
                commands=CommandRepository(session),
                audit_log=AuditLogRepository(session),
                project_id=project.id,
                agent_id=agent.id,
                action="retry_task",
                target_type="task",
                target_id="celery:t1",
                payload={"engine": "celery", "task_id": "t1"},
                issued_by=None,
                ip=None,
                user_agent="automation-rule:test",
            )
    finally:
        await engine.dispose()

    assert registry.required_retry_engines == ["celery"]


@pytest.mark.parametrize(
    ("action", "target_type", "target_id", "persisted_payload", "caller_payload"),
    [
        (
            "retry_task",
            "task",
            "celery:t1",
            {"engine": "celery", "task_id": "t1"},
            {"engine": "rq", "task_id": "t1"},
        ),
        (
            "bulk_retry",
            "bulk",
            None,
            {"filter": {"engine": "celery", "task_ids": ["t1"]}},
            {"filter": {"engine": "rq", "task_ids": ["t1"]}},
        ),
    ],
)
@pytest.mark.asyncio
async def test_idempotent_reissue_gates_the_persisted_retry_contract(
    action: str,
    target_type: str,
    target_id: str | None,
    persisted_payload: dict[str, Any],
    caller_payload: dict[str, Any],
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> None:
    """Session authority must describe the immutable row that is delivered."""
    settings = Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        audit_chain_secret=migrated_audit_chain_secret,  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )
    engine = create_async_engine(settings.database_url)
    database = DatabaseManager(engine)

    registry = RequirementRecordingRegistry()
    try:
        async with database.session(write=True) as session:
            project = Project(slug=f"canonical-{action}", name="Canonical retry")
            session.add(project)
            await session.flush()
            agent = Agent(
                project_id=project.id,
                name="agent",
                token_hash=secrets.token_hex(32),
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=["celery", "rq"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.ONLINE,
            )
            session.add(agent)
            await session.flush()
            existing, created = await CommandRepository(session).insert(
                project_id=project.id,
                agent_id=agent.id,
                issued_by=None,
                action=action,
                target_type=target_type,
                target_id=target_id,
                payload=persisted_payload,
                idempotency_key=f"canonical-reissue-{action}",
                timeout_at=datetime.now(UTC) + timedelta(minutes=5),
                source_ip=None,
            )
            assert created is True
            project_id, agent_id, existing_id = project.id, agent.id, existing.id
            await session.commit()

        # The re-issue is a second operation, so it gets a second write unit,
        # exactly as it would arriving on a second request or a second frame.
        async with database.session(write=True) as session:
            returned = await CommandDispatcher(
                settings=settings,
                registry=registry,  # type: ignore[arg-type]
                audit=AuditService(settings),
            ).issue(
                commands=CommandRepository(session),
                audit_log=AuditLogRepository(session),
                project_id=project_id,
                agent_id=agent_id,
                action=action,
                target_type=target_type,
                target_id=target_id,
                payload=caller_payload,
                issued_by=None,
                ip=None,
                user_agent="canonical-reissue-test",
                idempotency_key=f"canonical-reissue-{action}",
            )

            assert returned.id == existing_id
            assert returned.payload == persisted_payload
    finally:
        await engine.dispose()

    assert registry.required_retry_engines == ["celery"]


@pytest.mark.asyncio
async def test_cluster_notify_and_reconcile_select_attested_session(
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> None:
    """Both deferred delivery edges re-derive and enforce the row contract."""
    settings = Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        audit_chain_secret=migrated_audit_chain_secret,  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
    )
    engine = create_async_engine(settings.database_url)
    db = DatabaseManager(engine)
    delivered_to: list[str] = []

    async def deliver(command_id: uuid.UUID, ws: Any) -> bool:
        async with db.session() as session:
            generation = await CommandRepository(session).mark_dispatched(
                command_id,
                timeout_seconds=settings.command_timeout_seconds,
            )
            await session.commit()
        if generation:
            delivered_to.append(ws.name)
            return True
        return False

    registry = PostgresNotifyRegistry(
        settings=settings,
        db=db,
        dsn_provider=lambda: "postgresql://unused",
        deliver_local=deliver,
    )
    try:
        async with db.session() as session:
            project = Project(slug="cluster-retry", name="Cluster retry")
            session.add(project)
            await session.flush()
            agent = Agent(
                project_id=project.id,
                name="cluster-agent",
                token_hash=secrets.token_hex(32),
                protocol_version=CURRENT_PROTOCOL,
                framework_adapter="bare",
                engine_adapters=["celery"],
                scheduler_adapters=[],
                capabilities={},
                state=AgentState.ONLINE,
            )
            session.add(agent)
            await session.flush()
            command_ids: list[uuid.UUID] = []
            for task_id in ("notify", "reconcile"):
                command, _ = await CommandRepository(session).insert(
                    project_id=project.id,
                    agent_id=agent.id,
                    issued_by=None,
                    action="retry_task",
                    target_type="task",
                    target_id=f"celery:{task_id}",
                    payload={"engine": "celery", "task_id": task_id},
                    idempotency_key=None,
                    timeout_at=datetime.now(UTC) + timedelta(minutes=5),
                    source_ip=None,
                )
                command_ids.append(command.id)
            await session.commit()
            agent_id = agent.id
            project_id = project.id

        await registry.register(
            project_id=project_id,
            agent_id=agent_id,
            ws=FakeWebSocket("old-first"),
            worker_id="old",
            retry_contracts={},
        )
        await registry.register(
            project_id=project_id,
            agent_id=agent_id,
            ws=FakeWebSocket("current-second"),
            worker_id="current",
            retry_contracts={"celery": 1},
        )

        await registry._dispatch_notified_command(  # type: ignore[attr-defined]
            command_ids[0],
            agent_id,
            notified_retry_engine="celery",
        )
        await registry._reconcile_pending()  # type: ignore[attr-defined]

        assert delivered_to == ["current-second", "current-second"]
    finally:
        await engine.dispose()


LONGPOLL_TOKEN = "z4j_agent_retry_session_boundary"


@pytest.fixture
def longpoll_settings(
    migrated_db_url: str,
    migrated_audit_chain_secret: str,
) -> Settings:
    return Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        # A migrated database has Boundary F activated, so it refuses an audit
        # row that carries no chain authentication. Production always has this
        # configured; a test that omits it is not testing production.
        audit_chain_secret=migrated_audit_chain_secret,  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        registry_backend="local",
    )


@pytest.fixture
async def longpoll_app(longpoll_settings: Settings):
    engine = create_async_engine(longpoll_settings.database_url)
    app = create_app(longpoll_settings, engine=engine)
    yield app
    await engine.dispose()


@pytest.fixture
async def longpoll_client(longpoll_app):
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(
        transport=ASGITransport(app=longpoll_app),
        base_url="http://testserver",
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_longpoll_missing_contract_cannot_inherit_sticky_positive(
    longpoll_app,
    longpoll_client,
    longpoll_settings: Settings,
) -> None:
    """An old polling session must not claim a retry authorized by old metadata."""
    async with longpoll_app.state.db.session() as session:
        project = Project(slug="lp-retry", name="LP retry")
        session.add(project)
        await session.flush()
        agent = Agent(
            project_id=project.id,
            name="lp-agent",
            token_hash=hash_agent_token(
                plaintext=LONGPOLL_TOKEN,
                secret=longpoll_settings.secret.get_secret_value().encode("utf-8"),
            ),
            protocol_version=CURRENT_PROTOCOL,
            framework_adapter="bare",
            engine_adapters=["celery"],
            scheduler_adapters=[],
            capabilities={},
            state=AgentState.ONLINE,
            agent_metadata={"runtime_features": ["retry_by_reference"]},
        )
        session.add(agent)
        await session.flush()
        command, created = await CommandRepository(session).insert(
            project_id=project.id,
            agent_id=agent.id,
            issued_by=None,
            action="retry_task",
            target_type="task",
            target_id="celery:t1",
            payload={"engine": "celery", "task_id": "t1"},
            idempotency_key=None,
            timeout_at=datetime.now(UTC) + timedelta(minutes=5),
            source_ip=None,
        )
        assert created is True
        await session.commit()
        command_id = command.id

    response = await longpoll_client.get(
        "/api/v1/agent/commands",
        params={"wait": 0, "max_frames": 50},
        headers={
            "Authorization": f"Bearer {LONGPOLL_TOKEN}",
            "X-Z4J-Session-Nonce": "old-session-without-contract-header",
        },
    )

    assert response.status_code == 200
    assert response.json()["frames"] == []
    async with longpoll_app.state.db.session() as session:
        command = await CommandRepository(session).get(command_id)
        assert command is not None
        assert command.status == CommandStatus.PENDING


@pytest.mark.asyncio
async def test_longpoll_current_session_claims_only_its_attested_engine(
    longpoll_app,
    longpoll_client,
    longpoll_settings: Settings,
) -> None:
    token = f"{LONGPOLL_TOKEN}_current"
    async with longpoll_app.state.db.session() as session:
        project = Project(slug="lp-current", name="LP current")
        session.add(project)
        await session.flush()
        agent = Agent(
            project_id=project.id,
            name="lp-current-agent",
            token_hash=hash_agent_token(
                plaintext=token,
                secret=longpoll_settings.secret.get_secret_value().encode("utf-8"),
            ),
            protocol_version=CURRENT_PROTOCOL,
            framework_adapter="bare",
            engine_adapters=["celery"],
            scheduler_adapters=[],
            capabilities={},
            state=AgentState.ONLINE,
        )
        session.add(agent)
        await session.flush()
        command, _ = await CommandRepository(session).insert(
            project_id=project.id,
            agent_id=agent.id,
            issued_by=None,
            action="retry_task",
            target_type="task",
            target_id="celery:t2",
            payload={"engine": "celery", "task_id": "t2"},
            idempotency_key=None,
            timeout_at=datetime.now(UTC) + timedelta(minutes=5),
            source_ip=None,
        )
        await session.commit()
        command_id = command.id

    response = await longpoll_client.get(
        "/api/v1/agent/commands",
        params={"wait": 0, "max_frames": 50},
        headers={
            "Authorization": f"Bearer {token}",
            "X-Z4J-Session-Nonce": "current-session",
            "X-Z4J-Retry-Contracts": "celery=1",
        },
    )

    assert response.status_code == 200
    assert len(response.json()["frames"]) == 1
    async with longpoll_app.state.db.session() as session:
        command = await CommandRepository(session).get(command_id)
        assert command is not None
        assert command.status == CommandStatus.DISPATCHED
