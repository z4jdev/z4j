"""SQLite restore gates for the configured prior migration head.

The source is manufactured entirely by the current checkout: current models
write at current head, current migrations downgrade it, and current backup code
copies it.  These tests prove that self-generated schema-at-head path only.
They do not run a prior wheel/container and are not prior-artifact evidence.
"""

from __future__ import annotations

import asyncio
import shutil
import sqlite3
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest
from alembic import command
from alembic.config import Config
from alembic.util import CommandError
from alembic.util import pyfiles as alembic_pyfiles
from sqlalchemy import create_engine, select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session
from z4j_brain import management_restore as management_restore_module
from z4j_brain.backup import backup_sqlite, restore_sqlite
from z4j_brain.management_reset import release_manifest_digest
from z4j_brain.management_restore import (
    _PREVIOUS_RELEASE_HEAD,
    DatabaseRestoreRefused,
)
from z4j_brain.persistence.database import (
    DatabaseManager,
    create_engine_from_settings,
)
from z4j_brain.persistence.models import (
    AuditLog,
    Project,
    Schedule,
    ScheduleExternalStream,
)
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
)
from z4j_brain.persistence.repositories.schedule_external import (
    ScheduleExternalRepository,
)
from z4j_brain.schema_transition import RELEASE_MIGRATION_HEAD
from z4j_brain.secret_store import ensure_secret_store_directory
from z4j_brain.settings import Settings
from z4j_brain.startup import verify_production_authority_at_startup

from tests.unit.test_runtime_rollback_preparation import (
    TARGET_AUTHORITY,
    finalized_manifest,
)

_ROLLBACK_MIGRATION_FILENAME = "2026_07_30_0012_v1_9_schedule_control_columns.py"
_ALEMBIC_LOAD_MODULE_PY = alembic_pyfiles.load_module_py


def _assert_finalized_restore_fixture_authority(_bind: object) -> None:
    """Admit only the synthetic, fully validated authority at this test seam."""

    from z4j_brain.domain.runtime_rollback import validate_finalized_rollback_manifest

    authority = validate_finalized_rollback_manifest(
        finalized_manifest(),
        manifest_sha256=TARGET_AUTHORITY["manifest_sha256"],
    )
    assert authority["index"] == TARGET_AUTHORITY["index"]


def _load_restore_fixture_migration(
    module_id: str,
    path: str | Path,
) -> ModuleType:
    """Install the authority seam on Alembic's isolated revision module."""

    module = _ALEMBIC_LOAD_MODULE_PY(module_id, path)
    if Path(path).name == _ROLLBACK_MIGRATION_FILENAME:
        module._assert_runtime_rollback_prepared = (  # type: ignore[attr-defined]
            _assert_finalized_restore_fixture_authority
        )
    return module


@pytest.fixture
def previous_release_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[Config, str, str]]:
    private_home = ensure_secret_store_directory(
        tmp_path / "z4j-previous-release",
    )
    db_path = private_home / "z4j.db"
    sync_url = f"sqlite:///{db_path}"
    async_url = f"sqlite+aiosqlite:///{db_path}"
    backend_root = Path(__file__).resolve().parents[2]

    monkeypatch.setenv("Z4J_DATABASE_URL", async_url)
    monkeypatch.setenv("Z4J_SECRET", "x" * 64)
    monkeypatch.setenv("Z4J_SESSION_SECRET", "y" * 64)
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", "a" * 64)
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.chdir(backend_root)

    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    try:
        yield config, sync_url, async_url
    finally:
        shutil.rmtree(private_home, ignore_errors=True)


def _alembic_config() -> Config:
    """Build a fresh config: alembic binds one to the database it first ran."""

    backend_root = Path(__file__).resolve().parents[2]
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(backend_root / "src" / "z4j_brain" / "migrations"),
    )
    return config


def _schedule_data(name: str) -> dict[str, object]:
    return {
        "name": name,
        "task_name": f"jobs.{name}",
        "engine": "celery",
        "scheduler": "z4j-scheduler",
        "kind": "interval",
        "expression": "5m",
        "timezone": "UTC",
        "queue": None,
        "priority": "normal",
        "args": [],
        "kwargs": {},
        "is_enabled": True,
        "catch_up": "skip",
        "source": "dashboard",
    }


async def _populate(
    async_url: str,
    *,
    project_id: uuid.UUID,
    slug: str,
    schedule_names: tuple[str, ...],
    with_external_executor: bool,
) -> tuple[list[uuid.UUID], uuid.UUID | None]:
    """Write real rows through the product's own guarded write paths."""

    database = DatabaseManager(create_async_engine(async_url))
    schedule_ids: list[uuid.UUID] = []
    stream_id: uuid.UUID | None = None
    try:
        async with database.session(write=True) as session:
            session.add(Project(id=project_id, slug=slug, name=slug.title()))
            await session.commit()
        for index, name in enumerate(schedule_names):
            async with database.session(write=True) as session:
                row = await ScheduleControlRepository(session).create_current(
                    project_id=project_id,
                    data=_schedule_data(name),
                    planning_at=datetime(2026, 7, 25, 12, index, tzinfo=UTC),
                )
                schedule_ids.append(row.id)
                await session.commit()
        if with_external_executor:
            async with database.session(write=True) as session:
                stream = await ScheduleExternalRepository(
                    session,
                ).ensure_activation_epoch(
                    project_id=project_id,
                    owner="celery-beat",
                    source_scope=('{"kind":"scheduler-owner","owner":"celery-beat","version":1}'),
                    occurred_at=datetime(2026, 7, 25, 15, 0, tzinfo=UTC),
                    adapter_instance_id="previous-release-adapter",
                    executor_agent_id=uuid.uuid4(),
                    executor_registry_owner_id=uuid.uuid4(),
                    executor_session_generation=uuid.uuid4().hex,
                )
                stream_id = stream.id
                await session.commit()
    finally:
        await database.dispose()
    return schedule_ids, stream_id


def _build_current_checkout_prior_head_backup(
    monkeypatch: pytest.MonkeyPatch,
    *,
    target_async_url: str,
    source_path: Path,
    backup_path: Path,
    project_id: uuid.UUID,
    slug: str,
    schedule_names: tuple[str, ...] = ("nightly", "hourly"),
    with_external_executor: bool = False,
) -> tuple[list[uuid.UUID], uuid.UUID | None]:
    """Produce a current-checkout backup staged at the prior head.

    The rows are written at the current head so every Boundary-D trigger and
    the audit chain see the writes they expect, then the database is migrated
    back down to the configured prior head.  This intentionally makes no claim
    that its bytes match a backup emitted by a previously shipped artifact.
    """

    source_async_url = f"sqlite+aiosqlite:///{source_path}"
    monkeypatch.setenv("Z4J_DATABASE_URL", source_async_url)
    try:
        command.upgrade(_alembic_config(), "head")
        schedule_ids, stream_id = asyncio.run(
            _populate(
                source_async_url,
                project_id=project_id,
                slug=slug,
                schedule_names=schedule_names,
                with_external_executor=with_external_executor,
            ),
        )
        # These restore tests manufacture a prior-head archive; they do not
        # claim to prove the separately covered operator rollback ceremony.
        # Keep the exception local to this one manufacturing downgrade, and
        # require its synthetic authority to pass the production validator.
        with monkeypatch.context() as restore_fixture:
            restore_fixture.setattr(
                alembic_pyfiles,
                "load_module_py",
                _load_restore_fixture_migration,
            )
            command.downgrade(_alembic_config(), _PREVIOUS_RELEASE_HEAD)
    finally:
        monkeypatch.setenv("Z4J_DATABASE_URL", target_async_url)

    with sqlite3.connect(source_path) as probe:
        heads = probe.execute("SELECT version_num FROM alembic_version").fetchall()
    assert heads == [(_PREVIOUS_RELEASE_HEAD,)]

    backup_sqlite(source_async_url, backup_path)
    return schedule_ids, stream_id


def test_real_unfinalized_rollback_authority_refuses_the_manufacturing_downgrade(
    previous_release_install: tuple[Config, str, str],
) -> None:
    """The tracked pre-cutoff authority must stay fail-closed outside the seam."""

    config, _, async_url = previous_release_install
    command.upgrade(config, "head")
    asyncio.run(
        _populate(
            async_url,
            project_id=uuid.uuid4(),
            slug="unfinalized-authority",
            schedule_names=("guarded",),
            with_external_executor=False,
        ),
    )

    with pytest.raises(
        CommandError,
        match="rollback compatibility image authority is not finalized",
    ):
        command.downgrade(_alembic_config(), _PREVIOUS_RELEASE_HEAD)


def test_current_checkout_prior_head_backup_restores_with_its_rows(
    previous_release_install: tuple[Config, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A current-checkout backup staged at the prior head restores and starts."""

    config, sync_url, async_url = previous_release_install
    command.upgrade(config, "head")
    target = Path(sync_url.removeprefix("sqlite:///"))

    displaced_project_id = uuid.uuid4()
    asyncio.run(
        _populate(
            async_url,
            project_id=displaced_project_id,
            slug="displaced",
            schedule_names=("displaced-schedule",),
            with_external_executor=False,
        ),
    )

    source_project_id = uuid.uuid4()
    schedule_ids, _ = _build_current_checkout_prior_head_backup(
        monkeypatch,
        target_async_url=async_url,
        source_path=target.parent / "previous-release-source.db",
        backup_path=target.parent / "previous-release-backup.db",
        project_id=source_project_id,
        slug="restored",
    )

    operation_id = uuid.uuid4()
    result = restore_sqlite(
        async_url,
        target.parent / "previous-release-backup.db",
        operation=str(operation_id),
    )
    assert result["operation_id"] == str(operation_id)
    assert result["backend"] == "sqlite"

    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            head = session.execute(
                select(Schedule).where(Schedule.id.in_(schedule_ids)),
            )
            restored = sorted(head.scalars(), key=lambda row: row.name)
            assert [row.name for row in restored] == ["hourly", "nightly"]
            # The 1.9 columns the migration added must be present and
            # defaulted on rows that predate them.
            assert {row.overlap_policy for row in restored} == {"allow"}
            assert {row.paused_at for row in restored} == {None}
            # The restore rebase advances every restored schedule past the
            # barrier, so it must not have left the pre-restore revisions.
            assert all(row.schedule_revision >= 1 for row in restored)

            projects = set(session.execute(select(Project.id)).scalars())
            assert source_project_id in projects
            assert displaced_project_id not in projects

            marker = session.execute(
                select(AuditLog).where(
                    AuditLog.action == "audit.database_restored",
                    AuditLog.target_id == str(operation_id),
                ),
            ).scalar_one()
            metadata = marker.audit_metadata
            # The signed marker has to say where the data came from, not just
            # where the ceremony left it.
            assert metadata["source_migration_head"] == _PREVIOUS_RELEASE_HEAD
            assert metadata["upgraded_migration_head"] == RELEASE_MIGRATION_HEAD
            assert (
                metadata["source_schema_contract_digest"]
                != metadata["upgraded_schema_contract_digest"]
            )
            assert (
                metadata["schema_contract_digest"] == (metadata["upgraded_schema_contract_digest"])
            )
    finally:
        engine.dispose()

    with sqlite3.connect(target) as probe:
        heads = probe.execute("SELECT version_num FROM alembic_version").fetchall()
    assert heads == [(RELEASE_MIGRATION_HEAD,)]

    # A restored database nobody can start against is not a restored database.
    settings = Settings()  # type: ignore[call-arg]
    database = DatabaseManager(create_engine_from_settings(settings))
    try:
        report = asyncio.run(
            verify_production_authority_at_startup(
                db=database,
                settings=settings,
            ),
        )
        assert report.clean
    finally:
        asyncio.run(database.dispose())


def test_previous_release_authority_derives_real_executor_state(
    previous_release_install: tuple[Config, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """External executor authority is read from the source, never stubbed."""

    config, sync_url, async_url = previous_release_install
    command.upgrade(config, "head")
    target = Path(sync_url.removeprefix("sqlite:///"))
    backup_path = target.parent / "executor-backup.db"

    _, stream_id = _build_current_checkout_prior_head_backup(
        monkeypatch,
        target_async_url=async_url,
        source_path=target.parent / "executor-source.db",
        backup_path=backup_path,
        project_id=uuid.uuid4(),
        slug="executors",
        schedule_names=("watched",),
        with_external_executor=True,
    )
    assert stream_id is not None

    authority = management_restore_module._sqlite_source_authority(
        backup_path,
        source_digest="0" * 64,
    )
    assert authority["source_head"] == _PREVIOUS_RELEASE_HEAD
    external = authority["external_authority_manifest"]
    # A stubbed pre-Boundary-D manifest would report an empty external
    # authority here and silently skip the stopped-executor ceremony.
    assert external["requires_stopped_executor_attestation"] is True
    assert external["stream_count"] == 1
    assert external["epoch_count"] == 1
    assert [entry["stream_id"] for entry in external["executor_authority"]["streams"]] == [
        str(stream_id)
    ]
    assert external["executor_authority"]["streams"][0]["adapter_instance_id"] == (
        "previous-release-adapter"
    )
    assert [entry["stream_id"] for entry in external["executor_authority"]["epochs"]] == [
        str(stream_id)
    ]
    # The epoch allocator really advanced when the stream was activated, so a
    # hardcoded zero would be wrong here too.
    assert authority["epoch"] >= 1
    assert authority["revision"] >= 1
    assert authority["pruned_through"] >= 0
    assert len(authority["manifest_digest"]) == 64

    # And the derived flag has to reach the operator: the restore refuses
    # until the stopped-executor challenge is attested.
    with pytest.raises(
        DatabaseRestoreRefused,
        match="requires the exact stopped-executor",
    ):
        restore_sqlite(async_url, backup_path, operation=str(uuid.uuid4()))


def test_previous_release_restore_completes_after_executor_attestation(
    previous_release_install: tuple[Config, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The derived challenge is the one that finishes the ceremony."""

    config, sync_url, async_url = previous_release_install
    command.upgrade(config, "head")
    target = Path(sync_url.removeprefix("sqlite:///"))
    backup_path = target.parent / "attested-backup.db"

    _, stream_id = _build_current_checkout_prior_head_backup(
        monkeypatch,
        target_async_url=async_url,
        source_path=target.parent / "attested-source.db",
        backup_path=backup_path,
        project_id=uuid.uuid4(),
        slug="attested",
        schedule_names=("watched",),
        with_external_executor=True,
    )
    assert stream_id is not None

    operation_id = uuid.uuid4()
    with pytest.raises(DatabaseRestoreRefused) as refused:
        restore_sqlite(async_url, backup_path, operation=str(operation_id))
    challenge = str(refused.value).split("challenge ")[1].split(";")[0].strip()
    assert len(challenge) == 64

    result = restore_sqlite(
        async_url,
        backup_path,
        operation=str(operation_id),
        stopped_executor_attestation=challenge,
    )
    assert result["operation_id"] == str(operation_id)

    # Re-derive the manifest from the untouched source the way a resumed
    # operation would, and require the exact digest the ceremony signed.
    replayed = management_restore_module._sqlite_source_authority(
        backup_path,
        source_digest=result["source_digest"],
    )

    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            stream = session.get(ScheduleExternalStream, stream_id)
            assert stream is not None
            # A restored external stream is held until an operator reactivates
            # it; that hold is the point of the attestation.
            assert stream.phase == "RESTORE_REACTIVATION_REQUIRED"
            marker = session.execute(
                select(AuditLog).where(
                    AuditLog.action == "audit.database_restored",
                    AuditLog.target_id == str(operation_id),
                ),
            ).scalar_one()
            attestation = marker.audit_metadata["executor_attestation"]
            assert attestation["challenge"] == challenge
            # The attestation stays bound to the pre-upgrade authority the
            # operator was shown, which is what a resume re-derives.
            assert attestation["source_manifest_digest"] == (replayed["manifest_digest"])
            assert (
                attestation["source_external_authority_manifest"]
                == (replayed["external_authority_manifest"])
            )
    finally:
        engine.dispose()


def test_previous_release_restore_resumes_after_a_crash_mid_upgrade(
    previous_release_install: tuple[Config, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A candidate left behind by a crashed upgrade must not be reused."""

    config, sync_url, async_url = previous_release_install
    command.upgrade(config, "head")
    target = Path(sync_url.removeprefix("sqlite:///"))
    backup_path = target.parent / "resume-backup.db"

    source_project_id = uuid.uuid4()
    schedule_ids, _ = _build_current_checkout_prior_head_backup(
        monkeypatch,
        target_async_url=async_url,
        source_path=target.parent / "resume-source.db",
        backup_path=backup_path,
        project_id=source_project_id,
        slug="resumed",
        schedule_names=("resumable",),
    )

    real_upgrade = management_restore_module._upgrade_sqlite_database

    def _crash_after_upgrading(path: Path, **kwargs: object) -> None:
        real_upgrade(path, **kwargs)  # type: ignore[arg-type]
        raise KeyboardInterrupt("power loss after the candidate was migrated")

    monkeypatch.setattr(
        management_restore_module,
        "_upgrade_sqlite_database",
        _crash_after_upgrading,
    )
    operation_id = uuid.uuid4()
    with pytest.raises(KeyboardInterrupt):
        restore_sqlite(async_url, backup_path, operation=str(operation_id))

    phase_path = target.parent / ".z4j-restore" / str(operation_id) / "phase.json"
    phase = management_restore_module._read_phase(phase_path)
    assert phase["state"] == "PREFLIGHT_COMPLETE"
    assert (target.parent / ".z4j-restore" / str(operation_id) / "candidate.db").exists()

    monkeypatch.setattr(
        management_restore_module,
        "_upgrade_sqlite_database",
        real_upgrade,
    )
    result = restore_sqlite(async_url, backup_path, operation=str(operation_id))
    assert result["operation_id"] == str(operation_id)

    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            restored = session.execute(
                select(Schedule).where(Schedule.id.in_(schedule_ids)),
            ).scalars()
            assert [row.name for row in restored] == ["resumable"]
    finally:
        engine.dispose()


def _restored_project_ids(sync_url: str) -> set[uuid.UUID]:
    engine = create_engine(sync_url)
    try:
        with Session(engine) as session:
            return set(session.execute(select(Project.id)).scalars())
    finally:
        engine.dispose()


@pytest.mark.parametrize("field", ["revision", "pruned_through", "epoch"])
def test_previous_release_restore_refuses_an_authority_it_did_not_read(
    previous_release_install: tuple[Config, str, str],
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    """A derivation that describes some other database must not be believed.

    The whole ceremony downstream of the derivation trusts it, so a wrong
    Boundary-D fact would be carried into the signed marker unchallenged.
    """

    config, sync_url, async_url = previous_release_install
    command.upgrade(config, "head")
    target = Path(sync_url.removeprefix("sqlite:///"))
    backup_path = target.parent / f"unread-{field}-backup.db"

    displaced_project_id = uuid.uuid4()
    asyncio.run(
        _populate(
            async_url,
            project_id=displaced_project_id,
            slug="displaced",
            schedule_names=("displaced-schedule",),
            with_external_executor=False,
        ),
    )

    source_project_id = uuid.uuid4()
    _build_current_checkout_prior_head_backup(
        monkeypatch,
        target_async_url=async_url,
        source_path=target.parent / f"unread-{field}-source.db",
        backup_path=backup_path,
        project_id=source_project_id,
        slug="unread",
        schedule_names=("counted",),
    )

    real_builder = management_restore_module._SQLITE_SOURCE_MANIFEST_BUILDERS[
        _PREVIOUS_RELEASE_HEAD
    ]

    def _misreport(connection: sqlite3.Connection) -> dict[str, object]:
        return {**real_builder(connection), field: 987654}

    monkeypatch.setitem(
        management_restore_module._SQLITE_SOURCE_MANIFEST_BUILDERS,
        _PREVIOUS_RELEASE_HEAD,
        _misreport,
    )

    with pytest.raises(DatabaseRestoreRefused) as refused:
        restore_sqlite(async_url, backup_path, operation=str(uuid.uuid4()))
    # The operator has to be told which fact disagreed, not just that one did.
    assert field in str(refused.value)

    projects = _restored_project_ids(sync_url)
    assert displaced_project_id in projects
    assert source_project_id not in projects


def test_previous_release_restore_refuses_a_stubbed_pre_boundary_authority(
    previous_release_install: tuple[Config, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reusing the pre-Boundary-D stub for an activated source must not pass.

    The stub reports revision zero and no external authority at all, which for
    an activated previous-release source is both wrong and dangerous: it skips
    the stopped-executor ceremony that keeps a live executor away from the
    restored database. The restore has to notice rather than complete.
    """

    config, sync_url, async_url = previous_release_install
    command.upgrade(config, "head")
    target = Path(sync_url.removeprefix("sqlite:///"))
    backup_path = target.parent / "stubbed-backup.db"

    displaced_project_id = uuid.uuid4()
    asyncio.run(
        _populate(
            async_url,
            project_id=displaced_project_id,
            slug="displaced",
            schedule_names=("displaced-schedule",),
            with_external_executor=False,
        ),
    )

    source_project_id = uuid.uuid4()
    _, stream_id = _build_current_checkout_prior_head_backup(
        monkeypatch,
        target_async_url=async_url,
        source_path=target.parent / "stubbed-source.db",
        backup_path=backup_path,
        project_id=source_project_id,
        slug="stubbed",
        schedule_names=("watched",),
        with_external_executor=True,
    )
    assert stream_id is not None

    monkeypatch.setitem(
        management_restore_module._SQLITE_SOURCE_MANIFEST_BUILDERS,
        _PREVIOUS_RELEASE_HEAD,
        management_restore_module._legacy_source_boundary_authority,
    )

    with pytest.raises(DatabaseRestoreRefused) as refused:
        # No attestation is supplied on purpose: under the stub the ceremony
        # never asks for one, which is exactly the hole being closed.
        restore_sqlite(async_url, backup_path, operation=str(uuid.uuid4()))
    message = str(refused.value)
    assert "revision" in message
    assert "external executor authority" in message

    projects = _restored_project_ids(sync_url)
    assert displaced_project_id in projects
    assert source_project_id not in projects


def test_previous_release_restore_says_why_a_candidate_would_not_migrate(
    previous_release_install: tuple[Config, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A candidate that will not migrate is a refusal, not a stack trace."""

    config, sync_url, async_url = previous_release_install
    command.upgrade(config, "head")
    target = Path(sync_url.removeprefix("sqlite:///"))
    backup_path = target.parent / "unmigratable-backup.db"

    displaced_project_id = uuid.uuid4()
    asyncio.run(
        _populate(
            async_url,
            project_id=displaced_project_id,
            slug="displaced",
            schedule_names=("displaced-schedule",),
            with_external_executor=False,
        ),
    )

    source_project_id = uuid.uuid4()
    _build_current_checkout_prior_head_backup(
        monkeypatch,
        target_async_url=async_url,
        source_path=target.parent / "unmigratable-source.db",
        backup_path=backup_path,
        project_id=source_project_id,
        slug="unmigratable",
        schedule_names=("doomed",),
    )

    real_backup = management_restore_module._sqlite_backup

    def _damage_the_candidate(source: Path, destination: Path) -> None:
        real_backup(source, destination)
        if destination.name != "candidate.db":
            return
        # Take the table the release migration has to alter out from under it,
        # so the real alembic run fails the way a broken archive would.
        connection = sqlite3.connect(destination)
        try:
            connection.execute("ALTER TABLE schedules RENAME TO schedules_displaced")
            connection.commit()
        finally:
            connection.close()

    monkeypatch.setattr(
        management_restore_module,
        "_sqlite_backup",
        _damage_the_candidate,
    )

    with pytest.raises(DatabaseRestoreRefused) as refused:
        restore_sqlite(async_url, backup_path, operation=str(uuid.uuid4()))
    message = str(refused.value)
    # Which archive, where it was being taken, and what actually broke.
    assert _PREVIOUS_RELEASE_HEAD in message
    assert RELEASE_MIGRATION_HEAD in message
    assert "schedules" in message

    projects = _restored_project_ids(sync_url)
    assert displaced_project_id in projects
    assert source_project_id not in projects


#: table -> (statement under test, column the manifest order must follow)
_ORDERING_TABLES = {
    "schedule_external_streams": (
        management_restore_module._SOURCE_EXTERNAL_STREAM_QUERY,
        "id",
    ),
    "schedule_external_stream_epochs": (
        management_restore_module._SOURCE_EXTERNAL_EPOCH_QUERY,
        "epoch_uuid",
    ),
    "schedule_external_control_operations": (
        management_restore_module._SOURCE_EXTERNAL_OPERATION_QUERY,
        "id",
    ),
}


def test_manifest_rows_are_ordered_by_data_not_physical_layout(
    tmp_path: Path,
) -> None:
    """Resume re-derives the challenge, so row order cannot be physical."""

    path = tmp_path / "ordering.db"
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        for table in _ORDERING_TABLES:
            connection.execute(
                f"CREATE TABLE {table} ("
                "id TEXT, epoch_uuid TEXT, epoch_number INTEGER, status TEXT)",
            )
            # Inserted in reverse so the physical order is the opposite of the
            # order the manifest has to use.
            for number, identifier in ((9, "cccc"), (5, "bbbb"), (1, "aaaa")):
                connection.execute(
                    f"INSERT INTO {table}(id, epoch_uuid, epoch_number, status) "
                    "VALUES (?, ?, ?, 'PENDING')",
                    (identifier, identifier, number),
                )
        connection.commit()

        for table, (statement, key) in _ORDERING_TABLES.items():
            physical = [
                row[key]
                for row in connection.execute(
                    f"SELECT * FROM {table}",
                ).fetchall()
            ]
            assert physical == ["cccc", "bbbb", "aaaa"], table
            rows = management_restore_module._sqlite_manifest_rows(
                connection,
                statement,
            )
            assert [row[key] for row in rows] == ["aaaa", "bbbb", "cccc"], table
    finally:
        connection.close()


def test_manifest_digest_survives_a_different_physical_layout(
    tmp_path: Path,
) -> None:
    """Two databases holding the same rows must digest the same.

    Resume re-derives the attestation challenge from the manifest, so a
    manifest that depends on where SQLite happens to have put the rows
    produces a challenge the operator cannot satisfy on the second run.
    """

    digests: list[str] = []
    for label, insert_order in (
        ("ascending", ((1, "aaaa"), (5, "bbbb"), (9, "cccc"))),
        ("descending", ((9, "cccc"), (5, "bbbb"), (1, "aaaa"))),
    ):
        connection = sqlite3.connect(tmp_path / f"{label}.db")
        connection.row_factory = sqlite3.Row
        try:
            for table, (statement, _) in _ORDERING_TABLES.items():
                connection.execute(
                    f"CREATE TABLE {table} ("
                    "id TEXT, epoch_uuid TEXT, epoch_number INTEGER, status TEXT)",
                )
                for number, identifier in insert_order:
                    connection.execute(
                        f"INSERT INTO {table}(id, epoch_uuid, epoch_number, status) "
                        "VALUES (?, ?, ?, 'PENDING')",
                        (identifier, identifier, number),
                    )
                connection.commit()
                digests.append(
                    release_manifest_digest(
                        management_restore_module._sqlite_manifest_rows(
                            connection,
                            statement,
                        ),
                    ),
                )
        finally:
            connection.close()

    half = len(digests) // 2
    assert half == len(_ORDERING_TABLES)
    assert digests[:half] == digests[half:]


def test_import_guard_catches_a_head_with_no_manifest_builder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Adding a restorable head without code behind it must not ship."""

    # Positive control: the module as shipped satisfies its own guard.
    management_restore_module._assert_source_heads_are_consumed()

    monkeypatch.setitem(
        management_restore_module._SQLITE_SOURCE_SCHEMA_DIGESTS,
        "v9_9_imaginary_head",
        "0" * 64,
    )
    with pytest.raises(RuntimeError, match="manifest builder"):
        management_restore_module._assert_source_heads_are_consumed()

    # With a builder but no upgrade mode it still cannot restore, because
    # nothing downstream knows how to migrate the candidate.
    monkeypatch.setitem(
        management_restore_module._SQLITE_SOURCE_MANIFEST_BUILDERS,
        "v9_9_imaginary_head",
        management_restore_module._activated_source_boundary_authority,
    )
    with pytest.raises(RuntimeError, match="upgrade mode"):
        management_restore_module._assert_source_heads_are_consumed()

    monkeypatch.setitem(
        management_restore_module._SQLITE_SOURCE_UPGRADE_MODES,
        "v9_9_imaginary_head",
        "direct",
    )
    management_restore_module._assert_source_heads_are_consumed()


def test_import_guard_catches_a_consumer_for_an_unrestorable_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dropping a head from the allowlist must not leave dead branches."""

    monkeypatch.setitem(
        management_restore_module._SQLITE_SOURCE_UPGRADE_MODES,
        "v0_0_retired_head",
        "direct",
    )
    with pytest.raises(RuntimeError, match="unrestorable heads"):
        management_restore_module._assert_source_heads_are_consumed()
