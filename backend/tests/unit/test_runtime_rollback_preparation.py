"""Source-side proof for the image-bound 1.9 -> 1.8.2 restamp."""

from __future__ import annotations

import copy
import hashlib
import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.domain.runtime_rollback import (
    SEALED_TARGET_CADENCE_FINGERPRINT,
    SEALED_TARGET_CADENCE_PAYLOAD,
    RuntimeRollbackRefused,
    challenge_sha256,
    durable_evidence_sha256,
    preview_challenge,
    require_finalized_target_image,
    validate_finalized_rollback_manifest,
    validate_target_image,
)
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.models import Project, Schedule, ScheduleChangeLog
from z4j_brain.persistence.repositories import schedule_control as control_module
from z4j_brain.persistence.repositories import schedule_runtime_rollback as rollback_module
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
)

OLD_FINGERPRINT = "7d4e2328ee3298801d5fa2151ebf771b0b5ed186dded7ba7b7211bceabb043a1"
TARGET_IMAGE = "docker.io/z4jdev/z4j@sha256:" + ("a" * 64)
TARGET_DURABLE_AUTHORITY = {
    "artifact": {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": "sha256:" + ("2" * 64),
        "size": 501,
        "artifactType": "application/vnd.z4j.rollback-compat.qualification-evidence.v1",
    },
    "config": {
        "mediaType": "application/vnd.z4j.rollback-compat.durable-evidence-config.v1+json",
        "digest": "sha256:" + ("3" * 64),
        "size": 502,
    },
    "receipt": {
        "mediaType": "application/vnd.z4j.rollback-compat.qualification-receipt.v1+json",
        "digest": "sha256:" + ("4" * 64),
        "size": 503,
        "annotations": {"org.opencontainers.image.title": "qualification-receipt.json"},
    },
    "bundle": {
        "mediaType": "application/vnd.z4j.rollback-compat.sigstore-bundle.v1+json",
        "digest": "sha256:" + ("5" * 64),
        "size": 504,
        "annotations": {"org.opencontainers.image.title": "qualification.sigstore.json"},
    },
    "authentication": {
        "mediaType": "application/vnd.z4j.rollback-compat.receipt-authentication.v1+json",
        "digest": "sha256:" + ("6" * 64),
        "size": 505,
        "annotations": {"org.opencontainers.image.title": "qualification-authentication.json"},
    },
    "payload": [
        {
            "mediaType": "application/vnd.z4j.rollback-compat.evidence-payload.v1",
            "digest": "sha256:" + ("7" * 64),
            "size": 506,
            "annotations": {"org.opencontainers.image.title": "evidence/runtime.json"},
        },
    ],
}
TARGET_AUTHORITY = {
    "manifest_sha256": "b" * 64,
    "index": {"digest": "sha256:" + ("a" * 64), "size": 1000},
    "platforms": {
        "amd64": {
            "manifest": {"digest": "sha256:" + ("c" * 64), "size": 2000},
            "config": {"digest": "sha256:" + ("d" * 64), "size": 3000},
        },
        "arm64": {
            "manifest": {"digest": "sha256:" + ("e" * 64), "size": 2001},
            "config": {"digest": "sha256:" + ("f" * 64), "size": 3001},
        },
    },
    "release_receipt_sha256": "1" * 64,
    "qualification_durable_evidence": TARGET_DURABLE_AUTHORITY,
    "publication_gate_sha256": "04679f8790585cdc2bf99c267bbc84498a874cda6a0f0dbf961ccdbb500feb9c",
}


@pytest.fixture
async def database(migrated_db_url: str) -> AsyncIterator[DatabaseManager]:
    manager = DatabaseManager(create_async_engine(migrated_db_url))
    yield manager
    await manager.dispose()


def definition(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "name": "rollback",
        "task_name": "jobs.rollback",
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
    result.update(overrides)
    return result


async def create_old(
    database: DatabaseManager,
    monkeypatch: pytest.MonkeyPatch,
    slug: str,
    *,
    fingerprint: str = OLD_FINGERPRINT,
    definition_overrides: dict[str, object] | None = None,
) -> tuple[uuid.UUID, uuid.UUID]:
    monkeypatch.setattr(
        control_module,
        "cadence_runtime_fingerprint",
        lambda: fingerprint,
    )
    async with database.session(write=True) as session:
        project = Project(id=uuid.uuid4(), slug=slug, name=slug)
        session.add(project)
        await session.flush()
        row = await ScheduleControlRepository(session).create_current(
            project_id=project.id,
            data=definition(**(definition_overrides or {})),
            planning_at=datetime(2026, 1, 1, 12, 3, 7, tzinfo=UTC),
        )
        await session.commit()
        return project.id, row.id


def test_sealed_payload_and_challenge_authorities() -> None:
    canonical = json.dumps(
        SEALED_TARGET_CADENCE_PAYLOAD,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    assert hashlib.sha256(canonical).hexdigest() == SEALED_TARGET_CADENCE_FINGERPRINT
    assert validate_target_image(TARGET_IMAGE) == "sha256:" + ("a" * 64)
    with pytest.raises(RuntimeRollbackRefused, match="mutable"):
        validate_target_image("docker.io/z4jdev/z4j:1.8.2")
    challenge = preview_challenge({"row_set_digest": "c" * 64})
    assert "ALL-BRAIN-AND-SCHEDULER-EXECUTORS-ARE-STOPPED" in challenge
    assert (
        challenge_sha256(challenge)
        == hashlib.sha256(
            challenge.encode("ascii"),
        ).hexdigest()
    )


def finalized_manifest() -> dict[str, object]:
    source = json.loads(
        (
            Path(__file__).resolve().parents[3] / "docker/rollback-1.8.2-py3147/manifest.json"
        ).read_text(encoding="utf-8"),
    )
    candidate = source["candidate_image"]
    candidate["finalized"] = True
    candidate["index"] = copy.deepcopy(TARGET_AUTHORITY["index"])
    candidate["platforms"] = copy.deepcopy(TARGET_AUTHORITY["platforms"])
    candidate["release_receipt_sha256"] = TARGET_AUTHORITY["release_receipt_sha256"]
    candidate["qualification_durable_evidence"] = copy.deepcopy(
        TARGET_DURABLE_AUTHORITY,
    )
    return source


def test_manifest_finalization_is_exact_and_digest_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = finalized_manifest()
    authority = validate_finalized_rollback_manifest(
        manifest,
        manifest_sha256=TARGET_AUTHORITY["manifest_sha256"],
    )
    assert authority == {
        **TARGET_AUTHORITY,
        "cadence_payload": SEALED_TARGET_CADENCE_PAYLOAD,
        "cadence_runtime_fingerprint": SEALED_TARGET_CADENCE_FINGERPRINT,
    }
    monkeypatch.setattr(
        "z4j_brain.domain.runtime_rollback.load_finalized_rollback_manifest",
        lambda: authority,
    )
    assert require_finalized_target_image(TARGET_IMAGE) == authority
    with pytest.raises(RuntimeRollbackRefused, match="differs"):
        require_finalized_target_image(
            "docker.io/z4jdev/z4j@sha256:" + ("2" * 64),
        )


@pytest.mark.parametrize(
    ("path", "replacement"),
    (
        (("candidate_image", "finalized"), False),
        (("candidate_image", "index", "digest"), None),
        (("candidate_image", "platforms", "arm64", "config", "size"), 0),
        (("candidate_image", "release_receipt_sha256"), None),
        (("candidate_image", "qualification_receipt_format"), "wrong-format"),
        (("candidate_image", "release_receipt_semantics"), "self-referential"),
        (("candidate_image", "finalization_receipt_format"), "wrong-format"),
        (("candidate_image", "promotion_evidence_format"), "wrong-format"),
        (("candidate_image", "recovery_evidence_format"), "wrong-format"),
        (("candidate_image", "release_evidence_index_format"), "wrong-format"),
        (("candidate_image", "qualification_durable_evidence", "payload"), []),
        (("publication_gate", "cosign_version"), "3.1.2"),
        (("publication_gate", "receipt_authentication", "identity"), "untrusted"),
        (("publication_gate", "trivy", "ignore_unfixed"), True),
        (("cadence", "expected_runtime_fingerprint"), "2" * 64),
        (("source_release", "commit_sha1"), "3" * 40),
    ),
)
def test_manifest_finalization_mutations_refuse(
    path: tuple[str, ...],
    replacement: object,
) -> None:
    manifest = finalized_manifest()
    cursor = manifest
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = replacement
    with pytest.raises(RuntimeRollbackRefused):
        validate_finalized_rollback_manifest(
            manifest,
            manifest_sha256=TARGET_AUTHORITY["manifest_sha256"],
        )


@pytest.mark.parametrize("section", ("candidate_image", "publication_gate"))
def test_manifest_finalization_rejects_unsealed_fields(section: str) -> None:
    manifest = finalized_manifest()
    manifest[section]["unsealed"] = True

    with pytest.raises(RuntimeRollbackRefused, match=r"keys differ|publication gate"):
        validate_finalized_rollback_manifest(
            manifest,
            manifest_sha256=TARGET_AUTHORITY["manifest_sha256"],
        )


async def test_prepare_uses_guarded_revision_and_preserves_identity(
    database: DatabaseManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_id, schedule_id = await create_old(
        database,
        monkeypatch,
        "rollback-apply",
    )
    monkeypatch.setattr(
        rollback_module,
        "require_finalized_target_image",
        lambda _value: TARGET_AUTHORITY,
    )
    async with database.session() as session:
        before = await session.get(Schedule, schedule_id)
        assert before is not None
        preserved = (
            before.control_token,
            before.definition_digest,
            before.last_run_at,
            before.next_run_at,
            before.total_runs,
        )
        revision = int(before.schedule_revision or 0)

    async with database.session(write=True) as session:
        repository = ScheduleControlRepository(session)
        preview = await repository.plan_runtime_rollback(lock_rows=True)
        assert preview.changed_count == 1
        assert preview.rows[0].cursor_policy == "validated_from_change_log"
        result = await repository.prepare_runtime_rollback(
            target_release="1.8.2",
            target_image=TARGET_IMAGE,
            operation_id=uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            expected_row_set_digest=preview.row_set_digest,
            quiescence_challenge_sha256="b" * 64,
            target_durable_evidence_sha256="c" * 64,
            target_release_evidence_index={
                "sha256": "d" * 64,
                "size": 700,
                "completion": {"mode": "normal-promotion"},
            },
            target_evidence_terminal_stage="promotion",
            occurred_at=datetime(2026, 8, 20, 12, tzinfo=UTC),
        )
        assert result.revisions == ((schedule_id, revision + 1),)
        assert result.schedule_revision_watermark == revision + 1
        assert result.change_log_pruned_through == 0
        await session.commit()

    async with database.session() as session:
        after = await session.get(Schedule, schedule_id)
        assert after is not None
        assert after.project_id == project_id
        assert (
            after.control_token,
            after.definition_digest,
            after.last_run_at,
            after.next_run_at,
            after.total_runs,
        ) == preserved
        assert after.schedule_revision == revision + 1
        assert after.cadence_runtime_fingerprint == SEALED_TARGET_CADENCE_FINGERPRINT
        latest = (
            await session.execute(
                select(ScheduleChangeLog).where(
                    ScheduleChangeLog.revision == after.schedule_revision,
                ),
            )
        ).scalar_one()
        assert latest.snapshot is not None
        transition = latest.snapshot["transition"]
        assert transition["kind"] == "prepare_runtime_rollback"
        assert transition["definition_digest"] == after.definition_digest
        assert transition["target_durable_evidence_sha256"] == "c" * 64
        assert transition["target_release_evidence_index"]["sha256"] == "d" * 64
        assert transition["target_evidence_terminal_stage"] == "promotion"
        assert (
            durable_evidence_sha256({"result": "pass"})
            == hashlib.sha256(
                b'{"result":"pass"}\n',
            ).hexdigest()
        )

    async with database.session(write=True) as session:
        repository = ScheduleControlRepository(session)
        noop = await repository.plan_runtime_rollback(lock_rows=True)
        assert noop.changed_count == 0
        assert noop.noop_count == 1
        assert noop.rows[0].cursor_policy == "already_target"
        assert noop.rows[0].schedule_revision == revision + 1
        await session.rollback()


async def test_disabled_exhausted_and_target_noop_policy_matrix(
    database: DatabaseManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disabled_project, disabled_id = await create_old(
        database,
        monkeypatch,
        "rollback-disabled",
    )
    async with database.session(write=True) as session:
        disabled = await ScheduleControlRepository(session).update_current(
            project_id=disabled_project,
            schedule_id=disabled_id,
            data={"is_enabled": False},
            planning_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
        )
        assert disabled is not None
        await session.commit()

    _, exhausted_id = await create_old(
        database,
        monkeypatch,
        "rollback-exhausted",
        definition_overrides={
            "kind": "clocked",
            "expression": "2025-12-31T23:59:00+00:00",
        },
    )
    async with database.session(write=True) as session:
        repository = ScheduleControlRepository(session)
        exhausted = await session.get(Schedule, exhausted_id)
        assert exhausted is not None
        revision = await repository._allocate_revision()
        occurred_at = datetime(2026, 1, 1, 12, 5, tzinfo=UTC)
        overrides = {
            "last_run_at": datetime(2025, 12, 31, 23, 59, tzinfo=UTC),
            "next_run_at": None,
            "total_runs": 1,
            "schedule_revision": revision,
            "updated_at": occurred_at,
        }
        await repository._append_upsert(
            exhausted,
            revision=revision,
            overrides=overrides,
            occurred_at=occurred_at,
            transition={"kind": "test_completed_clocked_fire"},
        )
        for name, value in overrides.items():
            setattr(exhausted, name, value)
        await session.flush()
        await session.commit()

    _, target_id = await create_old(
        database,
        monkeypatch,
        "rollback-target-noop",
        fingerprint=SEALED_TARGET_CADENCE_FINGERPRINT,
    )

    async with database.session(write=True) as session:
        plan = await ScheduleControlRepository(session).plan_runtime_rollback(
            lock_rows=True,
        )
        rows = {row.schedule_id: row for row in plan.rows}
        assert rows[disabled_id].cursor_policy == "disabled_preserved"
        assert rows[disabled_id].changed is True
        assert rows[exhausted_id].cursor_policy == "exhausted_validated"
        assert rows[exhausted_id].new_next_run_at is None
        assert rows[target_id].cursor_policy == "already_target"
        assert rows[target_id].changed is False
        assert plan.changed_count == 2
        assert plan.noop_count == 1
        await session.rollback()


@pytest.mark.parametrize("blocker", ("paused", "quarantined"))
async def test_paused_or_quarantined_row_refuses_complete_plan(
    database: DatabaseManager,
    monkeypatch: pytest.MonkeyPatch,
    blocker: str,
) -> None:
    project_id, schedule_id = await create_old(
        database,
        monkeypatch,
        f"rollback-{blocker}",
    )
    async with database.session(write=True) as session:
        repository = ScheduleControlRepository(session)
        row = await session.get(Schedule, schedule_id)
        assert row is not None
        if blocker == "paused":
            transition = await repository.set_paused(
                project_id=project_id,
                schedule_id=schedule_id,
                paused=True,
                occurred_at=datetime(2026, 1, 1, 12, 5, tzinfo=UTC),
            )
        else:
            assert row.control_token is not None
            transition = await repository.quarantine(
                project_id=project_id,
                schedule_id=schedule_id,
                observed_control_token=row.control_token,
                reason_code="rollback-test",
                detail="unresolved definition",
                occurred_at=datetime(2026, 1, 1, 12, 5, tzinfo=UTC),
            )
        assert transition.outcome == "applied"
        await session.commit()

    match = "paused" if blocker == "paused" else "quarantine"
    async with database.session(write=True) as session:
        with pytest.raises(RuntimeRollbackRefused, match=match):
            await ScheduleControlRepository(session).plan_runtime_rollback(
                lock_rows=True,
            )


async def test_changed_cursor_with_inflight_evidence_refuses(
    database: DatabaseManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, schedule_id = await create_old(
        database,
        monkeypatch,
        "rollback-inflight",
    )
    async with database.session() as session:
        row = await session.get(Schedule, schedule_id)
        assert row is not None
        assert row.next_run_at is not None
        changed_next = row.next_run_at + timedelta(seconds=1)

    monkeypatch.setattr(
        rollback_module,
        "canonical_next_run_at",
        lambda **_kwargs: changed_next,
    )

    async def inflight_evidence(
        _repository: ScheduleControlRepository,
        *,
        schedule_ids: list[uuid.UUID],
        lock_rows: bool,
    ) -> tuple[set[uuid.UUID], dict[str, object]]:
        assert schedule_ids == [schedule_id]
        assert lock_rows is True
        return {schedule_id}, {
            "pending_fires": [{"schedule_id": str(schedule_id)}],
            "schedule_fires": [],
            "commands": [],
            "terminal_holds": [],
        }

    monkeypatch.setattr(rollback_module, "_load_evidence", inflight_evidence)
    async with database.session(write=True) as session:
        with pytest.raises(RuntimeRollbackRefused, match="unresolved fire evidence"):
            await ScheduleControlRepository(session).plan_runtime_rollback(
                lock_rows=True,
            )


async def test_enabled_repeating_null_cursor_refuses(
    database: DatabaseManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, schedule_id = await create_old(
        database,
        monkeypatch,
        "rollback-repeating-null",
    )
    async with database.session(write=True) as session:
        repository = ScheduleControlRepository(session)
        row = await session.get(Schedule, schedule_id)
        assert row is not None
        assert row.is_enabled is True
        assert row.last_run_at is None
        assert row.next_run_at is not None
        revision = await repository._allocate_revision()
        occurred_at = datetime(2026, 1, 1, 12, 6, tzinfo=UTC)
        overrides = {
            "next_run_at": None,
            "schedule_revision": revision,
            "updated_at": occurred_at,
        }
        await repository._append_upsert(
            row,
            revision=revision,
            overrides=overrides,
            occurred_at=occurred_at,
            transition={"kind": "test_repeating_null_cursor"},
        )
        for name, value in overrides.items():
            setattr(row, name, value)
        await session.flush()
        await session.commit()

    async with database.session(write=True) as session:
        with pytest.raises(RuntimeRollbackRefused, match="null cursor"):
            await ScheduleControlRepository(session).plan_runtime_rollback(
                lock_rows=True,
            )


async def test_pruned_never_fired_anchor_refuses_before_write(
    database: DatabaseManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_id, schedule_id = await create_old(
        database,
        monkeypatch,
        "rollback-pruned",
    )
    async with database.session(write=True) as session:
        repository = ScheduleControlRepository(session)
        updated = await repository.update_current(
            project_id=project_id,
            schedule_id=schedule_id,
            data={"name": "non-cadence-change"},
            planning_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
        )
        assert updated is not None
        assert updated.schedule_revision == 2
        assert await repository.prune_change_log(through_revision=1) == 1
        await session.commit()

    async with database.session(write=True) as session:
        with pytest.raises(RuntimeRollbackRefused, match="planning anchor"):
            await ScheduleControlRepository(session).plan_runtime_rollback(
                lock_rows=True,
            )
        row = await session.get(Schedule, schedule_id)
        assert row is not None
        assert row.schedule_revision == 2
        assert row.cadence_runtime_fingerprint == OLD_FINGERPRINT


async def test_repository_emits_exact_create_and_cadence_planner_anchors(
    database: DatabaseManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_id, schedule_id = await create_old(
        database,
        monkeypatch,
        "rollback-anchor-markers",
    )
    async with database.session(write=True) as session:
        row = await ScheduleControlRepository(session).update_current(
            project_id=project_id,
            schedule_id=schedule_id,
            data={"expression": "10m", "name": "cadence-and-management"},
            planning_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
        )
        assert row is not None
        await session.commit()

    async with database.session() as session:
        history = list(
            (
                await session.execute(
                    select(ScheduleChangeLog)
                    .where(ScheduleChangeLog.schedule_id == schedule_id)
                    .order_by(ScheduleChangeLog.revision),
                )
            ).scalars(),
        )
        assert len(history) == 2
        create = history[0].snapshot["transition"]
        assert create["kind"] == "planner_anchor"
        assert create["planner_anchor"] is True
        assert create["anchor_reason"] == "create"
        assert create["schedule_id"] == str(schedule_id)
        assert create["revision"] == history[0].revision
        assert create["changed_fields"] == sorted(history[0].snapshot["schedule"])
        update = history[1].snapshot["transition"]
        assert update["kind"] == "planner_anchor"
        assert update["anchor_reason"] == "cadence_change"
        assert update["schedule_id"] == str(schedule_id)
        assert update["revision"] == history[1].revision
        assert {"expression", "name", "schedule_revision", "updated_at"}.issubset(
            update["changed_fields"],
        )
        assert update["cadence_definition"]["expression"] == "10m"


async def test_unrelated_global_pruning_keeps_explicit_create_anchor(
    database: DatabaseManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dummy_project, dummy_id = await create_old(
        database,
        monkeypatch,
        "rollback-pruned-unrelated-dummy",
    )
    async with database.session(write=True) as session:
        deleted = await ScheduleControlRepository(session).delete_current(
            project_id=dummy_project,
            schedule_id=dummy_id,
            occurred_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
        )
        assert deleted.disposition == "deleted"
        assert deleted.committed_revision == 2
        await session.commit()

    _, target_id = await create_old(
        database,
        monkeypatch,
        "rollback-pruned-unrelated-target",
    )
    async with database.session(write=True) as session:
        repository = ScheduleControlRepository(session)
        assert await repository.prune_change_log(through_revision=2) == 2
        await session.commit()

    async with database.session(write=True) as session:
        plan = await ScheduleControlRepository(session).plan_runtime_rollback(
            lock_rows=True,
        )
        assert [row.schedule_id for row in plan.rows] == [target_id]
        assert plan.pruned_through == 2
        assert plan.rows[0].anchor_kind == "change_log_occurred_at"
        await session.rollback()


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("wrong-revision", "forged planner anchor"),
        ("missing-cadence-definition", "malformed planner anchor"),
        ("missing-snapshot-field", "incomplete cadence history snapshot"),
    ),
)
async def test_forged_or_incomplete_planner_anchor_refuses(
    database: DatabaseManager,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    message: str,
) -> None:
    _, schedule_id = await create_old(
        database,
        monkeypatch,
        f"rollback-anchor-{mutation}",
    )
    async with database.session() as session:
        row = await session.get(Schedule, schedule_id)
        assert row is not None
        change = (
            await session.execute(
                select(ScheduleChangeLog).where(
                    ScheduleChangeLog.schedule_id == schedule_id,
                ),
            )
        ).scalar_one()
        change.snapshot = copy.deepcopy(change.snapshot)
        if mutation == "wrong-revision":
            change.snapshot["transition"]["revision"] += 1
        elif mutation == "missing-cadence-definition":
            del change.snapshot["transition"]["cadence_definition"]
        else:
            del change.snapshot["schedule"]["expression"]
        with pytest.raises(RuntimeRollbackRefused, match=message):
            rollback_module._recover_planning_anchor(
                row=row,
                history=[change],
                pruned_through=0,
            )
        await session.rollback()


async def test_owner_cutover_anchor_requires_exact_repository_envelope(
    database: DatabaseManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_id, schedule_id = await create_old(
        database,
        monkeypatch,
        "rollback-owner-cutover-envelope",
    )
    async with database.session(write=True) as session:
        updated = await ScheduleControlRepository(session).update_current(
            project_id=project_id,
            schedule_id=schedule_id,
            data={"name": "owner-cutover"},
            planning_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
        )
        assert updated is not None
        await session.commit()

    async with database.session() as session:
        row = await session.get(Schedule, schedule_id)
        assert row is not None
        history = list(
            (
                await session.execute(
                    select(ScheduleChangeLog)
                    .where(ScheduleChangeLog.schedule_id == schedule_id)
                    .order_by(ScheduleChangeLog.revision),
                )
            ).scalars(),
        )
        assert len(history) == 2
        history = copy.deepcopy(history)
        history[0].snapshot["schedule"]["scheduler"] = "external-owner"
        valid = {
            "kind": "owner_cutover",
            "operation_id": "12345678-1234-5678-9234-567812345678",
            "from_owner": "external-owner",
            "to_owner": "z4j-scheduler",
            "cursor_policy": "PRESERVE",
        }
        history[1].snapshot["transition"] = valid
        recovered = rollback_module._recover_planning_anchor(
            row=row,
            history=history,
            pruned_through=0,
        )
        assert recovered == history[1].occurred_at.replace(tzinfo=UTC)

        mutations: tuple[dict[str, object], ...] = (
            {key: value for key, value in valid.items() if key != "operation_id"},
            {**valid, "unexpected": True},
            {**valid, "operation_id": "not-a-uuid"},
            {**valid, "from_owner": "wrong-owner"},
            {**valid, "to_owner": "other-scheduler"},
            {**valid, "cursor_policy": "GUESS"},
        )
        for transition in mutations:
            candidate = copy.deepcopy(history)
            candidate[1].snapshot["transition"] = transition
            with pytest.raises(
                RuntimeRollbackRefused,
                match="malformed owner-cutover anchor",
            ):
                rollback_module._recover_planning_anchor(
                    row=row,
                    history=candidate,
                    pruned_through=0,
                )
        await session.rollback()


async def test_nonadjacent_update_anchor_refuses(
    database: DatabaseManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_id, schedule_id = await create_old(
        database,
        monkeypatch,
        "rollback-anchor-nonadjacent",
    )
    async with database.session(write=True) as session:
        row = await ScheduleControlRepository(session).update_current(
            project_id=project_id,
            schedule_id=schedule_id,
            data={"expression": "15m"},
            planning_at=datetime(2026, 1, 1, 12, 4, tzinfo=UTC),
        )
        assert row is not None
        await session.commit()

    async with database.session() as session:
        row = await session.get(Schedule, schedule_id)
        assert row is not None
        latest = (
            await session.execute(
                select(ScheduleChangeLog).where(
                    ScheduleChangeLog.schedule_id == schedule_id,
                    ScheduleChangeLog.revision == row.schedule_revision,
                ),
            )
        ).scalar_one()
        with pytest.raises(RuntimeRollbackRefused, match="adjacent prior snapshot"):
            rollback_module._recover_planning_anchor(
                row=row,
                history=[latest],
                pruned_through=1,
            )
