"""Background audit exports and the scheduled chain-head export.

The synchronous export refuses above 50 000 rows (25 000 for xlsx), so an
install past about 550 audit rows a day cannot download its full retained
trail. These tests drive the whole replacement path as an operator would:
queue a job over HTTP, let the worker run, read the object out of the
sink. The sizes are real (60 000 rows), the bytes are compared against the
synchronous export for the same filter, and the head export is checked by
the one command that consumes it, ``audit verify --known-head``, run
in-process.
"""

# ruff: noqa: ASYNC240  tests read the files the sink wrote; blocking reads are the point
from __future__ import annotations

import asyncio
import json
import secrets
import sys
import uuid
import zipfile
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest
import z4j_brain.domain.workers.export_jobs as export_jobs_module
from httpx import ASGITransport, AsyncClient
from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.auth.scopes import required_scope
from z4j_brain.auth.sessions import SessionCookieCodec, cookie_name
from z4j_brain.domain.export_sinks import (
    LOCAL_FILE_MODE,
    ExportSinkError,
    LocalDirectorySink,
    S3Sink,
    SinkWriteResult,
    validate_key,
)
from z4j_brain.domain.workers.export_jobs import (
    AUDIT_ACTION_EXPORT_DONE,
    AUDIT_ACTION_EXPORT_FAILED,
    ExportJobsWorker,
    _safe_reason,
)
from z4j_brain.main import create_app
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import (
    ApiKey,
    AuditLog,
    Membership,
    Project,
    Session,
    User,
)
from z4j_brain.persistence.models.export_job import ExportJob
from z4j_brain.settings import ConfigError, Settings

_PASSWORD = "correct horse battery staple 9"
_BIG = 60_000


# ---------------------------------------------------------------------------
# Fixtures: a file-backed SQLite brain with a local sink
# ---------------------------------------------------------------------------


@pytest.fixture
def sink_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "exports"
    directory.mkdir()
    return directory


def _settings(tmp_path: Path, sink_dir: Path, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "database_url": f"sqlite+aiosqlite:///{(tmp_path / 'brain.db').as_posix()}",
        "secret": secrets.token_urlsafe(48),
        "session_secret": secrets.token_urlsafe(48),
        "environment": "dev",
        "log_json": False,
        "argon2_time_cost": 1,
        "argon2_memory_cost": 8192,
        "login_min_duration_ms": 10,
        "registry_backend": "local",
        "metrics_public": True,
        "disable_spa_fallback": True,
        "export_sink": "local",
        "export_sink_path": str(sink_dir),
        # Small pages so a 60k export takes many pages and progress moves.
        "export_jobs_page_size": 5_000,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def settings(tmp_path: Path, sink_dir: Path) -> Settings:
    return _settings(tmp_path, sink_dir)


@pytest.fixture
async def brain_app(settings: Settings):
    engine = create_async_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    app.state.lifespan_ready = True
    yield app
    await engine.dispose()


@pytest.fixture
async def seeded(settings: Settings, brain_app) -> dict[str, Any]:
    """A project, an admin member, an operator member and an outsider."""
    db = brain_app.state.db
    hasher = PasswordHasher(settings)
    project_id = uuid.uuid4()
    people = {}
    async with db.session() as s:
        s.add(Project(id=project_id, slug="default", name="Default"))
        await s.flush()
        for name, role in (
            ("admin", ProjectRole.ADMIN),
            ("auditor", ProjectRole.AUDITOR),
            ("operator", ProjectRole.OPERATOR),
            ("outsider", None),
        ):
            user_id = uuid.uuid4()
            session_id = uuid.uuid4()
            csrf = secrets.token_urlsafe(32)
            s.add(
                User(
                    id=user_id,
                    email=f"{name}@example.com",
                    password_hash=hasher.hash(_PASSWORD),
                    is_admin=False,
                    is_active=True,
                ),
            )
            await s.flush()
            if role is not None:
                s.add(Membership(user_id=user_id, project_id=project_id, role=role))
            s.add(
                Session(
                    id=session_id,
                    user_id=user_id,
                    csrf_token=csrf,
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                    ip_at_issue="127.0.0.1",
                    user_agent_at_issue="test",
                ),
            )
            people[name] = {"user_id": user_id, "session_id": session_id, "csrf": csrf}
        await s.commit()
    return {"project_id": project_id, **people}


def _client_for(brain_app, settings: Settings, person: dict[str, Any]) -> AsyncClient:
    from z4j_brain.auth.csrf import csrf_cookie_name

    client = AsyncClient(
        transport=ASGITransport(app=brain_app),
        base_url="http://testserver",
        headers={"X-CSRF-Token": person["csrf"]},
    )
    codec = SessionCookieCodec(settings)
    client.cookies.set(
        cookie_name(environment=settings.environment), codec.encode(person["session_id"])
    )
    client.cookies.set(csrf_cookie_name(environment=settings.environment), person["csrf"])
    return client


@pytest.fixture
async def client(brain_app, settings: Settings, seeded) -> AsyncIterator[AsyncClient]:
    async with _client_for(brain_app, settings, seeded["admin"]) as ac:
        yield ac


@pytest.fixture
def worker(brain_app) -> ExportJobsWorker:
    return ExportJobsWorker(
        db=brain_app.state.db,
        settings=brain_app.state.settings,
        audit=brain_app.state.audit_service,
        sink=brain_app.state.export_sink,
    )


async def _seed_audit_rows(
    db: DatabaseManager, project_id: uuid.UUID, user_id: uuid.UUID, n: int
) -> None:
    """``n`` rows, newest first by index, three per second so ties exist."""
    base = datetime(2026, 1, 1, tzinfo=UTC)
    batch: list[dict[str, Any]] = []
    async with db.session() as s:
        for i in range(n):
            batch.append(
                {
                    "id": uuid.uuid4(),
                    "project_id": project_id,
                    "user_id": user_id,
                    "action": f"test.action.{i % 7}",
                    "target_type": "task",
                    "target_id": f"t-{i}",
                    "result": "success",
                    "outcome": "allow" if i % 5 else "deny",
                    "audit_metadata": {"i": i, "note": "=not(a,formula)"},
                    "source_ip": "127.0.0.1",
                    # One cell in a thousand starts with a formula trigger.
                    "user_agent": "=hostile()" if i % 1000 == 0 else "pytest",
                    "occurred_at": base + timedelta(seconds=i // 3),
                },
            )
            if len(batch) >= 5_000:
                await s.execute(insert(AuditLog), batch)
                batch = []
        if batch:
            await s.execute(insert(AuditLog), batch)
        await s.commit()


async def _job(client: AsyncClient, job_id: str) -> dict[str, Any]:
    r = await client.get(f"/api/v1/projects/default/audit/export-jobs/{job_id}")
    assert r.status_code == 200, r.text
    return r.json()


async def _audit_actions(db: DatabaseManager, target_id: str) -> list[str]:
    async with db.session() as s:
        rows = (
            await s.execute(select(AuditLog.action).where(AuditLog.target_id == target_id))
        ).scalars()
        return sorted(rows)


# ---------------------------------------------------------------------------
# End to end against the local sink
# ---------------------------------------------------------------------------


async def test_csv_job_exports_sixty_thousand_rows_complete(
    brain_app, client, seeded, worker, sink_dir
) -> None:
    db = brain_app.state.db
    await _seed_audit_rows(db, seeded["project_id"], seeded["admin"]["user_id"], _BIG)

    # The synchronous path refuses this size; that refusal is the reason
    # the job path exists, so it is asserted rather than assumed.
    sync = await client.get("/api/v1/projects/default/audit?format=csv")
    assert sync.status_code == 422
    assert "export-jobs" in sync.text

    created = await client.post(
        "/api/v1/projects/default/audit/export-jobs",
        json={"format": "csv"},
    )
    assert created.status_code == 202, created.text
    job = created.json()
    assert job["status"] == "queued"
    assert job["sink"] == "local"
    assert created.headers["Location"].endswith(f"/audit/export-jobs/{job['id']}")

    listed = await client.get("/api/v1/projects/default/audit/export-jobs")
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()["items"]] == [job["id"]]
    assert listed.json()["sink"] == "local"
    assert listed.json()["sink_location"] == str(sink_dir)

    assert await worker.tick() is None

    done = await _job(client, job["id"])
    assert done["status"] == "done", done
    # Queueing the job wrote ``audit.export_job.created`` to this project's
    # trail, and the export is the trail, so it is one row longer than the
    # seed and that row is the newest.
    assert done["row_count"] == _BIG + 1
    assert done["downloadable"] is True
    assert done["error"] is None
    location = Path(done["location"])
    assert location.is_file()
    assert location.is_relative_to(sink_dir)
    assert done["size_bytes"] == location.stat().st_size > 0

    text = location.read_text(encoding="utf-8")
    lines = text.splitlines()
    assert len(lines) == _BIG + 2
    assert (
        lines[0]
        == "id,occurred_at,action,target_type,target_id,result,outcome,user_id,event_id,source_ip,user_agent,metadata"
    )
    # Newest first, like the synchronous export, and complete at the far
    # end. Three seeded rows share each timestamp and tie on id, so the
    # check is on the set at each end rather than one row.
    assert ",audit.export_job.created," in lines[1]
    assert {line.split(",")[4] for line in lines[2:5]} == {
        f"t-{_BIG - 3}",
        f"t-{_BIG - 2}",
        f"t-{_BIG - 1}",
    }
    assert {line.split(",")[4] for line in lines[-3:]} == {"t-0", "t-1", "t-2"}
    # Formula neutralisation reaches the job path too: the apostrophe is
    # on the cell, and the raw trigger never starts one.
    assert "'=hostile()" in text
    assert ",=hostile()," not in text
    assert await _audit_actions(db, job["id"]) == [
        AUDIT_ACTION_EXPORT_DONE,
        "audit.export_job.created",
    ]


async def test_json_job_exports_sixty_thousand_rows_complete(
    brain_app, client, seeded, worker
) -> None:
    db = brain_app.state.db
    await _seed_audit_rows(db, seeded["project_id"], seeded["admin"]["user_id"], _BIG)
    created = await client.post(
        "/api/v1/projects/default/audit/export-jobs",
        json={"format": "json", "fields": ["id", "target_id", "metadata"]},
    )
    assert created.status_code == 202, created.text
    await worker.tick()
    done = await _job(client, created.json()["id"])
    assert done["status"] == "done", done
    assert done["row_count"] == _BIG + 1

    items = json.loads(Path(done["location"]).read_text(encoding="utf-8"))
    assert len(items) == _BIG + 1
    assert list(items[0]) == ["id", "target_id", "metadata"]
    assert items[0]["target_id"] == created.json()["id"]
    assert {item["target_id"] for item in items[1:4]} == {
        f"t-{_BIG - 3}",
        f"t-{_BIG - 2}",
        f"t-{_BIG - 1}",
    }
    assert {item["target_id"] for item in items[-3:]} == {"t-0", "t-1", "t-2"}
    assert len({item["id"] for item in items}) == _BIG + 1


@pytest.mark.parametrize("export_format", ["csv", "json"])
async def test_job_bytes_equal_the_synchronous_export_for_the_same_filter(
    brain_app, client, seeded, worker, export_format: str
) -> None:
    """Same filter, same bytes: a job is the download without the cap."""
    db = brain_app.state.db
    await _seed_audit_rows(db, seeded["project_id"], seeded["admin"]["user_id"], 12_000)
    filters = {"action_prefix": "test.action.3", "outcome": "allow"}
    sync = await client.get(
        "/api/v1/projects/default/audit",
        params={"format": export_format, **filters},
    )
    assert sync.status_code == 200
    created = await client.post(
        "/api/v1/projects/default/audit/export-jobs",
        json={"format": export_format, **filters},
    )
    assert created.status_code == 202, created.text
    await worker.tick()
    done = await _job(client, created.json()["id"])
    assert done["status"] == "done", done
    assert done["filters"] == filters
    assert Path(done["location"]).read_bytes() == sync.content
    assert done["row_count"] > 1_000


async def test_xlsx_job_writes_a_workbook(brain_app, client, seeded, worker) -> None:
    db = brain_app.state.db
    await _seed_audit_rows(db, seeded["project_id"], seeded["admin"]["user_id"], 6_000)
    created = await client.post(
        "/api/v1/projects/default/audit/export-jobs",
        json={"format": "xlsx"},
    )
    assert created.status_code == 202, created.text
    await worker.tick()
    done = await _job(client, created.json()["id"])
    assert done["status"] == "done", done
    assert done["row_count"] == 6_001
    with zipfile.ZipFile(done["location"]) as workbook:
        assert "xl/worksheets/sheet1.xml" in workbook.namelist()


class _ProbeSink:
    """Wraps a sink and looks at the job row mid-stream."""

    kind = "local"
    downloadable = True

    def __init__(self, inner: LocalDirectorySink, db: DatabaseManager, job_id: uuid.UUID) -> None:
        self._inner = inner
        self._db = db
        self._job_id = job_id
        self.observed: list[tuple[str, int | None]] = []

    def describe(self) -> str:
        return self._inner.describe()

    def resolve_download(self, location: str) -> Path:
        return self._inner.resolve_download(location)

    async def write(
        self, key: str, chunks: AsyncIterator[bytes], *, content_type: str
    ) -> SinkWriteResult:
        async def probing() -> AsyncIterator[bytes]:
            async for chunk in chunks:
                async with self._db.session() as s:
                    row = (
                        await s.execute(select(ExportJob).where(ExportJob.id == self._job_id))
                    ).scalar_one()
                    self.observed.append((row.status, row.row_count))
                yield chunk

        return await self._inner.write(key, probing(), content_type=content_type)


async def test_progress_is_recorded_while_the_job_runs(brain_app, client, seeded) -> None:
    db = brain_app.state.db
    await _seed_audit_rows(db, seeded["project_id"], seeded["admin"]["user_id"], 20_000)
    created = await client.post(
        "/api/v1/projects/default/audit/export-jobs", json={"format": "csv"}
    )
    job_id = uuid.UUID(created.json()["id"])
    probe = _ProbeSink(brain_app.state.export_sink, db, job_id)
    worker = ExportJobsWorker(
        db=db,
        settings=brain_app.state.settings,
        audit=brain_app.state.audit_service,
        sink=probe,
    )
    await worker.tick()
    statuses = {status for status, _ in probe.observed}
    assert statuses == {"running"}
    counts = [count for _, count in probe.observed]
    # Header chunk sees 0, then each page's chunk sees the previous page's
    # count already written, so the sequence climbs and stops short of the end.
    assert counts[0] == 0
    assert counts == sorted(counts)
    assert 0 < counts[-1] < 20_001
    done = await _job(client, str(job_id))
    assert done["status"] == "done" and done["row_count"] == 20_001


class _FailingSink:
    kind = "local"
    downloadable = True

    def describe(self) -> str:
        return "/nowhere"

    async def write(
        self, key: str, chunks: AsyncIterator[bytes], *, content_type: str
    ) -> SinkWriteResult:
        async for _ in chunks:
            raise RuntimeError("bucket is read-only")
        raise AssertionError("unreachable")


async def test_a_sink_failure_marks_the_job_failed_with_the_reason(
    brain_app, client, seeded
) -> None:
    db = brain_app.state.db
    await _seed_audit_rows(db, seeded["project_id"], seeded["admin"]["user_id"], 50)
    created = await client.post(
        "/api/v1/projects/default/audit/export-jobs", json={"format": "csv"}
    )
    job_id = created.json()["id"]
    worker = ExportJobsWorker(
        db=db,
        settings=brain_app.state.settings,
        audit=brain_app.state.audit_service,
        sink=_FailingSink(),
    )
    assert await worker.tick() is None  # never raises
    failed = await _job(client, job_id)
    assert failed["status"] == "failed"
    assert failed["error"] == "RuntimeError: bucket is read-only"
    assert failed["downloadable"] is False
    assert failed["completed_at"] is not None
    assert await _audit_actions(db, job_id) == [
        "audit.export_job.created",
        AUDIT_ACTION_EXPORT_FAILED,
    ]


async def test_a_running_job_with_no_progress_is_failed_on_the_next_tick(
    brain_app, client, seeded, worker
) -> None:
    db = brain_app.state.db
    created = await client.post(
        "/api/v1/projects/default/audit/export-jobs", json={"format": "csv"}
    )
    job_id = uuid.UUID(created.json()["id"])
    async with db.session() as s:
        row = (await s.execute(select(ExportJob).where(ExportJob.id == job_id))).scalar_one()
        row.status = "running"
        row.started_at = datetime.now(UTC) - timedelta(hours=2)
        row.updated_at = datetime.now(UTC) - timedelta(hours=2)
        await s.commit()
    await worker.tick()
    stale = await _job(client, str(job_id))
    assert stale["status"] == "failed"
    assert "no progress" in stale["error"]


# ---------------------------------------------------------------------------
# Authorization: download, roles, API keys, no sink
# ---------------------------------------------------------------------------


async def test_download_streams_the_file_to_a_project_admin(
    brain_app, client, seeded, worker
) -> None:
    db = brain_app.state.db
    await _seed_audit_rows(db, seeded["project_id"], seeded["admin"]["user_id"], 300)
    created = await client.post(
        "/api/v1/projects/default/audit/export-jobs", json={"format": "csv"}
    )
    job_id = created.json()["id"]
    before = await client.get(f"/api/v1/projects/default/audit/export-jobs/{job_id}/download")
    assert before.status_code == 409
    await worker.tick()
    r = await client.get(f"/api/v1/projects/default/audit/export-jobs/{job_id}/download")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/csv")
    assert f"z4j-audit-default-{job_id}.csv" in r.headers["content-disposition"]
    assert r.content == Path((await _job(client, job_id))["location"]).read_bytes()
    assert r.headers["content-length"] == str(len(r.content))


async def _point_row_at(db: DatabaseManager, job_id: uuid.UUID, location: str) -> None:
    """What a writer of ``export_jobs.file_path`` (a role, an injection) can do."""
    async with db.session() as s:
        row = (await s.execute(select(ExportJob).where(ExportJob.id == job_id))).scalar_one()
        row.file_path = location
        await s.commit()


async def test_download_refuses_a_row_pointed_outside_the_sink(
    tmp_path: Path, brain_app, client, seeded, worker, sink_dir
) -> None:
    """The row is not trusted to name the file; the sink is.

    ``Path.relative_to`` is lexical and keeps ``..``, so a row whose location
    was ``<sink>/../brain.env`` used to be served as the brain user. The
    download now rebuilds the path from the configured base, refuses any
    part that is ``..``, resolves both ends, and follows no symlink.
    """
    db = brain_app.state.db
    await _seed_audit_rows(db, seeded["project_id"], seeded["admin"]["user_id"], 20)
    created = await client.post(
        "/api/v1/projects/default/audit/export-jobs", json={"format": "csv"}
    )
    job_id = uuid.UUID(created.json()["id"])
    await worker.tick()
    done = await _job(client, str(job_id))
    assert done["status"] == "done", done
    async with db.session() as s:
        stored = (
            await s.execute(select(ExportJob.file_path).where(ExportJob.id == job_id))
        ).scalar_one()
    # The row holds the key below the base; the API shows the rebuilt path.
    assert not Path(stored).is_absolute()
    assert stored.startswith("audit/default/")
    assert done["location"] == str(sink_dir / Path(stored))
    expected = (sink_dir / Path(stored)).read_bytes()
    url = f"/api/v1/projects/default/audit/export-jobs/{job_id}/download"

    # Positive control: a real job downloads.
    r = await client.get(url)
    assert r.status_code == 200
    assert r.content == expected

    secret_file = tmp_path / "brain.env"
    secret_file.write_text("Z4J_SECRET=hunter2-do-not-serve\n", encoding="utf-8")
    for location in (
        str(sink_dir / ".." / "brain.env"),
        str(sink_dir / "audit" / ".." / ".." / "brain.env"),
        str(secret_file),
        "../brain.env",
        "audit/default/../../../brain.env",
    ):
        await _point_row_at(db, job_id, location)
        r = await client.get(url)
        assert r.status_code == 404, (location, r.status_code, r.text)
        assert b"hunter2" not in r.content
        # Still reported as a job; only the download refuses.
        assert (await _job(client, str(job_id)))["status"] == "done"

    # A row written before the key was stored holds the absolute path inside
    # the base and is still served.
    await _point_row_at(db, job_id, str(sink_dir / Path(stored)))
    r = await client.get(url)
    assert r.status_code == 200
    assert r.content == expected

    if sys.platform != "win32":
        link = sink_dir / "audit" / "default" / "link.csv"
        link.symlink_to(secret_file)
        await _point_row_at(db, job_id, "audit/default/link.csv")
        r = await client.get(url)
        assert r.status_code == 404
        assert b"hunter2" not in r.content


class _RacingSink:
    """Writes for real, then loses the job to a stale sweep before the worker records it."""

    kind = "local"
    downloadable = True

    def __init__(self, inner: LocalDirectorySink, db: DatabaseManager, job_id: uuid.UUID) -> None:
        self._inner = inner
        self._db = db
        self._job_id = job_id
        self.written: list[str] = []
        self.discarded: list[str] = []

    def describe(self) -> str:
        return self._inner.describe()

    async def write(
        self, key: str, chunks: AsyncIterator[bytes], *, content_type: str
    ) -> SinkWriteResult:
        from z4j_brain.persistence.repositories.export_jobs import ExportJobRepository

        result = await self._inner.write(key, chunks, content_type=content_type)
        self.written.append(key)
        async with self._db.session(write=True) as s:
            assert await ExportJobRepository(s).mark_failed(self._job_id, reason="stale") is True
            await s.commit()
        return result

    async def discard(self, key: str) -> None:
        self.discarded.append(key)
        await self._inner.discard(key)


async def test_a_completion_that_lost_the_job_to_a_stale_sweep_discards_the_object(
    brain_app, client, seeded, sink_dir
) -> None:
    """``mark_done`` is compare-and-set; its answer is honoured.

    Another leader's stale sweep marked the job failed while this process
    was still writing. The failure stands: no ``audit.export_job.completed``
    row is appended on top of it, and the object just written is removed
    rather than left as an orphan no row refers to.
    """
    db = brain_app.state.db
    await _seed_audit_rows(db, seeded["project_id"], seeded["admin"]["user_id"], 50)
    created = await client.post(
        "/api/v1/projects/default/audit/export-jobs", json={"format": "csv"}
    )
    job_id = uuid.UUID(created.json()["id"])
    racing = _RacingSink(brain_app.state.export_sink, db, job_id)
    worker = ExportJobsWorker(
        db=db,
        settings=brain_app.state.settings,
        audit=brain_app.state.audit_service,
        sink=racing,
    )
    # The module logger is replaced outright rather than captured through
    # structlog's test helper, which misses events once the bound logger is
    # cached by an earlier test in the same process.
    recording_logger = Mock()
    with patch.object(export_jobs_module, "logger", recording_logger):
        assert await worker.tick() is None
    row = await _job(client, str(job_id))
    assert row["status"] == "failed"
    assert row["error"] == "stale"
    assert row["location"] is None
    assert row["downloadable"] is False
    assert await _audit_actions(db, str(job_id)) == ["audit.export_job.created"]
    assert racing.written == racing.discarded
    assert len(racing.written) == 1
    assert not (sink_dir / Path(racing.written[0])).exists()
    assert not list((sink_dir / "audit" / "default").iterdir())
    # The log says what happened to the object: there was one, and it went.
    (lost,) = recording_logger.error.call_args_list
    assert "the object written here is discarded" in lost.args[0]
    assert lost.kwargs["outcome"] == "done"


class _LosingFailingSink:
    """Loses the job to a stale sweep, then raises: nothing is ever stored."""

    kind = "local"
    downloadable = True

    def __init__(self, db: DatabaseManager, job_id: uuid.UUID) -> None:
        self._db = db
        self._job_id = job_id
        self.discarded: list[str] = []

    def describe(self) -> str:
        return "/nowhere"

    async def write(
        self, key: str, chunks: AsyncIterator[bytes], *, content_type: str
    ) -> SinkWriteResult:
        from z4j_brain.persistence.repositories.export_jobs import ExportJobRepository

        async with self._db.session(write=True) as s:
            assert await ExportJobRepository(s).mark_failed(self._job_id, reason="stale") is True
            await s.commit()
        raise RuntimeError("bucket is read-only")

    async def discard(self, key: str) -> None:
        self.discarded.append(key)


async def test_a_failure_that_lost_the_job_to_a_stale_sweep_says_nothing_was_retained(
    brain_app, client, seeded
) -> None:
    """The failed-and-lost path has no object: the log must not claim one was discarded.

    The write raised, so the sink retained nothing and there is no key; the
    sweep's failure stands, no row is appended, nothing is discarded, and
    the log line says so instead of describing an object that never existed.
    """
    db = brain_app.state.db
    await _seed_audit_rows(db, seeded["project_id"], seeded["admin"]["user_id"], 50)
    created = await client.post(
        "/api/v1/projects/default/audit/export-jobs", json={"format": "csv"}
    )
    job_id = uuid.UUID(created.json()["id"])
    losing = _LosingFailingSink(db, job_id)
    worker = ExportJobsWorker(
        db=db,
        settings=brain_app.state.settings,
        audit=brain_app.state.audit_service,
        sink=losing,
    )
    recording_logger = Mock()
    with patch.object(export_jobs_module, "logger", recording_logger):
        assert await worker.tick() is None
    row = await _job(client, str(job_id))
    assert row["status"] == "failed"
    assert row["error"] == "stale", "the sweep's terminal state stands"
    assert row["location"] is None
    assert await _audit_actions(db, str(job_id)) == ["audit.export_job.created"]
    assert losing.discarded == []
    (lost,) = recording_logger.error.call_args_list
    assert "nothing was retained here" in lost.args[0]
    assert "the write raised before any object was stored" in lost.args[0]
    assert "discarded" not in lost.args[0]
    assert lost.kwargs["outcome"] == "failed"
    assert lost.kwargs["location"] is None


async def test_an_auditor_queues_lists_reads_and_downloads_its_own_export(
    brain_app, settings, client, seeded, worker
) -> None:
    """The audit tier owns background exports, like the synchronous export."""
    await _seed_audit_rows(brain_app.state.db, seeded["project_id"], seeded["admin"]["user_id"], 10)
    async with _client_for(brain_app, settings, seeded["auditor"]) as auditor:
        created = await auditor.post(
            "/api/v1/projects/default/audit/export-jobs", json={"format": "json"}
        )
        assert created.status_code == 202, created.text
        job_id = created.json()["id"]
        await worker.tick()
        listed = await auditor.get("/api/v1/projects/default/audit/export-jobs")
        assert listed.status_code == 200
        assert job_id in {item["id"] for item in listed.json()["items"]}
        one = await auditor.get(f"/api/v1/projects/default/audit/export-jobs/{job_id}")
        assert one.status_code == 200 and one.json()["status"] == "done"
        download = await auditor.get(
            f"/api/v1/projects/default/audit/export-jobs/{job_id}/download"
        )
        assert download.status_code == 200, download.text


async def test_download_and_jobs_are_refused_below_the_audit_tier(
    brain_app, settings, client, seeded, worker
) -> None:
    await _seed_audit_rows(brain_app.state.db, seeded["project_id"], seeded["admin"]["user_id"], 10)
    created = await client.post(
        "/api/v1/projects/default/audit/export-jobs", json={"format": "csv"}
    )
    job_id = created.json()["id"]
    await worker.tick()
    assert (await _job(client, job_id))["status"] == "done"

    async with _client_for(brain_app, settings, seeded["operator"]) as operator:
        for path in (
            f"/api/v1/projects/default/audit/export-jobs/{job_id}/download",
            f"/api/v1/projects/default/audit/export-jobs/{job_id}",
            "/api/v1/projects/default/audit/export-jobs",
        ):
            r = await operator.get(path)
            assert r.status_code == 403, (path, r.text)
        r = await operator.post(
            "/api/v1/projects/default/audit/export-jobs", json={"format": "csv"}
        )
        assert r.status_code == 403

    # A non-member sees the same 404 as for an unknown project.
    async with _client_for(brain_app, settings, seeded["outsider"]) as outsider:
        r = await outsider.get(f"/api/v1/projects/default/audit/export-jobs/{job_id}/download")
        assert r.status_code == 404


async def _seed_api_key(
    brain_app, settings: Settings, project_id: uuid.UUID, scopes: list[str]
) -> str:
    from z4j_brain.api.api_keys import _hash_api_key

    plaintext = f"z4k_{secrets.token_urlsafe(32)}"
    async with brain_app.state.db.session() as s:
        user = User(
            id=uuid.uuid4(),
            email=f"key-{uuid.uuid4().hex[:8]}@example.com",
            password_hash=PasswordHasher(settings).hash(_PASSWORD),
            is_active=True,
        )
        s.add(user)
        await s.flush()
        s.add(Membership(user_id=user.id, project_id=project_id, role=ProjectRole.ADMIN))
        s.add(
            ApiKey(
                id=uuid.uuid4(),
                user_id=user.id,
                name="ci",
                token_hash=_hash_api_key(
                    plaintext=plaintext,
                    secret=settings.secret.get_secret_value().encode("utf-8"),
                ),
                prefix=plaintext[:8],
                scopes=scopes,
            ),
        )
        await s.commit()
    return plaintext


async def test_api_key_with_audit_read_can_queue_and_list_jobs(brain_app, settings, seeded) -> None:
    token = await _seed_api_key(brain_app, settings, seeded["project_id"], ["audit:read"])
    headers = {"Authorization": f"Bearer {token}"}
    async with AsyncClient(
        transport=ASGITransport(app=brain_app), base_url="http://testserver"
    ) as ac:
        r = await ac.post(
            "/api/v1/projects/default/audit/export-jobs",
            json={"format": "json"},
            headers=headers,
        )
        assert r.status_code == 202, r.text
        r = await ac.get("/api/v1/projects/default/audit/export-jobs", headers=headers)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 1
    async with brain_app.state.db.session() as s:
        row = (
            await s.execute(select(AuditLog).where(AuditLog.action == "audit.export_job.created"))
        ).scalar_one()
        assert row.api_key_id is not None


async def test_api_key_without_audit_scope_is_refused(brain_app, settings, seeded) -> None:
    token = await _seed_api_key(brain_app, settings, seeded["project_id"], ["tasks:read"])
    headers = {"Authorization": f"Bearer {token}"}
    async with AsyncClient(
        transport=ASGITransport(app=brain_app), base_url="http://testserver"
    ) as ac:
        r = await ac.post(
            "/api/v1/projects/default/audit/export-jobs",
            json={"format": "json"},
            headers=headers,
        )
        assert r.status_code == 403
        assert r.json()["details"]["required_scope"] == "audit:read"


def test_scope_for_the_tag_is_audit_read_on_every_method() -> None:
    assert required_scope(tags=["audit-exports"], method="POST") == "audit:read"
    assert required_scope(tags=["audit-exports"], method="GET") == "audit:read"
    assert required_scope(tags=["audit"], method="POST") == "audit:write"


async def test_unknown_field_names_are_rejected(client, seeded) -> None:
    r = await client.post(
        "/api/v1/projects/default/audit/export-jobs",
        json={"format": "csv", "fields": ["id", "password_hash"]},
    )
    assert r.status_code == 422
    assert r.json()["details"]["unknown"] == ["password_hash"]


async def test_queueing_without_a_sink_is_a_conflict(tmp_path: Path, sink_dir: Path) -> None:
    settings = _settings(tmp_path, sink_dir, export_sink="none", export_sink_path=None)
    engine = create_async_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    app.state.lifespan_ready = True
    try:
        assert app.state.export_sink is None
        assert "export_jobs_worker" not in [w.name for w in app.state.worker_supervisor._workers]
        hasher = PasswordHasher(settings)
        project_id, user_id, session_id, csrf = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), "c" * 32
        async with app.state.db.session() as s:
            s.add_all(
                [
                    Project(id=project_id, slug="default", name="Default"),
                    User(
                        id=user_id,
                        email="root@example.com",
                        password_hash=hasher.hash(_PASSWORD),
                        is_admin=True,
                        is_active=True,
                    ),
                ],
            )
            await s.flush()
            s.add(
                Session(
                    id=session_id,
                    user_id=user_id,
                    csrf_token=csrf,
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                    ip_at_issue="127.0.0.1",
                    user_agent_at_issue="test",
                ),
            )
            await s.commit()
        person = {"session_id": session_id, "csrf": csrf}
        async with _client_for(app, settings, person) as ac:
            r = await ac.post("/api/v1/projects/default/audit/export-jobs", json={"format": "csv"})
            assert r.status_code == 409
            assert "Z4J_EXPORT_SINK" in r.text
            listed = await ac.get("/api/v1/projects/default/audit/export-jobs")
            assert listed.json() == {"items": [], "sink": None, "sink_location": None}
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Scheduled head export: the envelope verify --known-head consumes
# ---------------------------------------------------------------------------


async def test_head_export_writes_an_envelope_that_verify_known_head_accepts(
    tmp_path: Path, sink_dir: Path, monkeypatch, capsys
) -> None:
    from z4j_brain.cli import main
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.domain.audit_verifier import verify_active_audit_generation

    from .test_audit_chain_boundary_f import AUDIT, MASTER, SESSION, _activate

    settings = _settings(
        tmp_path,
        sink_dir,
        secret=MASTER,
        session_secret=SESSION,
        audit_chain_secret=AUDIT,
        audit_head_export_interval_seconds=3600,
    )
    engine = create_async_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await _activate(engine, AuditService(settings))
    db = DatabaseManager(engine)
    worker = ExportJobsWorker(
        db=db,
        settings=settings,
        audit=AuditService(settings),
        sink=LocalDirectorySink(sink_dir),
    )
    try:
        assert worker.head_export_due() is True
        location = await worker.export_head_now()
        assert worker.head_export_due() is False
        assert location == str(sink_dir / "audit-head" / "current.json")

        current = sink_dir / "audit-head" / "current.json"
        dated = [p for p in (sink_dir / "audit-head").iterdir() if p.name != "current.json"]
        assert len(dated) == 1
        assert dated[0].read_bytes() == current.read_bytes()
        raw = current.read_text(encoding="utf-8")
        assert raw.endswith("\n")
        envelope = json.loads(raw)
        assert set(envelope) <= {
            "row_hmac",
            "hmac_version",
            "hmac_key_id",
            "generation",
            "occurred_at",
            "id",
        }
        assert envelope["hmac_version"] == 2

        # The consumer, in-process: the verifier the CLI calls.
        async with db.session() as session:
            report = await verify_active_audit_generation(
                session,
                settings,
                page_size=1000,
                known_head=envelope,
            )
        assert report.clean
        assert report.known_head_result == "CURRENT_MATCH"

        # A rolled-back head is no longer provable from the anchor.
        tampered = dict(envelope)
        tampered["row_hmac"] = ("b" if envelope["row_hmac"][0] != "b" else "c") + envelope[
            "row_hmac"
        ][1:]
        async with db.session() as session:
            report = await verify_active_audit_generation(
                session,
                settings,
                page_size=1000,
                known_head=tampered,
            )
        assert report.known_head_result == "UNPROVABLE"
    finally:
        await engine.dispose()

    # Byte for byte what ``z4j audit export-head`` prints for the same chain.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z4J_HOME", str(tmp_path))
    monkeypatch.setenv("Z4J_DATABASE_URL", settings.database_url)
    monkeypatch.setenv("Z4J_SECRET", MASTER)
    monkeypatch.setenv("Z4J_SESSION_SECRET", SESSION)
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", AUDIT)
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.setenv("Z4J_ALLOWED_HOSTS", '["localhost","127.0.0.1"]')
    # The CLI owns its own event loop (asyncio.run), so it runs off this one.
    assert await asyncio.to_thread(main, ["audit", "export-head"]) == 0
    assert capsys.readouterr().out.strip() == raw.strip()
    assert await asyncio.to_thread(main, ["audit", "verify", "--known-head", raw.strip()]) == 0
    assert "known-head: CURRENT_MATCH" in capsys.readouterr().out


async def test_head_export_is_skipped_without_a_chain_key(
    tmp_path: Path, sink_dir: Path, brain_app
) -> None:
    settings = _settings(tmp_path, sink_dir, audit_head_export_interval_seconds=3600)
    assert settings.audit_chain_secret is None
    worker = ExportJobsWorker(
        db=brain_app.state.db,
        settings=settings,
        audit=brain_app.state.audit_service,
        sink=brain_app.state.export_sink,
    )
    assert await worker.export_head_now() is None
    assert not (sink_dir / "audit-head").exists()


def test_head_export_is_off_at_zero(settings: Settings) -> None:
    assert settings.audit_head_export_interval_seconds == 0
    worker = ExportJobsWorker(db=None, settings=settings, audit=None, sink=None)  # type: ignore[arg-type]
    assert worker.head_export_due() is False


# ---------------------------------------------------------------------------
# Local sink
# ---------------------------------------------------------------------------


async def _one(payload: bytes) -> AsyncIterator[bytes]:
    yield payload


async def test_local_sink_writes_atomically_into_subdirectories(sink_dir: Path) -> None:
    sink = LocalDirectorySink(sink_dir)
    result = await sink.write("audit/default/x.csv", _one(b"a,b\r\n"), content_type="text/csv")
    assert result == SinkWriteResult(
        location=str(sink_dir / "audit" / "default" / "x.csv"),
        size_bytes=5,
        key="audit/default/x.csv",
    )
    assert (sink_dir / "audit" / "default" / "x.csv").read_bytes() == b"a,b\r\n"
    assert not [p for p in (sink_dir / "audit" / "default").iterdir() if p.name.endswith(".tmp")]
    # The key is what a job row stores; the absolute path is what rows written
    # before that held. Both name the same file below the base.
    assert sink.resolve_download(result.key) == sink_dir / "audit" / "default" / "x.csv"
    assert sink.resolve_download(result.location) == sink_dir / "audit" / "default" / "x.csv"
    assert sink.display_location(result.key) == result.location
    opened = sink.open_download(result.key)
    with opened.file as handle:
        assert handle.read() == b"a,b\r\n"
    assert opened.size_bytes == 5
    await sink.discard(result.key)
    assert not (sink_dir / "audit" / "default" / "x.csv").exists()
    await sink.discard(result.key)  # already gone: nothing to do, nothing raised


async def test_local_sink_rejects_unsafe_keys(sink_dir: Path) -> None:
    sink = LocalDirectorySink(sink_dir)
    for key in ("../x", "/abs", "a//b", ".hidden", "a\\b", ""):
        with pytest.raises(ExportSinkError):
            await sink.write(key, _one(b"x"), content_type="text/plain")
    assert validate_key("audit-head/current.json") == "audit-head/current.json"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes and symlinks")
async def test_local_sink_files_are_0640_and_symlinks_are_refused(
    tmp_path: Path, sink_dir: Path
) -> None:
    sink = LocalDirectorySink(sink_dir)
    result = await sink.write("a/f.json", _one(b"{}"), content_type="application/json")
    assert (Path(result.location).stat().st_mode & 0o777) == LOCAL_FILE_MODE

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (sink_dir / "linked").symlink_to(elsewhere)
    with pytest.raises(ExportSinkError):
        await sink.write("linked/f.json", _one(b"{}"), content_type="application/json")
    assert not (elsewhere / "f.json").exists()

    victim = tmp_path / "victim"
    victim.write_text("keep")
    (sink_dir / "a" / "target.json").symlink_to(victim)
    with pytest.raises(ExportSinkError):
        await sink.write("a/target.json", _one(b"{}"), content_type="application/json")
    assert victim.read_text() == "keep"
    with pytest.raises(ExportSinkError):
        sink.resolve_download(str(sink_dir / "a" / "target.json"))
    with pytest.raises(ExportSinkError):
        sink.open_download("a/target.json")
    # The open itself refuses a link (``O_NOFOLLOW``), not only the walk.
    with pytest.raises(ExportSinkError):
        sink.open_download(str(sink_dir / "a" / "target.json"))

    link_base = tmp_path / "base-link"
    link_base.symlink_to(sink_dir)
    with pytest.raises(ExportSinkError):
        LocalDirectorySink(link_base)


def test_local_sink_download_stays_inside_the_base(tmp_path: Path, sink_dir: Path) -> None:
    sink = LocalDirectorySink(sink_dir)
    outside = tmp_path / "outside.csv"
    outside.write_text("x")
    (sink_dir / "audit").mkdir()
    inside = sink_dir / "audit" / "real.csv"
    inside.write_text("y")
    # Positive control: the key and the legacy absolute form both resolve.
    assert sink.resolve_download("audit/real.csv") == inside
    assert sink.resolve_download(str(inside)) == inside
    # ``Path.relative_to`` is lexical and keeps ``..``; a row that names the
    # base and climbs out of it must not resolve, in either stored form.
    for location in (
        str(outside),
        str(sink_dir / ".." / "outside.csv"),
        str(sink_dir / "audit" / ".." / ".." / "outside.csv"),
        "../outside.csv",
        "audit/../../outside.csv",
        "audit/./real.csv",
        "audit//real.csv",
        "/outside.csv",
        "",
        ".",
        "..",
        "audit\\real.csv",
        "audit/missing.csv",
    ):
        with pytest.raises(ExportSinkError):
            sink.resolve_download(location)
        with pytest.raises(ExportSinkError):
            sink.open_download(location)
    assert outside.read_text() == "x"


# ---------------------------------------------------------------------------
# S3 sink against a fake client (no network)
# ---------------------------------------------------------------------------


class _FakeS3Client:
    """The aiobotocore method surface the sink uses, keyword arguments as boto spells them."""

    def __init__(self, store: dict[str, Any]) -> None:
        self._store = store
        self.calls: list[str] = []

    async def __aenter__(self) -> _FakeS3Client:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def put_object(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("put_object")
        self._store[f"{kw['Bucket']}/{kw['Key']}"] = {
            "body": bytes(kw["Body"]),
            "type": kw["ContentType"],
        }
        return {}

    async def create_multipart_upload(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("create_multipart_upload")
        self._store["_upload"] = {
            "bucket": kw["Bucket"],
            "key": kw["Key"],
            "type": kw["ContentType"],
            "parts": {},
        }
        return {"UploadId": "u-1"}

    async def upload_part(self, **kw: Any) -> dict[str, Any]:
        number = int(kw["PartNumber"])
        self.calls.append(f"upload_part:{number}")
        assert kw["UploadId"] == "u-1"
        self._store["_upload"]["parts"][number] = bytes(kw["Body"])
        return {"ETag": f'"etag-{number}"'}

    async def complete_multipart_upload(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("complete_multipart_upload")
        upload = self._store.pop("_upload")
        numbers = [part["PartNumber"] for part in kw["MultipartUpload"]["Parts"]]
        assert numbers == sorted(upload["parts"])
        self._store[f"{kw['Bucket']}/{kw['Key']}"] = {
            "body": b"".join(upload["parts"][n] for n in numbers),
            "type": upload["type"],
        }
        return {}

    async def abort_multipart_upload(self, **kw: Any) -> dict[str, Any]:
        del kw
        self.calls.append("abort_multipart_upload")
        self._store.pop("_upload", None)
        return {}

    async def delete_object(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("delete_object")
        self._store.pop(f"{kw['Bucket']}/{kw['Key']}", None)
        return {}


def _s3(store: dict[str, Any], **kwargs: Any) -> tuple[S3Sink, _FakeS3Client]:
    client = _FakeS3Client(store)
    sink = S3Sink(
        bucket="evidence",
        prefix="z4j-exports",
        endpoint_url="https://minio.internal:9000",
        access_key_id="AKIAEXAMPLE",
        secret_access_key="hunter2-secret",
        client_factory=lambda: client,
        **kwargs,
    )
    return sink, client


async def test_s3_sink_puts_small_objects_in_one_call() -> None:
    store: dict[str, Any] = {}
    sink, client = _s3(store)
    result = await sink.write(
        "audit/default/j.csv", _one(b"a,b\r\n1,2\r\n"), content_type="text/csv"
    )
    assert result == SinkWriteResult(
        location="s3://evidence/z4j-exports/audit/default/j.csv",
        size_bytes=10,
        key="audit/default/j.csv",
    )
    assert client.calls == ["put_object"]
    assert store["evidence/z4j-exports/audit/default/j.csv"] == {
        "body": b"a,b\r\n1,2\r\n",
        "type": "text/csv",
    }
    await sink.discard(result.key)
    assert client.calls[-1] == "delete_object"
    assert "evidence/z4j-exports/audit/default/j.csv" not in store


async def test_s3_sink_streams_large_objects_as_multipart() -> None:
    store: dict[str, Any] = {}
    part = 5 * 1024 * 1024
    sink, client = _s3(store, part_size=part)

    async def chunks() -> AsyncIterator[bytes]:
        for i in range(12):
            yield bytes([i]) * (1024 * 1024)  # 12 MiB in 1 MiB chunks

    result = await sink.write("audit/default/big.json", chunks(), content_type="application/json")
    assert result.size_bytes == 12 * 1024 * 1024
    assert client.calls == [
        "create_multipart_upload",
        "upload_part:1",
        "upload_part:2",
        "upload_part:3",
        "complete_multipart_upload",
    ]
    body = store["evidence/z4j-exports/audit/default/big.json"]["body"]
    assert len(body) == 12 * 1024 * 1024
    assert body[:1] == b"\x00" and body[-1:] == b"\x0b"


async def test_s3_sink_aborts_a_multipart_upload_when_the_stream_fails() -> None:
    store: dict[str, Any] = {}
    sink, client = _s3(store, part_size=5 * 1024 * 1024)

    async def chunks() -> AsyncIterator[bytes]:
        yield b"x" * (6 * 1024 * 1024)
        raise RuntimeError("database went away")

    with pytest.raises(RuntimeError):
        await sink.write("audit/default/half.csv", chunks(), content_type="text/csv")
    assert client.calls[-1] == "abort_multipart_upload"
    assert "_upload" not in store


def test_s3_sink_description_never_carries_a_credential() -> None:
    sink, _ = _s3({})
    assert sink.describe() == "s3://evidence/z4j-exports (https://minio.internal:9000)"
    assert "hunter2" not in sink.describe() and "AKIA" not in sink.describe()
    sink_with_userinfo = S3Sink(
        bucket="b", endpoint_url="https://AKIA:hunter2@host:9000", client_factory=lambda: None
    )
    assert sink_with_userinfo.describe() == "s3://b (https://host:9000)"


# ---------------------------------------------------------------------------
# A failing client's message never reaches the job row or the audit trail
# ---------------------------------------------------------------------------

_MARKER_PASS = "R2EENDPOINTPASS"
_MARKER_KEY = "AKIAR2EACCESSKEYID01"
_HOSTILE_TEXT = (
    "Could not connect to the endpoint URL: "
    f'"https://epuser:{_MARKER_PASS}@minio.internal:9000/evidence'
    f'?X-Amz-Credential={_MARKER_KEY}%2F20260101%2Fus-east-1"'
)


def _library_exception(module: str, name: str, **attrs: Any) -> BaseException:
    """An exception that says it comes from ``module``, carrying the hostile text."""
    cls = type(name, (Exception,), {"__module__": module})
    exc = cls(_HOSTILE_TEXT)
    for key, value in attrs.items():
        setattr(exc, key, value)
    return exc


class _HostileS3Client(_FakeS3Client):
    """A client whose failure carries the endpoint URL and the key id in its text."""

    def __init__(self, store: dict[str, Any], exc: BaseException) -> None:
        super().__init__(store)
        self._exc = exc

    async def put_object(self, **kw: Any) -> dict[str, Any]:
        del kw
        self.calls.append("put_object")
        raise self._exc


async def _failure_metadata(db: DatabaseManager, job_id: str) -> dict[str, Any]:
    async with db.session() as s:
        row = (
            await s.execute(
                select(AuditLog).where(
                    AuditLog.target_id == job_id,
                    AuditLog.action == AUDIT_ACTION_EXPORT_FAILED,
                )
            )
        ).scalar_one()
        return dict(row.audit_metadata)


@pytest.mark.parametrize(
    ("exc", "phrase"),
    [
        (
            _library_exception("botocore.exceptions", "EndpointConnectionError"),
            "endpoint unreachable",
        ),
        (
            _library_exception(
                "botocore.exceptions",
                "ClientError",
                response={"Error": {"Code": "AccessDenied", "Message": _HOSTILE_TEXT}},
            ),
            "access denied",
        ),
        (
            _library_exception(
                "botocore.exceptions",
                "ClientError",
                response={"Error": {"Code": "NoSuchBucket", "Message": _HOSTILE_TEXT}},
            ),
            "bucket missing",
        ),
        (
            _library_exception(
                "botocore.exceptions",
                "ClientError",
                response={"Error": {"Code": "NoSuchUpload", "Message": _HOSTILE_TEXT}},
            ),
            "upload aborted",
        ),
        (
            _library_exception(
                "aiohttp.client_exceptions",
                "ClientConnectorError",
                os_error=ConnectionRefusedError(111, "Connection refused"),
            ),
            "connection refused",
        ),
        (
            _library_exception(
                "botocore.exceptions",
                "ClientError",
                response={"Error": {"Code": _MARKER_PASS, "Message": _HOSTILE_TEXT}},
            ),
            "unknown error (ClientError)",
        ),
        (
            _library_exception("botocore.exceptions", "SomethingNewError"),
            "unknown error (SomethingNewError)",
        ),
    ],
    ids=[
        "endpoint",
        "access-denied",
        "bucket-missing",
        "upload-aborted",
        "refused",
        "hostile-code",
        "unknown",
    ],
)
async def test_a_library_failure_records_a_fixed_phrase_not_its_text(
    brain_app, client, seeded, exc: BaseException, phrase: str
) -> None:
    db = brain_app.state.db
    await _seed_audit_rows(db, seeded["project_id"], seeded["admin"]["user_id"], 50)
    created = await client.post(
        "/api/v1/projects/default/audit/export-jobs", json={"format": "csv"}
    )
    job_id = created.json()["id"]
    hostile = _HostileS3Client({}, exc)
    sink = S3Sink(
        bucket="evidence",
        prefix="z4j-exports",
        endpoint_url="https://minio.internal:9000",
        access_key_id=_MARKER_KEY,
        secret_access_key="hunter2-secret",
        client_factory=lambda: hostile,
    )
    worker = ExportJobsWorker(
        db=db,
        settings=brain_app.state.settings,
        audit=brain_app.state.audit_service,
        sink=sink,
    )
    assert await worker.tick() is None
    # Positive control: the failure really came out of the client.
    assert hostile.calls == ["put_object"]
    failed = await _job(client, job_id)
    assert failed["status"] == "failed"
    assert failed["error"] == phrase
    metadata = await _failure_metadata(db, job_id)
    assert metadata["error"] == phrase
    for surface in (json.dumps(failed), json.dumps(metadata)):
        assert _MARKER_PASS not in surface
        assert _MARKER_KEY not in surface


def test_safe_reason_keeps_our_own_text_with_any_userinfo_stripped() -> None:
    ours = RuntimeError(
        f"could not reach https://epuser:{_MARKER_PASS}@minio.internal:9000/evidence"
    )
    assert _safe_reason(ours) == (
        "RuntimeError: could not reach https://minio.internal:9000/evidence"
    )
    assert _safe_reason(ExportSinkError("export directory is missing")) == (
        "ExportSinkError: export directory is missing"
    )
    assert _safe_reason(ValueError()) == "ValueError"
    assert _safe_reason(ConnectionRefusedError(111, "Connection refused")) == "connection refused"
    wrapped = _library_exception("botocore.exceptions", "EndpointConnectionError")
    wrapped.kwargs = {"error": ConnectionRefusedError(111, "Connection refused")}  # type: ignore[attr-defined]
    assert _safe_reason(wrapped) == "connection refused"


async def test_s3_sink_names_the_extra_when_aiobotocore_is_missing(monkeypatch) -> None:
    import builtins

    real_import = builtins.__import__

    def refusing(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith("aiobotocore"):
            raise ImportError("No module named 'aiobotocore'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refusing)
    monkeypatch.delitem(sys.modules, "aiobotocore.session", raising=False)
    sink = S3Sink(bucket="b")
    with pytest.raises(ExportSinkError, match=r'pip install "z4j\[s3\]"'):
        await sink.write("k", _one(b"x"), content_type="text/plain")


# ---------------------------------------------------------------------------
# Settings contract
# ---------------------------------------------------------------------------


def test_settings_require_what_each_sink_needs(tmp_path: Path, sink_dir: Path) -> None:
    with pytest.raises(ConfigError, match="Z4J_EXPORT_SINK_PATH"):
        _settings(tmp_path, sink_dir, export_sink="local", export_sink_path=None)
    with pytest.raises(ConfigError, match="Z4J_EXPORT_SINK_S3_BUCKET"):
        _settings(tmp_path, sink_dir, export_sink="s3")
    with pytest.raises(ConfigError, match="needs an export sink"):
        _settings(tmp_path, sink_dir, export_sink="none", audit_head_export_interval_seconds=3600)
    with pytest.raises(ConfigError, match="at least 60"):
        _settings(tmp_path, sink_dir, audit_head_export_interval_seconds=30)
    with pytest.raises(ConfigError, match="set together"):
        _settings(tmp_path, sink_dir, export_sink_s3_access_key_id="k")
    s3 = _settings(
        tmp_path,
        sink_dir,
        export_sink="s3",
        export_sink_s3_bucket="evidence",
        export_sink_s3_access_key_id="k",
        export_sink_s3_secret_access_key="s",
        audit_head_export_interval_seconds=60,
    )
    assert "export_jobs_worker" in s3.leader_gated_worker_names()
    off = _settings(tmp_path, sink_dir, export_sink="none", export_sink_path=None)
    assert "export_jobs_worker" not in off.leader_gated_worker_names()


async def test_worker_tick_asks_for_the_leader_lock(brain_app, monkeypatch) -> None:
    from z4j_brain.domain.workers import _leader_lock

    asked: list[str] = []

    async def record(db: Any, name: str, *, announce: bool = True) -> None:
        asked.append(name)

    monkeypatch.setattr(_leader_lock, "try_acquire_singleton_lock", record)
    worker = next(
        w for w in brain_app.state.worker_supervisor._workers if w.name == "export_jobs_worker"
    )
    assert await worker.tick() is None
    assert asked == ["export_jobs_worker"]


async def test_repository_transitions_are_conditional(brain_app, seeded) -> None:
    from z4j_brain.persistence.repositories.export_jobs import ExportJobRepository

    async with brain_app.state.db.session() as s:
        repo = ExportJobRepository(s)
        job = await repo.create(
            user_id=seeded["admin"]["user_id"],
            project_id=seeded["project_id"],
            export_type="audit",
            export_format="csv",
            filters={},
            sink="local",
        )
        assert await repo.claim(job.id) is True
        assert await repo.claim(job.id) is False
        assert await repo.record_progress(job.id, rows_written=10) is True
        assert await repo.mark_done(job.id, rows_written=10, size_bytes=1, location="/x") is True
        assert await repo.mark_done(job.id, rows_written=10, size_bytes=1, location="/x") is False
        assert await repo.mark_failed(job.id, reason="late") is False
        assert await repo.count_pending_for_project(seeded["project_id"]) == 0
        await s.rollback()


async def test_tick_runs_more_than_one_job_and_asks_to_be_woken_when_more_wait(
    brain_app, client, seeded, worker, monkeypatch
) -> None:
    from z4j_brain.domain.workers import export_jobs as worker_mod

    await _seed_audit_rows(brain_app.state.db, seeded["project_id"], seeded["admin"]["user_id"], 5)
    for _ in range(3):
        r = await client.post("/api/v1/projects/default/audit/export-jobs", json={"format": "json"})
        assert r.status_code == 202
    monkeypatch.setattr(worker_mod, "MAX_JOBS_PER_TICK", 2)
    assert await worker.tick() == 0.5
    listed = (await client.get("/api/v1/projects/default/audit/export-jobs")).json()["items"]
    assert sorted(item["status"] for item in listed) == ["done", "done", "queued"]
    assert await worker.tick() is None
    listed = (await client.get("/api/v1/projects/default/audit/export-jobs")).json()["items"]
    assert [item["status"] for item in listed] == ["done", "done", "done"]
    await asyncio.sleep(0)
