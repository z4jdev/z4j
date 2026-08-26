"""``z4j misfires --project <slug>`` CLI: table + --json + exit codes.

Drives the real console-script entrypoint (``main(["misfires", ...])``
-> ``_run_misfires``) against a file-backed SQLite database seeded
through the real ``AuditService``, so the misfire rows under test are
genuine:

- populated project -> exit 0, table lists every schedule's misfire;
- ``--json`` -> exit 0, machine-readable object spanning schedules;
- unknown project slug -> exit 2;
- project with no misfires -> exit 0, friendly "no misfires" line.

Mirrors ``test_cli_audit_verify.py``: the CLI builds its own
``Settings()`` from the environment, so the seeding helper and the CLI
under test must agree on the DB file + signing secret.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import uuid
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.persistence import models  # noqa: F401  registers metadata
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import Project
from z4j_brain.persistence.repositories import AuditLogRepository
from z4j_brain.secret_store import protect_secret_store_directory
from z4j_brain.settings import Settings


@pytest.fixture
def cli_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Settings:
    db_url = f"sqlite+aiosqlite:///{(tmp_path / 'misfires.db').as_posix()}"
    secret = secrets.token_urlsafe(48)
    session_secret = secrets.token_urlsafe(48)
    monkeypatch.setenv("Z4J_DATABASE_URL", db_url)
    monkeypatch.setenv("Z4J_SECRET", secret)
    monkeypatch.setenv("Z4J_SESSION_SECRET", session_secret)
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.delenv("Z4J_PREVIOUS_SECRETS", raising=False)
    monkeypatch.setenv("Z4J_ALLOWED_HOSTS", '["localhost","127.0.0.1"]')
    private_home = tmp_path / "z4j-home"
    private_home.mkdir(mode=0o700)
    protect_secret_store_directory(private_home)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.chdir(tmp_path)
    return Settings(
        database_url=db_url,
        secret=secret,  # type: ignore[arg-type]
        session_secret=session_secret,  # type: ignore[arg-type]
        environment="dev",
    )


async def _seed(settings: Settings, *, with_misfires: bool = True) -> dict:
    """Create the schema, a ``default`` project, and misfire audit rows."""
    engine = create_async_engine(settings.database_url, future=True)
    project_id = uuid.uuid4()
    sched_a = uuid.uuid4()
    sched_b = uuid.uuid4()
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory = sessionmaker(  # type: ignore[call-overload]
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        audit = AuditService(settings)
        async with factory() as session:
            session.add(Project(id=project_id, slug="default", name="Default"))
            await session.commit()
            if with_misfires:
                for sid, sname, late, when in (
                    (sched_a, "nightly", 120.0, "2026-06-01T00:00:00+00:00"),
                    (sched_b, "hourly", 300.0, "2026-06-01T01:00:00+00:00"),
                    (sched_a, "nightly", 540.0, "2026-06-01T02:00:00+00:00"),
                ):
                    await audit.record(
                        AuditLogRepository(session),
                        action="scheduler.misfire_detected",
                        target_type="schedule",
                        target_id=str(sid),
                        result="failed",
                        outcome="error",
                        project_id=project_id,
                        metadata={
                            "name": sname,
                            "engine": "celery",
                            "kind": "interval",
                            "expected_fire_at": when,
                            "lateness_seconds": late,
                            "grace_seconds": 60,
                        },
                    )
                    await session.commit()
    finally:
        await engine.dispose()
    return {"sched_a": str(sched_a), "sched_b": str(sched_b)}


def _run_misfires(*extra: str) -> int:
    from z4j_brain.cli import main

    return main(["misfires", *extra])


def test_table_lists_misfires_across_schedules(
    cli_settings: Settings,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ids = asyncio.run(_seed(cli_settings))
    rc = _run_misfires("--project", "default")
    out = capsys.readouterr().out
    assert rc == 0
    # Header + both schedule ids appear (rows span schedules).
    assert "SCHEDULE ID" in out
    assert ids["sched_a"] in out
    assert ids["sched_b"] in out
    assert "3 misfire(s) for project 'default'" in out


def test_json_output_is_machine_readable(
    cli_settings: Settings,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ids = asyncio.run(_seed(cli_settings))
    rc = _run_misfires("--project", "default", "--json")
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert payload["project"] == "default"
    rows = payload["misfires"]
    assert len(rows) == 3
    # Newest first.
    assert rows[0]["lateness_seconds"] == 540.0
    assert rows[0]["schedule_id"] == ids["sched_a"]
    # Both schedules represented.
    assert {r["schedule_id"] for r in rows} == {ids["sched_a"], ids["sched_b"]}


def test_limit_flag_bounds_rows(
    cli_settings: Settings,
    capsys: pytest.CaptureFixture[str],
) -> None:
    asyncio.run(_seed(cli_settings))
    rc = _run_misfires("--project", "default", "--limit", "1", "--json")
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert len(payload["misfires"]) == 1
    assert payload["misfires"][0]["lateness_seconds"] == 540.0


def test_unknown_project_exits_two(
    cli_settings: Settings,
    capsys: pytest.CaptureFixture[str],
) -> None:
    asyncio.run(_seed(cli_settings))
    rc = _run_misfires("--project", "does-not-exist")
    err = capsys.readouterr().err
    assert rc == 2
    assert "not found" in err


def test_no_misfires_exits_zero_with_message(
    cli_settings: Settings,
    capsys: pytest.CaptureFixture[str],
) -> None:
    asyncio.run(_seed(cli_settings, with_misfires=False))
    rc = _run_misfires("--project", "default")
    out = capsys.readouterr().out
    assert rc == 0
    assert "no misfires recorded" in out
