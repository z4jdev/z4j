"""``Z4J_REDACTION_EXTRA_KEY_PATTERNS`` reaches the brain's ingest scrub.

Before this setting existed ``main.py`` passed ``extra_key_patterns=()``,
so only the built-in patterns ran brain-side. The ingest test here pairs
the positive case (a key matching an extra pattern is scrubbed) with the
negative control (the same key survives the default engine), so the
assertion can only pass because the setting was wired through.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from z4j_brain.domain.event_ingestor import EventIngestor
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.enums import AgentState
from z4j_brain.persistence.models import Agent, Project, Task
from z4j_brain.persistence.repositories import (
    AgentRepository,
    EventRepository,
    QueueRepository,
    TaskRepository,
)
from z4j_brain.settings import Settings

SECRET_VALUE = "LAUNCH-CODE-0000-1234"


def _settings(**overrides: object) -> Settings:
    kwargs: dict[str, object] = {
        "database_url": "sqlite+aiosqlite:///:memory:",
        "secret": secrets.token_urlsafe(48),
        "session_secret": secrets.token_urlsafe(48),
        "log_json": False,
        "environment": "dev",
        "disable_spa_fallback": True,
    }
    kwargs.update(overrides)
    return Settings(**kwargs)  # type: ignore[arg-type]


class TestSetting:
    def test_default_is_empty(self) -> None:
        assert _settings().redaction_extra_key_patterns == []

    def test_valid_patterns_are_kept_in_order(self) -> None:
        settings = _settings(redaction_extra_key_patterns=["^launch_code$", "customer_id"])
        assert settings.redaction_extra_key_patterns == ["^launch_code$", "customer_id"]

    def test_invalid_regex_is_refused_at_construction(self) -> None:
        with pytest.raises(ValidationError) as excinfo:
            _settings(redaction_extra_key_patterns=["^launch_code$", "(unclosed"])
        message = str(excinfo.value)
        assert "redaction_extra_key_patterns[1]" in message
        assert "not a valid regex" in message

    def test_empty_entry_is_refused(self) -> None:
        with pytest.raises(ValidationError, match=r"redaction_extra_key_patterns\[0\]"):
            _settings(redaction_extra_key_patterns=[""])

    def test_env_form_is_a_json_array(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("Z4J_REDACTION_EXTRA_KEY_PATTERNS", '["^launch_code$"]')
        assert _settings().redaction_extra_key_patterns == ["^launch_code$"]

    @pytest.mark.parametrize(
        ("env_value", "pattern"),
        [
            ('["(a+)+$"]', "(a+)+$"),
            ('["^(\\\\w+_)*ssn$"]', "^(\\w+_)*ssn$"),
        ],
    )
    def test_a_catastrophic_pattern_is_refused_with_the_limits_named(
        self, monkeypatch: pytest.MonkeyPatch, env_value: str, pattern: str
    ) -> None:
        """One crafted key against ``(a+)+$`` stalled a worker for two seconds."""
        monkeypatch.setenv("Z4J_REDACTION_EXTRA_KEY_PATTERNS", env_value)

        with pytest.raises(ValidationError) as excinfo:
            _settings()

        message = str(excinfo.value)
        assert "redaction_extra_key_patterns[0] is refused" in message
        assert repr(pattern) in message
        assert "20 ms" in message
        assert "100 ms" in message

    def test_a_benign_anchored_pattern_is_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("Z4J_REDACTION_EXTRA_KEY_PATTERNS", '["^customer_.*_token$"]')
        assert _settings().redaction_extra_key_patterns == ["^customer_.*_token$"]


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------


@pytest.fixture
async def session():  # type: ignore[no-untyped-def]
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


async def _ingest_one(session: AsyncSession, ingestor: EventIngestor) -> Task:
    project = Project(slug="default", name="Default")
    session.add(project)
    await session.commit()
    agent = Agent(
        project_id=project.id,
        name="web-01",
        token_hash=secrets.token_hex(32),
        protocol_version="1",
        framework_adapter="django",
        engine_adapters=["celery"],
        scheduler_adapters=[],
        capabilities={},
        state=AgentState.ONLINE,
    )
    session.add(agent)
    await session.commit()
    await ingestor.ingest_batch(
        events=[
            {
                "kind": "task.received",
                "engine": "celery",
                "task_id": "task-001",
                "occurred_at": datetime.now(UTC).isoformat(),
                "data": {
                    "task_name": "myapp.tasks.launch",
                    "kwargs": {"launch_code": SECRET_VALUE, "site": "north"},
                },
            }
        ],
        project_id=project.id,
        agent_id=agent.id,
        agents=AgentRepository(session),
        event_repo=EventRepository(session),
        task_repo=TaskRepository(session),
        queue_repo=QueueRepository(session),
    )
    await session.commit()
    return (await session.execute(select(Task))).scalar_one()


async def _app_ingestor(settings: Settings) -> tuple[EventIngestor, object]:
    engine = create_async_engine(settings.database_url, future=True)
    app = create_app(settings, engine=engine)
    return app.state.event_ingestor, engine


@pytest.mark.asyncio
async def test_default_patterns_leave_an_unlisted_key_alone(session: AsyncSession) -> None:
    """Negative control: without the setting, ``launch_code`` is not scrubbed."""
    ingestor, engine = await _app_ingestor(_settings())
    try:
        task = await _ingest_one(session, ingestor)
    finally:
        await engine.dispose()  # type: ignore[attr-defined]
    assert task.kwargs is not None
    assert SECRET_VALUE in str(task.kwargs)
    assert "north" in str(task.kwargs)


@pytest.mark.asyncio
async def test_extra_pattern_from_settings_scrubs_the_key_on_ingest(
    session: AsyncSession,
) -> None:
    ingestor, engine = await _app_ingestor(
        _settings(redaction_extra_key_patterns=["^launch_code$"])
    )
    try:
        task = await _ingest_one(session, ingestor)
    finally:
        await engine.dispose()  # type: ignore[attr-defined]
    assert task.kwargs is not None
    assert SECRET_VALUE not in str(task.kwargs)
    assert "north" in str(task.kwargs), "only the matching key is scrubbed"
