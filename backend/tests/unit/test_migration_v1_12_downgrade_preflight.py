"""The four row- or host-dependent 1.12 refusals cover the whole downgrade plan.

``v1_12_auditor_role``, ``v1_12_export_jobs_sink``,
``v1_12_channel_config_encrypted`` and ``v1_12_api_key_allowed_cidrs`` each
refuse on something only the live database or the host can answer: a
membership still holding ``auditor``, an SQLite library without ``ALTER TABLE
DROP COLUMN`` (the sink and the CIDR revisions both drop a column that way), a
channel config that decrypts under no listed secret. ``env.py`` reads
``DOWNGRADE_PREFLIGHT`` off every revision in the resolved plan before its
first step runs, so a plan from head down to ``v1_11_audit_append_tally`` that
crosses a refusing revision leaves the database exactly as it was: the head
still stamped, the export-job columns, the API-key CIDR column and the
forwarder state table all still present, and no channel row rewritten. With
the blockers cleared the same plan completes, and the inline refusals stay in
place behind it.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.runtime.environment import EnvironmentContext
from alembic.script import ScriptDirectory
from alembic.util import CommandError
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session
from z4j_brain.domain.secret_fields import (
    ENCRYPTED_PREFIX,
    NOTIFICATION_CHANNEL_CONFIG,
    USER_CHANNEL_CONFIG,
    SecretKeyring,
    encrypt_json,
)
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import Membership, Project, User

from tests.migration_head import code_head

TARGET = "v1_11_audit_append_tally"
CHANNEL_REVISION = "v1_12_channel_config_encrypted"
SINK_REVISION = "v1_12_export_jobs_sink"
AUDITOR_REVISION = "v1_12_auditor_role"
CIDR_REVISION = "v1_12_api_key_allowed_cidrs"

#: Every revision that declares a live-state guard. The operator docs count
#: these, so a new declarer updates this set, the pin below and the count on
#: the page.
PREFLIGHT_DECLARERS = frozenset(
    {
        "v1_9_schedule_control_columns",
        "v1_9_automation_rolling_window",
        "v1_9_delivery_recipient",
        "v1_9_audit_action_pattern",
        "v1_11_audit_append_tally",
        CHANNEL_REVISION,
        SINK_REVISION,
        AUDITOR_REVISION,
        CIDR_REVISION,
    }
)
#: The number the operations page states; it changes together with the set.
PREFLIGHT_DECLARER_COUNT = 9

MASTER = "x" * 64
PREVIOUS = "p" * 64
#: A master that is listed nowhere: a row written under it cannot be read.
STRANGER = "s" * 64

SLACK = {"webhook_url": "https://hooks.slack.com/services/T0/B0/X", "channel": "#ops"}
TELEGRAM = {"bot_token": "written-under-the-previous-master", "chat_id": "42"}
LOST = {"url": "https://hooks.example.com/lost", "hmac_secret": "WRITTEN-UNDER-STRANGER"}
WEBHOOK = {"url": "https://hooks.example.com/mine", "hmac_secret": "MINE"}

CHANNEL_REFUSAL = "does not decrypt under Z4J_SECRET"
AUDITOR_REFUSAL = "hold the 'auditor' role"
SQLITE_REFUSAL = "predates ALTER TABLE DROP COLUMN"


@pytest.fixture
def alembic_cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Config]:
    db_path = tmp_path / "brain.sqlite"
    monkeypatch.setenv("Z4J_DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("Z4J_SECRET", MASTER)
    monkeypatch.setenv("Z4J_PREVIOUS_SECRETS", PREVIOUS)
    monkeypatch.setenv("Z4J_SESSION_SECRET", "y" * 64)
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", "a" * 64)
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    private_home = tmp_path / "home"
    private_home.mkdir()
    private_home.chmod(0o700)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.chdir(tmp_path)

    backend_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(backend_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend_root / "src" / "z4j_brain" / "migrations"))
    cfg.attributes["test_sync_url"] = f"sqlite:///{db_path}"
    yield cfg


def _encrypted(value: dict[str, Any], secret: str, purpose: str) -> str:
    return encrypt_json(value, keyring=SecretKeyring.from_secrets(secret), purpose=purpose)


def _seed(cfg: Config, *, lost_channel: bool, auditor: bool) -> dict[str, str]:
    """Populate a head database; return the ids of the channel rows."""
    ids = {"slack": uuid.uuid4().hex, "telegram": uuid.uuid4().hex, "webhook": uuid.uuid4().hex}
    engine = create_engine(cfg.attributes["test_sync_url"])
    try:
        with Session(engine) as session:
            project = Project(id=uuid.uuid4(), slug="default", name="Default")
            user = User(
                id=uuid.uuid4(),
                email=f"{uuid.uuid4().hex[:10]}@example.com",
                password_hash="x",
                is_admin=False,
                is_active=True,
            )
            session.add_all([project, user])
            session.flush()
            role = ProjectRole.AUDITOR if auditor else ProjectRole.OPERATOR
            session.add(Membership(user_id=user.id, project_id=project.id, role=role))
            session.commit()
            project_id, user_id = project.id.hex, user.id.hex

        channels = [
            (ids["slack"], "slack", _encrypted(SLACK, MASTER, NOTIFICATION_CHANNEL_CONFIG)),
            (
                ids["telegram"],
                "telegram",
                _encrypted(TELEGRAM, PREVIOUS, NOTIFICATION_CHANNEL_CONFIG),
            ),
        ]
        if lost_channel:
            ids["lost"] = uuid.uuid4().hex
            channels.append(
                (ids["lost"], "webhook", _encrypted(LOST, STRANGER, NOTIFICATION_CHANNEL_CONFIG)),
            )
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO notification_channels (id, project_id, name, type, config, "
                    "is_active, created_at, updated_at) VALUES (:id, :pid, :name, :type, "
                    ":config, 1, datetime('now'), datetime('now'))",
                ),
                [
                    {"id": row_id, "pid": project_id, "name": kind, "type": kind, "config": config}
                    for row_id, kind, config in channels
                ],
            )
            conn.execute(
                sa.text(
                    "INSERT INTO user_channels (id, user_id, name, type, config, is_verified, "
                    "is_active, created_at, updated_at) VALUES (:id, :uid, 'mine', 'webhook', "
                    ":config, 0, 1, datetime('now'), datetime('now'))",
                ),
                {
                    "id": ids["webhook"],
                    "uid": user_id,
                    "config": _encrypted(WEBHOOK, MASTER, USER_CHANNEL_CONFIG),
                },
            )
    finally:
        engine.dispose()
    return ids


def _state(cfg: Config) -> dict[str, Any]:
    """Everything a plan from head to ``TARGET`` would drop or rewrite."""
    engine = create_engine(cfg.attributes["test_sync_url"])
    try:
        inspector = inspect(engine)
        with engine.connect() as conn:
            return {
                "version": conn.exec_driver_sql(
                    "SELECT version_num FROM alembic_version",
                ).scalar_one(),
                "export_jobs": {column["name"] for column in inspector.get_columns("export_jobs")},
                "api_keys": {column["name"] for column in inspector.get_columns("api_keys")},
                "audit_forward_state": inspector.has_table("audit_forward_state"),
                "channels": tuple(
                    conn.exec_driver_sql(
                        "SELECT id, config FROM notification_channels ORDER BY id",
                    ).all(),
                ),
                "user_channels": tuple(
                    conn.exec_driver_sql("SELECT id, config FROM user_channels ORDER BY id").all(),
                ),
                "roles": tuple(
                    str(row[0])
                    for row in conn.exec_driver_sql(
                        "SELECT role FROM memberships ORDER BY role",
                    ).all()
                ),
            }
    finally:
        engine.dispose()


def _forget_bound_configuration(cfg: Config) -> None:
    """Drop the configuration snapshot ``env.py`` bound to this Config.

    One Alembic invocation per process is the production shape, and the
    snapshot captured for it lives on the Config object. This module issues
    several commands from one Config, so after the environment changes it
    forgets the snapshot the way a fresh process would, and the next command
    captures the current environment.
    """
    cfg.attributes.pop("z4j_configuration_snapshot", None)
    cfg.attributes.pop("z4j_migration_settings", None)


def _reassign_auditors(cfg: Config, role: ProjectRole) -> None:
    engine = create_engine(cfg.attributes["test_sync_url"])
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text("UPDATE memberships SET role = :role WHERE role = 'auditor'"),
                {"role": role.value},
            )
    finally:
        engine.dispose()


def _downgrade_with(cfg: Config, script: ScriptDirectory, target: str) -> None:
    """``command.downgrade`` with a caller-supplied ScriptDirectory.

    The command builds its own ScriptDirectory, which loads every revision
    module afresh, so a patch on a revision module has to reach the one
    whose plan actually runs.
    """

    def plan(rev: Any, context: Any) -> Any:
        return script._downgrade_revs(target, rev)

    with EnvironmentContext(
        cfg,
        script,
        fn=plan,
        as_sql=False,
        starting_rev=None,
        destination_rev=target,
    ):
        script.run_env()


def _assert_at_head_with_everything_present(state: dict[str, Any]) -> None:
    assert state["version"] == code_head()
    assert {"sink", "size_bytes", "started_at"} <= state["export_jobs"]
    assert "allowed_cidrs" in state["api_keys"]
    assert state["audit_forward_state"] is True
    assert state["channels"] and state["user_channels"]
    for _, config in (*state["channels"], *state["user_channels"]):
        assert str(config).startswith(ENCRYPTED_PREFIX)


def test_each_wave_two_refusal_is_declared_as_a_preflight(alembic_cfg: Config) -> None:
    """``env.py`` only refuses before step one when the module declares it."""
    script = ScriptDirectory.from_config(alembic_cfg)
    declared = {
        revision.revision
        for revision in script.walk_revisions()
        if callable(getattr(revision.module, "DOWNGRADE_PREFLIGHT", None))
    }
    assert {CHANNEL_REVISION, SINK_REVISION, AUDITOR_REVISION, CIDR_REVISION} <= declared
    assert declared == PREFLIGHT_DECLARERS
    assert len(declared) == PREFLIGHT_DECLARER_COUNT


@pytest.mark.parametrize(
    ("lost_channel", "auditor", "refusal"),
    [
        pytest.param(True, False, CHANNEL_REFUSAL, id="undecryptable-channel-row"),
        pytest.param(False, True, AUDITOR_REFUSAL, id="auditor-membership"),
        pytest.param(True, True, f"{CHANNEL_REFUSAL}|{AUDITOR_REFUSAL}", id="both"),
    ],
)
def test_plan_is_refused_before_its_first_step(
    alembic_cfg: Config,
    lost_channel: bool,
    auditor: bool,
    refusal: str,
) -> None:
    command.upgrade(alembic_cfg, "head")
    _seed(alembic_cfg, lost_channel=lost_channel, auditor=auditor)
    before = _state(alembic_cfg)
    _assert_at_head_with_everything_present(before)

    with pytest.raises(CommandError, match=refusal):
        command.downgrade(alembic_cfg, TARGET)

    assert _state(alembic_cfg) == before

    # The move an operator makes next must not be the one that loses anything.
    command.upgrade(alembic_cfg, "head")
    assert _state(alembic_cfg) == before


@pytest.mark.parametrize("refusing", [SINK_REVISION, CIDR_REVISION])
def test_plan_is_refused_before_its_first_step_on_sqlite_without_drop_column(
    alembic_cfg: Config,
    monkeypatch: pytest.MonkeyPatch,
    refusing: str,
) -> None:
    """The host check is a preflight too, on both revisions that drop a column.

    The library under test can drop columns, so the version answer is forced
    on the one module object whose plan runs; the guard itself is untouched.
    Only the revision under test is forced, so a refusal naming it proves its
    own guard ran ahead of the plan, not that a neighbour refused first.
    """
    command.upgrade(alembic_cfg, "head")
    _seed(alembic_cfg, lost_channel=False, auditor=False)
    before = _state(alembic_cfg)
    _assert_at_head_with_everything_present(before)

    script = ScriptDirectory.from_config(alembic_cfg)
    revision = script.get_revision(refusing)
    assert revision is not None
    monkeypatch.setattr(revision.module, "_sqlite_supports_drop_column", lambda bind: False)

    with pytest.raises(CommandError, match=f"{SQLITE_REFUSAL}.*{refusing}"):
        _downgrade_with(alembic_cfg, script, TARGET)

    assert _state(alembic_cfg) == before


def test_plan_completes_once_the_blockers_are_cleared(
    alembic_cfg: Config,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command.upgrade(alembic_cfg, "head")
    ids = _seed(alembic_cfg, lost_channel=True, auditor=True)
    before = _state(alembic_cfg)
    with pytest.raises(CommandError):
        command.downgrade(alembic_cfg, TARGET)
    assert _state(alembic_cfg) == before

    # The operator's two manual moves: list the secret the lost row was
    # written under among the previous secrets, and reassign the auditor.
    monkeypatch.setenv("Z4J_PREVIOUS_SECRETS", f"{PREVIOUS},{STRANGER}")
    _forget_bound_configuration(alembic_cfg)
    _reassign_auditors(alembic_cfg, ProjectRole.VIEWER)

    command.downgrade(alembic_cfg, TARGET)
    after = _state(alembic_cfg)
    assert after["version"] == TARGET
    assert {"sink", "size_bytes", "started_at"}.isdisjoint(after["export_jobs"])
    assert "allowed_cidrs" not in after["api_keys"]
    assert after["audit_forward_state"] is False
    assert {str(row_id): json.loads(str(config)) for row_id, config in after["channels"]} == {
        ids["slack"]: SLACK,
        ids["telegram"]: TELEGRAM,
        ids["lost"]: LOST,
    }
    assert {str(row_id): json.loads(str(config)) for row_id, config in after["user_channels"]} == {
        ids["webhook"]: WEBHOOK,
    }
    assert after["roles"] == ("viewer",)

    # And forward again: every row encrypted, nothing lost.
    command.upgrade(alembic_cfg, "head")
    again = _state(alembic_cfg)
    assert again["version"] == code_head()
    assert {"sink", "size_bytes", "started_at"} <= again["export_jobs"]
    assert "allowed_cidrs" in again["api_keys"]
    assert again["audit_forward_state"] is True
    assert len(again["channels"]) == 3 and len(again["user_channels"]) == 1
    for _, config in (*again["channels"], *again["user_channels"]):
        assert str(config).startswith(ENCRYPTED_PREFIX)
