from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from argparse import Namespace
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.engine import make_url
from z4j_brain import cli
from z4j_brain.configuration import (
    ConfigurationCaptureError,
    capture_configuration,
    capture_explicit_configuration_file,
    settings_from_snapshot,
)
from z4j_brain.secret_store import (
    protect_secret_store_directory,
    update_secret_store,
)


def _grant_windows_everyone(path: Path) -> None:
    """Install an independently observable broad Windows allow ACE."""
    subprocess.run(
        [
            "icacls.exe",
            str(path),
            "/grant",
            "*S-1-1-0:(OI)(CI)(F)",
        ],
        check=True,
        capture_output=True,
    )


@pytest.fixture
def private_home() -> Iterator[Path]:
    path = Path(tempfile.mkdtemp(prefix="z4j-config-", dir="/tmp"))
    protect_secret_store_directory(path)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def test_capture_is_per_key_and_preserves_provenance(
    private_home: Path,
) -> None:
    cwd = private_home / "work"
    cwd.mkdir()
    update_secret_store(
        private_home / "secret.env",
        {
            "Z4J_SECRET": "m" * 48,
            "Z4J_SESSION_SECRET": "s" * 48,
            "Z4J_AUDIT_CHAIN_SECRET": "a" * 48,
            "Z4J_METRICS_AUTH_TOKEN": "store-token",
        },
    )
    config = private_home / "config.env"
    config.write_text("Z4J_BIND_PORT=9000\n", encoding="utf-8")
    dotenv = cwd / ".env"
    dotenv.write_text("Z4J_BIND_PORT=9100\n", encoding="utf-8")

    snapshot = capture_configuration(
        home=private_home,
        cwd=cwd,
        process_environment={
            "Z4J_SECRET": "e" * 48,
            "Z4J_DATABASE_URL": "sqlite+aiosqlite:///:memory:",
            "Z4J_ENVIRONMENT": "dev",
        },
    )

    assert snapshot.values["Z4J_SECRET"] == "e" * 48
    assert snapshot.source_for_field("secret") == "env (Z4J_SECRET)"
    assert snapshot.values["Z4J_AUDIT_CHAIN_SECRET"] == "a" * 48
    assert snapshot.source_for_field("audit_chain_secret") == "secret.env"
    assert snapshot.values["Z4J_BIND_PORT"] == "9100"
    assert snapshot.source_for_field("bind_port") == ".env"
    settings = settings_from_snapshot(snapshot)
    assert settings.bind_port == 9100


def test_structured_postgres_credentials_preserve_url_delimiters(
    private_home: Path,
) -> None:
    cwd = private_home / "work"
    cwd.mkdir()
    password = "r4:p@ss/word%"

    snapshot = capture_configuration(
        home=private_home,
        cwd=cwd,
        process_environment={
            "Z4J_SECRET": "m" * 48,
            "Z4J_SESSION_SECRET": "s" * 48,
            "Z4J_AUDIT_CHAIN_SECRET": "a" * 48,
            "Z4J_ENVIRONMENT": "dev",
            "Z4J_DATABASE_HOST": "z4j-postgres",
            "Z4J_DATABASE_PORT": "5432",
            "Z4J_DATABASE_USER": "z4j",
            "Z4J_DATABASE_PASSWORD": password,
            "Z4J_DATABASE_NAME": "z4j",
        },
        include_secret_store=False,
    )

    parsed = make_url(snapshot.values["Z4J_DATABASE_URL"])
    assert parsed.drivername == "postgresql+asyncpg"
    assert parsed.username == "z4j"
    assert parsed.password == password
    assert parsed.host == "z4j-postgres"
    assert parsed.port == 5432
    assert parsed.database == "z4j"
    assert snapshot.source_for_env_key("Z4J_DATABASE_URL").startswith("derived")
    assert (
        not {
            "Z4J_DATABASE_HOST",
            "Z4J_DATABASE_PORT",
            "Z4J_DATABASE_USER",
            "Z4J_DATABASE_PASSWORD",
            "Z4J_DATABASE_NAME",
        }
        & snapshot.values.keys()
    )
    assert settings_from_snapshot(snapshot).database_url == snapshot.values["Z4J_DATABASE_URL"]


def test_structured_postgres_credentials_refuse_partial_input(
    private_home: Path,
) -> None:
    cwd = private_home / "work"
    cwd.mkdir()

    with pytest.raises(ConfigurationCaptureError, match="incomplete structured"):
        capture_configuration(
            home=private_home,
            cwd=cwd,
            process_environment={
                "Z4J_DATABASE_HOST": "z4j-postgres",
                "Z4J_DATABASE_PASSWORD": "secret",
            },
            include_secret_store=False,
        )


def test_explicit_database_url_wins_over_structured_input(
    private_home: Path,
) -> None:
    cwd = private_home / "work"
    cwd.mkdir()
    explicit = "sqlite+aiosqlite:///:memory:"

    snapshot = capture_configuration(
        home=private_home,
        cwd=cwd,
        process_environment={
            "Z4J_DATABASE_URL": explicit,
            "Z4J_DATABASE_HOST": "ignored",
            "Z4J_DATABASE_PASSWORD": "ignored",
        },
        include_secret_store=False,
    )

    assert snapshot.values["Z4J_DATABASE_URL"] == explicit
    assert snapshot.source_for_env_key("Z4J_DATABASE_URL") == "env (Z4J_DATABASE_URL)"
    assert not any(
        key.startswith("Z4J_DATABASE_") and key != "Z4J_DATABASE_URL" for key in snapshot.values
    )


def test_comments_are_allowed_but_malformed_and_duplicates_refuse(
    private_home: Path,
) -> None:
    cwd = private_home / "work"
    cwd.mkdir()
    config = private_home / "config.env"
    config.write_text("# comment\n\nZ4J_BIND_PORT=9000\n", encoding="utf-8")
    capture_configuration(
        home=private_home,
        cwd=cwd,
        process_environment={},
        include_secret_store=False,
    )

    for content in (
        "Z4J_BIND_PORT\n",
        "Z4J_BIND_PORT=9000\nz4j_bind_port=9001\n",
        "this is not dotenv\n",
    ):
        config.write_text(content, encoding="utf-8")
        with pytest.raises(ConfigurationCaptureError):
            capture_configuration(
                home=private_home,
                cwd=cwd,
                process_environment={},
                include_secret_store=False,
            )


def test_explicit_file_with_secret_requires_private_mode(
    private_home: Path,
) -> None:
    cwd = private_home / "work"
    cwd.mkdir()
    config = private_home / "config.env"
    if os.name == "posix":
        config.write_text(
            "Z4J_AUDIT_CHAIN_SECRET=" + "a" * 48 + "\n",
            encoding="utf-8",
        )
        config.chmod(0o644)
        expected = "owner-private"
        cleanup = None
    else:
        # A same-volume move retains the source file's permissive inherited
        # DACL, so this exercises the real native ACL validator without a
        # locale-sensitive ``icacls`` subprocess.
        permissive = Path(
            tempfile.mkdtemp(prefix="z4j-config-permissive-", dir="/tmp"),
        )
        _grant_windows_everyone(permissive)
        source = permissive / "config.env"
        source.write_text(
            "Z4J_AUDIT_CHAIN_SECRET=" + "a" * 48 + "\n",
            encoding="utf-8",
        )
        source.replace(config)
        expected = "non-owner trustee"
        cleanup = permissive
    try:
        with pytest.raises(ConfigurationCaptureError, match=expected):
            capture_configuration(
                home=private_home,
                cwd=cwd,
                process_environment={},
                include_secret_store=False,
            )
    finally:
        if cleanup is not None:
            shutil.rmtree(cleanup, ignore_errors=True)


@pytest.mark.skipif(os.name != "nt", reason="native Windows ACL oracle")
def test_windows_private_explicit_secret_file_is_accepted(
    private_home: Path,
) -> None:
    cwd = private_home / "work"
    cwd.mkdir()
    config = private_home / "config.env"
    config.write_text(
        "Z4J_AUDIT_CHAIN_SECRET=" + "a" * 48 + "\n",
        encoding="utf-8",
    )

    snapshot = capture_configuration(
        home=private_home,
        cwd=cwd,
        process_environment={},
        include_secret_store=False,
    )

    assert snapshot.values["Z4J_AUDIT_CHAIN_SECRET"] == "a" * 48


@pytest.mark.skipif(os.name != "posix", reason="POSIX link oracle")
def test_symlink_refuses_before_values_escape(
    private_home: Path,
) -> None:
    cwd = private_home / "work"
    cwd.mkdir()
    target = private_home / "target.env"
    target.write_text(
        "Z4J_DATABASE_URL=sqlite+aiosqlite:///attacker.db\n"
        "Z4J_AUDIT_CHAIN_SECRET=" + "a" * 48 + "\n",
        encoding="utf-8",
    )
    (private_home / "config.env").symlink_to(target)
    with pytest.raises(ConfigurationCaptureError, match="regular file"):
        capture_configuration(
            home=private_home,
            cwd=cwd,
            process_environment={},
            include_secret_store=False,
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX link oracle")
def test_config_validate_uses_identity_stable_reader(
    private_home: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = private_home / "candidate-target.env"
    target.write_text(
        "Z4J_DATABASE_URL=sqlite+aiosqlite:///:memory:\n"
        "Z4J_SECRET=" + "m" * 48 + "\n"
        "Z4J_SESSION_SECRET=" + "s" * 48 + "\n"
        "Z4J_AUDIT_CHAIN_SECRET=" + "a" * 48 + "\n"
        "Z4J_ENVIRONMENT=dev\n"
        "Z4J_BIND_PORT=9123\n",
        encoding="utf-8",
    )
    candidate = private_home / "candidate.env"
    candidate.symlink_to(target)

    assert cli._run_config_validate(Namespace(path=str(candidate))) == 2
    captured = capsys.readouterr()
    assert "cannot safely capture" in captured.err
    assert "regular file, not a link" in captured.err
    assert "is valid" not in captured.out


def test_config_validate_reuses_private_secret_policy(
    private_home: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    candidate = private_home / "candidate.env"
    if os.name == "posix":
        candidate.write_text(
            "Z4J_AUDIT_CHAIN_SECRET=" + "a" * 48 + "\n",
            encoding="utf-8",
        )
        candidate.chmod(0o644)
        expected = "owner-private"
        cleanup = None
    else:
        permissive = Path(
            tempfile.mkdtemp(prefix="z4j-validate-permissive-", dir="/tmp"),
        )
        _grant_windows_everyone(permissive)
        source = permissive / "candidate.env"
        source.write_text(
            "Z4J_AUDIT_CHAIN_SECRET=" + "a" * 48 + "\n",
            encoding="utf-8",
        )
        source.replace(candidate)
        expected = "non-owner trustee"
        cleanup = permissive
    try:
        assert cli._run_config_validate(Namespace(path=str(candidate))) == 2
        assert expected in capsys.readouterr().err
    finally:
        if cleanup is not None:
            shutil.rmtree(cleanup, ignore_errors=True)


def test_config_validate_rejects_unknown_z4j_key(
    private_home: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    candidate = private_home / "candidate.env"
    candidate.write_text("Z4J_TOTALLY_MADE_UP=value\n", encoding="utf-8")

    assert cli._run_config_validate(Namespace(path=str(candidate))) == 1
    assert "unsupported setting key" in capsys.readouterr().err


def test_config_validate_accepts_non_settings_runtime_tunables(
    private_home: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    candidate = private_home / "candidate.env"
    candidate.write_text(
        "Z4J_AUTO_MIGRATE=false\nZ4J_ALEMBIC_INI=/srv/z4j/alembic.ini\nZ4J_DEBUG_HOST_ERRORS=off\n",
        encoding="utf-8",
    )

    assert cli._run_config_validate(Namespace(path=str(candidate))) == 0
    assert "3 setting(s) parsed" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("Z4J_AUTO_MIGRATE", "flase"),
        ("Z4J_AUTO_MIGRATE", "' false '"),
        ("Z4J_DEBUG_HOST_ERRORS", "sometimes"),
        ("Z4J_DEBUG_HOST_ERRORS", "' true '"),
        ("Z4J_ALEMBIC_INI", ""),
    ),
)
def test_config_validate_rejects_invalid_non_settings_tunable(
    private_home: Path,
    capsys: pytest.CaptureFixture[str],
    key: str,
    value: str,
) -> None:
    candidate = private_home / "candidate.env"
    candidate.write_text(f"{key}={value}\n", encoding="utf-8")

    assert cli._run_config_validate(Namespace(path=str(candidate))) == 1
    assert key in capsys.readouterr().err


def test_config_validate_uses_startup_json_decoder_for_composites(
    private_home: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    candidate = private_home / "candidate.env"
    candidate.write_text(
        'Z4J_ALLOWED_HOSTS=["z4j.example.com"]\nZ4J_CORS_ORIGINS=["https://z4j.example.com"]\n',
        encoding="utf-8",
    )

    assert cli._run_config_validate(Namespace(path=str(candidate))) == 0
    captured = capsys.readouterr()
    assert "tunables are valid" in captured.out
    assert "runtime bootstrap sources not checked" in captured.out


def test_dashboard_dotenv_quoting_survives_the_startup_reader(
    private_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = private_home / "dashboard-copy.env"
    candidate.write_text(
        'Z4J_EMBEDDED_SCHEDULER_ARGV=\'["serve","--label=a # b","O\\\'Brien","${HOME}"]\'\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", "/must-not-expand")

    parsed = capture_explicit_configuration_file(candidate)

    assert parsed["Z4J_EMBEDDED_SCHEDULER_ARGV"] == (
        '["serve","--label=a # b","O\'Brien","${HOME}"]'
    )


def test_generated_init_template_is_a_valid_tunables_candidate(
    private_home: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "z4j_home", lambda: private_home)
    monkeypatch.setattr(cli, "ensure_z4j_home", lambda: private_home.mkdir(exist_ok=True))

    assert cli._run_init(Namespace(force=False)) == 0
    capsys.readouterr()
    candidate = private_home / "config.env"
    assert candidate.stat().st_mode & 0o777 == 0o644
    assert "Z4J_FIRST_BOOT_ATTEMPTS_PER_IP=30" in candidate.read_text(encoding="utf-8")
    assert "Z4J_MAX_PAYLOAD_SIZE_BYTES=8192" in candidate.read_text(encoding="utf-8")
    assert "Z4J_MAX_WS_FRAME_BYTES=1048576" in candidate.read_text(encoding="utf-8")
    assert "Z4J_WS_MAX_FRAME_BYTES=1048576" in candidate.read_text(encoding="utf-8")
    assert "Z4J_RATELIMIT_FIRST_BOOT_ATTEMPTS_PER_IP" not in candidate.read_text(encoding="utf-8")
    assert cli._run_config_validate(Namespace(path=str(candidate))) == 0


def _clear_z4j_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in tuple(os.environ):
        if key.startswith("Z4J_"):
            monkeypatch.delenv(key, raising=False)


def test_fresh_sqlite_bootstrap_mints_four_independent_secrets(
    private_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_z4j_environment(monkeypatch)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.chdir(private_home)

    snapshot = cli._capture_serve_configuration()

    keys = (
        "Z4J_SECRET",
        "Z4J_SESSION_SECRET",
        "Z4J_METRICS_AUTH_TOKEN",
        "Z4J_AUDIT_CHAIN_SECRET",
    )
    values = [snapshot.values[key] for key in keys]
    assert len(set(values)) == len(values)
    assert all(snapshot.source_for_env_key(key) == "secret.env" for key in keys)


def test_existing_sqlite_without_store_refuses_replacement_keys(
    private_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_z4j_environment(monkeypatch)
    database = private_home / "z4j.db"
    database.touch()
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.setenv("Z4J_DATABASE_URL", f"sqlite+aiosqlite:///{database}")
    monkeypatch.setenv("Z4J_SECRET", "m" * 48)
    monkeypatch.setenv("Z4J_SESSION_SECRET", "s" * 48)
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", "a" * 48)
    monkeypatch.chdir(private_home)

    with pytest.raises(RuntimeError, match="no verified"):
        cli._capture_serve_configuration()


def test_pre_1_8_store_upgrade_adds_only_missing_audit_key(
    private_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_z4j_environment(monkeypatch)
    database = private_home / "z4j.db"
    database.touch()
    original = {
        "Z4J_SECRET": "m" * 48,
        "Z4J_SESSION_SECRET": "s" * 48,
        "Z4J_METRICS_AUTH_TOKEN": "metrics-winner",
    }
    update_secret_store(private_home / "secret.env", original)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.setenv("Z4J_DATABASE_URL", f"sqlite+aiosqlite:///{database}")
    monkeypatch.chdir(private_home)

    snapshot = cli._capture_serve_configuration()

    winner = capture_configuration(home=private_home, cwd=private_home)
    assert {key: winner.values[key] for key in original} == original
    assert winner.values["Z4J_AUDIT_CHAIN_SECRET"]
    assert snapshot.values["Z4J_AUDIT_CHAIN_SECRET"] == winner.values["Z4J_AUDIT_CHAIN_SECRET"]


def test_pre_1_8_management_upgrade_adds_missing_audit_key(
    private_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The documented Compose ceremony must bootstrap the same stored key."""
    _clear_z4j_environment(monkeypatch)
    database = private_home / "z4j.db"
    database.touch()
    original = {
        "Z4J_SECRET": "m" * 48,
        "Z4J_SESSION_SECRET": "s" * 48,
        "Z4J_METRICS_AUTH_TOKEN": "metrics-winner",
    }
    update_secret_store(private_home / "secret.env", original)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.setenv("Z4J_DATABASE_URL", f"sqlite+aiosqlite:///{database}")
    monkeypatch.setenv("Z4J_ENVIRONMENT", "production")
    monkeypatch.chdir(private_home)

    snapshot = cli._bootstrap_env_for_management_commands()

    winner = capture_configuration(home=private_home, cwd=private_home)
    assert {key: winner.values[key] for key in original} == original
    assert winner.values["Z4J_AUDIT_CHAIN_SECRET"]
    assert snapshot.values["Z4J_AUDIT_CHAIN_SECRET"] == (winner.values["Z4J_AUDIT_CHAIN_SECRET"])


def test_metrics_rotation_refuses_shadow_and_preserves_full_store(
    private_home: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _clear_z4j_environment(monkeypatch)
    original = {
        "Z4J_SECRET": "m" * 48,
        "Z4J_SESSION_SECRET": "s" * 48,
        "Z4J_METRICS_AUTH_TOKEN": "old-store-token",
        "Z4J_AUDIT_CHAIN_SECRET": "a" * 48,
    }
    update_secret_store(private_home / "secret.env", original)
    monkeypatch.setenv("Z4J_HOME", str(private_home))
    monkeypatch.chdir(private_home)
    monkeypatch.setenv("Z4J_METRICS_AUTH_TOKEN", "explicit-winner")

    assert cli._run_metrics_token_rotate(object()) == 2
    assert "effective token source is env" in capsys.readouterr().err
    assert (
        capture_configuration(home=private_home, cwd=private_home).values["Z4J_METRICS_AUTH_TOKEN"]
        == "explicit-winner"
    )

    monkeypatch.delenv("Z4J_METRICS_AUTH_TOKEN")
    assert cli._run_metrics_token_rotate(object()) == 0
    rotated = capsys.readouterr().out.strip()
    winner = capture_configuration(home=private_home, cwd=private_home)
    assert winner.values["Z4J_METRICS_AUTH_TOKEN"] == rotated
    assert winner.values["Z4J_SECRET"] == original["Z4J_SECRET"]
    assert winner.values["Z4J_AUDIT_CHAIN_SECRET"] == original["Z4J_AUDIT_CHAIN_SECRET"]


def test_doctor_does_not_call_disabled_metrics_public(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The public flag has no effect when the endpoint is not mounted."""
    monkeypatch.setenv("Z4J_METRICS_ENABLED", "false")
    monkeypatch.setenv("Z4J_METRICS_PUBLIC", "true")
    monkeypatch.setattr(cli, "_run_check", lambda _args: 0)
    monkeypatch.setattr(
        cli,
        "_build_settings_from_env",
        lambda: (_ for _ in ()).throw(RuntimeError("stop after static warnings")),
    )

    assert cli._run_doctor(Namespace()) == 0
    output = capsys.readouterr().out
    assert "Z4J_METRICS_PUBLIC=1 is set" not in output
