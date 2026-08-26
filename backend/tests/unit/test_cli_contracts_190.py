"""Release-1.9 CLI contract and fail-closed regressions."""

from __future__ import annotations

import importlib.metadata
import inspect
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from pydantic import SecretStr
from z4j_brain import cli


class _PyPIResponse:
    status_code = 200

    def __init__(self, latest: str) -> None:
        self._latest = latest

    def json(self) -> dict[str, dict[str, str]]:
        return {"info": {"version": self._latest}}

    def raise_for_status(self) -> None:
        return None


class _PyPIClient:
    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

    def __enter__(self) -> _PyPIClient:
        return self

    def __exit__(self, *args: object) -> None:
        del args

    def get(self, url: str) -> _PyPIResponse:
        if "/z4j-brain/" in url:
            raise httpx.ConnectError("offline")
        return _PyPIResponse("2.0.0")


def _patch_upgrade_catalogue(
    monkeypatch: pytest.MonkeyPatch,
    packages: set[str],
    installed: str,
) -> None:
    from z4j_brain.domain import version_check

    monkeypatch.setattr(
        version_check,
        "load_bundled",
        lambda: SimpleNamespace(packages=packages),
    )
    monkeypatch.setattr(importlib.metadata, "version", lambda _package: installed)
    monkeypatch.setattr(httpx, "Client", _PyPIClient)


def test_upgrade_does_not_call_an_installed_newer_version_behind(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _patch_upgrade_catalogue(monkeypatch, {"z4j"}, "3.0.0")

    assert cli.main(["upgrade", "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["behind_count"] == 0
    assert payload["newer_count"] == 1
    assert payload["rows"][0]["status"] == "newer"
    assert payload["rows"][0]["behind"] is False


@pytest.mark.parametrize("apply", [False, True])
def test_upgrade_lookup_failure_wins_over_a_simultaneous_behind_result(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    apply: bool,
) -> None:
    _patch_upgrade_catalogue(monkeypatch, {"z4j", "z4j-brain"}, "1.0.0")
    monkeypatch.setattr(
        "subprocess.run",
        lambda *_args, **_kwargs: pytest.fail("an incomplete scan must not mutate the venv"),
    )

    argv = ["upgrade", "--json"]
    if apply:
        argv.append("--apply")
    assert cli.main(argv) == 2

    payload = json.loads(capsys.readouterr().out)
    assert payload["behind_count"] == 1
    assert payload["network_error"] is not None
    assert {row["status"] for row in payload["rows"]} == {
        "behind",
        "lookup failed",
    }


def test_config_show_masks_typed_and_plain_string_secret_carriers(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    from z4j_brain import configuration

    settings = SimpleNamespace(
        model_fields={
            "api_key": object(),
            "database_url": object(),
            "first_boot_token_ttl_seconds": object(),
            "secret": object(),
        },
        api_key="plain-api-key-value",
        database_url="postgresql+asyncpg://alice:swordfish@db.example/z4j",
        first_boot_token_ttl_seconds=900,
        secret=SecretStr("typed-secret-value"),
    )
    monkeypatch.setattr(configuration, "capture_configuration", object)
    monkeypatch.setattr(configuration, "export_snapshot_environment", lambda _snapshot: None)
    monkeypatch.setattr(configuration, "settings_from_snapshot", lambda _snapshot: settings)
    monkeypatch.setattr(cli, "_config_source", lambda *_args: "secret.env")
    monkeypatch.setattr(cli, "z4j_home", lambda: tmp_path)

    assert cli.main(["config", "show"]) == 0

    output = capsys.readouterr().out
    assert "plain-api-key-value" not in output
    assert "alice" not in output
    assert "swordfish" not in output
    assert "typed-secret-value" not in output
    assert "first_boot_token_ttl_seconds  900" in output
    assert output.count("***") == 3


def test_auto_migrate_fails_closed_when_no_config_exists(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    fake_module = tmp_path / "installed" / "z4j_brain" / "cli.py"
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("Z4J_ALEMBIC_INI", raising=False)
    monkeypatch.setattr(cli, "__file__", str(fake_module))

    with pytest.raises(SystemExit) as raised:
        cli._auto_migrate()

    assert raised.value.code == 2
    assert "failed closed (alembic.ini not found)" in capsys.readouterr().err


def _help(capsys: pytest.CaptureFixture[str], *args: str) -> str:
    with pytest.raises(SystemExit) as raised:
        cli.main([*args, "--help"])
    assert raised.value.code == 0
    return capsys.readouterr().out


def test_operator_help_matches_destructive_and_worker_boundaries(
    capsys: pytest.CaptureFixture[str],
) -> None:
    root_help = _help(capsys)
    normalized_root_help = " ".join(root_help.split())
    assert "reset [--all]" not in root_help
    assert "reset --force" in root_help
    assert "total row counts" in normalized_root_help
    assert "recent task activity" not in root_help

    serve_help = _help(capsys, "serve")
    assert "always force one worker" in serve_help

    migrate_help = _help(capsys, "migrate")
    assert "does not remove newer columns" in migrate_help

    reset_help = _help(capsys, "reset")
    assert "explicitly recoverable retirement bundle" in reset_help


def test_audit_metrics_and_token_docs_state_the_real_aggregation_and_precedence() -> None:
    audit_doc = inspect.getdoc(cli._run_audit_verify) or ""
    metrics_doc = inspect.getdoc(cli._setup_multiprocess_metrics_env) or ""
    token_doc = inspect.getdoc(cli._run_metrics_token_show) or ""

    assert "not as independent" in audit_doc
    assert "per-row HMACs" in audit_doc
    assert "next successful scrape" in metrics_doc
    assert "./.env" in token_doc
    assert "~/.z4j/config.env" in token_doc
    assert token_doc.index("./.env") < token_doc.index("~/.z4j/config.env")
    assert token_doc.index("~/.z4j/config.env") < token_doc.index("~/.z4j/secret.env")

    source_doc = inspect.getdoc(cli._config_source) or ""
    assert "report ``secret.env`` for a secret field" in source_doc


def test_status_labels_are_total_rows_and_stored_revision() -> None:
    source = inspect.getsource(cli._run_status)
    assert "alembic revision" in source
    assert "active sessions" not in source
    assert "sessions" in source
