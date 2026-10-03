"""``z4j migrate prepare-runtime-rollback --help`` prints without any environment.

The ceremony has its own argument parser, but ``_run_migrate`` used to run the
Z4J_HOME bootstrap before dispatching to it, so a bare shell asking for help
got the bootstrap's failure instead of the usage text. Help and usage errors
now come from argparse alone; the bootstrap runs only once the arguments have
been accepted, which the last test here proves by making it the first thing
that fails.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from z4j_brain import cli


@pytest.fixture
def bare_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for key in tuple(os.environ):
        if key.startswith("Z4J_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        cli,
        "_bootstrap_env_for_management_commands",
        lambda **_kwargs: pytest.fail("--help must not bootstrap the environment"),
    )


@pytest.mark.usefixtures("bare_environment")
def test_help_prints_the_ceremony_usage(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["migrate", "prepare-runtime-rollback", "--help"])

    assert exit_info.value.code == 0
    out = capsys.readouterr().out
    assert "usage: z4j migrate prepare-runtime-rollback" in out
    for flag in (
        "--target",
        "--target-image",
        "--candidate-authority-root",
        "--rollback-evidence-root",
        "--stopped-executors-challenge",
    ):
        assert flag in out


@pytest.mark.usefixtures("bare_environment")
def test_usage_error_is_argparse_not_a_bootstrap_failure(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["migrate", "prepare-runtime-rollback", "--target", "x"])

    assert exit_info.value.code == 2
    err = capsys.readouterr().err
    assert "the following arguments are required" in err
    assert "Traceback" not in err


def test_accepted_arguments_still_bootstrap_before_any_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Positive control: the bootstrap moved after parsing, it did not vanish."""

    class _BootstrappedError(RuntimeError):
        pass

    def bootstrap(**_kwargs: object) -> None:
        raise _BootstrappedError

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_bootstrap_env_for_management_commands", bootstrap)

    with pytest.raises(_BootstrappedError):
        cli.main(
            [
                "migrate",
                "prepare-runtime-rollback",
                "--target",
                "anything",
                "--target-image",
                "registry/image@sha256:" + "0" * 64,
                "--candidate-authority-root",
                str(tmp_path / "authority"),
                "--rollback-evidence-root",
                str(tmp_path / "evidence"),
            ]
        )
