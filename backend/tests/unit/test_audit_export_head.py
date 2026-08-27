"""`audit export-head` must produce exactly what `verify --known-head` accepts.

The published mitigation for the disclosed database-writer limitation is to
anchor a chain head outside the database and check it later with
``z4j audit verify --known-head``. That advice is only followable if the product
can hand the operator a head in the form the verifier reads, so the contract
under test is a ROUND TRIP rather than the shape of either half alone.

The negative controls matter as much as the positive one. The verifier's parser
is a closed allow-list of six keys and reports INVALID on a seventh, so anyone
who later adds a signature or an exported_at timestamp to the envelope would be
making a change that reads as an improvement while silently breaking the only
surviving mitigation. The third test exists to stop that.
"""

from __future__ import annotations

import asyncio
import json

from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.cli import main
from z4j_brain.domain.audit_service import AuditService
from z4j_brain.persistence.base import Base
from z4j_brain.settings import Settings

from .test_audit_chain_boundary_f import (  # type: ignore[import-not-found]
    AUDIT,
    MASTER,
    SESSION,
    _activate,
)


def _install(tmp_path, monkeypatch, name: str) -> None:
    """An activated chain with one head, reachable by the CLI.

    Mirrors test_explicit_rotation_cli_commits_marker_and_state's setup, which
    is the established way to drive `main()` against a real file-backed chain.
    """

    database_url = f"sqlite+aiosqlite:///{(tmp_path / name).as_posix()}"
    settings = Settings(
        database_url=database_url,
        secret=MASTER,  # type: ignore[arg-type]
        session_secret=SESSION,  # type: ignore[arg-type]
        audit_chain_secret=AUDIT,  # type: ignore[arg-type]
        environment="dev",
    )

    async def _prepare() -> None:
        engine = create_async_engine(database_url)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        await _activate(engine, AuditService(settings))
        await engine.dispose()

    asyncio.run(_prepare())
    tmp_path.chmod(0o700)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z4J_HOME", str(tmp_path))
    monkeypatch.setenv("Z4J_DATABASE_URL", database_url)
    monkeypatch.setenv("Z4J_SECRET", MASTER)
    monkeypatch.setenv("Z4J_SESSION_SECRET", SESSION)
    monkeypatch.setenv("Z4J_AUDIT_CHAIN_SECRET", AUDIT)
    monkeypatch.setenv("Z4J_ENVIRONMENT", "dev")
    monkeypatch.setenv("Z4J_ALLOWED_HOSTS", '["localhost","127.0.0.1"]')


def _export(capsys) -> tuple[str, dict]:
    assert main(["audit", "export-head"]) == 0
    raw = capsys.readouterr().out.strip()
    return raw, json.loads(raw)


def test_export_head_round_trips_into_verify_known_head(tmp_path, monkeypatch, capsys):
    """The exported envelope verifies as the current head, unmodified."""

    _install(tmp_path, monkeypatch, "roundtrip.db")
    envelope, decoded = _export(capsys)

    assert set(decoded) <= {
        "row_hmac",
        "hmac_version",
        "hmac_key_id",
        "generation",
        "occurred_at",
        "id",
    }
    assert decoded["hmac_version"] == 2
    assert len(decoded["row_hmac"]) == 64
    assert decoded["row_hmac"].lower() == decoded["row_hmac"]

    # The positive control: the file an operator would have written, read back
    # by the command the documentation tells them to run.
    assert main(["audit", "verify", "--known-head", envelope]) == 0
    assert "known-head: CURRENT_MATCH" in capsys.readouterr().out


def test_a_tampered_head_is_not_reported_as_clean(tmp_path, monkeypatch, capsys):
    """One changed character in the anchored head must not pass."""

    _install(tmp_path, monkeypatch, "tampered.db")
    _, decoded = _export(capsys)

    original = decoded["row_hmac"]
    decoded["row_hmac"] = ("b" if original[0] != "b" else "c") + original[1:]

    # Nonzero, because the exit code is what an unattended anchor check pages on.
    assert main(["audit", "verify", "--known-head", json.dumps(decoded)]) == 1
    assert "known-head: UNPROVABLE" in capsys.readouterr().out


def test_the_envelope_may_not_grow_a_seventh_key(tmp_path, monkeypatch, capsys):
    """The parser is a closed allow-list, so nothing may be appended.

    This is the test that stops someone signing or timestamping the export.
    Either would read as an improvement and would make every anchored file
    unreadable by the one command that consumes it.
    """

    _install(tmp_path, monkeypatch, "seventh.db")
    _, decoded = _export(capsys)

    decoded["exported_at"] = "2026-08-26T00:00:00.000000Z"
    assert main(["audit", "verify", "--known-head", json.dumps(decoded)]) == 1
    assert "known-head: INVALID" in capsys.readouterr().out


def test_stdout_carries_the_envelope_and_nothing_else(tmp_path, monkeypatch, capsys):
    """Redirecting stdout must yield a complete file, so notes go to stderr."""

    _install(tmp_path, monkeypatch, "stdout.db")
    captured_out, decoded = _export(capsys)

    # Exactly one line, parseable on its own, with no banner or log mixed in.
    assert "\n" not in captured_out
    assert decoded["row_hmac"]
