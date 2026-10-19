"""PostgreSQL quarantine requires backup acknowledgement, even with --apply.

The real command/parser run against a fake DB that records SQL; no live
cleanup, backup or PostgreSQL connection is performed.
"""

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from z4j_brain import cli


@pytest.mark.parametrize("apply", [False, True])
@pytest.mark.parametrize("acknowledged", [False, True])
def test_postgres_cleanup_requires_separate_backup_acknowledgement(
    monkeypatch, capsys, apply, acknowledged
):
    mutations = []
    committed = Mock()

    class Session:
        async def execute(self, statement):
            sql = str(statement)
            if sql.startswith(("CREATE", "INSERT", "DELETE")):
                mutations.append(sql)
            return SimpleNamespace(
                fetchall=lambda: [("same-hmac", 2)], rowcount=1, scalar=lambda: 0
            )

        async def commit(self):
            committed()

    class Database:
        def __init__(self, engine):
            pass

        @asynccontextmanager
        async def session(self, **kwargs):
            yield Session()

        async def dispose(self):
            pass

    monkeypatch.setattr(cli, "_bootstrap_env_for_management_commands", lambda: None)
    monkeypatch.setattr(cli, "_has_boundary_f_audit_authority", AsyncMock(return_value=False))
    monkeypatch.setattr(
        "z4j_brain.settings.Settings",
        lambda: SimpleNamespace(database_url="postgresql+asyncpg://unused/unused"),
    )
    monkeypatch.setattr(
        "z4j_brain.persistence.database.create_engine_from_settings", lambda settings: None
    )
    monkeypatch.setattr("z4j_brain.persistence.database.DatabaseManager", Database)
    prompt = Mock(return_value="y")
    monkeypatch.setattr("builtins.input", prompt)
    args = [
        "audit",
        "fork-cleanup",
        *(["--apply"] if apply else []),
        *(["--no-backup"] if acknowledged else []),
    ]
    assert cli.main(args) == (0 if acknowledged else 2)
    if acknowledged:
        assert len(mutations) == 3
        committed.assert_called_once()
    else:
        assert mutations == []
        committed.assert_not_called()
        prompt.assert_not_called()
        assert "--no-backup" in capsys.readouterr().err
