"""Executable contract for libpq-style TLS on SQLAlchemy's asyncpg dialect."""

from __future__ import annotations

import asyncio
import inspect
import os
import ssl
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock
from urllib.parse import quote

import asyncpg
import pytest
from sqlalchemy.dialects.postgresql.asyncpg import PGDialect_asyncpg
from sqlalchemy.engine import make_url
from z4j_brain.persistence import database
from z4j_brain.postgres_tls import (
    PostgresTLSConfigurationError,
    asyncpg_dsn_and_connect_args,
    asyncpg_engine_url_and_connect_args,
    parse_asyncpg_tls_options,
)
from z4j_brain.websocket.dashboard_hub.postgres_notify import (
    PostgresNotifyDashboardHub,
)
from z4j_brain.websocket.registry.postgres_notify import PostgresNotifyRegistry


def _query_path(path: Path) -> str:
    return quote(str(path), safe="")


def test_negative_control_raw_sqlalchemy_url_passes_unsupported_sslmode() -> None:
    """Pin the exact pre-fix failure instead of only asserting new output."""

    dialect = PGDialect_asyncpg()
    raw_url = make_url(
        "postgresql+asyncpg://user:password@db/z4j?sslmode=require&target_session_attrs=read-write",
    )
    _, raw_kwargs = dialect.create_connect_args(raw_url)

    assert raw_kwargs["sslmode"] == "require"
    assert "sslmode" not in inspect.signature(asyncpg.connect).parameters

    normalized_url, connect_args = asyncpg_engine_url_and_connect_args(
        raw_url.render_as_string(hide_password=False),
    )
    _, normalized_kwargs = dialect.create_connect_args(make_url(normalized_url))
    assert "sslmode" not in normalized_kwargs
    assert normalized_kwargs["target_session_attrs"] == "read-write"
    assert isinstance(connect_args["ssl"], ssl.SSLContext)


def test_normalization_preserves_unrelated_and_repeated_query_values() -> None:
    normalized_url, connect_args = asyncpg_engine_url_and_connect_args(
        "postgresql+asyncpg://u:p@h/d?sslmode=require&server_setting=one&server_setting=two",
    )
    normalized = make_url(normalized_url)

    assert "sslmode" not in normalized.query
    assert normalized.query["server_setting"] == ("one", "two")
    assert isinstance(connect_args["ssl"], ssl.SSLContext)


def test_raw_asyncpg_dsn_uses_the_same_normalized_tls_bridge() -> None:
    dsn, connect_args = asyncpg_dsn_and_connect_args(
        "postgresql+asyncpg://u:p@h/d?SsLmOdE=ReQuIrE&server_setting=one",
    )
    parsed = make_url(dsn)

    assert parsed.drivername == "postgresql"
    assert parsed.query == {"server_setting": "one"}
    assert isinstance(connect_args["ssl"], ssl.SSLContext)


def test_require_encrypts_without_claiming_server_identity() -> None:
    _, connect_args = asyncpg_engine_url_and_connect_args(
        "postgresql+asyncpg://u:p@h/d?sslmode=require",
    )
    context = connect_args["ssl"]

    assert isinstance(context, ssl.SSLContext)
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False


class _FakeSSLContext:
    def __init__(self, _protocol: Any) -> None:
        self.minimum_version: Any = None
        self.check_hostname = True
        self.verify_mode = ssl.CERT_REQUIRED
        self.loaded_roots: list[str] = []
        self.loaded_chain: tuple[str, str] | None = None

    def load_verify_locations(self, *, cafile: str) -> None:
        self.loaded_roots.append(cafile)

    def load_cert_chain(self, *, certfile: str, keyfile: str) -> None:
        self.loaded_chain = (certfile, keyfile)


@pytest.mark.parametrize(
    ("mode", "hostname_checked"),
    [("verify-ca", False), ("verify-full", True)],
)
def test_verifying_modes_load_explicit_root_and_set_honest_semantics(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mode: str,
    hostname_checked: bool,
) -> None:
    root = tmp_path / "root.pem"
    root.write_text("test root", encoding="utf-8")
    monkeypatch.setattr("z4j_brain.postgres_tls.ssl.SSLContext", _FakeSSLContext)

    normalized_url, connect_args = asyncpg_engine_url_and_connect_args(
        f"postgresql+asyncpg://u:p@db.example/d?sslmode={mode}&sslrootcert={_query_path(root)}",
    )
    context = connect_args["ssl"]

    assert make_url(normalized_url).query == {}
    assert isinstance(context, _FakeSSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is hostname_checked
    assert context.loaded_roots == [str(root.resolve())]


def test_require_with_explicit_root_verifies_the_certificate_chain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "root.pem"
    root.write_text("test root", encoding="utf-8")
    monkeypatch.setattr("z4j_brain.postgres_tls.ssl.SSLContext", _FakeSSLContext)

    _, connect_args = asyncpg_engine_url_and_connect_args(
        f"postgresql+asyncpg://u:p@h/d?sslmode=require&sslrootcert={_query_path(root)}",
    )
    context = connect_args["ssl"]

    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is False


def test_verify_modes_refuse_missing_or_unreadable_root(tmp_path: Path) -> None:
    with pytest.raises(PostgresTLSConfigurationError, match="explicit sslrootcert"):
        parse_asyncpg_tls_options(
            "postgresql+asyncpg://u:p@h/d?sslmode=verify-full",
        )

    missing = tmp_path / "missing.pem"
    with pytest.raises(PostgresTLSConfigurationError, match="does not exist"):
        asyncpg_engine_url_and_connect_args(
            f"postgresql+asyncpg://u:p@h/d?sslmode=verify-ca&sslrootcert={_query_path(missing)}",
        )


def test_invalid_root_certificate_is_rejected(tmp_path: Path) -> None:
    invalid = tmp_path / "not-a-certificate.pem"
    invalid.write_text("not a certificate", encoding="utf-8")

    with pytest.raises(PostgresTLSConfigurationError, match="cannot be loaded"):
        asyncpg_engine_url_and_connect_args(
            f"postgresql+asyncpg://u:p@h/d?sslmode=verify-ca&sslrootcert={_query_path(invalid)}",
        )


def test_client_certificate_and_key_are_atomic_and_owner_private(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    certificate = tmp_path / "client.pem"
    certificate.write_text("test certificate", encoding="utf-8")
    key = tmp_path / "client.key"
    key.write_text("test key", encoding="utf-8")

    with pytest.raises(PostgresTLSConfigurationError, match="supplied together"):
        parse_asyncpg_tls_options(
            f"postgresql+asyncpg://u:p@h/d?sslmode=require&sslcert={_query_path(certificate)}",
        )

    if os.name != "nt":
        key.chmod(0o644)
        with pytest.raises(PostgresTLSConfigurationError, match="group or others"):
            asyncpg_engine_url_and_connect_args(
                "postgresql+asyncpg://u:p@h/d?sslmode=require"
                f"&sslcert={_query_path(certificate)}&sslkey={_query_path(key)}",
            )
        key.chmod(0o600)

    monkeypatch.setattr("z4j_brain.postgres_tls.ssl.SSLContext", _FakeSSLContext)
    _, connect_args = asyncpg_engine_url_and_connect_args(
        "postgresql+asyncpg://u:p@h/d?sslmode=require"
        f"&sslcert={_query_path(certificate)}&sslkey={_query_path(key)}",
    )
    context = connect_args["ssl"]
    assert context.loaded_chain == (str(certificate.resolve()), str(key.resolve()))


@pytest.mark.parametrize(
    ("mode", "expected_ssl"),
    [("disable", False), ("allow", "allow"), ("prefer", "prefer")],
)
def test_non_strict_modes_are_explicitly_translated(
    mode: str,
    expected_ssl: bool | str,
) -> None:
    normalized_url, connect_args = asyncpg_engine_url_and_connect_args(
        f"postgresql+asyncpg://u:p@h/d?sslmode={mode}",
    )

    assert "sslmode" not in make_url(normalized_url).query
    assert connect_args == {"ssl": expected_ssl}


def test_engine_wrapper_merges_connect_args_and_refuses_ssl_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_create_async_engine(url: str, **kwargs: Any) -> object:
        captured.update(url=url, **kwargs)
        return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

    monkeypatch.setattr(database, "create_async_engine", fake_create_async_engine)
    result = database.create_async_engine_from_url(
        "postgresql+asyncpg://u:p@h/d?sslmode=require&command_timeout=7",
        connect_args={"statement_cache_size": 32},
    )

    assert result is not None
    assert make_url(captured["url"]).query == {"command_timeout": "7"}
    assert captured["connect_args"]["statement_cache_size"] == 32
    assert isinstance(captured["connect_args"]["ssl"], ssl.SSLContext)

    with pytest.raises(ValueError, match="conflict"):
        database.create_async_engine_from_url(
            "postgresql+asyncpg://u:p@h/d?sslmode=require",
            connect_args={"ssl": False},
        )


@pytest.mark.asyncio
async def test_settings_engine_path_uses_the_normalized_url() -> None:
    import secrets

    from z4j_brain.persistence.database import create_engine_from_settings
    from z4j_brain.settings import Settings

    settings = Settings(  # type: ignore[arg-type]
        database_url=(
            "postgresql+asyncpg://u:p@h/d?sslmode=require&target_session_attrs=read-write"
        ),
        secret=secrets.token_urlsafe(48),
        session_secret=secrets.token_urlsafe(48),
        environment="dev",
    )
    engine = create_engine_from_settings(settings)
    try:
        assert "sslmode" not in engine.url.query
        assert engine.url.query["target_session_attrs"] == "read-write"
    finally:
        await engine.dispose()


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+asyncpg://u:p@h/d?sslmode=require&sslmode=prefer",
        "postgresql+asyncpg://u:p@h/d?sslmode=unknown",
        "postgresql+asyncpg://u:p@h/d?sslmode=disable&sslrootcert=/ca.pem",
        "postgresql+asyncpg://u:p@h/d?sslrootcert=/ca.pem",
    ],
)
def test_ambiguous_or_invalid_tls_query_is_rejected(url: str) -> None:
    with pytest.raises(PostgresTLSConfigurationError):
        parse_asyncpg_tls_options(url)


def test_sqlite_url_is_unchanged() -> None:
    url = "sqlite+aiosqlite:////tmp/z4j.db?timeout=20"
    normalized_url, connect_args = asyncpg_engine_url_and_connect_args(url)

    assert make_url(normalized_url) == make_url(url)
    assert connect_args == {}


@pytest.mark.asyncio
async def test_scheduler_listen_connection_reuses_configured_tls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from z4j_brain.scheduler_grpc.handlers import SchedulerServiceImpl

    connection = SimpleNamespace(
        add_listener=AsyncMock(),
        remove_listener=AsyncMock(),
        close=AsyncMock(),
    )
    connect = AsyncMock(return_value=connection)
    monkeypatch.setattr(asyncpg, "connect", connect)
    service = object.__new__(SchedulerServiceImpl)
    service._settings = SimpleNamespace(
        database_url=(
            "postgresql+asyncpg://watcher:p%40ssword@db.example.test:6543/z4j?sslmode=require"
        ),
    )
    context = SimpleNamespace(cancelled=lambda: True)

    stream = service._watch_via_listen(
        project_filter=None,
        resume_token="",
        context=context,
    )
    with pytest.raises(StopAsyncIteration):
        await anext(stream)

    kwargs = connect.await_args.kwargs
    assert kwargs["host"] == "db.example.test"
    assert kwargs["password"] == "p@ssword"
    assert isinstance(kwargs["ssl"], ssl.SSLContext)
    assert kwargs["ssl"].verify_mode == ssl.CERT_NONE


def _notify_listener(
    kind: str,
    database_url: str,
) -> PostgresNotifyRegistry | PostgresNotifyDashboardHub:
    settings = SimpleNamespace(
        asyncpg_connect_timeout=1.0,
        asyncpg_close_timeout=1.0,
        registry_listener_heartbeat_seconds=1.0,
        registry_listener_heartbeat_timeout_seconds=2.0,
        registry_listener_max_age_seconds=60.0,
    )
    if kind == "registry":

        async def deliver_local(_command_id: object, _websocket: object) -> bool:
            return True

        return PostgresNotifyRegistry(  # type: ignore[arg-type]
            settings=settings,
            db=object(),
            dsn_provider=lambda: database_url,
            deliver_local=deliver_local,
        )
    return PostgresNotifyDashboardHub(  # type: ignore[arg-type]
        settings=settings,
        db=object(),
        dsn_provider=lambda: database_url,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["registry", "dashboard"])
@pytest.mark.parametrize("tls_query", ["sslmode=require", "SsLmOdE=ReQuIrE"])
async def test_notify_listeners_use_normalized_tls_for_canonical_and_case_variants(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    tls_query: str,
) -> None:
    # A strict URL must own its complete TLS policy. The raw-listener path
    # previously let asyncpg consult these ambient libpq variables even when
    # the primary SQLAlchemy engine used the URL-derived context.
    monkeypatch.setenv("PGSSLROOTCERT", "/missing/ambient-postgres-root.pem")
    monkeypatch.setenv("PGSSLCERT", "/missing/ambient-postgres-client.pem")
    monkeypatch.setenv("PGSSLKEY", "/missing/ambient-postgres-client.key")
    connection = SimpleNamespace(
        add_listener=AsyncMock(),
        close=AsyncMock(),
    )
    connect = AsyncMock(return_value=connection)
    monkeypatch.setattr(asyncpg, "connect", connect)
    listener = _notify_listener(
        kind,
        "postgresql+asyncpg://listener:p%40ss@db.example.test:6543/z4j?"
        f"{tls_query}&target_session_attrs=read-write",
    )
    listener._stop_event.set()  # type: ignore[attr-defined]
    if isinstance(listener, PostgresNotifyRegistry):
        listener._reconcile_pending = AsyncMock()  # type: ignore[method-assign]

    await listener._listen_session()  # type: ignore[attr-defined]

    kwargs = connect.await_args.kwargs
    parsed = make_url(kwargs["dsn"])
    assert parsed.drivername == "postgresql"
    assert parsed.password == "p@ss"
    assert parsed.query == {"target_session_attrs": "read-write"}
    assert isinstance(kwargs["ssl"], ssl.SSLContext)
    assert kwargs["ssl"].verify_mode == ssl.CERT_NONE
    connection.close.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["registry", "dashboard"])
async def test_notify_listener_invalid_tls_configuration_does_not_reconnect(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    connect = AsyncMock()
    monkeypatch.setattr(asyncpg, "connect", connect)
    listener = _notify_listener(
        kind,
        "postgresql+asyncpg://u:p@db/z4j?sslmode=require&SsLmOdE=prefer",
    )

    await asyncio.wait_for(
        listener._run_listener_loop(),  # type: ignore[attr-defined]
        timeout=0.2,
    )

    connect.assert_not_awaited()
