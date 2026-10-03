"""Source-address allowlists, driven through the real app over HTTP.

Three lists, one contract: the client IP is whatever the trusted-proxy
resolver produced, the list is consulted after the credential authenticated
(the login route excepted), a refusal is a 403 whose body names only the
surface, and every refusal leaves an ``auth.ip_denied`` audit row and a
``z4j_auth_ip_denied_total{surface}`` increment.

The HTTP tests build the brain on file-backed SQLite with the ORM schema so
they are independent of the migration chain's current head; the migration
itself is covered in ``test_migration.py``.
"""

from __future__ import annotations

import secrets
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.api.metrics import registry
from z4j_brain.auth.csrf import csrf_cookie_name
from z4j_brain.auth.passwords import PasswordHasher
from z4j_brain.domain import ip_allowlist as ipa
from z4j_brain.main import create_app
from z4j_brain.persistence import models  # noqa: F401  register mappers
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models import ApiKey, AuditLog, Project, User
from z4j_brain.settings import Settings

_PW = "correct horse battery staple 9"
_EMAIL = "alice@example.com"

ALLOWED = "203.0.113.7"
DENIED = "198.51.100.9"
ALLOWED_V6 = "2001:db8::7"
DENIED_V6 = "2001:db8:ffff::1"
PROXY = "10.0.0.2"

#: A route an unbound key with ``home:read`` may call.
_BEARER_URL = "/api/v1/home/summary"
_SESSION_URL = "/api/v1/auth/me"


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    return Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'allowlist.sqlite'}",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        disable_spa_fallback=True,
        argon2_time_cost=1,
        argon2_memory_cost=8192,
        login_min_duration_ms=10,
        login_backoff_base_seconds=0.0,
        login_backoff_max_seconds=0.0,
        **overrides,
    )


@asynccontextmanager
async def _brain(tmp_path: Path, **overrides: Any) -> AsyncIterator[tuple[Any, Settings]]:
    settings = _settings(tmp_path, **overrides)
    engine = create_async_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(settings, engine=engine)
    app.state.lifespan_ready = True
    try:
        yield app, settings
    finally:
        await engine.dispose()


def _client(app: Any, ip: str, *, cookies: dict[str, str] | None = None) -> AsyncClient:
    """A client whose socket peer the brain sees as ``ip``."""
    return AsyncClient(
        transport=ASGITransport(app=app, client=(ip, 4321)),
        base_url="http://testserver",
        cookies=cookies,
    )


async def _seed_user(app: Any, settings: Settings) -> uuid.UUID:
    async with app.state.db.session() as session:
        user = User(
            id=uuid.uuid4(),
            email=_EMAIL,
            password_hash=PasswordHasher(settings).hash(_PW),
            display_name="Alice",
            is_admin=False,
            is_active=True,
        )
        session.add(user)
        await session.commit()
        return user.id


async def _seed_key(
    app: Any,
    settings: Settings,
    user_id: uuid.UUID,
    *,
    allowed_cidrs: list[str] | None = None,
) -> tuple[uuid.UUID, str]:
    from z4j_brain.api.api_keys import _hash_api_key

    plaintext = f"z4k_{secrets.token_urlsafe(32)}"
    key_id = uuid.uuid4()
    async with app.state.db.session() as session:
        existing = (
            await session.execute(select(Project).where(Project.slug == "default"))
        ).scalar_one_or_none()
        if existing is None:
            session.add(Project(id=uuid.uuid4(), slug="default", name="default"))
        session.add(
            ApiKey(
                id=key_id,
                user_id=user_id,
                name="probe",
                token_hash=_hash_api_key(
                    plaintext=plaintext,
                    secret=settings.secret.get_secret_value().encode("utf-8"),
                ),
                prefix=plaintext[:8],
                scopes=["home:read"],
                allowed_cidrs=allowed_cidrs,
            ),
        )
        await session.commit()
    return key_id, plaintext


async def _login(app: Any, ip: str) -> dict[str, str]:
    """Log in from ``ip`` and return the cookies a browser would keep."""
    async with _client(app, ip) as client:
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": _EMAIL, "password": _PW},
        )
    assert response.status_code == 200, response.text
    return dict(response.cookies.items())


async def _denial_rows(app: Any) -> list[AuditLog]:
    async with app.state.db.session() as session:
        rows = await session.execute(
            select(AuditLog)
            .where(AuditLog.action == ipa.AUDIT_ACTION)
            .order_by(AuditLog.occurred_at),
        )
        return list(rows.scalars().all())


async def _actions(app: Any) -> list[str]:
    async with app.state.db.session() as session:
        rows = await session.execute(select(AuditLog.action))
        return list(rows.scalars().all())


def _metric(surface: str) -> float:
    return registry.get_sample_value("z4j_auth_ip_denied_total", {"surface": surface}) or 0.0


def _assert_denied_body(response: Any, surface: str) -> None:
    assert response.status_code == 403, response.text
    body = response.json()
    assert body["error"] == ipa.ERROR_CODE
    assert body["message"] == ipa.DENIED_MESSAGE
    assert body["details"] == {"surface": surface}


# ---------------------------------------------------------------------------
# Pure matcher, parser and settings validation
# ---------------------------------------------------------------------------


def test_parse_cidr_list_canonicalises_and_dedupes() -> None:
    out = ipa.parse_cidr_list(
        [" 10.1.2.3/8 ", "203.0.113.7", "2001:DB8::/32", "10.0.0.0/8"],
        field_name="x",
    )
    assert out == ["10.0.0.0/8", "203.0.113.7/32", "2001:db8::/32"]
    assert ipa.parse_cidr_list(None, field_name="x") == []
    assert ipa.parse_cidr_list([], field_name="x") == []


@pytest.mark.parametrize(
    "bad",
    [
        ["10.0.0/8"],
        ["203.0.113.7/33"],
        ["2001:db8::/129"],
        [""],
        ["   "],
        ["example.com"],
        ["10.0.0.0/8,10.0.0.0/16"],
        ["a" * 65],
        [42],
        "10.0.0.0/8",
        # Zone-scoped IPv6: ``ipaddress`` would accept these and keep the
        # scope id, which no resolved client address ever carries.
        ["fe80::1%eth0"],
        ["fe80::%eth0/64"],
        ["fe80::1%25eth0"],
    ],
)
def test_parse_cidr_list_refuses_malformed(bad: Any) -> None:
    with pytest.raises(ValueError, match="allowed_cidrs"):
        ipa.parse_cidr_list(bad, field_name="allowed_cidrs")


def test_parse_cidr_list_names_a_zone_id() -> None:
    with pytest.raises(ValueError, match=r"zone id \('%eth0'\)") as refused:
        ipa.parse_cidr_list(["fe80::1%eth0"], field_name="agent_ip_allowlist")
    assert "agent_ip_allowlist entry 'fe80::1%eth0'" in str(refused.value)
    assert "without it" in str(refused.value)
    # The address without its zone is the entry to write.
    assert ipa.parse_cidr_list(["fe80::1"], field_name="x") == ["fe80::1/128"]


def test_ip_allowed_semantics() -> None:
    cidrs = ["10.0.0.0/8", "2001:db8::/32"]
    assert ipa.ip_allowed("10.200.1.1", cidrs)
    assert ipa.ip_allowed("2001:db8:1::1", cidrs)
    assert not ipa.ip_allowed("11.0.0.1", cidrs)
    assert not ipa.ip_allowed("2001:db9::1", cidrs)
    # An empty list restricts nothing, whatever the address looks like.
    assert ipa.ip_allowed("11.0.0.1", [])
    assert ipa.ip_allowed("", [])
    assert ipa.ip_allowed(None, [])
    # A non-empty list refuses what it cannot evaluate.
    assert not ipa.ip_allowed("", cidrs)
    assert not ipa.ip_allowed(None, cidrs)
    assert not ipa.ip_allowed("not-an-ip", cidrs)
    # Loopback is a range like any other: absent from the list, refused.
    assert not ipa.ip_allowed("127.0.0.1", cidrs)
    assert not ipa.ip_allowed("::1", cidrs)
    assert ipa.ip_allowed("127.0.0.1", ["127.0.0.1/32"])
    # A dual-stack socket reports IPv4 peers as IPv4-mapped IPv6 addresses.
    assert ipa.ip_allowed("::ffff:10.1.1.1", ["10.0.0.0/8"])
    assert not ipa.ip_allowed("::ffff:11.1.1.1", ["10.0.0.0/8"])


_CIDR_FIELDS = (
    "dashboard_ip_allowlist",
    "api_ip_allowlist",
    "agent_ip_allowlist",
    "trusted_proxies",
)


@pytest.mark.parametrize("bad", [["10.0.0/8"], ["fe80::1%eth0"]])
def test_settings_refuse_a_malformed_cidr(tmp_path: Path, bad: list[str]) -> None:
    for field in _CIDR_FIELDS:
        with pytest.raises(ValidationError, match=field):
            _settings(tmp_path, **{field: bad})


def test_trusted_proxies_are_canonical_and_a_catch_all_is_named(tmp_path: Path) -> None:
    from z4j_brain.auth.ip import TrustedProxyResolver

    settings = _settings(tmp_path, trusted_proxies=["10.1.2.3/8", "203.0.113.7"])
    assert settings.trusted_proxies == ["10.0.0.0/8", "203.0.113.7/32"]
    assert settings.catch_all_trusted_proxies() == []

    # Honoured, not refused: a mesh sidecar may be the only peer there is.
    # Named, because with it any peer picks its own client address.
    wide = _settings(tmp_path, trusted_proxies=["0.0.0.0/0", "10.0.0.0/8", "::/0"])
    assert wide.trusted_proxies == ["0.0.0.0/0", "10.0.0.0/8", "::/0"]
    assert wide.catch_all_trusted_proxies() == ["0.0.0.0/0", "::/0"]
    resolver = TrustedProxyResolver(wide.trusted_proxies)
    assert resolver.resolve(peer_ip=DENIED, xff_header=ALLOWED) == ALLOWED
    narrow = TrustedProxyResolver(settings.trusted_proxies)
    assert narrow.resolve(peer_ip=DENIED, xff_header=ALLOWED) == DENIED


def test_startup_warns_once_about_a_catch_all_trusted_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One structlog WARNING per boot, captured at the structlog layer.

    ``create_app`` re-points the process logging at whatever stdout is when
    it runs, so a stdout capture only sees the line on the first boot of the
    process; capturing the structlog event itself is order-independent.
    """
    import structlog.testing
    import z4j_brain.main as brain_main

    monkeypatch.setattr(brain_main, "configure_logging", lambda **_kwargs: None)
    # The module logger is a structlog proxy cached on first use with the
    # processors active then (an earlier test in the process); a fresh proxy
    # binds under the capture configuration.
    monkeypatch.setattr(brain_main, "logger", structlog.get_logger("z4j.brain.main"))
    with structlog.testing.capture_logs() as events:
        create_app(_settings(tmp_path, trusted_proxies=["::/0"], metrics_public=True))
    warnings = [
        event
        for event in events
        if event.get("log_level") == "warning" and "trusts every peer" in str(event.get("event"))
    ]
    assert len(warnings) == 1, events
    assert "::/0" in str(warnings[0]["event"])
    assert "X-Forwarded-For" in str(warnings[0]["event"])

    with structlog.testing.capture_logs() as events:
        create_app(_settings(tmp_path, trusted_proxies=["10.0.0.0/8"], metrics_public=True))
    assert not [event for event in events if "trusts every peer" in str(event.get("event"))]


def test_settings_store_canonical_form_and_read_env_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path, dashboard_ip_allowlist=["10.1.2.3/8", "203.0.113.7"])
    assert settings.dashboard_ip_allowlist == ["10.0.0.0/8", "203.0.113.7/32"]
    assert settings.api_ip_allowlist == []
    monkeypatch.setenv("Z4J_AGENT_IP_ALLOWLIST", '["192.0.2.0/24", "2001:db8::/32"]')
    assert _settings(tmp_path).agent_ip_allowlist == ["192.0.2.0/24", "2001:db8::/32"]


def test_check_agent_ip_counts_each_denial(tmp_path: Path) -> None:
    settings = _settings(tmp_path, agent_ip_allowlist=["192.0.2.0/24"])
    before = _metric("agent")
    assert ipa.check_agent_ip("192.0.2.9", settings=settings) is None
    assert _metric("agent") == before
    denial = ipa.check_agent_ip("192.0.3.9", settings=settings)
    assert denial is not None
    assert denial.surface == "agent"
    assert denial.ip == "192.0.3.9"
    assert denial.reason == "global_allowlist"
    assert _metric("agent") == before + 1
    # Unrestricted: nothing to deny, nothing counted.
    assert ipa.check_agent_ip("192.0.3.9", settings=_settings(tmp_path)) is None
    assert _metric("agent") == before + 1
    # The transport raises what the HTTP surfaces raise.
    error = denial.error()
    assert isinstance(error, ipa.IpDeniedError)
    assert error.code == "ip_denied"
    assert error.details == {"surface": "agent"}
    assert denial.audit_metadata()["surface"] == "agent"


# ---------------------------------------------------------------------------
# Dashboard surface: session cookies and the login route
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_cookie_allowed_and_denied(tmp_path: Path) -> None:
    async with _brain(tmp_path, dashboard_ip_allowlist=[f"{ALLOWED}/32"]) as (app, _):
        user_id = await _seed_user(app, _settings(tmp_path))
        cookies = await _login(app, ALLOWED)
        before = _metric("dashboard")

        async with _client(app, ALLOWED, cookies=cookies) as client:
            assert (await client.get(_SESSION_URL)).status_code == 200

        async with _client(app, DENIED, cookies=cookies) as client:
            response = await client.get(_SESSION_URL)
        _assert_denied_body(response, "dashboard")

        rows = await _denial_rows(app)
        assert len(rows) == 1
        row = rows[0]
        assert row.source_ip == DENIED
        assert row.user_id == user_id
        assert row.api_key_id is None
        assert row.outcome == "deny"
        assert row.audit_metadata["surface"] == "dashboard"
        assert row.audit_metadata["reason"] == "global_allowlist"
        assert row.audit_metadata["path"] == _SESSION_URL
        assert _metric("dashboard") == before + 1


@pytest.mark.asyncio
async def test_login_route_refuses_before_looking_at_credentials(tmp_path: Path) -> None:
    async with _brain(tmp_path, dashboard_ip_allowlist=[f"{ALLOWED}/32"]) as (app, _):
        await _seed_user(app, _settings(tmp_path))
        async with _client(app, DENIED) as client:
            wrong = await client.post(
                "/api/v1/auth/login",
                json={"email": _EMAIL, "password": "not the password"},
            )
            right = await client.post(
                "/api/v1/auth/login",
                json={"email": _EMAIL, "password": _PW},
            )
        # A 403 either way: the password was never checked, so a caller
        # outside the list cannot use the login route as an oracle.
        _assert_denied_body(wrong, "dashboard")
        _assert_denied_body(right, "dashboard")
        assert "set-cookie" not in right.headers

        actions = await _actions(app)
        assert actions.count(ipa.AUDIT_ACTION) == 2
        assert "auth.login" not in actions
        rows = await _denial_rows(app)
        assert all(r.user_id is None and r.source_ip == DENIED for r in rows)


@pytest.mark.asyncio
async def test_ipv6_allowlist(tmp_path: Path) -> None:
    async with _brain(tmp_path, dashboard_ip_allowlist=["2001:db8::/48"]) as (app, _):
        await _seed_user(app, _settings(tmp_path))
        cookies = await _login(app, ALLOWED_V6)
        async with _client(app, ALLOWED_V6, cookies=cookies) as client:
            assert (await client.get(_SESSION_URL)).status_code == 200
        async with _client(app, DENIED_V6, cookies=cookies) as client:
            _assert_denied_body(await client.get(_SESSION_URL), "dashboard")
        async with _client(app, ALLOWED, cookies=cookies) as client:
            _assert_denied_body(await client.get(_SESSION_URL), "dashboard")
        rows = await _denial_rows(app)
        assert [r.source_ip for r in rows] == [DENIED_V6, ALLOWED]


@pytest.mark.asyncio
async def test_spoofed_forwarded_for_from_an_untrusted_peer_is_ignored(
    tmp_path: Path,
) -> None:
    async with _brain(tmp_path, dashboard_ip_allowlist=[f"{ALLOWED}/32"]) as (app, _):
        await _seed_user(app, _settings(tmp_path))
        cookies = await _login(app, ALLOWED)
        async with _client(app, DENIED, cookies=cookies) as client:
            response = await client.get(
                _SESSION_URL,
                headers={"X-Forwarded-For": ALLOWED},
            )
        _assert_denied_body(response, "dashboard")
        rows = await _denial_rows(app)
        assert len(rows) == 1
        # The header did not become the audited address either.
        assert rows[0].source_ip == DENIED


@pytest.mark.asyncio
async def test_forwarded_for_from_a_trusted_proxy_is_the_address_matched(
    tmp_path: Path,
) -> None:
    async with _brain(
        tmp_path,
        dashboard_ip_allowlist=[f"{ALLOWED}/32"],
        trusted_proxies=[f"{PROXY}/32"],
    ) as (app, _):
        await _seed_user(app, _settings(tmp_path))
        # The proxy itself is outside the list; only the forwarded client
        # address counts, so login through the proxy works for ALLOWED.
        async with _client(app, PROXY) as client:
            login = await client.post(
                "/api/v1/auth/login",
                json={"email": _EMAIL, "password": _PW},
                headers={"X-Forwarded-For": ALLOWED},
            )
        assert login.status_code == 200, login.text
        cookies = dict(login.cookies.items())

        async with _client(app, PROXY, cookies=cookies) as client:
            ok = await client.get(_SESSION_URL, headers={"X-Forwarded-For": ALLOWED})
            denied = await client.get(_SESSION_URL, headers={"X-Forwarded-For": DENIED})
            bare = await client.get(_SESSION_URL)
        assert ok.status_code == 200, ok.text
        _assert_denied_body(denied, "dashboard")
        # No header from the proxy: the proxy is the client, and it is not listed.
        _assert_denied_body(bare, "dashboard")
        rows = await _denial_rows(app)
        assert [r.source_ip for r in rows] == [DENIED, PROXY]


@pytest.mark.asyncio
async def test_loopback_is_not_implicitly_exempt(tmp_path: Path) -> None:
    async with _brain(tmp_path, dashboard_ip_allowlist=["10.0.0.0/8"]) as (app, _):
        await _seed_user(app, _settings(tmp_path))
        cookies = await _login(app, "10.0.0.5")
        async with _client(app, "127.0.0.1", cookies=cookies) as client:
            _assert_denied_body(await client.get(_SESSION_URL), "dashboard")
        async with _client(app, "::1", cookies=cookies) as client:
            _assert_denied_body(await client.get(_SESSION_URL), "dashboard")


# ---------------------------------------------------------------------------
# API-key surface: the global list and the per-key list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_api_key_global_allowlist(tmp_path: Path) -> None:
    async with _brain(tmp_path, api_ip_allowlist=[f"{ALLOWED}/32"]) as (app, settings):
        user_id = await _seed_user(app, settings)
        key_id, plaintext = await _seed_key(app, settings, user_id)
        headers = {"Authorization": f"Bearer {plaintext}"}
        before = _metric("api")

        async with _client(app, ALLOWED) as client:
            assert (await client.get(_BEARER_URL, headers=headers)).status_code == 200
        async with _client(app, DENIED) as client:
            response = await client.get(_BEARER_URL, headers=headers)
        _assert_denied_body(response, "api")

        rows = await _denial_rows(app)
        assert len(rows) == 1
        row = rows[0]
        assert row.source_ip == DENIED
        assert row.user_id == user_id
        assert row.api_key_id == key_id
        assert row.audit_metadata["surface"] == "api"
        assert row.audit_metadata["api_key_id"] == str(key_id)
        assert row.audit_metadata["reason"] == "global_allowlist"
        assert _metric("api") == before + 1

        # A refused request is not a use of the key.
        async with app.state.db.session() as session:
            key = (await session.execute(select(ApiKey).where(ApiKey.id == key_id))).scalar_one()
            assert key.last_used_ip != DENIED


@pytest.mark.asyncio
async def test_per_key_cidrs_deny_even_when_the_global_list_allows(tmp_path: Path) -> None:
    async with _brain(tmp_path, api_ip_allowlist=["0.0.0.0/0"]) as (app, settings):
        user_id = await _seed_user(app, settings)
        key_id, plaintext = await _seed_key(
            app,
            settings,
            user_id,
            allowed_cidrs=["203.0.113.0/24"],
        )
        headers = {"Authorization": f"Bearer {plaintext}"}

        async with _client(app, ALLOWED) as client:
            assert (await client.get(_BEARER_URL, headers=headers)).status_code == 200
        async with _client(app, DENIED) as client:
            response = await client.get(_BEARER_URL, headers=headers)
        _assert_denied_body(response, "api")

        rows = await _denial_rows(app)
        assert len(rows) == 1
        assert rows[0].api_key_id == key_id
        assert rows[0].audit_metadata["reason"] == "key_allowed_cidrs"


@pytest.mark.asyncio
async def test_per_key_cidrs_apply_without_any_global_list(tmp_path: Path) -> None:
    async with _brain(tmp_path) as (app, settings):
        user_id = await _seed_user(app, settings)
        _, restricted = await _seed_key(app, settings, user_id, allowed_cidrs=[f"{ALLOWED}/32"])
        _, open_key = await _seed_key(app, settings, user_id)
        async with _client(app, DENIED) as client:
            _assert_denied_body(
                await client.get(_BEARER_URL, headers={"Authorization": f"Bearer {restricted}"}),
                "api",
            )
            ok = await client.get(_BEARER_URL, headers={"Authorization": f"Bearer {open_key}"})
        assert ok.status_code == 200, ok.text


@pytest.mark.asyncio
async def test_surfaces_are_independent(tmp_path: Path) -> None:
    """The dashboard list does not gate keys and the API list does not gate cookies."""
    async with _brain(
        tmp_path,
        dashboard_ip_allowlist=[f"{ALLOWED}/32"],
        api_ip_allowlist=[f"{DENIED}/32"],
    ) as (app, settings):
        user_id = await _seed_user(app, settings)
        _, plaintext = await _seed_key(app, settings, user_id)
        cookies = await _login(app, ALLOWED)
        async with _client(app, DENIED) as client:
            bearer = await client.get(
                _BEARER_URL,
                headers={"Authorization": f"Bearer {plaintext}"},
            )
        assert bearer.status_code == 200, bearer.text
        async with _client(app, ALLOWED, cookies=cookies) as client:
            assert (await client.get(_SESSION_URL)).status_code == 200
        assert await _denial_rows(app) == []


# ---------------------------------------------------------------------------
# Managing the per-key list over the API
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_list_and_update_allowed_cidrs_over_http(tmp_path: Path) -> None:
    async with _brain(tmp_path) as (app, settings):
        await _seed_user(app, settings)
        cookies = await _login(app, ALLOWED)
        csrf = {"X-CSRF-Token": cookies[csrf_cookie_name(environment=settings.environment)]}

        async with _client(app, ALLOWED, cookies=cookies) as client:
            created = await client.post(
                "/api/v1/api-keys",
                json={
                    "name": "ci",
                    "scopes": ["home:read"],
                    "allowed_cidrs": ["203.0.113.5/24", "2001:DB8::1", "203.0.113.5/24"],
                },
                headers=csrf,
            )
            assert created.status_code == 201, created.text
            body = created.json()
            assert body["allowed_cidrs"] == ["203.0.113.0/24", "2001:db8::1/128"]
            key_id = body["id"]

            listed = await client.get("/api/v1/api-keys")
            assert listed.status_code == 200
            assert [k["allowed_cidrs"] for k in listed.json() if k["id"] == key_id] == [
                ["203.0.113.0/24", "2001:db8::1/128"],
            ]

            # The stored list is what the bearer path enforces.
            async with _client(app, DENIED) as outsider:
                _assert_denied_body(
                    await outsider.get(
                        _BEARER_URL,
                        headers={"Authorization": f"Bearer {body['token']}"},
                    ),
                    "api",
                )

            updated = await client.patch(
                f"/api/v1/api-keys/{key_id}",
                json={"allowed_cidrs": ["198.51.100.0/24"]},
                headers=csrf,
            )
            assert updated.status_code == 200, updated.text
            assert updated.json()["allowed_cidrs"] == ["198.51.100.0/24"]

            cleared = await client.patch(
                f"/api/v1/api-keys/{key_id}",
                json={"allowed_cidrs": None},
                headers=csrf,
            )
            assert cleared.status_code == 200, cleared.text
            assert cleared.json()["allowed_cidrs"] is None

            # Cleared means the outsider is back in (no global list here).
            async with _client(app, DENIED) as outsider:
                ok = await outsider.get(
                    _BEARER_URL,
                    headers={"Authorization": f"Bearer {body['token']}"},
                )
            assert ok.status_code == 200, ok.text

            malformed = await client.post(
                "/api/v1/api-keys",
                json={"name": "bad", "scopes": ["home:read"], "allowed_cidrs": ["10.0.0/8"]},
                headers=csrf,
            )
            assert malformed.status_code == 422, malformed.text
            zoned = await client.post(
                "/api/v1/api-keys",
                json={"name": "bad", "scopes": ["home:read"], "allowed_cidrs": ["fe80::1%eth0"]},
                headers=csrf,
            )
            assert zoned.status_code == 422, zoned.text
            assert "zone id" in zoned.text and "fe80::1%eth0" in zoned.text
            too_many = await client.post(
                "/api/v1/api-keys",
                json={
                    "name": "bad",
                    "scopes": ["home:read"],
                    "allowed_cidrs": [f"10.0.{i}.0/24" for i in range(33)],
                },
                headers=csrf,
            )
            assert too_many.status_code == 422, too_many.text
            missing = await client.patch(
                f"/api/v1/api-keys/{uuid.uuid4()}",
                json={"allowed_cidrs": ["198.51.100.0/24"]},
                headers=csrf,
            )
            assert missing.status_code == 404, missing.text

        actions = await _actions(app)
        assert actions.count("api_key.updated") == 2
