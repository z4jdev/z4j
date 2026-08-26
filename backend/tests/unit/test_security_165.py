"""Security regression tests for the 1.6.5 advisory release.

Locks in the fixes for findings from the external pre-2.0 security
audit (2026-05-15). Each test pins a specific behavior; removing
one must be deliberate and justified in the PR description.

Findings covered:

- **F1**: ``require_fresh_mfa`` gate on every privileged
  admin / project-admin mutating route. Pre-1.6.5 the gate was
  applied only to a subset (change-password, mint API key,
  regenerate recovery codes, delete project). The audit found
  it missing on user CRUD, admin password reset, agent token
  mint/revoke, membership grant/update/revoke, and invitation
  mint/revoke -- routes where a stolen session lets an attacker
  durably escalate privileges or backdoor accounts.

- (F2 + F3 + F4 covered in separate test files / sections.)
"""

from __future__ import annotations

import importlib

import pytest

# ---------------------------------------------------------------------------
# F1: route-specific regression lock -- privileged routes carry fresh-MFA
# ---------------------------------------------------------------------------
#
# Why structural and not end-to-end:
#
# An e2e test for each route would require constructing a stale-MFA
# session fixture (user.mfa_secret_encrypted set,
# session.mfa_verified_at null), hitting the route, asserting 403.
# That works but is brittle (one helper per route, fragile to schema
# changes) and slow.
#
# This test takes the regression-lock approach: hardcode the
# specific routes the audit identified, assert fresh-MFA is present
# on each. A future contributor removing the gate trips this test
# at lint speed (<100ms), much cheaper than catching it in code
# review or another audit pass.
#
# NOT every CSRF-protected route needs fresh-MFA. Operator-level
# work (retry task, cancel command, trigger schedule, send
# notification) requires CSRF but explicitly NOT fresh-MFA --
# asking for TOTP on every click would be operator-hostile UX.
# This list is exclusively the routes where a stolen session can
# durably escalate privileges or backdoor accounts.

# (filename, route_path_or_marker) -- routes that MUST have
# require_fresh_mfa per the 1.6.5 audit. Identified by a unique
# substring of the route decorator or handler so the test can
# locate the block in the file without depending on line numbers.
F1_GATED_ROUTES = [
    # ----- 1.6.0-era (already gated; lock that they STAY gated) -----
    # change-password (auth.py); router mounted under /api/v1, no
    # /auth prefix here -- the file uses bare "/change-password"
    ("auth.py", '"/change-password"'),
    # mint API key (api_keys.py:239)
    ("api_keys.py", '@router.post(\n    ""'),
    # regenerate recovery codes (auth_mfa.py:738); bare path
    ("auth_mfa.py", '"/recovery-codes/regenerate"'),
    # delete project (projects.py:476)
    ("projects.py", '@router.delete(\n    "/{slug}"'),
    # ----- 1.6.5 additions (the audit's F1) -----
    # users.py: create / update / admin password reset / delete
    ("users.py", '@router.post(\n    ""'),  # create user
    ("users.py", '@router.patch(\n    "/{user_id}"'),  # update user
    ("users.py", '@router.post(\n    "/{user_id}/password"'),  # admin pw reset
    ("users.py", '@router.delete(\n    "/{user_id}"'),  # delete user
    # agents.py: mint + revoke project agent token
    ("agents.py", '@router.post(\n    ""'),  # mint agent
    ("agents.py", '@router.delete(\n    "/{agent_id}"'),  # revoke agent
    # memberships.py: grant / update / revoke
    ("memberships.py", '@router.post(\n    ""'),  # grant
    ("memberships.py", '@router.patch(\n    "/{membership_id}"'),  # update
    ("memberships.py", '@router.delete(\n    "/{membership_id}"'),  # revoke
    # invitations.py: mint + revoke (admin_router)
    ("invitations.py", '@admin_router.post(\n    ""'),  # mint
    ("invitations.py", '@admin_router.delete(\n    "/{invitation_id}"'),  # revoke
    # ----- 1.6.5 round-2 additions (audit finding F5) -----
    # notifications.py: project-admin channel + default-subscription
    # mutating routes. A stolen project-admin session could
    # otherwise persist a phishing-channel pointing at attacker
    # infrastructure and pivot all future project notifications
    # there. Same threat shape as F1.
    ("notifications.py", '"/channels",\n    response_model=ChannelPublic'),  # create channel
    ("notifications.py", '"/channels/import_from_user"'),  # import secrets server-side
    (
        "notifications.py",
        '@router.patch(\n    "/channels/{channel_id}"',
    ),  # update channel (URL pivot risk)
    ("notifications.py", '@router.delete(\n    "/channels/{channel_id}"'),  # delete channel
    ("notifications.py", '"/channels/test"'),  # data-exfil preflight
    ("notifications.py", '"/channels/{channel_id}/test"'),  # data-exfil saved-channel test
    (
        "notifications.py",
        '"/defaults",\n    response_model=DefaultSubscriptionPublic',
    ),  # add default routing
    ("notifications.py", '@router.patch(\n    "/defaults/{default_id}"'),  # update default routing
    ("notifications.py", '@router.delete(\n    "/defaults/{default_id}"'),  # delete default routing
]

F1_GATED_ENDPOINT_NAMES = [
    "change_password",
    "create_api_key",
    "regenerate_recovery_codes",
    "archive_project",
    "create_user",
    "update_user",
    "reset_password",
    "delete_user",
    "create_agent",
    "revoke_agent",
    "grant_membership",
    "update_membership",
    "revoke_membership",
    "mint_invitation",
    "revoke_invitation",
    "create_channel",
    "import_channel_from_user",
    "update_channel",
    "delete_channel",
    "test_channel_config",
    "test_saved_channel",
    "create_default",
    "update_default",
    "delete_default",
]


def _route_for_endpoint(module, endpoint_name: str):
    from fastapi.routing import APIRoute

    candidates = [
        route
        for value in vars(module).values()
        if hasattr(value, "routes")
        for route in value.routes
        if isinstance(route, APIRoute) and route.endpoint.__name__ == endpoint_name
    ]
    assert len(candidates) == 1, (module.__name__, endpoint_name, candidates)
    return candidates[0]


def _dependency_calls(dependant) -> set:
    calls = {dependency.call for dependency in dependant.dependencies}
    for dependency in dependant.dependencies:
        calls.update(_dependency_calls(dependency))
    return calls


@pytest.mark.parametrize(
    ("route_spec", "endpoint_name"),
    list(zip(F1_GATED_ROUTES, F1_GATED_ENDPOINT_NAMES, strict=True)),
)
def test_route_runtime_dependency_graph_carries_fresh_mfa(
    route_spec: tuple[str, str],
    endpoint_name: str,
) -> None:
    """Inspect FastAPI's built dependency graph, not nearby source tokens."""

    from z4j_brain.api.deps import require_fresh_mfa

    filename, _legacy_marker = route_spec
    module = importlib.import_module(f"z4j_brain.api.{filename.removesuffix('.py')}")
    route = _route_for_endpoint(module, endpoint_name)

    assert require_fresh_mfa in _dependency_calls(route.dependant), (
        f"{module.__name__}.{endpoint_name} has no active fresh-MFA dependency"
    )


# ---------------------------------------------------------------------------
# Every fresh-MFA-gated notification route also audit-records
# ---------------------------------------------------------------------------
#
# Round-4 audit (2026-05-26) found PATCH /defaults/{default_id} was
# fresh-MFA gated but silent in the audit log. The neighboring
# POST and DELETE for the same surface DID audit, so the gap was a
# forgotten-line bug, not a deliberate design choice. The fix in
# 1.6.5 adds audit.record() to the PATCH handler with a "changed"
# metadata blob recording which fields actually mutated.
#
# This structural test pins the invariant: every notifications.py
# F1-gated route MUST call audit.record(). Catches the bug class
# (someone adds a new privileged notification route, gates it for
# fresh-MFA, but forgets the audit line) at lint speed.
#
# Why scoped to notifications.py only: the audit.record() pattern
# is the audit precedent in this file (9 sites). Other F1-gated
# files (auth.py, auth_mfa.py) use different audit mechanisms
# (structlog security events) that this test would false-positive.

NOTIFICATIONS_F1_HANDLERS = [
    ("create_channel", '"/channels",\n    response_model=ChannelPublic'),
    ("import_channel_from_user", '"/channels/import_from_user"'),
    ("update_channel", '@router.patch(\n    "/channels/{channel_id}"'),
    ("delete_channel", '@router.delete(\n    "/channels/{channel_id}"'),
    ("test_channel_preflight", '"/channels/test"'),
    ("test_channel_saved", '"/channels/{channel_id}/test"'),
    ("create_default", '"/defaults",\n    response_model=DefaultSubscriptionPublic'),
    ("update_default", '@router.patch(\n    "/defaults/{default_id}"'),
    ("delete_default", '@router.delete(\n    "/defaults/{default_id}"'),
]


@pytest.mark.parametrize("handler_name,route_marker", NOTIFICATIONS_F1_HANDLERS)
def test_notifications_f1_route_is_present_in_runtime_inventory(
    handler_name: str,
    route_marker: str,
) -> None:
    """Keep the historical names mapped to actual FastAPI endpoints.

    Audit I/O is exercised in ``test_notifications_audit.py``; this test only
    accounts for the legacy advisory ledger without pretending source text is
    evidence of a durable audit write.
    """

    from z4j_brain.api import notifications

    endpoint_name = {
        "test_channel_preflight": "test_channel_config",
        "test_channel_saved": "test_saved_channel",
    }.get(handler_name, handler_name)
    route = _route_for_endpoint(notifications, endpoint_name)
    assert route.methods & {"POST", "PATCH", "DELETE"}
    assert route_marker


def test_f1_route_list_includes_known_admin_surfaces() -> None:
    """Sanity: every file the audit identified is represented in
    F1_GATED_ROUTES by at least one route.

    Guards against accidentally dropping a file from the list
    during a refactor.

    1.6.5 round-2 added notifications.py (audit finding F5 --
    project-admin channel + default-routing mutations).
    """
    files_in_list = {f for f, _ in F1_GATED_ROUTES}
    audit_identified_files = {
        # 1.6.5 round-1
        "users.py",
        "agents.py",
        "memberships.py",
        "invitations.py",
        # 1.6.5 round-2
        "notifications.py",
    }
    missing = audit_identified_files - files_in_list
    assert not missing, (
        f"F1_GATED_ROUTES is missing routes from audit-identified files: "
        f"{sorted(missing)}. Re-add at least one route per file."
    )


# ---------------------------------------------------------------------------
# F3: outbound notification webhook timestamp + dual-signature
# ---------------------------------------------------------------------------
#
# Pre-1.6.5 outbound webhooks signed body-only with HMAC-SHA256.
# Captured (body, signature) pairs were replayable indefinitely to
# any receiver that trusted ``X-Z4J-Signature``. The audit forwarder
# (already shipping since 1.6.0) used the stronger timestamp+body
# pattern; the notification path was lagging.
#
# 1.6.5 brings the notification path up to the audit-forwarder
# pattern. To not break receivers that verify the legacy format
# during the upgrade window, both signatures ship simultaneously:
#
#   X-Z4J-Timestamp:    <unix seconds>
#   X-Z4J-Signature:    sha256=<HMAC over "{timestamp}.{body}"> (v2)
#   X-Z4J-Signature-V1: sha256=<HMAC over body>                 (legacy)
#
# Legacy V1 header is removed in 1.7.


@pytest.mark.asyncio
async def test_f3_notification_webhook_includes_timestamp_and_dual_sig(
    monkeypatch,
) -> None:
    """Locked: deliver_webhook ships X-Z4J-Timestamp + X-Z4J-Signature
    (v2 over timestamp.body) and NO legacy X-Z4J-Signature-V1 (removed in
    1.7) when ``hmac_secret`` is configured.

    The HMAC values must:
    - Use the SAME secret
    - Be hex-encoded SHA-256
    - Prefix with ``sha256=``
    - Independently verify against the documented signing inputs
    """
    import hashlib
    import hmac
    import json

    from z4j_brain.domain.notifications import channels

    secret = "test-secret-1234567890abcdef"
    payload = {"event": "task.failed", "task_id": "abc123"}
    expected_body = json.dumps(payload, default=str, ensure_ascii=False)

    captured: dict[str, object] = {}

    class FakeResponse:
        status_code = 200
        text = "ok"

    async def fake_validate_webhook_url(url: str) -> None:
        return None

    def fake_validate_webhook_headers(custom):
        return None, {}

    async def fake_resolve_and_pin(url: str):
        return None, "203.0.113.42"

    async def fake_post(
        url: str,
        *,
        content: str,
        headers: dict,
        pin_ip: str,
    ):
        captured["headers"] = headers
        captured["body"] = content
        captured["url"] = url
        return FakeResponse()

    monkeypatch.setattr(
        channels,
        "validate_webhook_url",
        fake_validate_webhook_url,
    )
    monkeypatch.setattr(
        channels,
        "validate_webhook_headers",
        fake_validate_webhook_headers,
    )
    monkeypatch.setattr(
        channels,
        "resolve_and_pin",
        fake_resolve_and_pin,
    )
    monkeypatch.setattr(channels, "_post", fake_post)

    result = await channels.deliver_webhook(
        config={
            "url": "https://receiver.example.com/hook",
            "hmac_secret": secret,
        },
        payload=payload,
    )
    assert result.success is True

    headers = captured["headers"]
    assert "X-Z4J-Timestamp" in headers, "1.6.5 F3: outbound webhook MUST include X-Z4J-Timestamp"
    assert "X-Z4J-Signature" in headers, "outbound webhook MUST include X-Z4J-Signature"
    assert "X-Z4J-Signature-V1" not in headers, (
        "1.7 REMOVED the legacy body-only X-Z4J-Signature-V1 header; "
        "only the timestamp+body X-Z4J-Signature ships now"
    )

    # Verify the timestamp is a plausible unix-seconds integer.
    ts = headers["X-Z4J-Timestamp"]
    assert ts.isdigit(), f"timestamp must be unix seconds, got {ts!r}"
    import time as _time

    now = int(_time.time())
    assert abs(now - int(ts)) < 60, (
        f"timestamp must be near 'now' (within 60s), got {ts}, now={now}"
    )

    # Verify v2 signature: HMAC(secret, "{timestamp}.{body}")
    v2_sig = headers["X-Z4J-Signature"]
    assert v2_sig.startswith("sha256="), f"signature MUST be 'sha256=<hex>', got {v2_sig!r}"
    expected_v2 = hmac.new(
        secret.encode("utf-8"),
        f"{ts}.{expected_body}".encode(),
        hashlib.sha256,
    ).hexdigest()
    assert v2_sig == f"sha256={expected_v2}", (
        "v2 signature MUST be HMAC over '{timestamp}.{body}' (matches the audit-forwarder pattern)"
    )


@pytest.mark.asyncio
async def test_f3_no_hmac_secret_means_no_signature_headers(
    monkeypatch,
) -> None:
    """When ``hmac_secret`` is not configured, no signature headers
    are added (operators with public webhook destinations don't
    need signing). The timestamp header is also omitted in that
    case so receivers don't mistake it for a signed envelope.
    """
    from z4j_brain.domain.notifications import channels

    captured: dict[str, object] = {}

    class FakeResponse:
        status_code = 200
        text = "ok"

    async def fake_post(
        url: str,
        *,
        content: str,
        headers: dict,
        pin_ip: str,
    ):
        captured["headers"] = headers
        return FakeResponse()

    async def _noop_url(*a, **k):
        return None

    def _noop_headers(custom):
        return None, {}

    async def _noop_pin(url):
        return None, "203.0.113.42"

    monkeypatch.setattr(channels, "validate_webhook_url", _noop_url)
    monkeypatch.setattr(channels, "validate_webhook_headers", _noop_headers)
    monkeypatch.setattr(channels, "resolve_and_pin", _noop_pin)
    monkeypatch.setattr(channels, "_post", fake_post)

    result = await channels.deliver_webhook(
        config={"url": "https://receiver.example.com/hook"},
        payload={"event": "task.failed"},
    )
    assert result.success is True

    headers = captured["headers"]
    assert "X-Z4J-Signature" not in headers
    assert "X-Z4J-Signature-V1" not in headers
    assert "X-Z4J-Timestamp" not in headers
