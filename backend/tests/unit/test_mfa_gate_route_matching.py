"""Regression: the MFA gates must exempt their escape routes under the
route-path shape a REAL uvicorn server produces, not only the shape the
in-process ASGITransport test harness produces.

Backstory. Both MFA gates (``enforce_mfa_verified`` and
``enforce_mfa_enrollment``) refuse every route for a gated session except
a small allowlist -- the routes the session needs to heal itself (submit
the second factor, whoami, logout). The allowlist stores the FULL,
``/api/v1``-prefixed paths and the gate used to match them against
``request.scope["route"].path``.

The trap: ``scope["route"].path`` is NOT reliably the mounted path. Under
a live uvicorn server the ``APIRoute`` left in the scope reports its
router-local path (``/auth/mfa/verify``), so every prefixed allowlist
entry missed and the gate refused even ``/auth/mfa/verify`` itself -- a
user who turned on MFA could never present their code and was locked out
until an admin ran ``z4j reset-mfa``. Under the ASGITransport harness the
same route reports the prefixed path, so the existing route-level tests
saw the bug's opposite and stayed green. These tests reproduce the
uvicorn shape directly so the fix cannot silently regress.
"""

from __future__ import annotations

from starlette.requests import Request
from z4j_brain.api.deps import (
    _MFA_ENROLLMENT_EXEMPT_ROUTES,
    _MFA_VERIFICATION_EXEMPT_ROUTES,
    _matches_exempt_route,
)


class _StubRoute:
    """Minimal stand-in for the Starlette ``APIRoute`` in ``scope['route']``."""

    def __init__(self, path: str) -> None:
        self.path = path


def _request(method: str, url_path: str, route_path: str | None) -> Request:
    """Build a Request whose ``url.path`` and ``scope['route'].path`` differ.

    ``url_path`` is the actual app-relative path the client hit (always the
    full ``/api/v1/...`` form); ``route_path`` is what ``scope['route'].path``
    reports (``None`` to omit the route entirely).
    """
    scope: dict = {
        "type": "http",
        "method": method,
        "path": url_path,
        "raw_path": url_path.encode(),
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "server": ("testserver", 80),
    }
    if route_path is not None:
        scope["route"] = _StubRoute(route_path)
    return Request(scope)


class TestMatchesExemptRoute:
    def test_unprefixed_route_path_still_matches_via_url_path(self) -> None:
        """The uvicorn shape: route.path is router-local, url.path is full.

        This is the exact condition that locked users out. It must resolve
        to an exemption.
        """
        req = _request(
            "POST",
            "/api/v1/auth/mfa/verify",
            route_path="/auth/mfa/verify",
        )
        assert _matches_exempt_route(req, _MFA_VERIFICATION_EXEMPT_ROUTES) is True

    def test_prefixed_route_path_matches_too(self) -> None:
        """The ASGITransport / prefix-baking shape must keep working."""
        req = _request(
            "POST",
            "/api/v1/auth/mfa/verify",
            route_path="/api/v1/auth/mfa/verify",
        )
        assert _matches_exempt_route(req, _MFA_VERIFICATION_EXEMPT_ROUTES) is True

    def test_missing_route_object_falls_back_to_url_path(self) -> None:
        """No route in scope (edge case) -- url.path alone must decide."""
        req = _request("GET", "/api/v1/auth/me", route_path=None)
        assert _matches_exempt_route(req, _MFA_VERIFICATION_EXEMPT_ROUTES) is True

    def test_non_exempt_route_is_not_matched(self) -> None:
        """A route outside the allowlist must NOT be exempted -- the gate
        still has to bite for everything but the escape routes."""
        req = _request(
            "GET",
            "/api/v1/projects",
            route_path="/projects",
        )
        assert _matches_exempt_route(req, _MFA_VERIFICATION_EXEMPT_ROUTES) is False

    def test_method_is_discriminated(self) -> None:
        """The allowlist keys on (method, path); a wrong method on an
        allowlisted path must not slip through."""
        # /auth/mfa/verify is exempt for POST, never for GET.
        req = _request(
            "GET",
            "/api/v1/auth/mfa/verify",
            route_path="/auth/mfa/verify",
        )
        assert _matches_exempt_route(req, _MFA_VERIFICATION_EXEMPT_ROUTES) is False

    def test_enrollment_allowlist_matches_unprefixed_route_path(self) -> None:
        """The sibling enrollment gate carries the identical latent bug;
        its escape routes must resolve under the same uvicorn shape."""
        req = _request(
            "POST",
            "/api/v1/auth/mfa/enroll-complete",
            route_path="/auth/mfa/enroll-complete",
        )
        assert _matches_exempt_route(req, _MFA_ENROLLMENT_EXEMPT_ROUTES) is True

    def test_every_verification_exempt_route_resolves_unprefixed(self) -> None:
        """Sweep the whole allowlist: each entry must be reachable when
        route.path is the router-local (uvicorn) form."""
        for method, full_path in _MFA_VERIFICATION_EXEMPT_ROUTES:
            local = full_path[len("/api/v1") :]
            req = _request(method, full_path, route_path=local)
            assert _matches_exempt_route(req, _MFA_VERIFICATION_EXEMPT_ROUTES) is True, (
                f"{method} {full_path} not exempted with unprefixed route.path"
            )
