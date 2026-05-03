"""Double-submit CSRF token utilities.

Pattern:

1. The session cookie carries a per-session ``csrf_token``.
2. A second cookie ``__Host-z4j_csrf`` (NOT HttpOnly) carries the
   same value, so JavaScript on the dashboard can read it and
   echo it in an ``X-CSRF-Token`` request header.
3. On every state-changing request the server compares the
   header value to the session's ``csrf_token`` via
   :func:`hmac.compare_digest`.

The CSRF cookie is *not* the bearer of authentication - the
session cookie is. The CSRF cookie's only job is to be readable
by same-origin JS so it can be echoed back. An attacker who can
read the CSRF cookie cannot use it without ALSO holding the
session cookie (which is HttpOnly).

This module is FastAPI-free. The dep wrapper lives in
:mod:`z4j_brain.auth.deps`.
"""

from __future__ import annotations

import hmac

#: Cookie name in production. ``__Host-`` forces ``Secure=True``,
#: ``Path=/``, no ``Domain``.
CSRF_COOKIE_NAME_PROD: str = "__Host-z4j_csrf"

#: Cookie name in dev. Without the ``__Host-`` prefix so we can
#: use ``Secure=False`` on http://localhost.
CSRF_COOKIE_NAME_DEV: str = "z4j_csrf"

#: Header the dashboard uses to echo the CSRF cookie value.
CSRF_HEADER_NAME: str = "X-CSRF-Token"

#: HTTP methods exempt from CSRF (read-only methods).
CSRF_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})


def csrf_cookie_name(*, environment: str) -> str:
    """Return the CSRF cookie name appropriate to the environment."""
    return CSRF_COOKIE_NAME_DEV if environment == "dev" else CSRF_COOKIE_NAME_PROD


def csrf_cookie_kwargs(
    *,
    environment: str,
    max_age_seconds: int,
) -> dict[str, object]:
    """``response.set_cookie`` kwargs for the CSRF echo cookie.

    Crucially, ``httponly=False`` - the dashboard JS must be able
    to read this. ``samesite="strict"`` so the cookie cannot leak
    via cross-site GET navigation.
    """
    is_dev = environment == "dev"
    return {
        "max_age": max_age_seconds,
        "path": "/",
        "domain": None,
        "secure": not is_dev,
        "httponly": False,
        "samesite": "strict",
    }


def is_safe_method(method: str) -> bool:
    """True if ``method`` is one of GET / HEAD / OPTIONS."""
    return method.upper() in CSRF_SAFE_METHODS


def tokens_match(expected: str, supplied: str | None) -> bool:
    """Constant-time equality between the session token and the header.

    Returns False on missing header, length mismatch, or value
    mismatch - never raises. The constant-time guarantee is what
    makes this safe against length-extension and timing leak.
    """
    if not supplied:
        return False
    if len(supplied) != len(expected):
        return False
    return hmac.compare_digest(supplied, expected)


__all__ = [
    "CSRF_COOKIE_NAME_DEV",
    "CSRF_COOKIE_NAME_PROD",
    "CSRF_HEADER_NAME",
    "CSRF_SAFE_METHODS",
    "csrf_cookie_kwargs",
    "csrf_cookie_name",
    "is_safe_method",
    "tokens_match",
]
