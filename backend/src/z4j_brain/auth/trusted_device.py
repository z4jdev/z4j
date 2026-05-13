"""Cookie helpers for the ``z4j_mfa_trust`` "remember this device" flow.

The cookie carries an opaque 32-byte random id (urlsafe-base64). The
brain stores its SHA-256 hash in ``trusted_devices.cookie_id_hash``;
the plaintext id never lives in the database. Login + verify endpoints
use :func:`hash_cookie_id` to look up the row.

Cookie attributes mirror the session cookie's hardening:

- ``HttpOnly`` -- not readable from JS.
- ``Secure`` -- never sent over plaintext (relaxed in dev when
  ``Z4J_ALLOW_HTTP_PUBLIC_URL=true``).
- ``SameSite=Strict`` -- not sent on cross-site requests. Stricter
  than the session cookie (which uses Lax) because the trust cookie
  is exclusively for the login flow on this origin.
- ``Path=/`` -- sent on every request; the brain checks it only on
  the login + verify paths.

The cookie name is ``z4j_mfa_trust`` in dev and ``__Host-z4j_mfa_trust``
in production (the ``__Host-`` prefix is browser-enforced: it requires
Secure + Path=/ + no Domain attribute, which is exactly our shape).
"""

from __future__ import annotations

import hashlib
import secrets

from fastapi import Response

#: Cookie name when the session cookie is also using the ``__Host-``
#: prefix (production over HTTPS).
COOKIE_NAME_PROD: str = "__Host-z4j_mfa_trust"

#: Cookie name in dev (HTTP allowed). Browsers refuse to set ``__Host-``
#: cookies over plaintext.
COOKIE_NAME_DEV: str = "z4j_mfa_trust"

#: Number of bytes of randomness in the cookie value. 32 bytes = 256
#: bits -- comfortable margin against any brute-force attack.
COOKIE_RANDOM_BYTES: int = 32


def cookie_name(*, environment: str) -> str:
    """Pick the cookie name for the current environment.

    Same logic as :mod:`z4j_brain.auth.csrf` for parity.
    """
    if environment in ("dev", "development", "test"):
        return COOKIE_NAME_DEV
    return COOKIE_NAME_PROD


def mint_cookie_id() -> str:
    """Return a fresh opaque cookie id (urlsafe-base64, 32 bytes)."""
    return secrets.token_urlsafe(COOKIE_RANDOM_BYTES)


def hash_cookie_id(value: str) -> str:
    """SHA-256 hex digest of the cookie's plaintext id.

    The DB column ``trusted_devices.cookie_id_hash`` stores this. The
    server never persists the plaintext.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def cookie_kwargs(
    *,
    environment: str,
    max_age_seconds: int,
) -> dict[str, object]:
    """``Response.set_cookie`` keyword arguments for the trust cookie.

    Production (``__Host-`` prefix) requires Secure + Path=/ + no
    Domain. We enforce those regardless of environment so the dev
    cookie shape matches prod.
    """
    is_prod = environment not in ("dev", "development", "test")
    return {
        "max_age": max_age_seconds,
        "httponly": True,
        "secure": is_prod,
        "samesite": "strict",
        "path": "/",
    }


def set_trust_cookie(
    response: Response,
    *,
    cookie_value: str,
    environment: str,
    max_age_seconds: int,
) -> None:
    """Drop the trust cookie on the outbound response."""
    response.set_cookie(
        cookie_name(environment=environment),
        cookie_value,
        **cookie_kwargs(
            environment=environment, max_age_seconds=max_age_seconds,
        ),
    )


def clear_trust_cookie(response: Response, *, environment: str) -> None:
    """Delete the trust cookie (e.g. on disable / logout-from-all)."""
    response.delete_cookie(
        cookie_name(environment=environment),
        path="/",
    )


#: Max bytes of User-Agent we'll scan to derive a device label.
#: Anything beyond the first 500 chars is either misconfigured or
#: hostile; lowercasing a 50 KB UA on every verify call would burn
#: CPU for no signal. (1.6.0 audit High-6.)
_UA_SCAN_CAP: int = 500


def derive_label_from_user_agent(user_agent: str | None) -> str:
    """Synthesize a human-readable device label.

    Best-effort: extracts a browser name and an OS name from the UA
    string and concatenates. Falls back to ``Unknown device`` on a
    missing or unparseable UA.
    """
    if not user_agent:
        return "Unknown device"
    ua = user_agent[:_UA_SCAN_CAP].lower()
    browser = "Browser"
    for name in ("firefox", "chrome", "safari", "edge", "opera"):
        if name in ua:
            browser = name.capitalize()
            break
    os_label = "Unknown OS"
    for marker, label in (
        ("windows", "Windows"),
        ("mac os", "macOS"),
        ("macintosh", "macOS"),
        ("linux", "Linux"),
        ("android", "Android"),
        ("iphone", "iOS"),
        ("ipad", "iOS"),
    ):
        if marker in ua:
            os_label = label
            break
    return f"{browser} on {os_label}"


__all__ = [
    "COOKIE_NAME_DEV",
    "COOKIE_NAME_PROD",
    "COOKIE_RANDOM_BYTES",
    "clear_trust_cookie",
    "cookie_kwargs",
    "cookie_name",
    "derive_label_from_user_agent",
    "hash_cookie_id",
    "mint_cookie_id",
    "set_trust_cookie",
]
