"""Server-side sessions + signed cookie envelopes.

Two layers:

1. :class:`SessionCookieCodec` - encodes and decodes the cookie
   envelope. Uses :class:`itsdangerous.URLSafeTimedSerializer` so
   the cookie is HMAC-signed against ``settings.session_secret``.
   The envelope payload is just ``{"sid": "<session uuid>"}`` -
   the actual session state lives in the database.

2. :class:`SessionPayload` - the resolved session, ready to be
   attached to ``request.state.session`` after every authenticated
   middleware pass.

The DB-side bookkeeping (create, lookup-by-id, touch, revoke,
revoke-all-for-user) lives in :class:`SessionRepository`. This
module is FastAPI-free.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

if TYPE_CHECKING:
    from z4j_brain.persistence.models import Session as SessionRow
    from z4j_brain.settings import Settings


#: Cookie name in production. The ``__Host-`` prefix forces the
#: cookie to be ``Secure``, ``Path=/``, and have no ``Domain``
#: attribute - defends against subdomain cookie injection.
SESSION_COOKIE_NAME_PROD: str = "__Host-z4j_session"

#: Cookie name in dev. The ``__Host-`` prefix would forbid the
#: ``Secure=False`` setting we need for plain http://localhost
#: testing, so we drop it under ``environment="dev"``.
SESSION_COOKIE_NAME_DEV: str = "z4j_session"

#: itsdangerous salt - bumped on protocol-version changes.
_SESSION_SALT: str = "z4j-session-v1"


def cookie_name(*, environment: str) -> str:
    """Return the session cookie name appropriate to the environment."""
    return SESSION_COOKIE_NAME_DEV if environment == "dev" else SESSION_COOKIE_NAME_PROD


@dataclass(frozen=True, slots=True)
class SessionPayload:
    """The fully-resolved session attached to a request.

    Built by :class:`SessionResolver` after the cookie has been
    decoded, the DB row fetched, and all expiry checks have passed.
    The CSRF token is the per-session value the dashboard echoes in
    the ``X-CSRF-Token`` header on every state-changing request.
    """

    session_id: uuid.UUID
    user_id: uuid.UUID
    csrf_token: str
    issued_at: datetime
    expires_at: datetime
    last_seen_at: datetime
    user_agent_at_issue: str | None


class SessionCookieCodec:
    """Encode and decode the signed session cookie envelope.

    The envelope payload is intentionally minimal - just the
    session id. The actual session lives in the database; the
    cookie is only proof-of-knowledge of a valid session id signed
    by the brain.
    """

    __slots__ = ("_serializer", "_verify_serializers")

    def __init__(self, settings: Settings) -> None:
        # Encode-side: only the current secret. New cookies are
        # always signed with the active key.
        self._serializer = URLSafeTimedSerializer(
            settings.session_secret.get_secret_value(),
            salt=_SESSION_SALT,
        )
        # Round-6 audit fix SR-HIGH (Apr 2026): verify-side accepts
        # any secret in the rotation window so a Z4J_SESSION_SECRET
        # rotation does not log every active operator out at once.
        self._verify_serializers: list[URLSafeTimedSerializer] = []
        for raw in settings.all_session_secrets_for_verification():
            self._verify_serializers.append(
                URLSafeTimedSerializer(
                    raw.decode("utf-8"),
                    salt=_SESSION_SALT,
                ),
            )

    def encode(self, session_id: uuid.UUID) -> str:
        """Sign + serialize a session id into the cookie value."""
        return self._serializer.dumps({"sid": str(session_id)})

    def decode(
        self,
        cookie_value: str,
        *,
        max_age_seconds: int,
    ) -> uuid.UUID | None:
        """Verify the signature and return the session id, or None.

        Returns None on:

        - Bad signature (tampering, wrong secret)
        - Expired serializer envelope (older than ``max_age_seconds``)
        - Malformed payload (e.g. cookie not produced by us)

        Never raises. Callers treat None as "no session".
        """
        data: object | None = None
        for serializer in self._verify_serializers:
            try:
                data = serializer.loads(
                    cookie_value,
                    max_age=max_age_seconds,
                )
                break
            except SignatureExpired:
                # An expired-but-valid signature is conclusive: don't
                # let a previous-secret retry create a longer effective
                # lifetime than ``max_age_seconds`` allows.
                return None
            except BadSignature:
                continue
        if data is None:
            return None
        if not isinstance(data, dict):
            return None
        sid = data.get("sid")
        if not isinstance(sid, str):
            return None
        try:
            return uuid.UUID(sid)
        except ValueError:
            return None


def generate_csrf_token() -> str:
    """Return a fresh url-safe CSRF token (32 random bytes)."""
    return secrets.token_urlsafe(32)


def cookie_kwargs(
    *,
    environment: str,
    max_age_seconds: int,
    samesite: str = "lax",
) -> dict[str, object]:
    """Return the kwargs for ``response.set_cookie`` for a session.

    Production:
    - ``secure=True`` (mandatory)
    - ``httponly=True``
    - ``samesite="lax"`` for the session cookie (so cross-site
      navigation to /dashboard still authenticates)
    - ``path="/"`` (required by the ``__Host-`` prefix anyway)
    - ``domain=None`` (required by the ``__Host-`` prefix)

    Dev:
    - Same flags except ``secure=False``.
    """
    is_dev = environment == "dev"
    return {
        "max_age": max_age_seconds,
        "path": "/",
        "domain": None,
        "secure": not is_dev,
        "httponly": True,
        "samesite": samesite,
    }


def is_session_live(
    row: SessionRow,
    *,
    now: datetime,
    idle_timeout_seconds: int,
    user_password_changed_at: datetime | None,
) -> bool:
    """Return True if the session is currently usable.

    Checks every revocation reason:

    - ``revoked_at`` is set → revoked
    - ``expires_at`` < now → absolute lifetime exceeded
    - ``last_seen_at`` < now - idle_timeout → idle timeout
    - user changed their password after the session was issued →
      "rotate on password change" rule

    Idle and absolute checks happen here so the resolver does not
    need to know the timeout policy. The DB row is the source of
    truth for ``revoked_at`` and ``expires_at``; the policy comes
    from settings.

    SQLite returns naive datetimes from ``TIMESTAMPTZ`` columns
    even when SQLAlchemy declares ``DateTime(timezone=True)``. We
    coerce every datetime through :func:`_aware_utc` so the
    comparisons never raise on the test path.
    """
    if row.revoked_at is not None:
        return False
    now_utc = _aware_utc(now)
    if _aware_utc(row.expires_at) <= now_utc:
        return False
    idle_cutoff = now_utc.timestamp() - idle_timeout_seconds
    if _aware_utc(row.last_seen_at).timestamp() < idle_cutoff:
        return False
    if (
        user_password_changed_at is not None
        # 1-second grace window. The session's ``issued_at`` comes
        # from the DB's ``func.now()`` which is SECOND-precision on
        # SQLite but microsecond-precision on Postgres. The user's
        # ``password_changed_at`` is always Python-side
        # microsecond-precision. Without the grace, a session minted
        # in the same wall-clock second as a password change looks
        # "older" on SQLite (microsecond 0 <= microsecond N) and
        # gets rejected - breaking every session that the setup
        # flow and password-change flow mint immediately after
        # writing the user row. The grace is safe: no attacker can
        # exploit a 1-second window here (a compromised session
        # needs a valid cookie signature, which requires the
        # current secret, which changes when the operator rotates).
        and _aware_utc(row.issued_at)
        < _aware_utc(user_password_changed_at) - timedelta(seconds=1)
    ):
        return False
    return True


def aware_utc(value: datetime) -> datetime:
    """Coerce a (possibly naive) datetime to UTC-aware.

    Naive datetimes from the SQLite test path are assumed to
    already be UTC, which is true for everything we write
    (``datetime.now(UTC)`` or server-side ``func.now()`` on a
    UTC-configured database).
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


# Internal name kept for the existing call sites in this file.
_aware_utc = aware_utc


def utc_now() -> datetime:
    """Return ``datetime.now(UTC)`` - wrapped so tests can patch it."""
    return datetime.now(UTC)


__all__ = [
    "SESSION_COOKIE_NAME_DEV",
    "SESSION_COOKIE_NAME_PROD",
    "SessionCookieCodec",
    "SessionPayload",
    "aware_utc",
    "cookie_kwargs",
    "cookie_name",
    "generate_csrf_token",
    "is_session_live",
    "utc_now",
]
