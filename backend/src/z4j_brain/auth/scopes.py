"""API-key scope catalogue + mapping helpers.

z4j's scope model mirrors GitHub's fine-grained PATs: every scope
is ``{resource}:{verb}`` where *verb* is ``read`` or ``write``.
The admin umbrella ``admin:*`` is a single grant that unlocks
admin-only endpoints (user management, project creation, etc.);
it does NOT grant per-project writes on its own.

Endpoint → required-scope mapping is keyed off the route's first
FastAPI tag + the HTTP method. ``GET`` maps to ``read``; any other
method maps to ``write``. Routes with no tag, or with a tag listed
in :data:`PUBLIC_TAGS`, are always allowed (health checks, setup,
the login endpoint itself).

The whole point of this module is that adding a new endpoint that
uses one of the catalogued tags automatically inherits the right
scope requirement - there's no per-route decoration to forget.
"""

from __future__ import annotations

from typing import Final

#: All scopes that a user can request on an API key.  The order is
#: the order the UI renders them in.
ALL_SCOPES: Final[tuple[str, ...]] = (
    # Read-only
    "auth:read",
    "home:read",
    "projects:read",
    "tasks:read",
    "workers:read",
    "queues:read",
    "agents:read",
    "commands:read",
    "schedules:read",
    "audit:read",
    "memberships:read",
    "notifications:read",
    # Write
    "tasks:write",
    "commands:write",
    "agents:write",
    "projects:write",
    "memberships:write",
    "notifications:write",
    # Admin-gated (require is_admin on the owning user at mint time)
    "users:read",
    "users:write",
    "admin:*",
)

#: Scopes only a global admin can grant on a key they mint.
ADMIN_ONLY_SCOPES: Final[frozenset[str]] = frozenset({
    "users:read", "users:write", "projects:write", "admin:*",
})

#: FastAPI tags that are always allowed regardless of scope. These
#: are stateless / pre-auth endpoints where there is nothing to
#: protect with a scope check. Note that ``auth`` is NOT here -
#: ``/auth/login`` and ``/auth/logout`` are session-cookie-only
#: (there's no ``Depends(get_current_user)`` on them), so they
#: never hit this path. Read-only ``/auth/me`` is authorized via
#: the ``auth:read`` scope; every write endpoint under ``/auth``
#: is rejected outright for Bearer auth by
#: :data:`BEARER_DENY_TAGS` below.
PUBLIC_TAGS: Final[frozenset[str]] = frozenset({
    "health", "setup", "metrics",
})

#: Tags that API-key (Bearer) auth may never touch at all.
#: Session-cookie auth still works. These are user-identity-level
#: operations (change my password, revoke my sessions) where an
#: exfiltrated narrow-scope token must NOT be an escalation path.
BEARER_DENY_TAGS: Final[frozenset[str]] = frozenset({
    "auth",
})

#: When a token is bound to a specific project, we only let it
#: reach routes that either (a) carry a ``{slug}`` path param we
#: can match against the bound project, or (b) are in this
#: allowlist of cross-project read-only endpoints. Anything else
#: returns 403.
PROJECT_SCOPED_NONSLUG_ALLOWLIST: Final[frozenset[str]] = frozenset({
    # Cross-project home cards come pre-filtered to the caller's
    # visible projects; the scope itself (home:read) is still
    # required on top.
    "home",
    # Listing projects returns only rows the caller can see; a
    # project-scoped token sees only its bound project here.
    "projects",
})

#: FastAPI tag → scope resource. Any tag not listed here is treated
#: as admin-only (fail closed).
TAG_TO_RESOURCE: Final[dict[str, str]] = {
    "home": "home",
    "projects": "projects",
    "tasks": "tasks",
    "workers": "workers",
    "queues": "queues",
    "agents": "agents",
    "commands": "commands",
    "schedules": "schedules",
    "audit": "audit",
    "memberships": "memberships",
    "notifications": "notifications",
    "user-notifications": "notifications",
    "users": "users",
    "api-keys": "admin",  # minting/revoking keys is an admin surface
    "events": "tasks",    # raw event stream is a task-level surface
    "stats": "tasks",     # aggregate task stats roll up under tasks
    "auth": "auth",       # /auth/me read. Writes denied for Bearer.
}


#: Sentinel returned by :func:`required_scope` for routes that
#: have no registered tag mapping. NOT a real scope - ``admin:*``
#: intentionally does NOT satisfy it. This closes audit H1: a
#: new endpoint added without a TAG_TO_RESOURCE entry is
#: unreachable via Bearer auth until the developer explicitly
#: classifies it. Session-cookie callers are unaffected.
SCOPE_UNREACHABLE: Final[str] = "__unreachable__"


def required_scope(
    *,
    tags: list[str] | None,
    method: str,
) -> str | None:
    """Return the scope required to call the route, or ``None`` if
    the route is public. Returns :data:`SCOPE_UNREACHABLE` for
    unmapped tags so a new feature is denied to every Bearer token
    - including ``admin:*`` - until the developer adds an explicit
    TAG_TO_RESOURCE entry. Forces a review gate on every new
    endpoint.
    """
    if not tags:
        return SCOPE_UNREACHABLE
    tag = tags[0]
    if tag in PUBLIC_TAGS:
        return None
    resource = TAG_TO_RESOURCE.get(tag)
    if resource is None:
        return SCOPE_UNREACHABLE
    verb = "read" if method.upper() == "GET" else "write"
    return f"{resource}:{verb}"


def is_bearer_denied_tag(tag: str | None) -> bool:
    """Bearer (API-key) auth is denied outright for these tags.

    Covers identity-level operations (change password, revoke
    sessions, update my profile) where a narrow-scope token must
    never be allowed to escalate to full account takeover even if
    the scope check would otherwise pass.
    """
    return tag is not None and tag in BEARER_DENY_TAGS


def scope_satisfies(*, granted: list[str], required: str) -> bool:
    """Does the granted scope set cover the required one?

    Rules (in order):

    1. ``SCOPE_UNREACHABLE`` (an unmapped route) is satisfied by
       NO scope - not even ``admin:*``. Enforces a review gate
       on every new endpoint.
    2. ``admin:*`` covers every *mapped* scope.
    3. Exact match wins.
    4. ``write`` implies ``read`` on the same resource.
    """
    if required == SCOPE_UNREACHABLE:
        return False
    if "admin:*" in granted:
        return True
    if required in granted:
        return True
    # write → read implicit
    if required.endswith(":read"):
        resource = required.split(":", 1)[0]
        if f"{resource}:write" in granted:
            return True
    return False


def validate_requested_scopes(
    *,
    requested: list[str],
    user_is_admin: bool,
) -> tuple[list[str], list[str]]:
    """Split the requested scopes into ``(accepted, rejected)``.

    Scopes not in :data:`ALL_SCOPES` are rejected silently (typos,
    future scopes). Admin-only scopes are rejected for non-admin
    callers.
    """
    accepted: list[str] = []
    rejected: list[str] = []
    for s in requested:
        if s not in ALL_SCOPES:
            rejected.append(s)
            continue
        if s in ADMIN_ONLY_SCOPES and not user_is_admin:
            rejected.append(s)
            continue
        accepted.append(s)
    return accepted, rejected


__all__ = [
    "ADMIN_ONLY_SCOPES",
    "ALL_SCOPES",
    "BEARER_DENY_TAGS",
    "PROJECT_SCOPED_NONSLUG_ALLOWLIST",
    "PUBLIC_TAGS",
    "SCOPE_UNREACHABLE",
    "TAG_TO_RESOURCE",
    "is_bearer_denied_tag",
    "required_scope",
    "scope_satisfies",
    "validate_requested_scopes",
]
