"""Source-address allowlists for the brain's three authenticated surfaces.

Three optional CIDR lists restrict where a credential may be USED from:

* ``Z4J_DASHBOARD_IP_ALLOWLIST``: the login route and every request that
  authenticates with a session cookie.
* ``Z4J_API_IP_ALLOWLIST``: every request that authenticates with a Bearer
  API key. A key's own ``allowed_cidrs`` narrows this further: when set,
  the request must match the global list (if any) AND one of the key's
  own entries.
* ``Z4J_AGENT_IP_ALLOWLIST``: the agent transports (WebSocket and
  long-poll). This module only supplies :func:`check_agent_ip`; the
  transport resolves the peer and calls it.

Evaluation order, deliberately:

1. The address matched is the one :class:`~z4j_brain.auth.ip.TrustedProxyResolver`
   produced, so an ``X-Forwarded-For`` header only counts when the socket
   peer is inside ``Z4J_TRUSTED_PROXIES``. A header from anywhere else is
   ignored and the socket peer is what gets matched. With no trusted
   proxies at all, the peer is always the address matched, which behind an
   undeclared proxy is the proxy.
2. The dashboard and API lists are consulted AFTER the credential
   authenticates. The audit row can then name the user or key that was
   presented from the wrong place, which is the fact an operator wants
   when a credential leaks. The cost: a caller outside those lists can
   still tell a valid credential (403 ``ip_denied``) from an invalid one
   (401). The login route and the agent transports (the WebSocket hello
   and both long-poll routes) are the pre-credential checks: the login
   route because there is nothing to attribute yet, the agent transports
   because a machine token's validity and its project's archive state
   are not something an address outside the list should learn. Their
   ``auth.ip_denied`` rows carry no user or agent id.
3. The 403 body is the same whatever was presented: ``error`` is
   ``ip_denied`` and ``details`` names only the surface. The resolved
   address, the user and the key id go to the audit row, never to the
   caller.

An empty list means no restriction. Loopback is NOT implicitly exempt: a
list that omits ``127.0.0.1/32`` or ``::1/128`` refuses the brain's own
host too, which is what lets "only these addresses" be read literally. An
IPv4-mapped IPv6 peer (``::ffff:198.51.100.7``, what a dual-stack socket
reports for an IPv4 client) matches IPv4 entries. A request whose peer
address cannot be determined or parsed is refused by a non-empty list: a
restriction that cannot be evaluated is not satisfied.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Literal

from z4j_brain.errors import AuthorizationError

if TYPE_CHECKING:
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.repositories.audit_log import AuditLogRepository
    from z4j_brain.settings import Settings

Surface = Literal["dashboard", "api", "agent"]
DenialReason = Literal["global_allowlist", "key_allowed_cidrs"]
_Network = ipaddress.IPv4Network | ipaddress.IPv6Network
_Address = ipaddress.IPv4Address | ipaddress.IPv6Address

#: Upper bound on entries one API key may carry. A caller that needs more
#: ranges than this wants the global list, not a key.
MAX_KEY_CIDRS = 32
#: Longest well-formed entry (an IPv6 network with its prefix is 43 chars).
MAX_CIDR_LENGTH = 64
#: Longest address string an audit row's metadata keeps verbatim.
_MAX_IP_IN_METADATA = 64

#: The audit action every denial writes, on every surface.
AUDIT_ACTION = "auth.ip_denied"
#: The ``error`` code on the 403. Stable; the dashboard branches on it.
ERROR_CODE = "ip_denied"
#: The message every denial carries, independent of what was presented.
DENIED_MESSAGE = "source address is not allowed for this surface"


class IpDeniedError(AuthorizationError):
    """A credential was presented from an address its allowlist excludes.

    403 through the error middleware. ``details`` carries only the surface,
    so the body is identical for a valid session, a valid key, or the login
    route before any credential was checked.
    """

    code = ERROR_CODE


def parse_cidr_list(raw: Any, *, field_name: str) -> list[str]:
    """Validate ``raw`` as a list of CIDRs and return them in canonical form.

    Each entry is parsed with ``strict=False``, the same leniency the
    trusted-proxy list gets: ``10.1.2.3/8`` means ``10.0.0.0/8`` and a bare
    address means that one host. Entries are de-duplicated after
    canonicalisation and order is kept. Raises ``ValueError`` naming the
    field and the offending entry, which is what a pydantic validator and
    a request-body validator both want.
    """
    if raw is None:
        return []
    if isinstance(raw, str) or not isinstance(raw, Sequence):
        raise ValueError(f"{field_name} must be a list of CIDR strings")  # noqa: TRY004  pydantic validator must raise ValueError
    out: list[str] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, str):
            raise ValueError(f"{field_name} entries must be strings")  # noqa: TRY004  pydantic validator must raise ValueError
        text = entry.strip()
        if not text:
            raise ValueError(f"{field_name} must not contain an empty entry")
        if len(text) > MAX_CIDR_LENGTH:
            raise ValueError(
                f"{field_name} entries are bounded to {MAX_CIDR_LENGTH} characters",
            )
        if "%" in text:
            # ``ipaddress`` accepts a zone-scoped IPv6 literal (``fe80::1%eth0``)
            # and keeps the scope id in the canonical form, where it never
            # matches a peer: the brain compares addresses, not interfaces,
            # and a resolved client address carries no zone. Refuse it with
            # the reason rather than storing an entry that admits nobody.
            raise ValueError(
                f"{field_name} entry {text!r} carries an IPv6 zone id "
                f"({text[text.index('%') :]!r}); allowlists match addresses, "
                "not interfaces, so write the address or network without it",
            )
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise ValueError(
                f"{field_name} entry {text!r} is not a valid IPv4 or IPv6 CIDR",
            ) from exc
        canonical = str(network)
        if canonical in seen:
            continue
        seen.add(canonical)
        out.append(canonical)
    return out


@lru_cache(maxsize=64)
def _compile(cidrs: tuple[str, ...]) -> tuple[_Network, ...]:
    """Networks for a validated list; cached because the lists are tiny and fixed."""
    return tuple(ipaddress.ip_network(cidr, strict=False) for cidr in cidrs)


def _candidates(ip: str) -> tuple[_Address, ...]:
    """The address, plus its IPv4 form when it is an IPv4-mapped IPv6 address."""
    address = ipaddress.ip_address(ip)
    mapped = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
    return (address, mapped) if mapped is not None else (address,)


def ip_allowed(ip: str | None, cidrs: Sequence[str]) -> bool:
    """``True`` when ``cidrs`` is empty or one of its networks contains ``ip``.

    ``cidrs`` must already be canonical (see :func:`parse_cidr_list`); the
    settings validator and the API-key validator both guarantee that, so a
    malformed entry cannot surface here as a request-time 500.
    """
    if not cidrs:
        return True
    if not ip:
        return False
    try:
        candidates = _candidates(ip)
    except ValueError:
        return False
    networks = _compile(tuple(cidrs))
    return any(
        candidate.version == network.version and candidate in network
        for candidate in candidates
        for network in networks
    )


def _source_ip_for_audit(ip: str) -> str | None:
    """A value the ``inet`` column accepts, or ``None`` for one it would reject."""
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class IpDenial:
    """One refused request: what the 403, the audit row and the metric need.

    Carries plain values only (ids, not ORM rows) because the audit row is
    written after the request's session has closed.
    """

    surface: Surface
    ip: str
    reason: DenialReason
    user_id: uuid.UUID | None = None
    api_key_id: uuid.UUID | None = None

    def error(self) -> IpDeniedError:
        """The exception to raise: the same body on every surface."""
        return IpDeniedError(DENIED_MESSAGE, details={"surface": self.surface})

    def audit_metadata(self) -> dict[str, Any]:
        """What the ``auth.ip_denied`` row records beyond its fixed columns."""
        metadata: dict[str, Any] = {
            "surface": self.surface,
            "reason": self.reason,
            "ip": self.ip[:_MAX_IP_IN_METADATA],
        }
        if self.api_key_id is not None:
            metadata["api_key_id"] = str(self.api_key_id)
        return metadata


def _count(denial: IpDenial) -> IpDenial:
    """Bump ``z4j_auth_ip_denied_total{surface}`` and hand the denial back."""
    # Lazy: ``api.metrics`` imports ``api.deps``, which calls into this
    # module, so a module-level import would be a cycle.
    from z4j_brain.api.metrics import z4j_auth_ip_denied_total

    z4j_auth_ip_denied_total.labels(surface=denial.surface).inc()
    return denial


def _check(
    client_ip: str | None,
    *,
    surface: Surface,
    cidrs: Sequence[str],
    user_id: uuid.UUID | None = None,
    api_key_id: uuid.UUID | None = None,
) -> IpDenial | None:
    if ip_allowed(client_ip, cidrs):
        return None
    return _count(
        IpDenial(
            surface=surface,
            ip=client_ip or "",
            reason="global_allowlist",
            user_id=user_id,
            api_key_id=api_key_id,
        ),
    )


def check_dashboard_ip(
    client_ip: str | None,
    *,
    settings: Settings,
    user_id: uuid.UUID | None = None,
) -> IpDenial | None:
    """Evaluate ``Z4J_DASHBOARD_IP_ALLOWLIST`` for a session-cookie or login request.

    ``client_ip`` is the trusted-proxy-resolved address. Returns ``None``
    when the request may proceed, otherwise the denial (already counted in
    the metric) whose :meth:`IpDenial.error` the caller raises.
    """
    return _check(
        client_ip,
        surface="dashboard",
        cidrs=settings.dashboard_ip_allowlist,
        user_id=user_id,
    )


def check_api_ip(
    client_ip: str | None,
    *,
    settings: Settings,
    key_cidrs: Sequence[str] | None = None,
    api_key_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
) -> IpDenial | None:
    """Evaluate ``Z4J_API_IP_ALLOWLIST`` and then the key's own ``allowed_cidrs``.

    Both must pass. The global list is checked first so the denial reason
    says which boundary refused: ``global_allowlist`` is a deployment-wide
    rule, ``key_allowed_cidrs`` is one the key's owner wrote.
    """
    denial = _check(
        client_ip,
        surface="api",
        cidrs=settings.api_ip_allowlist,
        user_id=user_id,
        api_key_id=api_key_id,
    )
    if denial is not None:
        return denial
    if key_cidrs and not ip_allowed(client_ip, key_cidrs):
        return _count(
            IpDenial(
                surface="api",
                ip=client_ip or "",
                reason="key_allowed_cidrs",
                user_id=user_id,
                api_key_id=api_key_id,
            ),
        )
    return None


def check_agent_ip(client_ip: str | None, *, settings: Settings) -> IpDenial | None:
    """Evaluate ``Z4J_AGENT_IP_ALLOWLIST`` for an agent transport peer.

    The transport owns the hook: it resolves the peer (for a WebSocket that
    means running the trusted-proxy resolver itself, since the HTTP
    middleware does not see WebSocket scopes), calls this once per
    connection or long-poll request, and on a denial refuses the transport
    and writes the audit row with :func:`record_ip_denial`. The metric is
    counted here so a transport cannot refuse without being counted.
    """
    return _check(client_ip, surface="agent", cidrs=settings.agent_ip_allowlist)


async def record_ip_denial(
    audit: AuditService,
    audit_log: AuditLogRepository,
    denial: IpDenial,
    *,
    user_agent: str | None = None,
    path: str | None = None,
) -> None:
    """Append the ``auth.ip_denied`` row for ``denial`` on the caller's session.

    The caller commits. The row names the surface, the resolved address,
    the user and (for a key) the key id; an address the ``inet`` column
    would reject is kept verbatim in the metadata and left NULL in the
    column rather than failing the write.
    """
    metadata = denial.audit_metadata()
    if path:
        metadata["path"] = path[:200]
    await audit.record(
        audit_log,
        action=AUDIT_ACTION,
        target_type="auth_surface",
        target_id=denial.surface,
        result="failed",
        outcome="deny",
        user_id=denial.user_id,
        api_key_id=denial.api_key_id,
        source_ip=_source_ip_for_audit(denial.ip),
        user_agent=user_agent,
        metadata=metadata,
    )


__all__ = [
    "AUDIT_ACTION",
    "DENIED_MESSAGE",
    "ERROR_CODE",
    "MAX_CIDR_LENGTH",
    "MAX_KEY_CIDRS",
    "IpDenial",
    "IpDeniedError",
    "check_agent_ip",
    "check_api_ip",
    "check_dashboard_ip",
    "ip_allowed",
    "parse_cidr_list",
    "record_ip_denial",
]
