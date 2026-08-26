"""Real client IP resolution behind trusted reverse proxies.

The brain runs behind Caddy / nginx / a load-balancer in production.
Audit logs MUST record the real client IP, not the proxy's IP.
``X-Forwarded-For`` is the standard chain header - but it cannot be
trusted unconditionally: a malicious caller can supply an arbitrary
value when the brain is reachable directly, which would let them
forge audit log entries against any IP.

The pattern (per RFC 7239 §5.2 and OWASP):

1. Operator declares the trusted-proxy CIDRs in
   ``Z4J_TRUSTED_PROXIES``.
2. When the socket peer is trusted, every ``X-Forwarded-For`` hop is
   parsed as an IP address. A malformed or empty hop invalidates the
   whole header and falls back to the socket peer; arbitrary text can
   never become an audit IP.
3. We walk a valid chain from RIGHT to LEFT, skipping any address
   that's inside a trusted CIDR.
4. The first address we hit that is NOT trusted is the real client.
5. If the entire chain is trusted, the leftmost address is the
   client (this is the case when the brain has multiple proxies).
6. If no proxies are trusted (default), we just use the raw socket
   peer address.

This module is FastAPI-free. The middleware in
:mod:`z4j_brain.middleware.real_client_ip` adapts it to a
``starlette.Request``.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable


class TrustedProxyResolver:
    """Resolves the real client IP from a request's headers + peer.

    Construct once at startup with the configured trusted-proxy
    CIDRs; reuse for the lifetime of the process. Thread-safe - all
    state is read-only after construction.
    """

    __slots__ = ("_networks",)

    def __init__(self, trusted_cidrs: Iterable[str]) -> None:
        nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in trusted_cidrs:
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as exc:
                raise ValueError(
                    f"trusted_proxies entry {cidr!r} is not a valid CIDR",
                ) from exc
        self._networks = tuple(nets)

    def resolve(self, *, peer_ip: str | None, xff_header: str | None) -> str:
        """Return the real client IP.

        Args:
            peer_ip: The raw socket peer (``request.client.host``).
                Trusted as the source for ``xff_header`` only if it
                matches one of the trusted CIDRs.
            xff_header: The raw ``X-Forwarded-For`` header value, or
                None if absent.

        Returns:
            A validated, canonical IP from a trusted XFF chain, otherwise the
            raw socket peer. Empty string only if ``peer_ip`` is missing; an
            XFF header is never trusted without an immediate peer.
        """
        # No trusted proxies → never read the header.
        if not self._networks or peer_ip is None:
            return peer_ip or ""

        # Don't read XFF unless the immediate peer is trusted.
        if not self._is_trusted(peer_ip):
            return peer_ip

        if not xff_header:
            return peer_ip

        # Parse the WHOLE header before trusting any part of it. Silently
        # skipping an empty/malformed hop can splice two attacker-controlled
        # fragments into a plausible chain, while treating malformed text as
        # merely "untrusted" returns that text verbatim into audit rows. A bad
        # chain therefore fails closed to the authenticated transport peer.
        chain = self._parse_xff(xff_header)
        if chain is None:
            return peer_ip

        # Walk right-to-left, skipping trusted addresses, returning the first
        # untrusted hop. If everything is trusted, the leftmost is the client.
        for candidate in reversed(chain):
            if not self._is_trusted(candidate):
                return candidate
        return chain[0]

    def is_trusted(self, ip: str) -> bool:
        """Public form of :meth:`_is_trusted`. Tests + middleware use this."""
        return self._is_trusted(ip)

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _is_trusted(self, ip: str) -> bool:
        normalized = self._normalize_ip(ip)
        if normalized is None:
            return False
        addr = ipaddress.ip_address(normalized)
        return any(addr in net for net in self._networks)

    def _parse_xff(self, xff_header: str) -> tuple[str, ...] | None:
        """Parse a complete XFF chain, rejecting it on any invalid hop."""
        raw_chain = [hop.strip() for hop in xff_header.split(",")]
        if not raw_chain or any(not hop for hop in raw_chain):
            return None
        chain = tuple(self._normalize_ip(hop) for hop in raw_chain)
        if any(hop is None for hop in chain):
            return None
        # The None branch was rejected above; rebuilding keeps the returned
        # type precise without a cast tied to tuple-comprehension narrowing.
        return tuple(hop for hop in chain if hop is not None)

    @staticmethod
    def _normalize_ip(ip: str) -> str | None:
        """Return a canonical IP string, or ``None`` for malformed input."""
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return None
        # Round-trip through the numeric address to remove any valid IPv6
        # scope/zone identifier and canonicalize compressed spellings. The
        # parser rejects zones on IPv4 and malformed/multiple zone suffixes.
        return str(ipaddress.ip_address(int(parsed)))


__all__ = ["TrustedProxyResolver"]
