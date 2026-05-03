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
2. We walk the ``X-Forwarded-For`` chain from RIGHT to LEFT,
   skipping any address that's inside a trusted CIDR.
3. The first address we hit that is NOT trusted is the real client.
4. If the entire chain is trusted, the leftmost address is the
   client (this is the case when the brain has multiple proxies).
5. If no proxies are trusted (default), we just use the raw socket
   peer address.

This module is FastAPI-free. The middleware in
:mod:`z4j_brain.middleware.real_client_ip` adapts it to a
``starlette.Request``.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable


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
            A best-effort string IP. Empty string only if both
            ``peer_ip`` and ``xff_header`` are missing.
        """
        if peer_ip is None and xff_header is None:
            return ""

        # No trusted proxies → never read the header.
        if not self._networks or peer_ip is None:
            return peer_ip or ""

        # Don't read XFF unless the immediate peer is trusted.
        if not self._is_trusted(peer_ip):
            return peer_ip

        if not xff_header:
            return peer_ip

        # Walk right-to-left, skipping trusted addresses, returning
        # the first untrusted hop. If everything is trusted, the
        # leftmost is the client.
        chain = [hop.strip() for hop in xff_header.split(",") if hop.strip()]
        for candidate in reversed(chain):
            normalized = self._strip_zone(candidate)
            if not self._is_trusted(normalized):
                return normalized
        return self._strip_zone(chain[0]) if chain else peer_ip

    def is_trusted(self, ip: str) -> bool:
        """Public form of :meth:`_is_trusted`. Tests + middleware use this."""
        return self._is_trusted(ip)

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _is_trusted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(self._strip_zone(ip))
        except ValueError:
            return False
        return any(addr in net for net in self._networks)

    @staticmethod
    def _strip_zone(ip: str) -> str:
        """Strip an IPv6 zone identifier (``fe80::1%eth0`` → ``fe80::1``)."""
        if "%" in ip:
            return ip.split("%", 1)[0]
        return ip


__all__ = ["TrustedProxyResolver"]
