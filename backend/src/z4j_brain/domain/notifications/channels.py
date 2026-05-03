"""Notification delivery channels.

Each channel is a small async function that takes a config dict
(from NotificationChannel.config) and a payload dict (the
notification body), delivers the notification, and returns a
:class:`DeliveryResult`.

Channels are stateless - they don't hold connections or sessions.
The NotificationService constructs a fresh delivery on every fire.
Retry logic is owned by the service, not the channel.

Channel config shapes:

- webhook: {"url": "https://...", "headers": {"X-Custom": "val"},
            "hmac_secret": "optional-secret-for-signing"}
- email:   {"smtp_host": "smtp.gmail.com", "smtp_port": 587,
            "smtp_user": "...", "smtp_pass": "...",
            "smtp_tls": true, "from_addr": "alerts@example.com",
            "to_addrs": ["ops@example.com"]}
- slack:   {"webhook_url": "https://hooks.slack.com/services/..."}
- telegram: {"bot_token": "123456:ABC-DEF", "chat_id": "-100123456"}
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import re
import json
import logging
import socket
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("z4j.brain.notifications.channels")

#: Timeout for all outbound HTTP requests from notification channels.
_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# ---------------------------------------------------------------------------
# Shared HTTP client (PERF-04).
# ---------------------------------------------------------------------------
#
# The FastAPI lifespan installs a single ``httpx.AsyncClient`` at startup
# and calls :func:`set_shared_client` with it. Dispatchers then use
# :func:`_post` which reuses that pooled client (keep-alive + connection
# pool) instead of building a fresh TCP+TLS connection for every
# delivery. Tests and CLI paths that don't run the lifespan fall back
# to an ad-hoc short-lived client.
_shared_client: httpx.AsyncClient | None = None


def set_shared_client(client: httpx.AsyncClient | None) -> None:
    """Install (or clear) the process-wide shared HTTP client.

    Called from the FastAPI lifespan at startup with the pooled
    client, and again at shutdown with ``None``.
    """
    global _shared_client
    _shared_client = client


# Audit fix Low/Config-2 (1.4.0 pre-release pass): module-level
# flag for whether ``http://`` webhook targets are permitted.
# Default False -- HTTPS-only -- so a fresh deployment without any
# Z4J_NOTIFICATIONS_WEBHOOK_ALLOW_HTTP env var refuses plaintext
# webhook URLs at config time AND at dispatch time. Operators with
# legitimate internal-network http endpoints (intranet receivers,
# dev rigs) flip the brain Settings flag to opt in.
_allow_http_webhooks: bool = False


def set_allow_http_webhooks(allow: bool) -> None:
    """Install the http-webhook policy from brain Settings.

    Called from the FastAPI lifespan at startup with the value of
    ``settings.notifications_webhook_allow_http``. Tests can also
    flip this directly to exercise both modes.
    """
    global _allow_http_webhooks
    _allow_http_webhooks = bool(allow)


#: Hard cap on response body bytes we read from a webhook target.
#: Hostile webhooks could otherwise stream multi-GB responses
#: within the request timeout window and exhaust dispatcher
#: memory (R3 finding M14). 8 KiB is more than enough to capture
#: a useful error message.
_MAX_RESPONSE_BYTES = 8 * 1024


async def resolve_and_pin(url: str) -> tuple[str | None, str | None]:
    """Validate + return ``(error, safe_ip)``.

    Runs the same static URL checks + DNS-then-block-list
    validation as :func:`validate_webhook_url`, but also returns
    the first **safe resolved IP** so callers can connect to that
    exact IP instead of re-resolving the hostname at request time.

    This closes the DNS-rebinding window (R3 finding M15) - an
    attacker who controls a domain's DNS and flips the A record
    between validation and the actual HTTP connection would
    otherwise get a private IP dialled despite the upfront check.
    By pinning the validated IP, the connect step cannot be
    redirected by DNS.
    """
    static_error, hostname = _static_url_checks(url)
    if static_error is not None:
        return static_error, None
    assert hostname is not None

    ips = await _resolve_cached(hostname)
    if not ips:
        return f"cannot resolve hostname '{hostname}'", None

    safe_ip: str | None = None
    for raw_ip in ips:
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        # Round-7 audit fix R7-HIGH (Apr 2026): use the unified
        # semantic-property check that catches IPv4-mapped IPv6,
        # 6to4, NAT64, and CGNAT alongside the classic private/loopback
        # ranges. Pre-fix this loop iterated only ``_BLOCKED_NETWORKS``
        # and missed the v4-mapped-v6 bypass.
        block_reason = _ip_is_blocked(ip)
        if block_reason is not None:
            return block_reason, None
        if safe_ip is None:
            safe_ip = raw_ip
    if safe_ip is None:
        return f"no usable IP resolved for '{hostname}'", None
    return None, safe_ip


def _pin_url_to_ip(url: str, safe_ip: str) -> tuple[httpx.URL, str, int]:
    """Return ``(pinned_url, original_host, port)``.

    Rewrites the URL's host to the already-validated IP so the TCP
    connect targets exactly that IP. Callers still set the
    ``Host`` header + ``sni_hostname`` extension to the original
    hostname so virtual-host routing and TLS SNI / certificate
    verification keep working against the real domain, not the IP.
    """
    parsed = httpx.URL(url)
    original_host = parsed.host
    scheme = parsed.scheme or "https"
    default_port = 443 if scheme == "https" else 80
    port = parsed.port or default_port
    # Bracket IPv6 literals for the URL host field.
    ip_for_url = f"[{safe_ip}]" if ":" in safe_ip else safe_ip
    pinned = parsed.copy_with(host=ip_for_url)
    return pinned, original_host, port


async def _post(
    url: str,
    *,
    pin_ip: str | None = None,
    **kwargs: Any,
) -> httpx.Response:
    """POST ``url`` and return the response with body bounded.

    Uses httpx's streaming mode so an attacker-controlled webhook
    target streaming gigabytes back hits our ``_MAX_RESPONSE_BYTES``
    cap instead of buffering the whole response into memory. The
    returned response has its ``.content`` already populated with
    the truncated bytes so callers can use ``resp.text`` /
    ``resp.json()`` normally - they just see at most
    ``_MAX_RESPONSE_BYTES`` of it.

    When ``pin_ip`` is provided, the TCP connect targets that
    exact IP (DNS-rebinding defence, M15). The ``Host`` header
    and TLS ``sni_hostname`` extension are set to the original
    URL's hostname so virtual-host routing and TLS cert
    verification keep working against the real domain.
    """
    headers = kwargs.pop("headers", None) or {}
    request_url = url
    extensions: dict[str, Any] = {}
    if pin_ip is not None:
        pinned, original_host, _port = _pin_url_to_ip(url, pin_ip)
        request_url = str(pinned)
        # Round-7 audit fix R7-LOW (Apr 2026): the IP-pin's Host
        # header MUST win over any caller-supplied value. Otherwise
        # a future code path that bypassed ``validate_webhook_headers``
        # could let an attacker re-route the pinned request to a
        # different vhost on the resolved IP. The validator already
        # bans ``Host`` from incoming config, but defense-in-depth:
        # let the trailing dict of explicit pins override caller
        # input rather than the other way around.
        headers = {**headers, "Host": original_host}
        # Tell httpx/httpcore to use the original hostname for TLS
        # SNI AND for certificate hostname verification, even
        # though the socket connects to ``safe_ip``.
        extensions = {"sni_hostname": original_host}

    client_owner: httpx.AsyncClient
    using_shared = _shared_client is not None
    if using_shared:
        client_owner = _shared_client  # type: ignore[assignment]
    else:
        client_owner = httpx.AsyncClient(
            timeout=_TIMEOUT,
            follow_redirects=False,
        )
    try:
        req = client_owner.build_request(
            "POST",
            request_url,
            headers=headers,
            extensions=extensions or None,
            **kwargs,
        )
        resp = await client_owner.send(req, stream=True)
        try:
            buf = bytearray()
            async for chunk in resp.aiter_raw():
                buf.extend(chunk)
                if len(buf) >= _MAX_RESPONSE_BYTES:
                    del buf[_MAX_RESPONSE_BYTES:]
                    break
        finally:
            await resp.aclose()
        # Re-attach the bounded body so callers can use the public
        # httpx API (``resp.text``, ``resp.json()``) without
        # touching the streaming machinery themselves.
        resp = httpx.Response(
            status_code=resp.status_code,
            headers=resp.headers,
            content=bytes(buf),
            request=req,
        )
        return resp
    finally:
        if not using_shared:
            # Round-8 audit fix R8-Async-MED (Apr 2026): shield the
            # ad-hoc client close so a request-cancel mid-aclose
            # doesn't leak the client + its connection pool.
            try:
                await asyncio.shield(client_owner.aclose())
            except Exception:  # noqa: BLE001
                logger.debug(
                    "z4j notifications._post: shielded aclose raised",
                    exc_info=True,
                )

#: Allowed URL schemes for webhook targets. ``https`` is always
#: permitted; ``http`` is gated by :data:`_allow_http_webhooks`
#: (audit fix Low/Config-2, 1.4.0 pre-release pass).
_HTTPS_ONLY_SCHEMES = frozenset({"https"})
_HTTPS_PLUS_HTTP_SCHEMES = frozenset({"https", "http"})


def _allowed_schemes() -> frozenset[str]:
    """Return the active scheme allow-list based on operator policy."""
    return (
        _HTTPS_PLUS_HTTP_SCHEMES if _allow_http_webhooks
        else _HTTPS_ONLY_SCHEMES
    )

#: Private/reserved IP ranges that must never be targeted by webhooks.
#:
#: Round-7 audit fix R7-HIGH (Apr 2026): the prior list was
#: enumeration-based and missed IPv4-mapped IPv6 (``::ffff:127.0.0.1``,
#: ``::ffff:169.254.169.254``), those addresses do NOT match the
#: ``127.0.0.0/8`` / ``169.254.0.0/16`` IPv4 networks, so an attacker
#: who controlled a public AAAA record could resolve to a v6-mapped
#: loopback / link-local and bypass the entire SSRF guard. Also
#: missed CGNAT (RFC 6598, ``100.64.0.0/10``) which fronts a lot of
#: home-router admin UIs, benchmark range (``198.18.0.0/15``), and
#: 6to4 / NAT64 (``2002::/16`` and ``64:ff9b::/96``) which can route
#: to private IPv4 destinations through a v6 tunnel.
#:
#: We keep the explicit network list for the few ranges that
#: ``ipaddress`` doesn't classify as ``is_private`` (CGNAT, benchmark,
#: 6to4, NAT64) and additionally check the semantic predicates below
#: in :func:`_ip_is_blocked` so a single helper covers every shape.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),        # "this network" (RFC 1122)
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),    # R7-MED: CGNAT (RFC 6598)
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),    # R7-MED: benchmark (RFC 2544)
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / AWS metadata
    ipaddress.ip_network("::/128"),           # IPv6 unspecified
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),  # IPv6 private
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("2002::/16"),  # R7-MED: 6to4 (can wrap loopback)
    ipaddress.ip_network("64:ff9b::/96"),  # R7-MED: NAT64
]


def _ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Return a human-readable block reason or None if ``ip`` is OK.

    Round-7 audit fix R7-HIGH (Apr 2026): unifies the three SSRF
    checks the codebase used to repeat per-callsite. Always:

    1. Unwrap an IPv4-mapped IPv6 address (``::ffff:1.2.3.4``) into
       its 4-byte twin and recurse, without this, ``::ffff:127.0.0.1``
       passes every ``v4_address in v4_network`` check.
    2. Reject anything ``is_loopback`` / ``is_private`` /
       ``is_link_local`` / ``is_multicast`` / ``is_reserved`` /
       ``is_unspecified``. These predicates evaluate the full
       semantic class so future RFC additions don't silently slip
       through.
    3. Reject anything explicitly named in :data:`_BLOCKED_NETWORKS`
       for the few ranges (CGNAT, benchmark, 6to4, NAT64) that the
       semantic predicates don't classify as private but that an
       SSRF attacker could pivot through.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped
        if mapped is not None:
            inner = _ip_is_blocked(mapped)
            if inner is not None:
                return f"v4-mapped {inner}"
    if ip.is_loopback:
        return f"target IP {ip} is loopback"
    if ip.is_private:
        return f"target IP {ip} is in a private range"
    if ip.is_link_local:
        return f"target IP {ip} is link-local (cloud metadata reachable)"
    if ip.is_multicast:
        return f"target IP {ip} is multicast"
    if ip.is_reserved:
        return f"target IP {ip} is reserved"
    if ip.is_unspecified:
        return f"target IP {ip} is unspecified"
    for network in _BLOCKED_NETWORKS:
        if ip.version != network.version:
            continue
        if ip in network:
            return f"target IP {ip} is in blocked range {network}"
    return None


def _static_url_checks(url: str) -> tuple[str | None, str | None]:
    """Cheap URL checks that don't require DNS.

    Returns ``(error, hostname)``. If ``error`` is non-None the URL
    is rejected without a DNS lookup (faster for validation paths).
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return "invalid URL", None

    schemes = _allowed_schemes()
    if parsed.scheme not in schemes:
        if parsed.scheme == "http" and not _allow_http_webhooks:
            return (
                "scheme 'http' is not allowed by default; set "
                "Z4J_NOTIFICATIONS_WEBHOOK_ALLOW_HTTP=true to opt "
                "in (the operator policy default is HTTPS-only "
                "to prevent payload + header leakage in transit)"
            ), None
        return (
            f"scheme '{parsed.scheme}' not allowed (use {sorted(schemes)})"
        ), None

    hostname = parsed.hostname
    if not hostname:
        return "URL has no hostname", None

    return None, hostname


# Short-lived in-process DNS cache (PERF-05). Keyed by hostname,
# value is (expires_monotonic, [ip_strings]). Empty list = NXDOMAIN /
# resolver failure (so repeated misses are also cached briefly).
#
# Audit fix S007 (1.4.0): bounded LRU. Pre-fix the cache was an
# unbounded ``dict``, so an authenticated tenant who could create
# notification channels (or test webhooks) for many distinct
# hostnames could grow it without bound. The 30s TTL evicts on
# next-lookup, but a continuous flow of new hostnames would still
# accumulate stale entries between sweeps. The hard LRU cap
# guarantees bounded memory regardless of churn pattern.
#
# 10000 entries is well above any realistic deployment (a homelab
# brain has tens of channels; a multi-tenant deployment in the
# hundreds), and ~10K * (~80 bytes hostname + ~200 bytes value)
# tops out at ~3 MB. LRU eviction order is "oldest insert first"
# via the OrderedDict + move_to_end pattern.
_DNS_CACHE: "OrderedDict[str, tuple[float, list[str]]]" = OrderedDict()
_DNS_CACHE_MAX = 10_000
_DNS_TTL = 30.0


#: Hard timeout on a DNS resolve (audit P-5, added v1.0.14). The OS
#: resolver normally takes 5-50ms but a stale /etc/resolv.conf or
#: a slow upstream resolver can block for 30s+. Wrapping in
#: asyncio.wait_for caps the wait so a slow-DNS host can't block a
#: REST handler indefinitely.
_DNS_RESOLVE_TIMEOUT = 5.0


async def _resolve_cached(hostname: str) -> list[str]:
    """Resolve ``hostname`` with a short TTL cache and timeout.

    Returns a list of IP strings (may be empty if resolution failed
    or timed out). Uses ``asyncio.to_thread`` so the event loop
    never blocks on a slow resolver. Cache hits return without
    crossing the GIL.

    Per audit P-5 (v1.0.14+) the resolve is wrapped in
    ``asyncio.wait_for(_DNS_RESOLVE_TIMEOUT)`` so a hostname that
    points at a black-holed DNS server can't pin a REST request for
    the OS resolver's full retry budget (often 30s). On timeout the
    cache stores an empty result for the TTL window so we don't
    re-attempt every 100ms during a flood.
    """
    now = time.monotonic()
    entry = _DNS_CACHE.get(hostname)
    if entry is not None and entry[0] > now:
        # Audit fix S007 (1.4.0): touch MRU on hit so a hot
        # hostname doesn't get evicted while idle ones survive.
        _DNS_CACHE.move_to_end(hostname)
        return entry[1]
    try:
        infos = await asyncio.wait_for(
            asyncio.to_thread(
                socket.getaddrinfo, hostname, None, socket.AF_UNSPEC,
            ),
            timeout=_DNS_RESOLVE_TIMEOUT,
        )
    except (socket.gaierror, TimeoutError):
        # Both no-such-host and slow-resolver land here. Cache the
        # negative result so a flood of requests for the same bad
        # hostname doesn't multiply the wait.
        _set_dns_cache_entry(hostname, now + _DNS_TTL, [])
        return []
    ips: list[str] = []
    for _family, _type, _proto, _canonname, sockaddr in infos:
        ips.append(sockaddr[0])
    _set_dns_cache_entry(hostname, now + _DNS_TTL, ips)
    return ips


def _set_dns_cache_entry(
    hostname: str, expires_at: float, ips: list[str],
) -> None:
    """Insert into ``_DNS_CACHE`` and enforce the LRU cap.

    Audit fix S007 (1.4.0): bound the cache at ``_DNS_CACHE_MAX``
    entries. Eviction policy is oldest-insert-first via the
    OrderedDict; ``move_to_end`` on hit keeps hot keys alive.
    """
    _DNS_CACHE[hostname] = (expires_at, ips)
    _DNS_CACHE.move_to_end(hostname)
    while len(_DNS_CACHE) > _DNS_CACHE_MAX:
        _DNS_CACHE.popitem(last=False)


async def validate_webhook_url(url: str) -> str | None:
    """Validate a webhook URL is safe to request (async-safe).

    Returns an error string if the URL is blocked, or None if safe.
    Blocks private IPs, loopback, link-local, and non-HTTP(S) schemes.

    Uses ``getaddrinfo`` via ``asyncio.to_thread`` (cached for a short
    TTL) so the event loop is not blocked on slow DNS resolvers and
    bursts of deliveries to the same host hit the cache.

    Limitation: DNS rebinding attacks are possible if an attacker
    controls a domain's DNS and changes the A record between
    validation and the actual HTTP request. The httpx client is
    configured with ``follow_redirects=False`` to prevent
    redirect-based SSRF. Full DNS pinning would require a custom
    httpx transport.
    """
    static_error, hostname = _static_url_checks(url)
    if static_error is not None:
        return static_error
    assert hostname is not None

    ips = await _resolve_cached(hostname)
    if not ips:
        return f"cannot resolve hostname '{hostname}'"

    for raw_ip in ips:
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        # Round-7 audit fix R7-HIGH (Apr 2026): unified semantic check.
        block_reason = _ip_is_blocked(ip)
        if block_reason is not None:
            return block_reason

    return None


#: Telegram bot-token shape: ``<numeric-id>:<base62-secret>``.
#: Forbids ``@``, ``/``, ``.`` etc. so a malformed token cannot
#: smuggle ``user@attacker.internal:8080/x`` into the URL that
#: ``deliver_telegram`` constructs. Match-exact (fullmatch) -
#: trailing whitespace, newlines, or null bytes are rejected.
_TELEGRAM_BOT_TOKEN_RE = re.compile(r"^\d+:[A-Za-z0-9_-]+$")

#: Telegram chat_id shape: signed integer (groups can be negative)
#: or ``@channel_handle``. Anything else would affect URL parsing.
_TELEGRAM_CHAT_ID_RE = re.compile(r"^(-?\d+|@[A-Za-z0-9_]+)$")


def validate_telegram_config(config: dict[str, Any]) -> str | None:
    """Validate a telegram channel config. Returns None if safe.

    Closes the userinfo-smuggling SSRF: without strict validation
    an admin could supply ``bot_token = "123:abc@attacker.internal:8080/x"``,
    which httpx parses as userinfo and dials the attacker's host.
    Both the project-admin-managed channel path and the user-
    managed channel path MUST call this - the earlier code only
    wired it into the project path (external audit High #2).
    """
    bot_token = config.get("bot_token")
    if bot_token is not None:
        if not isinstance(bot_token, str) or not _TELEGRAM_BOT_TOKEN_RE.fullmatch(
            bot_token,
        ):
            return "telegram bot_token must match \\d+:[A-Za-z0-9_-]+"
    chat_id = config.get("chat_id")
    if chat_id is not None:
        if isinstance(chat_id, int):
            chat_id = str(chat_id)
        if not isinstance(chat_id, str) or not _TELEGRAM_CHAT_ID_RE.fullmatch(
            chat_id,
        ):
            return (
                "telegram chat_id must be a signed integer "
                "or @-prefixed handle"
            )
    return None


#: Ports we permit for SMTP delivery. Standard SMTP ports - a few
#: common + the Postfix submission port. Rejects Redis (6379),
#: Postgres (5432), SSH (22), HTTP admin panels (8000-8999),
#: cloud metadata (80 on 169.254.169.254), etc.
_SMTP_PORT_ALLOWLIST: frozenset[int] = frozenset({
    25,   # classic SMTP (rare for egress but kept for legacy)
    465,  # SMTPS (implicit TLS)
    587,  # submission port (STARTTLS) - the modern default
    2525, # common alternate for residential ISPs / cloud providers
})


async def validate_smtp_config(config: dict[str, Any]) -> str | None:
    """Validate an email/SMTP channel config. Returns None if safe.

    Email channels were an unrestricted server-side egress
    primitive - any authenticated user who could create a
    personal email channel got a blind internal-network
    reachability tool because dispatch ``aiosmtplib.send(hostname=host,
    port=port, ...)`` ran against arbitrary host/port values.
    This validator refuses:

    - Non-string / empty ``smtp_host``
    - Private / loopback / link-local IPs (via the same
      ``_BLOCKED_NETWORKS`` guard used for webhook URLs)
    - Non-standard ``smtp_port`` (allowlist above)

    Called by both the project-channel and user-channel validators
    (external audit High #3).
    """
    host = config.get("smtp_host")
    if host is not None:
        if not isinstance(host, str) or not host.strip():
            return "smtp_host is required"
        # Reject literal IP targeting private / loopback ranges.
        # A hostname is resolved via the same DNS cache we use
        # for webhook URLs - reuses the existing guard.
        stripped = host.strip()
        try:
            ip = ipaddress.ip_address(stripped)
        except ValueError:
            ip = None
        if ip is not None:
            # Round-7 audit fix R7-HIGH (Apr 2026): unified semantic check.
            block_reason = _ip_is_blocked(ip)
            if block_reason is not None:
                return f"smtp_host {block_reason}"
        else:
            # Resolve + check every A/AAAA. Same pattern as
            # ``validate_webhook_url``.
            ips = await _resolve_cached(stripped)
            if not ips:
                return f"cannot resolve smtp_host '{stripped}'"
            for raw_ip in ips:
                try:
                    resolved = ipaddress.ip_address(raw_ip)
                except ValueError:
                    continue
                block_reason = _ip_is_blocked(resolved)
                if block_reason is not None:
                    return (
                        f"smtp_host '{stripped}' resolves to a blocked "
                        f"address: {block_reason}"
                    )
    port_raw = config.get("smtp_port")
    if port_raw is not None:
        try:
            port = int(port_raw)
        except (TypeError, ValueError):
            return "smtp_port must be an integer"
        if port not in _SMTP_PORT_ALLOWLIST:
            return (
                f"smtp_port {port} is not in the allowlist "
                f"{sorted(_SMTP_PORT_ALLOWLIST)}"
            )
    return None


# Synchronous alias used by legacy dispatcher paths. New code should
# prefer :func:`validate_webhook_url` so the event loop is not blocked
# on DNS.
def _validate_webhook_url(url: str) -> str | None:
    static_error, hostname = _static_url_checks(url)
    if static_error is not None:
        return static_error
    assert hostname is not None
    try:
        resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
    except socket.gaierror:
        return f"cannot resolve hostname '{hostname}'"
    for _family, _type, _proto, _canonname, sockaddr in resolved:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        # Round-7 audit fix R7-HIGH (Apr 2026): unified semantic check.
        block_reason = _ip_is_blocked(ip)
        if block_reason is not None:
            return block_reason
    return None


# Header names that are NEVER allowed to be set by user config.
# Prevents auth-header injection and request-smuggling tricks.
_BLOCKED_HEADER_NAMES = frozenset({
    "host",
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
})


def validate_webhook_headers(
    headers: dict[str, Any] | None,
) -> tuple[str | None, dict[str, str]]:
    """Sanitize a user-supplied custom-header dict.

    Returns ``(error, safe_headers)``. Rejects reserved / hop-by-hop
    / auth headers, and any key or value containing CR/LF. Caps the
    total number of headers and total size.
    """
    if not headers:
        return None, {}
    if not isinstance(headers, dict):
        return "custom headers must be a JSON object", {}
    if len(headers) > 20:
        return "too many custom headers (max 20)", {}

    safe: dict[str, str] = {}
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, (str, int, float)):
            return f"header '{key}' has unsupported type", {}
        name = key.strip()
        val = str(value)
        if not name:
            return "custom header name is empty", {}
        if name.lower() in _BLOCKED_HEADER_NAMES:
            return f"header '{name}' is reserved and cannot be set", {}
        if "\r" in name or "\n" in name or "\r" in val or "\n" in val:
            return f"header '{name}' contains CR/LF", {}
        if len(name) > 100 or len(val) > 1024:
            return f"header '{name}' exceeds size limit", {}
        safe[name] = val
    return None, safe


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    """Outcome of a single delivery attempt."""

    success: bool
    status_code: int | None = None
    response_body: str | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------


async def deliver_webhook(
    config: dict[str, Any],
    payload: dict[str, Any],
) -> DeliveryResult:
    """POST JSON payload to the configured URL.

    If ``hmac_secret`` is set in the config, the request body is
    signed with HMAC-SHA256 and the signature is sent in the
    ``X-Z4J-Signature`` header so the receiver can verify
    authenticity.
    """
    url = config.get("url", "")
    if not url:
        return DeliveryResult(success=False, error="webhook URL is empty")

    # SSRF protection: validate scheme and block private/internal IPs.
    # Uses the async-safe validator so DNS lookup does not block the
    # event loop.
    ssrf_error = await validate_webhook_url(url)
    if ssrf_error:
        return DeliveryResult(success=False, error=f"blocked: {ssrf_error}")

    # Sanitize user-supplied headers at dispatch (the create/update
    # endpoints also reject these, but we re-validate in case a row
    # predates the validation).
    header_error, safe_custom_headers = validate_webhook_headers(
        config.get("headers"),
    )
    if header_error:
        return DeliveryResult(
            success=False,
            error=f"blocked: unsafe headers: {header_error}",
        )

    body = json.dumps(payload, default=str, ensure_ascii=False)
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "User-Agent": "z4j-brain/notification-webhook",
        **safe_custom_headers,
    }

    hmac_secret = config.get("hmac_secret")
    if hmac_secret:
        sig = hmac.new(
            hmac_secret.encode("utf-8"),
            body.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        headers["X-Z4J-Signature"] = f"sha256={sig}"

    try:
        # Re-validate + pin the target IP at dispatch time (M15
        # DNS-rebinding defence). Even though the config was
        # validated at PATCH/POST time, an attacker who controls
        # the hostname's DNS could flip the A record between
        # then and now - so we resolve again and connect to the
        # safe IP directly.
        err, safe_ip = await resolve_and_pin(url)
        if err is not None:
            return DeliveryResult(
                success=False, error=f"unsafe URL at dispatch: {err}",
            )
        resp = await _post(
            url, content=body, headers=headers, pin_ip=safe_ip,
        )
        return DeliveryResult(
            success=200 <= resp.status_code < 300,
            status_code=resp.status_code,
            response_body=resp.text[:1000],
        )
    except Exception as exc:
        return DeliveryResult(success=False, error=str(exc)[:500])


# ---------------------------------------------------------------------------
# Email (SMTP - bring your own credentials)
# ---------------------------------------------------------------------------


async def deliver_email(
    config: dict[str, Any],
    payload: dict[str, Any],
) -> DeliveryResult:
    """Send an email via SMTP.

    Uses ``aiosmtplib`` for async delivery. Supports STARTTLS
    (port 587, the Gmail app-password flow) and implicit TLS
    (port 465). No OAuth - just SMTP credentials.
    """
    try:
        import aiosmtplib
        from email.mime.text import MIMEText
    except ImportError:
        return DeliveryResult(
            success=False,
            error="aiosmtplib is not installed; email notifications unavailable",
        )

    host = config.get("smtp_host", "")
    port = int(config.get("smtp_port", 587))
    user = config.get("smtp_user", "")
    password = config.get("smtp_pass", "")
    use_tls = config.get("smtp_tls", True)
    from_addr = config.get("from_addr", user)
    # Transactional path: payload.to_addrs overrides the channel's
    # configured recipients. Used for invitation emails + password
    # reset - the recipient is the user being invited/reset, not
    # the channel's default alert list.
    to_addrs = payload.get("to_addrs") or config.get("to_addrs", [])

    if not host or not to_addrs:
        return DeliveryResult(success=False, error="SMTP config incomplete")

    # Dispatch-time blocklist re-check. We re-resolve the hostname
    # and refuse to send if any A/AAAA record now points at a
    # private / loopback / link-local range - closes the narrow
    # DNS-rebinding window between ``validate_smtp_config`` at
    # PATCH time and the actual dispatch.
    #
    # We deliberately do NOT pin the TCP connect to the resolved
    # IP (the way ``deliver_webhook`` / ``deliver_slack`` do).
    # Rationale: aiosmtplib's STARTTLS path uses
    # ``asyncio.loop.start_tls(..., server_hostname=...)``, which
    # on Python 3.14 / Windows fails to honour the hostname
    # override - the TLS layer still verifies the peer cert
    # against whatever ``hostname`` the SMTP client was
    # constructed with. Pinning to an IP therefore makes TLS
    # reject every public SMTP host with an "IP address mismatch"
    # error. The workable paths are:
    #
    #   (a) pin to IP + disable ``check_hostname`` + manually
    #       ssl.match_hostname(peer_cert, original_host) after
    #       handshake - preserves DNS-pin but reimplements cert
    #       verification. Audit liability.
    #   (b) dial the hostname directly - aiosmtplib does one
    #       fresh resolve internally, TLS verifies correctly,
    #       and we accept the few-second rebinding window.
    #
    # We take (b): the threat model for SMTP channels is
    # fundamentally different from webhooks. SMTP creds sit in
    # channel config and are limited to what the remote SMTP
    # server permits; DNS rebinding to a private IP would need
    # the attacker to control DNS for the SMTP hostname, which
    # for public providers (Gmail / Mailgun / Brevo / SendGrid /
    # Postmark) is infeasible. For operator-run SMTP hosts, the
    # blocklist below on re-resolve still refuses private-range
    # hits. Audit 2026-04-24 Medium-5 (to be filed): the R5 H2
    # finding is downgraded from "pin the IP" to "re-validate at
    # dispatch".
    try:
        import ipaddress as _ipaddress

        try:
            already_ip = _ipaddress.ip_address(host.strip())
        except ValueError:
            already_ip = None
        if already_ip is None:
            ips = await _resolve_cached(host)
            if not ips:
                return DeliveryResult(
                    success=False,
                    error=f"smtp_host '{host}' did not resolve",
                )
            for raw_ip in ips:
                try:
                    parsed_ip = _ipaddress.ip_address(raw_ip)
                except ValueError:
                    continue
                # Round-7 audit fix R7-HIGH (Apr 2026): unified
                # semantic check covers IPv4-mapped IPv6 etc.
                block_reason = _ip_is_blocked(parsed_ip)
                if block_reason is not None:
                    return DeliveryResult(
                        success=False,
                        error=(
                            f"smtp_host '{host}' resolved to a blocked "
                            f"address at dispatch: {block_reason}"
                        ),
                    )
    except Exception as exc:  # noqa: BLE001
        return DeliveryResult(
            success=False, error=f"smtp_host validation failed: {exc}",
        )

    subject = _build_email_subject(payload)
    body_text = _build_email_body(payload)

    # Round-6 audit fix Notif-MED (Apr 2026): defensive header
    # injection guard. The Subject / From / To values flow from a
    # mix of operator config (``from_addr``, ``to_addrs``) and
    # caller payload (``subject`` for transactional emails). A bare
    # ``msg["Subject"] = subject`` with an attacker-controlled
    # newline would let RFC 5322 header injection through (BCC
    # smuggling, body forgery). Reject any value containing CR/LF
    # before it reaches MIMEText, which itself accepts any string.
    def _no_crlf(value: str, field: str) -> str:
        if "\r" in value or "\n" in value:
            raise ValueError(
                f"email header {field} contains CR/LF; refusing to send",
            )
        return value

    try:
        safe_subject = _no_crlf(subject, "Subject")
        safe_from = _no_crlf(str(from_addr), "From")
        safe_to_list = [_no_crlf(str(addr), "To") for addr in to_addrs]
    except ValueError as exc:
        return DeliveryResult(success=False, error=str(exc))

    msg = MIMEText(body_text, "plain", "utf-8")
    msg["Subject"] = safe_subject
    msg["From"] = safe_from
    msg["To"] = ", ".join(safe_to_list)

    # Dial the hostname directly (see the long comment above for
    # why we don't pin the IP). Use the low-level SMTP class so
    # we control connect / login / send individually - cleaner
    # error attribution than the ``aiosmtplib.send()``
    # convenience, which also dropped the ``tls_hostname`` kwarg
    # in 5.x.
    #
    # TLS kwargs go on the CONSTRUCTOR, not as explicit calls.
    # aiosmtplib 5.x auto-STARTTLS during ``connect()`` when
    # ``start_tls=True``; calling ``.starttls()`` again after
    # that raises ``"Connection already using TLS"``.
    #
    # Port mapping:
    #   25 / 2525: plaintext (``use_tls=False`` + ``start_tls=False``)
    #   587:       submission + STARTTLS (``start_tls=True``)
    #   465:       implicit TLS from connect (``use_tls=True``)
    try:
        port_int = int(port)
        implicit_tls = port_int == 465
        explicit_starttls = bool(use_tls) and not implicit_tls

        client = aiosmtplib.SMTP(
            hostname=host,
            port=port_int,
            use_tls=implicit_tls,
            start_tls=explicit_starttls,
            timeout=10,
        )
        await client.connect()
        try:
            if user:
                await client.login(user, password)
            await client.send_message(msg)
        finally:
            try:
                await client.quit()
            except Exception:  # noqa: BLE001
                # ``quit()`` can throw after a successful send
                # if the server closes the socket fast; the
                # send already succeeded, don't mask that.
                pass
        return DeliveryResult(success=True, status_code=250)
    except Exception as exc:  # noqa: BLE001
        return DeliveryResult(success=False, error=str(exc)[:500])


def _build_email_subject(payload: dict[str, Any]) -> str:
    # Transactional-email path (invitations / password reset / setup):
    # the caller provides an explicit subject. Fall through to the
    # task-notification template when absent.
    override = payload.get("subject")
    if override:
        return str(override)[:200]
    trigger = payload.get("trigger", "notification")
    task_name = payload.get("task_name", "")
    priority = payload.get("priority", "normal")
    prefix = f"[{priority.upper()}] " if priority != "normal" else ""
    return f"{prefix}z4j: {trigger} - {task_name}" if task_name else f"{prefix}z4j: {trigger}"


def _build_email_body(payload: dict[str, Any]) -> str:
    # Transactional path: the caller provides a pre-formatted body.
    override = payload.get("body")
    if override:
        return str(override)
    lines = [
        f"Trigger: {payload.get('trigger', '?')}",
        f"Task: {payload.get('task_name', '?')}",
        f"Task ID: {payload.get('task_id', '?')}",
        f"Priority: {payload.get('priority', 'normal')}",
        f"State: {payload.get('state', '?')}",
        f"Project: {payload.get('project_slug', '?')}",
    ]
    exception = payload.get("exception")
    if exception:
        lines.append(f"\nException: {exception}")
    traceback = payload.get("traceback")
    if traceback:
        lines.append(f"\nTraceback:\n{traceback[:2000]}")
    lines.append(f"\n- z4j notification engine")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Slack (incoming webhook - no OAuth needed)
# ---------------------------------------------------------------------------


async def deliver_slack(
    config: dict[str, Any],
    payload: dict[str, Any],
) -> DeliveryResult:
    """POST a Block Kit message to a Slack incoming webhook URL."""
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        return DeliveryResult(success=False, error="Slack webhook URL is empty")

    # SSRF protection - Slack webhooks live at hooks.slack.com, but
    # since config is user-controlled we still run the same checks
    # that the webhook dispatcher does.
    ssrf_error = await validate_webhook_url(webhook_url)
    if ssrf_error:
        return DeliveryResult(success=False, error=f"blocked: {ssrf_error}")

    # Round-6 audit fix Notif-MED (Apr 2026): host-lock the Slack
    # dispatcher to ``hooks.slack.com``. Without this, a tenant
    # admin can register a "Slack" channel pointing at an arbitrary
    # attacker-controlled HTTPS endpoint and use it as a generic
    # data-exfil sink that LOOKS like Slack in the audit log. The
    # SSRF check above only rejects PRIVATE addresses; a public
    # attacker host passes it.
    try:
        slack_host = urlparse(webhook_url).hostname or ""
    except Exception:  # noqa: BLE001
        slack_host = ""
    if slack_host.lower() != "hooks.slack.com":
        return DeliveryResult(
            success=False,
            error=(
                "slack webhook_url must point at hooks.slack.com "
                "(host-lock enforced; configure a generic webhook "
                "channel for arbitrary HTTPS targets)"
            ),
        )

    trigger = payload.get("trigger", "notification")
    task_name = payload.get("task_name", "")
    priority = payload.get("priority", "normal")
    state = payload.get("state", "")
    task_id = payload.get("task_id", "")

    emoji = {"critical": "🔴", "high": "🟠", "normal": "🔵", "low": "⚪"}.get(
        priority, "🔵",
    )

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} z4j: {trigger}",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Task:*\n`{task_name}`"},
                {"type": "mrkdwn", "text": f"*State:*\n{state}"},
                {"type": "mrkdwn", "text": f"*Priority:*\n{priority}"},
                {"type": "mrkdwn", "text": f"*ID:*\n`{task_id[:12]}`"},
            ],
        },
    ]

    exception = payload.get("exception")
    if exception:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Exception:*\n```{exception[:500]}```",
            },
        })

    body = {"blocks": blocks}

    try:
        # M15: re-validate + pin the Slack webhook's IP at
        # dispatch time (same rationale as the generic webhook
        # dispatcher above).
        err, safe_ip = await resolve_and_pin(webhook_url)
        if err is not None:
            return DeliveryResult(
                success=False,
                error=f"unsafe slack URL at dispatch: {err}",
            )
        resp = await _post(
            webhook_url,
            json=body,
            headers={"Content-Type": "application/json"},
            pin_ip=safe_ip,
        )
        return DeliveryResult(
            success=resp.status_code == 200,
            status_code=resp.status_code,
            response_body=resp.text[:500],
        )
    except Exception as exc:
        return DeliveryResult(success=False, error=str(exc)[:500])


# ---------------------------------------------------------------------------
# Telegram (bot API - just a token + chat ID)
# ---------------------------------------------------------------------------


async def deliver_telegram(
    config: dict[str, Any],
    payload: dict[str, Any],
) -> DeliveryResult:
    """Send a message via the Telegram Bot API.

    Requires a bot token (from @BotFather) and a chat ID (the
    group or user to message). No OAuth, no webhook setup - just
    a POST to ``api.telegram.org``.
    """
    bot_token = config.get("bot_token", "")
    chat_id = config.get("chat_id", "")
    if not bot_token or not chat_id:
        return DeliveryResult(
            success=False,
            error="Telegram config incomplete (need bot_token + chat_id)",
        )

    trigger = payload.get("trigger", "notification")
    task_name = payload.get("task_name", "")
    priority = payload.get("priority", "normal")
    state = payload.get("state", "")

    emoji = {"critical": "🔴", "high": "🟠", "normal": "🔵", "low": "⚪"}.get(
        priority, "🔵",
    )

    lines = [
        f"{emoji} *z4j: {trigger}*",
        f"Task: `{task_name}`",
        f"State: {state}",
        f"Priority: {priority}",
    ]
    exception = payload.get("exception")
    if exception:
        lines.append(f"Exception: `{exception[:300]}`")

    text = "\n".join(lines)
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    try:
        # Defense-in-depth DNS pin at dispatch time, matching the
        # webhook and Slack dispatchers. api.telegram.org is a
        # trusted public host so the rebinding risk is lower than
        # for user-supplied URLs, but consistency prevents future
        # drift and costs nothing - same helper, same cached
        # resolver.
        err, safe_ip = await resolve_and_pin(url)
        if err is not None:
            return DeliveryResult(
                success=False,
                error=f"unsafe telegram URL at dispatch: {err}",
            )
        resp = await _post(
            url,
            json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "Markdown",
            },
            pin_ip=safe_ip,
        )
        return DeliveryResult(
            success=resp.status_code == 200,
            status_code=resp.status_code,
            response_body=resp.text[:500],
        )
    except Exception as exc:
        return DeliveryResult(success=False, error=str(exc)[:500])


# ---------------------------------------------------------------------------
# PagerDuty (Events API v2 - one POST per alert, integration key in body)
# ---------------------------------------------------------------------------


#: Allowed PagerDuty severity levels per Events API v2.
#: https://developer.pagerduty.com/docs/events-api-v2/trigger-events/
_PAGERDUTY_SEVERITIES = frozenset({"critical", "error", "warning", "info"})

#: Default mapping from z4j trigger -> PagerDuty severity. Operators
#: can override per-trigger via config["severity_map"]. Choices:
#: agent.offline -> critical (production outage signal)
#: task.failed -> error (something is wrong but the system is up)
#: task.retried, task.slow -> warning (degraded but recovering)
#: task.succeeded, agent.online -> info (audit-trail level)
_DEFAULT_SEVERITY_MAP: dict[str, str] = {
    "agent.offline": "critical",
    "agent.online": "info",
    "task.failed": "error",
    "task.retried": "warning",
    "task.slow": "warning",
    "task.succeeded": "info",
}


def validate_pagerduty_config(config: dict[str, Any]) -> str | None:
    """Return error string or None if config is acceptable.

    Required: integration_key (32-char routing key from a PD service's
    Events API v2 integration). Optional: severity_default (one of
    critical/error/warning/info), severity_map (per-trigger override).
    """
    key = config.get("integration_key", "")
    if not isinstance(key, str) or not key.strip():
        return "missing integration_key (32-char routing key from PagerDuty)"
    # PD integration keys are 32 hex chars, but we accept any 8-64 char
    # printable string in case PD changes the format. Reject obvious
    # smells (whitespace, control chars).
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,64}", key.strip()):
        return "integration_key must be 8-64 chars [A-Za-z0-9_-]"
    sev = config.get("severity_default", "warning")
    if sev not in _PAGERDUTY_SEVERITIES:
        return f"severity_default must be one of {sorted(_PAGERDUTY_SEVERITIES)}"
    smap = config.get("severity_map", {})
    if not isinstance(smap, dict):
        return "severity_map must be an object {trigger: severity}"
    # Cap dict size so a hostile or accidental large config can't
    # bloat the channel row or amplify dispatch-time payload merge
    # work (audit M-3). 32 is well above the universe of triggers
    # z4j supports today (~6) with headroom for future additions.
    if len(smap) > 32:
        return f"severity_map has too many entries ({len(smap)} > 32)"
    # Trigger pattern matches the project subscription trigger enum
    # plus the synthetic "test.dispatch" so test rows can be mapped
    # to a custom severity if the operator wants.
    _trigger_pattern = re.compile(
        r"^(task\.failed|task\.succeeded|task\.retried|task\.slow|"
        r"agent\.offline|agent\.online|test\.dispatch)$",
    )
    for trig, mapped in smap.items():
        # Audit M-3: enforce that keys are strings AND match a known
        # trigger pattern. Pre-1.0.14 the loop accepted any key type
        # (None, ints, bools) which would crash the dispatcher mid-
        # loop on str-only ops elsewhere.
        if not isinstance(trig, str):
            return (
                f"severity_map keys must be strings (got {type(trig).__name__})"
            )
        if not _trigger_pattern.fullmatch(trig):
            return (
                f"severity_map[{trig!r}] is not a recognized trigger "
                f"(must match task.* / agent.* / test.dispatch)"
            )
        if mapped not in _PAGERDUTY_SEVERITIES:
            return (
                f"severity_map[{trig!r}]={mapped!r} is not a valid PD "
                f"severity (one of {sorted(_PAGERDUTY_SEVERITIES)})"
            )
    return None


async def deliver_pagerduty(
    config: dict[str, Any],
    payload: dict[str, Any],
) -> DeliveryResult:
    """POST a trigger event to the PagerDuty Events API v2.

    Constructs the canonical payload shape PagerDuty expects:

      {"routing_key": "...", "event_action": "trigger",
       "dedup_key": "<project>/<trigger>/<task_id>",
       "payload": {
         "summary": "z4j: <trigger> on <task_name>",
         "source": "<project_id>",
         "severity": "<critical|error|warning|info>",
         "custom_details": {...full payload...},
       }}

    The dedup_key collapses repeat firings of the same alert into one
    PagerDuty incident (e.g. agent.offline retried every minute won't
    page someone 60 times - PD groups by dedup_key).
    """
    integration_key = config.get("integration_key", "").strip()
    if not integration_key:
        return DeliveryResult(
            success=False,
            error="PagerDuty config incomplete (need integration_key)",
        )

    trigger = str(payload.get("trigger", "notification"))
    task_name = str(payload.get("task_name", ""))
    task_id = str(payload.get("task_id", ""))
    project_id = str(payload.get("project_id", "z4j"))

    # Severity: per-trigger override > config default > built-in default.
    severity_map = {**_DEFAULT_SEVERITY_MAP, **config.get("severity_map", {})}
    severity = severity_map.get(
        trigger,
        config.get("severity_default", "warning"),
    )
    if severity not in _PAGERDUTY_SEVERITIES:
        severity = "warning"  # paranoia after a config edit gone wrong

    # dedup_key: collapses repeat firings into one PD incident. We
    # include task_id (when present) so distinct task failures don't
    # collapse together; trigger-only events (agent.offline) collapse
    # by (project, trigger, agent).
    dedup_parts = [project_id, trigger]
    if task_id:
        dedup_parts.append(task_id)
    elif payload.get("agent_id"):
        dedup_parts.append(str(payload["agent_id"]))
    dedup_key = "/".join(dedup_parts)[:255]  # PD caps at 255 chars

    summary_parts = [f"z4j: {trigger}"]
    if task_name:
        summary_parts.append(f"on `{task_name}`")
    summary = " ".join(summary_parts)[:1024]  # PD caps at 1024

    body = {
        "routing_key": integration_key,
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "payload": {
            "summary": summary,
            "source": project_id,
            "severity": severity,
            "component": str(payload.get("agent_name") or "z4j-brain"),
            "group": trigger,
            "class": "z4j.notification",
            "custom_details": {
                k: v for k, v in payload.items()
                # PD's UI handles ~64KB of custom_details; trim very
                # large fields to keep page-load fast.
                if not (isinstance(v, str) and len(v) > 4096)
            },
        },
    }

    url = "https://events.pagerduty.com/v2/enqueue"
    try:
        # Defense-in-depth DNS pin at dispatch time. events.pagerduty.com
        # is trusted-public, but consistent treatment with the other
        # public-host dispatchers (Telegram, Slack) prevents drift.
        err, safe_ip = await resolve_and_pin(url)
        if err is not None:
            return DeliveryResult(
                success=False,
                error=f"unsafe pagerduty URL at dispatch: {err}",
            )
        resp = await _post(
            url,
            json=body,
            headers={"Content-Type": "application/json"},
            pin_ip=safe_ip,
        )
        # PD returns 202 Accepted on success. 4xx = client error
        # (bad routing key, malformed payload). 5xx = retry.
        return DeliveryResult(
            success=resp.status_code == 202,
            status_code=resp.status_code,
            response_body=resp.text[:500],
        )
    except Exception as exc:
        return DeliveryResult(success=False, error=str(exc)[:500])


# ---------------------------------------------------------------------------
# Discord (incoming webhook - Slack-compatible payload via /slack endpoint)
# ---------------------------------------------------------------------------


def validate_discord_config(config: dict[str, Any]) -> str | None:
    """Discord webhooks live at ``discord.com/api/webhooks/<id>/<token>``.

    We intentionally do NOT enforce that hostname here - the SSRF
    helpers in :func:`validate_webhook_url` reject private IPs and
    bad schemes already, and a strict hostname check would break
    proxied / forwarded setups. The dispatcher hits the webhook URL
    verbatim (with optional ``/slack`` suffix to accept Slack payloads).
    """
    url = config.get("webhook_url", "")
    if not isinstance(url, str) or not url.strip():
        return "missing webhook_url"
    return None


async def deliver_discord(
    config: dict[str, Any],
    payload: dict[str, Any],
) -> DeliveryResult:
    """POST a notification to a Discord incoming webhook.

    Discord webhooks accept a Slack-compatible payload when the URL
    has the ``/slack`` suffix. We auto-append it so operators only
    need to paste the canonical webhook URL Discord shows them in
    Server Settings -> Integrations -> Webhooks.
    """
    webhook_url = config.get("webhook_url", "").strip()
    if not webhook_url:
        return DeliveryResult(
            success=False,
            error="Discord webhook URL is empty",
        )

    # SSRF protection - same checks the generic webhook dispatcher runs.
    ssrf_error = await validate_webhook_url(webhook_url)
    if ssrf_error:
        return DeliveryResult(
            success=False,
            error=f"blocked: {ssrf_error}",
        )

    # Round-6 audit fix Notif-MED (Apr 2026): host-lock the Discord
    # dispatcher to discord.com / discordapp.com / canary.discord.com /
    # ptb.discord.com (the four official webhook hosts). Same threat
    # model as the Slack host-lock above.
    _DISCORD_ALLOWED_HOSTS = frozenset({
        "discord.com",
        "discordapp.com",
        "canary.discord.com",
        "ptb.discord.com",
    })
    try:
        discord_host = (urlparse(webhook_url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        discord_host = ""
    if discord_host not in _DISCORD_ALLOWED_HOSTS:
        return DeliveryResult(
            success=False,
            error=(
                "discord webhook_url must point at an official discord "
                "host (discord.com, discordapp.com, canary.discord.com, "
                "ptb.discord.com); use the generic webhook channel for "
                "arbitrary HTTPS targets"
            ),
        )

    # Discord's Slack-compat endpoint accepts the same Block Kit-ish
    # payload deliver_slack already constructs, but Discord doesn't
    # render Slack Block Kit blocks - it falls back to the `text`
    # field. So we build a single text message instead.
    trigger = payload.get("trigger", "notification")
    task_name = payload.get("task_name", "")
    priority = payload.get("priority", "normal")
    state = payload.get("state", "")
    task_id = payload.get("task_id", "")

    emoji = {"critical": "🔴", "high": "🟠", "normal": "🔵", "low": "⚪"}.get(
        priority, "🔵",
    )
    lines = [
        f"{emoji} **z4j: {trigger}**",
        f"Task: `{task_name}`" if task_name else None,
        f"State: {state}" if state else None,
        f"Priority: {priority}",
        f"ID: `{task_id[:12]}`" if task_id else None,
    ]
    exception = payload.get("exception")
    if exception:
        lines.append(f"```{exception[:1500]}```")
    text = "\n".join(line for line in lines if line)

    # Auto-append /slack so operators paste the canonical webhook URL.
    target_url = webhook_url.rstrip("/")
    if not target_url.endswith("/slack"):
        target_url = target_url + "/slack"

    body = {"text": text, "username": "z4j"}

    try:
        err, safe_ip = await resolve_and_pin(target_url)
        if err is not None:
            return DeliveryResult(
                success=False,
                error=f"unsafe discord URL at dispatch: {err}",
            )
        resp = await _post(
            target_url,
            json=body,
            headers={"Content-Type": "application/json"},
            pin_ip=safe_ip,
        )
        # Discord returns 204 No Content on success for the /slack
        # endpoint (200 from /slack?wait=true).
        return DeliveryResult(
            success=resp.status_code in (200, 204),
            status_code=resp.status_code,
            response_body=resp.text[:500],
        )
    except Exception as exc:
        return DeliveryResult(success=False, error=str(exc)[:500])


# ---------------------------------------------------------------------------
# Dispatch router
# ---------------------------------------------------------------------------


CHANNEL_DISPATCHERS = {
    "webhook": deliver_webhook,
    "email": deliver_email,
    "slack": deliver_slack,
    "telegram": deliver_telegram,
    "pagerduty": deliver_pagerduty,
    "discord": deliver_discord,
}


__all__ = [
    "CHANNEL_DISPATCHERS",
    "DeliveryResult",
    "deliver_discord",
    "deliver_email",
    "deliver_pagerduty",
    "deliver_slack",
    "deliver_telegram",
    "deliver_webhook",
    "set_allow_http_webhooks",
    "set_shared_client",
    "validate_discord_config",
    "validate_pagerduty_config",
    "validate_webhook_headers",
    "validate_webhook_url",
]
