"""Audit-log sanitization for notification delivery rows.

Lives in ``domain.notifications`` so both the API-layer test-dispatch
path (``api.notifications._dispatch_test``) and the real-event
dispatch path (``domain.notifications.service``) can apply the same
scrubbing before writing to ``notification_deliveries.error`` /
``response_body``.

See :func:`sanitize_audit_text` for the leak classes this closes.
Audit findings H-1 / H-2 / H-3 from the v1.0.14 security pass.
"""

from __future__ import annotations

import re
from typing import Any

#: Mask token used for redacted URL substrings. Same string the API
#: layer uses for masked secret keys (``_MASK`` in
#: :mod:`z4j_brain.api.notifications`); duplicated here to keep this
#: module dependency-free of the API layer.
_MASK = "••••••••"

#: Keys whose values often appear in URLs or as bare tokens.
#: Webhook URLs may carry secrets in path or query; bot tokens and
#: integration keys are bare secrets that may show up in dispatcher
#: error strings ("auth failed for token X") or in responses.
_URL_BEARING_KEYS = (
    "webhook_url",
    "url",
    "bot_token",
    "integration_key",
)

#: Regex patterns for private / loopback / link-local IPv4. Used as
#: a defense-in-depth scrub when an SSRF-guard or DNS error message
#: shape changes and the literal "in blocked range" collapse misses.
_PRIVATE_IP_PATTERNS = (
    re.compile(r"\b10(?:\.\d{1,3}){3}\b"),
    re.compile(r"\b192\.168(?:\.\d{1,3}){2}\b"),
    re.compile(r"\b172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}\b"),
    re.compile(r"\b169\.254(?:\.\d{1,3}){2}\b"),
    re.compile(r"\b127(?:\.\d{1,3}){3}\b"),
)

#: Match SSRF-guard / DNS-resolution rejection messages whose verbose
#: form leaks the resolved internal IP. The replacement collapses
#: them to a generic policy message.
_SSRF_PATTERNS = (
    re.compile(r"target IP \S+ is in blocked range \S+"),
    re.compile(r"unsafe URL at dispatch:.*"),
    re.compile(r"unsafe slack URL at dispatch:.*"),
    re.compile(r"unsafe pagerduty URL at dispatch:.*"),
    re.compile(r"unsafe discord URL at dispatch:.*"),
    re.compile(r"unsafe telegram URL at dispatch:.*"),
)


def sanitize_audit_text(
    text: str | None,
    *,
    channel_config: dict[str, Any] | None = None,
    max_len: int = 2048,
) -> str | None:
    """Scrub free-form ``error`` / ``response_body`` for the audit log.

    Closes three audit-log leakage classes (audit H-1, H-2, H-3):

    - **Webhook URL with embedded secret in path** (Slack
      ``hooks.slack.com/services/T../B../<secret>``, Discord
      ``discord.com/api/webhooks/<id>/<token>``, Telegram
      ``api.telegram.org/bot<TOKEN>/...``). When httpx raises a
      timeout / DNS error its ``__str__`` includes the full URL.
      Persisting that into ``notification_deliveries.error`` defeats
      the masking ``_mask_config`` applies on ``GET /channels``: a
      second admin can read the secret by browsing the delivery log.
    - **Hostile webhook response body**: an admin (or, in the real
      dispatch path, any subscription targeting an attacker-controlled
      URL) returns HTML / phishing markup. Storing it verbatim trusts
      attacker bytes for a server-rendered admin surface.
    - **SSRF guard error reveals internal DNS**: rejection messages
      like ``"target IP 10.0.0.5 is in blocked range 10.0.0.0/8"`` let
      an admin enumerate internal-network DNS records via the audit
      log.

    Sanitization steps (in order):

    1. Strip control characters (``\\x00`` - ``\\x1f``) except tab/CR/LF.
    2. Replace any substring equal to a URL-bearing config value
       (webhook_url, url, bot_token, integration_key) with the mask.
       Skipped when ``channel_config`` is ``None`` or values are
       too short to be meaningful (< 8 chars).
    3. Collapse SSRF guard messages to ``"target rejected by policy"``.
    4. Replace private / loopback / link-local IPv4 substrings with
       ``"<private-ip>"``.
    5. Truncate to ``max_len`` last so masking isn't sliced.

    The unsanitized text is still available to operators via
    structlog (server-side log) - we trade audit-row readability for
    audit-row safety.
    """
    if text is None:
        return None
    cleaned = "".join(
        ch if (ch in "\t\n\r" or ord(ch) >= 0x20) else " "
        for ch in text
    )
    if channel_config:
        for key in _URL_BEARING_KEYS:
            value = channel_config.get(key)
            if isinstance(value, str) and len(value) >= 8:
                cleaned = cleaned.replace(value, _MASK)
    for pat in _SSRF_PATTERNS:
        cleaned = pat.sub("target rejected by policy", cleaned)
    for pat in _PRIVATE_IP_PATTERNS:
        cleaned = pat.sub("<private-ip>", cleaned)
    return cleaned[:max_len]


__all__ = ["sanitize_audit_text"]
