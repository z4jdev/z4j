"""Credential-safe public channel configs and merge semantics shared by both APIs."""

from __future__ import annotations

from typing import Any

MASK = "••••••••"
_CREDENTIAL_KEYS = (
    "smtp_pass",
    "hmac_secret",
    "bot_token",
    "password",
    "integration_key",
    "headers",
)
_MASKED_KEYS = (*_CREDENTIAL_KEYS, "url", "webhook_url")


def mask_config(config: dict[str, Any]) -> dict[str, Any]:
    """Redact complete URLs and header maps, whose arbitrary values may be secrets."""
    return {key: MASK if key in _MASKED_KEYS and value else value for key, value in config.items()}


def merge_config(
    existing: dict[str, Any],
    incoming: dict[str, Any],
    *,
    mask: str = MASK,
) -> tuple[dict[str, Any], bool]:
    """Preserve omitted/masked values and discard credentials on URL changes.

    Changing an SMTP host, port, or TLS mode also discards the saved password.
    Only explicitly supplied credentials can accompany a destination change;
    omitted credentials and echoed masks cannot carry saved secrets across.
    Empty strings explicitly clear a value. The boolean reports URL changes
    for the existing audit field; SMTP changes are included in ``config``.
    Validate the merged result before assigning it to a persistent channel.
    """
    merged = dict(existing or {})
    incoming = {
        key: value
        for key, value in (incoming or {}).items()
        if not (key in _MASKED_KEYS and value == mask)
    }
    url_changed = any(
        key in incoming and incoming[key] != merged.get(key) for key in ("url", "webhook_url")
    )
    smtp_changed = any(
        key in incoming and incoming[key] != merged.get(key, default)
        for key, default in (("smtp_host", None), ("smtp_port", 587), ("smtp_tls", True))
    )
    merged.update(incoming)
    if url_changed:
        for key in _CREDENTIAL_KEYS:
            if key not in incoming:
                merged.pop(key, None)
    if smtp_changed:
        for key in ("smtp_pass", "password"):
            if key not in incoming:
                merged.pop(key, None)
    return merged, url_changed
