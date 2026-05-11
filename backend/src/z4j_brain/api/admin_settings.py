"""Read-only ``/api/v1/admin/settings`` introspection endpoint.

Surfaces the brain's effective :class:`Settings` instance to the
dashboard's *Settings (read-only)* page so operators can see what
the running process is using without ssh-ing into the host to run
``z4j config show``.

Design notes:

- **Read-only on purpose.** ``~/.z4j/config.env`` is the source of
  truth. The dashboard is for visibility and a "copy current as
  ``.env``" UX, not for write-back. A write path would create three
  obvious confused-deputy problems (which file to write, who can
  edit it, how to atomically reload Settings) that we deliberately
  defer.
- **Secrets are masked at the boundary.** Any field typed as
  :class:`pydantic.SecretStr` (or any field whose name we
  conservatively flag as secret-shaped) is rendered as ``"***"``
  regardless of who's calling. The cleartext never crosses the
  wire.
- **Source attribution mirrors the CLI.** ``_config_source`` in
  ``z4j_brain.cli`` is the single source of truth for "where did
  this value come from". We import a thin re-export of that helper
  so the dashboard's source labels stay in lockstep with
  ``z4j config show`` output.

Auth: requires :func:`require_admin`, the same dep
``/admin/system`` uses. Non-admins get 403, anonymous gets 401.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from z4j_brain.api.deps import get_settings, require_admin
from z4j_brain.cli import _config_source
from z4j_core.paths import z4j_home

if TYPE_CHECKING:
    from z4j_brain.persistence.models import User
    from z4j_brain.settings import Settings


router = APIRouter(prefix="/admin/settings", tags=["admin-settings"])


class SettingItem(BaseModel):
    """One row in the effective-settings response."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(description="Pydantic field name on Settings.")
    value: str = Field(
        description=(
            "String-rendered effective value. Always a string so the "
            "table renderer doesn't have to special-case ints, lists, "
            "dicts, etc. Secrets are rendered as ``***``."
        ),
    )
    source: str = Field(
        description=(
            "Where the value came from: ``env``, ``config.env``, "
            "``secret.env``, ``.env``, or ``default``. Mirrors "
            "``z4j config show`` source labels."
        ),
    )
    is_secret: bool = Field(
        description=(
            "True when the value was masked. Drives the dashboard's "
            "tooltip explaining why the cell shows ``***``."
        ),
    )
    description: str = Field(
        description=(
            "Field description from the Pydantic model, or empty "
            "string when the field has no description set."
        ),
    )


class AdminSettingsResponse(BaseModel):
    """Top-level shape of ``GET /api/v1/admin/settings``."""

    model_config = ConfigDict(extra="forbid")

    z4j_home: str = Field(
        description=(
            "Resolved ``$Z4J_HOME`` directory the brain is using. "
            "Where ``config.env`` and ``secret.env`` live."
        ),
    )
    settings: list[SettingItem] = Field(
        description=(
            "Every Settings field, sorted alphabetically by name "
            "for stable output across requests."
        ),
    )


# Field-name patterns we treat as secret-shaped even when the type
# annotation isn't ``SecretStr``. Defense-in-depth: a future Settings
# field that lands as a plain ``str`` but holds credential material
# would otherwise leak in cleartext until someone notices and adds
# a ``SecretStr`` wrapper. Cheap belt over the type-system suspenders.
#
# Suffix-only matching deliberately, because plain substring matching
# false-positives on legitimate non-secret fields like
# ``first_boot_token_ttl_seconds`` (the TTL is just a number).
# Keeping the suffix list narrow means we mask exactly the fields
# that hold credential material under a non-SecretStr type.
_SECRET_NAME_SUFFIXES: tuple[str, ...] = (
    "_secret",
    "_password",
    "_token",
    "_api_key",
    "_private_key",
)
_SECRET_NAME_EXACT: frozenset[str] = frozenset({
    "secret",
    "password",
    "token",
    "api_key",
    "private_key",
})


def _normalize_source(raw_source: str) -> str:
    """Collapse ``_config_source`` output into a stable short label.

    The CLI helper returns ``"env (Z4J_FOO)"`` so the operator can
    see *which* env var won. The dashboard surfaces this as a chip
    and uses the short form for color-coding; the env-var name is
    redundant with the row's ``name`` column anyway. Keep
    ``"default"`` / ``"config.env"`` / ``"secret.env"`` / ``".env"``
    as-is.
    """
    if raw_source.startswith("env"):
        return "env"
    return raw_source


def _looks_secret(name: str) -> bool:
    """Belt-and-suspenders check for fields not typed as SecretStr."""
    lname = name.lower()
    if lname in _SECRET_NAME_EXACT:
        return True
    return any(lname.endswith(suffix) for suffix in _SECRET_NAME_SUFFIXES)


def _render_value(value: Any, *, is_secret: bool) -> str:
    """Render a Settings value as a string for the API row."""
    if is_secret:
        return "***"
    if value is None:
        return ""
    if isinstance(value, list) and not value:
        return "[]"
    if isinstance(value, dict) and not value:
        return "{}"
    return str(value)


@router.get(
    "",
    response_model=AdminSettingsResponse,
)
async def get_effective_settings(
    settings: "Settings" = Depends(get_settings),
    _admin: "User" = Depends(require_admin),
) -> AdminSettingsResponse:
    """Return the brain's effective settings + per-field source labels.

    Reads :attr:`fastapi.Request.app.state.settings` (the same
    :class:`Settings` instance every other handler depends on),
    iterates ``model_fields``, and emits one
    :class:`SettingItem` per field. Secrets are masked. Sorted
    alphabetically by field name for stable rendering.
    """
    # Build a snapshot of process env that mirrors what
    # ``_config_source`` expects from the CLI: only Z4J_-prefixed
    # vars matter for source attribution because Pydantic Settings
    # is configured to read that prefix exclusively.
    import os

    env = {k: v for k, v in os.environ.items() if k.startswith("Z4J_")}

    # Pydantic V2.11+: access model_fields off the class, not the
    # instance, to avoid the deprecation warning. The two are
    # functionally identical.
    model_fields = type(settings).model_fields

    items: list[SettingItem] = []
    for field_name in sorted(model_fields):
        field_info = model_fields[field_name]
        raw_value = getattr(settings, field_name)

        # SecretStr is the typed marker; the name-hint scan is a
        # defense-in-depth fallback for fields someone might have
        # forgotten to wrap.
        is_secret = (
            isinstance(raw_value, SecretStr)
            or _looks_secret(field_name)
        )
        if isinstance(raw_value, SecretStr):
            # Never call get_secret_value() here, even for an admin.
            # The dashboard is intentionally kept on the "see the
            # shape, not the value" side of the secret boundary.
            display = "***"
        else:
            display = _render_value(raw_value, is_secret=is_secret)

        description = (
            field_info.description if field_info.description else ""
        )

        items.append(
            SettingItem(
                name=field_name,
                value=display,
                source=_normalize_source(
                    _config_source(field_name, settings, env),
                ),
                is_secret=is_secret,
                description=description,
            ),
        )

    return AdminSettingsResponse(
        z4j_home=str(z4j_home()),
        settings=items,
    )


__all__ = ["AdminSettingsResponse", "SettingItem", "router"]
