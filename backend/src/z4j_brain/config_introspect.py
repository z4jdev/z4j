"""Settings-source attribution from the immutable startup snapshot."""

from __future__ import annotations

import os

from z4j_brain.configuration import active_configuration_snapshot


def config_source(
    field: str,
    *,
    env: dict[str, str] | None = None,
    is_secret_field: bool = False,
) -> str:
    """Return captured provenance without reopening a configuration path."""

    del is_secret_field
    snapshot = active_configuration_snapshot()
    if snapshot is not None:
        return snapshot.source_for_field(field)

    # Direct in-process tests may construct Settings without an entrypoint.
    # In that case only the already-present process environment is observable;
    # never reopen a path just to improve a display label.
    environment = os.environ if env is None else env
    key = f"Z4J_{field.upper()}"
    if key in environment:
        return f"env ({key})"
    return "default"


__all__ = ["config_source"]
