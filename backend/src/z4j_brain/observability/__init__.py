"""Observability glue (Sentry, OpenTelemetry, etc.).

Each submodule is independently optional. Operators opt in via env vars;
when the optional dependency is not installed, the helpers degrade to
no-ops so the brain runs unchanged.
"""

from __future__ import annotations

from z4j_brain.observability.otel import (
    build_resource_attributes,
    init_otel,
)
from z4j_brain.observability.sentry import (
    init_sentry,
    scrub_event,
)

__all__ = [
    "build_resource_attributes",
    "init_otel",
    "init_sentry",
    "scrub_event",
]
