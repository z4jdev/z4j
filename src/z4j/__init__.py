"""z4j - open-source control plane for Python task infrastructure.

This is the meta-package that brings together the z4j brain server
and the optional framework/engine adapters. Install with extras
for your stack:

    pip install z4j                    # brain + CLI (SQLite)
    pip install z4j[celery]            # + Celery agent
    pip install z4j[django]            # + Django adapter
    pip install z4j[django,celery]     # full Django + Celery stack
    pip install z4j[postgres]          # production Postgres backend
    pip install z4j[all]               # all agent adapters + Postgres backend

Quick start:

    z4j serve --port 7700 --admin-email you@dev.local \
        --admin-password 'replace-this-local-password!'

Then open http://localhost:7700.

Licensed under AGPL-3.0-or-later because this package ships the
brain server. The individual agent packages (z4j-core, z4j-bare,
z4j-django, z4j-celery, etc.) carry Apache-2.0 licenses and can be
installed separately. Consult the applicable license terms for the
combination you distribute or deploy.
"""

from __future__ import annotations

import importlib.metadata

try:
    # Authoritative for an installed dist: report z4j's OWN version, not a
    # dependency's (a bare ``from z4j_core.version import __version__``
    # re-export silently reported z4j-core's version instead).
    __version__ = importlib.metadata.version("z4j")
except importlib.metadata.PackageNotFoundError:
    # Source checkout without an installed dist: fall back to the
    # pyproject version literal, which scripts/check-versions.py keeps in
    # sync with [project].version.
    __version__ = "1.9.0"

__all__ = ["__version__"]
