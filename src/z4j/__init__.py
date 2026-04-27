"""z4j - open-source control plane for Python task infrastructure.

This is the meta-package that brings together the z4j brain server
and the optional framework/engine adapters. Install with extras
for your stack:

    pip install z4j                    # brain + CLI (SQLite)
    pip install z4j[celery]            # + Celery agent
    pip install z4j[django]            # + Django adapter
    pip install z4j[django,celery]     # full Django + Celery stack
    pip install z4j[postgres]          # production Postgres backend
    pip install z4j[all]               # everything

Quick start:

    z4j-brain serve --port 7700 --admin-email you@dev.local --admin-password changeme

Then open http://localhost:7700.

Licensed under AGPL-3.0-or-later because this package installs the
brain server (z4j-brain) by default. The individual agent packages
(z4j-core, z4j-bare, z4j-django, z4j-celery, etc.) are Apache 2.0 and
can be installed standalone with no AGPL obligation - see the repository
LICENSE files for details.
"""

from __future__ import annotations

from z4j_core.version import __version__

__all__ = ["__version__"]
