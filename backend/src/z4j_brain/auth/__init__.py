"""Authentication primitives.

Submodules:

- :mod:`z4j_brain.auth.passwords` - argon2id password hashing.
- :mod:`z4j_brain.auth.sessions` - server-side session storage and
  signed cookie envelopes.
- :mod:`z4j_brain.auth.csrf` - double-submit CSRF tokens.
- :mod:`z4j_brain.auth.ip` - real client IP resolution behind
  trusted reverse proxies.
- :mod:`z4j_brain.auth.deps` - FastAPI ``Depends`` adapters.

The submodules are deliberately framework-free below the
``deps.py`` layer - they take settings and return data, never
:class:`fastapi.Request`. The thin :mod:`deps` module is the only
place that knows about FastAPI. This makes the auth layer trivially
testable without spinning up an HTTP server.
"""

from __future__ import annotations
