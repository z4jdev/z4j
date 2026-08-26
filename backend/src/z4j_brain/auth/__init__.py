"""Authentication primitives.

Submodules:

- :mod:`z4j_brain.auth.passwords` - argon2id password hashing.
- :mod:`z4j_brain.auth.sessions` - server-side session storage and
  signed cookie envelopes.
- :mod:`z4j_brain.auth.csrf` - double-submit CSRF tokens.
- :mod:`z4j_brain.auth.ip` - real client IP resolution behind
  trusted reverse proxies.
- :mod:`z4j_brain.api.deps` - FastAPI ``Depends`` adapters.

The cryptographic, scope, session-codec, and IP-resolution primitives are
framework-free. Most FastAPI-bound adapters live in ``z4j_brain.api.deps``;
the deliberate exception inside this package is
``z4j_brain.auth.trusted_device``, whose cookie set/clear helpers accept a
:class:`fastapi.Response`.
"""

from __future__ import annotations
