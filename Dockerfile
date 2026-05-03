# =============================================================================
# z4j release Dockerfile.
#
# Slim runtime that pip-installs z4j from PyPI. The published wheel
# bundles the React dashboard, alembic.ini, and migrations -- so this
# Dockerfile does NOT need pnpm, Vite, or the monorepo source tree to build.
#
# Image is bit-identical to:
#   pip install "z4j[postgres]==${Z4J_VERSION}"
#   z4j serve
#
# Built by .github/workflows/release-docker.yml on tag push (multi-arch
# native amd64 + arm64). Published as z4jdev/z4j:VERSION + :latest.
#
# Note on the build-arg name: the workflow passes ``Z4J_BRAIN_VERSION``
# for backwards compatibility with the pre-1.4.0 build system (the
# secret name on GitHub uses that key). We accept it under both names.
# =============================================================================

ARG PYTHON_VERSION=3.14

FROM python:${PYTHON_VERSION}-slim-trixie AS runtime

# OCI image metadata -- consumed by Docker Hub UI, GitHub Container
# Registry, Syft, Trivy, Docker Scout, etc.
ARG Z4J_BRAIN_VERSION
ARG Z4J_VERSION
ENV Z4J_RESOLVED_VERSION="${Z4J_VERSION:-${Z4J_BRAIN_VERSION}}"
LABEL org.opencontainers.image.title="z4j" \
      org.opencontainers.image.description="z4j: open-source control plane for Python task infrastructure" \
      org.opencontainers.image.version="${Z4J_RESOLVED_VERSION}" \
      org.opencontainers.image.source="https://github.com/z4jdev/z4j" \
      org.opencontainers.image.url="https://pypi.org/project/z4j/" \
      org.opencontainers.image.documentation="https://z4j.dev" \
      org.opencontainers.image.vendor="z4j contributors" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    Z4J_LOG_JSON=true \
    Z4J_BIND_HOST=0.0.0.0 \
    Z4J_BIND_PORT=7700

# Install runtime OS deps + create non-root user.
#   - tini: proper PID-1 signal handling
#   - libpq5: required by asyncpg's wheel (Postgres driver)
#   - ca-certificates: TLS for PyPI / outbound HTTPS / OAuth providers
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libpq5 \
        tini; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --system --gid 10001 z4j; \
    useradd --system --uid 10001 --gid z4j --home-dir /app --shell /usr/sbin/nologin z4j; \
    mkdir -p /app /data; \
    chown -R z4j:z4j /app /data

# Install z4j from PyPI + run the leanness pass in the SAME RUN so
# the cleanup actually frees disk in the resulting layer (Docker
# layers are additive; cleanup in a later RUN keeps the original
# bytes around forever). The leanness pass trims ~80 MB of test
# fixtures, type stubs, bytecode, and unused SQLAlchemy dialects
# (we only ship support for sqlite + postgresql; the
# mssql/mysql/oracle dialect packages ship with SQLAlchemy by
# default but z4j never uses them).
RUN set -eux; \
    pip install --no-cache-dir "z4j[postgres]==${Z4J_RESOLVED_VERSION}"; \
    SITE_PACKAGES=$(python -c "import site; print(site.getsitepackages()[0])"); \
    find "${SITE_PACKAGES}" -type d -name '__pycache__' -prune -exec rm -rf {} +; \
    find "${SITE_PACKAGES}" -type f -name '*.pyc' -delete; \
    find "${SITE_PACKAGES}" -type d \( \
        -name 'tests' -o -name 'test' -o -name 'examples' \
      \) -prune -exec rm -rf {} + 2>/dev/null || true; \
    find "${SITE_PACKAGES}" -name '*.pyi' -delete; \
    rm -rf \
        "${SITE_PACKAGES}/sqlalchemy/dialects/mssql" \
        "${SITE_PACKAGES}/sqlalchemy/dialects/mysql" \
        "${SITE_PACKAGES}/sqlalchemy/dialects/oracle"; \
    find "${SITE_PACKAGES}" -type f -name '*.so' -exec strip --strip-unneeded {} + \
        2>/dev/null || true

# Entrypoint script: auto-mint secrets if not provided, auto-migrate,
# then exec z4j. Mirrors the dev Dockerfile's first-boot UX so users
# see identical behavior regardless of which image variant they use.
RUN printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    '' \
    '# SQLite-by-default. If the operator did not set Z4J_DATABASE_URL,' \
    '# we point at /data/z4j.db and configure the local registry' \
    '# backend (Postgres LISTEN/NOTIFY would not work over SQLite).' \
    '# This makes `docker run -p 7700:7700 z4jdev/z4j` zero-config.' \
    'if [ -z "${Z4J_DATABASE_URL:-}" ]; then' \
    '  mkdir -p /data' \
    '  export Z4J_DATABASE_URL="sqlite+aiosqlite:////data/z4j.db"' \
    '  export Z4J_REGISTRY_BACKEND="${Z4J_REGISTRY_BACKEND:-local}"' \
    '  export Z4J_ENVIRONMENT="${Z4J_ENVIRONMENT:-dev}"' \
    '  export Z4J_ALLOWED_HOSTS="${Z4J_ALLOWED_HOSTS:-[\"localhost\",\"127.0.0.1\"]}"' \
    '  echo "[z4j] using SQLite at /data/z4j.db (dev mode)"' \
    'fi' \
    '' \
    '# z4j first-boot UX:' \
    '#   1. Z4J_SECRET set by operator -> use it' \
    '#   2. /data/secret.env exists from a previous boot -> reuse it' \
    '#   3. neither -> mint fresh + persist to /data/secret.env' \
    'if [ -z "${Z4J_SECRET:-}" ]; then' \
    '  if [ -f /data/secret.env ]; then' \
    '    . /data/secret.env' \
    '    echo "[z4j] loaded persisted Z4J_SECRET from /data/secret.env"' \
    '  else' \
    '    mkdir -p /data' \
    '    Z4J_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")' \
    '    Z4J_SESSION_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")' \
    '    {' \
    '      printf "export Z4J_SECRET=%s\\n" "$Z4J_SECRET"' \
    '      printf "export Z4J_SESSION_SECRET=%s\\n" "$Z4J_SESSION_SECRET"' \
    '    } > /data/secret.env' \
    '    chmod 600 /data/secret.env' \
    '    echo "[z4j] minted fresh Z4J_SECRET + Z4J_SESSION_SECRET, persisted to /data/secret.env"' \
    '    echo "[z4j] WARNING: evaluation mode -- set Z4J_SECRET via env and back /data up for production"' \
    '  fi' \
    '  export Z4J_SECRET Z4J_SESSION_SECRET' \
    'fi' \
    '' \
    'echo "[z4j] running migrations"' \
    'z4j migrate upgrade head' \
    'echo "[z4j] starting server"' \
    'exec "$@"' \
    > /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh && \
    chown z4j:z4j /app/entrypoint.sh

# Mount /data for SQLite and persisted secrets. Volume-mount this
# named volume in production for durability across container restarts.
VOLUME /data

WORKDIR /app
USER z4j

EXPOSE 7700

# Health endpoint check -- z4j mounts /api/v1/health unauthenticated.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:7700/api/v1/health',timeout=3).status==200 else 1)"

ENTRYPOINT ["/usr/bin/tini", "--", "/app/entrypoint.sh"]
CMD ["z4j", "serve"]
