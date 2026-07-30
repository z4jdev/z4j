# =============================================================================
# z4j release Dockerfile.
#
# Slim runtime that installs z4j from this released source context. The
# sdist bundles the compiled React dashboard, alembic.ini, and migrations,
# so this Dockerfile does NOT need pnpm, Vite, or the monorepo source tree.
#
# The local install is load-bearing: ``docker compose up --build`` must be
# testable before this same version exists on PyPI, and must never silently
# build an older published z4j when invoked from a release artifact.
#
# Runtime contents are equivalent to:
#   pip install "/build/z4j[postgres,scheduler-grpc]" z4j-scheduler
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
    Z4J_BIND_PORT=7700 \
    Z4J_ENVIRONMENT=production \
    Z4J_PUBLIC_URL=http://localhost:7700 \
    Z4J_ALLOWED_HOSTS='["localhost","127.0.0.1"]' \
    Z4J_ALLOW_HTTP_PUBLIC_URL=true \
    Z4J_HOME=/data

# Copy the released package source before installing it. In the monorepo this
# context is packages/z4j; in an extracted sdist it is the sdist root. Both
# contain pyproject.toml, src/, and backend/src/, including the already-built
# dashboard assets.
COPY . /build/z4j

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
    chmod 0700 /data; \
    chown -R z4j:z4j /app /data

# Install z4j from the released build context. Release sdists carry matching
# z4j-core and z4j-scheduler sources in their Docker deployment payload so a
# candidate image can be built before the coordinated package wave is
# published. A checkout-local build can fall back to the index after that
# version exists; pre-publish monorepo builds use backend/Dockerfile, which
# installs the same three local sources.
#
# Run the leanness pass in the SAME RUN so the cleanup actually frees disk in the
# resulting layer (Docker
# layers are additive; cleanup in a later RUN keeps the original
# bytes around forever). The leanness pass trims ~80 MB of test
# fixtures, type stubs, bytecode, and unused SQLAlchemy dialects
# (we only ship support for sqlite + postgresql; the
# mssql/mysql/oracle dialect packages ship with SQLAlchemy by
# default but z4j never uses them).
RUN set -eux; \
    if [ -f /build/z4j/docker/vendor/z4j-core/pyproject.toml ] \
        && [ -f /build/z4j/docker/vendor/z4j-scheduler/pyproject.toml ]; then \
        pip install --no-cache-dir \
            "/build/z4j/docker/vendor/z4j-core" \
            "/build/z4j[postgres,scheduler-grpc]" \
            "/build/z4j/docker/vendor/z4j-scheduler"; \
    else \
        test -n "${Z4J_RESOLVED_VERSION}"; \
        # Track the brain's MINOR line, not its exact patch. An exact pin
        # makes the image unbuildable for any release that does not
        # republish the whole fleet: a flagship-only patch leaves
        # z4j-scheduler==<that patch> nonexistent on the index, and the
        # build fails at the last step with nothing wrong in the code.
        # The scheduler is compatible across a minor by contract, so
        # ~=X.Y.0 resolves the newest published patch of the same line.
        Z4J_SCHEDULER_LINE="$(printf '%s' "${Z4J_RESOLVED_VERSION}" | cut -d. -f1-2).0"; \
        pip install --no-cache-dir \
            "/build/z4j[postgres,scheduler-grpc]" \
            "z4j-scheduler~=${Z4J_SCHEDULER_LINE}"; \
    fi; \
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
        2>/dev/null || true; \
    rm -rf /build/z4j

# Volume mount for SQLite, persisted secrets, embedded PKI, allowed-hosts.
# Z4J_HOME=/data is set above so every state file lands here, covered by
# the named volume. Pre-1.5 the entrypoint shell duplicated the Python
# atomic-mint logic and only covered /data/secret.env + /data/z4j.db;
# /app/.z4j/embedded-pki and /app/.z4j/allowed-hosts leaked outside the
# volume. 1.5 collapses to a single Python code path.
VOLUME /data

WORKDIR /data
USER z4j

EXPOSE 7700

# Health endpoint check -- z4j mounts /api/v1/health unauthenticated.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:7700/api/v1/health',timeout=3).status==200 else 1)"

# `z4j serve` itself handles SQLite-by-default, atomic secret mint
# (mode 0o600, O_CREAT|O_EXCL|O_NOFOLLOW), and auto-migration via
# Z4J_AUTO_MIGRATE=true (the default). Identical code path runs on
# bare metal, in containers, and in CI.
ENTRYPOINT ["/usr/bin/tini", "--", "z4j"]
CMD ["serve"]
