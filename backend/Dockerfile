# syntax=docker/dockerfile:1.7
#
# z4j-brain unified image (backend + dashboard).
#
# Multi-stage build:
#   1. dashboard-builder - Node 24 + pnpm. Compiles the
#      TanStack Router + Vite dashboard to static HTML/CSS/JS.
#   2. python-builder    - Python 3.14 + uv. Builds the brain
#      backend wheel and resolves all runtime deps into a venv.
#   3. runtime           - Debian Trixie slim. Copies the venv
#      from stage 2 and the dashboard dist from stage 1, then
#      runs as a non-root user under tini.
#
# We deliberately base on python:3.14-slim-trixie (Debian 13).
# Alpine is not supported - see docs/CLAUDE.md §4.6 for the
# rationale (glibc wheels, asyncpg + argon2-cffi + uvloop
# compile-from-source pain on musl, enterprise scanner baselines).
#
# Build context: the monorepo root, NOT this directory:
#
#     docker build -f packages/z4j-brain/backend/Dockerfile -t z4j-brain .

ARG PYTHON_VERSION=3.14
ARG DEBIAN_RELEASE=trixie
ARG NODE_VERSION=24

# ---------------------------------------------------------------------------
# Stage 1 - dashboard build
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION}-bookworm-slim AS dashboard-builder

ENV CI=true \
    PNPM_HOME=/root/.local/share/pnpm \
    PATH=/root/.local/share/pnpm:$PATH

RUN corepack enable && corepack prepare pnpm@10.33.0 --activate

WORKDIR /dashboard

# Copy package metadata first so the install layer caches when
# only source changes.
COPY packages/z4j-brain/dashboard/package.json packages/z4j-brain/dashboard/pnpm-lock.yaml* ./

# Audit H22: NO ``|| pnpm install`` fallback. The previous fallback
# silently accepted a stale lockfile, which means a CVE'd
# transitive could land in the production image without anyone
# bumping the lockfile in source control. Build fails loudly if
# the lockfile is out of date - contributor runs ``pnpm install``
# locally, commits the new lockfile, push.
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile

# Copy the rest of the dashboard source and build.
COPY packages/z4j-brain/dashboard/ ./

RUN pnpm build

# Source maps are emitted with ``sourcemap: "hidden"`` in
# vite.config.ts - the bundle references them indirectly but the
# browser never auto-fetches them. Dropping them here (in the
# dashboard-builder stage, before ``COPY --from=dashboard-builder``)
# keeps the runtime dist/ layer ~3.5 MB smaller. Dropping them in a
# later ``RUN`` on the runtime stage would shadow but not reclaim.
RUN find dist -name '*.map' -delete

# ---------------------------------------------------------------------------
# Stage 2 - python builder
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-${DEBIAN_RELEASE} AS python-builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        libffi-dev \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "uv>=0.5.10"

# IMPORTANT: do NOT copy the workspace root pyproject.toml here.
# If uv sees a workspace root, it installs every workspace member
# as an editable .pth pointing at the build context - and the
# runtime stage doesn't have the build context, so imports fail
# at startup with "No module named z4j_core". By copying the two
# package trees into a non-workspace directory, uv builds real
# wheels from each pyproject.toml and installs them into /opt/venv.
WORKDIR /build
COPY packages/z4j-core /build/packages/z4j-core
COPY packages/z4j-brain /build/packages/z4j-brain
# z4j-scheduler is a separate PyPI package but bundling it inside the
# brain image enables the optional ``Z4J_EMBEDDED_SCHEDULER=true``
# sidecar (docs/SCHEDULER.md §21.3) without requiring a second image.
# The runtime cost is ~10 MB of pure-Python wheel; embedded mode stays
# off by default so the brain starts identically to pre-1.x releases
# unless the operator opts in.
COPY packages/z4j-scheduler /build/packages/z4j-scheduler

RUN uv venv /opt/venv \
    && VIRTUAL_ENV=/opt/venv uv pip install \
        --no-cache \
        /build/packages/z4j-core \
        "/build/packages/z4j-brain[postgres,scheduler-grpc]" \
        /build/packages/z4j-scheduler

# -----------------------------------------------------------------
# Image-leanness pass. The installed venv carries a few classes of
# bloat the brain never uses at runtime:
#
#   - ``__pycache__/`` and stray .pyc - we set
#     ``PYTHONDONTWRITEBYTECODE=1`` everywhere but the install step
#     still produced some during wheel unpacking.
#   - ``tests/``, ``test/``, ``examples/`` shipped inside some
#     wheels (sqlalchemy, pydantic-core, cryptography historically).
#   - ``*.dist-info/RECORD`` and friends - useful for
#     ``pip uninstall``, which a sealed image never does.
#   - C-extension debug sections in ``.so`` files - usually a
#     few hundred KB each across asyncpg + uvloop + httptools +
#     argon2.
#
# Combined this trims 30-50 MB off the runtime image without
# changing any observable behaviour.
# -----------------------------------------------------------------
RUN set -eux; \
    find /opt/venv -type d -name '__pycache__' -prune -exec rm -rf {} +; \
    find /opt/venv -type f -name '*.pyc' -delete; \
    find /opt/venv -type d \( \
        -name 'tests' -o -name 'test' -o -name 'examples' \
    \) -prune -exec rm -rf {} + 2>/dev/null || true; \
    # .pyi stubs are only consumed by type-checkers at build time;
    # mypy does not run inside the container.
    find /opt/venv -name '*.pyi' -delete; \
    # SQLAlchemy ships every dialect by default (~1 MB total). The
    # brain commits to PostgreSQL (production) + SQLite (evaluation).
    # Dropping mssql/mysql/oracle saves ~0.8 MB and trims attack
    # surface (fewer dialect parsers reachable from user-provided
    # URLs). Keeping postgresql + sqlite.
    rm -rf \
        /opt/venv/lib/python*/site-packages/sqlalchemy/dialects/mssql \
        /opt/venv/lib/python*/site-packages/sqlalchemy/dialects/mysql \
        /opt/venv/lib/python*/site-packages/sqlalchemy/dialects/oracle; \
    # Strip C-extension debug sections. ``strip`` is in
    # build-essential which is already installed in this stage.
    find /opt/venv -type f -name '*.so' -exec strip --strip-unneeded {} + \
        2>/dev/null || true

# ---------------------------------------------------------------------------
# Stage 3 - runtime
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-${DEBIAN_RELEASE} AS runtime

# OCI image metadata. Version is injected at build time via --build-arg
# Z4J_VERSION=... so we never have to keep a hardcoded version in sync
# with pyproject.toml. ``org.opencontainers.image.*`` labels are what
# Docker Hub, GitHub Container Registry, Syft, Trivy, and Docker Scout
# consume to render "Source", "License", etc.
ARG Z4J_VERSION=dev
LABEL org.opencontainers.image.title="z4j" \
      org.opencontainers.image.description="z4j: open-source control plane for Python task infrastructure" \
      org.opencontainers.image.version="${Z4J_VERSION}" \
      org.opencontainers.image.source="https://github.com/z4jdev/z4j-brain" \
      org.opencontainers.image.url="https://pypi.org/project/z4j-brain/" \
      org.opencontainers.image.documentation="https://z4j.dev" \
      org.opencontainers.image.vendor="z4j contributors" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    Z4J_LOG_JSON=true \
    Z4J_BIND_HOST=0.0.0.0 \
    Z4J_BIND_PORT=7700 \
    Z4J_DASHBOARD_DIST=/app/dashboard/dist \
    Z4J_ALEMBIC_INI=/app/alembic.ini

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libpq5 \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 z4j \
    && useradd --system --uid 10001 --gid z4j --home /app --shell /usr/sbin/nologin z4j

# Backend venv from python-builder.
COPY --from=python-builder /opt/venv /opt/venv

# Dashboard dist from dashboard-builder. Static files only -
# no Node runtime in the final image.
COPY --from=dashboard-builder /dashboard/dist /app/dashboard/dist

# -----------------------------------------------------------------
# Runtime leanness pass. The base image + our COPY'd venv + the
# dashboard dist ship with ~18 MB we can drop without losing any
# observable behavior:
#
#   - Dashboard source maps (~3.5 MB). vite.config.ts emits them
#     with ``sourcemap: "hidden"`` so the browser never fetches
#     them automatically; they're only useful to whoever holds
#     the image. We strip them so they're not shipped to every
#     operator.
#   - python:slim ships ``pip`` + ``ensurepip`` + ``idlelib`` +
#     ``tkinter`` + ``pydoc_data`` + ``turtledemo`` (~13 MB
#     combined). The brain runs against the /opt/venv wheel
#     install only; pip isn't invoked at runtime. The GUI /
#     demo modules are pure dead weight in a headless container.
#   - ``.pyi`` type-stub files (~200 KB) are only consumed at
#     type-check time. mypy doesn't run inside the container.
#
# If we ever need to add a runtime pip install this leanness pass
# removes, do it in a layer ABOVE this one so the ordering stays
# "install then prune."
# -----------------------------------------------------------------
RUN set -eux; \
    find /app/dashboard/dist -name '*.map' -delete; \
    rm -rf \
        /usr/local/lib/python3.14/site-packages/pip \
        /usr/local/lib/python3.14/site-packages/pip-*.dist-info \
        /usr/local/lib/python3.14/site-packages/setuptools* \
        /usr/local/lib/python3.14/site-packages/wheel* \
        /usr/local/lib/python3.14/ensurepip \
        /usr/local/lib/python3.14/idlelib \
        /usr/local/lib/python3.14/tkinter \
        /usr/local/lib/python3.14/turtledemo \
        /usr/local/lib/python3.14/pydoc_data \
        /usr/local/bin/pip* \
        /usr/local/bin/idle* \
        /usr/local/bin/2to3* \
        /usr/local/bin/pydoc* ; \
    find /opt/venv -name '*.pyi' -delete

# Runtime-specific alembic.ini.
#
# The source-tree alembic.ini uses `script_location = src/z4j_brain/migrations`
# which only resolves when run from the backend source dir. In the
# image we don't ship the source tree - only the installed wheel -
# so we use Python package notation, which alembic resolves through
# importlib against the wheel under /opt/venv. env.py is identical
# in both layouts so no other config changes are needed.
RUN printf '%s\n' \
    '[alembic]' \
    'script_location = z4j_brain:migrations' \
    'path_separator = os' \
    'timezone = UTC' \
    'sqlalchemy.url =' \
    '' \
    '[loggers]' \
    'keys = root,sqlalchemy,alembic' \
    '[handlers]' \
    'keys = console' \
    '[formatters]' \
    'keys = generic' \
    '[logger_root]' \
    'level = WARNING' \
    'handlers = console' \
    '[logger_sqlalchemy]' \
    'level = WARNING' \
    'handlers =' \
    'qualname = sqlalchemy.engine' \
    '[logger_alembic]' \
    'level = INFO' \
    'handlers =' \
    'qualname = alembic' \
    '[handler_console]' \
    'class = StreamHandler' \
    'args = (sys.stderr,)' \
    'level = NOTSET' \
    'formatter = generic' \
    '[formatter_generic]' \
    'format = %%(levelname)-5.5s [%%(name)s] %%(message)s' \
    'datefmt = %%Y-%%m-%%d %%H:%%M:%%S' \
    > /app/alembic.ini

# Entrypoint shim: handle SQLite defaults, run migrations, then exec.
# We use exec so the brain inherits PID 1 (under tini) and gets
# signals correctly on `docker stop`.
RUN printf '%s\n' \
    '#!/bin/sh' \
    'set -e' \
    '' \
    '# SQLite mode: if no DATABASE_URL is set, use SQLite in /data.' \
    '# Also set dev-friendly defaults for quick evaluation.' \
    'if [ -z "$Z4J_DATABASE_URL" ]; then' \
    '  mkdir -p /data' \
    '  export Z4J_DATABASE_URL="sqlite+aiosqlite:////data/z4j.db"' \
    '  export Z4J_REGISTRY_BACKEND="${Z4J_REGISTRY_BACKEND:-local}"' \
    '  export Z4J_ENVIRONMENT="${Z4J_ENVIRONMENT:-dev}"' \
    '  export Z4J_ALLOWED_HOSTS="${Z4J_ALLOWED_HOSTS:-[\"localhost\",\"127.0.0.1\"]}"' \
    '  echo "[z4j] using SQLite at /data/z4j.db (dev mode)"' \
    'fi' \
    '' \
    '# Secret handling - persist across restarts so an evaluation' \
    '# `docker run` that mints an agent token and sets up an admin' \
    '# user does not lose both on the next `docker restart`.' \
    '# Precedence:' \
    '#   1. explicit env (op-provided) - use as-is' \
    '#   2. /data/secret.env exists - source it (persisted from' \
    '#      a previous boot) so tokens/sessions remain valid' \
    '#   3. neither - mint fresh + persist to /data/secret.env' \
    'if [ -z "$Z4J_SECRET" ]; then' \
    '  if [ -f /data/secret.env ]; then' \
    '    # shellcheck disable=SC1091' \
    '    . /data/secret.env' \
    '    echo "[z4j] loaded persisted Z4J_SECRET from /data/secret.env"' \
    '  else' \
    '    mkdir -p /data' \
    '    Z4J_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")' \
    '    Z4J_SESSION_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")' \
    '    {' \
    '      printf "export Z4J_SECRET=%s\\n" "$Z4J_SECRET";' \
    '      printf "export Z4J_SESSION_SECRET=%s\\n" "$Z4J_SESSION_SECRET";' \
    '    } > /data/secret.env' \
    '    chmod 600 /data/secret.env' \
    '    echo "[z4j] minted fresh Z4J_SECRET + Z4J_SESSION_SECRET, persisted to /data/secret.env"' \
    '    echo "[z4j] WARNING: evaluation mode - set Z4J_SECRET via env and back /data up for production"' \
    '  fi' \
    '  export Z4J_SECRET Z4J_SESSION_SECRET' \
    'fi' \
    '' \
    'echo "[z4j] running migrations"' \
    'z4j-brain migrate upgrade head' \
    'echo "[z4j] starting server"' \
    'exec "$@"' \
    > /app/entrypoint.sh \
    && chmod +x /app/entrypoint.sh

# Create /data for SQLite mode. Volume-mount this for persistence.
RUN mkdir -p /data && chown z4j:z4j /data
VOLUME /data

# Make sure z4j owns its writable surfaces.
RUN chown -R z4j:z4j /app

WORKDIR /app
USER z4j

EXPOSE 7700

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:7700/api/v1/health',timeout=3).status==200 else 1)"

ENTRYPOINT ["/usr/bin/tini", "--", "/app/entrypoint.sh"]
CMD ["z4j-brain", "serve"]


# ---------------------------------------------------------------------------
# Stage 4 - dev-runtime (used by docker-compose.dev.yml only)
# ---------------------------------------------------------------------------
# Same venv as production but:
#   - no dashboard dist (Vite serves the dashboard from a sibling
#     container with HMR)
#   - source mounted as a volume so file changes hot-reload
#   - uvicorn --reload as the command
#   - runs as the non-root z4j user
#
# This stage exists so contributors can run the brain in Docker
# without paying the dashboard build cost on every restart.
FROM python:${PYTHON_VERSION}-slim-${DEBIAN_RELEASE} AS dev-runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    Z4J_LOG_JSON=false \
    Z4J_BIND_HOST=0.0.0.0 \
    Z4J_BIND_PORT=7700 \
    Z4J_ALEMBIC_INI=/app/alembic.ini

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libpq5 \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 z4j \
    && useradd --system --uid 10001 --gid z4j --home /app --shell /bin/sh z4j

COPY --from=python-builder /opt/venv /opt/venv

# /app is the working directory; create it before writing files
# into it (the production runtime stage gets /app implicitly via
# the dashboard COPY, but the dev runtime has nothing to COPY).
RUN mkdir -p /app

# Same runtime alembic.ini as the production stage. We can't COPY
# from a sibling stage cleanly across forks of the build graph, so
# this stage re-creates the file. It's a small price for keeping
# the dev brain on the exact same migration path as production.
RUN printf '%s\n' \
    '[alembic]' \
    'script_location = z4j_brain:migrations' \
    'path_separator = os' \
    'timezone = UTC' \
    'sqlalchemy.url =' \
    '' \
    '[loggers]' \
    'keys = root,sqlalchemy,alembic' \
    '[handlers]' \
    'keys = console' \
    '[formatters]' \
    'keys = generic' \
    '[logger_root]' \
    'level = WARNING' \
    'handlers = console' \
    '[logger_sqlalchemy]' \
    'level = WARNING' \
    'handlers =' \
    'qualname = sqlalchemy.engine' \
    '[logger_alembic]' \
    'level = INFO' \
    'handlers =' \
    'qualname = alembic' \
    '[handler_console]' \
    'class = StreamHandler' \
    'args = (sys.stderr,)' \
    'level = NOTSET' \
    'formatter = generic' \
    '[formatter_generic]' \
    'format = %%(levelname)-5.5s [%%(name)s] %%(message)s' \
    'datefmt = %%Y-%%m-%%d %%H:%%M:%%S' \
    > /app/alembic.ini

# Same entrypoint shim as production: run migrations to head, then
# exec the actual server. The shim is simple enough that it does
# not need a rebuild for hot-reload - uvicorn --reload watches the
# mounted source paths and restarts the python process in place.
RUN printf '%s\n' \
    '#!/bin/sh' \
    'set -e' \
    'echo "[z4j-brain] running alembic upgrade head"' \
    'z4j-brain migrate upgrade head' \
    'echo "[z4j-brain] starting dev server with hot-reload"' \
    'exec "$@"' \
    > /app/entrypoint.sh \
    && chmod +x /app/entrypoint.sh

RUN chown -R z4j:z4j /app

WORKDIR /app
USER z4j

EXPOSE 7700

ENTRYPOINT ["/usr/bin/tini", "--", "/app/entrypoint.sh"]
CMD ["uvicorn", "z4j_brain.main:create_app", \
     "--factory", "--host", "0.0.0.0", "--port", "7700", \
     "--reload", "--reload-dir", "/app/packages/z4j-brain/backend/src", \
     "--reload-dir", "/app/packages/z4j-core/src"]
