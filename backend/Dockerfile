# syntax=docker.io/docker/dockerfile:1.20.0@sha256:26147acbda4f14c5add9946e2fd2ed543fc402884fd75146bd342a7f6271dc1d
#
# z4j-brain unified image (backend + dashboard).
#
# Multi-stage build:
#   1. python-builder - Python 3.14.7 + uv. Builds the brain backend
#      wheel plus its two workspace siblings from THIS tree and
#      resolves every runtime dependency into /opt/venv.
#   2. runtime        - Debian Trixie slim. Copies the venv from stage 1
#      and the git-tracked compiled dashboard from the build context,
#      then runs as a non-root user under tini.
#   3. dev-runtime    - same venv, no bundled dashboard, hot-reload
#      uvicorn. Used by docker-compose.dev.yml only.
#
# We deliberately base on python:3.14-slim-trixie (Debian 13).
# Alpine is not supported - see docs/CLAUDE.md 4.6 for the
# rationale (glibc wheels, asyncpg + argon2-cffi + uvloop
# compile-from-source pain on musl, enterprise scanner baselines).
#
# 1.9.0 provenance note. This file builds from ordinary upstream base
# images. The production-authority apparatus that briefly lived here
# (sealed wheelhouse / system-bundle / dashboard-bundle carrier images,
# hash-locked offline installs, a sealed Debian .deb closure, a cosign
# verifier, and manifest receipt labels) is deferred to 2.x. Its three
# carrier images were never produced: packages/z4j/docker/production/
# README.md says the finalizer tranche is deliberately absent, and the
# manifest is pinned "unfinalized" with all-zero digests. Depending on
# them here made the image unbuildable, which is strictly worse than
# building it the way 1.8.0's shipping image was built. What that
# apparatus bought, and what this file does instead, is noted at each
# site below so nobody mistakes the ordinary build for the sealed one.
#
# Build context: the monorepo root, NOT this directory:
#
#     docker build --target runtime -f packages/z4j/backend/Dockerfile -t z4j .
#
# ALWAYS pass --target runtime for a production image: the LAST
# stage in this file is dev-runtime (hot-reload uvicorn, no bundled
# dashboard), and an untargeted build silently produces that.

# ---------------------------------------------------------------------------
# Stage 1 - python builder
# ---------------------------------------------------------------------------
# The base is pinned by tag AND digest. The tag documents intent, the
# digest is what actually gets pulled. 3.14.7 is load-bearing rather than
# cosmetic: the cadence runtime fingerprint hashes sys.version_info[:3]
# (packages/z4j/docker/production/probe.py), and .python-version at the
# repo root says 3.14.7. Bumping the patch here changes that fingerprint.
FROM docker.io/library/python:3.14.7-slim-trixie@sha256:83ff1d245a3d57d04152252d3ef9cb361494d0b3395abd65a5ebe91c401c8e83 AS python-builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UV_CACHE_DIR=/tmp/uv-cache \
    UV_NO_PROGRESS=1 \
    UV_PYTHON_DOWNLOADS=never

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        libffi-dev \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# uv 0.12.5 is the resolver version the 1.9.0 production manifest names
# (packages/z4j/docker/production/manifest.json, "resolver"). Pinning it
# exactly keeps this ordinary build on the same resolver the sealed build
# would have used. UV_PYTHON_DOWNLOADS=never above forbids uv from
# fetching some other CPython behind our back.
RUN pip install --no-cache-dir "uv==0.12.5"

# IMPORTANT: do NOT copy the workspace root pyproject.toml here.
# If uv sees a workspace root, it installs every workspace member
# as an editable .pth pointing at the build context - and the
# runtime stage doesn't have the build context, so imports fail
# at startup with "No module named z4j_core". By copying the three
# package trees into a non-workspace directory, uv builds real
# wheels from each pyproject.toml and installs them into /opt/venv.
WORKDIR /build
COPY packages/z4j-core /build/packages/z4j-core
# Post-1.4.0 the brain server ships in the ``z4j`` distribution
# (packages/z4j, which packages backend/src/z4j_brain). The old
# ``packages/z4j-brain`` directory is the metadata-only PyPI shim
# whose sole dependency is ``z4j`` -- installing THAT here made uv
# resolve the real brain FROM PYPI, so every image silently shipped
# the previously-published release's backend instead of the source
# tree it was built from (caught by the 1.7.0 boot smoke: a
# 1.7.0-tree image reported ``z4j --version`` = 1.6.9). Install the
# real package from the tree.
#
# This COPY also carries backend/src/z4j_brain/dashboard/dist, which
# [tool.hatch.build] artifacts pulls into the wheel, so the installed
# package keeps its own copy of the dashboard as a fallback for the
# ``pip install z4j`` path. That only works because .dockerignore
# re-includes exactly that one directory out of its blanket **/dist.
COPY packages/z4j /build/packages/z4j
# z4j-scheduler is a separate PyPI package but bundling it inside the
# brain image enables the optional ``Z4J_EMBEDDED_SCHEDULER=true``
# sidecar (docs/SCHEDULER.md 21.3) without requiring a second image.
# The runtime cost is ~10 MB of pure-Python wheel; embedded mode stays
# off by default so the brain starts identically to pre-1.x releases
# unless the operator opts in.
COPY packages/z4j-scheduler /build/packages/z4j-scheduler

# All three distributions are installed FROM THIS TREE, never from
# PyPI. Passing all three paths to one uv invocation is what makes the
# intra-wave requirements (z4j depends on z4j-core>=1.9.0,<2) resolve to
# the local trees instead of whatever the index happens to hold.
#
# Deferred with the apparatus: --require-hashes, --no-index and
# --offline against a sealed wheelhouse. This resolution reaches PyPI
# and is pinned only by the floors in each pyproject.toml, so two builds
# of the same commit on different days can carry different transitive
# versions.
RUN uv venv --python /usr/local/bin/python /opt/venv \
    && uv pip install \
        --python /opt/venv/bin/python \
        --no-cache \
        /build/packages/z4j-core \
        "/build/packages/z4j[postgres,scheduler-grpc]" \
        /build/packages/z4j-scheduler \
    && uv pip check --python /opt/venv/bin/python \
    && rm -rf /tmp/uv-cache

# -----------------------------------------------------------------
# Cadence closure guard.
#
# The sealed build ran probe.py and compared its output against a
# manifest expectation. The manifest is unfinalized, so that comparison
# has no authority to check against; but the half of it that depends on
# nothing outside this tree still works, and it still catches the
# failure that matters most: an install where the brain and the
# scheduler disagree about how a schedule fires.
#
# Checked here:
#   * the interpreter really is 3.14.7, because the runtime fingerprint
#     hashes sys.version_info[:3];
#   * the five cadence-affecting distributions resolved to the exact
#     versions both pyproject.toml files pin with ``==`` (tzdata 2026.3
#     in particular: 2026a computes fire times an hour wrong for seven
#     zones with future effect);
#   * z4j and z4j-scheduler agree on semantics version, behavior vector,
#     tzdata tree digest and runtime fingerprint.
#
# NOT checked here: that those values match a sealed, externally
# reviewed expectation. This proves internal agreement, not authority.
# -----------------------------------------------------------------
RUN /opt/venv/bin/python <<'PY'
import sys
from importlib import metadata

expected_python = (3, 14, 7)
actual_python = tuple(sys.version_info[:3])
if actual_python != expected_python:
    raise SystemExit(
        f"cadence guard: interpreter is {actual_python}, expected {expected_python}"
    )

pinned = {
    "astral": "3.2",
    "croniter": "6.2.2",
    "python-dateutil": "2.9.0.post0",
    "six": "1.17.0",
    "tzdata": "2026.3",
}
for name, want in sorted(pinned.items()):
    got = metadata.version(name)
    if got != want:
        raise SystemExit(f"cadence guard: {name} resolved to {got}, expected {want}")

from z4j_brain.domain.schedule_cadence import (
    CADENCE_SEMANTICS_VERSION as brain_semantics,
)
from z4j_brain.domain.schedule_cadence import (
    cadence_behavior_vector_digest as brain_behavior,
)
from z4j_brain.domain.schedule_cadence import (
    cadence_runtime_fingerprint as brain_fingerprint,
)
from z4j_brain.domain.schedule_runtime import packaged_tzdata_digest as brain_tzdata
from z4j_scheduler.tick._runtime import packaged_tzdata_digest as scheduler_tzdata
from z4j_scheduler.tick.cadence import (
    CADENCE_SEMANTICS_VERSION as scheduler_semantics,
)
from z4j_scheduler.tick.cadence import (
    cadence_behavior_vector_digest as scheduler_behavior,
)
from z4j_scheduler.tick.cadence import (
    cadence_runtime_fingerprint as scheduler_fingerprint,
)

for label, brain_value, scheduler_value in (
    ("semantics version", brain_semantics, scheduler_semantics),
    ("behavior vector", brain_behavior(), scheduler_behavior()),
    ("tzdata tree", brain_tzdata(), scheduler_tzdata()),
    ("runtime fingerprint", brain_fingerprint(), scheduler_fingerprint()),
):
    if brain_value != scheduler_value:
        raise SystemExit(
            f"cadence guard: brain and scheduler disagree on {label}: "
            f"{brain_value!r} != {scheduler_value!r}"
        )

print(
    "cadence guard: python "
    + ".".join(str(part) for part in actual_python)
    + ", fingerprint "
    + brain_fingerprint()
    + ", tzdata "
    + brain_tzdata()
)
PY

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
# Stage 2 - runtime
# ---------------------------------------------------------------------------
FROM docker.io/library/python:3.14.7-slim-trixie@sha256:83ff1d245a3d57d04152252d3ef9cb361494d0b3395abd65a5ebe91c401c8e83 AS runtime

# OCI image metadata. Version is injected at build time via --build-arg
# Z4J_VERSION=... so we never have to keep a hardcoded version in sync
# with pyproject.toml. ``org.opencontainers.image.*`` labels are what
# Docker Hub, GitHub Container Registry, Syft, Trivy, and Docker Scout
# consume to render "Source", "License", etc.
#
# The org.z4j.production.* receipt labels are NOT emitted. They named a
# manifest digest, a source-projection digest and three carrier index
# digests that do not exist; emitting them carrying the literal string
# "unfinalized" would be a provenance claim this image cannot back.
ARG Z4J_VERSION=dev
LABEL org.opencontainers.image.title="z4j" \
      org.opencontainers.image.description="z4j: open-source control plane for Python task infrastructure" \
      org.opencontainers.image.version="${Z4J_VERSION}" \
      org.opencontainers.image.source="https://github.com/z4jdev/z4j" \
      org.opencontainers.image.url="https://pypi.org/project/z4j/" \
      org.opencontainers.image.documentation="https://z4j.dev" \
      org.opencontainers.image.vendor="z4j contributors" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    Z4J_LOG_JSON=true \
    Z4J_BIND_HOST=0.0.0.0 \
    Z4J_BIND_PORT=7700 \
    Z4J_ENVIRONMENT=production \
    Z4J_PUBLIC_URL=http://localhost:7700 \
    Z4J_ALLOWED_HOSTS='["localhost","127.0.0.1"]' \
    Z4J_ALLOW_HTTP_PUBLIC_URL=true \
    Z4J_DASHBOARD_DIST=/app/dashboard/dist \
    Z4J_ALEMBIC_INI=/app/alembic.ini

# Deferred with the apparatus: the exact, signature-verified transitive
# .deb closure for these three packages, unpacked with the network off
# and then compared against a sealed package list. This is the ordinary
# apt path, so the versions are whatever trixie and trixie-security
# serve on the day of the build.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libpq5 \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 z4j \
    && useradd --system --uid 10001 --gid z4j --home /app --shell /usr/sbin/nologin z4j

# Backend venv from python-builder.
COPY --from=python-builder /opt/venv /opt/venv

# The compiled dashboard, straight from the tree.
#
# This is the git-tracked production bundle (151 files, carrying its own
# .build-inputs.sha256 / .build-output.sha256 receipts), not something
# rebuilt here. 1.8.0 compiled it in a Node stage; 1.9.0 tracks the
# compiled output instead, so the image needs no Node toolchain and no
# npm registry reachability at build time.
#
# Static files only, no Node runtime in the final image.
#
# If this COPY ever fails with "not found", the cause is almost
# certainly .dockerignore: its blanket ``**/dist`` rule has to keep the
# matching ``!packages/z4j/backend/src/z4j_brain/dashboard/dist`` pair
# of lines or this directory never reaches the build context. An image
# built without it answers 404 on ``/``, which is exactly the
# dashboard-less 1.8.0 release that 1.8.1 existed to fix.
COPY packages/z4j/backend/src/z4j_brain/dashboard/dist /app/dashboard/dist

# -----------------------------------------------------------------
# Runtime leanness pass. The base image + our COPY'd venv + the
# dashboard dist ship with ~18 MB we can drop without losing any
# observable behavior:
#
#   - Dashboard source maps (~3.5 MB). vite.config.ts emits them
#     with ``sourcemap: "hidden"`` so the browser never fetches
#     them automatically; they're only useful to whoever holds
#     the image. We strip them so they're not shipped to every
#     operator. The tracked bundle already carries none, and the
#     sweep stays so a future bundle that does cannot leak them.
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
    'format = %(levelname)-5.5s [%(name)s] %(message)s' \
    'datefmt = %Y-%m-%d %H:%M:%S' \
    > /app/alembic.ini

# 1.5: Z4J_HOME=/data routes every state file (DB, secrets, PKI,
# allowed-hosts, agent buffers if a host process runs in this image)
# under /data, which is the volume-mounted directory. Pre-1.5 the
# entrypoint shell duplicated Python's atomic-mint logic and only
# covered /data/secret.env + /data/z4j.db; /app/.z4j/embedded-pki/
# and /app/.z4j/allowed-hosts leaked outside the volume. 1.5 collapses
# to a single Python code path.
ENV Z4J_HOME=/data

# Create /data for SQLite mode. Volume-mount this for persistence. Docker
# initializes a fresh named volume from this directory's ownership and mode;
# keep it owner-private so secret-store bootstrap can run on the first boot.
RUN mkdir -p /data && chown z4j:z4j /data && chmod 0700 /data
VOLUME /data

# Make sure z4j owns its writable surfaces.
RUN chown -R z4j:z4j /app

WORKDIR /data
USER z4j

EXPOSE 7700

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:7700/api/v1/health',timeout=3).status==200 else 1)"

# `z4j serve` itself handles SQLite-by-default, atomic secret mint
# (mode 0o600, O_CREAT|O_EXCL|O_NOFOLLOW), and auto-migration via
# Z4J_AUTO_MIGRATE=true (the default). Identical code path runs on
# bare metal, in containers, and in CI. The legacy `z4j-brain`
# console script was retired in 1.4.0 in favor of the unified `z4j`.
ENTRYPOINT ["/usr/bin/tini", "--", "z4j"]
CMD ["serve"]


# ---------------------------------------------------------------------------
# Stage 3 - dev-runtime (used by docker-compose.dev.yml only)
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
FROM docker.io/library/python:3.14.7-slim-trixie@sha256:83ff1d245a3d57d04152252d3ef9cb361494d0b3395abd65a5ebe91c401c8e83 AS dev-runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    Z4J_LOG_JSON=false \
    Z4J_BIND_HOST=0.0.0.0 \
    Z4J_BIND_PORT=7700 \
    Z4J_ALEMBIC_INI=/app/alembic.ini

RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
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
    'format = %(levelname)-5.5s [%(name)s] %(message)s' \
    'datefmt = %Y-%m-%d %H:%M:%S' \
    > /app/alembic.ini

# Same entrypoint shim as production: run migrations to head, then
# exec the actual server. The shim is simple enough that it does
# not need a rebuild for hot-reload - uvicorn --reload watches the
# mounted source paths and restarts the python process in place.
RUN printf '%s\n' \
    '#!/bin/sh' \
    'set -e' \
    'echo "[z4j] running alembic upgrade head"' \
    'z4j migrate upgrade head' \
    'echo "[z4j] starting dev server with hot-reload"' \
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
     "--reload", "--reload-dir", "/app/packages/z4j/backend/src", \
     "--reload-dir", "/app/packages/z4j-core/src"]
