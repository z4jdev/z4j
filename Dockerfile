# syntax=docker.io/docker/dockerfile:1.20.0@sha256:26147acbda4f14c5add9946e2fd2ed543fc402884fd75146bd342a7f6271dc1d
# =============================================================================
# z4j release Dockerfile.
#
# Slim runtime that installs z4j from this released source context. The sdist
# bundles the compiled React dashboard, alembic.ini, and migrations, so this
# Dockerfile does NOT need pnpm, Vite, Node, or the monorepo source tree.
#
# The local install is load-bearing: ``docker compose up --build`` must be
# testable before this same version exists on PyPI, and must never silently
# build an older published z4j when invoked from a release artifact.
#
# Runtime contents are equivalent to:
#   uv pip install "/build/source[postgres,scheduler-grpc]" z4j-core z4j-scheduler
#   z4j serve
#
# Built by .github/workflows/release-docker.yml on tag push (multi-arch
# native amd64 + arm64). Published as z4jdev/z4j:VERSION + :latest.
#
# Note on the build-arg name: the workflow passes ``Z4J_BRAIN_VERSION``
# for backwards compatibility with the pre-1.4.0 build system (the
# secret name on GitHub uses that key). We accept it under both names.
#
# 1.9.0 provenance note. This file builds from ordinary upstream base images,
# the same way the 1.8.x images that actually shipped were built. The
# production-authority apparatus that briefly lived here (sealed wheelhouse /
# system-bundle / dashboard-bundle carrier images, hash-locked offline
# installs, a sealed Debian .deb closure, a cosign verifier, and manifest
# receipt labels) is deferred to 2.x. Its three carrier images were never
# produced: docker/production/README.md says the finalizer tranche is
# deliberately absent, and the manifest is pinned "unfinalized" with all-zero
# digests. Depending on them here made this file unbuildable, and since it is
# bundled into every published sdist, that would have shipped a Dockerfile no
# user could build, permanently. What that apparatus bought, and what this
# file does instead, is noted at each site below so nobody mistakes the
# ordinary build for the sealed one.
#
# TWO build contexts are supported, and both are real:
#
#   1. An extracted release sdist. The context root is the sdist root, which
#      carries docker/vendor/z4j-core and docker/vendor/z4j-scheduler. This is
#      the ``pip download --no-binary :all: z4j`` then ``docker build`` path,
#      and it is what docker-compose.yml builds.
#   2. A checkout of the flattened z4jdev/z4j repository, which
#      release-docker.yml builds. That tree carries no docker/ directory at
#      all, so the vendored sources are absent and the wave siblings resolve
#      from the index instead.
#
# Only the sdist path can be built before the coordinated package wave is
# published, which is exactly why the vendored payload exists.
# =============================================================================

# The base is pinned by tag AND digest. The tag documents intent, the digest is
# what actually gets pulled. 3.14.7 is load-bearing rather than cosmetic: the
# cadence runtime fingerprint hashes sys.version_info[:3], so bumping the patch
# here changes the fingerprint and the image would negotiate schedule firing
# differently from the wheels published beside it. 1.8.x pinned only the 3.14
# tag here and took whatever patch the tag pointed at on the day of the build.
FROM docker.io/library/python:3.14.7-slim-trixie@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS runtime

# OCI image metadata -- consumed by Docker Hub UI, GitHub Container
# Registry, Syft, Trivy, Docker Scout, etc.
#
# The org.z4j.production.* receipt labels are NOT emitted. They named a
# manifest digest, a source-projection digest and three carrier index digests
# that do not exist; emitting them carrying the literal string "unfinalized"
# would be a provenance claim this image cannot back.
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
    UV_NO_PROGRESS=1 \
    UV_PYTHON_DOWNLOADS=never \
    Z4J_LOG_JSON=true \
    Z4J_BIND_HOST=0.0.0.0 \
    Z4J_BIND_PORT=7700 \
    Z4J_ENVIRONMENT=production \
    Z4J_PUBLIC_URL=http://localhost:7700 \
    Z4J_ALLOWED_HOSTS='["localhost","127.0.0.1"]' \
    Z4J_ALLOW_HTTP_PUBLIC_URL=true \
    Z4J_DASHBOARD_DIST=/app/dashboard/dist \
    Z4J_HOME=/data

# Copy the released package source before installing it. In the flattened
# repository this context is the repository root; in an extracted sdist it is
# the sdist root. Both contain pyproject.toml, src/, and backend/src/,
# including the already-built dashboard assets.
COPY . /build/source

# Install runtime OS deps + create non-root user.
#   - tini: proper PID-1 signal handling
#   - libpq5: required by asyncpg's wheel (Postgres driver)
#   - ca-certificates: TLS for PyPI / outbound HTTPS / OAuth providers
#
# Deferred with the apparatus: the exact, signature-verified transitive .deb
# closure for these three packages, unpacked with the network off and then
# compared against a sealed package list. This is the ordinary apt path, so the
# versions are whatever trixie and trixie-security serve on the day of the
# build.
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
# published. A flattened-checkout build falls back to the index after that
# version exists.
#
# uv 0.12.5 is the resolver version the 1.9.0 production manifest names
# (docker/production/manifest.json, "resolver"). Pinning it exactly keeps this
# ordinary build on the same resolver the sealed build would have used, and
# UV_PYTHON_DOWNLOADS=never forbids uv from fetching some other CPython behind
# our back. uv is removed again in this same layer so it is not shipped.
#
# Deferred with the apparatus: --require-hashes, --no-index and --offline
# against a sealed wheelhouse, plus the reproducible-wheel readback. This
# resolution reaches PyPI and is pinned only by the floors in each
# pyproject.toml, so two builds of the same commit on different days can carry
# different transitive versions.
#
# Run the leanness pass in the SAME RUN so the cleanup actually frees disk in
# the resulting layer (Docker layers are additive; cleanup in a later RUN keeps
# the original bytes around forever). The leanness pass trims ~80 MB of test
# fixtures, type stubs, bytecode, and unused SQLAlchemy dialects (we only ship
# support for sqlite + postgresql; the mssql/mysql/oracle dialect packages ship
# with SQLAlchemy by default but z4j never uses them).
RUN set -eux; \
    pip install --no-cache-dir "uv==0.12.5"; \
    # Both siblings come from the sdist payload. There is deliberately no index
    # fallback: resolving z4j-scheduler from PyPI at build time is what made the
    # 1.8.1 image unbuildable on both architectures, looking for a companion
    # patch that was never published, with nothing wrong in the code. pyproject
    # force-includes docker/vendor into every sdist, so if these are missing the
    # context is not a released sdist and the build should stop rather than
    # silently reach for the network.
    test -f /build/source/docker/vendor/z4j-core/pyproject.toml; \
    test -f /build/source/docker/vendor/z4j-scheduler/pyproject.toml; \
    uv pip install --system --no-cache \
        "/build/source/docker/vendor/z4j-core" \
        "/build/source[postgres,scheduler-grpc]" \
        "/build/source/docker/vendor/z4j-scheduler"; \
    uv pip check --system; \
    pip uninstall -y uv; \
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
    rm -rf /build/source

# -----------------------------------------------------------------
# Cadence closure guard.
#
# The sealed build ran docker/production/probe.py and compared its output
# against a manifest expectation. The manifest is unfinalized, so that
# comparison has no authority to check against; but the half of it that depends
# on nothing outside this release carrier still works, and it still catches the
# failure that matters most: an install where the brain and the scheduler
# disagree about how a schedule fires.
#
# Checked here:
#   * the interpreter really is 3.14.7, because the runtime fingerprint
#     hashes sys.version_info[:3];
#   * the five cadence-affecting distributions resolved to the exact versions
#     both pyproject.toml files pin with ``==`` (tzdata 2026.3 in particular:
#     2026a computes fire times an hour wrong for seven zones with future
#     effect);
#   * z4j and z4j-scheduler agree on semantics version, behavior vector,
#     tzdata tree digest and runtime fingerprint;
#   * the fingerprint this image computes equals the one the installed brain
#     declares as its own sealed rollback target
#     (z4j_brain.domain.runtime_rollback.SEALED_TARGET_CADENCE_FINGERPRINT),
#     so the image cannot negotiate differently from the wheels beside it.
#     That constant is read from the package rather than restated here, so
#     this guard needs no digest of its own to keep in sync.
#
# NOT checked here: that those values match a sealed, externally reviewed
# expectation. This proves internal agreement, not authority.
# -----------------------------------------------------------------
RUN python <<'PY'
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

from z4j_brain.domain.runtime_rollback import SEALED_TARGET_CADENCE_FINGERPRINT
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

if brain_fingerprint() != SEALED_TARGET_CADENCE_FINGERPRINT:
    raise SystemExit(
        "cadence guard: image fingerprint "
        f"{brain_fingerprint()} does not equal the packaged target "
        f"{SEALED_TARGET_CADENCE_FINGERPRINT}"
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

# The compiled dashboard, straight from the release carrier.
#
# This is the git-tracked production bundle (151 files, carrying its own
# .build-inputs.sha256 / .build-output.sha256 receipts), not something rebuilt
# here. No Node toolchain and no npm registry reachability at build time.
#
# The installed wheel carries its own copy of this bundle as well, because
# [tool.hatch.build] artifacts pulls backend/src/z4j_brain/dashboard/** into
# it, and main.py falls back to that packaged copy. We still copy it to an
# explicit path and point Z4J_DASHBOARD_DIST at it, so that serving the
# dashboard is a stated property of this image rather than a side effect of
# wheel packaging that a future artifacts change could silently remove.
#
# If this COPY ever fails with "not found", the cause is almost certainly
# .dockerignore: its ``dist`` and ``dashboard/dist`` rules must stay anchored
# so they do not also match this path. An image built without it answers 404
# on ``/``, which is exactly the dashboard-less 1.8.0 release that 1.8.1
# existed to fix.
COPY backend/src/z4j_brain/dashboard/dist /app/dashboard/dist

# Source maps are not shipped to operators. vite.config.ts emits them with
# ``sourcemap: "hidden"`` so the browser never fetches them automatically. The
# tracked bundle already carries none; this sweep stays so a future bundle that
# does cannot leak them.
RUN set -eux; \
    find /app/dashboard/dist -name '*.map' -delete; \
    chown -R z4j:z4j /app

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
