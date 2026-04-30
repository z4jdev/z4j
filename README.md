# z4j

**Open-source control plane for Python task infrastructure.**
**License:** AGPL v3 - commercial license available (contact `licensing@z4j.com`).
**Status:** v1.0.10 (production-ready).

A modern, self-hosted alternative to Flower / Prometheus-only task
monitoring. Monitor, manage, and control Celery / RQ / Dramatiq /
Huey / arq / TaskIQ / APScheduler workers, tasks, schedules, and
queues from a single dashboard.

This is the **umbrella package**. Installing `z4j` gets you the
flagship experience (brain + dashboard + SQLite) plus a clean way
to layer in adapter engines via extras.

## Quick start - 30 seconds

```bash
pip install z4j
z4j serve
```

That's the entire setup. The first run automatically:

1. Creates `~/.z4j/z4j.db` (bundled SQLite, no Postgres needed for evaluation).
2. Mints HMAC signing keys to `~/.z4j/secret.env` (sessions + audit-log chaining survive restarts).
3. Runs Alembic migrations to head.
4. Boots the brain on `http://localhost:7700`.
5. Prints a one-time setup URL like `http://localhost:7700/setup?token=...`.

Open the URL in your browser, create the admin account, and you
land on the dashboard. Everything self-contained in `~/.z4j/`. To
start fresh: delete that directory and re-run.

See [z4j-brain](https://pypi.org/project/z4j-brain/) for the
complete configuration reference (defaults, retention, rate limits,
Argon2 cost, etc.). For production, set `Z4J_SECRET`,
`Z4J_SESSION_SECRET`, `Z4J_DATABASE_URL`, `Z4J_PUBLIC_URL`, and
`Z4J_ALLOWED_HOSTS` explicitly via env vars and back up the secret
store.

## Install shapes

```bash
# Just the brain (dashboard + SQLite)
pip install z4j

# Brain + Celery adapter (pulls z4j-celery + z4j-celerybeat)
pip install "z4j[celery]"

# Brain + Django + Celery
pip install "z4j[django,celery]"

# Switch the brain to PostgreSQL
pip install "z4j[postgres]"

# Every adapter engine at once (useful for CI)
pip install "z4j[agents]"

# The kitchen sink
pip install "z4j[all]"
```

### Install with [uv](https://docs.astral.sh/uv/)

The same shapes work verbatim under `uv`:

```bash
uv pip install z4j                  # brain-only
uv pip install "z4j[celery]"        # + celery adapter
uv pip install "z4j[django,celery]" # + django + celery
uv add z4j                          # add as a project dep
```

`uv` resolves the same dependency tree as `pip` (we run a uv smoke
test before every release), and gives you reproducible lockfiles
plus ~10x faster installs. Either tool ships the same wheel.

## Which adapter extras exist

| Extra | Installs | For |
|---|---|---|
| `[celery]` | z4j-celery + z4j-celerybeat | Celery workers + beat scheduler |
| `[django]` | z4j-django | Django task telemetry |
| `[flask]` | z4j-flask | Flask background tasks |
| `[fastapi]` | z4j-fastapi | FastAPI BackgroundTasks |
| `[rq]` | z4j-rq + z4j-rqscheduler | RQ workers + rq-scheduler |
| `[dramatiq]` | z4j-dramatiq | Dramatiq actors |
| `[huey]` | z4j-huey + z4j-hueyperiodic | Huey + periodic tasks |
| `[arq]` | z4j-arq + z4j-arqcron | arq workers + cron |
| `[taskiq]` | z4j-taskiq + z4j-taskiqscheduler | TaskIQ + scheduler |
| `[apscheduler]` | z4j-apscheduler | APScheduler jobs |
| `[bare]` | z4j-bare | Bare (no engine) agents |

## Which umbrella extras exist

| Extra | Installs | For |
|---|---|---|
| `[postgres]` | z4j-brain[postgres] (asyncpg) | Production PostgreSQL backend |
| `[agents]` | every engine adapter | Full-stack dev / CI testing |
| `[all]` | `[agents,postgres]` | Kitchen sink |

## Agent-only installs (no AGPL in your app's venv)

If you're adding z4j to an existing Django / Celery / Flask
application and you need Apache-2.0-only dependencies (no AGPL
in your proprietary code's venv), skip the umbrella and install
the standalone adapter packages directly:

```bash
pip install z4j-core z4j-django    # SDK + Django adapter
pip install z4j-celery             # SDK + Celery adapter
pip install z4j-rq                 # SDK + RQ adapter
```

Every adapter package is **Apache 2.0** and depends only on
`z4j-core` (also Apache 2.0). Point `Z4J_BRAIN_URL` at a running
brain and the adapter will start streaming telemetry.

## Docker Compose recipes

Prefer Docker to pip? This repo ships three ready-to-use compose
files alongside the Python package:

```bash
git clone https://github.com/z4jdev/z4j.git
cd z4j
cp .env.example .env     # fill in Z4J_SECRET, Z4J_SESSION_SECRET, etc.
```

Then pick your mode:

```bash
# Evaluation / homelab (SQLite bundled in the image):
docker compose up -d

# Production self-host (adds PostgreSQL 18 sidecar):
docker compose -f docker-compose.postgres.yml up -d

# Add Caddy auto-HTTPS on top of either mode:
docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d
# or:
docker compose -f docker-compose.postgres.yml -f docker-compose.caddy.yml up -d
```

All three compose files reference the same `z4jdev/z4j:latest`
image from [Docker Hub](https://hub.docker.com/r/z4jdev/z4j) - the
mode switch happens at runtime via `Z4J_DATABASE_URL`, not at build
time. Caddy is an optional overlay that layers auto-HTTPS on top.

Full deployment walkthrough, reverse-proxy alternatives (nginx,
Traefik, Cloudflare Tunnel), and production hardening guide:
<https://z4j.dev>.

## Licensing

`z4j` (this umbrella package) is **AGPL v3** because it installs
`z4j-brain` by default. If that is incompatible with your policy,
use the agent-only install recipe above.

- Agent packages (`z4j-core`, `z4j-celery`, `z4j-django`, ...):
  **Apache 2.0**. Free for proprietary use.
- Brain server (`z4j-brain`): **AGPL v3**. Commercial license
  available - contact `licensing@z4j.com`.

The split is deliberate. The brain is the network service operators
run; the agents are the client libraries integrators embed. AGPL
protects the server; Apache makes integration frictionless.

## Documentation

Complete documentation, tutorials, API reference, deployment
guides: <https://z4j.dev>.

- Source: <https://github.com/z4jdev/z4j>
- Issues: <https://github.com/z4jdev/z4j/issues>
- Changelog: <https://github.com/z4jdev/z4j/blob/main/CHANGELOG.md>
