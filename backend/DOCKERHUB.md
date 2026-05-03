# z4j

**Open-source control plane for Python task infrastructure** - FastAPI backend + React dashboard in a single container.

One dashboard for every Python task engine: Celery, RQ, Dramatiq, Huey, arq, TaskIQ, APScheduler, or plain scripts. Self-hosted. Zero external dependencies in the default mode (bundled SQLite).

**Links**: [PyPI](https://pypi.org/project/z4j/) - [GitHub](https://github.com/z4jdev/z4j) - [Docs](https://z4j.dev) - [Website](https://z4j.com)

---

## Quick start

Run the brain with SQLite (bundled, zero-config):

```bash
docker run -d --name z4j -p 7700:7700 -v z4j-data:/data z4jdev/z4j
docker logs -f z4j
```

The container:

- Auto-generates `Z4J_SECRET` + `Z4J_SESSION_SECRET` on first boot and persists them to `/data/secret.env` (survives restarts).
- Runs Alembic migrations to head.
- Prints a one-time setup URL in the logs: `http://localhost:7700/setup?token=...`

Open that URL, create the admin, and you land on the dashboard.

## Production: with PostgreSQL

For multi-admin, high-throughput, or compliance-grade deployments, use PostgreSQL. The same image switches mode based on `Z4J_DATABASE_URL`:

```bash
docker run -d --name z4j \
  -p 7700:7700 \
  -v z4j-data:/data \
  -e Z4J_DATABASE_URL=postgresql+asyncpg://user:pass@postgres-host:5432/z4j \
  -e Z4J_SECRET=$(openssl rand -hex 48) \
  -e Z4J_SESSION_SECRET=$(openssl rand -hex 48) \
  -e Z4J_PUBLIC_URL=https://z4j.example.com \
  -e Z4J_ALLOWED_HOSTS='["z4j.example.com"]' \
  z4jdev/z4j:1.0.1
```

PostgreSQL unlocks horizontal scale-out (`LISTEN/NOTIFY`-based registry fan-out), range-partitioned events, and `tsvector` full-text search.

## Docker Compose (recommended)

The [z4jdev/z4j repo](https://github.com/z4jdev/z4j) ships ready-to-use compose files:

```bash
git clone https://github.com/z4jdev/z4j.git
cd z4j

# SQLite (evaluation / homelab):
docker compose up -d

# PostgreSQL (production):
docker compose -f docker-compose.postgres.yml up -d

# Add Caddy auto-HTTPS on top of either:
docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d
```

## Environment variables

| Var | Default | Purpose |
|---|---|---|
| `Z4J_DATABASE_URL` | (unset = bundled SQLite) | `postgresql+asyncpg://...` for Postgres mode |
| `Z4J_SECRET` | auto-generated | HMAC signing key (>= 32 bytes) |
| `Z4J_SESSION_SECRET` | auto-generated | Session cookie signing key (>= 32 bytes) |
| `Z4J_BIND_PORT` | `7700` | ASGI port |
| `Z4J_PUBLIC_URL` | `http://localhost:7700` | Used to build setup + password-reset links |
| `Z4J_ENVIRONMENT` | `production` | Set to `dev` to relax host-header + HTTPS checks |
| `Z4J_ALLOWED_HOSTS` | (required in prod) | JSON array of allowed Host headers |
| `Z4J_BOOTSTRAP_ADMIN_EMAIL` + `_PASSWORD` | (unset) | If both set on empty DB, skip the setup-URL step and provision the admin directly |
| `Z4J_EVENT_RETENTION_DAYS` | `30` | How long raw events live |
| `Z4J_AUDIT_RETENTION_DAYS` | `90` | Audit-log row lifetime |
| `Z4J_METRICS_ENABLED` | `true` | Expose Prometheus `/metrics` |

Full reference (30+ additional tunables for rate limits, Argon2 cost, CORS, session cookies, etc.): <https://z4j.dev>.

## Volumes

| Path | Purpose |
|---|---|
| `/data` | SQLite DB + persisted boot-time secrets. Mount a named volume in production. |

## What's inside

- **Backend**: FastAPI + SQLAlchemy 2.0 async (Python 3.14-slim-trixie base image)
- **Dashboard**: React 19 + TanStack Start + Tailwind CSS 4, served from the same process at `/`
- **Migrations**: Alembic, auto-applied on first boot, bundled inside the image
- **Database**: SQLite (via `aiosqlite`) bundled by default; PostgreSQL 18 supported via `Z4J_DATABASE_URL`

Image size: **~234 MB uncompressed / ~52 MB compressed on-wire**.

## Platform support

- **linux/amd64**: v1.0.1 (current)
- **linux/arm64**: not yet in 1.0.1. Adding in 1.0.2 via CI-driven multi-arch builds.

If you're on an M-series Mac or arm64 Linux host right now, install via pip instead: `pip install z4j`.

## Tags

- `z4jdev/z4j:1.0.1` - version-pinned, recommended for production
- `z4jdev/z4j:latest` - always-current, convenient for evaluation

## License

AGPL-3.0-or-later. Commercial license available (`licensing@z4j.com`).

The **brain** image is AGPL. All **agent packages** (`z4j-core`, `z4j-celery`, `z4j-django`, `z4j-rq`, etc. - the client libraries your application embeds) are Apache 2.0 and do **not** subject your application to the AGPL.

## Related

- [`pip install z4j`](https://pypi.org/project/z4j/) - PyPI umbrella (same content, for Python-native installs)
- [`pip install z4j`](https://pypi.org/project/z4j/) - PyPI brain package (AGPL)
- [github.com/z4jdev](https://github.com/z4jdev) - all 20 public repos (brain + 17 agent packages + umbrella + org profile)
