# Changelog

All notable changes to `z4j` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.1] - 2026-04-29

### Changed

- **Floor bumped to `z4j-brain>=1.2.1`** (was `>=1.2.0`).
  `z4j-brain` 1.2.1 ships the dashboard SPA rebuild that fixes
  two JavaScript crashes in the bundled UI:
  - `/settings/notifications/subscriptions` was throwing
    `(e ?? []) is not iterable`
  - `/projects/{slug}/schedules` was throwing `t.filter is not
    a function`
  Both stemmed from the same root cause: the cursor-walking
  hooks (`useUserSubscriptions`, `useSchedules`) were updated in
  the source to walk the new `{items, next_cursor}` envelope,
  but the SPA was bundled before that change landed. 1.2.1
  rebuilds the SPA and re-bundles it into the wheel. Plus the
  3 audit findings (F1 legacy slot collision, F2 per-agent
  worker cap, F3 atomic mark_offline) and the new
  `agent_workers` durable persistence layer + REST endpoint.
  This umbrella bump means `pip install -U z4j` always pulls
  the fixed brain.

## [1.2.0] - 2026-04-29

### Changed

- **Floor bumps for the worker-first wave:**
  `z4j-core>=1.2.0,<1.3`, `z4j-brain>=1.2.0,<1.3`,
  `z4j-bare>=1.2.0`, `z4j-django>=1.2.0`, `z4j-flask>=1.2.0`,
  `z4j-fastapi>=1.2.0`. Operators pinning `z4j>=1.2.0` get the
  multi-worker fix end-to-end - their gunicorn / Celery worker
  fleet shows up as N discrete workers on the brain instead of
  fighting for the single agent slot.

### Worker-first protocol summary

1.2.0 fixes the multi-worker flap that bit operators running
gunicorn with `--workers 4` (or any Celery / RQ / Dramatiq
worker pool with concurrency > 1). The brain's WebSocket
registry now accepts multiple concurrent connections per
agent_id, keyed by a worker_id the agent generates at startup.

The dashboard's workers page enrichment (filter by role,
per-worker pid / role / status columns) lands in 1.2.1; brain
1.2.0 already accepts the data, but the UI still shows the
1.1.x view. Operators can confirm the fix by watching brain
logs for the absence of `4002` close codes after upgrading.

Backward-compatible: old agents (1.1.x) stay on the single-
slot legacy path, and new brains accept them transparently.
Old brains accept new agents but ignore the new fields - same
behavior as 1.1.x.


## [1.1.2] - 2026-04-28

### Fixed

- **Agent stuck-offline failure mode resolved across the family.**
  Before 1.1.2, framework agents (Django, Flask, FastAPI, bare)
  treated `AuthenticationError` and `ProtocolError` as fatal and
  stopped reconnecting forever - leaving the agent process alive
  but offline until the host process was restarted. The 1.1.2
  wave bumps every framework + engine adapter to a wheel that
  picks up the supervisor forever-retry fix in `z4j-bare 1.1.2`.

### Added

- **Unified resilience CLI** across every framework, engine, and
  the scheduler. Both invocation forms work for every package:
  - `z4j-django doctor | check | status | restart`
  - `python -m z4j_django doctor | check | status | restart`
  - same for `z4j-flask`, `z4j-fastapi`, `z4j-bare`,
    `z4j-celery`, `z4j-rq`, `z4j-dramatiq`, `z4j-huey`,
    `z4j-arq`, `z4j-taskiq`, `z4j-scheduler`
  Engines (libraries, not runtimes) get doctor / check / status /
  version; frameworks (and bare) also get restart (SIGHUP via
  pidfile, skipping the supervisor's exponential backoff).
- **Pidfile + SIGHUP control surface.** Every framework agent
  writes a pidfile under `$Z4J_RUNTIME_DIR` (default `~/.z4j/`)
  on startup; `restart` reads it and signals the running process.
- **`Z4J_BUFFER_DIR`** env var for explicit buffer-directory
  override.

### Changed

- **Floor bumps:** every framework + engine adapter raised to
  `>=1.1.2` in the umbrella's extras. Operators pinning
  `z4j>=1.1.2` are guaranteed the resilience wave end-to-end.

## [1.1.1] - 2026-04-28

### Changed

- **Floor bumped to `z4j-brain>=1.1.1`** (was `>=1.1.0`).
  `z4j-brain` 1.1.0 shipped a migration that crashed mid-flight on
  populated DBs with pre-existing audit-chain forks (sqlite3
  IntegrityError from `2026_04_28_0012_audit_unique`). 1.1.1 adds a
  pre-flight check that refuses cleanly with a precise remediation
  message pointing at the new `z4j audit fork-cleanup` CLI. This
  umbrella bump means `pip install -U z4j` always pulls the fixed
  brain; operators can no longer accidentally land on the broken
  wheel via the umbrella.

## [1.1.0] - 2026-04-27

> **The always-works baseline.** Coordinated ecosystem release: the
> four anchor packages (`z4j-core`, `z4j-brain`, `z4j-scheduler`, and
> this umbrella) all ship at 1.1.0 simultaneously. From v1.1.0 forward
> every patch within the v1.1.x line is bidirectionally compatible
> per `docs/MIGRATIONS.md` — operators can pin `z4j>=1.1.0,<1.2` and
> never worry about which patch they're upgrading from or to.
>
> Adapter packages (`z4j-celery`, `z4j-django`, `z4j-flask`,
> `z4j-fastapi`, `z4j-rq`, `z4j-dramatiq`, `z4j-bare`, etc.) stay at
> their current versions — none have changes worth shipping in this
> wave. The umbrella's adapter extras pin compatible floors.

### Changed

- Bumps `z4j-brain` pin to `>=1.1.0,<1.2` and `z4j-core` pin to
  `>=1.1.0,<1.2`. v1.1.0 brain ships the five v1.0.x compat fixes
  (alembic-flap-loop on downgrade, scheduler-worker connection-pool
  starvation, `extra="forbid"` rolling-upgrade traps, stale SPA
  `index.html` after upgrade) plus the embedded scheduler sidecar
  feature, the `:diff` reconciliation preview endpoint, the gRPC
  `too_many_pings` keepalive fix, and the mTLS AuthContext
  bytes/str shape fix. v1.1.0 core surfaces the new
  `Schedule.catch_up` / `source` / `source_hash` fields and the
  `CatchUpPolicy` enum so external SDK consumers can deserialize
  brain responses cleanly. See z4j-brain 1.1.0 + z4j-core 1.1.0
  CHANGELOGs and `docs/MIGRATIONS.md` for the additive-only contract
  that backs the bidirectional-compat guarantee.

### Added

- **`z4j-scheduler` joins the ecosystem at 1.1.0.** First PyPI
  release of the engine-agnostic dynamic scheduler companion
  process. Operators who want the embedded single-container deploy
  set `Z4J_EMBEDDED_SCHEDULER=true` on the brain (the brain auto-
  mints loopback mTLS certs and supervises the scheduler subprocess);
  operators who want a separate scheduler process install
  `pip install z4j-scheduler` and connect via gRPC. Either way the
  brain's `SchedulerService` is gated behind
  `Z4J_SCHEDULER_GRPC_ENABLED` so default installs pay nothing.

## [1.0.18] - 2026-04-27

### Added

- Bumps `z4j-brain` floor to `>=1.0.18,<1.1` which lands two new
  edit flows in the dashboard: **personal subscriptions** and
  **project default subscriptions** can both now be edited
  in-place (pencil icon next to the trash icon on each row)
  instead of the delete-and-recreate workaround. Backend gained
  a `trigger` field on `PATCH /api/v1/user/subscriptions/{id}`
  for full parity with the project-defaults edit endpoint.
- New **`GET /api/v1/user/deliveries`** endpoint: personal
  delivery history across all of the user's projects, with
  optional `?project_slug=` filter and cursor pagination. Mirror
  of the per-project delivery audit log, scoped to the calling
  user. Includes deliveries from projects the user has since
  left (audit data outlives membership; the dashboard renders
  those rows with a "you left this project" badge).
- **Filter parity** between personal subscriptions and project
  defaults dialogs. Both now expose `priority`, `task_name_pattern`,
  AND `queue` filter inputs plus inline help on the priority
  filter explaining the `@z4j_meta(priority='critical')`
  annotation requirement. Personal sub dialog also gained a
  project-channels picker so members can route personal subs
  through admin-managed shared channels.

### Changed

- **Notification settings reorganized into role-based hubs.** The
  five notification routes collapsed into two tabbed hubs by
  role: **"Global Notifications"** (personal, three tabs:
  My Subscriptions / My Channels / My Delivery History) and
  **"Project Notifications"** (admin-only, three tabs: Project
  Channels / Default Subscriptions / Delivery Log). Old URLs
  redirect permanently so bookmarks survive. Zero data model
  changes; pure UI reorganization. See
  [z4j-brain 1.0.18 CHANGELOG](https://github.com/z4jdev/z4j-brain/blob/main/CHANGELOG.md#1018---2026-04-27).

### Fixed

- Latent cursor off-by-one in the project delivery-log endpoint
  silently skipped one row per page boundary. Fixed in both the
  project endpoint and the new personal `/user/deliveries`
  endpoint (encode the last visible row, not the overflow).

### Compatibility

- Backwards compatible. Operator action: `pip install -U z4j` and
  restart. No DB migrations, no env changes.
- Non-admin project members lose visibility of the project
  Notifications sidebar entry (every tab inside is admin-only —
  members manage their notifications from the personal hub). No
  permission change, just a sidebar de-clutter.

## [1.0.17] - 2026-04-27

### Fixed

- Bumps `z4j-brain` floor to `>=1.0.17,<1.1` which fixes a long-
  standing SQLite bug: saving a default or per-user subscription
  with channel ids 500'd because the `uuid_array()` SQLite
  fallback couldn't JSON-serialize `uuid.UUID` instances. Bug
  present in v1.0.0..v1.0.16; SQLite-only (Postgres unaffected).
  Operator action: `pip install -U z4j` and restart. See
  [z4j-brain 1.0.17 CHANGELOG](https://github.com/z4jdev/z4j-brain/blob/main/CHANGELOG.md#1017---2026-04-27).

## [1.0.16] - 2026-04-27

### Fixed

- Bumps `z4j-brain` floor to `>=1.0.16,<1.1` which restores the
  dashboard SPA in the wheel. The 1.0.15 wheel on PyPI was
  missing `dashboard/dist/` (a v1.0.11 packaging regression that
  re-emerged in the release-split script) so `GET /` returned
  `{"detail":"Not Found"}` on every fresh install. Operator
  action: `pip install -U z4j` and restart - no DB migrations,
  no env changes. Docker users were unaffected. See
  [z4j-brain 1.0.16 CHANGELOG](https://github.com/z4jdev/z4j-brain/blob/main/CHANGELOG.md#1016---2026-04-27).

## [1.0.15] - 2026-04-27

### Performance

- Bumps `z4j-brain` floor to `>=1.0.15,<1.1` which lands the
  **P-1 batched heartbeat upsert** — replaces N+1 worker upsert
  round-trips per event batch with a single
  `INSERT...ON CONFLICT DO UPDATE` (dialect-aware on
  Postgres + SQLite). Worker hostnames in the batch are
  deduplicated and flushed as one statement; heartbeat
  carries `max(occurred_at)` instead of racing with
  wall-clock `now()`. Verified end-to-end against a real
  WebSocket: 50 events from 3 workers collapse to 3 worker
  rows with `last_heartbeat = max(occurred_at)` per worker
  (delta 0.000s). 200-event batch now issues exactly **one**
  INSERT against `workers` (was 200 SELECTs + up to 200
  INSERTs/UPDATEs). See [z4j-brain 1.0.15 CHANGELOG](https://github.com/z4jdev/z4j-brain/blob/main/CHANGELOG.md#1015---2026-04-27).

### Security

- Bumps `z4j-brain` floor to `>=1.0.15,<1.1` which adds **SPA
  catch-all hardening** — typo'd `/api/v1/...` URLs now return
  clean 404 JSON instead of being shadowed by the dashboard
  SPA's `index.html` (which broke frontend code with
  `Unexpected token '<'`). Defends `/api/`, `/ws/`, `/metrics`,
  `/auth/`, `/setup/`, `/healthz`, `/.well-known/`,
  `/openapi.json`, `/docs`, `/redoc`, and `/assets/` from
  ever being served as the SPA fallback.

### Fixed

- SQLite migration downgrade across the v1.0.15 schema is now
  safe (uses `op.batch_alter_table` for column drops). Required
  for any operator who deploys to SQLite for eval and needs to
  roll back.
- Latent `ImportError` on certain personal-notification 403
  paths is now a real HTTP 403 envelope.

## [1.0.14] - 2026-04-24

### Security (BREAKING)

- Bumps `z4j-brain` floor to `>=1.0.14,<1.1` which closes two silent-leak defaults:
  1. `z4j serve` now refuses to start when `Z4J_ENVIRONMENT=dev` AND the bind host is non-loopback — the unsafe combo that exposed dev-mode cookies and disabled host validation to anyone who could reach the port.
  2. Default bind host in dev mode is now `127.0.0.1` (was `0.0.0.0`).

  See [/operations/dev-vs-production/](https://z4j.dev/operations/dev-vs-production/) for the migration guide. Most deployments need three env vars added to their systemd unit (`Z4J_ENVIRONMENT=production`, `Z4J_PUBLIC_URL=https://...`, `Z4J_ALLOWED_HOSTS`) and a restart.

### Added

- Bumps `z4j-brain` floor to `>=1.0.14,<1.1` which adds **PagerDuty + Discord native notification channels**, multi-select cross-import (project channels ↔ personal channels), the **`z4j metrics-token rotate`** CLI for token hygiene, **`--environment` / `--env`** flag on `z4j serve`, and a 21-item security audit hardening pass (Codex audit + independent triple audit) covering notification audit-log secret leakage, ReDoS, DoS-input caps, rate limits, IP allow-list discipline, deepcopy of imported configs, atomic file creation for the metrics token, and bonus pre-existing-bug fixes. See [z4j-brain 1.0.14 CHANGELOG](https://github.com/z4jdev/z4j-brain/blob/main/CHANGELOG.md#1014---2026-04-24).

## [1.0.13] - 2026-04-24

### Security (BREAKING)

- Bumps `z4j-brain` floor to `>=1.0.13,<1.1` which makes `/metrics` fail-secure by default. Fresh installs and in-place upgrades auto-mint `Z4J_METRICS_AUTH_TOKEN` and persist it to `~/.z4j/secret.env`; `/metrics` returns 401 unless the correct `Authorization: Bearer <token>` is presented OR the operator explicitly sets `Z4J_METRICS_PUBLIC=1`. Closes the default-insecure `/metrics` footgun introduced in 1.0.11. See [z4j-brain 1.0.13 CHANGELOG](https://github.com/z4jdev/z4j-brain/blob/main/CHANGELOG.md#1013---2026-04-24) for operator migration notes.

## [1.0.12] - 2026-04-24

### Fixed

- Bumps `z4j-brain` floor to `>=1.0.12,<1.1` which restores the dashboard SPA. The 1.0.11 wheel on PyPI accidentally shipped the Python code without the bundled SPA, so `GET /` returned `{"detail": "Not Found"}` on every fresh install. `pip install -U z4j` and restart - no DB migrations, no env changes.

## [1.0.11] - 2026-04-24

### Changed

- Bumps pinned versions to match the v1.0.11 audit-hardening wave: `z4j-core>=1.0.5`, `z4j-brain>=1.0.11,<1.1`. See [z4j-brain CHANGELOG](https://github.com/z4jdev/z4j-brain/blob/main/CHANGELOG.md#1011---2026-04-24) for the security findings closed (4 Medium + 3 Low). **Note**: 1.0.11 shipped without the dashboard SPA in the wheel - upgrade directly to 1.0.12 instead.

## [1.0.4] - 2026-04-23

### Fixed

- **Bumps `z4j-brain` floor to `>=1.0.4`** which fixes four UX bugs in the bare-metal first-boot flow:
  1. Stale-DB cross-version safety net: when a fresh secret is auto-minted, any pre-existing `~/.z4j/z4j.db` from a crashed older install is moved aside to `.stale-bak`.
  2. Setup rate-limit budget bumped from 5 to 30 attempts per IP per 15-min window.
  3. Rate-limit lockout no longer self-perpetuates (used to count each blocked retry, extending the window indefinitely).
  4. Setup error messages now include actionable guidance instead of the opaque "setup token expired or already used".
- New `z4j-brain reset-setup` CLI command for stuck operators (escape hatch when locked out without wanting to nuke `~/.z4j/`).

### Compatibility

- Backwards compatible. Compose files unchanged from 1.0.3.

## [1.0.3] - 2026-04-22

### Fixed

- **Bumps `z4j-brain` floor to `>=1.0.3`** which fixes the zero-config bare-metal `pip install z4j && z4j-brain serve` flow. Before this fix, the CLI auto-defaulted `Z4J_DATABASE_URL` to `~/.z4j/z4j.db` but did NOT auto-mint HMAC signing keys, so `z4j-brain serve` crashed with a Pydantic `ValidationError: secret + session_secret Field required` until the operator manually exported them. The Docker entrypoint had always done this; the bare-metal CLI now matches.
- README "Quick start" rewritten: `pip install z4j && z4j-brain serve` is now the entire flow. No manual `secrets.token_urlsafe` dance.

### Compatibility

- Backwards compatible. Operators who already set `Z4J_SECRET`, `Z4J_SESSION_SECRET`, etc. via env vars or compose files see no behavior change. The auto-mint kicks in only when those env vars are unset.
- Compose files unchanged from 1.0.2.

## [1.0.2] - 2026-04-22

### Added

- **Docker Compose recipes ship with the package.** `docker-compose.yml` (SQLite mode), `docker-compose.postgres.yml` (PostgreSQL sidecar), `docker-compose.caddy.yml` (Let's Encrypt HTTPS overlay), and `.env.example` are now included in the `z4j` sdist and the [z4jdev/z4j GitHub repo](https://github.com/z4jdev/z4j). Operators can `git clone github.com/z4jdev/z4j && docker compose up -d` for a fully working self-host without reading the Dockerfile.
- Compose files reference the public `z4jdev/z4j:latest` image on Docker Hub (published in v1.0.1 of the brain).

### Notes

- Wheel content is unchanged from 1.0.1 - the compose files are sdist + repo artifacts, not runtime Python code. `pip install z4j==1.0.1` and `pip install z4j==1.0.2` land identical Python on disk. The sdist (and the GitHub repo) is where compose recipes appear.

## [1.0.1] - 2026-04-22

First public release of the z4j umbrella package. Synchronized with z4j-brain 1.0.1.

### Features

- **Meta-install for the z4j control plane.** `pip install z4j` resolves to `z4j-brain>=1.0.1` + `z4j-core>=1.0.1`, giving a fully working brain server (dashboard, REST API, WebSocket gateway, SQLite DB, Alembic migrations, CLI) in one command. Mirrors the `docker run z4jdev/z4j` experience for Python-first operators.
- **Clean extras surface for adapter selection**: `[celery]`, `[django]`, `[flask]`, `[fastapi]`, `[rq]`, `[dramatiq]`, `[huey]`, `[arq]`, `[taskiq]`, `[apscheduler]`, `[bare]`. Each extra pulls the engine adapter plus its companion scheduler (where applicable) in one shot, covering the 95% case.
- **Infra pass-through extra** `[postgres]` defers to `z4j-brain[postgres]`, so asyncpg's version floor stays owned by the brain package rather than being duplicated here.
- **Convenience bundles**: `[agents]` (every engine adapter at once) and `[all]` (= `[agents,postgres]`, the kitchen sink for CI / dev rigs).
- **Agent-only install recipe documented** for organizations whose policy forbids AGPL code: `pip install z4j-core z4j-<adapter>` keeps Apache-2.0 purity without touching the brain.

### Notes

- **OpenTelemetry is not shipped.** The umbrella intentionally does not expose an `[otel]` extra. z4j-brain 1.0.1 simultaneously drops its own `[otel]` extra because the packages were installed but the integration code was never wired (no `TracerProvider` init, no FastAPI instrumentation, no OTLP export path). OpenTelemetry support will return as a real working feature in a future release, at which point both packages will reintroduce the extra. Until then, the working observability story is Prometheus `/metrics` + structlog JSON logs, both wired in z4j-brain since 1.0.0.

### Compatibility

- Python 3.11, 3.12, 3.13, 3.14.
- Operating-system independent (Linux, macOS, Windows).
- Depends on `z4j-brain>=1.0.1` (AGPL v3) and `z4j-core>=1.0.1` (Apache 2.0).

## Links

- Repository: <https://github.com/z4jdev/z4j>
- Issues: <https://github.com/z4jdev/z4j/issues>
- PyPI: <https://pypi.org/project/z4j/>

[Unreleased]: https://github.com/z4jdev/z4j/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/z4jdev/z4j/releases/tag/v1.0.0
