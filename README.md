# z4j

[![PyPI version](https://img.shields.io/pypi/v/z4j.svg)](https://pypi.org/project/z4j/)
[![Python](https://img.shields.io/pypi/pyversions/z4j.svg)](https://pypi.org/project/z4j/)
[![License](https://img.shields.io/pypi/l/z4j.svg)](https://github.com/z4jdev/z4j/blob/main/LICENSE)

The all-in-one z4j umbrella package. Open-source control plane for
Python task queues.

One `pip install z4j` brings z4j (dashboard + API)
into your environment. Use extras to pull the agent packages your
workers need: framework adapters (Django, Flask, FastAPI), engine
adapters (Celery, RQ, Dramatiq, Huey, arq, TaskIQ), and their
schedule companions. Every adapter cross-versions to the same z4j
release line, so the floors stay in sync without manual pinning.

## Compatibility

Brain: Python 3.11+, PostgreSQL 18.3+ recommended (minimum 17), or
bundled SQLite.

Every adapter pulled through the `[django,celery]` / `[fastapi,arq]` / etc. extras carries its own framework / engine version floor. Full per-adapter matrix at <https://z4j.dev/reference/compatibility/>.

## What is z4j

z4j is one product split into 20 PyPI packages so each piece can be
installed only where it's needed. The umbrella `z4j` is the
operator-friendly entry point that wires the right combination
together for you.

The architecture is straightforward:

- **One brain deployment per environment.** Dashboard, API, audit
  log. SQLite runs one worker process; PostgreSQL deployments can use
  multiple workers or replicas against shared state.
- **One agent per worker / app process.** A thin pip package that
  imports inside your Django / Flask / FastAPI app or your Celery /
  RQ / Dramatiq worker, connects over an authenticated WebSocket (or
  the configured HTTPS long-poll transport), and streams task / worker /
  queue / schedule events.
- **Operator worker actions flow back through the agent transport.** Retry,
  cancel, bulk retry, purge, and restart use the agent command channel.
  Schedule changes are stored and audited by the brain; the scheduler
  consumes them through its separate gRPC protocol.

The `z4j` server distribution is AGPL v3 and runs as its own process. The
agent packages imported by applications are Apache-2.0 and can be installed
independently of the server distribution; consult the license terms for the
obligations that apply to your deployment.

## What's in the box

- **Brain** ([`z4j`](https://github.com/z4jdev/z4j)).
  Server, dashboard, API, RBAC, HMAC-chained audit log,
  notifications, reconciliation worker.
- **Engine-agnostic dynamic scheduler**
  ([`z4j-scheduler`](https://github.com/z4jdev/z4j-scheduler)).
  Optional companion process for projects that want one canonical
  scheduler across mixed engines, with live editing from the
  dashboard, HA leader election, and audited schedule mutations.
- **Framework adapters.** [`z4j-django`](https://github.com/z4jdev/z4j-django),
  [`z4j-flask`](https://github.com/z4jdev/z4j-flask),
  [`z4j-fastapi`](https://github.com/z4jdev/z4j-fastapi), plus the
  framework-free [`z4j-bare`](https://github.com/z4jdev/z4j-bare)
  for plain Celery / RQ / Dramatiq workers.
- **Engine adapters.** [`z4j-celery`](https://github.com/z4jdev/z4j-celery),
  [`z4j-rq`](https://github.com/z4jdev/z4j-rq),
  [`z4j-dramatiq`](https://github.com/z4jdev/z4j-dramatiq),
  [`z4j-huey`](https://github.com/z4jdev/z4j-huey),
  [`z4j-arq`](https://github.com/z4jdev/z4j-arq),
  [`z4j-taskiq`](https://github.com/z4jdev/z4j-taskiq).
- **Scheduler adapters.** [`z4j-celerybeat`](https://github.com/z4jdev/z4j-celerybeat),
  [`z4j-rqscheduler`](https://github.com/z4jdev/z4j-rqscheduler),
  [`z4j-apscheduler`](https://github.com/z4jdev/z4j-apscheduler),
  [`z4j-arqcron`](https://github.com/z4jdev/z4j-arqcron),
  [`z4j-hueyperiodic`](https://github.com/z4jdev/z4j-hueyperiodic),
  [`z4j-taskiqscheduler`](https://github.com/z4jdev/z4j-taskiqscheduler).

## Try the live demo (no install)

[**demo.z4j.dev**](https://demo.z4j.dev) is the dashboard SPA
running in your browser against pre-baked fake data. One click on
the pre-filled login lands you in a populated control plane with
four sample projects: Celery + celery-beat (small healthy starter),
FastAPI + arq + arq-cron, Django + Celery + django-celery-beat
with a current incident scenario (failing schedule, alert firing,
worker offline), and a mixed-engine z4j-scheduler showcase
driving Celery + RQ + Dramatiq workers from one place.

It is a navigable preview, not a sandbox: every Create / Update /
Delete button toast-blocks (`This is a demo. Refresh to reset;
install z4j to make changes for real.`), no real backend is
connected, refresh resets to a clean state. Useful before you
commit to `pip install`.

## Install

The minimum useful install is z4j plus the framework + engine
your stack actually uses. Use the extras instead of pinning each
package by hand:

```bash
pip install z4j                          # brain only
pip install 'z4j[django,celery]'         # Django + Celery + celery-beat
pip install 'z4j[fastapi,arq]'           # FastAPI + arq + arq-cron
pip install 'z4j[flask,rq]'              # Flask + RQ + rq-scheduler
```

Where a dedicated schedule companion exists, the engine extra pulls it too
(for example, `[celery]` pulls `z4j-celery` + `z4j-celerybeat`). The
`[dramatiq]` extra installs only `z4j-dramatiq`; `[apscheduler]` is available
separately for applications that use APScheduler.
The engine-agnostic dynamic scheduler is its own service and its
own package, install it alongside the brain when you want it:

```bash
pip install z4j-scheduler
```

That same-environment install supplies the brain's optional gRPC runtime. If
the scheduler runs in a separate environment, install `z4j[scheduler-grpc]`
on the brain as well and configure its mTLS scheduler listener.

Then start z4j:

```bash
z4j serve
```

The packaged SQLite path persists independent HMAC, session, audit-chain, and
metrics secrets on first boot, runs Alembic migrations, creates
`~/.z4j/z4j.db`, and prints a one-time setup URL to stderr that creates the
first admin user. PostgreSQL does not auto-mint those secrets. Install its
drivers with `pip install 'z4j[postgres]'`, set
`Z4J_DATABASE_URL=postgresql+asyncpg://...`, and explicitly configure
`Z4J_SECRET`, `Z4J_SESSION_SECRET`, and the independent
`Z4J_AUDIT_CHAIN_SECRET`, plus the production URL and allowed hosts described
in the install guide.

## Why use z4j

z4j is designed to replace separate, engine-specific operational surfaces
with one control plane. It provides:

- One dashboard across mixed engines (Celery + RQ + arq side by
  side, common operator workflow).
- An RBAC-governed action surface for retry, cancel, bulk retry, purge, and
  restart.
- An HMAC-chained audit log for changes made through z4j. It detects paths that
  skip the audit authority, but does not defend against a database role that
  can rewrite both the log and its chain state; the security threat model
  documents that boundary.
- Live editing, without per-daemon restarts, for schedules owned by the
  engine-agnostic z4j scheduler.
- Self-hosted with no unsolicited vendor telemetry or automatic version
  polling. Optional Sentry and OpenTelemetry exporters send data only when an
  operator installs and configures them. The brain contacts its configurable
  version URL only when an admin clicks *Check for updates* in Settings; the
  separate `z4j upgrade` command contacts PyPI only when an operator invokes
  it.

z4j is the boring, self-hosted, audit-friendly choice. Built for
homelab operators who want one place to look, and for
compliance-sensitive teams who need to answer "who did what when"
at quarter-end.

## Documentation

Full docs at [z4j.dev](https://z4j.dev). The install guide at
[z4j.dev/getting-started/install/](https://z4j.dev/getting-started/install/)
covers all three paths (pip-SQLite, Docker-SQLite, Docker-Postgres).

## License

AGPL-3.0-or-later, see [LICENSE](LICENSE). The `z4j` server distribution and
frozen `z4j-brain` compatibility shim are AGPL. The independently installable
shared core, agent packages, and scheduler are Apache-2.0; consult the license
terms for the obligations that apply to your deployment.
Commercial licenses available; contact licensing@z4j.com.

## Links

- Homepage: https://z4j.com
- Documentation: https://z4j.dev
- PyPI: https://pypi.org/project/z4j/
- Issues: https://github.com/z4jdev/z4j/issues
- Changelog: [CHANGELOG.md](CHANGELOG.md)
- Security: security@z4j.com (see [SECURITY.md](SECURITY.md))
