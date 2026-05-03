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

## What is z4j

z4j is one product split into 20 PyPI packages so each piece can be
installed only where it's needed. The umbrella `z4j` is the
operator-friendly entry point that wires the right combination
together for you.

The architecture is straightforward:

- **One brain process per environment.** Dashboard, API, audit
  log. Persistent storage in SQLite or Postgres.
- **One agent per worker / app process.** A thin pip package that
  imports inside your Django / Flask / FastAPI app or your Celery /
  RQ / Dramatiq worker, opens an authenticated WebSocket to the
  brain, and streams every task / worker / queue / schedule event.
- **Operator actions flow back the same channel.** Retry, cancel,
  bulk retry, purge, restart, schedule CRUD, manual trigger.

z4j is AGPL v3 and isolated in its own process. The agent
packages your application imports are Apache-2.0 each, so your
application code is never AGPL-tainted.

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

## Install

The minimum useful install is z4j plus the framework + engine
your stack actually uses. Use the extras instead of pinning each
package by hand:

```bash
pip install z4j                          # brain only
pip install 'z4j[django,celery]'         # Django + Celery + celery-beat
pip install 'z4j[fastapi,arq]'           # FastAPI + arq + arq-cron
pip install 'z4j[flask,rq]'              # Flask + RQ + rq-scheduler
pip install 'z4j[django,celery,scheduler]'   # add z4j-scheduler too
```

Each extra pulls the matching engine adapter and its schedule
companion (e.g. `[celery]` pulls `z4j-celery` + `z4j-celerybeat`).
The `[scheduler]` extra adds `z4j-scheduler` for operators who want
the engine-agnostic dynamic scheduler.

Then start z4j:

```bash
z4j serve
```

First boot mints HMAC secrets, runs Alembic migrations, creates a
SQLite database at `~/.z4j/z4j.db`, and prints a one-time setup URL
to stderr that creates the first admin user. Set
`Z4J_DATABASE_URL=postgresql+asyncpg://...` to use Postgres.

## Why use z4j

z4j exists because every Python task queue ships its own
viewer-grade tool (Flower for Celery, rq-dashboard for RQ, Dramatiq
has none) and they all stop at viewer-grade. None of them give you:

- One dashboard across mixed engines (Celery + RQ + arq side by
  side, common operator workflow).
- An action surface (retry, cancel, bulk retry, purge, restart)
  that's safe to put in front of operations and compliance teams.
- A real audit log that an auditor can walk linearly.
- Live schedule editing across engines without per-daemon
  restarts.
- Self-hosted with no telemetry. z4j phones home only when
  an admin clicks *Check for updates* in Settings, and that URL is
  configurable.

z4j is the boring, self-hosted, audit-friendly choice. Built for
homelab operators who want one place to look, and for
compliance-sensitive teams who need to answer "who did what when"
at quarter-end.

## Documentation

Full docs at [z4j.dev](https://z4j.dev). The install guide at
[z4j.dev/getting-started/install/](https://z4j.dev/getting-started/install/)
covers all three paths (pip-SQLite, Docker-SQLite, Docker-Postgres).

## License

AGPL-3.0-or-later, see [LICENSE](LICENSE). Note: only z4j is
AGPL. Every agent package your application imports is Apache-2.0,
so your application code is never AGPL-tainted. Commercial licenses
available; contact licensing@z4j.com.

## Links

- Homepage: https://z4j.com
- Documentation: https://z4j.dev
- PyPI: https://pypi.org/project/z4j/
- Issues: https://github.com/z4jdev/z4j/issues
- Changelog: [CHANGELOG.md](CHANGELOG.md)
- Security: security@z4j.com (see [SECURITY.md](SECURITY.md))
