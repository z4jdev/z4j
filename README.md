# z4j

[![PyPI version](https://img.shields.io/pypi/v/z4j.svg)](https://pypi.org/project/z4j/)
[![Python](https://img.shields.io/pypi/pyversions/z4j.svg)](https://pypi.org/project/z4j/)
[![License](https://img.shields.io/pypi/l/z4j.svg)](https://github.com/z4jdev/z4j/blob/main/LICENSE)

The all-in-one z4j umbrella package, open-source control plane for Python task queues.

One `pip install z4j` brings the brain server (dashboard + API) into your
environment. Use extras to pull the agent packages your workers need -
framework adapters (Django, Flask, FastAPI), engine adapters (Celery, RQ,
Dramatiq, Huey, arq, TaskIQ), and their schedule companions. Every
adapter cross-versions to the same z4j release line, so floors stay
in sync without manual pinning.

## Install

```bash
pip install z4j
z4j serve
```

For an existing app, install the framework + engine extras you need:

```bash
pip install 'z4j[django,celery]'
pip install 'z4j[flask,rq]'
pip install 'z4j[fastapi,arq]'
```

Each extra pulls the matching engine adapter and its schedule companion
(e.g. `[celery]` pulls `z4j-celery` + `z4j-celerybeat`).

## What's in the box

- **Brain** (`z4j-brain`), server, dashboard, API, audit log
- **Framework adapters**, Django, Flask, FastAPI, plus a framework-free
  agent runtime
- **Engine adapters**, Celery, RQ, Dramatiq, Huey, arq, TaskIQ
- **Scheduler adapters**, Celery Beat, rq-scheduler, APScheduler, arq
  cron, Huey @periodic_task, taskiq-scheduler
- **Engine-agnostic scheduler** (`z4j-scheduler`), optional companion
  process for projects that want a single canonical scheduler across
  engines

## Architecture in one paragraph

One brain process per environment. One agent per worker / app process,
streaming task / worker / queue / schedule events to the brain over an
authenticated WebSocket. The dashboard surfaces every event, exposes
the operator action surface (retry, cancel, bulk retry, purge, restart,
schedule CRUD), and ships a tamper-evident HMAC-chained audit log.

## Documentation

Full docs at [z4j.dev](https://z4j.dev).

## License

AGPL-3.0-or-later, see [LICENSE](LICENSE). Note: only the brain is
AGPL. Every agent package your application imports is Apache-2.0,
so your application code is never AGPL-tainted.

## Links

- Homepage: https://z4j.com
- Documentation: https://z4j.dev
- PyPI: https://pypi.org/project/z4j/
- Issues: https://github.com/z4jdev/z4j/issues
- Changelog: [CHANGELOG.md](CHANGELOG.md)
- Security: security@z4j.com (see [SECURITY.md](SECURITY.md))
