# Changelog

## 1.7.0 (2026-07-07)

* **Automation rule engine**: governed per-project rules (notify / retry / cancel) with a rolling-window circuit breaker, per-project kill switch, dry-run mode, and an HMAC-chained audit of every firing; destructive actions require ADMIN plus fresh MFA, re-verified at fire time. New dashboard Automation area.
* **Issues** (failure fingerprinting), **brain-side misfire detection**, **per-operator fire attribution**, a **durable automation firing outbox**, and Postgres RANGE-partitioning of the fire-history table.
* Purge confirmation is now a keyed HMAC derived from the project secret and verified server-side.
* See the root CHANGELOG for the full detail of this release.
* Python 3.11 is now the minimum supported version (3.10 dropped).
* Part of the coordinated 1.7.0 fleet release (unified fleet version, green lint/format/import-boundary gate).

## 1.4.0 (2026-05-02)

Initial 1.4.0 release: the consolidated z4j control plane. Server, dashboard, REST API, audit log, and reconciliation all ship in this distribution (pre-1.4.0 they shipped under the `z4j` PyPI name; that name is now a metadata-only compatibility shim). Engine and framework adapters available via extras: `pip install z4j[django,celery]`.
