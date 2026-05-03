# Changelog

## 1.4.0 (2026-05-02)

Initial 1.4.0 release: the consolidated z4j control plane. Server, dashboard, REST API, audit log, and reconciliation all ship in this distribution (pre-1.4.0 they shipped under the `z4j` PyPI name; that name is now a metadata-only compatibility shim). Engine and framework adapters available via extras: `pip install z4j[django,celery]`.
