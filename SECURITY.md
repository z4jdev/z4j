# Security Policy

This is the policy published with the standalone `z4j` brain repository. It
mirrors the canonical root `SECURITY.md` in the release source; the detailed
product threat model is published at
[z4j.dev](https://z4j.dev/security/threat-model/).

## Reporting a vulnerability

If you believe you have found a security vulnerability in z4j, **do not open a
public GitHub issue**. Email `security@z4j.com` instead. We do not currently
publish a PGP key; send only a contact request first if the report should not
travel in plain email.

We follow the [disclose.io](https://disclose.io) baseline and commit to:

- acknowledging your report within **48 hours**;
- providing a preliminary assessment within **5 business days**;
- fixing a confirmed critical issue within **7 days of confirmation**, and
  another confirmed issue within **30 days of confirmation**;
- coordinating public disclosure within a default **90-day window from your
  first report**; and
- crediting you in the release notes, with your permission.

## Published advisories

Published advisories appear under
[z4jdev/z4j security advisories](https://github.com/z4jdev/z4j/security/advisories)
after a fix ships. Security fixes shipped without a coordinated advisory remain
recorded in `CHANGELOG.md`.

## Supported versions

Security fixes are issued for the current minor line. Critical fixes are
backported to the previous minor when operators cannot upgrade promptly.

| Version line | Receives security fixes |
|---|---|
| 1.9.x | Yes (current) |
| 1.8.x | Critical only |
| < 1.8.x | No (please upgrade) |

## Known limitation: database writers can defeat both database guards

The PostgreSQL schedule-control and audit-chain guards do **not** defend
against a database role that can write their tables. Their triggers authorize
using session configuration values that any client can set. Such a role can
allocate a schedule revision and matching change-log entry before changing a
schedule, or delete an audit-log suffix and restore an earlier still-valid
chain state. Verification then accepts the shortened history. The role does
not need to know or forge a secret in either case.

These guards still catch application bugs, downgraded adapters, operator
mistakes, and code paths that bypass the owning service. Treat write access to
the z4j schema as equivalent to control of these integrity guarantees:

- give the brain a dedicated database role and do not share it with reporting
  tools or hand-run migrations;
- keep database backups private; and
- for evidence that must survive a hostile database role, export chain heads
  to a durable append-only sink outside that database and verify with
  `z4j audit verify --known-head`.

The built-in audit webhook is best-effort and is not such an append-only sink.
The database-boundary redesign is deferred to 2.0; its acceptance criterion is
that a role holding only table privileges cannot alter a schedule or shorten
the audit log without verification reporting it.

## Security-critical surface

This repository ships the z4j brain, including authentication, sessions and
CSRF, project RBAC, agent transport, automation, the audit trail, and the
bundled dashboard. Reports about the brain or any official z4j package are in
scope. Reports about third-party dependencies should go to their maintainers.
