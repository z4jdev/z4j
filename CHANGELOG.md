# Changelog

All notable changes to this package are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.4] - 2026-04-30

**Floor bump for the per-agent version visibility feature.**

z4j-brain 1.3.4 ships per-agent version display + an
operator-initiated *Check for updates* button on the dashboard.
Privacy posture is unchanged: no automatic phone-home, the
brain ships with a bundled snapshot of all package versions,
and the *Check for updates* button is the only way the brain
ever reaches out (configurable, can be disabled entirely).

### Changed

- Floor: `z4j-brain>=1.3.4,<2` (was `>=1.3.3`)
- `[postgres]` extra: `z4j-brain[postgres]>=1.3.4,<2`
- No changes to z4j-core, z4j-bare, or any adapter package.

### Compatibility

Drop-in `pip install --upgrade z4j` from any 1.3.x. No DB
migration. Restart the brain.

## [1.3.3] - 2026-04-30

**Schedule snapshot feature wave: floors bumped to pick up the
new automatic schedule reconciliation across z4j-core, z4j-bare,
z4j-brain.**

The 1.3.3 wave ships a unified end-to-end flow that closes the
"existing celery-beat schedules don't show up in the dashboard"
onboarding gap. Three coordinated changes:

- **z4j-core 1.3.1**: new `EventKind.SCHEDULE_SNAPSHOT` carrying
  the full inventory of an agent's scheduler adapter.
- **z4j-bare 1.3.1**: agent emits the snapshot at boot, on a
  configurable periodic timer (default 15 min), and on the new
  `schedule.resync` command.
- **z4j-brain 1.3.3**: ingestor reconciles the snapshot
  (insert / update / delete-missing per `(project, scheduler)`),
  REST endpoint `POST /projects/{slug}/schedules:resync`,
  dashboard *Sync now* button on the Schedules page.

After upgrading: the operator clicks *Sync now* once and every
existing schedule from celery-beat / rq-scheduler / apscheduler /
arqcron / hueyperiodic / taskiqscheduler appears immediately. The
periodic timer keeps state in sync going forward. No declarative
config, no CLI runs, no JSON pasting.

### Changed

- Floors:
  - `z4j-core>=1.3.1,<2` (was `>=1.3.0`)
  - `z4j-brain>=1.3.3,<2` (was `>=1.3.2`)
  - `z4j-bare`: family adapters (z4j-django / z4j-flask /
    z4j-fastapi / z4j-celery / z4j-bare) keep their existing
    floors. Operators who want the snapshot feature on the agent
    side install/upgrade `z4j-bare>=1.3.1` directly in their app
    process; agents at 1.3.0 keep working without the new
    behaviour.
- `[postgres]` extra pinned to `z4j-brain[postgres]>=1.3.3,<2`.

### Compatibility

Drop-in `pip install --upgrade z4j` from any 1.3.x. No DB
migration. Restart the brain after upgrade. Existing schedules
surface within ~10 seconds of the next agent reconnect (or
immediately when *Sync now* is clicked).

## [1.3.2] - 2026-04-30

**Floor bump: pin `z4j-brain>=1.3.2`.**

z4j-brain 1.3.1 shipped a regression where global admins
(`user.is_admin=True`) couldn't create per-user notification
subscriptions through the dashboard — the POST endpoint queried
the `Membership` table directly and 403'd with *you are not a
member of this project* even though `/auth/me` synthesises an
admin membership on every project. z4j-brain 1.3.2 fixes the
contradiction by switching the create endpoint to the canonical
`PolicyEngine.require_member` helper.

### Changed

- Floor: `z4j-brain>=1.3.2,<2` (from `>=1.3.1,<2`).
- `[postgres]` extra likewise pinned to `z4j-brain[postgres]>=1.3.2,<2`.

### Compatibility

Drop-in `pip install --upgrade z4j` from any 1.3.x. No migration.
Restart the brain.

## [1.3.1] - 2026-04-30

**Hotfix wave: bump `z4j-brain` floor to >=1.3.1.**

z4j-brain 1.3.0 shipped a worker-heartbeat upsert bug that left
the dashboard's Workers tab empty on every install (the agent
showed online but no worker rows ever materialised). z4j-brain
1.3.1 fixes both the bulk-upsert path and a Postgres-only raw-SQL
mismatch on the agent connect path.

### Changed

- Floor bumped: `z4j-brain>=1.3.1,<2` (from `>=1.3.0,<2`).
- `[postgres]` extra likewise pinned to `z4j-brain[postgres]>=1.3.1,<2`.
- Engine adapters (z4j-core, z4j-bare, z4j-celery, z4j-django, …)
  unchanged — the bug was brain-only.

### Compatibility

Drop-in `pip install --upgrade z4j` from any 1.3.x. No DB
migration. Restart the brain after upgrade. See z4j-brain 1.3.1
CHANGELOG for the bug detail and the regression coverage added
to prevent recurrence.

## [1.3.0] - 2026-05-15

**Initial release of the 1.3.x line.**

z4j 1.3.0 is a clean-slate reset of the 1.x ecosystem. All prior
1.x versions on PyPI (1.0.x, 1.1.x, 1.2.x) are yanked — they
remain installable by exact pin but `pip install` no longer
selects them. Operators upgrading from any prior 1.x deployment
are expected to back up their database and run a fresh install
against 1.3.x; there is no in-place migration path.

### Why the reset

The 1.0/1.1/1.2 line accumulated complexity organically across
many small releases. By 1.2.2 the codebase carried defensive
shims, deep audit-history annotations, and a 19-step alembic
migration chain that made onboarding harder than it needed to
be. 1.3.0 ships the same feature set as 1.2.2 but with:

- One consolidated alembic migration containing the entire
  schema, with explicit `compat` metadata declaring the version
  window in which it can be applied.
- HMAC canonical form starts at v1 (no v1→v4 fallback chain in
  the verifier).
- Defensive `getattr` shims removed for fields that exist in the
  final model.
- "Audit fix Round-N" annotations removed from the codebase.

### Release discipline (new)

PyPI publishes now require an explicit `Z4J_PUBLISH_AUTHORIZED=1`
environment variable to be set in the publish-script invocation.
The 1.0-1.2 wave shipped patches too quickly and had to yank/
unyank versions; the new gate makes that mistake impossible.

### Migrating from 1.x

1. Back up your database (`z4j-brain backup --out backup.sql`).
2. Bring the brain down.
3. `pip install -U z4j` to pick up 1.3.0.
4. `z4j-brain migrate upgrade head` runs the consolidated
   migration; it detects an empty `alembic_version` table and
   applies the single `v1_3_0_initial` revision.
5. Bring the brain back up. The dashboard, audit log, and
   schedule data structures are preserved across the migration
   when the operator restores from the backup; if you started
   fresh, you'll see an empty brain.

### See also

- `CHANGELOG-1.x-legacy.md` in this package's source tree for
  the complete 1.0/1.1/1.2 release history.

## [Unreleased]
