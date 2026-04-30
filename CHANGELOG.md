# Changelog

All notable changes to this package are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
