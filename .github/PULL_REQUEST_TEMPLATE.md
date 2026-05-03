<!--
Thanks for contributing to z4j. Please fill this template out.
-->

## Summary

<!-- One paragraph describing what this PR does. -->

## Why

<!-- Why is this change needed? What alternatives were considered? The
     diff shows WHAT changed; this section shows WHY. -->

## How to test

<!-- Specific steps a reviewer can take to verify. -->

1.
2.
3.

## Checklist

- [ ] Tests added (unit + integration where applicable)
- [ ] `uv run ruff check .` and `uv run ruff format --check .` pass locally
- [ ] `uv run pytest -xvs tests/unit/` passes locally
- [ ] If this touches Postgres-only paths: `uv run pytest -xvs tests/integration/` passes locally against Postgres 18
- [ ] Docs updated if user-visible behavior changed (z4j.dev for operator docs, z4j.com for marketing)
- [ ] `CHANGELOG.md` entry added under `[Unreleased]`
- [ ] No `# type: ignore` without a comment explaining why
- [ ] No `print()` / `console.log` left in code
- [ ] If this touches the wire protocol, the protocol version is bumped or the change is additive
- [ ] If this adds an Alembic migration: `downgrade()` is implemented AND `tests/integration/test_migration_pg.py::TestMigrationRoundTrip` passes locally against Postgres 18. Destructive migrations (drop column with data, narrow type, etc.) explicitly set `irreversible = True` in the `compat` dict and the `downgrade()` body raises `CommandError` with a message pointing operators at backup-restore.

## Risks

<!-- What could go wrong? What did you not test? Is there anything a
     reviewer should look at with extra care? -->

## Related issues

<!-- Closes #..., Fixes #..., Related to #... -->
