# z4j E2E spine (Playwright)

A focused browser spine that must pass before release. These tests are a
tripwire for operator-critical flows, not a browser coverage target.

## Running locally

From the repository root, run `make test-e2e`. This is destructive: it calls
`scripts/e2e_bootstrap.sh`, which installs the dashboard dependencies from the
lockfile, generates a fresh route tree before Vite starts, and then
deletes the dev Compose volumes. Playwright runs inside the same pinned image used by CI.
Do not point it at development data you need to keep.

## Running in CI

The `.github/workflows/e2e.yml` GitHub Action uses the same bootstrap:

1. Installs locked dashboard dependencies and generates routes before Vite
2. Starts docker-compose with `Z4J_BOOTSTRAP_ADMIN_EMAIL` +
   `Z4J_BOOTSTRAP_ADMIN_PASSWORD` env vars set
3. Requires a real Chromium page to render the Email and Sign in controls
4. Runs Playwright in the pinned browser image against the running stack
5. Uploads the Playwright HTML report on failure

## Adding a scenario

Keep the bar high. New tests should cover a feature that:

- A new operator hits in the first 15 minutes, AND
- A refactor could silently break, AND
- The existing unit / integration tests do not already catch.

If any of those is false, write a unit test instead. The spine
stays small on purpose.

## Flaky? Fix the root cause.

The pinned Make target sets `CI=1`, matching the workflow's two retries for
transient infrastructure failures. A scenario that needs retries consistently
still has a bug; do not hide it with a per-test retry override.
