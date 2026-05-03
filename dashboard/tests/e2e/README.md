# z4j E2E spine (Playwright)

Ten golden-path scenarios that MUST pass before any release. This
is the safety net enterprise-readiness §1 called out. These tests
are intentionally small - not a coverage goal, a tripwire.

## Running locally

```bash
# 1. spin up a clean brain + dashboard
scripts/e2e_bootstrap.sh

# 2. install playwright (first time only)
cd packages/z4j/dashboard
pnpm install
pnpm exec playwright install --with-deps chromium

# 3. run the spine
pnpm test:e2e
```

## Running in CI

The `.github/workflows/e2e.yml` GitHub Action does this for you:

1. Starts docker-compose with `Z4J_BOOTSTRAP_ADMIN_EMAIL` +
   `Z4J_BOOTSTRAP_ADMIN_PASSWORD` env vars set
2. Waits for brain health + dashboard ready
3. Runs `pnpm test:e2e` against the running stack
4. Uploads the Playwright HTML report on failure

## Adding a scenario

Keep the bar high. New tests should cover a feature that:

- A new operator hits in the first 15 minutes, AND
- A refactor could silently break, AND
- The existing unit / integration tests do not already catch.

If any of those is false, write a unit test instead. The spine
stays small on purpose.

## Flaky? Fix the root cause.

`test.retries` is `2` only in CI and exists for transient
infrastructure blips (docker networking, sqlite lock under heavy
parallel load). If a scenario needs retries to pass locally, the
scenario has a bug - file it, don't paper over it with `.retry(3)`.
