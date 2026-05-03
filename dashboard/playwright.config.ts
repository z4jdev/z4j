import { defineConfig, devices } from "@playwright/test";

/**
 * z4j dashboard Playwright config.
 *
 * Targets the dev brain at `http://localhost:7701` by default
 * (the Vite proxy forwards /api/v1 to the brain at 7700 so
 * cookies + CSRF stay same-origin - exactly matches what a real
 * operator sees).
 *
 * Tests assume a fresh brain, seeded with a single admin account
 * via the `Z4J_BOOTSTRAP_ADMIN_EMAIL` / `Z4J_BOOTSTRAP_ADMIN_PASSWORD`
 * env path. CI calls `scripts/e2e_bootstrap.sh` before running
 * this config.
 */
export default defineConfig({
  testDir: "./tests/e2e",
  // Sequential on purpose. These tests mutate shared state
  // (projects, users, API keys). Parallelism would require
  // per-worker isolation which isn't worth the bookkeeping cost
  // at ~15 scenarios.
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 2 : 0,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : "list",

  use: {
    baseURL: process.env.Z4J_E2E_BASE_URL ?? "http://localhost:7701",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    // CSRF + session cookies live on the base URL - keep them.
    storageState: undefined,
  },

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],

  // Visual-regression tuning. Anti-aliasing differences between
  // host runners and CI render the same pixel slightly differently
  // depending on font hinting; ``maxDiffPixelRatio`` lets a few-pixel
  // edge band slip through without flagging a real regression.
  // The threshold is intentionally tight (0.5%): bigger drift
  // typically means a real layout / palette change that should be
  // reviewed.
  expect: {
    toHaveScreenshot: {
      maxDiffPixelRatio: 0.005,
      animations: "disabled",
      caret: "hide",
    },
  },
});
