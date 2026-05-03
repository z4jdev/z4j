/**
 * Visual-regression baseline for the dashboard's most-viewed pages.
 *
 * Every page below is one a real operator visits multiple times a
 * day. A Tailwind upgrade, a shadcn bump, or a "tiny CSS tweak"
 * that re-skins the wrong primitive shows up here as a diff in
 * the next CI run.
 *
 * How baselines work:
 *
 *   1. First run on a new branch generates the snapshots under
 *      ``tests/e2e/visual-regression.spec.ts-snapshots/``.
 *      Commit them.
 *   2. Subsequent runs compare the live page to the committed
 *      snapshot; any diff above ``maxDiffPixelRatio: 0.005``
 *      (configured in playwright.config.ts) fails the job.
 *   3. Intentional UI change → run ``pnpm test:e2e -- --update-
 *      snapshots`` locally, commit the new snapshot, push.
 *
 * Anti-flake hygiene:
 *
 * - Playwright config disables animations + caret blink globally.
 * - We mask elements that are inherently dynamic (timestamps,
 *   uptime counters) so they don't trigger spurious diffs.
 * - We wait for ``networkidle`` so async-loaded data is on screen
 *   before the snapshot.
 *
 * Pages covered (the five most-viewed in operator usage):
 *
 *   1. Home dashboard
 *   2. Tasks list
 *   3. Workers list
 *   4. Audit log
 *   5. Settings → Users
 */
import { expect } from "@playwright/test";
import { test } from "./fixtures";

const TIMESTAMP_MASK = [
  // The DateCell component renders relative timestamps (5 min
  // ago, 2 hours ago) - intrinsically dynamic, would diff every
  // run. Mask anything inside [data-testid="datecell"] OR with
  // the explicit "tabular-nums" class which we use for live
  // counters.
  "[data-testid='datecell']",
  ".tabular-nums",
];

async function maskTimestamps(page: import("@playwright/test").Page) {
  return TIMESTAMP_MASK.map((sel) => page.locator(sel));
}

test.describe("Visual regression - high-traffic pages", () => {
  test("Home dashboard", async ({ adminPage }) => {
    await adminPage.goto("/");
    await adminPage.waitForLoadState("networkidle");
    await expect(adminPage).toHaveScreenshot("home.png", {
      fullPage: true,
      mask: await maskTimestamps(adminPage),
    });
  });

  test("Tasks list", async ({ adminPage }) => {
    await adminPage.goto("/projects/default/tasks");
    await adminPage.waitForLoadState("networkidle");
    await expect(adminPage).toHaveScreenshot("tasks.png", {
      fullPage: true,
      mask: await maskTimestamps(adminPage),
    });
  });

  test("Workers list", async ({ adminPage }) => {
    await adminPage.goto("/projects/default/workers");
    await adminPage.waitForLoadState("networkidle");
    await expect(adminPage).toHaveScreenshot("workers.png", {
      fullPage: true,
      mask: await maskTimestamps(adminPage),
    });
  });

  test("Audit log", async ({ adminPage }) => {
    await adminPage.goto("/projects/default/audit");
    await adminPage.waitForLoadState("networkidle");
    await expect(adminPage).toHaveScreenshot("audit.png", {
      fullPage: true,
      mask: await maskTimestamps(adminPage),
    });
  });

  test("Settings - Users", async ({ adminPage }) => {
    await adminPage.goto("/settings/users");
    await adminPage.waitForLoadState("networkidle");
    await expect(adminPage).toHaveScreenshot("settings-users.png", {
      fullPage: true,
      mask: await maskTimestamps(adminPage),
    });
  });
});
