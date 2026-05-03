/**
 * Crash-coverage E2E pass.
 *
 * Walks every authenticated dashboard route and asserts:
 *   1. The page returns 200 (no server error)
 *   2. The browser console reports zero `error`-level messages
 *   3. The page text never contains the patterns characteristic of
 *      the data-shape bugs that bit 1.2.0 in production:
 *        - "(e ?? []) is not iterable"
 *        - "is not a function"
 *        - "Cannot read properties of"
 *        - any "Application error" / React error-boundary banner
 *
 * This is the test that would have caught the live crashes on
 * tasks.jfk.work (subscriptions + schedules pages crashing because
 * the bundled SPA was stale relative to the cursor-walking hook
 * source) BEFORE we shipped 1.2.0.
 *
 * Add a route here every time the dashboard adds a new top-level
 * page. Keep it minimal: route + a brief description. The spec
 * itself iterates - no boilerplate per route.
 */
import { test, expect } from "./fixtures";
import type { Page, ConsoleMessage } from "@playwright/test";

// Routes to verify. Includes every primary authenticated page +
// the nested setting tabs + the previously-crashing pages from
// 1.2.0 (subscriptions, project schedules) explicitly.
const ROUTES: { path: string; needsProject: boolean; label: string }[] = [
  // Top-level personal pages
  { path: "/home", needsProject: false, label: "home" },
  { path: "/settings", needsProject: false, label: "settings" },
  { path: "/settings/profile", needsProject: false, label: "settings/profile" },
  { path: "/settings/sessions", needsProject: false, label: "settings/sessions" },
  { path: "/settings/projects", needsProject: false, label: "settings/projects" },
  { path: "/settings/users", needsProject: false, label: "settings/users" },
  { path: "/settings/api-keys", needsProject: false, label: "settings/api-keys" },
  // Personal notification hub - the BUG-1 page
  {
    path: "/settings/notifications",
    needsProject: false,
    label: "settings/notifications",
  },
  {
    path: "/settings/notifications/subscriptions",
    needsProject: false,
    label: "settings/notifications/subscriptions (BUG-1)",
  },
  {
    path: "/settings/notifications/channels",
    needsProject: false,
    label: "settings/notifications/channels",
  },
  {
    path: "/settings/notifications/deliveries",
    needsProject: false,
    label: "settings/notifications/deliveries",
  },
  // Project-scoped pages (requires a project to exist; we create one)
  {
    path: "/projects/{slug}",
    needsProject: true,
    label: "projects/{slug}",
  },
  {
    path: "/projects/{slug}/tasks",
    needsProject: true,
    label: "projects/{slug}/tasks",
  },
  {
    path: "/projects/{slug}/workers",
    needsProject: true,
    label: "projects/{slug}/workers",
  },
  {
    path: "/projects/{slug}/agents",
    needsProject: true,
    label: "projects/{slug}/agents",
  },
  {
    path: "/projects/{slug}/queues",
    needsProject: true,
    label: "projects/{slug}/queues",
  },
  {
    path: "/projects/{slug}/schedules",
    needsProject: true,
    label: "projects/{slug}/schedules (BUG-2)",
  },
  {
    path: "/projects/{slug}/commands",
    needsProject: true,
    label: "projects/{slug}/commands",
  },
  {
    path: "/projects/{slug}/audit",
    needsProject: true,
    label: "projects/{slug}/audit",
  },
  {
    path: "/projects/{slug}/settings",
    needsProject: true,
    label: "projects/{slug}/settings",
  },
  {
    path: "/projects/{slug}/settings/notifications/channels",
    needsProject: true,
    label: "projects/{slug}/settings/notifications/channels",
  },
  {
    path: "/projects/{slug}/settings/notifications/subscriptions",
    needsProject: true,
    label: "projects/{slug}/settings/notifications/subscriptions",
  },
  {
    path: "/projects/{slug}/settings/notifications/deliveries",
    needsProject: true,
    label: "projects/{slug}/settings/notifications/deliveries",
  },
];

const CRASH_PATTERNS = [
  /is not iterable/i,
  /is not a function/i,
  /Cannot read prop/i,
  /Cannot read properties of/i,
  /Application error/i,
  /Something went wrong/i,
  /Unexpected token/i,
  /TypeError:/i,
];

interface RouteFinding {
  label: string;
  status: "PASS" | "FAIL";
  consoleErrors: string[];
  textCrashes: string[];
}

async function visitRoute(
  page: Page,
  url: string,
): Promise<{ consoleErrors: string[]; textCrashes: string[] }> {
  const consoleErrors: string[] = [];
  const consoleHandler = (msg: ConsoleMessage): void => {
    if (msg.type() === "error") {
      const text = msg.text();
      // Filter known-benign noise: react-query devtools warnings,
      // CORS preflight noise, etc. Keep narrow - we want to fail
      // loudly on real errors.
      if (text.includes("Failed to load resource")) return;
      if (text.includes("DevTools")) return;
      consoleErrors.push(text);
    }
  };
  page.on("console", consoleHandler);

  const pageErrors: string[] = [];
  const errorHandler = (err: Error): void => {
    pageErrors.push(`${err.name}: ${err.message}`);
  };
  page.on("pageerror", errorHandler);

  await page.goto(url, { waitUntil: "domcontentloaded" });
  // Give React a beat to render + any data fetch to fire.
  await page.waitForTimeout(2000);

  page.off("console", consoleHandler);
  page.off("pageerror", errorHandler);

  const bodyText = (await page.textContent("body")) ?? "";
  const textCrashes: string[] = [];
  for (const pattern of CRASH_PATTERNS) {
    const match = bodyText.match(pattern);
    if (match) textCrashes.push(match[0]);
  }

  // Page errors are always crashes
  return {
    consoleErrors: [...consoleErrors, ...pageErrors],
    textCrashes,
  };
}

test.describe("crash-coverage", () => {
  // Reused across the iteration so we only create the project once.
  let slug: string | null = null;

  test.beforeAll(async () => {
    slug = `e2e-crash-${Math.random().toString(36).slice(2, 8)}`;
  });

  // 22 routes * ~3s each = ~70s, plus auth + project create.
  // Bump test timeout to 3 minutes to give comfortable headroom.
  test.setTimeout(180_000);

  test("no JavaScript crashes on any authenticated page", async ({
    adminPage,
    api,
  }) => {
    // Create one test project so the project-scoped routes have
    // a slug to navigate to. Also creates a project membership so
    // the auth checks pass.
    if (slug) {
      await api.post("/projects", {
        slug,
        name: `E2E Crash Coverage ${slug}`,
        environment: "development",
      });
    }

    const findings: RouteFinding[] = [];

    for (const route of ROUTES) {
      const url = route.needsProject
        ? route.path.replace("{slug}", slug ?? "")
        : route.path;
      const result = await visitRoute(adminPage, url);
      const finding: RouteFinding = {
        label: route.label,
        status:
          result.consoleErrors.length > 0 || result.textCrashes.length > 0
            ? "FAIL"
            : "PASS",
        consoleErrors: result.consoleErrors,
        textCrashes: result.textCrashes,
      };
      findings.push(finding);
    }

    // Print summary even on success so the audit trail exists.
    // eslint-disable-next-line no-console
    console.log("\n=== crash-coverage findings ===");
    for (const f of findings) {
      const tag = f.status === "PASS" ? "[OK]  " : "[FAIL]";
      // eslint-disable-next-line no-console
      console.log(`  ${tag} ${f.label}`);
      for (const err of f.consoleErrors)
        // eslint-disable-next-line no-console
        console.log(`         console: ${err.slice(0, 200)}`);
      for (const crash of f.textCrashes)
        // eslint-disable-next-line no-console
        console.log(`         text-crash: ${crash}`);
    }

    const failed = findings.filter((f) => f.status === "FAIL");
    expect(
      failed,
      `${failed.length} routes had crashes. See findings above.`,
    ).toHaveLength(0);
  });
});
