/**
 * Playwright test fixtures for the z4j E2E spine.
 *
 * Provides:
 *
 * - `adminPage`  - a Page already authenticated as the bootstrap
 *                  admin. Handles login + CSRF header priming so
 *                  individual tests stay focused on the behaviour
 *                  they're exercising, not the auth rigmarole.
 * - `api`        - a lightweight fetch wrapper bound to the same
 *                  cookies the browser holds, for endpoints that
 *                  the UI doesn't expose directly (minting tokens,
 *                  seeding fixtures, etc.).
 *
 * Environment contract (set by CI or `make e2e`):
 *
 *   Z4J_E2E_BASE_URL    defaults to http://localhost:7701
 *   Z4J_E2E_ADMIN_EMAIL defaults to e2e@example.com
 *   Z4J_E2E_ADMIN_PW    defaults to e2e-admin-pw-2026!
 */
import { test as base, expect, type Page } from "@playwright/test";

export const ADMIN_EMAIL =
  process.env.Z4J_E2E_ADMIN_EMAIL ?? "e2e@example.com";
export const ADMIN_PASSWORD =
  process.env.Z4J_E2E_ADMIN_PW ?? "e2e-admin-pw-2026!";

interface ApiClient {
  get<T = unknown>(path: string): Promise<T>;
  post<T = unknown>(path: string, body?: unknown): Promise<T>;
  patch<T = unknown>(path: string, body?: unknown): Promise<T>;
  delete<T = unknown>(path: string): Promise<T>;
}

function apiFactory(page: Page): ApiClient {
  const base = async <T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> => {
    // The browser context already has the session cookie. Use
    // page.request so CSRF + cookie handling stays native.
    const csrfCookie = (await page.context().cookies())
      .find((c) => c.name === "z4j_csrf")
      ?.value;
    const response = await page.request.fetch(`/api/v1${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        ...(csrfCookie ? { "X-CSRF-Token": csrfCookie } : {}),
      },
      data: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (!response.ok()) {
      const text = await response.text();
      throw new Error(
        `API ${method} ${path} failed: ${response.status()} ${text}`,
      );
    }
    const raw = await response.text();
    return (raw ? JSON.parse(raw) : (undefined as T)) as T;
  };
  return {
    get: (p) => base("GET", p),
    post: (p, b) => base("POST", p, b),
    patch: (p, b) => base("PATCH", p, b),
    delete: (p) => base("DELETE", p),
  };
}

export const test = base.extend<{
  adminPage: Page;
  api: ApiClient;
}>({
  adminPage: async ({ page }, use) => {
    // Login via the UI so we exercise the login form too. Keeps
    // the fixture honest: if the login form breaks, every test
    // fails at the fixture stage, which is a loud, early signal.
    await page.goto("/login");
    await page.getByLabel(/email/i).fill(ADMIN_EMAIL);
    // Be specific: the login form has a "Show password" toggle
    // button whose aria-label also matches /password/i, so the
    // looser ``getByLabel`` matcher trips strict-mode and fails
    // every E2E test. Anchor on the textbox role.
    await page
      .getByRole("textbox", { name: /password/i })
      .fill(ADMIN_PASSWORD);
    await page.getByRole("button", { name: /sign in/i }).click();
    // Post-login the router lands somewhere authenticated - either
    // /home (multi-project) or /projects/{slug} (single-project).
    // Either satisfies us.
    await expect(page).toHaveURL(/\/(home|projects\/)/, { timeout: 10_000 });
    await use(page);
  },

  api: async ({ page }, use) => {
    await use(apiFactory(page));
  },
});

export { expect };
