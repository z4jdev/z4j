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
import {
  test as base,
  expect,
  type Page,
  type APIRequestContext,
} from "@playwright/test";

export const ADMIN_EMAIL = process.env.Z4J_E2E_ADMIN_EMAIL ?? "e2e@example.com";
export const ADMIN_PASSWORD =
  process.env.Z4J_E2E_ADMIN_PW ?? "e2e-admin-pw-2026!";

interface ApiClient {
  get<T = unknown>(path: string): Promise<T>;
  post<T = unknown>(path: string, body?: unknown): Promise<T>;
  patch<T = unknown>(path: string, body?: unknown): Promise<T>;
  delete<T = unknown>(path: string): Promise<T>;
  /**
   * Raw request that returns the APIResponse (for status-code assertions
   * on expected failures like 204 / 409). Carries the session cookie +
   * CSRF by default; pass ``noCookie: true`` for bearer-only requests.
   */
  raw(
    method: string,
    path: string,
    opts?: {
      body?: unknown;
      headers?: Record<string, string>;
      noCookie?: boolean;
    },
  ): Promise<import("@playwright/test").APIResponse>;
}

async function authHeaders(page: Page): Promise<Record<string, string>> {
  // page.request does NOT reliably attach the browser context's session
  // cookie to a relative-URL fetch (the HttpOnly z4j_session set through
  // the dev-server proxy), which 401'd every mutating request. Build the
  // Cookie header explicitly from context().cookies() (which DOES see
  // HttpOnly cookies) and echo the CSRF token the double-submit check
  // wants. This is the reliable, native-cookie-independent path.
  const cookies = await page.context().cookies();
  const cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join("; ");
  // Dev uses the unprefixed cookie; production hardens it with ``__Host-``.
  // Accept both so this same spine can verify the released production image.
  const csrf = cookies.find((c) =>
    ["__Host-z4j_csrf", "z4j_csrf"].includes(c.name),
  )?.value;
  return {
    ...(cookieHeader ? { Cookie: cookieHeader } : {}),
    ...(csrf ? { "X-CSRF-Token": csrf } : {}),
  };
}

function apiFactory(page: Page, bearerRequest: APIRequestContext): ApiClient {
  const raw = async (
    method: string,
    path: string,
    opts: {
      body?: unknown;
      headers?: Record<string, string>;
      noCookie?: boolean;
    } = {},
  ) => {
    const auth = opts.noCookie ? {} : await authHeaders(page);
    // page.request shares the browser's cookie jar even when Cookie is omitted.
    // The separate request fixture keeps bearer-only checks truly session-free.
    const client = opts.noCookie ? bearerRequest : page.request;
    return client.fetch(`/api/v1${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        ...auth,
        ...(opts.headers ?? {}),
      },
      data: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
  };
  const base = async <T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> => {
    const response = await raw(method, path, { body });
    if (!response.ok()) {
      const text = await response.text();
      throw new Error(
        `API ${method} ${path} failed: ${response.status()} ${text}`,
      );
    }
    const text = await response.text();
    return (text ? JSON.parse(text) : (undefined as T)) as T;
  };
  return {
    get: (p) => base("GET", p),
    post: (p, b) => base("POST", p, b),
    patch: (p, b) => base("PATCH", p, b),
    delete: (p) => base("DELETE", p),
    raw,
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
    await page.getByRole("textbox", { name: /password/i }).fill(ADMIN_PASSWORD);
    await page.getByRole("button", { name: /sign in/i }).click();
    // Post-login the router lands somewhere authenticated - either
    // /home (multi-project) or /projects/{slug} (single-project).
    // Either satisfies us.
    await expect(page).toHaveURL(/\/(home|projects\/)/, { timeout: 10_000 });
    await use(page);
  },

  // Depend on ``adminPage`` (not the bare ``page``) so requesting ``api``
  // always runs the login first -- otherwise a test that asks for ``api``
  // but not ``adminPage`` would issue requests from an unauthenticated
  // page and every mutation would 401 on the CSRF/auth check.
  api: async ({ adminPage, request }, use) => {
    await use(apiFactory(adminPage, request));
  },
});

export { expect };
