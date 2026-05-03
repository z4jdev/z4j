/**
 * api.demo.ts -- in-browser mock-fetch interceptor for demo.z4j.dev.
 *
 * Loaded ONLY when the SPA was built with VITE_Z4J_DEMO_MODE=true
 * (see scripts/build-demo.mjs and the conditional import in api.ts).
 * In production builds this file's bytes are tree-shaken away by the
 * `if (import.meta.env.VITE_Z4J_DEMO_MODE)` gate around the import.
 *
 * Architecture per DEMO-Z4J-DEV-DESIGN.md:
 *
 * 1. Read-side endpoints (GETs) are matched against `ROUTES` and
 *    served from pre-baked JSON files under /demo-data/ (relative
 *    to the SPA bundle, so they go through Cloudflare Pages' static
 *    asset cache).
 * 2. Login + logout are intercepted as one-off "successful mutations"
 *    so the auth-state hook flips to logged-in and the router
 *    navigates to the dashboard. Every other mutation (POST / PATCH /
 *    PUT / DELETE) fires the `demo:blocked-mutation` event, which a
 *    DemoBanner listener turns into a user-visible toast.
 * 3. Unknown GETs return a 404 envelope so the dashboard surfaces an
 *    empty state rather than breaking. This is intentional during
 *    MVP rollout: as more endpoints get seed data, fewer 404s are
 *    surfaced. Eventually every dashboard-reachable endpoint is
 *    backed by a real route here.
 *
 * Adding a new route:
 *   1. Drop a JSON file at src/lib/demo-data/<path>.json
 *   2. Add a row to ROUTES below
 *   3. Run `pnpm build:demo && pnpm preview:demo` to verify
 *
 * Adding seed data shapes:
 *   The JSON shapes must match the OpenAPI types under
 *   src/lib/openapi-types.gen.ts. If the dashboard's TypeScript
 *   complains at build time, the seed data is wrong; fix the JSON.
 */

import { applyDemoTimestamps } from "./demo-timestamps";

// ---------------------------------------------------------------------------
// Route table
// ---------------------------------------------------------------------------

interface RouteHandler {
  method: string;
  pattern: RegExp;
  handler: (
    request: Request,
    match: RegExpMatchArray,
  ) => Promise<Response> | Response;
}

/**
 * Resolve a JSON file under /demo-data/ relative to the SPA bundle's
 * root. Returns 200 with the parsed-and-timestamped body or 404 if
 * the file is missing.
 */
function serveJson(file: string) {
  return async (): Promise<Response> => {
    const response = await fetch(`/demo-data/${file}`, {
      // No credentials for static asset fetches - they go through
      // the same origin but to Cloudflare Pages' static-asset path,
      // not the API path. CSRF + cookie are not relevant.
      credentials: "omit",
    });
    if (!response.ok) {
      return new Response(
        JSON.stringify({
          error: "demo_data_missing",
          message: `No demo data file at /demo-data/${file}`,
        }),
        { status: 404, headers: { "content-type": "application/json" } },
      );
    }
    const data: unknown = await response.json();
    return new Response(JSON.stringify(applyDemoTimestamps(data)), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
}

/**
 * Login intercept. Accepts ANY input and returns success because
 * the form is pre-filled with `demo@example.com / demo`, but a
 * curious visitor might edit the values; the friendliest UX is to
 * succeed regardless and route them to the dashboard.
 */
async function handleLogin(request: Request): Promise<Response> {
  let body: { email?: string } = {};
  try {
    body = (await request.clone().json()) as { email?: string };
  } catch {
    // Empty / non-JSON body is also fine.
  }
  const email = body.email || "demo@example.com";
  return new Response(
    JSON.stringify({
      user: {
        id: "00000000-0000-4000-8000-000000000001",
        email,
        display_name: "Demo Admin",
        is_admin: true,
        is_active: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    }),
    {
      status: 200,
      headers: { "content-type": "application/json" },
    },
  );
}

/**
 * Logout intercept. The SPA clears its in-memory auth state on a
 * 200 response; nothing else to do.
 */
function handleLogout(): Response {
  return new Response(null, { status: 204 });
}

const ROUTES: RouteHandler[] = [
  // Auth
  { method: "POST", pattern: /^\/api\/v1\/auth\/login$/, handler: handleLogin },
  { method: "POST", pattern: /^\/api\/v1\/auth\/logout$/, handler: handleLogout },
  { method: "GET", pattern: /^\/api\/v1\/auth\/me$/, handler: serveJson("auth/me.json") },

  // Server health pill in the topbar (refetches every 30s; if this
  // 404s the pill flips to "z4j offline" which makes the demo feel
  // half-broken).
  { method: "GET", pattern: /^\/api\/v1\/health$/, handler: serveJson("system/health.json") },

  // First-boot check used by /login's beforeLoad guard. The demo is
  // never first-boot (a "demo admin" exists), so always return false
  // to keep visitors on the login page rather than redirecting them
  // to the inline /setup form served by z4j (which we can also demo
  // separately).
  {
    method: "GET",
    pattern: /^\/api\/v1\/setup\/status$/,
    handler: () =>
      new Response(JSON.stringify({ first_boot: false }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  },

  // Home (landing dashboard for the global view)
  { method: "GET", pattern: /^\/api\/v1\/home\/summary$/, handler: serveJson("home/summary.json") },
  { method: "GET", pattern: /^\/api\/v1\/home\/recent-failures/, handler: serveJson("home/recent-failures.json") },

  // Projects (collection + per-project detail)
  { method: "GET", pattern: /^\/api\/v1\/projects$/, handler: serveJson("projects/index.json") },
  {
    method: "GET",
    pattern: /^\/api\/v1\/projects\/([^/]+)$/,
    handler: (_req, match) => serveJson(`projects/${match[1]}/detail.json`)(),
  },

  // Per-project lists. Each maps to a single JSON file per project.
  // Tasks endpoint accepts query params (status, page, etc.) but the
  // demo serves the same canned page regardless; the dashboard's
  // filter UI still renders, just not predictively.
  {
    method: "GET",
    pattern: /^\/api\/v1\/projects\/([^/]+)\/tasks/,
    handler: (_req, match) => serveJson(`projects/${match[1]}/tasks.json`)(),
  },
  {
    method: "GET",
    pattern: /^\/api\/v1\/projects\/([^/]+)\/schedules/,
    handler: (_req, match) => serveJson(`projects/${match[1]}/schedules.json`)(),
  },
  {
    method: "GET",
    pattern: /^\/api\/v1\/projects\/([^/]+)\/agents/,
    handler: (_req, match) => serveJson(`projects/${match[1]}/agents.json`)(),
  },
  {
    method: "GET",
    pattern: /^\/api\/v1\/projects\/([^/]+)\/audit/,
    handler: (_req, match) => serveJson(`projects/${match[1]}/audit.json`)(),
  },
  {
    method: "GET",
    pattern: /^\/api\/v1\/projects\/([^/]+)\/events/,
    handler: (_req, match) => serveJson(`projects/${match[1]}/events.json`)(),
  },
  {
    method: "GET",
    pattern: /^\/api\/v1\/projects\/([^/]+)\/commands/,
    handler: (_req, match) => serveJson(`projects/${match[1]}/commands.json`)(),
  },
  {
    method: "GET",
    pattern: /^\/api\/v1\/projects\/([^/]+)\/queues/,
    handler: (_req, match) => serveJson(`projects/${match[1]}/queues.json`)(),
  },
  {
    method: "GET",
    pattern: /^\/api\/v1\/projects\/([^/]+)\/workers/,
    handler: (_req, match) => serveJson(`projects/${match[1]}/workers.json`)(),
  },
  // Project overview stats (the big card grid on /projects/<slug>/).
  // Query params (hours=24 etc.) are ignored; demo serves a fixed
  // snapshot per project regardless of the time-range selector.
  {
    method: "GET",
    pattern: /^\/api\/v1\/projects\/([^/]+)\/stats/,
    handler: (_req, match) => serveJson(`projects/${match[1]}/stats.json`)(),
  },
  // Trend buckets for the charts on the trends route. Query params
  // ignored; the dashboard re-renders against the same snapshot
  // when the user flips window / bucket size.
  {
    method: "GET",
    pattern: /^\/api\/v1\/projects\/([^/]+)\/trends/,
    handler: (_req, match) => serveJson(`projects/${match[1]}/trends.json`)(),
  },
  {
    method: "GET",
    pattern: /^\/api\/v1\/projects\/([^/]+)\/notifications\/channels/,
    handler: (_req, match) => serveJson(`projects/${match[1]}/notifications-channels.json`)(),
  },
  {
    method: "GET",
    pattern: /^\/api\/v1\/projects\/([^/]+)\/notifications\/deliveries/,
    handler: (_req, match) => serveJson(`projects/${match[1]}/notifications-deliveries.json`)(),
  },
  {
    method: "GET",
    pattern: /^\/api\/v1\/projects\/([^/]+)\/notifications\/defaults/,
    handler: (_req, match) => serveJson(`projects/${match[1]}/notifications-defaults.json`)(),
  },
  {
    method: "GET",
    pattern: /^\/api\/v1\/projects\/([^/]+)\/memberships/,
    handler: (_req, match) => serveJson(`projects/${match[1]}/memberships.json`)(),
  },
  {
    method: "GET",
    pattern: /^\/api\/v1\/projects\/([^/]+)\/invitations/,
    handler: (_req, match) => serveJson(`projects/${match[1]}/invitations.json`)(),
  },

  // User-scoped endpoints (settings)
  { method: "GET", pattern: /^\/api\/v1\/user\/channels/, handler: serveJson("user/channels.json") },
  { method: "GET", pattern: /^\/api\/v1\/user\/subscriptions/, handler: serveJson("user/subscriptions.json") },
  { method: "GET", pattern: /^\/api\/v1\/user\/deliveries/, handler: serveJson("user/deliveries.json") },
  { method: "GET", pattern: /^\/api\/v1\/user\/notifications\/unread-count/, handler: serveJson("user/notifications-unread-count.json") },
  { method: "GET", pattern: /^\/api\/v1\/user\/notifications/, handler: serveJson("user/notifications.json") },

  // Implicit-mutation no-ops: the dashboard fires these on small UI
  // interactions (mark-read, dismiss). Returning 200 with no body keeps
  // React Query happy without surfacing a demo-toast every click.
  {
    method: "POST",
    pattern: /^\/api\/v1\/user\/notifications\/[^/]+\/read$/,
    handler: () => new Response(null, { status: 204 }),
  },
  {
    method: "POST",
    pattern: /^\/api\/v1\/user\/notifications\/read-all$/,
    handler: () => new Response(null, { status: 204 }),
  },
];

// ---------------------------------------------------------------------------
// Mock fetch entry point
// ---------------------------------------------------------------------------

/**
 * Drop-in replacement for `fetch()`, installed at build-time when
 * VITE_Z4J_DEMO_MODE is true. Same signature as the global fetch so
 * the api.ts caller does not need a special case.
 */
export async function demoFetch(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  const url = typeof input === "string"
    ? input
    : input instanceof URL
      ? input.toString()
      : input.url;
  const path = url.replace(/^https?:\/\/[^/]+/, "");
  const method = (init?.method ?? "GET").toUpperCase();

  // /api/v1/* and /setup* go through the interceptor. /metrics, /ws,
  // and any /demo-data/* fetches go through real fetch (the dashboard
  // does not call /metrics or /ws from React Query, but defense in
  // depth never hurts).
  if (
    !path.startsWith("/api/v1") &&
    !path.startsWith("/setup")
  ) {
    return fetch(input, init);
  }

  for (const route of ROUTES) {
    if (route.method !== method) continue;
    const m = path.match(route.pattern);
    if (m) {
      // Construct a Request-like object so handlers that need to
      // read the body have one. URL might be a relative path; that
      // is fine for body-reading purposes.
      const req = new Request(
        url.startsWith("http") ? url : `http://demo.z4j.dev${url}`,
        init,
      );
      return route.handler(req, m);
    }
  }

  // Unhandled mutation -> demo toast.
  if (method !== "GET" && method !== "HEAD") {
    if (typeof window !== "undefined") {
      window.dispatchEvent(
        new CustomEvent("demo:blocked-mutation", {
          detail: { path, method },
        }),
      );
    }
    // Return a synthetic success so React Query does not flag it as
    // a failure (which would surface a red banner). The toast IS
    // the user-visible signal that this action did not really happen.
    return new Response(JSON.stringify({ ok: true, demo: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }

  // Unhandled GET -> 404 with a structured envelope. The dashboard
  // already handles 404s as empty states for collection endpoints.
  return new Response(
    JSON.stringify({
      error: "demo_route_not_implemented",
      message: `No demo data for ${method} ${path}`,
    }),
    {
      status: 404,
      headers: { "content-type": "application/json" },
    },
  );
}
