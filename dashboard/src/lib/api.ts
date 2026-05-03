/**
 * Brain REST client.
 *
 * Wraps `fetch` with:
 *
 * 1. **Same-origin credentials** so the session cookie travels.
 * 2. **CSRF echo** - reads the `__Host-z4j_csrf` (or `z4j_csrf` in
 *    dev) cookie and sends it back as the `X-CSRF-Token` header
 *    on every state-changing request, matching z4j's
 *    double-submit pattern from B3.
 * 3. **Typed JSON parse** - successful responses are parsed and
 *    returned typed; failures throw a typed `ApiError`.
 *
 * Every dashboard hook in `src/hooks/*` calls through this
 * module - there is no raw `fetch` anywhere else.
 */
import type { ErrorEnvelope } from "./api-types";

const API_BASE = "/api/v1";

const CSRF_COOKIE_NAMES = ["__Host-z4j_csrf", "z4j_csrf"];
const CSRF_HEADER = "X-CSRF-Token";

/**
 * Typed error thrown by the api client on any non-2xx response.
 *
 * Carries z4j's structured error envelope so callers can
 * branch on `code` (e.g. show a 401 → redirect to /login, show
 * a 422 → render field-level validation messages).
 */
export class ApiError extends Error {
  status: number;
  code: string;
  details: Record<string, unknown>;
  requestId: string | null;

  constructor(
    status: number,
    envelope: ErrorEnvelope | { message?: string },
  ) {
    super(envelope.message ?? `request failed (${status})`);
    this.name = "ApiError";
    this.status = status;
    if ("error" in envelope) {
      this.code = envelope.error;
      this.details = envelope.details ?? {};
      this.requestId = envelope.request_id ?? null;
    } else {
      this.code = "unknown";
      this.details = {};
      this.requestId = null;
    }
  }
}

function getCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const value = document.cookie
    .split("; ")
    .find((row) => row.startsWith(`${name}=`));
  if (!value) return null;
  try {
    return decodeURIComponent(value.split("=")[1] ?? "");
  } catch {
    return null;
  }
}

function getCsrfToken(): string | null {
  for (const name of CSRF_COOKIE_NAMES) {
    const value = getCookie(name);
    if (value) return value;
  }
  return null;
}

interface ApiCallOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE" | "PUT";
  body?: unknown;
  signal?: AbortSignal;
  query?: Record<string, string | number | boolean | null | undefined>;
  /**
   * Internal flag - set automatically when we are inside a single
   * CSRF-rotation retry. Callers must never set this themselves.
   */
  _csrfRetried?: boolean;
}

/**
 * Make a typed call to z4j REST API.
 *
 * Throws `ApiError` on any non-2xx response. The caller is
 * expected to catch and translate to a UI message.
 *
 * **CSRF rotation** - z4j rotates the CSRF cookie on a
 * handful of identity events (password change, session re-bind).
 * In a long-lived dashboard tab the cookie value the client read
 * at request-build time can briefly disagree with the server's
 * expectation. Rather than surface a confusing 403 to the user
 * for a transient mismatch, we transparently retry exactly once
 * after re-reading `document.cookie`. The retry is identified
 * via the `_csrfRetried` flag so a *real* CSRF failure (stale
 * cookie that genuinely won't refresh) still bubbles up.
 */
export async function apiCall<T>(
  path: string,
  options: ApiCallOptions = {},
): Promise<T> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = {
    Accept: "application/json",
  };

  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  // CSRF for state-changing methods.
  if (method !== "GET") {
    const csrf = getCsrfToken();
    if (csrf) {
      headers[CSRF_HEADER] = csrf;
    }
  }

  let url = buildRequestUrl(path);

  if (options.query) {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(options.query)) {
      if (value === undefined || value === null || value === "") continue;
      params.append(key, String(value));
    }
    const qs = params.toString();
    if (qs) {
      url += `?${qs}`;
    }
  }

  let response: Response;
  try {
    response = await fetch(url, {
      method,
      headers,
      credentials: "include",
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
      signal: options.signal,
    });
  } catch (err) {
    // Network errors: no internet, DNS failure, CORS blocked, aborted.
    throw new ApiError(0, {
      error: "network_error",
      message:
        err instanceof Error ? err.message : "Network request failed",
    });
  }

  // 204 No Content path - no body to parse.
  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  let parsed: unknown = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      // Non-JSON body - pass through as a generic error message.
      if (!response.ok) {
        throw new ApiError(response.status, {
          message: text.slice(0, 500),
        });
      }
      return undefined as T;
    }
  }

  if (!response.ok) {
    const envelope = (parsed ?? { message: response.statusText }) as
      | ErrorEnvelope
      | { message?: string };
    if (
      response.status === 403 &&
      method !== "GET" &&
      !options._csrfRetried &&
      "error" in envelope &&
      (envelope.details?.reason === "csrf_mismatch" ||
        envelope.error === "csrf_mismatch")
    ) {
      // Cookie rotated under us. Re-read document.cookie and retry
      // exactly once. We deliberately do not pre-warm with /auth/me:
      // the browser already attaches the latest Set-Cookie value to
      // the very next fetch, so simply retrying picks it up.
      return apiCall<T>(path, { ...options, _csrfRetried: true });
    }
    throw new ApiError(response.status, envelope as ErrorEnvelope);
  }

  return parsed as T;
}

// ---------------------------------------------------------------------------
// Convenience verb shortcuts
// ---------------------------------------------------------------------------

export const api = {
  get<T>(path: string, query?: ApiCallOptions["query"]): Promise<T> {
    return apiCall<T>(path, { method: "GET", query });
  },
  post<T>(path: string, body?: unknown): Promise<T> {
    return apiCall<T>(path, { method: "POST", body });
  },
  patch<T>(path: string, body?: unknown): Promise<T> {
    return apiCall<T>(path, { method: "PATCH", body });
  },
  put<T>(path: string, body?: unknown): Promise<T> {
    return apiCall<T>(path, { method: "PUT", body });
  },
  delete<T>(path: string): Promise<T> {
    return apiCall<T>(path, { method: "DELETE" });
  },
};

function buildRequestUrl(path: string): string {
  if (/^https?:\/\//i.test(path)) {
    if (typeof window === "undefined") {
      throw new Error("absolute API URLs require a browser origin");
    }
    const url = new URL(path);
    if (url.origin !== window.location.origin) {
      throw new Error("refusing cross-origin API request");
    }
    return `${url.pathname}${url.search}${url.hash}`;
  }
  return `${API_BASE}${path.startsWith("/") ? path : `/${path}`}`;
}
