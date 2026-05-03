/**
 * TanStack Query client setup.
 *
 * Single instance per browser tab. Default retry policy is one
 * retry on transient failures, ZERO retries on auth errors so a
 * 401 redirects to /login immediately instead of spinning.
 *
 * Global 401 handler: when ANY query or mutation comes back 401,
 * the full client cache is cleared and the browser is sent to
 * ``/login``. Without this, the dashboard would keep rendering
 * the previous user's data after a session expiry / revoke,
 * because the per-route ``beforeLoad`` only runs on navigation.
 */
import { MutationCache, QueryCache, QueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ApiError } from "./api";

let redirectingToLogin = false;
// Throttle duplicate 403 toasts - a page that fires multiple queries
// in parallel against the same forbidden resource would otherwise
// stack the user with identical messages.
let last403At = 0;

function handleForbiddenError(error: unknown): void {
  if (!(error instanceof ApiError) || error.status !== 403) return;
  // Silent on mutations that have their own inline toast (the
  // mutation's ``onError`` wins) - here we only surface 403s from
  // background queries, which are otherwise invisible.
  const now = Date.now();
  if (now - last403At < 1500) return;
  last403At = now;
  // Use a static description (audit M3): server-supplied messages
  // can leak handler internals. The static copy is enough - 403s
  // rarely give actionable user-facing info anyway.
  toast.error("Permission denied", {
    description: "your role doesn't have access to that resource",
  });
}

function handleAuthError(error: unknown): void {
  handleForbiddenError(error);
  if (!(error instanceof ApiError) || error.status !== 401) return;
  // On the login page itself, 401 is expected (not logged in yet).
  // Don't redirect or clear - just ignore.
  if (
    typeof window !== "undefined" &&
    window.location.pathname.startsWith("/login")
  ) {
    return;
  }
  if (redirectingToLogin) return;
  redirectingToLogin = true;
  queryClient.clear();
  if (typeof window !== "undefined") {
    window.location.href = "/login";
  }
  // Reset the flag after a short delay so future 401s (e.g. in
  // another tab that navigated away from /login) are handled.
  setTimeout(() => {
    redirectingToLogin = false;
  }, 2000);
}

export const queryClient = new QueryClient({
  queryCache: new QueryCache({ onError: handleAuthError }),
  mutationCache: new MutationCache({ onError: handleAuthError }),
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      gcTime: 5 * 60_000,
      refetchOnWindowFocus: true,
      retry: (failureCount, error) => {
        if (error instanceof ApiError) {
          if (error.status === 401 || error.status === 403) {
            return false;
          }
          if (error.status >= 400 && error.status < 500) {
            return false;
          }
        }
        return failureCount < 2;
      },
    },
    mutations: {
      retry: false,
    },
  },
});
