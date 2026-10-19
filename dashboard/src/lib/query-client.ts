/**
 * TanStack Query client setup.
 *
 * Single instance per browser tab. Default query retry policy is two
 * retries on transient failures, ZERO retries on auth errors so a
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
let redirectingToReverify = false;
// Throttle duplicate 403 toasts - a page that fires multiple queries
// in parallel against the same forbidden resource would otherwise
// stack the user with identical messages.
let last403At = 0;

function handleMfaReverifyRequired(error: unknown): boolean {
  // True iff the error was the sensitive-action MFA gate
  // (require_fresh_mfa). On match: clear the query cache so the
  // dashboard doesn't keep showing stale post-mutation state, then
  // redirect to /login/mfa carrying ``?next=<current path>`` so the
  // verify page can send the user back where they started. Without
  // the next param the user always lands on / after re-verifying,
  // loses any in-progress form context, and has to re-navigate
  // manually. (1.6.0 audit Medium-4 + UX session follow-up.)
  if (!(error instanceof ApiError)) return false;
  if (error.status !== 403) return false;
  if (error.code !== "mfa_reverify_required") return false;
  if (redirectingToReverify) return true;
  redirectingToReverify = true;
  toast.warning("Re-verify with MFA", {
    description:
      "this action requires a fresh MFA code; redirecting...",
  });
  queryClient.clear();
  if (typeof window !== "undefined") {
    // Capture pathname + search + hash so the verify page can take
    // the user back to exactly the URL they were on, query-string
    // and fragment included. Skip the capture when we are already
    // on /login/mfa to avoid a self-redirect loop on a flapping
    // gate.
    const here = window.location;
    const onMfaPage = here.pathname === "/login/mfa";
    const next = onMfaPage
      ? ""
      : `?next=${encodeURIComponent(
          here.pathname + here.search + here.hash,
        )}`;
    window.location.href = `/login/mfa${next}`;
  }
  setTimeout(() => {
    redirectingToReverify = false;
  }, 2000);
  return true;
}

function handleForbiddenError(error: unknown): void {
  if (!(error instanceof ApiError) || error.status !== 403) return;
  // MFA re-verify gate is a 403 too; route it before the generic
  // "Permission denied" toast.
  if (handleMfaReverifyRequired(error)) return;
  // Shared by query and mutation caches. Local mutation error handlers
  // also run; this throttle only deduplicates the global 403 toast.
  const now = Date.now();
  if (now - last403At < 1500) return;
  last403At = now;
  // Use static descriptions (audit M3): server-supplied messages
  // can leak handler internals. The stable error code says which
  // gate refused, so the copy can name it without echoing the body.
  if (error.code === "mfa_enrollment_required") {
    toast.error("Two-factor enrollment required", {
      description:
        "Enroll in two-factor authentication under Settings, Security to continue.",
    });
    return;
  }
  if (error.code === "ip_denied") {
    toast.error("Access denied from this network", {
      description: "This network address is not on the IP allowlist.",
    });
    return;
  }
  toast.error("Permission denied", {
    description:
      "Your role, project access or a security check does not allow this request.",
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
