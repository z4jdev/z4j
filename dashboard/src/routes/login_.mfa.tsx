/**
 * MFA second-step verification (login flow).
 *
 * Reached from /login when LoginResponse.mfa_required is true. The
 * session is already minted (server-side); this page just stamps
 * sessions.mfa_verified_at = NOW() so the sensitive-action gate
 * accepts the caller afterwards. If the user checks "Trust this
 * device for 30 days", the server mints a z4j_mfa_trust cookie and
 * future logins skip this step until the cookie expires.
 */
import { useState } from "react";
import { createFileRoute, useNavigate, redirect } from "@tanstack/react-router";
import { AlertCircle, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { ThemeToggle } from "@/components/layout/theme-toggle";
import { Z4jMark } from "@/components/z4j-mark";
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useMfaVerify } from "@/hooks/use-mfa";
import { api, ApiError } from "@/lib/api";

interface MfaSearch {
  /** Path the verify page should send the user back to after a
   * successful verify. Set by ``query-client.ts`` when the
   * sensitive-action gate fires mid-mutation so the user lands
   * back on the page they were already working in. Validated as
   * a same-origin relative path to keep this from being an open-
   * redirect vector. */
  next?: string;
}

export const Route = createFileRoute("/login_/mfa")({
  validateSearch: (raw: Record<string, unknown>): MfaSearch => {
    const next = raw.next;
    return typeof next === "string" && next.length > 0
      ? { next }
      : {};
  },
  // beforeLoad: bounce visitors who have no session to /login. A
  // direct-navigation visitor (bookmark, refresh, copy-pasted URL)
  // would otherwise see the verify form and get a 401 on submit,
  // which the audit flagged as confusing. (1.6.0 audit M6.)
  beforeLoad: async () => {
    try {
      await api.get("/auth/me");
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        throw redirect({ to: "/login" });
      }
      // Any other error: let the page render and surface it inline.
    }
  },
  component: MfaPage,
});

/** Whether ``raw`` is safe to navigate to after MFA verify.
 *
 * Same-origin only: must start with a single ``/`` (not ``//`` or
 * ``/\\`` which the browser interprets as a protocol-relative URL
 * pointing somewhere else). Anything that looks like an absolute
 * URL is rejected. The brain trusts the dashboard origin; an
 * attacker who could plant a phishing path in the ``next`` param
 * would otherwise turn the MFA gate into an open redirect.
 */
function isSafeNextPath(raw: string | undefined): raw is string {
  if (!raw) return false;
  if (!raw.startsWith("/")) return false;
  if (raw.startsWith("//") || raw.startsWith("/\\")) return false;
  return true;
}

function MfaPage() {
  const navigate = useNavigate();
  const search = Route.useSearch();
  const verify = useMfaVerify();
  const [code, setCode] = useState("");
  const [remember, setRemember] = useState(false);
  const [error, setError] = useState<{
    title: string;
    description: string;
  } | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const result = await verify.mutateAsync({
        code: code.trim(),
        remember_device: remember,
      });
      // The brain echoes ``used_recovery_code`` and the remaining
      // count when a recovery code (rather than a TOTP code) was
      // accepted. The user MUST notice they just burned a single-
      // use code so they go regenerate the set; a quiet "verified"
      // toast hides that and is exactly how someone gets locked
      // out next time their phone dies.
      if (result.used_recovery_code) {
        const remaining = result.remaining_recovery_codes ?? 0;
        toast.warning("Recovery code used", {
          description:
            `${remaining} recovery code${remaining === 1 ? "" : "s"} ` +
            `left. Regenerate the set in Settings -> Security ` +
            `whenever you can; each code only works once.`,
          duration: 8000,
        });
      } else {
        toast.success("verified");
      }
      // When the sensitive-action gate redirected us here mid-flow it
      // tacked ``?next=<original path>`` onto the URL. Send the user
      // back so they pick up where they left off; fall back to ``/``
      // for the normal login-second-step case where they were just
      // signing in fresh. ``window.location.href`` (not navigate())
      // because the source path may live behind a route that needs a
      // full reload of its query cache after the new mfa_verified_at
      // stamp.
      const dest = isSafeNextPath(search.next) ? search.next : "/";
      if (dest === "/") {
        navigate({ to: "/" });
      } else if (typeof window !== "undefined") {
        window.location.href = dest;
      }
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 429) {
          setError({
            title: "Too many attempts",
            description:
              "MFA verify is rate-limited per IP. Wait a minute and try again.",
          });
          return;
        }
        if (err.status === 401) {
          setError({
            title: "Invalid code",
            description:
              "Enter a fresh 6-digit code from your authenticator app, or a XXXX-XXXX-XXXX recovery code.",
          });
          return;
        }
      }
      setError({
        title: "Could not verify",
        description:
          err instanceof Error
            ? err.message
            : "An unexpected error occurred. Try again.",
      });
    }
  }

  return (
    <div className="relative grid min-h-screen w-full place-items-center bg-muted/30 p-6">
      <div className="absolute right-4 top-4">
        <ThemeToggle />
      </div>

      <div className="w-full max-w-sm space-y-8">
        {/* Brand mark above the card. Identical to /login + the
            authenticated sidebar so the user does not feel
            teleported between two different apps when the MFA
            second step kicks in. */}
        <div className="flex items-center justify-center gap-3">
          <div className="flex size-10 shrink-0 items-center justify-center rounded-md bg-primary text-primary-foreground shadow-sm">
            <Z4jMark className="size-6" />
          </div>
          <div className="flex min-w-0 flex-col leading-tight">
            <span className="text-sm font-semibold">z4j</span>
            <span className="text-xs text-muted-foreground">
              control plane
            </span>
          </div>
        </div>

        <div className="rounded-xl border border-border bg-card p-8 shadow-sm">
          <div className="mb-6 space-y-1.5">
            <h1 className="text-xl font-semibold tracking-tight">
              Two-factor verification
            </h1>
            <p className="text-sm text-muted-foreground">
              Enter the 6-digit code from your authenticator app, or a
              single-use recovery code.
            </p>
          </div>

          <form onSubmit={onSubmit} className="space-y-5">
            {error && (
              <Alert variant="destructive" role="alert" aria-live="polite">
                <AlertCircle />
                <AlertTitle>{error.title}</AlertTitle>
                <AlertDescription>
                  <p>{error.description}</p>
                </AlertDescription>
              </Alert>
            )}

            <div className="space-y-2">
              <Label htmlFor="mfa-code">Code</Label>
              <Input
                id="mfa-code"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                autoFocus
                required
                value={code}
                onChange={(e) => {
                  setCode(e.target.value);
                  if (error) setError(null);
                }}
                placeholder="123456 or AAAA-BBBB-CCCC"
                className="h-11"
              />
            </div>

            <div className="flex items-start gap-2">
              <Checkbox
                id="mfa-remember"
                checked={remember}
                onCheckedChange={(v) => setRemember(v === true)}
                className="mt-0.5"
              />
              <Label
                htmlFor="mfa-remember"
                className="text-sm font-normal leading-snug text-muted-foreground"
              >
                Skip the code at sign-in on this browser for 30 days.
                <span className="block text-xs">
                  Sensitive actions (change password, mint API key)
                  will still ask for a fresh code.
                </span>
              </Label>
            </div>

            <Button
              type="submit"
              className="mt-3 h-11 w-full text-sm font-medium"
              disabled={verify.isPending || code.length < 6}
            >
              {verify.isPending && (
                <Loader2 className="size-4 animate-spin" />
              )}
              Verify
            </Button>
          </form>
        </div>
      </div>
    </div>
  );
}
