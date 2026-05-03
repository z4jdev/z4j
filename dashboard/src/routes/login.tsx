import { useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { AlertCircle, Eye, EyeOff, Loader2 } from "lucide-react";
import { Z4jMark } from "@/components/z4j-mark";
import { ThemeToggle } from "@/components/layout/theme-toggle";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useLogin } from "@/hooks/use-auth";
import { api, ApiError } from "@/lib/api";
import type { SetupStatusResponse } from "@/lib/api-types";

export const Route = createFileRoute("/login")({
  // First-boot guard: if z4j has no admin yet, the login form
  // would just produce 401 invalid_credentials forever (there's no
  // user to authenticate). Hard-redirect to the inline /setup form
  // served by z4j instead. Mirrors the check on the `/` index
  // route - covers the case where the user navigates directly to
  // /login (bookmark, refresh after a prior session).
  beforeLoad: async () => {
    try {
      const status = await api.get<SetupStatusResponse>("/setup/status");
      if (status.first_boot && typeof window !== "undefined") {
        window.location.href = "/setup";
      }
    } catch (err) {
      if (!(err instanceof ApiError)) throw err;
    }
  },
  component: LoginPage,
});

/**
 * Map an ApiError from the login endpoint to an operator-facing
 * message pair (title + description). z4j's auth service
 * returns distinct error codes for the three login-failure modes
 * (bad creds, locked out, inactive user); generic networking /
 * server errors fall through to a safe default.
 *
 * Kept verbose so the user can tell "wrong password" (try again)
 * from "locked out" (wait) from "account disabled" (contact admin)
 * without having to decode status codes.
 */
function describeLoginError(err: unknown): { title: string; description: string } {
  if (err instanceof ApiError) {
    // Rate-limit / lockout - 429 on z4j when login attempts
    // exceed the configured per-identity / per-IP ceiling.
    if (err.status === 429) {
      return {
        title: "Too many login attempts",
        description:
          "The account is temporarily locked. Wait a few minutes and try again.",
      };
    }
    // 403 on this endpoint means the user row exists but is_active
    // is false - "account disabled", not "wrong password".
    if (err.status === 403) {
      return {
        title: "Account disabled",
        description:
          "Your account has been disabled. Ask a z4j admin to re-enable it.",
      };
    }
    if (err.status === 401) {
      return {
        title: "Invalid email or password",
        description: "Check the address, the capitalisation of the password, and try again.",
      };
    }
    if (err.status >= 500) {
      return {
        title: "Server error",
        description:
          "z4j returned a server error. Check the server logs or try again in a moment.",
      };
    }
  }
  return {
    title: "Could not sign in",
    description:
      err instanceof Error
        ? err.message
        : "An unexpected error occurred. Try again.",
  };
}

// Demo build (VITE_Z4J_DEMO_MODE=true) pre-fills the login form so a
// demo visitor only has to click Sign in to land on the dashboard.
// In production these stay empty strings so the form renders blank.
const IS_DEMO = import.meta.env.VITE_Z4J_DEMO_MODE === "true";
const DEMO_EMAIL = "demo@example.com";
const DEMO_PASSWORD = "demo";

function LoginPage() {
  const navigate = useNavigate();
  const login = useLogin();
  const [email, setEmail] = useState(IS_DEMO ? DEMO_EMAIL : "");
  const [password, setPassword] = useState(IS_DEMO ? DEMO_PASSWORD : "");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<{
    title: string;
    description: string;
  } | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    // Clear any stale error from a previous failed attempt so a
    // half-visible red block doesn't persist while the spinner is
    // running.
    setError(null);
    try {
      await login.mutateAsync({ email, password });
      toast.success("welcome back");
      navigate({ to: "/" });
    } catch (err) {
      setError(describeLoginError(err));
    }
  }

  return (
    <div className="relative grid min-h-screen w-full place-items-center bg-background p-6">
      <div className="absolute right-4 top-4">
        <ThemeToggle />
      </div>
      <div className="w-full max-w-sm space-y-6">
        <div className="flex items-center justify-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-lg shadow-primary/20">
            <Z4jMark className="size-6" />
          </div>
          <div>
            <h1 className="text-xl font-semibold leading-none">z4j</h1>
            <p className="text-xs text-muted-foreground">control plane</p>
          </div>
        </div>

        <Card className="border-border/60 shadow-xl shadow-black/5">
          <CardHeader className="pb-4">
            <CardTitle>Sign in</CardTitle>
            <CardDescription>
              Use your dashboard credentials to access the control plane.
            </CardDescription>
          </CardHeader>
          <form onSubmit={onSubmit}>
            <CardContent className="space-y-4">
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
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  autoComplete="email"
                  required
                  value={email}
                  onChange={(e) => {
                    setEmail(e.target.value);
                    // Editing either field is an implicit "I know,
                    // I'm trying again" - drop the stale banner so
                    // the form looks clean while the user re-types.
                    if (error) setError(null);
                  }}
                  placeholder="you@example.com"
                  aria-invalid={error ? true : undefined}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    autoComplete="current-password"
                    required
                    value={password}
                    onChange={(e) => {
                      setPassword(e.target.value);
                      if (error) setError(null);
                    }}
                    placeholder="enter your password"
                    className="pr-10"
                    aria-invalid={error ? true : undefined}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground transition-colors hover:text-foreground"
                    aria-label={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? (
                      <EyeOff className="size-4" />
                    ) : (
                      <Eye className="size-4" />
                    )}
                  </button>
                </div>
              </div>
            </CardContent>
            <CardFooter className="pt-2">
              <Button type="submit" className="w-full" disabled={login.isPending}>
                {login.isPending && (
                  <Loader2 className="size-4 animate-spin" />
                )}
                Sign in
              </Button>
            </CardFooter>
          </form>
        </Card>

        {IS_DEMO && (
          <div
            role="note"
            className="rounded-lg border border-yellow-300/60 bg-yellow-50 px-4 py-3 text-xs leading-relaxed text-yellow-950 dark:border-yellow-400/40 dark:bg-yellow-400/10 dark:text-yellow-100"
          >
            <p>
              <strong className="font-semibold">DEMO MODE</strong> -- credentials
              are pre-filled (
              <code className="rounded bg-yellow-200/60 px-1 font-mono dark:bg-yellow-400/20">
                demo@example.com
              </code>{" "}
              /{" "}
              <code className="rounded bg-yellow-200/60 px-1 font-mono dark:bg-yellow-400/20">
                demo
              </code>
              ). Click Sign in to continue. No real account, no real services.{" "}
              <a
                href="https://z4j.com/install/"
                target="_blank"
                rel="noopener"
                className="font-semibold underline decoration-1 underline-offset-2 hover:decoration-2"
              >
                Install z4j for real
              </a>
              .
            </p>
          </div>
        )}

      </div>
    </div>
  );
}
