/**
 * Public password-reset confirmation page.
 *
 * The brain emails `/reset#token=...`. The fragment is deliberately consumed
 * once into component memory, then both fragment and unsupported query data
 * are removed with `replaceState` before the user can interact with the form.
 * The token is never put into router search state, storage, rendered text, or
 * a log message.
 */
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  AlertCircle,
  CheckCircle2,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  LogIn,
} from "lucide-react";
import { useLayoutEffect, useState } from "react";

import { ThemeToggle } from "@/components/layout/theme-toggle";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Z4jMark } from "@/components/z4j-mark";
import {
  PASSWORD_POLICY_FALLBACK,
  type PasswordPolicy,
  usePasswordPolicy,
  usePasswordResetConfirm,
} from "@/hooks/use-auth";
import { ApiError } from "@/lib/api";

export const Route = createFileRoute("/reset")({
  component: PasswordResetPage,
});

const RESET_TOKEN_RE = /^#token=([A-Za-z0-9_-]{43})$/;
const MAX_PASSWORD_LENGTH = 256;
const COMPOSITION_EXEMPT_LENGTH = 16;

export function passwordResetTokenFromHash(hash: string): string | undefined {
  return RESET_TOKEN_RE.exec(hash)?.[1];
}

/** Remove secret-bearing and unsupported URL data without adding history. */
export function scrubPasswordResetLocation(): void {
  if (typeof window === "undefined") return;
  if (!window.location.search && !window.location.hash) return;

  window.history.replaceState(
    window.history.state,
    "",
    window.location.pathname || "/reset",
  );
}

function passwordLength(value: string): number {
  // Python's len() counts Unicode code points; Array.from keeps the browser's
  // validation aligned for non-BMP passwords instead of counting UTF-16 units.
  return Array.from(value).length;
}

export function passwordCharacterClassCount(password: string): number {
  const hasLower = /\p{Ll}/u.test(password);
  const hasUpper = /\p{Lu}/u.test(password);
  const hasDigit = /\p{Nd}/u.test(password);
  const hasSymbol = /[^\p{L}\p{N}\s]/u.test(password);
  return (
    Number(hasLower) + Number(hasUpper) + Number(hasDigit) + Number(hasSymbol)
  );
}

type PasswordField = "password" | "confirmation";

export type PasswordResetValidationError = {
  field: PasswordField;
  message: string;
};

export function validatePasswordResetForm(
  password: string,
  confirmation: string,
  policy: PasswordPolicy,
): PasswordResetValidationError | null {
  const length = passwordLength(password);

  if (length === 0) {
    return { field: "password", message: "Enter a new password." };
  }
  if (length < policy.min_length) {
    return {
      field: "password",
      message: `Use at least ${policy.min_length} characters.`,
    };
  }
  if (length > MAX_PASSWORD_LENGTH) {
    return {
      field: "password",
      message: `Use no more than ${MAX_PASSWORD_LENGTH} characters.`,
    };
  }
  if (
    length < COMPOSITION_EXEMPT_LENGTH &&
    passwordCharacterClassCount(password) < policy.required_character_classes
  ) {
    return {
      field: "password",
      message: `Use at least ${policy.required_character_classes} character types: ${policy.character_class_names.join(", ")}.`,
    };
  }
  if (confirmation.length === 0) {
    return {
      field: "confirmation",
      message: "Confirm your new password.",
    };
  }
  if (password !== confirmation) {
    return {
      field: "confirmation",
      message: "The passwords do not match.",
    };
  }
  return null;
}

type ResetError = PasswordResetValidationError & {
  title: string;
};

export function describePasswordResetError(error: unknown): ResetError {
  if (error instanceof ApiError) {
    if (error.status === 422 || error.code.startsWith("password_")) {
      return {
        field: "password",
        title: "Password not accepted",
        message:
          "The password did not meet the server's policy. Review the requirements and choose another password.",
      };
    }
    if (error.status === 429) {
      return {
        field: "password",
        title: "Too many attempts",
        message: "Wait a few minutes, then try this reset again.",
      };
    }
    if (error.status === 0) {
      return {
        field: "password",
        title: "Could not reach z4j",
        message: "Check your connection and try again on this page.",
      };
    }
    if (error.status >= 500) {
      return {
        field: "password",
        title: "Server error",
        message: "z4j could not reset the password. Try again in a moment.",
      };
    }
  }

  return {
    field: "password",
    title: "Could not reset password",
    message: "The password was not changed. Try again on this page.",
  };
}

function initialResetToken(): string | undefined {
  return typeof window === "undefined"
    ? undefined
    : passwordResetTokenFromHash(window.location.hash);
}

function PasswordResetPage() {
  const [token, setToken] = useState<string | undefined>(initialResetToken);
  const [outcome, setOutcome] = useState<"entry" | "expired" | "success">(
    "entry",
  );

  // Layout timing removes the fragment before the first painted interaction.
  // replaceState also ensures the secret-bearing URL is not a back-stack item.
  useLayoutEffect(() => {
    scrubPasswordResetLocation();
  }, []);

  if (outcome === "success") {
    return (
      <ResetShell>
        <div className="space-y-5" role="status" aria-live="polite">
          <div className="flex items-start gap-3">
            <CheckCircle2 className="mt-0.5 size-6 text-success" />
            <div>
              <h1 className="text-xl font-semibold">Password reset</h1>
              <p className="mt-1 text-sm text-muted-foreground">
                Your password has been changed and existing sessions have been
                signed out. Sign in with your new password.
              </p>
            </div>
          </div>
          <Button asChild className="w-full">
            <Link to="/login">
              <LogIn className="size-4" />
              Go to login
            </Link>
          </Button>
        </div>
      </ResetShell>
    );
  }

  if (!token) {
    return (
      <ResetShell>
        <div className="space-y-5">
          <div className="flex items-start gap-3" role="alert">
            <AlertCircle className="mt-0.5 size-6 text-destructive" />
            <div>
              <h1 className="text-xl font-semibold">
                Password reset link invalid
              </h1>
              <p className="mt-1 text-sm text-muted-foreground">
                {outcome === "expired"
                  ? "This link is invalid, expired, or has already been used. Request a fresh reset link."
                  : "Open the complete link from your reset email. Reset links expire after 30 minutes and can be used once."}
              </p>
            </div>
          </div>
          <Button asChild variant="outline" className="w-full">
            <Link to="/login">
              <LogIn className="size-4" />
              Go to login
            </Link>
          </Button>
        </div>
      </ResetShell>
    );
  }

  return (
    <ResetForm
      token={token}
      onExpired={() => {
        setToken(undefined);
        setOutcome("expired");
      }}
      onSuccess={() => {
        setToken(undefined);
        setOutcome("success");
      }}
    />
  );
}

function ResetForm({
  token,
  onExpired,
  onSuccess,
}: {
  token: string;
  onExpired: () => void;
  onSuccess: () => void;
}) {
  const resetPassword = usePasswordResetConfirm();
  const policy = usePasswordPolicy().data ?? PASSWORD_POLICY_FALLBACK;
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmation, setShowConfirmation] = useState(false);
  const [error, setError] = useState<ResetError | null>(null);

  const requirementsId = "reset-password-requirements";
  const errorId = "reset-password-error";
  const passwordDescribedBy =
    error?.field === "password"
      ? `${requirementsId} ${errorId}`
      : requirementsId;
  const confirmationDescribedBy =
    error?.field === "confirmation" ? errorId : undefined;

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);

    const validation = validatePasswordResetForm(
      password,
      confirmation,
      policy,
    );
    if (validation) {
      setError({ title: "Check your password", ...validation });
      return;
    }

    try {
      const response = await resetPassword.mutateAsync({
        token,
        new_password: password,
      });
      resetPassword.reset();
      if (!response.success) {
        setError(describePasswordResetError(undefined));
        return;
      }
      setPassword("");
      setConfirmation("");
      scrubPasswordResetLocation();
      onSuccess();
    } catch (caught) {
      resetPassword.reset();
      if (
        caught instanceof ApiError &&
        (caught.status === 404 || caught.code === "invalid_or_expired")
      ) {
        setPassword("");
        setConfirmation("");
        onExpired();
        return;
      }
      setError(describePasswordResetError(caught));
    }
  }

  const clearError = () => {
    if (error) setError(null);
  };

  return (
    <ResetShell>
      <div className="mb-6 space-y-1.5">
        <div className="mb-3 flex items-center gap-2 text-primary">
          <KeyRound className="size-5" />
          <span className="text-sm font-medium">Account recovery</span>
        </div>
        <h1 className="text-xl font-semibold tracking-tight">
          Choose a new password
        </h1>
        <p className="text-sm text-muted-foreground">
          This single-use reset link expires 30 minutes after it was sent.
        </p>
      </div>

      <form onSubmit={onSubmit} className="space-y-5" noValidate>
        {error && (
          <Alert
            id={errorId}
            variant="destructive"
            role="alert"
            aria-live="assertive"
          >
            <AlertCircle />
            <AlertTitle>{error.title}</AlertTitle>
            <AlertDescription>
              <p>{error.message}</p>
            </AlertDescription>
          </Alert>
        )}

        <div className="space-y-2">
          <Label htmlFor="reset-password">New password</Label>
          <div className="relative">
            <Input
              id="reset-password"
              type={showPassword ? "text" : "password"}
              autoComplete="new-password"
              autoCapitalize="none"
              autoCorrect="off"
              required
              value={password}
              onChange={(event) => {
                setPassword(event.target.value);
                clearError();
              }}
              className="h-11 pr-10"
              aria-invalid={error?.field === "password" || undefined}
              aria-describedby={passwordDescribedBy}
            />
            <button
              type="button"
              onClick={() => setShowPassword((shown) => !shown)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              aria-label={
                showPassword ? "Hide new password" : "Show new password"
              }
              aria-controls="reset-password"
              aria-pressed={showPassword}
            >
              {showPassword ? (
                <EyeOff className="size-4" />
              ) : (
                <Eye className="size-4" />
              )}
            </button>
          </div>
          <p
            id={requirementsId}
            className="text-xs leading-relaxed text-muted-foreground"
          >
            Use at least {policy.min_length} characters. Passwords shorter than{" "}
            {COMPOSITION_EXEMPT_LENGTH} characters need{" "}
            {policy.required_character_classes} of:{" "}
            {policy.character_class_names.join(", ")}. Common passwords are
            rejected.
          </p>
        </div>

        <div className="space-y-2">
          <Label htmlFor="reset-password-confirmation">
            Confirm new password
          </Label>
          <div className="relative">
            <Input
              id="reset-password-confirmation"
              type={showConfirmation ? "text" : "password"}
              autoComplete="new-password"
              autoCapitalize="none"
              autoCorrect="off"
              required
              value={confirmation}
              onChange={(event) => {
                setConfirmation(event.target.value);
                clearError();
              }}
              className="h-11 pr-10"
              aria-invalid={error?.field === "confirmation" || undefined}
              aria-describedby={confirmationDescribedBy}
            />
            <button
              type="button"
              onClick={() => setShowConfirmation((shown) => !shown)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              aria-label={
                showConfirmation
                  ? "Hide password confirmation"
                  : "Show password confirmation"
              }
              aria-controls="reset-password-confirmation"
              aria-pressed={showConfirmation}
            >
              {showConfirmation ? (
                <EyeOff className="size-4" />
              ) : (
                <Eye className="size-4" />
              )}
            </button>
          </div>
        </div>

        <Button
          type="submit"
          className="w-full"
          disabled={resetPassword.isPending}
          aria-busy={resetPassword.isPending}
        >
          {resetPassword.isPending && (
            <Loader2 className="size-4 animate-spin" />
          )}
          {resetPassword.isPending ? "Resetting password…" : "Reset password"}
        </Button>
      </form>
    </ResetShell>
  );
}

function ResetShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="relative grid min-h-screen w-full place-items-center bg-muted/30 p-6">
      <div className="absolute right-4 top-4">
        <ThemeToggle />
      </div>

      <main className="w-full max-w-sm space-y-8">
        <div className="flex items-center justify-center gap-3">
          <div className="flex size-10 shrink-0 items-center justify-center rounded-md bg-primary text-primary-foreground">
            <Z4jMark className="size-6" />
          </div>
          <div className="flex min-w-0 flex-col leading-tight">
            <span className="text-sm font-semibold">z4j</span>
            <span className="text-xs text-muted-foreground">control plane</span>
          </div>
        </div>

        <div className="panel-surface p-8">{children}</div>
      </main>
    </div>
  );
}
