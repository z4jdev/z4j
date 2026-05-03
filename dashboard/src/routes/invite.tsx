/**
 * Public `/invite?token=...` accept page.
 *
 * An invitee lands here from the admin's shared invite link. We:
 *
 * 1. Validate the token via ``/api/v1/invitations/preview`` (GET,
 *    anonymous) and render "you've been invited to X".
 * 2. Collect display name + password.
 * 3. POST to ``/api/v1/invitations/accept`` - the server creates the
 *    user, grants membership, and stamps the invitation as
 *    accepted, atomically in one transaction.
 * 4. Redirect to the login page on success.
 *
 * Deliberately NOT under ``/_authenticated/*`` - the invitee is not
 * logged in yet. Token validity IS the auth.
 */
import { useState } from "react";
import {
  createFileRoute,
  Link,
  useNavigate,
  useSearch,
} from "@tanstack/react-router";
import { AlertCircle, CheckCircle2, LogIn } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  useAcceptInvitation,
  useInvitationPreview,
} from "@/hooks/use-invitations";
import { ApiError } from "@/lib/api";

interface InviteSearch {
  token?: string;
}

export const Route = createFileRoute("/invite")({
  component: InvitePage,
  validateSearch: (search: Record<string, unknown>): InviteSearch => ({
    token: typeof search.token === "string" ? search.token : undefined,
  }),
});

function InvitePage() {
  const { token } = useSearch({ from: "/invite" });
  const navigate = useNavigate();
  const preview = useInvitationPreview(token);
  const accept = useAcceptInvitation();

  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [passwordConfirm, setPasswordConfirm] = useState("");

  if (!token) {
    return (
      <InviteShell>
        <ErrorView
          title="Invitation link missing token"
          message="This page requires an invitation token. Ask the admin who invited you to re-send their invite link."
        />
      </InviteShell>
    );
  }

  if (preview.isLoading) {
    return (
      <InviteShell>
        <Skeleton className="h-24 w-full" />
      </InviteShell>
    );
  }

  if (preview.isError) {
    return (
      <InviteShell>
        <ErrorView
          title="Invitation invalid or expired"
          message="This invitation link is no longer valid. It may have been accepted, revoked, or expired. Ask the admin for a fresh invitation."
        />
      </InviteShell>
    );
  }

  const invite = preview.data!;

  const handleAccept = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== passwordConfirm) {
      toast.error("Passwords do not match");
      return;
    }
    try {
      await accept.mutateAsync({
        token,
        display_name: displayName.trim(),
        password,
      });
      toast.success(
        `Welcome! Your account is ready. Please log in with ${invite.email}.`,
      );
      // Navigate to login - the invitee signs in with their new
      // credentials. We don't auto-login because the accept endpoint
      // does not set a session (matches the invite flow's spec).
      navigate({ to: "/login" });
    } catch (err) {
      const msg = err instanceof ApiError
        ? err.message
        : err instanceof Error ? err.message : "Accept failed";
      toast.error(msg);
    }
  };

  return (
    <InviteShell>
      <div className="space-y-4">
        <div className="flex items-start gap-3">
          <CheckCircle2 className="mt-0.5 size-6 text-primary" />
          <div>
            <h1 className="text-xl font-semibold">You've been invited</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Join <strong>{invite.project_name}</strong> as{" "}
              <Badge variant="outline">{invite.role}</Badge> on z4j.
            </p>
          </div>
        </div>

        <form onSubmit={handleAccept} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="invite-email">Email</Label>
            <Input
              id="invite-email"
              type="email"
              value={invite.email}
              readOnly
              disabled
              className="font-mono"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="invite-name">Display name</Label>
            <Input
              id="invite-name"
              required
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Alex Chen"
              minLength={1}
              maxLength={200}
              autoFocus
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="invite-password">Choose a password</Label>
            <Input
              id="invite-password"
              type="password"
              required
              minLength={12}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="minimum 12 characters"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="invite-password-confirm">Confirm password</Label>
            <Input
              id="invite-password-confirm"
              type="password"
              required
              minLength={12}
              value={passwordConfirm}
              onChange={(e) => setPasswordConfirm(e.target.value)}
            />
          </div>
          <Button
            type="submit"
            className="w-full"
            disabled={accept.isPending}
          >
            {accept.isPending ? "Creating account…" : "Accept invitation"}
          </Button>
        </form>

        <p className="text-xs text-muted-foreground">
          Already have an account on this z4j instance?{" "}
          <Link to="/login" className="underline">
            Log in instead
          </Link>{" "}
          - ask the admin to add you to the project directly.
        </p>
      </div>
    </InviteShell>
  );
}

function InviteShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-muted/30 p-4">
      <Card className="w-full max-w-md p-6">{children}</Card>
    </div>
  );
}

function ErrorView({
  title,
  message,
}: {
  title: string;
  message: string;
}) {
  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3">
        <AlertCircle className="mt-0.5 size-6 text-destructive" />
        <div>
          <h1 className="text-xl font-semibold">{title}</h1>
          <p className="mt-1 text-sm text-muted-foreground">{message}</p>
        </div>
      </div>
      <Button asChild variant="outline" className="w-full">
        <Link to="/login">
          <LogIn className="size-4" />
          Go to login
        </Link>
      </Button>
    </div>
  );
}
