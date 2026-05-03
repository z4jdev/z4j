/**
 * Account settings page - profile, security, and API key management.
 *
 * Three tabs:
 *   Profile    - display name, timezone, read-only account info
 *   Security   - change password, manage active sessions
 *   API Keys   - create / revoke personal API keys
 */
import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { api } from "@/lib/api";
import {
  Check,
  Copy,
  Key,
  Loader2,
  Plus,
  Shield,
  Trash2,
  User,
} from "lucide-react";
import { toast } from "sonner";
import { EmptyState } from "@/components/domain/empty-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { formatAbsolute } from "@/lib/format";
import { DateCell } from "@/components/domain/date-cell";
import { PageHeader } from "@/components/domain/page-header";
import type { UserMePublic } from "@/lib/api-types";

export const Route = createFileRoute("/_authenticated/settings/account")({
  component: AccountPage,
});

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Session {
  id: string;
  issued_at: string;
  last_seen_at: string;
  ip_at_issue: string | null;
  user_agent_at_issue: string | null;
  is_current: boolean;
}

interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  last_used_at: string | null;
  expires_at: string | null;
  created_at: string;
}

interface CreateApiKeyResponse {
  token: string;
}

// ---------------------------------------------------------------------------
// Common timezones
// ---------------------------------------------------------------------------

const TIMEZONES = [
  "UTC",
  "America/New_York",
  "America/Chicago",
  "America/Denver",
  "America/Los_Angeles",
  "America/Anchorage",
  "Pacific/Honolulu",
  "America/Toronto",
  "America/Vancouver",
  "America/Sao_Paulo",
  "America/Argentina/Buenos_Aires",
  "America/Mexico_City",
  "Europe/London",
  "Europe/Paris",
  "Europe/Berlin",
  "Europe/Amsterdam",
  "Europe/Zurich",
  "Europe/Madrid",
  "Europe/Rome",
  "Europe/Stockholm",
  "Europe/Helsinki",
  "Europe/Warsaw",
  "Europe/Moscow",
  "Europe/Istanbul",
  "Asia/Dubai",
  "Asia/Kolkata",
  "Asia/Bangkok",
  "Asia/Singapore",
  "Asia/Shanghai",
  "Asia/Hong_Kong",
  "Asia/Tokyo",
  "Asia/Seoul",
  "Australia/Sydney",
  "Australia/Melbourne",
  "Pacific/Auckland",
] as const;

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

function AccountPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Account"
        description="Your profile, password, and active sessions."
      />
      <Tabs defaultValue="profile" className="space-y-4">
        <TabsList>
        <TabsTrigger value="profile" className="gap-1.5">
          <User className="size-4" />
          Profile
        </TabsTrigger>
        <TabsTrigger value="security" className="gap-1.5">
          <Shield className="size-4" />
          Security
        </TabsTrigger>
      </TabsList>

        <TabsContent value="profile">
          <ProfileTab />
        </TabsContent>
        <TabsContent value="security">
          <SecurityTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Profile tab
// ---------------------------------------------------------------------------

function ProfileTab() {
  const { data: user, isLoading } = useQuery<UserMePublic>({
    queryKey: ["auth-me"],
    queryFn: () => api.get<UserMePublic>("/auth/me"),
    staleTime: 60_000,
  });

  const qc = useQueryClient();

  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [timezone, setTimezone] = useState("");
  const [initialized, setInitialized] = useState(false);

  // Seed form state once user data arrives.
  if (user && !initialized) {
    setFirstName(user.first_name ?? "");
    setLastName(user.last_name ?? "");
    // If display_name was never explicitly set it comes back derived
    // from first/last. We only want to prefill the textbox when the
    // user actually chose a custom display_name, so blank it when
    // the rendered form opens.
    setDisplayName("");
    setTimezone(user.timezone ?? "UTC");
    setInitialized(true);
  }

  const updateProfile = useMutation({
    mutationFn: (body: {
      first_name: string | null;
      last_name: string | null;
      display_name: string | null;
      timezone: string;
    }) => api.patch<UserMePublic>("/auth/me", body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["auth-me"] });
      toast.success("Profile updated");
    },
    onError: (err) => toast.error(`Failed: ${err.message}`),
  });

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    updateProfile.mutate({
      first_name: firstName.trim() || null,
      last_name: lastName.trim() || null,
      display_name: displayName.trim() || null,
      timezone,
    });
  };

  if (isLoading) return <Skeleton className="h-64 w-full" />;
  if (!user) return null;

  return (
    <div className="space-y-6">
      {/* Editable fields */}
      <Card className="p-6">
        <h3 className="text-sm font-semibold">Profile</h3>
        <p className="mt-1 text-xs text-muted-foreground">
          Update your name and timezone.
        </p>
        <form onSubmit={handleSave} className="mt-4 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label htmlFor="account-first">First name</Label>
              <Input
                id="account-first"
                value={firstName}
                onChange={(e) => setFirstName(e.target.value)}
                maxLength={100}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="account-last">Last name</Label>
              <Input
                id="account-last"
                value={lastName}
                onChange={(e) => setLastName(e.target.value)}
                maxLength={100}
              />
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="account-display">
              Display name{" "}
              <span className="text-xs text-muted-foreground">(optional)</span>
            </Label>
            <Input
              id="account-display"
              placeholder={
                user.first_name || user.last_name
                  ? `${user.first_name ?? ""} ${user.last_name ?? ""}`.trim()
                  : "Derived from first + last if blank"
              }
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              maxLength={200}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="account-tz">Timezone</Label>
            <Select value={timezone} onValueChange={setTimezone}>
              <SelectTrigger id="account-tz">
                <SelectValue placeholder="Select timezone" />
              </SelectTrigger>
              <SelectContent>
                {TIMEZONES.map((tz) => (
                  <SelectItem key={tz} value={tz}>
                    {tz}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <Button type="submit" disabled={updateProfile.isPending}>
            {updateProfile.isPending ? (
              <>
                <Loader2 className="size-4 animate-spin" />
                Saving...
              </>
            ) : (
              "Save"
            )}
          </Button>
        </form>
      </Card>

      {/* Read-only account info */}
      <Card className="p-6">
        <h3 className="text-sm font-semibold">Account Info</h3>
        <p className="mt-1 text-xs text-muted-foreground">
          Read-only information about your account.
        </p>
        <div className="mt-4">
          <Table>
            <TableBody>
              <TableRow>
                <TableCell className="w-1/3 py-2 font-medium text-muted-foreground">
                  Email
                </TableCell>
                <TableCell className="py-2 font-mono text-sm">
                  {user.email}
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="w-1/3 py-2 font-medium text-muted-foreground">
                  Account created
                </TableCell>
                <TableCell className="py-2 text-sm">
                  {formatAbsolute(user.created_at)}
                </TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </div>
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Security tab
// ---------------------------------------------------------------------------

function SecurityTab() {
  return (
    <div className="space-y-6">
      <PasswordSection />
      <SessionsSection />
    </div>
  );
}

function PasswordSection() {
  const [currentPw, setCurrentPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");

  const changePw = useMutation({
    mutationFn: (body: { current_password: string; new_password: string }) =>
      api.post<void>("/auth/change-password", body),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (newPw !== confirmPw) {
      toast.error("Passwords do not match");
      return;
    }
    changePw.mutate(
      { current_password: currentPw, new_password: newPw },
      {
        onSuccess: () => {
          toast.success("Password changed. Please log in again.");
          setCurrentPw("");
          setNewPw("");
          setConfirmPw("");
          setTimeout(() => {
            window.location.href = "/login";
          }, 1500);
        },
        onError: (err) => toast.error(`Failed: ${err.message}`),
      },
    );
  };

  return (
    <Card className="p-6">
      <h3 className="text-sm font-semibold">Change Password</h3>
      <p className="mt-1 text-xs text-muted-foreground">
        All sessions are revoked after a password change.
      </p>
      <form onSubmit={handleSubmit} className="mt-4 space-y-4">
        <div className="space-y-2">
          <Label htmlFor="account-pwd-current">Current password</Label>
          <Input
            id="account-pwd-current"
            type="password"
            autoComplete="current-password"
            value={currentPw}
            onChange={(e) => setCurrentPw(e.target.value)}
            required
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="account-pwd-new">New password</Label>
          <Input
            id="account-pwd-new"
            type="password"
            autoComplete="new-password"
            minLength={8}
            value={newPw}
            onChange={(e) => setNewPw(e.target.value)}
            required
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="account-pwd-confirm">Confirm new password</Label>
          <Input
            id="account-pwd-confirm"
            type="password"
            autoComplete="new-password"
            minLength={8}
            value={confirmPw}
            onChange={(e) => setConfirmPw(e.target.value)}
            required
          />
          {newPw && confirmPw && newPw !== confirmPw && (
            <p className="text-xs text-destructive">
              Passwords do not match.
            </p>
          )}
        </div>
        <Button type="submit" disabled={changePw.isPending}>
          {changePw.isPending ? (
            <>
              <Loader2 className="size-4 animate-spin" />
              Changing...
            </>
          ) : (
            "Change Password"
          )}
        </Button>
      </form>
    </Card>
  );
}

function SessionsSection() {
  const qc = useQueryClient();

  const { data: sessions, isLoading } = useQuery<Session[]>({
    queryKey: ["sessions"],
    queryFn: () => api.get<Session[]>("/auth/sessions"),
    staleTime: 30_000,
  });

  const revokeSession = useMutation({
    mutationFn: (sessionId: string) =>
      api.post<void>(`/auth/sessions/${sessionId}/revoke`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["sessions"] });
      toast.success("Session revoked");
    },
    onError: (err) => toast.error(`Failed: ${err.message}`),
  });

  const revokeAllOther = useMutation({
    mutationFn: async () => {
      const others = (sessions ?? []).filter((s) => !s.is_current);
      await Promise.all(
        others.map((s) =>
          api.post<void>(`/auth/sessions/${s.id}/revoke`),
        ),
      );
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["sessions"] });
      toast.success("All other sessions revoked");
    },
    onError: (err) => toast.error(`Failed: ${err.message}`),
  });

  const otherCount = (sessions ?? []).filter((s) => !s.is_current).length;

  return (
    <Card className="p-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold">Active Sessions</h3>
          <p className="mt-1 text-xs text-muted-foreground">
            Devices and browsers where you are currently signed in.
          </p>
        </div>
        {otherCount > 0 && (
          <Button
            variant="outline"
            size="sm"
            disabled={revokeAllOther.isPending}
            onClick={() => revokeAllOther.mutate()}
          >
            {revokeAllOther.isPending ? (
              <>
                <Loader2 className="size-4 animate-spin" />
                Revoking...
              </>
            ) : (
              "Revoke all other sessions"
            )}
          </Button>
        )}
      </div>

      {isLoading && <Skeleton className="mt-4 h-32 w-full" />}

      {sessions && sessions.length > 0 && (
        <div className="mt-4 overflow-hidden rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Device</TableHead>
                <TableHead>IP</TableHead>
                <TableHead>Last active</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {sessions.map((session) => (
                <TableRow
                  key={session.id}
                  className={
                    session.is_current ? "bg-primary/5" : undefined
                  }
                >
                  <TableCell
                    className="max-w-[250px] truncate text-xs"
                    title={session.user_agent_at_issue ?? ""}
                  >
                    {session.user_agent_at_issue == null ? (
                      <span className="text-muted-foreground">unknown</span>
                    ) : session.user_agent_at_issue.length > 80 ? (
                      session.user_agent_at_issue.slice(0, 80) + "..."
                    ) : (
                      session.user_agent_at_issue
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {session.ip_at_issue ?? (
                      <span className="text-muted-foreground">unknown</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <DateCell value={session.last_seen_at} />
                  </TableCell>
                  <TableCell>
                    {session.is_current ? (
                      <Badge variant="success">Current</Badge>
                    ) : (
                      <Badge variant="muted">Active</Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    {!session.is_current && (
                      <Button
                        variant="ghost"
                        size="icon"
                        className="text-muted-foreground hover:text-destructive"
                        disabled={revokeSession.isPending}
                        onClick={() => revokeSession.mutate(session.id)}
                        aria-label="Revoke this session"
                      >
                        <Trash2 className="size-4" />
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </Card>
  );
}
