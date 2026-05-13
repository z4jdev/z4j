/**
 * Account settings page -- the user's profile.
 *
 * Two cards:
 *   1. Profile  (name, display name, timezone) + read-only account info
 *   2. Password (one button that opens a Change Password modal)
 *
 * MFA, trusted devices, and active sessions used to live on a Security
 * sub-tab here; in 1.6.0 they moved to /settings/security (their own
 * sidebar entry) because the second factor is meaningful enough to
 * deserve a top-level destination rather than being hidden one click
 * deeper than Account.
 */
import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
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
  TableRow,
} from "@/components/ui/table";
import { formatAbsolute } from "@/lib/format";
import { PageHeader } from "@/components/domain/page-header";
import type { UserMePublic } from "@/lib/api-types";

export const Route = createFileRoute("/_authenticated/settings/account")({
  component: AccountPage,
});

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

function AccountPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Account"
        description="Your profile and password."
      />
      <ProfileCard />
      <PasswordCard />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Profile + read-only account info
// ---------------------------------------------------------------------------

function ProfileCard() {
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

  if (user && !initialized) {
    setFirstName(user.first_name ?? "");
    setLastName(user.last_name ?? "");
    // Display name comes back derived from first/last when not
    // explicitly set; blank the input so the user can see they have
    // a fresh override slot rather than the auto-derived value.
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
    <>
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
              <span className="text-xs text-muted-foreground">
                (optional)
              </span>
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
    </>
  );
}

// ---------------------------------------------------------------------------
// Password card (button opens a modal)
// ---------------------------------------------------------------------------

function PasswordCard() {
  const [open, setOpen] = useState(false);
  return (
    <Card className="p-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold">Password</h3>
          <p className="mt-1 text-xs text-muted-foreground">
            Sign-in password. Changing it revokes every other active
            session and trusted device.
          </p>
        </div>
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger asChild>
            <Button variant="outline">
              <KeyRound className="size-4" />
              Change password
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Change password</DialogTitle>
            </DialogHeader>
            <ChangePasswordForm onDone={() => setOpen(false)} />
          </DialogContent>
        </Dialog>
      </div>
    </Card>
  );
}

function ChangePasswordForm({ onDone }: { onDone: () => void }) {
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
          onDone();
          setTimeout(() => {
            window.location.href = "/login";
          }, 1500);
        },
        onError: (err) => toast.error(`Failed: ${err.message}`),
      },
    );
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
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
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onDone}>
          Cancel
        </Button>
        <Button type="submit" disabled={changePw.isPending}>
          {changePw.isPending ? (
            <>
              <Loader2 className="size-4 animate-spin" />
              Changing...
            </>
          ) : (
            "Change password"
          )}
        </Button>
      </DialogFooter>
    </form>
  );
}
