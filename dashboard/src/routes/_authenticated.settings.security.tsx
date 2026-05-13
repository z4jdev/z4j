/**
 * Security settings page -- two-factor auth, trusted devices, and
 * active sessions. Split out from the Account page in 1.6.0 because
 * MFA + recovery codes + trusted devices have enough surface area to
 * deserve their own destination in the settings sidebar; the previous
 * Profile / Security sub-tab hierarchy hid the second factor one
 * click deeper than it should be.
 *
 * Change-password lives on the Account page (modal). Logging out
 * of other devices lives here, alongside the rest of the auth UI.
 */
import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { QRCodeSVG } from "qrcode.react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, Loader2, Shield, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { DateCell } from "@/components/domain/date-cell";
import { PageHeader } from "@/components/domain/page-header";
import {
  useEnrollComplete,
  useEnrollStart,
  useMfaDisable,
  useMfaStatus,
  useRegenerateRecoveryCodes,
  useRevokeTrustedDevice,
  useTrustCurrentDevice,
  useTrustedDevices,
} from "@/hooks/use-mfa";

export const Route = createFileRoute("/_authenticated/settings/security")({
  component: SecurityPage,
});

interface Session {
  id: string;
  issued_at: string;
  last_seen_at: string;
  ip_at_issue: string | null;
  user_agent_at_issue: string | null;
  is_current: boolean;
}

function SecurityPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Security"
        description="Two-factor authentication, trusted devices, and active sessions."
      />
      <MfaSection />
      <SessionsSection />
    </div>
  );
}

// ---------------------------------------------------------------------------
// MFA / TOTP
// ---------------------------------------------------------------------------

function MfaSection() {
  const status = useMfaStatus();

  if (status.isLoading) {
    return <Skeleton className="h-32 w-full" />;
  }
  if (!status.data) return null;

  return (
    <Card className="p-6">
      <h3 className="text-sm font-semibold">Two-factor authentication</h3>
      <p className="mt-1 text-xs text-muted-foreground">
        TOTP via your authenticator app, plus single-use recovery codes
        in case you lose your phone.
      </p>
      <div className="mt-4">
        {status.data.enrolled ? (
          <MfaEnabledPanel
            enrolledAt={status.data.enrolled_at}
            remainingCodes={status.data.remaining_recovery_codes}
          />
        ) : (
          <MfaEnrollPanel />
        )}
      </div>
    </Card>
  );
}

function MfaEnrollPanel() {
  const [step, setStep] = useState<"intro" | "scan" | "verify" | "done">(
    "intro",
  );
  const [secret, setSecret] = useState<string | null>(null);
  const [url, setUrl] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);

  const enrollStart = useEnrollStart();
  const enrollComplete = useEnrollComplete();

  if (step === "intro") {
    return (
      <Button
        onClick={async () => {
          try {
            const data = await enrollStart.mutateAsync();
            setSecret(data.secret_base32);
            setUrl(data.provisioning_url);
            setStep("scan");
          } catch (err) {
            toast.error(
              `Could not start enrollment: ${
                err instanceof Error ? err.message : String(err)
              }`,
            );
          }
        }}
        disabled={enrollStart.isPending}
      >
        {enrollStart.isPending && (
          <Loader2 className="size-4 animate-spin" />
        )}
        Set up two-factor authentication
      </Button>
    );
  }

  if (step === "scan" && secret && url) {
    return (
      <div className="space-y-4">
        <div className="rounded-md border bg-muted/40 p-4 space-y-3">
          <p className="text-sm font-medium">
            Scan or type into your authenticator app
          </p>
          <p className="text-xs text-muted-foreground">
            Open Authy / 1Password / Aegis / Bitwarden / Google
            Authenticator. Scan the QR code below, or tap "Show secret"
            and type the base32 string in manually.
          </p>
          <div className="flex justify-center rounded-md border bg-white p-4">
            <QRCodeSVG
              value={url}
              size={192}
              level="M"
              includeMargin={false}
            />
          </div>
          <details className="space-y-2">
            <summary className="cursor-pointer text-xs font-medium text-muted-foreground hover:text-foreground">
              Can't scan? Show secret to type manually
            </summary>
            <div className="space-y-2 pt-2">
              <Label className="text-xs">Secret (base32)</Label>
              <div className="flex items-center gap-2">
                <code className="flex-1 break-all rounded bg-background p-2 text-xs font-mono">
                  {secret}
                </code>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    navigator.clipboard.writeText(secret);
                    toast.success("Secret copied to clipboard");
                  }}
                  aria-label="Copy secret to clipboard"
                >
                  <Copy className="size-4" />
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Provisioning URL (advanced):
              </p>
              <code className="block break-all rounded bg-background p-2 text-[10px] font-mono">
                {url}
              </code>
            </div>
          </details>
        </div>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              const data = await enrollComplete.mutateAsync({ code });
              setRecoveryCodes(data.recovery_codes);
              setStep("done");
            } catch (err) {
              toast.error(
                `Code rejected. Try again with a fresh code. (${
                  err instanceof Error ? err.message : String(err)
                })`,
              );
            }
          }}
          className="space-y-3"
        >
          <div className="space-y-2">
            <Label htmlFor="mfa-enroll-code">
              Enter the 6-digit code from your app
            </Label>
            <Input
              id="mfa-enroll-code"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              value={code}
              onChange={(e) =>
                setCode(e.target.value.replace(/\D/g, ""))
              }
              required
            />
          </div>
          <Button
            type="submit"
            disabled={code.length !== 6 || enrollComplete.isPending}
          >
            {enrollComplete.isPending && (
              <Loader2 className="size-4 animate-spin" />
            )}
            Confirm and activate
          </Button>
        </form>
      </div>
    );
  }

  if (step === "done" && recoveryCodes) {
    return <RecoveryCodesPanel codes={recoveryCodes} />;
  }

  return null;
}

function RecoveryCodesPanel({ codes }: { codes: string[] }) {
  const [acknowledged, setAcknowledged] = useState(false);
  return (
    <div className="space-y-4">
      <div className="rounded-md border border-amber-300/60 bg-amber-50 p-4 text-sm dark:border-amber-400/40 dark:bg-amber-400/10">
        <p className="font-medium">Save your recovery codes</p>
        <p className="mt-1 text-xs text-muted-foreground">
          Each code is single-use. Store them somewhere only you can
          access (password manager, printed copy in a safe). They
          will not be shown again. Regenerate to invalidate the set.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-2 font-mono text-sm">
        {codes.map((c) => (
          <code
            key={c}
            className="rounded bg-muted px-2 py-1 text-center"
          >
            {c}
          </code>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Button
          variant="outline"
          onClick={() => {
            navigator.clipboard.writeText(codes.join("\n"));
            toast.success("Copied to clipboard");
          }}
        >
          <Copy className="size-4" />
          Copy all
        </Button>
        <Button
          variant="outline"
          onClick={() => {
            const blob = new Blob([codes.join("\n") + "\n"], {
              type: "text/plain",
            });
            const a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = "z4j-recovery-codes.txt";
            a.click();
            URL.revokeObjectURL(a.href);
          }}
        >
          Download as .txt
        </Button>
      </div>
      <div className="flex items-center gap-2">
        <Checkbox
          id="ack-recovery"
          checked={acknowledged}
          onCheckedChange={(v) => setAcknowledged(v === true)}
        />
        <Label
          htmlFor="ack-recovery"
          className="text-sm font-normal text-muted-foreground"
        >
          I have saved my recovery codes
        </Label>
      </div>
      <Button
        disabled={!acknowledged}
        onClick={() => window.location.reload()}
      >
        Done
      </Button>
    </div>
  );
}

function MfaEnabledPanel({
  enrolledAt,
  remainingCodes,
}: {
  enrolledAt: string | null;
  remainingCodes: number;
}) {
  const [disableOpen, setDisableOpen] = useState(false);
  const [regenOpen, setRegenOpen] = useState(false);
  const [newCodes, setNewCodes] = useState<string[] | null>(null);
  const regen = useRegenerateRecoveryCodes();

  return (
    <div className="space-y-4">
      <Alert>
        <Shield className="size-4" />
        <AlertTitle>Two-factor authentication is on</AlertTitle>
        <AlertDescription>
          {/* DateCell renders both the relative ("1 minute ago") and
              the absolute timestamp as block-level rows, so any
              trailing inline punctuation lands on its own line and
              looks like an orphaned period. Wrap the date in a
              span so it stays inline with "Enrolled", and drop the
              period entirely. */}
          {enrolledAt && (
            <p className="text-xs">
              Enrolled <DateCell value={enrolledAt} />
            </p>
          )}
          <p className="text-xs">
            {remainingCodes} recovery code{remainingCodes === 1 ? "" : "s"}{" "}
            remaining.
          </p>
        </AlertDescription>
      </Alert>
      <div className="flex flex-wrap gap-2">
        <Dialog open={regenOpen} onOpenChange={setRegenOpen}>
          <DialogTrigger asChild>
            <Button variant="outline">Regenerate recovery codes</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Regenerate recovery codes</DialogTitle>
            </DialogHeader>
            {newCodes ? (
              <RecoveryCodesPanel codes={newCodes} />
            ) : (
              <>
                <p className="text-sm text-muted-foreground">
                  This deletes your current codes and mints a fresh
                  set. Any unused codes you've stored will stop working.
                </p>
                <DialogFooter>
                  <Button
                    variant="outline"
                    onClick={() => setRegenOpen(false)}
                  >
                    Cancel
                  </Button>
                  <Button
                    disabled={regen.isPending}
                    onClick={async () => {
                      try {
                        const data = await regen.mutateAsync();
                        setNewCodes(data.recovery_codes);
                      } catch (err) {
                        toast.error(
                          err instanceof Error ? err.message : String(err),
                        );
                      }
                    }}
                  >
                    {regen.isPending && (
                      <Loader2 className="size-4 animate-spin" />
                    )}
                    Regenerate
                  </Button>
                </DialogFooter>
              </>
            )}
          </DialogContent>
        </Dialog>
        <Dialog open={disableOpen} onOpenChange={setDisableOpen}>
          <DialogTrigger asChild>
            <Button variant="destructive">
              Disable two-factor authentication
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>
                Disable two-factor authentication
              </DialogTitle>
            </DialogHeader>
            <MfaDisableForm onDone={() => setDisableOpen(false)} />
          </DialogContent>
        </Dialog>
      </div>
      <TrustedDevicesList />
    </div>
  );
}

function MfaDisableForm({ onDone }: { onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const disable = useMfaDisable();
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        try {
          await disable.mutateAsync({ password, code });
          toast.success("Two-factor authentication disabled");
          onDone();
          window.location.reload();
        } catch (err) {
          toast.error(
            err instanceof Error ? err.message : String(err),
          );
        }
      }}
      className="space-y-3"
    >
      <p className="text-sm text-muted-foreground">
        Enter your current password and a fresh code from your
        authenticator app.
      </p>
      <div className="space-y-2">
        <Label htmlFor="disable-pwd">Password</Label>
        <Input
          id="disable-pwd"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="disable-code">Authenticator code</Label>
        <Input
          id="disable-code"
          type="text"
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={6}
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
          required
        />
      </div>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onDone}>
          Cancel
        </Button>
        <Button
          type="submit"
          variant="destructive"
          disabled={disable.isPending || code.length !== 6}
        >
          {disable.isPending && (
            <Loader2 className="size-4 animate-spin" />
          )}
          Disable
        </Button>
      </DialogFooter>
    </form>
  );
}

function TrustedDevicesList() {
  const devices = useTrustedDevices();
  const revoke = useRevokeTrustedDevice();
  const trustCurrent = useTrustCurrentDevice();

  if (devices.isLoading) return <Skeleton className="h-24 w-full" />;

  // The current browser is "already trusted" when the trusted-devices
  // list includes a row with ``is_current === true`` and the row is
  // not revoked. If so, hide the "Trust this device" CTA. If not,
  // show it so the user has somewhere to mint trust without having
  // to log out + back in.
  const rows = devices.data ?? [];
  const currentRow = rows.find((d) => d.is_current && !d.revoked_at);
  const trustCurrentButton = currentRow ? null : (
    <Button
      size="sm"
      variant="outline"
      disabled={trustCurrent.isPending}
      onClick={async () => {
        try {
          await trustCurrent.mutateAsync();
          toast.success("This browser is now trusted for 30 days");
        } catch (err) {
          toast.error(
            err instanceof Error ? err.message : String(err),
          );
        }
      }}
    >
      {trustCurrent.isPending && (
        <Loader2 className="size-4 animate-spin" />
      )}
      Trust this device for 30 days
    </Button>
  );

  if (rows.length === 0) {
    return (
      <div className="mt-2 space-y-3">
        <h4 className="text-sm font-semibold">Trusted devices</h4>
        <p className="text-xs text-muted-foreground">
          Trusting a browser lets it skip the two-factor step{" "}
          <em>at sign-in</em> for 30 days. It does NOT skip the
          re-verify prompt that appears before sensitive actions
          like changing your password or minting an API key --
          those still ask for a fresh code on every device.
        </p>
        {trustCurrentButton}
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="mt-2 flex items-center justify-between gap-2">
        <h4 className="text-sm font-semibold">Trusted devices</h4>
        {trustCurrentButton}
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Device</TableHead>
            <TableHead>Last seen</TableHead>
            <TableHead>Expires</TableHead>
            <TableHead className="w-16">Status</TableHead>
            <TableHead className="w-24" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((d) => (
            <TableRow key={d.id}>
              <TableCell>
                {d.label}
                {d.is_current && (
                  <Badge variant="secondary" className="ml-2">
                    this device
                  </Badge>
                )}
              </TableCell>
              <TableCell>
                <DateCell value={d.last_seen_at} />
              </TableCell>
              <TableCell>
                <DateCell value={d.expires_at} />
              </TableCell>
              <TableCell>
                {d.revoked_at ? (
                  <Badge variant="outline">revoked</Badge>
                ) : (
                  <Badge>active</Badge>
                )}
              </TableCell>
              <TableCell>
                {!d.revoked_at && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={async () => {
                      try {
                        await revoke.mutateAsync(d.id);
                        toast.success("Device revoked");
                      } catch (err) {
                        toast.error(
                          err instanceof Error
                            ? err.message
                            : String(err),
                        );
                      }
                    }}
                  >
                    Revoke
                  </Button>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Active sessions
// ---------------------------------------------------------------------------

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
          <h3 className="text-sm font-semibold">Active sessions</h3>
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
