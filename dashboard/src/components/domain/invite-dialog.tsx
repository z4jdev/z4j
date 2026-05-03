/**
 * Invite-teammate dialog.
 *
 * Admin enters email + role, we mint an invitation via the API, then
 * show the plaintext token ONCE alongside a copy button + full URL.
 * After the admin closes the dialog the plaintext is gone - the
 * server does not expose it again.
 */
import { useEffect, useState } from "react";
import { Copy, UserPlus } from "lucide-react";
import { toast } from "sonner";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useMintInvitation } from "@/hooks/use-invitations";
import { ApiError } from "@/lib/api";

export function InviteDialog({ slug }: { slug: string }) {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("viewer");
  const [mintedToken, setMintedToken] = useState<string | null>(null);
  const [acceptUrl, setAcceptUrl] = useState<string | null>(null);

  const mutation = useMintInvitation(slug);

  // Reset every time the dialog closes so the plaintext token never
  // leaks into a subsequent open.
  useEffect(() => {
    if (!open) {
      setMintedToken(null);
      setAcceptUrl(null);
      setEmail("");
      setRole("viewer");
    }
  }, [open]);

  const handleMint = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await mutation.mutateAsync({ email, role });
      setMintedToken(res.token);
      // Prefer the dashboard's origin; fall back to the server-
      // supplied relative path if window isn't available (SSR).
      const origin = typeof window !== "undefined" ? window.location.origin : "";
      setAcceptUrl(`${origin}${res.accept_url_path}`);
    } catch (err) {
      const msg = err instanceof ApiError
        ? err.message
        : err instanceof Error
          ? err.message
          : "Failed to mint invitation";
      toast.error(msg);
    }
  };

  const copyUrl = async () => {
    if (!acceptUrl) return;
    try {
      await navigator.clipboard.writeText(acceptUrl);
      toast.success("Invite link copied");
    } catch {
      toast.error("Copy failed - select + ctrl/cmd+C manually");
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <UserPlus className="size-4" />
          Invite
        </Button>
      </DialogTrigger>
      <DialogContent>
        {mintedToken && acceptUrl ? (
          <>
            <DialogHeader>
              <DialogTitle>Invitation link ready</DialogTitle>
              <DialogDescription>
                Send this link to <code className="font-mono">{email}</code>.
                The link is shown <strong>once</strong> - copy it now; the
                server does not expose it again.
              </DialogDescription>
            </DialogHeader>
            <div className="my-4 space-y-2">
              <Label htmlFor="invite-url">Invite link</Label>
              <div className="flex gap-2">
                <Input
                  id="invite-url"
                  readOnly
                  value={acceptUrl}
                  className="font-mono text-xs"
                  onFocus={(e) => e.currentTarget.select()}
                />
                <Button
                  type="button"
                  variant="outline"
                  onClick={copyUrl}
                  aria-label="copy invite link"
                >
                  <Copy className="size-4" />
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Valid for 7 days. Role: <strong>{role}</strong>.
                You can revoke this invitation before it's accepted from the
                Pending invitations table below.
              </p>
            </div>
            <DialogFooter>
              <Button onClick={() => setOpen(false)}>Done</Button>
            </DialogFooter>
          </>
        ) : (
          <form onSubmit={handleMint}>
            <DialogHeader>
              <DialogTitle>Invite a teammate</DialogTitle>
              <DialogDescription>
                Generate a single-use invitation link for a new team member.
                They&rsquo;ll complete signup with their own password.
              </DialogDescription>
            </DialogHeader>
            <div className="my-6 space-y-4">
              <div className="space-y-2">
                <Label htmlFor="invite-email">Email</Label>
                <Input
                  id="invite-email"
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="teammate@example.com"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="invite-role">Role</Label>
                <Select value={role} onValueChange={setRole}>
                  <SelectTrigger id="invite-role">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="viewer">Viewer (read-only)</SelectItem>
                    <SelectItem value="operator">
                      Operator (retry / cancel / bulk actions)
                    </SelectItem>
                    <SelectItem value="admin">
                      Admin (full project access)
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setOpen(false)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={mutation.isPending}>
                {mutation.isPending ? "Minting…" : "Generate invite link"}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
