import { sortTimestamp } from "@/lib/table-sorting";
/**
 * Pending-invitations table - shown on the Members admin page below
 * the active members list. Lets admins revoke outstanding invites
 * before they're accepted.
 */
import { Trash2 } from "lucide-react";
import { toast } from "sonner";

import { useConfirm } from "@/components/domain/confirm-dialog";
import { DateCell } from "@/components/domain/date-cell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  useInvitations,
  useRevokeInvitation,
  type InvitationPublic,
} from "@/hooks/use-invitations";
import { ApiError } from "@/lib/api";

export function PendingInvitations({ slug }: { slug: string }) {
  const { data: pending, isLoading } = useInvitations(slug);
  const { confirm, dialog } = useConfirm();
  const revoke = useRevokeInvitation(slug);

  const handleRevoke = (inv: InvitationPublic) => {
    confirm({
      title: "Revoke invitation",
      description: (
        <>
          Revoke the invitation for <code>{inv.email}</code>? The link becomes
          unusable. You can always send a fresh invitation later.
        </>
      ),
      confirmLabel: "Revoke",
      onConfirm: async () => {
        try {
          await revoke.mutateAsync(inv.id);
          toast.success("Invitation revoked");
        } catch (err) {
          const msg =
            err instanceof ApiError
              ? err.message
              : err instanceof Error
                ? err.message
                : "Revoke failed";
          toast.error(msg);
        }
      },
    });
  };

  if (isLoading) return null;
  if (!pending || pending.length === 0) return null;

  return (
    <>
      {dialog}
      <div className="space-y-2">
        <h3 className="text-sm font-semibold">Pending invitations</h3>
        <p className="text-xs text-muted-foreground">
          Teammates with an active invite link that hasn't been accepted yet.
        </p>
      </div>
      <Card className="overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead sortKey="c0">Email</TableHead>
              <TableHead sortKey="c1">Role</TableHead>
              <TableHead sortKey="c2">Expires</TableHead>
              <TableHead sortKey="c3">Sent</TableHead>
              <TableHead className="text-right w-[80px]">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {pending.map((inv) => (
              <TableRow
                sortValues={{
                  c0: inv.email,
                  c1: inv.role,
                  c2: sortTimestamp(inv.expires_at),
                  c3: sortTimestamp(inv.created_at),
                }}
                key={inv.id}
              >
                <TableCell className="font-mono text-sm">{inv.email}</TableCell>
                <TableCell>
                  <Badge variant="outline">{inv.role}</Badge>
                </TableCell>
                <TableCell>
                  <DateCell value={inv.expires_at} />
                </TableCell>
                <TableCell>
                  <DateCell value={inv.created_at} />
                </TableCell>
                <TableCell className="text-right">
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={() => handleRevoke(inv)}
                    aria-label={`revoke invitation for ${inv.email}`}
                  >
                    <Trash2 className="size-4" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Card>
    </>
  );
}
