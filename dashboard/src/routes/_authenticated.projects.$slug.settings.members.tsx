/**
 * Project settings - Members section.
 *
 * Lists project members with role management and removal.
 *
 * Role changes are deliberately NOT auto-save. A previous version
 * fired the PATCH the instant the Select value changed, which made
 * an accidental mousewheel scroll or stray keyboard press silently
 * alter an admin's role. Instead the Select stores a pending value
 * locally; the user sees Save / Cancel buttons and must confirm
 * explicitly. This matches enterprise settings patterns (Sentry,
 * Linear, Grafana) and avoids footguns around self-demotion.
 *
 * Last-admin protection is enforced server-side (backend refuses to
 * demote or remove the only remaining admin), and mirrored in this
 * UI so the Save button is disabled before the request even fires.
 */
import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Trash2, X } from "lucide-react";
import { toast } from "sonner";
import { useConfirm } from "@/components/domain/confirm-dialog";
import { api, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
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
import { DateCell } from "@/components/domain/date-cell";
import { InviteDialog } from "@/components/domain/invite-dialog";
import { PendingInvitations } from "@/components/domain/pending-invitations";
import { RoleBadge } from "@/components/domain/role-badge";
import { useCan, useCurrentUserRole } from "@/hooks/use-memberships";

export const Route = createFileRoute(
  "/_authenticated/projects/$slug/settings/members",
)({
  component: MembersPage,
});

interface MemberPublic {
  id: string;
  user_id: string;
  project_id: string;
  user_email: string;
  user_display_name: string | null;
  role: string;
  created_at: string;
}

function MembersPage() {
  const { slug } = Route.useParams();
  const queryClient = useQueryClient();
  const canInvite = useCan(slug, "manage_invitations");
  const myRole = useCurrentUserRole(slug);
  const { data: members, isLoading } = useQuery<MemberPublic[]>({
    queryKey: ["memberships", slug],
    queryFn: () => api.get<MemberPublic[]>(`/projects/${slug}/memberships`),
  });

  const { confirm, dialog: confirmDialog } = useConfirm();

  // pendingRoles[membership_id] is the value the user picked but has
  // not yet saved. Absent means the row is not dirty.
  const [pendingRoles, setPendingRoles] = useState<Record<string, string>>({});
  const [savingId, setSavingId] = useState<string | null>(null);

  // How many admins the project has right now. Used to disable
  // last-admin demotion in the UI before the user even hits Save.
  const adminCount = (members ?? []).filter((m) => m.role === "admin").length;

  async function saveRole(member: MemberPublic) {
    const nextRole = pendingRoles[member.id];
    if (!nextRole || nextRole === member.role) {
      // Nothing to save; just clear any pending state.
      setPendingRoles((p) => {
        const { [member.id]: _, ...rest } = p;
        return rest;
      });
      return;
    }
    setSavingId(member.id);
    try {
      await api.patch(`/projects/${slug}/memberships/${member.id}`, {
        role: nextRole,
      });
      queryClient.invalidateQueries({ queryKey: ["memberships", slug] });
      setPendingRoles((p) => {
        const { [member.id]: _, ...rest } = p;
        return rest;
      });
      toast.success(`Role updated to ${nextRole}`);
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : "Failed to update role";
      toast.error(msg);
    } finally {
      setSavingId(null);
    }
  }

  function cancelRole(memberId: string) {
    setPendingRoles((p) => {
      const { [memberId]: _, ...rest } = p;
      return rest;
    });
  }

  const handleRemove = (member: MemberPublic) => {
    // Match the server's last-admin guard in the UI so the user gets a
    // clear, up-front "why not" instead of a rejected request after
    // the confirm dialog.
    if (member.role === "admin" && adminCount <= 1) {
      toast.error(
        "Cannot remove the last admin - promote another member first",
      );
      return;
    }
    confirm({
      title: "Remove member",
      description: (
        <>
          Remove <code>{member.user_email}</code> from this project? They
          will lose access immediately.
        </>
      ),
      confirmLabel: "Remove",
      onConfirm: async () => {
        try {
          await api.delete(`/projects/${slug}/memberships/${member.id}`);
          queryClient.invalidateQueries({
            queryKey: ["memberships", slug],
          });
          toast.success("Member removed");
        } catch (err) {
          const msg =
            err instanceof ApiError
              ? err.message
              : err instanceof Error
                ? err.message
                : "Failed to remove member";
          toast.error(msg);
        }
      },
    });
  };

  return (
    <div className="space-y-6">
      {confirmDialog}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold">Project Members</h3>
            {myRole && (
              <span className="flex items-center gap-1 text-xs text-muted-foreground">
                your role:
                <RoleBadge role={myRole} />
              </span>
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            Users who have access to this project and their roles.
          </p>
        </div>
        {canInvite && <InviteDialog slug={slug} />}
      </div>

      {isLoading && <Skeleton className="h-32 w-full" />}

      {members && members.length > 0 && (
        <Card className="overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Joined</TableHead>
                <TableHead className="w-28" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {members.map((m) => {
                const pending = pendingRoles[m.id];
                const isDirty = pending !== undefined && pending !== m.role;
                const isLastAdmin = m.role === "admin" && adminCount <= 1;
                const isSaving = savingId === m.id;
                return (
                  <TableRow key={m.id}>
                    <TableCell>
                      <div>
                        <div className="font-medium">
                          {m.user_display_name || m.user_email.split("@")[0]}
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {m.user_email}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <RoleBadge role={m.role} />
                        <Select
                          value={pending ?? m.role}
                          onValueChange={(v) =>
                            setPendingRoles((p) => ({ ...p, [m.id]: v }))
                          }
                          disabled={isSaving}
                        >
                          <SelectTrigger
                            className="h-7 w-28 text-xs"
                            aria-label={`Change role for ${m.user_email}`}
                          >
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="admin">admin</SelectItem>
                            <SelectItem value="operator">
                              operator
                            </SelectItem>
                            <SelectItem
                              value="viewer"
                              disabled={isLastAdmin}
                            >
                              viewer
                            </SelectItem>
                          </SelectContent>
                        </Select>
                        {isDirty && (
                          <>
                            <Button
                              variant="default"
                              size="sm"
                              className="h-7 px-2 text-xs"
                              disabled={
                                isSaving ||
                                (isLastAdmin && pending !== "admin")
                              }
                              onClick={() => saveRole(m)}
                              aria-label="Save role change"
                            >
                              <Check className="size-3" />
                              Save
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-7 px-2 text-xs"
                              disabled={isSaving}
                              onClick={() => cancelRole(m.id)}
                              aria-label="Cancel role change"
                            >
                              <X className="size-3" />
                            </Button>
                          </>
                        )}
                        {isLastAdmin && !isDirty && (
                          <span
                            className="text-[10px] text-muted-foreground"
                            title="Promote another member to admin before changing this one"
                          >
                            last admin
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <DateCell value={m.created_at} />
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 text-xs text-destructive disabled:opacity-40"
                        onClick={() => handleRemove(m)}
                        disabled={isLastAdmin}
                        aria-label={`Remove ${m.user_email}`}
                        title={
                          isLastAdmin
                            ? "Cannot remove the last admin"
                            : "Remove member"
                        }
                      >
                        <Trash2 className="size-3" />
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </Card>
      )}

      {members && members.length === 0 && (
        <Card className="p-8 text-center text-sm text-muted-foreground">
          No members found. The project admin has automatic access.
        </Card>
      )}

      <PendingInvitations slug={slug} />
    </div>
  );
}
