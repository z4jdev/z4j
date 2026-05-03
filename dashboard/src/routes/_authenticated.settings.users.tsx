/**
 * User management settings page - admin only.
 *
 * List, create, activate/deactivate, and change roles for users.
 * Moved from the standalone admin route into the unified settings hub.
 */
import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import {
  KeyRound,
  Pencil,
  Plus,
  Shield,
  ShieldOff,
  Trash2,
  UserCheck,
  UserX,
  Users,
} from "lucide-react";
import { toast } from "sonner";
import { EmptyState } from "@/components/domain/empty-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  type UserAdmin,
  useCreateUser,
  useDeleteUser,
  useResetUserPassword,
  useUpdateUser,
  useUsers,
} from "@/hooks/use-users";
import { useConfirm } from "@/components/domain/confirm-dialog";
import { QueryError } from "@/components/domain/query-error";
import { useMe } from "@/hooks/use-auth";
import { DateCell } from "@/components/domain/date-cell";
import { PageHeader } from "@/components/domain/page-header";
import { ApiError } from "@/lib/api";

export const Route = createFileRoute("/_authenticated/settings/users")({
  component: UsersPage,
});

function UsersPage() {
  const { data: users, isLoading, isError, error, refetch } = useUsers();
  const { data: me } = useMe();
  const updateUser = useUpdateUser();
  const deleteUser = useDeleteUser();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editUser, setEditUser] = useState<UserAdmin | null>(null);
  const [resetPwUser, setResetPwUser] = useState<UserAdmin | null>(null);
  const { confirm, dialog: confirmDialog } = useConfirm();

  // Count of currently-active global admins. Used to disable the
  // "remove admin" / "deactivate" actions on the only remaining one
  // so the user sees "why not" up front instead of a 409 after the
  // click. Backend enforces the same invariant.
  const activeAdminCount = (users ?? []).filter(
    (u) => u.is_admin && u.is_active,
  ).length;

  const onError = (err: unknown) => {
    const msg =
      err instanceof ApiError
        ? err.message
        : err instanceof Error
          ? err.message
          : "Request failed";
    toast.error(msg);
  };

  const toggleActive = (id: string, currentlyActive: boolean) => {
    updateUser.mutate(
      { id, is_active: !currentlyActive },
      {
        onSuccess: () =>
          toast.success(currentlyActive ? "User deactivated" : "User activated"),
        onError,
      },
    );
  };

  const toggleAdmin = (id: string, currentlyAdmin: boolean) => {
    updateUser.mutate(
      { id, is_admin: !currentlyAdmin },
      {
        onSuccess: () =>
          toast.success(
            currentlyAdmin ? "Admin role removed" : "Admin role granted",
          ),
        onError,
      },
    );
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Users"
        description="Manage user accounts, roles, and access."
        actions={
          <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus className="size-4" />
                Add User
              </Button>
            </DialogTrigger>
            <DialogContent>
              <CreateUserDialog onCreated={() => setDialogOpen(false)} />
            </DialogContent>
          </Dialog>
        }
      />

      {isLoading && <Skeleton className="h-64 w-full" />}
      {isError && (
        <QueryError
          message={error instanceof Error ? error.message : "Failed to load users"}
          onRetry={() => refetch()}
        />
      )}
      {users && users.length === 0 && (
        <EmptyState
          icon={Users}
          title="No users"
          description="This shouldn't happen - at least the admin user should exist."
        />
      )}
      {users && users.length > 0 && (
        <Card className="overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last Login</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map((user) => {
                const isSelf = me?.id === user.id;
                // A row is "last-admin protected" when demoting OR
                // deactivating this user would bring the active-admin
                // count to zero.
                const isLastActiveAdmin =
                  user.is_admin && user.is_active && activeAdminCount <= 1;
                // Demote is blocked if it's self OR if this is the
                // last active admin.
                const demoteBlocked =
                  user.is_admin && (isSelf || isLastActiveAdmin);
                // Deactivate is blocked for the same reasons, on an
                // already-active user only.
                const deactivateBlocked =
                  user.is_active &&
                  ((user.is_admin && isLastActiveAdmin) || isSelf);

                let demoteTitle: string;
                if (!user.is_admin) demoteTitle = "Grant admin role";
                else if (isSelf) demoteTitle = "Cannot remove your own admin role";
                else if (isLastActiveAdmin)
                  demoteTitle =
                    "Cannot remove the last admin - promote another user first";
                else demoteTitle = "Remove admin role";

                let deactivateTitle: string;
                if (!user.is_active) deactivateTitle = "Activate user";
                else if (isSelf) deactivateTitle = "Cannot deactivate your own account";
                else if (user.is_admin && isLastActiveAdmin)
                  deactivateTitle =
                    "Cannot deactivate the last admin - promote another user first";
                else deactivateTitle = "Deactivate user";

                return (
                  <TableRow key={user.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <div>
                          <div className="font-medium">
                            {user.display_name || user.email.split("@")[0]}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {user.email}
                          </div>
                        </div>
                        {isSelf && (
                          <Badge variant="muted" className="text-[10px]">
                            you
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Badge variant={user.is_admin ? "default" : "muted"}>
                          {user.is_admin ? "admin" : "user"}
                        </Badge>
                        {isLastActiveAdmin && (
                          <span
                            className="text-[10px] text-muted-foreground"
                            title="Promote another user to admin before changing this one"
                          >
                            last admin
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={user.is_active ? "success" : "destructive"}
                      >
                        {user.is_active ? "active" : "inactive"}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {user.last_login_at ? (
                        <DateCell value={user.last_login_at} />
                      ) : (
                        "Never"
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          title="Edit profile"
                          aria-label="Edit profile"
                          onClick={() => setEditUser(user)}
                        >
                          <Pencil className="size-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          title="Reset password"
                          aria-label="Reset password"
                          onClick={() => setResetPwUser(user)}
                        >
                          <KeyRound className="size-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          title={demoteTitle}
                          aria-label={demoteTitle}
                          disabled={demoteBlocked}
                          className="disabled:opacity-40"
                          onClick={() =>
                            toggleAdmin(user.id, user.is_admin)
                          }
                        >
                          {user.is_admin ? (
                            <ShieldOff className="size-4" />
                          ) : (
                            <Shield className="size-4" />
                          )}
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          title={deactivateTitle}
                          aria-label={deactivateTitle}
                          disabled={deactivateBlocked}
                          className="disabled:opacity-40"
                          onClick={() =>
                            toggleActive(user.id, user.is_active)
                          }
                        >
                          {user.is_active ? (
                            <UserX className="size-4 text-destructive" />
                          ) : (
                            <UserCheck className="size-4 text-success" />
                          )}
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          title={
                            isSelf
                              ? "Cannot delete your own account"
                              : user.is_admin && isLastActiveAdmin
                                ? "Cannot delete the last admin - promote another user first"
                                : "Delete user"
                          }
                          aria-label="Delete user"
                          disabled={
                            isSelf || (user.is_admin && isLastActiveAdmin)
                          }
                          className="disabled:opacity-40"
                          onClick={() =>
                            confirm({
                              title: "Delete user",
                              description: (
                                <>
                                  Permanently delete{" "}
                                  <code>{user.email}</code>? Their
                                  memberships, sessions and personal
                                  channels are removed; audit rows are
                                  anonymised. This cannot be undone.
                                </>
                              ),
                              confirmLabel: "Delete",
                              onConfirm: () => {
                                deleteUser.mutate(user.id, {
                                  onSuccess: () =>
                                    toast.success("User deleted"),
                                  onError,
                                });
                              },
                            })
                          }
                        >
                          <Trash2 className="size-4 text-destructive" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </Card>
      )}

      {confirmDialog}

      <Dialog
        open={editUser !== null}
        onOpenChange={(open) => {
          if (!open) setEditUser(null);
        }}
      >
        <DialogContent>
          {editUser && (
            <EditUserDialog
              user={editUser}
              onSaved={() => setEditUser(null)}
            />
          )}
        </DialogContent>
      </Dialog>

      <Dialog
        open={resetPwUser !== null}
        onOpenChange={(open) => {
          if (!open) setResetPwUser(null);
        }}
      >
        <DialogContent>
          {resetPwUser && (
            <ResetPasswordDialog
              user={resetPwUser}
              onDone={() => setResetPwUser(null)}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

function CreateUserDialog({ onCreated }: { onCreated: () => void }) {
  const createUser = useCreateUser();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [isAdmin, setIsAdmin] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createUser.mutate(
      {
        email,
        password,
        first_name: firstName.trim() || null,
        last_name: lastName.trim() || null,
        display_name: displayName.trim() || undefined,
        is_admin: isAdmin,
      },
      {
        onSuccess: () => {
          toast.success("User created");
          onCreated();
        },
        onError: (err) => toast.error(`Failed: ${err.message}`),
      },
    );
  };

  return (
    <form onSubmit={handleSubmit}>
      <DialogHeader>
        <DialogTitle>Create User</DialogTitle>
      </DialogHeader>
      <div className="mt-4 space-y-4">
        <div className="space-y-2">
          <Label htmlFor="create-user-email">Email</Label>
          <Input
            id="create-user-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-2">
            <Label htmlFor="create-user-first">First name</Label>
            <Input
              id="create-user-first"
              value={firstName}
              onChange={(e) => setFirstName(e.target.value)}
              maxLength={100}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="create-user-last">Last name</Label>
            <Input
              id="create-user-last"
              value={lastName}
              onChange={(e) => setLastName(e.target.value)}
              maxLength={100}
            />
          </div>
        </div>
        <div className="space-y-2">
          <Label htmlFor="create-user-display">
            Display name{" "}
            <span className="text-xs text-muted-foreground">(optional)</span>
          </Label>
          <Input
            id="create-user-display"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder="Derived from first + last if blank"
            maxLength={200}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="create-user-password">Password</Label>
          <Input
            id="create-user-password"
            type="password"
            minLength={8}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        <div className="flex items-center gap-2">
          <Switch
            id="create-user-admin"
            checked={isAdmin}
            onCheckedChange={setIsAdmin}
          />
          <Label htmlFor="create-user-admin">Admin role</Label>
        </div>
      </div>
      <DialogFooter className="mt-6">
        <Button type="submit" disabled={createUser.isPending}>
          {createUser.isPending ? "Creating..." : "Create User"}
        </Button>
      </DialogFooter>
    </form>
  );
}

function EditUserDialog({
  user,
  onSaved,
}: {
  user: UserAdmin;
  onSaved: () => void;
}) {
  const updateUser = useUpdateUser();
  const [firstName, setFirstName] = useState(user.first_name ?? "");
  const [lastName, setLastName] = useState(user.last_name ?? "");
  const [displayName, setDisplayName] = useState(user.display_name ?? "");
  const [timezone, setTimezone] = useState(user.timezone);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    updateUser.mutate(
      {
        id: user.id,
        first_name: firstName.trim() || null,
        last_name: lastName.trim() || null,
        display_name: displayName.trim() || null,
        timezone,
      },
      {
        onSuccess: () => {
          toast.success("User updated");
          onSaved();
        },
        onError: (err) => toast.error(`Failed: ${err.message}`),
      },
    );
  };

  return (
    <form onSubmit={handleSubmit}>
      <DialogHeader>
        <DialogTitle>Edit user</DialogTitle>
      </DialogHeader>
      <div className="mt-4 space-y-4">
        <div className="space-y-2">
          <Label htmlFor="edit-user-email">Email</Label>
          <Input
            id="edit-user-email"
            value={user.email}
            readOnly
            disabled
          />
          <p className="text-xs text-muted-foreground">
            Email is the user's login identity and cannot be changed here.
          </p>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-2">
            <Label htmlFor="edit-user-first">First name</Label>
            <Input
              id="edit-user-first"
              value={firstName}
              onChange={(e) => setFirstName(e.target.value)}
              maxLength={100}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="edit-user-last">Last name</Label>
            <Input
              id="edit-user-last"
              value={lastName}
              onChange={(e) => setLastName(e.target.value)}
              maxLength={100}
            />
          </div>
        </div>
        <div className="space-y-2">
          <Label htmlFor="edit-user-display">
            Display name{" "}
            <span className="text-xs text-muted-foreground">(optional)</span>
          </Label>
          <Input
            id="edit-user-display"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder="Derived from first + last if blank"
            maxLength={200}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="edit-user-tz">Timezone</Label>
          <Input
            id="edit-user-tz"
            value={timezone}
            onChange={(e) => setTimezone(e.target.value)}
            placeholder="UTC"
            maxLength={64}
          />
          <p className="text-xs text-muted-foreground">
            IANA timezone, e.g. <code>America/New_York</code>.
          </p>
        </div>
      </div>
      <DialogFooter className="mt-6">
        <Button
          type="submit"
          disabled={updateUser.isPending}
        >
          {updateUser.isPending ? "Saving..." : "Save changes"}
        </Button>
      </DialogFooter>
    </form>
  );
}

function ResetPasswordDialog({
  user,
  onDone,
}: {
  user: UserAdmin;
  onDone: () => void;
}) {
  const resetPw = useResetUserPassword();
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const mismatch =
    confirmPassword.length > 0 && password !== confirmPassword;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (mismatch) return;
    resetPw.mutate(
      { id: user.id, new_password: password },
      {
        onSuccess: () => {
          toast.success(
            "Password reset. All existing sessions for this user are revoked.",
          );
          onDone();
        },
        onError: (err) => toast.error(`Failed: ${err.message}`),
      },
    );
  };

  return (
    <form onSubmit={handleSubmit}>
      <DialogHeader>
        <DialogTitle>Reset password</DialogTitle>
      </DialogHeader>
      <div className="mt-4 space-y-4">
        <p className="text-xs text-muted-foreground">
          Sets a new password for <code>{user.email}</code> and
          signs them out of every active session. Deliver the new
          password out of band.
        </p>
        <div className="space-y-2">
          <Label htmlFor="reset-pwd-new">New password</Label>
          <Input
            id="reset-pwd-new"
            type="password"
            minLength={8}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="reset-pwd-confirm">Confirm password</Label>
          <Input
            id="reset-pwd-confirm"
            type="password"
            minLength={8}
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
          />
          {mismatch && (
            <p className="text-xs text-destructive">
              Passwords do not match.
            </p>
          )}
        </div>
      </div>
      <DialogFooter className="mt-6">
        <Button
          type="submit"
          variant="destructive"
          disabled={resetPw.isPending || password.length < 8 || mismatch}
        >
          {resetPw.isPending ? "Resetting..." : "Reset password"}
        </Button>
      </DialogFooter>
    </form>
  );
}
