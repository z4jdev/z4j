/**
 * Membership + role helpers.
 *
 * The current user's memberships are included on `/auth/me` as
 * `memberships: { project_id, project_slug, role }[]`, so we can
 * answer "is this user a project admin?" - and every downstream
 * role/permission question - without extra API calls.
 *
 * Backend enforces RBAC on every mutating endpoint
 * (see api/deps.py + domain/policy_engine.py). These hooks are the
 * *UI-side* mirror of that: we hide buttons the user can't click
 * rather than flashing a 403 after they click.
 */
import { useMe } from "@/hooks/use-auth";

export type ProjectRole = "admin" | "operator" | "auditor" | "viewer";

export const PROJECT_ROLES: readonly ProjectRole[] = [
  "viewer",
  "auditor",
  "operator",
  "admin",
] as const;

export function isProjectRole(value: unknown): value is ProjectRole {
  return (
    typeof value === "string" &&
    (PROJECT_ROLES as readonly string[]).includes(value)
  );
}

export type ProjectCapability =
  | "view"
  /** Read, export and verify the audit trail: auditor and admin only. */
  | "read_audit"
  | "retry_task"
  | "cancel_task"
  | "delete_tasks"
  | "bulk_action"
  | "purge_queue"
  | "operate_schedules"
  | "admin_schedules"
  /** @deprecated Use operate_schedules or admin_schedules for schedule UI. */
  | "manage_schedules"
  | "manage_automation"
  | "manage_agents"
  | "manage_members"
  | "manage_channels"
  | "manage_invitations";

/** Pure role matrix shared by the hook and fail-sensitive unit tests.
 *
 * Mirrors ``z4j_core.policy``: admin holds everything; viewer reads;
 * auditor reads plus the audit trail and nothing else; operator acts
 * on the data plane and does not read the audit trail. Auditor and
 * operator are siblings, neither inherits the other. */
export function canProjectRole(
  role: ProjectRole | null,
  action: ProjectCapability,
): boolean {
  if (role === null) return false;
  if (role === "admin") return true;
  if (role === "viewer") return action === "view";
  if (role === "auditor") return action === "view" || action === "read_audit";

  // Operators can execute data-plane actions but cannot mutate admin-owned
  // definitions, perform admin-only destructive operations, or read the
  // audit trail.
  switch (action) {
    case "read_audit":
      return false;
    case "view":
    case "retry_task":
    case "cancel_task":
    case "bulk_action":
    case "purge_queue":
    case "operate_schedules":
    case "manage_schedules":
    case "manage_automation":
      return true;
    case "delete_tasks":
    case "admin_schedules":
    case "manage_agents":
    case "manage_members":
    case "manage_channels":
    case "manage_invitations":
      return false;
  }
}

/**
 * Returns the user's effective role on a given project, or ``null``
 * when they are not a member.
 *
 * Global (system) admins are treated as project admins on every
 * project - matches the backend's ``require_admin`` dependency.
 */
export function useCurrentUserRole(
  slug: string | undefined,
): ProjectRole | null {
  const { data: me } = useMe();
  if (!me || !slug) return null;
  if (me.is_admin) return "admin";
  const m = me.memberships?.find((mem) => mem.project_slug === slug);
  const role = m?.role;
  return isProjectRole(role) ? role : null;
}

export function useIsProjectAdmin(slug: string): boolean {
  return useCurrentUserRole(slug) === "admin";
}

export function useIsProjectOperator(slug: string): boolean {
  const role = useCurrentUserRole(slug);
  return role === "admin" || role === "operator";
}

export function useIsProjectMember(slug: string): boolean {
  return useCurrentUserRole(slug) !== null;
}

/**
 * Capability-check hook - answers "can the current user do action X
 * on this project?" Centralised so a single source decides what
 * each role can do, matching the server-side policy table.
 */
export function useCan(
  slug: string | undefined,
  action: ProjectCapability,
): boolean {
  return canProjectRole(useCurrentUserRole(slug), action);
}
