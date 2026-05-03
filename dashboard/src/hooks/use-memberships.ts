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

export type ProjectRole = "admin" | "operator" | "viewer";

/**
 * Returns the user's effective role on a given project, or ``null``
 * when they are not a member.
 *
 * Global (system) admins are treated as project admins on every
 * project - matches the backend's ``require_admin`` dependency.
 */
export function useCurrentUserRole(slug: string | undefined): ProjectRole | null {
  const { data: me } = useMe();
  if (!me || !slug) return null;
  if (me.is_admin) return "admin";
  const m = me.memberships?.find((mem) => mem.project_slug === slug);
  const role = m?.role;
  if (role === "admin" || role === "operator" || role === "viewer") {
    return role;
  }
  return null;
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
  action:
    | "view"
    | "retry_task"
    | "cancel_task"
    | "bulk_action"
    | "purge_queue"
    | "manage_schedules"
    | "manage_agents"
    | "manage_members"
    | "manage_channels"
    | "manage_invitations",
): boolean {
  const role = useCurrentUserRole(slug);
  if (role === null) return false;
  if (role === "admin") return true;
  if (role === "operator") {
    // Operators can do data-plane actions but NOT admin ones.
    switch (action) {
      case "manage_agents":
      case "manage_members":
      case "manage_channels":
      case "manage_invitations":
        return false;
      default:
        return true;
    }
  }
  // Viewers: read-only.
  return action === "view";
}
