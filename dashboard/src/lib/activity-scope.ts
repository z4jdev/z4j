import { canProjectRole, type ProjectRole } from "@/hooks/use-memberships";

export type ProjectlessActivityScope = "personal" | "brain-wide";

/** The slice of ``/auth/me`` the feed's project scope is decided from. */
export interface ActivityCaller {
  is_admin: boolean;
  memberships: readonly { project_slug: string; role: ProjectRole }[];
}

/**
 * Whether the caller holds the audit tier anywhere: an instance admin, or
 * the auditor or admin role on at least one project. Without it the feed
 * carries only the caller's own user-scoped rows, so there is no project
 * to filter by.
 */
export function holdsAuditTier(caller: ActivityCaller): boolean {
  return (
    caller.is_admin ||
    caller.memberships.some((m) => canProjectRole(m.role, "read_audit"))
  );
}

/**
 * The projects whose rows the caller may see in the feed: every project
 * for an instance admin, else those where the caller's role satisfies
 * ``read_audit``. Mirrors the brain's scope rule, so the filter never
 * offers a project that would only answer an empty page.
 */
export function auditableProjects<T extends { slug: string }>(
  caller: ActivityCaller | undefined,
  projects: readonly T[],
): T[] {
  if (!caller) return [];
  if (caller.is_admin) return [...projects];
  const readable = new Set(
    caller.memberships
      .filter((m) => canProjectRole(m.role, "read_audit"))
      .map((m) => m.project_slug),
  );
  return projects.filter((p) => readable.has(p.slug));
}

/** Label a project-less activity row from the identities actually rendered. */
export function projectlessActivityScope(
  rowUserId: string | null,
  currentUserId: string | null,
): ProjectlessActivityScope {
  return currentUserId !== null &&
    rowUserId !== null &&
    rowUserId === currentUserId
    ? "personal"
    : "brain-wide";
}
