export type ProjectlessActivityScope = "personal" | "brain-wide";

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
