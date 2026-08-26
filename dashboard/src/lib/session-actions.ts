import { api } from "@/lib/api";

/** Revoke every session owned by the caller except the request session. */
export function revokeOtherSessions(): Promise<void> {
  return api.post<void>("/auth/sessions/revoke-others");
}
