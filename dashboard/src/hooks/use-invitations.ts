/**
 * Hooks for the multi-user invitation flow.
 *
 * Backend endpoints (see packages/z4j/backend/src/z4j_brain/api/invitations.py):
 *
 *   Admin (session-auth, CSRF, role=admin):
 *     POST   /projects/{slug}/invitations
 *     GET    /projects/{slug}/invitations
 *     DELETE /projects/{slug}/invitations/{id}
 *
 *   Public (anonymous, token-gated):
 *     GET    /invitations/preview?token=...
 *     POST   /invitations/accept
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

export interface InvitationPublic {
  id: string;
  project_id: string;
  email: string;
  role: string;
  invited_by: string | null;
  expires_at: string;
  accepted_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

export interface InvitationMintResponse {
  invitation: InvitationPublic;
  /** Plaintext token - shown to the admin ONCE at mint time.
   *  The server does not expose it again. */
  token: string;
  accept_url_path: string;
}

export interface InvitationPreview {
  email: string;
  role: string;
  project_slug: string;
  project_name: string;
  expires_at: string;
}

export interface InvitationAcceptResponse {
  user_id: string;
  project_slug: string;
  role: string;
}

/** List pending (non-accepted, non-revoked, non-expired) invitations for a project. */
export function useInvitations(slug: string | undefined) {
  return useQuery<InvitationPublic[]>({
    queryKey: ["invitations", slug],
    queryFn: () => api.get<InvitationPublic[]>(
      `/projects/${slug}/invitations`,
    ),
    enabled: !!slug,
    staleTime: 30_000,
  });
}

/** Admin: mint a new invitation. Response contains the plaintext token ONCE. */
export function useMintInvitation(slug: string) {
  const qc = useQueryClient();
  return useMutation<
    InvitationMintResponse,
    Error,
    { email: string; role: string; ttl_days?: number }
  >({
    mutationFn: (body) =>
      api.post<InvitationMintResponse>(
        `/projects/${slug}/invitations`,
        body,
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["invitations", slug] });
    },
  });
}

/** Admin: revoke a pending invitation. */
export function useRevokeInvitation(slug: string) {
  const qc = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (invitationId) =>
      api.delete(`/projects/${slug}/invitations/${invitationId}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["invitations", slug] });
    },
  });
}

/** Public: validate a token and fetch safe display info for the accept page. */
export function useInvitationPreview(token: string | null | undefined) {
  return useQuery<InvitationPreview>({
    queryKey: ["invitation-preview", token],
    queryFn: () => api.get<InvitationPreview>(
      `/invitations/preview`,
      { token: token as string },
    ),
    enabled: !!token,
    retry: false,
    staleTime: 60_000,
  });
}

/** Public: accept an invitation and create the invitee's user + membership. */
export function useAcceptInvitation() {
  return useMutation<
    InvitationAcceptResponse,
    Error,
    { token: string; display_name: string; password: string }
  >({
    mutationFn: (body) =>
      api.post<InvitationAcceptResponse>("/invitations/accept", body),
  });
}
