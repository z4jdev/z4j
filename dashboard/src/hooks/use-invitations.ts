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
 *     POST   /invitations/preview  { token }
 *     POST   /invitations/accept
 */
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, apiCall } from "@/lib/api";

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

interface InvitationPreviewState {
  data: InvitationPreview | undefined;
  isLoading: boolean;
  isError: boolean;
}

const EMPTY_PREVIEW: InvitationPreviewState = {
  data: undefined,
  isLoading: false,
  isError: false,
};

/** List pending (non-accepted, non-revoked, non-expired) invitations for a project. */
export function useInvitations(slug: string | undefined) {
  return useQuery<InvitationPublic[]>({
    queryKey: ["invitations", slug],
    queryFn: () => api.get<InvitationPublic[]>(`/projects/${slug}/invitations`),
    enabled: !!slug,
    staleTime: 30_000,
  });
}

/**
 * Admin: mint a new invitation. Response contains the plaintext token ONCE.
 *
 * The response and input deliberately bypass React Query's mutation cache.
 * The caller owns the one-time response only for as long as it needs to show
 * the link; this hook retains only a pending counter and invalidates the
 * non-secret pending-invitations query after success.
 */
export function useMintInvitation(slug: string) {
  const qc = useQueryClient();
  const [isPending, setIsPending] = useState(false);
  const mounted = useRef(true);
  const pendingCount = useRef(0);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const mutateAsync = useCallback(
    async (body: {
      email: string;
      role: string;
      ttl_days?: number;
    }): Promise<InvitationMintResponse> => {
      pendingCount.current += 1;
      if (mounted.current) setIsPending(true);
      try {
        const response = await api.post<InvitationMintResponse>(
          `/projects/${slug}/invitations`,
          body,
        );
        void qc.invalidateQueries({ queryKey: ["invitations", slug] });
        return response;
      } finally {
        pendingCount.current -= 1;
        if (mounted.current && pendingCount.current === 0) {
          setIsPending(false);
        }
      }
    },
    [qc, slug],
  );

  return { isPending, mutateAsync };
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

/**
 * Public: validate a token and fetch safe display info for the accept page.
 *
 * This request intentionally does not use React Query. A bearer token in a
 * query key or mutation variable is visible in cache inspection and devtools;
 * the preview response only needs component-local lifetime. The token travels
 * in a JSON POST body and errors are reduced to a boolean, so neither request
 * metadata nor retained error state contains the credential.
 */
export function useInvitationPreview(token: string | null | undefined) {
  const [state, setState] = useState<InvitationPreviewState>(() =>
    token ? { ...EMPTY_PREVIEW, isLoading: true } : EMPTY_PREVIEW,
  );

  // Clear a previous token's display data before the browser paints a token
  // change. Only non-secret response data is retained in component state.
  useLayoutEffect(() => {
    setState(token ? { ...EMPTY_PREVIEW, isLoading: true } : EMPTY_PREVIEW);
  }, [token]);

  useEffect(() => {
    if (!token) return;

    let active = true;
    let controller: AbortController | undefined;

    // Scheduling the call avoids React StrictMode's development-only first
    // setup/cleanup pass issuing a duplicate rate-limited preview request.
    queueMicrotask(() => {
      if (!active) return;
      controller = new AbortController();
      void apiCall<InvitationPreview>("/invitations/preview", {
        method: "POST",
        body: { token },
        signal: controller.signal,
      }).then(
        (data) => {
          if (active) setState({ data, isLoading: false, isError: false });
        },
        () => {
          if (active) {
            setState({ data: undefined, isLoading: false, isError: true });
          }
        },
      );
    });

    return () => {
      active = false;
      controller?.abort();
    };
  }, [token]);

  return state;
}

/**
 * Public: accept an invitation and create the invitee's user + membership.
 *
 * This small local mutation intentionally keeps the bearer token out of React
 * Query's mutation cache and devtools metadata. It retains only a pending
 * counter; the request body exists solely for the lifetime of the fetch.
 */
export function useAcceptInvitation() {
  const [isPending, setIsPending] = useState(false);
  const mounted = useRef(true);
  const pendingCount = useRef(0);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const mutateAsync = useCallback(
    async (body: {
      token: string;
      display_name: string;
      password: string;
    }): Promise<InvitationAcceptResponse> => {
      pendingCount.current += 1;
      if (mounted.current) setIsPending(true);
      try {
        return await api.post<InvitationAcceptResponse>(
          "/invitations/accept",
          body,
        );
      } finally {
        pendingCount.current -= 1;
        if (mounted.current && pendingCount.current === 0) {
          setIsPending(false);
        }
      }
    },
    [],
  );

  return { isPending, mutateAsync };
}
