import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import type { LoginRequest, LoginResponse, UserMePublic } from "@/lib/api-types";

const ME_KEY = ["auth", "me"] as const;
const POLICY_KEY = ["auth", "policy"] as const;

/**
 * Public-readable password policy (added in 1.6.5 advisory F4).
 *
 * Pre-1.6.5 the dashboard hardcoded `minLength={8}` on password
 * inputs, but the backend default was 8 and the docs said 12 --
 * three sources of truth for one value, drifting independently.
 * 1.6.5 makes the backend authoritative; the dashboard reads
 * this hook and applies the returned `min_length` directly so
 * the field hint, validator, and backend stay in lockstep.
 */
export type PasswordPolicy = {
  min_length: number;
  required_character_classes: number;
  character_class_names: string[];
};

export function usePasswordPolicy() {
  return useQuery<PasswordPolicy, ApiError>({
    queryKey: POLICY_KEY,
    queryFn: () => api.get<PasswordPolicy>("/auth/policy"),
    staleTime: 5 * 60_000, // policy rarely changes; refetch every 5 min at most
    retry: false,
  });
}

/** Fallback when the policy fetch hasn't returned yet OR errors.
 * Matches the backend's 1.6.5 default (12) so pre-fetch renders
 * don't briefly accept passwords the backend will reject on
 * submit. Audit round-2 caught a drift here where this said 8
 * while the backend default had moved to 12 -- a UX regression
 * (not a security bypass; the backend still enforces). */
export const PASSWORD_POLICY_FALLBACK: PasswordPolicy = {
  min_length: 12,
  required_character_classes: 3,
  character_class_names: ["lowercase", "uppercase", "digit", "symbol"],
};

export function useMe() {
  return useQuery<UserMePublic, ApiError>({
    queryKey: ME_KEY,
    queryFn: () => api.get<UserMePublic>("/auth/me"),
    staleTime: 30_000,
    retry: false,
  });
}

export function useLogin() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: LoginRequest) =>
      api.post<LoginResponse>("/auth/login", body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ME_KEY });
    },
  });
}

export function useLogout() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.post<void>("/auth/logout"),
    onSuccess: () => {
      qc.clear();
    },
  });
}
