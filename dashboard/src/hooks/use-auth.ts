import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import type { LoginRequest, LoginResponse, UserMePublic } from "@/lib/api-types";

const ME_KEY = ["auth", "me"] as const;

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
