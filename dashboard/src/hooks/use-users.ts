/**
 * Hooks for the user management API (admin-only).
 */
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { api } from "@/lib/api";

export interface UserAdmin {
  id: string;
  email: string;
  first_name: string | null;
  last_name: string | null;
  display_name: string | null;
  is_admin: boolean;
  is_active: boolean;
  timezone: string;
  created_at: string;
  last_login_at: string | null;
}

export interface CreateUserRequest {
  email: string;
  password: string;
  first_name?: string | null;
  last_name?: string | null;
  display_name?: string;
  is_admin?: boolean;
}

export interface UpdateUserRequest {
  first_name?: string | null;
  last_name?: string | null;
  display_name?: string | null;
  is_admin?: boolean | null;
  is_active?: boolean | null;
  timezone?: string;
}

export function useUsers() {
  return useQuery<UserAdmin[]>({
    queryKey: ["users"],
    queryFn: () => api.get<UserAdmin[]>("/users"),
    staleTime: 60_000,
  });
}

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateUserRequest) =>
      api.post<UserAdmin>("/users", body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }),
  });
}

export function useUpdateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...body }: UpdateUserRequest & { id: string }) =>
      api.patch<UserAdmin>(`/users/${id}`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }),
  });
}

export function useChangePassword() {
  return useMutation({
    mutationFn: (body: { current_password: string; new_password: string }) =>
      api.post<void>("/auth/change-password", body),
  });
}

export function useResetUserPassword() {
  return useMutation({
    mutationFn: ({ id, new_password }: { id: string; new_password: string }) =>
      api.post<void>(`/users/${id}/password`, { new_password }),
  });
}

export function useDeleteUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.delete<void>(`/users/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }),
  });
}
