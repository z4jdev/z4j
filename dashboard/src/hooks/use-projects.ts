import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { ProjectPublic } from "@/lib/api-types";

export function useProjects() {
  return useQuery<ProjectPublic[]>({
    queryKey: ["projects"],
    queryFn: () => api.get<ProjectPublic[]>("/projects"),
  });
}

export function useProject(slug: string) {
  return useQuery<ProjectPublic>({
    queryKey: ["projects", slug],
    queryFn: () => api.get<ProjectPublic>(`/projects/${slug}`),
    enabled: !!slug,
  });
}

export function useCreateProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      slug: string;
      name: string;
      description?: string | null;
      environment?: string;
      retention_days?: number;
    }) => api.post<ProjectPublic>("/projects", body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["projects"] }),
  });
}

export function useUpdateProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      slug,
      ...body
    }: {
      slug: string;
      name?: string;
      description?: string | null;
      environment?: string;
      timezone?: string;
      retention_days?: number;
      new_slug?: string;
    }) => {
      const { new_slug, ...rest } = body;
      const payload: Record<string, unknown> = { ...rest };
      if (new_slug && new_slug !== slug) payload.slug = new_slug;
      return api.patch<ProjectPublic>(`/projects/${slug}`, payload);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["projects"] }),
  });
}

export function useDeleteProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (slug: string) => api.delete<void>(`/projects/${slug}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["projects"] }),
  });
}
