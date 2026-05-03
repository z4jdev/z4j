import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type {
  AgentPublic,
  CreateAgentRequest,
  CreateAgentResponse,
} from "@/lib/api-types";

export function useAgents(slug: string) {
  return useQuery<AgentPublic[]>({
    queryKey: ["agents", slug],
    queryFn: () => api.get<AgentPublic[]>(`/projects/${slug}/agents`),
    enabled: !!slug,
    // Live updates arrive via /ws/dashboard agent.changed.
    staleTime: 30_000,
  });
}

export function useCreateAgent(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateAgentRequest) =>
      api.post<CreateAgentResponse>(`/projects/${slug}/agents`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agents", slug] });
      qc.invalidateQueries({ queryKey: ["stats", slug] });
    },
  });
}

export function useRevokeAgent(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (agentId: string) =>
      api.delete<void>(`/projects/${slug}/agents/${agentId}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agents", slug] });
      qc.invalidateQueries({ queryKey: ["stats", slug] });
    },
  });
}
