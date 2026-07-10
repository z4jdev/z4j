import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

// Response + request shapes mirror z4j_brain.api.automation_rules
// (RulePublic / RuleCreateRequest / RuleUpdateRequest). Hand-declared
// here, co-located with the hooks, matching the use-schedules.ts pattern.

export interface AutomationRulePublic {
  id: string;
  project_id: string;
  name: string;
  is_enabled: boolean;
  dry_run: boolean;
  trigger: string;
  conditions: Record<string, unknown>;
  actions: Array<Record<string, unknown>>;
  max_executions_per_window: number;
  window_seconds: number;
  cb_tripped: boolean;
  cb_execution_count: number;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface AutomationRuleCreateBody {
  name: string;
  trigger: string;
  conditions?: Record<string, unknown>;
  actions?: Array<Record<string, unknown>>;
  dry_run?: boolean;
  is_enabled?: boolean;
  max_executions_per_window?: number;
  window_seconds?: number;
}

// Partial update. Send ONLY the keys the operator changed: the backend
// 422s on an explicit JSON null for any field.
export interface AutomationRuleUpdateBody {
  name?: string;
  trigger?: string;
  conditions?: Record<string, unknown>;
  actions?: Array<Record<string, unknown>>;
  dry_run?: boolean;
  is_enabled?: boolean;
  max_executions_per_window?: number;
  window_seconds?: number;
}

export interface AutomationSettings {
  automation_enabled: boolean;
}

export function useAutomationRules(slug: string) {
  return useQuery<AutomationRulePublic[]>({
    queryKey: ["automation-rules", slug],
    queryFn: async () => {
      const page = await api.get<{ items: AutomationRulePublic[] }>(
        `/projects/${slug}/automation/rules`,
      );
      return page.items;
    },
    enabled: !!slug,
    refetchInterval: 30_000,
  });
}

export function useAutomationSettings(slug: string) {
  return useQuery<AutomationSettings>({
    queryKey: ["automation-settings", slug],
    queryFn: () =>
      api.get<AutomationSettings>(`/projects/${slug}/automation/settings`),
    enabled: !!slug,
    refetchInterval: 30_000,
  });
}

export function useSetAutomationSettings(slug: string) {
  const qc = useQueryClient();
  return useMutation<AutomationSettings, Error, boolean>({
    mutationFn: (automation_enabled) =>
      api.put<AutomationSettings>(`/projects/${slug}/automation/settings`, {
        automation_enabled,
      }),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["automation-settings", slug] }),
  });
}

export function useCreateAutomationRule(slug: string) {
  const qc = useQueryClient();
  return useMutation<AutomationRulePublic, Error, AutomationRuleCreateBody>({
    mutationFn: (body) =>
      api.post<AutomationRulePublic>(`/projects/${slug}/automation/rules`, body),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["automation-rules", slug] }),
  });
}

export function useUpdateAutomationRule(slug: string) {
  const qc = useQueryClient();
  return useMutation<
    AutomationRulePublic,
    Error,
    { ruleId: string; body: AutomationRuleUpdateBody }
  >({
    mutationFn: ({ ruleId, body }) =>
      api.patch<AutomationRulePublic>(
        `/projects/${slug}/automation/rules/${ruleId}`,
        body,
      ),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["automation-rules", slug] }),
  });
}

export function useDeleteAutomationRule(slug: string) {
  const qc = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (ruleId) =>
      api.delete<void>(`/projects/${slug}/automation/rules/${ruleId}`),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["automation-rules", slug] }),
  });
}

// Reset a tripped circuit breaker back to healthy so a rule that ran away
// (and dropped to notify-only failsafe) resumes normal execution.
export function useResetAutomationCircuit(slug: string) {
  const qc = useQueryClient();
  return useMutation<AutomationRulePublic, Error, string>({
    mutationFn: (ruleId) =>
      api.post<AutomationRulePublic>(
        `/projects/${slug}/automation/rules/${ruleId}/reset-circuit`,
      ),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["automation-rules", slug] }),
  });
}
