import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { DeadLetterPage } from "@/lib/api-types";

export interface DeadLetterFilters {
  /** Required: the listing is one engine's dead-letter store. */
  engine: string;
  queue?: string;
  cursor?: string | null;
  limit?: number;
}

/**
 * One page of an engine's dead letters, read live through the agent.
 *
 * The brain issues a ``dlq.list`` command and waits for the agent's answer,
 * so a request can take a few seconds and can fail with 409 (no online agent
 * advertises ``list_dead_letters`` for the engine) or 504 (the agent did not
 * answer in time). Neither is transient enough to retry silently, which is
 * why ``retry`` is off: the page shows the reason and offers a refresh.
 */
export function useDeadLetters(slug: string, filters: DeadLetterFilters) {
  return useQuery<DeadLetterPage>({
    queryKey: ["dead-letters", slug, filters],
    queryFn: () =>
      api.get<DeadLetterPage>(`/projects/${slug}/dead-letters`, {
        engine: filters.engine,
        queue: filters.queue || undefined,
        cursor: filters.cursor ?? undefined,
        limit: filters.limit ?? 50,
      }),
    enabled: !!slug && !!filters.engine,
    placeholderData: keepPreviousData,
    staleTime: 10_000,
    retry: false,
  });
}
