/**
 * Live-updates hook for the dashboard.
 *
 * Mounted once at the project layout level
 * (``_authenticated.projects.$slug.tsx``). Resolves the slug to a
 * project_id via the cached ``useMe`` response, opens a
 * :class:`DashboardSocket`, and on every inbound topic invalidates
 * the matching TanStack Query keys so the existing per-page
 * REST hooks refetch on the next render.
 *
 * Topic → invalidation map (V1):
 *
 *   task.changed     → ["tasks", slug],   ["stats", slug]
 *   command.changed  → ["commands", slug], ["tasks", slug]
 *   agent.changed    → ["agents", slug],   ["stats", slug]
 *
 * z4j emits one topic per "thing changed" - never per row -
 * so a high-volume agent doesn't drown the dashboard in invalidations.
 */
import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  DashboardSocket,
  type DashboardEvent,
  type DashboardSocketStatus,
} from "@/lib/dashboard-socket";
import { useMe } from "@/hooks/use-auth";

export interface UseDashboardSocketResult {
  /** Connection status - useful for a small "live" indicator. */
  status: DashboardSocketStatus;
  /** True once the project_id resolves and the socket is open. */
  ready: boolean;
}

export function useDashboardSocket(slug: string): UseDashboardSocketResult {
  const qc = useQueryClient();
  const { data: me } = useMe();
  const [status, setStatus] = useState<DashboardSocketStatus>("connecting");
  const socketRef = useRef<DashboardSocket | null>(null);

  // Resolve slug → project_id from cached memberships. Admins
  // without an explicit membership for the slug fall back to
  // matching by slug across the membership list (V1: a project
  // they don't belong to as a user simply doesn't appear; the
  // backend will close 4403 anyway).
  const projectId = me?.memberships.find((m) => m.project_slug === slug)
    ?.project_id;

  useEffect(() => {
    if (!projectId) return;

    const socket = new DashboardSocket({
      projectId,
      onEvent: (event: DashboardEvent) => {
        switch (event.topic) {
          case "task.changed":
            qc.invalidateQueries({ queryKey: ["tasks", slug] });
            qc.invalidateQueries({ queryKey: ["stats", slug] });
            // Task-detail event timeline reads from ["events",slug,...]
            // - refresh it on any task mutation in this project.
            qc.invalidateQueries({ queryKey: ["events", slug] });
            break;
          case "command.changed":
            qc.invalidateQueries({ queryKey: ["commands", slug] });
            qc.invalidateQueries({ queryKey: ["tasks", slug] });
            break;
          case "agent.changed":
            qc.invalidateQueries({ queryKey: ["agents", slug] });
            qc.invalidateQueries({ queryKey: ["stats", slug] });
            break;
        }
      },
      onStatusChange: setStatus,
    });
    socketRef.current = socket;

    return () => {
      socket.close();
      socketRef.current = null;
    };
    // Re-open the socket if the project changes (slug navigation)
    // or the user resolves later than the first render.
  }, [projectId, slug, qc]);

  return {
    status,
    ready: status === "open" && projectId !== undefined,
  };
}
