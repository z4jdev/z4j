import type { AgentPublic } from "@/lib/api-types";

type AgentInventoryFields = Pick<
  AgentPublic,
  "engine_adapters" | "capabilities" | "last_connect_at"
>;
type AgentCandidateFields = AgentInventoryFields &
  Pick<AgentPublic, "last_seen_at">;
type AgentAction = "retry_task" | "cancel_task";

/**
 * Whether the brain holds this agent's adapter inventory.
 *
 * Only a WebSocket ``hello`` records ``engine_adapters``, ``capabilities`` and
 * ``last_connect_at``. The long-poll transport sends no hello, so its row
 * keeps the empty inventory it was minted with: unreported, not "no engines".
 * A connected agent that listed no engines (a scheduler-only process) has
 * reported, and stays excluded from task commands.
 */
export function reportsAdapterInventory(
  agent: Pick<AgentPublic, "engine_adapters" | "last_connect_at">,
): boolean {
  return agent.last_connect_at != null || agent.engine_adapters.length > 0;
}

/** HELLO advertises a list per adapter, not a flat action-to-boolean map. */
export function supportsAgentAction(
  agent: AgentInventoryFields | undefined,
  engine: string,
  action: AgentAction,
): boolean {
  if (!agent) return false;
  // Nothing to compare against. The brain still admits each delivery against
  // the receiving session; long-poll states its retry contracts on every poll.
  if (!reportsAdapterInventory(agent)) return true;
  if (!agent.engine_adapters.includes(engine)) return false;
  const advertised = agent.capabilities[engine];
  if (!Array.isArray(advertised) || !advertised.includes(action)) return false;
  // Match the server's safe retry-by-reference admission contract.
  return (
    action !== "retry_task" || advertised.includes("retry_by_reference_v1")
  );
}

/**
 * Agents that may own a task on ``engine``, in the brain's order: each agent
 * whose hello listed the engine, and each agent that never reported any but
 * has uploaded frames. A token that never connected cannot own a task and is
 * not a candidate.
 */
export function agentsForEngine<T extends AgentCandidateFields>(
  agents: readonly T[] | undefined,
  engine: string,
): T[] {
  return (
    agents?.filter((agent) =>
      reportsAdapterInventory(agent)
        ? agent.engine_adapters.includes(engine)
        : agent.last_seen_at != null,
    ) ?? []
  );
}

/**
 * A command target chosen without operator input, from the same candidates.
 * An agent whose hello advertised the action wins over one whose inventory
 * is unreported.
 */
export function pickAgentForAction<T extends AgentCandidateFields>(
  agents: readonly T[],
  engine: string,
  action: AgentAction,
): T | undefined {
  const capable = agentsForEngine(agents, engine).filter((agent) =>
    supportsAgentAction(agent, engine, action),
  );
  return capable.find((agent) => reportsAdapterInventory(agent)) ?? capable[0];
}

/**
 * Pair every row with a command target before anything is sent, and name the
 * engines no agent can act on. A caller sends nothing unless ``unserved`` is
 * empty, so a selection is never left partly done.
 */
export function resolveCommandTargets<
  R extends { engine: string },
  T extends AgentCandidateFields & Pick<AgentPublic, "id">,
>(
  agents: readonly T[],
  rows: readonly R[],
  action: AgentAction,
): { targets: { row: R; agent: T }[]; unserved: string[] } {
  const targets: { row: R; agent: T }[] = [];
  const unserved = new Set<string>();
  for (const row of rows) {
    const agent = pickAgentForAction(agents, row.engine, action);
    if (agent) {
      targets.push({ row, agent });
    } else {
      unserved.add(row.engine);
    }
  }
  return { targets, unserved: [...unserved] };
}

