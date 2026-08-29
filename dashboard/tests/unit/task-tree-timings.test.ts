/**
 * nodeTimings splits a task's span into queue wait and execution. A worker
 * clock ahead of the brain's must not produce a negative segment.
 */
import { describe, expect, it } from "vitest";

import { nodeTimings } from "@/components/domain/task-tree";
import type { TaskTreeNode } from "@/hooks/use-tasks";

function node(overrides: Partial<TaskTreeNode>): TaskTreeNode {
  return {
    task_id: "t",
    name: "n",
    state: "success",
    parent_task_id: null,
    root_task_id: null,
    received_at: "2026-08-28T10:00:00.000Z",
    started_at: "2026-08-28T10:04:00.000Z",
    finished_at: "2026-08-28T10:04:00.040Z",
    ...overrides,
  } as TaskTreeNode;
}

describe("nodeTimings", () => {
  it("separates wait from run", () => {
    expect(nodeTimings(node({}))).toEqual({ waitMs: 240_000, execMs: 40, totalMs: 240_040 });
  });

  it("clamps a start outside the span", () => {
    expect(nodeTimings(node({ started_at: "2026-08-28T09:59:00.000Z" }))).toEqual({
      waitMs: 0,
      execMs: 240_040,
      totalMs: 240_040,
    });
    expect(nodeTimings(node({ started_at: "2026-08-28T10:05:00.000Z" }))).toEqual({
      waitMs: 240_040,
      execMs: 0,
      totalMs: 240_040,
    });
  });

  it("reports no split without a start, and nothing without an end", () => {
    expect(nodeTimings(node({ started_at: null }))).toEqual({ waitMs: null, execMs: null, totalMs: 240_040 });
    expect(nodeTimings(node({ finished_at: null }))).toBeNull();
  });
});
