/**
 * The canvas node: hover text on the node itself, and a two-segment bar that
 * ends on its track.
 */
import { describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";

vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  Link: ({ children }: { children?: React.ReactNode }) => <a href="#">{children}</a>,
}));

import { TaskTree } from "@/components/domain/task-tree";

const nodes = [
  {
    task_id: "root",
    name: "reports.rollup",
    state: "success",
    parent_task_id: null,
    root_task_id: "root",
    received_at: "2026-08-28T10:00:00.000Z",
    started_at: "2026-08-28T10:00:01.000Z",
    finished_at: "2026-08-28T10:10:00.000Z",
  },
  {
    task_id: "child",
    name: "reports.shard",
    state: "success",
    parent_task_id: "root",
    root_task_id: "root",
    received_at: "2026-08-28T10:00:02.000Z",
    started_at: "2026-08-28T10:04:02.000Z",
    finished_at: "2026-08-28T10:04:08.000Z",
  },
];

describe("TaskTree", () => {
  it("draws wait and run segments inside the track and puts the timing on the node's hover text", () => {
    const { container } = render(
      <TaskTree
        slug="p"
        engine="celery"
        activeTaskId="child"
        data={{ root_task_id: "root", node_count: 2, truncated: false, nodes } as never}
      />,
    );
    const titles = Array.from(container.querySelectorAll("title")).map((t) => t.textContent ?? "");
    expect(titles.some((t) => t.includes("reports.shard") && t.includes("waiting") && t.includes("running"))).toBe(true);
    const bars = Array.from(container.querySelectorAll("rect")).filter((r) => r.getAttribute("height") === "6");
    // Two nodes, each a track plus at least the execution segment.
    expect(bars.length).toBeGreaterThanOrEqual(4);
    for (const r of bars) {
      const x = Number(r.getAttribute("x"));
      const w = Number(r.getAttribute("width"));
      expect(x).toBeGreaterThanOrEqual(10);
      expect(x + w).toBeLessThanOrEqual(170.0001);
    }
  });
});
