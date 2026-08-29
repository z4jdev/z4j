/**
 * The configuration lint panel must reserve space while loading, survive a
 * payload without a workers array, and render its detail text in a
 * foreground colour (it once used a background token and was invisible).
 */
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";

const state = { data: undefined as unknown, isPending: false, isError: false };
vi.mock("@/hooks/use-workers", () => ({ useWorkerLint: () => state }));

import { WorkerLintPanel } from "@/components/domain/worker-lint-panel";

const finding = {
  rule_id: "celery.acks-late-off",
  severity: "medium",
  setting: "task_acks_late",
  title: "Tasks are acknowledged before they run",
  detail: "The broker is told the task is handled the moment it is delivered.",
  remedy: "Set task_acks_late = True.",
};

describe("WorkerLintPanel", () => {
  it("shows a skeleton while pending", () => {
    state.data = undefined;
    state.isPending = true;
    state.isError = false;
    render(<WorkerLintPanel slug="p" />);
    expect(screen.getByText("Configuration lint")).toBeInTheDocument();
    expect(screen.getByText("Reading reported worker settings.")).toBeInTheDocument();
  });

  it("renders nothing, and does not throw, on a payload without a workers array", () => {
    state.isPending = false;
    for (const bad of [{}, [], { workers: "nope" }, { items: [] }]) {
      state.data = bad;
      const { container, unmount } = render(<WorkerLintPanel slug="p" />);
      expect(container).toBeEmptyDOMElement();
      unmount();
    }
  });

  it("renders a finding's detail in a foreground colour", () => {
    state.isPending = false;
    state.data = {
      workers_evaluated: 1,
      workers_not_evaluated: 0,
      findings_by_severity: { medium: 1 },
      workers: [
        {
          worker_id: "w1",
          worker_name: "worker-1",
          engine: "celery",
          hostname: "h1",
          evaluated: true,
          findings: [finding],
        },
      ],
    };
    render(<WorkerLintPanel slug="p" />);
    const detail = screen.getByText(finding.detail);
    expect(detail.className).toContain("text-muted-foreground");
    expect(detail.className).not.toContain("--color-muted");
    expect(screen.getByText(finding.title)).toBeInTheDocument();
  });
});
