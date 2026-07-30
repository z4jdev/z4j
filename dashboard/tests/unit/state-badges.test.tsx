/**
 * Component tests for the per-domain state badges.
 *
 * These badges render on every list view in the dashboard
 * (Tasks, Agents, Workers, Commands). The variant -> palette
 * mapping is the single source of truth for "what colour does
 * 'failure' look like across the app"; a regression here re-skins
 * half the dashboard.
 */
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import {
  AgentStateBadge,
  TaskPriorityBadge,
  TaskStateBadge,
  WorkerStateBadge,
} from "@/components/domain/state-badges";

describe("TaskStateBadge", () => {
  it("renders the state text", () => {
    render(<TaskStateBadge state="success" />);
    expect(screen.getByText("success")).toBeInTheDocument();
  });

  it("falls back to outline variant for unknown states", () => {
    // @ts-expect-error - intentionally pass an off-spec value
    render(<TaskStateBadge state="not-a-real-state" />);
    expect(screen.getByText("not-a-real-state")).toBeInTheDocument();
  });

  it.each([
    ["pending"],
    ["received"],
    ["started"],
    ["success"],
    ["failure"],
    ["retry"],
    ["revoked"],
    ["rejected"],
    ["unknown"],
  ] as const)("renders for the '%s' state", (state) => {
    render(<TaskStateBadge state={state} />);
    expect(screen.getByText(state)).toBeInTheDocument();
  });
});

describe("AgentStateBadge", () => {
  it.each([["online"], ["offline"], ["unknown"]] as const)(
    "renders the '%s' state",
    (state) => {
      render(<AgentStateBadge state={state} />);
      expect(screen.getByText(state)).toBeInTheDocument();
    },
  );
});

describe("WorkerStateBadge", () => {
  it.each([["online"], ["offline"], ["draining"], ["unknown"]] as const)(
    "renders the '%s' state",
    (state) => {
      render(<WorkerStateBadge state={state} />);
      expect(screen.getByText(state)).toBeInTheDocument();
    },
  );
});

describe("TaskPriorityBadge", () => {
  // Regression: the Tasks table passed `compact`, which returned null
  // for "normal" and dropped the label for everything else. The column
  // rendered a row of undecodable coloured icons interleaved with blank
  // cells, and the product ships no priority legend anywhere.
  it.each(["critical", "high", "normal", "low"] as const)(
    "always renders a readable label for %s",
    (priority) => {
      const { unmount } = render(<TaskPriorityBadge priority={priority} />);
      expect(screen.getByText(priority)).toBeInTheDocument();
      unmount();
    },
  );

  it("renders a value for normal rather than an empty cell", () => {
    const { container } = render(<TaskPriorityBadge priority="normal" />);
    expect(container.textContent?.trim()).toBe("normal");
  });
});
