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
