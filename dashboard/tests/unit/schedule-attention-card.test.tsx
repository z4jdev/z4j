/**
 * The overview's "Schedules needing attention" card: silent while the list
 * is unknown or healthy, worst first when something is failing, and honest
 * about a breaker that is switched off.
 */
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";

const listState = { data: undefined as unknown, isPending: false, isError: false };
let threshold = 5;

vi.mock("@/hooks/use-schedules", () => ({
  useSchedules: () => listState,
  useCircuitBreakerThreshold: () => ({ data: threshold }),
  useScheduleRuns: () => ({ data: undefined, isError: false, isPending: false }),
}));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  createFileRoute: () => (opts: unknown) => opts,
  Link: ({ children, ...rest }: { children?: React.ReactNode } & Record<string, unknown>) => (
    <a href="#" aria-label={typeof rest["aria-label"] === "string" ? (rest["aria-label"] as string) : undefined}>
      {children}
    </a>
  ),
}));

import { ScheduleAttentionCard } from "@/routes/_authenticated.projects.$slug.index";

function schedule(name: string, failures: number | null) {
  return {
    id: `id-${name}`,
    name,
    task_name: `app.${name}`,
    last_run_at: null,
    consecutive_failures: failures,
  };
}

describe("ScheduleAttentionCard", () => {
  it("renders nothing while the list is loading, on an error, or when all is healthy", () => {
    listState.data = undefined;
    listState.isPending = true;
    listState.isError = false;
    const loading = render(<ScheduleAttentionCard slug="p" />);
    expect(loading.container).toBeEmptyDOMElement();
    loading.unmount();

    listState.isPending = false;
    listState.isError = true;
    const failed = render(<ScheduleAttentionCard slug="p" />);
    expect(failed.container).toBeEmptyDOMElement();
    failed.unmount();

    listState.isError = false;
    listState.data = [schedule("a", 0), schedule("b", null)];
    const healthy = render(<ScheduleAttentionCard slug="p" />);
    expect(healthy.container).toBeEmptyDOMElement();
  });

  it("lists failing schedules worst first", () => {
    listState.data = [schedule("one", 1), schedule("three", 3), schedule("zero", 0), schedule("two", 2)];
    listState.isPending = false;
    listState.isError = false;
    threshold = 5;
    render(<ScheduleAttentionCard slug="p" />);
    expect(screen.getByText("Schedules needing attention")).toBeInTheDocument();
    const names = screen.getAllByText(/^(one|two|three|zero)$/).map((n) => n.textContent);
    expect(names).toEqual(["three", "two", "one"]);
    expect(screen.getByText("3 of 5 failing")).toBeInTheDocument();
    expect(screen.getByText(/auto-disables a schedule at 5/)).toBeInTheDocument();
  });

  it("says the breaker is off when the threshold is 0", () => {
    listState.data = [schedule("one", 2)];
    threshold = 0;
    render(<ScheduleAttentionCard slug="p" />);
    expect(screen.getByText(/switched off/)).toBeInTheDocument();
    expect(screen.getByText("2 failing")).toBeInTheDocument();
  });
});
