import { expect, it, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  AgentHealthDialog,
  latestLossSources,
  type HealthSnapshot,
} from "@/components/domain/agent-health-dialog";
import { api } from "@/lib/api";

vi.mock("@/lib/api", () => ({ api: { get: vi.fn() } }));
vi.mock("@/components/domain/date-cell", () => ({
  DateCell: ({ value }: { value: string }) => <span>{value}</span>,
}));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
const sample = (id: number, runtime = "runtime-a"): HealthSnapshot => ({
  id,
  captured_at: "2026-09-10T12:00:00Z",
  worker_id: "worker-a",
  telemetry_loss: {
    buffer_id: "buffer-a",
    runtime_id: runtime,
    capacity_evicted_frames: 3,
    content_rejected_frames: 1,
    event_records: 7,
    command_results: 2,
    other_frames: 0,
    unclassified_frames: 0,
    adapter_events: { rq: 4 },
  },
});
function show() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <AgentHealthDialog
        slug="test"
        agent={{ id: "agent-a", name: "Agent A" }}
        onClose={() => {}}
      />
    </QueryClientProvider>,
  );
}
it("does not sum repeated reports or repeat a buffer across runtime restarts", () => {
  const sources = latestLossSources([
    sample(3, "runtime-b"),
    sample(2),
    sample(1),
  ]);
  expect(sources.buffers).toHaveLength(1);
  expect(sources.buffers[0].id).toBe(3);
  expect(sources.runtimes).toHaveLength(2);
});
it("treats old-agent and missing reports as unavailable, not healthy", async () => {
  vi.mocked(api.get).mockResolvedValue([
    { ...sample(1), telemetry_loss: null },
  ]);
  show();
  expect(
    await screen.findByText(/No loss accounting available/),
  ).toBeInTheDocument();
});
it("renders event and command-result loss separately", async () => {
  vi.mocked(api.get).mockResolvedValue([sample(1)]);
  show();
  expect(await screen.findByText("Event records lost")).toBeInTheDocument();
  expect(screen.getByText("Results lost")).toBeInTheDocument();
  expect(screen.getByText("7")).toBeInTheDocument();
  expect(screen.getByText("2")).toBeInTheDocument();
  expect(screen.getByText("4")).toBeInTheDocument();
  expect(api.get).toHaveBeenCalledWith("/projects/test/agents/agent-a/health");
});
