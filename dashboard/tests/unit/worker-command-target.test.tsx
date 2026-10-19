import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Suspense, type ComponentType, type ReactNode } from "react";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { AgentPublic } from "@/lib/api-types";

const state = vi.hoisted(() => ({
  agents: [] as AgentPublic[],
  worker: {} as Record<string, unknown>,
  canOperate: true,
  pool: vi.fn(),
  add: vi.fn(),
  remove: vi.fn(),
  restart: vi.fn(),
}));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  createFileRoute: () => (options: Record<string, unknown>) => ({
    options,
    useParams: () => ({ slug: "project", workerId: "worker" }),
  }),
  Link: ({ children }: { children: ReactNode }) => <a>{children}</a>,
}));
vi.mock("@/hooks/use-workers", () => ({
  useWorkerDetail: () => ({ data: state.worker, isLoading: false }),
}));
vi.mock("@/hooks/use-agents", () => ({
  useAgents: () => ({ data: state.agents }),
}));
vi.mock("@/hooks/use-memberships", () => ({ useCan: () => state.canOperate }));
vi.mock("@/hooks/use-commands", () => ({
  usePoolResize: () => ({ mutateAsync: state.pool, isPending: false }),
  useAddConsumer: () => ({ mutateAsync: state.add, isPending: false }),
  useCancelConsumer: () => ({ mutateAsync: state.remove, isPending: false }),
  useRestartWorker: () => ({ mutateAsync: state.restart, isPending: false }),
}));
vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));
vi.mock("@/components/domain/page-header", () => ({
  PageHeader: () => <h1>Worker</h1>,
}));
vi.mock("@/components/domain/page-shell", () => ({
  PageShell: ({ children }: { children: ReactNode }) => <main>{children}</main>,
}));
vi.mock("@/components/ui/tabs", () => {
  const Plain = ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  );
  return {
    Tabs: Plain,
    TabsList: Plain,
    TabsTrigger: Plain,
    TabsContent: Plain,
  };
});
vi.mock("@/components/ui/dialog", () => {
  const Plain = ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  );
  return {
    Dialog: ({ open, children }: { open: boolean; children: ReactNode }) =>
      open ? <div>{children}</div> : null,
    DialogContent: Plain,
    DialogDescription: Plain,
    DialogFooter: Plain,
    DialogHeader: Plain,
    DialogTitle: Plain,
  };
});

import { Route } from "@/routes/_authenticated.projects.$slug.workers_.$workerId";
const Component = Route.options.component as ComponentType & {
  preload?: () => Promise<void>;
};
const Page = () => (
  <Suspense fallback={null}>
    <Component />
  </Suspense>
);
beforeAll(async () => {
  await Component.preload?.();
});
const actions = [
  "pool_grow",
  "pool_shrink",
  "add_consumer",
  "cancel_consumer",
  "restart_worker",
];
const agent = (id: string): AgentPublic => ({
  id,
  project_id: "project",
  name: id,
  state: "online",
  protocol_version: "2",
  framework_adapter: "bare",
  engine_adapters: ["celery"],
  scheduler_adapters: [],
  capabilities: { celery: actions },
  last_seen_at: "2026-10-15T00:00:00Z",
  last_connect_at: "2026-10-15T00:00:00Z",
  created_at: "2026-10-15T00:00:00Z",
  is_outdated: false,
});

beforeEach(() => {
  vi.clearAllMocks();
  state.canOperate = true;
  state.agents = [agent("unrelated-first"), agent("reporter")];
  state.worker = {
    id: "worker",
    project_id: "project",
    agent_id: "reporter",
    name: "celery@host",
    engine: "celery",
    state: "online",
    queues: ["default"],
    active_tasks: 0,
    metadata: { active_queues: [{ name: "default" }] },
  };
});

describe("worker command identity", () => {
  it("binds every action to the reporter and explicit engine, not the first online agent", async () => {
    render(<Page />);
    fireEvent.click(screen.getByRole("button", { name: "Pool +1" }));
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    fireEvent.click(screen.getByRole("button", { name: "Add Queue" }));
    fireEvent.change(screen.getByLabelText("Queue name"), {
      target: { value: "jobs" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add consumer" }));
    fireEvent.click(screen.getByRole("button", { name: "Restart Worker" }));
    fireEvent.click(screen.getByRole("button", { name: "Restart pool" }));
    await waitFor(() => expect(state.restart).toHaveBeenCalledOnce());
    for (const call of [state.pool, state.add, state.remove, state.restart]) {
      expect(call).toHaveBeenCalledWith(
        expect.objectContaining({
          agent_id: "reporter",
          engine: "celery",
          worker_name: "celery@host",
        }),
      );
    }
  });

  it.each([
    "missing",
    "offline",
    "unknown_inventory",
    "different_engine",
    "unsupported",
  ])("refuses controls for %s provenance or inventory", (reason) => {
    const owner = state.agents[1];
    if (reason === "missing") state.worker.agent_id = null;
    if (reason === "offline") owner.state = "offline";
    if (reason === "unknown_inventory") {
      owner.engine_adapters = [];
      owner.last_connect_at = null;
      owner.capabilities = {};
    }
    if (reason === "different_engine") owner.engine_adapters = ["rq"];
    if (reason === "unsupported") owner.capabilities = { celery: [] };
    render(<Page />);
    for (const name of [
      "Pool +1",
      "Pool -1",
      "Add Queue",
      "Restart Worker",
      "Remove",
    ]) {
      expect(screen.getByRole("button", { name })).toBeDisabled();
    }
    expect(screen.getByText(/controls unavailable/i)).toBeInTheDocument();
  });

  it("retains the viewer restriction on removal", () => {
    state.canOperate = false;
    render(<Page />);
    expect(
      screen.queryByRole("button", { name: "Restart Worker" }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove" })).toBeDisabled();
  });

  it("checks the exact action instead of disabling every native control", () => {
    state.agents[1].capabilities = { celery: ["pool_grow", "restart_worker"] };
    render(<Page />);
    expect(screen.getByRole("button", { name: "Pool +1" })).toBeEnabled();
    expect(
      screen.getByRole("button", { name: "Restart Worker" }),
    ).toBeEnabled();
    expect(screen.getByRole("button", { name: "Pool -1" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Remove" })).toBeDisabled();
  });

  it("refuses an open restart confirmation if the reporter disappears", () => {
    const page = render(<Page />);
    fireEvent.click(screen.getByRole("button", { name: "Restart Worker" }));
    state.worker.agent_id = null;
    page.rerender(<Page />);
    const confirm = screen.getByRole("button", { name: "Restart pool" });
    expect(confirm).toBeDisabled();
    fireEvent.click(confirm);
    expect(state.restart).not.toHaveBeenCalled();
  });
});
