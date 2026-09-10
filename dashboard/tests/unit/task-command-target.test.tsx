/**
 * Task detail command targeting.
 *
 * An agent on the long-poll transport never sends a WebSocket hello, so the
 * brain never records its engines or capabilities. Such an agent must stay a
 * command target, while an agent whose hello listed only other engines must
 * not become one.
 */
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { Suspense, type ComponentType, type ReactNode } from "react";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { AgentPublic, TaskPublic } from "@/lib/api-types";

const detailState = vi.hoisted(() => ({
  agents: [] as AgentPublic[],
  task: null as TaskPublic | null,
}));

const commands = vi.hoisted(() => ({
  retry: vi.fn(),
  cancel: vi.fn(),
  rateLimit: vi.fn(),
}));

vi.mock("@tanstack/react-router", async (importOriginal) => {
  const React = await import("react");
  const original =
    await importOriginal<typeof import("@tanstack/react-router")>();
  return {
    ...original,
    createFileRoute: (path: string) => (options: Record<string, unknown>) => ({
      ...options,
      options,
      fullPath: path,
      useParams: () => ({
        slug: "project",
        engine: "celery",
        taskId: "task-1",
      }),
      useSearch: () => ({}),
    }),
    Link: ({ children }: { children: ReactNode }) =>
      React.createElement("a", { href: "#route" }, children),
  };
});

vi.mock("sonner", () => ({
  toast: { error: vi.fn(), success: vi.fn() },
}));

vi.mock("@/lib/api", () => ({
  ApiError: class ApiError extends Error {},
}));

vi.mock("@/hooks/use-memberships", () => ({
  useCan: () => true,
}));

vi.mock("@/hooks/use-agents", () => ({
  useAgents: () => ({ data: detailState.agents }),
}));

vi.mock("@/hooks/use-tasks", () => ({
  useTask: () => ({
    data: detailState.task,
    isLoading: false,
    isError: false,
    refetch: vi.fn(),
  }),
  useTaskTree: () => ({ data: undefined, isError: false, refetch: vi.fn() }),
}));

vi.mock("@/hooks/use-events", () => ({
  useEventsForTask: () => ({
    data: { items: [] },
    isError: false,
    refetch: vi.fn(),
  }),
}));

vi.mock("@/hooks/use-commands", () => ({
  useRetryTask: () => ({ mutateAsync: commands.retry, isPending: false }),
  useCancelTask: () => ({ mutateAsync: commands.cancel, isPending: false }),
  useRateLimit: () => ({ mutateAsync: commands.rateLimit, isPending: false }),
}));

vi.mock("@/components/domain/page-header", async () => {
  const React = await import("react");
  return {
    PageHeader: ({ title, actions }: { title: string; actions?: ReactNode }) =>
      React.createElement(
        "header",
        null,
        React.createElement("h1", null, title),
        actions,
      ),
  };
});

vi.mock("@/components/domain/page-shell", async () => {
  const React = await import("react");
  return {
    PageShell: ({ children }: { children: ReactNode }) =>
      React.createElement("main", null, children),
  };
});

vi.mock("@/components/domain/task-tree", () => ({
  TaskTree: () => null,
}));

vi.mock("@/components/ui/button", async () => {
  const React = await import("react");
  return {
    Button: ({
      children,
      asChild,
      variant: _variant,
      size: _size,
      ...props
    }: React.ButtonHTMLAttributes<HTMLButtonElement> & {
      asChild?: boolean;
      variant?: string;
      size?: string;
    }) =>
      asChild
        ? React.createElement(React.Fragment, null, children)
        : React.createElement("button", { type: "button", ...props }, children),
  };
});

vi.mock("@/components/ui/dialog", async () => {
  const React = await import("react");
  const Part = ({ children }: { children?: ReactNode }) =>
    React.createElement(React.Fragment, null, children);
  return {
    Dialog: ({ open, children }: { open: boolean; children?: ReactNode }) =>
      open ? React.createElement(React.Fragment, null, children) : null,
    DialogContent: Part,
    DialogDescription: Part,
    DialogFooter: Part,
    DialogHeader: Part,
    DialogTitle: Part,
  };
});

// Radix Select needs pointer APIs jsdom lacks. This stand-in keeps the
// value/onValueChange contract, so a test picks an option by clicking it.
vi.mock("@/components/ui/select", async () => {
  const React = await import("react");
  const Choice = React.createContext<{
    value?: string;
    onValueChange?: (value: string) => void;
  }>({});
  return {
    Select: ({
      value,
      onValueChange,
      children,
    }: {
      value?: string;
      onValueChange?: (value: string) => void;
      children?: ReactNode;
    }) =>
      React.createElement(
        Choice.Provider,
        { value: { value, onValueChange } },
        children,
      ),
    SelectTrigger: ({
      children,
      "aria-label": label,
    }: {
      children?: ReactNode;
      "aria-label"?: string;
    }) =>
      React.createElement(
        "div",
        { role: "combobox", "aria-label": label },
        children,
      ),
    SelectValue: () => null,
    SelectContent: ({ children }: { children?: ReactNode }) =>
      React.createElement("div", { role: "listbox" }, children),
    SelectItem: function SelectItem({
      value,
      children,
    }: {
      value: string;
      children?: ReactNode;
    }) {
      const choice = React.useContext(Choice);
      return React.createElement(
        "div",
        {
          role: "option",
          "aria-selected": choice.value === value,
          onClick: () => choice.onValueChange?.(value),
        },
        children,
      );
    },
  };
});

import { Route } from "@/routes/_authenticated.projects.$slug.tasks_.$engine.$taskId";

type PreloadableRouteComponent = ComponentType & {
  preload?: () => Promise<void>;
};

const TaskDetailPage = (
  Route as unknown as {
    options: { component: PreloadableRouteComponent };
  }
).options.component;

const CONNECTED_AT = "2026-09-01T00:00:00Z";
const CONTRACT = ["cancel_task", "retry_task", "retry_by_reference_v1"];
const TASK_COMMAND = { engine: "celery", task_id: "task-1" };
const PICK_AN_AGENT =
  "Select the agent that owns this task before issuing a command.";

function agentFixture(
  name: string,
  overrides: Partial<AgentPublic>,
): AgentPublic {
  return {
    id: `agent-${name}`,
    project_id: "project-id",
    name,
    state: "online",
    protocol_version: "2",
    framework_adapter: "bare",
    engine_adapters: [],
    scheduler_adapters: [],
    capabilities: {},
    last_seen_at: CONNECTED_AT,
    last_connect_at: CONNECTED_AT,
    created_at: CONNECTED_AT,
    is_outdated: false,
    ...overrides,
  };
}

/** A WebSocket agent: its hello recorded the adapters it loaded. */
function helloAgent(
  name: string,
  capabilities: Record<string, string[]>,
): AgentPublic {
  return agentFixture(name, {
    engine_adapters: Object.keys(capabilities),
    capabilities,
  });
}

/**
 * The row a long-poll agent keeps. Verified uploads refresh its liveness, but
 * no hello replaces the mint-time inventory or sets ``last_connect_at``.
 */
function longPollAgent(name: string): AgentPublic {
  return agentFixture(name, {
    protocol_version: "0",
    framework_adapter: "unknown",
    last_connect_at: null,
  });
}

/** A token minted but never used: no upload, no hello. */
function neverConnected(): AgentPublic {
  return agentFixture("never-connected", {
    state: "unknown",
    protocol_version: "0",
    framework_adapter: "unknown",
    last_seen_at: null,
    last_connect_at: null,
  });
}

function taskFixture(): TaskPublic {
  return {
    id: "row-1",
    project_id: "project-id",
    engine: "celery",
    task_id: "task-1",
    name: "reports.build",
    queue: "default",
    state: "failure",
    priority: "normal",
    args: null,
    kwargs: null,
    result: null,
    exception: null,
    traceback: null,
    retry_count: 0,
    eta: null,
    received_at: null,
    started_at: null,
    finished_at: null,
    runtime_ms: null,
    worker_name: null,
    parent_task_id: null,
    root_task_id: null,
    tags: [],
    created_at: CONNECTED_AT,
    updated_at: CONNECTED_AT,
  };
}

// Resolve the code-split component before timing individual assertions.
beforeAll(async () => {
  await TaskDetailPage.preload?.();
}, 30_000);

async function renderDetail() {
  await act(async () => {
    render(
      <Suspense fallback={null}>
        <TaskDetailPage />
      </Suspense>,
    );
    await Promise.resolve();
  });
  await screen.findByRole("heading", { name: "reports.build" });
}

const button = (name: string) => screen.getByRole("button", { name });

describe("task detail command target", () => {
  beforeEach(() => {
    detailState.task = taskFixture();
    for (const command of Object.values(commands)) {
      command.mockReset();
      command.mockResolvedValue(undefined);
    }
  });

  it("targets a long-poll agent whose transport never reported engines", async () => {
    detailState.agents = [longPollAgent("long-poll")];
    await renderDetail();

    expect(
      screen.queryByRole("combobox", { name: "Command target agent" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(PICK_AN_AGENT)).not.toBeInTheDocument();
    expect(button("Retry")).toBeEnabled();
    expect(button("Cancel")).toBeEnabled();

    fireEvent.click(button("Retry"));
    await waitFor(() =>
      expect(commands.retry).toHaveBeenCalledWith({
        agent_id: "agent-long-poll",
        ...TASK_COMMAND,
      }),
    );
    fireEvent.click(button("Cancel"));
    await waitFor(() =>
      expect(commands.cancel).toHaveBeenCalledWith({
        agent_id: "agent-long-poll",
        ...TASK_COMMAND,
      }),
    );
  });

  it("offers every agent that may own the task and none reporting other engines", async () => {
    detailState.agents = [
      neverConnected(),
      helloAgent("scheduler-only", {}),
      helloAgent("rq-worker", { rq: CONTRACT }),
      helloAgent("celery-legacy", { celery: ["cancel_task", "retry_task"] }),
      helloAgent("celery-worker", { celery: CONTRACT }),
      longPollAgent("long-poll"),
    ];
    await renderDetail();

    expect(
      screen.getByRole("combobox", { name: "Command target agent" }),
    ).toBeInTheDocument();
    expect(
      screen.getAllByRole("option").map((option) => option.textContent),
    ).toEqual([
      "celery-legacy · online",
      "celery-worker · online",
      "long-poll · online · engines not reported",
    ]);
    // Several candidates: nothing is chosen on the operator's behalf.
    expect(button("Retry")).toBeDisabled();
    expect(button("Cancel")).toBeDisabled();
    expect(screen.getByText(PICK_AN_AGENT)).toBeInTheDocument();

    // A reported inventory must still advertise the safe retry contract.
    fireEvent.click(screen.getByRole("option", { name: /^celery-legacy/ }));
    expect(button("Retry")).toBeDisabled();
    expect(button("Cancel")).toBeEnabled();

    fireEvent.click(screen.getByRole("option", { name: /^long-poll/ }));
    expect(button("Retry")).toBeEnabled();
    fireEvent.click(button("Retry"));
    await waitFor(() =>
      expect(commands.retry).toHaveBeenCalledWith({
        agent_id: "agent-long-poll",
        ...TASK_COMMAND,
      }),
    );

    fireEvent.click(screen.getByRole("option", { name: /^celery-worker/ }));
    fireEvent.click(button("Cancel"));
    await waitFor(() =>
      expect(commands.cancel).toHaveBeenCalledWith({
        agent_id: "agent-celery-worker",
        ...TASK_COMMAND,
      }),
    );
  });

  it("auto-targets the only reporting agent when a token never connected", async () => {
    detailState.agents = [
      helloAgent("celery-worker", { celery: CONTRACT }),
      neverConnected(),
    ];
    await renderDetail();

    expect(
      screen.queryByRole("combobox", { name: "Command target agent" }),
    ).not.toBeInTheDocument();
    expect(button("Retry")).toBeEnabled();
    fireEvent.click(button("Retry"));
    await waitFor(() =>
      expect(commands.retry).toHaveBeenCalledWith({
        agent_id: "agent-celery-worker",
        ...TASK_COMMAND,
      }),
    );
  });

  it("says so when no agent in the project runs the task's engine", async () => {
    detailState.agents = [
      helloAgent("rq-worker", { rq: CONTRACT }),
      neverConnected(),
    ];
    await renderDetail();

    expect(
      screen.getByText("No agent in this project runs celery tasks."),
    ).toBeInTheDocument();
    expect(screen.queryByText(PICK_AN_AGENT)).not.toBeInTheDocument();
    expect(button("Retry")).toBeDisabled();
    expect(button("Cancel")).toBeDisabled();
  });

  it("keeps the neutral hint while the agent list is still loading", async () => {
    detailState.agents = undefined as unknown as AgentPublic[];
    await renderDetail();

    expect(screen.getByText(PICK_AN_AGENT)).toBeInTheDocument();
    expect(
      screen.queryByText("No agent in this project runs celery tasks."),
    ).not.toBeInTheDocument();
    expect(button("Retry")).toBeDisabled();
  });

  it("preselects the only agent that reported the engine beside a long-poll agent", async () => {
    detailState.agents = [
      helloAgent("celery-worker", { celery: CONTRACT }),
      longPollAgent("long-poll"),
    ];
    await renderDetail();

    expect(
      screen.getByRole("combobox", { name: "Command target agent" }),
    ).toBeInTheDocument();
    expect(screen.queryByText(PICK_AN_AGENT)).not.toBeInTheDocument();
    expect(button("Retry")).toBeEnabled();
    fireEvent.click(button("Retry"));
    await waitFor(() =>
      expect(commands.retry).toHaveBeenCalledWith({
        agent_id: "agent-celery-worker",
        ...TASK_COMMAND,
      }),
    );

    // The long-poll agent is still one choice away.
    fireEvent.click(screen.getByRole("option", { name: /^long-poll/ }));
    fireEvent.click(button("Cancel"));
    await waitFor(() =>
      expect(commands.cancel).toHaveBeenCalledWith({
        agent_id: "agent-long-poll",
        ...TASK_COMMAND,
      }),
    );
  });
});
