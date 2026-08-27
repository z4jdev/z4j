import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { Suspense, type ComponentType, type ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SchedulePublic, TaskPublic } from "@/lib/api-types";

const routeState = vi.hoisted(() => ({
  role: "admin" as "admin" | "operator" | "viewer",
  taskRows: [] as TaskPublic[],
  scheduleRows: [] as SchedulePublic[],
}));

const mutations = vi.hoisted(() => ({
  apiGet: vi.fn(),
  apiPost: vi.fn(),
  apiPostResource: vi.fn(),
  trigger: vi.fn(),
  toggle: vi.fn(),
  deleteSchedule: vi.fn(),
  resync: vi.fn(),
  pause: vi.fn(),
  resume: vi.fn(),
}));

vi.mock("lucide-react", async () => {
  const React = await import("react");
  const Icon = () => React.createElement("span");
  return {
    ArrowDown: Icon,
    ArrowUp: Icon,
    ArrowUpDown: Icon,
    Ban: Icon,
    Check: Icon,
    ChevronDown: Icon,
    ChevronLeft: Icon,
    ChevronRight: Icon,
    ChevronsLeft: Icon,
    ClipboardList: Icon,
    Download: Icon,
    FileJson: Icon,
    FileSpreadsheet: Icon,
    FileText: Icon,
    GitCompare: Icon,
    History: Icon,
    Minus: Icon,
    Pause: Icon,
    Pencil: Icon,
    Play: Icon,
    Plus: Icon,
    RefreshCcwDot: Icon,
    RotateCcw: Icon,
    Trash2: Icon,
    TriangleAlert: Icon,
  };
});

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
      useParams: () => ({ slug: "project" }),
      useSearch: () => ({ state: "failure" }),
    }),
    Link: ({ children }: { children: ReactNode }) =>
      React.createElement("a", { href: "#route" }, children),
    useNavigate: () => vi.fn(),
  };
});

vi.mock("@tanstack/react-query", async (importOriginal) => {
  const original =
    await importOriginal<typeof import("@tanstack/react-query")>();
  return {
    ...original,
    useQueryClient: () => ({ invalidateQueries: vi.fn() }),
  };
});

vi.mock("sonner", () => ({
  toast: {
    error: vi.fn(),
    success: vi.fn(),
    warning: vi.fn(),
  },
}));

vi.mock("@/lib/api", () => ({
  api: {
    get: mutations.apiGet,
    post: mutations.apiPost,
    postResource: mutations.apiPostResource,
  },
  ApiError: class ApiError extends Error {
    status = 500;
    code = "test";
  },
}));

vi.mock("@/hooks/use-memberships", () => ({
  useCan: (_slug: string, action: string) => {
    if (routeState.role === "admin") return true;
    if (routeState.role === "viewer") return action === "view";
    return [
      "view",
      "retry_task",
      "cancel_task",
      "bulk_action",
      "purge_queue",
      "operate_schedules",
      "manage_schedules",
      "manage_automation",
    ].includes(action);
  },
}));

vi.mock("@/hooks/use-tasks", () => ({
  buildExportUrl: () => "/export",
  useTasks: () => ({
    data: { items: routeState.taskRows, next_cursor: null },
    isLoading: false,
    isError: false,
    isFetching: false,
    refetch: vi.fn(),
  }),
}));

vi.mock("@/hooks/use-schedules", () => ({
  useSchedules: () => ({
    data: routeState.scheduleRows,
    isLoading: false,
    isFetching: false,
    refetch: vi.fn(),
  }),
  useToggleSchedule: () => ({
    mutateAsync: mutations.toggle,
    isPending: false,
  }),
  useTriggerSchedule: () => ({
    mutateAsync: mutations.trigger,
    isPending: false,
  }),
  usePauseSchedule: () => ({
    mutateAsync: mutations.pause,
    isPending: false,
  }),
  useResumeSchedule: () => ({
    mutateAsync: mutations.resume,
    isPending: false,
  }),
  useDeleteSchedule: () => ({
    mutateAsync: mutations.deleteSchedule,
    isPending: false,
  }),
  useScheduleResync: () => ({
    mutateAsync: mutations.resync,
    isPending: false,
  }),
  useProjectMisfires: () => ({ data: [] }),
}));

vi.mock("@/components/domain/confirm-dialog", () => ({
  useConfirm: () => ({ confirm: vi.fn(), dialog: null }),
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

vi.mock("@/components/domain/filter-toolbar", async () => {
  const React = await import("react");
  return {
    FilterToolbar: ({ filters }: { filters?: ReactNode }) =>
      React.createElement("div", null, filters),
  };
});

vi.mock("@/components/domain/refresh-button", () => ({
  RefreshButton: () => null,
}));

vi.mock("@/components/domain/state-badges", async () => {
  const React = await import("react");
  const Badge = () => React.createElement("span");
  return {
    TaskPriorityBadge: Badge,
    TaskStateBadge: Badge,
    SchedulePausedBadge: Badge,
  };
});

vi.mock("@/components/domain/empty-state", () => ({
  EmptyState: () => null,
}));

vi.mock("@/components/domain/query-error", () => ({
  QueryError: () => null,
}));

vi.mock("@/components/domain/date-cell", () => ({
  DateCell: () => null,
}));

vi.mock("@/components/domain/page-shell", async () => {
  const React = await import("react");
  return {
    PageShell: ({ children }: { children: ReactNode }) =>
      React.createElement("main", null, children),
  };
});

vi.mock("@/components/domain/schedule-form-dialog", async () => {
  const React = await import("react");
  return {
    ScheduleFormDialog: ({
      open,
      existing,
    }: {
      open: boolean;
      existing?: SchedulePublic;
    }) =>
      React.createElement("output", {
        "data-testid": "schedule-form",
        "data-open": String(open),
        "data-existing": existing?.id ?? "",
      }),
  };
});

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

vi.mock("@/components/ui/select", async () => {
  const React = await import("react");
  const Part = ({ children }: { children?: ReactNode }) =>
    React.createElement("div", null, children);
  return {
    Select: Part,
    SelectContent: Part,
    SelectItem: Part,
    SelectTrigger: Part,
    SelectValue: () => null,
  };
});

vi.mock("@/components/ui/dropdown-menu", async () => {
  const React = await import("react");
  const Part = ({ children }: { children?: ReactNode }) =>
    React.createElement("div", null, children);
  return {
    DropdownMenu: Part,
    DropdownMenuCheckboxItem: Part,
    DropdownMenuContent: Part,
    DropdownMenuItem: Part,
    DropdownMenuLabel: Part,
    DropdownMenuSeparator: () => null,
    DropdownMenuTrigger: Part,
  };
});

vi.mock("@/components/ui/skeleton", () => ({ Skeleton: () => null }));

vi.mock("@/components/ui/switch", async () => {
  const React = await import("react");
  return {
    Switch: ({
      checked,
      disabled,
      onCheckedChange,
    }: {
      checked: boolean;
      disabled?: boolean;
      onCheckedChange?: (checked: boolean) => void;
    }) =>
      React.createElement("button", {
        type: "button",
        role: "switch",
        "aria-checked": checked,
        disabled,
        onClick: () => onCheckedChange?.(!checked),
      }),
  };
});

import { Route as TasksRoute } from "@/routes/_authenticated.projects.$slug.tasks";
import { Route as SchedulesRoute } from "@/routes/_authenticated.projects.$slug.schedules";

const TasksPage = (
  TasksRoute as unknown as {
    options: { component: React.ComponentType };
  }
).options.component;

const SchedulesPage = (
  SchedulesRoute as unknown as {
    options: { component: React.ComponentType };
  }
).options.component;

type PreloadableRouteComponent = ComponentType & {
  preload?: () => Promise<void>;
};

async function renderRoute(Page: PreloadableRouteComponent) {
  await Page.preload?.();
  let view: ReturnType<typeof render> | undefined;
  await act(async () => {
    view = render(
      <Suspense fallback={null}>
        <Page />
      </Suspense>,
    );
    await Promise.resolve();
  });
  if (!view) throw new Error("route did not render");
  return view;
}

function taskFixture(id: string, name: string): TaskPublic {
  return {
    id,
    project_id: "project-id",
    engine: "celery",
    task_id: `task-${id}`,
    name,
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
    created_at: "2026-08-13T00:00:00Z",
    updated_at: "2026-08-13T00:00:00Z",
  };
}

function scheduleFixture(id: string, name: string): SchedulePublic {
  return {
    id,
    project_id: "project-id",
    engine: "celery",
    scheduler: "z4j-scheduler",
    name,
    task_name: `task.${id}`,
    kind: "cron",
    expression: "0 * * * *",
    timezone: "UTC",
    queue: "default",
    args: [],
    kwargs: {},
    priority: "normal",
    is_enabled: true,
    last_run_at: null,
    next_run_at: null,
    total_runs: 0,
    external_id: null,
    created_at: "2026-08-13T00:00:00Z",
    updated_at: "2026-08-13T00:00:00Z",
    catch_up: "skip",
    source: "dashboard",
    source_hash: null,
    overlap_policy: "allow",
    paused_at: null,
  };
}

describe("route-level stable selection identity", () => {
  beforeEach(() => {
    routeState.role = "admin";
    routeState.taskRows = [];
    routeState.scheduleRows = [];
    for (const mutation of Object.values(mutations)) {
      mutation.mockReset();
      mutation.mockResolvedValue(undefined);
    }
    vi.restoreAllMocks();
  });

  it("deletes the originally selected task after a same-scope refetch inserts a row", async () => {
    const selected = taskFixture("row-a", "A");
    const other = taskFixture("row-b", "B");
    routeState.taskRows = [selected, other];
    vi.spyOn(window, "confirm").mockReturnValue(true);

    const { rerender } = await renderRoute(TasksPage);
    fireEvent.click(
      (await screen.findAllByRole("checkbox", { name: "Select row" }))[0],
    );
    await screen.findByText("1 selected");

    routeState.taskRows = [
      taskFixture("row-new", "New"),
      { ...selected, name: "A updated" },
      other,
    ];
    await act(async () => {
      rerender(
        <Suspense fallback={null}>
          <TasksPage />
        </Suspense>,
      );
    });
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() =>
      expect(mutations.apiPost).toHaveBeenCalledWith(
        "/projects/project/tasks/bulk-delete",
        { task_ids: ["row-a"] },
      ),
    );
    expect(mutations.apiPost).not.toHaveBeenCalledWith(expect.anything(), {
      task_ids: ["row-new"],
    });
  });

  it("triggers the originally selected schedule after a same-scope refetch inserts a row", async () => {
    const selected = scheduleFixture("schedule-a", "A");
    const other = scheduleFixture("schedule-b", "B");
    routeState.role = "operator";
    routeState.scheduleRows = [selected, other];

    const { rerender } = await renderRoute(SchedulesPage);
    fireEvent.click(
      (await screen.findAllByRole("checkbox", { name: "Select row" }))[0],
    );
    await screen.findByText("1 selected");

    routeState.scheduleRows = [
      scheduleFixture("schedule-new", "New"),
      { ...selected, name: "A updated" },
      other,
    ];
    await act(async () => {
      rerender(
        <Suspense fallback={null}>
          <SchedulesPage />
        </Suspense>,
      );
    });
    fireEvent.click(screen.getByRole("button", { name: "Trigger" }));

    await waitFor(() =>
      expect(mutations.trigger).toHaveBeenCalledWith("schedule-a"),
    );
    expect(mutations.trigger).not.toHaveBeenCalledWith("schedule-new");
  });
});

describe("schedules route capability surfaces", () => {
  beforeEach(() => {
    routeState.scheduleRows = [scheduleFixture("schedule-a", "A")];
    for (const mutation of Object.values(mutations)) {
      mutation.mockReset();
      mutation.mockResolvedValue(undefined);
    }
  });

  it("keeps a viewer read-only", async () => {
    routeState.role = "viewer";
    await renderRoute(SchedulesPage);
    await screen.findByRole("heading", { name: "Schedules" });

    expect(screen.queryByText("New schedule")).not.toBeInTheDocument();
    expect(screen.queryByText("Sync now")).not.toBeInTheDocument();
    expect(screen.queryByText("Reconcile diff")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Run" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByTitle("Edit")).not.toBeInTheDocument();
    expect(screen.queryByTitle("Delete")).not.toBeInTheDocument();
    expect(screen.getByRole("switch")).toBeDisabled();
    expect(screen.queryByTestId("schedule-form")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("checkbox", { name: "Select row" }));
    await screen.findByText("1 selected");
    for (const action of ["Trigger", "Enable", "Disable", "Delete"]) {
      expect(
        screen.queryByRole("button", { name: action }),
      ).not.toBeInTheDocument();
    }
    expect(mutations.trigger).not.toHaveBeenCalled();
    expect(mutations.toggle).not.toHaveBeenCalled();
    expect(mutations.deleteSchedule).not.toHaveBeenCalled();
    expect(mutations.resync).not.toHaveBeenCalled();
  });

  it("shows operators only schedule operation controls", async () => {
    routeState.role = "operator";
    await renderRoute(SchedulesPage);
    await screen.findByRole("heading", { name: "Schedules" });

    expect(screen.getByRole("button", { name: "Run" })).toBeInTheDocument();
    expect(screen.getByRole("switch")).toBeEnabled();
    expect(screen.queryByText("New schedule")).not.toBeInTheDocument();
    expect(screen.queryByText("Sync now")).not.toBeInTheDocument();
    expect(screen.queryByText("Reconcile diff")).not.toBeInTheDocument();
    expect(screen.queryByTitle("Edit")).not.toBeInTheDocument();
    expect(screen.queryByTitle("Delete")).not.toBeInTheDocument();
    expect(screen.queryByTestId("schedule-form")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("checkbox", { name: "Select row" }));
    await screen.findByText("1 selected");
    expect(screen.getByRole("button", { name: "Trigger" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Enable" })).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Disable (1)" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Delete" }),
    ).not.toBeInTheDocument();
  });

  it("shows admins both operation and schedule-definition controls", async () => {
    routeState.role = "admin";
    await renderRoute(SchedulesPage);
    await screen.findByRole("heading", { name: "Schedules" });

    expect(
      screen.getByRole("button", { name: "New schedule" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Sync now" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Reconcile diff" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run" })).toBeInTheDocument();
    expect(screen.getByTitle("Edit")).toBeInTheDocument();
    expect(screen.getByTitle("Delete")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "New schedule" }));
    expect(screen.getByTestId("schedule-form")).toHaveAttribute(
      "data-open",
      "true",
    );

    fireEvent.click(screen.getByRole("checkbox", { name: "Select row" }));
    await screen.findByText("1 selected");
    expect(screen.getByRole("button", { name: "Trigger" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Enable" })).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Disable (1)" }),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Delete" })).toHaveLength(2);
  });
});
