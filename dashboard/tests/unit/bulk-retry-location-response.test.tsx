import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { Suspense } from "react";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { bulkRetryStorageKey } from "@/lib/bulk-retry-storage";

const apiMocks = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  postResource: vi.fn(),
}));
const routeMocks = vi.hoisted(() => ({
  search: { state: "failure" } as Record<string, string>,
}));
const tableMocks = vi.hoisted(() => ({
  selectionMode: "all-pages" as "all-pages" | "explicit-empty",
}));
const permissionMocks = vi.hoisted(() => ({
  role: "admin" as "admin" | "operator" | "viewer",
}));

vi.mock("lucide-react", async () => {
  const React = await import("react");
  const Icon = () => React.createElement("span");
  return {
    Ban: Icon,
    ChevronDown: Icon,
    ClipboardList: Icon,
    Download: Icon,
    FileJson: Icon,
    FileSpreadsheet: Icon,
    FileText: Icon,
    RotateCcw: Icon,
    Trash2: Icon,
  };
});

vi.mock("@tanstack/react-router", async (importOriginal) => {
  const original =
    await importOriginal<typeof import("@tanstack/react-router")>();
  return {
    ...original,
    createFileRoute: () => (options: Record<string, unknown>) => ({
      ...options,
      options,
      fullPath: "/projects/$slug/tasks",
      useParams: () => ({ slug: "project" }),
      useSearch: () => routeMocks.search,
    }),
    Link: ({ children }: { children: React.ReactNode }) => children,
    useNavigate: () => vi.fn(),
  };
});

vi.mock("@tanstack/react-query", () => ({
  useQueryClient: () => ({ invalidateQueries: vi.fn() }),
}));

vi.mock("@/lib/api", () => ({
  api: apiMocks,
  ApiError: class ApiError extends Error {
    status: number;
    code: string;

    constructor(status: number, envelope: { error?: string }) {
      super(`request failed (${status})`);
      this.status = status;
      this.code = envelope.error ?? "unknown";
    }
  },
}));

vi.mock("@/hooks/use-memberships", () => ({
  useCan: (_slug: string, action: string) => {
    if (permissionMocks.role === "admin") return true;
    if (permissionMocks.role === "viewer") return action === "view";
    return [
      "view",
      "retry_task",
      "cancel_task",
      "bulk_action",
      "operate_schedules",
      "manage_automation",
    ].includes(action);
  },
}));

vi.mock("@/hooks/use-tasks", () => ({
  buildExportUrl: () => "/export",
  useTasks: () => ({
    data: {
      items: [{ id: "row-1", task_id: "task-1", engine: "celery" }],
      next_cursor: null,
    },
    isLoading: false,
    isError: false,
    isFetching: false,
    refetch: vi.fn(),
  }),
}));

vi.mock("@/components/domain/page-header", () => ({
  PageHeader: () => null,
}));

vi.mock("@/components/domain/filter-toolbar", async () => {
  const React = await import("react");
  return {
    FilterToolbar: ({
      filters,
      onSearchChange,
    }: {
      filters: React.ReactNode;
      onSearchChange: (value: string) => void;
    }) =>
      React.createElement(
        "div",
        null,
        React.createElement(
          "button",
          {
            "aria-label": "set-search-filter",
            onClick: () => onSearchChange("needle"),
          },
          "search",
        ),
        filters,
      ),
  };
});

vi.mock("@/components/domain/refresh-button", () => ({
  RefreshButton: () => null,
}));

vi.mock("@/components/domain/state-badges", () => ({
  TaskPriorityBadge: () => null,
  TaskStateBadge: () => null,
}));

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
    PageShell: ({ children }: { children: React.ReactNode }) =>
      React.createElement("div", null, children),
  };
});

vi.mock("@/components/ui/button", async () => {
  const React = await import("react");
  return {
    Button: ({
      children,
      ...props
    }: React.ButtonHTMLAttributes<HTMLButtonElement>) =>
      React.createElement("button", props, children),
  };
});

vi.mock("@/components/ui/select", async () => {
  const React = await import("react");
  const Select = ({
    children,
    onValueChange,
  }: {
    children?: React.ReactNode;
    onValueChange?: (value: string) => void;
  }) =>
    React.createElement(
      "div",
      null,
      React.createElement(
        "button",
        {
          "aria-label": "set-critical-filter",
          onClick: () => onValueChange?.("critical"),
        },
        "critical",
      ),
      children,
    );
  const SelectPart = ({ children }: { children?: React.ReactNode }) =>
    React.createElement("div", null, children);
  return {
    Select,
    SelectContent: SelectPart,
    SelectItem: SelectPart,
    SelectTrigger: SelectPart,
    SelectValue: SelectPart,
  };
});

vi.mock("@/components/ui/skeleton", () => ({
  Skeleton: () => null,
}));

vi.mock("@/components/ui/dropdown-menu", async () => {
  const React = await import("react");
  const MenuPart = ({ children }: { children?: React.ReactNode }) =>
    React.createElement("div", null, children);
  const CheckboxItem = ({
    children,
    onCheckedChange,
    checked: _checked,
    onSelect: _onSelect,
    ...props
  }: {
    children?: React.ReactNode;
    onCheckedChange?: (checked: boolean) => void;
    checked?: boolean;
    onSelect?: (event: Event) => void;
    "aria-label"?: string;
  }) =>
    React.createElement(
      "button",
      {
        ...props,
        onClick: () => onCheckedChange?.(true),
      },
      children,
    );
  return {
    DropdownMenu: MenuPart,
    DropdownMenuCheckboxItem: CheckboxItem,
    DropdownMenuContent: MenuPart,
    DropdownMenuItem: MenuPart,
    DropdownMenuLabel: MenuPart,
    DropdownMenuSeparator: () => null,
    DropdownMenuTrigger: MenuPart,
  };
});

vi.mock("@/components/ui/data-table", async () => {
  const React = await import("react");
  return {
    DataTable: ({
      toolbar,
    }: {
      toolbar: (context: Record<string, unknown>) => React.ReactNode;
    }) =>
      React.createElement(
        "div",
        null,
        toolbar({
          selectedCount: 0,
          allPagesSelected: false,
          showSelectAllPages: false,
          selectedRows: [],
          clearSelection: vi.fn(),
          selectAllPages: vi.fn(),
          selectPageOnly: vi.fn(),
        }),
        toolbar({
          selectedCount: 1,
          allPagesSelected: tableMocks.selectionMode === "all-pages",
          showSelectAllPages: false,
          selectedRows: [],
          clearSelection: vi.fn(),
          selectAllPages: vi.fn(),
          selectPageOnly: vi.fn(),
        }),
      ),
  };
});

import { Route } from "@/routes/_authenticated.projects.$slug.tasks";

const TasksPage = (
  Route as unknown as {
    options: { component: React.ComponentType };
  }
).options.component;

describe("durable bulk-retry response Location binding", () => {
  beforeAll(async () => {
    await (
      TasksPage as React.ComponentType & {
        preload?: () => Promise<void>;
      }
    ).preload?.();
  });

  beforeEach(() => {
    window.localStorage.clear();
    routeMocks.search = { state: "failure" };
    tableMocks.selectionMode = "all-pages";
    permissionMocks.role = "admin";
    vi.restoreAllMocks();
    apiMocks.get.mockReset();
    apiMocks.post.mockReset();
    apiMocks.postResource.mockReset();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    vi.spyOn(window, "alert").mockImplementation(() => undefined);
    vi.spyOn(window.crypto, "randomUUID").mockReturnValue(
      "01234567-89ab-4def-8123-456789abcdef",
    );
  });

  it("posts the exact all-pages bulk-delete state, priority, and literal search", async () => {
    await act(async () => {
      render(
        <Suspense fallback={null}>
          <TasksPage />
        </Suspense>,
      );
      await Promise.resolve();
    });
    fireEvent.click(
      await screen.findByRole("button", { name: "toggle-critical-priority" }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "toggle-high-priority" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "set-search-filter" }));
    fireEvent.click(screen.getByRole("button", { name: /delete/i }));

    await waitFor(() => expect(apiMocks.post).toHaveBeenCalledOnce());
    expect(apiMocks.post).toHaveBeenCalledWith(
      "/projects/project/tasks/bulk-delete",
      {
        filter_state: "failure",
        filter_priority: ["critical", "high"],
        filter_search: "needle",
      },
    );
    expect(window.confirm).toHaveBeenCalledWith(
      "Delete up to 10,000 matching task records? This cannot be undone.",
    );
  });

  it("never broadens a priority-only all-pages delete to an empty body", async () => {
    routeMocks.search = {};
    await act(async () => {
      render(
        <Suspense fallback={null}>
          <TasksPage />
        </Suspense>,
      );
      await Promise.resolve();
    });
    fireEvent.click(
      await screen.findByRole("button", { name: "toggle-critical-priority" }),
    );
    fireEvent.click(await screen.findByRole("button", { name: /delete/i }));

    await waitFor(() => expect(apiMocks.post).toHaveBeenCalledOnce());
    expect(apiMocks.post).toHaveBeenCalledWith(
      "/projects/project/tasks/bulk-delete",
      { filter_priority: ["critical"] },
    );
  });

  it("does not issue an unfiltered all-pages bulk-delete", async () => {
    routeMocks.search = {};
    await act(async () => {
      render(
        <Suspense fallback={null}>
          <TasksPage />
        </Suspense>,
      );
      await Promise.resolve();
    });
    fireEvent.click(await screen.findByRole("button", { name: /delete/i }));

    expect(apiMocks.post).not.toHaveBeenCalled();
    expect(window.alert).toHaveBeenCalledWith(
      expect.stringContaining("at least one task filter"),
    );
  });

  it("does not issue an explicit-ID bulk-delete for an empty selection", async () => {
    tableMocks.selectionMode = "explicit-empty";
    await act(async () => {
      render(
        <Suspense fallback={null}>
          <TasksPage />
        </Suspense>,
      );
      await Promise.resolve();
    });
    fireEvent.click(screen.getByRole("button", { name: /delete/i }));

    expect(apiMocks.post).not.toHaveBeenCalled();
    expect(window.alert).toHaveBeenCalledWith(
      expect.stringContaining("at least one task"),
    );
  });

  it("shows operator retry and revoke controls but not admin-only delete", async () => {
    permissionMocks.role = "operator";
    tableMocks.selectionMode = "explicit-empty";
    await act(async () => {
      render(
        <Suspense fallback={null}>
          <TasksPage />
        </Suspense>,
      );
      await Promise.resolve();
    });

    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Revoke" })).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Delete" }),
    ).not.toBeInTheDocument();
  });

  it("shows task delete only to an admin", async () => {
    permissionMocks.role = "admin";
    await act(async () => {
      render(
        <Suspense fallback={null}>
          <TasksPage />
        </Suspense>,
      );
      await Promise.resolve();
    });

    expect(screen.getByRole("button", { name: "Delete" })).toBeInTheDocument();
  });

  it.each([
    [
      "another project",
      "/api/v1/projects/other/bulk-retry-requests/11234567-89ab-4def-8123-456789abcdef",
    ],
    [
      "a different same-project request",
      "/api/v1/projects/project/bulk-retry-requests/11234567-89ab-4def-8123-456789abcdef",
    ],
  ])(
    "retains the unresolved record when a terminal body carries %s Location",
    async (_case, responseLocation) => {
      apiMocks.postResource.mockImplementation(
        async (
          _path: string,
          body: { idempotency_key: string },
          onLocation: (location: string) => void,
        ) => {
          onLocation(responseLocation);
          return {
            location: responseLocation,
            data: {
              id: "01234567-89ab-4def-8123-456789abcdef",
              idempotency_key: body.idempotency_key,
              status: "succeeded",
            },
          };
        },
      );

      await act(async () => {
        render(
          <Suspense fallback={null}>
            <TasksPage />
          </Suspense>,
        );
        await Promise.resolve();
      });
      fireEvent.click(await screen.findByRole("button", { name: /retry/i }));

      await waitFor(() => expect(apiMocks.postResource).toHaveBeenCalledOnce());
      expect(
        window.localStorage.getItem(bulkRetryStorageKey("project")),
        "a mismatched Location must preserve the ambiguous operation record",
      ).not.toBeNull();
      expect(window.alert).toHaveBeenCalledWith(
        expect.stringContaining("identity does not match"),
      );
    },
  );

  it("posts the exact state, priority, and search selection shown by the table", async () => {
    const location =
      "/api/v1/projects/project/bulk-retry-requests/01234567-89ab-4def-8123-456789abcdef";
    apiMocks.postResource.mockImplementation(
      async (
        _path: string,
        body: { idempotency_key: string },
        onLocation: (value: string) => void,
      ) => {
        onLocation(location);
        return {
          location,
          data: {
            id: "01234567-89ab-4def-8123-456789abcdef",
            idempotency_key: body.idempotency_key,
            status: "in_progress",
          },
        };
      },
    );

    await act(async () => {
      render(
        <Suspense fallback={null}>
          <TasksPage />
        </Suspense>,
      );
      await Promise.resolve();
    });
    fireEvent.click(
      screen.getByRole("button", { name: "toggle-critical-priority" }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "toggle-high-priority" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "set-search-filter" }));
    fireEvent.click(await screen.findByRole("button", { name: /retry/i }));

    await waitFor(() => expect(apiMocks.postResource).toHaveBeenCalledOnce());
    expect(apiMocks.postResource.mock.calls[0]?.[1]).toEqual({
      idempotency_key: "01234567-89ab-4def-8123-456789abcdef",
      filter: {
        state: "failure",
        priority: ["critical", "high"],
        search: "needle",
      },
      max: 1000,
    });
  });

  it("refuses all-matching retry without an explicit state scope", async () => {
    routeMocks.search = {};
    await act(async () => {
      render(
        <Suspense fallback={null}>
          <TasksPage />
        </Suspense>,
      );
      await Promise.resolve();
    });

    fireEvent.click(await screen.findByRole("button", { name: /retry/i }));

    expect(apiMocks.postResource).not.toHaveBeenCalled();
    expect(apiMocks.post).not.toHaveBeenCalled();
    expect(window.alert).toHaveBeenCalledWith(
      "Choose an explicit task state before retrying all matching tasks.",
    );
  });

  it("clears an unambiguous over-limit refusal so filters can be narrowed", async () => {
    const { ApiError } = await import("@/lib/api");
    apiMocks.postResource.mockRejectedValue(
      new ApiError(400, { error: "matching task count exceeds max" }),
    );

    await act(async () => {
      render(
        <Suspense fallback={null}>
          <TasksPage />
        </Suspense>,
      );
      await Promise.resolve();
    });
    fireEvent.click(await screen.findByRole("button", { name: /retry/i }));

    await waitFor(() => expect(apiMocks.postResource).toHaveBeenCalledOnce());
    expect(
      window.localStorage.getItem(bulkRetryStorageKey("project")),
    ).toBeNull();
    expect(window.alert).toHaveBeenCalledWith(
      expect.stringContaining("exceeds the retry limit"),
    );
  });

  it("retains a generic 400 that does not prove an over-limit refusal", async () => {
    const { ApiError } = await import("@/lib/api");
    apiMocks.postResource.mockRejectedValue(new ApiError(400, {}));

    await act(async () => {
      render(
        <Suspense fallback={null}>
          <TasksPage />
        </Suspense>,
      );
      await Promise.resolve();
    });
    fireEvent.click(await screen.findByRole("button", { name: /retry/i }));

    await waitFor(() => expect(apiMocks.postResource).toHaveBeenCalledOnce());
    expect(
      window.localStorage.getItem(bulkRetryStorageKey("project")),
      "an unclassified 400 can follow an ambiguously committed parent",
    ).not.toBeNull();
  });

  it("retains an ambiguous conflict without a resource Location", async () => {
    const { ApiError } = await import("@/lib/api");
    apiMocks.postResource.mockRejectedValue(new ApiError(409, {}));

    await act(async () => {
      render(
        <Suspense fallback={null}>
          <TasksPage />
        </Suspense>,
      );
      await Promise.resolve();
    });
    fireEvent.click(await screen.findByRole("button", { name: /retry/i }));

    await waitFor(() => expect(apiMocks.postResource).toHaveBeenCalledOnce());
    expect(
      window.localStorage.getItem(bulkRetryStorageKey("project")),
      "a conflict can represent an unresolved reservation",
    ).not.toBeNull();
  });

  it("retains an observed resource Location even when parsing ends in 400", async () => {
    const { ApiError } = await import("@/lib/api");
    const location =
      "/api/v1/projects/project/bulk-retry-requests/01234567-89ab-4def-8123-456789abcdef";
    apiMocks.postResource.mockImplementation(
      async (
        _path: string,
        _body: unknown,
        onLocation: (value: string) => void,
      ) => {
        onLocation(location);
        throw new ApiError(400, {});
      },
    );

    await act(async () => {
      render(
        <Suspense fallback={null}>
          <TasksPage />
        </Suspense>,
      );
      await Promise.resolve();
    });
    fireEvent.click(await screen.findByRole("button", { name: /retry/i }));

    await waitFor(() => expect(apiMocks.postResource).toHaveBeenCalledOnce());
    expect(
      JSON.parse(
        window.localStorage.getItem(bulkRetryStorageKey("project")) ?? "{}",
      ).location,
    ).toBe(location);
  });
});
