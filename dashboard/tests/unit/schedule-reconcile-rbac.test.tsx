import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { Suspense } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

type Confirmation = {
  confirmLabel?: string;
  onConfirm: () => Promise<void> | void;
  title?: string;
  variant?: string;
};

const reconcileMocks = vi.hoisted(() => ({
  role: "admin" as "admin" | "operator" | "viewer",
  diff: vi.fn(),
  importSchedules: vi.fn(),
  confirm: vi.fn(),
  confirmation: null as Confirmation | null,
  diffResult: {
    summary: {
      insert: 1,
      update: 0,
      delete: 0,
      unchanged: 0,
      total: 1,
    },
    inserted: [],
    updated: [],
    deleted: [],
    unchanged: [],
  },
}));

vi.mock("lucide-react", async () => {
  const React = await import("react");
  const Icon = () => React.createElement("span");
  return {
    AlertTriangle: Icon,
    ArrowLeft: Icon,
    Check: Icon,
    Diff: Icon,
    Equal: Icon,
    GitCompare: Icon,
    MinusCircle: Icon,
    PlayCircle: Icon,
    PlusCircle: Icon,
  };
});

vi.mock("@tanstack/react-router", async (importOriginal) => {
  const React = await import("react");
  const original =
    await importOriginal<typeof import("@tanstack/react-router")>();
  return {
    ...original,
    createFileRoute: () => (options: Record<string, unknown>) => ({
      ...options,
      options,
      useParams: () => ({ slug: "project" }),
    }),
    Link: ({ children }: { children: React.ReactNode }) =>
      React.createElement("a", { href: "#schedules" }, children),
  };
});

vi.mock("sonner", () => ({
  toast: {
    error: vi.fn(),
    success: vi.fn(),
    warning: vi.fn(),
  },
}));

vi.mock("@/hooks/use-memberships", () => ({
  useCan: (_slug: string, capability: string) =>
    capability === "admin_schedules" && reconcileMocks.role === "admin",
}));

vi.mock("@/hooks/use-schedules", () => ({
  useCircuitBreakerThreshold: () => ({ data: 0 }),
  useScheduleRuns: () => ({ data: undefined }),
  useScheduleDiff: () => ({
    data: reconcileMocks.diffResult,
    isPending: false,
    mutateAsync: reconcileMocks.diff,
  }),
  useScheduleImport: () => ({
    isPending: false,
    mutateAsync: reconcileMocks.importSchedules,
  }),
}));

vi.mock("@/components/domain/confirm-dialog", () => ({
  useConfirm: () => ({
    confirm: (options: Confirmation) => {
      reconcileMocks.confirm(options);
      reconcileMocks.confirmation = options;
    },
    dialog: null,
  }),
}));

vi.mock("@/components/domain/page-header", async () => {
  const React = await import("react");
  return {
    PageHeader: ({
      title,
      description,
    }: {
      title: string;
      description: string;
    }) =>
      React.createElement(
        "header",
        null,
        React.createElement("h1", null, title),
        React.createElement("p", null, description),
      ),
  };
});

vi.mock("@/components/domain/empty-state", async () => {
  const React = await import("react");
  return {
    EmptyState: ({
      title,
      description,
    }: {
      title: string;
      description: string;
    }) =>
      React.createElement(
        "section",
        null,
        React.createElement("h2", null, title),
        React.createElement("p", null, description),
      ),
  };
});

vi.mock("@/components/domain/page-shell", async () => {
  const React = await import("react");
  return {
    PageShell: ({ children }: { children: React.ReactNode }) =>
      React.createElement("main", null, children),
  };
});

vi.mock("@/components/ui/button", async () => {
  const React = await import("react");
  return {
    Button: ({
      children,
      variant: _variant,
      size: _size,
      ...props
    }: React.ButtonHTMLAttributes<HTMLButtonElement> & {
      variant?: string;
      size?: string;
    }) => React.createElement("button", { type: "button", ...props }, children),
  };
});

vi.mock("@/components/ui/card", async () => {
  const React = await import("react");
  const Part = ({ children }: { children?: React.ReactNode }) =>
    React.createElement("div", null, children);
  return {
    Card: Part,
    CardContent: Part,
    CardHeader: Part,
    CardTitle: Part,
  };
});

vi.mock("@/components/ui/badge", async () => {
  const React = await import("react");
  return {
    Badge: ({ children }: { children?: React.ReactNode }) =>
      React.createElement("span", null, children),
  };
});

vi.mock("@/components/ui/input", async () => {
  const React = await import("react");
  return {
    Input: (props: React.InputHTMLAttributes<HTMLInputElement>) =>
      React.createElement("input", props),
  };
});

vi.mock("@/components/ui/label", async () => {
  const React = await import("react");
  return {
    Label: (props: React.LabelHTMLAttributes<HTMLLabelElement>) =>
      React.createElement("label", props),
  };
});

vi.mock("@/components/ui/select", async () => {
  const React = await import("react");
  const Part = ({ children }: { children?: React.ReactNode }) =>
    React.createElement("div", null, children);
  return {
    Select: ({
      children,
      onValueChange,
    }: {
      children?: React.ReactNode;
      onValueChange?: (value: string) => void;
    }) =>
      React.createElement(
        "div",
        null,
        children,
        React.createElement(
          "button",
          {
            type: "button",
            "aria-label": "set-replace-mode",
            onClick: () => onValueChange?.("replace_for_source"),
          },
          "replace_for_source",
        ),
      ),
    SelectContent: Part,
    SelectItem: Part,
    SelectTrigger: Part,
    SelectValue: () => null,
  };
});

vi.mock("@/components/ui/skeleton", async () => {
  const React = await import("react");
  return {
    Skeleton: () => React.createElement("div"),
  };
});

vi.mock("@/components/ui/textarea", async () => {
  const React = await import("react");
  return {
    Textarea: (props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) =>
      React.createElement("textarea", props),
  };
});

vi.mock("@/lib/api", () => ({
  ApiError: class ApiError extends Error {},
}));

import { Route } from "@/routes/_authenticated.projects.$slug.schedules_.reconcile";

const ReconcilePage = (
  Route as unknown as {
    options: { component: React.ComponentType };
  }
).options.component;

async function renderReconcileRoute() {
  await (
    ReconcilePage as React.ComponentType & {
      preload?: () => Promise<void>;
    }
  ).preload?.();
  await act(async () => {
    render(
      <Suspense fallback={null}>
        <ReconcilePage />
      </Suspense>,
    );
    await Promise.resolve();
  });
}

function makeDiffResult(insert: number, deleted = 0) {
  return {
    summary: {
      insert,
      update: 0,
      delete: deleted,
      unchanged: 0,
      total: insert + deleted,
    },
    inserted: [],
    updated: [],
    deleted: [],
    unchanged: [],
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

async function runPreview(schedules: Array<Record<string, unknown>>) {
  fireEvent.change(await screen.findByLabelText(/Schedules \(JSON array\)/i), {
    target: { value: JSON.stringify(schedules) },
  });
  fireEvent.click(screen.getByRole("button", { name: /Run diff/i }));
  await waitFor(() => expect(reconcileMocks.diff).toHaveBeenCalled());
  await screen.findByRole("button", { name: /Apply this diff/i });
}

describe("schedule reconciliation route RBAC", () => {
  beforeEach(() => {
    reconcileMocks.role = "admin";
    reconcileMocks.confirmation = null;
    reconcileMocks.diff.mockReset();
    reconcileMocks.diff.mockResolvedValue(reconcileMocks.diffResult);
    reconcileMocks.importSchedules.mockReset();
    reconcileMocks.importSchedules.mockResolvedValue({
      inserted: 1,
      updated: 0,
      unchanged: 0,
      deleted: 0,
      failed: 0,
    });
    reconcileMocks.confirm.mockReset();
  });

  it.each(["operator", "viewer"] as const)(
    "keeps a direct-route %s in an admin-required, non-mutating state",
    async (role) => {
      reconcileMocks.role = role;
      await renderReconcileRoute();

      expect(
        await screen.findByRole("heading", {
          name: "admin access required",
        }),
      ).toBeInTheDocument();
      expect(
        screen.queryByLabelText(/Schedules \(JSON array\)/i),
      ).not.toBeInTheDocument();
      expect(
        screen.queryByRole("button", { name: /Run diff/i }),
      ).not.toBeInTheDocument();
      expect(
        screen.queryByRole("button", { name: /Apply this diff/i }),
      ).not.toBeInTheDocument();

      for (const button of screen.queryAllByRole("button")) {
        fireEvent.click(button);
      }

      expect(reconcileMocks.diff).not.toHaveBeenCalled();
      expect(reconcileMocks.importSchedules).not.toHaveBeenCalled();
      expect(reconcileMocks.confirm).not.toHaveBeenCalled();
    },
  );

  it("uses the exact same deeply frozen request for preview and apply", async () => {
    await renderReconcileRoute();

    const schedules = [
      { name: "nightly-report", kwargs: { destination: "audit" } },
    ];
    await runPreview(schedules);

    const expectedBody = {
      mode: "upsert",
      source_filter: undefined,
      schedules,
    };
    expect(reconcileMocks.diff).toHaveBeenCalledWith(expectedBody);
    const previewRequest = reconcileMocks.diff.mock.calls[0]?.[0];
    expect(Object.isFrozen(previewRequest)).toBe(true);
    expect(Object.isFrozen(previewRequest.schedules)).toBe(true);
    expect(Object.isFrozen(previewRequest.schedules[0])).toBe(true);
    expect(Object.isFrozen(previewRequest.schedules[0].kwargs)).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: /Apply this diff/i }));
    expect(reconcileMocks.confirm).toHaveBeenCalledOnce();
    expect(reconcileMocks.confirmation).not.toBeNull();

    const confirmation = reconcileMocks.confirmation;
    if (!confirmation) throw new Error("confirmation was not captured");
    await act(async () => {
      await confirmation.onConfirm();
    });

    expect(reconcileMocks.importSchedules).toHaveBeenCalledOnce();
    expect(reconcileMocks.importSchedules).toHaveBeenCalledWith(expectedBody);
    expect(reconcileMocks.importSchedules.mock.calls[0]?.[0]).toBe(
      previewRequest,
    );
  });

  it.each(["mode", "source", "text"] as const)(
    "invalidates and hides Apply when the %s input changes",
    async (input) => {
      await renderReconcileRoute();
      await runPreview([{ name: "nightly-report" }]);

      if (input === "mode") {
        fireEvent.click(
          screen.getByRole("button", { name: "set-replace-mode" }),
        );
      } else if (input === "source") {
        fireEvent.change(screen.getByLabelText(/Source filter/i), {
          target: { value: "declarative:django" },
        });
      } else {
        fireEvent.change(screen.getByLabelText(/Schedules \(JSON array\)/i), {
          target: { value: "[]" },
        });
      }

      expect(
        screen.queryByRole("button", { name: /Apply this diff/i }),
      ).not.toBeInTheDocument();
      expect(reconcileMocks.importSchedules).not.toHaveBeenCalled();
    },
  );

  it("blocks the upsert-preview to empty replace-for-source data-loss sequence", async () => {
    await renderReconcileRoute();
    await runPreview([{ name: "nightly-report" }]);

    fireEvent.click(screen.getByRole("button", { name: "set-replace-mode" }));
    fireEvent.change(screen.getByLabelText(/Source filter/i), {
      target: { value: "declarative:django" },
    });
    fireEvent.change(screen.getByLabelText(/Schedules \(JSON array\)/i), {
      target: { value: "[]" },
    });

    expect(
      screen.queryByRole("button", { name: /Apply this diff/i }),
    ).not.toBeInTheDocument();
    expect(reconcileMocks.confirm).not.toHaveBeenCalled();
    expect(reconcileMocks.importSchedules).not.toHaveBeenCalled();
  });

  it("expires an already-open confirmation when any preview input changes", async () => {
    await renderReconcileRoute();
    await runPreview([{ name: "nightly-report" }]);
    fireEvent.click(screen.getByRole("button", { name: /Apply this diff/i }));
    const confirmation = reconcileMocks.confirmation;
    if (!confirmation) throw new Error("confirmation was not captured");

    fireEvent.change(screen.getByLabelText(/Schedules \(JSON array\)/i), {
      target: { value: "[]" },
    });
    await act(async () => {
      await confirmation.onConfirm();
    });

    expect(reconcileMocks.importSchedules).not.toHaveBeenCalled();
  });

  it("binds a destructive confirmation summary and import to one replace snapshot", async () => {
    reconcileMocks.diff.mockResolvedValueOnce(makeDiffResult(0, 3));
    await renderReconcileRoute();
    fireEvent.click(screen.getByRole("button", { name: "set-replace-mode" }));
    fireEvent.change(screen.getByLabelText(/Source filter/i), {
      target: { value: "declarative:django" },
    });
    await runPreview([]);

    const previewRequest = reconcileMocks.diff.mock.calls[0]?.[0];
    fireEvent.click(screen.getByRole("button", { name: /Apply this diff/i }));
    expect(reconcileMocks.confirm).toHaveBeenCalledWith(
      expect.objectContaining({
        confirmLabel: "Apply + delete",
        title: "Apply diff and delete 3 schedules?",
        variant: "destructive",
      }),
    );
    const confirmation = reconcileMocks.confirmation;
    if (!confirmation) throw new Error("confirmation was not captured");
    await act(async () => {
      await confirmation.onConfirm();
    });

    expect(reconcileMocks.importSchedules.mock.calls[0]?.[0]).toBe(
      previewRequest,
    );
    expect(reconcileMocks.importSchedules).toHaveBeenCalledWith({
      mode: "replace_for_source",
      source_filter: "declarative:django",
      schedules: [],
    });
  });

  it("does not restore an earlier preview when overlapping responses resolve out of order", async () => {
    const first = deferred<ReturnType<typeof makeDiffResult>>();
    const second = deferred<ReturnType<typeof makeDiffResult>>();
    reconcileMocks.diff
      .mockImplementationOnce(() => first.promise)
      .mockImplementationOnce(() => second.promise);
    await renderReconcileRoute();

    const textarea = await screen.findByLabelText(/Schedules \(JSON array\)/i);
    const firstSchedules = [{ name: "first" }];
    const secondSchedules = [{ name: "second" }];
    fireEvent.change(textarea, {
      target: { value: JSON.stringify(firstSchedules) },
    });
    fireEvent.click(screen.getByRole("button", { name: /Run diff/i }));
    fireEvent.change(textarea, {
      target: { value: JSON.stringify(secondSchedules) },
    });
    fireEvent.click(screen.getByRole("button", { name: /Run diff/i }));

    await act(async () => {
      second.resolve(makeDiffResult(2));
      await second.promise;
    });
    fireEvent.click(
      await screen.findByRole("button", { name: /Apply this diff/i }),
    );
    expect(reconcileMocks.confirm).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Apply diff (2 changes)?" }),
    );
    const confirmation = reconcileMocks.confirmation;
    if (!confirmation) throw new Error("confirmation was not captured");

    await act(async () => {
      first.resolve(makeDiffResult(9));
      await first.promise;
    });
    await act(async () => {
      await confirmation.onConfirm();
    });

    expect(reconcileMocks.importSchedules).toHaveBeenCalledOnce();
    expect(reconcileMocks.importSchedules).toHaveBeenCalledWith({
      mode: "upsert",
      source_filter: undefined,
      schedules: secondSchedules,
    });
  });

  it("clears a successful preview before a new failed diff and never reuses it", async () => {
    await renderReconcileRoute();
    await runPreview([{ name: "nightly-report" }]);
    reconcileMocks.diff.mockRejectedValueOnce(new Error("diff unavailable"));

    fireEvent.click(screen.getByRole("button", { name: /Run diff/i }));
    expect(
      screen.queryByRole("button", { name: /Apply this diff/i }),
    ).not.toBeInTheDocument();
    await waitFor(() => expect(reconcileMocks.diff).toHaveBeenCalledTimes(2));
    expect(
      screen.queryByRole("button", { name: /Apply this diff/i }),
    ).not.toBeInTheDocument();
    expect(reconcileMocks.importSchedules).not.toHaveBeenCalled();
  });
});
