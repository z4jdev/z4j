/**
 * Editing a saved schedule must never rewrite its timing.
 *
 * The capability table only decides which kinds the form offers for
 * an engine. The brain accepts any kind for any engine through the
 * API, CLI and declarative sync, so a Huey or Dramatiq clocked or solar
 * row, or an RQ, arq or taskiq solar row, is legitimate. Opening one in the
 * Edit dialog must show that kind and send it back unchanged when the
 * operator saves some other field.
 */
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SchedulePublic } from "@/lib/api-types";
import { KIND_LABELS } from "@/lib/schedule-presets";

const formMocks = vi.hoisted(() => ({
  create: vi.fn(),
  update: vi.fn(),
}));

vi.mock("sonner", () => ({
  toast: {
    error: vi.fn(),
    success: vi.fn(),
  },
}));

vi.mock("@/hooks/use-schedules", () => ({
  useCreateSchedule: () => ({
    isPending: false,
    mutateAsync: formMocks.create,
  }),
  useUpdateSchedule: () => ({
    isPending: false,
    mutateAsync: formMocks.update,
  }),
}));

vi.mock("@/lib/api", () => ({
  ApiError: class ApiError extends Error {},
}));

// Radix Select renders its options only while open, which jsdom cannot
// drive reliably. This stand-in keeps each option in the DOM as a
// button that picks its value. "report empty value" makes the same
// onValueChange("") call Radix's hidden form <select> makes when the
// controlled value changes in the commit that first renders its option.
vi.mock("@/components/ui/select", async () => {
  const React = await import("react");
  type SelectState = {
    value?: string;
    onValueChange?: (value: string) => void;
  };
  const SelectContext = React.createContext<SelectState>({});
  return {
    Select: ({
      children,
      value,
      onValueChange,
    }: SelectState & { children?: ReactNode }) =>
      React.createElement(
        SelectContext.Provider,
        { value: { value, onValueChange } },
        React.createElement(
          "div",
          { "data-select": "" },
          children,
          React.createElement(
            "button",
            { type: "button", onClick: () => onValueChange?.("") },
            "report empty value",
          ),
        ),
      ),
    SelectTrigger: ({
      children,
      ...props
    }: React.ButtonHTMLAttributes<HTMLButtonElement>) =>
      React.createElement(
        "button",
        { type: "button", role: "combobox", ...props },
        children,
      ),
    SelectValue: () =>
      React.createElement(
        React.Fragment,
        null,
        React.useContext(SelectContext).value,
      ),
    SelectContent: ({ children }: { children?: ReactNode }) =>
      React.createElement("div", { role: "listbox" }, children),
    SelectItem: ({
      children,
      value,
    }: {
      children?: ReactNode;
      value: string;
    }) => {
      const select = React.useContext(SelectContext);
      return React.createElement(
        "button",
        {
          type: "button",
          role: "option",
          "aria-selected": select.value === value,
          onClick: () => select.onValueChange?.(value),
        },
        children,
      );
    },
  };
});

import { ScheduleFormDialog } from "@/components/domain/schedule-form-dialog";

const CLOCKED = "2026-12-25T09:00:00Z";
const SOLAR = "sunset:51.5074:-0.1278";

// Labels of the plain inputs the save test edits.
const FIELD_LABELS = {
  queue: "Queue (optional)",
  task_name: "Task name",
} as const;

function savedSchedule(overrides: Partial<SchedulePublic>): SchedulePublic {
  return {
    id: "schedule-1",
    project_id: "project-id",
    engine: "huey",
    scheduler: "z4j-scheduler",
    name: "year-end-report",
    task_name: "jobs.report",
    kind: "clocked",
    expression: CLOCKED,
    timezone: "UTC",
    queue: null,
    args: [],
    kwargs: {},
    priority: "normal",
    is_enabled: true,
    last_run_at: null,
    next_run_at: null,
    total_runs: 0,
    consecutive_failures: null,
    external_id: null,
    created_at: "2026-09-01T00:00:00Z",
    updated_at: "2026-09-01T00:00:00Z",
    catch_up: "skip",
    source: "declarative:django",
    source_hash: null,
    overlap_policy: "allow",
    paused_at: null,
    ...overrides,
  };
}

function renderEditDialog(existing: SchedulePublic) {
  render(
    <ScheduleFormDialog
      slug="project"
      open
      onClose={() => {}}
      existing={existing}
    />,
  );
}

function expectTiming(kindLabel: string, expression: string) {
  expect(screen.getByRole("option", { name: kindLabel })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  expect(screen.getByRole("textbox", { name: "Expression" })).toHaveValue(
    expression,
  );
}

function reportEmptyValue(selectLabel: string) {
  const select = screen
    .getByRole("combobox", { name: selectLabel })
    .closest<HTMLElement>("[data-select]");
  if (!select) throw new Error(`${selectLabel} select not rendered`);
  fireEvent.click(
    within(select).getByRole("button", { name: "report empty value" }),
  );
}

describe("ScheduleFormDialog editing a saved schedule", () => {
  beforeEach(() => {
    formMocks.create.mockReset();
    formMocks.update.mockReset();
    formMocks.update.mockResolvedValue(savedSchedule({}));
  });

  it.each([
    { engine: "huey", kind: "clocked", expression: CLOCKED, field: "queue" },
    {
      engine: "dramatiq",
      kind: "clocked",
      expression: CLOCKED,
      field: "queue",
    },
    { engine: "huey", kind: "solar", expression: SOLAR, field: "queue" },
    { engine: "dramatiq", kind: "solar", expression: SOLAR, field: "queue" },
    { engine: "rq", kind: "solar", expression: SOLAR, field: "queue" },
    // arq has no queue routing, so the form disables its queue input.
    {
      engine: "arq",
      kind: "solar",
      expression: "sunrise:40.7128:-74.006",
      field: "task_name",
    },
    {
      engine: "taskiq",
      kind: "solar",
      expression: "sunset:37.7749:-122.4194",
      field: "queue",
    },
  ] as const)(
    "keeps a $engine $kind schedule's kind and expression when its $field is saved",
    async ({ engine, kind, expression, field }) => {
      const existing = savedSchedule({ engine, kind, expression });
      renderEditDialog(existing);

      expectTiming(KIND_LABELS[kind], expression);
      expect(
        screen.getByRole("combobox", { name: "Kind" }),
      ).toHaveAccessibleDescription(/kept as saved/i);

      const edited = field === "queue" ? "reports" : "jobs.renamed";
      fireEvent.change(
        screen.getByRole("textbox", { name: FIELD_LABELS[field] }),
        { target: { value: edited } },
      );
      fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

      await waitFor(() => expect(formMocks.update).toHaveBeenCalledOnce());
      expect(formMocks.update).toHaveBeenCalledWith({
        scheduleId: existing.id,
        body: {
          engine,
          kind,
          expression,
          task_name: "jobs.report",
          timezone: "UTC",
          queue: null,
          args: [],
          kwargs: {},
          catch_up: "skip",
          is_enabled: true,
          [field]: edited,
        },
      });
      expect(formMocks.create).not.toHaveBeenCalled();
    },
  );

  it("keeps the saved kind across engines that allow it and resets it for one that does not", () => {
    renderEditDialog(savedSchedule({ engine: "huey", kind: "clocked" }));

    // celery offers clocked, and huey keeps offering the saved kind.
    fireEvent.click(screen.getByRole("option", { name: "celery" }));
    expectTiming(KIND_LABELS.clocked, CLOCKED);
    fireEvent.click(screen.getByRole("option", { name: "huey" }));
    expectTiming(KIND_LABELS.clocked, CLOCKED);

    // dramatiq offers no clocked kind, so choosing it resets the kind to
    // cron rather than building an unsupported combination.
    fireEvent.click(screen.getByRole("option", { name: "dramatiq" }));
    expectTiming(KIND_LABELS.cron, "0 * * * *");
    expect(
      screen.queryByRole("option", { name: KIND_LABELS.clocked }),
    ).not.toBeInTheDocument();
  });

  it("ignores the empty value Radix Select can report in place of an operator choice", async () => {
    const existing = savedSchedule({
      engine: "rq",
      kind: "solar",
      expression: SOLAR,
    });
    renderEditDialog(existing);

    reportEmptyValue("Kind");
    reportEmptyValue("Engine");

    expectTiming(KIND_LABELS.solar, SOLAR);
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(formMocks.update).toHaveBeenCalledOnce());
    expect(formMocks.update).toHaveBeenCalledWith({
      scheduleId: existing.id,
      body: expect.objectContaining({
        engine: "rq",
        kind: "solar",
        expression: SOLAR,
      }),
    });
  });

  it("keeps the saved kind when the dialog switches to another saved row", () => {
    const { rerender } = render(
      <ScheduleFormDialog
        slug="project"
        open
        onClose={() => {}}
        existing={savedSchedule({
          id: "schedule-0",
          engine: "dramatiq",
          kind: "cron",
          expression: "0 9 * * *",
        })}
      />,
    );
    rerender(
      <ScheduleFormDialog
        slug="project"
        open
        onClose={() => {}}
        existing={savedSchedule({ engine: "huey", kind: "clocked" })}
      />,
    );
    expectTiming(KIND_LABELS.clocked, CLOCKED);
  });
});
