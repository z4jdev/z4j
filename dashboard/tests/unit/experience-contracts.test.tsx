import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { projectNavigation } from "@/components/layout/project-navigation";
import { guidedAction, guidedConditions } from "@/lib/automation-builder";
import { parseTaskListSearch } from "@/lib/task-list-search";
import { scheduleSummary } from "@/lib/schedule-presets";
import {
  agentsForEngine,
  pickAgentForAction,
  supportsAgentAction,
} from "@/lib/agent-capabilities";
import { FormField } from "@/components/domain/form-field";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

/** A timestamp the brain writes only when a WebSocket hello completes. */
const CONNECTED_AT = "2026-09-01T00:00:00Z";

describe("live agent capability contracts", () => {
  it("scopes actions to the selected engine and requires safe retry admission", () => {
    const agent = {
      last_connect_at: CONNECTED_AT,
      engine_adapters: ["celery", "rq"],
      capabilities: {
        celery: ["cancel_task", "retry_task", "retry_by_reference_v1"],
        rq: ["retry_task"],
      },
    };
    expect(supportsAgentAction(agent, "celery", "cancel_task")).toBe(true);
    expect(supportsAgentAction(agent, "celery", "retry_task")).toBe(true);
    expect(supportsAgentAction(agent, "rq", "retry_task")).toBe(false);
    expect(supportsAgentAction(agent, "rq", "cancel_task")).toBe(false);
    expect(supportsAgentAction(agent, "huey", "cancel_task")).toBe(false);
  });
  it("does not grant actions from unknown or legacy flat fixture shapes", () => {
    expect(supportsAgentAction(undefined, "celery", "retry_task")).toBe(false);
    for (const capabilities of [
      {},
      { retry_task: true },
      { celery: "retry_task" },
    ]) {
      expect(
        supportsAgentAction(
          {
            engine_adapters: ["celery"],
            capabilities,
            last_connect_at: CONNECTED_AT,
          },
          "celery",
          "retry_task",
        ),
      ).toBe(false);
    }
  });
  it("treats an inventory the transport never reported as unknown, not empty", () => {
    // The row a long-poll agent keeps: no hello, so nothing was recorded.
    const longPoll = {
      engine_adapters: [],
      capabilities: {},
      last_connect_at: null,
      last_seen_at: CONNECTED_AT,
    };
    expect(supportsAgentAction(longPoll, "celery", "retry_task")).toBe(true);
    expect(supportsAgentAction(longPoll, "rq", "cancel_task")).toBe(true);
    // A hello that listed no engines is a report (a scheduler-only process).
    const schedulerOnly = { ...longPoll, last_connect_at: CONNECTED_AT };
    expect(supportsAgentAction(schedulerOnly, "celery", "cancel_task")).toBe(
      false,
    );
    expect(supportsAgentAction(schedulerOnly, "celery", "retry_task")).toBe(
      false,
    );
  });
  it("keeps unreported agents eligible and drops agents reporting other engines", () => {
    const contract = ["cancel_task", "retry_task", "retry_by_reference_v1"];
    const agents = [
      // A token minted but never used: no upload, no hello.
      {
        id: "never-connected",
        engine_adapters: [],
        capabilities: {},
        last_connect_at: null,
        last_seen_at: null,
      },
      {
        id: "scheduler-only",
        engine_adapters: [],
        capabilities: {},
        last_connect_at: CONNECTED_AT,
        last_seen_at: CONNECTED_AT,
      },
      {
        id: "rq",
        engine_adapters: ["rq"],
        capabilities: { rq: contract },
        last_connect_at: CONNECTED_AT,
        last_seen_at: CONNECTED_AT,
      },
      {
        id: "long-poll",
        engine_adapters: [],
        capabilities: {},
        last_connect_at: null,
        last_seen_at: CONNECTED_AT,
      },
      {
        id: "celery",
        engine_adapters: ["celery"],
        capabilities: { celery: contract },
        last_connect_at: CONNECTED_AT,
        last_seen_at: CONNECTED_AT,
      },
    ];
    const ids = (engine: string) =>
      agentsForEngine(agents, engine).map(({ id }) => id);
    expect(ids("celery")).toEqual(["long-poll", "celery"]);
    expect(ids("rq")).toEqual(["rq", "long-poll"]);
    expect(agentsForEngine(undefined, "celery")).toEqual([]);
    // Without operator input an advertised contract wins over an unknown one,
    // and a token that never connected is never picked.
    const pick = (engine: string, pool = agents) =>
      pickAgentForAction(pool, engine, "retry_task")?.id;
    expect(pick("celery")).toBe("celery");
    expect(pick("dramatiq")).toBe("long-poll");
    expect(
      pick(
        "dramatiq",
        agents.filter(({ id }) => id !== "long-poll"),
      ),
    ).toBeUndefined();
  });
});

describe("scoped navigation", () => {

  it("never invents a project on workspace routes or before permissions resolve", () => {
    expect(projectNavigation(undefined, "admin")).toEqual([]);
    expect(projectNavigation("prod", null)).toEqual([]);
  });
  it("keeps admin-only destinations out of operator and viewer navigation", () => {
    for (const role of ["viewer", "operator"] as const) {
      const labels = projectNavigation("prod", role).map((item) => item.label);
      expect(labels).toContain("Issues");
      expect(labels).toContain("Automation");
      expect(labels).not.toContain("Agents");
      expect(labels).not.toContain("Audit log");
    }
    expect(
      projectNavigation("prod", "admin").map((item) => item.label),
    ).toContain("Agents");
  });
});
describe("lossless guided automation", () => {
  it("preserves supported flat conditions", () => {
    expect(guidedConditions('{"engine":"rq","task_name":"email"}')).toEqual({
      engine: "rq",
      task_name: "email",
    });
    expect(guidedConditions("{}")).toEqual({});
  });
  it("requires advanced mode for grouping, numeric conditions or unknown fields", () => {
    for (const text of [
      '{"or":[{"engine":"rq"}]}',
      '{"runtime_ms_gt":10}',
      '{"engine":["rq"]}',
      '{"future":true}',
      "[]",
      "null",
      "{",
    ])
      expect(guidedConditions(text)).toBeNull();
  });
  it("never discards extra action parameters or multiple actions", () => {
    expect(guidedAction('[{"type":"retry"}]')).toBe("retry");
    for (const text of [
      '[{"type":"notify","channel_id":"x"}]',
      '[{"type":"notify"},{"type":"retry"}]',
      "[null]",
      '[{"type":"purge"}]',
    ])
      expect(guidedAction(text)).toBeNull();
  });
});
describe("task deep-link validation", () => {
  it("retains supported scope and drops invalid states and priorities", () => {
    expect(
      parseTaskListSearch({
        state: "failure",
        search: "email",
        priority: ["critical", "bogus"],
      }),
    ).toEqual({ state: "failure", search: "email", priority: ["critical"] });
    expect(
      parseTaskListSearch({ state: "bogus", search: {}, priority: "critical" }),
    ).toEqual({ state: undefined, search: undefined, priority: undefined });
  });
});
describe("accessible field wiring", () => {
  it("associates a text input with its label and error", () => {
    render(
      <FormField label="Rule name" error="Required">
        <Input defaultValue="" />
      </FormField>,
    );
    expect(
      screen.getByRole("textbox", { name: "Rule name" }),
    ).toHaveAccessibleDescription("Required");
    expect(screen.getByRole("textbox")).toHaveAttribute("aria-invalid", "true");
    fireEvent.click(screen.getByText("Rule name"));
  });
  it("labels the control inside a nested select", () => {
    render(
      <FormField label="Engine" hint="Select a task engine">
        <Select defaultValue="rq">
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="rq">RQ</SelectItem>
          </SelectContent>
        </Select>
      </FormField>,
    );
    expect(
      screen.getByRole("combobox", { name: "Engine" }),
    ).toHaveAccessibleDescription("Select a task engine");
  });
});
it("describes presets without pretending to calculate custom cron execution", () => {
  expect(scheduleSummary("cron", "0 9 * * *", "Europe/London")).toBe(
    "Daily at 09:00 · Europe/London",
  );
  expect(scheduleSummary("cron", "invalid", "UTC")).toBe("Custom cron · UTC");
});
