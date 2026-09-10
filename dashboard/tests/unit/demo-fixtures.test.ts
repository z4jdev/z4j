/**
 * The public demo is served from JSON fixtures that no compiler checks. These
 * assertions keep them on the brain's vocabulary and consistent with each
 * other, which is how "acked_ok" shipped once.
 */
import { describe, expect, it } from "vitest";

import { OUTCOME_BY_STATUS } from "@/components/domain/schedule-run-strip";

interface RunCell {
  fire_id: string;
  status: string;
  latency_ms: number | null;
  error_code?: string | null;
}
interface RunsDoc {
  items: { schedule_id: string; runs: RunCell[] }[];
  circuit_breaker_threshold: number;
}
interface ScheduleRecord {
  id: string;
  name: string;
  consecutive_failures?: number;
  next_run_at_offset_s?: number | null;
  is_enabled?: boolean;
  paused_at?: string | null;
}
interface LintDoc {
  workers_evaluated: number;
  workers_not_evaluated: number;
  findings_by_severity: Record<string, number>;
  workers: {
    engine: string;
    evaluated: boolean;
    findings: { rule_id: string; severity: string }[];
  }[];
}

const runsDocs = import.meta.glob<{ default: RunsDoc }>(
  "../../src/lib/demo-data/projects/*/schedule-runs.json",
  { eager: true },
);
const scheduleDocs = import.meta.glob<{
  default: { items: ScheduleRecord[] } | ScheduleRecord[];
}>("../../src/lib/demo-data/projects/*/schedules.json", { eager: true });
const lintDocs = import.meta.glob<{ default: LintDoc }>(
  "../../src/lib/demo-data/projects/*/workers-lint.json",
  { eager: true },
);

const projectOf = (path: string) => path.split("/").at(-2) ?? path;

describe("demo schedule-runs fixtures", () => {
  const known = new Set(Object.keys(OUTCOME_BY_STATUS));

  it("exist for four projects", () => {
    expect(Object.keys(runsDocs)).toHaveLength(4);
  });

  for (const [path, mod] of Object.entries(runsDocs)) {
    const project = projectOf(path);
    const doc = mod.default;
    const schedulesMod = Object.entries(scheduleDocs).find(
      ([p]) => projectOf(p) === project,
    )?.[1];
    const schedules = Array.isArray(schedulesMod?.default)
      ? schedulesMod.default
      : (schedulesMod?.default.items ?? []);

    it(`${project}: every fire status is one the brain writes`, () => {
      for (const row of doc.items) {
        for (const c of row.runs)
          expect(known, `${row.schedule_id} ${c.status}`).toContain(c.status);
      }
    });

    it(`${project}: fire ids are unique and disjoint from schedule ids`, () => {
      const ids = doc.items.flatMap((r) => r.runs.map((c) => c.fire_id));
      expect(new Set(ids).size).toBe(ids.length);
      const scheduleIds = new Set(schedules.map((s) => s.id));
      for (const id of ids) expect(scheduleIds.has(id), id).toBe(false);
    });

    it(`${project}: consecutive_failures matches the fixture's own history`, () => {
      const rows = new Map(doc.items.map((r) => [r.schedule_id, r.runs]));
      for (const s of schedules) {
        let run = 0;
        for (const c of rows.get(s.id) ?? []) {
          if (c.status !== "failed" && c.status !== "acked_failed") break;
          run += 1;
        }
        expect(s.consecutive_failures, s.name).toBe(
          Math.min(run, doc.circuit_breaker_threshold),
        );
      }
    });

    it(`${project}: failed cells carry error detail, in-flight cells carry none`, () => {
      for (const row of doc.items) {
        for (const c of row.runs) {
          if (c.status === "acked_failed" || c.status === "failed")
            expect(c.error_code, row.schedule_id).toBeTruthy();
          if (c.status === "accepted" || c.status === "pending") {
            expect(c.latency_ms).toBeNull();
            expect(c.error_code ?? null).toBeNull();
          }
        }
      }
    });

    it(`${project}: an enabled, unpaused schedule is not seeded overdue`, () => {
      for (const s of schedules) {
        if (s.is_enabled === false || s.paused_at) continue;
        if (
          typeof s.next_run_at_offset_s === "number" &&
          s.name !== "emails.send_scheduled_campaigns"
        ) {
          expect(s.next_run_at_offset_s, s.name).toBeGreaterThan(0);
        }
      }
    });
  }
});

describe("demo worker lint fixtures", () => {
  for (const [path, mod] of Object.entries(lintDocs)) {
    const project = projectOf(path);
    const doc = mod.default;
    it(`${project}: only celery workers are evaluated and the counts agree`, () => {
      for (const w of doc.workers) {
        expect(w.evaluated, w.engine).toBe(w.engine === "celery");
        for (const f of w.findings)
          expect(f.rule_id).toMatch(/^celery\.[a-z-]+$/);
      }
      expect(doc.workers_evaluated).toBe(
        doc.workers.filter((w) => w.evaluated).length,
      );
      expect(doc.workers_not_evaluated).toBe(
        doc.workers.filter((w) => !w.evaluated).length,
      );
      const bySeverity: Record<string, number> = {};
      for (const w of doc.workers)
        for (const f of w.findings)
          bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
      expect(doc.findings_by_severity).toEqual(bySeverity);
    });
  }
});

describe("demo agent capability fixtures", () => {
  const docs = import.meta.glob<{
    default: {
      engine_adapters: string[];
      capabilities: Record<string, unknown>;
    }[];
  }>("../../src/lib/demo-data/projects/*/agents.json", { eager: true });
  for (const [path, mod] of Object.entries(docs)) {
    it(`${projectOf(path)}: capabilities use the live per-adapter wire format`, () => {
      for (const agent of mod.default) {
        for (const [engine, capabilities] of Object.entries(
          agent.capabilities,
        )) {
          expect(agent.engine_adapters).toContain(engine);
          expect(Array.isArray(capabilities)).toBe(true);
          for (const capability of capabilities as unknown[])
            expect(typeof capability).toBe("string");
        }
      }
    });
  }
});
