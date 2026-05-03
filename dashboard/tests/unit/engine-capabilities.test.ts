/**
 * Tests for the per-engine capability map.
 *
 * docs/SCHEDULER.md §13.1 promises form-field gating per engine.
 * The capability map IS the gating - if a wrong entry lands here
 * the form silently restricts a legitimate workflow (or worse,
 * permits a kind the adapter doesn't actually support and the
 * operator hits a runtime failure later).
 *
 * These tests pin the matrix so the next person adding an engine
 * has a forced moment to think about what their adapter supports.
 */

import { describe, expect, it } from "vitest";

import {
  capsForEngine,
  isKindSupported,
} from "@/lib/engine-capabilities";

describe("capsForEngine", () => {
  it("celery supports every kind including solar", () => {
    const c = capsForEngine("celery");
    expect(c.kinds).toEqual(
      expect.arrayContaining(["cron", "interval", "one_shot", "solar"]),
    );
    expect(c.hasQueues).toBe(true);
    expect(c.queueHint).toContain("RabbitMQ");
  });

  it("rq supports cron / interval / one_shot but NOT solar", () => {
    const r = capsForEngine("rq");
    expect(r.kinds).toEqual(
      expect.arrayContaining(["cron", "interval", "one_shot"]),
    );
    expect(r.kinds).not.toContain("solar");
    expect(r.hasQueues).toBe(true);
  });

  it("dramatiq supports cron + interval only", () => {
    const d = capsForEngine("dramatiq");
    expect(d.kinds.sort()).toEqual(["cron", "interval"]);
  });

  it("arq has no queues", () => {
    // Distinguishing case - the queue field gates on this. arq
    // addresses tasks by function name with no broker-side queue
    // routing, so the form must disable the field.
    const a = capsForEngine("arq");
    expect(a.hasQueues).toBe(false);
    expect(a.queueHint).toMatch(/no queue/i);
  });

  it("huey supports cron + interval", () => {
    const h = capsForEngine("huey");
    expect(h.kinds.sort()).toEqual(["cron", "interval"]);
  });

  it("taskiq supports cron / interval / one_shot", () => {
    const t = capsForEngine("taskiq");
    expect(t.kinds.sort()).toEqual(["cron", "interval", "one_shot"]);
  });

  it("unknown engine falls back to permissive defaults", () => {
    // A future engine adapter (say "z4j-procrastinate") should not
    // be silently restricted before this map is updated. Better to
    // permit and refine.
    const u = capsForEngine("not-a-real-engine");
    expect(u.kinds.length).toBe(4);
    expect(u.hasQueues).toBe(true);
  });

  it("engine name is case-insensitive", () => {
    expect(capsForEngine("RQ").kinds).toEqual(capsForEngine("rq").kinds);
    expect(capsForEngine("Celery").kinds).toEqual(capsForEngine("celery").kinds);
  });
});

describe("isKindSupported", () => {
  it("rq + solar is unsupported", () => {
    expect(isKindSupported("rq", "solar")).toBe(false);
  });

  it("celery + solar is supported", () => {
    expect(isKindSupported("celery", "solar")).toBe(true);
  });

  it("every engine supports interval", () => {
    // Interval is the universal kind - simplest semantics, every
    // adapter pair handles it. If this assertion ever flips for a
    // new engine, the form's safe-fallback (snap kind back to
    // 'cron' on engine change) needs to be revisited.
    for (const engine of ["celery", "rq", "dramatiq", "arq", "huey", "taskiq"]) {
      expect(isKindSupported(engine, "interval")).toBe(true);
    }
  });

  it("every engine except dramatiq + huey supports one_shot", () => {
    expect(isKindSupported("celery", "one_shot")).toBe(true);
    expect(isKindSupported("rq", "one_shot")).toBe(true);
    expect(isKindSupported("arq", "one_shot")).toBe(true);
    expect(isKindSupported("taskiq", "one_shot")).toBe(true);
    expect(isKindSupported("dramatiq", "one_shot")).toBe(false);
    expect(isKindSupported("huey", "one_shot")).toBe(false);
  });
});
