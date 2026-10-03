/**
 * The dead-letters page offers only engines whose dead letters an agent can
 * actually list, and requeues only through an agent that advertises it.
 */
import { describe, expect, it } from "vitest";

import {
  enginesAdvertising,
  pickAgentForAction,
  supportsAgentAction,
} from "@/lib/agent-capabilities";
import { projectNavigation } from "@/components/layout/project-navigation";

/** A timestamp the brain writes only when a WebSocket hello completes. */
const CONNECTED_AT = "2026-09-01T00:00:00Z";

const rq = {
  id: "rq-agent",
  last_connect_at: CONNECTED_AT,
  last_seen_at: CONNECTED_AT,
  engine_adapters: ["rq"],
  capabilities: {
    rq: [
      "submit_task",
      "retry_task",
      "requeue_dead_letter",
      "list_dead_letters",
      "retry_by_reference_v1",
    ],
  },
};

const dramatiqRedis = {
  id: "dramatiq-agent",
  last_connect_at: CONNECTED_AT,
  last_seen_at: CONNECTED_AT,
  engine_adapters: ["dramatiq"],
  capabilities: {
    dramatiq: ["submit_task", "retry_task", "purge_queue", "list_dead_letters"],
  },
};

const celery = {
  id: "celery-agent",
  last_connect_at: CONNECTED_AT,
  last_seen_at: CONNECTED_AT,
  engine_adapters: ["celery"],
  capabilities: { celery: ["submit_task", "retry_task", "bulk_retry"] },
};

const longPoll = {
  id: "long-poll",
  last_connect_at: null,
  last_seen_at: CONNECTED_AT,
  engine_adapters: [],
  capabilities: {},
};

describe("engines whose dead letters can be listed", () => {
  it("come only from hellos that advertised list_dead_letters, sorted", () => {
    expect(
      enginesAdvertising([celery, rq, dramatiqRedis], "list_dead_letters"),
    ).toEqual(["dramatiq", "rq"]);
    expect(enginesAdvertising([celery], "list_dead_letters")).toEqual([]);
    expect(enginesAdvertising(undefined, "list_dead_letters")).toEqual([]);
  });

  it("never include an engine on the word of an unreported inventory", () => {
    // The brain admits a long-poll agent per command, but it has told the
    // dashboard nothing, so there is no engine to offer.
    expect(enginesAdvertising([longPoll], "list_dead_letters")).toEqual([]);
    expect(supportsAgentAction(longPoll, "rq", "list_dead_letters")).toBe(true);
  });
});

describe("requeue follows the advertised capability, not the engine", () => {
  it("is offered for rq and withheld for a dramatiq agent that lists only", () => {
    const agents = [rq, dramatiqRedis, celery];
    expect(pickAgentForAction(agents, "rq", "requeue_dead_letter")?.id).toBe(
      "rq-agent",
    );
    expect(
      pickAgentForAction(agents, "dramatiq", "requeue_dead_letter"),
    ).toBeUndefined();
    expect(
      pickAgentForAction(agents, "celery", "requeue_dead_letter"),
    ).toBeUndefined();
  });

  it("does not demand the safe retry marker, which only retries need", () => {
    const old = { ...rq, capabilities: { rq: ["requeue_dead_letter"] } };
    expect(supportsAgentAction(old, "rq", "requeue_dead_letter")).toBe(true);
    expect(supportsAgentAction(old, "rq", "retry_task")).toBe(false);
  });
});

describe("navigation", () => {
  it("places dead letters beside tasks for every project role", () => {
    for (const role of ["viewer", "operator", "admin"] as const) {
      const labels = projectNavigation("prod", role).map((item) => item.label);
      expect(labels.indexOf("Dead letters")).toBe(labels.indexOf("Tasks") + 1);
    }
    const item = projectNavigation("prod", "viewer").find(
      (entry) => entry.label === "Dead letters",
    );
    expect(item?.to).toBe("/projects/prod/dead-letters");
    expect(item?.group).toBe("Monitor");
  });
});
