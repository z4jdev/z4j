/**
 * The demo interceptor's audit routes, driven through ``demoFetch`` against
 * the real seed files. The audit route used to be unanchored, so the Exports
 * panel's ``/audit/export-jobs`` request was answered with the audit page and
 * rendered as twenty empty export jobs.
 */
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { demoFetch } from "@/lib/api.demo";

const DATA_ROOT = resolve(__dirname, "../../src/lib/demo-data");

/** The static-asset fetch the interceptor makes for a seed file. */
async function diskFetch(input: RequestInfo | URL): Promise<Response> {
  const url = typeof input === "string" ? input : input.toString();
  const match = /^\/demo-data\/(.+)$/.exec(url);
  if (!match) return new Response("not a demo asset", { status: 500 });
  try {
    const body = await readFile(resolve(DATA_ROOT, match[1]), "utf8");
    return new Response(body, {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  } catch {
    return new Response("missing", { status: 404 });
  }
}

const get = (path: string) => demoFetch(path, { method: "GET" });

describe("demo audit routing", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn(diskFetch));
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("answers the export-jobs list as a brain without a sink does", async () => {
    const res = await get(
      "/api/v1/projects/example.com/audit/export-jobs?limit=20",
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      items: [],
      sink: null,
      sink_location: null,
    });
  });

  it("answers a single export job, and its download, with a 404", async () => {
    for (const path of [
      "/api/v1/projects/example.com/audit/export-jobs/0b3f7e2a-3c1e-4d2b-9a1f-6d2c1b0e9f11",
      "/api/v1/projects/example.com/audit/export-jobs/0b3f7e2a-3c1e-4d2b-9a1f-6d2c1b0e9f11/download",
    ]) {
      const res = await get(path);
      expect(res.status, path).toBe(404);
      expect((await res.json()).error).toBe("demo_record_not_found");
    }
  });

  it("still pages the audit log itself, with and without a query", async () => {
    for (const path of [
      "/api/v1/projects/example.com/audit",
      "/api/v1/projects/example.com/audit?limit=20",
    ]) {
      const res = await get(path);
      expect(res.status, path).toBe(200);
      const body = (await res.json()) as {
        items: Array<Record<string, unknown>>;
      };
      expect(body.items.length, path).toBeGreaterThan(0);
      expect(body.items[0], path).toHaveProperty("action");
      expect(body, path).not.toHaveProperty("sink");
    }
  });
});
