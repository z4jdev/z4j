import { afterEach, describe, expect, it, vi } from "vitest";

import { demoFetch } from "@/lib/api.demo";

afterEach(() => vi.unstubAllGlobals());

describe("demo request identity", () => {
  it("selects task detail by engine as well as task ID", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({ items: [
      { task_id: "shared-id", engine: "celery", name: "celery-task" },
      { task_id: "shared-id", engine: "rq", name: "rq-task" },
    ] })));
    const response = await demoFetch("/api/v1/projects/demo/tasks/rq/shared-id");
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ engine: "rq", name: "rq-task" });
  });

  it("returns 404 when the task ID exists only in another engine", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({ items: [
      { task_id: "celery-only", engine: "celery" },
    ] })));
    const response = await demoFetch("/api/v1/projects/demo/tasks/rq/celery-only");
    expect(response.status).toBe(404);
  });

  it("preserves a Request object's POST method and login body", async () => {
    const request = new Request("https://demo.z4j.com/api/v1/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "request@example.com" }),
    });
    const response = await demoFetch(request);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ user: { email: "request@example.com" } });
  });

  it("applies explicit init overrides to a Request object", async () => {
    const request = new Request("https://demo.z4j.com/api/v1/auth/login", {
      method: "PUT",
      body: JSON.stringify({ email: "original@example.com" }),
    });
    const response = await demoFetch(request, {
      method: "POST",
      body: JSON.stringify({ email: "override@example.com" }),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ user: { email: "override@example.com" } });
  });

  it("forwards non-API Request objects and init without replacing them", async () => {
    const response = new Response("asset");
    const fetch = vi.fn(async () => response);
    vi.stubGlobal("fetch", fetch);
    const request = new Request("https://demo.z4j.com/demo-data/sample.json");
    const init = { cache: "no-store" } as const;
    expect(await demoFetch(request, init)).toBe(response);
    expect(fetch).toHaveBeenCalledWith(request, init);
  });
});
