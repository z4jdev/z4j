import { afterEach, describe, expect, it, vi } from "vitest";

import { api, apiCall } from "@/lib/api";
import { buildAuditExportUrl } from "@/hooks/use-audit";
import { buildExportUrl } from "@/hooks/use-tasks";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("apiCall", () => {
  it("refuses cross-origin absolute URLs before fetch", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      apiCall("https://evil.example/api/v1/projects"),
    ).rejects.toThrow("cross-origin");

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("allows same-origin absolute URLs", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const body = await apiCall<{ ok: boolean }>(
      `${window.location.origin}/api/v1/projects`,
    );

    expect(body).toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/projects",
      expect.objectContaining({ credentials: "include" }),
    );
  });

  it("exposes a durable Location before response-body processing", async () => {
    const text = vi.fn().mockRejectedValue(new Error("body stream lost"));
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        status: 202,
        ok: true,
        headers: new Headers({
          Location: "/api/v1/projects/p/bulk-retry-requests/r",
        }),
        text,
      }),
    );
    const locations: string[] = [];

    await expect(
      api.postResource(
        "/projects/p/bulk-retry-requests",
        { idempotency_key: "k" },
        (location) => locations.push(location),
      ),
    ).rejects.toThrow("body stream lost");

    expect(locations).toEqual(["/api/v1/projects/p/bulk-retry-requests/r"]);
  });

  it("normalizes FastAPI structured detail into an ApiError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            detail: {
              error: "matching task count exceeds max",
              max: 1000,
              matched_at_least: 1001,
            },
          }),
          {
            status: 400,
            headers: { "Content-Type": "application/json" },
          },
        ),
      ),
    );

    await expect(
      apiCall("/projects/p/bulk-retry-requests", {
        method: "POST",
        body: {},
      }),
    ).rejects.toMatchObject({
      status: 400,
      code: "matching task count exceeds max",
      details: {
        max: 1000,
        matched_at_least: 1001,
      },
    });
  });
});

describe("export URL builders", () => {
  it("encodes task export project slugs as path segments", () => {
    expect(buildExportUrl("bad/slug", "csv")).toBe(
      "/api/v1/projects/bad%2Fslug/tasks?format=csv",
    );
  });

  it("encodes audit export project slugs as path segments", () => {
    expect(buildAuditExportUrl("bad/slug", "json")).toBe(
      "/api/v1/projects/bad%2Fslug/audit?format=json",
    );
  });
});
