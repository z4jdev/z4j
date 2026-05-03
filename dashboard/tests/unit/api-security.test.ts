import { afterEach, describe, expect, it, vi } from "vitest";

import { apiCall } from "@/lib/api";
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
