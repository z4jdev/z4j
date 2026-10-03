import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  exportJobsRefetchInterval,
  useExportJobs,
  type ExportJobListResponse,
} from "@/hooks/use-export-jobs";

const IDLE_POLL_MS = 30_000;

function listResponse(status: string | null): ExportJobListResponse {
  return {
    items:
      status === null
        ? []
        : [
            {
              id: "0b3f7e2a-3c1e-4d2b-9a1f-6d2c1b0e9f11",
              project_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
              user_id: "1b4e28ba-2fa1-11d2-883f-0016d3cca427",
              export_type: "audit",
              format: "jsonl",
              status,
              sink: "local",
              location: null,
              created_at: "2026-10-03T00:00:00Z",
              started_at: null,
              completed_at: null,
              row_count: null,
              size_bytes: null,
              error: null,
              filters: {},
              downloadable: false,
            },
          ],
    sink: "local",
    sink_location: null,
  };
}

describe("exportJobsRefetchInterval", () => {
  it("stops polling once the list query is in error", () => {
    expect(
      exportJobsRefetchInterval({ status: "error", data: undefined }),
    ).toBe(false);
    // A stale success payload does not keep an errored query polling.
    expect(
      exportJobsRefetchInterval({
        status: "error",
        data: listResponse("running"),
      }),
    ).toBe(false);
  });

  it("polls fast while a job moves and slowly once settled", () => {
    expect(
      exportJobsRefetchInterval({
        status: "success",
        data: listResponse("queued"),
      }),
    ).toBe(3_000);
    expect(
      exportJobsRefetchInterval({
        status: "success",
        data: listResponse("running"),
      }),
    ).toBe(3_000);
    expect(
      exportJobsRefetchInterval({
        status: "success",
        data: listResponse("succeeded"),
      }),
    ).toBe(IDLE_POLL_MS);
    expect(
      exportJobsRefetchInterval({
        status: "success",
        data: listResponse(null),
      }),
    ).toBe(IDLE_POLL_MS);
    expect(
      exportJobsRefetchInterval({ status: "pending", data: undefined }),
    ).toBe(IDLE_POLL_MS);
  });
});

describe("useExportJobs polling", () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    // Only the timers react-query schedules on: the poll interval and its
    // setTimeout(0) notifier. React's own scheduler stays real.
    vi.useFakeTimers({
      toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval"],
    });
    queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
  });

  afterEach(() => {
    queryClient.clear();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("stops polling after an error and resumes after a successful refetch", async () => {
    const fetchMock = vi.fn().mockImplementation(() =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            error: "forbidden",
            message: "auditor or admin role required",
            request_id: null,
            details: {},
          }),
          { status: 403, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const wrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    );
    const { result } = renderHook(() => useExportJobs("p"), { wrapper });

    await vi.waitFor(() => expect(result.current.status).toBe("error"));
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenLastCalledWith(
      "/api/v1/projects/p/audit/export-jobs?limit=20",
      expect.objectContaining({ method: "GET" }),
    );

    // Three idle poll periods pass; the 403 is not repeated.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(IDLE_POLL_MS * 3 + 1_000);
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);

    // The role was granted (or the brain came back): the next refetch
    // succeeds and the idle poll resumes.
    fetchMock.mockImplementation(() =>
      Promise.resolve(
        new Response(JSON.stringify(listResponse(null)), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );
    await act(async () => {
      await result.current.refetch();
    });
    await vi.waitFor(() => expect(result.current.status).toBe("success"));
    expect(fetchMock).toHaveBeenCalledTimes(2);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(IDLE_POLL_MS + 1_000);
    });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
});
