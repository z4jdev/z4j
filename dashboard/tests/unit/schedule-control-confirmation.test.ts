import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import { waitForScheduleControl } from "@/hooks/use-schedules";

vi.mock("@/lib/api", () => ({ api: { get: vi.fn() } }));

const location =
  "/api/v1/projects/example/schedules/external-control-operations/operation";

describe("native schedule confirmation", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
  });
  afterEach(() => vi.useRealTimers());

  it("keeps an accepted operation pending until source confirmation", async () => {
    vi.mocked(api.get)
      .mockResolvedValueOnce({ id: "operation", status: "CLAIMED" })
      .mockResolvedValueOnce({ id: "operation", status: "APPLIED" });
    let completed = false;
    const waiting = waitForScheduleControl(location).then(() => {
      completed = true;
    });
    await vi.advanceTimersByTimeAsync(500);
    expect(completed).toBe(false);
    await vi.advanceTimersByTimeAsync(500);
    await waiting;
    expect(completed).toBe(true);
  });

  it("reports uncertain outcomes instead of success", async () => {
    vi.mocked(api.get).mockResolvedValue({
      id: "operation",
      status: "AMBIGUOUS",
    });
    await expect(waitForScheduleControl(location)).rejects.toThrow(
      "check the native schedule",
    );
  });

  it("bounds waiting without claiming completion", async () => {
    vi.mocked(api.get).mockResolvedValue({
      id: "operation",
      status: "PENDING",
    });
    const result = expect(waitForScheduleControl(location)).rejects.toThrow(
      "awaiting source confirmation",
    );
    await vi.runAllTimersAsync();
    await result;
  });

  it("refuses a foreign operation URL", async () => {
    await expect(
      waitForScheduleControl("https://unrelated.example/operation"),
    ).rejects.toThrow("invalid status address");
    expect(api.get).not.toHaveBeenCalled();
  });
});
