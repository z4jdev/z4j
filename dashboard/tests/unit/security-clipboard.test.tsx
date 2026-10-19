import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Suspense, type ComponentType } from "react";

const state = vi.hoisted(() => ({
  copy: vi.fn(), success: vi.fn(), error: vi.fn(),
  start: vi.fn(), complete: vi.fn(),
}));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  createFileRoute: () => (options: Record<string, unknown>) => ({ options }),
}));
vi.mock("@tanstack/react-query", () => ({
  useQueryClient: () => ({ invalidateQueries: vi.fn() }),
  useQuery: () => ({ data: [] }),
  useMutation: () => ({ mutate: vi.fn() }),
}));
vi.mock("@/hooks/use-mfa", () => ({
  useMfaStatus: () => ({ data: { enrolled: false } }),
  useEnrollStart: () => ({ mutateAsync: state.start }),
  useEnrollComplete: () => ({ mutateAsync: state.complete }),
  useMfaDisable: vi.fn(), useRegenerateRecoveryCodes: vi.fn(),
  useRevokeTrustedDevice: vi.fn(), useTrustCurrentDevice: vi.fn(), useTrustedDevices: vi.fn(),
}));
vi.mock("sonner", () => ({ toast: { success: state.success, error: state.error } }));
import { Route } from "@/routes/_authenticated.settings.security";
const Page = (Route as unknown as { options: { component: ComponentType & { preload?: () => Promise<void> } } }).options.component;
beforeAll(async () => { await Page.preload?.(); }, 30_000);
beforeEach(() => {
  vi.clearAllMocks();
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: state.copy } });
  state.start.mockResolvedValue({ secret_base32: "TESTSECRET", provisioning_url: "otpauth://totp/z4j?secret=TESTSECRET" });
  state.complete.mockResolvedValue({ recovery_codes: ["AAAA-BBBB-CCCC", "DDDD-EEEE-FFFF"] });
});
async function showCopyButton(kind: "secret" | "recovery") {
  render(<Suspense fallback={null}><Page /></Suspense>);
  fireEvent.click(await screen.findByRole("button", { name: "Set up two-factor authentication" }));
  const secretButton = await screen.findByLabelText("Copy secret to clipboard");
  if (kind === "secret") return secretButton;
  fireEvent.change(screen.getByLabelText("Enter the 6-digit code from your app"), { target: { value: "123456" } });
  fireEvent.click(screen.getByRole("button", { name: "Confirm and activate" }));
  return screen.findByRole("button", { name: "Copy all" });
}
describe("security clipboard feedback", () => {
  it.each(["secret", "recovery"] as const)("does not report %s copied before the browser accepts it", async (kind) => {
    let resolve!: () => void;
    state.copy.mockReturnValue(new Promise<void>((done) => { resolve = done; }));
    fireEvent.click(await showCopyButton(kind));
    expect(state.copy).toHaveBeenCalledOnce();
    expect(state.success).not.toHaveBeenCalled();
    resolve();
    await waitFor(() => expect(state.success).toHaveBeenCalledOnce());
    expect(state.error).not.toHaveBeenCalled();
  });
  it.each(["secret", "recovery"] as const)("reports denied %s copy without claiming success", async (kind) => {
    state.copy.mockRejectedValue(new DOMException("Clipboard denied", "NotAllowedError"));
    fireEvent.click(await showCopyButton(kind));
    await waitFor(() => expect(state.error).toHaveBeenCalledWith(expect.stringContaining("Could not copy")));
    expect(state.success).not.toHaveBeenCalled();
    expect(screen.getByText(kind === "secret" ? "TESTSECRET" : "AAAA-BBBB-CCCC")).toBeInTheDocument();
  });
});
