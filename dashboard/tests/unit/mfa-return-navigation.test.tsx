import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Suspense, type ComponentType } from "react";
import { isSafeNextPath } from "@/lib/safe-next-path";

const state = vi.hoisted(() => ({ next: "", navigate: vi.fn(), verify: vi.fn() }));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  createFileRoute: () => (options: Record<string, unknown>) => ({
    options, useSearch: () => ({ next: state.next }),
  }),
  useNavigate: () => state.navigate,
  redirect: vi.fn(),
}));
vi.mock("@/hooks/use-mfa", () => ({
  useMfaVerify: () => ({ mutateAsync: state.verify, isPending: false }),
}));
vi.mock("@/lib/api", () => ({ api: { get: vi.fn() }, ApiError: class extends Error {} }));
vi.mock("@/components/layout/theme-toggle", () => ({ ThemeToggle: () => null }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), warning: vi.fn() } }));

import { Route } from "@/routes/login_.mfa";
const MfaPage = (Route as unknown as { options: { component: ComponentType & { preload?: () => Promise<void> } } }).options.component;

beforeAll(async () => { await MfaPage.preload?.(); }, 30_000);

beforeEach(() => {
  vi.clearAllMocks();
  state.verify.mockResolvedValue({ used_recovery_code: false });
});

describe("MFA return navigation", () => {
  it.each([
    "/", "/projects/demo/tasks", "/settings/security?tab=mfa#codes",
    "/tasks?query=https://example.com", "/tasks?q=%09%2Fexample.com",
  ])("accepts an ordinary same-origin return path %j", (path) => {
    expect(isSafeNextPath(path)).toBe(true);
  });

  it.each([
    "/\t/evil.example", "/\n/evil.example", "/\r/evil.example",
    "/\t\\evil.example", "//evil.example", "/\\evil.example", "https://evil.example",
  ])("returns home instead of following unsafe next %j", async (next) => {
    state.next = next;
    render(<Suspense fallback={null}><MfaPage /></Suspense>);
    fireEvent.change(await screen.findByLabelText("Code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    await waitFor(() => expect(state.navigate).toHaveBeenCalledWith({ to: "/" }));
    expect(state.verify).toHaveBeenCalledOnce();
  });
});
