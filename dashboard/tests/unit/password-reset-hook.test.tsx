import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

const postSpy = vi.hoisted(() => vi.fn());

vi.mock("@/lib/api", () => ({
  api: {
    get: vi.fn(),
    post: (...args: unknown[]) => postSpy(...args),
  },
  ApiError: class ApiError extends Error {},
}));

import { usePasswordResetConfirm } from "@/hooks/use-auth";

describe("usePasswordResetConfirm", () => {
  it("posts the exact reset-confirm endpoint and releases sensitive variables", async () => {
    const queryClient = new QueryClient({
      defaultOptions: { mutations: { retry: false } },
    });
    const wrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    );
    postSpy.mockResolvedValue({ success: true });
    const { result } = renderHook(() => usePasswordResetConfirm(), { wrapper });
    const body = {
      token: "S".repeat(43),
      new_password: "Abcd1234!xyz",
    };

    await act(async () => {
      await result.current.mutateAsync(body);
    });

    expect(postSpy).toHaveBeenCalledWith("/auth/password-reset/confirm", body);

    act(() => result.current.reset());
    await waitFor(() => {
      expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
    });
  });
});
