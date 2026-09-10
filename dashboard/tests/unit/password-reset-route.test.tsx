import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Suspense } from "react";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "@/lib/api";

const authMocks = vi.hoisted(() => ({
  mutateAsync: vi.fn(),
  reset: vi.fn(),
}));

vi.mock("@tanstack/react-router", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-router")>()),
  createFileRoute: () => (options: Record<string, unknown>) => ({
    ...options,
    options,
  }),
  Link: ({ children, to }: { children: React.ReactNode; to: string }) => (
    <a href={to}>{children}</a>
  ),
}));

vi.mock("@/components/layout/theme-toggle", () => ({
  ThemeToggle: () => <button type="button">Switch theme</button>,
}));

vi.mock("@/hooks/use-auth", () => ({
  PASSWORD_POLICY_FALLBACK: {
    min_length: 12,
    required_character_classes: 3,
    character_class_names: ["lowercase", "uppercase", "digit", "symbol"],
  },
  usePasswordPolicy: () => ({
    data: {
      min_length: 12,
      required_character_classes: 3,
      character_class_names: ["lowercase", "uppercase", "digit", "symbol"],
    },
  }),
  usePasswordResetConfirm: () => ({
    mutateAsync: authMocks.mutateAsync,
    reset: authMocks.reset,
    isPending: false,
  }),
}));

import { Route } from "@/routes/reset";

const PasswordResetPage = (
  Route as unknown as {
    options: { component: React.ComponentType };
  }
).options.component;

beforeAll(async () => {
  await (
    PasswordResetPage as React.ComponentType & { preload?: () => Promise<void> }
  ).preload?.();
}, 30_000);

const token = "R".repeat(43);

function setResetLocation(suffix: string) {
  window.history.replaceState({}, "", `/reset${suffix}`);
}

async function renderPage() {
  await act(async () => {
    render(
      <Suspense fallback={<p>Loading reset form</p>}>
        <PasswordResetPage />
      </Suspense>,
    );
  });
}

describe("PasswordResetPage", () => {
  beforeEach(() => {
    authMocks.mutateAsync.mockReset();
    authMocks.reset.mockReset();
    setResetLocation("");
  });

  it("captures only a valid fragment token and scrubs query and fragment from history", async () => {
    setResetLocation(`?token=query-must-not-win#token=${token}`);

    await renderPage();

    expect(
      await screen.findByRole("heading", { name: /choose a new password/i }),
    ).toBeInTheDocument();
    expect(window.location.pathname).toBe("/reset");
    expect(window.location.search).toBe("");
    expect(window.location.hash).toBe("");
    expect(document.body).not.toHaveTextContent(token);
  });

  it("rejects a query-only token, clears it, and never exposes the form", async () => {
    setResetLocation(`?token=${token}`);

    await renderPage();

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /password reset link invalid/i,
    );
    expect(screen.queryByLabelText(/^new password$/i)).not.toBeInTheDocument();
    expect(window.location.href).not.toContain(token);
    expect(authMocks.mutateAsync).not.toHaveBeenCalled();
  });

  it("wires accessible new-password fields and blocks client-invalid input", async () => {
    const user = userEvent.setup();
    setResetLocation(`#token=${token}`);
    await renderPage();

    const password = await screen.findByLabelText(/^new password$/i);
    const confirmation = screen.getByLabelText(/confirm new password/i);
    expect(password).toHaveAttribute("autocomplete", "new-password");
    expect(confirmation).toHaveAttribute("autocomplete", "new-password");

    await user.type(password, "too-short");
    await user.type(confirmation, "different");
    await user.click(screen.getByRole("button", { name: /^reset password$/i }));

    expect(screen.getByRole("alert")).toHaveTextContent(
      /use at least 12 characters/i,
    );
    expect(password).toHaveAttribute("aria-invalid", "true");
    expect(authMocks.mutateAsync).not.toHaveBeenCalled();
  });

  it("posts the exact body, clears secrets, and announces success", async () => {
    const user = userEvent.setup();
    authMocks.mutateAsync.mockResolvedValue({ success: true });
    setResetLocation(`#token=${token}`);
    await renderPage();

    await user.type(
      await screen.findByLabelText(/^new password$/i),
      "Abcd1234!xyz",
    );
    await user.type(
      screen.getByLabelText(/confirm new password/i),
      "Abcd1234!xyz",
    );
    await user.click(screen.getByRole("button", { name: /^reset password$/i }));

    await waitFor(() => {
      expect(authMocks.mutateAsync).toHaveBeenCalledWith({
        token,
        new_password: "Abcd1234!xyz",
      });
    });
    expect(authMocks.reset).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("status")).toHaveTextContent(
      /password has been changed/i,
    );
    expect(screen.getByRole("link", { name: /go to login/i })).toHaveAttribute(
      "href",
      "/login",
    );
    expect(screen.queryByLabelText(/^new password$/i)).not.toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(token);
    expect(window.location.href).not.toContain(token);
  });

  it("clears secrets and shows the generic terminal state for an expired token", async () => {
    const user = userEvent.setup();
    authMocks.mutateAsync.mockRejectedValue(
      new ApiError(404, {
        error: "invalid_or_expired",
        message: `do not render ${token}`,
      }),
    );
    setResetLocation(`#token=${token}`);
    await renderPage();

    await user.type(
      await screen.findByLabelText(/^new password$/i),
      "Abcd1234!xyz",
    );
    await user.type(
      screen.getByLabelText(/confirm new password/i),
      "Abcd1234!xyz",
    );
    await user.click(screen.getByRole("button", { name: /^reset password$/i }));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(
        /invalid, expired, or has already been used/i,
      );
    });
    expect(screen.queryByLabelText(/^new password$/i)).not.toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(token);
    expect(window.location.href).not.toContain(token);
  });
});
