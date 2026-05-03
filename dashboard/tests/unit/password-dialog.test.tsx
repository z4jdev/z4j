/**
 * Component tests for ``PasswordChangeDialog``.
 *
 * Covers the load-bearing validations:
 * - Mismatched new + confirm shows the inline error AND blocks
 *   submission (does not call the change-password mutation).
 * - Matching passwords pass through to the mutation.
 * - The form labels are wired to inputs via ``htmlFor`` (a11y
 *   regression guard for the audit ``a11y-label-htmlfor`` pass).
 */
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { PasswordChangeDialog } from "@/components/layout/password-dialog";

// ``useChangePassword`` calls the API; we replace it with a spy
// so the test does not need a real fetch + brain backend.
const mutateSpy = vi.fn();

vi.mock("@/hooks/use-users", () => ({
  useChangePassword: () => ({
    mutate: mutateSpy,
    isPending: false,
  }),
}));

// ``sonner`` calls touch global state; the test is happy with
// no-op stubs.
vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

function renderDialog() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <PasswordChangeDialog />
    </QueryClientProvider>,
  );
}

async function openDialog(user: ReturnType<typeof userEvent.setup>) {
  const trigger = screen.getByRole("button", { name: /change password/i });
  await user.click(trigger);
}

describe("PasswordChangeDialog", () => {
  it("renders inputs paired to labels via htmlFor", async () => {
    const user = userEvent.setup();
    renderDialog();
    await openDialog(user);

    // ``getByLabelText`` walks the htmlFor->id pairing - if the
    // pairing is missing this throws and the test fails.
    expect(screen.getByLabelText(/current password/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^new password/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/confirm new password/i)).toBeInTheDocument();
  });

  it("blocks submission when new + confirm do not match", async () => {
    const user = userEvent.setup();
    mutateSpy.mockClear();
    renderDialog();
    await openDialog(user);

    await user.type(screen.getByLabelText(/current password/i), "old-pass-1234");
    await user.type(screen.getByLabelText(/^new password/i), "new-pass-abcd");
    await user.type(
      screen.getByLabelText(/confirm new password/i),
      "DIFFERENT-pass",
    );

    // The inline validation message renders.
    expect(
      screen.getByText(/passwords do not match/i),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /change password/i }));

    // Mutation must NOT have fired.
    expect(mutateSpy).not.toHaveBeenCalled();
  });

  it("calls the mutation when new + confirm match", async () => {
    const user = userEvent.setup();
    mutateSpy.mockClear();
    renderDialog();
    await openDialog(user);

    await user.type(screen.getByLabelText(/current password/i), "old-pass-1234");
    await user.type(screen.getByLabelText(/^new password/i), "new-pass-abcd");
    await user.type(
      screen.getByLabelText(/confirm new password/i),
      "new-pass-abcd",
    );

    await user.click(screen.getByRole("button", { name: /change password/i }));

    expect(mutateSpy).toHaveBeenCalledTimes(1);
    expect(mutateSpy).toHaveBeenCalledWith(
      { current_password: "old-pass-1234", new_password: "new-pass-abcd" },
      expect.any(Object),
    );
  });
});
