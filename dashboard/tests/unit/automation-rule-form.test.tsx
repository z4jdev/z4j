import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AutomationRuleFormDialog } from "@/components/domain/automation-rule-form-dialog";

function renderDialog(isAdmin = false) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <AutomationRuleFormDialog
        slug="proj"
        open
        onClose={() => {}}
        isAdmin={isAdmin}
      />
    </QueryClientProvider>,
  );
}

describe("AutomationRuleFormDialog", () => {
  it("renders the create title and its fields", () => {
    renderDialog();
    expect(screen.getByText("New automation rule")).toBeInTheDocument();
    expect(screen.getByText("Trigger")).toBeInTheDocument();
    // dry_run + enabled switches both present.
    expect(screen.getAllByRole("switch")).toHaveLength(2);
  });

  it("blocks submit with a required error when the name is empty", async () => {
    const user = userEvent.setup();
    renderDialog();
    await user.click(screen.getByRole("button", { name: /create rule/i }));
    // trigger/conditions/actions all default valid; only name fails.
    expect(await screen.findByText("required")).toBeInTheDocument();
  });

  it("warns a non-admin when the actions include a destructive type", async () => {
    renderDialog(false);
    // The actions textarea starts with a notify-only default (no warning).
    expect(screen.queryByText(/destructive action/i)).not.toBeInTheDocument();
    // The actions textarea is the only field whose value contains "notify".
    // Set the JSON directly (userEvent.type treats {,[ as key syntax).
    fireEvent.click(screen.getByRole("button", { name: "Edit advanced JSON" }));
    const actions = screen.getByRole("textbox", {
      name: "Actions (JSON array)",
    });
    fireEvent.change(actions, { target: { value: '[{"type":"retry"}]' } });
    expect(await screen.findByText(/destructive action/i)).toBeInTheDocument();
  });
});
