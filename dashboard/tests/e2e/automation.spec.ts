/**
 * z4j E2E - automation rule create (happy path).
 *
 * The 1.7 rule engine's operator-facing entry point: create a rule
 * from the Automation page and confirm it lands in the list. We use
 * the NOTIFY action - the safe, non-destructive action that ships
 * enabled for every role (retry / cancel are ADMIN + fresh-MFA gated
 * and would drag a step-up flow into what should be a stable smoke
 * test). The rule form already defaults to a single ``notify`` action
 * and the ``task.failed`` trigger, so creating one is a name away.
 *
 * Deliberately NOT asserted here: that the rule actually FIRES. Firing
 * depends on a real task-failure event flowing through the dispatcher
 * on its own schedule; asserting on that timing is the kind of async
 * flake this suite exists to avoid. We assert the create round-trips
 * to the list (and clean up after ourselves so the run is repeatable).
 */
import { test, expect } from "./fixtures";

const rand = () => Math.random().toString(36).slice(2, 8);

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

test.describe("automation - rule create", () => {
  test("create a NOTIFY rule and see it in the list", async ({ adminPage }) => {
    const name = `e2e-notify-${rand()}`;

    // The default project is seeded on first boot; the crash-coverage
    // and visual-regression specs rely on it too.
    await adminPage.goto("/projects/default/automation");
    await expect(
      adminPage.getByRole("heading", { name: /^automation$/i }),
    ).toBeVisible();

    // Open the create dialog. New rule => name + the shipped defaults
    // (task.failed trigger, a single notify action, dry-run on).
    await adminPage.getByRole("button", { name: /new rule/i }).click();
    const dialog = adminPage.getByRole("dialog");
    await expect(
      dialog.getByRole("heading", { name: /new automation rule/i }),
    ).toBeVisible();

    // The Name field has no associated <label for>; target its
    // placeholder (the notify action + trigger defaults are already
    // populated, so name is the only field we need to set). Wait for
    // it to be editable so we never race the dialog's open transition.
    const nameField = dialog.getByPlaceholder("retry-flaky-emails");
    await expect(nameField).toBeEditable();
    await nameField.fill(name);
    await dialog.getByRole("button", { name: /create rule/i }).click();

    // Dialog closes and the new rule shows in the table with its
    // trigger + notify action rendered.
    await expect(dialog).toBeHidden();
    const row = adminPage.getByRole("row", {
      name: new RegExp(escapeRegex(name)),
    });
    await expect(row).toBeVisible();
    await expect(row).toContainText("task.failed");
    await expect(row).toContainText("notify");

    // Clean up so the suite can re-run against a reused brain. Scope
    // the confirm dialog by its heading so we never bind to the create
    // dialog mid-exit-transition.
    await row.getByRole("button", { name: "Delete", exact: true }).click();
    const confirm = adminPage
      .getByRole("dialog")
      .filter({ hasText: /delete rule/i });
    await expect(
      confirm.getByRole("heading", { name: /delete rule/i }),
    ).toBeVisible();
    await confirm.getByRole("button", { name: "Delete", exact: true }).click();
    await expect(confirm).toBeHidden();

    await expect(
      adminPage.getByRole("row", { name: new RegExp(escapeRegex(name)) }),
    ).toHaveCount(0);
  });
});
