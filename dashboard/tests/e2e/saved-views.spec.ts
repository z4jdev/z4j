import { expect } from "@playwright/test";
import { test } from "./fixtures";

test("personal task views persist, apply, rename, replace filters and delete", async ({
  adminPage: page,
}) => {
  const name = `Payment failures ${Date.now()}`;
  await page.goto("/projects/default/tasks");
  await page.getByRole("combobox", { name: "Task state" }).click();
  await page.getByRole("option", { name: "failure", exact: true }).click();
  await page
    .getByRole("searchbox", { name: "Search", exact: true })
    .fill("payment");
  await page.getByRole("button", { name: "Saved views", exact: true }).click();
  await page.getByRole("menuitem", { name: "Save current filters…" }).click();
  let dialog = page.getByRole("dialog", { name: "Save task view" });
  await dialog.getByRole("textbox", { name: "View name" }).fill(name);
  await dialog.getByRole("button", { name: "Save view", exact: true }).click();
  await expect(dialog).toBeHidden();
  await page.goto("/projects/default/tasks");
  await page.getByRole("button", { name: "Saved views", exact: true }).click();
  await page.getByRole("menuitem", { name: new RegExp(name) }).click();
  await expect(
    page.getByRole("searchbox", { name: "Search", exact: true }),
  ).toHaveValue("payment");
  await expect(
    page.getByRole("combobox", { name: "Task state" }),
  ).toContainText("failure");
  await page.reload();
  await expect(
    page.getByRole("searchbox", { name: "Search", exact: true }),
  ).toHaveValue("payment");
  await page.getByRole("button", { name: /^Clear(?:\s*\d+)?$/ }).click();
  await page
    .getByRole("searchbox", { name: "Search", exact: true })
    .fill("invoice");
  await page.getByRole("button", { name: "Saved views", exact: true }).click();
  await page.getByRole("menuitem", { name: "Manage views…" }).click();
  dialog = page.getByRole("dialog", { name: "Manage saved views" });
  await dialog
    .getByRole("button", { name: `Edit ${name}`, exact: true })
    .click();
  dialog = page.getByRole("dialog", { name: "Edit saved view" });
  await dialog
    .getByRole("textbox", { name: "View name" })
    .fill(`${name} renamed`);
  await dialog.getByRole("button", { name: "Save changes" }).click();
  dialog = page.getByRole("dialog", { name: "Manage saved views" });
  // Renaming must preserve the saved filters unless replacement is explicit.
  await dialog.getByRole("button", { name: `Apply ${name} renamed` }).click();
  await expect(
    page.getByRole("searchbox", { name: "Search", exact: true }),
  ).toHaveValue("payment");
  await page
    .getByRole("searchbox", { name: "Search", exact: true })
    .fill("invoice");
  await page.getByRole("button", { name: "Saved views", exact: true }).click();
  await page.getByRole("menuitem", { name: "Manage views…" }).click();
  await page.getByRole("button", { name: `Edit ${name} renamed` }).click();
  dialog = page.getByRole("dialog", { name: "Edit saved view" });
  await dialog
    .getByRole("checkbox", {
      name: "Replace saved filters with the current task filters",
    })
    .check();
  await dialog.getByRole("button", { name: "Save changes" }).click();
  await page
    .getByRole("dialog", { name: "Manage saved views" })
    .getByRole("button", { name: `Apply ${name} renamed` })
    .click();
  await expect(
    page.getByRole("searchbox", { name: "Search", exact: true }),
  ).toHaveValue("invoice");
  await page.getByRole("button", { name: "Saved views", exact: true }).click();
  await page.getByRole("menuitem", { name: "Manage views…" }).click();
  await page.getByRole("button", { name: `Delete ${name} renamed` }).click();
  await page
    .getByRole("dialog", { name: "Delete saved view" })
    .getByRole("button", { name: "Delete view", exact: true })
    .click();
  await expect(
    page.getByRole("dialog", { name: "Delete saved view" }),
  ).toBeHidden();
  await expect(
    page.getByRole("button", { name: `Apply ${name} renamed` }),
  ).toHaveCount(0);
  // Close the parent explicitly after the nested confirmation. Keyboard focus
  // and Escape are covered separately without overlapping two exit animations.
  await page
    .getByRole("dialog", { name: "Manage saved views" })
    .getByRole("button", { name: "Close", exact: true })
    .click();
  await expect(
    page.getByRole("searchbox", { name: "Search", exact: true }),
  ).toHaveValue("invoice");
});
