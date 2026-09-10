import { expect, test } from "@playwright/test";

for (const width of [390, 768, 1440]) {
  test(`saved views apply real filters and fit at ${width}px`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/projects/django.example.com/tasks");
    await page
      .getByRole("button", { name: "Saved views", exact: true })
      .click();
    await page.getByRole("menuitem", { name: /^Failed tasks/ }).click();
    await expect(
      page.getByRole("combobox", { name: "Task state" }),
    ).toContainText("failure");
    await expect(page).toHaveURL(/state=failure/);
    await page
      .getByRole("button", { name: "Saved views", exact: true })
      .click();
    await page.getByRole("menuitem", { name: "Manage views…" }).click();
    const dialog = page.getByRole("dialog", { name: "Manage saved views" });
    await expect(
      dialog.getByRole("button", { name: "Apply Urgent tasks" }),
    ).toBeVisible();
    await dialog.getByRole("button", { name: "Apply Urgent tasks" }).click();
    await expect(
      page.getByRole("button", { name: "Filter by priority" }),
    ).toContainText("2 priorities");
    await expect(
      page.getByRole("combobox", { name: "Task state" }),
    ).toContainText("All states");
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
  });
}

test("view query failure has a retry and demo saves remain blocked", async ({
  page,
}) => {
  await page.route("**/demo-data/user/saved-task-views.json", (route) =>
    route.fulfill({ status: 503, body: "unavailable" }),
  );
  await page.goto("/projects/django.example.com/tasks");
  await page.getByRole("button", { name: "Saved views", exact: true }).click();
  await expect(
    page.getByRole("menuitem", { name: /Could not load views/ }),
  ).toBeVisible({ timeout: 15000 });
  await page.unroute("**/demo-data/user/saved-task-views.json");
  await page.getByRole("menuitem", { name: /Could not load views/ }).click();
  await page.getByRole("button", { name: "Saved views", exact: true }).click();
  await page.getByRole("menuitem", { name: "Save current filters…" }).click();
  const dialog = page.getByRole("dialog", { name: "Save task view" });
  await dialog
    .getByRole("textbox", { name: "View name" })
    .fill("Demo must not save");
  await dialog.getByRole("button", { name: "Save view", exact: true }).click();
  await expect(dialog.getByRole("alert")).toBeVisible();
  await expect(dialog).toBeVisible();
});

test("a full collection of saved views scrolls inside the menu", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 640 });
  await page.route("**/demo-data/user/saved-task-views.json", (route) =>
    route.fulfill({
      json: Array.from({ length: 100 }, (_, i) => ({
        id: `view-${i}`,
        name: `Saved filter ${i + 1}`,
        filters: { state: null, priority: [], search: `query-${i + 1}` },
        created_at: "2026-09-01T10:00:00Z",
        updated_at: "2026-09-01T10:00:00Z",
      })),
    }),
  );
  await page.goto("/projects/django.example.com/tasks");
  await page.getByRole("button", { name: "Saved views", exact: true }).click();
  const menu = page.getByRole("menu");
  const box = await menu.boundingBox();
  expect(box).not.toBeNull();
  expect(box!.y).toBeGreaterThanOrEqual(0);
  expect(box!.y + box!.height).toBeLessThanOrEqual(640);
  await page.getByRole("menuitem", { name: /^Saved filter 100 / }).click();
  await expect(
    page.getByRole("searchbox", { name: "Search", exact: true }),
  ).toHaveValue("query-100");
});

test("saved views supports keyboard dismissal and dialog focus return", async ({
  page,
}) => {
  await page.goto("/projects/django.example.com/tasks");
  const trigger = page.getByRole("button", {
    name: "Saved views",
    exact: true,
  });
  // Verify keyboard focus against the loaded menu. Opening while the
  // asynchronous view query is pending legitimately focuses another item.
  await trigger.click();
  await expect(page.getByRole("menuitem", { name: /^Failed tasks/ })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("menu")).toBeHidden();
  await expect(trigger).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("menuitem", { name: /^Failed tasks/ }),
  ).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(trigger).toBeFocused();
  await trigger.click();
  await page.getByRole("menuitem", { name: "Manage views…" }).click();
  await expect(
    page.getByRole("dialog", { name: "Manage saved views" }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(trigger).toBeFocused();
});
