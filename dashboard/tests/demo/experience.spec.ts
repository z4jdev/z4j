import { test, expect } from "@playwright/test";

const project = "/projects/django.example.com";
test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("z4j-theme", "light"));
});

test("task filters survive an investigation", async ({ page }) => {
  await page.goto(`${project}/tasks?state=failure`);
  await page
    .getByRole("searchbox", { name: "Search", exact: true })
    .fill("reports");
  await expect(page).toHaveURL(/search=reports/);
  const taskLink = page.locator('a[href*="/tasks/celery/"]').first();
  await expect(taskLink).toHaveAttribute("href", /reports/);
  await taskLink.click();
  await page.getByRole("link", { name: "Back to tasks" }).click();
  await expect(page).toHaveURL(/\/tasks\?state=failure&search=reports/);
  await expect(
    page.getByRole("searchbox", { name: "Search", exact: true }),
  ).toHaveValue("reports");
});

test("task actions require an explicit capable agent when several are available", async ({
  page,
}) => {
  await page.goto(`${project}/tasks?state=failure`);
  await page.locator('a[href*="/tasks/celery/"]').first().click();
  await expect(
    page.getByRole("button", { name: "Retry", exact: true }),
  ).toBeDisabled();
  await page.getByRole("combobox", { name: "Command target agent" }).click();
  await page.getByRole("option").first().click();
  await expect(
    page.getByRole("button", { name: "Retry", exact: true }),
  ).toBeEnabled();
  await expect(
    page.getByRole("button", { name: "Cancel", exact: true }),
  ).toBeEnabled();
});

test("issues expose related task history and retain their filter", async ({
  page,
}) => {
  await page.goto(`${project}/issues`);
  await page.getByRole("button", { name: "Ongoing", exact: true }).click();
  await expect(page).toHaveURL(/status=ongoing/);
  await page.locator("summary").first().click();
  await expect(
    page.getByRole("link", { name: "Search history for this task" }).first(),
  ).toBeVisible();
  await page.reload();
  await expect(
    page.getByRole("button", { name: "Ongoing", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
});

test("failed issue requests cannot produce an all-clear", async ({ page }) => {
  await page.route(
    "**/demo-data/projects/django.example.com/issues.json",
    (route) =>
      route.fulfill({
        status: 503,
        contentType: "application/json",
        body: "{}",
      }),
  );
  await page.goto(`${project}/issues`);
  await expect(
    page.getByText(
      "Issues are unavailable. Their recovery status could not be checked.",
    ),
  ).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText("No issues in this view")).toHaveCount(0);
});

test("search opens shortcut help and workspace navigation has no invented project", async ({
  page,
}) => {
  await page.goto("/home");
  await page.getByRole("button", { name: "Search pages and tasks" }).click();
  await expect(
    page.getByRole("dialog").locator('a[href*="/projects/default"]'),
  ).toHaveCount(0);
  await page.getByRole("option", { name: /Keyboard shortcuts/ }).click();
  await expect(
    page.getByRole("heading", { name: /Keyboard Shortcuts/i }),
  ).toBeVisible();
});

test("schedule presets populate the accessible expression field", async ({
  page,
}) => {
  await page.goto(`${project}/schedules`);
  await page.getByRole("button", { name: /New schedule/i }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("button", { name: "Weekdays at 09:00" }).click();
  await expect(
    dialog.getByRole("textbox", { name: "Expression", exact: true }),
  ).toHaveValue("0 9 * * 1-5");
  await expect(
    dialog.getByRole("combobox", { name: "If a scheduled run was missed" }),
  ).toBeVisible();
});

test("automation retains JSON the guided editor cannot represent", async ({
  page,
}) => {
  await page.goto(`${project}/automation`);
  await page.getByRole("button", { name: /New rule/i }).click();
  const dialog = page.getByRole("dialog");
  await dialog
    .getByRole("textbox", { name: "Task name contains" })
    .fill("email");
  await dialog.getByRole("button", { name: "Edit advanced JSON" }).click();
  const conditions = dialog.getByRole("textbox", {
    name: "Conditions (JSON object)",
  });
  expect(JSON.parse(await conditions.inputValue())).toEqual({
    task_name: "email",
  });
  const advanced = '{"or":[{"engine":"rq"},{"engine":"celery"}]}';
  await conditions.fill(advanced);
  await expect(
    dialog.getByRole("button", { name: "Use guided editor" }),
  ).toBeDisabled();
  await expect(conditions).toHaveValue(advanced);
});

test("demo mutations remain blocked", async ({ page }) => {
  await page.goto(`${project}/automation`);
  await page.getByRole("button", { name: /New rule/i }).click();
  const dialog = page.getByRole("dialog");
  await dialog
    .getByRole("textbox", { name: "Name", exact: true })
    .fill("Demo regression check");
  await dialog.getByRole("button", { name: "Create rule" }).click();
  await expect(page.getByText("This is a demo", { exact: true })).toBeVisible();
  await expect(dialog).toBeVisible();
  // Sonner injects its own CSS after the app stylesheet. Its toast must
  // still use the same elevation as the other floating surfaces.
  const elevation = await dialog.evaluate(
    (element) => getComputedStyle(element).boxShadow,
  );
  const shadows = await page
    .locator("[data-sonner-toast]")
    .evaluateAll((elements) =>
      elements.map((element) => getComputedStyle(element).boxShadow),
    );
  expect(shadows.length).toBeGreaterThan(0);
  // Tailwind prepends transparent ring layers to the dialog shadow.
  for (const shadow of shadows) {
    expect(shadow).not.toBe("none");
    expect(elevation.endsWith(shadow)).toBe(true);
  }
});

test("collapsed project switching and mobile focus return", async ({
  page,
}) => {
  await page.goto(project);
  await page.getByRole("button", { name: "Collapse sidebar" }).click();
  await page.getByRole("button", { name: /Switch project:/ }).click();
  await page.getByRole("menuitem", { name: "Workspace home" }).click();
  await expect(page).toHaveURL(/\/home$/);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Open menu" }).click();
  await expect(
    page.getByRole("dialog", { name: "Navigation", exact: true }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("button", { name: "Open menu" })).toBeFocused();
});

for (const width of [390, 768, 1024]) {
  test(`working surfaces fit a ${width}px viewport`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    for (const route of ["tasks", "schedules", "issues", "automation"]) {
      await page.goto(`${project}/${route}`);
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
        route,
      ).toBe(true);
    }
  });
}
