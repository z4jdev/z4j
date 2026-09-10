import { test, expect, type Page } from "@playwright/test";
const project = "/projects/tasks.example.com";
const lists = [
  "commands",
  "audit",
  "agents",
  "queues",
  "workers",
  "tasks",
  "schedules",
  "issues",
  "automation",
];
async function geometry(page: Page) {
  return page.evaluate(() => {
    const box = (selector: string) => {
      const b = document.querySelector(selector)!.getBoundingClientRect();
      return { x: b.x, y: b.y, width: b.width, height: b.height };
    };
    return {
      header: box('[data-slot="page-header"]'),
      search: box('[data-slot="filter-toolbar"] input'),
      tableHead: (({ x, y, height }) => ({ x, y, height }))(box("thead tr")),
    };
  });
}
test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("z4j-theme", "light"));
});
for (const width of [1440, 768, 390]) {
  test(`Commands and Audit share control geometry at ${width}px`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.goto(`${project}/commands`);
    await expect(page.locator("tbody tr").first()).toBeVisible();
    const commands = await geometry(page);
    await page.goto(`${project}/audit`);
    await expect(page.locator("tbody tr").first()).toBeVisible();
    expect(await geometry(page)).toEqual(commands);
    for (const route of ["commands", "audit"]) {
      await page.goto(`${project}/${route}`);
      await expect(
        page.locator('thead button:not([role="checkbox"])'),
      ).toHaveCount(5);
      const before = await geometry(page);
      await page
        .getByRole("searchbox", { name: "Search", exact: true })
        .fill("no-record-matches-this-filter-xyz");
      await expect(page.locator('[data-slot="empty-state"]')).toBeVisible();
      expect(await geometry(page)).toEqual(before);
      await expect(
        page.getByRole("button", { name: "Go to first page" }),
      ).toBeVisible();
    }
  });
}
test("all project lists keep search first, with canonical controls and sortable columns", async ({
  page,
}) => {
  for (const route of lists) {
    await page.goto(`${project}/${route}`);
    await expect(
      page.locator('[data-slot="filter-toolbar"] input'),
    ).toBeVisible();
    await expect(page.locator("h1")).toHaveCount(1);
    const g = await geometry(page);
    expect(g.search.x).toBe(g.header.x);
    expect(g.search.y - (g.header.y + g.header.height)).toBe(24);
    expect(g.search.width).toBe(320);
    expect(g.search.height).toBe(36);
    expect(g.tableHead.height).toBe(44);
    const heights = await page
      .locator('[data-slot="page-actions"] [data-slot="button"]')
      .evaluateAll((buttons) =>
        buttons.map((button) => button.getBoundingClientRect().height),
      );
    expect(heights.every((height) => height === 36)).toBe(true);
    const unsortable = await page
      .locator("th")
      .evaluateAll((headers) =>
        headers
          .filter(
            (header) =>
              header.textContent?.trim() &&
              !["Actions", "Manage"].includes(header.textContent.trim()) &&
              !header.querySelector('button:not([role="checkbox"])'),
          )
          .map((header) => header.textContent),
      );
    expect(unsortable, route).toEqual([]);
  }
});
for (const route of ["commands", "audit"]) {
  test(`${route} retains controls and headers when requests fail`, async ({
    page,
  }) => {
    await page.route(
      `**/demo-data/projects/tasks.example.com/${route}.json*`,
      (response) =>
        response.fulfill({
          status: 503,
          contentType: "application/json",
          body: "{}",
        }),
    );
    await page.goto(`${project}/${route}`);
    await expect(
      page.getByRole("searchbox", { name: "Search", exact: true }),
    ).toBeVisible();
    await expect(page.locator("th")).toHaveCount(5);
    await expect(page.getByRole("alert")).toBeVisible({ timeout: 15000 });
    await expect(
      page.getByRole("button", { name: "Retry", exact: true }),
    ).toBeVisible();
    await expect(page.locator('[data-slot="empty-state"]')).toHaveCount(0);
  });
}
test("sorting works in the browser and retains record links", async ({
  page,
}) => {
  await page.goto(`${project}/queues`);
  await page.getByRole("button", { name: "Name", exact: true }).focus();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("columnheader", { name: "Name", exact: true }),
  ).toHaveAttribute("aria-sort", "ascending");
  const values = await page
    .locator("tbody tr td:first-child")
    .allTextContents();
  expect(values).toEqual(
    [...values].sort(
      new Intl.Collator(undefined, { numeric: true, sensitivity: "base" })
        .compare,
    ),
  );
  await page.goto(`${project}/tasks`);
  const href = await page
    .locator('tbody a[href*="/tasks/"]')
    .first()
    .getAttribute("href");
  await page.getByRole("button", { name: "Task", exact: true }).click();
  await expect(page.locator(`tbody a[href="${href}"]`)).toHaveCount(1);
});
test("project pages, details and notification tabs contain wide content on phones", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 1000 });
  for (const route of [
    "",
    ...lists,
    "schedules/30000000-0000-4003-c000-000000000001",
    "workers/70000000-0000-4003-0000-000000000001",
    "tasks/celery/d430af8d-6d77-581f-9ad2-a4c7782c7d18",
    "settings/notifications/channels",
    "settings/notifications/subscriptions",
    "settings/notifications/deliveries",
  ]) {
    await page.goto(`${project}/${route}`);
    await expect(page.locator("h1")).toBeVisible();
    await page.waitForLoadState("networkidle");
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
      route,
    ).toBe(true);
  }
});

test("notification subpages have one page title and a separate section heading", async ({
  page,
}) => {
  for (const scope of [
    "/settings/notifications",
    `${project}/settings/notifications`,
  ]) {
    for (const tab of ["channels", "subscriptions", "deliveries"]) {
      await page.goto(`${scope}/${tab}`);
      await expect(page.locator("h1")).toHaveCount(1);
      await expect(page.locator("h1")).toBeVisible();
    }
  }
});

test("task search retains keyboard focus and bulk controls fit on phones", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 1000 });
  await page.goto(`${project}/tasks`);
  await page
    .getByRole("checkbox", { name: "Select row", exact: true })
    .first()
    .click();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page
    .locator('[data-slot="collection-controls"]')
    .getByRole("button", { name: "Cancel", exact: true })
    .click();
  const search = page.getByRole("searchbox");
  await search.pressSequentially("health", { delay: 100 });
  await expect(search).toHaveValue("health");
  await expect(search).toBeFocused();
  await expect(page.locator("tbody")).toContainText("health");
});
