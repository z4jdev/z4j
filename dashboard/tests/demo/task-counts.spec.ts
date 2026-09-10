import { expect, test } from "@playwright/test";
import history from "../../src/lib/demo-data/projects/django.example.com/tasks.json" with { type: "json" };

const path = "/projects/django.example.com/tasks";
const total = history.items.length;
const footer = '[data-slot="table-pagination"] [role="status"]';

test("total and all-matching selection include records beyond the current page", async ({
  page,
}) => {
  await page.goto(path);
  await expect(page.locator(footer)).toHaveText(
    `Showing 50 of ${total} matching tasks`,
  );
  await expect(
    page.getByLabel(`${total} matching tasks`, { exact: true }),
  ).toBeVisible();
  await page.getByRole("checkbox", { name: "Select all", exact: true }).check();
  await expect(page.getByText("50 selected", { exact: true })).toBeVisible();
  await page
    .getByRole("button", { name: `Select all ${total} matching`, exact: true })
    .click();
  await expect(
    page.getByText(`All ${total} matching tasks selected`, { exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "This page only", exact: true })
    .click();
  await expect(page.getByText("50 selected", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Go to next page" }).click();
  await expect(page.locator(footer)).toHaveText(
    `Showing ${total - 50} of ${total} matching tasks`,
  );
  await expect(
    page.getByRole("button", { name: "Go to next page" }),
  ).toBeDisabled();
  await page.getByRole("checkbox", { name: "Select all", exact: true }).check();
  await expect(
    page.getByRole("button", {
      name: `Select all ${total} matching`,
      exact: true,
    }),
  ).toBeVisible();
});

test("page size changes the visible row count while preserving the total", async ({
  page,
}) => {
  await page.goto(path);
  await expect(page.locator(footer)).toContainText(
    `of ${total} matching tasks`,
  );
  await page.getByRole("combobox", { name: "Rows per page" }).click();
  await page.getByRole("option", { name: "10", exact: true }).click();
  await expect(page.locator(footer)).toHaveText(
    `Showing 10 of ${total} matching tasks`,
  );
  await expect(
    page.getByRole("checkbox", { name: "Select row", exact: true }),
  ).toHaveCount(10);
});

test("filtered totals follow state, priority, literal search, and zero results", async ({
  page,
}) => {
  const matches = history.items.filter(
    (task) => task.state === "failure" && task.priority === "high",
  );
  await page.goto(`${path}?state=failure`);
  await page
    .getByRole("button", { name: "Filter by priority", exact: true })
    .click();
  await page
    .getByRole("menuitemcheckbox", {
      name: "toggle-high-priority",
      exact: true,
    })
    .click();
  await page.keyboard.press("Escape");
  await expect(
    page.getByRole("button", { name: "Filter by priority", exact: true }),
  ).toHaveText("high");
  await page.reload();
  await expect(page.locator(footer)).toHaveText(
    `Showing ${matches.length} of ${matches.length} matching tasks`,
  );
  await page.getByRole("searchbox").fill("no-task-matches-this-value");
  await expect(page.locator(footer)).toHaveText(
    "Showing 0 of 0 matching tasks",
  );
  await expect(
    page.getByLabel("0 matching tasks", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /Select all .*matching/ }),
  ).toHaveCount(0);
  await page.goto(
    `${path}?search=${encodeURIComponent(history.items[0].queue!)}`,
  );
  const queue = history.items[0].queue!.toLowerCase();
  const searched = history.items.filter((task) =>
    [task.name, task.task_id, task.queue, task.worker_name].some((v) =>
      String(v ?? "")
        .toLowerCase()
        .includes(queue),
    ),
  ).length;
  await expect(page.locator(footer)).toHaveText(
    `Showing ${Math.min(50, searched)} of ${searched} matching tasks`,
  );
});

test("a pending filter cannot expose the previous total or bulk selection", async ({
  page,
}) => {
  await page.goto(path);
  await expect(page.locator(footer)).toContainText(
    `of ${total} matching tasks`,
  );
  let release!: () => void;
  const pending = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route(
    "**/demo-data/projects/django.example.com/tasks.json",
    async (route) => {
      await pending;
      await route.continue();
    },
  );
  try {
    await page.getByRole("searchbox").fill("no-task-matches-this-value");
    await expect(page.locator(footer)).toHaveText("Loading records…");
    await expect(
      page.getByLabel(`${total} matching tasks`, { exact: true }),
    ).toHaveCount(0);
    await expect(
      page.getByRole("checkbox", { name: "Select row", exact: true }),
    ).toHaveCount(0);
  } finally {
    release();
    await page.unrouteAll({ behavior: "wait" });
  }
  await expect(page.locator(footer)).toHaveText(
    "Showing 0 of 0 matching tasks",
  );
});

test("failed reads show unavailable records rather than a zero or stale total", async ({
  page,
}) => {
  await page.route(
    "**/demo-data/projects/django.example.com/tasks.json",
    (route) => route.fulfill({ status: 503, body: "unavailable" }),
  );
  await page.goto(path);
  await expect(page.locator(footer)).toHaveText("Records unavailable", {
    timeout: 20_000,
  });
  await expect(page.getByLabel(/\d+ matching tasks/)).toHaveCount(0);
  await expect(page.getByRole("searchbox")).toBeVisible();
});

test("large totals and selection controls remain usable on phones", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 1000 });
  await page.route(
    "**/demo-data/projects/django.example.com/tasks.json",
    (route) =>
      route.fulfill({
        json: {
          items: Array.from({ length: 12345 }, (_, index) => ({
            ...history.items[0],
            id: `counted-${index}`,
            task_id: `counted-${index}`,
          })),
          next_cursor: null,
        },
      }),
  );
  await page.goto(path);
  await expect(page.locator(footer)).toHaveText(
    "Showing 50 of 12,345 matching tasks",
  );
  await page.getByRole("checkbox", { name: "Select all", exact: true }).check();
  await page
    .getByRole("button", { name: "Select all 12,345 matching", exact: true })
    .click();
  await expect(
    page.getByText("All 12,345 matching tasks selected", { exact: true }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.unrouteAll({ behavior: "wait" });
});
