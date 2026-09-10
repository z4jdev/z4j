import { expect, test } from "@playwright/test";

const project = "/projects/django.example.com";

for (const theme of ["light", "dark"]) {
  test(`collapsed navigation tooltip paints above the task search in ${theme} mode`, async ({
    page,
  }) => {
    await page.addInitScript((mode) => {
      localStorage.setItem("z4j-theme", mode);
      localStorage.setItem("z4j-sidebar-collapsed", "1");
    }, theme);
    await page.goto(`${project}/tasks`);
    await expect(page.getByPlaceholder("Search tasks...")).toBeVisible();
    const tasks = page
      .getByRole("complementary", { name: "Primary navigation" })
      .getByRole("link", { name: "Tasks", exact: true });
    await tasks.hover();
    const tooltip = page.locator('[data-slot="tooltip-content"]');
    await expect(tooltip).toBeVisible();
    // Test the actual paint order at the overlap, not just a z-index value.
    await expect
      .poll(() =>
        tooltip.evaluate((element) => {
          const tip = element.getBoundingClientRect();
          const search = document
            .querySelector('input[placeholder="Search tasks..."]')!
            .getBoundingClientRect();
          const left = Math.max(tip.left, search.left);
          const right = Math.min(tip.right, search.right);
          const top = Math.max(tip.top, search.top);
          const bottom = Math.min(tip.bottom, search.bottom);
          return (
            right > left &&
            bottom > top &&
            element.contains(
              document.elementFromPoint((left + right) / 2, (top + bottom) / 2),
            )
          );
        }),
      )
      .toBe(true);
    // A pointer can cross from the trigger onto the label without losing it.
    await tooltip.hover();
    await expect(tooltip).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(tooltip).toBeHidden();
  });
}

test("keyboard tooltips remain inside a short viewport and dismiss without moving focus", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1024, height: 600 });
  await page.addInitScript(() =>
    localStorage.setItem("z4j-sidebar-collapsed", "1"),
  );
  await page.goto(`${project}/tasks`);
  const settings = page
    .getByRole("complementary", { name: "Primary navigation" })
    .getByRole("link", { name: "Global Settings", exact: true });
  await settings.focus();
  const tooltip = page.locator('[data-slot="tooltip-content"]');
  await expect(tooltip).toBeVisible();
  const bounds = await tooltip.boundingBox();
  expect(bounds!.x).toBeGreaterThanOrEqual(8);
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(1016);
  expect(bounds!.y).toBeGreaterThanOrEqual(8);
  expect(bounds!.y + bounds!.height).toBeLessThanOrEqual(592);
  await page.keyboard.press("Escape");
  await expect(tooltip).toBeHidden();
  await expect(settings).toBeFocused();
});

for (const width of [390, 768, 1440]) {
  test(`search has one reachable close control with no input or Esc overlap at ${width}px`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto(`${project}/tasks`);
    const trigger = page.getByRole("button", {
      name: "Search pages and tasks",
    });
    await trigger.click();
    const dialog = page.getByRole("dialog", { name: "Search pages and tasks" });
    const input = dialog.getByRole("combobox", {
      name: "Search pages and tasks",
    });
    const close = dialog.getByRole("button", {
      name: "Close search",
      exact: true,
    });
    await expect(close).toHaveCount(1);
    await expect(
      dialog.getByRole("button", { name: "Close", exact: true }),
    ).toHaveCount(0);
    await expect(input).toBeFocused();
    await input.fill(
      "A long task search that must never cover the close control",
    );
    // Measure after the opening scale animation reaches its final dimensions.
    await dialog.evaluate(async (element) => {
      await Promise.all(
        element.getAnimations().map((animation) => animation.finished),
      );
    });
    const field = await input.boundingBox();
    const action = await close.boundingBox();
    const modal = await dialog.boundingBox();
    expect(field!.x + field!.width + 7).toBeLessThanOrEqual(action!.x);
    expect(action!.width).toBeGreaterThanOrEqual(36);
    expect(action!.height).toBeGreaterThanOrEqual(36);
    expect(action!.x + action!.width).toBeLessThanOrEqual(
      modal!.x + modal!.width,
    );
    expect(modal!.x).toBeGreaterThanOrEqual(0);
    expect(modal!.x + modal!.width).toBeLessThanOrEqual(width);
    if (width >= 640) {
      const hint = await close.locator("kbd").boundingBox();
      const icon = await close.locator("svg").boundingBox();
      expect(hint!.x + hint!.width + 7).toBeLessThanOrEqual(icon!.x);
    } else {
      await expect(close.locator("kbd")).toBeHidden();
    }
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
    await expect(trigger).toBeFocused();
    await trigger.click();
    await expect(input).toHaveValue("");
    await input.fill("worker");
    await close.click();
    await expect(dialog).toBeHidden();
    await expect(trigger).toBeFocused();
    await trigger.click();
    await expect(input).toHaveValue("");
    await input.fill("queue");
    await page.keyboard.press("Control+k");
    await expect(dialog).toBeHidden();
    await expect(trigger).toBeFocused();
    await page.keyboard.press("Control+k");
    await expect(input).toHaveValue("");
    await input.fill("agent");
    await page.mouse.click(10, 10);
    await expect(dialog).toBeHidden();
    await expect(trigger).toBeFocused();
    await trigger.click();
    await expect(input).toHaveValue("");
    await input.fill("Keyboard shortcuts");
    await page.keyboard.press("Enter");
    await expect(
      page.getByRole("dialog", { name: "Keyboard shortcuts" }),
    ).toBeVisible();
    await expect(dialog).toBeHidden();
    await expect
      .poll(() =>
        page
          .getByRole("dialog", { name: "Keyboard shortcuts" })
          .evaluate((element) => element.contains(document.activeElement)),
      )
      .toBe(true);
  });
}

test("ordinary dialogs retain their default close button", async ({ page }) => {
  await page.goto("/settings/notifications/channels");
  const edit = page
    .locator('[data-slot="channel-card"]')
    .first()
    .getByRole("button", { name: /^Edit / });
  await edit.click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await expect(dialog).toBeHidden();
  await expect(edit).toBeFocused();
});
