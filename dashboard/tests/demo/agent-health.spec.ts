import { test, expect } from "@playwright/test";

for (const width of [390, 1440]) {
  test(`agent health is reachable and readable at ${width}px`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/projects/tasks.example.com/agents");
    const trigger = page.getByRole("button", {
      name: "View health for celery-worker-1",
      exact: true,
    });
    await trigger.click();
    const dialog = page.getByRole("dialog", { name: /Agent health/ });
    await expect(dialog).toBeVisible();
    await expect(
      dialog.getByText("Event records lost", { exact: true }),
    ).toBeVisible();
    await expect(
      dialog.getByText("Queue events lost", { exact: true }),
    ).toBeVisible();
    await expect(dialog.getByText("celery", { exact: true })).toBeVisible();
    await expect
      .poll(() =>
        dialog.evaluate(
          (element) => element.scrollWidth <= element.clientWidth,
        ),
      )
      .toBe(true);
    const bounds = await dialog.boundingBox();
    expect(bounds!.x).toBeGreaterThanOrEqual(0);
    expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(width);
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
    await expect(trigger).toBeFocused();
  });
}
