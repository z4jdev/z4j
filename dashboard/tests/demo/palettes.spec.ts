import { expect, test } from "@playwright/test";
import type { Locator } from "@playwright/test";

async function textContrast(locator: Locator) {
  return locator.evaluate((element) => {
    const style = getComputedStyle(element);
    const canvas = document.createElement("canvas");
    canvas.width = canvas.height = 1;
    const context = canvas.getContext("2d")!;
    const luminance = (color: string) => {
      context.clearRect(0, 0, 1, 1);
      context.fillStyle = color;
      context.fillRect(0, 0, 1, 1);
      const pixels = context.getImageData(0, 0, 1, 1).data;
      return [0.2126, 0.7152, 0.0722].reduce((sum, weight, index) => {
        const value = pixels[index] / 255;
        return (
          sum +
          weight *
            (value <= 0.04045
              ? value / 12.92
              : ((value + 0.055) / 1.055) ** 2.4)
        );
      }, 0);
    };
    const values = [
      luminance(style.color),
      luminance(style.backgroundColor),
    ].sort((a, b) => a - b);
    return (values[1] + 0.05) / (values[0] + 0.05);
  });
}

test("every palette preserves text contrast on primary buttons, hover, and selected navigation", async ({
  page,
}) => {
  for (const palette of ["Sapphire", "Jade", "Iris", "Sandstone"]) {
    for (const theme of ["Light", "Dark"]) {
      await page.goto("/settings/appearance");
      await page.getByRole("radio", { name: palette, exact: true }).check();
      await page.getByRole("radio", { name: theme, exact: true }).check();
      await page.goto("/settings/notifications/channels");
      const button = page.getByRole("button", {
        name: "Add Channel",
        exact: true,
      });
      await expect(button).toBeVisible();
      expect(
        await textContrast(button),
        `${palette} ${theme} button`,
      ).toBeGreaterThanOrEqual(4.5);
      await button.hover();
      await button.evaluate(async (element) => {
        element.getBoundingClientRect();
        await Promise.all(
          element.getAnimations().map((animation) => animation.finished),
        );
      });
      await expect
        .poll(() => textContrast(button), {
          message: `${palette} ${theme} hover`,
        })
        .toBeGreaterThanOrEqual(4.5);
      const selected = page
        .getByRole("navigation", { name: "Settings", exact: true })
        .locator('[aria-current="page"]');
      expect(
        await textContrast(selected),
        `${palette} ${theme} selected navigation`,
      ).toBeGreaterThanOrEqual(4.5);
      await page.mouse.move(0, 0);
    }
  }
});

for (const name of ["Sapphire", "Jade", "Iris", "Sandstone"]) {
  test(`${name} coordinates light and dark navigation and persists on deep links`, async ({
    page,
  }) => {
    await page.goto("/settings/appearance");
    await page.getByRole("radio", { name: "Light", exact: true }).check();
    await page.getByRole("radio", { name, exact: true }).check();
    await expect(page.locator("html")).toHaveAttribute(
      "data-palette",
      name.toLowerCase(),
    );
    const readRail = () =>
      page.locator('aside[aria-label="Primary navigation"]').evaluate((e) => {
        const style = getComputedStyle(e);
        return { background: style.backgroundColor, color: style.color };
      });
    const light = await readRail();
    const brightness = (color: string) =>
      color
        .match(/[\d.]+/g)!
        .slice(0, 3)
        .map(Number)
        .reduce((a, b) => a + b, 0) / 3;
    expect(brightness(light.background)).toBeGreaterThan(225);
    expect(brightness(light.color)).toBeLessThan(90);
    await page.getByRole("radio", { name: "Dark", exact: true }).check();
    await expect(page.locator("html")).toHaveClass(/dark/);
    const dark = await readRail();
    expect(brightness(dark.background)).toBeLessThan(65);
    expect(brightness(dark.color)).toBeGreaterThan(220);
    await page.goto("/projects/tasks.example.com/commands");
    await page.reload();
    await expect(page.locator("html")).toHaveAttribute(
      "data-palette",
      name.toLowerCase(),
    );
    await expect(page.locator("html")).toHaveClass(/dark/);
    await expect(
      page.getByRole("heading", { name: "Commands", exact: true }),
    ).toBeVisible();
    expect(await readRail()).toEqual(dark);
  });
}

test("appearance choices work with the keyboard, reset and fit on phones", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 1000 });
  await page.goto("/settings/appearance");
  const sapphire = page.getByRole("radio", { name: "Sapphire", exact: true });
  await sapphire.focus();
  await page.keyboard.press("ArrowRight");
  await expect(
    page.getByRole("radio", { name: "Jade", exact: true }),
  ).toBeChecked();
  await page.getByRole("radio", { name: "Dark", exact: true }).check();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.getByRole("button", { name: "Reset appearance" }).click();
  await expect(sapphire).toBeChecked();
  await expect(
    page.getByRole("radio", { name: "System", exact: true }),
  ).toBeChecked();
  await expect(
    page.getByRole("button", { name: "Reset appearance" }),
  ).toBeDisabled();
});
