import { expect, test } from "@playwright/test";

const project = "/projects/tasks.example.com";

test("project navigation stays in scope and the switcher returns to workspace pages", async ({
  page,
}) => {
  await page.goto(`${project}/commands`);
  const navigation = page.getByRole("complementary", {
    name: "Primary navigation",
  });
  await expect(
    navigation.getByRole("link", { name: "Home", exact: true }),
  ).toHaveCount(0);
  await expect(
    navigation.getByRole("link", { name: "Activity", exact: true }),
  ).toHaveCount(0);
  await expect(
    navigation.getByRole("link", { name: "Commands", exact: true }),
  ).toHaveAttribute("aria-current", "page");
  await navigation.getByRole("button", { name: /Switch project:/ }).click();
  await page
    .getByRole("menuitem", { name: "Workspace home", exact: true })
    .click();
  await expect(
    navigation.getByRole("link", { name: "Home", exact: true }),
  ).toBeVisible();
  await expect(
    navigation.getByRole("link", { name: "Activity", exact: true }),
  ).toBeVisible();
});

for (const width of [390, 768, 1440]) {
  test(`demo footer stays below reachable content at ${width}px`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto(`${project}/commands`);
    const footer = page.getByRole("contentinfo", { name: "Demo mode" });
    await expect(footer).toBeVisible();
    const bounds = await footer.boundingBox();
    expect(Math.round(bounds!.y + bounds!.height)).toBe(900);
    expect((await page.locator("main > header").boundingBox())!.y).toBe(0);
    expect(
      (await page.locator('[data-slot="page-header"]').boundingBox())!.y,
    ).toBeLessThan(100);
    if (width >= 768) {
      const rail = await page
        .getByRole("complementary", { name: "Primary navigation" })
        .boundingBox();
      expect(rail!.y + rail!.height).toBeLessThanOrEqual(bounds!.y);
    }
    await page.evaluate(() =>
      window.scrollTo(0, document.documentElement.scrollHeight),
    );
    const pagination = await page
      .locator('[data-slot="table-pagination"]')
      .boundingBox();
    expect(pagination!.y + pagination!.height).toBeLessThanOrEqual(bounds!.y);
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    await footer
      .getByRole("combobox", { name: "Explore a demo scenario" })
      .click();
    await page
      .getByRole("option", { name: "Healthy project", exact: true })
      .click();
    await expect(page).toHaveURL(/\/projects\/example.com$/);
    await expect(footer).toBeVisible();
  });
}

for (const width of [390, 768, 1024, 1213, 1440]) {
  test(`visible settings links navigate and follow deep links at ${width}px`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/settings/appearance");
    const sections = page.getByRole("navigation", {
      name: "Settings",
      exact: true,
    });
    await expect(sections.getByRole("link")).toHaveCount(11);
    for (const link of await sections.getByRole("link").all()) {
      await expect(link).toBeInViewport();
    }
    await expect(
      sections.getByRole("link", { name: "Appearance", exact: true }),
    ).toHaveAttribute("aria-current", "page");
    const security = sections.getByRole("link", {
      name: "Security",
      exact: true,
    });
    await security.focus();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/\/settings\/security$/);
    await expect(
      page.getByRole("heading", { name: "Security", exact: true }),
    ).toBeVisible();
    await page.goto("/settings/notifications/deliveries");
    await expect(
      sections.getByRole("link", { name: "Notifications", exact: true }),
    ).toHaveAttribute("aria-current", "page");
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
  });
}

test("desktop settings keep grouped navigation with an explicit active page", async ({
  page,
}) => {
  await page.goto("/settings/appearance");
  const navigation = page.getByRole("navigation", {
    name: "Settings",
    exact: true,
  });
  await expect(navigation).toBeVisible();
  await expect(navigation.getByRole("link")).toHaveCount(11);
  await expect(
    navigation.getByRole("link", { name: "Appearance", exact: true }),
  ).toHaveAttribute("aria-current", "page");
  await expect(
    page.getByRole("combobox", { name: "Settings section", exact: true }),
  ).toBeHidden();
});

test("settings navigation exposes only personal categories to non-admins", async ({
  page,
}) => {
  await page.route("**/demo-data/auth/me.json", async (route) => {
    const response = await route.fetch();
    await route.fulfill({
      json: { ...(await response.json()), is_admin: false },
    });
  });
  await page.goto("/settings/appearance");
  const navigation = page.getByRole("navigation", {
    name: "Settings",
    exact: true,
  });
  await expect(navigation.getByRole("link")).toHaveCount(6);
  await expect(
    navigation.getByRole("group", { name: "Administration" }),
  ).toHaveCount(0);
  await page.unrouteAll({ behavior: "wait" });
});

test("settings categories remain reachable on short laptop screens", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1024, height: 600 });
  await page.goto("/settings/appearance");
  const runtime = page
    .getByRole("navigation", { name: "Settings", exact: true })
    .getByRole("link", { name: "Runtime config" });
  await runtime.focus();
  const bounds = await runtime.boundingBox();
  const footer = await page
    .getByRole("contentinfo", { name: "Demo mode" })
    .boundingBox();
  expect(bounds!.y + bounds!.height).toBeLessThanOrEqual(footer!.y);
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/settings\/runtime$/);
});

for (const theme of ["light", "dark"]) {
  test(`cards and collections share one flat surface treatment in ${theme} mode`, async ({
    page,
  }) => {
    await page.addInitScript(
      (mode) => localStorage.setItem("z4j-theme", mode),
      theme,
    );
    let expected: unknown;
    for (const route of [
      project,
      `${project}/commands`,
      `${project}/audit`,
      "/settings/users",
    ]) {
      await page.goto(route);
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      const surfaces = await page
        .locator(".panel-surface")
        .evaluateAll((elements) =>
          elements
            .filter(
              (element) => !element.parentElement?.closest(".panel-surface"),
            )
            .map((element) => {
              const style = getComputedStyle(element);
              return {
                border: style.borderTopWidth,
                borderStyle: style.borderTopStyle,
                color: style.borderTopColor,
                radius: style.borderRadius,
                shadow: style.boxShadow,
                background: style.backgroundColor,
              };
            }),
        );
      expect(surfaces.length, route).toBeGreaterThan(0);
      expected ??= surfaces[0];
      for (const surface of surfaces) {
        expect(surface, route).toEqual(expected);
        expect(surface).toMatchObject({
          border: "1px",
          borderStyle: "solid",
          radius: "8px",
          shadow: "none",
        });
      }
    }
  });
}
