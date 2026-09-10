import { expect, test } from "@playwright/test";

const scopes = [
  {
    base: "/projects/example.com/settings/notifications",
    label: "Project",
    navigation: "Project notification settings",
  },
  {
    base: "/settings/notifications",
    label: "Global",
    navigation: "Notification settings",
  },
];

for (const scope of scopes) {
  for (const width of [390, 768, 1182, 1440]) {
    test(`${scope.label} channels fill the content and tabs need no scrolling at ${width}px`, async ({
      page,
    }) => {
      await page.setViewportSize({ width, height: 1000 });
      await page.goto(`${scope.base}/channels`);
      const heading = page.locator('[data-slot="section-header"]');
      await expect(heading.getByRole("heading", { level: 2 })).toHaveText(
        `${scope.label} Channels`,
      );
      const cards = page.locator('[data-slot="channel-card"]');
      await expect(cards.first()).toBeVisible();
      const section = await heading.boundingBox();
      for (const card of await cards.all()) {
        const bounds = await card.boundingBox();
        expect(bounds!.x).toBeCloseTo(section!.x, 0);
        expect(bounds!.width).toBeCloseTo(section!.width, 0);
        for (const button of await card.getByRole("button").all()) {
          const action = await button.boundingBox();
          expect(action!.x).toBeGreaterThanOrEqual(bounds!.x);
          expect(action!.x + action!.width).toBeLessThanOrEqual(
            bounds!.x + bounds!.width,
          );
          expect(action!.y + action!.height).toBeLessThanOrEqual(
            bounds!.y + bounds!.height,
          );
        }
      }
      const navigation = page.getByRole("navigation", {
        name: scope.navigation,
        exact: true,
      });
      await expect(navigation.getByRole("link")).toHaveCount(3);
      const overflow = await navigation.evaluate((element) =>
        [element, element.parentElement!].some(
          (node) =>
            node.scrollHeight > node.clientHeight ||
            node.scrollWidth > node.clientWidth,
        ),
      );
      expect(overflow).toBe(false);
      for (const section of ["Subscriptions", "Notification Log", "Channels"]) {
        const link = navigation.getByRole("link", {
          name: `${scope.label} ${section}`,
          exact: true,
        });
        await link.focus();
        await page.keyboard.press("Enter");
        await expect(link).toHaveAttribute("aria-current", "page");
      }
      await cards
        .first()
        .getByRole("button", { name: /^Edit / })
        .click();
      await expect(
        page
          .getByRole("dialog")
          .getByRole("textbox", { name: "Name", exact: true }),
      ).not.toHaveValue("");
      await page.keyboard.press("Escape");
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth > innerWidth,
        ),
      ).toBe(false);
    });
  }
}

test("long channel names and destinations wrap without covering mobile actions", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 1000 });
  const name = "Operations".repeat(20);
  for (const scope of scopes) {
    const fixture =
      scope.label === "Project"
        ? "**/demo-data/projects/example.com/notifications-channels.json"
        : "**/demo-data/user/channels.json";
    await page.route(fixture, (route) =>
      route.fulfill({
        json: [
          {
            id: "wide-channel",
            name,
            type: "email",
            is_active: true,
            is_verified: true,
            config: {
              smtp_host: "smtp." + "long-host".repeat(20) + ".example.com",
            },
          },
        ],
      }),
    );
    await page.goto(`${scope.base}/channels`);
    const card = page.locator('[data-slot="channel-card"]');
    await expect(card.getByText(name, { exact: true })).toBeVisible();
    expect(await card.evaluate((e) => e.scrollWidth > e.clientWidth)).toBe(
      false,
    );
    const details = await card.getByText(name, { exact: true }).boundingBox();
    const edit = card.getByRole("button", {
      name: `Edit ${name}`,
      exact: true,
    });
    const action = await edit.boundingBox();
    expect(action!.y).toBeGreaterThan(details!.y + details!.height);
    await edit.click();
    await expect(
      page
        .getByRole("dialog")
        .getByRole("textbox", { name: "Name", exact: true }),
    ).toHaveValue(name);
    await page.keyboard.press("Escape");
    await page.unrouteAll({ behavior: "wait" });
  }
});
