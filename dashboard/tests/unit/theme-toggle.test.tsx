/**
 * Tests for ``ThemeToggle``.
 *
 * The dropdown menu uses Radix portals, so the items are rendered
 * outside the trigger's subtree. ``getByRole`` walks the whole
 * document, so the assertions below find them either way.
 */
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { ThemeProvider } from "@/components/layout/theme-provider";
import { ThemeToggle } from "@/components/layout/theme-toggle";

function renderToggle() {
  return render(
    <ThemeProvider>
      <ThemeToggle />
    </ThemeProvider>,
  );
}

describe("ThemeToggle", () => {
  it("renders an accessible 'Switch theme' button", () => {
    renderToggle();
    expect(
      screen.getByRole("button", { name: /switch theme/i }),
    ).toBeInTheDocument();
  });

  it("opens the menu and shows all three options on click", async () => {
    const user = userEvent.setup();
    renderToggle();
    await user.click(screen.getByRole("button", { name: /switch theme/i }));

    expect(screen.getByRole("menuitem", { name: /light/i })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: /dark/i })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: /system/i })).toBeInTheDocument();
  });

  it("switches the html class when a different theme is picked", async () => {
    const user = userEvent.setup();
    renderToggle();

    await user.click(screen.getByRole("button", { name: /switch theme/i }));
    await user.click(screen.getByRole("menuitem", { name: /light/i }));

    expect(document.documentElement.classList.contains("light")).toBe(true);
    expect(document.documentElement.classList.contains("dark")).toBe(false);
  });
});
