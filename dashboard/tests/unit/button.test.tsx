/**
 * Tests for the ``Button`` UI primitive.
 *
 * Used on every page in the dashboard. Variants, size,
 * disabled-state click suppression, and asChild slot composition
 * are all load-bearing and trivially regressable on a Tailwind 4
 * upgrade or a CVA bump.
 */
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { Button } from "@/components/ui/button";

describe("Button", () => {
  it("renders children", () => {
    render(<Button>Click</Button>);
    expect(screen.getByRole("button", { name: "Click" })).toBeInTheDocument();
  });

  it("invokes onClick when clicked", async () => {
    const handler = vi.fn();
    const user = userEvent.setup();
    render(<Button onClick={handler}>Click</Button>);
    await user.click(screen.getByRole("button"));
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("does NOT invoke onClick when disabled", async () => {
    const handler = vi.fn();
    const user = userEvent.setup();
    render(
      <Button onClick={handler} disabled>
        Click
      </Button>,
    );
    await user.click(screen.getByRole("button"));
    expect(handler).not.toHaveBeenCalled();
  });

  it.each([
    ["default", "bg-primary"],
    ["destructive", "bg-destructive"],
    ["outline", "border-input"],
    ["secondary", "bg-secondary"],
    ["ghost", "hover:bg-accent"],
    ["link", "underline-offset-4"],
  ] as const)("variant '%s' applies the right palette", (variant, expected) => {
    render(<Button variant={variant}>x</Button>);
    expect(screen.getByRole("button").className).toContain(expected);
  });

  it.each([
    ["default", "h-9"],
    ["sm", "h-8"],
    ["lg", "h-10"],
    ["icon", "size-9"],
  ] as const)("size '%s' applies the right dimension", (size, expected) => {
    render(<Button size={size}>x</Button>);
    expect(screen.getByRole("button").className).toContain(expected);
  });

  it("renders the slotted child when asChild is true", () => {
    render(
      <Button asChild>
        <a href="#anchor">As link</a>
      </Button>,
    );
    const link = screen.getByRole("link", { name: "As link" });
    expect(link.tagName).toBe("A");
    expect(link).toBeInTheDocument();
  });
});
