/**
 * Tests for the ``Badge`` UI primitive.
 *
 * The variant -> Tailwind palette mapping is the source of truth
 * for every state badge across the dashboard. A typo in the cva
 * config silently re-skins half the app (Tasks/Workers/Agents/
 * Commands all flow through here), so we pin every variant.
 */
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { Badge, badgeVariants } from "@/components/ui/badge";

describe("Badge", () => {
  it("renders its children", () => {
    render(<Badge>hello</Badge>);
    expect(screen.getByText("hello")).toBeInTheDocument();
  });

  it("defaults to the 'default' variant when none is provided", () => {
    render(<Badge>x</Badge>);
    const el = screen.getByText("x");
    expect(el.className).toContain("bg-primary");
  });

  it.each([
    ["default", "bg-primary"],
    ["secondary", "bg-secondary"],
    ["destructive", "bg-destructive"],
    ["outline", "border-border"],
    ["success", "bg-success"],
    ["warning", "bg-warning"],
    ["muted", "bg-muted"],
  ] as const)("variant '%s' applies %s class", (variant, expected) => {
    render(<Badge variant={variant}>x</Badge>);
    const el = screen.getByText("x");
    expect(el.className).toContain(expected);
  });

  it("merges user-provided className with the variant classes", () => {
    render(
      <Badge variant="success" className="custom-extra">
        x
      </Badge>,
    );
    const el = screen.getByText("x");
    expect(el.className).toContain("custom-extra");
    expect(el.className).toContain("bg-success");
  });

  it("renders as a <span> by default", () => {
    const { container } = render(<Badge>x</Badge>);
    const el = container.firstElementChild;
    expect(el?.tagName).toBe("SPAN");
  });

  it("uses the slotted child when asChild is true", () => {
    render(
      <Badge asChild>
        <a href="#anchor">link badge</a>
      </Badge>,
    );
    const link = screen.getByRole("link", { name: "link badge" });
    expect(link).toBeInTheDocument();
    expect(link.tagName).toBe("A");
  });
});

describe("badgeVariants helper", () => {
  it("returns a class string for any variant", () => {
    const cls = badgeVariants({ variant: "warning" });
    expect(cls).toContain("bg-warning");
    expect(typeof cls).toBe("string");
  });
});
