import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";

import { DateCell } from "@/components/domain/date-cell";
import { formatAbsolute, formatRelative } from "@/lib/format";

const when = new Date(Date.now() - 3 * 60_000).toISOString();

describe("DateCell", () => {
  it("renders one line with the absolute time on hover by default", () => {
    const { container } = render(<DateCell value={when} />);
    const cell = container.firstElementChild as HTMLElement;
    expect(cell.getAttribute("title")).toBe(formatAbsolute(when));
    expect(cell.textContent).toBe(formatRelative(when));
    expect(container.textContent).not.toContain(formatAbsolute(when));
  });

  it("renders the absolute time on its own line when requested", () => {
    const { container } = render(<DateCell value={when} compact={false} />);
    expect(container.textContent).toContain(formatRelative(when));
    expect(container.textContent).toContain(formatAbsolute(when));
  });
});
