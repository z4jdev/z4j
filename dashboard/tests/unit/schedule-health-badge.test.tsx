import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { ScheduleHealthBadge } from "@/components/domain/state-badges";

describe("ScheduleHealthBadge", () => {
  it("stays blank while the schedule is healthy", () => {
    const { container } = render(<ScheduleHealthBadge consecutiveFailures={0} threshold={5} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("reads as a proportion of the threshold", () => {
    render(<ScheduleHealthBadge consecutiveFailures={3} threshold={5} />);
    expect(screen.getByText("3 of 5 failing")).toBeInTheDocument();
  });

  it("says so when the breaker is switched off", () => {
    render(<ScheduleHealthBadge consecutiveFailures={2} threshold={0} />);
    expect(screen.getByText("2 failing")).toBeInTheDocument();
    expect(screen.getByText("2 failing").closest("[title]")?.getAttribute("title")).toMatch(/switched off/);
  });

  it("turns destructive at the threshold", () => {
    render(<ScheduleHealthBadge consecutiveFailures={5} threshold={5} />);
    expect(screen.getByText("5 of 5 failing").closest("[title]")?.getAttribute("title")).toMatch(/at the auto-disable threshold/);
  });
});
