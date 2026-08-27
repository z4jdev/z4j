/**
 * The banner is the only thing that tells a user why the dashboard closed.
 *
 * When enforcement targets a user who has not enrolled, the brain answers every
 * non-exempt route with 403 mfa_enrollment_required and the client renders the
 * generic "your role doesn't have access" toast. That tells the user they lack
 * permission, which is wrong and offers no way out. The status endpoint stays
 * reachable past the deadline precisely so this can be shown instead.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { MfaEnrollmentBanner } from "@/components/domain/mfa-enrollment-banner";

const mockUseMfaStatus = vi.fn();

vi.mock("@/hooks/use-mfa", () => ({
  useMfaStatus: () => mockUseMfaStatus(),
}));

vi.mock("@tanstack/react-router", () => ({
  // An anchor without href has no implicit link role, so the mock maps the
  // router's `to` onto href and keeps `to` for the assertion below.
  Link: ({ children, to, ...rest }: { children: React.ReactNode; to: string }) => (
    <a href={to} data-to={to} {...rest}>
      {children}
    </a>
  ),
}));

describe("MfaEnrollmentBanner", () => {
  it("renders nothing for a user enforcement does not target", () => {
    mockUseMfaStatus.mockReturnValue({
      data: { enrolled: true, enrollment_required: false },
    });
    const { container } = render(<MfaEnrollmentBanner />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing before the status has loaded", () => {
    // Rendering a scary banner on a slow first paint would be worse than
    // rendering nothing, so undefined must be treated as "not yet known".
    mockUseMfaStatus.mockReturnValue({ data: undefined });
    const { container } = render(<MfaEnrollmentBanner />);
    expect(container).toBeEmptyDOMElement();
  });

  it("names the deadline while the grace window is still open", () => {
    const future = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000);
    mockUseMfaStatus.mockReturnValue({
      data: {
        enrolled: false,
        enrollment_required: true,
        enrollment_deadline: future.toISOString(),
      },
    });
    render(<MfaEnrollmentBanner />);

    expect(screen.getByText(/required for your account/i)).toBeInTheDocument();
    expect(screen.getByText(/Enroll before/i)).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /set up two-factor/i }),
    ).toHaveAttribute("data-to", "/settings/security");
  });

  it("says the dashboard is closed once the deadline has passed", () => {
    const past = new Date(Date.now() - 60_000);
    mockUseMfaStatus.mockReturnValue({
      data: {
        enrolled: false,
        enrollment_required: true,
        enrollment_deadline: past.toISOString(),
      },
    });
    render(<MfaEnrollmentBanner />);

    expect(screen.getByText(/required to continue/i)).toBeInTheDocument();
    expect(screen.getByText(/grace period has ended/i)).toBeInTheDocument();
  });

  it("still offers a route to enrol when no deadline has been set", () => {
    // enrollment_deadline is null until a login observes the policy, so the
    // banner must work without one rather than waiting for a clock to start.
    mockUseMfaStatus.mockReturnValue({
      data: {
        enrolled: false,
        enrollment_required: true,
        enrollment_deadline: null,
      },
    });
    render(<MfaEnrollmentBanner />);

    expect(screen.getByText(/keep access when the grace period ends/i)).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /set up two-factor/i }),
    ).toBeInTheDocument();
  });
});
