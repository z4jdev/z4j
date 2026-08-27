import { Link } from "@tanstack/react-router";
import { ShieldAlert } from "lucide-react";
import { useMfaStatus } from "@/hooks/use-mfa";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

/**
 * Tells a user that enrollment is required of them, and where to do it.
 *
 * Without this the enforcement policy is invisible from the dashboard: the
 * brain answers every non-exempt route with 403 mfa_enrollment_required, the
 * client turns that into the generic "your role doesn't have access" toast, and
 * the user is told they lack permission rather than that they need to enroll.
 * The status endpoint stays reachable past the deadline precisely so this can
 * be rendered.
 */
export function MfaEnrollmentBanner() {
  const { data: status } = useMfaStatus();
  if (!status?.enrollment_required) return null;

  const deadline = status.enrollment_deadline
    ? new Date(status.enrollment_deadline)
    : null;
  const expired = deadline !== null && deadline.getTime() <= Date.now();

  return (
    <Alert variant="warning" className="mb-4">
      <ShieldAlert />
      <AlertTitle>
        {expired
          ? "Two-factor authentication is required to continue"
          : "Two-factor authentication is required for your account"}
      </AlertTitle>
      <AlertDescription>
        <p>
          {expired
            ? "The grace period has ended, so the rest of the dashboard is closed to this account until you enroll."
            : deadline !== null
              ? `Enroll before ${deadline.toLocaleString()} to keep access.`
              : "Enroll to keep access when the grace period ends."}{" "}
          <Link
            to="/settings/security"
            className="font-medium underline underline-offset-2"
          >
            Set up two-factor authentication
          </Link>
          .
        </p>
      </AlertDescription>
    </Alert>
  );
}
