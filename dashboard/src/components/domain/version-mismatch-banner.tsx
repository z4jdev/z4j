import { Link } from "@tanstack/react-router";
import { AlertTriangle } from "lucide-react";
import { useAgents } from "@/hooks/use-agents";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

export interface VersionMismatchBannerProps {
  slug: string;
}

export function VersionMismatchBanner({ slug }: VersionMismatchBannerProps) {
  const { data: agents } = useAgents(slug);
  const outdated = (agents ?? []).filter((a) => a.is_outdated);
  if (outdated.length === 0) return null;

  const names = outdated.map((a) => a.name);
  const preview =
    names.length <= 3
      ? names.join(", ")
      : `${names.slice(0, 3).join(", ")} and ${names.length - 3} more`;

  return (
    <Alert variant="warning" className="mb-4">
      <AlertTriangle />
      <AlertTitle>
        {outdated.length === 1
          ? "1 agent is on an older wire protocol"
          : `${outdated.length} agents are on an older wire protocol`}
      </AlertTitle>
      <AlertDescription>
        <p>
          {preview} - upgrade to the latest agent package to avoid
          compatibility issues on future brain releases.{" "}
          <Link
            to="/projects/$slug/agents"
            params={{ slug }}
            className="font-medium underline underline-offset-2"
          >
            View agents
          </Link>
          .
        </p>
      </AlertDescription>
    </Alert>
  );
}
