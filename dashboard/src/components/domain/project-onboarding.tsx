import { Link } from "@tanstack/react-router";
import { ArrowRight, CheckCircle2, Network } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useCan } from "@/hooks/use-memberships";

/** First useful action for an empty project; never interprets zero agents as healthy. */
export function ProjectOnboarding({ slug }: { slug: string }) {
  const canManage = useCan(slug, "manage_agents");
  return (
    <section
      className="panel-surface p-5 md:p-6"
      aria-labelledby="connect-title"
    >
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <div className="mb-3 flex items-center gap-2 text-sm font-medium text-primary">
            <Network className="size-4" />
            Get connected
          </div>
          <h2
            id="connect-title"
            className="text-xl font-semibold tracking-tight"
          >
            Bring your first worker into view.
          </h2>
          <p className="mt-2 max-w-xl text-sm text-muted-foreground">
            Connect an agent to start seeing tasks, workers and schedules in{" "}
            {slug}.
          </p>
        </div>
        {canManage ? (
          <Button asChild>
            <Link to="/projects/$slug/agents" params={{ slug }}>
              Connect an agent <ArrowRight className="size-4" />
            </Link>
          </Button>
        ) : (
          <p className="max-w-xs text-sm text-muted-foreground">
            Ask a project administrator to create an agent credential.
          </p>
        )}
      </div>
      <ol className="mt-6 grid gap-3 border-t pt-5 text-sm sm:grid-cols-3">
        <li>
          <span className="mr-2 font-mono text-primary">01</span>Choose your
          stack
        </li>
        <li>
          <span className="mr-2 font-mono text-primary">02</span>Configure the
          worker
        </li>
        <li className="flex items-center gap-2">
          <CheckCircle2 className="size-4 text-muted-foreground" />
          Verify the first task
        </li>
      </ol>
    </section>
  );
}
