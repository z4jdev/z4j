import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { CheckCircle2, Copy, ExternalLink, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useProject } from "@/hooks/use-projects";
import { useAgents } from "@/hooks/use-agents";
import { useTasks } from "@/hooks/use-tasks";

/** Non-secret configuration is copyable; one-time credentials stay in the mint dialog. */
export function AgentConnectGuide({ slug }: { slug: string }) {
  const [framework, setFramework] = useState("django");
  const [engine, setEngine] = useState("celery");
  const [brainUrl, setBrainUrl] = useState(window.location.origin);
  const project = useProject(slug);
  const agents = useAgents(slug);
  const tasks = useTasks(slug, { limit: 1 });
  const connected = agents.data?.some((agent) => agent.state === "online");
  const observed = !!tasks.data?.items.length;
  const config = `Z4J_BRAIN_URL=${brainUrl}\nZ4J_PROJECT_ID=${project.data?.id ?? "<project UUID>"}\nZ4J_TOKEN=<bearer token shown above>\nZ4J_HMAC_SECRET=<HMAC secret shown above>`;
  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      toast.success("Copied");
    } catch {
      toast.error("Clipboard unavailable. Select and copy the text.");
    }
  }
  return (
    <div className="space-y-5 border-t pt-5">
      <div className="space-y-3">
        <h3 className="text-sm font-semibold">
          1. Install in your worker environment
        </h3>
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1.5">
            <Label htmlFor="connect-framework">Framework</Label>
            <Select value={framework} onValueChange={setFramework}>
              <SelectTrigger id="connect-framework">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {["django", "flask", "fastapi", "bare"].map((v) => (
                  <SelectItem key={v} value={v}>
                    {v === "bare" ? "Plain Python" : v}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="connect-engine">Task engine</Label>
            <Select value={engine} onValueChange={setEngine}>
              <SelectTrigger id="connect-engine">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {["celery", "rq", "dramatiq", "huey", "arq", "taskiq"].map(
                  (v) => (
                    <SelectItem key={v} value={v}>
                      {v}
                    </SelectItem>
                  ),
                )}
              </SelectContent>
            </Select>
          </div>
        </div>
        <div className="flex items-start gap-2 rounded-lg bg-background p-3">
          <code className="min-w-0 flex-1 break-words text-sm">
            pip install z4j-{framework} z4j-{engine}
          </code>
          <Button
            type="button"
            size="icon"
            variant="ghost"
            aria-label="Copy install command"
            onClick={() => copy(`pip install z4j-${framework} z4j-${engine}`)}
          >
            <Copy className="size-4" />
          </Button>
        </div>
        <p className="text-sm text-muted-foreground">
          Installing the packages is the first step. Add the startup hooks for
          your worker using the{" "}
          <a
            href={`https://z4j.dev/engines/${engine}/`}
            target="_blank"
            rel="noreferrer"
            className="text-primary underline"
          >
            {engine} integration guide{" "}
            <ExternalLink className="inline size-3" />
          </a>{" "}
          and{" "}
          <a
            href={`https://z4j.dev/frameworks/${framework}/`}
            target="_blank"
            rel="noreferrer"
            className="text-primary underline"
          >
            {framework === "bare" ? "plain Python" : framework} guide
          </a>
          .
        </p>
      </div>
      <div className="space-y-3">
        <h3 className="text-sm font-semibold">2. Configure the connection</h3>
        <Label htmlFor="connect-url">
          Brain URL reachable from this worker
        </Label>
        <Input
          id="connect-url"
          value={brainUrl}
          onChange={(e) => setBrainUrl(e.target.value)}
          type="url"
        />
        <p className="text-xs text-muted-foreground">
          Use your deployed address when the worker is on another host. A
          container's localhost points to itself.
        </p>
        <pre className="overflow-auto rounded-lg border bg-background p-3 text-xs">
          {config}
        </pre>
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={!project.data?.id}
          onClick={() => copy(config)}
        >
          Copy environment template
        </Button>
        {project.isError && (
          <p role="alert" className="text-sm text-destructive">
            Project configuration is unavailable. Reopen this guide after the
            connection recovers.
          </p>
        )}
        <p className="text-xs text-muted-foreground">
          Replace both credential placeholders with the values above, then
          restart the worker. Store credentials with your deployment's secrets.
        </p>
      </div>
      <div className="space-y-3">
        <h3 className="text-sm font-semibold">3. Verify the connection</h3>
        <div aria-live="polite" className="space-y-2 text-sm">
          <p className="flex items-center gap-2">
            <CheckCircle2
              className={
                connected
                  ? "size-4 text-success"
                  : "size-4 text-muted-foreground"
              }
            />
            {agents.isError
              ? "Agent connection could not be checked"
              : connected
                ? "An agent is online in this project"
                : "Waiting for an agent to connect"}
          </p>
          <p className="flex items-center gap-2">
            <CheckCircle2
              className={
                observed
                  ? "size-4 text-success"
                  : "size-4 text-muted-foreground"
              }
            />
            {tasks.isError
              ? "Task activity could not be checked"
              : observed
                ? "Task activity received in this project"
                : "Run a task through your worker to verify event capture"}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={agents.isFetching || tasks.isFetching}
            onClick={() => {
              void agents.refetch();
              void tasks.refetch();
            }}
          >
            <RefreshCw className="size-3.5" />
            Check connection
          </Button>
          {observed && (
            <Button asChild variant="ghost" size="sm">
              <Link to="/projects/$slug/tasks" params={{ slug }}>
                Open tasks
              </Link>
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
