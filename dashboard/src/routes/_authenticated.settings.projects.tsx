/**
 * Project management settings page - admin only.
 *
 * List, create, edit, and archive projects. Cannot archive the last
 * remaining project - the backend enforces this and the UI disables
 * the button as a hint.
 */
import { useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { FolderKanban, Pencil, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { EmptyState } from "@/components/domain/empty-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  useCreateProject,
  useDeleteProject,
  useProjects,
  useUpdateProject,
} from "@/hooks/use-projects";
import { DateCell } from "@/components/domain/date-cell";
import { PageHeader } from "@/components/domain/page-header";

export const Route = createFileRoute("/_authenticated/settings/projects")({
  component: ProjectsPage,
});

// ---------------------------------------------------------------------------
// Slug helpers
// ---------------------------------------------------------------------------

const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$/;

function toSlug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 50);
}

// Curated options for the Environment select. The backend column is
// free-form (max 40 chars) but constraining the UI to a short menu
// keeps values consistent across projects and avoids typos like
// "Prod" vs "production" fragmenting the UI filters.
const ENVIRONMENTS = ["production", "staging", "development", "test"] as const;

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

function ProjectsPage() {
  const { data: projects, isLoading } = useProjects();
  const [createOpen, setCreateOpen] = useState(false);
  const [editSlug, setEditSlug] = useState<string | null>(null);
  const [deleteSlug, setDeleteSlug] = useState<string | null>(null);

  const activeCount = projects?.filter((p) => p.is_active).length ?? 0;
  const editProject = projects?.find((p) => p.slug === editSlug) ?? null;
  const deleteProject = projects?.find((p) => p.slug === deleteSlug) ?? null;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Projects"
        description="Create, edit, and archive projects."
        actions={
          <Dialog open={createOpen} onOpenChange={setCreateOpen}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus className="size-4" />
                Create Project
              </Button>
            </DialogTrigger>
            <DialogContent>
              <CreateProjectDialog onCreated={() => setCreateOpen(false)} />
            </DialogContent>
          </Dialog>
        }
      />

      {isLoading && <Skeleton className="h-64 w-full" />}
      {projects && projects.length === 0 && (
        <EmptyState
          icon={FolderKanban}
          title="No projects"
          description="Create your first project to get started."
        />
      )}
      {projects && projects.length > 0 && (
        <Card className="overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Slug</TableHead>
                <TableHead>Environment</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {projects.map((project) => (
                <TableRow key={project.id}>
                  <TableCell>
                    <Link
                      to="/projects/$slug"
                      params={{ slug: project.slug }}
                      className="font-medium hover:underline"
                    >
                      {project.name}
                    </Link>
                    {project.description && (
                      <div className="max-w-xs truncate text-xs text-muted-foreground">
                        {project.description}
                      </div>
                    )}
                  </TableCell>
                  <TableCell>
                    <code className="rounded bg-muted px-1.5 py-0.5 text-xs">
                      {project.slug}
                    </code>
                  </TableCell>
                  <TableCell>
                    <Badge variant="muted">{project.environment}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={project.is_active ? "success" : "destructive"}
                    >
                      {project.is_active ? "active" : "archived"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <DateCell value={project.created_at} />
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        title="Edit project"
                        aria-label={`Edit project ${project.name}`}
                        onClick={() => setEditSlug(project.slug)}
                      >
                        <Pencil className="size-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        title={
                          activeCount <= 1 && project.is_active
                            ? "Cannot archive the last project"
                            : "Archive project"
                        }
                        aria-label={`Archive project ${project.name}`}
                        disabled={
                          !project.is_active ||
                          (activeCount <= 1 && project.is_active)
                        }
                        onClick={() => setDeleteSlug(project.slug)}
                      >
                        <Trash2 className="size-4 text-destructive" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Edit dialog */}
      <Dialog
        open={editSlug !== null}
        onOpenChange={(open) => {
          if (!open) setEditSlug(null);
        }}
      >
        <DialogContent>
          {editProject && (
            <EditProjectDialog
              project={editProject}
              onSaved={() => setEditSlug(null)}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* Delete confirmation dialog */}
      <Dialog
        open={deleteSlug !== null}
        onOpenChange={(open) => {
          if (!open) setDeleteSlug(null);
        }}
      >
        <DialogContent>
          {deleteProject && (
            <DeleteProjectDialog
              project={deleteProject}
              onDeleted={() => setDeleteSlug(null)}
              onCancel={() => setDeleteSlug(null)}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Create dialog
// ---------------------------------------------------------------------------

function CreateProjectDialog({ onCreated }: { onCreated: () => void }) {
  const createProject = useCreateProject();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [description, setDescription] = useState("");
  const [environment, setEnvironment] = useState<string>("production");
  const [slugTouched, setSlugTouched] = useState(false);

  const slugValue = slugTouched ? slug : toSlug(name);
  const slugValid = SLUG_RE.test(slugValue);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!slugValid) return;
    createProject.mutate(
      {
        name,
        slug: slugValue,
        description: description || undefined,
        environment,
      },
      {
        onSuccess: () => {
          toast.success("Project created");
          onCreated();
        },
        onError: (err) => toast.error(`Failed: ${err.message}`),
      },
    );
  };

  return (
    <form onSubmit={handleSubmit}>
      <DialogHeader>
        <DialogTitle>Create Project</DialogTitle>
        <DialogDescription>
          Add a new project to your z4j instance.
        </DialogDescription>
      </DialogHeader>
      <div className="mt-4 space-y-4">
        <div className="space-y-2">
          <Label htmlFor="create-project-name">Name</Label>
          <Input
            id="create-project-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="My Project"
            required
            minLength={1}
            maxLength={200}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="create-project-slug">Slug</Label>
          <Input
            id="create-project-slug"
            value={slugValue}
            onChange={(e) => {
              setSlugTouched(true);
              setSlug(toSlug(e.target.value));
            }}
            placeholder="my-project"
            required
            minLength={3}
            maxLength={50}
          />
          <p className="text-xs text-muted-foreground">
            Lowercase letters, numbers, and hyphens. 3-50 characters.
          </p>
          {slugValue && !slugValid && (
            <p className="text-xs text-destructive">
              Invalid slug format. Must be 3-50 characters: lowercase
              alphanumeric and hyphens, cannot start or end with a hyphen.
            </p>
          )}
        </div>
        <div className="space-y-2">
          <Label htmlFor="create-project-env">Environment</Label>
          <Select value={environment} onValueChange={setEnvironment}>
            <SelectTrigger id="create-project-env">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {ENVIRONMENTS.map((env) => (
                <SelectItem key={env} value={env}>
                  {env}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label htmlFor="create-project-desc">Description (optional)</Label>
          <Input
            id="create-project-desc"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="A brief description of this project"
            maxLength={2000}
          />
        </div>
      </div>
      <DialogFooter className="mt-6">
        <Button
          type="submit"
          disabled={createProject.isPending || !name || !slugValid}
        >
          {createProject.isPending ? "Creating..." : "Create Project"}
        </Button>
      </DialogFooter>
    </form>
  );
}

// ---------------------------------------------------------------------------
// Edit dialog
// ---------------------------------------------------------------------------

interface ProjectShape {
  slug: string;
  name: string;
  description: string | null;
  environment: string;
}

function EditProjectDialog({
  project,
  onSaved,
}: {
  project: ProjectShape;
  onSaved: () => void;
}) {
  const updateProject = useUpdateProject();
  const [name, setName] = useState(project.name);
  const [slugInput, setSlugInput] = useState(project.slug);
  const [description, setDescription] = useState(project.description ?? "");
  const [environment, setEnvironment] = useState(project.environment);

  const slugChanged = slugInput !== project.slug;
  const slugValid = SLUG_RE.test(slugInput);
  // If the user picked an environment outside the curated list
  // historically, keep it visible in the dropdown so they can
  // recognize it; otherwise only the curated values appear.
  const envOptions = ENVIRONMENTS.includes(
    environment as (typeof ENVIRONMENTS)[number],
  )
    ? ENVIRONMENTS
    : ([environment, ...ENVIRONMENTS] as readonly string[]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (slugChanged && !slugValid) return;
    updateProject.mutate(
      {
        slug: project.slug,
        new_slug: slugChanged ? slugInput : undefined,
        name,
        description: description || null,
        environment,
      },
      {
        onSuccess: () => {
          toast.success("Project updated");
          onSaved();
        },
        onError: (err) => toast.error(`Failed: ${err.message}`),
      },
    );
  };

  return (
    <form onSubmit={handleSubmit}>
      <DialogHeader>
        <DialogTitle>Edit Project</DialogTitle>
        <DialogDescription>
          Update details for{" "}
          <code className="rounded bg-muted px-1 py-0.5 text-xs">
            {project.slug}
          </code>
        </DialogDescription>
      </DialogHeader>
      <div className="mt-4 space-y-4">
        <div className="space-y-2">
          <Label htmlFor="edit-project-name">Name</Label>
          <Input
            id="edit-project-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            minLength={1}
            maxLength={200}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="edit-project-slug">Slug</Label>
          <Input
            id="edit-project-slug"
            value={slugInput}
            onChange={(e) => setSlugInput(toSlug(e.target.value))}
            required
            minLength={3}
            maxLength={50}
          />
          <p className="text-xs text-muted-foreground">
            Lowercase letters, numbers, and hyphens. Changing the slug
            breaks bookmarked URLs and any external integration that
            references this project by slug.
          </p>
          {slugInput && !slugValid && (
            <p className="text-xs text-destructive">
              Invalid slug format. Must be 3-50 characters: lowercase
              alphanumeric and hyphens, cannot start or end with a hyphen.
            </p>
          )}
        </div>
        <div className="space-y-2">
          <Label htmlFor="edit-project-env">Environment</Label>
          <Select value={environment} onValueChange={setEnvironment}>
            <SelectTrigger id="edit-project-env">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {envOptions.map((env) => (
                <SelectItem key={env} value={env}>
                  {env}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label htmlFor="edit-project-desc">Description</Label>
          <Input
            id="edit-project-desc"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="A brief description of this project"
            maxLength={2000}
          />
        </div>
      </div>
      <DialogFooter className="mt-6">
        <Button
          type="submit"
          disabled={
            updateProject.isPending || !name || (slugChanged && !slugValid)
          }
        >
          {updateProject.isPending ? "Saving..." : "Save Changes"}
        </Button>
      </DialogFooter>
    </form>
  );
}

// ---------------------------------------------------------------------------
// Delete confirmation dialog
// ---------------------------------------------------------------------------

function DeleteProjectDialog({
  project,
  onDeleted,
  onCancel,
}: {
  project: ProjectShape;
  onDeleted: () => void;
  onCancel: () => void;
}) {
  const deleteProject = useDeleteProject();
  const [confirmSlug, setConfirmSlug] = useState("");

  const confirmed = confirmSlug === project.slug;

  const handleDelete = () => {
    deleteProject.mutate(project.slug, {
      onSuccess: () => {
        toast.success("Project archived");
        onDeleted();
      },
      onError: (err) => toast.error(`Failed: ${err.message}`),
    });
  };

  return (
    <>
      <DialogHeader>
        <DialogTitle>Archive Project</DialogTitle>
        <DialogDescription>
          This will archive the project and hide it from all views. The
          project data and audit history will be preserved.
        </DialogDescription>
      </DialogHeader>
      <div className="mt-4 space-y-4">
        <p className="text-sm text-muted-foreground">
          To confirm, type the project slug{" "}
          <code className="rounded bg-muted px-1 py-0.5 text-xs font-semibold">
            {project.slug}
          </code>{" "}
          below:
        </p>
        <Input
          value={confirmSlug}
          onChange={(e) => setConfirmSlug(e.target.value)}
          placeholder={project.slug}
        />
      </div>
      <DialogFooter className="mt-6">
        <Button variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button
          variant="destructive"
          disabled={!confirmed || deleteProject.isPending}
          onClick={handleDelete}
        >
          {deleteProject.isPending ? "Archiving..." : "Archive Project"}
        </Button>
      </DialogFooter>
    </>
  );
}
