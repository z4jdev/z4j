/**
 * Notification bell -- shows recent in-app notifications in a dropdown.
 *
 * Backed by the per-user notification inbox:
 *   GET /user/notifications
 *   GET /user/notifications/unread-count
 *   POST /user/notifications/{id}/read
 *   POST /user/notifications/read-all
 */
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { Bell, BellOff, Check, Settings } from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  useMarkAllRead,
  useMarkRead,
  useUnreadCount,
  useUserNotifications,
  type TriggerType,
  type UserNotification,
} from "@/hooks/use-notifications";
import { useProjects } from "@/hooks/use-projects";
import { formatRelative } from "@/lib/format";

/** Map a trigger to a colored dot (tailwind bg class). */
function triggerDotClass(trigger: TriggerType | string): string {
  switch (trigger) {
    case "task.failed":
      return "bg-destructive";
    case "task.succeeded":
      return "bg-green-500";
    case "task.retried":
      return "bg-yellow-500";
    default:
      return "bg-muted-foreground";
  }
}

export function NotificationBell() {
  const params = useParams({ strict: false });
  const routeSlug = (params as { slug?: string }).slug;
  const navigate = useNavigate();

  const { data: unreadData } = useUnreadCount();
  const { data: notifications } = useUserNotifications({ limit: 20 });
  const { data: projects } = useProjects();
  const markRead = useMarkRead();
  const markAllRead = useMarkAllRead();

  const unreadCount = unreadData?.unread ?? 0;
  const hasNotifications = notifications && notifications.length > 0;

  const resolveProjectSlug = (n: UserNotification): string | null => {
    if (routeSlug) return routeSlug;
    return projects?.find((p) => p.id === n.project_id)?.slug ?? null;
  };

  const handleRowClick = (n: UserNotification) => {
    // Mark as read (if not already)
    if (!n.read_at) {
      markRead.mutate(n.id, {
        onError: (err) => {
          const msg = err instanceof Error ? err.message : "Request failed";
          toast.error(msg);
        },
      });
    }
    // Deep-link to the task detail if we can resolve a slug + task_id
    // + engine. Multi-engine: if the backend didn't stamp ``engine``
    // onto the notification (older events from before BUG-2 was
    // fixed), refuse to deep-link rather than guessing "celery" -
    // the guess was the bug.
    const taskId =
      typeof n.data?.task_id === "string" ? (n.data.task_id as string) : null;
    const engine =
      typeof n.data?.engine === "string" ? (n.data.engine as string) : null;
    const targetSlug = resolveProjectSlug(n);
    if (taskId && targetSlug && engine) {
      navigate({
        to: "/projects/$slug/tasks/$engine/$taskId",
        params: { slug: targetSlug, engine, taskId },
      });
    }
  };

  const handleMarkAllRead = () => {
    markAllRead.mutate(undefined, {
      onError: (err) => {
        const msg = err instanceof Error ? err.message : "Request failed";
        toast.error(msg);
      },
    });
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          aria-label={
            unreadCount > 0
              ? `${unreadCount} unread notifications`
              : "Notifications"
          }
          className="relative"
        >
          <Bell className="size-4" />
          {unreadCount > 0 && (
            <span className="absolute right-1.5 top-1.5 flex size-2 items-center justify-center">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-destructive opacity-75" />
              <span className="relative inline-flex size-2 rounded-full bg-destructive" />
            </span>
          )}
        </Button>
      </DropdownMenuTrigger>

      <DropdownMenuContent align="end" className="w-80">
        <DropdownMenuLabel className="flex items-center justify-between">
          <span>Notifications</span>
          {unreadCount > 0 && (
            <button
              type="button"
              onClick={handleMarkAllRead}
              className="flex items-center gap-1 text-xs font-normal text-muted-foreground hover:text-foreground transition-colors"
            >
              <Check className="size-3" />
              Mark all read
            </button>
          )}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />

        {hasNotifications ? (
          <>
            <div className="max-h-72 overflow-y-auto">
              {notifications.map((n) => (
                <NotificationRow
                  key={n.id}
                  notification={n}
                  onClick={() => handleRowClick(n)}
                />
              ))}
            </div>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <Link
                to="/settings/notifications"
                className="flex items-center gap-2 text-xs"
              >
                <Settings className="size-3.5" />
                Configure notifications
              </Link>
            </DropdownMenuItem>
          </>
        ) : (
          <div className="flex flex-col items-center gap-2 py-8 text-center px-4">
            <BellOff className="size-6 text-muted-foreground/60" />
            <p className="text-sm font-medium">No notifications yet</p>
            <p className="text-xs text-muted-foreground">
              Subscribe to task events to get notified here.
            </p>
            <Button variant="outline" size="sm" asChild className="mt-1">
              <Link to="/settings/notifications">
                <Settings className="size-3.5 mr-1.5" />
                Configure notifications
              </Link>
            </Button>
          </div>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function NotificationRow({
  notification,
  onClick,
}: {
  notification: UserNotification;
  onClick: () => void;
}) {
  const isUnread = !notification.read_at;
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex w-full items-start gap-3 px-3 py-2 text-left hover:bg-accent/50 transition-colors"
    >
      {/* Unread dot */}
      <div className="mt-1.5 shrink-0">
        {isUnread ? (
          <span className="block size-2 rounded-full bg-primary" />
        ) : (
          <span className="block size-2" />
        )}
      </div>

      <div
        className={cn(
          "min-w-0 flex-1 space-y-0.5",
          !isUnread && "text-muted-foreground",
        )}
      >
        <div className="flex items-center gap-2">
          <span
            className={cn(
              "block size-2 shrink-0 rounded-full",
              triggerDotClass(notification.trigger),
            )}
          />
          <span className="truncate text-sm font-medium">
            {notification.title}
          </span>
        </div>

        {notification.body && (
          <p className="truncate text-xs text-muted-foreground">
            {notification.body}
          </p>
        )}

        <p className="text-[11px] text-muted-foreground/70">
          {formatRelative(notification.created_at)}
        </p>
      </div>
    </button>
  );
}
