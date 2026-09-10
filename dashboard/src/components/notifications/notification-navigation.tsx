import { Link } from "@tanstack/react-router";

/** Shared route navigation for the personal and project notification hubs. */
export function NotificationNavigation({ slug }: { slug?: string }) {
  const scope = slug ? "Project" : "Global";
  const base = slug
    ? "/projects/$slug/settings/notifications"
    : "/settings/notifications";
  const sections = [
    { path: "channels", label: "Channels" },
    { path: "subscriptions", label: "Subscriptions" },
    { path: "deliveries", label: "Notification Log" },
  ] as const;

  return (
    <nav
      aria-label={
        slug ? "Project notification settings" : "Notification settings"
      }
      className="flex flex-wrap gap-x-4 gap-y-1 border-b"
    >
      {sections.map((section) => (
        <Link
          key={section.path}
          to={`${base}/${section.path}`}
          params={slug ? { slug } : undefined}
          replace
          className="inline-flex min-h-11 items-center border-b-2 px-1 py-2 text-sm font-medium transition-colors"
          activeProps={{ className: "border-primary text-primary" }}
          inactiveProps={{
            className:
              "border-transparent text-muted-foreground hover:border-border hover:text-foreground",
          }}
        >
          {scope} {section.label}
        </Link>
      ))}
    </nav>
  );
}
