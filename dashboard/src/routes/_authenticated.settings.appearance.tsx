/**
 * Appearance settings page - theme and primary color selection.
 *
 * Moved from the project-scoped settings page to the global settings hub
 * since theme/color preferences are user-level, not project-level.
 */
import { useEffect, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useTheme } from "@/components/layout/theme-provider";
import { Check, Monitor, Moon, Sun } from "lucide-react";
import { Card } from "@/components/ui/card";
import { PageHeader } from "@/components/domain/page-header";

export const Route = createFileRoute("/_authenticated/settings/appearance")({
  component: AppearancePage,
});

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PRIMARY_COLORS = [
  { name: "Blue", hue: 250, color: "oklch(0.55 0.18 250)" },
  { name: "Violet", hue: 280, color: "oklch(0.55 0.18 280)" },
  { name: "Purple", hue: 310, color: "oklch(0.55 0.18 310)" },
  { name: "Rose", hue: 350, color: "oklch(0.55 0.18 350)" },
  { name: "Red", hue: 25, color: "oklch(0.55 0.18 25)" },
  { name: "Orange", hue: 50, color: "oklch(0.55 0.18 50)" },
  { name: "Green", hue: 150, color: "oklch(0.55 0.18 150)" },
  { name: "Teal", hue: 180, color: "oklch(0.55 0.18 180)" },
  { name: "Cyan", hue: 210, color: "oklch(0.55 0.18 210)" },
] as const;

const THEME_OPTIONS = [
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
  { value: "system", label: "System", icon: Monitor },
] as const;

const COLOR_STORAGE_KEY = "z4j-primary-hue";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function applyPrimaryHue(hue: number) {
  const root = document.documentElement;
  root.style.setProperty("--primary", `oklch(0.55 0.18 ${hue})`);
  root.style.setProperty("--primary-foreground", `oklch(0.99 0.005 ${hue})`);
  root.style.setProperty("--ring", `oklch(0.55 0.18 ${hue})`);
  root.style.setProperty("--sidebar-primary", `oklch(0.55 0.18 ${hue})`);
  root.style.setProperty(
    "--sidebar-primary-foreground",
    `oklch(0.99 0.005 ${hue})`,
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function AppearancePage() {
  const { theme, setTheme } = useTheme();
  const [activeHue, setActiveHue] = useState<number>(() => {
    if (typeof window === "undefined") return 250;
    const stored = localStorage.getItem(COLOR_STORAGE_KEY);
    return stored ? parseInt(stored, 10) : 250;
  });

  // Apply saved hue on mount.
  useEffect(() => {
    applyPrimaryHue(activeHue);
  }, [activeHue]);

  const selectColor = (hue: number) => {
    setActiveHue(hue);
    applyPrimaryHue(hue);
    try {
      localStorage.setItem(COLOR_STORAGE_KEY, String(hue));
    } catch {
      // localStorage may be disabled
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Appearance"
        description="Theme and accent color."
      />
      {/* Theme */}
      <Card className="p-6">
        <h3 className="text-sm font-semibold">Theme</h3>
        <p className="mt-1 text-xs text-muted-foreground">
          Choose how the dashboard looks. System follows your OS preference.
        </p>
        <div className="mt-4 flex gap-3">
          {THEME_OPTIONS.map((opt) => {
            const Icon = opt.icon;
            const active = theme === opt.value;
            return (
              <button
                key={opt.value}
                type="button"
                onClick={() => setTheme(opt.value)}
                className={`flex flex-col items-center gap-2 rounded-lg border-2 px-6 py-4 text-sm font-medium transition-colors ${
                  active
                    ? "border-primary bg-primary/5 text-primary"
                    : "border-border bg-card text-muted-foreground hover:border-primary/30 hover:bg-accent"
                }`}
              >
                <Icon className="size-5" />
                {opt.label}
              </button>
            );
          })}
        </div>
      </Card>

      {/* Primary color */}
      <Card className="p-6">
        <h3 className="text-sm font-semibold">Primary color</h3>
        <p className="mt-1 text-xs text-muted-foreground">
          The accent color used for buttons, links, and active states.
        </p>
        <div className="mt-4 flex flex-wrap gap-3">
          {PRIMARY_COLORS.map((c) => (
            <button
              key={c.hue}
              type="button"
              onClick={() => selectColor(c.hue)}
              title={c.name}
              className={`relative flex size-9 items-center justify-center rounded-full border-2 transition-transform hover:scale-110 ${
                activeHue === c.hue
                  ? "border-foreground"
                  : "border-transparent"
              }`}
            >
              <span
                className="size-7 rounded-full"
                style={{ background: c.color }}
              />
              {activeHue === c.hue && (
                <Check className="absolute size-3.5 text-white" />
              )}
            </button>
          ))}
        </div>
      </Card>
    </div>
  );
}
