import { createFileRoute } from "@tanstack/react-router";
import { Check, Monitor, Moon, Palette, RotateCcw, Sun } from "lucide-react";
import { PageHeader } from "@/components/domain/page-header";
import { useTheme } from "@/components/layout/theme-provider";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Z4jMark } from "@/components/z4j-mark";
import { DEFAULT_PALETTE, PALETTES, type PaletteId } from "@/lib/palettes";

export const Route = createFileRoute("/_authenticated/settings/appearance")({
  component: AppearancePage,
});

const MODES = [
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
  { value: "system", label: "System", icon: Monitor },
] as const;

function AppearancePage() {
  const { theme, resolvedTheme, setTheme, palette, setPalette } = useTheme();
  const activePalette = PALETTES.find((item) => item.id === palette)!;
  return (
    <div className="appearance-settings space-y-6">
      <PageHeader
        icon={Palette}
        title="Appearance"
        description="Choose a coordinated palette and display mode."
        actions={
          <Button
            variant="outline"
            disabled={theme === "system" && palette === DEFAULT_PALETTE}
            onClick={() => {
              setTheme("system");
              setPalette(DEFAULT_PALETTE);
            }}
          >
            <RotateCcw className="size-4" />
            Reset appearance
          </Button>
        }
      />

      <Card className="p-5 sm:p-6">
        <fieldset className="min-w-0">
          <legend className="text-base font-semibold">Display mode</legend>
          <p className="mt-1 text-sm text-muted-foreground">
            Light and dark each have their own surfaces. System follows your
            device.
          </p>
          <div className="mt-4 grid max-w-md grid-cols-3 gap-2">
            {MODES.map(({ value, label, icon: Icon }) => (
              <label
                key={value}
                className="relative flex min-h-11 cursor-pointer flex-wrap items-center justify-center gap-x-2 gap-y-1 rounded-lg border bg-card px-2 py-2 text-sm font-medium transition-colors hover:bg-accent has-[:checked]:border-primary has-[:checked]:bg-accent has-[:checked]:text-accent-foreground has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-ring has-[:focus-visible]:ring-offset-2 has-[:focus-visible]:ring-offset-background"
              >
                <input
                  type="radio"
                  name="display-mode"
                  value={value}
                  checked={theme === value}
                  onChange={() => setTheme(value)}
                  className="absolute inset-0 z-10 m-0 size-full cursor-pointer opacity-0"
                />
                <Icon className="size-4" aria-hidden="true" />
                {label}
              </label>
            ))}
          </div>
        </fieldset>
      </Card>

      <fieldset className="min-w-0">
        <legend className="text-base font-semibold">Color palette</legend>
        <p className="mt-1 text-sm text-muted-foreground">
          Choose an accent for actions, selected navigation, icons and charts.
          Surfaces stay neutral. Previews follow your display mode.
        </p>
        <div className="appearance-palette-grid mt-4 grid gap-4">
          {PALETTES.map((item) => (
            <label
              key={item.id}
              className="relative min-w-0 cursor-pointer overflow-hidden rounded-lg border bg-card p-1 transition-colors hover:border-primary/50 has-[:checked]:border-primary has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-ring has-[:focus-visible]:ring-offset-2 has-[:focus-visible]:ring-offset-background"
            >
              <input
                type="radio"
                name="color-palette"
                value={item.id}
                aria-label={item.name}
                aria-describedby={`palette-${item.id}-description`}
                checked={palette === item.id}
                onChange={() => setPalette(item.id)}
                className="absolute inset-0 z-10 m-0 size-full cursor-pointer opacity-0"
              />
              <PalettePreview palette={item.id} />
              <div className="px-3 pb-3 pt-4 sm:px-4 sm:pb-4">
                <div className="flex items-center gap-2">
                  <span className="font-semibold">{item.name}</span>
                  {item.id === DEFAULT_PALETTE && (
                    <span className="rounded-md bg-muted px-2 py-0.5 text-xs text-muted-foreground">
                      Default
                    </span>
                  )}
                  <span
                    aria-hidden="true"
                    className={`ml-auto flex size-5 items-center justify-center rounded-full border ${palette === item.id ? "border-primary bg-primary text-primary-foreground" : "border-input"}`}
                  >
                    {palette === item.id && <Check className="size-3" />}
                  </span>
                </div>
                <p
                  id={`palette-${item.id}-description`}
                  className="mt-1 text-sm text-muted-foreground"
                >
                  {item.description}
                </p>
              </div>
            </label>
          ))}
        </div>
      </fieldset>
      <p role="status" className="text-sm text-muted-foreground">
        {activePalette.name} · {resolvedTheme === "dark" ? "Dark" : "Light"}
        {theme === "system" ? " (System)" : ""} · Applied across the dashboard.
      </p>
    </div>
  );
}

/** Decorative app thumbnail; it consumes the exact palette tokens used by the UI. */
function PalettePreview({ palette }: { palette: PaletteId }) {
  return (
    <div
      data-palette-preview={palette}
      aria-hidden="true"
      className="grid h-40 grid-cols-[64px_minmax(0,1fr)] overflow-hidden rounded-lg bg-[var(--z4j-canvas)] text-[var(--z4j-ink)]"
    >
      <div className="space-y-3 border-r border-[var(--z4j-line)] bg-[var(--z4j-rail)] px-2 py-3">
        <span className="mb-4 flex size-5 items-center justify-center rounded-md bg-[var(--z4j-blue)] text-[var(--z4j-primary-foreground)]">
          <Z4jMark className="size-3" />
        </span>
        <div className="rounded bg-[var(--z4j-nav-selected)] p-1.5">
          <div className="h-1 w-7 rounded-full bg-[var(--z4j-blue)]" />
        </div>
        {[28, 34, 22].map((width) => (
          <div
            key={width}
            className="ml-1.5 h-1 rounded-full bg-[var(--z4j-muted)] opacity-40"
            style={{ width }}
          />
        ))}
      </div>
      <div className="min-w-0 space-y-3 p-3">
        <div className="flex items-center justify-between gap-2">
          <span className="text-[10px] font-semibold">Overview</span>
          <span className="rounded bg-[var(--z4j-blue)] px-2 py-1 text-[8px] font-medium text-[var(--z4j-primary-foreground)]">
            Create
          </span>
        </div>
        <div className="grid grid-cols-3 gap-2">
          {["Tasks", "Workers", "Queues"].map((label) => (
            <div
              key={label}
              className="space-y-1.5 rounded border border-[var(--z4j-line)] bg-[var(--z4j-surface)] p-1.5"
            >
              <div className="text-[8px] text-[var(--z4j-muted)]">{label}</div>
              <div className="h-1.5 w-3/5 rounded-full bg-[var(--z4j-blue)]" />
            </div>
          ))}
        </div>
        <div className="flex h-12 items-end gap-1.5 rounded border border-[var(--z4j-line)] bg-[var(--z4j-surface)] px-2 pt-1.5">
          {[35, 52, 43, 72, 60, 90, 77, 98].map((height, index) => (
            <div
              key={height}
              className="flex-1 rounded-t-sm"
              style={{
                height: `${height}%`,
                background:
                  index < 5 ? "var(--z4j-blue)" : "var(--z4j-secondary-accent)",
                opacity: index % 2 ? 1 : 0.6,
              }}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
