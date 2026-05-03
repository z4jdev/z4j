/**
 * Theme switcher - light / dark / system.
 *
 * Renders an icon-button trigger that shows the active theme's
 * icon (sun for light, moon for dark, monitor for system) and a
 * dropdown with the three options + a check next to the active
 * one. The local ``ThemeProvider`` (formerly ``next-themes``)
 * handles persistence + the ``prefers-color-scheme`` sync.
 */
import { Check, Monitor, Moon, Sun } from "lucide-react";
import { useTheme } from "@/components/layout/theme-provider";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

const OPTIONS = [
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
  { value: "system", label: "System", icon: Monitor },
] as const;

export function ThemeToggle() {
  const { theme, setTheme, resolvedTheme } = useTheme();

  // Trigger icon: shows the resolved theme so a "system" pick still
  // gives a meaningful glyph instead of a generic monitor.
  const triggerIcon =
    theme === "system" ? Monitor : resolvedTheme === "dark" ? Moon : Sun;
  const TriggerIcon = triggerIcon;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" aria-label="Switch theme">
          <TriggerIcon className="size-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-40">
        <DropdownMenuLabel>Appearance</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {OPTIONS.map((opt) => {
          const Icon = opt.icon;
          const active = theme === opt.value;
          return (
            <DropdownMenuItem key={opt.value} onSelect={() => setTheme(opt.value)}>
              <Icon className="size-4" />
              <span>{opt.label}</span>
              {active && <Check className="ml-auto size-4" />}
            </DropdownMenuItem>
          );
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
