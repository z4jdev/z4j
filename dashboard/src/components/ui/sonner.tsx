/**
 * Toast notifications via Sonner.
 *
 * Mounted once in main.tsx. Triggered via ``import { toast } from
 * "sonner"`` from any component.
 *
 * Defaults picked for visibility:
 *
 * - ``position="top-center"``. Top-right collides with the "Add
 *   Channel" / "New Task" action-button region and the user's eye
 *   focus stays centred after clicking a row-level action; toasts
 *   in the corner got missed routinely. Top-center keeps them in
 *   the reading flow.
 * - ``richColors`` owns success/error/warning/info styling. We do
 *   NOT re-apply a ``bg-card`` override on the generic toast
 *   class - that flattened every toast type to the same muted
 *   card background and defeated the colour semantics.
 * - ``closeButton`` - Sonner auto-dismisses after ``duration``
 *   but a manual close lets operators dismiss an error banner
 *   without waiting it out.
 * - ``expand=true`` so a burst of toasts (e.g. two workers going
 *   offline in quick succession) stacks visibly instead of hiding
 *   all but the top one.
 *
 * The ``sonner/dist/styles.css`` import is REQUIRED - without it
 * Sonner renders unstyled DOM at the bottom of the page (no
 * positioning, no animation, no richColors, no closeButton).
 * Sonner 2.x ships positioning + animation CSS only in this
 * file; no auto-injection.
 */
import { useTheme } from "@/components/layout/theme-provider";
import { Toaster as SonnerToaster } from "sonner";
import "sonner/dist/styles.css";
import type { ComponentProps } from "react";

type ToasterProps = ComponentProps<typeof SonnerToaster>;

export function Toaster({ ...props }: ToasterProps) {
  const { theme } = useTheme();
  return (
    <SonnerToaster
      theme={theme as ToasterProps["theme"]}
      className="toaster group"
      position="top-center"
      richColors
      closeButton
      expand
      toastOptions={{
        duration: 5_000,
        classNames: {
          description: "group-[.toast]:text-muted-foreground",
          actionButton:
            "group-[.toast]:bg-primary group-[.toast]:text-primary-foreground",
          cancelButton:
            "group-[.toast]:bg-muted group-[.toast]:text-muted-foreground",
        },
      }}
      {...props}
    />
  );
}
