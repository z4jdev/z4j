/**
 * Shared utility helpers.
 *
 * `cn` is the canonical shadcn helper that merges Tailwind class
 * strings while collapsing conflicting utilities - written by
 * tailwind-merge so the LATER class wins. Used by every component
 * in src/components.
 */
import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
