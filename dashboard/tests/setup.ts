/**
 * Vitest global setup.
 *
 * - Installs ``@testing-library/jest-dom`` matchers (e.g.
 *   ``expect(el).toBeInTheDocument()``).
 * - Calls ``cleanup`` after each test so the happy-dom container
 *   is reset between cases - leaking DOM nodes is the most
 *   common source of flaky React tests.
 * - Stubs out ``window.matchMedia`` (needed by next-themes,
 *   sonner, and shadcn primitives that probe for color-scheme
 *   preference).
 */
import "@testing-library/jest-dom/vitest";
import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

afterEach(() => {
  cleanup();
});

if (typeof window !== "undefined" && !window.matchMedia) {
  window.matchMedia = (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  }) as MediaQueryList;
}
