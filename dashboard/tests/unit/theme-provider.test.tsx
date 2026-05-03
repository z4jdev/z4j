/**
 * Tests for ``ThemeProvider`` / ``useTheme``.
 *
 * Guards the supply-chain cut: this module replaced the
 * ``next-themes`` npm package as part of the April 2026
 * dep-minimisation pass (SECURITY.md §16.1). The contract these
 * tests pin down is the same one every consumer relied on:
 *
 * - default theme is ``"dark"`` for a control plane
 * - localStorage persists across reloads under key ``z4j-theme``
 * - ``"system"`` resolves via ``prefers-color-scheme``
 * - the ``html`` element's class swaps in lock-step with the
 *   resolved theme
 * - ``useTheme()`` outside the provider throws (defensive)
 */
import { describe, expect, it, beforeEach } from "vitest";
import { act, render, renderHook } from "@testing-library/react";

import {
  ThemeProvider,
  useTheme,
} from "@/components/layout/theme-provider";

beforeEach(() => {
  // Wipe persisted theme between tests so the default is honoured.
  try {
    window.localStorage.removeItem("z4j-theme");
  } catch {
    /* SSR-safe no-op */
  }
  // Reset the html class set we touch in the provider.
  document.documentElement.classList.remove("dark", "light");
  document.documentElement.style.colorScheme = "";
});

describe("ThemeProvider defaults", () => {
  it("resolves to dark on first paint", () => {
    const { result } = renderHook(() => useTheme(), {
      wrapper: ({ children }) => <ThemeProvider>{children}</ThemeProvider>,
    });
    expect(result.current.theme).toBe("dark");
    expect(result.current.resolvedTheme).toBe("dark");
  });

  it("applies the dark class to <html>", () => {
    render(
      <ThemeProvider>
        <span>x</span>
      </ThemeProvider>,
    );
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    expect(document.documentElement.style.colorScheme).toBe("dark");
  });
});

describe("setTheme", () => {
  it("updates resolvedTheme synchronously and persists to localStorage", () => {
    const { result } = renderHook(() => useTheme(), {
      wrapper: ({ children }) => <ThemeProvider>{children}</ThemeProvider>,
    });

    act(() => {
      result.current.setTheme("light");
    });
    expect(result.current.theme).toBe("light");
    expect(result.current.resolvedTheme).toBe("light");
    expect(window.localStorage.getItem("z4j-theme")).toBe("light");

    act(() => {
      result.current.setTheme("dark");
    });
    expect(result.current.resolvedTheme).toBe("dark");
    expect(window.localStorage.getItem("z4j-theme")).toBe("dark");
  });

  it("swaps the html class in lock-step", () => {
    const { result } = renderHook(() => useTheme(), {
      wrapper: ({ children }) => <ThemeProvider>{children}</ThemeProvider>,
    });

    act(() => {
      result.current.setTheme("light");
    });
    expect(document.documentElement.classList.contains("light")).toBe(true);
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    expect(document.documentElement.style.colorScheme).toBe("light");
  });
});

describe("system theme resolution", () => {
  it("reads prefers-color-scheme to resolve 'system'", () => {
    // Stub matchMedia to report "prefers-color-scheme: dark".
    window.matchMedia = (query: string) => ({
      matches: query.includes("dark"),
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }) as MediaQueryList;

    const { result } = renderHook(() => useTheme(), {
      wrapper: ({ children }) => <ThemeProvider>{children}</ThemeProvider>,
    });

    act(() => {
      result.current.setTheme("system");
    });
    expect(result.current.theme).toBe("system");
    expect(result.current.resolvedTheme).toBe("dark");
  });
});

describe("persistence on first mount", () => {
  it("hydrates from localStorage instead of using the default", () => {
    window.localStorage.setItem("z4j-theme", "light");
    const { result } = renderHook(() => useTheme(), {
      wrapper: ({ children }) => <ThemeProvider>{children}</ThemeProvider>,
    });
    expect(result.current.theme).toBe("light");
  });

  it("ignores garbage values in localStorage", () => {
    window.localStorage.setItem("z4j-theme", "neon-pink");
    const { result } = renderHook(() => useTheme(), {
      wrapper: ({ children }) => <ThemeProvider>{children}</ThemeProvider>,
    });
    expect(result.current.theme).toBe("dark");
  });
});

describe("useTheme outside ThemeProvider", () => {
  it("throws so the bug is loud, not silent", () => {
    // Disable React's logged error noise just for this assertion.
    const errSpy = (globalThis.console.error = () => {}) as never;
    try {
      expect(() => renderHook(() => useTheme())).toThrow(
        /useTheme must be used inside <ThemeProvider>/,
      );
    } finally {
      void errSpy;
    }
  });
});
