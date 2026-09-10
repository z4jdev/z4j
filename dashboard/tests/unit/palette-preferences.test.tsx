import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ThemeProvider, useTheme } from "@/components/layout/theme-provider";
import { PALETTES, resolvePalette } from "@/lib/palettes";

const html = readFileSync(resolve(process.cwd(), "index.html"), "utf8");
const bootstrap = html.match(/<script>([\s\S]*?)<\/script>/)![1];
const executeBootstrap = () =>
  new Function("window", "document", "localStorage", bootstrap)(
    window,
    document,
    window.localStorage,
  );
const wrapper = ({ children }: { children: React.ReactNode }) => (
  <ThemeProvider>{children}</ThemeProvider>
);

beforeEach(() => {
  localStorage.clear();
  document.documentElement.className = "";
  delete document.documentElement.dataset.palette;
});
afterEach(() => vi.restoreAllMocks());

describe("palette preference lifecycle", () => {
  it("uses Sapphire by default and preserves a selected palette after remount", () => {
    const first = renderHook(() => useTheme(), { wrapper });
    expect(first.result.current.palette).toBe("sapphire");
    act(() => first.result.current.setPalette("jade"));
    expect(document.documentElement).toHaveAttribute("data-palette", "jade");
    expect(localStorage.getItem("z4j-palette")).toBe("jade");
    first.unmount();
    const next = renderHook(() => useTheme(), { wrapper });
    expect(next.result.current.palette).toBe("jade");
  });

  it("changes display mode without replacing the chosen palette", () => {
    localStorage.setItem("z4j-palette", "iris");
    const { result } = renderHook(() => useTheme(), { wrapper });
    act(() => result.current.setTheme("dark"));
    expect(document.documentElement).toHaveClass("dark");
    expect(document.documentElement).toHaveAttribute("data-palette", "iris");
    act(() => result.current.setTheme("light"));
    expect(document.documentElement).not.toHaveClass("dark");
    expect(result.current.palette).toBe("iris");
  });

  it("synchronizes palette and display mode between tabs", () => {
    const { result } = renderHook(() => useTheme(), { wrapper });
    act(() => {
      localStorage.setItem("z4j-palette", "sandstone");
      window.dispatchEvent(new StorageEvent("storage", { key: "z4j-palette" }));
      localStorage.setItem("z4j-theme", "dark");
      window.dispatchEvent(new StorageEvent("storage", { key: "z4j-theme" }));
    });
    expect(result.current.palette).toBe("sandstone");
    expect(result.current.resolvedTheme).toBe("dark");
    act(() => {
      localStorage.clear();
      window.dispatchEvent(new StorageEvent("storage", { key: null }));
    });
    expect(result.current.palette).toBe("sapphire");
    expect(result.current.theme).toBe("system");
  });

  it("still applies a preference when browser storage is blocked", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("Storage blocked");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("Storage blocked");
    });
    expect(executeBootstrap).not.toThrow();
    expect(document.documentElement).toHaveClass("light");
    const { result } = renderHook(() => useTheme(), { wrapper });
    act(() => result.current.setPalette("jade"));
    expect(document.documentElement).toHaveAttribute("data-palette", "jade");
  });
});

describe("pre-paint bootstrap and provider agree", () => {
  it.each(PALETTES)("restores $name before React mounts", ({ id }) => {
    localStorage.setItem("z4j-palette", id);
    localStorage.setItem("z4j-theme", "light");
    executeBootstrap();
    expect(document.documentElement).toHaveAttribute("data-palette", id);
    const { result } = renderHook(() => useTheme(), { wrapper });
    expect(result.current.palette).toBe(id);
  });

  it.each(["250", "280", "310", "350", "25", "50", "150", "180", "210"])(
    "migrates the previous %s hue consistently",
    (hue) => {
      localStorage.setItem("z4j-primary-hue", hue);
      executeBootstrap();
      const expected = resolvePalette(null, hue);
      expect(document.documentElement).toHaveAttribute(
        "data-palette",
        expected,
      );
      const { result } = renderHook(() => useTheme(), { wrapper });
      expect(result.current.palette).toBe(expected);
      act(() => result.current.setPalette("sapphire"));
      executeBootstrap();
      expect(document.documentElement).toHaveAttribute(
        "data-palette",
        "sapphire",
      );
    },
  );

  it.each(["garbage", "__proto__", "constructor", "361", "-1", "", "250px"])(
    "rejects invalid saved values: %s",
    (value) => {
      localStorage.setItem("z4j-palette", value);
      localStorage.setItem("z4j-primary-hue", value);
      executeBootstrap();
      expect(document.documentElement).toHaveAttribute(
        "data-palette",
        "sapphire",
      );
      const { result } = renderHook(() => useTheme(), { wrapper });
      expect(result.current.palette).toBe("sapphire");
    },
  );
});
