/**
 * Display mode and coordinated palette preferences, shared by every route.
 * The inline bootstrap applies the same values before first paint. This
 * provider follows system mode, persists browser choices and synchronizes tabs.
 * Palette migration and the bootstrap are checked together in unit tests.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  isPalette,
  PALETTE_STORAGE_KEY,
  readStoredPalette,
  type PaletteId,
} from "@/lib/palettes";

type Theme = "light" | "dark" | "system";
type ResolvedTheme = "light" | "dark";

interface ThemeContextValue {
  theme: Theme;
  resolvedTheme: ResolvedTheme;
  setTheme: (next: Theme) => void;
  palette: PaletteId;
  setPalette: (next: PaletteId) => void;
}

const STORAGE_KEY = "z4j-theme";
const DEFAULT_THEME: Theme = "system";

const ThemeContext = createContext<ThemeContextValue | null>(null);

function readStoredTheme(): Theme {
  if (typeof window === "undefined") return DEFAULT_THEME;
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (raw === "light" || raw === "dark" || raw === "system") return raw;
  } catch {
    // localStorage may throw on Safari private mode / SSR; ignore.
  }
  return DEFAULT_THEME;
}

function systemPrefersDark(): boolean {
  if (typeof window === "undefined" || !window.matchMedia) return true;
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function applyHtmlClass(resolved: ResolvedTheme): void {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  // Use ``classList.toggle`` so we never accidentally remove a
  // sibling class the host page might have added (none today, but
  // the contract should be defensive).
  root.classList.toggle("dark", resolved === "dark");
  root.classList.toggle("light", resolved === "light");
  // ``color-scheme`` lets the browser style scrollbars / form
  // controls correctly without us shipping CSS for them.
  root.style.colorScheme = resolved;
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() => readStoredTheme());
  const [palette, setPaletteState] = useState<PaletteId>(readStoredPalette);
  const [systemDark, setSystemDark] = useState<boolean>(() =>
    systemPrefersDark(),
  );

  // Watch ``prefers-color-scheme`` so a "system" pick follows the
  // OS in real time without a page refresh.
  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mql = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = (e: MediaQueryListEvent) => setSystemDark(e.matches);
    mql.addEventListener("change", handler);
    return () => mql.removeEventListener("change", handler);
  }, []);

  const resolvedTheme: ResolvedTheme = useMemo(() => {
    if (theme === "system") return systemDark ? "dark" : "light";
    return theme;
  }, [theme, systemDark]);

  // Apply the HTML class on every resolved-theme change. We do
  // this synchronously inside an effect so the painted DOM always
  // matches React state by the next animation frame.
  useEffect(() => {
    applyHtmlClass(resolvedTheme);
  }, [resolvedTheme]);

  useEffect(() => {
    document.documentElement.dataset.palette = palette;
  }, [palette]);

  // Preferences are local to this browser; keep other open tabs in sync.
  useEffect(() => {
    const sync = (event: StorageEvent) => {
      if (event.key === STORAGE_KEY || event.key === null)
        setThemeState(readStoredTheme());
      if (
        event.key === PALETTE_STORAGE_KEY ||
        event.key === "z4j-primary-hue" ||
        event.key === null
      )
        setPaletteState(readStoredPalette());
    };
    window.addEventListener("storage", sync);
    return () => window.removeEventListener("storage", sync);
  }, []);

  const setPalette = useCallback((next: PaletteId) => {
    if (!isPalette(next)) return;
    setPaletteState(next);
    try {
      window.localStorage.setItem(PALETTE_STORAGE_KEY, next);
    } catch {
      // Applying a palette still works when browser storage is unavailable.
    }
  }, []);

  const setTheme = useCallback((next: Theme) => {
    setThemeState(next);
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // localStorage write failure is not worth a toast - the
      // class still applies for this session, the persistence
      // just doesn't survive a reload. Fail silently.
    }
  }, []);

  const value = useMemo<ThemeContextValue>(
    () => ({ theme, resolvedTheme, setTheme, palette, setPalette }),
    [theme, resolvedTheme, setTheme, palette, setPalette],
  );

  return (
    <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (ctx === null) {
    // Defensive: every consumer must be inside <ThemeProvider>.
    // Returning a static fallback would mask the bug; throwing
    // surfaces it in dev and the error boundary catches it in
    // production.
    throw new Error("useTheme must be used inside <ThemeProvider>");
  }
  return ctx;
}
