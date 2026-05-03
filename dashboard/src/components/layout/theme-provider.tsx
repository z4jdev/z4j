/**
 * Dark/light/system theme provider.
 *
 * Inlined replacement for the ``next-themes`` npm package as part
 * of the npm-supply-chain minimisation pass (SECURITY.md §16.1).
 * The package is fine, well-maintained, and 50 KB in npm; we
 * dropped it because the surface we use (three modes, one
 * ``html.dark`` class, ``prefers-color-scheme`` sync,
 * localStorage persistence) is ~60 lines of code we'd rather own
 * directly than accept another publish-path-to-compromise on.
 *
 * Drop-in compatible with the API every consumer used:
 *   - ``<ThemeProvider>{children}</ThemeProvider>`` at app root
 *   - ``const { theme, setTheme, resolvedTheme } = useTheme()``
 *
 * The HTML element is initialised with ``class="dark"`` by the
 * inline boot script in ``index.html`` so the first paint is dark
 * by default for a control plane. The provider then reads
 * ``localStorage.z4j-theme``; if it differs, it swaps the class
 * before React commits its first frame.
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

type Theme = "light" | "dark" | "system";
type ResolvedTheme = "light" | "dark";

interface ThemeContextValue {
  theme: Theme;
  resolvedTheme: ResolvedTheme;
  setTheme: (next: Theme) => void;
}

const STORAGE_KEY = "z4j-theme";
const DEFAULT_THEME: Theme = "dark";

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
    () => ({ theme, resolvedTheme, setTheme }),
    [theme, resolvedTheme, setTheme],
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
