/**
 * Vite config for the z4j brain dashboard.
 *
 * Static-output build per docs/CLAUDE.md §4.5: the dashboard
 * compiles to plain HTML/CSS/JS and is served by FastAPI from
 * `/app/dashboard/dist`. No Node runtime in production.
 *
 * In dev, every `/api/v1/*`, `/setup*`, `/metrics`, and `/ws/agent`
 * request is proxied to the FastAPI brain on localhost:7700 so
 * cookies, CSRF tokens, and WebSocket upgrades all flow through
 * the same origin.
 */
// Vite + Vitest. The ``test`` field is consumed by Vitest at
// runtime and ignored by Vite proper; the cast keeps strict
// typecheck happy without us having to import a vitest-pinned
// ``defineConfig`` (which trips on transitive vite-version
// mismatches when vitest pins an older vite typing).
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { TanStackRouterVite } from "@tanstack/router-plugin/vite";
import path from "node:path";

const vitestConfig = {
  // Vitest config. ``jsdom`` provides the DOM shim - we picked it
  // over the slightly-faster ``happy-dom`` because jsdom is the
  // boring Mozilla project everyone has heard of (10+ years of
  // React tutorials use it), so the supply-chain story is short.
  // The setup file installs jest-dom matchers AND the ``cleanup``
  // after-each so test isolation is automatic.
  globals: true,
  environment: "jsdom",
  setupFiles: ["./tests/setup.ts"],
  include: ["tests/unit/**/*.{test,spec}.{ts,tsx}"],
  css: true,
  coverage: {
    provider: "v8",
    reporter: ["text", "html"],
    include: ["src/**/*.{ts,tsx}"],
    exclude: [
      "src/**/*.d.ts",
      "src/routeTree.gen.ts",
      "src/main.tsx",
    ],
  },
};

export default defineConfig({
  // Vitest reads ``test`` at runtime; vite's typing doesn't know
  // about it, so we tunnel it through a cast.
  ...({ test: vitestConfig } as object),
  plugins: [
    TanStackRouterVite({
      target: "react",
      autoCodeSplitting: true,
      routesDirectory: "./src/routes",
      generatedRouteTree: "./src/routeTree.gen.ts",
    }),
    react(),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    // In docker-compose.dev.yml the dashboard runs in its own
    // container; z4j is at ``z4j:7700`` on the docker
    // network. VITE_BRAIN_URL is set by compose. Outside docker
    // (bare ``pnpm dev``) it falls back to localhost:7700.
    host: "0.0.0.0",
    port: 5173,
    proxy: (() => {
      const brainHttp =
        process.env.VITE_BRAIN_URL || "http://127.0.0.1:7700";
      const brainWs = brainHttp.replace(/^http/, "ws");
      return {
        "/api/v1": { target: brainHttp, changeOrigin: true },
        "/setup": { target: brainHttp, changeOrigin: true },
        "/metrics": { target: brainHttp, changeOrigin: true },
        "/ws": { target: brainWs, ws: true, changeOrigin: true },
      };
    })(),
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2022",
    // 1.6.3 security advisory: never emit source maps in production
    // builds. Pre-1.6.3 used ``"hidden"`` which still emitted the
    // .map files (just stripped the //# sourceMappingURL pointer),
    // leaving them reachable for any attacker who guessed
    // ``<chunk>.js.map`` against the publicly mounted ``/assets/``
    // static handler. Source maps reproduce the unminified React
    // source: every TanStack route definition, every API client
    // method name, every developer comment - useful recon material
    // even without credential leakage. Dev keeps inline maps for DX.
    sourcemap: process.env.NODE_ENV === "production" ? false : true,
    rollupOptions: {
      output: {
        // Vite 8 dropped the record form of manualChunks; rollup
        // only accepts a function now. Same semantic effect -
        // pin the big vendors into their own chunks so the hash
        // of one does not invalidate the others on a content bump.
        manualChunks: (id: string): string | undefined => {
          if (id.includes("node_modules/react/") ||
              id.includes("node_modules/react-dom/")) return "react";
          if (id.includes("node_modules/@tanstack/react-router")) return "router";
          if (id.includes("node_modules/@tanstack/react-query")) return "query";
          if (id.includes("node_modules/@tanstack/react-table")) return "table";
          return undefined;
        },
      },
    },
  },
});
