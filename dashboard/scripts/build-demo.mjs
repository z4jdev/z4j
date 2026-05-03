/**
 * build-demo.mjs -- build the dashboard SPA in demo mode.
 *
 * Sets VITE_Z4J_DEMO_MODE=true so the in-browser mock-fetch
 * interceptor (src/lib/api.demo.ts) replaces real `fetch()`
 * calls. Output lands in dist-demo/ so the production build at
 * dist/ is not clobbered.
 *
 * Done as a Node script (not an inline npm-script env-var
 * assignment) for cross-platform compatibility -- the shell
 * syntax `VAR=val cmd` does not work on Windows cmd.exe, and we
 * do not want to add cross-env as a dependency just for this.
 *
 * After the Vite build finishes this script also copies the
 * pre-baked demo data tree from src/lib/demo-data/ to
 * dist-demo/demo-data/ so the SPA can fetch JSON files at
 * runtime alongside its bundle.
 *
 * The actual `vite build` is invoked via `pnpm exec` rather than
 * `import("vite")` because pnpm's symlinked node_modules layout
 * does not always expose vite to direct ESM imports from
 * /scripts/, but `pnpm exec` always finds it.
 *
 * See DEMO-Z4J-DEV-DESIGN.md for the full architecture.
 */
import { spawnSync } from "node:child_process";
import { cp, mkdir, access, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const dashboardRoot = resolve(__dirname, "..");

console.log("[build:demo] running vite build with VITE_Z4J_DEMO_MODE=true");
const env = { ...process.env, VITE_Z4J_DEMO_MODE: "true" };
const result = spawnSync(
  "pnpm",
  ["exec", "vite", "build", "--outDir", "dist-demo", "--emptyOutDir"],
  {
    cwd: dashboardRoot,
    env,
    stdio: "inherit",
    shell: true, // needed on Windows so `pnpm` resolves the .cmd shim
  },
);
if (result.status !== 0) {
  console.error(`[build:demo] vite build failed with exit code ${result.status}`);
  process.exit(result.status ?? 1);
}

const dataSrc = resolve(dashboardRoot, "src/lib/demo-data");
const dataDst = resolve(dashboardRoot, "dist-demo/demo-data");
let hasDataTree = false;
try {
  await access(dataSrc);
  hasDataTree = true;
} catch {
  console.log(
    "[build:demo] no src/lib/demo-data/ tree to copy (skipping); the " +
      "interceptor will return 404 for unknown routes which surfaces in " +
      "the dashboard as empty states until seed data is added.",
  );
}
if (hasDataTree) {
  await mkdir(dataDst, { recursive: true });
  await cp(dataSrc, dataDst, { recursive: true });
  console.log(`[build:demo] copied demo data tree: ${dataSrc} -> ${dataDst}`);
}

// Cloudflare Pages uses _redirects (SPA fallback) and _headers
// (cache + security headers). Vite does not generate these, so we
// write them here every build. Keeping them next to the build script
// (rather than in public/) means the production `pnpm build` does
// NOT pick them up -- only the demo build does, which is the only
// place SPA fallback makes sense (production serves the SPA via
// FastAPI, which has its own catch-all).
await writeFile(
  resolve(dashboardRoot, "dist-demo/_redirects"),
  "/*    /index.html   200\n",
);
await writeFile(
  resolve(dashboardRoot, "dist-demo/_headers"),
  [
    "/assets/*",
    "  Cache-Control: public, max-age=31536000, immutable",
    "",
    "/demo-data/*",
    "  Cache-Control: public, max-age=300",
    "",
    "/*",
    "  X-Frame-Options: DENY",
    "  X-Content-Type-Options: nosniff",
    "  Referrer-Policy: strict-origin-when-cross-origin",
    "",
  ].join("\n"),
);

console.log("[build:demo] wrote _redirects + _headers for Cloudflare Pages");
console.log("[build:demo] done. Output: dist-demo/");
