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
import { cp, mkdir, access, readFile, writeFile } from "node:fs/promises";
import { readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const dashboardRoot = resolve(__dirname, "..");
const distDemoPath = resolve(dashboardRoot, "dist-demo");

console.log("[build:demo] running vite build with VITE_Z4J_DEMO_MODE=true");
// R7-L6: explicitly pin NODE_ENV=production so vite.config.ts's
// production-only ``sourcemap: false`` branch fires. Without this,
// build-demo inherits whatever NODE_ENV the operator's shell has
// (often unset, which means vite's mode-detection falls back to
// ``development`` for the implicit-mode case and emits .map files
// alongside every chunk). The 1.6.3 advisory's "no source maps in
// production" posture covers demo.z4j.dev too -- it's a publicly
// reachable build and source maps reproduce the unminified React
// source for any attacker who guesses ``<chunk>.js.map``.
const env = {
  ...process.env,
  VITE_Z4J_DEMO_MODE: "true",
  NODE_ENV: "production",
};
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

// R7-L6 backstop: walk dist-demo and fail if any .map file slipped
// through. The NODE_ENV=production env above is the primary control,
// but a future vite.config.ts edit, plugin, or operator override
// could still produce maps -- this catches that at build time rather
// than at deploy time when the maps would already be reachable on
// demo.z4j.dev. The check covers ALL nested directories (assets/,
// etc.), not just the top level.
function* walkForMaps(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walkForMaps(p);
    } else if (entry.name.endsWith(".map")) {
      yield p;
    }
  }
}
const stragglerMaps = [...walkForMaps(distDemoPath)];
if (stragglerMaps.length > 0) {
  console.error(
    `[build:demo] FAIL: ${stragglerMaps.length} .map file(s) found in ` +
      `dist-demo (violates 1.6.3 no-source-maps posture; see R7-L6):`,
  );
  for (const m of stragglerMaps.slice(0, 10)) {
    console.error(`  ${m}`);
  }
  if (stragglerMaps.length > 10) {
    console.error(`  ... and ${stragglerMaps.length - 10} more`);
  }
  process.exit(1);
}
console.log("[build:demo] OK: 0 .map files in dist-demo (R7-L6 guard)");

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
// Defense-in-depth CSP for the demo build. The mock-fetch
// interceptor + WebSocket short-circuit already prevent any
// outbound server-side request from inside the demo SPA. The CSP
// is the BACKSTOP: even if a future code change accidentally
// introduces an outbound fetch / WebSocket / image / script load
// to anywhere except this origin, the browser refuses it. Reset
// demo and every other UI control are now physically incapable
// of reaching any server other than demo.z4j.dev's static-asset
// surface.
//
// What's allowed:
//   default-src 'self'              -- everything from this origin
//   script-src 'self' 'sha256-XXX'  -- bundle JS + the dist/index.html
//                                     theme-flicker inline script
//                                     (computed from the built
//                                     index.html so any change to
//                                     the inline script automatically
//                                     re-rolls into the CSP next build)
//   style-src 'self' 'unsafe-inline' -- Tailwind injects inline styles
//   img-src 'self' data:            -- bundled SVG + data URIs
//   font-src 'self' data:           -- bundled fonts + data URIs
//   connect-src 'self'              -- fetch/XHR/WS to this origin only
//   frame-ancestors 'none'          -- nobody can iframe demo.z4j.dev
//   base-uri 'self'                 -- no <base> hijack
//   form-action 'self'              -- no off-origin form posts
//
// Compute SHA256 of every inline <script> in dist-demo/index.html.
// Vite typically emits at most one (the theme-flicker shim). This
// loop tolerates multiple in case future template changes add more.
const indexHtml = await readFile(
  resolve(dashboardRoot, "dist-demo/index.html"),
  "utf8",
);
const inlineScriptHashes = [];
const inlineScriptRe = /<script>([\s\S]*?)<\/script>/g;
let inlineMatch;
while ((inlineMatch = inlineScriptRe.exec(indexHtml)) !== null) {
  const sha = createHash("sha256").update(inlineMatch[1]).digest("base64");
  inlineScriptHashes.push(`'sha256-${sha}'`);
}
console.log(
  `[build:demo] CSP script-src includes ${inlineScriptHashes.length} inline script hash(es)`,
);
const scriptSrc = ["'self'", ...inlineScriptHashes].join(" ");

const csp = [
  "default-src 'self'",
  `script-src ${scriptSrc}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join("; ");

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
    `  Content-Security-Policy: ${csp}`,
    "",
  ].join("\n"),
);

console.log("[build:demo] wrote _redirects + _headers for Cloudflare Pages");
console.log("[build:demo] done. Output: dist-demo/");
