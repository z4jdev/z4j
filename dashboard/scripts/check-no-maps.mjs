#!/usr/bin/env node
/**
 * 1.6.6 (audit R7-L6 follow-up): walker guard that fails the
 * production dashboard build if any .map file ended up in dist/.
 *
 * Sits at the production-build boundary as the third independent
 * layer of the no-source-maps posture:
 *
 *   1. vite.config.ts sets ``sourcemap: false`` when ``mode ===
 *      "production"`` (the function-form refactor in this same
 *      release; pre-1.6.6 used process.env.NODE_ENV which was
 *      flaky).
 *   2. THIS script: a build-time walker that exits non-zero if
 *      any *.map file survives in dist/, catching a future vite
 *      regression / plugin / operator override.
 *   3. release-split.sh ships a wheel-time assertion that blocks
 *      publish if .map files made it into the wheel.
 *
 * Same shape as the L-6 guard inside build-demo.mjs but operates
 * on the production dist/ that ships in the brain wheel.
 *
 * Run: node scripts/check-no-maps.mjs
 * Exit: 0 = clean, 1 = .map files present (fails the build).
 */
import { readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const dashboardRoot = resolve(__dirname, "..");
const distPath = resolve(dashboardRoot, "dist");

function* walkForMaps(dir) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    // dist/ may not exist if vite build errored earlier; let that
    // surface elsewhere and exit silently here.
    if (err.code === "ENOENT") return;
    throw err;
  }
  for (const entry of entries) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walkForMaps(p);
    } else if (entry.name.endsWith(".map")) {
      yield p;
    }
  }
}

const stragglers = [...walkForMaps(distPath)];
if (stragglers.length > 0) {
  console.error(
    `[check-no-maps] FAIL: ${stragglers.length} .map file(s) found ` +
      `in production dist/ (violates 1.6.3 no-source-maps posture; ` +
      `see R7-L6):`,
  );
  for (const m of stragglers.slice(0, 10)) {
    console.error(`  ${m}`);
  }
  if (stragglers.length > 10) {
    console.error(`  ... and ${stragglers.length - 10} more`);
  }
  console.error(
    "\nLikely cause: vite.config.ts sourcemap setting changed, " +
      "or a plugin re-enabled them. Check vite.config.ts build.sourcemap " +
      "and any plugin that touches build.rollupOptions.output.sourcemap.",
  );
  process.exit(1);
}
console.log("[check-no-maps] OK: 0 .map files in production dist/");
