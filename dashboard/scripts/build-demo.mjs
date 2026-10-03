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
 * It then writes the Cloudflare Pages files (route-manifest.json,
 * _redirects, 404.html, _headers) and holds the finished dist-demo/
 * to the rules in scripts/demo-pages-config.mjs before it exits.
 *
 * The actual `vite build` is invoked via `pnpm exec` rather than
 * `import("vite")` because pnpm's symlinked node_modules layout
 * does not always expose vite to direct ESM imports from
 * /scripts/, but `pnpm exec` always finds it.
 *
 * See DEMO-Z4J-DEV-DESIGN.md for the full architecture.
 */
import { spawnSync } from "node:child_process";
import { copyFile, cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  BUILD_WRITTEN_ENTRIES,
  buildHeaders,
  buildRedirects,
  extractRouteManifestPaths,
  validateDemoPagesDist,
} from "./demo-pages-config.mjs";
import {
  isReleaseVersion,
  requireDemoDataTree,
  stampDemoVersions,
} from "./stamp-demo-versions.mjs";

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
// production" posture covers demo.z4j.com too -- it's a publicly
// reachable build and source maps reproduce the unminified React
// source for any attacker who guesses ``<chunk>.js.map``.
const env = {
  ...process.env,
  VITE_Z4J_DEMO_MODE: "true",
  NODE_ENV: "production",
};
// ``--config.verify-deps-before-run=false``: pnpm 11 no longer reads the
// ``pnpm.onlyBuiltDependencies`` allowlist from package.json (it moved to
// pnpm-workspace.yaml), so with ``ignore-scripts``/``enable-pre-post-scripts``
// on, esbuild's build script counts as "ignored" and pnpm's pre-run
// deps-status reconcile aborts ``pnpm exec`` with ERR_PNPM_IGNORED_BUILDS
// before vite ever runs. node_modules is already installed and in policy;
// the reconcile is spurious, so we skip it -- the same posture the
// sites/z4j-demo/.npmrc already documents for the wrapper's own pnpm calls.
// This only skips the pre-run check; it does NOT enable any install script.
const result = spawnSync(
  "pnpm",
  [
    "--config.verify-deps-before-run=false",
    "exec",
    "vite",
    "build",
    "--outDir",
    "dist-demo",
    "--emptyOutDir",
    // Emit hashed assets under /static/ rather than the default
    // /assets/. Cloudflare pinned SPA-fallback HTML under several
    // /assets/ URLs with `immutable, max-age=31536000` (see the
    // _redirects comment below), and a poisoned entry at that TTL
    // cannot be outrun by redeploying - the URL has to change.
    // Moving the namespace once retires every poisoned key at the
    // edge. Demo build only; the production build is untouched.
    "--assetsDir",
    "static",
  ],
  {
    cwd: dashboardRoot,
    env,
    stdio: "inherit",
    shell: true, // needed on Windows so `pnpm` resolves the .cmd shim
  },
);
if (result.status !== 0) {
  console.error(
    `[build:demo] vite build failed with exit code ${result.status}`,
  );
  process.exit(result.status ?? 1);
}

// R7-L6 backstop: walk dist-demo and fail if any .map file slipped
// through. The NODE_ENV=production env above is the primary control,
// but a future vite.config.ts edit, plugin, or operator override
// could still produce maps -- this catches that at build time rather
// than at deploy time when the maps would already be reachable on
// demo.z4j.com. The check covers ALL nested directories (assets/,
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
await requireDemoDataTree(dataSrc);
await mkdir(dataDst, { recursive: true });
await cp(dataSrc, dataDst, { recursive: true });
console.log(`[build:demo] copied demo data tree: ${dataSrc} -> ${dataDst}`);
// versions.json is tracked inside packages/z4j and therefore lands at the
// root of the published polyrepo, where the dashboard sits one level down.
// The old ../../../VERSION path only resolved in the dev monorepo.
const versionFile = resolve(dashboardRoot, "../versions.json");
// versions.json is a document, not a bare string: read the umbrella's entry.
let version;
try {
  const manifest = JSON.parse(await readFile(versionFile, "utf8"));
  version = manifest?.packages?.z4j?.version ?? manifest?.packages?.z4j;
} catch (err) {
  console.error(`[build:demo] cannot read ${versionFile}: ${err.message}`);
  process.exit(1);
}
if (!isReleaseVersion(version)) {
  console.error(
    `[build:demo] versions.json has no usable z4j version: ${JSON.stringify(version)}`,
  );
  process.exit(1);
}
const inventory = await stampDemoVersions(dataDst, version, {
  files: 7,
  fields: 24,
});
if (inventory.files !== 7 || inventory.fields !== 24) {
  console.error(
    `[build:demo] unexpected z4j version inventory: ` +
      `${inventory.fields} field(s) in ${inventory.files} file(s); ` +
      "expected 24 fields in 7 files",
  );
  process.exit(1);
}
console.log(
  `[build:demo] stamped ${inventory.changedFields} z4j release field(s) ` +
    `across ${inventory.changedFiles} demo file(s) to ${version} ` +
    `(verified ${inventory.fields} fields in ${inventory.files} files)`,
);

// Publish the real router paths. Cross-site link checks use them to tell a
// valid demo deep link from a nonexistent page, and _redirects below is
// generated from the same list.
const routeSource = await readFile(
  join(dashboardRoot, "src/routeTree.gen.ts"),
  "utf8",
);
const paths = extractRouteManifestPaths(routeSource);
if (!paths.includes("/projects/$slug/issues"))
  throw new Error("Demo route manifest is incomplete");
await writeFile(
  join(distDemoPath, "route-manifest.json"),
  JSON.stringify({ paths }, null, 2) + "\n",
);

// Cloudflare Pages routing. Vite does not generate _redirects, _headers or
// 404.html, so this script writes them on every demo build; keeping them
// out of public/ means the production `pnpm build` never picks them up
// (FastAPI serves that SPA with its own catch-all).
//
// What Pages did with the _redirects this script used to write:
//   /static/*    /index.html   404
//   /*    /index.html   200
// It rejected both lines (404 is not a permitted status, and a splat
// rewrite to /index.html is refused as a loop), so there were zero rules,
// and nothing warned because `wrangler pages deploy` uploads the file
// unparsed. With no top-level 404.html, Pages runs in single-page-
// application mode: every unmatched path gets index.html with 200, and
// _headers still applies to the request path. A missing hashed chunk
// therefore came back as 200 text/html with `immutable, max-age=31536000`,
// which is what took demo.z4j.com down: a chunk requested during the upload
// window had the fallback HTML pinned at the edge for a year (in the
// browser-shaped cache variant only, so curl looked healthy), and every
// later visitor got HTML where a module was expected:
//   "Expected a JavaScript-or-Wasm module script but the server
//    responded with a MIME type of ''"
//
// What the build writes now:
//   - 404.html, a byte copy of the final index.html (further down, after
//     the Rocket Loader opt-out). Its presence turns single-page-application
//     mode off, so an unknown path is a real 404 that still boots the SPA
//     into its own Not Found view. Pages sends every 404 with
//     `Cache-Control: no-store` whatever _headers says, so a miss under
//     /static/ can no longer be pinned.
//   - _redirects, a rewrite to "/" with 200 for every router path: an exact
//     rule per static path, and one splat per static prefix of the dynamic
//     paths (/projects/* for /projects/$slug/...). The target has to be "/",
//     because Pages turns a rewrite to /index.html or any .html path into a
//     308 redirect.
// scripts/demo-pages-config.mjs holds these rules and re-checks the finished
// dist-demo/ at the end of this script.
const distEntries = [
  ...new Set([...readdirSync(distDemoPath), ...BUILD_WRITTEN_ENTRIES]),
];
let redirects;
try {
  redirects = buildRedirects(paths, distEntries);
} catch (err) {
  console.error(`[build:demo] cannot generate _redirects: ${err.message}`);
  process.exit(1);
}
await writeFile(resolve(dashboardRoot, "dist-demo/_redirects"), redirects);
// Defense-in-depth CSP for the demo build. The mock-fetch
// interceptor + WebSocket short-circuit already prevent any
// outbound server-side request from inside the demo SPA. The CSP
// is the BACKSTOP: even if a future code change accidentally
// introduces an outbound fetch / WebSocket / image / script load
// to anywhere except this origin, the browser refuses it. Reset
// demo and every other UI control are now physically incapable
// of reaching any server other than demo.z4j.com's static-asset
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
//   frame-ancestors 'none'          -- nobody can iframe demo.z4j.com
//   base-uri 'self'                 -- no <base> hijack
//   form-action 'self'              -- no off-origin form posts
//
// Compute SHA256 of every inline <script> in dist-demo/index.html.
// Vite typically emits at most one (the theme-flicker shim). This
// loop tolerates multiple in case future template changes add more.
// Opt every script tag out of Cloudflare Rocket Loader BEFORE the CSP
// hashes are computed.
//
// Rocket Loader is a zone-level Cloudflare setting. When it is on it
// rewrites the HTML at the edge: it turns
//   <script type="module" src="...">
// into
//   <script type="<token>-module" src="...">
// and injects its own loader. A module script whose type has been
// rewritten is never executed as a module, so the SPA never mounts -
// the page renders completely blank with NO console error, because no
// application code ever ran. It also mutates the inline theme script,
// which invalidates the sha256 in the CSP below and gets that script
// blocked as well.
//
// This bit us on demo.z4j.com: the same build worked on
// *.pages.dev (which bypasses zone settings) and was blank on the
// custom domain. ``data-cfasync="false"`` is Cloudflare's documented
// opt-out and Rocket Loader leaves those tags untouched, so the build
// is self-defending regardless of how the zone is configured.
const indexHtmlPath = resolve(dashboardRoot, "dist-demo/index.html");
const rawIndexHtml = await readFile(indexHtmlPath, "utf8");
let cfasyncAdded = 0;
const guardedIndexHtml = rawIndexHtml.replace(
  /<script(?![^>]*\bdata-cfasync=)([^>]*)>/g,
  (_match, attrs) => {
    cfasyncAdded += 1;
    return `<script data-cfasync="false"${attrs}>`;
  },
);
if (guardedIndexHtml !== rawIndexHtml) {
  await writeFile(indexHtmlPath, guardedIndexHtml, "utf8");
}
console.log(
  `[build:demo] added data-cfasync="false" to ${cfasyncAdded} script tag(s) (Rocket Loader opt-out)`,
);

const indexHtml = guardedIndexHtml;
const inlineScriptHashes = [];
// Match any INLINE script (one with no ``src``), regardless of the other
// attributes it carries. This used to be the literal `<script>` with no
// attributes at all, which silently produced ZERO hashes the moment the
// Rocket Loader opt-out above added ``data-cfasync`` to the tag - and a
// CSP with no hash blocks the inline theme script outright.
const inlineScriptRe = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g;
let inlineMatch;
while ((inlineMatch = inlineScriptRe.exec(indexHtml)) !== null) {
  // Hash the text a browser hashes: the HTML parser turns CRLF and a lone CR
  // into LF first, so a CRLF checkout must not yield a hash no browser uses.
  const text = inlineMatch[1].replace(/\r\n?/g, "\n");
  const sha = createHash("sha256").update(text).digest("base64");
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

// 404.html turns Pages' single-page-application mode off (see the
// _redirects comment above). It is the final index.html byte for byte,
// Rocket Loader opt-out included, so a 404 still boots the SPA and its
// inline theme script still matches the CSP hash.
await copyFile(indexHtmlPath, resolve(dashboardRoot, "dist-demo/404.html"));

// `no-transform` on the HTML: the Cloudflare zone injects an inline JavaScript
// detections bootstrap (a fresh Ray ID and timestamp per request, so no CSP
// hash can ever match it) and the Web Analytics beacon into demo.z4j.com
// pages, and the CSP blocks both, leaving two console errors. Cloudflare
// injects neither into a response carrying `Cache-Control: no-transform`.
// /static/* and /demo-data/* detach that value and restate their own, so
// scripts and data stay compressed at the edge. Pages replaces Cache-Control
// with `no-store` on every 404, so a 404 page (an unknown path, or a route
// asked for with a trailing slash) never carries no-transform: it can still
// get both injections and the two console errors, which _headers cannot
// prevent.
await writeFile(
  resolve(dashboardRoot, "dist-demo/_headers"),
  buildHeaders(csp),
);

// The demo must not be indexed (_headers sends X-Robots-Tag: noindex), and a
// crawler only sees that header on a page it is allowed to fetch. Without this
// file the exact-route _redirects send /robots.txt to the 404 shell, which
// crawlers read as "no rules", so an explicit allow-all is the honest form.
await writeFile(
  resolve(dashboardRoot, "dist-demo/robots.txt"),
  [
    "# A sample dashboard, not documentation. Every page is served with",
    "# X-Robots-Tag: noindex; crawling stays allowed so that header is seen.",
    "User-agent: *",
    "Allow: /",
    "",
  ].join("\n"),
);

const ruleCount = redirects
  .split("\n")
  .filter((line) => line !== "" && !line.startsWith("#")).length;
console.log(
  `[build:demo] wrote _redirects (${ruleCount} rules), 404.html and _headers for Cloudflare Pages`,
);

// Re-read the finished dist-demo/ and hold it to the same rules, so a step
// moved out of order, or a file Pages would silently ignore, fails the build
// here instead of breaking demo.z4j.com.
const pagesViolations = await validateDemoPagesDist(distDemoPath, { csp });
if (pagesViolations.length > 0) {
  console.error(
    `[build:demo] FAIL: ${pagesViolations.length} Cloudflare Pages ` +
      "contract violation(s) in dist-demo:",
  );
  for (const violation of pagesViolations) {
    console.error(`  ${violation}`);
  }
  process.exit(1);
}
console.log(
  "[build:demo] OK: _redirects, 404.html and _headers meet the Pages contract",
);
console.log("[build:demo] done. Output: dist-demo/");
