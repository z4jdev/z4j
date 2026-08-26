/** Generate and validate the dashboard's tracked TanStack route tree. */

import { lstat, readdir, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { resolveConfig } from "vite";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const dashboardRoot = resolve(scriptDirectory, "..");
const sourceDirectory = join(dashboardRoot, "src");
const generatedRouteTree = join(sourceDirectory, "routeTree.gen.ts");
const args = new Set(process.argv.slice(2));

if ([...args].some((arg) => arg !== "--fresh")) {
  throw new Error("usage: node scripts/generate-routes.mjs [--fresh]");
}

if (args.has("--fresh")) {
  await rm(generatedRouteTree, { force: true });
  for (const entry of await readdir(sourceDirectory)) {
    if (entry.startsWith("routeTree.gen.ts.timestamp-")) {
      await rm(join(sourceDirectory, entry), { force: true });
    }
  }
}

process.chdir(dashboardRoot);
await resolveConfig(
  { root: dashboardRoot },
  "build",
  "production",
  "production",
);

const generated = await lstat(generatedRouteTree).catch(() => null);
if (generated === null || !generated.isFile() || generated.size === 0) {
  throw new Error(
    "TanStack route generation did not produce a non-empty regular " +
      "src/routeTree.gen.ts",
  );
}
