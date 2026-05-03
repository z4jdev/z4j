#!/usr/bin/env node
/**
 * Pull the brain's live OpenAPI spec into ``src/lib/openapi-snapshot.json``.
 *
 * Used by the "OpenAPI <-> TS contract test" workflow:
 *
 *   1. dev: ``pnpm openapi:fetch`` → snapshot.json
 *   2. dev: ``pnpm openapi:gen``    → openapi-types.gen.ts
 *   3. CI:  ``pnpm openapi:check``  → regenerates against the
 *       snapshot and diffs - any drift between hand-written
 *       ``api-types.ts`` and the generated types fails the build.
 *
 * The snapshot lives in source so CI does not need the brain
 * running. Update it deliberately when the API changes.
 */
import { writeFileSync } from "node:fs";

const url =
  process.env.Z4J_OPENAPI_URL ?? "http://127.0.0.1:7700/api/v1/openapi.json";

const res = await fetch(url);
if (!res.ok) {
  console.error(
    `Failed to fetch ${url}: HTTP ${res.status}. ` +
      `Is the brain running? Set Z4J_OPENAPI_URL to override.`,
  );
  process.exit(1);
}
const spec = await res.json();
writeFileSync(
  new URL("../src/lib/openapi-snapshot.json", import.meta.url),
  JSON.stringify(spec, null, 2) + "\n",
);
console.log(
  `Wrote OpenAPI snapshot from ${url} ` +
    `(${Object.keys(spec.paths ?? {}).length} paths).`,
);
