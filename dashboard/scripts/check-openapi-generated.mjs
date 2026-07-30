#!/usr/bin/env node
/** Compare the generated OpenAPI types using a cross-platform temp path. */

import { readFileSync, rmSync } from "node:fs";

const committed = new URL("../src/lib/openapi-types.gen.ts", import.meta.url);
const candidate = new URL(
  "../src/lib/.openapi-types.gen.check.ts",
  import.meta.url,
);

try {
  if (readFileSync(committed, "utf8") !== readFileSync(candidate, "utf8")) {
    console.error(
      'OpenAPI -> TS drift detected. Run "pnpm openapi:gen" and commit.',
    );
    process.exitCode = 1;
  }
} finally {
  rmSync(candidate, { force: true });
}
