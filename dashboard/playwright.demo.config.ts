import { defineConfig } from "@playwright/test";

/** Browser regression suite for the same static build deployed to demo.z4j.dev. */
export default defineConfig({
  testDir: "./tests/demo",
  outputDir: "./test-results/demo",
  fullyParallel: false,
  workers: 1,
  timeout: 45_000,
  use: {
    baseURL: "http://127.0.0.1:4173",
    viewport: { width: 1440, height: 1000 },
    colorScheme: "light",
    trace: "retain-on-failure",
    launchOptions: {
      executablePath: process.env.Z4J_QA_CHROMIUM_PATH || undefined,
    },
  },
  webServer: {
    command:
      "node node_modules/vite/bin/vite.js preview --outDir dist-demo --port 4173 --host 127.0.0.1",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
