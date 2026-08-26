/**
 * Prove that the dashboard is rendered before any visual baseline is taken.
 *
 * A successful fetch of Vite's index HTML does not prove that its browser
 * module graph is usable. Starting Vite before the tracked TanStack route tree
 * is refreshed can pin every browser request to stale optimized-dependency
 * hashes. The result is HTTP 200 with a blank #root.
 *
 * Use a real browser and the same login control as the functional spine. This
 * remains fail-closed: a blank page, failed module, or missing login contract
 * aborts the suite before screenshots or stateful tests run.
 */
import { chromium, type FullConfig } from "@playwright/test";

const READINESS_TIMEOUT_MS = 120_000;
const MAX_DIAGNOSTICS = 20;

export default async function globalSetup(config: FullConfig): Promise<void> {
  const baseURL =
    config.projects[0]?.use?.baseURL ??
    process.env.Z4J_E2E_BASE_URL ??
    "http://localhost:7701";
  const loginURL = new URL("/login", baseURL).toString();
  const diagnostics: string[] = [];
  const remember = (message: string): void => {
    if (diagnostics.length < MAX_DIAGNOSTICS) diagnostics.push(message);
  };

  const browser = await chromium.launch();
  const context = await browser.newContext();
  const page = await context.newPage();
  page.on("pageerror", (error) => remember(`pageerror: ${error.message}`));
  page.on("console", (message) => {
    if (message.type() === "error") remember(`console: ${message.text()}`);
  });
  page.on("requestfailed", (request) => {
    remember(
      `requestfailed: ${request.method()} ${request.url()} ` +
        `(${request.failure()?.errorText ?? "unknown error"})`,
    );
  });

  try {
    const response = await page.goto(loginURL, {
      waitUntil: "domcontentloaded",
      timeout: READINESS_TIMEOUT_MS,
    });
    if (response === null || !response.ok()) {
      throw new Error(
        `navigation returned ${response === null ? "no response" : response.status()}`,
      );
    }
    await page.getByLabel(/^Email$/i).waitFor({
      state: "visible",
      timeout: READINESS_TIMEOUT_MS,
    });
    await page.getByRole("button", { name: /^Sign in$/i }).waitFor({
      state: "visible",
      timeout: READINESS_TIMEOUT_MS,
    });
    console.log(`[global-setup] rendered login ready at ${loginURL}`);
  } catch (error) {
    const details = diagnostics.length > 0 ? `\n${diagnostics.join("\n")}` : "";
    throw new Error(
      `[global-setup] dashboard did not render a usable login at ${loginURL}: ` +
        `${error instanceof Error ? error.message : String(error)}${details}`,
      { cause: error },
    );
  } finally {
    try {
      await context.close();
    } finally {
      await browser.close();
    }
  }
}
